"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.isWebhookReplayed = isWebhookReplayed;
exports.markWebhookProcessed = markWebhookProcessed;
const express_1 = __importDefault(require("express"));
const helmet_1 = __importDefault(require("helmet"));
const cors_1 = __importDefault(require("cors"));
const config_1 = require("./config");
const logger_1 = require("./logger");
const handlers_1 = require("./handlers");
const metrics = __importStar(require("./metrics"));
const middleware_1 = require("./middleware");
// Webhook replay protection cache with size limit to prevent memory exhaustion
const processedWebhooks = new Map();
const WEBHOOK_CACHE_TTL = 5 * 60 * 1000; // 5 minutes
const MAX_WEBHOOK_CACHE_SIZE = 10000; // Maximum entries to prevent DoS
// Cleanup old webhook entries periodically
function cleanupWebhookCache() {
    const now = Date.now();
    for (const [eventId, timestamp] of processedWebhooks.entries()) {
        if (now - timestamp > WEBHOOK_CACHE_TTL) {
            processedWebhooks.delete(eventId);
        }
    }
}
// Check if webhook was already processed (replay protection)
// NOTE: This only CHECKS - does not mark. Call markWebhookProcessed() after validation.
function isWebhookReplayed(eventId) {
    return processedWebhooks.has(eventId);
}
// Mark webhook as processed (call AFTER all validations pass)
// SECURITY: Enforce maximum cache size to prevent memory exhaustion DoS
function markWebhookProcessed(eventId) {
    // If at capacity, remove oldest entries first (FIFO eviction)
    if (processedWebhooks.size >= MAX_WEBHOOK_CACHE_SIZE) {
        // Map maintains insertion order, so first key is oldest
        const oldestKey = processedWebhooks.keys().next().value;
        if (oldestKey) {
            processedWebhooks.delete(oldestKey);
        }
    }
    processedWebhooks.set(eventId, Date.now());
}
// Sanitize string for safe logging (prevent log injection)
function sanitizeForLog(input, maxLen = 64) {
    return input
        .replace(/[\n\r\t\x00-\x1f\x7f-\x9f]/g, '')
        .substring(0, maxLen);
}
// Rate limiter using token bucket with size limit to prevent memory exhaustion
class RateLimiter {
    buckets = new Map();
    rate;
    burst;
    // SECURITY: Maximum number of tracked IPs to prevent memory exhaustion DoS
    static MAX_BUCKETS = 10000;
    constructor(rate, burst) {
        this.rate = rate;
        this.burst = burst;
    }
    allow(key) {
        const now = Date.now();
        let bucket = this.buckets.get(key);
        if (!bucket) {
            // SECURITY: Enforce maximum bucket count to prevent memory exhaustion
            if (this.buckets.size >= RateLimiter.MAX_BUCKETS) {
                // Evict oldest entry (Map maintains insertion order)
                const oldestKey = this.buckets.keys().next().value;
                if (oldestKey) {
                    this.buckets.delete(oldestKey);
                }
            }
            bucket = { tokens: this.burst, lastRefill: now };
            this.buckets.set(key, bucket);
        }
        // Refill tokens based on time elapsed
        const elapsed = (now - bucket.lastRefill) / 1000;
        bucket.tokens = Math.min(this.burst, bucket.tokens + elapsed * this.rate);
        bucket.lastRefill = now;
        if (bucket.tokens >= 1) {
            bucket.tokens -= 1;
            return true;
        }
        return false;
    }
    // Cleanup old entries periodically
    cleanup() {
        const now = Date.now();
        const maxAge = 60000; // 1 minute
        for (const [key, bucket] of this.buckets.entries()) {
            if (now - bucket.lastRefill > maxAge) {
                this.buckets.delete(key);
            }
        }
    }
}
// Circuit breaker for CRE gateway
// SECURITY: Uses atomic-like state transitions to prevent TOCTOU race conditions
class CircuitBreaker {
    state = 'closed';
    failures = 0;
    lastFailure = 0;
    lastStateChange = 0;
    threshold;
    resetTimeout;
    constructor(threshold = 5, resetTimeoutMs = 30000) {
        this.threshold = threshold;
        this.resetTimeout = resetTimeoutMs;
        this.lastStateChange = Date.now();
    }
    isOpen() {
        const now = Date.now();
        switch (this.state) {
            case 'closed':
                return false;
            case 'open':
                // Check if we should transition to half-open
                if (now - this.lastFailure >= this.resetTimeout) {
                    this.state = 'half-open';
                    this.lastStateChange = now;
                    return false; // Allow one request through
                }
                return true;
            case 'half-open':
                // In half-open state, allow requests through to test
                return false;
            default:
                return false;
        }
    }
    recordFailure() {
        const now = Date.now();
        this.failures++;
        this.lastFailure = now;
        if (this.state === 'half-open') {
            // Failed during half-open, go back to open
            this.state = 'open';
            this.lastStateChange = now;
        }
        else if (this.failures >= this.threshold) {
            // Threshold reached, open the circuit
            this.state = 'open';
            this.lastStateChange = now;
        }
    }
    recordSuccess() {
        const now = Date.now();
        if (this.state === 'half-open') {
            // Success during half-open, close the circuit
            this.state = 'closed';
            this.failures = 0;
            this.lastStateChange = now;
        }
        else if (this.state === 'closed') {
            // Reset failure count on success in closed state
            this.failures = 0;
        }
    }
    getFailures() {
        return this.failures;
    }
    getState() {
        return this.state;
    }
}
// Get client IP from request
function getClientIp(req) {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string') {
        return forwarded.split(',')[0].trim();
    }
    return req.socket.remoteAddress || 'unknown';
}
// Start the server
async function main() {
    let config;
    try {
        config = (0, config_1.loadConfig)();
    }
    catch (error) {
        logger_1.logger.error('Failed to load configuration', { error: error.message });
        process.exit(1);
    }
    logger_1.logger.info('Starting Ducat Gateway', {
        workflowId: config.workflowId,
        gatewayUrl: config.gatewayUrl,
        port: config.port,
    });
    // Initialize state (using createAppState to include quoteCache and nostrClient)
    const { QuoteCache } = await Promise.resolve().then(() => __importStar(require('./cache')));
    const { NostrClient } = await Promise.resolve().then(() => __importStar(require('./nostr')));
    const state = {
        config,
        pendingRequests: new Map(),
        startTime: new Date(),
        quoteCache: new QuoteCache(),
        nostrClient: new NostrClient(config.nostrRelayUrl, config.oraclePubkey),
    };
    // Set max pending gauge
    metrics.setMaxPending(config.maxPending);
    // Initialize middleware
    const rateLimiter = new RateLimiter(config.ipRateLimit, config.ipBurstLimit);
    const circuitBreaker = new CircuitBreaker();
    // Create Express app
    const app = (0, express_1.default)();
    // Security middleware - helmet adds various security headers
    app.use((0, helmet_1.default)({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'none'"],
            },
        },
        hsts: {
            maxAge: 31536000,
            includeSubDomains: true,
        },
    }));
    // CORS - restrict to configured origins (default: none for API-only service)
    const allowedOrigins = process.env.CORS_ALLOWED_ORIGINS?.split(',') || [];
    app.use((0, cors_1.default)({
        origin: allowedOrigins.length > 0 ? allowedOrigins : false,
        methods: ['GET', 'POST'],
        allowedHeaders: ['Content-Type', 'Authorization'],
    }));
    // Parse JSON bodies with size limit
    app.use(express_1.default.json({ limit: '1mb' }));
    // Metrics middleware (must be before request logging to capture all requests)
    app.use(middleware_1.metricsMiddleware);
    // Request logging middleware
    app.use((req, res, next) => {
        const start = Date.now();
        const clientIp = getClientIp(req);
        res.on('finish', () => {
            const duration = Date.now() - start;
            logger_1.logger.info('Request completed', {
                method: req.method,
                path: req.path,
                status: res.statusCode,
                duration: `${duration}ms`,
                clientIp,
            });
        });
        next();
    });
    // Rate limiting middleware (skip health endpoints)
    app.use((req, res, next) => {
        if (req.path === '/health' || req.path === '/readiness') {
            return next();
        }
        const clientIp = getClientIp(req);
        if (!rateLimiter.allow(clientIp)) {
            logger_1.logger.warn('Rate limit exceeded', { clientIp, path: req.path });
            metrics.recordRateLimitRejected(req.path);
            res.status(429).json({ error: 'rate limit exceeded' });
            return;
        }
        next();
    });
    // Routes
    app.get('/api/quote', async (req, res) => {
        // Check circuit breaker
        if (circuitBreaker.isOpen()) {
            logger_1.logger.warn('Circuit breaker open, rejecting request');
            res.status(503).json({ error: 'service temporarily unavailable' });
            return;
        }
        try {
            await (0, handlers_1.handleCreate)(req, res, state);
            circuitBreaker.recordSuccess();
        }
        catch (error) {
            circuitBreaker.recordFailure();
            logger_1.logger.error('Quote handler error', { error: error.message });
            res.status(500).json({ error: 'internal server error' });
        }
    });
    app.get('/api/price', (req, res) => {
        (0, handlers_1.handlePrice)(req, res, state);
    });
    app.post('/webhook/ducat', async (req, res) => {
        try {
            await (0, handlers_1.handleWebhook)(req, res, state);
        }
        catch (error) {
            logger_1.logger.error('Webhook handler error', { error: error.message });
            res.status(500).json({ error: 'internal server error' });
        }
    });
    app.get('/health', (req, res) => {
        (0, handlers_1.handleHealth)(req, res, state);
    });
    app.get('/readiness', async (req, res) => {
        try {
            await (0, handlers_1.handleReadiness)(req, res, state);
        }
        catch (error) {
            logger_1.logger.error('Readiness handler error', { error: error.message });
            res.status(500).json({ error: 'internal server error' });
        }
    });
    app.get('/metrics', async (req, res) => {
        try {
            res.set('Content-Type', metrics.getContentType());
            res.send(await metrics.getMetrics());
        }
        catch (error) {
            logger_1.logger.error('Metrics handler error', { error: error.message });
            res.status(500).json({ error: 'internal server error' });
        }
    });
    app.get('/status/:id', (req, res) => {
        (0, handlers_1.handleStatus)(req, res, state);
    });
    app.post('/check', async (req, res) => {
        // Check circuit breaker
        if (circuitBreaker.isOpen()) {
            logger_1.logger.warn('Circuit breaker open, rejecting request');
            res.status(503).json({ error: 'service temporarily unavailable' });
            return;
        }
        try {
            await (0, handlers_1.handleCheck)(req, res, state);
            circuitBreaker.recordSuccess();
        }
        catch (error) {
            circuitBreaker.recordFailure();
            logger_1.logger.error('Check handler error', { error: error.message });
            res.status(500).json({ error: 'internal server error' });
        }
    });
    // 404 handler
    app.use((req, res) => {
        res.status(404).json({ error: 'not found' });
    });
    // Error handler
    app.use((err, req, res, _next) => {
        logger_1.logger.error('Unhandled error', { error: err.message, stack: err.stack });
        res.status(500).json({ error: 'internal server error' });
    });
    // Start background tasks
    (0, handlers_1.startCleanupTask)(state);
    if (config.liquidationEnabled) {
        (0, handlers_1.startLiquidationPoller)(state);
    }
    // Cleanup rate limiter and webhook cache periodically
    setInterval(() => {
        rateLimiter.cleanup();
        cleanupWebhookCache();
    }, 60000);
    // Start server
    const server = app.listen(config.port, () => {
        logger_1.logger.info(`Ducat Gateway listening on port ${config.port}`);
    });
    // Graceful shutdown
    const shutdown = async (signal) => {
        logger_1.logger.info(`Received ${signal}, shutting down gracefully`);
        server.close(() => {
            logger_1.logger.info('HTTP server closed');
            process.exit(0);
        });
        // Force exit after 10 seconds
        setTimeout(() => {
            logger_1.logger.error('Forced shutdown after timeout');
            process.exit(1);
        }, 10000);
    };
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
}
main().catch((error) => {
    logger_1.logger.error('Fatal error', { error: error.message });
    process.exit(1);
});
//# sourceMappingURL=index.js.map
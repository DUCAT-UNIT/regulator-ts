import express, { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import { loadConfig, GatewayConfig } from './config';
import { logger } from './logger';
import {
  AppState,
  handleCreate,
  handleWebhook,
  handleHealth,
  handlePrice,
  handleReadiness,
  handleStatus,
  handleCheck,
  startCleanupTask,
  startLiquidationPoller,
} from './handlers';
import * as metrics from './metrics';
import { metricsMiddleware } from './middleware';

// Webhook replay protection cache with size limit to prevent memory exhaustion
const processedWebhooks = new Map<string, number>();
const WEBHOOK_CACHE_TTL = 5 * 60 * 1000; // 5 minutes
const MAX_WEBHOOK_CACHE_SIZE = 10000; // Maximum entries to prevent DoS

// Cleanup old webhook entries periodically
function cleanupWebhookCache(): void {
  const now = Date.now();
  for (const [eventId, timestamp] of processedWebhooks.entries()) {
    if (now - timestamp > WEBHOOK_CACHE_TTL) {
      processedWebhooks.delete(eventId);
    }
  }
}

// Check if webhook was already processed (replay protection)
// NOTE: This only CHECKS - does not mark. Call markWebhookProcessed() after validation.
export function isWebhookReplayed(eventId: string): boolean {
  return processedWebhooks.has(eventId);
}

// Mark webhook as processed (call AFTER all validations pass)
// SECURITY: Enforce maximum cache size to prevent memory exhaustion DoS
export function markWebhookProcessed(eventId: string): void {
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
function sanitizeForLog(input: string, maxLen: number = 64): string {
  return input
    .replace(/[\n\r\t\x00-\x1f\x7f-\x9f]/g, '')
    .substring(0, maxLen);
}

// Rate limiter using token bucket with size limit to prevent memory exhaustion
class RateLimiter {
  private buckets: Map<string, { tokens: number; lastRefill: number }> = new Map();
  private rate: number;
  private burst: number;
  // SECURITY: Maximum number of tracked IPs to prevent memory exhaustion DoS
  private static readonly MAX_BUCKETS = 10000;

  constructor(rate: number, burst: number) {
    this.rate = rate;
    this.burst = burst;
  }

  allow(key: string): boolean {
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
  cleanup(): void {
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
  private state: 'closed' | 'open' | 'half-open' = 'closed';
  private failures: number = 0;
  private lastFailure: number = 0;
  private lastStateChange: number = 0;
  private readonly threshold: number;
  private readonly resetTimeout: number;

  constructor(threshold: number = 5, resetTimeoutMs: number = 30000) {
    this.threshold = threshold;
    this.resetTimeout = resetTimeoutMs;
    this.lastStateChange = Date.now();
  }

  isOpen(): boolean {
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

  recordFailure(): void {
    const now = Date.now();
    this.failures++;
    this.lastFailure = now;

    if (this.state === 'half-open') {
      // Failed during half-open, go back to open
      this.state = 'open';
      this.lastStateChange = now;
    } else if (this.failures >= this.threshold) {
      // Threshold reached, open the circuit
      this.state = 'open';
      this.lastStateChange = now;
    }
  }

  recordSuccess(): void {
    const now = Date.now();

    if (this.state === 'half-open') {
      // Success during half-open, close the circuit
      this.state = 'closed';
      this.failures = 0;
      this.lastStateChange = now;
    } else if (this.state === 'closed') {
      // Reset failure count on success in closed state
      this.failures = 0;
    }
  }

  getFailures(): number {
    return this.failures;
  }

  getState(): string {
    return this.state;
  }
}

// Get client IP from request
function getClientIp(req: Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string') {
    return forwarded.split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}

// Start the server
async function main(): Promise<void> {
  let config: GatewayConfig;
  try {
    config = loadConfig();
  } catch (error) {
    logger.error('Failed to load configuration', { error: (error as Error).message });
    process.exit(1);
  }

  logger.info('Starting Ducat Gateway', {
    workflowId: config.workflowId,
    gatewayUrl: config.gatewayUrl,
    port: config.port,
  });

  // Initialize state (using createAppState to include quoteCache and nostrClient)
  const { QuoteCache } = await import('./cache');
  const { NostrClient } = await import('./nostr');

  const state: AppState = {
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
  const app = express();

  // Security middleware - helmet adds various security headers
  app.use(helmet({
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
  app.use(cors({
    origin: allowedOrigins.length > 0 ? allowedOrigins : false,
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  }));

  // Parse JSON bodies with size limit
  app.use(express.json({ limit: '1mb' }));

  // Metrics middleware (must be before request logging to capture all requests)
  app.use(metricsMiddleware);

  // Request logging middleware
  app.use((req: Request, res: Response, next: NextFunction) => {
    const start = Date.now();
    const clientIp = getClientIp(req);

    res.on('finish', () => {
      const duration = Date.now() - start;
      logger.info('Request completed', {
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
  app.use((req: Request, res: Response, next: NextFunction) => {
    if (req.path === '/health' || req.path === '/readiness') {
      return next();
    }

    const clientIp = getClientIp(req);
    if (!rateLimiter.allow(clientIp)) {
      logger.warn('Rate limit exceeded', { clientIp, path: req.path });
      metrics.recordRateLimitRejected(req.path);
      res.status(429).json({ error: 'rate limit exceeded' });
      return;
    }

    next();
  });

  // Routes
  app.get('/api/quote', async (req: Request, res: Response) => {
    // Check circuit breaker
    if (circuitBreaker.isOpen()) {
      logger.warn('Circuit breaker open, rejecting request');
      res.status(503).json({ error: 'service temporarily unavailable' });
      return;
    }

    try {
      await handleCreate(req, res, state);
      circuitBreaker.recordSuccess();
    } catch (error) {
      circuitBreaker.recordFailure();
      logger.error('Quote handler error', { error: (error as Error).message });
      res.status(500).json({ error: 'internal server error' });
    }
  });

  app.get('/api/price', (req: Request, res: Response) => {
    handlePrice(req, res, state);
  });

  app.post('/webhook/ducat', async (req: Request, res: Response) => {
    try {
      await handleWebhook(req, res, state);
    } catch (error) {
      logger.error('Webhook handler error', { error: (error as Error).message });
      res.status(500).json({ error: 'internal server error' });
    }
  });

  app.get('/health', (req: Request, res: Response) => {
    handleHealth(req, res, state);
  });

  app.get('/readiness', async (req: Request, res: Response) => {
    try {
      await handleReadiness(req, res, state);
    } catch (error) {
      logger.error('Readiness handler error', { error: (error as Error).message });
      res.status(500).json({ error: 'internal server error' });
    }
  });

  app.get('/metrics', async (req: Request, res: Response) => {
    try {
      res.set('Content-Type', metrics.getContentType());
      res.send(await metrics.getMetrics());
    } catch (error) {
      logger.error('Metrics handler error', { error: (error as Error).message });
      res.status(500).json({ error: 'internal server error' });
    }
  });

  app.get('/status/:id', (req: Request, res: Response) => {
    handleStatus(req, res, state);
  });

  app.post('/check', async (req: Request, res: Response) => {
    // Check circuit breaker
    if (circuitBreaker.isOpen()) {
      logger.warn('Circuit breaker open, rejecting request');
      res.status(503).json({ error: 'service temporarily unavailable' });
      return;
    }

    try {
      await handleCheck(req, res, state);
      circuitBreaker.recordSuccess();
    } catch (error) {
      circuitBreaker.recordFailure();
      logger.error('Check handler error', { error: (error as Error).message });
      res.status(500).json({ error: 'internal server error' });
    }
  });

  // 404 handler
  app.use((req: Request, res: Response) => {
    res.status(404).json({ error: 'not found' });
  });

  // Error handler
  app.use((err: Error, req: Request, res: Response, _next: NextFunction) => {
    logger.error('Unhandled error', { error: err.message, stack: err.stack });
    res.status(500).json({ error: 'internal server error' });
  });

  // Start background tasks
  startCleanupTask(state);

  if (config.liquidationEnabled) {
    startLiquidationPoller(state);
  }

  // Cleanup rate limiter and webhook cache periodically
  setInterval(() => {
    rateLimiter.cleanup();
    cleanupWebhookCache();
  }, 60000);

  // Start server
  const server = app.listen(config.port, () => {
    logger.info(`Ducat Gateway listening on port ${config.port}`);
  });

  // Graceful shutdown
  const shutdown = async (signal: string) => {
    logger.info(`Received ${signal}, shutting down gracefully`);

    server.close(() => {
      logger.info('HTTP server closed');
      process.exit(0);
    });

    // Force exit after 10 seconds
    setTimeout(() => {
      logger.error('Forced shutdown after timeout');
      process.exit(1);
    }, 10000);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

main().catch((error) => {
  logger.error('Fatal error', { error: error.message });
  process.exit(1);
});

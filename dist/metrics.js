"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.uptimeSeconds = exports.errorsRecovered = exports.rateLimitRejected = exports.dependencyStatus = exports.healthChecks = exports.requestTimeouts = exports.requestsCleanedUp = exports.workflowTriggers = exports.webhookSignatureFailures = exports.webhooksReceived = exports.maxPendingGauge = exports.pendingRequestsGauge = exports.httpRequestDuration = exports.httpRequestsTotal = exports.register = void 0;
exports.recordHttpRequest = recordHttpRequest;
exports.recordHttpDuration = recordHttpDuration;
exports.setPendingRequests = setPendingRequests;
exports.setMaxPending = setMaxPending;
exports.recordWebhookReceived = recordWebhookReceived;
exports.recordWebhookSignatureFailure = recordWebhookSignatureFailure;
exports.recordWorkflowTrigger = recordWorkflowTrigger;
exports.recordRequestsCleanedUp = recordRequestsCleanedUp;
exports.recordRequestTimeout = recordRequestTimeout;
exports.recordHealthCheck = recordHealthCheck;
exports.setDependencyStatus = setDependencyStatus;
exports.recordRateLimitRejected = recordRateLimitRejected;
exports.recordErrorRecovered = recordErrorRecovered;
exports.setUptimeSeconds = setUptimeSeconds;
exports.getMetrics = getMetrics;
exports.getContentType = getContentType;
const prom_client_1 = __importDefault(require("prom-client"));
// Create a registry
exports.register = new prom_client_1.default.Registry();
// Add default metrics (process CPU, memory, etc.)
prom_client_1.default.collectDefaultMetrics({ register: exports.register });
// HTTP request metrics
exports.httpRequestsTotal = new prom_client_1.default.Counter({
    name: 'gateway_http_requests_total',
    help: 'Total number of HTTP requests by endpoint and status',
    labelNames: ['endpoint', 'method', 'status'],
    registers: [exports.register],
});
exports.httpRequestDuration = new prom_client_1.default.Histogram({
    name: 'gateway_http_request_duration_seconds',
    help: 'HTTP request latency in seconds',
    labelNames: ['endpoint', 'method'],
    buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
    registers: [exports.register],
});
// Pending requests gauge
exports.pendingRequestsGauge = new prom_client_1.default.Gauge({
    name: 'gateway_pending_requests',
    help: 'Current number of pending requests',
    registers: [exports.register],
});
// Max pending gauge
exports.maxPendingGauge = new prom_client_1.default.Gauge({
    name: 'gateway_max_pending',
    help: 'Maximum pending requests allowed',
    registers: [exports.register],
});
// Webhook metrics
exports.webhooksReceived = new prom_client_1.default.Counter({
    name: 'gateway_webhooks_received_total',
    help: 'Total number of webhooks received by event type',
    labelNames: ['event_type', 'matched'],
    registers: [exports.register],
});
exports.webhookSignatureFailures = new prom_client_1.default.Counter({
    name: 'gateway_webhook_signature_failures_total',
    help: 'Total number of webhook signature verification failures',
    labelNames: ['reason'],
    registers: [exports.register],
});
// Workflow trigger metrics
exports.workflowTriggers = new prom_client_1.default.Counter({
    name: 'gateway_workflow_triggers_total',
    help: 'Total number of workflow triggers by operation and status',
    labelNames: ['operation', 'status'],
    registers: [exports.register],
});
// Cleanup metrics
exports.requestsCleanedUp = new prom_client_1.default.Counter({
    name: 'gateway_requests_cleaned_up_total',
    help: 'Total number of old requests cleaned up',
    registers: [exports.register],
});
// Timeout metrics
exports.requestTimeouts = new prom_client_1.default.Counter({
    name: 'gateway_request_timeouts_total',
    help: 'Total number of request timeouts by endpoint',
    labelNames: ['endpoint'],
    registers: [exports.register],
});
// Health check metrics
exports.healthChecks = new prom_client_1.default.Counter({
    name: 'gateway_health_checks_total',
    help: 'Total number of health/readiness checks by status',
    labelNames: ['type', 'status'],
    registers: [exports.register],
});
exports.dependencyStatus = new prom_client_1.default.Gauge({
    name: 'gateway_dependency_status',
    help: 'Status of dependencies (1=up, 0.5=degraded, 0=down)',
    labelNames: ['dependency'],
    registers: [exports.register],
});
// Rate limiting metrics
exports.rateLimitRejected = new prom_client_1.default.Counter({
    name: 'gateway_rate_limit_rejected_total',
    help: 'Total number of requests rejected due to rate limiting',
    labelNames: ['endpoint'],
    registers: [exports.register],
});
// Panic/error recovery metrics
exports.errorsRecovered = new prom_client_1.default.Counter({
    name: 'gateway_errors_recovered_total',
    help: 'Total number of errors recovered by the server',
    registers: [exports.register],
});
// Uptime metric
exports.uptimeSeconds = new prom_client_1.default.Gauge({
    name: 'gateway_uptime_seconds',
    help: 'Server uptime in seconds',
    registers: [exports.register],
});
// Helper functions for recording metrics
function recordHttpRequest(endpoint, method, status) {
    exports.httpRequestsTotal.labels(endpoint, method, status.toString()).inc();
}
function recordHttpDuration(endpoint, method, durationSecs) {
    exports.httpRequestDuration.labels(endpoint, method).observe(durationSecs);
}
function setPendingRequests(count) {
    exports.pendingRequestsGauge.set(count);
}
function setMaxPending(max) {
    exports.maxPendingGauge.set(max);
}
function recordWebhookReceived(eventType, matched) {
    exports.webhooksReceived.labels(eventType, matched.toString()).inc();
}
function recordWebhookSignatureFailure(reason) {
    exports.webhookSignatureFailures.labels(reason).inc();
}
function recordWorkflowTrigger(operation, success) {
    exports.workflowTriggers.labels(operation, success ? 'success' : 'error').inc();
}
function recordRequestsCleanedUp(count) {
    exports.requestsCleanedUp.inc(count);
}
function recordRequestTimeout(endpoint) {
    exports.requestTimeouts.labels(endpoint).inc();
}
function recordHealthCheck(checkType, status) {
    exports.healthChecks.labels(checkType, status).inc();
}
function setDependencyStatus(dependency, status) {
    exports.dependencyStatus.labels(dependency).set(status);
}
function recordRateLimitRejected(endpoint) {
    exports.rateLimitRejected.labels(endpoint).inc();
}
function recordErrorRecovered() {
    exports.errorsRecovered.inc();
}
function setUptimeSeconds(seconds) {
    exports.uptimeSeconds.set(seconds);
}
// Get all metrics as Prometheus text format
async function getMetrics() {
    return exports.register.metrics();
}
// Get content type for Prometheus
function getContentType() {
    return exports.register.contentType;
}
//# sourceMappingURL=metrics.js.map
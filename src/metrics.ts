import client from 'prom-client';

// Create a registry
export const register = new client.Registry();

// Add default metrics (process CPU, memory, etc.)
client.collectDefaultMetrics({ register });

// HTTP request metrics
export const httpRequestsTotal = new client.Counter({
  name: 'gateway_http_requests_total',
  help: 'Total number of HTTP requests by endpoint and status',
  labelNames: ['endpoint', 'method', 'status'],
  registers: [register],
});

export const httpRequestDuration = new client.Histogram({
  name: 'gateway_http_request_duration_seconds',
  help: 'HTTP request latency in seconds',
  labelNames: ['endpoint', 'method'],
  buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
  registers: [register],
});

// Pending requests gauge
export const pendingRequestsGauge = new client.Gauge({
  name: 'gateway_pending_requests',
  help: 'Current number of pending requests',
  registers: [register],
});

// Max pending gauge
export const maxPendingGauge = new client.Gauge({
  name: 'gateway_max_pending',
  help: 'Maximum pending requests allowed',
  registers: [register],
});

// Webhook metrics
export const webhooksReceived = new client.Counter({
  name: 'gateway_webhooks_received_total',
  help: 'Total number of webhooks received by event type',
  labelNames: ['event_type', 'matched'],
  registers: [register],
});

export const webhookSignatureFailures = new client.Counter({
  name: 'gateway_webhook_signature_failures_total',
  help: 'Total number of webhook signature verification failures',
  labelNames: ['reason'],
  registers: [register],
});

// Workflow trigger metrics
export const workflowTriggers = new client.Counter({
  name: 'gateway_workflow_triggers_total',
  help: 'Total number of workflow triggers by operation and status',
  labelNames: ['operation', 'status'],
  registers: [register],
});

// Cleanup metrics
export const requestsCleanedUp = new client.Counter({
  name: 'gateway_requests_cleaned_up_total',
  help: 'Total number of old requests cleaned up',
  registers: [register],
});

// Timeout metrics
export const requestTimeouts = new client.Counter({
  name: 'gateway_request_timeouts_total',
  help: 'Total number of request timeouts by endpoint',
  labelNames: ['endpoint'],
  registers: [register],
});

// Health check metrics
export const healthChecks = new client.Counter({
  name: 'gateway_health_checks_total',
  help: 'Total number of health/readiness checks by status',
  labelNames: ['type', 'status'],
  registers: [register],
});

export const dependencyStatus = new client.Gauge({
  name: 'gateway_dependency_status',
  help: 'Status of dependencies (1=up, 0.5=degraded, 0=down)',
  labelNames: ['dependency'],
  registers: [register],
});

// Rate limiting metrics
export const rateLimitRejected = new client.Counter({
  name: 'gateway_rate_limit_rejected_total',
  help: 'Total number of requests rejected due to rate limiting',
  labelNames: ['endpoint'],
  registers: [register],
});

// Panic/error recovery metrics
export const errorsRecovered = new client.Counter({
  name: 'gateway_errors_recovered_total',
  help: 'Total number of errors recovered by the server',
  registers: [register],
});

// Uptime metric
export const uptimeSeconds = new client.Gauge({
  name: 'gateway_uptime_seconds',
  help: 'Server uptime in seconds',
  registers: [register],
});

// Helper functions for recording metrics
export function recordHttpRequest(endpoint: string, method: string, status: number): void {
  httpRequestsTotal.labels(endpoint, method, status.toString()).inc();
}

export function recordHttpDuration(endpoint: string, method: string, durationSecs: number): void {
  httpRequestDuration.labels(endpoint, method).observe(durationSecs);
}

export function setPendingRequests(count: number): void {
  pendingRequestsGauge.set(count);
}

export function setMaxPending(max: number): void {
  maxPendingGauge.set(max);
}

export function recordWebhookReceived(eventType: string, matched: boolean): void {
  webhooksReceived.labels(eventType, matched.toString()).inc();
}

export function recordWebhookSignatureFailure(reason: string): void {
  webhookSignatureFailures.labels(reason).inc();
}

export function recordWorkflowTrigger(operation: string, success: boolean): void {
  workflowTriggers.labels(operation, success ? 'success' : 'error').inc();
}

export function recordRequestsCleanedUp(count: number): void {
  requestsCleanedUp.inc(count);
}

export function recordRequestTimeout(endpoint: string): void {
  requestTimeouts.labels(endpoint).inc();
}

export function recordHealthCheck(checkType: string, status: string): void {
  healthChecks.labels(checkType, status).inc();
}

export function setDependencyStatus(dependency: string, status: number): void {
  dependencyStatus.labels(dependency).set(status);
}

export function recordRateLimitRejected(endpoint: string): void {
  rateLimitRejected.labels(endpoint).inc();
}

export function recordErrorRecovered(): void {
  errorsRecovered.inc();
}

export function setUptimeSeconds(seconds: number): void {
  uptimeSeconds.set(seconds);
}

// Get all metrics as Prometheus text format
export async function getMetrics(): Promise<string> {
  return register.metrics();
}

// Get content type for Prometheus
export function getContentType(): string {
  return register.contentType;
}

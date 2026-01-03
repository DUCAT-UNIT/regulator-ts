import { Request, Response } from 'express';
import { timingSafeEqual } from 'crypto';
import { GatewayConfig } from './config';
import {
  generateJwt,
  generateRequestId,
  getTag,
  sha256Hex,
  truncateEventId,
  verifyWebhookSignature,
} from './crypto';
import {
  createRequestSchema,
  checkRequestSchema,
  webhookPayloadSchema,
  PendingRequest,
  WebhookPayload,
  PriceContractResponse,
  QuoteResponse,
  SyncResponse,
  HealthResponse,
  ReadinessResponse,
  DependencyHealth,
  AtRiskResponse,
  toV25Quote,
} from './types';
import { QuoteCache } from './cache';
import { NostrClient, calculateCommitHash, calculateCollateralRatio } from './nostr';
import logger from './logger';
import * as metrics from './metrics';

// Import replay protection from index
let isWebhookReplayed: (eventId: string) => boolean;
let markWebhookProcessed: (eventId: string) => void;
try {
  // Dynamic import to avoid circular dependency
  const indexModule = require('./index');
  isWebhookReplayed = indexModule.isWebhookReplayed;
  markWebhookProcessed = indexModule.markWebhookProcessed;
} catch {
  // Fallback for testing - simple in-memory cache
  const cache = new Map<string, boolean>();
  isWebhookReplayed = (eventId: string) => cache.has(eventId);
  markWebhookProcessed = (eventId: string) => { cache.set(eventId, true); };
}

/**
 * Constant-time string comparison to prevent timing attacks
 */
function secureCompare(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  return timingSafeEqual(bufA, bufB);
}

/**
 * Validate hex string format
 */
function isValidHex(str: string, expectedLen?: number): boolean {
  if (expectedLen && str.length !== expectedLen) {
    return false;
  }
  return /^[0-9a-fA-F]+$/.test(str);
}

/**
 * SECURITY: Safe JSON parse that rejects prototype pollution attempts
 * Throws if the parsed object contains __proto__, constructor, or prototype keys
 */
function safeJsonParse<T>(json: string): T {
  const parsed = JSON.parse(json);

  // Check for prototype pollution keys recursively
  const checkForPollution = (obj: unknown, path: string = ''): void => {
    if (obj === null || typeof obj !== 'object') {
      return;
    }

    const dangerousKeys = ['__proto__', 'constructor', 'prototype'];
    for (const key of Object.keys(obj as object)) {
      if (dangerousKeys.includes(key)) {
        throw new Error(`Prototype pollution attempt detected at ${path}${key}`);
      }
      checkForPollution((obj as Record<string, unknown>)[key], `${path}${key}.`);
    }
  };

  checkForPollution(parsed);
  return parsed as T;
}

// Application state
export interface AppState {
  config: GatewayConfig;
  pendingRequests: Map<string, PendingRequest>;
  startTime: Date;
  quoteCache: QuoteCache;
  nostrClient: NostrClient;
}

export function createAppState(config: GatewayConfig): AppState {
  return {
    config,
    pendingRequests: new Map(),
    startTime: new Date(),
    quoteCache: new QuoteCache(),
    nostrClient: new NostrClient(config.nostrRelayUrl, config.oraclePubkey),
  };
}

/**
 * GET /api/quote?th=PRICE - Create threshold commitment
 *
 * New flow:
 * 1. Get cached price data from webhooks
 * 2. Calculate commit_hash locally (d-tag)
 * 3. Try local cache first
 * 4. Try Nostr relay lookup
 * 5. Fall back to CRE workflow if quote not found
 */
export async function handleCreate(req: Request, res: Response, state: AppState): Promise<void> {
  try {
    // Parse and validate query params
    const parseResult = createRequestSchema.safeParse(req.query);
    if (!parseResult.success) {
      res.status(400).json({ error: parseResult.error.errors[0].message });
      return;
    }

    const { th } = parseResult.data;
    const tholdPrice = Math.floor(th);

    // Step 1: Get cached price data
    const cachedPrice = state.quoteCache.getPrice();
    if (!cachedPrice) {
      logger.warn('No cached price data available, falling back to CRE');
      await fallbackToCRE(req, res, state, th);
      return;
    }

    logger.debug('Using cached price', {
      basePrice: cachedPrice.basePrice,
      baseStamp: cachedPrice.baseStamp,
    });

    // Step 2: Calculate commit_hash locally (d-tag for Nostr lookup)
    let commitHash: string;
    try {
      commitHash = calculateCommitHash(
        state.config.oraclePubkey,
        state.config.chainNetwork,
        cachedPrice.basePrice,
        cachedPrice.baseStamp,
        tholdPrice
      );
    } catch (error) {
      logger.error('Failed to calculate commit_hash', { error: String(error) });
      res.status(500).json({ error: 'Internal server error' });
      return;
    }

    logger.debug('Calculated commit_hash', { commitHash, tholdPrice });

    // Step 3: Try local cache first
    const cachedQuote = state.quoteCache.getQuote(commitHash);
    if (cachedQuote) {
      logger.info('Quote served from local cache', { commitHash });
      const collateralRatio = calculateCollateralRatio(cachedPrice.basePrice, tholdPrice);
      sendQuoteResponse(res, cachedQuote, collateralRatio);
      return;
    }

    // Step 4: Try Nostr relay lookup
    try {
      const nostrQuote = await state.nostrClient.fetchQuoteByDTag(commitHash);
      if (nostrQuote) {
        // Found in Nostr! Cache it and return
        state.quoteCache.setQuote(commitHash, nostrQuote);
        logger.info('Quote served from Nostr relay', { commitHash });
        const collateralRatio = calculateCollateralRatio(cachedPrice.basePrice, tholdPrice);
        sendQuoteResponse(res, nostrQuote, collateralRatio);
        return;
      }
    } catch (error) {
      logger.warn('Failed to fetch quote from Nostr relay', {
        commitHash,
        error: String(error),
      });
      // Fall through to CRE fallback
    }

    // Step 5: Fall back to CRE workflow
    logger.info('Quote not found in cache or Nostr, falling back to CRE', { commitHash });
    await fallbackToCRE(req, res, state, th);
  } catch (error) {
    logger.error('Error in handleCreate', { error: String(error) });
    res.status(500).json({ error: 'Internal server error' });
  }
}

/**
 * Send QuoteResponse with collateral ratio (v2.5 format)
 */
function sendQuoteResponse(res: Response, quote: PriceContractResponse, collateralRatio: number): void {
  const v25Quote = toV25Quote(quote);
  const response: QuoteResponse = {
    ...v25Quote,
    collateral_ratio: collateralRatio,
  };
  res.json(response);
}

/**
 * Fall back to CRE workflow when quote not found in cache/Nostr
 */
async function fallbackToCRE(req: Request, res: Response, state: AppState, th: number): Promise<void> {
  // Check capacity
  if (state.pendingRequests.size >= state.config.maxPending) {
    logger.warn('Max pending requests reached', {
      current: state.pendingRequests.size,
      max: state.config.maxPending,
    });
    res.status(503).json({ error: 'Server at capacity, please retry later' });
    return;
  }

  // Generate domain with cryptographically random component to prevent prediction attacks
  // An attacker who can predict domains could pre-send forged webhooks
  // Use 16 chars of randomness (2^64 space) to prevent birthday attack collisions
  const randomPart = generateRequestId().slice(0, 16);
  const domain = `req-${Date.now()}-${randomPart}`;
  const trackingKey = domain;

  // Create promise for webhook result
  let resolveWebhook: (payload: WebhookPayload) => void;
  let rejectWebhook: (error: Error) => void;
  const webhookPromise = new Promise<WebhookPayload>((resolve, reject) => {
    resolveWebhook = resolve;
    rejectWebhook = reject;
  });

  // Register pending request
  const pending: PendingRequest = {
    requestId: trackingKey,
    createdAt: new Date(),
    resolve: resolveWebhook!,
    reject: rejectWebhook!,
    status: 'pending',
  };
  state.pendingRequests.set(trackingKey, pending);

  // Update pending requests gauge
  metrics.setPendingRequests(state.pendingRequests.size);

  logger.info('CRE fallback initiated', {
    domain,
    thresholdPrice: th,
    trackingKey,
    pendingCount: state.pendingRequests.size,
  });

  // Trigger CRE workflow
  try {
    await triggerWorkflow(state, 'create', domain, th, undefined, state.config.callbackUrl);
    metrics.recordWorkflowTrigger('create', true);
  } catch (error) {
    logger.error('Failed to trigger workflow', { domain, error: String(error) });
    state.pendingRequests.delete(trackingKey);
    metrics.setPendingRequests(state.pendingRequests.size);
    metrics.recordWorkflowTrigger('create', false);
    // SECURITY: Don't expose internal error details to clients
    res.status(500).json({ error: 'Failed to trigger workflow' });
    return;
  }

  // Wait for webhook or timeout
  const timeoutPromise = new Promise<'timeout'>((resolve) =>
    setTimeout(() => resolve('timeout'), state.config.blockTimeoutMs)
  );

  const result = await Promise.race([webhookPromise, timeoutPromise]);

  if (result === 'timeout') {
    logger.warn('CRE fallback timeout', { domain, requestId: trackingKey });

    const pendingReq = state.pendingRequests.get(trackingKey);
    if (pendingReq) {
      pendingReq.status = 'timeout';
    }

    metrics.recordRequestTimeout('create');

    const response: SyncResponse = {
      status: 'timeout',
      request_id: trackingKey,
      message: `Request is still processing. Use GET /status/${trackingKey} to check status.`,
    };
    res.status(202).json(response);
  } else {
    logger.info('CRE fallback completed', {
      domain,
      eventId: truncateEventId(result.event_id),
    });

    const pendingReq = state.pendingRequests.get(trackingKey);
    if (pendingReq) {
      pendingReq.status = 'completed';
      pendingReq.result = result;
    }

    // Parse CRE response (using safe parser to prevent prototype pollution)
    try {
      const contract: PriceContractResponse = safeJsonParse(result.content);

      // Calculate collateral ratio from response
      const collateralRatio = calculateCollateralRatio(contract.base_price, contract.thold_price);

      // Cache the quote for future requests
      state.quoteCache.setQuote(contract.commit_hash, contract);

      // Convert to v2.5 format before sending to client
      sendQuoteResponse(res, contract, collateralRatio);
    } catch {
      res.json({ raw: result.content });
    }
  }
}

/**
 * POST /webhook/ducat - CRE callback endpoint
 */
export async function handleWebhook(req: Request, res: Response, state: AppState): Promise<void> {
  try {
    // Parse payload
    const parseResult = webhookPayloadSchema.safeParse(req.body);
    if (!parseResult.success) {
      res.status(400).json({ error: 'Invalid JSON' });
      return;
    }

    const payload = parseResult.data;

    // Validate content is not empty
    if (!payload.content) {
      logger.warn('Webhook has empty content', { eventId: truncateEventId(payload.event_id) });
      res.status(400).json({ error: 'Webhook content cannot be empty' });
      return;
    }

    // Verify signature
    try {
      verifyWebhookSignature(payload);
    } catch (error) {
      logger.error('Webhook signature verification failed', {
        error: String(error),
        eventId: truncateEventId(payload.event_id),
      });
      metrics.recordWebhookSignatureFailure('invalid_signature');
      res.status(401).json({ error: 'Signature verification failed' });
      return;
    }

    // Check for replay attack
    if (isWebhookReplayed(payload.event_id)) {
      logger.warn('Webhook replay detected', {
        eventId: truncateEventId(payload.event_id),
      });
      res.status(409).json({ error: 'Duplicate webhook' });
      return;
    }

    // Verify pubkey matches expected (constant-time comparison)
    if (!secureCompare(payload.pubkey, state.config.expectedWebhookPubkey)) {
      logger.warn('Webhook signed by unauthorized key', {
        eventId: truncateEventId(payload.event_id),
      });
      metrics.recordWebhookSignatureFailure('unauthorized_key');
      res.status(401).json({ error: 'Webhook signed by unauthorized key' });
      return;
    }

    // SECURITY: Check timestamp freshness using direct comparison to avoid integer overflow
    // Webhooks older than 5 minutes are rejected to limit replay window
    // Allow 5 seconds of future drift to handle minor clock skew between servers
    const currentTime = Math.floor(Date.now() / 1000);
    const maxClockSkew = 5; // 5 seconds
    const maxWebhookAge = 300; // 5 minutes

    if (payload.created_at > currentTime + maxClockSkew) {
      logger.warn('Webhook has future timestamp', {
        createdAt: payload.created_at,
        currentTime,
      });
      res.status(401).json({ error: 'Invalid timestamp' });
      return;
    }
    if (payload.created_at < currentTime - maxWebhookAge) {
      logger.warn('Webhook timestamp expired', {
        createdAt: payload.created_at,
        currentTime,
      });
      res.status(401).json({ error: 'Webhook expired' });
      return;
    }

    // Mark webhook as processed AFTER all validations pass
    // This prevents cache poisoning attacks where an attacker sends a
    // forged webhook to block the legitimate one
    markWebhookProcessed(payload.event_id);

    // Cache price data from webhook for the new quote flow
    // This allows handleCreate to serve quotes without calling CRE
    cacheWebhookPrice(payload, state);

    // Extract domain from tags
    const domain = getTag(payload.tags, 'domain');
    if (!domain) {
      logger.warn('Webhook missing required domain tag', {
        eventId: truncateEventId(payload.event_id),
      });
      res.status(400).json({ error: 'Missing required domain tag' });
      return;
    }

    // Find pending request and resolve it
    const pending = state.pendingRequests.get(domain);
    let matched = false;
    if (pending?.resolve) {
      pending.resolve(payload);
      matched = true;
      logger.info('Webhook received and matched', {
        eventType: payload.event_type,
        domain,
        eventId: truncateEventId(payload.event_id),
      });
    } else {
      logger.debug('Webhook received but no pending request found', {
        domain,
        eventId: truncateEventId(payload.event_id),
      });
    }

    metrics.recordWebhookReceived(payload.event_type, matched);

    res.json({ status: 'OK' });
  } catch (error) {
    logger.error('Error in handleWebhook', { error: String(error) });
    res.status(500).json({ error: 'Internal server error' });
  }
}

/**
 * Cache price data from webhook for the new quote flow
 */
function cacheWebhookPrice(payload: WebhookPayload, state: AppState): void {
  if (!payload.content) {
    return;
  }

  try {
    const priceContract: PriceContractResponse = JSON.parse(payload.content);

    // Only cache if we have valid price data
    if (priceContract.base_price <= 0 || priceContract.base_stamp <= 0) {
      logger.debug('Invalid price data in webhook (ignoring)', {
        basePrice: priceContract.base_price,
        baseStamp: priceContract.base_stamp,
      });
      return;
    }

    // Update the price cache
    state.quoteCache.setPrice(priceContract.base_price, priceContract.base_stamp);
    logger.debug('Cached price from webhook', {
      basePrice: priceContract.base_price,
      baseStamp: priceContract.base_stamp,
    });

    // Also cache the full quote if we have a commit_hash
    if (priceContract.commit_hash) {
      state.quoteCache.setQuote(priceContract.commit_hash, priceContract);
      logger.debug('Cached quote from webhook', {
        commitHash: priceContract.commit_hash,
      });
    }
  } catch (error) {
    logger.debug('Could not parse webhook content as price contract (ignoring)', {
      error: String(error),
    });
  }
}

/**
 * POST /check - Check threshold breach
 */
export async function handleCheck(req: Request, res: Response, state: AppState): Promise<void> {
  try {
    // Parse and validate request body
    const parseResult = checkRequestSchema.safeParse(req.body);
    if (!parseResult.success) {
      res.status(400).json({ error: 'Invalid domain or thold_hash' });
      return;
    }

    const { domain, thold_hash } = parseResult.data;

    // Check capacity
    if (state.pendingRequests.size >= state.config.maxPending) {
      res.status(503).json({ error: 'Server at capacity, please retry later' });
      return;
    }

    const trackingKey = domain;

    // Create promise for webhook result
    let resolveWebhook: (payload: WebhookPayload) => void;
    const webhookPromise = new Promise<WebhookPayload>((resolve) => {
      resolveWebhook = resolve;
    });

    // Register pending request
    const pending: PendingRequest = {
      requestId: trackingKey,
      createdAt: new Date(),
      resolve: resolveWebhook!,
      status: 'pending',
    };
    state.pendingRequests.set(trackingKey, pending);

    // Update pending requests gauge
    metrics.setPendingRequests(state.pendingRequests.size);

    logger.info('CHECK request initiated', { domain, tholdHash: thold_hash });

    // Trigger CRE workflow
    try {
      await triggerWorkflow(state, 'check', domain, undefined, thold_hash, state.config.callbackUrl);
      metrics.recordWorkflowTrigger('check', true);
    } catch (error) {
      logger.error('Failed to trigger workflow', { domain, error: String(error) });
      state.pendingRequests.delete(trackingKey);
      metrics.setPendingRequests(state.pendingRequests.size);
      metrics.recordWorkflowTrigger('check', false);
      // SECURITY: Don't expose internal error details to clients
      res.status(500).json({ error: 'Failed to trigger workflow' });
      return;
    }

    // Wait for webhook or timeout
    const timeoutPromise = new Promise<'timeout'>((resolve) =>
      setTimeout(() => resolve('timeout'), state.config.blockTimeoutMs)
    );

    const result = await Promise.race([webhookPromise, timeoutPromise]);

    if (result === 'timeout') {
      logger.warn('CHECK request timeout', { domain });

      const pendingReq = state.pendingRequests.get(trackingKey);
      if (pendingReq) {
        pendingReq.status = 'timeout';
      }

      metrics.recordRequestTimeout('check');

      const response: SyncResponse = {
        status: 'timeout',
        request_id: trackingKey,
        message: `Request is still processing. Use GET /status/${trackingKey} to check status.`,
      };
      res.status(202).json(response);
    } else {
      if (result.event_type === 'breach') {
        logger.info('BREACH detected - secret revealed', { domain });
      } else {
        logger.info('CHECK completed', { domain, status: result.event_type });
      }

      const pendingReq = state.pendingRequests.get(trackingKey);
      if (pendingReq) {
        pendingReq.status = 'completed';
        pendingReq.result = result;
      }

      // Using safe parser to prevent prototype pollution
      try {
        const contract: PriceContractResponse = safeJsonParse(result.content);
        res.json(contract);
      } catch {
        res.json({ raw: result.content });
      }
    }
  } catch (error) {
    logger.error('Error in handleCheck', { error: String(error) });
    res.status(500).json({ error: 'Internal server error' });
  }
}

/**
 * GET /status/:id - Check request status
 */
export function handleStatus(req: Request, res: Response, state: AppState): void {
  const requestId = req.params.id || req.params.requestId;

  if (!requestId) {
    res.status(400).json({ error: 'Missing request_id' });
    return;
  }

  const pending = state.pendingRequests.get(requestId);
  if (!pending) {
    res.status(404).json({ error: 'Request not found' });
    return;
  }

  if (pending.status === 'completed' && pending.result) {
    // Using safe parser to prevent prototype pollution
    try {
      const contract: PriceContractResponse = safeJsonParse(pending.result.content);
      res.json(contract);
      return;
    } catch {
      // Fall through to standard response
    }
  }

  const response: SyncResponse = {
    status: pending.status,
    request_id: requestId,
    result: pending.result,
    message: pending.status === 'pending' ? 'Request is still processing' : undefined,
  };

  res.json(response);
}

/**
 * GET /health - Liveness probe
 */
export function handleHealth(req: Request, res: Response, state: AppState): void {
  const uptime = Date.now() - state.startTime.getTime();

  metrics.recordHealthCheck('liveness', 'healthy');

  const response: HealthResponse = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: `${uptime}ms`,
  };

  res.json(response);
}

/**
 * GET /api/price - Return the latest cached price from oracle
 */
export function handlePrice(req: Request, res: Response, state: AppState): void {
  const cached = state.quoteCache.getPrice();

  if (!cached) {
    res.status(503).json({
      error: 'no price available',
      message: 'price data is stale or not yet received',
    });
    return;
  }

  res.json({
    USD: cached.basePrice,
    time: cached.baseStamp,
  });
}

/**
 * GET /readiness - Readiness probe
 */
export async function handleReadiness(req: Request, res: Response, state: AppState): Promise<void> {
  const dependencies: Record<string, DependencyHealth> = {};
  let overallStatus = 'healthy';

  // Check CRE gateway
  const creHealth = await checkCreGateway(state);
  if (creHealth.status !== 'up') {
    overallStatus = 'degraded';
  }
  dependencies['cre_gateway'] = creHealth;

  // Check capacity
  const currentPending = state.pendingRequests.size;
  const capacityPercent = (currentPending / state.config.maxPending) * 100;

  let capacityStatus: string;
  let capacityMessage: string;

  if (capacityPercent >= 100) {
    overallStatus = 'unhealthy';
    capacityStatus = 'down';
    capacityMessage = 'At capacity limit';
  } else if (capacityPercent >= 90) {
    overallStatus = 'degraded';
    capacityStatus = 'degraded';
    capacityMessage = 'Near capacity limit';
  } else {
    capacityStatus = 'up';
    capacityMessage = 'Capacity available';
  }

  dependencies['capacity'] = {
    status: capacityStatus,
    message: capacityMessage,
    last_checked: new Date().toISOString(),
  };

  // Authentication check
  dependencies['authentication'] = {
    status: 'up',
    message: 'Private key loaded',
    last_checked: new Date().toISOString(),
  };

  const uptime = Date.now() - state.startTime.getTime();

  const response: ReadinessResponse = {
    status: overallStatus,
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    uptime: `${uptime}ms`,
    dependencies,
    metrics: {
      pending_requests: currentPending,
      max_pending: state.config.maxPending,
      capacity_used_percent: capacityPercent,
    },
  };

  // Record health check and update dependency status metrics
  metrics.recordHealthCheck('readiness', overallStatus);

  // Update dependency status gauges (1.0 = up, 0.5 = degraded, 0.0 = down)
  for (const [name, health] of Object.entries(dependencies)) {
    let statusValue: number;
    switch (health.status) {
      case 'up':
        statusValue = 1.0;
        break;
      case 'degraded':
        statusValue = 0.5;
        break;
      default:
        statusValue = 0.0;
    }
    metrics.setDependencyStatus(name, statusValue);
  }

  const statusCode = overallStatus === 'unhealthy' ? 503 : 200;
  res.status(statusCode).json(response);
}

/**
 * GET /metrics - Prometheus metrics (deprecated - now using prom-client)
 */
export function handleMetrics(req: Request, res: Response, state: AppState): void {
  const pending = state.pendingRequests.size;
  const uptime = Math.floor((Date.now() - state.startTime.getTime()) / 1000);

  const metrics = `# HELP gateway_pending_requests Current number of pending requests
# TYPE gateway_pending_requests gauge
gateway_pending_requests ${pending}

# HELP gateway_uptime_seconds Server uptime in seconds
# TYPE gateway_uptime_seconds counter
gateway_uptime_seconds ${uptime}

# HELP gateway_max_pending Maximum pending requests allowed
# TYPE gateway_max_pending gauge
gateway_max_pending ${state.config.maxPending}
`;

  res.set('Content-Type', 'text/plain; charset=utf-8');
  res.send(metrics);
}

/**
 * Trigger CRE workflow
 */
async function triggerWorkflow(
  state: AppState,
  op: string,
  domain: string,
  tholdPrice?: number,
  tholdHash?: string,
  callbackUrl?: string
): Promise<void> {
  const input: Record<string, unknown> = {
    domain,
    callback_url: callbackUrl,
  };

  if (tholdPrice !== undefined) {
    input['thold_price'] = tholdPrice;
  }
  if (tholdHash !== undefined) {
    input['thold_hash'] = tholdHash;
  }

  // Create JSON-RPC request
  const reqId = Date.now().toString();
  const rpcRequest = {
    jsonrpc: '2.0',
    id: reqId,
    method: 'workflows.execute',
    params: {
      input,
      workflow: {
        workflowID: state.config.workflowId,
      },
    },
  };

  const rpcJson = JSON.stringify(rpcRequest);

  // Compute digest
  const digest = sha256Hex(rpcJson);

  // Generate JWT
  const jti = generateRequestId();
  const token = await generateJwt(
    state.config.privateKeyHex,
    state.config.authorizedKey,
    digest,
    jti
  );

  // Send request
  const response = await fetch(state.config.gatewayUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
    body: rpcJson,
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`non-success status ${response.status}: ${body}`);
  }
}

/**
 * Check CRE gateway health
 */
async function checkCreGateway(state: AppState): Promise<DependencyHealth> {
  const start = Date.now();

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(state.config.gatewayUrl, {
      method: 'HEAD',
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    const latency = Date.now() - start;
    const status = latency > 2000 ? 'degraded' : 'up';
    const message = latency > 2000 ? 'Slow response time' : 'Reachable';

    return {
      status,
      latency: `${latency}ms`,
      message,
      last_checked: new Date().toISOString(),
    };
  } catch (error) {
    logger.warn('CRE gateway health check failed', { error: String(error) });
    return {
      status: 'down',
      message: `Unreachable: ${error}`,
      last_checked: new Date().toISOString(),
    };
  }
}

/**
 * Start cleanup task for old requests
 */
export function startCleanupTask(state: AppState): void {
  setInterval(() => {
    const now = Date.now();
    const toDelete: string[] = [];

    for (const [key, pending] of state.pendingRequests) {
      const age = now - pending.createdAt.getTime();

      let shouldDelete = false;
      if (pending.status === 'completed' || pending.status === 'timeout') {
        shouldDelete = age > 5 * 60 * 1000; // 5 minutes
      } else if (pending.status === 'pending') {
        shouldDelete = age > state.config.blockTimeoutMs * 2;
      }

      if (shouldDelete) {
        toDelete.push(key);
      }
    }

    for (const key of toDelete) {
      state.pendingRequests.delete(key);
    }

    // Update metrics
    if (toDelete.length > 0) {
      metrics.recordRequestsCleanedUp(toDelete.length);
      metrics.setPendingRequests(state.pendingRequests.size);
      logger.info('Cleanup completed', {
        removed: toDelete.length,
        pending: state.pendingRequests.size,
      });
    }

    // Update uptime metric
    const uptime = Math.floor((Date.now() - state.startTime.getTime()) / 1000);
    metrics.setUptimeSeconds(uptime);
  }, state.config.cleanupIntervalMs);
}

/**
 * Start liquidation polling task
 */
export function startLiquidationPoller(state: AppState): void {
  if (!state.config.liquidationEnabled) {
    return;
  }

  logger.info('Starting liquidation service poller', {
    url: state.config.liquidationUrl,
    intervalMs: state.config.liquidationIntervalMs,
  });

  setInterval(async () => {
    try {
      const response = await fetch(state.config.liquidationUrl);
      if (response.ok) {
        const data = await response.json() as AtRiskResponse;
        if (data.total_count > 0) {
          logger.info('At-risk vaults detected', {
            count: data.total_count,
            currentPrice: data.current_price,
          });

          // Trigger batch evaluate for at-risk vaults (validate hex format)
          const tholdHashes = data.at_risk_vaults
            .filter(v => isValidHex(v.thold_hash, 40))
            .map(v => v.thold_hash);

          if (tholdHashes.length > 0) {
            await triggerBatchEvaluate(state, tholdHashes);
          }
        } else {
          logger.debug('No at-risk vaults', {
            currentPrice: data.current_price,
          });
        }
      }
    } catch (error) {
      logger.warn('Liquidation service unreachable', { error: String(error) });
    }
  }, state.config.liquidationIntervalMs);
}

// CRE has a 30KB maximum request size limit (including headers and body).
// Each thold_hash is ~45 bytes (40 hex chars + JSON overhead).
// With JSON-RPC wrapper overhead (~500 bytes), we can fit ~650 vaults max.
// Using 500 per batch for safety margin.
const CRE_BATCH_SIZE = 500;

// Delay between batches to avoid CRE rate limits (429 errors observed at 500ms)
const CRE_BATCH_DELAY_MS = 10000;

/**
 * Trigger batch evaluate workflow with batching to respect CRE 30KB limit
 */
async function triggerBatchEvaluate(state: AppState, tholdHashes: string[]): Promise<void> {
  if (tholdHashes.length === 0) {
    return;
  }

  const totalVaults = tholdHashes.length;
  const numBatches = Math.ceil(totalVaults / CRE_BATCH_SIZE);

  logger.info('Triggering CRE evaluate for at-risk vaults', {
    totalVaults,
    batchSize: CRE_BATCH_SIZE,
    numBatches,
  });

  let successCount = 0;
  let errorCount = 0;

  for (let i = 0; i < totalVaults; i += CRE_BATCH_SIZE) {
    const end = Math.min(i + CRE_BATCH_SIZE, totalVaults);
    const batch = tholdHashes.slice(i, end);
    const batchNum = Math.floor(i / CRE_BATCH_SIZE) + 1;

    // Generate a unique domain for this batch
    const domain = `liq-${Date.now()}-b${batchNum}`;

    try {
      await triggerSingleBatchEvaluate(state, domain, batch);
      logger.info('Triggered evaluate workflow batch', {
        batch: batchNum,
        batchSize: batch.length,
        totalBatches: numBatches,
        domain,
      });
      successCount++;
    } catch (error) {
      logger.error('Failed to trigger evaluate workflow batch', {
        batch: batchNum,
        batchSize: batch.length,
        totalBatches: numBatches,
        error: String(error),
      });
      errorCount++;
    }

    // Delay between batches to avoid CRE rate limits
    if (end < totalVaults) {
      await new Promise(resolve => setTimeout(resolve, CRE_BATCH_DELAY_MS));
    }
  }

  logger.info('Completed triggering evaluate workflow batches', {
    successfulBatches: successCount,
    failedBatches: errorCount,
    totalVaults,
  });
}

/**
 * Trigger a single batch evaluate workflow
 */
async function triggerSingleBatchEvaluate(
  state: AppState,
  domain: string,
  tholdHashes: string[]
): Promise<void> {
  const input = {
    domain,
    thold_hashes: tholdHashes,
    callback_url: state.config.callbackUrl,
  };

  const reqId = Date.now().toString();
  const rpcRequest = {
    jsonrpc: '2.0',
    id: reqId,
    method: 'workflows.execute',
    params: {
      input,
      workflow: {
        workflowID: state.config.workflowId,
      },
    },
  };

  const rpcJson = JSON.stringify(rpcRequest);
  const digest = sha256Hex(rpcJson);

  const jti = generateRequestId();
  const token = await generateJwt(
    state.config.privateKeyHex,
    state.config.authorizedKey,
    digest,
    jti
  );

  const response = await fetch(state.config.gatewayUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
    body: rpcJson,
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`non-success status ${response.status}: ${body}`);
  }
}

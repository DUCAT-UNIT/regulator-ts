import { Request, Response } from 'express';
import { GatewayConfig } from './config';
import { PendingRequest } from './types';
import { QuoteCache } from './cache';
import { NostrClient } from './nostr';
export interface AppState {
    config: GatewayConfig;
    pendingRequests: Map<string, PendingRequest>;
    startTime: Date;
    quoteCache: QuoteCache;
    nostrClient: NostrClient;
}
export declare function createAppState(config: GatewayConfig): AppState;
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
export declare function handleCreate(req: Request, res: Response, state: AppState): Promise<void>;
/**
 * POST /webhook/ducat - CRE callback endpoint
 */
export declare function handleWebhook(req: Request, res: Response, state: AppState): Promise<void>;
/**
 * POST /check - Check threshold breach
 */
export declare function handleCheck(req: Request, res: Response, state: AppState): Promise<void>;
/**
 * GET /status/:id - Check request status
 */
export declare function handleStatus(req: Request, res: Response, state: AppState): void;
/**
 * GET /health - Liveness probe
 */
export declare function handleHealth(req: Request, res: Response, state: AppState): void;
/**
 * GET /api/price - Return the latest cached price from oracle
 */
export declare function handlePrice(req: Request, res: Response, state: AppState): void;
/**
 * GET /readiness - Readiness probe
 */
export declare function handleReadiness(req: Request, res: Response, state: AppState): Promise<void>;
/**
 * GET /metrics - Prometheus metrics (deprecated - now using prom-client)
 */
export declare function handleMetrics(req: Request, res: Response, state: AppState): void;
/**
 * Start cleanup task for old requests
 */
export declare function startCleanupTask(state: AppState): void;
/**
 * Start liquidation polling task
 */
export declare function startLiquidationPoller(state: AppState): void;
//# sourceMappingURL=handlers.d.ts.map
import { z } from 'zod';
export type RequestStatus = 'pending' | 'completed' | 'timeout';
export interface PendingRequest {
    requestId: string;
    createdAt: Date;
    resolve?: (payload: WebhookPayload) => void;
    reject?: (error: Error) => void;
    status: RequestStatus;
    result?: WebhookPayload;
}
export declare const webhookPayloadSchema: any;
export type WebhookPayload = z.infer<typeof webhookPayloadSchema>;
export interface PriceContractResponse {
    chain_network: string;
    oracle_pubkey: string;
    base_price: number;
    base_stamp: number;
    commit_hash: string;
    contract_id: string;
    oracle_sig: string;
    thold_hash: string;
    thold_key: string | null;
    thold_price: number;
}
export interface PriceQuoteResponse {
    srv_network: string;
    srv_pubkey: string;
    quote_origin: string;
    quote_price: number;
    quote_stamp: number;
    latest_origin: string;
    latest_price: number;
    latest_stamp: number;
    event_origin: string | null;
    event_price: number | null;
    event_stamp: number | null;
    event_type: string;
    thold_hash: string;
    thold_key: string | null;
    thold_price: number;
    is_expired: boolean;
    req_id: string;
    req_sig: string;
}
export declare function toV25Quote(contract: PriceContractResponse): PriceQuoteResponse;
export interface QuoteResponse extends PriceQuoteResponse {
    collateral_ratio: number;
}
export declare const createRequestSchema: any;
export type CreateRequest = z.infer<typeof createRequestSchema>;
export declare const checkRequestSchema: any;
export type CheckRequest = z.infer<typeof checkRequestSchema>;
export interface SyncResponse {
    status: string;
    request_id: string;
    data?: unknown;
    result?: WebhookPayload;
    message?: string;
}
export interface HealthResponse {
    status: string;
    timestamp: string;
    uptime: string;
}
export interface ReadinessResponse {
    status: string;
    timestamp: string;
    version: string;
    uptime: string;
    dependencies: Record<string, DependencyHealth>;
    metrics: HealthMetrics;
}
export interface DependencyHealth {
    status: string;
    latency?: string;
    message?: string;
    last_checked: string;
}
export interface HealthMetrics {
    pending_requests: number;
    max_pending: number;
    capacity_used_percent: number;
}
export interface AtRiskVault {
    vault_id: string;
    thold_hash: string;
    thold_price: number;
    current_ratio: number;
    collateral_btc: number;
    debt_dusd: number;
}
export interface AtRiskResponse {
    at_risk_vaults: AtRiskVault[];
    total_count: number;
    current_price: number;
    threshold: number;
    timestamp: number;
}
export interface JwtHeader {
    alg: string;
    typ: string;
}
export interface JwtPayload {
    digest: string;
    iss: string;
    iat: number;
    exp: number;
    jti: string;
}
//# sourceMappingURL=types.d.ts.map
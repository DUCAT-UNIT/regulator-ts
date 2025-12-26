import { z } from 'zod';

// Request status enum
export type RequestStatus = 'pending' | 'completed' | 'timeout';

// Pending request tracking
export interface PendingRequest {
  requestId: string;
  createdAt: Date;
  resolve?: (payload: WebhookPayload) => void;
  reject?: (error: Error) => void;
  status: RequestStatus;
  result?: WebhookPayload;
}

// SECURITY: Tag array limits to prevent memory exhaustion DoS
const MAX_TAGS = 100;
const MAX_TAG_ELEMENTS = 10;
const MAX_TAG_ELEMENT_LEN = 1024;

// Tag element schema with length limit
const tagElementSchema = z.string().max(MAX_TAG_ELEMENT_LEN);

// Tag array schema with element count limit
const tagSchema = z.array(tagElementSchema).max(MAX_TAG_ELEMENTS);

// Webhook payload from CRE
export const webhookPayloadSchema = z.object({
  event_type: z.string(),
  event_id: z.string(),
  pubkey: z.string(),
  created_at: z.number(),
  kind: z.number(),
  tags: z.array(tagSchema).max(MAX_TAGS),
  content: z.string(),
  sig: z.string(),
  nostr_event: z.any().optional(),
});

export type WebhookPayload = z.infer<typeof webhookPayloadSchema>;

// Price contract response - internal CRE format
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

// v2.5 Price quote response matching client-sdk main branch schema
// NOTE: Prices are number (float64) to match cre-hmac which uses float64 for HMAC computation
export interface PriceQuoteResponse {
  quote_price: number;
  quote_stamp: number;
  oracle_pk: string;
  req_id: string;
  req_sig: string;
  thold_hash: string;
  thold_price: number;
  is_expired: boolean;
  eval_price: number | null;
  eval_stamp: number | null;
  thold_key: string | null;
}

// Convert internal format to v2.5 client-sdk format
export function toV25Quote(contract: PriceContractResponse): PriceQuoteResponse {
  const isExpired = contract.thold_key !== null;
  return {
    quote_price: contract.base_price,
    quote_stamp: contract.base_stamp,
    oracle_pk: contract.oracle_pubkey,
    req_id: contract.commit_hash,
    req_sig: contract.oracle_sig,
    thold_hash: contract.thold_hash,
    thold_price: contract.thold_price,
    is_expired: isExpired,
    eval_price: isExpired ? contract.base_price : null,
    eval_stamp: isExpired ? contract.base_stamp : null,
    thold_key: contract.thold_key,
  };
}

// Quote response with collateral ratio for frontend - v2.5 format
export interface QuoteResponse extends PriceQuoteResponse {
  collateral_ratio: number; // Collateral ratio as percentage (e.g., 135.0 for 135%)
}

// Create quote request (query params)
export const createRequestSchema = z.object({
  th: z.coerce.number().positive('threshold price must be positive'),
  domain: z.string().optional(),
});

export type CreateRequest = z.infer<typeof createRequestSchema>;

// Check request body
// Max domain length per DNS spec limit
const MAX_DOMAIN_LENGTH = 253;

export const checkRequestSchema = z.object({
  domain: z.string().min(1).max(MAX_DOMAIN_LENGTH, 'domain too long'),
  thold_hash: z.string().length(40).regex(/^[0-9a-fA-F]+$/, 'thold_hash must be hex'),
});

export type CheckRequest = z.infer<typeof checkRequestSchema>;

// Sync response for timeout/pending states
export interface SyncResponse {
  status: string;
  request_id: string;
  data?: unknown;
  result?: WebhookPayload;
  message?: string;
}

// Health check response
export interface HealthResponse {
  status: string;
  timestamp: string;
  uptime: string;
}

// Readiness response with dependency status
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

// At-risk vault from liquidation service
export interface AtRiskVault {
  vault_id: string;
  thold_hash: string;
  thold_price: number;
  current_ratio: number;
  collateral_btc: number;
  debt_dusd: number;
}

// Response from liquidation service
export interface AtRiskResponse {
  at_risk_vaults: AtRiskVault[];
  total_count: number;
  current_price: number;
  threshold: number;
  timestamp: number;
}

// JWT header
export interface JwtHeader {
  alg: string;
  typ: string;
}

// JWT payload
export interface JwtPayload {
  digest: string;
  iss: string;
  iat: number;
  exp: number;
  jti: string;
}

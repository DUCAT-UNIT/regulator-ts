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
  // Server identity
  srv_network: string;   // "main" | "test"
  srv_pubkey: string;    // Oracle public key (hex)

  // Quote price (at commitment creation)
  quote_origin: string;  // "link" | "nostr" | "cre"
  quote_price: number;   // BTC/USD price
  quote_stamp: number;   // Unix timestamp

  // Latest price (most recent observation)
  latest_origin: string;
  latest_price: number;
  latest_stamp: number;

  // Event price (at breach, if any)
  event_origin: string | null;
  event_price: number | null;
  event_stamp: number | null;
  event_type: string;    // "active" | "breach"

  // Threshold commitment
  thold_hash: string;
  thold_key: string | null;
  thold_price: number;

  // State & signatures
  is_expired: boolean;
  req_id: string;
  req_sig: string;
}

// Convert internal format to v2.5 client-sdk format
export function toV25Quote(contract: PriceContractResponse): PriceQuoteResponse {
  const isExpired = contract.thold_key !== null;
  const origin = 'cre';
  return {
    // Server identity
    srv_network: contract.chain_network,
    srv_pubkey: contract.oracle_pubkey,
    // Quote price
    quote_origin: origin,
    quote_price: contract.base_price,
    quote_stamp: contract.base_stamp,
    // Latest price (same as quote for CRE responses)
    latest_origin: origin,
    latest_price: contract.base_price,
    latest_stamp: contract.base_stamp,
    // Event price
    event_origin: isExpired ? origin : null,
    event_price: isExpired ? contract.base_price : null,
    event_stamp: isExpired ? contract.base_stamp : null,
    event_type: isExpired ? 'breach' : 'active',
    // Threshold commitment
    thold_hash: contract.thold_hash,
    thold_key: contract.thold_key,
    thold_price: contract.thold_price,
    // State & signatures
    is_expired: isExpired,
    req_id: contract.commit_hash,
    req_sig: contract.oracle_sig,
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

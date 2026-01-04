"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.checkRequestSchema = exports.createRequestSchema = exports.webhookPayloadSchema = void 0;
exports.toV25Quote = toV25Quote;
const zod_1 = require("zod");
// SECURITY: Tag array limits to prevent memory exhaustion DoS
const MAX_TAGS = 100;
const MAX_TAG_ELEMENTS = 10;
const MAX_TAG_ELEMENT_LEN = 1024;
// Tag element schema with length limit
const tagElementSchema = zod_1.z.string().max(MAX_TAG_ELEMENT_LEN);
// Tag array schema with element count limit
const tagSchema = zod_1.z.array(tagElementSchema).max(MAX_TAG_ELEMENTS);
// Webhook payload from CRE
exports.webhookPayloadSchema = zod_1.z.object({
    event_type: zod_1.z.string(),
    event_id: zod_1.z.string(),
    pubkey: zod_1.z.string(),
    created_at: zod_1.z.number(),
    kind: zod_1.z.number(),
    tags: zod_1.z.array(tagSchema).max(MAX_TAGS),
    content: zod_1.z.string(),
    sig: zod_1.z.string(),
    nostr_event: zod_1.z.any().optional(),
});
// Convert internal format to v2.5 client-sdk format
function toV25Quote(contract) {
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
// Create quote request (query params)
exports.createRequestSchema = zod_1.z.object({
    th: zod_1.z.coerce.number().positive('threshold price must be positive'),
    domain: zod_1.z.string().optional(),
});
// Check request body
// Max domain length per DNS spec limit
const MAX_DOMAIN_LENGTH = 253;
exports.checkRequestSchema = zod_1.z.object({
    domain: zod_1.z.string().min(1).max(MAX_DOMAIN_LENGTH, 'domain too long'),
    thold_hash: zod_1.z.string().length(40).regex(/^[0-9a-fA-F]+$/, 'thold_hash must be hex'),
});
//# sourceMappingURL=types.js.map
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.loadConfig = loadConfig;
const zod_1 = require("zod");
const configSchema = zod_1.z.object({
    workflowId: zod_1.z.string().min(1),
    gatewayUrl: zod_1.z.string().url(),
    authorizedKey: zod_1.z.string().min(1),
    callbackUrl: zod_1.z.string().url(),
    privateKeyHex: zod_1.z.string().length(64),
    blockTimeoutMs: zod_1.z.number().positive(),
    cleanupIntervalMs: zod_1.z.number().positive(),
    maxPending: zod_1.z.number().positive(),
    ipRateLimit: zod_1.z.number().positive(),
    ipBurstLimit: zod_1.z.number().positive(),
    expectedWebhookPubkey: zod_1.z.string().length(64),
    liquidationUrl: zod_1.z.string(),
    liquidationIntervalMs: zod_1.z.number().positive(),
    liquidationEnabled: zod_1.z.boolean(),
    port: zod_1.z.number().positive(),
    // Nostr relay configuration for quote lookup
    nostrRelayUrl: zod_1.z.string(),
    oraclePubkey: zod_1.z.string().length(64),
    chainNetwork: zod_1.z.string().min(1),
});
function loadConfig() {
    const workflowId = process.env.CRE_WORKFLOW_ID;
    if (!workflowId) {
        throw new Error('CRE_WORKFLOW_ID environment variable not set');
    }
    const gatewayUrl = process.env.CRE_GATEWAY_URL || 'https://01.gateway.zone-a.cre.chain.link';
    const authorizedKey = process.env.DUCAT_AUTHORIZED_KEY;
    if (!authorizedKey) {
        throw new Error('DUCAT_AUTHORIZED_KEY environment variable not set');
    }
    const callbackUrl = process.env.GATEWAY_CALLBACK_URL;
    if (!callbackUrl) {
        throw new Error('GATEWAY_CALLBACK_URL environment variable not set');
    }
    let privateKeyHex = process.env.DUCAT_PRIVATE_KEY;
    if (!privateKeyHex) {
        throw new Error('DUCAT_PRIVATE_KEY environment variable not set');
    }
    privateKeyHex = privateKeyHex.replace(/^0x/, '');
    if (privateKeyHex.length !== 64) {
        throw new Error(`Private key must be 64 hex chars, got ${privateKeyHex.length}`);
    }
    const blockTimeoutMs = parseInt(process.env.BLOCK_TIMEOUT_SECONDS || '60', 10) * 1000;
    const cleanupIntervalMs = parseInt(process.env.CLEANUP_INTERVAL_SECONDS || '120', 10) * 1000;
    const maxPending = parseInt(process.env.MAX_PENDING_REQUESTS || '1000', 10);
    const ipRateLimit = parseFloat(process.env.IP_RATE_LIMIT || '10');
    const ipBurstLimit = parseInt(process.env.IP_BURST_LIMIT || '20', 10);
    let expectedWebhookPubkey = process.env.CRE_WEBHOOK_PUBKEY;
    if (!expectedWebhookPubkey) {
        if (process.env.NODE_ENV === 'test') {
            // Test mode fallback - matches Go test key
            expectedWebhookPubkey = '6a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb3';
        }
        else {
            throw new Error('CRE_WEBHOOK_PUBKEY environment variable not set (required in production)');
        }
    }
    const liquidationUrl = process.env.LIQUIDATION_SERVICE_URL ||
        'http://localhost:4001/liq/api/at-risk';
    const liquidationIntervalMs = parseInt(process.env.LIQUIDATION_INTERVAL_SECONDS || '90', 10) * 1000;
    const liquidationEnabled = process.env.LIQUIDATION_ENABLED !== 'false' &&
        process.env.LIQUIDATION_ENABLED !== '0';
    const port = parseInt(process.env.PORT || '8080', 10);
    // Nostr relay configuration
    const nostrRelayUrl = process.env.NOSTR_RELAY_URL || 'https://relay.ducat.dev';
    let oraclePubkey = process.env.ORACLE_PUBKEY;
    if (!oraclePubkey) {
        // Use test default for development
        oraclePubkey = '0000000000000000000000000000000000000000000000000000000000000000';
        if (process.env.NODE_ENV !== 'test') {
            console.warn('ORACLE_PUBKEY not set - using test default');
        }
    }
    const chainNetwork = process.env.CHAIN_NETWORK || 'mutiny';
    const config = {
        workflowId,
        gatewayUrl,
        authorizedKey,
        callbackUrl,
        privateKeyHex,
        blockTimeoutMs,
        cleanupIntervalMs,
        maxPending,
        ipRateLimit,
        ipBurstLimit,
        expectedWebhookPubkey,
        liquidationUrl,
        liquidationIntervalMs,
        liquidationEnabled,
        port,
        nostrRelayUrl,
        oraclePubkey,
        chainNetwork,
    };
    return configSchema.parse(config);
}
//# sourceMappingURL=config.js.map
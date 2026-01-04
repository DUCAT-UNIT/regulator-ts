"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.NostrClient = void 0;
exports.calculateCommitHash = calculateCommitHash;
exports.calculateCollateralRatio = calculateCollateralRatio;
const crypto_1 = require("crypto");
const logger_1 = __importDefault(require("./logger"));
/** Nostr client for fetching quotes from relay */
class NostrClient {
    relayUrl;
    oraclePubkey;
    constructor(relayUrl, oraclePubkey) {
        this.relayUrl = relayUrl;
        this.oraclePubkey = oraclePubkey;
    }
    /**
     * Fetch quote from Nostr relay by d-tag (commit_hash)
     * Uses NIP-33 addressable events (kind:30078)
     */
    async fetchQuoteByDTag(dtag) {
        const url = `${this.relayUrl}/nostr/addressable?pubkey=${encodeURIComponent(this.oraclePubkey)}&kind=30078&d=${encodeURIComponent(dtag)}`;
        logger_1.default.debug('Fetching quote from Nostr', { url, dtag });
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 10000);
            const response = await fetch(url, { signal: controller.signal });
            clearTimeout(timeoutId);
            if (response.status === 404) {
                return null; // Quote not found
            }
            if (!response.ok) {
                const body = await response.text();
                throw new Error(`Relay returned status ${response.status}: ${body}`);
            }
            const data = await response.json();
            // Try to parse as single event or array
            let event;
            if (Array.isArray(data)) {
                if (data.length === 0) {
                    return null;
                }
                event = data[0];
            }
            else {
                event = data;
            }
            // Parse content as PriceContractResponse
            const quote = JSON.parse(event.content);
            logger_1.default.debug('Quote fetched from Nostr', { dtag, commitHash: quote.commit_hash });
            return quote;
        }
        catch (error) {
            if (error.name === 'AbortError') {
                logger_1.default.warn('Nostr relay request timed out', { dtag });
            }
            else {
                logger_1.default.warn('Failed to fetch quote from Nostr', { dtag, error: String(error) });
            }
            throw error;
        }
    }
}
exports.NostrClient = NostrClient;
/**
 * Calculate commit_hash using BIP-340 tagged hash
 * commit_hash = hash340("DUCAT/commit", oracle_pubkey || chain_network || base_price || base_stamp || thold_price)
 */
function calculateCommitHash(oraclePubkey, chainNetwork, basePrice, baseStamp, tholdPrice) {
    // Validate oracle pubkey
    if (!/^[0-9a-fA-F]{64}$/.test(oraclePubkey)) {
        throw new Error('Invalid oracle pubkey: must be 64 hex characters');
    }
    const pubkeyBytes = Buffer.from(oraclePubkey, 'hex');
    if (pubkeyBytes.length !== 32) {
        throw new Error('Oracle pubkey must be 32 bytes');
    }
    // BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg)
    const tag = 'DUCAT/commit';
    const tagHash = (0, crypto_1.createHash)('sha256').update(tag).digest();
    // Build message: pubkey || network || base_price || base_stamp || thold_price
    const networkBytes = Buffer.from(chainNetwork, 'utf8');
    const basePriceBytes = Buffer.alloc(4);
    basePriceBytes.writeUInt32BE(basePrice >>> 0);
    const baseStampBytes = Buffer.alloc(4);
    baseStampBytes.writeUInt32BE(baseStamp >>> 0);
    const tholdPriceBytes = Buffer.alloc(4);
    tholdPriceBytes.writeUInt32BE(tholdPrice >>> 0);
    const msg = Buffer.concat([
        pubkeyBytes,
        networkBytes,
        basePriceBytes,
        baseStampBytes,
        tholdPriceBytes,
    ]);
    // Compute tagged hash
    const hash = (0, crypto_1.createHash)('sha256')
        .update(tagHash)
        .update(tagHash)
        .update(msg)
        .digest();
    return hash.toString('hex');
}
/**
 * Calculate collateral ratio as percentage
 * ratio = (thold_price / base_price) * 100
 */
function calculateCollateralRatio(basePrice, tholdPrice) {
    if (basePrice === 0) {
        return 0;
    }
    return (tholdPrice / basePrice) * 100;
}
//# sourceMappingURL=nostr.js.map
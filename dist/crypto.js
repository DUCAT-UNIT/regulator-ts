"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateRequestId = generateRequestId;
exports.signEthereumMessage = signEthereumMessage;
exports.privateKeyToAddress = privateKeyToAddress;
exports.generateJwt = generateJwt;
exports.verifyWebhookSignature = verifyWebhookSignature;
exports.sha256Hex = sha256Hex;
exports.getTag = getTag;
exports.truncateEventId = truncateEventId;
const sha256_1 = require("@noble/hashes/sha256");
const sha3_1 = require("@noble/hashes/sha3");
const secp256k1_1 = require("@noble/curves/secp256k1");
const secp256k1_2 = require("@noble/curves/secp256k1");
const utils_1 = require("@noble/hashes/utils");
/**
 * Generate a cryptographically random 32-character hex request ID
 */
function generateRequestId() {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return (0, utils_1.bytesToHex)(bytes);
}
/**
 * Sign a message using Ethereum's prefixed message format
 * Returns a 65-byte signature in the form r||s||v
 */
async function signEthereumMessage(privateKeyHex, message) {
    const privateKeyBytes = (0, utils_1.hexToBytes)(privateKeyHex);
    // Create Ethereum signed message prefix
    // IMPORTANT: Use byte length, not character count (they differ for Unicode)
    const messageBytes = new TextEncoder().encode(message);
    const prefix = `\x19Ethereum Signed Message:\n${messageBytes.length}`;
    const prefixBytes = new TextEncoder().encode(prefix);
    // Concatenate prefix and message bytes
    const fullMessage = new Uint8Array(prefixBytes.length + messageBytes.length);
    fullMessage.set(prefixBytes, 0);
    fullMessage.set(messageBytes, prefixBytes.length);
    // Hash with Keccak256
    const messageHash = (0, sha3_1.keccak_256)(fullMessage);
    // Sign the message (returns recovery id in the signature)
    const signature = secp256k1_1.secp256k1.sign(messageHash, privateKeyBytes, { lowS: true });
    // Get r and s as bytes
    const rBytes = signature.r.toString(16).padStart(64, '0');
    const sBytes = signature.s.toString(16).padStart(64, '0');
    // Calculate recovery ID
    const recoveryBit = signature.recovery;
    // Format: r || s || v (Ethereum format: v = recovery_id + 27)
    const result = new Uint8Array(65);
    result.set((0, utils_1.hexToBytes)(rBytes), 0);
    result.set((0, utils_1.hexToBytes)(sBytes), 32);
    result[64] = recoveryBit + 27;
    return result;
}
/**
 * Derive Ethereum address from private key
 */
function privateKeyToAddress(privateKeyHex) {
    const privateKeyBytes = (0, utils_1.hexToBytes)(privateKeyHex);
    const publicKey = secp256k1_1.secp256k1.getPublicKey(privateKeyBytes, false); // Uncompressed (65 bytes)
    // Remove 0x04 prefix and hash with Keccak256
    const publicKeyNoPrefix = publicKey.slice(1);
    const hash = (0, sha3_1.keccak_256)(publicKeyNoPrefix);
    // Take last 20 bytes for address
    return '0x' + (0, utils_1.bytesToHex)(hash.slice(12));
}
/**
 * Base64URL encode without padding
 */
function base64UrlEncode(data) {
    const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    const base64 = Buffer.from(bytes).toString('base64');
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
/**
 * Generate a JWT token for CRE gateway authentication
 */
async function generateJwt(privateKeyHex, address, digest, jti) {
    const now = Math.floor(Date.now() / 1000);
    // Create header
    const header = {
        alg: 'ETH',
        typ: 'JWT',
    };
    const headerB64 = base64UrlEncode(JSON.stringify(header));
    // Create payload
    const payload = {
        digest,
        iss: address,
        iat: now,
        exp: now + 300, // 5 minutes
        jti,
    };
    const payloadB64 = base64UrlEncode(JSON.stringify(payload));
    // Create message to sign
    const message = `${headerB64}.${payloadB64}`;
    // Sign with Ethereum prefix
    const signature = await signEthereumMessage(privateKeyHex, message);
    const signatureB64 = base64UrlEncode(signature);
    return `${message}.${signatureB64}`;
}
/**
 * Verify webhook signature (BIP-340 Schnorr)
 */
function verifyWebhookSignature(payload) {
    // Validate required fields
    if (!payload.event_id) {
        throw new Error('missing event_id');
    }
    if (!payload.pubkey) {
        throw new Error('missing pubkey');
    }
    if (!payload.sig) {
        throw new Error('missing signature');
    }
    // Validate field lengths
    if (payload.event_id.length !== 64) {
        throw new Error(`invalid event_id length: expected 64 hex chars, got ${payload.event_id.length}`);
    }
    if (payload.pubkey.length !== 64) {
        throw new Error(`invalid pubkey length: expected 64 hex chars, got ${payload.pubkey.length}`);
    }
    if (payload.sig.length !== 128) {
        throw new Error(`invalid signature length: expected 128 hex chars, got ${payload.sig.length}`);
    }
    // Recompute event ID to verify integrity
    // NIP-01 format: [0, <pubkey>, <created_at>, <kind>, <tags>, <content>]
    const serialized = JSON.stringify([
        0,
        payload.pubkey,
        payload.created_at,
        payload.kind,
        payload.tags,
        payload.content,
    ]);
    const computedHash = (0, sha256_1.sha256)(new TextEncoder().encode(serialized));
    const computedId = (0, utils_1.bytesToHex)(computedHash);
    if (computedId !== payload.event_id) {
        throw new Error(`event_id mismatch: computed ${computedId}, got ${payload.event_id}`);
    }
    // Verify Schnorr signature
    const sigBytes = (0, utils_1.hexToBytes)(payload.sig);
    const pubkeyBytes = (0, utils_1.hexToBytes)(payload.pubkey);
    const eventIdBytes = (0, utils_1.hexToBytes)(payload.event_id);
    // SECURITY: Reject all-zero signatures to prevent potential bypass attacks
    if (sigBytes.every(b => b === 0)) {
        throw new Error('invalid signature: all-zero signature rejected');
    }
    // SECURITY: Reject all-zero pubkeys to prevent point-at-infinity attacks
    if (pubkeyBytes.every(b => b === 0)) {
        throw new Error('invalid pubkey: all-zero pubkey rejected');
    }
    const isValid = secp256k1_2.schnorr.verify(sigBytes, eventIdBytes, pubkeyBytes);
    if (!isValid) {
        throw new Error('schnorr signature verification failed');
    }
}
/**
 * Compute SHA256 hash and return as hex string prefixed with 0x
 */
function sha256Hex(data) {
    const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    const hash = (0, sha256_1.sha256)(bytes);
    return '0x' + (0, utils_1.bytesToHex)(hash);
}
/**
 * Extract domain tag from webhook tags
 */
function getTag(tags, key) {
    const tag = tags.find(t => t.length >= 2 && t[0] === key);
    return tag?.[1];
}
/**
 * Truncate event ID for logging (prevents log injection)
 */
function truncateEventId(eventId) {
    if (eventId.length <= 16) {
        return eventId;
    }
    return eventId.slice(0, 16);
}
//# sourceMappingURL=crypto.js.map
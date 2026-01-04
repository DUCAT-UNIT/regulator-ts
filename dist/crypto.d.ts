import type { WebhookPayload } from './types';
/**
 * Generate a cryptographically random 32-character hex request ID
 */
export declare function generateRequestId(): string;
/**
 * Sign a message using Ethereum's prefixed message format
 * Returns a 65-byte signature in the form r||s||v
 */
export declare function signEthereumMessage(privateKeyHex: string, message: string): Promise<Uint8Array>;
/**
 * Derive Ethereum address from private key
 */
export declare function privateKeyToAddress(privateKeyHex: string): string;
/**
 * Generate a JWT token for CRE gateway authentication
 */
export declare function generateJwt(privateKeyHex: string, address: string, digest: string, jti: string): Promise<string>;
/**
 * Verify webhook signature (BIP-340 Schnorr)
 */
export declare function verifyWebhookSignature(payload: WebhookPayload): void;
/**
 * Compute SHA256 hash and return as hex string prefixed with 0x
 */
export declare function sha256Hex(data: Uint8Array | string): string;
/**
 * Extract domain tag from webhook tags
 */
export declare function getTag(tags: string[][], key: string): string | undefined;
/**
 * Truncate event ID for logging (prevents log injection)
 */
export declare function truncateEventId(eventId: string): string;
//# sourceMappingURL=crypto.d.ts.map
import { sha256 } from '@noble/hashes/sha256';
import { keccak_256 } from '@noble/hashes/sha3';
import { secp256k1 } from '@noble/curves/secp256k1';
import { schnorr } from '@noble/curves/secp256k1';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import type { WebhookPayload, JwtHeader, JwtPayload } from './types';

/**
 * Generate a cryptographically random 32-character hex request ID
 */
export function generateRequestId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

/**
 * Sign a message using Ethereum's prefixed message format
 * Returns a 65-byte signature in the form r||s||v
 */
export async function signEthereumMessage(privateKeyHex: string, message: string): Promise<Uint8Array> {
  const privateKeyBytes = hexToBytes(privateKeyHex);

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
  const messageHash = keccak_256(fullMessage);

  // Sign the message (returns recovery id in the signature)
  const signature = secp256k1.sign(messageHash, privateKeyBytes, { lowS: true });

  // Get r and s as bytes
  const rBytes = signature.r.toString(16).padStart(64, '0');
  const sBytes = signature.s.toString(16).padStart(64, '0');

  // Calculate recovery ID
  const recoveryBit = signature.recovery;

  // Format: r || s || v (Ethereum format: v = recovery_id + 27)
  const result = new Uint8Array(65);
  result.set(hexToBytes(rBytes), 0);
  result.set(hexToBytes(sBytes), 32);
  result[64] = recoveryBit + 27;

  return result;
}

/**
 * Derive Ethereum address from private key
 */
export function privateKeyToAddress(privateKeyHex: string): string {
  const privateKeyBytes = hexToBytes(privateKeyHex);
  const publicKey = secp256k1.getPublicKey(privateKeyBytes, false); // Uncompressed (65 bytes)

  // Remove 0x04 prefix and hash with Keccak256
  const publicKeyNoPrefix = publicKey.slice(1);
  const hash = keccak_256(publicKeyNoPrefix);

  // Take last 20 bytes for address
  return '0x' + bytesToHex(hash.slice(12));
}

/**
 * Base64URL encode without padding
 */
function base64UrlEncode(data: Uint8Array | string): string {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const base64 = Buffer.from(bytes).toString('base64');
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Generate a JWT token for CRE gateway authentication
 */
export async function generateJwt(
  privateKeyHex: string,
  address: string,
  digest: string,
  jti: string
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);

  // Create header
  const header: JwtHeader = {
    alg: 'ETH',
    typ: 'JWT',
  };
  const headerB64 = base64UrlEncode(JSON.stringify(header));

  // Create payload
  const payload: JwtPayload = {
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
export function verifyWebhookSignature(payload: WebhookPayload): void {
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

  const computedHash = sha256(new TextEncoder().encode(serialized));
  const computedId = bytesToHex(computedHash);

  if (computedId !== payload.event_id) {
    throw new Error(`event_id mismatch: computed ${computedId}, got ${payload.event_id}`);
  }

  // Verify Schnorr signature
  const sigBytes = hexToBytes(payload.sig);
  const pubkeyBytes = hexToBytes(payload.pubkey);
  const eventIdBytes = hexToBytes(payload.event_id);

  // SECURITY: Reject all-zero signatures to prevent potential bypass attacks
  if (sigBytes.every(b => b === 0)) {
    throw new Error('invalid signature: all-zero signature rejected');
  }

  // SECURITY: Reject all-zero pubkeys to prevent point-at-infinity attacks
  if (pubkeyBytes.every(b => b === 0)) {
    throw new Error('invalid pubkey: all-zero pubkey rejected');
  }

  const isValid = schnorr.verify(sigBytes, eventIdBytes, pubkeyBytes);
  if (!isValid) {
    throw new Error('schnorr signature verification failed');
  }
}

/**
 * Compute SHA256 hash and return as hex string prefixed with 0x
 */
export function sha256Hex(data: Uint8Array | string): string {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const hash = sha256(bytes);
  return '0x' + bytesToHex(hash);
}

/**
 * Extract domain tag from webhook tags
 */
export function getTag(tags: string[][], key: string): string | undefined {
  const tag = tags.find(t => t.length >= 2 && t[0] === key);
  return tag?.[1];
}

/**
 * Truncate event ID for logging (prevents log injection)
 */
export function truncateEventId(eventId: string): string {
  if (eventId.length <= 16) {
    return eventId;
  }
  return eventId.slice(0, 16);
}

"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = require("../crypto");
const sha256_1 = require("@noble/hashes/sha256");
const secp256k1_1 = require("@noble/curves/secp256k1");
const utils_1 = require("@noble/hashes/utils");
// Helper to compute valid Nostr event_id
function computeEventId(pubkey, created_at, kind, tags, content) {
    const serialized = JSON.stringify([0, pubkey, created_at, kind, tags, content]);
    const hash = (0, sha256_1.sha256)(new TextEncoder().encode(serialized));
    return (0, utils_1.bytesToHex)(hash);
}
describe('generateRequestId', () => {
    it('should generate a 32-character hex string', () => {
        const id = (0, crypto_1.generateRequestId)();
        expect(id).toHaveLength(32);
        expect(/^[0-9a-f]+$/.test(id)).toBe(true);
    });
    it('should generate unique IDs', () => {
        const id1 = (0, crypto_1.generateRequestId)();
        const id2 = (0, crypto_1.generateRequestId)();
        expect(id1).not.toBe(id2);
    });
});
describe('sha256Hex', () => {
    it('should return a 0x-prefixed 64-char hex hash for string input', () => {
        const hash = (0, crypto_1.sha256Hex)('test message');
        expect(hash).toMatch(/^0x[0-9a-f]{64}$/);
    });
    it('should return a 0x-prefixed 64-char hex hash for Uint8Array input', () => {
        const bytes = new Uint8Array([116, 101, 115, 116]); // 'test' in bytes
        const hash = (0, crypto_1.sha256Hex)(bytes);
        expect(hash).toMatch(/^0x[0-9a-f]{64}$/);
    });
    it('should produce consistent hashes', () => {
        const hash1 = (0, crypto_1.sha256Hex)('hello world');
        const hash2 = (0, crypto_1.sha256Hex)('hello world');
        expect(hash1).toBe(hash2);
    });
    it('should produce same hash for string and equivalent Uint8Array', () => {
        const hashStr = (0, crypto_1.sha256Hex)('test');
        const hashBytes = (0, crypto_1.sha256Hex)(new Uint8Array([116, 101, 115, 116]));
        expect(hashStr).toBe(hashBytes);
    });
    it('should produce different hashes for different inputs', () => {
        const hash1 = (0, crypto_1.sha256Hex)('message1');
        const hash2 = (0, crypto_1.sha256Hex)('message2');
        expect(hash1).not.toBe(hash2);
    });
});
describe('truncateEventId', () => {
    it('should truncate to 16 chars for long IDs', () => {
        const eventId = 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890';
        expect((0, crypto_1.truncateEventId)(eventId)).toBe('abcdef1234567890');
    });
    it('should not truncate short IDs', () => {
        const shortId = 'abcd1234';
        expect((0, crypto_1.truncateEventId)(shortId)).toBe('abcd1234');
    });
    it('should handle exactly 16 char IDs', () => {
        const id = '1234567890123456';
        expect((0, crypto_1.truncateEventId)(id)).toBe('1234567890123456');
    });
});
describe('getTag', () => {
    it('should return tag value when found', () => {
        const tags = [
            ['domain', 'test-domain'],
            ['type', 'create'],
        ];
        expect((0, crypto_1.getTag)(tags, 'domain')).toBe('test-domain');
        expect((0, crypto_1.getTag)(tags, 'type')).toBe('create');
    });
    it('should return undefined when tag not found', () => {
        const tags = [['domain', 'test']];
        expect((0, crypto_1.getTag)(tags, 'nonexistent')).toBeUndefined();
    });
    it('should return undefined for empty tags', () => {
        expect((0, crypto_1.getTag)([], 'domain')).toBeUndefined();
    });
    it('should return undefined for incomplete tags', () => {
        const tags = [['domain']]; // Only key, no value
        expect((0, crypto_1.getTag)(tags, 'domain')).toBeUndefined();
    });
});
describe('generateJwt', () => {
    const testPrivateKey = 'e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c';
    const testAddress = '0xtest123';
    const testDigest = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
    const testJti = 'test-jti-12345678';
    it('should generate a valid JWT with 3 parts', async () => {
        const jwt = await (0, crypto_1.generateJwt)(testPrivateKey, testAddress, testDigest, testJti);
        const parts = jwt.split('.');
        expect(parts).toHaveLength(3);
        expect(parts[0]).toBeTruthy();
        expect(parts[1]).toBeTruthy();
        expect(parts[2]).toBeTruthy();
    });
    it('should generate consistent JWTs for same inputs', async () => {
        // Note: JWTs include timestamps so they won't be exactly equal,
        // but the structure should be consistent
        const jwt = await (0, crypto_1.generateJwt)(testPrivateKey, testAddress, testDigest, testJti);
        const parts = jwt.split('.');
        // Header should be consistent (same algorithm)
        const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
        expect(header.alg).toBe('ETH');
        expect(header.typ).toBe('JWT');
    });
});
describe('verifyWebhookSignature', () => {
    // Test private key for generating valid Schnorr signatures
    const testPrivateKey = 'e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c';
    const testPubkey = (0, utils_1.bytesToHex)(secp256k1_1.schnorr.getPublicKey(testPrivateKey));
    it('should throw for invalid event_id length', () => {
        const payload = {
            event_type: 'test',
            event_id: 'short',
            pubkey: 'b'.repeat(64),
            created_at: 1234567890,
            kind: 1,
            tags: [],
            content: 'test',
            sig: 'c'.repeat(128),
        };
        expect(() => (0, crypto_1.verifyWebhookSignature)(payload)).toThrow('event_id length');
    });
    it('should throw for invalid pubkey length', () => {
        const payload = {
            event_type: 'test',
            event_id: 'a'.repeat(64),
            pubkey: 'short',
            created_at: 1234567890,
            kind: 1,
            tags: [],
            content: 'test',
            sig: 'c'.repeat(128),
        };
        expect(() => (0, crypto_1.verifyWebhookSignature)(payload)).toThrow('pubkey length');
    });
    it('should throw for invalid signature length', () => {
        const payload = {
            event_type: 'test',
            event_id: 'a'.repeat(64),
            pubkey: 'b'.repeat(64),
            created_at: 1234567890,
            kind: 1,
            tags: [],
            content: 'test',
            sig: 'short',
        };
        expect(() => (0, crypto_1.verifyWebhookSignature)(payload)).toThrow('signature length');
    });
    it('should throw for missing event_id', () => {
        const payload = {
            event_type: 'test',
            event_id: '',
            pubkey: 'b'.repeat(64),
            created_at: 1234567890,
            kind: 1,
            tags: [],
            content: 'test',
            sig: 'c'.repeat(128),
        };
        expect(() => (0, crypto_1.verifyWebhookSignature)(payload)).toThrow('event_id');
    });
    it('should throw for missing pubkey', () => {
        const payload = {
            event_type: 'test',
            event_id: 'a'.repeat(64),
            pubkey: '',
            created_at: 1234567890,
            kind: 1,
            tags: [],
            content: 'test',
            sig: 'c'.repeat(128),
        };
        expect(() => (0, crypto_1.verifyWebhookSignature)(payload)).toThrow('pubkey');
    });
    it('should throw for missing signature', () => {
        const payload = {
            event_type: 'test',
            event_id: 'a'.repeat(64),
            pubkey: 'b'.repeat(64),
            created_at: 1234567890,
            kind: 1,
            tags: [],
            content: 'test',
            sig: '',
        };
        expect(() => (0, crypto_1.verifyWebhookSignature)(payload)).toThrow('signature');
    });
    it('should throw for event_id mismatch', () => {
        const payload = {
            event_type: 'test',
            event_id: 'a'.repeat(64), // This won't match the computed hash
            pubkey: testPubkey,
            created_at: 1234567890,
            kind: 1,
            tags: [],
            content: 'test',
            sig: 'c'.repeat(128),
        };
        expect(() => (0, crypto_1.verifyWebhookSignature)(payload)).toThrow('event_id mismatch');
    });
    it('should throw for all-zero signature with valid event_id', () => {
        // Create a valid event_id with all-zero signature to test the security check
        const created_at = 1234567890;
        const kind = 1;
        const tags = [];
        const content = 'test content';
        const event_id = computeEventId(testPubkey, created_at, kind, tags, content);
        const payload = {
            event_type: 'test',
            event_id,
            pubkey: testPubkey,
            created_at,
            kind,
            tags,
            content,
            sig: '0'.repeat(128), // All-zero signature
        };
        expect(() => (0, crypto_1.verifyWebhookSignature)(payload)).toThrow('all-zero signature rejected');
    });
    it('should throw for all-zero pubkey with valid event_id', () => {
        // Create a valid event_id with all-zero pubkey to test the security check
        const zeroPubkey = '0'.repeat(64);
        const created_at = 1234567890;
        const kind = 1;
        const tags = [];
        const content = 'test content';
        const event_id = computeEventId(zeroPubkey, created_at, kind, tags, content);
        const payload = {
            event_type: 'test',
            event_id,
            pubkey: zeroPubkey,
            created_at,
            kind,
            tags,
            content,
            sig: 'a'.repeat(128), // Non-zero signature (will fail after pubkey check)
        };
        expect(() => (0, crypto_1.verifyWebhookSignature)(payload)).toThrow('all-zero pubkey rejected');
    });
    it('should throw for invalid Schnorr signature with valid event_id', () => {
        // Create a valid event_id but with invalid (non-matching) signature
        const created_at = 1234567890;
        const kind = 1;
        const tags = [];
        const content = 'test content';
        const event_id = computeEventId(testPubkey, created_at, kind, tags, content);
        const payload = {
            event_type: 'test',
            event_id,
            pubkey: testPubkey,
            created_at,
            kind,
            tags,
            content,
            sig: 'ab'.repeat(64), // Invalid signature
        };
        expect(() => (0, crypto_1.verifyWebhookSignature)(payload)).toThrow('schnorr signature verification failed');
    });
    it('should verify valid Schnorr signature successfully', () => {
        // Create a fully valid Nostr event with correct signature
        const created_at = 1234567890;
        const kind = 1;
        const tags = [['domain', 'test-domain']];
        const content = 'valid test content';
        const event_id = computeEventId(testPubkey, created_at, kind, tags, content);
        // Sign the event_id with Schnorr
        const eventIdBytes = (0, sha256_1.sha256)(new TextEncoder().encode(JSON.stringify([0, testPubkey, created_at, kind, tags, content])));
        const signature = secp256k1_1.schnorr.sign(eventIdBytes, testPrivateKey);
        const sigHex = (0, utils_1.bytesToHex)(signature);
        const payload = {
            event_type: 'test',
            event_id,
            pubkey: testPubkey,
            created_at,
            kind,
            tags,
            content,
            sig: sigHex,
        };
        // Should not throw - verification succeeds
        expect(() => (0, crypto_1.verifyWebhookSignature)(payload)).not.toThrow();
    });
});
describe('privateKeyToAddress', () => {
    const testPrivateKey = 'e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c';
    it('should derive a valid Ethereum address', () => {
        const address = (0, crypto_1.privateKeyToAddress)(testPrivateKey);
        expect(address).toMatch(/^0x[0-9a-f]{40}$/);
    });
    it('should produce consistent addresses for same key', () => {
        const address1 = (0, crypto_1.privateKeyToAddress)(testPrivateKey);
        const address2 = (0, crypto_1.privateKeyToAddress)(testPrivateKey);
        expect(address1).toBe(address2);
    });
    it('should produce different addresses for different keys', () => {
        const address1 = (0, crypto_1.privateKeyToAddress)(testPrivateKey);
        const differentKey = 'a0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c';
        const address2 = (0, crypto_1.privateKeyToAddress)(differentKey);
        expect(address1).not.toBe(address2);
    });
});
describe('signEthereumMessage', () => {
    const testPrivateKey = 'e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c';
    it('should produce a 65-byte signature', async () => {
        const signature = await (0, crypto_1.signEthereumMessage)(testPrivateKey, 'test message');
        expect(signature).toHaveLength(65);
    });
    it('should produce Ethereum-format v value (27-30)', async () => {
        const signature = await (0, crypto_1.signEthereumMessage)(testPrivateKey, 'test message');
        const v = signature[64];
        expect(v).toBeGreaterThanOrEqual(27);
        expect(v).toBeLessThanOrEqual(30);
    });
    it('should produce consistent signatures for same message', async () => {
        const sig1 = await (0, crypto_1.signEthereumMessage)(testPrivateKey, 'test');
        const sig2 = await (0, crypto_1.signEthereumMessage)(testPrivateKey, 'test');
        // r and s should be the same (deterministic signing)
        expect(sig1.slice(0, 64)).toEqual(sig2.slice(0, 64));
    });
    it('should produce different signatures for different messages', async () => {
        const sig1 = await (0, crypto_1.signEthereumMessage)(testPrivateKey, 'message1');
        const sig2 = await (0, crypto_1.signEthereumMessage)(testPrivateKey, 'message2');
        expect(sig1).not.toEqual(sig2);
    });
    it('should handle unicode messages correctly', async () => {
        const signature = await (0, crypto_1.signEthereumMessage)(testPrivateKey, 'hello 世界 🌍');
        expect(signature).toHaveLength(65);
    });
});
//# sourceMappingURL=crypto.test.js.map
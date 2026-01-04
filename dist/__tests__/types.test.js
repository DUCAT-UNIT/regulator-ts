"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const types_1 = require("../types");
describe('createRequestSchema', () => {
    it('should validate valid request with threshold', () => {
        const result = types_1.createRequestSchema.safeParse({ th: '50000' });
        expect(result.success).toBe(true);
        if (result.success) {
            expect(result.data.th).toBe(50000);
        }
    });
    it('should coerce string to number', () => {
        const result = types_1.createRequestSchema.safeParse({ th: '99.5' });
        expect(result.success).toBe(true);
        if (result.success) {
            expect(result.data.th).toBe(99.5);
        }
    });
    it('should reject negative threshold', () => {
        const result = types_1.createRequestSchema.safeParse({ th: '-100' });
        expect(result.success).toBe(false);
    });
    it('should reject zero threshold', () => {
        const result = types_1.createRequestSchema.safeParse({ th: '0' });
        expect(result.success).toBe(false);
    });
    it('should reject missing threshold', () => {
        const result = types_1.createRequestSchema.safeParse({});
        expect(result.success).toBe(false);
    });
    it('should accept optional domain', () => {
        const result = types_1.createRequestSchema.safeParse({ th: '100', domain: 'test-domain' });
        expect(result.success).toBe(true);
        if (result.success) {
            expect(result.data.domain).toBe('test-domain');
        }
    });
});
describe('checkRequestSchema', () => {
    it('should validate valid request', () => {
        const result = types_1.checkRequestSchema.safeParse({
            domain: 'test-domain',
            thold_hash: 'a'.repeat(40),
        });
        expect(result.success).toBe(true);
    });
    it('should reject empty domain', () => {
        const result = types_1.checkRequestSchema.safeParse({
            domain: '',
            thold_hash: 'a'.repeat(40),
        });
        expect(result.success).toBe(false);
    });
    it('should reject wrong hash length - too short', () => {
        const result = types_1.checkRequestSchema.safeParse({
            domain: 'test',
            thold_hash: 'abc',
        });
        expect(result.success).toBe(false);
    });
    it('should reject wrong hash length - too long', () => {
        const result = types_1.checkRequestSchema.safeParse({
            domain: 'test',
            thold_hash: 'a'.repeat(41),
        });
        expect(result.success).toBe(false);
    });
    it('should reject missing domain', () => {
        const result = types_1.checkRequestSchema.safeParse({
            thold_hash: 'a'.repeat(40),
        });
        expect(result.success).toBe(false);
    });
    it('should reject missing thold_hash', () => {
        const result = types_1.checkRequestSchema.safeParse({
            domain: 'test',
        });
        expect(result.success).toBe(false);
    });
});
describe('webhookPayloadSchema', () => {
    const validPayload = {
        event_type: 'create',
        event_id: 'a'.repeat(64),
        pubkey: 'b'.repeat(64),
        created_at: 1234567890,
        kind: 1,
        tags: [['domain', 'test']],
        content: '{"test": true}',
        sig: 'c'.repeat(128),
    };
    it('should validate valid payload', () => {
        const result = types_1.webhookPayloadSchema.safeParse(validPayload);
        expect(result.success).toBe(true);
    });
    it('should accept optional nostr_event', () => {
        const result = types_1.webhookPayloadSchema.safeParse({
            ...validPayload,
            nostr_event: { some: 'data' },
        });
        expect(result.success).toBe(true);
    });
    it('should reject missing required fields', () => {
        const incomplete = { event_type: 'test' };
        const result = types_1.webhookPayloadSchema.safeParse(incomplete);
        expect(result.success).toBe(false);
    });
    it('should validate tags as array of string arrays', () => {
        const result = types_1.webhookPayloadSchema.safeParse({
            ...validPayload,
            tags: [['key1', 'value1'], ['key2', 'value2', 'extra']],
        });
        expect(result.success).toBe(true);
    });
    it('should accept empty tags array', () => {
        const result = types_1.webhookPayloadSchema.safeParse({
            ...validPayload,
            tags: [],
        });
        expect(result.success).toBe(true);
    });
    it('should validate created_at as number', () => {
        const result = types_1.webhookPayloadSchema.safeParse({
            ...validPayload,
            created_at: 'not-a-number',
        });
        expect(result.success).toBe(false);
    });
    it('should validate kind as number', () => {
        const result = types_1.webhookPayloadSchema.safeParse({
            ...validPayload,
            kind: 'not-a-number',
        });
        expect(result.success).toBe(false);
    });
});
//# sourceMappingURL=types.test.js.map
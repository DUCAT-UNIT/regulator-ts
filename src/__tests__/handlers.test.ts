import { Request, Response } from 'express';
import {
  AppState,
  createAppState,
  handleCreate,
  handleWebhook,
  handleHealth,
  handleReadiness,
  handleMetrics,
  handleStatus,
  handleCheck,
  startCleanupTask,
  startLiquidationPoller,
} from '../handlers';
import { GatewayConfig } from '../config';
import type { WebhookPayload } from '../types';

// Mock the crypto functions
jest.mock('../crypto', () => ({
  generateRequestId: jest.fn(() => 'abcdef1234567890abcdef1234567890'),
  generateJwt: jest.fn(() => Promise.resolve('mock.jwt.token')),
  sha256Hex: jest.fn(() => '0x1234567890abcdef'),
  getTag: jest.fn((tags: string[][], key: string) => {
    const tag = tags.find(t => t.length >= 2 && t[0] === key);
    return tag?.[1];
  }),
  truncateEventId: jest.fn((id: string) => id.slice(0, 16)),
  verifyWebhookSignature: jest.fn(),
}));

// Mock logger - must mock both default export and named export
jest.mock('../logger', () => ({
  __esModule: true,
  default: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}));

// Mock fetch
global.fetch = jest.fn(() =>
  Promise.resolve({
    ok: true,
    status: 200,
    text: () => Promise.resolve('{}'),
    json: () => Promise.resolve({}),
  } as unknown as globalThis.Response)
) as jest.Mock;

// Mock replay protection
jest.mock('../index', () => ({
  isWebhookReplayed: jest.fn(() => false),
  markWebhookProcessed: jest.fn(),
}));

const createMockConfig = (overrides: Partial<GatewayConfig> = {}): GatewayConfig => ({
  workflowId: 'test-workflow',
  gatewayUrl: 'https://test-gateway.com',
  authorizedKey: '0xtest123',
  callbackUrl: 'http://localhost:8080/webhook/ducat',
  privateKeyHex: 'e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c',
  maxPending: 100,
  blockTimeoutMs: 100, // Short timeout for tests
  cleanupIntervalMs: 60000,
  ipRateLimit: 10,
  ipBurstLimit: 20,
  port: 8080,
  expectedWebhookPubkey: 'a'.repeat(64),
  liquidationEnabled: false,
  liquidationUrl: 'http://localhost:4001/liq/api/at-risk',
  liquidationIntervalMs: 1000,
  ...overrides,
});

const createMockRequest = (overrides: Partial<Request> = {}): Request => {
  return {
    query: {},
    body: {},
    params: {},
    headers: {},
    ...overrides,
  } as Request;
};

interface MockResponse {
  _status: number;
  _json: unknown;
  _data: string;
  status: jest.Mock;
  json: jest.Mock;
  send: jest.Mock;
  set: jest.Mock;
}

const createMockResponse = (): MockResponse => {
  const mockRes: MockResponse = {
    _status: 200,
    _json: null,
    _data: '',
    status: jest.fn(),
    json: jest.fn(),
    send: jest.fn(),
    set: jest.fn(),
  };

  mockRes.status.mockImplementation((code: number) => {
    mockRes._status = code;
    return mockRes;
  });

  mockRes.json.mockImplementation((data: unknown) => {
    mockRes._json = data;
    return mockRes;
  });

  mockRes.send.mockImplementation((data: string) => {
    mockRes._data = data;
    return mockRes;
  });

  mockRes.set.mockImplementation(() => mockRes);

  return mockRes;
};

describe('createAppState', () => {
  it('should create app state with config', () => {
    const config = createMockConfig();
    const state = createAppState(config);

    expect(state.config).toBe(config);
    expect(state.pendingRequests).toBeInstanceOf(Map);
    expect(state.startTime).toBeInstanceOf(Date);
  });
});

describe('handleHealth', () => {
  it('should return healthy status', () => {
    const config = createMockConfig();
    const state = createAppState(config);
    const req = createMockRequest();
    const res = createMockResponse();

    handleHealth(req, res as unknown as Response, state);

    expect(res.json).toHaveBeenCalled();
    expect(res._json).toMatchObject({
      status: 'healthy',
    });
  });
});

describe('handleMetrics', () => {
  it('should return prometheus metrics', () => {
    const config = createMockConfig();
    const state = createAppState(config);
    const req = createMockRequest();
    const res = createMockResponse();

    handleMetrics(req, res as unknown as Response, state);

    expect(res.set).toHaveBeenCalledWith('Content-Type', 'text/plain; charset=utf-8');
    expect(res.send).toHaveBeenCalled();
    expect(res._data).toContain('gateway_pending_requests');
    expect(res._data).toContain('gateway_uptime_seconds');
    expect(res._data).toContain('gateway_max_pending');
  });
});

describe('handleStatus', () => {
  it('should return 400 if request_id is missing', () => {
    const config = createMockConfig();
    const state = createAppState(config);
    const req = createMockRequest({ params: {} });
    const res = createMockResponse();

    handleStatus(req, res as unknown as Response, state);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res._json).toMatchObject({ error: 'Missing request_id' });
  });

  it('should return 404 if request not found', () => {
    const config = createMockConfig();
    const state = createAppState(config);
    const req = createMockRequest({ params: { id: 'nonexistent' } });
    const res = createMockResponse();

    handleStatus(req, res as unknown as Response, state);

    expect(res.status).toHaveBeenCalledWith(404);
    expect(res._json).toMatchObject({ error: 'Request not found' });
  });

  it('should return pending status', () => {
    const config = createMockConfig();
    const state = createAppState(config);
    const requestId = 'test-request-id';
    state.pendingRequests.set(requestId, {
      requestId,
      createdAt: new Date(),
      status: 'pending',
    });

    const req = createMockRequest({ params: { id: requestId } });
    const res = createMockResponse();

    handleStatus(req, res as unknown as Response, state);

    expect(res.json).toHaveBeenCalled();
    expect(res._json).toMatchObject({
      status: 'pending',
      request_id: requestId,
    });
  });

  it('should return completed result with parsed contract', () => {
    const config = createMockConfig();
    const state = createAppState(config);
    const requestId = 'test-request-id';
    const mockResult: WebhookPayload = {
      event_type: 'create',
      event_id: 'a'.repeat(64),
      pubkey: 'b'.repeat(64),
      created_at: Date.now(),
      kind: 1,
      tags: [],
      content: JSON.stringify({ contract_id: 'test' }),
      sig: 'c'.repeat(128),
    };

    state.pendingRequests.set(requestId, {
      requestId,
      createdAt: new Date(),
      status: 'completed',
      result: mockResult,
    });

    const req = createMockRequest({ params: { id: requestId } });
    const res = createMockResponse();

    handleStatus(req, res as unknown as Response, state);

    expect(res.json).toHaveBeenCalled();
    expect(res._json).toMatchObject({ contract_id: 'test' });
  });

  it('should return completed status with invalid JSON content', () => {
    const config = createMockConfig();
    const state = createAppState(config);
    const requestId = 'test-request-id';
    const mockResult: WebhookPayload = {
      event_type: 'create',
      event_id: 'a'.repeat(64),
      pubkey: 'b'.repeat(64),
      created_at: Date.now(),
      kind: 1,
      tags: [],
      content: 'not valid json',
      sig: 'c'.repeat(128),
    };

    state.pendingRequests.set(requestId, {
      requestId,
      createdAt: new Date(),
      status: 'completed',
      result: mockResult,
    });

    const req = createMockRequest({ params: { id: requestId } });
    const res = createMockResponse();

    handleStatus(req, res as unknown as Response, state);

    expect(res.json).toHaveBeenCalled();
    expect(res._json).toMatchObject({
      status: 'completed',
      request_id: requestId,
    });
  });

  it('should return timeout status', () => {
    const config = createMockConfig();
    const state = createAppState(config);
    const requestId = 'test-request-id';

    state.pendingRequests.set(requestId, {
      requestId,
      createdAt: new Date(),
      status: 'timeout',
    });

    const req = createMockRequest({ params: { id: requestId } });
    const res = createMockResponse();

    handleStatus(req, res as unknown as Response, state);

    expect(res.json).toHaveBeenCalled();
    expect(res._json).toMatchObject({
      status: 'timeout',
      request_id: requestId,
    });
  });

  it('should use requestId param if id is not provided', () => {
    const config = createMockConfig();
    const state = createAppState(config);
    const requestId = 'test-request-id';
    state.pendingRequests.set(requestId, {
      requestId,
      createdAt: new Date(),
      status: 'pending',
    });

    const req = createMockRequest({ params: { requestId } });
    const res = createMockResponse();

    handleStatus(req, res as unknown as Response, state);

    expect(res.json).toHaveBeenCalled();
    expect(res._json).toMatchObject({
      status: 'pending',
      request_id: requestId,
    });
  });
});

describe('handleCreate', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (global.fetch as jest.Mock).mockResolvedValue({
      ok: true,
      status: 200,
      text: () => Promise.resolve('{}'),
      json: () => Promise.resolve({}),
    });
  });

  it('should return 400 for missing threshold', async () => {
    const config = createMockConfig();
    const state = createAppState(config);
    const req = createMockRequest({ query: {} });
    const res = createMockResponse();

    await handleCreate(req, res as unknown as Response, state);

    expect(res.status).toHaveBeenCalledWith(400);
  });

  it('should return 400 for invalid threshold', async () => {
    const config = createMockConfig();
    const state = createAppState(config);
    const req = createMockRequest({ query: { th: 'invalid' } });
    const res = createMockResponse();

    await handleCreate(req, res as unknown as Response, state);

    expect(res.status).toHaveBeenCalledWith(400);
  });

  it('should return 400 for negative threshold', async () => {
    const config = createMockConfig();
    const state = createAppState(config);
    const req = createMockRequest({ query: { th: '-100' } });
    const res = createMockResponse();

    await handleCreate(req, res as unknown as Response, state);

    expect(res.status).toHaveBeenCalledWith(400);
  });

  it('should return 503 when at capacity', async () => {
    const config = createMockConfig({ maxPending: 0 });
    const state = createAppState(config);
    const req = createMockRequest({ query: { th: '100' } });
    const res = createMockResponse();

    await handleCreate(req, res as unknown as Response, state);

    expect(res.status).toHaveBeenCalledWith(503);
    expect(res._json).toMatchObject({ error: 'Server at capacity, please retry later' });
  });

  it('should return 500 when workflow trigger fails', async () => {
    (global.fetch as jest.Mock).mockRejectedValueOnce(new Error('Network error'));

    const config = createMockConfig();
    const state = createAppState(config);
    const req = createMockRequest({ query: { th: '100' } });
    const res = createMockResponse();

    await handleCreate(req, res as unknown as Response, state);

    expect(res.status).toHaveBeenCalledWith(500);
    expect(res._json).toMatchObject({ error: 'Failed to trigger workflow' });
  });

  it('should return 202 on timeout', async () => {
    const config = createMockConfig({ blockTimeoutMs: 10 });
    const state = createAppState(config);
    const req = createMockRequest({ query: { th: '100' } });
    const res = createMockResponse();

    await handleCreate(req, res as unknown as Response, state);

    expect(res.status).toHaveBeenCalledWith(202);
    expect(res._json).toMatchObject({ status: 'timeout' });
  });

  it('should return contract on successful webhook', async () => {
    const config = createMockConfig({ blockTimeoutMs: 5000 });
    const state = createAppState(config);
    const req = createMockRequest({ query: { th: '100' } });
    const res = createMockResponse();

    // Start the request
    const createPromise = handleCreate(req, res as unknown as Response, state);

    // Wait a bit for the pending request to be registered
    await new Promise(resolve => setTimeout(resolve, 50));

    // Find the pending request and resolve it
    const keys = Array.from(state.pendingRequests.keys());
    expect(keys.length).toBe(1);
    const pending = state.pendingRequests.get(keys[0]);
    if (pending?.resolve) {
      pending.resolve({
        event_type: 'create',
        event_id: 'a'.repeat(64),
        pubkey: 'b'.repeat(64),
        created_at: Math.floor(Date.now() / 1000),
        kind: 1,
        tags: [],
        content: JSON.stringify({ contract_id: 'test-contract' }),
        sig: 'c'.repeat(128),
      });
    }

    await createPromise;

    expect(res.json).toHaveBeenCalled();
    expect(res._json).toMatchObject({ contract_id: 'test-contract' });
  });

  it('should return raw content on invalid JSON', async () => {
    const config = createMockConfig({ blockTimeoutMs: 5000 });
    const state = createAppState(config);
    const req = createMockRequest({ query: { th: '100' } });
    const res = createMockResponse();

    const createPromise = handleCreate(req, res as unknown as Response, state);

    await new Promise(resolve => setTimeout(resolve, 50));

    const keys = Array.from(state.pendingRequests.keys());
    const pending = state.pendingRequests.get(keys[0]);
    if (pending?.resolve) {
      pending.resolve({
        event_type: 'create',
        event_id: 'a'.repeat(64),
        pubkey: 'b'.repeat(64),
        created_at: Math.floor(Date.now() / 1000),
        kind: 1,
        tags: [],
        content: 'not json',
        sig: 'c'.repeat(128),
      });
    }

    await createPromise;

    expect(res.json).toHaveBeenCalled();
    expect(res._json).toMatchObject({ raw: 'not json' });
  });

  it('should return raw content on prototype pollution attempt', async () => {
    const config = createMockConfig({ blockTimeoutMs: 5000 });
    const state = createAppState(config);
    const req = createMockRequest({ query: { th: '100' } });
    const res = createMockResponse();

    const createPromise = handleCreate(req, res as unknown as Response, state);

    await new Promise(resolve => setTimeout(resolve, 50));

    const keys = Array.from(state.pendingRequests.keys());
    const pending = state.pendingRequests.get(keys[0]);
    if (pending?.resolve) {
      pending.resolve({
        event_type: 'create',
        event_id: 'a'.repeat(64),
        pubkey: 'b'.repeat(64),
        created_at: Math.floor(Date.now() / 1000),
        kind: 1,
        tags: [],
        content: '{"__proto__": {"polluted": true}}',
        sig: 'c'.repeat(128),
      });
    }

    await createPromise;

    expect(res.json).toHaveBeenCalled();
    // Should fall back to raw because safeJsonParse throws
    expect(res._json).toMatchObject({ raw: '{"__proto__": {"polluted": true}}' });
  });
});

describe('handleCheck', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (global.fetch as jest.Mock).mockResolvedValue({
      ok: true,
      status: 200,
      text: () => Promise.resolve('{}'),
      json: () => Promise.resolve({}),
    });
  });

  it('should return 400 for missing domain', async () => {
    const config = createMockConfig();
    const state = createAppState(config);
    const req = createMockRequest({
      body: { thold_hash: 'a'.repeat(40) },
    });
    const res = createMockResponse();

    await handleCheck(req, res as unknown as Response, state);

    expect(res.status).toHaveBeenCalledWith(400);
  });

  it('should return 400 for invalid thold_hash length', async () => {
    const config = createMockConfig();
    const state = createAppState(config);
    const req = createMockRequest({
      body: { domain: 'test-domain', thold_hash: 'short' },
    });
    const res = createMockResponse();

    await handleCheck(req, res as unknown as Response, state);

    expect(res.status).toHaveBeenCalledWith(400);
  });

  it('should return 400 for non-hex thold_hash', async () => {
    const config = createMockConfig();
    const state = createAppState(config);
    const req = createMockRequest({
      body: { domain: 'test-domain', thold_hash: 'z'.repeat(40) },
    });
    const res = createMockResponse();

    await handleCheck(req, res as unknown as Response, state);

    expect(res.status).toHaveBeenCalledWith(400);
  });

  it('should return 503 when at capacity', async () => {
    const config = createMockConfig({ maxPending: 0 });
    const state = createAppState(config);
    const req = createMockRequest({
      body: { domain: 'test-domain', thold_hash: 'a'.repeat(40) },
    });
    const res = createMockResponse();

    await handleCheck(req, res as unknown as Response, state);

    expect(res.status).toHaveBeenCalledWith(503);
  });

  it('should return 500 when workflow trigger fails', async () => {
    (global.fetch as jest.Mock).mockRejectedValueOnce(new Error('Network error'));

    const config = createMockConfig();
    const state = createAppState(config);
    const req = createMockRequest({
      body: { domain: 'test-domain', thold_hash: 'a'.repeat(40) },
    });
    const res = createMockResponse();

    await handleCheck(req, res as unknown as Response, state);

    expect(res.status).toHaveBeenCalledWith(500);
    expect(res._json).toMatchObject({ error: 'Failed to trigger workflow' });
  });

  it('should return 202 on timeout', async () => {
    const config = createMockConfig({ blockTimeoutMs: 10 });
    const state = createAppState(config);
    const req = createMockRequest({
      body: { domain: 'test-domain', thold_hash: 'a'.repeat(40) },
    });
    const res = createMockResponse();

    await handleCheck(req, res as unknown as Response, state);

    expect(res.status).toHaveBeenCalledWith(202);
    expect(res._json).toMatchObject({ status: 'timeout' });
  });

  it('should return contract on successful webhook', async () => {
    const config = createMockConfig({ blockTimeoutMs: 5000 });
    const state = createAppState(config);
    const domain = 'test-domain';
    const req = createMockRequest({
      body: { domain, thold_hash: 'a'.repeat(40) },
    });
    const res = createMockResponse();

    const checkPromise = handleCheck(req, res as unknown as Response, state);

    await new Promise(resolve => setTimeout(resolve, 50));

    const pending = state.pendingRequests.get(domain);
    if (pending?.resolve) {
      pending.resolve({
        event_type: 'check',
        event_id: 'a'.repeat(64),
        pubkey: 'b'.repeat(64),
        created_at: Math.floor(Date.now() / 1000),
        kind: 1,
        tags: [],
        content: JSON.stringify({ contract_id: 'test-contract' }),
        sig: 'c'.repeat(128),
      });
    }

    await checkPromise;

    expect(res.json).toHaveBeenCalled();
    expect(res._json).toMatchObject({ contract_id: 'test-contract' });
  });

  it('should log breach event type', async () => {
    const config = createMockConfig({ blockTimeoutMs: 5000 });
    const state = createAppState(config);
    const domain = 'test-domain';
    const req = createMockRequest({
      body: { domain, thold_hash: 'a'.repeat(40) },
    });
    const res = createMockResponse();

    const checkPromise = handleCheck(req, res as unknown as Response, state);

    await new Promise(resolve => setTimeout(resolve, 50));

    const pending = state.pendingRequests.get(domain);
    if (pending?.resolve) {
      pending.resolve({
        event_type: 'breach',
        event_id: 'a'.repeat(64),
        pubkey: 'b'.repeat(64),
        created_at: Math.floor(Date.now() / 1000),
        kind: 1,
        tags: [],
        content: JSON.stringify({ contract_id: 'test-contract', thold_key: 'secret' }),
        sig: 'c'.repeat(128),
      });
    }

    await checkPromise;

    expect(res.json).toHaveBeenCalled();
  });

  it('should return raw content on invalid JSON', async () => {
    const config = createMockConfig({ blockTimeoutMs: 5000 });
    const state = createAppState(config);
    const domain = 'test-domain';
    const req = createMockRequest({
      body: { domain, thold_hash: 'a'.repeat(40) },
    });
    const res = createMockResponse();

    const checkPromise = handleCheck(req, res as unknown as Response, state);

    await new Promise(resolve => setTimeout(resolve, 50));

    const pending = state.pendingRequests.get(domain);
    if (pending?.resolve) {
      pending.resolve({
        event_type: 'check',
        event_id: 'a'.repeat(64),
        pubkey: 'b'.repeat(64),
        created_at: Math.floor(Date.now() / 1000),
        kind: 1,
        tags: [],
        content: 'not json',
        sig: 'c'.repeat(128),
      });
    }

    await checkPromise;

    expect(res.json).toHaveBeenCalled();
    expect(res._json).toMatchObject({ raw: 'not json' });
  });
});

describe('handleWebhook', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    const { verifyWebhookSignature } = require('../crypto');
    verifyWebhookSignature.mockImplementation(() => {});
  });

  it('should return 400 for invalid JSON', async () => {
    const config = createMockConfig();
    const state = createAppState(config);
    const req = createMockRequest({
      body: null,
    });
    const res = createMockResponse();

    await handleWebhook(req, res as unknown as Response, state);

    expect(res.status).toHaveBeenCalledWith(400);
  });

  it('should return 400 for empty content', async () => {
    const config = createMockConfig();
    const state = createAppState(config);
    const req = createMockRequest({
      body: {
        event_type: 'create',
        event_id: 'a'.repeat(64),
        pubkey: 'b'.repeat(64),
        created_at: Math.floor(Date.now() / 1000),
        kind: 1,
        tags: [['domain', 'test-domain']],
        content: '',
        sig: 'c'.repeat(128),
      },
    });
    const res = createMockResponse();

    await handleWebhook(req, res as unknown as Response, state);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res._json).toMatchObject({ error: 'Webhook content cannot be empty' });
  });

  it('should return 401 for failed signature verification', async () => {
    const { verifyWebhookSignature } = require('../crypto');
    verifyWebhookSignature.mockImplementation(() => {
      throw new Error('invalid signature');
    });

    const config = createMockConfig();
    const state = createAppState(config);
    const req = createMockRequest({
      body: {
        event_type: 'create',
        event_id: 'a'.repeat(64),
        pubkey: 'b'.repeat(64),
        created_at: Math.floor(Date.now() / 1000),
        kind: 1,
        tags: [['domain', 'test-domain']],
        content: 'test content',
        sig: 'c'.repeat(128),
      },
    });
    const res = createMockResponse();

    await handleWebhook(req, res as unknown as Response, state);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res._json).toMatchObject({ error: 'Signature verification failed' });
  });

  it('should return 409 for replayed webhook', async () => {
    const { isWebhookReplayed } = require('../index');
    isWebhookReplayed.mockReturnValue(true);

    const config = createMockConfig();
    const state = createAppState(config);
    const req = createMockRequest({
      body: {
        event_type: 'create',
        event_id: 'a'.repeat(64),
        pubkey: 'b'.repeat(64),
        created_at: Math.floor(Date.now() / 1000),
        kind: 1,
        tags: [['domain', 'test-domain']],
        content: 'test content',
        sig: 'c'.repeat(128),
      },
    });
    const res = createMockResponse();

    await handleWebhook(req, res as unknown as Response, state);

    expect(res.status).toHaveBeenCalledWith(409);
    expect(res._json).toMatchObject({ error: 'Duplicate webhook' });

    isWebhookReplayed.mockReturnValue(false);
  });

  it('should return 401 for unauthorized pubkey', async () => {
    const { isWebhookReplayed } = require('../index');
    isWebhookReplayed.mockReturnValue(false);

    const config = createMockConfig();
    const state = createAppState(config);
    const req = createMockRequest({
      body: {
        event_type: 'create',
        event_id: 'a'.repeat(64),
        pubkey: 'unauthorized'.padEnd(64, '0'),
        created_at: Math.floor(Date.now() / 1000),
        kind: 1,
        tags: [['domain', 'test-domain']],
        content: 'test content',
        sig: 'c'.repeat(128),
      },
    });
    const res = createMockResponse();

    await handleWebhook(req, res as unknown as Response, state);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res._json).toMatchObject({ error: 'Webhook signed by unauthorized key' });
  });

  it('should return 401 for pubkey with different length (covers secureCompare length check)', async () => {
    const { isWebhookReplayed } = require('../index');
    isWebhookReplayed.mockReturnValue(false);

    const config = createMockConfig();
    const state = createAppState(config);
    // Use a pubkey with wrong length to trigger the early return in secureCompare
    const req = createMockRequest({
      body: {
        event_type: 'create',
        event_id: 'a'.repeat(64),
        pubkey: 'short', // Different length than expectedWebhookPubkey
        created_at: Math.floor(Date.now() / 1000),
        kind: 1,
        tags: [['domain', 'test-domain']],
        content: 'test content',
        sig: 'c'.repeat(128),
      },
    });
    const res = createMockResponse();

    await handleWebhook(req, res as unknown as Response, state);

    expect(res.status).toHaveBeenCalledWith(401);
  });

  it('should return 401 for future timestamp', async () => {
    const { isWebhookReplayed } = require('../index');
    isWebhookReplayed.mockReturnValue(false);

    const config = createMockConfig();
    const state = createAppState(config);
    const futureTime = Math.floor(Date.now() / 1000) + 600; // 10 minutes in future
    const req = createMockRequest({
      body: {
        event_type: 'create',
        event_id: 'a'.repeat(64),
        pubkey: config.expectedWebhookPubkey,
        created_at: futureTime,
        kind: 1,
        tags: [['domain', 'test-domain']],
        content: 'test content',
        sig: 'c'.repeat(128),
      },
    });
    const res = createMockResponse();

    await handleWebhook(req, res as unknown as Response, state);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res._json).toMatchObject({ error: 'Invalid timestamp' });
  });

  it('should return 401 for expired timestamp', async () => {
    const { isWebhookReplayed } = require('../index');
    isWebhookReplayed.mockReturnValue(false);

    const config = createMockConfig();
    const state = createAppState(config);
    const oldTime = Math.floor(Date.now() / 1000) - 600; // 10 minutes ago
    const req = createMockRequest({
      body: {
        event_type: 'create',
        event_id: 'a'.repeat(64),
        pubkey: config.expectedWebhookPubkey,
        created_at: oldTime,
        kind: 1,
        tags: [['domain', 'test-domain']],
        content: 'test content',
        sig: 'c'.repeat(128),
      },
    });
    const res = createMockResponse();

    await handleWebhook(req, res as unknown as Response, state);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res._json).toMatchObject({ error: 'Webhook expired' });
  });

  it('should return 400 for missing domain tag', async () => {
    const { isWebhookReplayed } = require('../index');
    isWebhookReplayed.mockReturnValue(false);

    const config = createMockConfig();
    const state = createAppState(config);
    const req = createMockRequest({
      body: {
        event_type: 'create',
        event_id: 'a'.repeat(64),
        pubkey: config.expectedWebhookPubkey,
        created_at: Math.floor(Date.now() / 1000),
        kind: 1,
        tags: [], // No domain tag
        content: 'test content',
        sig: 'c'.repeat(128),
      },
    });
    const res = createMockResponse();

    await handleWebhook(req, res as unknown as Response, state);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res._json).toMatchObject({ error: 'Missing required domain tag' });
  });

  it('should match pending request and return OK', async () => {
    const { isWebhookReplayed, markWebhookProcessed } = require('../index');
    isWebhookReplayed.mockReturnValue(false);

    const config = createMockConfig();
    const state = createAppState(config);
    const domain = 'test-domain';

    // Create a pending request with a resolve function
    let resolvedPayload: WebhookPayload | null = null;
    state.pendingRequests.set(domain, {
      requestId: domain,
      createdAt: new Date(),
      status: 'pending',
      resolve: (payload: WebhookPayload) => {
        resolvedPayload = payload;
      },
    });

    const req = createMockRequest({
      body: {
        event_type: 'create',
        event_id: 'a'.repeat(64),
        pubkey: config.expectedWebhookPubkey,
        created_at: Math.floor(Date.now() / 1000),
        kind: 1,
        tags: [['domain', domain]],
        content: 'test content',
        sig: 'c'.repeat(128),
      },
    });
    const res = createMockResponse();

    await handleWebhook(req, res as unknown as Response, state);

    expect(res.json).toHaveBeenCalled();
    expect(res._json).toMatchObject({ status: 'OK' });
    expect(markWebhookProcessed).toHaveBeenCalled();
    expect(resolvedPayload).not.toBeNull();
  });

  it('should return OK even without pending request', async () => {
    const { isWebhookReplayed, markWebhookProcessed } = require('../index');
    isWebhookReplayed.mockReturnValue(false);

    const config = createMockConfig();
    const state = createAppState(config);

    const req = createMockRequest({
      body: {
        event_type: 'create',
        event_id: 'a'.repeat(64),
        pubkey: config.expectedWebhookPubkey,
        created_at: Math.floor(Date.now() / 1000),
        kind: 1,
        tags: [['domain', 'no-pending-request']],
        content: 'test content',
        sig: 'c'.repeat(128),
      },
    });
    const res = createMockResponse();

    await handleWebhook(req, res as unknown as Response, state);

    expect(res.json).toHaveBeenCalled();
    expect(res._json).toMatchObject({ status: 'OK' });
  });
});

describe('handleReadiness', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('should return healthy status when gateway is reachable', async () => {
    (global.fetch as jest.Mock).mockResolvedValueOnce({
      ok: true,
      status: 200,
    });

    const config = createMockConfig();
    const state = createAppState(config);
    const req = createMockRequest();
    const res = createMockResponse();

    await handleReadiness(req, res as unknown as Response, state);

    expect(res.json).toHaveBeenCalled();
    expect(res._json).toMatchObject({
      status: 'healthy',
    });
    expect((res._json as Record<string, unknown>).dependencies).toBeDefined();
    expect((res._json as Record<string, unknown>).metrics).toBeDefined();
  });

  it('should return degraded status when gateway is unreachable', async () => {
    (global.fetch as jest.Mock).mockRejectedValueOnce(new Error('Network error'));

    const config = createMockConfig();
    const state = createAppState(config);
    const req = createMockRequest();
    const res = createMockResponse();

    await handleReadiness(req, res as unknown as Response, state);

    expect(res.json).toHaveBeenCalled();
    expect(res._json).toMatchObject({
      status: 'degraded',
    });
  });

  it('should return unhealthy status when at capacity', async () => {
    (global.fetch as jest.Mock).mockResolvedValueOnce({
      ok: true,
      status: 200,
    });

    const config = createMockConfig({ maxPending: 1 });
    const state = createAppState(config);

    // Fill up to capacity
    state.pendingRequests.set('req1', {
      requestId: 'req1',
      createdAt: new Date(),
      status: 'pending',
    });

    const req = createMockRequest();
    const res = createMockResponse();

    await handleReadiness(req, res as unknown as Response, state);

    expect(res.status).toHaveBeenCalledWith(503);
    expect(res._json).toMatchObject({
      status: 'unhealthy',
    });
  });

  it('should return degraded status when near capacity', async () => {
    (global.fetch as jest.Mock).mockResolvedValueOnce({
      ok: true,
      status: 200,
    });

    const config = createMockConfig({ maxPending: 10 });
    const state = createAppState(config);

    // Fill up to 90% capacity
    for (let i = 0; i < 9; i++) {
      state.pendingRequests.set(`req${i}`, {
        requestId: `req${i}`,
        createdAt: new Date(),
        status: 'pending',
      });
    }

    const req = createMockRequest();
    const res = createMockResponse();

    await handleReadiness(req, res as unknown as Response, state);

    expect(res.json).toHaveBeenCalled();
    expect(res._json).toMatchObject({
      status: 'degraded',
    });
  });
});

describe('startCleanupTask', () => {
  beforeEach(() => {
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('should clean up old completed requests', () => {
    // Use a long blockTimeoutMs so recent requests are not cleaned
    const config = createMockConfig({ cleanupIntervalMs: 1000, blockTimeoutMs: 60000 });
    const state = createAppState(config);

    // Add an old completed request with a fixed timestamp (10 minutes ago)
    const oldDate = new Date(Date.now() - 10 * 60 * 1000);
    state.pendingRequests.set('old-completed', {
      requestId: 'old-completed',
      createdAt: oldDate,
      status: 'completed',
    });

    // Add a recent request that should survive cleanup
    state.pendingRequests.set('recent', {
      requestId: 'recent',
      createdAt: new Date(),
      status: 'pending',
    });

    expect(state.pendingRequests.size).toBe(2);

    startCleanupTask(state);

    // Run timers
    jest.runOnlyPendingTimers();

    // Old completed should be gone (> 5 min), recent should remain
    expect(state.pendingRequests.has('old-completed')).toBe(false);
    expect(state.pendingRequests.has('recent')).toBe(true);
  });

  it('should clean up old timeout requests', () => {
    const config = createMockConfig({ cleanupIntervalMs: 1000 });
    const state = createAppState(config);

    const oldDate = new Date(Date.now() - 10 * 60 * 1000);
    state.pendingRequests.set('old-timeout', {
      requestId: 'old-timeout',
      createdAt: oldDate,
      status: 'timeout',
    });

    startCleanupTask(state);
    jest.runOnlyPendingTimers();

    expect(state.pendingRequests.has('old-timeout')).toBe(false);
  });

  it('should clean up old pending requests beyond double timeout', () => {
    const config = createMockConfig({ cleanupIntervalMs: 1000, blockTimeoutMs: 1000 });
    const state = createAppState(config);

    // Pending request older than 2x blockTimeoutMs
    const oldDate = new Date(Date.now() - 5000);
    state.pendingRequests.set('old-pending', {
      requestId: 'old-pending',
      createdAt: oldDate,
      status: 'pending',
    });

    startCleanupTask(state);
    jest.runOnlyPendingTimers();

    expect(state.pendingRequests.has('old-pending')).toBe(false);
  });

  it('should not delete recent requests', () => {
    // Use a very long timeout so recent requests are not cleaned up
    const config = createMockConfig({ cleanupIntervalMs: 1000, blockTimeoutMs: 60000 });
    const state = createAppState(config);

    // Add only recent requests - needs to be truly recent
    state.pendingRequests.set('recent', {
      requestId: 'recent',
      createdAt: new Date(),
      status: 'pending',
    });

    startCleanupTask(state);
    jest.runOnlyPendingTimers();

    // Recent request should still be there (not old enough to clean)
    expect(state.pendingRequests.has('recent')).toBe(true);
  });
});

describe('startLiquidationPoller', () => {
  beforeEach(() => {
    jest.useFakeTimers();
    jest.clearAllMocks();
    (global.fetch as jest.Mock).mockResolvedValue({
      ok: true,
      status: 200,
      text: () => Promise.resolve('{}'),
      json: () => Promise.resolve({ total_count: 0, current_price: 50000, at_risk_vaults: [] }),
    });
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('should not start when liquidation is disabled', () => {
    const config = createMockConfig({ liquidationEnabled: false });
    const state = createAppState(config);

    startLiquidationPoller(state);

    // Should return immediately without setting interval
    jest.advanceTimersByTime(10000);
    expect(global.fetch).not.toHaveBeenCalled();
  });

  it('should poll liquidation service when enabled', async () => {
    const config = createMockConfig({
      liquidationEnabled: true,
      liquidationIntervalMs: 1000,
    });
    const state = createAppState(config);

    (global.fetch as jest.Mock).mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ total_count: 0, current_price: 50000, at_risk_vaults: [] }),
    });

    startLiquidationPoller(state);

    // Advance timer to trigger poll
    jest.advanceTimersByTime(1000);
    await Promise.resolve(); // Let async code run

    expect(global.fetch).toHaveBeenCalledWith(config.liquidationUrl);
  });

  it('should trigger batch evaluate for at-risk vaults', async () => {
    const config = createMockConfig({
      liquidationEnabled: true,
      liquidationIntervalMs: 1000,
    });
    const state = createAppState(config);

    (global.fetch as jest.Mock)
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          total_count: 2,
          current_price: 50000,
          at_risk_vaults: [
            { thold_hash: 'a'.repeat(40) },
            { thold_hash: 'b'.repeat(40) },
          ],
        }),
      })
      .mockResolvedValue({
        ok: true,
        text: () => Promise.resolve('{}'),
      });

    startLiquidationPoller(state);

    jest.advanceTimersByTime(1000);
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();

    // Should have called fetch twice - once for liquidation check, once for batch evaluate
    expect(global.fetch).toHaveBeenCalledTimes(2);
  });

  it('should filter invalid thold_hash values', async () => {
    const config = createMockConfig({
      liquidationEnabled: true,
      liquidationIntervalMs: 1000,
    });
    const state = createAppState(config);

    (global.fetch as jest.Mock)
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          total_count: 2,
          current_price: 50000,
          at_risk_vaults: [
            { thold_hash: 'invalid' }, // Should be filtered
            { thold_hash: 'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz' }, // Non-hex, should be filtered
          ],
        }),
      });

    startLiquidationPoller(state);

    jest.advanceTimersByTime(1000);
    await Promise.resolve();

    // Should only call fetch once (liquidation check) - no batch evaluate because all filtered
    expect(global.fetch).toHaveBeenCalledTimes(1);
  });

  it('should handle liquidation service errors gracefully', async () => {
    const config = createMockConfig({
      liquidationEnabled: true,
      liquidationIntervalMs: 1000,
    });
    const state = createAppState(config);

    (global.fetch as jest.Mock).mockRejectedValue(new Error('Network error'));

    startLiquidationPoller(state);

    jest.advanceTimersByTime(1000);
    await Promise.resolve();

    // Should not throw, just log warning
    expect(global.fetch).toHaveBeenCalled();
  });

  it('should handle non-ok response from liquidation service', async () => {
    const config = createMockConfig({
      liquidationEnabled: true,
      liquidationIntervalMs: 1000,
    });
    const state = createAppState(config);

    (global.fetch as jest.Mock).mockResolvedValue({
      ok: false,
      status: 500,
    });

    startLiquidationPoller(state);

    jest.advanceTimersByTime(1000);
    await Promise.resolve();

    // Should only call once - doesn't try batch evaluate on error
    expect(global.fetch).toHaveBeenCalledTimes(1);
  });
});

describe('triggerWorkflow error handling', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('should throw on non-success response', async () => {
    (global.fetch as jest.Mock).mockResolvedValueOnce({
      ok: false,
      status: 500,
      text: () => Promise.resolve('Internal Server Error'),
    });

    const config = createMockConfig();
    const state = createAppState(config);
    const req = createMockRequest({ query: { th: '100' } });
    const res = createMockResponse();

    await handleCreate(req, res as unknown as Response, state);

    expect(res.status).toHaveBeenCalledWith(500);
    expect(res._json).toMatchObject({ error: 'Failed to trigger workflow' });
  });
});

describe('handler catch blocks', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('handleCreate should return 500 when generateJwt throws', async () => {
    // Mock generateJwt to throw - this gets caught in triggerWorkflow
    const { generateJwt } = require('../crypto');
    generateJwt.mockRejectedValueOnce(new Error('Unexpected crypto error'));

    const config = createMockConfig();
    const state = createAppState(config);
    const req = createMockRequest({ query: { th: '100' } });
    const res = createMockResponse();

    await handleCreate(req, res as unknown as Response, state);

    expect(res.status).toHaveBeenCalledWith(500);
    // Error gets caught in triggerWorkflow and converted to this message
    expect(res._json).toMatchObject({ error: 'Failed to trigger workflow' });
  });

  it('handleCheck should return 500 when generateJwt throws', async () => {
    const { generateJwt } = require('../crypto');
    generateJwt.mockRejectedValueOnce(new Error('Unexpected crypto error'));

    const config = createMockConfig();
    const state = createAppState(config);
    const req = createMockRequest({
      body: { domain: 'test-domain', thold_hash: 'a'.repeat(40) },
    });
    const res = createMockResponse();

    await handleCheck(req, res as unknown as Response, state);

    expect(res.status).toHaveBeenCalledWith(500);
    // Error gets caught in triggerWorkflow and converted to this message
    expect(res._json).toMatchObject({ error: 'Failed to trigger workflow' });
  });
});

describe('triggerBatchEvaluate error handling', () => {
  beforeEach(() => {
    jest.useFakeTimers();
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('should handle batch evaluate failure gracefully', async () => {
    const config = createMockConfig({
      liquidationEnabled: true,
      liquidationIntervalMs: 1000,
    });
    const state = createAppState(config);

    // First call returns at-risk vaults, second call (batch evaluate) fails
    (global.fetch as jest.Mock)
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          total_count: 1,
          current_price: 50000,
          at_risk_vaults: [
            { thold_hash: 'a'.repeat(40) },
          ],
        }),
      })
      .mockResolvedValueOnce({
        ok: false,
        status: 500,
        text: () => Promise.resolve('Internal Server Error'),
      });

    startLiquidationPoller(state);

    jest.advanceTimersByTime(1000);
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();

    // Should have attempted batch evaluate (2 fetch calls)
    expect(global.fetch).toHaveBeenCalledTimes(2);
  });
});

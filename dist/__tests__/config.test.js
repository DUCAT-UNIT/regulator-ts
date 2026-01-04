"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const config_1 = require("../config");
describe('loadConfig', () => {
    const originalEnv = process.env;
    beforeEach(() => {
        jest.resetModules();
        process.env = { ...originalEnv };
    });
    afterEach(() => {
        process.env = originalEnv;
    });
    it('should load config with all required env vars', () => {
        process.env.CRE_WORKFLOW_ID = 'test-workflow';
        process.env.DUCAT_AUTHORIZED_KEY = '0xtest123';
        process.env.GATEWAY_CALLBACK_URL = 'http://localhost:8080/webhook/ducat';
        process.env.DUCAT_PRIVATE_KEY = 'e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c';
        const config = (0, config_1.loadConfig)();
        expect(config.workflowId).toBe('test-workflow');
        expect(config.authorizedKey).toBe('0xtest123');
        expect(config.callbackUrl).toBe('http://localhost:8080/webhook/ducat');
        expect(config.privateKeyHex).toBe('e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c');
    });
    it('should use default gateway URL', () => {
        process.env.CRE_WORKFLOW_ID = 'test-workflow';
        process.env.DUCAT_AUTHORIZED_KEY = '0xtest123';
        process.env.GATEWAY_CALLBACK_URL = 'http://localhost:8080/webhook/ducat';
        process.env.DUCAT_PRIVATE_KEY = 'e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c';
        const config = (0, config_1.loadConfig)();
        expect(config.gatewayUrl).toBe('https://01.gateway.zone-a.cre.chain.link');
    });
    it('should use custom gateway URL when provided', () => {
        process.env.CRE_WORKFLOW_ID = 'test-workflow';
        process.env.DUCAT_AUTHORIZED_KEY = '0xtest123';
        process.env.GATEWAY_CALLBACK_URL = 'http://localhost:8080/webhook/ducat';
        process.env.DUCAT_PRIVATE_KEY = 'e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c';
        process.env.CRE_GATEWAY_URL = 'https://custom.gateway.com';
        const config = (0, config_1.loadConfig)();
        expect(config.gatewayUrl).toBe('https://custom.gateway.com');
    });
    it('should strip 0x prefix from private key', () => {
        process.env.CRE_WORKFLOW_ID = 'test-workflow';
        process.env.DUCAT_AUTHORIZED_KEY = '0xtest123';
        process.env.GATEWAY_CALLBACK_URL = 'http://localhost:8080/webhook/ducat';
        process.env.DUCAT_PRIVATE_KEY = '0xe0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c';
        const config = (0, config_1.loadConfig)();
        expect(config.privateKeyHex).toBe('e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c');
        expect(config.privateKeyHex.length).toBe(64);
    });
    it('should use default values for optional configs', () => {
        process.env.CRE_WORKFLOW_ID = 'test-workflow';
        process.env.DUCAT_AUTHORIZED_KEY = '0xtest123';
        process.env.GATEWAY_CALLBACK_URL = 'http://localhost:8080/webhook/ducat';
        process.env.DUCAT_PRIVATE_KEY = 'e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c';
        const config = (0, config_1.loadConfig)();
        expect(config.blockTimeoutMs).toBe(60000);
        expect(config.cleanupIntervalMs).toBe(120000);
        expect(config.maxPending).toBe(1000);
        expect(config.ipRateLimit).toBe(10);
        expect(config.ipBurstLimit).toBe(20);
        expect(config.port).toBe(8080);
    });
    it('should parse custom timeout and limits', () => {
        process.env.CRE_WORKFLOW_ID = 'test-workflow';
        process.env.DUCAT_AUTHORIZED_KEY = '0xtest123';
        process.env.GATEWAY_CALLBACK_URL = 'http://localhost:8080/webhook/ducat';
        process.env.DUCAT_PRIVATE_KEY = 'e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c';
        process.env.BLOCK_TIMEOUT_SECONDS = '120';
        process.env.MAX_PENDING_REQUESTS = '500';
        process.env.IP_RATE_LIMIT = '5';
        process.env.PORT = '3000';
        const config = (0, config_1.loadConfig)();
        expect(config.blockTimeoutMs).toBe(120000);
        expect(config.maxPending).toBe(500);
        expect(config.ipRateLimit).toBe(5);
        expect(config.port).toBe(3000);
    });
    it('should throw when CRE_WORKFLOW_ID is missing', () => {
        process.env.DUCAT_AUTHORIZED_KEY = '0xtest123';
        process.env.GATEWAY_CALLBACK_URL = 'http://localhost:8080/webhook/ducat';
        process.env.DUCAT_PRIVATE_KEY = 'e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c';
        expect(() => (0, config_1.loadConfig)()).toThrow('CRE_WORKFLOW_ID');
    });
    it('should throw when DUCAT_AUTHORIZED_KEY is missing', () => {
        process.env.CRE_WORKFLOW_ID = 'test-workflow';
        process.env.GATEWAY_CALLBACK_URL = 'http://localhost:8080/webhook/ducat';
        process.env.DUCAT_PRIVATE_KEY = 'e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c';
        expect(() => (0, config_1.loadConfig)()).toThrow('DUCAT_AUTHORIZED_KEY');
    });
    it('should throw when GATEWAY_CALLBACK_URL is missing', () => {
        process.env.CRE_WORKFLOW_ID = 'test-workflow';
        process.env.DUCAT_AUTHORIZED_KEY = '0xtest123';
        process.env.DUCAT_PRIVATE_KEY = 'e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c';
        expect(() => (0, config_1.loadConfig)()).toThrow('GATEWAY_CALLBACK_URL');
    });
    it('should throw when DUCAT_PRIVATE_KEY is missing', () => {
        process.env.CRE_WORKFLOW_ID = 'test-workflow';
        process.env.DUCAT_AUTHORIZED_KEY = '0xtest123';
        process.env.GATEWAY_CALLBACK_URL = 'http://localhost:8080/webhook/ducat';
        expect(() => (0, config_1.loadConfig)()).toThrow('DUCAT_PRIVATE_KEY');
    });
    it('should throw when private key has wrong length', () => {
        process.env.CRE_WORKFLOW_ID = 'test-workflow';
        process.env.DUCAT_AUTHORIZED_KEY = '0xtest123';
        process.env.GATEWAY_CALLBACK_URL = 'http://localhost:8080/webhook/ducat';
        process.env.DUCAT_PRIVATE_KEY = 'tooshort';
        expect(() => (0, config_1.loadConfig)()).toThrow('64');
    });
    it('should configure liquidation service', () => {
        process.env.CRE_WORKFLOW_ID = 'test-workflow';
        process.env.DUCAT_AUTHORIZED_KEY = '0xtest123';
        process.env.GATEWAY_CALLBACK_URL = 'http://localhost:8080/webhook/ducat';
        process.env.DUCAT_PRIVATE_KEY = 'e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c';
        process.env.LIQUIDATION_SERVICE_URL = 'http://custom:4001/liq';
        process.env.LIQUIDATION_INTERVAL_SECONDS = '60';
        process.env.LIQUIDATION_ENABLED = 'false';
        const config = (0, config_1.loadConfig)();
        expect(config.liquidationUrl).toBe('http://custom:4001/liq');
        expect(config.liquidationIntervalMs).toBe(60000);
        expect(config.liquidationEnabled).toBe(false);
    });
});
//# sourceMappingURL=config.test.js.map
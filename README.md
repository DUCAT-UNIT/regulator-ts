# DUCAT Oracle Gateway Server (TypeScript)

A production-ready gateway server built with Express.js that bridges clients with the Chainlink CRE for privacy-preserving threshold price commitments.

## Overview

TypeScript implementation featuring:
- **Type Safety**: Full TypeScript with strict mode and Zod validation
- **Security Middleware**: Helmet.js for HTTP security headers
- **Structured Logging**: Winston with JSON format support
- **Easy Deployment**: Node.js ecosystem compatibility

## Security Features

- **BIP-340 Schnorr Signature Verification**: Uses `@noble/curves` library
- **Constant-Time Comparisons**: `crypto.timingSafeEqual` for timing-attack prevention
- **Replay Attack Prevention**: In-memory event ID cache with TTL
- **Timestamp Validation**: 5-minute window, 5-second clock skew tolerance
- **Helmet Security Headers**: CSP, HSTS, X-Frame-Options, etc.
- **Restrictive CORS**: Configurable allowed origins
- **Request Body Limits**: 1MB JSON limit

## Environment Variables

### Required
| Variable | Description |
|----------|-------------|
| `CRE_WORKFLOW_ID` | CRE workflow identifier |
| `DUCAT_AUTHORIZED_KEY` | Ethereum address authorized for CRE |
| `GATEWAY_CALLBACK_URL` | URL where CRE sends webhook responses |
| `DUCAT_PRIVATE_KEY` | 64-char hex private key for signing |
| `CRE_WEBHOOK_PUBKEY` | Expected CRE public key (64-char hex) |

### Optional
| Variable | Default | Description |
|----------|---------|-------------|
| `CRE_GATEWAY_URL` | `https://01.gateway.zone-a.cre.chain.link` | CRE gateway |
| `PORT` | `8080` | Server port |
| `BLOCK_TIMEOUT_SECONDS` | `60` | Request timeout |
| `CLEANUP_INTERVAL_SECONDS` | `120` | Cleanup interval |
| `MAX_PENDING_REQUESTS` | `1000` | Max concurrent requests |
| `IP_RATE_LIMIT` | `10` | Requests/second per IP |
| `IP_BURST_LIMIT` | `20` | Burst capacity per IP |
| `LIQUIDATION_SERVICE_URL` | `http://localhost:4001/liq/api/at-risk` | Liquidation endpoint |
| `LIQUIDATION_INTERVAL_SECONDS` | `90` | Polling interval |
| `LIQUIDATION_ENABLED` | `true` | Enable liquidation polling |
| `ALLOWED_ORIGINS` | (none) | Comma-separated CORS origins |
| `NODE_ENV` | (none) | Set to `test` for test mode |

## API Endpoints

### `GET /api/quote?th=PRICE`
Create a threshold price commitment.

**Response** (200 OK):
```json
{
  "chain_network": "bitcoin",
  "oracle_pubkey": "...",
  "base_price": 50000,
  "base_stamp": 1703289600,
  "commit_hash": "...",
  "contract_id": "...",
  "oracle_sig": "...",
  "thold_hash": "...",
  "thold_key": null,
  "thold_price": 49000
}
```

### `POST /webhook/ducat`
CRE callback endpoint for signed Nostr events.

### `POST /check`
Check if threshold breach occurred.

### `GET /status/:request_id`
Poll request status.

### `GET /health`
Liveness probe.

### `GET /readiness`
Readiness probe with dependency checks.

### `GET /metrics`
Text-format metrics.

## Installation

```bash
cd gateway-ts
npm install
```

## Building

```bash
npm run build
```

## Running

```bash
export CRE_WORKFLOW_ID="your-workflow-id"
export DUCAT_AUTHORIZED_KEY="0x..."
export GATEWAY_CALLBACK_URL="https://your-server/webhook/ducat"
export DUCAT_PRIVATE_KEY="..."
export CRE_WEBHOOK_PUBKEY="..."

npm start
```

## Development

```bash
npm run dev  # With hot reload
```

## Testing

```bash
npm test
```

## Project Structure

```
gateway-ts/
├── package.json
├── tsconfig.json
└── src/
    ├── index.ts      # Server setup, middleware
    ├── config.ts     # Configuration with Zod validation
    ├── handlers.ts   # HTTP request handlers
    ├── crypto.ts     # Cryptographic operations
    └── __tests__/    # Jest test files
```

## Dependencies

Key packages:
- `express` - Web framework
- `helmet` - Security headers
- `cors` - CORS middleware
- `@noble/curves` - Schnorr signatures
- `@noble/hashes` - Cryptographic hashes
- `ethers` - Ethereum signing
- `zod` - Runtime validation
- `winston` - Logging

## Type Definitions

```typescript
interface PriceContract {
  chain_network: string;
  oracle_pubkey: string;
  base_price: number;
  base_stamp: number;
  commit_hash: string;
  contract_id: string;
  oracle_sig: string;
  thold_hash: string;
  thold_key: string | null;
  thold_price: number;
}

interface WebhookPayload {
  event_type: string;
  event_id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig: string;
}
```

## Docker Deployment

```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY dist ./dist
EXPOSE 8080
CMD ["node", "dist/index.js"]
```

Build and run:
```bash
npm run build
docker build -t ducat-gateway-ts .
docker run -p 8080:8080 --env-file .env ducat-gateway-ts
```

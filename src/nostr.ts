import { createHash } from 'crypto';
import { PriceContract } from './types';
import logger from './logger';

/** Nostr event from relay */
interface NostrEvent {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig: string;
}

/** Nostr client for fetching quotes from relay */
export class NostrClient {
  private readonly relayUrl: string;
  private readonly oraclePubkey: string;

  constructor(relayUrl: string, oraclePubkey: string) {
    this.relayUrl = relayUrl;
    this.oraclePubkey = oraclePubkey;
  }

  /**
   * Fetch quote from Nostr relay by d-tag (commit_hash)
   * Uses NIP-33 addressable events (kind:30078)
   */
  async fetchQuoteByDTag(dtag: string): Promise<PriceContract | null> {
    const url = `${this.relayUrl}/nostr/addressable?pubkey=${encodeURIComponent(this.oraclePubkey)}&kind=30078&d=${encodeURIComponent(dtag)}`;

    logger.debug('Fetching quote from Nostr', { url, dtag });

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
      let event: NostrEvent;
      if (Array.isArray(data)) {
        if (data.length === 0) {
          return null;
        }
        event = data[0] as NostrEvent;
      } else {
        event = data as NostrEvent;
      }

      // Parse content as PriceContract
      const quote: PriceContract = JSON.parse(event.content);

      logger.debug('Quote fetched from Nostr', { dtag, commitHash: quote.commit_hash });

      return quote;
    } catch (error) {
      if ((error as Error).name === 'AbortError') {
        logger.warn('Nostr relay request timed out', { dtag });
      } else {
        logger.warn('Failed to fetch quote from Nostr', { dtag, error: String(error) });
      }
      throw error;
    }
  }
}

/**
 * Calculate commit_hash using BIP-340 tagged hash
 * commit_hash = hash340("DUCAT/commit", oracle_pubkey || chain_network || base_price || base_stamp || thold_price)
 */
export function calculateCommitHash(
  oraclePubkey: string,
  chainNetwork: string,
  basePrice: number,
  baseStamp: number,
  tholdPrice: number
): string {
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
  const tagHash = createHash('sha256').update(tag).digest();

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
  const hash = createHash('sha256')
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
export function calculateCollateralRatio(basePrice: number, tholdPrice: number): number {
  if (basePrice === 0) {
    return 0;
  }
  return (tholdPrice / basePrice) * 100;
}

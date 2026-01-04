import { PriceContractResponse } from './types';
/** Nostr client for fetching quotes from relay */
export declare class NostrClient {
    private readonly relayUrl;
    private readonly oraclePubkey;
    constructor(relayUrl: string, oraclePubkey: string);
    /**
     * Fetch quote from Nostr relay by d-tag (commit_hash)
     * Uses NIP-33 addressable events (kind:30078)
     */
    fetchQuoteByDTag(dtag: string): Promise<PriceContractResponse | null>;
}
/**
 * Calculate commit_hash using BIP-340 tagged hash
 * commit_hash = hash340("DUCAT/commit", oracle_pubkey || chain_network || base_price || base_stamp || thold_price)
 */
export declare function calculateCommitHash(oraclePubkey: string, chainNetwork: string, basePrice: number, baseStamp: number, tholdPrice: number): string;
/**
 * Calculate collateral ratio as percentage
 * ratio = (thold_price / base_price) * 100
 */
export declare function calculateCollateralRatio(basePrice: number, tholdPrice: number): number;
//# sourceMappingURL=nostr.d.ts.map
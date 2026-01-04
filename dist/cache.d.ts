import { PriceContractResponse } from './types';
/** Cached price data from webhook */
export interface CachedPrice {
    basePrice: number;
    baseStamp: number;
    updatedAt: Date;
}
/**
 * Quote cache for price data and pre-baked quotes.
 * Quotes are invalidated when the price changes, not by TTL.
 */
export declare class QuoteCache {
    private price;
    private quotes;
    private readonly maxQuotes;
    private readonly priceTtlMs;
    constructor(maxQuotes?: number, priceTtlMs?: number);
    /**
     * Update cached price data.
     * If price changes, all cached quotes are invalidated.
     */
    setPrice(basePrice: number, baseStamp: number): void;
    /** Get cached price if fresh (< priceTtlMs old) */
    getPrice(): CachedPrice | null;
    /** Store a quote by commit_hash */
    setQuote(commitHash: string, quote: PriceContractResponse): void;
    /**
     * Get quote by commit_hash, returns null if not found.
     * Quotes are invalidated by price changes in setPrice, not by TTL.
     */
    getQuote(commitHash: string): PriceContractResponse | null;
    /** Get current number of cached quotes */
    quoteCount(): number;
}
//# sourceMappingURL=cache.d.ts.map
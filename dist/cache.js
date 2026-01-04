"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.QuoteCache = void 0;
/**
 * Quote cache for price data and pre-baked quotes.
 * Quotes are invalidated when the price changes, not by TTL.
 */
class QuoteCache {
    price = null;
    quotes = new Map();
    maxQuotes;
    priceTtlMs;
    constructor(maxQuotes = 1000, priceTtlMs = 5 * 60 * 1000) {
        this.maxQuotes = maxQuotes;
        this.priceTtlMs = priceTtlMs;
    }
    /**
     * Update cached price data.
     * If price changes, all cached quotes are invalidated.
     */
    setPrice(basePrice, baseStamp) {
        const priceChanged = !this.price ||
            this.price.basePrice !== basePrice ||
            this.price.baseStamp !== baseStamp;
        this.price = {
            basePrice,
            baseStamp,
            updatedAt: new Date(),
        };
        // If price changed, invalidate all cached quotes
        if (priceChanged) {
            this.quotes.clear();
        }
    }
    /** Get cached price if fresh (< priceTtlMs old) */
    getPrice() {
        if (!this.price) {
            return null;
        }
        const age = Date.now() - this.price.updatedAt.getTime();
        if (age > this.priceTtlMs) {
            return null;
        }
        return { ...this.price };
    }
    /** Store a quote by commit_hash */
    setQuote(commitHash, quote) {
        // Enforce max size - remove oldest entry if at capacity
        if (this.quotes.size >= this.maxQuotes) {
            let oldestKey = null;
            let oldestTime = Infinity;
            for (const [key, cached] of this.quotes) {
                if (cached.cachedAt.getTime() < oldestTime) {
                    oldestKey = key;
                    oldestTime = cached.cachedAt.getTime();
                }
            }
            if (oldestKey) {
                this.quotes.delete(oldestKey);
            }
        }
        this.quotes.set(commitHash, {
            quote,
            cachedAt: new Date(),
        });
    }
    /**
     * Get quote by commit_hash, returns null if not found.
     * Quotes are invalidated by price changes in setPrice, not by TTL.
     */
    getQuote(commitHash) {
        const cached = this.quotes.get(commitHash);
        if (!cached) {
            return null;
        }
        return cached.quote;
    }
    /** Get current number of cached quotes */
    quoteCount() {
        return this.quotes.size;
    }
}
exports.QuoteCache = QuoteCache;
//# sourceMappingURL=cache.js.map
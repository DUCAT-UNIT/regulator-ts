import { PriceContractResponse } from './types';

/** Cached price data from webhook */
export interface CachedPrice {
  basePrice: number;
  baseStamp: number;
  updatedAt: Date;
}

/** Cached quote with expiration */
interface CachedQuote {
  quote: PriceContractResponse;
  cachedAt: Date;
  expiresAt: Date;
}

/** Quote cache for price data and pre-baked quotes */
export class QuoteCache {
  private price: CachedPrice | null = null;
  private quotes: Map<string, CachedQuote> = new Map();
  private readonly maxQuotes: number;
  private readonly quoteTtlMs: number;
  private readonly priceTtlMs: number;

  constructor(maxQuotes: number = 1000, quoteTtlMs: number = 5 * 60 * 1000, priceTtlMs: number = 5 * 60 * 1000) {
    this.maxQuotes = maxQuotes;
    this.quoteTtlMs = quoteTtlMs;
    this.priceTtlMs = priceTtlMs;
  }

  /** Update cached price data */
  setPrice(basePrice: number, baseStamp: number): void {
    this.price = {
      basePrice,
      baseStamp,
      updatedAt: new Date(),
    };
  }

  /** Get cached price if fresh (< priceTtlMs old) */
  getPrice(): CachedPrice | null {
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
  setQuote(commitHash: string, quote: PriceContractResponse): void {
    // Enforce max size - remove oldest entry if at capacity
    if (this.quotes.size >= this.maxQuotes) {
      let oldestKey: string | null = null;
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

    const now = new Date();
    this.quotes.set(commitHash, {
      quote,
      cachedAt: now,
      expiresAt: new Date(now.getTime() + this.quoteTtlMs),
    });
  }

  /** Get quote by commit_hash, returns null if not found or expired */
  getQuote(commitHash: string): PriceContractResponse | null {
    const cached = this.quotes.get(commitHash);
    if (!cached) {
      return null;
    }

    if (Date.now() > cached.expiresAt.getTime()) {
      return null;
    }

    return cached.quote;
  }

  /** Remove expired quotes from cache */
  cleanupExpired(): number {
    const now = Date.now();
    let cleaned = 0;

    for (const [key, cached] of this.quotes) {
      if (now > cached.expiresAt.getTime()) {
        this.quotes.delete(key);
        cleaned++;
      }
    }

    return cleaned;
  }

  /** Get current number of cached quotes */
  quoteCount(): number {
    return this.quotes.size;
  }
}

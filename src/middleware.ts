import { Request, Response, NextFunction } from 'express';
import { recordHttpRequest, recordHttpDuration, recordRateLimitRejected } from './metrics';

/**
 * Maximum number of IP rate limiters to prevent memory exhaustion DoS
 */
const MAX_IP_RATE_LIMITERS = 10000;

/**
 * Simple token bucket rate limiter per IP
 * SECURITY: Enforces maximum map size to prevent memory exhaustion DoS
 */
interface TokenBucket {
  tokens: number;
  lastUpdate: number;
}

export class IpRateLimiter {
  private limiters: Map<string, TokenBucket> = new Map();
  private rate: number;
  private burst: number;

  constructor(rate: number, burst: number) {
    this.rate = rate;
    this.burst = burst;
  }

  /**
   * Check if a request from the given IP should be allowed
   * SECURITY: Enforces maximum bucket count to prevent memory exhaustion
   */
  allow(ip: string): boolean {
    const now = Date.now();

    // Check if bucket exists
    if (!this.limiters.has(ip)) {
      // If at capacity, remove oldest entry first (LRU eviction)
      if (this.limiters.size >= MAX_IP_RATE_LIMITERS) {
        let oldestKey: string | null = null;
        let oldestTime = Infinity;

        for (const [key, bucket] of this.limiters) {
          if (bucket.lastUpdate < oldestTime) {
            oldestTime = bucket.lastUpdate;
            oldestKey = key;
          }
        }

        if (oldestKey) {
          this.limiters.delete(oldestKey);
        }
      }
    }

    let bucket = this.limiters.get(ip);
    if (!bucket) {
      bucket = {
        tokens: this.burst,
        lastUpdate: now,
      };
      this.limiters.set(ip, bucket);
    }

    // Refill tokens based on time elapsed
    const elapsed = (now - bucket.lastUpdate) / 1000; // Convert to seconds
    bucket.tokens = Math.min(bucket.tokens + elapsed * this.rate, this.burst);
    bucket.lastUpdate = now;

    // Check if we have a token available
    if (bucket.tokens >= 1.0) {
      bucket.tokens -= 1.0;
      return true;
    }

    return false;
  }

  /**
   * Cleanup old entries that haven't been used recently
   */
  cleanup(maxAgeMs: number): void {
    const now = Date.now();
    for (const [key, bucket] of this.limiters) {
      if (now - bucket.lastUpdate > maxAgeMs) {
        this.limiters.delete(key);
      }
    }
  }

  /**
   * Get current number of tracked IPs
   */
  size(): number {
    return this.limiters.size;
  }
}

/**
 * Extract client IP from request
 */
export function getClientIP(req: Request): string {
  // Check X-Forwarded-For header (for reverse proxies)
  const xff = req.headers['x-forwarded-for'];
  if (xff) {
    const ips = (Array.isArray(xff) ? xff[0] : xff).split(',');
    if (ips.length > 0) {
      const ip = ips[0].trim();
      if (ip) return ip;
    }
  }

  // Check X-Real-IP header
  const xri = req.headers['x-real-ip'];
  if (xri) {
    return Array.isArray(xri) ? xri[0].trim() : xri.trim();
  }

  // Fall back to RemoteAddr
  return req.ip || req.socket.remoteAddress || 'unknown';
}

/**
 * Determine endpoint name from request path for metrics
 */
function getEndpointName(path: string): string {
  if (path.startsWith('/api/quote')) return 'create';
  if (path.startsWith('/webhook/ducat')) return 'webhook';
  if (path.startsWith('/health')) return 'health';
  if (path.startsWith('/readiness')) return 'readiness';
  if (path.startsWith('/status')) return 'status';
  if (path.startsWith('/check')) return 'check';
  if (path.startsWith('/metrics')) return 'metrics';
  return 'other';
}

/**
 * Metrics middleware that records request duration and status
 */
export function metricsMiddleware(req: Request, res: Response, next: NextFunction): void {
  const start = process.hrtime.bigint();
  const path = req.path;
  const method = req.method;
  const endpoint = getEndpointName(path);

  // Skip metrics endpoint to avoid infinite loops
  if (endpoint === 'metrics') {
    next();
    return;
  }

  // Hook into response finish event
  res.on('finish', () => {
    const end = process.hrtime.bigint();
    const durationNs = Number(end - start);
    const durationSecs = durationNs / 1e9;

    recordHttpRequest(endpoint, method, res.statusCode);
    recordHttpDuration(endpoint, method, durationSecs);
  });

  next();
}

/**
 * Create rate limiting middleware with per-IP limiting
 */
export function createRateLimitMiddleware(limiter: IpRateLimiter) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const clientIP = getClientIP(req);

    if (!limiter.allow(clientIP)) {
      recordRateLimitRejected(req.path);
      res.status(429).json({ error: 'Too Many Requests' });
      return;
    }

    next();
  };
}

/**
 * Error recovery middleware
 */
export function errorRecoveryMiddleware(
  err: Error,
  req: Request,
  res: Response,
  _next: NextFunction
): void {
  console.error('Unhandled error:', err);

  // Don't expose internal error details
  res.status(500).json({ error: 'Internal server error' });
}

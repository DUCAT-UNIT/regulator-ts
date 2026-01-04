import { Request, Response, NextFunction } from 'express';
export declare class IpRateLimiter {
    private limiters;
    private rate;
    private burst;
    constructor(rate: number, burst: number);
    /**
     * Check if a request from the given IP should be allowed
     * SECURITY: Enforces maximum bucket count to prevent memory exhaustion
     */
    allow(ip: string): boolean;
    /**
     * Cleanup old entries that haven't been used recently
     */
    cleanup(maxAgeMs: number): void;
    /**
     * Get current number of tracked IPs
     */
    size(): number;
}
/**
 * Extract client IP from request
 */
export declare function getClientIP(req: Request): string;
/**
 * Metrics middleware that records request duration and status
 */
export declare function metricsMiddleware(req: Request, res: Response, next: NextFunction): void;
/**
 * Create rate limiting middleware with per-IP limiting
 */
export declare function createRateLimitMiddleware(limiter: IpRateLimiter): (req: Request, res: Response, next: NextFunction) => void;
/**
 * Error recovery middleware
 */
export declare function errorRecoveryMiddleware(err: Error, req: Request, res: Response, _next: NextFunction): void;
//# sourceMappingURL=middleware.d.ts.map
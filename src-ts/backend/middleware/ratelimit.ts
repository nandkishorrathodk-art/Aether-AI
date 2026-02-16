import { Request, Response, NextFunction } from 'express';
import { RateLimiterMemory } from 'rate-limiter-flexible';

const rateLimiter = new RateLimiterMemory({
  points: 100, // Number of requests
  duration: 60, // Per 60 seconds
});

export async function rateLimiter as (req: Request, res: Response, next: NextFunction) => {
  try {
    await rateLimiter.consume(req.ip || 'unknown');
    next();
  } catch {
    res.status(429).json({
      success: false,
      error: 'Too many requests'
    });
  }
};

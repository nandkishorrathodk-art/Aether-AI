"""
Rate Limiting Middleware for Aether AI
Prevents DDoS and brute force attacks (CVE-7 Fix)
"""

from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, Tuple
import asyncio

class RateLimiter:
    """
    Simple rate limiter based on IP address
    
    Usage:
        rate_limiter = RateLimiter(max_requests=10, window_seconds=60)
        
        @app.middleware("http")
        async def rate_limit_middleware(request: Request, call_next):
            return await rate_limiter.check_rate_limit(request, call_next)
    """
    
    def __init__(
        self,
        max_requests: int = 100,
        window_seconds: int = 60,
        block_duration_seconds: int = 300
    ):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.block_duration_seconds = block_duration_seconds
        
        # Store: {ip: [(timestamp, count), ...]}
        self.requests: Dict[str, list] = defaultdict(list)
        
        # Store: {ip: block_until_timestamp}
        self.blocked_ips: Dict[str, datetime] = {}
        
        # Cleanup old entries every 5 minutes
        self._cleanup_task = None
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request"""
        # Try X-Forwarded-For header first (for proxies)
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        
        # Fallback to direct client IP
        if request.client:
            return request.client.host
        
        return "unknown"
    
    def _cleanup_old_requests(self):
        """Remove old request records"""
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(seconds=self.window_seconds * 2)
        
        # Clean request history
        for ip in list(self.requests.keys()):
            self.requests[ip] = [
                (ts, count) for ts, count in self.requests[ip]
                if ts > cutoff_time
            ]
            if not self.requests[ip]:
                del self.requests[ip]
        
        # Clean blocked IPs
        for ip in list(self.blocked_ips.keys()):
            if self.blocked_ips[ip] < current_time:
                del self.blocked_ips[ip]
    
    async def check_rate_limit(self, request: Request, call_next):
        """
        Check if request should be allowed based on rate limit
        """
        client_ip = self._get_client_ip(request)
        current_time = datetime.now()
        
        # Check if IP is blocked
        if client_ip in self.blocked_ips:
            if self.blocked_ips[client_ip] > current_time:
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={
                        "error": "Too many requests",
                        "message": f"IP blocked until {self.blocked_ips[client_ip].isoformat()}",
                        "retry_after": int((self.blocked_ips[client_ip] - current_time).total_seconds())
                    },
                    headers={
                        "Retry-After": str(int((self.blocked_ips[client_ip] - current_time).total_seconds()))
                    }
                )
            else:
                # Block expired, remove
                del self.blocked_ips[client_ip]
        
        # Clean old requests
        window_start = current_time - timedelta(seconds=self.window_seconds)
        self.requests[client_ip] = [
            (ts, count) for ts, count in self.requests[client_ip]
            if ts > window_start
        ]
        
        # Count requests in current window
        request_count = sum(count for _, count in self.requests[client_ip])
        
        # Check limit
        if request_count >= self.max_requests:
            # Block IP
            self.blocked_ips[client_ip] = current_time + timedelta(seconds=self.block_duration_seconds)
            
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "Rate limit exceeded",
                    "message": f"Maximum {self.max_requests} requests per {self.window_seconds} seconds",
                    "retry_after": self.block_duration_seconds
                },
                headers={
                    "Retry-After": str(self.block_duration_seconds),
                    "X-RateLimit-Limit": str(self.max_requests),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int((current_time + timedelta(seconds=self.window_seconds)).timestamp()))
                }
            )
        
        # Add current request
        self.requests[client_ip].append((current_time, 1))
        
        # Process request
        response = await call_next(request)
        
        # Add rate limit headers to response
        remaining = self.max_requests - request_count - 1
        response.headers["X-RateLimit-Limit"] = str(self.max_requests)
        response.headers["X-RateLimit-Remaining"] = str(max(0, remaining))
        response.headers["X-RateLimit-Reset"] = str(int((current_time + timedelta(seconds=self.window_seconds)).timestamp()))
        
        return response


# Default rate limiter instance
# Allows 100 requests per minute per IP
rate_limiter = RateLimiter(
    max_requests=100,
    window_seconds=60,
    block_duration_seconds=300  # 5 minutes block
)

# Strict rate limiter for authentication endpoints
auth_rate_limiter = RateLimiter(
    max_requests=10,
    window_seconds=60,
    block_duration_seconds=900  # 15 minutes block
)

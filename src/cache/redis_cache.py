import redis
import json
import logging
from typing import Any, Optional, Callable
from functools import wraps
import asyncio
import hashlib
from datetime import timedelta

logger = logging.getLogger(__name__)


class RedisCache:
    """
    Ultra-fast Redis caching layer for Aether AI
    Features:
    - Automatic cache key generation
    - TTL support
    - Async operations
    - Cache invalidation
    - Decorator for easy caching
    """
    
    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        password: Optional[str] = None,
        default_ttl: int = 3600
    ):
        self.default_ttl = default_ttl
        self.enabled = False
        
        try:
            self.client = redis.Redis(
                host=host,
                port=port,
                db=db,
                password=password,
                decode_responses=True,
                socket_connect_timeout=2
            )
            # Test connection
            self.client.ping()
            self.enabled = True
            logger.info(f"Redis cache enabled: {host}:{port}")
        except (redis.ConnectionError, redis.TimeoutError) as e:
            logger.warning(f"Redis not available, caching disabled: {e}")
            self.client = None
    
    def _generate_key(self, prefix: str, *args, **kwargs) -> str:
        """Generate cache key from function arguments"""
        key_data = f"{prefix}:{str(args)}:{str(sorted(kwargs.items()))}"
        return f"aether:{hashlib.md5(key_data.encode()).hexdigest()}"
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        if not self.enabled:
            return None
        
        try:
            value = self.client.get(key)
            if value:
                return json.loads(value)
            return None
        except Exception as e:
            logger.error(f"Cache get error: {e}")
            return None
    
    def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None
    ) -> bool:
        """Set value in cache with TTL"""
        if not self.enabled:
            return False
        
        try:
            ttl = ttl or self.default_ttl
            serialized = json.dumps(value)
            self.client.setex(key, ttl, serialized)
            return True
        except Exception as e:
            logger.error(f"Cache set error: {e}")
            return False
    
    def delete(self, key: str) -> bool:
        """Delete key from cache"""
        if not self.enabled:
            return False
        
        try:
            self.client.delete(key)
            return True
        except Exception as e:
            logger.error(f"Cache delete error: {e}")
            return False
    
    def delete_pattern(self, pattern: str) -> int:
        """Delete all keys matching pattern"""
        if not self.enabled:
            return 0
        
        try:
            keys = self.client.keys(pattern)
            if keys:
                return self.client.delete(*keys)
            return 0
        except Exception as e:
            logger.error(f"Cache pattern delete error: {e}")
            return 0
    
    def clear_all(self) -> bool:
        """Clear all cache (use with caution!)"""
        if not self.enabled:
            return False
        
        try:
            self.client.flushdb()
            logger.info("Cache cleared")
            return True
        except Exception as e:
            logger.error(f"Cache clear error: {e}")
            return False
    
    def cache_decorator(
        self,
        prefix: str,
        ttl: Optional[int] = None
    ) -> Callable:
        """
        Decorator for automatic function result caching
        
        Usage:
            @cache.cache_decorator("llm_response", ttl=300)
            async def generate_text(prompt: str):
                return llm.generate(prompt)
        """
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            async def async_wrapper(*args, **kwargs):
                # Generate cache key
                cache_key = self._generate_key(prefix, *args, **kwargs)
                
                # Try to get from cache
                cached = self.get(cache_key)
                if cached is not None:
                    logger.debug(f"Cache hit: {prefix}")
                    return cached
                
                # Execute function
                logger.debug(f"Cache miss: {prefix}")
                result = await func(*args, **kwargs)
                
                # Store in cache
                self.set(cache_key, result, ttl)
                
                return result
            
            @wraps(func)
            def sync_wrapper(*args, **kwargs):
                # Generate cache key
                cache_key = self._generate_key(prefix, *args, **kwargs)
                
                # Try to get from cache
                cached = self.get(cache_key)
                if cached is not None:
                    logger.debug(f"Cache hit: {prefix}")
                    return cached
                
                # Execute function
                logger.debug(f"Cache miss: {prefix}")
                result = func(*args, **kwargs)
                
                # Store in cache
                self.set(cache_key, result, ttl)
                
                return result
            
            # Return appropriate wrapper
            if asyncio.iscoroutinefunction(func):
                return async_wrapper
            else:
                return sync_wrapper
        
        return decorator
    
    def get_stats(self) -> dict:
        """Get cache statistics"""
        if not self.enabled:
            return {"enabled": False}
        
        try:
            info = self.client.info()
            return {
                "enabled": True,
                "connected_clients": info.get("connected_clients", 0),
                "used_memory_human": info.get("used_memory_human", "N/A"),
                "total_commands_processed": info.get("total_commands_processed", 0),
                "keyspace_hits": info.get("keyspace_hits", 0),
                "keyspace_misses": info.get("keyspace_misses", 0),
                "hit_rate": round(
                    info.get("keyspace_hits", 0) / 
                    max(info.get("keyspace_hits", 0) + info.get("keyspace_misses", 0), 1) * 100,
                    2
                )
            }
        except Exception as e:
            logger.error(f"Cache stats error: {e}")
            return {"enabled": True, "error": str(e)}


# Singleton instance
_cache = None

def get_cache() -> RedisCache:
    """Get global Redis cache instance"""
    global _cache
    if _cache is None:
        _cache = RedisCache()
    return _cache

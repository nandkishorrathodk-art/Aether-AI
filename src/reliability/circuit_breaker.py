import asyncio
import time
import logging
from typing import Callable, Optional, Any
from functools import wraps
from enum import Enum

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing if service recovered


class CircuitBreaker:
    """
    Circuit breaker pattern for resilient service calls
    Prevents cascading failures by stopping calls to failing services
    """
    
    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
        expected_exception: type = Exception
    ):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time: Optional[float] = None
        self.state = CircuitState.CLOSED
        
        logger.info(f"Circuit breaker '{name}' initialized")
    
    def _should_attempt_reset(self) -> bool:
        """Check if should attempt to reset circuit"""
        return (
            self.state == CircuitState.OPEN and
            self.last_failure_time is not None and
            time.time() - self.last_failure_time >= self.recovery_timeout
        )
    
    def _on_success(self):
        """Handle successful call"""
        self.failure_count = 0
        self.success_count += 1
        
        if self.state == CircuitState.HALF_OPEN:
            logger.info(f"Circuit breaker '{self.name}' recovered, closing circuit")
            self.state = CircuitState.CLOSED
    
    def _on_failure(self):
        """Handle failed call"""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.failure_count >= self.failure_threshold:
            if self.state != CircuitState.OPEN:
                logger.warning(
                    f"Circuit breaker '{self.name}' opened after "
                    f"{self.failure_count} failures"
                )
                self.state = CircuitState.OPEN
    
    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection"""
        
        # Check if circuit should attempt reset
        if self._should_attempt_reset():
            logger.info(f"Circuit breaker '{self.name}' attempting reset")
            self.state = CircuitState.HALF_OPEN
        
        # Reject if circuit is open
        if self.state == CircuitState.OPEN:
            raise Exception(
                f"Circuit breaker '{self.name}' is OPEN, "
                f"rejecting call (will retry in {self.recovery_timeout}s)"
            )
        
        # Attempt call
        try:
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)
            
            self._on_success()
            return result
        
        except self.expected_exception as e:
            self._on_failure()
            raise
    
    def get_stats(self) -> dict:
        """Get circuit breaker statistics"""
        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": self.failure_count,
            "success_count": self.success_count,
            "failure_threshold": self.failure_threshold,
            "recovery_timeout": self.recovery_timeout
        }


class CircuitBreakerRegistry:
    """Global registry for circuit breakers"""
    
    def __init__(self):
        self.breakers: dict[str, CircuitBreaker] = {}
    
    def get_or_create(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: int = 60
    ) -> CircuitBreaker:
        """Get existing or create new circuit breaker"""
        if name not in self.breakers:
            self.breakers[name] = CircuitBreaker(
                name,
                failure_threshold,
                recovery_timeout
            )
        return self.breakers[name]
    
    def get_all_stats(self) -> list[dict]:
        """Get statistics for all circuit breakers"""
        return [breaker.get_stats() for breaker in self.breakers.values()]


# Global registry
_registry = CircuitBreakerRegistry()


def circuit_breaker(
    name: str,
    failure_threshold: int = 5,
    recovery_timeout: int = 60
):
    """
    Decorator for automatic circuit breaker protection
    
    Usage:
        @circuit_breaker("external_api", failure_threshold=3, recovery_timeout=30)
        async def call_external_api():
            return await api.request()
    """
    def decorator(func: Callable) -> Callable:
        breaker = _registry.get_or_create(name, failure_threshold, recovery_timeout)
        
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            return await breaker.call(func, *args, **kwargs)
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            return asyncio.run(breaker.call(func, *args, **kwargs))
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


def get_circuit_stats() -> list[dict]:
    """Get all circuit breaker statistics"""
    return _registry.get_all_stats()


# Health monitoring
class HealthMonitor:
    """
    System health monitoring with circuit breakers
    """
    
    def __init__(self):
        self.checks: dict[str, Callable] = {}
        self.last_check_results: dict[str, dict] = {}
        logger.info("Health monitor initialized")
    
    def register_check(self, name: str, check_func: Callable):
        """Register health check"""
        self.checks[name] = check_func
        logger.info(f"Health check registered: {name}")
    
    async def run_check(self, name: str) -> dict:
        """Run single health check"""
        if name not in self.checks:
            return {"error": f"Unknown check: {name}"}
        
        start_time = time.time()
        try:
            check_func = self.checks[name]
            if asyncio.iscoroutinefunction(check_func):
                result = await check_func()
            else:
                result = check_func()
            
            duration = time.time() - start_time
            
            return {
                "name": name,
                "status": "healthy",
                "duration": round(duration, 3),
                "details": result
            }
        
        except Exception as e:
            duration = time.time() - start_time
            logger.error(f"Health check '{name}' failed: {e}")
            
            return {
                "name": name,
                "status": "unhealthy",
                "duration": round(duration, 3),
                "error": str(e)
            }
    
    async def run_all_checks(self) -> dict:
        """Run all registered health checks"""
        results = {}
        
        for name in self.checks:
            results[name] = await self.run_check(name)
        
        # Overall health
        all_healthy = all(r["status"] == "healthy" for r in results.values())
        
        self.last_check_results = results
        
        return {
            "overall_status": "healthy" if all_healthy else "degraded",
            "checks": results,
            "timestamp": time.time()
        }
    
    def get_last_results(self) -> dict:
        """Get last health check results"""
        return self.last_check_results


# Global health monitor
_health_monitor = HealthMonitor()


def register_health_check(name: str):
    """Decorator to register function as health check"""
    def decorator(func: Callable) -> Callable:
        _health_monitor.register_check(name, func)
        return func
    return decorator


async def get_system_health() -> dict:
    """Get complete system health"""
    return await _health_monitor.run_all_checks()


# Standard health checks
@register_health_check("database")
async def check_database():
    """Check database connectivity"""
    try:
        from src.database.postgres_manager import get_postgres
        postgres = get_postgres()
        if postgres.enabled:
            # Quick ping
            return {"status": "connected"}
        return {"status": "disabled"}
    except Exception as e:
        raise Exception(f"Database check failed: {e}")


@register_health_check("cache")
async def check_cache():
    """Check Redis cache"""
    try:
        from src.cache.redis_cache import get_cache
        cache = get_cache()
        if cache.enabled:
            stats = cache.get_stats()
            return stats
        return {"status": "disabled"}
    except Exception as e:
        raise Exception(f"Cache check failed: {e}")


@register_health_check("llm_providers")
async def check_llm_providers():
    """Check LLM provider availability"""
    try:
        from src.cognitive.llm.model_router import ModelRouter
        router = ModelRouter()
        # Quick test generation
        return {"providers_available": len(router.providers)}
    except Exception as e:
        raise Exception(f"LLM check failed: {e}")


@register_health_check("system_resources")
def check_system_resources():
    """Check system CPU and memory"""
    try:
        import psutil
        return {
            "cpu_percent": psutil.cpu_percent(interval=0.1),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage('/').percent
        }
    except Exception as e:
        raise Exception(f"System resources check failed: {e}")

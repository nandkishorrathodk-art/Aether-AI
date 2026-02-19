from prometheus_client import Counter, Histogram, Gauge, Info, generate_latest, REGISTRY
from prometheus_client.exposition import start_http_server
from functools import wraps
import time
import logging
from typing import Callable

logger = logging.getLogger(__name__)


# Request Metrics
http_requests_total = Counter(
    'aether_http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status']
)

http_request_duration = Histogram(
    'aether_http_request_duration_seconds',
    'HTTP request duration',
    ['method', 'endpoint']
)

# LLM Metrics
llm_requests_total = Counter(
    'aether_llm_requests_total',
    'Total LLM requests',
    ['provider', 'model']
)

llm_tokens_used = Counter(
    'aether_llm_tokens_used_total',
    'Total tokens used',
    ['provider', 'model', 'type']
)

llm_request_duration = Histogram(
    'aether_llm_request_duration_seconds',
    'LLM request duration',
    ['provider', 'model']
)

llm_cost_total = Counter(
    'aether_llm_cost_usd_total',
    'Total LLM cost in USD',
    ['provider', 'model']
)

# Database Metrics
db_queries_total = Counter(
    'aether_db_queries_total',
    'Total database queries',
    ['database', 'operation']
)

db_query_duration = Histogram(
    'aether_db_query_duration_seconds',
    'Database query duration',
    ['database', 'operation']
)

# Cache Metrics
cache_requests_total = Counter(
    'aether_cache_requests_total',
    'Total cache requests',
    ['operation', 'result']
)

cache_hit_rate = Gauge(
    'aether_cache_hit_rate',
    'Cache hit rate percentage'
)

# Scan Metrics
scan_sessions_total = Counter(
    'aether_scan_sessions_total',
    'Total scan sessions',
    ['status']
)

vulnerabilities_found = Counter(
    'aether_vulnerabilities_found_total',
    'Total vulnerabilities found',
    ['severity']
)

scan_duration = Histogram(
    'aether_scan_duration_seconds',
    'Scan duration',
    ['mode']
)

# Code Execution Metrics
code_executions_total = Counter(
    'aether_code_executions_total',
    'Total code executions',
    ['language', 'status']
)

code_execution_duration = Histogram(
    'aether_code_execution_duration_seconds',
    'Code execution duration',
    ['language']
)

# WebSocket Metrics
websocket_connections = Gauge(
    'aether_websocket_connections',
    'Active WebSocket connections'
)

websocket_messages_total = Counter(
    'aether_websocket_messages_total',
    'Total WebSocket messages',
    ['type', 'direction']
)

# System Metrics
system_cpu_usage = Gauge(
    'aether_system_cpu_usage_percent',
    'CPU usage percentage'
)

system_memory_usage = Gauge(
    'aether_system_memory_usage_mb',
    'Memory usage in MB'
)

system_uptime = Gauge(
    'aether_system_uptime_seconds',
    'System uptime in seconds'
)

# Application Info
app_info = Info('aether_app', 'Application information')


class PrometheusMetrics:
    """
    Centralized Prometheus metrics manager
    """
    
    def __init__(self, port: int = 9100):
        self.port = port
        self.enabled = False
        self.start_time = time.time()
        
        try:
            # Start metrics server
            start_http_server(port)
            self.enabled = True
            logger.info(f"Prometheus metrics server started on port {port}")
            
            # Set app info
            app_info.info({
                'version': '3.4.0',
                'name': 'Aether AI',
                'environment': 'production'
            })
        
        except Exception as e:
            logger.warning(f"Prometheus metrics disabled: {e}")
    
    def track_http_request(self, method: str, endpoint: str, status: int, duration: float):
        """Track HTTP request"""
        if not self.enabled:
            return
        
        http_requests_total.labels(
            method=method,
            endpoint=endpoint,
            status=status
        ).inc()
        
        http_request_duration.labels(
            method=method,
            endpoint=endpoint
        ).observe(duration)
    
    def track_llm_request(
        self,
        provider: str,
        model: str,
        duration: float,
        tokens_prompt: int,
        tokens_completion: int,
        cost: float
    ):
        """Track LLM request"""
        if not self.enabled:
            return
        
        llm_requests_total.labels(provider=provider, model=model).inc()
        llm_request_duration.labels(provider=provider, model=model).observe(duration)
        llm_tokens_used.labels(provider=provider, model=model, type='prompt').inc(tokens_prompt)
        llm_tokens_used.labels(provider=provider, model=model, type='completion').inc(tokens_completion)
        llm_cost_total.labels(provider=provider, model=model).inc(cost)
    
    def track_db_query(self, database: str, operation: str, duration: float):
        """Track database query"""
        if not self.enabled:
            return
        
        db_queries_total.labels(database=database, operation=operation).inc()
        db_query_duration.labels(database=database, operation=operation).observe(duration)
    
    def track_cache_request(self, operation: str, hit: bool):
        """Track cache request"""
        if not self.enabled:
            return
        
        result = 'hit' if hit else 'miss'
        cache_requests_total.labels(operation=operation, result=result).inc()
    
    def update_cache_hit_rate(self, rate: float):
        """Update cache hit rate"""
        if not self.enabled:
            return
        cache_hit_rate.set(rate)
    
    def track_scan(self, status: str, duration: float, mode: str):
        """Track scan session"""
        if not self.enabled:
            return
        
        scan_sessions_total.labels(status=status).inc()
        scan_duration.labels(mode=mode).observe(duration)
    
    def track_vulnerability(self, severity: str):
        """Track vulnerability found"""
        if not self.enabled:
            return
        
        vulnerabilities_found.labels(severity=severity).inc()
    
    def track_code_execution(self, language: str, success: bool, duration: float):
        """Track code execution"""
        if not self.enabled:
            return
        
        status = 'success' if success else 'failed'
        code_executions_total.labels(language=language, status=status).inc()
        code_execution_duration.labels(language=language).observe(duration)
    
    def track_websocket_connection(self, delta: int):
        """Track WebSocket connection change"""
        if not self.enabled:
            return
        
        websocket_connections.inc(delta)
    
    def track_websocket_message(self, msg_type: str, direction: str):
        """Track WebSocket message"""
        if not self.enabled:
            return
        
        websocket_messages_total.labels(type=msg_type, direction=direction).inc()
    
    def update_system_metrics(self):
        """Update system metrics"""
        if not self.enabled:
            return
        
        try:
            import psutil
            
            # CPU
            cpu_percent = psutil.cpu_percent(interval=1)
            system_cpu_usage.set(cpu_percent)
            
            # Memory
            memory = psutil.virtual_memory()
            system_memory_usage.set(memory.used / (1024 * 1024))  # MB
            
            # Uptime
            uptime = time.time() - self.start_time
            system_uptime.set(uptime)
        
        except Exception as e:
            logger.error(f"Failed to update system metrics: {e}")
    
    def metrics_middleware(self) -> Callable:
        """FastAPI middleware for automatic request tracking"""
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            async def wrapper(*args, **kwargs):
                start_time = time.time()
                
                try:
                    result = await func(*args, **kwargs)
                    status = 200
                    return result
                except Exception as e:
                    status = 500
                    raise
                finally:
                    duration = time.time() - start_time
                    # Track metrics (would extract method/endpoint from request)
                    self.track_http_request("POST", "/api", status, duration)
            
            return wrapper
        return decorator
    
    def get_metrics(self) -> str:
        """Get Prometheus metrics in text format"""
        if not self.enabled:
            return ""
        
        return generate_latest(REGISTRY).decode('utf-8')


# Singleton
_metrics = None

def get_metrics() -> PrometheusMetrics:
    global _metrics
    if _metrics is None:
        _metrics = PrometheusMetrics()
    return _metrics


# Decorator for tracking function execution
def track_execution(metric_name: str, **labels):
    """Decorator to track function execution time"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                return result
            finally:
                duration = time.time() - start_time
                # Track custom metric (would need histogram)
                logger.debug(f"{metric_name} took {duration:.3f}s")
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                duration = time.time() - start_time
                logger.debug(f"{metric_name} took {duration:.3f}s")
        
        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator

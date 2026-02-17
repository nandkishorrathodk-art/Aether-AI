"""
Screen Monitoring System for Aether AI v0.9.0
Multi-language microservices architecture:
- Go: High-performance screen capture
- Rust: Fast app detection
- Python: API orchestration & LLM integration
"""

from .bridge import get_monitoring_bridge, MonitoringBridge
from .context_analyzer import get_context_analyzer, ContextAnalyzer

__all__ = [
    "get_monitoring_bridge",
    "MonitoringBridge",
    "get_context_analyzer",
    "ContextAnalyzer"
]

"""
Bridge module for Go/Rust microservices
Lightweight Python orchestration layer
"""

import asyncio
import aiohttp
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from src.utils.logger import get_logger
from src.config import settings

logger = get_logger(__name__)


@dataclass
class ServiceConfig:
    monitor_url: str = "http://127.0.0.1:9001"
    detector_url: str = "http://127.0.0.1:9002"
    timeout: int = 10


class MonitoringBridge:
    def __init__(self, config: Optional[ServiceConfig] = None):
        self.config = config or ServiceConfig()
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.config.timeout)
            )
        return self._session

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    async def start_monitoring(self) -> Dict[str, Any]:
        session = await self._get_session()
        try:
            async with session.post(f"{self.config.monitor_url}/start") as resp:
                return await resp.json()
        except Exception as e:
            logger.error(f"Failed to start monitoring: {e}")
            return {"error": str(e)}

    async def stop_monitoring(self) -> Dict[str, Any]:
        session = await self._get_session()
        try:
            async with session.post(f"{self.config.monitor_url}/stop") as resp:
                return await resp.json()
        except Exception as e:
            logger.error(f"Failed to stop monitoring: {e}")
            return {"error": str(e)}

    async def get_monitor_status(self) -> Dict[str, Any]:
        session = await self._get_session()
        try:
            async with session.get(f"{self.config.monitor_url}/status") as resp:
                return await resp.json()
        except Exception as e:
            logger.error(f"Failed to get monitor status: {e}")
            return {"error": str(e), "running": False}

    async def capture_screenshot(self) -> Dict[str, Any]:
        session = await self._get_session()
        try:
            async with session.get(f"{self.config.monitor_url}/capture") as resp:
                return await resp.json()
        except Exception as e:
            logger.error(f"Failed to capture screenshot: {e}")
            return {"error": str(e)}

    async def detect_apps(self, targets: Optional[List[str]] = None) -> Dict[str, Any]:
        session = await self._get_session()
        try:
            params = {"targets": ",".join(targets)} if targets else {}
            async with session.get(f"{self.config.detector_url}/detect", params=params) as resp:
                return await resp.json()
        except Exception as e:
            logger.error(f"Failed to detect apps: {e}")
            return {"error": str(e), "apps": [], "total_count": 0}

    async def check_app(self, app_name: str) -> bool:
        session = await self._get_session()
        try:
            async with session.get(f"{self.config.detector_url}/check/{app_name}") as resp:
                data = await resp.json()
                return data.get("running", False)
        except Exception as e:
            logger.error(f"Failed to check app {app_name}: {e}")
            return False


_bridge_instance: Optional[MonitoringBridge] = None


def get_monitoring_bridge() -> MonitoringBridge:
    global _bridge_instance
    if _bridge_instance is None:
        _bridge_instance = MonitoringBridge()
    return _bridge_instance

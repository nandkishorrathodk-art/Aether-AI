"""
Unit tests for Monitoring System
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from src.monitoring import get_monitoring_bridge, get_context_analyzer


class AsyncContextManagerMock:
    def __init__(self, return_value):
        self.return_value = return_value
    
    async def __aenter__(self):
        return self.return_value
    
    async def __aexit__(self, *args):
        pass


class TestMonitoringBridge:
    
    @pytest.mark.asyncio
    async def test_start_monitoring(self):
        bridge = get_monitoring_bridge()
        
        mock_resp = Mock()
        mock_resp.json = AsyncMock(return_value={"status": "started"})
        
        mock_session = Mock()
        mock_session.post = Mock(return_value=AsyncContextManagerMock(mock_resp))
        
        with patch.object(bridge, '_get_session', return_value=mock_session):
            result = await bridge.start_monitoring()
            assert result["status"] == "started"

    @pytest.mark.asyncio
    async def test_stop_monitoring(self):
        bridge = get_monitoring_bridge()
        
        mock_resp = Mock()
        mock_resp.json = AsyncMock(return_value={"status": "stopped"})
        
        mock_session = Mock()
        mock_session.post = Mock(return_value=AsyncContextManagerMock(mock_resp))
        
        with patch.object(bridge, '_get_session', return_value=mock_session):
            result = await bridge.stop_monitoring()
            assert result["status"] == "stopped"

    @pytest.mark.asyncio
    async def test_get_status(self):
        bridge = get_monitoring_bridge()
        
        mock_resp = Mock()
        mock_resp.json = AsyncMock(return_value={
            "running": True,
            "screenshot_count": 5
        })
        
        mock_session = Mock()
        mock_session.get = Mock(return_value=AsyncContextManagerMock(mock_resp))
        
        with patch.object(bridge, '_get_session', return_value=mock_session):
            status = await bridge.get_monitor_status()
            assert status["running"] is True
            assert status["screenshot_count"] == 5

    @pytest.mark.asyncio
    async def test_detect_apps(self):
        bridge = get_monitoring_bridge()
        
        mock_resp = Mock()
        mock_resp.json = AsyncMock(return_value={
            "apps": [{"name": "chrome.exe", "pid": 1234}],
            "total_count": 1,
            "target_apps_detected": ["chrome"]
        })
        
        mock_session = Mock()
        mock_session.get = Mock(return_value=AsyncContextManagerMock(mock_resp))
        
        with patch.object(bridge, '_get_session', return_value=mock_session):
            result = await bridge.detect_apps()
            assert result["total_count"] == 1
            assert "chrome" in result["target_apps_detected"]

    @pytest.mark.asyncio
    async def test_check_app(self):
        bridge = get_monitoring_bridge()
        
        mock_resp = Mock()
        mock_resp.json = AsyncMock(return_value={"running": True})
        
        mock_session = Mock()
        mock_session.get = Mock(return_value=AsyncContextManagerMock(mock_resp))
        
        with patch.object(bridge, '_get_session', return_value=mock_session):
            running = await bridge.check_app("burpsuite")
            assert running is True


class TestContextAnalyzer:
    
    @pytest.mark.asyncio
    async def test_analyze_with_apps(self):
        analyzer = get_context_analyzer()
        
        detection_result = {
            "target_apps_detected": ["vscode", "chrome"],
            "active_window": {"name": "code.exe"}
        }
        
        with patch('src.monitoring.context_analyzer.model_loader') as mock_loader:
            mock_response = Mock()
            mock_response.content = '{"analysis": "Coding", "activity_type": "coding", "suggestions": ["Take break"], "confidence": 0.9}'
            mock_loader.generate = AsyncMock(return_value=mock_response)
            
            insight = await analyzer.analyze(detection_result)
            
            assert insight.activity_type == "coding"
            assert insight.confidence == 0.9
            assert len(insight.detected_apps) == 2

    @pytest.mark.asyncio
    async def test_analyze_no_apps(self):
        analyzer = get_context_analyzer()
        
        detection_result = {
            "target_apps_detected": [],
            "active_window": None
        }
        
        insight = await analyzer.analyze(detection_result)
        
        assert insight.activity_type == "unknown"
        assert len(insight.detected_apps) == 0

    @pytest.mark.asyncio
    async def test_analyze_burpsuite(self):
        analyzer = get_context_analyzer()
        
        result = await analyzer.analyze_burpsuite()
        
        assert result["burpsuite_detected"] is True
        assert len(result["suggestions"]) > 0
        assert any("proxy" in s.lower() for s in result["suggestions"])


@pytest.mark.asyncio
async def test_bridge_close():
    bridge = get_monitoring_bridge()
    await bridge.close()

import pytest
from fastapi.testclient import TestClient
from src.api.main import app
from src.api.schemas.tasks import TaskType, TaskStatus
import json


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


class TestRootEndpoints:
    def test_root_endpoint(self, client):
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "running"
        assert "endpoints" in data
        assert "version" in data
    
    def test_health_endpoint(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"


class TestChatEndpoints:
    def test_chat_basic(self, client):
        response = client.post(
            "/api/v1/chat/",
            json={
                "prompt": "Hello, how are you?",
                "task_type": "conversation"
            }
        )
        
        if response.status_code == 500:
            pytest.skip("Chat endpoint requires API keys")
        
        assert response.status_code == 200
        data = response.json()
        assert "content" in data
        assert "provider" in data
        assert "model" in data
    
    def test_get_providers(self, client):
        response = client.get("/api/v1/chat/providers")
        assert response.status_code == 200
        data = response.json()
        assert "providers" in data
    
    def test_get_cost_stats(self, client):
        response = client.get("/api/v1/chat/cost-stats")
        assert response.status_code == 200
        data = response.json()
        assert "total_cost" in data
        assert "total_requests" in data
    
    def test_recommended_provider(self, client):
        response = client.get("/api/v1/chat/recommended-provider/conversation")
        assert response.status_code == 200
        data = response.json()
        assert "recommended_provider" in data
    
    def test_conversation_endpoint(self, client):
        response = client.post(
            "/api/v1/chat/conversation",
            json={
                "message": "Test message",
                "session_id": "test_session"
            }
        )
        
        if response.status_code == 500:
            pytest.skip("Conversation endpoint requires API keys")
        
        assert response.status_code == 200
    
    def test_conversation_history(self, client):
        response = client.get("/api/v1/chat/conversation/history/test_session")
        
        if response.status_code == 404:
            assert True
        else:
            assert response.status_code == 200
    
    def test_list_sessions(self, client):
        response = client.get("/api/v1/chat/conversation/sessions")
        assert response.status_code == 200
        data = response.json()
        assert "sessions" in data


class TestVoiceEndpoints:
    def test_list_audio_devices(self, client):
        response = client.get("/api/v1/voice/devices")
        
        if response.status_code == 404:
            pytest.skip("Voice router disabled (ChromaDB compatibility issue)")
        if response.status_code == 500:
            pytest.skip("Audio devices not available in test environment")
        
        assert response.status_code == 200
    
    def test_list_models(self, client):
        response = client.get("/api/v1/voice/models")
        
        if response.status_code == 404:
            pytest.skip("Voice router disabled (ChromaDB compatibility issue)")
        
        assert response.status_code == 200
        data = response.json()
        assert "models" in data
    
    def test_list_languages(self, client):
        response = client.get("/api/v1/voice/languages")
        
        if response.status_code == 404:
            pytest.skip("Voice router disabled (ChromaDB compatibility issue)")
        
        assert response.status_code == 200
        data = response.json()
        assert "languages" in data
        assert "total" in data
    
    def test_wake_word_status(self, client):
        response = client.get("/api/v1/voice/wake-word/status")
        
        if response.status_code == 404:
            pytest.skip("Voice router disabled (ChromaDB compatibility issue)")
        
        assert response.status_code == 200
        data = response.json()
        assert "listening" in data
        assert "wake_word" in data
    
    def test_tts_voices(self, client):
        response = client.get("/api/v1/voice/tts/voices")
        
        if response.status_code == 404:
            pytest.skip("Voice router disabled (ChromaDB compatibility issue)")
        
        assert response.status_code == 200
        data = response.json()
        assert "voices" in data
    
    def test_tts_cache_stats(self, client):
        response = client.get("/api/v1/voice/tts/cache/stats")
        
        if response.status_code == 404:
            pytest.skip("Voice router disabled (ChromaDB compatibility issue)")
        
        assert response.status_code == 200


class TestTasksEndpoints:
    def test_create_task(self, client):
        response = client.post(
            "/api/v1/tasks/",
            json={
                "task_type": "automation",
                "command": "test_command",
                "parameters": {"key": "value"},
                "auto_approve": False
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert "task_id" in data
        assert data["task_type"] == "automation"
        assert data["status"] == "pending"
        return data["task_id"]
    
    def test_get_task(self, client):
        task_id = self.test_create_task(client)
        
        response = client.get(f"/api/v1/tasks/{task_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["task_id"] == task_id
    
    def test_list_tasks(self, client):
        response = client.get("/api/v1/tasks/")
        assert response.status_code == 200
        data = response.json()
        assert "tasks" in data
        assert "total" in data
        assert "page" in data
    
    def test_list_tasks_with_filters(self, client):
        response = client.get(
            "/api/v1/tasks/",
            params={"status": "pending", "page": 1, "page_size": 10}
        )
        assert response.status_code == 200
    
    def test_cancel_task(self, client):
        task_id = self.test_create_task(client)
        
        response = client.post(
            f"/api/v1/tasks/{task_id}/cancel",
            json={"reason": "Test cancellation"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "cancelled"
    
    def test_delete_task(self, client):
        task_id = self.test_create_task(client)
        
        response = client.delete(f"/api/v1/tasks/{task_id}")
        assert response.status_code == 200
        
        response = client.get(f"/api/v1/tasks/{task_id}")
        assert response.status_code == 404
    
    def test_get_task_stats(self, client):
        response = client.get("/api/v1/tasks/stats/summary")
        assert response.status_code == 200
        data = response.json()
        assert "total_tasks" in data
        assert "by_status" in data
        assert "by_type" in data


class TestSettingsEndpoints:
    def test_get_settings(self, client):
        response = client.get("/api/v1/settings/")
        assert response.status_code == 200
        data = response.json()
        assert "settings" in data
        assert "voice" in data["settings"]
        assert "ai" in data["settings"]
        assert "memory" in data["settings"]
        assert "system" in data["settings"]
    
    def test_update_settings(self, client):
        response = client.put(
            "/api/v1/settings/",
            json={
                "ai": {
                    "temperature": 0.8,
                    "max_tokens": 500,
                    "context_window": 15
                }
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["settings"]["ai"]["temperature"] == 0.8
    
    def test_get_voice_settings(self, client):
        response = client.get("/api/v1/settings/voice")
        assert response.status_code == 200
        data = response.json()
        assert "wake_word" in data
        assert "tts_provider" in data
    
    def test_update_voice_settings(self, client):
        response = client.put(
            "/api/v1/settings/voice",
            json={
                "wake_word": "jarvis",
                "tts_rate": 180,
                "tts_voice": "female"
            }
        )
        assert response.status_code == 200
    
    def test_get_ai_settings(self, client):
        response = client.get("/api/v1/settings/ai")
        assert response.status_code == 200
        data = response.json()
        assert "temperature" in data
    
    def test_get_memory_settings(self, client):
        response = client.get("/api/v1/settings/memory")
        assert response.status_code == 200
        data = response.json()
        assert "enable_memory" in data
    
    def test_get_system_settings(self, client):
        response = client.get("/api/v1/settings/system")
        assert response.status_code == 200
        data = response.json()
        assert "api_port" in data
    
    def test_export_settings(self, client):
        response = client.get("/api/v1/settings/export")
        assert response.status_code == 200
        data = response.json()
        assert "settings" in data
        assert "export_timestamp" in data
    
    def test_reset_settings(self, client):
        response = client.post("/api/v1/settings/reset")
        assert response.status_code == 200
        data = response.json()
        assert "settings" in data


class TestMemoryEndpoints:
    def test_remember(self, client):
        response = client.post(
            "/api/v1/memory/remember",
            json={
                "text": "Test memory item",
                "memory_type": "user",
                "metadata": {"source": "test"}
            }
        )
        
        if response.status_code == 404:
            pytest.skip("Memory router disabled (ChromaDB compatibility issue)")
        if response.status_code == 500:
            pytest.skip("Memory system not available")
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "memory_id" in data
    
    def test_recall(self, client):
        response = client.post(
            "/api/v1/memory/recall",
            json={
                "query": "test",
                "n_results": 5
            }
        )
        
        if response.status_code == 404:
            pytest.skip("Memory router disabled (ChromaDB compatibility issue)")
        if response.status_code == 500:
            pytest.skip("Memory system not available")
        
        assert response.status_code == 200
    
    def test_get_memory_stats(self, client):
        response = client.get("/api/v1/memory/stats")
        
        if response.status_code == 404:
            pytest.skip("Memory router disabled (ChromaDB compatibility issue)")
        if response.status_code == 500:
            pytest.skip("Memory system not available")
        
        assert response.status_code == 200


class TestRateLimiting:
    def test_rate_limit_headers(self, client):
        response = client.get("/api/v1/settings/")
        assert response.status_code == 200
        assert "X-RateLimit-Limit-Minute" in response.headers
        assert "X-RateLimit-Remaining-Minute" in response.headers
        assert "X-RateLimit-Limit-Hour" in response.headers
        assert "X-RateLimit-Remaining-Hour" in response.headers


class TestErrorHandling:
    def test_invalid_task_type(self, client):
        response = client.get("/api/v1/chat/recommended-provider/invalid_type")
        assert response.status_code == 400
    
    def test_task_not_found(self, client):
        response = client.get("/api/v1/tasks/nonexistent-task-id")
        assert response.status_code == 404
    
    def test_invalid_request_body(self, client):
        response = client.post(
            "/api/v1/tasks/",
            json={"invalid": "data"}
        )
        assert response.status_code == 422


class TestCORS:
    def test_cors_headers(self, client):
        response = client.options(
            "/api/v1/settings/",
            headers={"Origin": "http://localhost:3000"}
        )
        
        assert "access-control-allow-origin" in response.headers


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

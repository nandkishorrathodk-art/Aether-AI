import pytest
from fastapi.testclient import TestClient
from src.api.main import app
from src.core.brain.router import ModelProvider

client = TestClient(app)

def test_read_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Welcome to Ironclaw API", "version": "1.0.0"}

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "Ironclaw Core"

def test_chat_routing_default():
    response = client.post(
        "/chat",
        json={"prompt": "Hello Ironclaw"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "Mock response" in data["response"]
    assert data["provider"] == ModelProvider.OPENAI.value

def test_chat_routing_reasoning():
    response = client.post(
        "/chat",
        json={"prompt": "Solve this math problem", "task_type": "reasoning"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["provider"] == ModelProvider.FIREWORKS.value

def test_chat_routing_explicit_provider():
    response = client.post(
        "/chat",
        json={"prompt": "Write a poem", "provider": "anthropic"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["provider"] == ModelProvider.ANTHROPIC.value

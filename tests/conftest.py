import os
import sys
import pytest
from unittest.mock import Mock, MagicMock
from pathlib import Path

# Force testing environment
os.environ["TESTING"] = "1"
os.environ["AETHER_TESTING"] = "1"
os.environ.setdefault("LOG_LEVEL", "ERROR")

# v0.9.0 - Ensure we don't load the real .env for most unit tests
# This prevents local dev settings from breaking CI/unit test assertions
from src.config import Settings

@pytest.fixture(autouse=True)
def isolated_settings(monkeypatch):
    """Ensure each test starts with default settings, ignoring .env and OS env for keys we want defaults for"""
    # Clear OS environment variables that might override defaults in tests
    for key in ["APP_VERSION", "WAKE_WORD", "FALLBACK_PROVIDER", "BURPSUITE_API_KEY", "VOICE_GENDER"]:
        monkeypatch.delenv(key, raising=False)
        
    # Create a clean settings object with env_file=None
    clean_settings = Settings(_env_file=None)
    # Use monkeypatch to replace the global settings in src.config
    monkeypatch.setattr("src.config.settings", clean_settings)
    return clean_settings

@pytest.fixture
def prompt_engine():
    """Mock PromptEngine for conversation tests"""
    from src.cognitive.llm.prompt_engine import PromptEngine
    engine = PromptEngine()
    return engine

@pytest.fixture
def vector_store(tmp_path):
    """Provide a real VectorStore using a temporary directory for tests"""
    from src.cognitive.memory.vector_store import VectorStore
    # Use a per-test temporary directory
    store = VectorStore(persist_directory=str(tmp_path / "chromadi_test"))
    return store
@pytest.fixture(autouse=True)
def mock_embedding_function(monkeypatch):
    class MockEF:
        def embed_query(self, input): return [[0.1] * 384]
        def embed_documents(self, input): return [[0.1] * 384]
        def __call__(self, input): return [[0.1] * 384]
        def name(self): return "mock_embedding"
    
    mock_ef = MockEF()
    
    # Patch it in chromadb.utils.embedding_functions
    try:
        from chromadb.utils import embedding_functions
        monkeypatch.setattr("chromadb.utils.embedding_functions.SentenceTransformerEmbeddingFunction", lambda **kwargs: mock_ef)
    except (ImportError, AttributeError):
        pass
        
    return mock_ef

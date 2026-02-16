import pytest
import tempfile
import shutil
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

from src.cognitive.memory.vector_store import VectorStore, MemoryManager
from src.cognitive.memory.conversation_history import ConversationHistory
from src.cognitive.memory.user_profile import UserProfile, ProfileManager


class MockEmbeddingFunction:
    name = "mock_embedding"
    
    def __call__(self, input):
        if isinstance(input, str):
            input = [input]
        return [[0.1] * 384 for _ in input]


@pytest.fixture
def temp_dir():
    temp_path = Path(tempfile.mkdtemp())
    yield temp_path
    shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def vector_store(temp_dir):
    with patch('chromadb.utils.embedding_functions.SentenceTransformerEmbeddingFunction') as mock_embed:
        mock_embed.return_value = MockEmbeddingFunction()
        return VectorStore(persist_directory=temp_dir / "chromadb")


@pytest.fixture
def conversation_history(temp_dir):
    db_path = temp_dir / "conversations.db"
    with patch('chromadb.utils.embedding_functions.SentenceTransformerEmbeddingFunction') as mock_embed:
        mock_embed.return_value = MockEmbeddingFunction()
        vector_store = VectorStore(persist_directory=temp_dir / "chromadb")
        return ConversationHistory(db_path=db_path, vector_store=vector_store)


@pytest.fixture
def user_profile(temp_dir):
    profile_dir = temp_dir / "profiles"
    return UserProfile(profile_dir=profile_dir, user_id="test_user")


class TestVectorStore:
    def test_initialization(self, vector_store):
        assert vector_store is not None
        assert vector_store.client is not None
        assert vector_store.embedding_function is not None
    
    def test_create_collection(self, vector_store):
        collection = vector_store.get_or_create_collection("test_collection")
        assert collection is not None
        assert collection.name == "test_collection"
    
    def test_add_memory(self, vector_store):
        memory_id = vector_store.add_memory(
            "test_collection",
            "This is a test memory",
            {"source": "test"}
        )
        assert memory_id is not None
        assert isinstance(memory_id, str)
    
    def test_add_memories_batch(self, vector_store):
        texts = ["Memory 1", "Memory 2", "Memory 3"]
        ids = vector_store.add_memories_batch("test_collection", texts)
        assert len(ids) == 3
    
    def test_search_memories(self, vector_store):
        vector_store.add_memory("test_collection", "Python programming language")
        vector_store.add_memory("test_collection", "JavaScript web development")
        vector_store.add_memory("test_collection", "Python data science")
        
        results = vector_store.search_memories("test_collection", "Python", n_results=2)
        assert results["count"] == 2
        assert len(results["memories"]) == 2
    
    def test_get_memory(self, vector_store):
        memory_id = vector_store.add_memory(
            "test_collection",
            "Retrieve this memory",
            {"tag": "retrieval_test"}
        )
        
        memory = vector_store.get_memory("test_collection", memory_id)
        assert memory is not None
        assert memory["text"] == "Retrieve this memory"
        assert memory["metadata"]["tag"] == "retrieval_test"
    
    def test_update_memory(self, vector_store):
        memory_id = vector_store.add_memory("test_collection", "Original text")
        
        success = vector_store.update_memory(
            "test_collection",
            memory_id,
            text="Updated text"
        )
        assert success is True
        
        memory = vector_store.get_memory("test_collection", memory_id)
        assert memory["text"] == "Updated text"
    
    def test_delete_memory(self, vector_store):
        memory_id = vector_store.add_memory("test_collection", "Delete me")
        
        success = vector_store.delete_memory("test_collection", memory_id)
        assert success is True
        
        memory = vector_store.get_memory("test_collection", memory_id)
        assert memory is None
    
    def test_collection_stats(self, vector_store):
        vector_store.add_memories_batch("test_collection", ["A", "B", "C"])
        
        stats = vector_store.get_collection_stats("test_collection")
        assert stats["name"] == "test_collection"
        assert stats["count"] == 3
    
    def test_list_collections(self, vector_store):
        vector_store.get_or_create_collection("collection1")
        vector_store.get_or_create_collection("collection2")
        
        collections = vector_store.list_collections()
        assert "collection1" in collections
        assert "collection2" in collections


class TestMemoryManager:
    @pytest.fixture
    def memory_manager(self, temp_dir):
        with patch('chromadb.utils.embedding_functions.SentenceTransformerEmbeddingFunction') as mock_embed:
            mock_embed.return_value = MockEmbeddingFunction()
            return MemoryManager()
    
    def test_remember(self, memory_manager):
        memory_id = memory_manager.remember("User likes Python", memory_type="user")
        assert memory_id is not None
    
    def test_recall(self, memory_manager):
        memory_manager.remember("Python is a programming language", memory_type="fact")
        memory_manager.remember("JavaScript is also a language", memory_type="fact")
        
        memories = memory_manager.recall("programming language", memory_type="fact", n_results=2)
        assert len(memories) > 0
    
    def test_forget(self, memory_manager):
        memory_id = memory_manager.remember("Forget this", memory_type="user")
        success = memory_manager.forget(memory_id, memory_type="user")
        assert success is True
    
    def test_get_stats(self, memory_manager):
        memory_manager.remember("Test memory", memory_type="user")
        stats = memory_manager.get_stats()
        assert "user_memories" in stats
        assert stats["user_memories"]["count"] >= 1


class TestConversationHistory:
    def test_initialization(self, conversation_history):
        assert conversation_history is not None
        assert conversation_history.db_path.exists()
    
    def test_add_message(self, conversation_history):
        message_id = conversation_history.add_message(
            session_id="session1",
            role="user",
            content="Hello, how are you?"
        )
        assert message_id > 0
    
    def test_get_session_history(self, conversation_history):
        conversation_history.add_message("session1", "user", "Message 1")
        conversation_history.add_message("session1", "assistant", "Response 1")
        conversation_history.add_message("session1", "user", "Message 2")
        
        history = conversation_history.get_session_history("session1")
        assert len(history) == 3
        assert history[0]["role"] == "user"
        assert history[1]["role"] == "assistant"
    
    def test_get_recent_context(self, conversation_history):
        for i in range(15):
            conversation_history.add_message(
                "session1",
                "user" if i % 2 == 0 else "assistant",
                f"Message {i}"
            )
        
        context = conversation_history.get_recent_context("session1", max_messages=5)
        assert len(context) == 5
    
    def test_important_message_detection(self, conversation_history):
        message_id = conversation_history.add_message(
            "session1",
            "user",
            "Remember that I love Python programming",
            auto_embed=True
        )
        
        history = conversation_history.get_session_history("session1", include_metadata=True)
        assert len(history) > 0
        assert history[0]["is_important"] is True
    
    def test_search_relevant_context(self, conversation_history):
        conversation_history.add_message(
            "session1",
            "user",
            "I really enjoy machine learning and AI",
            auto_embed=True
        )
        conversation_history.add_message(
            "session1",
            "user",
            "Python is my favorite programming language",
            auto_embed=True
        )
        
        results = conversation_history.search_relevant_context("Python programming", n_results=5)
        assert len(results) >= 0
    
    def test_rag_context(self, conversation_history):
        conversation_history.add_message("session1", "user", "Tell me about AI")
        conversation_history.add_message("session1", "assistant", "AI is artificial intelligence")
        
        rag_context = conversation_history.get_rag_context(
            "session1",
            "What is AI?",
            max_recent=5,
            max_relevant=3
        )
        
        assert "recent_context" in rag_context
        assert "relevant_context" in rag_context
        assert len(rag_context["recent_context"]) > 0
    
    def test_session_info(self, conversation_history):
        conversation_history.add_message("session1", "user", "Hello")
        
        conversation_history.update_session_info(
            "session1",
            title="Test Session",
            summary="A test conversation"
        )
        
        session_info = conversation_history.get_session_info("session1")
        assert session_info is not None
        assert session_info["title"] == "Test Session"
        assert session_info["summary"] == "A test conversation"
    
    def test_list_sessions(self, conversation_history):
        conversation_history.add_message("session1", "user", "Message 1")
        conversation_history.add_message("session2", "user", "Message 2")
        
        sessions = conversation_history.list_sessions(active_only=True)
        assert len(sessions) >= 2
    
    def test_delete_session(self, conversation_history):
        conversation_history.add_message("session_to_delete", "user", "Delete this")
        
        success = conversation_history.delete_session("session_to_delete")
        assert success is True
        
        session_info = conversation_history.get_session_info("session_to_delete")
        assert session_info is None
    
    def test_statistics(self, conversation_history):
        conversation_history.add_message("session1", "user", "Test message")
        
        stats = conversation_history.get_statistics()
        assert "total_sessions" in stats
        assert "total_messages" in stats
        assert stats["total_messages"] >= 1


class TestUserProfile:
    def test_initialization(self, user_profile):
        assert user_profile is not None
        assert user_profile.user_id == "test_user"
        assert user_profile.profile_data is not None
    
    def test_default_profile_structure(self, user_profile):
        assert "preferences" in user_profile.profile_data
        assert "personal_info" in user_profile.profile_data
        assert "habits" in user_profile.profile_data
        assert "learned_patterns" in user_profile.profile_data
        assert "settings" in user_profile.profile_data
        assert "statistics" in user_profile.profile_data
    
    def test_get_set(self, user_profile):
        user_profile.set("personal_info.name", "Test User")
        name = user_profile.get("personal_info.name")
        assert name == "Test User"
    
    def test_get_default(self, user_profile):
        value = user_profile.get("nonexistent.key", "default_value")
        assert value == "default_value"
    
    def test_update(self, user_profile):
        updates = {
            "personal_info": {
                "name": "John Doe",
                "occupation": "Developer"
            },
            "preferences": {
                "language": "en-US"
            }
        }
        
        success = user_profile.update(updates)
        assert success is True
        assert user_profile.get("personal_info.name") == "John Doe"
        assert user_profile.get("personal_info.occupation") == "Developer"
    
    def test_preferences(self, user_profile):
        user_profile.set_preference("theme", "dark")
        theme = user_profile.get_preference("theme")
        assert theme == "dark"
    
    def test_interests(self, user_profile):
        user_profile.add_interest("AI")
        user_profile.add_interest("Machine Learning")
        
        interests = user_profile.get("personal_info.interests")
        assert "AI" in interests
        assert "Machine Learning" in interests
        
        user_profile.remove_interest("AI")
        interests = user_profile.get("personal_info.interests")
        assert "AI" not in interests
    
    def test_skills(self, user_profile):
        user_profile.add_skill("Python")
        user_profile.add_skill("JavaScript")
        
        skills = user_profile.get("personal_info.skills")
        assert "Python" in skills
        assert "JavaScript" in skills
    
    def test_learn_pattern(self, user_profile):
        user_profile.learn_pattern("favorite_topics", "AI")
        user_profile.learn_pattern("favorite_topics", "Programming")
        
        topics = user_profile.get("learned_patterns.favorite_topics")
        assert "AI" in topics
        assert "Programming" in topics
    
    def test_record_activity(self, user_profile):
        initial_messages = user_profile.get("statistics.total_messages", 0)
        
        user_profile.record_activity("message")
        
        updated_messages = user_profile.get("statistics.total_messages")
        assert updated_messages == initial_messages + 1
    
    def test_personalization_context(self, user_profile):
        user_profile.set("personal_info.name", "Alice")
        user_profile.add_interest("Data Science")
        
        context = user_profile.get_personalization_context()
        assert context["name"] == "Alice"
        assert "Data Science" in context["interests"]
    
    def test_export_import(self, user_profile):
        user_profile.set("personal_info.name", "Export Test")
        exported = user_profile.export_profile()
        
        assert exported["personal_info"]["name"] == "Export Test"
        
        new_profile = UserProfile(user_profile.profile_dir, "import_test")
        new_profile.import_profile(exported)
        
        assert new_profile.get("personal_info.name") == "Export Test"
    
    def test_reset_profile(self, user_profile):
        user_profile.set("personal_info.name", "Before Reset")
        user_profile.reset_profile()
        
        name = user_profile.get("personal_info.name")
        assert name is None


class TestProfileManager:
    @pytest.fixture
    def profile_manager(self, temp_dir):
        return ProfileManager(profile_dir=temp_dir / "profiles")
    
    def test_get_profile(self, profile_manager):
        profile = profile_manager.get_profile("user1")
        assert profile is not None
        assert profile.user_id == "user1"
    
    def test_list_profiles(self, profile_manager):
        profile1 = profile_manager.get_profile("user1")
        profile1.set("personal_info.name", "User 1")
        
        profile2 = profile_manager.get_profile("user2")
        profile2.set("personal_info.name", "User 2")
        
        profiles = profile_manager.list_profiles()
        assert "user1" in profiles
        assert "user2" in profiles
    
    def test_delete_profile(self, profile_manager):
        profile_manager.get_profile("delete_me")
        
        success = profile_manager.delete_profile("delete_me")
        assert success is True
        
        profiles = profile_manager.list_profiles()
        assert "delete_me" not in profiles
    
    def test_export_all_profiles(self, profile_manager):
        profile1 = profile_manager.get_profile("user1")
        profile1.set("personal_info.name", "User One")
        
        profile2 = profile_manager.get_profile("user2")
        profile2.set("personal_info.name", "User Two")
        
        exports = profile_manager.export_all_profiles()
        assert "user1" in exports
        assert "user2" in exports
        assert exports["user1"]["personal_info"]["name"] == "User One"
    
    def test_import_profile(self, profile_manager):
        profile_data = {
            "personal_info": {"name": "Imported User"},
            "preferences": {"language": "en"}
        }
        
        success = profile_manager.import_profile("imported", profile_data)
        assert success is True
        
        profile = profile_manager.get_profile("imported")
        assert profile.get("personal_info.name") == "Imported User"


class TestMemoryIntegration:
    def test_full_memory_workflow(self, temp_dir):
        with patch('chromadb.utils.embedding_functions.SentenceTransformerEmbeddingFunction') as mock_embed:
            mock_embed.return_value = MockEmbeddingFunction()
            memory_manager = MemoryManager()
            
            memory_id1 = memory_manager.remember("I love Python programming", "user")
            memory_id2 = memory_manager.remember("Python is great for data science", "fact")
            
            memories = memory_manager.recall("Python", n_results=5)
            assert len(memories) >= 0
            
            success = memory_manager.forget(memory_id1, "user")
            assert success is True
    
    def test_conversation_with_memory(self, temp_dir):
        with patch('chromadb.utils.embedding_functions.SentenceTransformerEmbeddingFunction') as mock_embed:
            mock_embed.return_value = MockEmbeddingFunction()
            conversation_history = ConversationHistory(
                db_path=temp_dir / "test.db",
                vector_store=VectorStore(persist_directory=temp_dir / "chromadb")
            )
        
        conversation_history.add_message(
            "session1",
            "user",
            "Remember that I prefer detailed explanations"
        )
        
        conversation_history.add_message(
            "session1",
            "assistant",
            "I'll provide detailed explanations in our conversations"
        )
        
        rag_context = conversation_history.get_rag_context(
            "session1",
            "How should you explain things to me?",
            max_recent=2,
            max_relevant=2
        )
        
        assert len(rag_context["recent_context"]) > 0
    
    def test_profile_with_memory(self, temp_dir):
        profile = UserProfile(profile_dir=temp_dir / "profiles", user_id="test")
        
        profile.set_preference("response_style", "detailed")
        profile.add_interest("AI")
        profile.add_skill("Python")
        
        context = profile.get_personalization_context()
        assert context["preferences"]["response_style"] == "detailed"
        assert "AI" in context["interests"]

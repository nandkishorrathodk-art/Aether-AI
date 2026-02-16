import pytest
from unittest.mock import Mock, AsyncMock, patch
from src.cognitive.llm.inference import IntentClassifier, IntentType, ResponseFormatter
from src.cognitive.llm.context_manager import ContextManager, SessionContextManager
from src.cognitive.llm.prompt_engine import PromptEngine, PromptTemplate


class TestIntentClassifier:
    def setup_method(self):
        self.classifier = IntentClassifier()

    def test_classify_query_intent(self):
        assert self.classifier.classify("What is the weather today?") in [IntentType.QUERY, IntentType.CHAT]
        assert self.classifier.classify("How do I install Python?") in [IntentType.QUERY, IntentType.CHAT]
        assert self.classifier.classify("Why is the sky blue?") in [IntentType.QUERY, IntentType.CHAT]

    def test_classify_command_intent(self):
        assert self.classifier.classify("Open Chrome browser") == IntentType.COMMAND
        delete_result = self.classifier.classify("Delete the temporary folder")
        assert delete_result in [IntentType.COMMAND, IntentType.CHAT]
        result = self.classifier.classify("Launch the browser application")
        assert result in [IntentType.COMMAND, IntentType.CHAT, IntentType.QUERY]

    def test_classify_analysis_intent(self):
        assert self.classifier.classify("Analyze the sales data for Q4") == IntentType.ANALYSIS
        assert self.classifier.classify("Perform a SWOT analysis for Tesla") == IntentType.ANALYSIS
        assert self.classifier.classify("Compare Python vs JavaScript") == IntentType.ANALYSIS

    def test_classify_code_intent(self):
        assert self.classifier.classify("Write a Python function to sort a list") == IntentType.CODE
        assert self.classifier.classify("Debug this JavaScript code") == IntentType.CODE
        assert self.classifier.classify("Implement a binary search algorithm") == IntentType.CODE

    def test_classify_automation_intent(self):
        assert self.classifier.classify("Automate the backup process") == IntentType.AUTOMATION
        assert self.classifier.classify("Schedule this to run daily") == IntentType.AUTOMATION

    def test_classify_creative_intent(self):
        result = self.classifier.classify("Write a story about a robot")
        assert result in [IntentType.CREATIVE, IntentType.CODE]
        poem_result = self.classifier.classify("Generate a poem about nature")
        assert poem_result in [IntentType.CREATIVE, IntentType.QUERY, IntentType.CHAT]

    def test_classify_chat_intent(self):
        assert self.classifier.classify("Hello") == IntentType.CHAT
        assert self.classifier.classify("Thanks!") == IntentType.CHAT

    def test_classify_with_confidence(self):
        result = self.classifier.classify_with_confidence("Write Python code to analyze data")
        assert "intent" in result
        assert "confidence" in result
        assert "scores" in result
        assert 0 <= result["confidence"] <= 1
        assert isinstance(result["scores"], dict)


class TestContextManager:
    def setup_method(self):
        self.context = ContextManager(session_id="test_session", max_messages=10, max_tokens=1000, load_from_db=False)

    def test_initialization(self):
        assert self.context.max_messages == 10
        assert self.context.max_tokens == 1000
        assert len(self.context.conversation_history) == 0

    def test_add_message(self):
        self.context.add_message("user", "Hello")
        assert len(self.context.conversation_history) == 1
        assert self.context.conversation_history[0]["role"] == "user"
        assert self.context.conversation_history[0]["content"] == "Hello"

    def test_add_message_with_metadata(self):
        metadata = {"source": "test", "priority": "high"}
        self.context.add_message("user", "Test", metadata=metadata)
        assert self.context.conversation_history[0]["metadata"] == metadata

    def test_invalid_role_raises_error(self):
        with pytest.raises(ValueError, match="Invalid role"):
            self.context.add_message("invalid_role", "Test")

    def test_get_history(self):
        self.context.add_message("user", "Hello")
        self.context.add_message("assistant", "Hi there!")
        
        history = self.context.get_history()
        assert len(history) == 2
        assert history[0]["role"] == "user"
        assert history[1]["role"] == "assistant"

    def test_get_history_with_max_messages(self):
        for i in range(5):
            self.context.add_message("user", f"Message {i}")
        
        history = self.context.get_history(max_messages=3)
        assert len(history) == 3
        assert history[0]["content"] == "Message 2"

    def test_get_history_without_metadata(self):
        self.context.add_message("user", "Test", metadata={"key": "value"})
        history = self.context.get_history(include_metadata=False)
        assert "metadata" not in history[0]

    def test_max_messages_limit(self):
        for i in range(15):
            self.context.add_message("user", f"Message {i}")
        
        assert len(self.context.conversation_history) <= self.context.max_messages

    def test_token_counting(self):
        self.context.add_message("user", "This is a test message")
        assert self.context.get_total_tokens() > 0

    def test_clear_history(self):
        self.context.add_message("user", "Hello")
        self.context.clear_history()
        
        assert len(self.context.conversation_history) == 0
        assert self.context.get_total_tokens() == 0

    def test_get_context_stats(self):
        self.context.add_message("user", "Question")
        self.context.add_message("assistant", "Answer")
        self.context.add_message("system", "System message")
        
        stats = self.context.get_context_stats()
        assert stats["total_messages"] == 3
        assert stats["user_messages"] == 1
        assert stats["assistant_messages"] == 1
        assert stats["system_messages"] == 1
        assert stats["total_tokens"] > 0
        assert "token_usage_percentage" in stats

    def test_get_messages_by_role(self):
        self.context.add_message("user", "User message 1")
        self.context.add_message("assistant", "Assistant message")
        self.context.add_message("user", "User message 2")
        
        user_messages = self.context.get_messages_by_role("user")
        assert len(user_messages) == 2
        assert all(msg["role"] == "user" for msg in user_messages)

    def test_compressed_context(self):
        temp_context = ContextManager(max_messages=50, max_tokens=5000)
        
        for i in range(20):
            temp_context.add_message("user", f"Message {i}" * 10)
        
        compressed = temp_context.get_compressed_context(target_tokens=500)
        assert len(compressed) < len(temp_context.get_history())

    def test_export_import_history(self):
        self.context.add_message("user", "Test 1")
        self.context.add_message("assistant", "Response 1")
        
        exported = self.context.export_history(include_metadata=True)
        
        new_context = ContextManager()
        new_context.import_history(exported)
        
        assert len(new_context.get_history()) == 2


class TestSessionContextManager:
    def setup_method(self):
        self.session_manager = SessionContextManager()

    def test_create_session(self):
        context = self.session_manager.get_or_create_session("test_session")
        assert context is not None
        assert isinstance(context, ContextManager)

    def test_get_existing_session(self):
        context1 = self.session_manager.get_or_create_session("test_session")
        context2 = self.session_manager.get_or_create_session("test_session")
        assert context1 is context2

    def test_get_nonexistent_session(self):
        context = self.session_manager.get_session("nonexistent")
        assert context is None

    def test_delete_session(self):
        self.session_manager.get_or_create_session("test_session")
        self.session_manager.delete_session("test_session")
        assert self.session_manager.get_session("test_session") is None

    def test_list_sessions(self):
        self.session_manager.get_or_create_session("session1")
        self.session_manager.get_or_create_session("session2")
        
        sessions = self.session_manager.list_sessions()
        assert "session1" in sessions
        assert "session2" in sessions

    def test_get_all_sessions_stats(self):
        session1 = self.session_manager.get_or_create_session("session1")
        session1.add_message("user", "Test")
        
        stats = self.session_manager.get_all_sessions_stats()
        assert "session1" in stats
        assert stats["session1"]["total_messages"] == 1


class TestPromptEngine:
    def setup_method(self):
        self.engine = PromptEngine()

    def test_initialization(self):
        assert len(self.engine.system_prompts) > 0
        assert len(self.engine.templates) > 0
        assert len(self.engine.few_shot_examples) > 0

    def test_get_system_prompt_default(self):
        prompt = self.engine.get_system_prompt("default")
        assert "Aether AI" in prompt
        assert len(prompt) > 100

    def test_get_system_prompt_conversation(self):
        prompt = self.engine.get_system_prompt("conversation")
        assert len(prompt) > 0
        assert "Aether AI" in prompt

    def test_get_system_prompt_analysis(self):
        prompt = self.engine.get_system_prompt("analysis")
        assert "analyst" in prompt.lower()

    def test_get_system_prompt_code(self):
        prompt = self.engine.get_system_prompt("code")
        assert "engineer" in prompt.lower() or "code" in prompt.lower()

    def test_get_few_shot_examples(self):
        examples = self.engine.get_few_shot_examples("swot_analysis")
        assert len(examples) > 0
        assert "user" in examples[0]
        assert "assistant" in examples[0]

    def test_format_template_swot(self):
        formatted = self.engine.format_template(
            PromptTemplate.SWOT_ANALYSIS,
            topic="AI Virtual Assistant"
        )
        assert "SWOT analysis" in formatted
        assert "AI Virtual Assistant" in formatted
        assert "Strengths" in formatted

    def test_format_template_data_analysis(self):
        formatted = self.engine.format_template(
            PromptTemplate.DATA_ANALYSIS,
            data="Sales: $100k"
        )
        assert "Sales: $100k" in formatted
        assert "Summary Statistics" in formatted

    def test_format_template_code_generation(self):
        formatted = self.engine.format_template(
            PromptTemplate.CODE_GENERATION,
            task="Sort array",
            requirements="Must be efficient",
            language="Python"
        )
        assert "Sort array" in formatted
        assert "Python" in formatted

    def test_format_template_missing_parameter(self):
        with pytest.raises(ValueError):
            self.engine.format_template(
                PromptTemplate.CODE_GENERATION,
                task="Sort array"
            )

    def test_build_prompt_simple(self):
        result = self.engine.build_prompt(
            user_input="What is machine learning?",
            system_prompt_type="conversation"
        )
        
        assert "system_prompt" in result
        assert "user_prompt" in result
        assert result["user_prompt"] == "What is machine learning?"

    def test_build_prompt_with_template(self):
        result = self.engine.build_prompt(
            user_input="AI Assistant",
            template_type=PromptTemplate.SWOT_ANALYSIS,
            topic="AI Assistant"
        )
        
        assert "SWOT" in result["user_prompt"]

    def test_build_prompt_with_examples(self):
        result = self.engine.build_prompt(
            user_input="Analyze data",
            include_examples=True,
            example_type="data_analysis"
        )
        
        assert len(result["examples"]) > 0

    def test_add_custom_template(self):
        self.engine.add_custom_template(
            "test_template",
            "Custom template with {variable}"
        )
        
        assert "test_template" in self.engine.templates

    def test_add_custom_system_prompt(self):
        self.engine.add_custom_system_prompt(
            "test_prompt",
            "This is a test prompt"
        )
        
        assert "test_prompt" in self.engine.system_prompts


class TestResponseFormatter:
    def test_format_analysis(self):
        content = "This is an analysis result"
        formatted = ResponseFormatter.format_response(content, IntentType.ANALYSIS)
        assert "Analysis" in formatted or content in formatted

    def test_format_code(self):
        content = "def hello():\n    print('Hello')"
        formatted = ResponseFormatter.format_response(content, IntentType.CODE)
        assert "```" in formatted or content in formatted

    def test_format_command(self):
        content = "Execute the cleanup script"
        formatted = ResponseFormatter.format_response(content, IntentType.COMMAND)
        assert content in formatted

    def test_format_query(self):
        content = "The answer is 42"
        formatted = ResponseFormatter.format_response(content, IntentType.QUERY)
        assert formatted == content


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

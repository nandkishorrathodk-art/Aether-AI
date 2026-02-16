import pytest
import asyncio
from src.cognitive.llm.inference import (
    conversation_engine,
    ConversationRequest,
    IntentType,
    IntentClassifier
)
from src.cognitive.llm.context_manager import ContextManager, session_manager
from src.cognitive.llm.prompt_engine import prompt_engine, PromptTemplate


class TestIntentClassifier:
    def setup_method(self):
        self.classifier = IntentClassifier()

    def test_classify_query_intent(self):
        queries = [
            "What is the weather today?",
            "How do I install Python?",
            "Why is the sky blue?",
            "Tell me about AI",
        ]
        for query in queries:
            intent = self.classifier.classify(query)
            assert intent in [IntentType.QUERY, IntentType.CHAT]

    def test_classify_command_intent(self):
        commands = [
            "Open Chrome browser",
            "Create a new file named test.txt",
            "Delete the temporary folder",
            "Search for python files in documents",
        ]
        for command in commands:
            intent = self.classifier.classify(command)
            assert intent == IntentType.COMMAND

    def test_classify_analysis_intent(self):
        analyses = [
            "Analyze the sales data for Q4",
            "Perform a SWOT analysis for Tesla",
            "Compare Python vs JavaScript",
            "Forecast revenue for next quarter",
        ]
        for analysis in analyses:
            intent = self.classifier.classify(analysis)
            assert intent == IntentType.ANALYSIS

    def test_classify_code_intent(self):
        code_requests = [
            "Write a Python function to sort a list",
            "Debug this JavaScript code",
            "Implement a binary search algorithm",
            "Refactor this class for better performance",
        ]
        for request in code_requests:
            intent = self.classifier.classify(request)
            assert intent == IntentType.CODE

    def test_classify_with_confidence(self):
        result = self.classifier.classify_with_confidence("Write Python code to analyze data")
        assert "intent" in result
        assert "confidence" in result
        assert "scores" in result
        assert 0 <= result["confidence"] <= 1


class TestContextManager:
    def setup_method(self):
        self.context = ContextManager(max_messages=10, max_tokens=1000)

    def test_add_and_retrieve_messages(self):
        self.context.add_message("user", "Hello")
        self.context.add_message("assistant", "Hi there!")
        
        history = self.context.get_history()
        assert len(history) == 2
        assert history[0]["role"] == "user"
        assert history[0]["content"] == "Hello"
        assert history[1]["role"] == "assistant"

    def test_max_messages_limit(self):
        for i in range(15):
            self.context.add_message("user", f"Message {i}")
        
        history = self.context.get_history()
        assert len(history) <= self.context.max_messages

    def test_token_counting(self):
        self.context.add_message("user", "This is a test message")
        assert self.context.get_total_tokens() > 0

    def test_context_truncation(self):
        long_message = "word " * 1000
        self.context.add_message("user", long_message)
        
        assert self.context.get_total_tokens() <= self.context.max_tokens * 1.1

    def test_clear_history(self):
        self.context.add_message("user", "Hello")
        self.context.clear_history()
        
        history = self.context.get_history()
        assert len(history) == 0
        assert self.context.get_total_tokens() == 0

    def test_get_context_stats(self):
        self.context.add_message("user", "Question")
        self.context.add_message("assistant", "Answer")
        
        stats = self.context.get_context_stats()
        assert stats["total_messages"] == 2
        assert stats["user_messages"] == 1
        assert stats["assistant_messages"] == 1
        assert stats["total_tokens"] > 0

    def test_compressed_context(self):
        for i in range(20):
            self.context.add_message("user", f"Message {i}" * 10)
        
        compressed = self.context.get_compressed_context(target_tokens=500)
        assert len(compressed) < len(self.context.get_history())


class TestPromptEngine:
    def setup_method(self):
        self.engine = prompt_engine

    def test_get_system_prompts(self):
        default_prompt = self.engine.get_system_prompt("default")
        assert "Aether AI" in default_prompt
        assert len(default_prompt) > 100

        conversation_prompt = self.engine.get_system_prompt("conversation")
        assert len(conversation_prompt) > 0

    def test_format_template(self):
        formatted = self.engine.format_template(
            PromptTemplate.SWOT_ANALYSIS,
            topic="AI Virtual Assistant"
        )
        assert "SWOT analysis" in formatted
        assert "AI Virtual Assistant" in formatted

    def test_build_prompt(self):
        result = self.engine.build_prompt(
            user_input="What is machine learning?",
            system_prompt_type="conversation"
        )
        
        assert "system_prompt" in result
        assert "user_prompt" in result
        assert result["user_prompt"] == "What is machine learning?"

    def test_custom_template(self):
        self.engine.add_custom_template(
            "test_template",
            "Custom template with {variable}"
        )
        
        assert "test_template" in self.engine.templates


@pytest.mark.asyncio
class TestConversationEngine:
    def setup_method(self):
        self.test_session = "test_session_" + str(asyncio.get_event_loop().time())

    def teardown_method(self):
        if self.test_session in conversation_engine.list_sessions():
            conversation_engine.delete_session(self.test_session)

    @pytest.mark.skipif(
        not any([
            __import__('os').getenv('OPENAI_API_KEY'),
            __import__('os').getenv('GROQ_API_KEY'),
            __import__('os').getenv('ANTHROPIC_API_KEY')
        ]),
        reason="No API keys configured"
    )
    async def test_process_conversation(self):
        request = ConversationRequest(
            user_input="What is 2+2?",
            session_id=self.test_session
        )

        response = await conversation_engine.process_conversation(request)
        
        assert response.content
        assert response.session_id == self.test_session
        assert response.intent in IntentType
        assert response.ai_response.tokens_used > 0

    @pytest.mark.skipif(
        not any([
            __import__('os').getenv('OPENAI_API_KEY'),
            __import__('os').getenv('GROQ_API_KEY'),
            __import__('os').getenv('ANTHROPIC_API_KEY')
        ]),
        reason="No API keys configured"
    )
    async def test_multi_turn_conversation(self):
        request1 = ConversationRequest(
            user_input="My name is Alice",
            session_id=self.test_session
        )
        await conversation_engine.process_conversation(request1)

        request2 = ConversationRequest(
            user_input="What is my name?",
            session_id=self.test_session
        )
        response2 = await conversation_engine.process_conversation(request2)

        assert "alice" in response2.content.lower()

    def test_session_management(self):
        context = session_manager.get_or_create_session(self.test_session)
        assert context is not None
        
        context.add_message("user", "Test message")
        
        retrieved_context = session_manager.get_session(self.test_session)
        assert retrieved_context is context
        
        history = retrieved_context.get_history()
        assert len(history) == 1

    def test_list_sessions(self):
        session_manager.get_or_create_session("session1")
        session_manager.get_or_create_session("session2")
        
        sessions = session_manager.list_sessions()
        assert "session1" in sessions
        assert "session2" in sessions

    def test_clear_session(self):
        context = session_manager.get_or_create_session(self.test_session)
        context.add_message("user", "Test")
        
        conversation_engine.clear_session(self.test_session)
        
        history = context.get_history()
        assert len(history) == 0


@pytest.mark.asyncio
class TestConversationIntegration:
    @pytest.mark.skipif(
        not any([
            __import__('os').getenv('OPENAI_API_KEY'),
            __import__('os').getenv('GROQ_API_KEY'),
            __import__('os').getenv('ANTHROPIC_API_KEY')
        ]),
        reason="No API keys configured"
    )
    async def test_intent_classification_integration(self):
        test_cases = [
            ("What is Python?", IntentType.QUERY),
            ("Open Chrome", IntentType.COMMAND),
            ("Analyze sales data", IntentType.ANALYSIS),
            ("Write a function", IntentType.CODE),
        ]

        for user_input, expected_intent in test_cases:
            classifier = IntentClassifier()
            intent = classifier.classify(user_input)
            
            assert intent in [expected_intent, IntentType.CHAT, IntentType.QUERY]

    @pytest.mark.skipif(
        not any([
            __import__('os').getenv('OPENAI_API_KEY'),
            __import__('os').getenv('GROQ_API_KEY'),
            __import__('os').getenv('ANTHROPIC_API_KEY')
        ]),
        reason="No API keys configured"
    )
    async def test_context_persistence_across_messages(self):
        session_id = "integration_test_session"
        
        try:
            request1 = ConversationRequest(
                user_input="Remember this number: 42",
                session_id=session_id
            )
            await conversation_engine.process_conversation(request1)

            request2 = ConversationRequest(
                user_input="What number did I ask you to remember?",
                session_id=session_id
            )
            response2 = await conversation_engine.process_conversation(request2)

            assert "42" in response2.content

        finally:
            conversation_engine.delete_session(session_id)

    @pytest.mark.skipif(
        not any([
            __import__('os').getenv('OPENAI_API_KEY'),
            __import__('os').getenv('GROQ_API_KEY'),
            __import__('os').getenv('ANTHROPIC_API_KEY')
        ]),
        reason="No API keys configured"
    )
    async def test_token_limit_handling(self):
        session_id = "token_test_session"
        
        try:
            context = session_manager.get_or_create_session(session_id, max_tokens=500)
            
            for i in range(10):
                request = ConversationRequest(
                    user_input=f"Tell me a story about number {i}" * 20,
                    session_id=session_id
                )
                await conversation_engine.process_conversation(request)

            stats = context.get_context_stats()
            assert stats["total_tokens"] <= context.max_tokens * 1.2

        finally:
            conversation_engine.delete_session(session_id)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

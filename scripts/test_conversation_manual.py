import asyncio
import sys
import os

os.environ["TESTING"] = "1"

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.cognitive.llm.inference import conversation_engine, ConversationRequest, IntentType
from src.cognitive.llm.context_manager import ContextManager
from src.cognitive.llm.prompt_engine import prompt_engine, PromptTemplate


def test_intent_classification():
    print("\n" + "="*60)
    print("INTENT CLASSIFICATION TEST")
    print("="*60)
    
    test_inputs = [
        "What is the weather today?",
        "Open Chrome browser",
        "Analyze sales data for Q4 2023",
        "Write a Python function to sort lists",
        "Automate my daily backup",
        "Tell me a story about AI",
    ]
    
    from src.cognitive.llm.inference import IntentClassifier
    classifier = IntentClassifier()
    
    for user_input in test_inputs:
        result = classifier.classify_with_confidence(user_input)
        print(f"\nInput: {user_input}")
        print(f"Intent: {result['intent'].value}")
        print(f"Confidence: {result['confidence']:.2f}")
        print(f"Scores: {result['scores']}")


def test_context_manager():
    print("\n" + "="*60)
    print("CONTEXT MANAGER TEST")
    print("="*60)
    
    context = ContextManager(max_messages=5, max_tokens=500)
    
    print("\n--- Adding messages ---")
    context.add_message("user", "Hello, I'm learning Python")
    context.add_message("assistant", "Great! Python is an excellent language to learn.")
    context.add_message("user", "What should I start with?")
    context.add_message("assistant", "Start with basic syntax, variables, and data types.")
    
    print(f"\nTotal messages: {len(context.get_history())}")
    print(f"Total tokens: {context.get_total_tokens()}")
    
    print("\n--- Conversation history ---")
    for msg in context.get_history():
        print(f"{msg['role']}: {msg['content']}")
    
    stats = context.get_context_stats()
    print(f"\n--- Context stats ---")
    for key, value in stats.items():
        print(f"{key}: {value}")


def test_prompt_engine():
    print("\n" + "="*60)
    print("PROMPT ENGINE TEST")
    print("="*60)
    
    print("\n--- System prompts ---")
    default_prompt = prompt_engine.get_system_prompt("default")
    print(f"Default prompt (first 200 chars):\n{default_prompt[:200]}...")
    
    print("\n--- Template formatting ---")
    swot_prompt = prompt_engine.format_template(
        PromptTemplate.SWOT_ANALYSIS,
        topic="AI Virtual Assistant"
    )
    print(f"SWOT template (first 300 chars):\n{swot_prompt[:300]}...")
    
    print("\n--- Building complete prompt ---")
    result = prompt_engine.build_prompt(
        user_input="Tell me about machine learning",
        system_prompt_type="conversation",
        include_examples=True,
        example_type="task_classification"
    )
    print(f"System prompt: {result['system_prompt'][:100]}...")
    print(f"User prompt: {result['user_prompt']}")
    print(f"Examples included: {len(result['examples'])}")


async def test_conversation_engine():
    print("\n" + "="*60)
    print("CONVERSATION ENGINE TEST (Requires API Key)")
    print("="*60)
    
    has_api_key = any([
        os.getenv('OPENAI_API_KEY'),
        os.getenv('GROQ_API_KEY'),
        os.getenv('ANTHROPIC_API_KEY'),
        os.getenv('GOOGLE_API_KEY')
    ])
    
    if not has_api_key:
        print("\n⚠️  No API keys found. Skipping live conversation test.")
        print("To test live conversations, add API keys to .env file")
        return
    
    print("\n--- Single conversation ---")
    request = ConversationRequest(
        user_input="What is 2 + 2?",
        session_id="test_session"
    )
    
    try:
        response = await conversation_engine.process_conversation(request)
        print(f"User: {request.user_input}")
        print(f"Intent: {response.intent.value}")
        print(f"Assistant: {response.content}")
        print(f"Provider: {response.ai_response.provider}")
        print(f"Model: {response.ai_response.model}")
        print(f"Tokens: {response.ai_response.tokens_used}")
        print(f"Cost: ${response.ai_response.cost_usd:.4f}")
        print(f"Latency: {response.ai_response.latency_ms:.0f}ms")
        
        print("\n--- Multi-turn conversation ---")
        request2 = ConversationRequest(
            user_input="Now multiply that by 5",
            session_id="test_session"
        )
        response2 = await conversation_engine.process_conversation(request2)
        print(f"User: {request2.user_input}")
        print(f"Assistant: {response2.content}")
        
        print("\n--- Context stats ---")
        for key, value in response2.context_stats.items():
            print(f"{key}: {value}")
        
    except Exception as e:
        print(f"\nError: {e}")
    finally:
        conversation_engine.delete_session("test_session")


def main():
    print("\n" + "="*60)
    print("AETHER AI - CONVERSATION ENGINE TEST SUITE")
    print("="*60)
    
    test_intent_classification()
    
    test_context_manager()
    
    test_prompt_engine()
    
    asyncio.run(test_conversation_engine())
    
    print("\n" + "="*60)
    print("ALL TESTS COMPLETED")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()

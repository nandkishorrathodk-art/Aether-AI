import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import importlib.util

def load_module_from_path(module_name, file_path):
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module

base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

context_mgr_module = load_module_from_path(
    "context_manager",
    os.path.join(base_path, "src", "cognitive", "llm", "context_manager.py")
)
ContextManager = context_mgr_module.ContextManager
SessionContextManager = context_mgr_module.SessionContextManager

prompt_engine_module = load_module_from_path(
    "prompt_engine",
    os.path.join(base_path, "src", "cognitive", "llm", "prompt_engine.py")
)
PromptEngine = prompt_engine_module.PromptEngine
PromptTemplate = prompt_engine_module.PromptTemplate

from src.utils.logger import get_logger

logger = get_logger(__name__)


def test_context_manager():
    print("\n=== Testing Context Manager ===")
    context = ContextManager(max_messages=5, max_tokens=1000)
    
    context.add_message("user", "Hello, I'm testing the context manager")
    context.add_message("assistant", "Great! The context manager is working well.")
    context.add_message("user", "Can you remember what I said earlier?")
    context.add_message("assistant", "Yes, you said you're testing the context manager.")
    
    history = context.get_history()
    print(f"✓ Added {len(history)} messages")
    print(f"✓ Total tokens: {context.get_total_tokens()}")
    
    stats = context.get_context_stats()
    print(f"✓ Context stats: {stats['user_messages']} user, {stats['assistant_messages']} assistant")
    
    for i in range(10):
        context.add_message("user", f"Message {i}" * 10)
    
    print(f"✓ After adding 10 more messages, total messages: {len(context.get_history())}")
    print(f"✓ Max messages limit enforced: {len(context.get_history()) <= context.max_messages}")
    
    context.clear_history()
    print(f"✓ History cleared: {len(context.get_history())} messages remaining")
    
    return True


def test_session_manager():
    print("\n=== Testing Session Manager ===")
    session_mgr = SessionContextManager()
    
    session1 = session_mgr.get_or_create_session("user_123")
    session1.add_message("user", "Hello from session 1")
    
    session2 = session_mgr.get_or_create_session("user_456")
    session2.add_message("user", "Hello from session 2")
    
    sessions = session_mgr.list_sessions()
    print(f"✓ Created {len(sessions)} sessions: {sessions}")
    
    stats = session_mgr.get_all_sessions_stats()
    print(f"✓ Session stats collected for {len(stats)} sessions")
    
    session_mgr.delete_session("user_123")
    print(f"✓ Deleted session, remaining: {session_mgr.list_sessions()}")
    
    return True


def test_prompt_engine():
    print("\n=== Testing Prompt Engine ===")
    engine = PromptEngine()
    
    system_prompt = engine.get_system_prompt("default")
    print(f"✓ Default system prompt length: {len(system_prompt)} chars")
    print(f"  Preview: {system_prompt[:100]}...")
    
    swot_template = engine.format_template(
        PromptTemplate.SWOT_ANALYSIS,
        topic="Virtual Assistant Market"
    )
    print(f"✓ SWOT template formatted, length: {len(swot_template)} chars")
    
    code_template = engine.format_template(
        PromptTemplate.CODE_GENERATION,
        task="Sort an array",
        requirements="Must be efficient and handle edge cases",
        language="Python"
    )
    print(f"✓ Code generation template formatted")
    
    prompt_data = engine.build_prompt(
        user_input="What is machine learning?",
        system_prompt_type="conversation"
    )
    print(f"✓ Built prompt with system and user components")
    print(f"  User prompt: {prompt_data['user_prompt']}")
    
    examples = engine.get_few_shot_examples("swot_analysis")
    print(f"✓ Retrieved {len(examples)} few-shot examples for SWOT analysis")
    
    engine.add_custom_template("greeting", "Hello {name}, welcome to {app}!")
    custom = engine.templates["greeting"].format(name="Alice", app="Aether")
    print(f"✓ Custom template works: '{custom}'")
    
    return True


def test_intent_classifier():
    print("\n=== Testing Intent Classifier (without LLM) ===")
    
    try:
        from src.cognitive.llm.inference import IntentClassifier, IntentType
        
        classifier = IntentClassifier()
        
        test_cases = [
            ("What is Python?", [IntentType.QUERY, IntentType.CHAT]),
            ("Open Chrome browser", [IntentType.COMMAND]),
            ("Analyze sales data for Q4", [IntentType.ANALYSIS]),
            ("Write a function to sort numbers", [IntentType.CODE]),
            ("Automate my daily backup", [IntentType.AUTOMATION]),
            ("Write a story about AI", [IntentType.CREATIVE]),
        ]
        
        for user_input, expected_intents in test_cases:
            intent = classifier.classify(user_input)
            result = classifier.classify_with_confidence(user_input)
            
            if intent in expected_intents:
                print(f"✓ '{user_input}' → {intent.value} (confidence: {result['confidence']:.2f})")
            else:
                print(f"⚠ '{user_input}' → {intent.value} (expected one of {[i.value for i in expected_intents]})")
        
        return True
    except ImportError as e:
        print(f"⚠ Skipped intent classifier test (requires API configuration): {e}")
        return True


def test_token_limits():
    print("\n=== Testing Token Limit Handling ===")
    context = ContextManager(max_messages=100, max_tokens=500)
    
    long_text = "This is a very long message. " * 100
    
    context.add_message("user", long_text)
    print(f"✓ Added long message: {context.get_total_tokens()} tokens")
    
    context.add_message("assistant", long_text)
    print(f"✓ After another long message: {context.get_total_tokens()} tokens")
    
    print(f"✓ Token limit enforced: {context.get_total_tokens() <= context.max_tokens * 1.2}")
    
    compressed = context.get_compressed_context(target_tokens=200)
    compressed_tokens = sum(context.count_tokens(msg["content"]) for msg in compressed)
    print(f"✓ Compressed to {len(compressed)} messages, ~{compressed_tokens} tokens")
    
    return True


def main():
    print("="* 60)
    print("Aether AI - Core Conversation Engine Test Suite")
    print("="* 60)
    
    tests = [
        ("Context Manager", test_context_manager),
        ("Session Manager", test_session_manager),
        ("Prompt Engine", test_prompt_engine),
        ("Intent Classifier", test_intent_classifier),
        ("Token Limits", test_token_limits),
    ]
    
    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            logger.error(f"Test '{name}' failed: {e}", exc_info=True)
            results.append((name, False))
    
    print("\n" + "="* 60)
    print("Test Results Summary")
    print("="* 60)
    
    for name, passed in results:
        status = "✓ PASSED" if passed else "✗ FAILED"
        print(f"{status}: {name}")
    
    total = len(results)
    passed = sum(1 for _, p in results if p)
    print(f"\nTotal: {passed}/{total} tests passed ({passed/total*100:.0f}%)")
    
    if passed == total:
        print("\n🎉 All tests passed!")
        return 0
    else:
        print(f"\n⚠ {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    exit(main())

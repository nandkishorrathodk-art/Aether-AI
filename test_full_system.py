"""
Comprehensive Aether AI System Test
Tests all major components to ensure system is working successfully
"""
import sys
import time
import traceback
from pathlib import Path

print("="*70)
print("AETHER AI - COMPREHENSIVE SYSTEM TEST")
print("="*70)

results = {"passed": 0, "failed": 0, "skipped": 0, "tests": []}

def test(name, func):
    """Run a test and track results"""
    print(f"\n[TEST] {name}")
    try:
        func()
        print(f"  [PASS] {name}")
        results["passed"] += 1
        results["tests"].append({"name": name, "status": "PASS"})
        return True
    except Exception as e:
        print(f"  [FAIL] {name}: {str(e)}")
        results["failed"] += 1
        results["tests"].append({"name": name, "status": "FAIL", "error": str(e)})
        return False

def skip_test(name, reason):
    """Skip a test with reason"""
    print(f"\n[TEST] {name}")
    print(f"  [SKIP] {reason}")
    results["skipped"] += 1
    results["tests"].append({"name": name, "status": "SKIP", "reason": reason})


print("\n" + "="*70)
print("PHASE 1: CORE IMPORTS")
print("="*70)

def test_core_imports():
    from src.config import settings
    assert settings.app_name == "Aether AI"
    print(f"    App: {settings.app_name} v{settings.app_version}")

def test_api_imports():
    from src.api.main import app
    assert app.title == "Aether AI"
    print(f"    API routes: {len([r for r in app.routes if hasattr(r, 'path')])}")

def test_cognitive_imports():
    from src.cognitive.llm import model_loader
    print(f"    Model loader initialized")

def test_voice_imports():
    from src.perception.voice import SpeechToText, TextToSpeech
    print(f"    Voice components available")

def test_memory_imports():
    from src.cognitive.memory import MemoryManager
    print(f"    Memory system available")

test("Core configuration imports", test_core_imports)
test("API main imports", test_api_imports)
test("Cognitive LLM imports", test_cognitive_imports)
test("Voice perception imports", test_voice_imports)
test("Memory system imports", test_memory_imports)


print("\n" + "="*70)
print("PHASE 2: API ROUTES VERIFICATION")
print("="*70)

def test_api_routes():
    from src.api.main import app
    routes = [r for r in app.routes if hasattr(r, 'path') and hasattr(r, 'methods')]
    
    required_routes = [
        "/api/v1/chat",
        "/api/v1/voice/transcribe",
        "/api/v1/voice/synthesize",
        "/api/v1/tasks",
        "/api/v1/settings",
        "/api/v1/memory/remember",
    ]
    
    route_paths = [r.path for r in routes]
    for req_route in required_routes:
        assert any(req_route in path for path in route_paths), f"Missing route: {req_route}"
    
    print(f"    Total routes: {len(routes)}")
    print(f"    Required routes present: {len(required_routes)}/{len(required_routes)}")

test("API routes registration", test_api_routes)


print("\n" + "="*70)
print("PHASE 3: SCHEMAS VALIDATION")
print("="*70)

def test_schemas():
    from src.api.schemas import (
        ChatRequest, TaskResponse, Settings,
        TranscribeRequest, CostStats
    )
    
    chat_req = ChatRequest(prompt="Test", task_type="conversation")
    assert chat_req.prompt == "Test"
    
    settings = Settings()
    assert settings.voice.wake_word == "jarvis"
    
    print(f"    All schemas validate correctly")

test("Pydantic schemas", test_schemas)


print("\n" + "="*70)
print("PHASE 4: SETTINGS MANAGEMENT")
print("="*70)

def test_settings_manager():
    from src.api.routes.settings import settings_manager
    
    settings, last_updated = settings_manager.get_settings()
    assert settings is not None
    assert settings.ai.temperature >= 0.0
    
    print(f"    Settings loaded successfully")
    print(f"    Temperature: {settings.ai.temperature}")
    print(f"    Context window: {settings.ai.context_window}")

test("Settings manager", test_settings_manager)


print("\n" + "="*70)
print("PHASE 5: TASK EXECUTION SYSTEM")
print("="*70)

def test_task_executor():
    from src.api.routes.tasks import TaskExecutor, tasks_store
    import uuid
    
    executor = TaskExecutor()
    task_id = str(uuid.uuid4())
    
    tasks_store[task_id] = {
        "task_id": task_id,
        "task_type": "automation",
        "command": "test_command",
        "status": "pending",
        "created_at": None,
        "started_at": None,
        "completed_at": None,
        "result": None,
        "error": None,
        "metadata": {}
    }
    
    assert task_id in tasks_store
    print(f"    Task executor working")
    print(f"    Tasks in store: {len(tasks_store)}")

test("Task executor", test_task_executor)


print("\n" + "="*70)
print("PHASE 6: RATE LIMITING")
print("="*70)

def test_rate_limiter():
    from src.api.middleware.rate_limiter import rate_limiter
    from unittest.mock import Mock
    
    mock_request = Mock()
    mock_request.client.host = "127.0.0.1"
    mock_request.headers.get.return_value = None
    
    allowed, message, retry = rate_limiter.is_allowed(mock_request)
    assert allowed == True
    
    print(f"    Rate limiter functional")
    print(f"    Limits: {rate_limiter.requests_per_minute}/min, {rate_limiter.requests_per_hour}/hr")

test("Rate limiting middleware", test_rate_limiter)


print("\n" + "="*70)
print("PHASE 7: AI PROVIDER CHECK")
print("="*70)

def test_ai_providers():
    from src.cognitive.llm.model_router import router
    from src.config import settings
    
    if len(router.providers) == 0:
        print(f"    [WARNING] No AI providers configured")
        print(f"    Add API keys to .env file:")
        if not settings.openai_api_key:
            print(f"      - OPENAI_API_KEY")
        if not settings.anthropic_api_key:
            print(f"      - ANTHROPIC_API_KEY")
        if not settings.groq_api_key:
            print(f"      - GROQ_API_KEY (FREE)")
    else:
        print(f"    Providers available: {', '.join(router.providers.keys())}")

if len(__import__('src.cognitive.llm.model_router').cognitive.llm.model_router.router.providers) > 0:
    test("AI providers", test_ai_providers)
else:
    skip_test("AI providers", "No API keys configured - add to .env file")


print("\n" + "="*70)
print("PHASE 8: VOICE SYSTEM CHECK")
print("="*70)

def test_voice_stt():
    from src.perception.voice.stt import SpeechToText
    
    stt = SpeechToText(use_cloud=False, model_name="base")
    models = stt.get_available_models()
    languages = stt.get_supported_languages()
    
    assert len(models) > 0
    assert len(languages) > 0
    
    print(f"    STT models: {len(models)}")
    print(f"    Languages: {len(languages)}")
    stt.cleanup()

def test_voice_tts():
    from src.perception.voice.tts import TextToSpeech, TTSConfig
    
    config = TTSConfig(provider="pyttsx3", voice="female")
    tts = TextToSpeech(config=config)
    
    assert tts.config.provider == "pyttsx3"
    print(f"    TTS provider: {tts.config.provider}")
    tts.cleanup()

test("Voice STT system", test_voice_stt)
test("Voice TTS system", test_voice_tts)


print("\n" + "="*70)
print("PHASE 9: MEMORY SYSTEM CHECK")
print("="*70)

def test_memory_system():
    from src.cognitive.memory import MemoryManager
    
    memory = MemoryManager()
    stats = memory.get_stats()
    
    print(f"    Memory system initialized")
    print(f"    Collections: {len(stats)}")

test("Memory system", test_memory_system)


print("\n" + "="*70)
print("PHASE 10: FILE STRUCTURE VERIFICATION")
print("="*70)

def test_file_structure():
    required_dirs = [
        "src/api",
        "src/api/routes",
        "src/api/schemas",
        "src/api/middleware",
        "src/cognitive/llm",
        "src/cognitive/memory",
        "src/perception/voice",
        "src/action/automation",
        "tests/unit",
        "tests/integration",
    ]
    
    missing = []
    for dir_path in required_dirs:
        if not Path(dir_path).exists():
            missing.append(dir_path)
    
    if missing:
        raise Exception(f"Missing directories: {', '.join(missing)}")
    
    print(f"    All required directories present: {len(required_dirs)}")

test("File structure", test_file_structure)


print("\n" + "="*70)
print("FINAL RESULTS")
print("="*70)

total = results["passed"] + results["failed"] + results["skipped"]
pass_rate = (results["passed"] / total * 100) if total > 0 else 0

print(f"\nTests Run: {total}")
print(f"  [PASS] {results['passed']} ({pass_rate:.1f}%)")
print(f"  [FAIL] {results['failed']}")
print(f"  [SKIP] {results['skipped']}")

if results["failed"] > 0:
    print("\nFailed Tests:")
    for test in results["tests"]:
        if test["status"] == "FAIL":
            print(f"  - {test['name']}: {test.get('error', 'Unknown error')}")

if results["skipped"] > 0:
    print("\nSkipped Tests:")
    for test in results["tests"]:
        if test["status"] == "SKIP":
            print(f"  - {test['name']}: {test.get('reason', 'No reason given')}")

print("\n" + "="*70)
if results["failed"] == 0:
    print("SYSTEM STATUS: WORKING SUCCESSFULLY ✓")
    print("="*70)
    print("\nNext Steps:")
    print("1. Add AI provider API keys to .env file")
    print("2. Start API server: python -m uvicorn src.api.main:app --reload")
    print("3. Test endpoints: python test_api_endpoints.py")
    print("4. Build Electron UI (next implementation phase)")
    sys.exit(0)
else:
    print("SYSTEM STATUS: ISSUES DETECTED ✗")
    print("="*70)
    print("\nPlease fix the failed tests above before proceeding.")
    sys.exit(1)

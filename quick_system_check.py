"""Quick Aether AI System Check"""
import sys
import os

os.environ['TESTING'] = '1'

print("="*60)
print("AETHER AI - QUICK SYSTEM CHECK")
print("="*60)

passed = 0
failed = 0

# Test 1: Configuration
print("\n[1/10] Configuration...")
try:
    from src.config import settings
    print(f"  [OK] {settings.app_name} v{settings.app_version}")
    passed += 1
except Exception as e:
    print(f"  [FAIL] {e}")
    failed += 1

# Test 2: API Structure
print("\n[2/10] API Structure...")
try:
    from pathlib import Path
    assert Path("src/api/main.py").exists()
    assert Path("src/api/routes").exists()
    assert Path("src/api/schemas").exists()
    assert Path("src/api/middleware").exists()
    print(f"  [OK] All API files present")
    passed += 1
except Exception as e:
    print(f"  [FAIL] {e}")
    failed += 1

# Test 3: Routes
print("\n[3/10] Route Files...")
try:
    from pathlib import Path
    routes = ["chat.py", "voice.py", "memory.py", "tasks.py", "settings.py"]
    for route in routes:
        assert Path(f"src/api/routes/{route}").exists(), f"Missing {route}"
    print(f"  [OK] All 5 route files present")
    passed += 1
except Exception as e:
    print(f"  [FAIL] {e}")
    failed += 1

# Test 4: Schemas
print("\n[4/10] Schema Files...")
try:
    from pathlib import Path
    schemas = ["chat.py", "tasks.py", "settings.py", "voice.py"]
    for schema in schemas:
        assert Path(f"src/api/schemas/{schema}").exists(), f"Missing {schema}"
    print(f"  [OK] All 4 schema files present")
    passed += 1
except Exception as e:
    print(f"  [FAIL] {e}")
    failed += 1

# Test 5: Middleware
print("\n[5/10] Middleware...")
try:
    from src.api.middleware import rate_limit_middleware
    print(f"  [OK] Rate limiting middleware available")
    passed += 1
except Exception as e:
    print(f"  [FAIL] {e}")
    failed += 1

# Test 6: Schemas Import
print("\n[6/10] Schema Validation...")
try:
    from src.api.schemas import ChatRequest, Settings, TaskResponse
    chat = ChatRequest(prompt="test", task_type="conversation")
    settings = Settings()
    print(f"  [OK] Schemas validate correctly")
    passed += 1
except Exception as e:
    print(f"  [FAIL] {e}")
    failed += 1

# Test 7: Voice Components
print("\n[7/10] Voice Components...")
try:
    from pathlib import Path
    assert Path("src/perception/voice/stt.py").exists()
    assert Path("src/perception/voice/tts.py").exists()
    assert Path("src/perception/voice/audio_utils.py").exists()
    print(f"  [OK] Voice components present")
    passed += 1
except Exception as e:
    print(f"  [FAIL] {e}")
    failed += 1

# Test 8: Memory Components
print("\n[8/10] Memory Components...")
try:
    from pathlib import Path
    assert Path("src/cognitive/memory").exists()
    print(f"  [OK] Memory system present")
    passed += 1
except Exception as e:
    print(f"  [FAIL] {e}")
    failed += 1

# Test 9: Tests
print("\n[9/10] Test Files...")
try:
    from pathlib import Path
    assert Path("tests/unit").exists()
    assert Path("tests/integration").exists()
    assert Path("tests/integration/test_api.py").exists()
    print(f"  [OK] Test framework present")
    passed += 1
except Exception as e:
    print(f"  [FAIL] {e}")
    failed += 1

# Test 10: Environment
print("\n[10/10] Environment Setup...")
try:
    from pathlib import Path
    assert Path(".env").exists()
    assert Path("requirements.txt").exists()
    assert Path("venv").exists()
    
    with open(".env") as f:
        env_content = f.read()
    
    has_groq = "gsk_" in env_content
    has_fireworks = "fw_" in env_content
    
    print(f"  [OK] Environment configured")
    if has_groq or has_fireworks:
        print(f"    - AI Providers: {'Groq' if has_groq else ''} {'Fireworks' if has_fireworks else ''}")
    passed += 1
except Exception as e:
    print(f"  [FAIL] {e}")
    failed += 1

# Results
print("\n" + "="*60)
print(f"RESULTS: {passed}/10 tests passed")
print("="*60)

if failed == 0:
    print("\n[OK] SYSTEM READY")
    print("\nQuick Start:")
    print("  1. Start API: python -m uvicorn src.api.main:app --reload")
    print("  2. Open: http://127.0.0.1:8000/docs")
    print("  3. Test endpoints with Swagger UI")
    sys.exit(0)
else:
    print(f"\n[FAIL] {failed} issue(s) found")
    sys.exit(1)

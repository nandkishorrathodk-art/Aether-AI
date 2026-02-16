#!/usr/bin/env python3
"""
Comprehensive System Test for Aether AI
Tests all critical components without starting servers
"""

import sys
import os

# Suppress warnings for cleaner output
import warnings
warnings.filterwarnings("ignore")

def test_imports():
    """Test critical imports"""
    print("[1/8] Testing Imports...")
    
    try:
        from src.api.main import app
        from src.cognitive.llm.model_loader import ModelLoader
        from src.cognitive.llm.context_manager import ContextManager
        from src.cognitive.memory.vector_store import VectorStore
        from src.perception.voice.wake_word import WakeWordDetector
        from src.action.automation.script_executor import ScriptExecutor
        print("  [OK] All critical imports successful")
        return True
    except Exception as e:
        print(f"  [FAIL] Import error: {e}")
        return False

def test_configuration():
    """Test configuration loading"""
    print("\n[2/8] Testing Configuration...")
    
    try:
        from src.config import settings
        print(f"  - App: {settings.app_name}")
        print(f"  - Environment: {settings.environment}")
        print(f"  - API Port: {settings.api_port}")
        print("  [OK] Configuration loaded")
        return True
    except Exception as e:
        print(f"  [FAIL] Config error: {e}")
        return False

def test_model_loader():
    """Test AI model loader"""
    print("\n[3/8] Testing Model Loader...")
    
    try:
        from src.cognitive.llm.model_loader import ModelLoader
        loader = ModelLoader()
        providers = loader.get_available_providers()
        print(f"  - Available providers: {len(providers)}")
        print("  [OK] Model loader initialized")
        return True
    except Exception as e:
        print(f"  [FAIL] Model loader error: {e}")
        return False

def test_context_manager():
    """Test context manager"""
    print("\n[4/8] Testing Context Manager...")
    
    try:
        from src.cognitive.llm.context_manager import ContextManager
        ctx = ContextManager(session_id="test_comprehensive", load_from_db=False)
        ctx.add_message("user", "Hello test")
        history = ctx.get_history()
        assert len(history) == 1, "History should have 1 message"
        print(f"  - Messages: {len(history)}")
        print("  [OK] Context manager working")
        return True
    except Exception as e:
        print(f"  [FAIL] Context manager error: {e}")
        return False

def test_memory_system():
    """Test memory system"""
    print("\n[5/8] Testing Memory System...")
    
    try:
        from src.cognitive.memory.vector_store import MemoryManager
        from src.cognitive.memory.user_profile import UserProfile
        from src.cognitive.memory.conversation_history import ConversationHistory
        
        mem = MemoryManager()
        profile = UserProfile(user_id="test_user")
        history = ConversationHistory()
        
        print("  - MemoryManager: initialized")
        print("  - UserProfile: initialized")
        print("  - ConversationHistory: initialized")
        print("  [OK] Memory system initialized")
        return True
    except Exception as e:
        print(f"  [FAIL] Memory error: {e}")
        return False

def test_automation():
    """Test automation system"""
    print("\n[6/8] Testing Automation...")
    
    try:
        from src.action.automation.command_registry import CommandRegistry
        registry = CommandRegistry()
        cmds = list(registry.commands.keys())
        print(f"  - Registered commands: {len(cmds)}")
        print("  [OK] Automation system ready")
        return True
    except Exception as e:
        print(f"  [FAIL] Automation error: {e}")
        return False

def test_voice_components():
    """Test voice components"""
    print("\n[7/8] Testing Voice Components...")
    
    try:
        from src.perception.voice.stt import SpeechToText
        from src.perception.voice.tts import TextToSpeech, TTSConfig
        
        # Test STT (without loading model)
        print("  - STT: SpeechToText class available")
        
        # Test TTS
        config = TTSConfig()
        tts = TextToSpeech(config=config)
        print("  - TTS: TextToSpeech initialized")
        
        print("  [OK] Voice components ready")
        return True
    except Exception as e:
        print(f"  [FAIL] Voice error: {e}")
        return False

def test_api_routes():
    """Test API routes"""
    print("\n[8/8] Testing API Routes...")
    
    try:
        from src.api.main import app
        routes = [r.path for r in app.routes]
        
        route_categories = {
            "chat": [r for r in routes if "/chat" in r],
            "voice": [r for r in routes if "/voice" in r],
            "memory": [r for r in routes if "/memory" in r],
            "tasks": [r for r in routes if "/tasks" in r]
        }
        
        print(f"  - Total routes: {len(routes)}")
        for cat, cat_routes in route_categories.items():
            print(f"  - {cat.title()}: {len(cat_routes)} routes")
        
        print("  [OK] API routes registered")
        return True
    except Exception as e:
        print(f"  [FAIL] API error: {e}")
        return False

def main():
    print("=" * 60)
    print("AETHER AI - Comprehensive System Test")
    print("=" * 60)
    
    results = []
    
    results.append(test_imports())
    results.append(test_configuration())
    results.append(test_model_loader())
    results.append(test_context_manager())
    results.append(test_memory_system())
    results.append(test_automation())
    results.append(test_voice_components())
    results.append(test_api_routes())
    
    print("\n" + "=" * 60)
    passed = sum(results)
    total = len(results)
    percentage = (passed / total) * 100
    
    print(f"Results: {passed}/{total} tests passed ({percentage:.1f}%)")
    
    if passed == total:
        print("\n[SUCCESS] All systems operational!")
        print("\nAether AI is ready to use:")
        print("  1. Start backend: python -m src.api.main")
        print("  2. Start frontend: cd ui && npm start")
        print("  3. Voice pipeline: python scripts/test_voice_pipeline.py")
        return 0
    else:
        print(f"\n[WARNING] {total - passed} tests failed")
        print("Please review errors above")
        return 1

if __name__ == "__main__":
    sys.exit(main())

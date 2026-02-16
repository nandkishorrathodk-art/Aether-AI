#!/usr/bin/env python3
"""Quick import check for Aether AI components"""

import sys
import traceback

def test_import(module_name, description):
    """Test importing a module"""
    try:
        __import__(module_name)
        print(f"[OK] {description}")
        return True
    except Exception as e:
        print(f"[FAIL] {description}")
        print(f"  Error: {e}")
        return False

def test_from_import(module_name, attr_name, description):
    """Test importing from a module"""
    try:
        module = __import__(module_name, fromlist=[attr_name])
        getattr(module, attr_name)
        print(f"[OK] {description}")
        return True
    except Exception as e:
        print(f"[FAIL] {description}")
        print(f"  Error: {e}")
        traceback.print_exc()
        return False

def main():
    print("=" * 60)
    print("AETHER AI - Import Verification")
    print("=" * 60)
    
    results = []
    
    # Core dependencies
    print("\n[1/6] Core Dependencies")
    results.append(test_import("fastapi", "FastAPI"))
    results.append(test_import("chromadb", "ChromaDB"))
    results.append(test_import("torch", "PyTorch"))
    
    # Voice components
    print("\n[2/6] Voice Components")
    results.append(test_from_import("src.perception.voice.stt", "STT", "STT"))
    results.append(test_from_import("src.perception.voice.tts", "TTS", "TTS"))
    results.append(test_from_import("src.perception.voice.wake_word", "WakeWordDetector", "Wake Word"))
    
    # LLM components
    print("\n[3/6] LLM Components")
    results.append(test_from_import("src.cognitive.llm.model_loader", "ModelLoader", "Model Loader"))
    results.append(test_from_import("src.cognitive.llm.model_router", "ModelRouter", "Model Router"))
    results.append(test_from_import("src.cognitive.llm.context_manager", "ContextManager", "Context Manager"))
    
    # Memory components
    print("\n[4/6] Memory Components")
    results.append(test_from_import("src.cognitive.memory.vector_store", "VectorStore", "Vector Store"))
    results.append(test_from_import("src.cognitive.memory.conversation_history", "ConversationHistory", "Conversation History"))
    results.append(test_from_import("src.cognitive.memory.user_profile", "UserProfile", "User Profile"))
    
    # Automation components
    print("\n[5/6] Automation Components")
    results.append(test_from_import("src.action.automation.script_executor", "ScriptExecutor", "Script Executor"))
    results.append(test_from_import("src.action.automation.gui_control", "GUIController", "GUI Controller"))
    results.append(test_from_import("src.action.automation.file_operations", "SafeFileOperations", "File Operations"))
    
    # API components
    print("\n[6/6] API Components")
    results.append(test_from_import("src.api.main", "app", "FastAPI App"))
    
    # Summary
    print("\n" + "=" * 60)
    passed = sum(results)
    total = len(results)
    print(f"Results: {passed}/{total} imports successful ({100*passed//total}%)")
    
    if passed == total:
        print("[SUCCESS] All imports OK - System ready")
        return 0
    else:
        print(f"[WARNING] {total - passed} imports failed - Issues detected")
        return 1

if __name__ == "__main__":
    sys.exit(main())

"""Test script to verify Aether Brain imports"""

print("Testing Aether Brain imports...")

try:
    from src.cognitive.memory.vector_store import VectorStore, get_vector_store
    print("[OK] Vector Store imported")
except Exception as e:
    print(f"[FAIL] Vector Store import failed: {e}")
    exit(1)

try:
    from src.cognitive.tools.tavily_search import TavilySearchTool, get_tavily_search
    print("[OK] Tavily Search imported")
except Exception as e:
    print(f"[FAIL] Tavily Search import failed: {e}")
    exit(1)

try:
    from src.cognitive.tools.file_system import FileSystemTool, get_file_system
    print("[OK] File System Tool imported")
except Exception as e:
    print(f"[FAIL] File System Tool import failed: {e}")
    exit(1)

try:
    from src.cognitive.tools.code_executor import CodeExecutorTool, get_code_executor
    print("[OK] Code Executor Tool imported")
except Exception as e:
    print(f"[FAIL] Code Executor Tool import failed: {e}")
    exit(1)

try:
    from src.cognitive.aether_brain import AetherBrain, get_aether_brain
    print("[OK] Aether Brain imported")
except Exception as e:
    print(f"[FAIL] Aether Brain import failed: {e}")
    exit(1)

print("\n[SUCCESS] All Aether Brain components successfully imported!")
print("\nComponents loaded:")
print("- VectorStore (Long-term memory)")
print("- TavilySearchTool (Web search)")
print("- FileSystemTool (File operations)")
print("- CodeExecutorTool (Code execution)")
print("- AetherBrain (Main orchestrator)")

"""Test if backend can start"""
import sys
print("Testing backend imports...")

try:
    from src.api.main import app
    print("✓ Backend imports successful!")
    print("Backend is ready to start")
except Exception as e:
    print(f"✗ Backend import failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

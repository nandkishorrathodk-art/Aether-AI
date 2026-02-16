#!/usr/bin/env python
"""Test ChromaDB import and compatibility"""

try:
    import chromadb
    print(f"[OK] ChromaDB imported successfully (version: {chromadb.__version__})")
    
    # Try creating a client
    client = chromadb.Client()
    print("[OK] ChromaDB client created successfully")
    
    # Try httpx import
    import httpx
    print(f"[OK] httpx imported successfully (version: {httpx.__version__})")
    
    print("\n[SUCCESS] ALL TESTS PASSED - ChromaDB is compatible!")
    
except Exception as e:
    print(f"[ERROR] {e}")
    import traceback
    traceback.print_exc()

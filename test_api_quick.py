#!/usr/bin/env python3
"""Quick API health check"""

import sys

try:
    from src.api.main import app
    print("[OK] API app imported successfully")
    
    # Check routes
    routes = [r.path for r in app.routes]
    print(f"[OK] {len(routes)} routes registered")
    
    # Check critical routes
    critical = ["/api/v1/chat", "/api/v1/voice/transcribe", "/api/v1/memory/remember"]
    missing = [r for r in critical if r not in routes]
    
    if missing:
        print(f"[WARNING] Missing routes: {missing}")
    else:
        print("[OK] All critical routes present")
    
    sys.exit(0)
except Exception as e:
    print(f"[FAIL] API check failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

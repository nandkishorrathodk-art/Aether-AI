import sys
import traceback

try:
    print("Testing API imports...")
    from src.api.main import app
    print("[OK] API imports successful")
    
    print("\nTesting route imports...")
    from src.api.routes import chat, voice, memory, tasks
    from src.api.routes import settings as settings_route
    print("[OK] Route imports successful")
    
    print("\nTesting schema imports...")
    from src.api.schemas import (
        ChatRequest, TaskResponse, Settings,
        TranscribeRequest, CostStats
    )
    print("[OK] Schema imports successful")
    
    print("\nTesting middleware imports...")
    from src.api.middleware import rate_limit_middleware
    print("[OK] Middleware imports successful")
    
    print("\n" + "="*50)
    print("ALL IMPORTS SUCCESSFUL!")
    print("="*50)
    
    print("\nAPI Configuration:")
    print(f"  Title: {app.title}")
    print(f"  Version: {app.version}")
    print(f"  Description: {app.description}")
    
    print("\nRegistered Routes:")
    for route in app.routes:
        if hasattr(route, 'path') and hasattr(route, 'methods'):
            methods = ','.join(route.methods) if route.methods else 'N/A'
            print(f"  {methods:10} {route.path}")
    
except Exception as e:
    print(f"\n[ERROR] {e}")
    traceback.print_exc()
    sys.exit(1)

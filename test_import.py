try:
    from src.api.main import app
    print("SUCCESS: App imported successfully")
    print("FastAPI version check OK")
except Exception as e:
    print(f"FAILED: Import failed: {e}")
    import traceback
    traceback.print_exc()

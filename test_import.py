try:
    from src.api.main import app
    print("SUCCESS: Main app imported successfully!")
except Exception as e:
    print(f"ERROR importing main app: {e}")
    import traceback
    traceback.print_exc()

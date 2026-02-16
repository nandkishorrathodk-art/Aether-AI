import requests
import json
import time

BASE_URL = "http://127.0.0.1:8000"

def test_root():
    print("Testing GET /...")
    response = requests.get(f"{BASE_URL}/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "running"
    print("  [OK] Root endpoint working")
    return data

def test_health():
    print("Testing GET /health...")
    response = requests.get(f"{BASE_URL}/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    print("  [OK] Health endpoint working")

def test_settings_get():
    print("Testing GET /api/v1/settings...")
    response = requests.get(f"{BASE_URL}/api/v1/settings/")
    assert response.status_code == 200
    data = response.json()
    assert "settings" in data
    print("  [OK] Settings GET working")

def test_settings_update():
    print("Testing PUT /api/v1/settings...")
    payload = {
        "ai": {
            "temperature": 0.8,
            "max_tokens": 500,
            "context_window": 15
        }
    }
    response = requests.put(f"{BASE_URL}/api/v1/settings/", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["settings"]["ai"]["temperature"] == 0.8
    print("  [OK] Settings UPDATE working")

def test_create_task():
    print("Testing POST /api/v1/tasks...")
    payload = {
        "task_type": "automation",
        "command": "test_command",
        "parameters": {"key": "value"},
        "auto_approve": False
    }
    response = requests.post(f"{BASE_URL}/api/v1/tasks/", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "task_id" in data
    print(f"  [OK] Task created: {data['task_id']}")
    return data["task_id"]

def test_get_task(task_id):
    print(f"Testing GET /api/v1/tasks/{task_id}...")
    response = requests.get(f"{BASE_URL}/api/v1/tasks/{task_id}")
    assert response.status_code == 200
    print("  [OK] Task GET working")

def test_list_tasks():
    print("Testing GET /api/v1/tasks...")
    response = requests.get(f"{BASE_URL}/api/v1/tasks/")
    assert response.status_code == 200
    data = response.json()
    assert "tasks" in data
    print(f"  [OK] Tasks listed: {data['total']} total")

def test_task_stats():
    print("Testing GET /api/v1/tasks/stats/summary...")
    response = requests.get(f"{BASE_URL}/api/v1/tasks/stats/summary")
    assert response.status_code == 200
    print("  [OK] Task stats working")

def main():
    print("="*60)
    print("AETHER AI - API ENDPOINT TESTS")
    print("="*60)
    print(f"\nTesting API at: {BASE_URL}")
    print("Starting in 2 seconds (make sure server is running)...\n")
    time.sleep(2)
    
    try:
        root_data = test_root()
        test_health()
        test_settings_get()
        test_settings_update()
        task_id = test_create_task()
        test_get_task(task_id)
        test_list_tasks()
        test_task_stats()
        
        print("\n" + "="*60)
        print("ALL TESTS PASSED!")
        print("="*60)
        print("\nAPI Endpoints Registered:")
        for key, value in root_data.get("endpoints", {}).items():
            print(f"  {key:25} {value}")
        
    except requests.exceptions.ConnectionError:
        print("\n[ERROR] Could not connect to API server.")
        print("Please start the server with: python -m uvicorn src.api.main:app")
        return 1
    except AssertionError as e:
        print(f"\n[ERROR] Test failed: {e}")
        return 1
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())

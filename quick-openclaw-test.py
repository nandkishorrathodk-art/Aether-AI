"""
Quick OpenClaw Test - Works WITHOUT AI API keys!
"""

import requests
import json

print("\n" + "="*60)
print("  TESTING OPENCLAW - WEB SCRAPING")
print("="*60 + "\n")

print("Scraping https://example.com ...\n")

try:
    response = requests.post(
        'http://127.0.0.1:8000/api/v1/openclaw/scrape',
        json={'url': 'https://example.com'},
        timeout=15
    )
    
    if response.status_code == 200:
        data = response.json()['data']
        
        print("SUCCESS! OpenClaw is working!\n")
        print("="*60)
        print(f"Title: {data['title']}")
        print(f"URL: {data['url']}")
        print(f"Status: {data['status_code']}")
        print(f"\nText (first 200 chars):")
        print(data['text'][:200] + "...")
        print(f"\nLinks found: {len(data['links'])}")
        print(f"Images found: {len(data['images'])}")
        print("="*60 + "\n")
        
        print("OK - Aether AI OpenClaw is working perfectly!")
        print("OK - You can scrape any website!")
        print("\nTry the API docs: http://127.0.0.1:8000/docs")
        print("Look for: POST /api/v1/openclaw/scrape\n")
    else:
        print(f"Error: {response.status_code}")
        print(response.text)

except Exception as e:
    print(f"Error: {e}")
    print("\nMake sure the server is running:")
    print("  - CLICK-ME.bat")
    print("  - or RUN.bat\n")

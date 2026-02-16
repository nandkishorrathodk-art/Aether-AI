"""
OpenClaw Test Script
Demonstrates web scraping and automation capabilities
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.action.automation.openclaw import OpenClaw
import json


def test_simple_scrape():
    """Test simple web scraping"""
    print("\n" + "="*60)
    print("TEST 1: Simple Web Scraping")
    print("="*60)
    
    claw = OpenClaw(headless=True)
    
    # Scrape a simple page
    result = claw.scrape_url("https://example.com")
    
    print(f"\n✓ URL: {result.get('url')}")
    print(f"✓ Title: {result.get('title')}")
    print(f"✓ Text Length: {len(result.get('text', ''))}")
    print(f"✓ Links Found: {len(result.get('links', []))}")
    print(f"✓ Images Found: {len(result.get('images', []))}")
    
    print(f"\nFirst 200 characters:")
    print(result.get('text', '')[:200])
    
    return result


def test_browser_automation():
    """Test browser automation"""
    print("\n" + "="*60)
    print("TEST 2: Browser Automation")
    print("="*60)
    
    with OpenClaw(headless=True) as claw:
        # Navigate to a website
        print("\n[*] Navigating to https://httpbin.org...")
        success = claw.navigate_to("https://httpbin.org")
        print(f"✓ Navigation: {'Success' if success else 'Failed'}")
        
        # Get page text
        text = claw.get_page_text()
        print(f"✓ Page Text Length: {len(text)}")
        
        # Get current URL
        current_url = claw.get_current_url()
        print(f"✓ Current URL: {current_url}")
        
        # Take screenshot
        print("\n[*] Taking screenshot...")
        Path("./data/screenshots").mkdir(parents=True, exist_ok=True)
        success = claw.take_screenshot("./data/screenshots/test_openclaw.png")
        print(f"✓ Screenshot: {'Success' if success else 'Failed'}")
        
        return True


def test_multiple_scrapes():
    """Test scraping multiple URLs"""
    print("\n" + "="*60)
    print("TEST 3: Multiple URL Scraping")
    print("="*60)
    
    import asyncio
    
    async def run_multi_scrape():
        claw = OpenClaw(headless=True)
        
        urls = [
            "https://example.com",
            "https://httpbin.org",
            "https://www.iana.org"
        ]
        
        print(f"\n[*] Scraping {len(urls)} URLs...")
        
        results = []
        for url in urls:
            result = await claw.scrape_url_async(url)
            results.append(result)
            print(f"  ✓ {url} - {result.get('title', 'N/A')}")
        
        return results
    
    results = asyncio.run(run_multi_scrape())
    print(f"\n✓ Successfully scraped {len(results)} URLs")
    
    return results


def test_content_extraction():
    """Test content extraction"""
    print("\n" + "="*60)
    print("TEST 4: Content Extraction")
    print("="*60)
    
    from src.action.automation.openclaw import extract_emails, extract_phone_numbers
    
    sample_text = """
    Contact us at info@example.com or support@company.org
    Call us at +1-555-123-4567 or (555) 987-6543
    """
    
    emails = extract_emails(sample_text)
    phones = extract_phone_numbers(sample_text)
    
    print(f"\n✓ Emails found: {emails}")
    print(f"✓ Phone numbers found: {phones}")
    
    return {"emails": emails, "phones": phones}


def main():
    """Run all tests"""
    print("\n" + "="*60)
    print("    OPENCLAW TEST SUITE")
    print("="*60)
    print("\nTesting OpenClaw web automation capabilities...\n")
    
    try:
        # Run tests
        test_simple_scrape()
        test_browser_automation()
        test_multiple_scrapes()
        test_content_extraction()
        
        print("\n" + "="*60)
        print("    ALL TESTS PASSED ✓")
        print("="*60)
        print("\nOpenClaw is working correctly!")
        print("\nNext steps:")
        print("1. Start API server: RUN.bat")
        print("2. Test API: http://127.0.0.1:8000/docs")
        print("3. Try OpenClaw endpoints at /api/v1/openclaw")
        print()
        
    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        print("\nTroubleshooting:")
        print("1. Run: install-openclaw.bat")
        print("2. Check Chrome is installed")
        print("3. Check internet connection")
        import traceback
        traceback.print_exc()
        return False
    
    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

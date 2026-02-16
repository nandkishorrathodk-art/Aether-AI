# OpenClaw - Quick Start Guide

OpenClaw is now integrated into Aether AI! 🎉

## What is OpenClaw?

OpenClaw is a powerful **web scraping and browser automation** module that gives Aether AI the ability to:
- 🔍 Scrape websites (static & dynamic content)
- 🤖 Automate browser interactions (click, fill forms, navigate)
- 📊 Extract structured data (tables, lists, specific elements)
- 📸 Take screenshots
- 🚀 Scrape multiple URLs concurrently

## Quick Setup (3 Steps)

### 1. Install Dependencies
```bash
install-openclaw.bat
```

This installs:
- BeautifulSoup4 (HTML parsing)
- Selenium (browser automation)
- WebDriver Manager (Chrome driver)

### 2. Start Aether AI
```bash
RUN.bat
```

### 3. Test OpenClaw
Visit: http://127.0.0.1:8000/docs

Look for **openclaw** endpoints

## Quick Test

### Test the API
Open browser and go to:
```
http://127.0.0.1:8000/api/v1/openclaw/status
```

You should see:
```json
{
  "status": "active",
  "driver_active": false,
  "headless": true,
  "timeout": 30
}
```

### Scrape a Website
**POST** `http://127.0.0.1:8000/api/v1/openclaw/scrape`

Body:
```json
{
  "url": "https://example.com"
}
```

Response:
```json
{
  "success": true,
  "data": {
    "url": "https://example.com",
    "title": "Example Domain",
    "text": "Example Domain This domain is...",
    "links": [...],
    "images": [...],
    "status_code": 200
  }
}
```

## Python Example

```python
from src.action.automation.openclaw import OpenClaw

# Simple scraping
claw = OpenClaw()
result = claw.scrape_url("https://example.com")
print(result['title'])
print(result['text'][:200])

# Browser automation
with OpenClaw() as claw:
    claw.navigate_to("https://example.com")
    claw.click_element("#button")
    claw.take_screenshot("./screenshot.png")
```

## Test Script

Run the comprehensive test:
```bash
python scripts\test_openclaw.py
```

This tests:
1. ✓ Simple web scraping
2. ✓ Browser automation
3. ✓ Multiple URL scraping
4. ✓ Content extraction

## API Endpoints

### Core Functions
- `GET /api/v1/openclaw/status` - Get status
- `POST /api/v1/openclaw/scrape` - Scrape single URL
- `POST /api/v1/openclaw/scrape/multiple` - Scrape multiple URLs
- `POST /api/v1/openclaw/navigate` - Navigate to URL

### Automation
- `POST /api/v1/openclaw/click` - Click element
- `POST /api/v1/openclaw/form/fill` - Fill form
- `POST /api/v1/openclaw/form/submit` - Submit form
- `GET /api/v1/openclaw/page/text` - Get page text
- `POST /api/v1/openclaw/screenshot` - Take screenshot

### Advanced
- `POST /api/v1/openclaw/extract` - Extract by selector
- `POST /api/v1/openclaw/extract/table` - Extract table
- `POST /api/v1/openclaw/execute/script` - Run JavaScript

Full API docs: http://127.0.0.1:8000/docs

## Use Cases

### 1. Monitor Competitor Prices
```bash
POST /api/v1/openclaw/scrape
{
  "url": "https://competitor.com/products"
}
```

Then extract prices:
```bash
POST /api/v1/openclaw/extract
{
  "selector": ".product-price"
}
```

### 2. Scrape News Headlines
```bash
POST /api/v1/openclaw/scrape/multiple
{
  "urls": [
    "https://news-site-1.com",
    "https://news-site-2.com"
  ]
}
```

### 3. Automate Form Filling
```bash
# Navigate
POST /api/v1/openclaw/navigate
{"url": "https://form.example.com"}

# Fill form
POST /api/v1/openclaw/form/fill
{
  "fields": {
    "#email": "user@example.com",
    "#message": "Hello!"
  }
}

# Submit
POST /api/v1/openclaw/form/submit
{"selector": "#contact-form"}
```

### 4. Extract Table Data
```bash
# Navigate to page with table
POST /api/v1/openclaw/navigate
{"url": "https://data-site.com/table"}

# Extract table
POST /api/v1/openclaw/extract/table
{"selector": "table.data-table"}
```

## Troubleshooting

### "Chrome driver not found"
```bash
pip install webdriver-manager
```

### "Element not found"
Add wait time:
```python
claw.wait_for_element("#element-id", timeout=10)
```

### "Timeout error"
Increase timeout:
```python
claw = OpenClaw(timeout=60)  # 60 seconds
```

### Check logs
```
logs\aether.log
```

## Next Steps

1. **Read full docs**: `docs\OPENCLAW.md`
2. **Try the API**: http://127.0.0.1:8000/docs
3. **Run tests**: `python scripts\test_openclaw.py`
4. **Integrate with AI**: Ask Aether AI to "scrape website X"

## Example Conversation

```
User: "Scrape the title and all links from example.com"

Aether AI: 
  [Uses OpenClaw automatically]
  
  "I found the following:
  - Title: Example Domain
  - Found 2 links:
    1. https://www.iana.org/domains/example
    2. https://www.iana.org/domains/reserved"
```

## Features Summary

✅ **Web Scraping**
- Static HTML pages
- Dynamic JavaScript pages
- Multiple URLs concurrently

✅ **Browser Automation**
- Click buttons
- Fill & submit forms
- Navigate (back/forward/refresh)

✅ **Data Extraction**
- Text content
- Links & images
- Tables (as JSON)
- Custom CSS selectors
- Metadata & OpenGraph tags

✅ **Advanced**
- Screenshots
- JavaScript execution
- Cookie management
- Async/await support

## API Integration

OpenClaw works seamlessly with Aether AI:

```
User: "What's the latest news on AI?"

Aether AI:
  1. Uses OpenClaw to scrape news sites
  2. Extracts headlines and summaries
  3. Analyzes content with AI
  4. Returns intelligent summary
```

---

**OpenClaw** is ready to use! 🚀

Start scraping: http://127.0.0.1:8000/api/v1/openclaw/status

# OpenClaw - Web Automation & Scraping

**OpenClaw** is Aether AI's intelligent web browsing and scraping module, providing powerful automation capabilities for web interactions.

## Features

### 🔍 Web Scraping
- **Static Content**: Extract text, links, images, and metadata from web pages
- **Dynamic Content**: Handle JavaScript-rendered pages with Selenium
- **Concurrent Scraping**: Scrape multiple URLs simultaneously
- **Content Extraction**: Extract tables, forms, and specific elements

### 🤖 Browser Automation
- **Navigation**: Visit URLs, go back/forward, refresh pages
- **Interaction**: Click buttons, fill forms, submit data
- **Screenshots**: Capture page screenshots
- **JavaScript Execution**: Run custom JavaScript code
- **Cookie Management**: Handle cookies and sessions

### 📊 Data Extraction
- **Structured Data**: Extract tables as JSON/dict format
- **Custom Selectors**: Use CSS selectors to extract specific content
- **Email/Phone Extraction**: Built-in regex patterns
- **Metadata Extraction**: Get page metadata, OpenGraph tags, etc.

## Installation

### Quick Install
```bash
install-openclaw.bat
```

This installs:
- BeautifulSoup4 (HTML parsing)
- Selenium (browser automation)
- lxml (fast XML/HTML processing)
- WebDriver Manager (auto Chrome driver setup)

### Manual Install
```bash
pip install beautifulsoup4 selenium lxml html5lib webdriver-manager
```

## Usage

### 1. Simple Web Scraping

```python
from src.action.automation.openclaw import OpenClaw

# Initialize
claw = OpenClaw(headless=True)

# Scrape a URL
result = claw.scrape_url("https://example.com")

print(result['title'])      # Page title
print(result['text'])        # Visible text
print(result['links'])       # All links
print(result['images'])      # All images
print(result['metadata'])    # Meta tags
```

### 2. Browser Automation

```python
with OpenClaw(headless=False) as claw:
    # Navigate
    claw.navigate_to("https://example.com")
    
    # Click button
    claw.click_element("#submit-btn")
    
    # Fill form
    claw.fill_form({
        "#username": "user@example.com",
        "#password": "secret123"
    })
    
    # Submit
    claw.submit_form("#login-form")
    
    # Screenshot
    claw.take_screenshot("./screenshot.png")
```

### 3. Multi-URL Scraping

```python
import asyncio

async def scrape_multiple():
    claw = OpenClaw()
    
    urls = [
        "https://example.com",
        "https://httpbin.org",
        "https://api.github.com"
    ]
    
    results = []
    for url in urls:
        result = await claw.scrape_url_async(url)
        results.append(result)
    
    return results

results = asyncio.run(scrape_multiple())
```

### 4. Table Extraction

```python
with OpenClaw() as claw:
    claw.navigate_to("https://example.com/data-table")
    
    # Extract table as list of dicts
    table_data = claw.extract_table("table.data-table")
    
    # table_data = [
    #     {"Name": "John", "Age": "30", "City": "NYC"},
    #     {"Name": "Jane", "Age": "25", "City": "LA"},
    #     ...
    # ]
```

## API Endpoints

OpenClaw is fully integrated into Aether AI's REST API.

### Base URL
```
http://127.0.0.1:8000/api/v1/openclaw
```

### Available Endpoints

#### GET `/status`
Get OpenClaw status and configuration

**Response:**
```json
{
  "status": "active",
  "driver_active": false,
  "headless": true,
  "timeout": 30
}
```

#### POST `/scrape`
Scrape a single URL

**Request:**
```json
{
  "url": "https://example.com",
  "extract_links": true,
  "extract_images": true,
  "extract_metadata": true
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "url": "https://example.com",
    "title": "Example Domain",
    "text": "Example Domain...",
    "links": ["https://...", "..."],
    "images": ["https://...", "..."],
    "metadata": {...},
    "status_code": 200,
    "scraped_at": "2024-02-08T..."
  }
}
```

#### POST `/scrape/multiple`
Scrape multiple URLs concurrently

**Request:**
```json
{
  "urls": [
    "https://example.com",
    "https://httpbin.org"
  ],
  "max_concurrent": 5
}
```

#### POST `/navigate`
Navigate to URL with browser

**Request:**
```json
{
  "url": "https://example.com"
}
```

#### POST `/click`
Click element on current page

**Request:**
```json
{
  "selector": "#submit-button",
  "by": "css"
}
```

#### POST `/form/fill`
Fill form fields

**Request:**
```json
{
  "fields": {
    "#username": "user@example.com",
    "#password": "secret123"
  }
}
```

#### POST `/form/submit`
Submit form

**Request:**
```json
{
  "selector": "#login-form"
}
```

#### GET `/page/text`
Get visible text from current page

#### GET `/page/source`
Get HTML source of current page

#### GET `/page/url`
Get current page URL

#### POST `/extract`
Extract elements by CSS selector

**Request:**
```json
{
  "selector": "a.product-link",
  "attribute": "href"
}
```

#### POST `/extract/table`
Extract table data

**Request:**
```json
{
  "selector": "table.data-table"
}
```

#### POST `/screenshot`
Take screenshot

**Request:**
```json
{
  "filename": "my-screenshot.png"
}
```

#### POST `/execute/script`
Execute JavaScript

**Request:**
```json
{
  "script": "return document.title;"
}
```

#### Navigation Endpoints
- `POST /navigation/back` - Go back
- `POST /navigation/forward` - Go forward  
- `POST /navigation/refresh` - Refresh page

#### Other Endpoints
- `GET /cookies` - Get all cookies
- `POST /close` - Close browser driver

## Testing

Run the test suite:
```bash
python scripts\test_openclaw.py
```

Tests include:
1. Simple web scraping
2. Browser automation
3. Multiple URL scraping
4. Content extraction (emails, phones)

## Integration with Aether AI

OpenClaw is fully integrated with Aether AI's cognitive engine:

```python
# AI can use OpenClaw automatically
response = await conversation_engine.process_conversation({
    "user_input": "Scrape the latest news from example.com",
    "session_id": "user123"
})

# AI will:
# 1. Understand the intent (web scraping)
# 2. Call OpenClaw module
# 3. Extract relevant information
# 4. Return structured response
```

## Use Cases

### 1. Competitive Intelligence
```python
# Monitor competitor pricing
with OpenClaw() as claw:
    claw.navigate_to("https://competitor.com/products")
    prices = claw.extract_by_selector(".product-price")
```

### 2. Content Aggregation
```python
# Aggregate news from multiple sources
urls = [
    "https://news-site-1.com",
    "https://news-site-2.com",
    "https://news-site-3.com"
]

async def aggregate_news():
    claw = OpenClaw()
    results = []
    for url in urls:
        data = await claw.scrape_url_async(url)
        results.append(data)
    return results
```

### 3. Form Automation
```python
# Automate form submissions
with OpenClaw() as claw:
    claw.navigate_to("https://form.example.com")
    claw.fill_form({
        "#name": "John Doe",
        "#email": "john@example.com",
        "#message": "Hello!"
    })
    claw.submit_form("#contact-form")
```

### 4. Data Collection
```python
# Collect structured data
with OpenClaw() as claw:
    claw.navigate_to("https://data-site.com/table")
    data = claw.extract_table("table.results")
    
    # Save to database or file
    import pandas as pd
    df = pd.DataFrame(data)
    df.to_csv("extracted_data.csv")
```

## Best Practices

### 1. Use Headless Mode in Production
```python
claw = OpenClaw(headless=True)  # Faster, no UI
```

### 2. Handle Timeouts
```python
claw = OpenClaw(timeout=60)  # 60 second timeout
```

### 3. Close Driver After Use
```python
# Use context manager
with OpenClaw() as claw:
    # Your code
    pass

# Or manually close
claw = OpenClaw()
try:
    claw.navigate_to("...")
finally:
    claw.close_driver()
```

### 4. Respect robots.txt
Always check if scraping is allowed:
```python
import requests
response = requests.get("https://example.com/robots.txt")
print(response.text)
```

### 5. Rate Limiting
Add delays between requests:
```python
import time

for url in urls:
    claw.scrape_url(url)
    time.sleep(2)  # 2 second delay
```

## Troubleshooting

### Chrome Driver Issues
```bash
# Auto-install correct driver
pip install webdriver-manager

# Then in code:
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

service = Service(ChromeDriverManager().install())
```

### Timeout Errors
```python
# Increase timeout
claw = OpenClaw(timeout=120)  # 2 minutes
```

### Element Not Found
```python
# Wait for element
claw.wait_for_element("#my-element", timeout=20)
```

### JavaScript Not Executed
```python
# Ensure page is fully loaded
import time
claw.navigate_to("https://...")
time.sleep(3)  # Wait for JS to execute
```

## Limitations

1. **Rate Limiting**: Some sites may block automated requests
2. **CAPTCHAs**: Cannot automatically solve CAPTCHAs
3. **Dynamic Content**: May require additional wait times
4. **JavaScript-Heavy Sites**: May be slower to scrape
5. **Legal Compliance**: Always check terms of service

## Resources

- **Selenium Docs**: https://selenium-python.readthedocs.io/
- **BeautifulSoup Docs**: https://www.crummy.com/software/BeautifulSoup/
- **CSS Selectors**: https://www.w3schools.com/cssref/css_selectors.php

## Support

For issues or questions:
1. Check logs: `logs/aether.log`
2. Run tests: `python scripts\test_openclaw.py`
3. Check API docs: http://127.0.0.1:8000/docs

---

**OpenClaw** - Intelligent Web Automation for Aether AI

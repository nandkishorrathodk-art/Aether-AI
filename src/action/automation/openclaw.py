"""
OpenClaw - Web Browsing & Scraping Automation Module
Integrated into Aether AI for intelligent web interactions
"""

import asyncio
import aiohttp
from typing import Dict, List, Optional, Any, Union
from pathlib import Path
from datetime import datetime
import json
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import requests
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException, NoSuchElementException

from src.utils.logger import get_logger

logger = get_logger(__name__)


class OpenClaw:
    """
    OpenClaw: Intelligent Web Automation & Scraping Engine
    
    Capabilities:
    - Web scraping (static & dynamic content)
    - Browser automation (Selenium)
    - Content extraction (text, links, images, tables)
    - Screenshot capture
    - Form filling & submission
    - Multi-page navigation
    - JavaScript execution
    - Cookie management
    """
    
    def __init__(self, headless: bool = True, timeout: int = 30):
        self.headless = headless
        self.timeout = timeout
        self.driver = None
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        logger.info("OpenClaw initialized")
    
    def _init_driver(self) -> webdriver.Chrome:
        """Initialize Selenium WebDriver"""
        if self.driver is None:
            options = Options()
            if self.headless:
                options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-gpu')
            options.add_argument('--window-size=1920,1080')
            
            try:
                self.driver = webdriver.Chrome(options=options)
                self.driver.set_page_load_timeout(self.timeout)
                logger.info("Chrome WebDriver initialized")
            except Exception as e:
                logger.error(f"Failed to initialize WebDriver: {e}")
                raise
        
        return self.driver
    
    def close_driver(self):
        """Close WebDriver"""
        if self.driver:
            try:
                self.driver.quit()
                self.driver = None
                logger.info("WebDriver closed")
            except Exception as e:
                logger.error(f"Error closing WebDriver: {e}")
    
    # ==================== SIMPLE WEB SCRAPING ====================
    
    def scrape_url(self, url: str) -> Dict[str, Any]:
        """
        Simple web scraping for static content
        
        Returns:
            {
                "url": str,
                "title": str,
                "text": str,
                "links": List[str],
                "images": List[str],
                "metadata": Dict
            }
        """
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Remove script and style elements
            for script in soup(["script", "style"]):
                script.decompose()
            
            # Extract data
            title = soup.title.string if soup.title else ""
            text = soup.get_text(separator='\n', strip=True)
            
            # Extract links
            links = []
            for link in soup.find_all('a', href=True):
                absolute_url = urljoin(url, link['href'])
                links.append(absolute_url)
            
            # Extract images
            images = []
            for img in soup.find_all('img', src=True):
                absolute_url = urljoin(url, img['src'])
                images.append(absolute_url)
            
            # Extract metadata
            metadata = {}
            for meta in soup.find_all('meta'):
                name = meta.get('name') or meta.get('property', '')
                content = meta.get('content', '')
                if name and content:
                    metadata[name] = content
            
            result = {
                "url": url,
                "title": title,
                "text": text,
                "links": links[:50],  # Limit to 50 links
                "images": images[:20],  # Limit to 20 images
                "metadata": metadata,
                "status_code": response.status_code,
                "scraped_at": datetime.now().isoformat()
            }
            
            logger.info(f"Successfully scraped {url}")
            return result
            
        except Exception as e:
            logger.error(f"Failed to scrape {url}: {e}")
            return {
                "url": url,
                "error": str(e),
                "scraped_at": datetime.now().isoformat()
            }
    
    async def scrape_url_async(self, url: str) -> Dict[str, Any]:
        """Async version of scrape_url"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                    content = await response.read()
                    
                    soup = BeautifulSoup(content, 'html.parser')
                    
                    for script in soup(["script", "style"]):
                        script.decompose()
                    
                    title = soup.title.string if soup.title else ""
                    text = soup.get_text(separator='\n', strip=True)
                    
                    links = [urljoin(url, link['href']) for link in soup.find_all('a', href=True)]
                    images = [urljoin(url, img['src']) for img in soup.find_all('img', src=True)]
                    
                    return {
                        "url": url,
                        "title": title,
                        "text": text,
                        "links": links[:50],
                        "images": images[:20],
                        "status_code": response.status,
                        "scraped_at": datetime.now().isoformat()
                    }
        except Exception as e:
            logger.error(f"Async scrape failed for {url}: {e}")
            return {"url": url, "error": str(e)}
    
    # ==================== BROWSER AUTOMATION ====================
    
    def navigate_to(self, url: str) -> bool:
        """Navigate to URL using Selenium"""
        try:
            driver = self._init_driver()
            driver.get(url)
            logger.info(f"Navigated to {url}")
            return True
        except Exception as e:
            logger.error(f"Navigation failed: {e}")
            return False
    
    def get_page_source(self) -> str:
        """Get current page HTML source"""
        if self.driver:
            return self.driver.page_source
        return ""
    
    def get_page_text(self) -> str:
        """Get visible text from current page"""
        try:
            if self.driver:
                soup = BeautifulSoup(self.driver.page_source, 'html.parser')
                for script in soup(["script", "style"]):
                    script.decompose()
                return soup.get_text(separator='\n', strip=True)
            return ""
        except Exception as e:
            logger.error(f"Failed to extract page text: {e}")
            return ""
    
    def click_element(self, selector: str, by: str = "css") -> bool:
        """
        Click element on page
        
        Args:
            selector: Element selector
            by: Selection method - "css", "xpath", "id", "class"
        """
        try:
            driver = self._init_driver()
            
            by_map = {
                "css": By.CSS_SELECTOR,
                "xpath": By.XPATH,
                "id": By.ID,
                "class": By.CLASS_NAME
            }
            
            element = WebDriverWait(driver, 10).until(
                EC.element_to_be_clickable((by_map.get(by, By.CSS_SELECTOR), selector))
            )
            element.click()
            logger.info(f"Clicked element: {selector}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to click element {selector}: {e}")
            return False
    
    def fill_form(self, fields: Dict[str, str]) -> bool:
        """
        Fill form fields
        
        Args:
            fields: Dict of {selector: value} pairs
        """
        try:
            driver = self._init_driver()
            
            for selector, value in fields.items():
                element = WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, selector))
                )
                element.clear()
                element.send_keys(value)
                logger.debug(f"Filled field {selector}")
            
            logger.info(f"Filled {len(fields)} form fields")
            return True
            
        except Exception as e:
            logger.error(f"Failed to fill form: {e}")
            return False
    
    def submit_form(self, selector: str) -> bool:
        """Submit form by selector"""
        try:
            driver = self._init_driver()
            form = driver.find_element(By.CSS_SELECTOR, selector)
            form.submit()
            logger.info("Form submitted")
            return True
        except Exception as e:
            logger.error(f"Failed to submit form: {e}")
            return False
    
    def take_screenshot(self, filepath: str) -> bool:
        """Take screenshot of current page"""
        try:
            driver = self._init_driver()
            driver.save_screenshot(filepath)
            logger.info(f"Screenshot saved to {filepath}")
            return True
        except Exception as e:
            logger.error(f"Failed to take screenshot: {e}")
            return False
    
    def execute_script(self, script: str) -> Any:
        """Execute JavaScript on page"""
        try:
            if self.driver:
                result = self.driver.execute_script(script)
                logger.info("JavaScript executed")
                return result
            return None
        except Exception as e:
            logger.error(f"Failed to execute script: {e}")
            return None
    
    def wait_for_element(self, selector: str, timeout: int = 10) -> bool:
        """Wait for element to appear"""
        try:
            driver = self._init_driver()
            WebDriverWait(driver, timeout).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, selector))
            )
            return True
        except TimeoutException:
            logger.warning(f"Element {selector} not found within {timeout}s")
            return False
    
    # ==================== ADVANCED EXTRACTION ====================
    
    def extract_table(self, table_selector: str = "table") -> List[Dict[str, str]]:
        """Extract table data as list of dicts"""
        try:
            if self.driver:
                soup = BeautifulSoup(self.driver.page_source, 'html.parser')
            else:
                return []
            
            table = soup.select_one(table_selector)
            if not table:
                return []
            
            headers = [th.get_text(strip=True) for th in table.find_all('th')]
            
            if not headers:
                first_row = table.find('tr')
                if first_row:
                    headers = [td.get_text(strip=True) for td in first_row.find_all('td')]
            
            rows = []
            for tr in table.find_all('tr')[1:]:
                cells = [td.get_text(strip=True) for td in tr.find_all('td')]
                if cells:
                    row_dict = {}
                    for i, cell in enumerate(cells):
                        key = headers[i] if i < len(headers) else f"column_{i}"
                        row_dict[key] = cell
                    rows.append(row_dict)
            
            logger.info(f"Extracted {len(rows)} rows from table")
            return rows
            
        except Exception as e:
            logger.error(f"Failed to extract table: {e}")
            return []
    
    def extract_by_selector(self, selector: str, attribute: Optional[str] = None) -> List[str]:
        """Extract elements by CSS selector"""
        try:
            if self.driver:
                soup = BeautifulSoup(self.driver.page_source, 'html.parser')
                elements = soup.select(selector)
                
                if attribute:
                    return [elem.get(attribute, '') for elem in elements if elem.get(attribute)]
                else:
                    return [elem.get_text(strip=True) for elem in elements]
            return []
        except Exception as e:
            logger.error(f"Failed to extract by selector: {e}")
            return []
    
    # ==================== UTILITY METHODS ====================
    
    def get_cookies(self) -> List[Dict]:
        """Get all cookies from current session"""
        if self.driver:
            return self.driver.get_cookies()
        return []
    
    def add_cookie(self, cookie: Dict):
        """Add cookie to session"""
        if self.driver:
            self.driver.add_cookie(cookie)
    
    def get_current_url(self) -> str:
        """Get current page URL"""
        if self.driver:
            return self.driver.current_url
        return ""
    
    def go_back(self):
        """Navigate back"""
        if self.driver:
            self.driver.back()
    
    def go_forward(self):
        """Navigate forward"""
        if self.driver:
            self.driver.forward()
    
    def refresh(self):
        """Refresh current page"""
        if self.driver:
            self.driver.refresh()
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close_driver()
        return False


# ==================== HELPER FUNCTIONS ====================

def clean_text(text: str) -> str:
    """Clean extracted text"""
    text = re.sub(r'\s+', ' ', text)
    text = text.strip()
    return text


def extract_emails(text: str) -> List[str]:
    """Extract email addresses from text"""
    pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    return re.findall(pattern, text)


def extract_phone_numbers(text: str) -> List[str]:
    """Extract phone numbers from text"""
    pattern = r'\+?\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}'
    return re.findall(pattern, text)


def is_valid_url(url: str) -> bool:
    """Validate URL"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

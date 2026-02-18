"""
Live Web Crawler for Real-Time Bug Bounty Testing
Discovers endpoints, parameters, and attack surfaces dynamically
"""

import asyncio
from typing import List, Dict, Set, Optional, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import re
from datetime import datetime
from collections import defaultdict

from bs4 import BeautifulSoup
import aiohttp

from src.utils.logger import get_logger
from src.automation.browser_controller import BrowserController

logger = get_logger(__name__)


class LiveCrawler:
    """
    Real-time web crawler that discovers endpoints, parameters, and injection points
    """
    
    def __init__(self, base_url: str, max_depth: int = 3, max_pages: int = 50):
        """
        Initialize live crawler
        
        Args:
            base_url: Starting URL for crawl
            max_depth: Maximum crawl depth
            max_pages: Maximum pages to crawl
        """
        self.base_url = base_url
        self.max_depth = max_depth
        self.max_pages = max_pages
        
        self.visited_urls: Set[str] = set()
        self.discovered_urls: Set[str] = set()
        self.discovered_endpoints: List[Dict] = []
        self.discovered_parameters: Dict[str, Set[str]] = defaultdict(set)
        self.discovered_forms: List[Dict] = []
        
        self.is_running = False
        self.crawl_stats = {
            "pages_crawled": 0,
            "endpoints_found": 0,
            "parameters_found": 0,
            "forms_found": 0,
            "start_time": None,
            "end_time": None
        }
        
        parsed = urlparse(base_url)
        self.domain = parsed.netloc
        self.scheme = parsed.scheme
    
    def _is_valid_url(self, url: str) -> bool:
        """Check if URL is valid and in scope"""
        try:
            parsed = urlparse(url)
            
            if parsed.netloc != self.domain:
                return False
            
            if parsed.scheme not in ['http', 'https']:
                return False
            
            excluded_extensions = [
                '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico',
                '.css', '.js', '.woff', '.woff2', '.ttf', '.eot',
                '.pdf', '.zip', '.tar', '.gz'
            ]
            
            if any(url.lower().endswith(ext) for ext in excluded_extensions):
                return False
            
            return True
            
        except Exception:
            return False
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL (remove fragments, sort parameters)"""
        parsed = urlparse(url)
        
        query_params = parse_qs(parsed.query)
        sorted_params = sorted(query_params.items())
        normalized_query = urlencode(sorted_params, doseq=True)
        
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if normalized_query:
            normalized += f"?{normalized_query}"
        
        return normalized
    
    def _extract_urls_from_html(self, html: str, current_url: str) -> Set[str]:
        """Extract URLs from HTML content"""
        urls = set()
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            for tag in soup.find_all(['a', 'link'], href=True):
                href = tag.get('href')
                if href:
                    absolute_url = urljoin(current_url, href)
                    if self._is_valid_url(absolute_url):
                        urls.add(self._normalize_url(absolute_url))
            
            for tag in soup.find_all(['script', 'img', 'iframe'], src=True):
                src = tag.get('src')
                if src:
                    absolute_url = urljoin(current_url, src)
                    if self._is_valid_url(absolute_url):
                        urls.add(self._normalize_url(absolute_url))
            
            api_endpoints = re.findall(r'["\']([/][a-zA-Z0-9/_\-\.]+)["\']', html)
            for endpoint in api_endpoints:
                absolute_url = urljoin(current_url, endpoint)
                if self._is_valid_url(absolute_url):
                    urls.add(self._normalize_url(absolute_url))
            
        except Exception as e:
            logger.error(f"Failed to extract URLs: {e}")
        
        return urls
    
    def _extract_parameters(self, url: str) -> Set[str]:
        """Extract parameters from URL"""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            return set(params.keys())
        except Exception:
            return set()
    
    def _extract_forms(self, html: str, current_url: str) -> List[Dict]:
        """Extract forms and their inputs"""
        forms = []
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            for form in soup.find_all('form'):
                form_data = {
                    "url": current_url,
                    "action": urljoin(current_url, form.get('action', '')),
                    "method": form.get('method', 'get').upper(),
                    "inputs": []
                }
                
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_data = {
                        "name": input_tag.get('name', ''),
                        "type": input_tag.get('type', 'text'),
                        "id": input_tag.get('id', ''),
                        "value": input_tag.get('value', ''),
                        "placeholder": input_tag.get('placeholder', '')
                    }
                    
                    if input_data["name"]:
                        form_data["inputs"].append(input_data)
                
                if form_data["inputs"]:
                    forms.append(form_data)
                    self.discovered_forms.append(form_data)
            
        except Exception as e:
            logger.error(f"Failed to extract forms: {e}")
        
        return forms
    
    async def _crawl_url(self, url: str, depth: int = 0) -> Dict[str, Any]:
        """Crawl a single URL"""
        if depth > self.max_depth:
            return {"status": "skipped", "reason": "max_depth"}
        
        if url in self.visited_urls:
            return {"status": "skipped", "reason": "already_visited"}
        
        if len(self.visited_urls) >= self.max_pages:
            return {"status": "skipped", "reason": "max_pages"}
        
        self.visited_urls.add(url)
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    html = await response.text()
                    
                    self.crawl_stats["pages_crawled"] += 1
                    
                    endpoint_info = {
                        "url": url,
                        "method": "GET",
                        "status_code": response.status,
                        "content_type": response.headers.get('Content-Type', ''),
                        "content_length": len(html),
                        "discovered_at": datetime.now().isoformat(),
                        "depth": depth
                    }
                    self.discovered_endpoints.append(endpoint_info)
                    self.crawl_stats["endpoints_found"] += 1
                    
                    params = self._extract_parameters(url)
                    if params:
                        self.discovered_parameters[url].update(params)
                        self.crawl_stats["parameters_found"] += len(params)
                    
                    forms = self._extract_forms(html, url)
                    if forms:
                        self.crawl_stats["forms_found"] += len(forms)
                    
                    new_urls = self._extract_urls_from_html(html, url)
                    self.discovered_urls.update(new_urls)
                    
                    crawl_tasks = []
                    for new_url in list(new_urls)[:5]:
                        if new_url not in self.visited_urls:
                            crawl_tasks.append(self._crawl_url(new_url, depth + 1))
                    
                    if crawl_tasks:
                        await asyncio.gather(*crawl_tasks, return_exceptions=True)
                    
                    return {
                        "status": "success",
                        "url": url,
                        "new_urls": len(new_urls),
                        "forms": len(forms)
                    }
                    
        except asyncio.TimeoutError:
            logger.warning(f"Timeout crawling: {url}")
            return {"status": "error", "error": "timeout", "url": url}
        
        except Exception as e:
            logger.error(f"Failed to crawl {url}: {e}")
            return {"status": "error", "error": str(e), "url": url}
    
    async def start(self) -> Dict[str, Any]:
        """Start crawling from base URL"""
        try:
            logger.info(f"Starting live crawl of: {self.base_url}")
            self.is_running = True
            self.crawl_stats["start_time"] = datetime.now().isoformat()
            
            await self._crawl_url(self.base_url, depth=0)
            
            self.is_running = False
            self.crawl_stats["end_time"] = datetime.now().isoformat()
            
            logger.info(f"Crawl complete. Pages: {self.crawl_stats['pages_crawled']}, "
                       f"Endpoints: {self.crawl_stats['endpoints_found']}, "
                       f"Forms: {self.crawl_stats['forms_found']}")
            
            return {
                "status": "success",
                "stats": self.crawl_stats,
                "endpoints": len(self.discovered_endpoints),
                "forms": len(self.discovered_forms),
                "parameters": sum(len(v) for v in self.discovered_parameters.values())
            }
            
        except Exception as e:
            logger.error(f"Crawl failed: {e}", exc_info=True)
            self.is_running = False
            return {"status": "error", "error": str(e)}
    
    def get_endpoints(self, limit: Optional[int] = None) -> List[Dict]:
        """Get discovered endpoints"""
        if limit:
            return self.discovered_endpoints[:limit]
        return self.discovered_endpoints
    
    def get_forms(self, limit: Optional[int] = None) -> List[Dict]:
        """Get discovered forms"""
        if limit:
            return self.discovered_forms[:limit]
        return self.discovered_forms
    
    def get_parameters(self) -> Dict[str, List[str]]:
        """Get all discovered parameters"""
        return {url: list(params) for url, params in self.discovered_parameters.items()}
    
    def get_injection_points(self) -> List[Dict]:
        """
        Get all potential injection points (parameters and form inputs)
        """
        injection_points = []
        
        for url, params in self.discovered_parameters.items():
            for param in params:
                injection_points.append({
                    "type": "url_parameter",
                    "url": url,
                    "parameter": param,
                    "method": "GET"
                })
        
        for form in self.discovered_forms:
            for input_field in form["inputs"]:
                if input_field["type"] not in ["submit", "button", "reset"]:
                    injection_points.append({
                        "type": "form_input",
                        "url": form["url"],
                        "action": form["action"],
                        "method": form["method"],
                        "input_name": input_field["name"],
                        "input_type": input_field["type"]
                    })
        
        logger.info(f"Found {len(injection_points)} potential injection points")
        return injection_points
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current crawl statistics"""
        return {
            **self.crawl_stats,
            "is_running": self.is_running,
            "urls_in_queue": len(self.discovered_urls - self.visited_urls),
            "total_parameters": sum(len(v) for v in self.discovered_parameters.values())
        }


_crawler_instance: Optional[LiveCrawler] = None


def get_live_crawler(base_url: str, max_depth: int = 3, max_pages: int = 50) -> LiveCrawler:
    """Get or create live crawler instance"""
    global _crawler_instance
    _crawler_instance = LiveCrawler(base_url, max_depth, max_pages)
    return _crawler_instance

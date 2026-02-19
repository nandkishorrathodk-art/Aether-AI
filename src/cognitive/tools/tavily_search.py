"""
Tavily Search Tool - AI-Optimized Web Search

Tavily is specifically designed for AI agents:
- Returns clean, structured data (not HTML soup)
- Filters out ads and SEO spam
- Optimized for LLM consumption
- Much better than Google/Bing for AI agents

Boss, ab Aether ko duniya ki koi bhi jankari mil sakti hai!
"""

import logging
from typing import List, Dict, Optional, Any
import os
from datetime import datetime

logger = logging.getLogger(__name__)

try:
    from tavily import TavilyClient
    TAVILY_AVAILABLE = True
except ImportError:
    logger.warning("Tavily not installed. Install with: pip install tavily-python")
    TAVILY_AVAILABLE = False


class TavilySearchTool:
    """
    Tavily search tool for Jarvis brain
    
    Gives Aether the ability to search the web for current information
    like a human would Google something.
    
    Example:
        search = TavilySearchTool()
        results = search.search("Latest AI news 2026")
    """
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize Tavily search
        
        Args:
            api_key: Tavily API key (or set TAVILY_API_KEY env var)
        """
        if not TAVILY_AVAILABLE:
            logger.error("Tavily not installed!")
            self.client = None
            return
        
        self.api_key = api_key or os.getenv("TAVILY_API_KEY")
        
        if not self.api_key:
            logger.warning("No Tavily API key found. Get free key from: https://tavily.com")
            self.client = None
        else:
            try:
                self.client = TavilyClient(api_key=self.api_key)
                logger.info("Tavily Search Tool initialized")
            except Exception as e:
                logger.error(f"Failed to initialize Tavily: {e}")
                self.client = None
    
    def search(
        self,
        query: str,
        max_results: int = 5,
        search_depth: str = "advanced",
        include_domains: Optional[List[str]] = None,
        exclude_domains: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Search the web using Tavily
        
        Args:
            query: Search query
            max_results: Number of results (default 5)
            search_depth: "basic" or "advanced" (advanced is deeper/slower)
            include_domains: Only search these domains
            exclude_domains: Exclude these domains
            
        Returns:
            List of search results with clean content
        """
        if not self.client:
            logger.error("Tavily client not available")
            return []
        
        try:
            response = self.client.search(
                query=query,
                max_results=max_results,
                search_depth=search_depth,
                include_domains=include_domains,
                exclude_domains=exclude_domains
            )
            
            results = []
            for item in response.get('results', []):
                results.append({
                    "title": item.get('title', ''),
                    "url": item.get('url', ''),
                    "content": item.get('content', ''),
                    "score": item.get('score', 0.0),
                    "published_date": item.get('published_date', None)
                })
            
            logger.info(f"Tavily search '{query}' returned {len(results)} results")
            return results
        
        except Exception as e:
            logger.error(f"Tavily search failed: {e}")
            return []
    
    def quick_answer(self, query: str) -> Optional[str]:
        """
        Get a quick answer to a question
        
        Args:
            query: Question to ask
            
        Returns:
            Direct answer string or None
        """
        if not self.client:
            return None
        
        try:
            response = self.client.qna_search(query=query)
            answer = response.get('answer', None)
            
            if answer:
                logger.info(f"Quick answer for '{query}': {answer[:100]}")
            
            return answer
        
        except Exception as e:
            logger.error(f"Quick answer failed: {e}")
            return None
    
    def search_news(
        self,
        query: str,
        max_results: int = 5,
        days: int = 7
    ) -> List[Dict[str, Any]]:
        """
        Search recent news articles
        
        Args:
            query: News topic to search
            max_results: Number of articles
            days: How many days back to search
            
        Returns:
            List of news articles
        """
        if not self.client:
            return []
        
        try:
            response = self.client.search(
                query=query,
                max_results=max_results,
                search_depth="advanced",
                days=days
            )
            
            results = []
            for item in response.get('results', []):
                if item.get('published_date'):
                    results.append({
                        "title": item.get('title', ''),
                        "url": item.get('url', ''),
                        "content": item.get('content', ''),
                        "published_date": item.get('published_date'),
                        "score": item.get('score', 0.0)
                    })
            
            results.sort(key=lambda x: x['published_date'], reverse=True)
            
            logger.info(f"Found {len(results)} news articles for '{query}'")
            return results
        
        except Exception as e:
            logger.error(f"News search failed: {e}")
            return []
    
    def is_available(self) -> bool:
        """Check if Tavily is available and configured"""
        return self.client is not None


_tavily_instance = None

def get_tavily_search() -> TavilySearchTool:
    """Get global Tavily search instance"""
    global _tavily_instance
    
    if _tavily_instance is None:
        _tavily_instance = TavilySearchTool()
    
    return _tavily_instance


logger.info("Tavily Search Tool loaded")

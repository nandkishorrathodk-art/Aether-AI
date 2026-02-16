"""
Web Research - Automated research, scraping, and knowledge synthesis.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import requests
from bs4 import BeautifulSoup
import re


@dataclass
class ResearchResult:
    """Web research result."""
    query: str
    sources: List[Dict[str, Any]]
    summary: str
    key_findings: List[str]
    confidence: float
    timestamp: str


@dataclass
class WebPage:
    """Web page content."""
    url: str
    title: str
    content: str
    extracted_data: Dict[str, Any]
    timestamp: str


class WebResearcher:
    """
    Automated web research and knowledge synthesis system.
    
    Performs research queries, scrapes content, and synthesizes insights.
    """
    
    def __init__(self, llm_provider=None):
        """
        Initialize web researcher.
        
        Args:
            llm_provider: LLM for content synthesis
        """
        self.llm_provider = llm_provider
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
    
    def research(self, query: str, max_sources: int = 5) -> ResearchResult:
        """
        Conduct automated research on a topic.
        
        Args:
            query: Research query
            max_sources: Maximum sources to analyze
            
        Returns:
            ResearchResult with findings
        """
        sources = self._search_web(query, max_sources)
        
        pages = []
        for source in sources:
            try:
                page = self.scrape_page(source['url'])
                pages.append(page)
            except Exception as e:
                print(f"Failed to scrape {source['url']}: {e}")
        
        summary = self._synthesize_content(query, pages)
        
        key_findings = self._extract_key_findings(query, pages)
        
        confidence = self._assess_confidence(sources, pages)
        
        return ResearchResult(
            query=query,
            sources=[{'url': p.url, 'title': p.title} for p in pages],
            summary=summary,
            key_findings=key_findings,
            confidence=confidence,
            timestamp=datetime.now().isoformat()
        )
    
    def _search_web(self, query: str, max_results: int) -> List[Dict[str, str]]:
        """
        Search web for relevant sources.
        
        Note: This is a placeholder. In production, integrate with:
        - Google Custom Search API
        - Bing Search API
        - DuckDuckGo API
        """
        return [
            {'url': f'https://example.com/result{i}', 'title': f'Result {i}'}
            for i in range(1, max_results + 1)
        ]
    
    def scrape_page(self, url: str) -> WebPage:
        """
        Scrape web page content.
        
        Args:
            url: Page URL
            
        Returns:
            WebPage with extracted content
        """
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            for script in soup(['script', 'style']):
                script.decompose()
            
            title = soup.title.string if soup.title else url
            
            paragraphs = soup.find_all('p')
            content = '\n\n'.join([p.get_text().strip() for p in paragraphs if p.get_text().strip()])
            
            extracted_data = self._extract_structured_data(soup)
            
            return WebPage(
                url=url,
                title=title,
                content=content[:5000],
                extracted_data=extracted_data,
                timestamp=datetime.now().isoformat()
            )
            
        except Exception as e:
            raise Exception(f"Failed to scrape {url}: {str(e)}")
    
    def _extract_structured_data(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Extract structured data from page."""
        data = {}
        
        headings = [h.get_text().strip() for h in soup.find_all(['h1', 'h2', 'h3']) if h.get_text().strip()]
        data['headings'] = headings[:10]
        
        links = [a.get('href') for a in soup.find_all('a', href=True)]
        data['link_count'] = len(links)
        
        images = soup.find_all('img')
        data['image_count'] = len(images)
        
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        if meta_desc:
            data['meta_description'] = meta_desc.get('content', '')
        
        return data
    
    def _synthesize_content(self, query: str, pages: List[WebPage]) -> str:
        """Synthesize research findings."""
        if not self.llm_provider:
            return self._synthesize_content_heuristic(pages)
        
        combined_content = '\n\n---\n\n'.join([
            f"Source: {page.title}\n{page.content[:1000]}"
            for page in pages
        ])
        
        prompt = f"""Synthesize research findings for: {query}

Sources:
{combined_content}

Provide a comprehensive 3-4 paragraph summary of key insights:

Summary:"""
        
        try:
            response = self.llm_provider.generate(
                prompt,
                max_tokens=500,
                temperature=0.5,
                task_type='analysis'
            )
            
            return response.get('content', '').strip()
            
        except Exception as e:
            print(f"Synthesis error: {e}")
            return self._synthesize_content_heuristic(pages)
    
    def _synthesize_content_heuristic(self, pages: List[WebPage]) -> str:
        """Fallback synthesis without LLM."""
        if not pages:
            return "No sources available for synthesis."
        
        all_content = ' '.join([page.content for page in pages])
        
        sentences = re.split(r'[.!?]\s+', all_content)
        
        summary_sentences = sentences[:5]
        
        return '. '.join(summary_sentences) + '.'
    
    def _extract_key_findings(self, query: str, pages: List[WebPage]) -> List[str]:
        """Extract key findings from sources."""
        findings = []
        
        for page in pages[:3]:
            sentences = re.split(r'[.!?]\s+', page.content)
            
            relevant = [
                s for s in sentences
                if any(word.lower() in s.lower() for word in query.split())
                and len(s) > 50
            ]
            
            findings.extend(relevant[:2])
        
        return findings[:5]
    
    def _assess_confidence(self, sources: List[Dict[str, str]], 
                          pages: List[WebPage]) -> float:
        """Assess research confidence."""
        confidence = 0.5
        
        if len(pages) >= 3:
            confidence += 0.2
        
        total_content = sum(len(page.content) for page in pages)
        if total_content > 2000:
            confidence += 0.2
        
        if len(pages) >= len(sources) * 0.8:
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    def extract_data_from_page(self, url: str, selectors: Dict[str, str]) -> Dict[str, Any]:
        """
        Extract specific data from page using CSS selectors.
        
        Args:
            url: Page URL
            selectors: Dict of {field_name: css_selector}
            
        Returns:
            Extracted data dictionary
        """
        page = self.scrape_page(url)
        
        soup = BeautifulSoup(page.content, 'html.parser')
        
        extracted = {}
        
        for field, selector in selectors.items():
            elements = soup.select(selector)
            
            if elements:
                extracted[field] = [elem.get_text().strip() for elem in elements]
            else:
                extracted[field] = []
        
        return extracted
    
    def monitor_page_changes(self, url: str, previous_content: Optional[str] = None) -> Dict[str, Any]:
        """Monitor page for changes."""
        current_page = self.scrape_page(url)
        
        if not previous_content:
            return {
                'changed': False,
                'current_content': current_page.content,
                'message': 'No previous content to compare'
            }
        
        current_hash = hash(current_page.content)
        previous_hash = hash(previous_content)
        
        changed = current_hash != previous_hash
        
        return {
            'changed': changed,
            'current_content': current_page.content,
            'timestamp': current_page.timestamp,
            'url': url
        }
    
    def build_knowledge_graph(self, topic: str, depth: int = 2) -> Dict[str, Any]:
        """
        Build knowledge graph for a topic.
        
        Args:
            topic: Central topic
            depth: Exploration depth
            
        Returns:
            Knowledge graph structure
        """
        nodes = [{'id': topic, 'type': 'root', 'level': 0}]
        edges = []
        
        research = self.research(topic, max_sources=3)
        
        for i, finding in enumerate(research.key_findings[:5]):
            node_id = f"{topic}_finding_{i}"
            nodes.append({'id': node_id, 'type': 'finding', 'level': 1, 'content': finding})
            edges.append({'from': topic, 'to': node_id, 'type': 'has_finding'})
        
        for source in research.sources[:3]:
            node_id = source['url']
            nodes.append({'id': node_id, 'type': 'source', 'level': 1, 'title': source['title']})
            edges.append({'from': topic, 'to': node_id, 'type': 'sourced_from'})
        
        return {
            'topic': topic,
            'nodes': nodes,
            'edges': edges,
            'depth': depth,
            'timestamp': datetime.now().isoformat()
        }

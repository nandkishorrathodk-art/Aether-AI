"""
Trend Analyzer Module
Analyzes trends in bug bounty programs, YouTube, and tech job market
"""

import logging
from typing import Dict, List, Optional
from datetime import datetime
import aiohttp
import asyncio
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


class TrendData:
    """Data model for trend information"""
    
    def __init__(
        self,
        category: str,
        trends: List[Dict],
        analysis: str,
        updated_at: str
    ):
        self.category = category
        self.trends = trends
        self.analysis = analysis
        self.updated_at = updated_at
    
    def to_dict(self) -> Dict:
        return {
            "category": self.category,
            "trends": self.trends,
            "analysis": self.analysis,
            "updated_at": self.updated_at
        }


class TrendAnalyzer:
    """Analyzes trends across multiple domains"""
    
    def __init__(self):
        self.cache = {}
        self.cache_duration = 3600
        logger.info("TrendAnalyzer initialized")
    
    async def analyze_bug_bounty_trends(self) -> TrendData:
        """Analyze bug bounty program trends"""
        logger.info("Analyzing bug bounty trends")
        
        if self._is_cached("bug_bounty"):
            return self.cache["bug_bounty"]
        
        trends = []
        
        trends.append({
            "program": "Apple Security Bounty",
            "max_payout": 2000000,
            "bonus_potential": 5000000,
            "focus_areas": [
                "Network attacks without user interaction",
                "Kernel code execution",
                "Lockdown Mode bypass",
                "Zero-click attacks"
            ],
            "status": "active",
            "difficulty": "high",
            "url": "https://security.apple.com/bounty/"
        })
        
        trends.append({
            "program": "Google VRP",
            "max_payout": 151515,
            "focus_areas": [
                "Chrome vulnerabilities",
                "Android exploits",
                "Google Cloud security",
                "Authentication bypasses"
            ],
            "status": "active",
            "difficulty": "medium-high",
            "url": "https://bughunters.google.com/"
        })
        
        trends.append({
            "program": "Microsoft Bug Bounty",
            "max_payout": 100000,
            "focus_areas": [
                "Azure security",
                "Microsoft 365",
                "Windows vulnerabilities",
                "Identity platform"
            ],
            "status": "active",
            "difficulty": "medium",
            "url": "https://www.microsoft.com/en-us/msrc/bounty"
        })
        
        try:
            web3_trends = await self._fetch_immunefi_trends()
            trends.extend(web3_trends)
        except Exception as e:
            logger.error(f"Failed to fetch Immunefi trends: {e}")
        
        analysis = self._analyze_bug_bounty_data(trends)
        
        trend_data = TrendData(
            category="bug_bounty",
            trends=trends,
            analysis=analysis,
            updated_at=datetime.now().isoformat()
        )
        
        self.cache["bug_bounty"] = trend_data
        return trend_data
    
    async def analyze_youtube_trends(self) -> TrendData:
        """Analyze YouTube trending topics and CPM rates"""
        logger.info("Analyzing YouTube trends")
        
        if self._is_cached("youtube"):
            return self.cache["youtube"]
        
        trends = [
            {
                "niche": "AI Tools & Reviews",
                "cpm_range": [10, 25],
                "competition": "medium",
                "growth_rate": "high",
                "recommended": True,
                "keywords": ["ChatGPT", "AI productivity", "automation tools"]
            },
            {
                "niche": "Faceless Ambient Content",
                "cpm_range": [5, 15],
                "competition": "low",
                "growth_rate": "medium",
                "recommended": True,
                "keywords": ["sleep sounds", "study music", "meditation"]
            },
            {
                "niche": "Historical What-Ifs",
                "cpm_range": [8, 20],
                "competition": "medium",
                "growth_rate": "high",
                "recommended": True,
                "keywords": ["alternate history", "what if scenarios"]
            },
            {
                "niche": "Betrayal/Story Time",
                "cpm_range": [10, 18],
                "competition": "high",
                "growth_rate": "medium",
                "recommended": False,
                "keywords": ["relationship stories", "revenge stories"]
            },
            {
                "niche": "Cybersecurity Education",
                "cpm_range": [12, 30],
                "competition": "low",
                "growth_rate": "high",
                "recommended": True,
                "keywords": ["ethical hacking", "bug bounty tutorials", "security news"]
            }
        ]
        
        analysis = self._analyze_youtube_data(trends)
        
        trend_data = TrendData(
            category="youtube",
            trends=trends,
            analysis=analysis,
            updated_at=datetime.now().isoformat()
        )
        
        self.cache["youtube"] = trend_data
        return trend_data
    
    async def analyze_tech_job_trends(self) -> TrendData:
        """Analyze tech job market trends"""
        logger.info("Analyzing tech job market trends")
        
        if self._is_cached("tech_jobs"):
            return self.cache["tech_jobs"]
        
        trends = [
            {
                "role": "Security Engineer",
                "avg_salary_usd": 150000,
                "remote_available": True,
                "demand": "very_high",
                "required_skills": [
                    "Penetration testing",
                    "Vulnerability assessment",
                    "Security automation",
                    "Cloud security"
                ]
            },
            {
                "role": "Bug Bounty Hunter (Full-time)",
                "avg_salary_usd": 200000,
                "remote_available": True,
                "demand": "high",
                "required_skills": [
                    "Web app security",
                    "Exploit development",
                    "Reverse engineering",
                    "Report writing"
                ]
            },
            {
                "role": "AI/ML Engineer",
                "avg_salary_usd": 180000,
                "remote_available": True,
                "demand": "very_high",
                "required_skills": [
                    "Python",
                    "TensorFlow/PyTorch",
                    "LLM development",
                    "Model deployment"
                ]
            },
            {
                "role": "DevSecOps Engineer",
                "avg_salary_usd": 140000,
                "remote_available": True,
                "demand": "high",
                "required_skills": [
                    "CI/CD security",
                    "Container security",
                    "Infrastructure as Code",
                    "Security automation"
                ]
            }
        ]
        
        analysis = self._analyze_job_market_data(trends)
        
        trend_data = TrendData(
            category="tech_jobs",
            trends=trends,
            analysis=analysis,
            updated_at=datetime.now().isoformat()
        )
        
        self.cache["tech_jobs"] = trend_data
        return trend_data
    
    async def get_all_trends(self) -> Dict:
        """Get all trend analyses"""
        logger.info("Fetching all trends")
        
        bug_bounty_trends = await self.analyze_bug_bounty_trends()
        youtube_trends = await self.analyze_youtube_trends()
        job_trends = await self.analyze_tech_job_trends()
        
        return {
            "bug_bounty": bug_bounty_trends.to_dict(),
            "youtube": youtube_trends.to_dict(),
            "tech_jobs": job_trends.to_dict(),
            "generated_at": datetime.now().isoformat()
        }
    
    async def _fetch_immunefi_trends(self) -> List[Dict]:
        """Fetch Web3 bug bounty trends from Immunefi (simulated)"""
        return [
            {
                "program": "Immunefi Web3 Programs",
                "max_payout": 10000000,
                "focus_areas": [
                    "Smart contract vulnerabilities",
                    "DeFi protocol exploits",
                    "Blockchain consensus bugs",
                    "Wallet security"
                ],
                "status": "active",
                "difficulty": "high",
                "note": "High payouts but requires blockchain expertise",
                "url": "https://immunefi.com/"
            }
        ]
    
    def _analyze_bug_bounty_data(self, trends: List[Dict]) -> str:
        """Generate analysis of bug bounty trends"""
        total_programs = len(trends)
        max_payout = max(t.get("max_payout", 0) for t in trends)
        
        analysis = f"Analysis: {total_programs} active programs tracked. "
        analysis += f"Highest payout: ${max_payout:,}. "
        analysis += "Focus on Apple Security Bounty for maximum earning potential. "
        analysis += "Web3/DeFi programs offer high payouts but require specialized skills. "
        analysis += "Recommendation: Start with Google/Microsoft programs for learning, "
        analysis += "then target Apple for high-value bugs."
        
        return analysis
    
    def _analyze_youtube_data(self, trends: List[Dict]) -> str:
        """Generate analysis of YouTube trends"""
        recommended = [t for t in trends if t.get("recommended", False)]
        avg_cpm = sum(sum(t["cpm_range"]) / 2 for t in trends) / len(trends)
        
        analysis = f"Analysis: {len(recommended)} recommended niches out of {len(trends)}. "
        analysis += f"Average CPM: ${avg_cpm:.2f}. "
        analysis += "AI Tools & Cybersecurity Education offer best combination of CPM and low competition. "
        analysis += "Faceless content is ideal for scaling with automation. "
        analysis += "Focus on high-CPM niches ($10+) for better monetization."
        
        return analysis
    
    def _analyze_job_market_data(self, trends: List[Dict]) -> str:
        """Generate analysis of job market trends"""
        avg_salary = sum(t.get("avg_salary_usd", 0) for t in trends) / len(trends)
        remote_count = sum(1 for t in trends if t.get("remote_available", False))
        
        analysis = f"Analysis: {len(trends)} high-demand roles tracked. "
        analysis += f"Average salary: ${avg_salary:,.0f}. "
        analysis += f"{remote_count} roles offer remote work. "
        analysis += "Security and AI/ML roles show highest demand. "
        analysis += "Bug Bounty Hunter full-time positions offer competitive salaries. "
        analysis += "Recommendation: Build security skills for best career prospects."
        
        return analysis
    
    def _is_cached(self, category: str) -> bool:
        """Check if trend data is cached and valid"""
        if category not in self.cache:
            return False
        
        cached_data = self.cache[category]
        cached_time = datetime.fromisoformat(cached_data.updated_at)
        
        age_seconds = (datetime.now() - cached_time).total_seconds()
        return age_seconds < self.cache_duration
    
    def clear_cache(self):
        """Clear trend cache"""
        self.cache.clear()
        logger.info("Trend cache cleared")

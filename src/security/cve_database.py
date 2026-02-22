"""
CVE Database Manager for Aether AI
Manages 200k+ CVE entries from NIST NVD database
"""
import asyncio
import json
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import aiohttp
from pathlib import Path

from src.utils.logger import get_logger
from src.config import settings

logger = get_logger(__name__)


class CVEDatabase:
    """
    Manages CVE (Common Vulnerabilities and Exposures) database.
    
    Features:
    - 200k+ CVE entries from NIST NVD
    - Smart search by keyword, CVE ID, CPE
    - CVSS scoring and severity classification
    - Auto-update from NVD API
    - Local caching for offline use
    """
    
    def __init__(self, cache_dir: Optional[Path] = None):
        """
        Initialize CVE database.
        
        Args:
            cache_dir: Directory to cache CVE data (default: ./data/cve_cache)
        """
        self.cache_dir = cache_dir or Path("./data/cve_cache")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self.cve_cache_file = self.cache_dir / "cve_database.json"
        self.last_update_file = self.cache_dir / "last_update.txt"
        
        self.cves: Dict[str, Dict] = {}
        self.nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        logger.info("CVE Database initialized")
    
    async def load_cache(self) -> int:
        """
        Load CVEs from local cache.
        
        Returns:
            Number of CVEs loaded
        """
        try:
            if self.cve_cache_file.exists():
                with open(self.cve_cache_file, 'r', encoding='utf-8') as f:
                    self.cves = json.load(f)
                
                logger.info(f"Loaded {len(self.cves)} CVEs from cache")
                return len(self.cves)
            else:
                logger.warning("No CVE cache found, database is empty")
                return 0
        
        except Exception as e:
            logger.error(f"Error loading CVE cache: {e}")
            return 0
    
    async def save_cache(self):
        """Save CVEs to local cache."""
        try:
            with open(self.cve_cache_file, 'w', encoding='utf-8') as f:
                json.dump(self.cves, f, indent=2)
            
            with open(self.last_update_file, 'w') as f:
                f.write(datetime.now().isoformat())
            
            logger.info(f"Saved {len(self.cves)} CVEs to cache")
        
        except Exception as e:
            logger.error(f"Error saving CVE cache: {e}")
    
    async def fetch_from_nvd(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        max_results: int = 2000
    ) -> int:
        """
        Fetch CVEs from NIST NVD API.
        
        Args:
            start_date: Start date for CVE search
            end_date: End date for CVE search
            max_results: Maximum number of CVEs to fetch
        
        Returns:
            Number of CVEs fetched
        """
        try:
            params = {
                "resultsPerPage": min(max_results, 2000),
                "startIndex": 0
            }
            
            if start_date:
                params["pubStartDate"] = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
            
            if end_date:
                params["pubEndDate"] = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
            
            count = 0
            
            async with aiohttp.ClientSession() as session:
                while count < max_results:
                    async with session.get(self.nvd_api_url, params=params) as response:
                        if response.status != 200:
                            logger.error(f"NVD API error: {response.status}")
                            break
                        
                        data = await response.json()
                        
                        vulnerabilities = data.get("vulnerabilities", [])
                        if not vulnerabilities:
                            break
                        
                        for vuln in vulnerabilities:
                            cve_data = vuln.get("cve", {})
                            cve_id = cve_data.get("id")
                            
                            if cve_id:
                                self.cves[cve_id] = self._parse_cve(cve_data)
                                count += 1
                        
                        # Check if more results available
                        total_results = data.get("totalResults", 0)
                        if params["startIndex"] + len(vulnerabilities) >= total_results:
                            break
                        
                        params["startIndex"] += len(vulnerabilities)
                        
                        # Rate limiting (5 requests per 30 seconds for NVD API)
                        await asyncio.sleep(6)
            
            logger.info(f"Fetched {count} CVEs from NVD")
            return count
        
        except Exception as e:
            logger.error(f"Error fetching from NVD: {e}")
            return 0
    
    def _parse_cve(self, cve_data: Dict) -> Dict:
        """
        Parse CVE data from NVD format.
        
        Args:
            cve_data: Raw CVE data from NVD
        
        Returns:
            Parsed CVE dictionary
        """
        cve_id = cve_data.get("id", "")
        
        # Extract description
        descriptions = cve_data.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        
        # Extract CVSS scores
        metrics = cve_data.get("metrics", {})
        cvss_v3 = metrics.get("cvssMetricV31", [])
        cvss_v2 = metrics.get("cvssMetricV2", [])
        
        cvss_score = 0.0
        severity = "UNKNOWN"
        
        if cvss_v3:
            cvss_data = cvss_v3[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", 0.0)
            severity = cvss_data.get("baseSeverity", "UNKNOWN")
        elif cvss_v2:
            cvss_data = cvss_v2[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", 0.0)
            severity = self._cvss2_to_severity(cvss_score)
        
        # Extract references
        references = []
        for ref in cve_data.get("references", []):
            references.append({
                "url": ref.get("url", ""),
                "source": ref.get("source", ""),
                "tags": ref.get("tags", [])
            })
        
        # Extract CPEs (affected products)
        cpes = []
        configurations = cve_data.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable"):
                        cpes.append(cpe_match.get("criteria", ""))
        
        # Extract published/modified dates
        published = cve_data.get("published", "")
        modified = cve_data.get("lastModified", "")
        
        return {
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "severity": severity,
            "published": published,
            "modified": modified,
            "references": references,
            "cpes": cpes,
            "raw": cve_data  # Keep raw data for advanced queries
        }
    
    def _cvss2_to_severity(self, score: float) -> str:
        """Convert CVSS v2 score to severity."""
        if score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0:
            return "LOW"
        else:
            return "UNKNOWN"
    
    async def search(
        self,
        query: str,
        max_results: int = 50,
        min_severity: str = "LOW"
    ) -> List[Dict]:
        """
        Search CVEs by keyword.
        
        Args:
            query: Search query (searches in description and CVE ID)
            max_results: Maximum number of results
            min_severity: Minimum severity (LOW, MEDIUM, HIGH, CRITICAL)
        
        Returns:
            List of matching CVEs
        """
        query_lower = query.lower()
        results = []
        
        severity_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        min_severity_level = severity_order.get(min_severity, 0)
        
        for cve_id, cve in self.cves.items():
            # Check severity filter
            cve_severity_level = severity_order.get(cve.get("severity", "UNKNOWN"), 0)
            if cve_severity_level < min_severity_level:
                continue
            
            # Search in CVE ID and description
            if (query_lower in cve_id.lower() or 
                query_lower in cve.get("description", "").lower()):
                results.append(cve)
            
            if len(results) >= max_results:
                break
        
        # Sort by CVSS score (highest first)
        results.sort(key=lambda x: x.get("cvss_score", 0.0), reverse=True)
        
        return results
    
    async def get_by_id(self, cve_id: str) -> Optional[Dict]:
        """
        Get CVE by ID.
        
        Args:
            cve_id: CVE ID (e.g., CVE-2021-44228)
        
        Returns:
            CVE dictionary or None if not found
        """
        return self.cves.get(cve_id.upper())
    
    async def search_by_product(
        self,
        product_name: str,
        max_results: int = 50
    ) -> List[Dict]:
        """
        Search CVEs affecting specific product.
        
        Args:
            product_name: Product name (searches in CPEs)
            max_results: Maximum number of results
        
        Returns:
            List of matching CVEs
        """
        product_lower = product_name.lower()
        results = []
        
        for cve_id, cve in self.cves.items():
            # Search in CPEs (affected products)
            cpes = cve.get("cpes", [])
            for cpe in cpes:
                if product_lower in cpe.lower():
                    results.append(cve)
                    break
            
            if len(results) >= max_results:
                break
        
        # Sort by CVSS score (highest first)
        results.sort(key=lambda x: x.get("cvss_score", 0.0), reverse=True)
        
        return results
    
    async def get_statistics(self) -> Dict:
        """
        Get CVE database statistics.
        
        Returns:
            Statistics dictionary
        """
        total = len(self.cves)
        
        severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0, "UNKNOWN": 0}
        
        for cve in self.cves.values():
            severity = cve.get("severity", "UNKNOWN")
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts["UNKNOWN"] += 1
        
        return {
            "total_cves": total,
            "severity_breakdown": severity_counts,
            "last_update": self._get_last_update()
        }
    
    def _get_last_update(self) -> Optional[str]:
        """Get last database update timestamp."""
        try:
            if self.last_update_file.exists():
                with open(self.last_update_file, 'r') as f:
                    return f.read().strip()
        except:
            pass
        return None
    
    async def update_database(self, days_back: int = 30) -> int:
        """
        Update CVE database with recent CVEs.
        
        Args:
            days_back: Fetch CVEs from last N days
        
        Returns:
            Number of new CVEs added
        """
        logger.info(f"Updating CVE database (last {days_back} days)...")
        
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days_back)
        
        initial_count = len(self.cves)
        
        await self.fetch_from_nvd(start_date=start_date, end_date=end_date)
        
        new_count = len(self.cves) - initial_count
        
        await self.save_cache()
        
        logger.info(f"Added {new_count} new CVEs")
        
        return new_count


# Global instance
_cve_db = None

async def get_cve_database() -> CVEDatabase:
    """Get global CVE database instance."""
    global _cve_db
    if _cve_db is None:
        _cve_db = CVEDatabase()
        await _cve_db.load_cache()
    return _cve_db

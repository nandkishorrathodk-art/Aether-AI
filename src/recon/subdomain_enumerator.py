"""
Subdomain Enumeration

Find subdomains using multiple techniques: DNS, certificate transparency, brute force.
"""

import asyncio
import subprocess
import json
import dns.resolver
from typing import List, Set, Dict, Any
from pathlib import Path
from src.utils.logger import get_logger

logger = get_logger(__name__)


class SubdomainEnumerator:
    """
    Automated subdomain enumeration
    """
    
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.resolver.lifetime = 2
        self.wordlist_path = Path("data/wordlists/subdomains.txt")
        logger.info("Subdomain Enumerator initialized")
    
    async def enumerate(
        self,
        domain: str,
        methods: List[str] = None,
        max_results: int = 500
    ) -> Dict[str, Any]:
        """
        Enumerate subdomains using multiple methods
        
        Args:
            domain: Target domain
            methods: Methods to use (None = all available)
            max_results: Maximum number of results
            
        Returns:
            Dict with subdomains and metadata
        """
        try:
            if methods is None:
                methods = ["dns", "crt", "bruteforce"]
            
            all_subdomains = set()
            results_by_method = {}
            
            if "dns" in methods:
                logger.info(f"Running DNS enumeration for {domain}")
                dns_results = await self._dns_enumeration(domain)
                all_subdomains.update(dns_results)
                results_by_method["dns"] = dns_results
            
            if "crt" in methods:
                logger.info(f"Running Certificate Transparency search for {domain}")
                crt_results = await self._certificate_transparency(domain)
                all_subdomains.update(crt_results)
                results_by_method["crt"] = crt_results
            
            if "bruteforce" in methods:
                logger.info(f"Running brute force enumeration for {domain}")
                brute_results = await self._brute_force(domain, max_results)
                all_subdomains.update(brute_results)
                results_by_method["bruteforce"] = brute_results
            
            if "external" in methods:
                logger.info(f"Running external tool enumeration for {domain}")
                external_results = await self._external_tools(domain)
                all_subdomains.update(external_results)
                results_by_method["external"] = external_results
            
            alive_subdomains = await self._check_alive(list(all_subdomains)[:max_results])
            
            logger.info(f"Found {len(all_subdomains)} total subdomains, {len(alive_subdomains)} alive")
            
            return {
                "domain": domain,
                "total_found": len(all_subdomains),
                "alive_count": len(alive_subdomains),
                "subdomains": sorted(list(all_subdomains))[:max_results],
                "alive_subdomains": sorted(alive_subdomains),
                "results_by_method": {k: len(v) for k, v in results_by_method.items()},
                "methods_used": methods
            }
            
        except Exception as e:
            logger.error(f"Subdomain enumeration failed: {e}")
            return {
                "domain": domain,
                "error": str(e),
                "subdomains": []
            }
    
    async def _dns_enumeration(self, domain: str) -> Set[str]:
        """DNS-based subdomain enumeration"""
        subdomains = set()
        
        common_subdomains = [
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
            "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
            "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn",
            "ns3", "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx",
            "static", "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar",
            "wiki", "web", "media", "email", "images", "img", "www1", "intranet",
            "portal", "video", "sip", "dns2", "api", "cdn", "stats", "dns1", "ns4",
            "www3", "dns", "search", "staging", "server", "mx1", "chat", "wap", "my",
            "svn", "mail1", "sites", "proxy", "ads", "host", "crm", "cms", "backup",
            "mx2", "lyncdiscover", "info", "apps", "download", "remote", "db", "forums",
            "store", "relay", "files", "newsletter", "app", "live", "owa", "en"
        ]
        
        tasks = []
        for sub in common_subdomains:
            tasks.append(self._check_dns(f"{sub}.{domain}"))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for i, result in enumerate(results):
            if result and not isinstance(result, Exception):
                subdomains.add(f"{common_subdomains[i]}.{domain}")
        
        return subdomains
    
    async def _check_dns(self, hostname: str) -> bool:
        """Check if DNS resolves"""
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self.resolver.resolve, hostname, 'A')
            return True
        except:
            return False
    
    async def _certificate_transparency(self, domain: str) -> Set[str]:
        """Certificate Transparency logs search"""
        subdomains = set()
        
        try:
            import aiohttp
            
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        for entry in data:
                            name_value = entry.get("name_value", "")
                            for subdomain in name_value.split("\n"):
                                subdomain = subdomain.strip()
                                if subdomain.endswith(domain) and "*" not in subdomain:
                                    subdomains.add(subdomain)
                        
                        logger.info(f"Certificate Transparency found {len(subdomains)} subdomains")
        
        except Exception as e:
            logger.warning(f"Certificate Transparency search failed: {e}")
        
        return subdomains
    
    async def _brute_force(self, domain: str, max_results: int) -> Set[str]:
        """Brute force subdomain enumeration"""
        subdomains = set()
        
        if not self.wordlist_path.exists():
            logger.warning(f"Wordlist not found at {self.wordlist_path}, creating basic one")
            self._create_default_wordlist()
        
        try:
            with open(self.wordlist_path, 'r') as f:
                wordlist = [line.strip() for line in f if line.strip()]
            
            wordlist = wordlist[:max_results]
            
            tasks = []
            for word in wordlist:
                tasks.append(self._check_dns(f"{word}.{domain}"))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for i, result in enumerate(results):
                if result and not isinstance(result, Exception):
                    subdomains.add(f"{wordlist[i]}.{domain}")
        
        except Exception as e:
            logger.error(f"Brute force enumeration failed: {e}")
        
        return subdomains
    
    def _create_default_wordlist(self):
        """Create default subdomain wordlist"""
        self.wordlist_path.parent.mkdir(parents=True, exist_ok=True)
        
        default_words = [
            "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
            "blog", "shop", "store", "cdn", "static", "assets", "images",
            "secure", "portal", "vpn", "remote", "webmail", "mx", "smtp",
            "pop", "imap", "dns", "ns1", "ns2", "backup", "db", "database"
        ]
        
        self.wordlist_path.write_text("\n".join(default_words))
    
    async def _external_tools(self, domain: str) -> Set[str]:
        """Use external tools if available (subfinder, amass)"""
        subdomains = set()
        
        try:
            result = subprocess.run(
                ["subfinder", "-d", domain, "-silent"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                subs = result.stdout.strip().split("\n")
                subdomains.update([s.strip() for s in subs if s.strip()])
                logger.info(f"Subfinder found {len(subdomains)} subdomains")
        
        except FileNotFoundError:
            logger.info("Subfinder not installed, skipping")
        except Exception as e:
            logger.warning(f"Subfinder failed: {e}")
        
        return subdomains
    
    async def _check_alive(self, subdomains: List[str]) -> List[str]:
        """Check which subdomains are alive (HTTP/HTTPS accessible)"""
        alive = []
        
        try:
            import aiohttp
            
            async with aiohttp.ClientSession() as session:
                tasks = []
                for subdomain in subdomains[:100]:
                    tasks.append(self._check_http(session, subdomain))
                
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for i, result in enumerate(results):
                    if result and not isinstance(result, Exception):
                        alive.append(subdomains[i])
        
        except Exception as e:
            logger.error(f"Alive check failed: {e}")
        
        return alive
    
    async def _check_http(self, session, subdomain: str) -> bool:
        """Check if subdomain responds to HTTP/HTTPS"""
        for protocol in ["https", "http"]:
            try:
                url = f"{protocol}://{subdomain}"
                async with session.get(url, timeout=3, allow_redirects=True) as response:
                    if response.status < 500:
                        return True
            except:
                continue
        return False

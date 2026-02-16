"""
Reconnaissance Engine

Automated reconnaissance for bug bounty targets.
Includes subdomain enumeration, port scanning, technology detection,
and asset discovery with AI-powered analysis.
"""

import asyncio
import aiohttp
import socket
import dns.resolver
import subprocess
import re
from typing import List, Dict, Set, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class Target:
    """Bug bounty target"""
    domain: str
    program_name: str
    scope: List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)
    
    # Discovered assets
    subdomains: Set[str] = field(default_factory=set)
    ip_addresses: Set[str] = field(default_factory=set)
    open_ports: Dict[str, List[int]] = field(default_factory=dict)  # IP -> ports
    technologies: Dict[str, List[str]] = field(default_factory=dict)  # URL -> techs
    urls: Set[str] = field(default_factory=set)
    
    # Metadata
    discovered_at: datetime = field(default_factory=datetime.now)
    last_updated: datetime = field(default_factory=datetime.now)


class ReconEngine:
    """
    Automated reconnaissance engine
    
    Features:
    - Subdomain enumeration (passive and active)
    - Port scanning (optimized for web services)
    - Technology detection (Wappalyzer-style)
    - Screenshot capture
    - Directory bruteforcing
    - Parameter discovery
    """
    
    def __init__(self, ai_client=None):
        """
        Initialize reconnaissance engine
        
        Args:
            ai_client: AI client for intelligent analysis
        """
        self.ai_client = ai_client
        self.timeout = 10
        self.max_subdomains = 1000
        
        # Common ports for web services
        self.common_ports = [80, 443, 8000, 8080, 8443, 3000, 5000, 8888]
        
        # Technology fingerprints
        self.tech_fingerprints = {
            'WordPress': ['/wp-content/', '/wp-includes/', '/wp-admin/'],
            'Joomla': ['/administrator/', '/components/', '/modules/'],
            'Drupal': ['/sites/', '/modules/', '/themes/'],
            'Django': ['csrfmiddlewaretoken', '__admin'],
            'Laravel': ['/vendor/laravel/', 'laravel_session'],
            'React': ['react', 'reactDOM'],
            'Vue.js': ['Vue.js', '__vue__'],
            'Angular': ['ng-version', 'angular'],
            'ASP.NET': ['__VIEWSTATE', 'asp.net'],
            'PHP': ['<?php', '.php'],
            'Node.js': ['X-Powered-By: Express'],
        }
    
    async def enumerate_subdomains_passive(self, domain: str) -> Set[str]:
        """
        Passive subdomain enumeration using public sources
        
        Args:
            domain: Target domain
            
        Returns:
            Set of discovered subdomains
        """
        subdomains = set()
        
        # Certificate Transparency logs
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://crt.sh/?q=%.{domain}&output=json"
                async with session.get(url, timeout=self.timeout) as response:
                    if response.status == 200:
                        data = await response.json()
                        for entry in data:
                            name = entry.get('name_value', '')
                            if name:
                                # Handle wildcards and multiple names
                                for subdomain in name.split('\n'):
                                    subdomain = subdomain.strip()
                                    if subdomain.endswith(domain) and '*' not in subdomain:
                                        subdomains.add(subdomain)
        except Exception as e:
            logger.error(f"crt.sh enumeration failed: {e}")
        
        # DNS records (common subdomains)
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'staging', 'test',
            'beta', 'cdn', 'assets', 'static', 'images', 'img', 'blog',
            'shop', 'store', 'portal', 'dashboard', 'app', 'mobile',
            'vpn', 'remote', 'secure', 'sso', 'auth', 'login'
        ]
        
        for sub in common_subdomains:
            subdomain = f"{sub}.{domain}"
            if await self.check_dns_exists(subdomain):
                subdomains.add(subdomain)
        
        logger.info(f"Found {len(subdomains)} subdomains for {domain}")
        return subdomains
    
    async def check_dns_exists(self, domain: str) -> bool:
        """Check if domain has DNS record"""
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, socket.gethostbyname, domain)
            return True
        except socket.gaierror:
            return False
    
    async def resolve_domain(self, domain: str) -> Set[str]:
        """Resolve domain to IP addresses"""
        ips = set()
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, socket.gethostbyname_ex, domain)
            ips.update(result[2])
        except socket.gaierror:
            pass
        return ips
    
    async def scan_ports(self, ip: str, ports: List[int] = None) -> List[int]:
        """
        Scan ports on IP address
        
        Args:
            ip: IP address
            ports: List of ports to scan (default: common web ports)
            
        Returns:
            List of open ports
        """
        if ports is None:
            ports = self.common_ports
        
        open_ports = []
        
        async def check_port(port):
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=2
                )
                writer.close()
                await writer.wait_closed()
                return port
            except:
                return None
        
        tasks = [check_port(port) for port in ports]
        results = await asyncio.gather(*tasks)
        
        open_ports = [port for port in results if port is not None]
        logger.info(f"Found {len(open_ports)} open ports on {ip}: {open_ports}")
        
        return open_ports
    
    async def detect_technologies(self, url: str) -> List[str]:
        """
        Detect technologies used by website
        
        Args:
            url: Website URL
            
        Returns:
            List of detected technologies
        """
        technologies = []
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=self.timeout) as response:
                    html = await response.text()
                    headers = response.headers
                    
                    # Check fingerprints
                    for tech, patterns in self.tech_fingerprints.items():
                        for pattern in patterns:
                            if pattern in html or pattern in str(headers):
                                technologies.append(tech)
                                break
                    
                    # Check headers
                    server = headers.get('Server', '')
                    if server:
                        technologies.append(f"Server: {server}")
                    
                    x_powered_by = headers.get('X-Powered-By', '')
                    if x_powered_by:
                        technologies.append(f"Powered-By: {x_powered_by}")
        
        except Exception as e:
            logger.error(f"Technology detection failed for {url}: {e}")
        
        return technologies
    
    async def discover_endpoints(self, url: str, wordlist: List[str] = None) -> Set[str]:
        """
        Discover endpoints using directory bruteforcing
        
        Args:
            url: Base URL
            wordlist: List of paths to try (default: common paths)
            
        Returns:
            Set of discovered URLs
        """
        if wordlist is None:
            wordlist = [
                '/admin', '/login', '/api', '/v1', '/v2', '/graphql',
                '/swagger', '/docs', '/debug', '/.git', '/.env',
                '/config', '/backup', '/test', '/dev'
            ]
        
        discovered = set()
        
        async def check_path(path):
            test_url = url.rstrip('/') + path
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(test_url, timeout=5, allow_redirects=False) as response:
                        if response.status in [200, 301, 302, 401, 403]:
                            return test_url
            except:
                pass
            return None
        
        tasks = [check_path(path) for path in wordlist]
        results = await asyncio.gather(*tasks)
        
        discovered = {url for url in results if url is not None}
        logger.info(f"Discovered {len(discovered)} endpoints for {url}")
        
        return discovered
    
    async def run_full_recon(self, target: Target) -> Target:
        """
        Run full reconnaissance on target
        
        Args:
            target: Target configuration
            
        Returns:
            Updated target with discovered assets
        """
        logger.info(f"Starting reconnaissance for {target.domain}")
        
        # Step 1: Subdomain enumeration
        target.subdomains = await self.enumerate_subdomains_passive(target.domain)
        
        # Add main domain
        target.subdomains.add(target.domain)
        
        # Step 2: Resolve to IPs
        for subdomain in list(target.subdomains)[:50]:  # Limit for speed
            ips = await self.resolve_domain(subdomain)
            target.ip_addresses.update(ips)
        
        # Step 3: Port scanning
        for ip in list(target.ip_addresses)[:10]:  # Limit IPs
            open_ports = await self.scan_ports(ip)
            if open_ports:
                target.open_ports[ip] = open_ports
        
        # Step 4: Technology detection
        for subdomain in list(target.subdomains)[:20]:  # Limit for speed
            for protocol in ['http', 'https']:
                url = f"{protocol}://{subdomain}"
                try:
                    techs = await self.detect_technologies(url)
                    if techs:
                        target.technologies[url] = techs
                        target.urls.add(url)
                except:
                    continue
        
        # Step 5: Endpoint discovery
        for url in list(target.urls)[:10]:  # Limit URLs
            endpoints = await self.discover_endpoints(url)
            target.urls.update(endpoints)
        
        target.last_updated = datetime.now()
        
        logger.info(f"Reconnaissance complete for {target.domain}")
        logger.info(f"  Subdomains: {len(target.subdomains)}")
        logger.info(f"  IPs: {len(target.ip_addresses)}")
        logger.info(f"  URLs: {len(target.urls)}")
        
        return target
    
    async def ai_analyze_target(self, target: Target) -> Dict[str, Any]:
        """
        Use AI to analyze reconnaissance results
        
        Args:
            target: Target with reconnaissance data
            
        Returns:
            AI analysis with recommendations
        """
        if not self.ai_client:
            return {"error": "AI client not configured"}
        
        # Prepare data for AI
        recon_data = {
            "domain": target.domain,
            "subdomains_count": len(target.subdomains),
            "ips_count": len(target.ip_addresses),
            "technologies": target.technologies,
            "urls_count": len(target.urls),
            "open_ports": target.open_ports
        }
        
        prompt = f"""Analyze this bug bounty target reconnaissance data and provide insights:

Domain: {target.domain}
Subdomains found: {len(target.subdomains)}
IP addresses: {len(target.ip_addresses)}
Open ports: {len(target.open_ports)} hosts with open ports
URLs discovered: {len(target.urls)}

Technologies detected:
{json.dumps(target.technologies, indent=2)}

Please provide:
1. Attack surface analysis
2. High-value targets to focus on
3. Potential vulnerability areas based on technologies
4. Recommended next steps for bug bounty hunting
5. Security risks to investigate
"""
        
        try:
            from src.cognitive.llm.model_loader import ModelLoader
            loader = ModelLoader()
            
            response = loader.generate(
                prompt=prompt,
                task_type="analysis",
                max_tokens=1000
            )
            
            return {
                "analysis": response,
                "target_summary": recon_data
            }
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            return {"error": str(e)}


# Example usage
async def main():
    engine = ReconEngine()
    
    # Create target
    target = Target(
        domain="example.com",
        program_name="Example Bug Bounty Program",
        scope=["*.example.com"],
        out_of_scope=["admin.example.com"]
    )
    
    # Run reconnaissance
    target = await engine.run_full_recon(target)
    
    # Show results
    print(f"\nReconnaissance Results for {target.domain}:")
    print(f"  Subdomains: {len(target.subdomains)}")
    print(f"  IPs: {len(target.ip_addresses)}")
    print(f"  Open Ports: {len(target.open_ports)}")
    print(f"  URLs: {len(target.urls)}")
    print(f"  Technologies: {len(target.technologies)}")
    
    if target.subdomains:
        print(f"\nFirst 10 subdomains:")
        for sub in list(target.subdomains)[:10]:
            print(f"    - {sub}")


if __name__ == "__main__":
    asyncio.run(main())

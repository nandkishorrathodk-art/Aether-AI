"""
Threat Intelligence Integration
Real-time threat feeds and intelligence gathering
"""

import asyncio
import requests
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
import json
import logging

logger = logging.getLogger(__name__)


@dataclass
class ThreatIndicator:
    """Threat indicator from intelligence feed"""
    indicator_type: str
    value: str
    threat_type: str
    severity: str
    confidence: float
    source: str
    first_seen: datetime
    last_seen: datetime
    description: str = ""
    tags: List[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "indicator_type": self.indicator_type,
            "value": self.value,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "source": self.source,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "description": self.description,
            "tags": self.tags or []
        }


class ThreatIntelligencePlatform:
    """
    Comprehensive threat intelligence platform
    
    Features:
    - Multiple threat feed integration
    - Real-time threat updates
    - IOC (Indicators of Compromise) matching
    - Threat actor tracking
    - Attack pattern recognition
    """
    
    def __init__(self, cache_dir: str = "data/threat_intel"):
        """Initialize threat intelligence platform"""
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self.indicators: Dict[str, ThreatIndicator] = {}
        self.feeds = self._initialize_feeds()
        
        self._load_cache()
        logger.info("Threat Intelligence Platform initialized")
    
    def _initialize_feeds(self) -> Dict[str, Dict[str, str]]:
        """Initialize threat intelligence feed sources"""
        return {
            "abuse_ch": {
                "name": "Abuse.ch",
                "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
                "type": "ip"
            },
            "alienvault_otx": {
                "name": "AlienVault OTX",
                "url": "https://otx.alienvault.com/api/v1/pulses/subscribed",
                "type": "multi",
                "requires_auth": True
            },
            "emergingthreats": {
                "name": "Emerging Threats",
                "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
                "type": "ip"
            },
            "malware_bazaar": {
                "name": "MalwareBazaar",
                "url": "https://bazaar.abuse.ch/export/csv/recent/",
                "type": "hash"
            }
        }
    
    def _load_cache(self):
        """Load cached threat indicators"""
        cache_file = self.cache_dir / "threat_cache.json"
        
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    data = json.load(f)
                    
                    for key, indicator_data in data.items():
                        self.indicators[key] = ThreatIndicator(
                            indicator_type=indicator_data['indicator_type'],
                            value=indicator_data['value'],
                            threat_type=indicator_data['threat_type'],
                            severity=indicator_data['severity'],
                            confidence=indicator_data['confidence'],
                            source=indicator_data['source'],
                            first_seen=datetime.fromisoformat(indicator_data['first_seen']),
                            last_seen=datetime.fromisoformat(indicator_data['last_seen']),
                            description=indicator_data.get('description', ''),
                            tags=indicator_data.get('tags', [])
                        )
                
                logger.info(f"Loaded {len(self.indicators)} threat indicators from cache")
            except Exception as e:
                logger.warning(f"Failed to load threat cache: {e}")
    
    def _save_cache(self):
        """Save threat indicators to cache"""
        cache_file = self.cache_dir / "threat_cache.json"
        
        try:
            data = {}
            for key, indicator in self.indicators.items():
                data[key] = indicator.to_dict()
            
            with open(cache_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            logger.info(f"Saved {len(self.indicators)} threat indicators to cache")
        except Exception as e:
            logger.error(f"Failed to save threat cache: {e}")
    
    async def update_feeds(self, feed_names: List[str] = None):
        """
        Update threat intelligence feeds
        
        Args:
            feed_names: Specific feeds to update (default: all)
        """
        if feed_names is None:
            feed_names = list(self.feeds.keys())
        
        for feed_name in feed_names:
            if feed_name not in self.feeds:
                logger.warning(f"Unknown feed: {feed_name}")
                continue
            
            try:
                await self._update_feed(feed_name)
            except Exception as e:
                logger.error(f"Failed to update feed {feed_name}: {e}")
        
        self._save_cache()
    
    async def _update_feed(self, feed_name: str):
        """Update specific threat feed"""
        feed_config = self.feeds[feed_name]
        
        if feed_config.get('requires_auth'):
            logger.info(f"Skipping feed {feed_name} (requires authentication)")
            return
        
        try:
            response = requests.get(feed_config['url'], timeout=30)
            
            if response.status_code == 200:
                if feed_config['type'] == 'ip':
                    self._parse_ip_feed(response.text, feed_name)
                elif feed_config['type'] == 'hash':
                    self._parse_hash_feed(response.text, feed_name)
                
                logger.info(f"Updated feed: {feed_name}")
        except Exception as e:
            logger.error(f"Failed to fetch feed {feed_name}: {e}")
    
    def _parse_ip_feed(self, content: str, source: str):
        """Parse IP-based threat feed"""
        for line in content.split('\n'):
            line = line.strip()
            
            if not line or line.startswith('#'):
                continue
            
            parts = line.split(',')
            ip = parts[0].strip()
            
            if ip:
                key = f"ip:{ip}"
                
                if key in self.indicators:
                    self.indicators[key].last_seen = datetime.now()
                else:
                    self.indicators[key] = ThreatIndicator(
                        indicator_type="ip",
                        value=ip,
                        threat_type="malicious_ip",
                        severity="MEDIUM",
                        confidence=0.7,
                        source=source,
                        first_seen=datetime.now(),
                        last_seen=datetime.now(),
                        description=f"Malicious IP from {source}"
                    )
    
    def _parse_hash_feed(self, content: str, source: str):
        """Parse hash-based threat feed"""
        for line in content.split('\n'):
            line = line.strip()
            
            if not line or line.startswith('#'):
                continue
            
            parts = line.split(',')
            if len(parts) >= 2:
                file_hash = parts[0].strip()
                
                key = f"hash:{file_hash}"
                
                if key in self.indicators:
                    self.indicators[key].last_seen = datetime.now()
                else:
                    self.indicators[key] = ThreatIndicator(
                        indicator_type="hash",
                        value=file_hash,
                        threat_type="malware",
                        severity="HIGH",
                        confidence=0.8,
                        source=source,
                        first_seen=datetime.now(),
                        last_seen=datetime.now(),
                        description=f"Malware hash from {source}"
                    )
    
    def check_indicator(self, indicator_type: str, value: str) -> Optional[ThreatIndicator]:
        """
        Check if indicator is known threat
        
        Args:
            indicator_type: Type (ip, domain, hash, etc.)
            value: Indicator value
        
        Returns:
            ThreatIndicator if found
        """
        key = f"{indicator_type}:{value}"
        return self.indicators.get(key)
    
    def search_threats(
        self,
        query: str = None,
        threat_type: str = None,
        min_severity: str = None,
        min_confidence: float = 0.0
    ) -> List[ThreatIndicator]:
        """
        Search threat indicators
        
        Args:
            query: Search query
            threat_type: Filter by threat type
            min_severity: Minimum severity (CRITICAL, HIGH, MEDIUM, LOW)
            min_confidence: Minimum confidence score
        
        Returns:
            List of matching indicators
        """
        results = []
        
        severity_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        min_severity_idx = severity_order.index(min_severity) if min_severity else 0
        
        for indicator in self.indicators.values():
            if query and query.lower() not in indicator.value.lower():
                continue
            
            if threat_type and indicator.threat_type != threat_type:
                continue
            
            if min_severity:
                indicator_severity_idx = severity_order.index(indicator.severity)
                if indicator_severity_idx < min_severity_idx:
                    continue
            
            if indicator.confidence < min_confidence:
                continue
            
            results.append(indicator)
        
        return sorted(results, key=lambda x: (
            severity_order.index(x.severity), x.confidence
        ), reverse=True)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get threat intelligence statistics"""
        threat_types = {}
        severity_counts = {}
        
        for indicator in self.indicators.values():
            threat_types[indicator.threat_type] = threat_types.get(indicator.threat_type, 0) + 1
            severity_counts[indicator.severity] = severity_counts.get(indicator.severity, 0) + 1
        
        recent_threats = [
            i for i in self.indicators.values()
            if i.last_seen > datetime.now() - timedelta(days=7)
        ]
        
        return {
            "total_indicators": len(self.indicators),
            "threat_types": threat_types,
            "severity_distribution": severity_counts,
            "recent_threats_7d": len(recent_threats),
            "feeds_configured": len(self.feeds),
            "last_updated": datetime.now().isoformat()
        }
    
    async def enrich_vulnerability(
        self,
        vulnerability: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Enrich vulnerability data with threat intelligence
        
        Args:
            vulnerability: Vulnerability dictionary
        
        Returns:
            Enriched vulnerability data
        """
        enriched = vulnerability.copy()
        enriched['threat_intelligence'] = {
            "active_exploits": False,
            "in_the_wild": False,
            "threat_actors": [],
            "attack_patterns": []
        }
        
        cve_id = vulnerability.get('cve_id')
        if cve_id:
            related_threats = self.search_threats(query=cve_id)
            if related_threats:
                enriched['threat_intelligence']['active_exploits'] = True
                enriched['threat_intelligence']['in_the_wild'] = len(related_threats) > 5
        
        return enriched

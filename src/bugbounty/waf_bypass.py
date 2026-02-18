"""
WAF Bypass Techniques

Implements various payload encoding and obfuscation techniques to bypass WAFs.
"""

import base64
import urllib.parse
import html
import re
from typing import List, Dict, Any
from src.utils.logger import get_logger

logger = get_logger(__name__)


class WAFBypass:
    """
    WAF bypass techniques for penetration testing
    """
    
    def __init__(self):
        logger.info("WAF Bypass module initialized")
    
    def generate_bypass_payloads(
        self,
        original_payload: str,
        vulnerability_type: str,
        techniques: List[str] = None
    ) -> List[Dict[str, str]]:
        """
        Generate multiple bypass variants of a payload
        
        Args:
            original_payload: Original exploit payload
            vulnerability_type: Type of vulnerability (sqli, xss, etc.)
            techniques: Specific techniques to use (None = all)
            
        Returns:
            List of bypass payloads with descriptions
        """
        try:
            if techniques is None:
                techniques = ["all"]
            
            payloads = []
            
            if "all" in techniques or "url_encoding" in techniques:
                payloads.extend(self._url_encoding_variants(original_payload))
            
            if "all" in techniques or "case_variation" in techniques:
                payloads.extend(self._case_variation(original_payload))
            
            if "all" in techniques or "comment_injection" in techniques:
                if vulnerability_type == "sqli":
                    payloads.extend(self._sql_comment_injection(original_payload))
            
            if "all" in techniques or "null_byte" in techniques:
                payloads.extend(self._null_byte_injection(original_payload))
            
            if "all" in techniques or "unicode" in techniques:
                payloads.extend(self._unicode_encoding(original_payload))
            
            if "all" in techniques or "hex_encoding" in techniques:
                if vulnerability_type == "sqli":
                    payloads.extend(self._hex_encoding(original_payload))
            
            if "all" in techniques or "concatenation" in techniques:
                if vulnerability_type == "sqli":
                    payloads.extend(self._sql_concatenation(original_payload))
            
            if "all" in techniques or "html_entities" in techniques:
                if vulnerability_type in ["xss", "html_injection"]:
                    payloads.extend(self._html_entity_encoding(original_payload))
            
            if "all" in techniques or "javascript_obfuscation" in techniques:
                if vulnerability_type == "xss":
                    payloads.extend(self._javascript_obfuscation(original_payload))
            
            logger.info(f"Generated {len(payloads)} bypass variants")
            
            return payloads
            
        except Exception as e:
            logger.error(f"Failed to generate bypass payloads: {e}")
            return []
    
    def _url_encoding_variants(self, payload: str) -> List[Dict]:
        """URL encoding variants"""
        return [
            {
                "payload": urllib.parse.quote(payload),
                "technique": "URL Encoding (Single)",
                "description": "Standard URL encoding"
            },
            {
                "payload": urllib.parse.quote(urllib.parse.quote(payload)),
                "technique": "URL Encoding (Double)",
                "description": "Double URL encoding to bypass filters"
            },
            {
                "payload": self._mixed_url_encoding(payload),
                "technique": "URL Encoding (Mixed)",
                "description": "Mixed case URL encoding (%2f vs %2F)"
            }
        ]
    
    def _mixed_url_encoding(self, payload: str) -> str:
        """Mixed case URL encoding"""
        encoded = ""
        for i, char in enumerate(payload):
            if char.isalnum():
                encoded += char
            else:
                hex_val = format(ord(char), 'x')
                if i % 2 == 0:
                    encoded += f"%{hex_val.upper()}"
                else:
                    encoded += f"%{hex_val.lower()}"
        return encoded
    
    def _case_variation(self, payload: str) -> List[Dict]:
        """Case variation techniques"""
        return [
            {
                "payload": payload.upper(),
                "technique": "Upper Case",
                "description": "All uppercase"
            },
            {
                "payload": payload.lower(),
                "technique": "Lower Case",
                "description": "All lowercase"
            },
            {
                "payload": self._random_case(payload),
                "technique": "Random Case",
                "description": "Randomly mixed case"
            }
        ]
    
    def _random_case(self, payload: str) -> str:
        """Random case variation"""
        import random
        result = ""
        for char in payload:
            if char.isalpha():
                result += char.upper() if random.choice([True, False]) else char.lower()
            else:
                result += char
        return result
    
    def _sql_comment_injection(self, payload: str) -> List[Dict]:
        """SQL comment injection techniques"""
        
        keywords = ["SELECT", "UNION", "WHERE", "FROM", "AND", "OR", "ORDER"]
        
        payloads = []
        
        for keyword in keywords:
            if keyword in payload.upper():
                commented = payload.replace(keyword, f"{keyword}/**/")
                payloads.append({
                    "payload": commented,
                    "technique": f"SQL Comment Injection ({keyword})",
                    "description": f"Insert /**/ comment after {keyword}"
                })
                
                commented2 = payload.replace(keyword, f"{keyword}/*comment*/")
                payloads.append({
                    "payload": commented2,
                    "technique": f"SQL Named Comment ({keyword})",
                    "description": f"Insert named comment after {keyword}"
                })
        
        spaces_replaced = payload.replace(" ", "/**/")
        payloads.append({
            "payload": spaces_replaced,
            "technique": "SQL Comment for Spaces",
            "description": "Replace all spaces with /**/"
        })
        
        return payloads
    
    def _null_byte_injection(self, payload: str) -> List[Dict]:
        """Null byte injection"""
        return [
            {
                "payload": payload + "%00",
                "technique": "Null Byte Append",
                "description": "Append null byte to bypass extension checks"
            },
            {
                "payload": payload.replace(" ", "%00"),
                "technique": "Null Byte for Spaces",
                "description": "Replace spaces with null bytes"
            }
        ]
    
    def _unicode_encoding(self, payload: str) -> List[Dict]:
        """Unicode encoding variants"""
        payloads = []
        
        unicode_encoded = ""
        for char in payload:
            unicode_encoded += f"\\u{ord(char):04x}"
        
        payloads.append({
            "payload": unicode_encoded,
            "technique": "Unicode Encoding",
            "description": "Full unicode encoding"
        })
        
        mixed_unicode = ""
        for i, char in enumerate(payload):
            if i % 2 == 0 and not char.isalnum():
                mixed_unicode += f"\\u{ord(char):04x}"
            else:
                mixed_unicode += char
        
        payloads.append({
            "payload": mixed_unicode,
            "technique": "Mixed Unicode",
            "description": "Partial unicode encoding"
        })
        
        return payloads
    
    def _hex_encoding(self, payload: str) -> List[Dict]:
        """Hex encoding for SQL"""
        hex_payload = "0x" + payload.encode().hex()
        
        return [
            {
                "payload": hex_payload,
                "technique": "Hex Encoding",
                "description": "Convert string to hex format"
            }
        ]
    
    def _sql_concatenation(self, payload: str) -> List[Dict]:
        """SQL string concatenation"""
        
        words = payload.split()
        
        concat_variants = []
        
        mysql_concat = "CONCAT(" + ",".join([f"'{word}'" for word in words]) + ")"
        concat_variants.append({
            "payload": mysql_concat,
            "technique": "MySQL CONCAT",
            "description": "MySQL CONCAT function"
        })
        
        mssql_concat = "+".join([f"'{word}'" for word in words])
        concat_variants.append({
            "payload": mssql_concat,
            "technique": "MSSQL Concatenation",
            "description": "MSSQL + concatenation"
        })
        
        oracle_concat = "||".join([f"'{word}'" for word in words])
        concat_variants.append({
            "payload": oracle_concat,
            "technique": "Oracle Concatenation",
            "description": "Oracle || concatenation"
        })
        
        return concat_variants
    
    def _html_entity_encoding(self, payload: str) -> List[Dict]:
        """HTML entity encoding for XSS"""
        
        decimal_encoded = ""
        for char in payload:
            decimal_encoded += f"&#{ord(char)};"
        
        hex_encoded = ""
        for char in payload:
            hex_encoded += f"&#x{ord(char):x};"
        
        return [
            {
                "payload": html.escape(payload),
                "technique": "HTML Escape",
                "description": "Standard HTML entity encoding"
            },
            {
                "payload": decimal_encoded,
                "technique": "Decimal HTML Entities",
                "description": "Decimal numeric character references"
            },
            {
                "payload": hex_encoded,
                "technique": "Hex HTML Entities",
                "description": "Hexadecimal numeric character references"
            }
        ]
    
    def _javascript_obfuscation(self, payload: str) -> List[Dict]:
        """JavaScript obfuscation techniques"""
        
        payloads = []
        
        char_codes = "[" + ",".join([str(ord(c)) for c in payload]) + "]"
        fromcharcode = f"String.fromCharCode({','.join([str(ord(c)) for c in payload])})"
        
        payloads.append({
            "payload": fromcharcode,
            "technique": "String.fromCharCode",
            "description": "Convert to character codes"
        })
        
        eval_variant = f"eval({fromcharcode})"
        payloads.append({
            "payload": eval_variant,
            "technique": "Eval + fromCharCode",
            "description": "Combine eval with character codes"
            })
        
        escaped = payload.replace("<", "\\x3c").replace(">", "\\x3e").replace("'", "\\x27").replace('"', "\\x22")
        payloads.append({
            "payload": escaped,
            "technique": "Hex Escape",
            "description": "Hex escape special characters"
        })
        
        return payloads
    
    def test_waf_detection(self, url: str, payload: str) -> Dict[str, Any]:
        """
        Test if WAF is present and blocking payloads
        
        Args:
            url: Target URL
            payload: Test payload
            
        Returns:
            WAF detection results
        """
        try:
            import requests
            
            normal_response = requests.get(url, timeout=5)
            malicious_response = requests.get(url, params={"test": payload}, timeout=5)
            
            waf_detected = False
            waf_indicators = []
            
            if malicious_response.status_code in [403, 406, 429, 503]:
                waf_detected = True
                waf_indicators.append(f"Blocked status code: {malicious_response.status_code}")
            
            waf_headers = ["x-waf", "x-sucuri", "cloudflare", "x-akamai"]
            for header in waf_headers:
                if header in malicious_response.headers:
                    waf_detected = True
                    waf_indicators.append(f"WAF header detected: {header}")
            
            waf_body_keywords = ["blocked", "firewall", "security", "suspicious"]
            for keyword in waf_body_keywords:
                if keyword.lower() in malicious_response.text.lower():
                    waf_detected = True
                    waf_indicators.append(f"WAF keyword in response: {keyword}")
                    break
            
            return {
                "waf_detected": waf_detected,
                "indicators": waf_indicators,
                "normal_status": normal_response.status_code,
                "malicious_status": malicious_response.status_code,
                "recommendation": "Use bypass techniques" if waf_detected else "No WAF detected"
            }
            
        except Exception as e:
            logger.error(f"WAF detection test failed: {e}")
            return {
                "waf_detected": False,
                "error": str(e)
            }

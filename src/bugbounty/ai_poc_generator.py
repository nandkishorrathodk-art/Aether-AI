"""
AI-Powered Proof-of-Concept Generator

Generates exploitation code for discovered vulnerabilities using LLM.
"""

import asyncio
from typing import Dict, List, Optional, Any
from src.cognitive.llm.llm_wrapper import LLMInference
from src.utils.logger import get_logger

logger = get_logger(__name__)


class AIPoCGenerator:
    """
    AI-powered PoC generator for bug bounty vulnerabilities
    """
    
    def __init__(self):
        self.llm = LLMInference()
        logger.info("AI PoC Generator initialized")
    
    async def generate_poc(
        self,
        vulnerability_type: str,
        target_url: str,
        description: str,
        parameters: Optional[Dict] = None,
        context: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generate Proof-of-Concept exploit code
        
        Args:
            vulnerability_type: Type of vulnerability (sqli, xss, idor, etc.)
            target_url: Target URL
            description: Vulnerability description
            parameters: Vulnerable parameters
            context: Additional context
            
        Returns:
            Dict with PoC code, explanation, and risk assessment
        """
        try:
            logger.info(f"Generating PoC for {vulnerability_type} at {target_url}")
            
            prompt = self._build_poc_prompt(
                vulnerability_type,
                target_url,
                description,
                parameters,
                context
            )
            
            response = await self.llm.get_completion(prompt)
            
            poc_data = self._parse_poc_response(response, vulnerability_type)
            
            logger.info(f"Generated PoC successfully for {vulnerability_type}")
            
            return {
                "success": True,
                "vulnerability_type": vulnerability_type,
                "target_url": target_url,
                "poc_code": poc_data.get("code", ""),
                "explanation": poc_data.get("explanation", ""),
                "prerequisites": poc_data.get("prerequisites", []),
                "expected_outcome": poc_data.get("expected_outcome", ""),
                "remediation": poc_data.get("remediation", ""),
                "cvss_score": poc_data.get("cvss_score", 0.0),
                "risk_level": poc_data.get("risk_level", "medium")
            }
            
        except Exception as e:
            logger.error(f"Failed to generate PoC: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def _build_poc_prompt(
        self,
        vuln_type: str,
        url: str,
        description: str,
        parameters: Optional[Dict],
        context: Optional[str]
    ) -> str:
        """Build prompt for LLM to generate PoC"""
        
        prompt = f"""You are a professional security researcher. Generate a detailed, safe Proof-of-Concept (PoC) for the following vulnerability:

**Vulnerability Type:** {vuln_type}
**Target URL:** {url}
**Description:** {description}
"""
        
        if parameters:
            prompt += f"\n**Vulnerable Parameters:** {parameters}"
        
        if context:
            prompt += f"\n**Additional Context:** {context}"
        
        prompt += """

Please provide:

1. **PoC Code** (Python/curl/JavaScript - whichever is most appropriate)
   - Should be safe and non-destructive
   - Include comments explaining each step
   - Use real examples but sanitize sensitive data

2. **Step-by-step Explanation**
   - How the exploit works
   - Why it works
   - What the attacker can achieve

3. **Prerequisites**
   - Tools needed
   - Permissions required
   - Environment setup

4. **Expected Outcome**
   - What happens when PoC is executed
   - Visual proof or response expected

5. **Remediation**
   - How to fix this vulnerability
   - Secure coding practices

6. **CVSS Score** (0.0-10.0)

7. **Risk Level** (low/medium/high/critical)

Format your response as:
```
CODE:
[PoC code here]

EXPLANATION:
[Detailed explanation]

PREREQUISITES:
- [Item 1]
- [Item 2]

EXPECTED_OUTCOME:
[What happens]

REMEDIATION:
[Fix recommendations]

CVSS_SCORE: [score]
RISK_LEVEL: [level]
```
"""
        
        return prompt
    
    def _parse_poc_response(self, response: str, vuln_type: str) -> Dict:
        """Parse LLM response into structured PoC data"""
        
        result = {
            "code": "",
            "explanation": "",
            "prerequisites": [],
            "expected_outcome": "",
            "remediation": "",
            "cvss_score": 5.0,
            "risk_level": "medium"
        }
        
        try:
            sections = {
                "CODE:": "code",
                "EXPLANATION:": "explanation",
                "PREREQUISITES:": "prerequisites",
                "EXPECTED_OUTCOME:": "expected_outcome",
                "REMEDIATION:": "remediation"
            }
            
            current_section = None
            lines = response.split("\n")
            
            for line in lines:
                line_stripped = line.strip()
                
                if line_stripped.startswith("CVSS_SCORE:"):
                    try:
                        result["cvss_score"] = float(line_stripped.split(":", 1)[1].strip())
                    except:
                        pass
                    continue
                
                if line_stripped.startswith("RISK_LEVEL:"):
                    result["risk_level"] = line_stripped.split(":", 1)[1].strip().lower()
                    continue
                
                for marker, section_name in sections.items():
                    if line_stripped.startswith(marker):
                        current_section = section_name
                        break
                else:
                    if current_section:
                        if current_section == "prerequisites":
                            if line_stripped.startswith("-"):
                                result["prerequisites"].append(line_stripped[1:].strip())
                        else:
                            if result[current_section]:
                                result[current_section] += "\n" + line
                            else:
                                result[current_section] = line
            
            result["code"] = result["code"].strip()
            result["explanation"] = result["explanation"].strip()
            result["expected_outcome"] = result["expected_outcome"].strip()
            result["remediation"] = result["remediation"].strip()
            
        except Exception as e:
            logger.error(f"Failed to parse PoC response: {e}")
        
        return result
    
    async def generate_exploit_chain(
        self,
        vulnerabilities: List[Dict]
    ) -> Dict[str, Any]:
        """
        Generate chained exploit for multiple vulnerabilities
        
        Args:
            vulnerabilities: List of vulnerabilities to chain
            
        Returns:
            Chained exploit PoC
        """
        try:
            logger.info(f"Generating exploit chain for {len(vulnerabilities)} vulnerabilities")
            
            vuln_summary = "\n".join([
                f"{i+1}. {v.get('type', 'unknown')} at {v.get('url', 'unknown')}"
                for i, v in enumerate(vulnerabilities)
            ])
            
            prompt = f"""You are a professional security researcher. Create a chained exploit that combines multiple vulnerabilities:

**Vulnerabilities:**
{vuln_summary}

**Details:**
"""
            
            for i, vuln in enumerate(vulnerabilities):
                prompt += f"\n{i+1}. **{vuln.get('type', 'unknown')}**"
                prompt += f"\n   URL: {vuln.get('url', 'unknown')}"
                prompt += f"\n   Description: {vuln.get('description', 'No description')}"
                if vuln.get('parameters'):
                    prompt += f"\n   Parameters: {vuln['parameters']}"
                prompt += "\n"
            
            prompt += """
Create a chained exploit that:
1. Leverages each vulnerability in sequence
2. Shows how combining them increases impact
3. Provides complete PoC code
4. Explains the attack flow
5. Assesses final impact and CVSS score

Format:
```
CHAIN_FLOW:
[Step-by-step attack flow]

POC_CODE:
[Complete exploit code]

IMPACT:
[What attacker achieves with chain]

CVSS_SCORE: [score]
RISK_LEVEL: [level]
```
"""
            
            response = await self.llm.get_completion(prompt)
            
            return {
                "success": True,
                "chain_length": len(vulnerabilities),
                "vulnerabilities": vulnerabilities,
                "chain_flow": self._extract_section(response, "CHAIN_FLOW:"),
                "poc_code": self._extract_section(response, "POC_CODE:"),
                "impact": self._extract_section(response, "IMPACT:"),
                "cvss_score": self._extract_cvss(response),
                "risk_level": self._extract_risk_level(response)
            }
            
        except Exception as e:
            logger.error(f"Failed to generate exploit chain: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def _extract_section(self, text: str, marker: str) -> str:
        """Extract section from response"""
        try:
            if marker not in text:
                return ""
            
            start = text.index(marker) + len(marker)
            rest = text[start:]
            
            next_markers = ["CHAIN_FLOW:", "POC_CODE:", "IMPACT:", "CVSS_SCORE:", "RISK_LEVEL:"]
            end = len(rest)
            
            for next_marker in next_markers:
                if next_marker != marker and next_marker in rest:
                    pos = rest.index(next_marker)
                    if pos < end:
                        end = pos
            
            return rest[:end].strip()
        except:
            return ""
    
    def _extract_cvss(self, text: str) -> float:
        """Extract CVSS score from response"""
        try:
            if "CVSS_SCORE:" in text:
                line = [l for l in text.split("\n") if "CVSS_SCORE:" in l][0]
                score_str = line.split(":", 1)[1].strip()
                return float(score_str)
        except:
            pass
        return 0.0
    
    def _extract_risk_level(self, text: str) -> str:
        """Extract risk level from response"""
        try:
            if "RISK_LEVEL:" in text:
                line = [l for l in text.split("\n") if "RISK_LEVEL:" in l][0]
                return line.split(":", 1)[1].strip().lower()
        except:
            pass
        return "medium"

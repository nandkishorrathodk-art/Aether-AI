"""
Program Analyzer - Autonomous Bug Bounty Program Parser

Automatically reads bug bounty program pages, extracts scope, rules, and payouts.
NO HUMAN INPUT NEEDED - fully autonomous!
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
import aiohttp
from bs4 import BeautifulSoup
import json

from src.cognitive.llm.llm_wrapper import LLMInference
from src.bugbounty.voice_notifier import get_voice_notifier
from src.config import settings

logger = logging.getLogger(__name__)


@dataclass
class ProgramScope:
    """Program scope information"""
    in_scope: List[str]
    out_of_scope: List[str]
    wildcards: List[str]
    notes: str


@dataclass
class ProgramRules:
    """Program rules and restrictions"""
    allowed_actions: List[str]
    forbidden_actions: List[str]
    required_auth: bool
    rate_limits: Optional[str]
    notes: str


@dataclass
class PayoutInfo:
    """Payout information"""
    min_payout: Optional[int]
    max_payout: Optional[int]
    critical_range: Optional[str]
    high_range: Optional[str]
    medium_range: Optional[str]
    low_range: Optional[str]
    currency: str = "USD"
    notes: str = ""


@dataclass
class BugBountyProgram:
    """Complete bug bounty program information"""
    name: str
    url: str
    platform: str  # "hackerone", "bugcrowd", "custom", etc.
    scope: ProgramScope
    rules: ProgramRules
    payouts: PayoutInfo
    last_updated: datetime
    raw_content: str
    confidence_score: float  # 0.0-1.0 how confident AI is about extraction


class ProgramAnalyzer:
    """
    Autonomous Bug Bounty Program Analyzer
    
    Khud se program page khol ke:
    - Scope extract karega
    - Rules samjhega
    - Payout structure nikaalega
    - Sab kuch return karega
    
    Usage:
        analyzer = ProgramAnalyzer()
        program = await analyzer.analyze_program("https://security.apple.com/bounty/")
        print(f"Max payout: ${program.payouts.max_payout}")
    """
    
    def __init__(self, enable_voice: bool = False):
        self.llm = LLMInference()
        self.voice = get_voice_notifier(enable_voice=enable_voice)
        logger.info("Program Analyzer initialized - Ready to parse bounty programs autonomously")
    
    async def analyze_program(
        self,
        program_url: str,
        use_vision: bool = False
    ) -> BugBountyProgram:
        """
        Analyze bug bounty program autonomously
        
        Args:
            program_url: URL of bounty program page
            use_vision: Use vision system for screenshot analysis (future)
            
        Returns:
            Complete program information
        """
        logger.info(f"Analyzing bug bounty program: {program_url}")
        
        # Voice: Announce analysis start
        await self.voice.announce_program_analysis_start(program_url.split('/')[2])  # Extract domain
        
        # Step 1: Fetch program page
        raw_html = await self._fetch_page(program_url)
        
        # Step 2: Extract clean text
        clean_text = self._extract_text(raw_html)
        
        # Step 3: AI extraction
        program_data = await self._ai_extract_program(clean_text, program_url)
        
        logger.info(f"Program analysis complete - Confidence: {program_data.confidence_score:.2%}")
        
        # Voice: Announce analysis complete
        await self.voice.announce_program_analysis_complete(
            program_data.name,
            len(program_data.scope.in_scope),
            program_data.payouts.max_payout
        )
        
        return program_data
    
    async def _fetch_page(self, url: str) -> str:
        """Fetch webpage content"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    headers={
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    },
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status != 200:
                        raise Exception(f"HTTP {response.status}")
                    
                    html = await response.text()
                    logger.info(f"Fetched {len(html)} bytes from {url}")
                    return html
        
        except Exception as e:
            logger.error(f"Failed to fetch {url}: {e}")
            raise
    
    def _extract_text(self, html: str) -> str:
        """Extract clean text from HTML"""
        soup = BeautifulSoup(html, 'html.parser')
        
        # Remove script and style elements
        for script in soup(["script", "style", "nav", "footer"]):
            script.decompose()
        
        # Get text
        text = soup.get_text(separator='\n', strip=True)
        
        # Clean up whitespace
        lines = [line.strip() for line in text.split('\n') if line.strip()]
        clean = '\n'.join(lines)
        
        # Limit size for LLM
        if len(clean) > 15000:
            clean = clean[:15000] + "\n...[truncated]"
        
        return clean
    
    async def _ai_extract_program(
        self,
        page_text: str,
        program_url: str
    ) -> BugBountyProgram:
        """Use AI to extract program information"""
        
        extraction_prompt = f"""You are analyzing a bug bounty program page. Extract ALL information accurately.

PROGRAM PAGE CONTENT:
{page_text}

Extract the following in STRICT JSON format:

{{
  "name": "Program name (e.g., 'Apple Security Bounty')",
  "platform": "hackerone|bugcrowd|intigriti|yeswehack|custom",
  "scope": {{
    "in_scope": ["list of in-scope domains/assets with wildcards like *.apple.com"],
    "out_of_scope": ["list of explicitly excluded domains/services"],
    "wildcards": ["list of wildcard patterns found"],
    "notes": "any important scope notes or clarifications"
  }},
  "rules": {{
    "allowed_actions": ["what testing is allowed - e.g., 'Authenticated testing', 'Source code review'"],
    "forbidden_actions": ["what is forbidden - e.g., 'DoS attacks', 'Social engineering', 'Physical testing'"],
    "required_auth": true/false (is authentication required for testing?),
    "rate_limits": "any rate limit info or null",
    "notes": "any important rule clarifications"
  }},
  "payouts": {{
    "min_payout": minimum_amount_in_dollars (number or null),
    "max_payout": maximum_amount_in_dollars (number or null),
    "critical_range": "range for critical bugs (e.g., '$100,000 - $2,000,000')",
    "high_range": "range for high severity",
    "medium_range": "range for medium severity",
    "low_range": "range for low severity",
    "currency": "USD|EUR|etc",
    "notes": "any special payout notes like bonuses"
  }},
  "confidence": 0.95 (your confidence in this extraction, 0.0-1.0)
}}

RULES:
1. Extract EXACT information from the page - don't make assumptions
2. If info is missing, use null
3. Be thorough with scope - this is CRITICAL for safe testing
4. Capture ALL forbidden actions to avoid violations
5. Return ONLY valid JSON, nothing else

JSON:"""

        try:
            response = await self.llm.generate_async(
                prompt=extraction_prompt,
                max_tokens=2000,
                temperature=0.1  # Low temp for accuracy
            )
            
            # Parse JSON from response
            json_str = response.strip()
            if json_str.startswith("```json"):
                json_str = json_str.split("```json")[1].split("```")[0].strip()
            elif json_str.startswith("```"):
                json_str = json_str.split("```")[1].split("```")[0].strip()
            
            data = json.loads(json_str)
            
            # Build program object
            program = BugBountyProgram(
                name=data.get("name", "Unknown Program"),
                url=program_url,
                platform=data.get("platform", "custom"),
                scope=ProgramScope(**data.get("scope", {})),
                rules=ProgramRules(**data.get("rules", {})),
                payouts=PayoutInfo(**data.get("payouts", {})),
                last_updated=datetime.now(),
                raw_content=page_text[:1000],  # Store sample
                confidence_score=data.get("confidence", 0.7)
            )
            
            logger.info(f"Extracted program: {program.name}")
            logger.info(f"Scope: {len(program.scope.in_scope)} in-scope, {len(program.scope.out_of_scope)} out-of-scope")
            logger.info(f"Max payout: ${program.payouts.max_payout}")
            
            return program
        
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI response as JSON: {e}")
            logger.error(f"Response was: {response[:500]}")
            raise
        
        except Exception as e:
            logger.error(f"AI extraction failed: {e}")
            raise
    
    async def analyze_multiple_programs(
        self,
        program_urls: List[str]
    ) -> List[BugBountyProgram]:
        """Analyze multiple programs concurrently"""
        tasks = [self.analyze_program(url) for url in program_urls]
        programs = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out failures
        valid_programs = [p for p in programs if isinstance(p, BugBountyProgram)]
        
        logger.info(f"Analyzed {len(valid_programs)}/{len(program_urls)} programs successfully")
        
        return valid_programs
    
    def program_to_dict(self, program: BugBountyProgram) -> Dict[str, Any]:
        """Convert program to dictionary for JSON serialization"""
        data = asdict(program)
        data['last_updated'] = program.last_updated.isoformat()
        return data
    
    async def quick_scope_check(
        self,
        program_url: str,
        target_url: str
    ) -> bool:
        """
        Quick check if target is in scope
        
        Args:
            program_url: Bug bounty program page
            target_url: Target to check (e.g., "test.apple.com")
            
        Returns:
            True if in scope, False otherwise
        """
        program = await self.analyze_program(program_url)
        
        # Check against in-scope patterns
        from fnmatch import fnmatch
        
        for pattern in program.scope.in_scope:
            if fnmatch(target_url, pattern):
                # Check not in out-of-scope
                for exclusion in program.scope.out_of_scope:
                    if fnmatch(target_url, exclusion):
                        logger.warning(f"{target_url} matches in-scope but is explicitly excluded")
                        return False
                
                logger.info(f"{target_url} is IN SCOPE (matches {pattern})")
                
                # Voice: Announce in scope
                await self.voice.announce_scope_check(target_url, True)
                
                return True
        
        logger.warning(f"{target_url} is OUT OF SCOPE")
        
        # Voice: Announce out of scope
        await self.voice.announce_scope_check(target_url, False)
        
        return False


# Known program URLs for quick access
KNOWN_PROGRAMS = {
    "apple": "https://security.apple.com/bounty/",
    "google": "https://bughunters.google.com/about/rules/",
    "microsoft": "https://www.microsoft.com/en-us/msrc/bounty",
    "meta": "https://www.facebook.com/whitehat",
    "tesla": "https://www.tesla.com/legal/security",
}


async def main():
    """Test program analyzer"""
    analyzer = ProgramAnalyzer()
    
    # Test with Apple
    print("Analyzing Apple Security Bounty...")
    program = await analyzer.analyze_program(KNOWN_PROGRAMS["apple"])
    
    print(f"\nProgram: {program.name}")
    print(f"Platform: {program.platform}")
    print(f"\nScope ({len(program.scope.in_scope)} assets):")
    for asset in program.scope.in_scope[:5]:
        print(f"  - {asset}")
    
    print(f"\nForbidden Actions:")
    for action in program.rules.forbidden_actions:
        print(f"  - {action}")
    
    print(f"\nMax Payout: ${program.payouts.max_payout:,}")
    print(f"Confidence: {program.confidence_score:.2%}")
    
    # Test scope check
    print("\n--- Scope Checks ---")
    is_in_scope = await analyzer.quick_scope_check(
        KNOWN_PROGRAMS["apple"],
        "www.apple.com"
    )
    print(f"www.apple.com in scope: {is_in_scope}")


if __name__ == "__main__":
    asyncio.run(main())

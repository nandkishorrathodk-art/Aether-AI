"""
Bug Bounty Voice Notifier

Speaks notifications during bug hunting (TTS only - no voice input).
Hindi-English mix personality!
"""

import asyncio
import logging
from typing import Optional, Dict, Any
from datetime import datetime

from src.perception.voice.tts import TextToSpeech, TTSConfig
from src.bugbounty.models import Vulnerability, VulnerabilitySeverity, BugReport
from src.config import settings

logger = logging.getLogger(__name__)


class BugBountyVoiceNotifier:
    """
    Voice notifications for bug bounty hunting
    
    Speaks updates in Hindi-English mix:
    - "Ji boss! Program analysis complete!"
    - "Boss! Critical bug mila - IDOR vulnerability!"
    - "Scan shuru ho gaya boss, 10 minutes lagenge"
    
    Usage:
        notifier = BugBountyVoiceNotifier()
        await notifier.announce_bug_found(vulnerability)
    """
    
    def __init__(self, enable_voice: bool = True, personality: str = "friendly"):
        """
        Initialize voice notifier
        
        Args:
            enable_voice: Enable/disable voice notifications
            personality: "friendly", "professional", "excited"
        """
        self.enable_voice = enable_voice
        self.personality = personality
        
        if self.enable_voice:
            try:
                self.tts = TextToSpeech(TTSConfig(
                    provider="pyttsx3",  # Fast offline TTS
                    voice="female",
                    rate=170,  # Slightly faster for excitement
                    volume=10.0  # Max volume
                ))
                logger.info("Voice notifier initialized - Ready to speak!")
            except Exception as e:
                logger.error(f"TTS initialization failed: {e}")
                self.enable_voice = False
        
        logger.info(f"Bug Bounty Voice Notifier ready (voice={'ON' if enable_voice else 'OFF'})")
    
    def _speak(self, text: str):
        """Speak text with TTS"""
        if not self.enable_voice:
            return
        
        try:
            logger.info(f"Speaking: {text}")
            self.tts.speak(text)
        except Exception as e:
            logger.error(f"TTS failed: {e}")
    
    async def _speak_async(self, text: str):
        """Speak text asynchronously"""
        if not self.enable_voice:
            return
        
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._speak, text)
    
    # === Program Analysis Notifications ===
    
    async def announce_program_analysis_start(self, program_name: str):
        """Announce program analysis starting"""
        messages = {
            "friendly": f"Ji boss! {program_name} program analyze kar raha hoon. Ek minute rukiye.",
            "professional": f"Starting analysis of {program_name} bug bounty program.",
            "excited": f"Boss! {program_name} ka program padh raha hoon - scope nikal leta hoon!"
        }
        
        await self._speak_async(messages.get(self.personality, messages["friendly"]))
    
    async def announce_program_analysis_complete(
        self,
        program_name: str,
        scope_count: int,
        max_payout: Optional[int] = None
    ):
        """Announce program analysis complete"""
        if max_payout:
            payout_msg = f"Maximum payout {max_payout} dollars hai boss!"
        else:
            payout_msg = ""
        
        messages = {
            "friendly": f"Ji boss! {program_name} analysis complete. {scope_count} in-scope targets mile. {payout_msg}",
            "professional": f"Program analysis complete. Found {scope_count} in-scope targets. Maximum payout: {max_payout} dollars.",
            "excited": f"Boss dekho! {program_name} ready hai! {scope_count} targets, max payout {max_payout} dollars! Bahut scope hai!"
        }
        
        await self._speak_async(messages.get(self.personality, messages["friendly"]))
    
    async def announce_scope_check(self, target: str, in_scope: bool):
        """Announce scope validation result"""
        if in_scope:
            messages = {
                "friendly": f"Ji boss! {target} in-scope hai. Scan kar sakte hain.",
                "professional": f"{target} is in scope. You may proceed with testing.",
                "excited": f"Boss! {target} bilkul in-scope hai! Shuru karte hain!"
            }
        else:
            messages = {
                "friendly": f"Boss sorry, {target} out-of-scope hai. Is target pe scan nahi kar sakte.",
                "professional": f"{target} is out of scope. Testing on this target is not permitted.",
                "excited": f"Ruko boss! {target} out-of-scope hai! Program rules violate ho jayenge!"
            }
        
        await self._speak_async(messages.get(self.personality, messages["friendly"]))
    
    # === Hunt Status Notifications ===
    
    async def announce_hunt_start(self, target: str):
        """Announce autonomous hunt starting"""
        messages = {
            "friendly": f"Ji boss! {target} pe autonomous scan shuru kar raha hoon. Updates deta rahunga.",
            "professional": f"Starting automated security scan on {target}. I will notify you of any findings.",
            "excited": f"Boss! {target} ka full scan shuru! Burp Suite ready, proxies set, let's find some bugs!"
        }
        
        await self._speak_async(messages.get(self.personality, messages["friendly"]))
    
    async def announce_scan_progress(self, requests_sent: int, endpoints_found: int):
        """Announce scan progress"""
        messages = {
            "friendly": f"Boss, {requests_sent} requests send kiye, {endpoints_found} endpoints mile.",
            "professional": f"Progress update: {requests_sent} requests completed, {endpoints_found} endpoints discovered.",
            "excited": f"Boss! {requests_sent} requests done! {endpoints_found} endpoints mil gaye!"
        }
        
        await self._speak_async(messages.get(self.personality, messages["friendly"]))
    
    # === Bug Discovery Notifications ===
    
    async def announce_bug_found(self, vulnerability: Vulnerability):
        """Announce bug found - MAIN ALERT!"""
        severity = vulnerability.severity.value.upper()
        vuln_type = vulnerability.type
        
        # Severity-based urgency
        if vulnerability.severity == VulnerabilitySeverity.CRITICAL:
            messages = {
                "friendly": f"BOSS! CRITICAL BUG MILA! {vuln_type} vulnerability! Bahut important hai boss!",
                "professional": f"CRITICAL vulnerability found: {vuln_type}. Immediate attention required.",
                "excited": f"BOSS DEKHO! CRITICAL {vuln_type} MIL GAYA! Yeh to jackpot hai! Report ready karein?"
            }
        elif vulnerability.severity == VulnerabilitySeverity.HIGH:
            messages = {
                "friendly": f"Boss! High severity bug mila - {vuln_type}. Achha finding hai!",
                "professional": f"High severity vulnerability detected: {vuln_type}.",
                "excited": f"Boss! High {vuln_type} mil gaya! Payout toh pakka hai!"
            }
        elif vulnerability.severity == VulnerabilitySeverity.MEDIUM:
            messages = {
                "friendly": f"Boss, medium severity {vuln_type} mila. Dekh lete hain.",
                "professional": f"Medium severity {vuln_type} vulnerability found.",
                "excited": f"Boss! Medium {vuln_type} - chalega yaar, report kar dete hain!"
            }
        else:
            messages = {
                "friendly": f"Boss, low severity {vuln_type} mila.",
                "professional": f"Low severity {vuln_type} identified.",
                "excited": f"Boss, low {vuln_type} hai - bonus mein add kar denge!"
            }
        
        await self._speak_async(messages.get(self.personality, messages["friendly"]))
    
    async def announce_multiple_bugs(self, count: int, critical: int, high: int):
        """Announce multiple bugs found"""
        messages = {
            "friendly": f"Ji boss! Total {count} bugs mile. {critical} critical aur {high} high severity!",
            "professional": f"Scan complete. {count} vulnerabilities found: {critical} critical, {high} high severity.",
            "excited": f"BOSS! {count} BUGS MIL GAYE! {critical} critical, {high} high! Paisa hi paisa hoga!"
        }
        
        await self._speak_async(messages.get(self.personality, messages["friendly"]))
    
    # === Report Generation Notifications ===
    
    async def announce_poc_generation(self, vuln_type: str):
        """Announce PoC generation"""
        messages = {
            "friendly": f"Boss, {vuln_type} ka proof of concept code bana raha hoon.",
            "professional": f"Generating proof of concept exploit for {vuln_type}.",
            "excited": f"Boss! {vuln_type} ka PoC banata hoon - full working exploit!"
        }
        
        await self._speak_async(messages.get(self.personality, messages["friendly"]))
    
    async def announce_report_ready(self, report_format: str):
        """Announce report generation complete"""
        messages = {
            "friendly": f"Ji boss! {report_format} format mein report ready hai. Check kar sakte ho.",
            "professional": f"Bug report generated in {report_format} format. Ready for review.",
            "excited": f"Boss! Report tayyar! {report_format} mein perfect likha hai - submit kar do!"
        }
        
        await self._speak_async(messages.get(self.personality, messages["friendly"]))
    
    async def announce_payout_estimate(self, min_payout: int, max_payout: int):
        """Announce estimated payout"""
        messages = {
            "friendly": f"Boss, is bug ka estimated payout {min_payout} se {max_payout} dollars hai.",
            "professional": f"Estimated payout range: {min_payout} to {max_payout} dollars.",
            "excited": f"Boss! {min_payout} se {max_payout} dollars mil sakte hain! Lambo ka dream kar sakte ho!"
        }
        
        await self._speak_async(messages.get(self.personality, messages["friendly"]))
    
    # === Platform Submission Notifications ===
    
    async def announce_submission_start(self, platform: str):
        """Announce report submission starting"""
        messages = {
            "friendly": f"Boss, {platform} pe report submit kar raha hoon.",
            "professional": f"Submitting report to {platform}.",
            "excited": f"Boss! {platform} pe submit kar raha hoon - fingers crossed!"
        }
        
        await self._speak_async(messages.get(self.personality, messages["friendly"]))
    
    async def announce_submission_complete(self, platform: str, report_id: str):
        """Announce submission success"""
        messages = {
            "friendly": f"Ji boss! {platform} pe successfully submit ho gaya. Report ID: {report_id}",
            "professional": f"Report successfully submitted to {platform}. Report ID: {report_id}",
            "excited": f"Boss DONE! {platform} pe submit! ID: {report_id}! Ab wait karo payout ka!"
        }
        
        await self._speak_async(messages.get(self.personality, messages["friendly"]))
    
    # === Error Notifications ===
    
    async def announce_error(self, error_type: str):
        """Announce error occurred"""
        messages = {
            "friendly": f"Boss sorry, {error_type} error aa gaya. Main fix karne ki koshish kar raha hoon.",
            "professional": f"Error encountered: {error_type}. Attempting recovery.",
            "excited": f"Boss! {error_type} problem hai! Ruko main solve karta hoon!"
        }
        
        await self._speak_async(messages.get(self.personality, messages["friendly"]))
    
    async def announce_burp_not_found(self):
        """Announce Burp Suite not detected"""
        messages = {
            "friendly": "Boss, Burp Suite nahi mil raha. Please Burp Suite Pro start kar do.",
            "professional": "Burp Suite not detected. Please start Burp Suite Professional.",
            "excited": "Boss! Burp Suite to kholo pehle! Scan kaise karun?"
        }
        
        await self._speak_async(messages.get(self.personality, messages["friendly"]))
    
    # === Motivational Messages ===
    
    async def celebrate_success(self):
        """Celebrate successful bug find"""
        messages = {
            "friendly": "Shabash boss! Aap best ho! Bug mil gaya!",
            "professional": "Excellent work. Vulnerability successfully identified.",
            "excited": "YESSS BOSS! Tumhara naam top leaderboard pe hoga! You're the best!"
        }
        
        await self._speak_async(messages.get(self.personality, messages["friendly"]))
    
    async def encourage_during_scan(self):
        """Encourage during long scan"""
        messages = {
            "friendly": "Boss thoda wait karo, main dhund raha hoon bugs. Patience rakho!",
            "professional": "Scan in progress. Please wait while I analyze the target.",
            "excited": "Boss! Scan chal raha hai full speed pe! Kuch na kuch milega pakka!"
        }
        
        await self._speak_async(messages.get(self.personality, messages["friendly"]))
    
    # === Utility ===
    
    def set_personality(self, personality: str):
        """Change personality style"""
        if personality in ["friendly", "professional", "excited"]:
            self.personality = personality
            logger.info(f"Personality changed to: {personality}")
    
    def enable(self):
        """Enable voice notifications"""
        self.enable_voice = True
        logger.info("Voice notifications enabled")
    
    def disable(self):
        """Disable voice notifications"""
        self.enable_voice = False
        logger.info("Voice notifications disabled")


# Global instance for easy access
_notifier_instance: Optional[BugBountyVoiceNotifier] = None


def get_voice_notifier(enable_voice: bool = True) -> BugBountyVoiceNotifier:
    """Get global voice notifier instance"""
    global _notifier_instance
    
    if _notifier_instance is None:
        _notifier_instance = BugBountyVoiceNotifier(enable_voice=enable_voice)
    
    return _notifier_instance


async def test_notifier():
    """Test voice notifier"""
    notifier = BugBountyVoiceNotifier(enable_voice=True, personality="excited")
    
    print("Testing voice notifications...")
    
    # Test program analysis
    await notifier.announce_program_analysis_start("Apple Security Bounty")
    await asyncio.sleep(2)
    
    await notifier.announce_program_analysis_complete("Apple", 15, 2000000)
    await asyncio.sleep(2)
    
    # Test scope check
    await notifier.announce_scope_check("www.apple.com", True)
    await asyncio.sleep(2)
    
    # Test hunt start
    await notifier.announce_hunt_start("https://www.apple.com")
    await asyncio.sleep(2)
    
    # Test bug found
    vuln = Vulnerability(
        type="IDOR",
        severity=VulnerabilitySeverity.CRITICAL,
        url="https://www.apple.com/api/orders/12345",
        description="Insecure Direct Object Reference",
        evidence="Can access other users' orders",
        confidence=0.95
    )
    await notifier.announce_bug_found(vuln)
    await asyncio.sleep(2)
    
    # Test celebration
    await notifier.celebrate_success()
    
    print("Voice test complete!")


if __name__ == "__main__":
    asyncio.run(test_notifier())

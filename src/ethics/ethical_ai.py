"""
Ethical AI Guardian
Ensures Aether AI operates ethically and responsibly
"""
from typing import Dict, Any, List
from src.utils.logger import get_logger
from .bias_detector import BiasDetector
from .transparency import TransparencyEngine

logger = get_logger(__name__)


class EthicalAIGuard:
    """
    Comprehensive ethical AI enforcement
    - Prevents harmful outputs
    - Ensures fairness
    - Maintains transparency
    - Empowers users
    """
    
    def __init__(self):
        self.bias_detector = BiasDetector()
        self.transparency = TransparencyEngine()
        self.harmful_keywords = self._load_harmful_keywords()
        logger.info("Ethical AI Guard initialized")
        
    def _load_harmful_keywords(self) -> List[str]:
        """Keywords that indicate potentially harmful content"""
        return [
            "how to hack", "how to steal", "illegal",
            "harm others", "violent", "discriminate"
        ]
        
    def validate_response(self, response: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Comprehensive ethical validation of AI response
        
        Returns validation result with:
        - is_ethical: bool
        - concerns: List[str]
        - recommendations: List[str]
        """
        context = context or {}
        concerns = []
        recommendations = []
        
        bias_audit = self.bias_detector.audit_response(response)
        if bias_audit["bias_detected"]:
            concerns.append(f"Bias detected: {', '.join(bias_audit['bias_types'])}")
            recommendations.append("Regenerate response with bias mitigation")
            
        for keyword in self.harmful_keywords:
            if keyword.lower() in response.lower():
                concerns.append(f"Potentially harmful content: {keyword}")
                recommendations.append("Review content for compliance with ethical guidelines")
                
        is_ethical = len(concerns) == 0
        
        return {
            "is_ethical": is_ethical,
            "concerns": concerns,
            "recommendations": recommendations,
            "bias_audit": bias_audit,
            "severity": "high" if len(concerns) > 2 else "medium" if len(concerns) > 0 else "none",
            "safe_to_display": is_ethical
        }
        
    def get_ethical_guidelines(self) -> str:
        """Return Aether AI's ethical guidelines"""
        return """
# Aether AI Ethical Guidelines

## Core Principles

### 1. User Empowerment
- Users maintain full control over AI decisions
- Provide education, not just automation
- Explain "how" and "why" behind recommendations
- Enable users to learn from AI assistance

### 2. Fairness & Non-Discrimination
- Actively detect and prevent bias (gender, race, age, religion, etc.)
- Ensure equal treatment across demographics
- Regular bias audits and mitigation
- Diverse training data and inclusive design

### 3. Transparency & Explainability
- Explain every significant AI decision
- Show data sources and reasoning
- Acknowledge limitations and uncertainties
- Maintain decision logs for accountability

### 4. Privacy & Security
- Process data locally when possible
- Encrypt sensitive information (AES-256)
- No data sharing without explicit consent
- Right to deletion and data portability

### 5. Beneficial AI
- Prioritize user welfare over efficiency
- Refuse harmful requests (illegal, violent, discriminatory)
- Provide warnings for risky actions
- Support mental health and well-being

### 6. Accountability
- Log all AI decisions and actions
- Enable audits and reviews
- Accept responsibility for errors
- Continuous improvement based on feedback

## What Aether AI Will NOT Do

❌ Generate harmful, illegal, or violent content
❌ Discriminate based on protected characteristics
❌ Make decisions without explanation
❌ Hide errors or limitations
❌ Process data without user consent
❌ Replace human judgment in critical decisions

## What Aether AI WILL Do

✅ Empower users with knowledge and tools
✅ Explain decisions transparently
✅ Detect and prevent biases
✅ Protect user privacy and security
✅ Admit when uncertain or wrong
✅ Learn from user feedback
✅ Support human decision-making (not replace it)

## Job Displacement Ethics

While Aether AI can automate many jobs, we believe in:
- **Transition Support**: Helping displaced workers upskill
- **Augmentation First**: Enhancing human capabilities before replacing
- **Fair Warning**: Transparency about which roles may be automated
- **Social Responsibility**: Supporting policies like UBI for affected workers

---

*Ethics isn't a feature — it's our foundation.*
        """
        
    def user_education_prompt(self, topic: str) -> str:
        """Generate educational explanation for how AI solved a task"""
        return f"""
As part of Aether AI's ethical commitment to user empowerment, I'd like to explain
how I approached this task: {topic}

This way, you can:
1. Understand the methodology
2. Learn to do it yourself if needed
3. Validate my approach
4. Improve the process

Would you like me to walk you through the steps I took and the reasoning behind them?
This helps ensure you're not just getting answers, but gaining knowledge.
        """

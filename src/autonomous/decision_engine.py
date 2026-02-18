"""
Decision Engine - Makes intelligent decisions without human input

Decides: "Is this a bug?", "Should I exploit?", "Should I submit?"
"""

from typing import Dict, Any, List
from src.cognitive.llm.llm_wrapper import LLMInference
from src.utils.logger import get_logger

logger = get_logger(__name__)


class DecisionEngine:
    """
    Makes autonomous decisions about security findings and actions.
    """
    
    def __init__(self):
        self.llm = LLMInference()
        self.decision_history = []
        logger.info("🤔 Decision Engine initialized")
    
    async def is_this_a_bug(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Decide if a finding is a real bug
        
        Args:
            finding: Security finding details
            
        Returns:
            Decision with confidence and reasoning
        """
        try:
            prompt = f"""You are a professional security researcher. Analyze this finding:

**Type:** {finding.get('type', 'unknown')}
**Location:** {finding.get('location', 'unknown')}
**Evidence:** {finding.get('evidence', 'none')}
**Context:** {finding.get('context', 'none')}

Decide:
1. Is this a REAL vulnerability or false positive?
2. What is the severity? (low/medium/high/critical)
3. Is it exploitable?
4. What's the confidence level? (0.0 to 1.0)

Respond in JSON:
{{
  "is_bug": true/false,
  "severity": "high",
  "exploitable": true/false,
  "confidence": 0.85,
  "reasoning": "Explanation...",
  "false_positive_risk": 0.15
}}
"""
            
            response = await self.llm.get_completion(prompt)
            
            import json
            import re
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                decision = json.loads(json_match.group(0))
            else:
                decision = self._default_bug_decision(finding)
            
            self.decision_history.append({
                "type": "bug_validation",
                "finding": finding,
                "decision": decision
            })
            
            logger.info(f"Bug decision: {decision.get('is_bug')} (confidence: {decision.get('confidence', 0)})")
            
            return decision
            
        except Exception as e:
            logger.error(f"Bug decision failed: {e}")
            return self._default_bug_decision(finding)
    
    def _default_bug_decision(self, finding: Dict) -> Dict:
        """Default conservative decision"""
        return {
            "is_bug": False,
            "severity": "low",
            "exploitable": False,
            "confidence": 0.3,
            "reasoning": "Unable to analyze, defaulting to safe decision",
            "false_positive_risk": 0.7
        }
    
    async def should_exploit(self, bug: Dict[str, Any]) -> Dict[str, Any]:
        """
        Decide if we should attempt to exploit a bug
        
        Args:
            bug: Validated bug details
            
        Returns:
            Exploitation decision
        """
        try:
            severity = bug.get('severity', 'low')
            confidence = bug.get('confidence', 0.5)
            
            if severity in ['critical', 'high'] and confidence > 0.7:
                should_exploit = True
            elif severity == 'medium' and confidence > 0.8:
                should_exploit = True
            else:
                should_exploit = False
            
            prompt = f"""Should we attempt to exploit this vulnerability?

**Severity:** {severity}
**Confidence:** {confidence}
**Type:** {bug.get('type', 'unknown')}

Consider:
- Is it safe to test?
- What's the risk of breaking something?
- Is it ethical in bug bounty context?
- What's the potential impact?

Respond in JSON:
{{
  "should_exploit": true/false,
  "risk_level": "low/medium/high",
  "safety_precautions": ["precaution 1", "precaution 2"],
  "recommended_approach": "Description...",
  "reasoning": "Why..."
}}
"""
            
            response = await self.llm.get_completion(prompt)
            
            import json
            import re
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                decision = json.loads(json_match.group(0))
            else:
                decision = {
                    "should_exploit": should_exploit,
                    "risk_level": "medium",
                    "safety_precautions": ["Test in isolated environment"],
                    "recommended_approach": "Careful manual testing",
                    "reasoning": "Conservative approach"
                }
            
            logger.info(f"Exploit decision: {decision.get('should_exploit')}")
            
            return decision
            
        except Exception as e:
            logger.error(f"Exploit decision failed: {e}")
            return {
                "should_exploit": False,
                "risk_level": "high",
                "reasoning": f"Error in decision making: {e}"
            }
    
    async def should_submit_report(self, bug: Dict[str, Any], report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Decide if report is ready for submission
        
        Args:
            bug: Bug details
            report: Generated report
            
        Returns:
            Submission decision
        """
        try:
            from src.bugbounty.report_scorer import ReportScorer
            
            scorer = ReportScorer()
            score_result = scorer.score_report(report)
            
            percentage = score_result.get('percentage', 0)
            
            should_submit = percentage >= 70
            
            decision = {
                "should_submit": should_submit,
                "report_score": percentage,
                "quality_rating": score_result.get('quality_rating'),
                "reasoning": "",
                "improvements_needed": score_result.get('recommendations', [])
            }
            
            if should_submit:
                decision["reasoning"] = "Report quality is good enough for submission"
            else:
                decision["reasoning"] = f"Report score ({percentage}%) below threshold (70%)"
            
            logger.info(f"Submit decision: {should_submit} (score: {percentage}%)")
            
            return decision
            
        except Exception as e:
            logger.error(f"Submit decision failed: {e}")
            return {
                "should_submit": False,
                "reasoning": f"Error evaluating report: {e}"
            }
    
    async def choose_next_action(self, context: Dict[str, Any]) -> str:
        """
        Choose next autonomous action based on context
        
        Args:
            context: Current state/context
            
        Returns:
            Next action to take
        """
        try:
            current_state = context.get('state', 'idle')
            findings_count = context.get('findings_count', 0)
            time_elapsed = context.get('time_elapsed_minutes', 0)
            
            prompt = f"""You are an autonomous AI hacker. Choose your next action:

**Current State:** {current_state}
**Findings So Far:** {findings_count}
**Time Elapsed:** {time_elapsed} minutes
**Context:** {context.get('additional_context', '')}

Available actions:
- continue_scanning: Keep scanning for more bugs
- analyze_findings: Deep dive into current findings
- exploit_bug: Attempt to exploit discovered bugs
- generate_reports: Create bug reports
- submit_reports: Submit to platform
- take_break: Pause for a bit
- stop: End session

Choose the MOST PRODUCTIVE next action.

Respond with just the action name.
"""
            
            response = await self.llm.get_completion(prompt)
            
            action = response.strip().lower()
            
            valid_actions = [
                "continue_scanning", "analyze_findings", "exploit_bug",
                "generate_reports", "submit_reports", "take_break", "stop"
            ]
            
            if action not in valid_actions:
                action = "continue_scanning"
            
            logger.info(f"Next action chosen: {action}")
            
            return action
            
        except Exception as e:
            logger.error(f"Action choice failed: {e}")
            return "continue_scanning"

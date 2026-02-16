"""
AI Transparency Engine
Explains AI decisions to users
"""
from typing import Dict, Any, List
from dataclasses import dataclass
from datetime import datetime
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class DecisionExplanation:
    decision: str
    reasoning: List[str]
    confidence: float
    alternatives_considered: List[str]
    data_sources: List[str]
    limitations: List[str]
    timestamp: datetime


class TransparencyEngine:
    """
    Provides explanations for AI decisions
    Builds trust through transparency
    """
    
    def __init__(self):
        self.explanation_history: List[DecisionExplanation] = []
        logger.info("Transparency Engine initialized")
        
    def explain_provider_choice(
        self,
        chosen_provider: str,
        task_type: str,
        alternatives: List[str],
        reasoning: Dict[str, Any]
    ) -> DecisionExplanation:
        """Explain why a specific AI provider was chosen"""
        
        explanation = DecisionExplanation(
            decision=f"Selected {chosen_provider} for {task_type} task",
            reasoning=[
                f"{chosen_provider} is optimized for {task_type} tasks",
                f"Speed: {reasoning.get('speed', 'fast')} tokens/second",
                f"Cost: {reasoning.get('cost', 'optimal')}",
                f"Quality: {reasoning.get('quality', 'high')}"
            ],
            confidence=reasoning.get('confidence', 0.85),
            alternatives_considered=alternatives,
            data_sources=["Provider benchmarks", "Historical performance", "Cost analysis"],
            limitations=[
                "Performance may vary based on query complexity",
                "Provider availability subject to API status"
            ],
            timestamp=datetime.now()
        )
        
        self.explanation_history.append(explanation)
        return explanation
        
    def explain_agent_selection(
        self,
        agent_type: str,
        task: str,
        rationale: str
    ) -> DecisionExplanation:
        """Explain why specific agent was selected"""
        
        explanation = DecisionExplanation(
            decision=f"Assigned {agent_type} agent to task",
            reasoning=[
                f"Task: {task}",
                f"Rationale: {rationale}",
                f"{agent_type} agent has specialized training for this domain"
            ],
            confidence=0.9,
            alternatives_considered=["Multi-agent collaboration", "General-purpose agent"],
            data_sources=["Agent capability matrix", "Task classification"],
            limitations=["Single-agent approach may miss cross-domain insights"],
            timestamp=datetime.now()
        )
        
        self.explanation_history.append(explanation)
        return explanation
        
    def explain_recommendation(
        self,
        recommendation: str,
        evidence: List[str],
        confidence: float
    ) -> str:
        """Generate human-readable explanation for a recommendation"""
        
        explanation = f"""
**Recommendation**: {recommendation}

**Why I recommend this**:
{chr(10).join(f"• {item}" for item in evidence)}

**Confidence Level**: {confidence:.0%}

**How I arrived at this**:
I analyzed the available data using specialized AI models trained on similar scenarios.
My recommendation is based on patterns identified in the data and industry best practices.

**Limitations to consider**:
• This recommendation is based on the information provided
• Results may vary based on specific implementation details
• Human oversight and domain expertise should validate this recommendation

**Transparency Note**: This decision was made by Aether AI's analysis engine.
You can review the underlying data and request alternative approaches.
        """
        
        return explanation.strip()
        
    def get_decision_log(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent decision explanations"""
        recent = self.explanation_history[-limit:]
        
        return [
            {
                "decision": exp.decision,
                "reasoning": exp.reasoning,
                "confidence": exp.confidence,
                "timestamp": exp.timestamp.isoformat()
            }
            for exp in recent
        ]
        
    def generate_transparency_report(self) -> str:
        """Generate full transparency report"""
        
        report = f"""
# AI Transparency Report

**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Total Decisions Logged**: {len(self.explanation_history)}

## How Aether AI Makes Decisions

### 1. Multi-Provider Intelligence
Aether uses 6 different AI providers (OpenAI, Anthropic, Google, Groq, Fireworks, OpenRouter).
For each task, we select the optimal provider based on:
- Task type (analysis, code, creative, etc.)
- Speed requirements
- Cost optimization
- Quality targets

### 2. Multi-Agent Collaboration
Specialized AI agents handle different domains:
- **Analysis Agent**: Business analysis, SWOT, data interpretation
- **Coding Agent**: Software development, debugging
- **Creative Agent**: Content creation, brainstorming
- **Strategy Agent**: High-level planning, consulting
- **Security Agent**: Threat detection, compliance

### 3. Ethical Safeguards
- **Bias Detection**: Scans all responses for gender, racial, age, religious biases
- **Transparency**: Explains all decisions and recommendations
- **User Control**: You can override any AI decision
- **Privacy**: All data processed locally when possible

### 4. Continuous Improvement
Aether learns from:
- User feedback and corrections
- Performance metrics
- Error analysis
- Industry best practices

## Recent Decisions

{chr(10).join(f"- {exp.decision} (confidence: {exp.confidence:.0%})" for exp in self.explanation_history[-5:])}

## Your Rights

You have the right to:
✓ Request explanation for any AI decision
✓ Override or reject AI recommendations
✓ Delete your data at any time
✓ Export your conversation history
✓ Opt-out of specific features

---

*Transparency builds trust. We explain our decisions, you stay in control.*
        """
        
        return report.strip()

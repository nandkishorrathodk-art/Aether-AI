"""
Advanced SWOT Analysis Tool
Replaces: Business analysts, strategic consultants
"""
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from src.cognitive.agents.multi_agent_system import MultiAgentSystem, AgentTask, AgentType
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class SWOTResult:
    strengths: List[str]
    weaknesses: List[str]
    opportunities: List[str]
    threats: List[str]
    strategic_recommendations: List[str]
    confidence_score: float
    analysis_summary: str


class SWOTAnalyzer:
    """
    AI-powered SWOT analysis
    Replaces 10-20 hours of consultant work with seconds
    """
    
    def __init__(self, multi_agent_system: Optional[MultiAgentSystem] = None):
        self.mas = multi_agent_system or MultiAgentSystem()
        logger.info("SWOT Analyzer initialized")
        
    async def analyze(
        self,
        entity_name: str,
        entity_type: str = "company",
        context: Dict[str, Any] = None
    ) -> SWOTResult:
        """
        Perform comprehensive SWOT analysis
        
        Args:
            entity_name: Name of company/product/project to analyze
            entity_type: Type of entity (company, product, project, individual)
            context: Additional context (industry, market, financials, etc.)
        """
        context = context or {}
        logger.info(f"Performing SWOT analysis for {entity_name}")
        
        prompt = f"""
        Perform a comprehensive SWOT analysis for:
        
        **Entity**: {entity_name}
        **Type**: {entity_type}
        **Context**: {context}
        
        Provide detailed analysis in the following format:
        
        ## STRENGTHS (Internal positive factors)
        List 5-7 key strengths with explanations
        
        ## WEAKNESSES (Internal negative factors)
        List 5-7 key weaknesses with explanations
        
        ## OPPORTUNITIES (External positive factors)
        List 5-7 key opportunities with explanations
        
        ## THREATS (External negative factors)
        List 5-7 key threats with explanations
        
        ## STRATEGIC RECOMMENDATIONS
        Provide 5 actionable strategic recommendations based on the SWOT analysis
        
        ## EXECUTIVE SUMMARY
        2-3 paragraph summary of key findings
        """
        
        task = AgentTask(
            task_type=AgentType.ANALYSIS,
            prompt=prompt,
            context=context,
            priority=8,
            timeout=90
        )
        
        response = await self.mas.process_task(task)
        
        swot_data = self._parse_swot_response(response.result)
        
        return SWOTResult(
            strengths=swot_data["strengths"],
            weaknesses=swot_data["weaknesses"],
            opportunities=swot_data["opportunities"],
            threats=swot_data["threats"],
            strategic_recommendations=swot_data["recommendations"],
            confidence_score=response.confidence,
            analysis_summary=swot_data["summary"]
        )
        
    def _parse_swot_response(self, response_text: str) -> Dict[str, List[str]]:
        """Parse AI response into structured SWOT components"""
        result = {
            "strengths": [],
            "weaknesses": [],
            "opportunities": [],
            "threats": [],
            "recommendations": [],
            "summary": ""
        }
        
        lines = response_text.split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            
            if "STRENGTHS" in line.upper():
                current_section = "strengths"
            elif "WEAKNESSES" in line.upper():
                current_section = "weaknesses"
            elif "OPPORTUNITIES" in line.upper():
                current_section = "opportunities"
            elif "THREATS" in line.upper():
                current_section = "threats"
            elif "RECOMMENDATIONS" in line.upper():
                current_section = "recommendations"
            elif "SUMMARY" in line.upper():
                current_section = "summary"
            elif line.startswith(('-', '*', '•', '1.', '2.', '3.', '4.', '5.', '6.', '7.')):
                clean_line = line.lstrip('-*•0123456789. ')
                if clean_line and current_section and current_section != "summary":
                    result[current_section].append(clean_line)
            elif current_section == "summary" and line:
                result["summary"] += line + " "
                
        result["summary"] = result["summary"].strip()
        
        if not result["summary"]:
            result["summary"] = "SWOT analysis completed. See detailed breakdown above."
            
        return result
        
    def format_report(self, swot: SWOTResult, entity_name: str) -> str:
        """Format SWOT analysis as professional report"""
        report = f"""
# SWOT Analysis Report: {entity_name}

**Generated**: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Confidence Score**: {swot.confidence_score:.0%}

---

## Executive Summary

{swot.analysis_summary}

---

## Detailed Analysis

### 💪 STRENGTHS (Internal Positive Factors)

{self._format_list(swot.strengths)}

### ⚠️ WEAKNESSES (Internal Negative Factors)

{self._format_list(swot.weaknesses)}

### 🚀 OPPORTUNITIES (External Positive Factors)

{self._format_list(swot.opportunities)}

### 🔥 THREATS (External Negative Factors)

{self._format_list(swot.threats)}

---

## Strategic Recommendations

{self._format_list(swot.strategic_recommendations, numbered=True)}

---

## SWOT Matrix

| Internal Factors | External Factors |
|-----------------|------------------|
| **Strengths** ({len(swot.strengths)}) | **Opportunities** ({len(swot.opportunities)}) |
| **Weaknesses** ({len(swot.weaknesses)}) | **Threats** ({len(swot.threats)}) |

---

*This report was generated by Aether AI - Professional Business Analysis System*
*Replaces 10-20 hours of consultant work | Typical consulting cost saved: $2,000 - $10,000*
        """
        
        return report.strip()
        
    def _format_list(self, items: List[str], numbered: bool = False) -> str:
        """Format list items for report"""
        if not items:
            return "- None identified"
            
        if numbered:
            return "\n".join(f"{i+1}. {item}" for i, item in enumerate(items))
        else:
            return "\n".join(f"- {item}" for item in items)
            
    async def compare_swot(
        self,
        entities: List[Dict[str, str]]
    ) -> Dict[str, Any]:
        """
        Compare SWOT analyses for multiple entities
        Useful for competitive analysis
        """
        logger.info(f"Comparing SWOT for {len(entities)} entities")
        
        swot_results = {}
        for entity in entities:
            swot = await self.analyze(
                entity_name=entity["name"],
                entity_type=entity.get("type", "company"),
                context=entity.get("context", {})
            )
            swot_results[entity["name"]] = swot
            
        return {
            "entities_compared": len(entities),
            "swot_analyses": swot_results,
            "competitive_summary": self._generate_comparative_summary(swot_results)
        }
        
    def _generate_comparative_summary(self, swot_results: Dict[str, SWOTResult]) -> str:
        """Generate summary comparing multiple SWOT analyses"""
        summary = "## Comparative SWOT Summary\n\n"
        
        for entity, swot in swot_results.items():
            summary += f"### {entity}\n"
            summary += f"- Strengths: {len(swot.strengths)} identified\n"
            summary += f"- Weaknesses: {len(swot.weaknesses)} identified\n"
            summary += f"- Opportunities: {len(swot.opportunities)} identified\n"
            summary += f"- Threats: {len(swot.threats)} identified\n"
            summary += f"- Overall confidence: {swot.confidence_score:.0%}\n\n"
            
        return summary

"""SWOT Analysis automation for strategic business planning."""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import json
from datetime import datetime


@dataclass
class SWOTComponent:
    """A single SWOT component (strength, weakness, opportunity, or threat)."""
    category: str
    item: str
    description: str
    impact: str
    priority: int
    evidence: List[str]
    recommendations: List[str]


class SWOTAnalyzer:
    """
    Automated SWOT Analysis engine for business intelligence.
    
    Generates comprehensive strategic analysis reports for companies,
    projects, or situations.
    """
    
    def __init__(self, llm_provider=None):
        """
        Initialize SWOT analyzer.
        
        Args:
            llm_provider: Language model provider for analysis
        """
        self.llm_provider = llm_provider
        self.analysis_history: List[Dict[str, Any]] = []
        
    def analyze(self, subject: str, context: Optional[Dict[str, Any]] = None,
                include_recommendations: bool = True) -> Dict[str, Any]:
        """
        Perform comprehensive SWOT analysis.
        
        Args:
            subject: Company, project, or situation to analyze
            context: Additional context (industry, market data, etc.)
            include_recommendations: Include strategic recommendations
            
        Returns:
            Complete SWOT analysis with insights
        """
        context = context or {}
        
        if self.llm_provider:
            analysis = self._analyze_with_llm(subject, context)
        else:
            analysis = self._analyze_heuristic(subject, context)
        
        strategic_insights = self._generate_strategic_insights(analysis)
        
        if include_recommendations:
            recommendations = self._generate_recommendations(analysis, strategic_insights)
        else:
            recommendations = []
        
        risk_assessment = self._assess_risks(analysis)
        
        opportunity_matrix = self._create_opportunity_matrix(analysis)
        
        result = {
            'subject': subject,
            'timestamp': datetime.now().isoformat(),
            'strengths': analysis['strengths'],
            'weaknesses': analysis['weaknesses'],
            'opportunities': analysis['opportunities'],
            'threats': analysis['threats'],
            'strategic_insights': strategic_insights,
            'recommendations': recommendations,
            'risk_assessment': risk_assessment,
            'opportunity_matrix': opportunity_matrix,
            'summary': self._generate_summary(analysis, strategic_insights)
        }
        
        self.analysis_history.append(result)
        
        return result
    
    def _analyze_with_llm(self, subject: str, context: Dict[str, Any]) -> Dict[str, List[SWOTComponent]]:
        """Perform SWOT analysis using LLM."""
        context_str = json.dumps(context, indent=2) if context else "No additional context"
        
        prompt = f"""Conduct a comprehensive SWOT analysis for: {subject}

Context: {context_str}

Provide a detailed SWOT analysis with:
1. **Strengths**: Internal positive attributes (5-7 items)
2. **Weaknesses**: Internal limitations (5-7 items)
3. **Opportunities**: External favorable conditions (5-7 items)
4. **Threats**: External challenges (5-7 items)

For each item, provide:
- Clear description
- Impact level (High/Medium/Low)
- Priority (1-5)
- Evidence or reasoning

Format each section as:
## STRENGTHS
- **[Item]**: [Description] | Impact: [level] | Priority: [number]

## WEAKNESSES
- **[Item]**: [Description] | Impact: [level] | Priority: [number]

## OPPORTUNITIES
- **[Item]**: [Description] | Impact: [level] | Priority: [number]

## THREATS
- **[Item]**: [Description] | Impact: [level] | Priority: [number]

SWOT Analysis:"""
        
        try:
            response = self.llm_provider.generate(
                prompt,
                max_tokens=2000,
                temperature=0.7,
                task_type='analysis'
            )
            
            content = response.get('content', '')
            return self._parse_swot_response(content)
        except Exception as e:
            print(f"LLM SWOT analysis error: {e}")
            return self._analyze_heuristic(subject, context)
    
    def _analyze_heuristic(self, subject: str, context: Dict[str, Any]) -> Dict[str, List[SWOTComponent]]:
        """Fallback heuristic SWOT analysis."""
        return {
            'strengths': [
                SWOTComponent(
                    category="Strengths",
                    item="Market Position",
                    description=f"{subject} has established market presence",
                    impact="High",
                    priority=5,
                    evidence=["Market data", "Brand recognition"],
                    recommendations=["Leverage for expansion"]
                ),
                SWOTComponent(
                    category="Strengths",
                    item="Innovation Capability",
                    description="Strong R&D and product development",
                    impact="High",
                    priority=4,
                    evidence=["Product portfolio", "Patents"],
                    recommendations=["Invest in emerging technologies"]
                ),
                SWOTComponent(
                    category="Strengths",
                    item="Customer Base",
                    description="Loyal and growing customer base",
                    impact="Medium",
                    priority=4,
                    evidence=["Customer retention rates"],
                    recommendations=["Expand loyalty programs"]
                )
            ],
            'weaknesses': [
                SWOTComponent(
                    category="Weaknesses",
                    item="Cost Structure",
                    description="Higher operational costs than competitors",
                    impact="Medium",
                    priority=4,
                    evidence=["Financial statements"],
                    recommendations=["Optimize supply chain"]
                ),
                SWOTComponent(
                    category="Weaknesses",
                    item="Geographic Limitations",
                    description="Limited presence in emerging markets",
                    impact="Medium",
                    priority=3,
                    evidence=["Market coverage data"],
                    recommendations=["Develop international strategy"]
                )
            ],
            'opportunities': [
                SWOTComponent(
                    category="Opportunities",
                    item="Market Expansion",
                    description="Growing demand in new markets",
                    impact="High",
                    priority=5,
                    evidence=["Market research", "Trend analysis"],
                    recommendations=["Enter high-growth markets"]
                ),
                SWOTComponent(
                    category="Opportunities",
                    item="Digital Transformation",
                    description="Technology adoption creating new channels",
                    impact="High",
                    priority=5,
                    evidence=["Industry reports"],
                    recommendations=["Invest in digital platforms"]
                ),
                SWOTComponent(
                    category="Opportunities",
                    item="Strategic Partnerships",
                    description="Collaboration opportunities with key players",
                    impact="Medium",
                    priority=4,
                    evidence=["Industry networking"],
                    recommendations=["Pursue strategic alliances"]
                )
            ],
            'threats': [
                SWOTComponent(
                    category="Threats",
                    item="Competition",
                    description="Intense competition from established and new players",
                    impact="High",
                    priority=5,
                    evidence=["Competitive analysis"],
                    recommendations=["Differentiate offerings"]
                ),
                SWOTComponent(
                    category="Threats",
                    item="Regulatory Changes",
                    description="Evolving regulations affecting operations",
                    impact="Medium",
                    priority=4,
                    evidence=["Regulatory updates"],
                    recommendations=["Enhance compliance monitoring"]
                ),
                SWOTComponent(
                    category="Threats",
                    item="Economic Uncertainty",
                    description="Market volatility and economic downturns",
                    impact="Medium",
                    priority=3,
                    evidence=["Economic indicators"],
                    recommendations=["Diversify revenue streams"]
                )
            ]
        }
    
    def _parse_swot_response(self, content: str) -> Dict[str, List[SWOTComponent]]:
        """Parse SWOT components from LLM response."""
        result = {
            'strengths': [],
            'weaknesses': [],
            'opportunities': [],
            'threats': []
        }
        
        current_category = None
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            
            if line.upper().startswith('## STRENGTHS') or line.upper().startswith('STRENGTHS'):
                current_category = 'strengths'
            elif line.upper().startswith('## WEAKNESSES') or line.upper().startswith('WEAKNESSES'):
                current_category = 'weaknesses'
            elif line.upper().startswith('## OPPORTUNITIES') or line.upper().startswith('OPPORTUNITIES'):
                current_category = 'opportunities'
            elif line.upper().startswith('## THREATS') or line.upper().startswith('THREATS'):
                current_category = 'threats'
            elif line.startswith('-') and current_category:
                component = self._parse_component_line(line, current_category.capitalize())
                if component:
                    result[current_category].append(component)
        
        for category in result:
            if not result[category]:
                result[category] = self._analyze_heuristic("", {}).get(category, [])[:3]
        
        return result
    
    def _parse_component_line(self, line: str, category: str) -> Optional[SWOTComponent]:
        """Parse a single SWOT component line."""
        try:
            line = line.lstrip('- ').strip()
            
            if '**' in line:
                parts = line.split('**')
                item = parts[1] if len(parts) > 1 else "Item"
                rest = parts[2] if len(parts) > 2 else line
            else:
                parts = line.split(':', 1)
                item = parts[0].strip()
                rest = parts[1].strip() if len(parts) > 1 else line
            
            description = rest.split('|')[0].strip().rstrip(':').strip()
            
            impact = "Medium"
            if 'impact: high' in rest.lower():
                impact = "High"
            elif 'impact: low' in rest.lower():
                impact = "Low"
            
            priority = 3
            for i in range(1, 6):
                if f'priority: {i}' in rest.lower():
                    priority = i
                    break
            
            return SWOTComponent(
                category=category,
                item=item,
                description=description,
                impact=impact,
                priority=priority,
                evidence=[],
                recommendations=[]
            )
        except Exception as e:
            print(f"Parse error: {e}")
            return None
    
    def _generate_strategic_insights(self, analysis: Dict[str, List[SWOTComponent]]) -> List[str]:
        """Generate strategic insights from SWOT analysis."""
        insights = []
        
        high_priority_strengths = [s for s in analysis['strengths'] if s.priority >= 4]
        if high_priority_strengths:
            insights.append(
                f"Leverage {len(high_priority_strengths)} key strengths: " +
                ", ".join(s.item for s in high_priority_strengths[:3])
            )
        
        critical_weaknesses = [w for w in analysis['weaknesses'] if w.impact == "High"]
        if critical_weaknesses:
            insights.append(
                f"Address {len(critical_weaknesses)} critical weakness(es) immediately"
            )
        
        high_impact_opportunities = [o for o in analysis['opportunities'] if o.impact == "High"]
        if high_impact_opportunities:
            insights.append(
                f"Capitalize on {len(high_impact_opportunities)} high-impact opportunities for growth"
            )
        
        major_threats = [t for t in analysis['threats'] if t.priority >= 4]
        if major_threats:
            insights.append(
                f"Mitigate {len(major_threats)} major threats through strategic planning"
            )
        
        if len(analysis['strengths']) > len(analysis['weaknesses']):
            insights.append("Strong internal position - focus on offensive strategies")
        else:
            insights.append("Internal improvements needed - prioritize defensive strategies")
        
        return insights
    
    def _generate_recommendations(self, analysis: Dict[str, List[SWOTComponent]],
                                  insights: List[str]) -> List[Dict[str, Any]]:
        """Generate actionable strategic recommendations."""
        recommendations = []
        
        recommendations.append({
            'strategy': 'SO Strategy (Strengths-Opportunities)',
            'description': 'Use strengths to capitalize on opportunities',
            'actions': [
                f"Leverage {s.item} to pursue {o.item}"
                for s in analysis['strengths'][:2]
                for o in analysis['opportunities'][:2]
            ][:3]
        })
        
        recommendations.append({
            'strategy': 'WO Strategy (Weaknesses-Opportunities)',
            'description': 'Overcome weaknesses by taking advantage of opportunities',
            'actions': [
                f"Address {w.item} to enable {o.item}"
                for w in analysis['weaknesses'][:2]
                for o in analysis['opportunities'][:2]
            ][:3]
        })
        
        recommendations.append({
            'strategy': 'ST Strategy (Strengths-Threats)',
            'description': 'Use strengths to avoid or reduce threats',
            'actions': [
                f"Apply {s.item} to counter {t.item}"
                for s in analysis['strengths'][:2]
                for t in analysis['threats'][:2]
            ][:3]
        })
        
        recommendations.append({
            'strategy': 'WT Strategy (Weaknesses-Threats)',
            'description': 'Minimize weaknesses and avoid threats',
            'actions': [
                f"Reduce {w.item} to minimize exposure to {t.item}"
                for w in analysis['weaknesses'][:2]
                for t in analysis['threats'][:2]
            ][:3]
        })
        
        return recommendations
    
    def _assess_risks(self, analysis: Dict[str, List[SWOTComponent]]) -> Dict[str, Any]:
        """Assess overall risk profile."""
        threat_score = sum(5 - t.priority + 1 for t in analysis['threats']) / max(len(analysis['threats']), 1)
        weakness_score = sum(5 - w.priority + 1 for w in analysis['weaknesses']) / max(len(analysis['weaknesses']), 1)
        
        risk_score = (threat_score + weakness_score) / 2
        
        if risk_score > 4:
            risk_level = "High"
        elif risk_score > 2.5:
            risk_level = "Medium"
        else:
            risk_level = "Low"
        
        return {
            'risk_level': risk_level,
            'risk_score': round(risk_score, 2),
            'primary_risks': [t.item for t in sorted(analysis['threats'], key=lambda x: x.priority, reverse=True)[:3]],
            'mitigation_priority': "Immediate" if risk_level == "High" else "Medium-term"
        }
    
    def _create_opportunity_matrix(self, analysis: Dict[str, List[SWOTComponent]]) -> List[Dict[str, Any]]:
        """Create opportunity prioritization matrix."""
        opportunities = analysis['opportunities']
        
        matrix = []
        for opp in opportunities:
            impact_score = {'High': 3, 'Medium': 2, 'Low': 1}.get(opp.impact, 2)
            effort_score = 4 - opp.priority if opp.priority <= 3 else 1
            
            value = impact_score / effort_score
            
            if value > 2:
                quadrant = "Quick Wins"
            elif impact_score == 3:
                quadrant = "Strategic Investments"
            elif effort_score == 1:
                quadrant = "Fill-ins"
            else:
                quadrant = "Hard Slogs"
            
            matrix.append({
                'opportunity': opp.item,
                'impact': opp.impact,
                'effort': ['High', 'Medium', 'Low'][effort_score - 1] if effort_score <= 3 else 'Very Low',
                'value_score': round(value, 2),
                'quadrant': quadrant,
                'recommendation': "Pursue immediately" if quadrant == "Quick Wins" else "Plan carefully"
            })
        
        return sorted(matrix, key=lambda x: x['value_score'], reverse=True)
    
    def _generate_summary(self, analysis: Dict[str, List[SWOTComponent]],
                         insights: List[str]) -> str:
        """Generate executive summary."""
        summary = f"""SWOT Analysis Summary

Key Findings:
- {len(analysis['strengths'])} Strengths identified
- {len(analysis['weaknesses'])} Weaknesses identified
- {len(analysis['opportunities'])} Opportunities identified
- {len(analysis['threats'])} Threats identified

Strategic Insights:
"""
        for insight in insights:
            summary += f"• {insight}\n"
        
        return summary
    
    def export_report(self, analysis: Dict[str, Any], format: str = 'markdown') -> str:
        """
        Export SWOT analysis as formatted report.
        
        Args:
            analysis: SWOT analysis result
            format: Output format ('markdown', 'html', 'json')
            
        Returns:
            Formatted report string
        """
        if format == 'json':
            return json.dumps(analysis, indent=2, default=str)
        elif format == 'html':
            return self._generate_html_report(analysis)
        else:
            return self._generate_markdown_report(analysis)
    
    def _generate_markdown_report(self, analysis: Dict[str, Any]) -> str:
        """Generate Markdown report."""
        report = f"""# SWOT Analysis Report

**Subject**: {analysis['subject']}  
**Date**: {analysis['timestamp']}

{analysis['summary']}

## Strengths

"""
        for s in analysis['strengths']:
            report += f"### {s.item}\n"
            report += f"**Description**: {s.description}  \n"
            report += f"**Impact**: {s.impact} | **Priority**: {s.priority}\n\n"
        
        report += "## Weaknesses\n\n"
        for w in analysis['weaknesses']:
            report += f"### {w.item}\n"
            report += f"**Description**: {w.description}  \n"
            report += f"**Impact**: {w.impact} | **Priority**: {w.priority}\n\n"
        
        report += "## Opportunities\n\n"
        for o in analysis['opportunities']:
            report += f"### {o.item}\n"
            report += f"**Description**: {o.description}  \n"
            report += f"**Impact**: {o.impact} | **Priority**: {o.priority}\n\n"
        
        report += "## Threats\n\n"
        for t in analysis['threats']:
            report += f"### {t.item}\n"
            report += f"**Description**: {t.description}  \n"
            report += f"**Impact**: {t.impact} | **Priority**: {t.priority}\n\n"
        
        report += "## Strategic Recommendations\n\n"
        for rec in analysis['recommendations']:
            report += f"### {rec['strategy']}\n"
            report += f"{rec['description']}\n\n"
            report += "**Actions**:\n"
            for action in rec['actions']:
                report += f"- {action}\n"
            report += "\n"
        
        report += f"## Risk Assessment\n\n"
        risk = analysis['risk_assessment']
        report += f"**Risk Level**: {risk['risk_level']}  \n"
        report += f"**Risk Score**: {risk['risk_score']}/5  \n"
        report += f"**Mitigation Priority**: {risk['mitigation_priority']}\n\n"
        
        return report
    
    def _generate_html_report(self, analysis: Dict[str, Any]) -> str:
        """Generate HTML report."""
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>SWOT Analysis - {analysis['subject']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        .swot-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
        .swot-box {{ border: 2px solid #ddd; padding: 15px; border-radius: 5px; }}
        .strengths {{ border-color: #4CAF50; }}
        .weaknesses {{ border-color: #f44336; }}
        .opportunities {{ border-color: #2196F3; }}
        .threats {{ border-color: #FF9800; }}
        .item {{ margin-bottom: 15px; }}
        .priority-high {{ font-weight: bold; }}
    </style>
</head>
<body>
    <h1>SWOT Analysis Report</h1>
    <p><strong>Subject:</strong> {analysis['subject']}</p>
    <p><strong>Date:</strong> {analysis['timestamp']}</p>
    
    <div class="swot-grid">
        <div class="swot-box strengths">
            <h2>Strengths</h2>
            {''.join(f'<div class="item"><strong>{s.item}</strong><br>{s.description}</div>' for s in analysis['strengths'])}
        </div>
        <div class="swot-box weaknesses">
            <h2>Weaknesses</h2>
            {''.join(f'<div class="item"><strong>{w.item}</strong><br>{w.description}</div>' for w in analysis['weaknesses'])}
        </div>
        <div class="swot-box opportunities">
            <h2>Opportunities</h2>
            {''.join(f'<div class="item"><strong>{o.item}</strong><br>{o.description}</div>' for o in analysis['opportunities'])}
        </div>
        <div class="swot-box threats">
            <h2>Threats</h2>
            {''.join(f'<div class="item"><strong>{t.item}</strong><br>{t.description}</div>' for t in analysis['threats'])}
        </div>
    </div>
</body>
</html>"""

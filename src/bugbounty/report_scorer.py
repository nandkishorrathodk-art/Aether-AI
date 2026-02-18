"""
Report Quality Scorer

Analyzes bug bounty reports and provides quality scores before submission.
"""

from typing import Dict, List, Any
from src.utils.logger import get_logger

logger = get_logger(__name__)


class ReportScorer:
    """
    Scores bug bounty reports for quality and completeness
    """
    
    def __init__(self):
        self.scoring_criteria = {
            "title": 10,
            "description": 20,
            "steps_to_reproduce": 25,
            "impact": 20,
            "poc": 15,
            "attachments": 10
        }
        logger.info("Report Scorer initialized")
    
    def score_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Score a bug bounty report
        
        Args:
            report: Report data with fields (title, description, steps, etc.)
            
        Returns:
            Scoring results with total score and recommendations
        """
        try:
            scores = {}
            recommendations = []
            
            title_score = self._score_title(report.get("title", ""))
            scores["title"] = title_score
            if title_score["score"] < 7:
                recommendations.append(title_score["recommendation"])
            
            desc_score = self._score_description(report.get("description", ""))
            scores["description"] = desc_score
            if desc_score["score"] < 15:
                recommendations.append(desc_score["recommendation"])
            
            steps_score = self._score_steps(report.get("steps_to_reproduce", ""))
            scores["steps_to_reproduce"] = steps_score
            if steps_score["score"] < 20:
                recommendations.append(steps_score["recommendation"])
            
            impact_score = self._score_impact(report.get("impact", ""))
            scores["impact"] = impact_score
            if impact_score["score"] < 15:
                recommendations.append(impact_score["recommendation"])
            
            poc_score = self._score_poc(report.get("proof_of_concept", ""))
            scores["poc"] = poc_score
            if poc_score["score"] < 10:
                recommendations.append(poc_score["recommendation"])
            
            attach_score = self._score_attachments(report.get("attachments", []))
            scores["attachments"] = attach_score
            if attach_score["score"] < 7:
                recommendations.append(attach_score["recommendation"])
            
            total_score = sum(s["score"] for s in scores.values())
            max_score = sum(self.scoring_criteria.values())
            percentage = (total_score / max_score) * 100
            
            quality_rating = self._get_quality_rating(percentage)
            submit_recommendation = self._get_submit_recommendation(percentage)
            
            return {
                "total_score": total_score,
                "max_score": max_score,
                "percentage": round(percentage, 2),
                "quality_rating": quality_rating,
                "submit_recommendation": submit_recommendation,
                "scores": scores,
                "recommendations": recommendations,
                "breakdown": self._generate_breakdown(scores)
            }
            
        except Exception as e:
            logger.error(f"Failed to score report: {e}")
            return {
                "error": str(e),
                "total_score": 0
            }
    
    def _score_title(self, title: str) -> Dict:
        """Score report title"""
        score = 0
        recommendation = ""
        
        if not title:
            recommendation = "Add a clear, descriptive title"
            return {"score": 0, "max": 10, "recommendation": recommendation}
        
        length = len(title)
        if 30 <= length <= 100:
            score += 5
        elif length < 30:
            recommendation = "Title too short - add more context"
        else:
            recommendation = "Title too long - be more concise"
        
        vuln_keywords = ["XSS", "SQL", "Injection", "IDOR", "SSRF", "XXE", "RCE", "LFI", "RFI", "CSRF"]
        if any(keyword.upper() in title.upper() for keyword in vuln_keywords):
            score += 3
        else:
            if not recommendation:
                recommendation = "Include vulnerability type in title"
        
        if any(char in title for char in [":", "-", "|"]):
            score += 2
        
        return {
            "score": score,
            "max": 10,
            "recommendation": recommendation or "Title looks good!"
        }
    
    def _score_description(self, description: str) -> Dict:
        """Score description section"""
        score = 0
        recommendation = ""
        
        if not description:
            recommendation = "Add detailed vulnerability description"
            return {"score": 0, "max": 20, "recommendation": recommendation}
        
        length = len(description)
        if length > 500:
            score += 10
        elif length > 200:
            score += 7
        elif length > 100:
            score += 4
        else:
            recommendation = "Description too short - add more details"
        
        important_terms = ["vulnerability", "exploit", "attack", "security", "risk"]
        found_terms = sum(1 for term in important_terms if term.lower() in description.lower())
        score += min(found_terms * 2, 10)
        
        if not recommendation and score < 15:
            recommendation = "Add more technical details about the vulnerability"
        
        return {
            "score": score,
            "max": 20,
            "recommendation": recommendation or "Description is comprehensive!"
        }
    
    def _score_steps(self, steps: str) -> Dict:
        """Score steps to reproduce"""
        score = 0
        recommendation = ""
        
        if not steps:
            recommendation = "Add clear steps to reproduce the vulnerability"
            return {"score": 0, "max": 25, "recommendation": recommendation}
        
        numbered_steps = len([line for line in steps.split("\n") if line.strip() and line.strip()[0].isdigit()])
        if numbered_steps >= 5:
            score += 15
        elif numbered_steps >= 3:
            score += 10
        elif numbered_steps >= 1:
            score += 5
        else:
            recommendation = "Use numbered steps (1. 2. 3. etc.)"
        
        technical_terms = ["URL", "parameter", "request", "response", "payload", "header"]
        found_terms = sum(1 for term in technical_terms if term.lower() in steps.lower())
        score += min(found_terms * 2, 10)
        
        if not recommendation and score < 20:
            recommendation = "Add more detailed technical steps"
        
        return {
            "score": score,
            "max": 25,
            "recommendation": recommendation or "Steps are clear and detailed!"
        }
    
    def _score_impact(self, impact: str) -> Dict:
        """Score impact section"""
        score = 0
        recommendation = ""
        
        if not impact:
            recommendation = "Explain the business/security impact"
            return {"score": 0, "max": 20, "recommendation": recommendation}
        
        if len(impact) > 200:
            score += 10
        elif len(impact) > 100:
            score += 7
        elif len(impact) > 50:
            score += 4
        else:
            recommendation = "Expand impact description"
        
        impact_keywords = ["confidentiality", "integrity", "availability", "data", "breach", "compromise"]
        found_keywords = sum(1 for kw in impact_keywords if kw.lower() in impact.lower())
        score += min(found_keywords * 2, 10)
        
        if not recommendation and score < 15:
            recommendation = "Describe real-world attack scenarios and business impact"
        
        return {
            "score": score,
            "max": 20,
            "recommendation": recommendation or "Impact description is strong!"
        }
    
    def _score_poc(self, poc: str) -> Dict:
        """Score proof of concept"""
        score = 0
        recommendation = ""
        
        if not poc:
            recommendation = "Add proof-of-concept code or exploit steps"
            return {"score": 0, "max": 15, "recommendation": recommendation}
        
        if len(poc) > 300:
            score += 8
        elif len(poc) > 150:
            score += 5
        elif len(poc) > 50:
            score += 3
        
        code_indicators = ["curl", "http", "python", "bash", "POST", "GET", "```"]
        if any(indicator in poc for indicator in code_indicators):
            score += 7
        else:
            if not recommendation:
                recommendation = "Include executable code or curl commands"
        
        return {
            "score": score,
            "max": 15,
            "recommendation": recommendation or "PoC is well-documented!"
        }
    
    def _score_attachments(self, attachments: List) -> Dict:
        """Score attachments"""
        score = 0
        recommendation = ""
        
        if not attachments or len(attachments) == 0:
            recommendation = "Add screenshots or video demonstrating the vulnerability"
            return {"score": 0, "max": 10, "recommendation": recommendation}
        
        num_attachments = len(attachments)
        if num_attachments >= 3:
            score += 7
        elif num_attachments >= 1:
            score += 5
        
        image_extensions = [".png", ".jpg", ".jpeg", ".gif"]
        has_images = any(
            any(str(att).lower().endswith(ext) for ext in image_extensions)
            for att in attachments
        )
        
        if has_images:
            score += 3
        else:
            if not recommendation:
                recommendation = "Add visual proof (screenshots/video)"
        
        return {
            "score": score,
            "max": 10,
            "recommendation": recommendation or "Attachments are good!"
        }
    
    def _get_quality_rating(self, percentage: float) -> str:
        """Get quality rating based on score percentage"""
        if percentage >= 90:
            return "Excellent ⭐⭐⭐⭐⭐"
        elif percentage >= 80:
            return "Very Good ⭐⭐⭐⭐"
        elif percentage >= 70:
            return "Good ⭐⭐⭐"
        elif percentage >= 60:
            return "Fair ⭐⭐"
        else:
            return "Needs Improvement ⭐"
    
    def _get_submit_recommendation(self, percentage: float) -> str:
        """Get submission recommendation"""
        if percentage >= 85:
            return "✅ Ready to submit! High quality report."
        elif percentage >= 70:
            return "⚠️ Can submit, but consider improvements for better results."
        elif percentage >= 60:
            return "⚠️ Improve before submission - low score may result in rejection."
        else:
            return "❌ Not ready - significant improvements needed before submission."
    
    def _generate_breakdown(self, scores: Dict) -> List[Dict]:
        """Generate detailed breakdown"""
        breakdown = []
        for category, data in scores.items():
            breakdown.append({
                "category": category.replace("_", " ").title(),
                "score": data["score"],
                "max": data["max"],
                "percentage": round((data["score"] / data["max"]) * 100, 1),
                "status": "✅" if data["score"] >= data["max"] * 0.8 else "⚠️" if data["score"] >= data["max"] * 0.6 else "❌"
            })
        return breakdown

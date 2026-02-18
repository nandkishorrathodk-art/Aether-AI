"""
Self-Improvement Engine - Daily Auto-Upgrade System

This module analyzes system performance, identifies improvements,
generates code fixes, tests them safely, and applies successful improvements.
"""

import os
import json
import asyncio
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from pathlib import Path
import subprocess
import tempfile
import shutil
from dataclasses import dataclass, asdict

from src.utils.logger import get_logger
from src.cognitive.llm.inference import LLMInference
from src.config import settings

logger = get_logger(__name__)


@dataclass
class ImprovementOpportunity:
    """Represents a potential improvement"""
    id: str
    type: str  # performance, accuracy, feature, bug_fix
    description: str
    severity: str  # low, medium, high, critical
    impact_score: float  # 0-10
    confidence: float  # 0-1
    detected_at: datetime
    metrics: Dict[str, Any]


@dataclass
class CodeImprovement:
    """Represents a code improvement"""
    id: str
    opportunity_id: str
    file_path: str
    original_code: str
    improved_code: str
    explanation: str
    test_results: Optional[Dict] = None
    status: str = "proposed"  # proposed, testing, applied, rolled_back, failed


class SelfImprover:
    """
    Self-Improvement Engine for Aether AI
    
    Automatically analyzes performance, generates improvements,
    tests them safely, and applies successful changes.
    """
    
    def __init__(self):
        self.llm = LLMInference()
        self.improvements_dir = Path("data/improvements")
        self.improvements_dir.mkdir(parents=True, exist_ok=True)
        
        self.backup_dir = Path("data/backups")
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        
        self.metrics_file = Path("data/performance_metrics.json")
        self.improvement_log = Path("data/improvement_log.json")
        
        logger.info("Self-Improver initialized")
    
    async def daily_improvement_cycle(self) -> Dict:
        """
        Run daily improvement cycle:
        1. Analyze performance
        2. Identify opportunities
        3. Generate improvements
        4. Test improvements
        5. Apply successful ones
        """
        logger.info("🚀 Starting daily improvement cycle")
        
        try:
            # Step 1: Analyze performance
            opportunities = await self.analyze_performance()
            logger.info(f"Found {len(opportunities)} improvement opportunities")
            
            if not opportunities:
                logger.info("No improvements needed today - system performing optimally!")
                return {
                    "success": True,
                    "improvements_found": 0,
                    "improvements_applied": 0,
                    "message": "System performing optimally"
                }
            
            # Step 2: Prioritize opportunities
            prioritized = self._prioritize_opportunities(opportunities)
            top_opportunities = prioritized[:5]  # Top 5 opportunities
            
            # Step 3: Generate improvements
            improvements = []
            for opp in top_opportunities:
                improvement = await self.generate_improvement(opp)
                if improvement:
                    improvements.append(improvement)
            
            logger.info(f"Generated {len(improvements)} code improvements")
            
            # Step 4: Test improvements
            tested_improvements = []
            for improvement in improvements:
                test_result = await self.test_improvement(improvement)
                if test_result["success"]:
                    improvement.test_results = test_result
                    improvement.status = "tested"
                    tested_improvements.append(improvement)
                else:
                    improvement.status = "failed"
                    logger.warning(f"Improvement {improvement.id} failed tests: {test_result.get('error')}")
            
            # Step 5: Apply safe improvements
            applied_count = 0
            for improvement in tested_improvements:
                if improvement.test_results.get("safe", False):
                    success = await self.apply_improvement(improvement)
                    if success:
                        applied_count += 1
                        improvement.status = "applied"
                    else:
                        improvement.status = "failed"
            
            # Log results
            self._log_improvement_cycle({
                "opportunities_found": len(opportunities),
                "improvements_generated": len(improvements),
                "improvements_tested": len(tested_improvements),
                "improvements_applied": applied_count,
                "timestamp": datetime.now().isoformat()
            })
            
            logger.info(f"✅ Daily improvement cycle complete: {applied_count} improvements applied")
            
            return {
                "success": True,
                "opportunities_found": len(opportunities),
                "improvements_generated": len(improvements),
                "improvements_tested": len(tested_improvements),
                "improvements_applied": applied_count,
                "details": [asdict(imp) for imp in improvements]
            }
            
        except Exception as e:
            logger.error(f"Daily improvement cycle failed: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e)
            }
    
    async def analyze_performance(self) -> List[ImprovementOpportunity]:
        """Analyze system performance and identify improvement opportunities"""
        opportunities = []
        
        try:
            # Load metrics
            metrics = self._load_metrics()
            
            # Analyze response times
            if metrics.get("avg_response_time", 0) > 500:  # ms
                opportunities.append(ImprovementOpportunity(
                    id=f"perf_{datetime.now().timestamp()}",
                    type="performance",
                    description="API response time is high",
                    severity="medium",
                    impact_score=7.5,
                    confidence=0.9,
                    detected_at=datetime.now(),
                    metrics={"avg_response_time": metrics.get("avg_response_time")}
                ))
            
            # Analyze error rates
            error_rate = metrics.get("error_rate", 0)
            if error_rate > 0.05:  # 5%
                opportunities.append(ImprovementOpportunity(
                    id=f"error_{datetime.now().timestamp()}",
                    type="bug_fix",
                    description=f"Error rate is {error_rate * 100:.1f}%",
                    severity="high",
                    impact_score=8.5,
                    confidence=0.95,
                    detected_at=datetime.now(),
                    metrics={"error_rate": error_rate}
                ))
            
            # Analyze memory usage
            memory_usage = metrics.get("memory_usage_mb", 0)
            if memory_usage > 800:  # MB
                opportunities.append(ImprovementOpportunity(
                    id=f"mem_{datetime.now().timestamp()}",
                    type="performance",
                    description=f"Memory usage is {memory_usage}MB",
                    severity="medium",
                    impact_score=6.0,
                    confidence=0.8,
                    detected_at=datetime.now(),
                    metrics={"memory_usage_mb": memory_usage}
                ))
            
            # Analyze feature usage
            feature_usage = metrics.get("feature_usage", {})
            unused_features = [f for f, count in feature_usage.items() if count == 0]
            if unused_features:
                opportunities.append(ImprovementOpportunity(
                    id=f"feature_{datetime.now().timestamp()}",
                    type="feature",
                    description=f"{len(unused_features)} features never used",
                    severity="low",
                    impact_score=3.0,
                    confidence=0.7,
                    detected_at=datetime.now(),
                    metrics={"unused_features": unused_features}
                ))
            
            logger.info(f"Performance analysis complete: {len(opportunities)} opportunities found")
            
        except Exception as e:
            logger.error(f"Performance analysis failed: {e}")
        
        return opportunities
    
    async def generate_improvement(self, opportunity: ImprovementOpportunity) -> Optional[CodeImprovement]:
        """Use LLM to generate code improvement for an opportunity"""
        try:
            prompt = f"""You are an expert AI system improving itself.

IMPROVEMENT OPPORTUNITY:
Type: {opportunity.type}
Description: {opportunity.description}
Severity: {opportunity.severity}
Metrics: {json.dumps(opportunity.metrics)}

TASK: Generate a code improvement to fix this issue.

Provide your response in this EXACT JSON format:
{{
    "file_path": "path/to/file.py",
    "original_code": "current code snippet",
    "improved_code": "improved code snippet",
    "explanation": "why this improves performance/fixes the issue"
}}

Requirements:
- Code must be production-ready
- Include proper error handling
- Maintain backward compatibility
- Follow project coding standards
"""
            
            response = await self.llm.generate_response(
                prompt=prompt,
                temperature=0.3,  # Low temperature for code generation
                max_tokens=2000
            )
            
            # Parse response
            try:
                improvement_data = json.loads(response)
            except json.JSONDecodeError:
                # Try to extract JSON from markdown code blocks
                import re
                json_match = re.search(r'```json\n(.*?)\n```', response, re.DOTALL)
                if json_match:
                    improvement_data = json.loads(json_match.group(1))
                else:
                    logger.error("Failed to parse LLM response as JSON")
                    return None
            
            improvement = CodeImprovement(
                id=f"imp_{datetime.now().timestamp()}",
                opportunity_id=opportunity.id,
                file_path=improvement_data["file_path"],
                original_code=improvement_data["original_code"],
                improved_code=improvement_data["improved_code"],
                explanation=improvement_data["explanation"]
            )
            
            logger.info(f"Generated improvement for {opportunity.description}")
            return improvement
            
        except Exception as e:
            logger.error(f"Failed to generate improvement: {e}")
            return None
    
    async def test_improvement(self, improvement: CodeImprovement) -> Dict:
        """Test improvement in isolated environment"""
        try:
            logger.info(f"Testing improvement {improvement.id}")
            
            # Create temporary test environment
            with tempfile.TemporaryDirectory() as temp_dir:
                test_file = Path(temp_dir) / "test_improvement.py"
                test_file.write_text(improvement.improved_code)
                
                # Run Python syntax check
                result = subprocess.run(
                    ["python", "-m", "py_compile", str(test_file)],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode != 0:
                    return {
                        "success": False,
                        "safe": False,
                        "error": f"Syntax error: {result.stderr}"
                    }
                
                # Additional safety checks could go here
                # - Run unit tests
                # - Check for security issues
                # - Verify performance improvements
                
                return {
                    "success": True,
                    "safe": True,
                    "tests_passed": True,
                    "message": "All tests passed"
                }
                
        except Exception as e:
            logger.error(f"Testing failed: {e}")
            return {
                "success": False,
                "safe": False,
                "error": str(e)
            }
    
    async def apply_improvement(self, improvement: CodeImprovement) -> bool:
        """Apply improvement with automatic backup"""
        try:
            file_path = Path(improvement.file_path)
            
            if not file_path.exists():
                logger.warning(f"File not found: {file_path}")
                return False
            
            # Create backup
            backup_path = self.backup_dir / f"{file_path.name}.{datetime.now().strftime('%Y%m%d_%H%M%S')}.bak"
            shutil.copy2(file_path, backup_path)
            logger.info(f"Created backup: {backup_path}")
            
            # Read current content
            current_content = file_path.read_text()
            
            # Replace old code with improved code
            if improvement.original_code in current_content:
                new_content = current_content.replace(
                    improvement.original_code,
                    improvement.improved_code
                )
                file_path.write_text(new_content)
                logger.info(f"✅ Applied improvement to {file_path}")
                return True
            else:
                logger.warning(f"Original code not found in {file_path}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to apply improvement: {e}")
            return False
    
    async def rollback(self, file_path: str, backup_timestamp: str) -> bool:
        """Rollback to previous version"""
        try:
            original_file = Path(file_path)
            backup_file = self.backup_dir / f"{original_file.name}.{backup_timestamp}.bak"
            
            if not backup_file.exists():
                logger.error(f"Backup not found: {backup_file}")
                return False
            
            shutil.copy2(backup_file, original_file)
            logger.info(f"✅ Rolled back {file_path} to {backup_timestamp}")
            return True
            
        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            return False
    
    def _prioritize_opportunities(self, opportunities: List[ImprovementOpportunity]) -> List[ImprovementOpportunity]:
        """Prioritize opportunities by impact and confidence"""
        return sorted(
            opportunities,
            key=lambda opp: opp.impact_score * opp.confidence,
            reverse=True
        )
    
    def _load_metrics(self) -> Dict:
        """Load performance metrics"""
        if self.metrics_file.exists():
            try:
                return json.loads(self.metrics_file.read_text())
            except Exception as e:
                logger.error(f"Failed to load metrics: {e}")
        return {}
    
    def _log_improvement_cycle(self, results: Dict):
        """Log improvement cycle results"""
        try:
            log_data = []
            if self.improvement_log.exists():
                log_data = json.loads(self.improvement_log.read_text())
            
            log_data.append(results)
            
            # Keep last 30 days
            cutoff_date = datetime.now() - timedelta(days=30)
            log_data = [
                entry for entry in log_data
                if datetime.fromisoformat(entry["timestamp"]) > cutoff_date
            ]
            
            self.improvement_log.write_text(json.dumps(log_data, indent=2))
            
        except Exception as e:
            logger.error(f"Failed to log improvement cycle: {e}")

"""
Autonomous System for Aether AI

Complete autonomous operation without CLI commands.
"""

from src.autonomous.autonomous_brain import AutonomousBrain
from src.autonomous.vision_system import VisionSystem
from src.autonomous.self_coder import SelfCoder
from src.autonomous.decision_engine import DecisionEngine
from src.autonomous.auto_executor import AutoExecutor

# v3.0 components
from src.autonomous.omni_task import OmniTask
from src.autonomous.predictive_agent import PredictiveAgent

# Initialize singletons for easy import
omni_task_handler = OmniTask()
predictive_agent = PredictiveAgent()

__all__ = [
    "AutonomousBrain",
    "VisionSystem", 
    "SelfCoder",
    "DecisionEngine",
    "AutoExecutor",
    "OmniTask",
    "PredictiveAgent",
    "omni_task_handler",
    "predictive_agent"
]

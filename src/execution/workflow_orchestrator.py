"""
Workflow Orchestrator
End-to-end workflow coordination with intelligent retry, error recovery, and verification
"""
import asyncio
import time
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass
from enum import Enum

from src.execution.workflow_state_manager import (
    WorkflowStateManager, workflow_state_manager,
    Workflow, WorkflowStep, WorkflowState, StepState
)
from src.verification.verification_engine import (
    VerificationEngine, verification_engine,
    VerificationRule, VerificationResult, CommonVerifications
)
from src.automation.element_detector import element_detector
from src.automation.window_manager import window_manager
from src.autonomous.vision_system import VisionSystem
from src.features.automation import DesktopAutomation
from src.utils.logger import get_logger

logger = get_logger(__name__)


class RetryStrategy(Enum):
    """Retry strategies for failed steps"""
    IMMEDIATE = "immediate"  # Retry immediately
    EXPONENTIAL_BACKOFF = "exponential_backoff"  # Wait increasingly longer
    ALTERNATIVE_METHOD = "alternative_method"  # Try different approach
    MANUAL_INTERVENTION = "manual_intervention"  # Ask user
    SKIP = "skip"  # Skip this step


@dataclass
class RetryConfig:
    """Retry configuration for a step"""
    max_retries: int = 3
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL_BACKOFF
    base_delay: float = 2.0  # seconds
    alternative_actions: List[Callable] = None
    
    def __post_init__(self):
        if self.alternative_actions is None:
            self.alternative_actions = []
    
    def get_delay(self, retry_count: int) -> float:
        """Calculate delay before retry"""
        if self.strategy == RetryStrategy.IMMEDIATE:
            return 0.0
        elif self.strategy == RetryStrategy.EXPONENTIAL_BACKOFF:
            return self.base_delay * (2 ** retry_count)
        else:
            return self.base_delay


class WorkflowOrchestrator:
    """
    Orchestrates complete workflows with:
    - State management and persistence
    - Vision-based verification
    - Intelligent retry and error recovery  
    - Progress reporting
    - Workflow resumption
    """
    
    def __init__(
        self,
        state_manager: Optional[WorkflowStateManager] = None,
        verification_engine: Optional[VerificationEngine] = None
    ):
        self.state_manager = state_manager or workflow_state_manager
        self.verifier = verification_engine or verification_engine
        self.vision = VisionSystem()
        
        self.active_workflows: Dict[str, asyncio.Task] = {}
        self.progress_callbacks: Dict[str, Callable] = {}
        
        logger.info("WorkflowOrchestrator initialized")
    
    async def execute_workflow(
        self,
        workflow: Workflow,
        steps: List[WorkflowStep],
        verification_rules: Optional[Dict[str, List[VerificationRule]]] = None,
        retry_configs: Optional[Dict[str, RetryConfig]] = None,
        progress_callback: Optional[Callable] = None
    ) -> bool:
        """
        Execute complete workflow with verification and retry
        
        Args:
            workflow: Workflow definition
            steps: List of workflow steps
            verification_rules: Map of step_id → verification rules
            retry_configs: Map of step_id → retry configuration
            progress_callback: Function to call with progress updates
            
        Returns:
            True if workflow completed successfully
        """
        workflow_id = workflow.workflow_id
        
        logger.info(f"[ORCHESTRATOR] Starting workflow '{workflow.name}' ({workflow_id})")
        logger.info(f"[ORCHESTRATOR] Total steps: {len(steps)}")
        
        # Create workflow in state manager
        self.state_manager.create_workflow(workflow)
        
        # Add all steps
        for step in steps:
            self.state_manager.add_step(step)
        
        # Update workflow state to EXECUTING
        self.state_manager.update_workflow_state(
            workflow_id,
            WorkflowState.EXECUTING,
            reason="Workflow execution started"
        )
        
        # Store progress callback
        if progress_callback:
            self.progress_callbacks[workflow_id] = progress_callback
        
        # Execute steps sequentially
        success = True
        
        for step in steps:
            step_id = step.step_id
            
            logger.info(f"[ORCHESTRATOR] Executing step {step.step_number}/{len(steps)}: {step.description}")
            
            # Report progress
            await self._report_progress(workflow_id, step.step_number, len(steps), step.description)
            
            # Execute step with retry logic
            step_success = await self._execute_step_with_retry(
                step,
                verification_rules.get(step_id, []) if verification_rules else [],
                retry_configs.get(step_id, RetryConfig()) if retry_configs else RetryConfig()
            )
            
            if not step_success:
                logger.error(f"[ORCHESTRATOR] Step {step.step_number} failed after retries")
                success = False
                
                # Update workflow state to FAILED
                self.state_manager.update_workflow_state(
                    workflow_id,
                    WorkflowState.FAILED,
                    reason=f"Step {step.step_number} failed",
                    error=step.error
                )
                break
            
            logger.info(f"[ORCHESTRATOR] ✓ Step {step.step_number} completed successfully")
        
        # Update final workflow state
        if success:
            self.state_manager.update_workflow_state(
                workflow_id,
                WorkflowState.COMPLETED,
                reason="All steps completed successfully"
            )
            logger.info(f"[ORCHESTRATOR] ✓ Workflow '{workflow.name}' completed successfully")
        
        # Final progress report
        await self._report_progress(workflow_id, len(steps), len(steps), "Workflow complete" if success else "Workflow failed")
        
        return success
    
    async def _execute_step_with_retry(
        self,
        step: WorkflowStep,
        verification_rules: List[VerificationRule],
        retry_config: RetryConfig
    ) -> bool:
        """Execute a single step with retry logic"""
        
        step_id = step.step_id
        
        for attempt in range(retry_config.max_retries + 1):
            if attempt > 0:
                logger.info(f"[RETRY] Attempt {attempt + 1}/{retry_config.max_retries + 1} for step '{step.description}'")
                
                # Calculate delay
                delay = retry_config.get_delay(attempt - 1)
                if delay > 0:
                    logger.info(f"[RETRY] Waiting {delay}s before retry...")
                    await asyncio.sleep(delay)
                
                # Update retry count
                step.retry_count = attempt
                self.state_manager.update_step_state(
                    step_id,
                    StepState.EXECUTING,
                    result={"retry_attempt": attempt}
                )
            
            # Update step state to EXECUTING
            if attempt == 0:
                self.state_manager.update_step_state(step_id, StepState.EXECUTING)
            
            # Log execution event
            self.state_manager.log_event(
                step.workflow_id,
                "step_execution_start",
                {
                    "step_id": step_id,
                    "step_number": step.step_number,
                    "attempt": attempt + 1,
                    "description": step.description
                },
                step_id
            )
            
            # Execute the step action
            try:
                action_success, result = await self._execute_step_action(step, attempt, retry_config)
                
                if not action_success:
                    logger.warning(f"[EXECUTE] Step action failed: {result.get('error') if isinstance(result, dict) else result}")
                    continue  # Retry
                
                # Update step result
                step.result = result
                
            except Exception as e:
                logger.error(f"[EXECUTE] Step action raised exception: {e}")
                step.error = str(e)
                continue  # Retry
            
            # Verify step completion if verification rules provided
            if verification_rules:
                logger.info(f"[VERIFY] Running verification for step '{step.description}'")
                
                # Update state to VERIFYING
                self.state_manager.update_step_state(step_id, StepState.VERIFYING)
                
                # Run verification
                outcomes = self.verifier.verify_step(step_id, verification_rules)
                
                # Check if verification passed
                if self.verifier.all_passed(outcomes):
                    logger.info(f"[VERIFY] ✓ Verification passed for step '{step.description}'")
                    step.verification_status = "passed"
                else:
                    logger.warning(f"[VERIFY] ✗ Verification failed for step '{step.description}'")
                    failures = self.verifier.get_failure_details(outcomes)
                    logger.warning(f"[VERIFY] Failures: {failures}")
                    step.verification_status = "failed"
                    step.error = f"Verification failed: {'; '.join(failures)}"
                    continue  # Retry
            else:
                # No verification rules - assume success
                step.verification_status = "skipped"
            
            # Step completed successfully
            self.state_manager.update_step_state(
                step_id,
                StepState.COMPLETED,
                result=step.result,
                verification_status=step.verification_status
            )
            
            logger.info(f"[EXECUTE] ✓ Step '{step.description}' completed")
            return True
        
        # All retries exhausted
        logger.error(f"[EXECUTE] ✗ Step '{step.description}' failed after {retry_config.max_retries + 1} attempts")
        
        self.state_manager.update_step_state(
            step_id,
            StepState.FAILED,
            error=step.error or "Max retries exceeded",
            verification_status=step.verification_status
        )
        
        return False
    
    async def _execute_step_action(
        self,
        step: WorkflowStep,
        attempt: int,
        retry_config: RetryConfig
    ) -> tuple[bool, Any]:
        """
        Execute the actual step action
        
        Returns:
            (success: bool, result: Any)
        """
        action_type = step.action_type
        params = step.parameters
        
        try:
            # Route to appropriate execution engine based on action_type
            if action_type == "open_app":
                app_name = params.get("app", params.get("name", ""))
                DesktopAutomation.open_app(app_name)
                return True, {"app": app_name, "status": "opened"}
            
            elif action_type == "click_element":
                element_id = params.get("element_id")
                success = element_detector.click_element(element_id)
                return success, {"element_id": element_id, "clicked": success}
            
            elif action_type == "type_text":
                text = params.get("text", "")
                DesktopAutomation.type_text(text)
                return True, {"text": text, "status": "typed"}
            
            elif action_type == "wait":
                duration = params.get("duration", 1.0)
                await asyncio.sleep(duration)
                return True, {"duration": duration, "status": "waited"}
            
            elif action_type == "vision_verify":
                expected_state = params.get("expected_state", "")
                analysis = await self.vision.analyze_screen("current")
                # Simplified check - can be enhanced
                success = expected_state.lower() in str(analysis).lower()
                return success, {"vision_result": analysis, "matched": success}
            
            elif action_type == "custom":
                # Execute custom function
                func = params.get("function")
                if callable(func):
                    result = await func() if asyncio.iscoroutinefunction(func) else func()
                    return True, result
                else:
                    return False, {"error": "No valid function provided"}
            
            else:
                logger.warning(f"[EXECUTE] Unknown action type: {action_type}")
                return False, {"error": f"Unknown action type: {action_type}"}
        
        except Exception as e:
            logger.error(f"[EXECUTE] Action execution error: {e}")
            return False, {"error": str(e)}
    
    async def _report_progress(
        self,
        workflow_id: str,
        current_step: int,
        total_steps: int,
        description: str
    ):
        """Report workflow progress"""
        progress_data = {
            "workflow_id": workflow_id,
            "current_step": current_step,
            "total_steps": total_steps,
            "progress_percentage": int((current_step / total_steps) * 100) if total_steps > 0 else 0,
            "description": description
        }
        
        if workflow_id in self.progress_callbacks:
            callback = self.progress_callbacks[workflow_id]
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(progress_data)
                else:
                    callback(progress_data)
            except Exception as e:
                logger.error(f"[PROGRESS] Callback error: {e}")
    
    async def resume_workflow(self, workflow_id: str) -> bool:
        """Resume a paused or failed workflow"""
        
        logger.info(f"[ORCHESTRATOR] Resuming workflow {workflow_id}")
        
        # Get workflow from database
        workflow = self.state_manager.get_workflow(workflow_id)
        if not workflow:
            logger.error(f"[ORCHESTRATOR] Workflow {workflow_id} not found")
            return False
        
        # Get all steps
        steps = self.state_manager.get_workflow_steps(workflow_id)
        
        # Find incomplete steps
        incomplete_steps = [s for s in steps if s.state not in [StepState.COMPLETED, StepState.SKIPPED]]
        
        logger.info(f"[ORCHESTRATOR] Resuming from step {workflow.current_step_number + 1}")
        logger.info(f"[ORCHESTRATOR] Remaining steps: {len(incomplete_steps)}")
        
        # Update state to RESUMING
        self.state_manager.update_workflow_state(
            workflow_id,
            WorkflowState.RESUMING,
            reason="Workflow resumption started"
        )
        
        # Execute remaining steps (simplified - would need full retry config restoration)
        workflow.state = WorkflowState.EXECUTING
        self.state_manager.update_workflow_state(workflow_id, WorkflowState.EXECUTING)
        
        # Continue with incomplete steps
        for step in incomplete_steps:
            step_success = await self._execute_step_with_retry(
                step,
                [],  # Would need to restore verification rules
                RetryConfig()
            )
            
            if not step_success:
                self.state_manager.update_workflow_state(
                    workflow_id,
                    WorkflowState.FAILED,
                    reason=f"Step {step.step_number} failed on resume"
                )
                return False
        
        # Mark as completed
        self.state_manager.update_workflow_state(
            workflow_id,
            WorkflowState.COMPLETED,
            reason="Workflow resumed and completed"
        )
        
        return True
    
    def pause_workflow(self, workflow_id: str, reason: str = "User requested"):
        """Pause an active workflow"""
        logger.info(f"[ORCHESTRATOR] Pausing workflow {workflow_id}: {reason}")
        
        self.state_manager.update_workflow_state(
            workflow_id,
            WorkflowState.PAUSED,
            reason=reason
        )
        
        # Cancel active task if running
        if workflow_id in self.active_workflows:
            self.active_workflows[workflow_id].cancel()
    
    def get_workflow_status(self, workflow_id: str) -> Dict[str, Any]:
        """Get current workflow status"""
        return self.state_manager.get_workflow_summary(workflow_id)


# Global instance
workflow_orchestrator = WorkflowOrchestrator()

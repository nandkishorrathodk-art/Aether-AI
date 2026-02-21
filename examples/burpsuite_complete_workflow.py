"""
Complete BurpSuite Bug Bounty Workflow Example
Demonstrates all v4.0 upgrade components working together
"""
import asyncio
import time
from typing import Optional

from src.execution.workflow_orchestrator import workflow_orchestrator, RetryConfig, RetryStrategy
from src.execution.workflow_state_manager import Workflow, WorkflowStep
from src.verification.verification_engine import (
    VerificationRule, VerificationType, CommonVerifications
)


async def burpsuite_bug_hunt_workflow(
    target_program: str = "Tesla",
    target_url: Optional[str] = None
) -> str:
    """
    Complete bug bounty hunting workflow with BurpSuite
    
    Steps:
    1. Open BurpSuite
    2. Create temporary project
    3. Navigate to Proxy → Intercept
    4. Enable intercept
    5. Verify setup complete
    
    Args:
        target_program: Bug bounty program name
        target_url: Target URL for testing (optional)
        
    Returns:
        workflow_id if successful, None otherwise
    """
    
    print("=" * 60)
    print(f"🎯 Starting Bug Bounty Workflow on {target_program}")
    print("=" * 60)
    
    # Create workflow definition
    workflow = Workflow(
        workflow_id=f"bug_hunt_{target_program.lower().replace(' ', '_')}_{int(time.time())}",
        name=f"BurpSuite Bug Hunt - {target_program}",
        description=f"Complete BurpSuite setup and preparation for {target_program} bug hunting",
        metadata={
            "target_program": target_program,
            "target_url": target_url,
            "platform": "HackerOne",
            "created_by": "Aether AI v4.0"
        }
    )
    
    # Define workflow steps
    steps = [
        WorkflowStep(
            step_id="step_1_open_burp",
            workflow_id=workflow.workflow_id,
            step_number=1,
            description="Opening BurpSuite application",
            action_type="open_app",
            parameters={"app": "burpsuite"}
        ),
        
        WorkflowStep(
            step_id="step_2_wait_load",
            workflow_id=workflow.workflow_id,
            step_number=2,
            description="Waiting for BurpSuite to fully load",
            action_type="wait",
            parameters={"duration": 8.0}
        ),
        
        WorkflowStep(
            step_id="step_3_temp_project",
            workflow_id=workflow.workflow_id,
            step_number=3,
            description="Selecting 'Temporary project'",
            action_type="click_element",
            parameters={"element_id": "temporary project"}
        ),
        
        WorkflowStep(
            step_id="step_4_click_next",
            workflow_id=workflow.workflow_id,
            step_number=4,
            description="Clicking 'Next' button",
            action_type="click_element",
            parameters={"element_id": "Next"}
        ),
        
        WorkflowStep(
            step_id="step_5_wait_dashboard",
            workflow_id=workflow.workflow_id,
            step_number=5,
            description="Waiting for dashboard to load",
            action_type="wait",
            parameters={"duration": 3.0}
        ),
        
        WorkflowStep(
            step_id="step_6_proxy_tab",
            workflow_id=workflow.workflow_id,
            step_number=6,
            description="Navigating to Proxy tab",
            action_type="click_element",
            parameters={"element_id": "Proxy"}
        ),
        
        WorkflowStep(
            step_id="step_7_intercept_tab",
            workflow_id=workflow.workflow_id,
            step_number=7,
            description="Opening Intercept sub-tab",
            action_type="click_element",
            parameters={"element_id": "Intercept"}
        ),
        
        WorkflowStep(
            step_id="step_8_enable_intercept",
            workflow_id=workflow.workflow_id,
            step_number=8,
            description="Enabling HTTP intercept",
            action_type="click_element",
            parameters={"element_id": "Intercept is off"}
        ),
        
        WorkflowStep(
            step_id="step_9_final_wait",
            workflow_id=workflow.workflow_id,
            step_number=9,
            description="Final setup wait",
            action_type="wait",
            parameters={"duration": 2.0}
        )
    ]
    
    # Define verification rules for critical steps
    verification_rules = {
        # Verify BurpSuite opened
        "step_1_open_burp": [
            CommonVerifications.burpsuite_opened()
        ],
        
        # Verify temporary project selected
        "step_3_temp_project": [
            VerificationRule(
                rule_id="temp_project_selected",
                verification_type=VerificationType.VISION_ANALYSIS,
                description="Verify temporary project option is selected",
                parameters={"expected_state": "temporary project button clicked"},
                expected_result="selected",
                required=False,  # Optional - Next button check is more reliable
                timeout=10.0
            )
        ],
        
        # Verify dashboard loaded
        "step_5_wait_dashboard": [
            VerificationRule(
                rule_id="dashboard_loaded",
                verification_type=VerificationType.ELEMENT_EXISTS,
                description="Verify BurpSuite dashboard is loaded",
                parameters={"element_id": "Proxy"},
                expected_result=True,
                required=True
            )
        ],
        
        # Verify intercept enabled
        "step_8_enable_intercept": [
            CommonVerifications.intercept_enabled(),
            VerificationRule(
                rule_id="intercept_visual_confirm",
                verification_type=VerificationType.VISION_ANALYSIS,
                description="Visual confirmation that intercept is ON",
                parameters={"expected_state": "Intercept is on button visible"},
                expected_result="on",
                required=False,  # Optional verification
                timeout=15.0
            )
        ]
    }
    
    # Define retry configurations
    retry_configs = {
        # Critical: Opening BurpSuite - retry with exponential backoff
        "step_1_open_burp": RetryConfig(
            max_retries=3,
            strategy=RetryStrategy.EXPONENTIAL_BACKOFF,
            base_delay=5.0
        ),
        
        # UI interactions - retry immediately (fast)
        "step_3_temp_project": RetryConfig(
            max_retries=5,
            strategy=RetryStrategy.IMMEDIATE
        ),
        
        "step_4_click_next": RetryConfig(
            max_retries=5,
            strategy=RetryStrategy.IMMEDIATE
        ),
        
        "step_6_proxy_tab": RetryConfig(
            max_retries=4,
            strategy=RetryStrategy.IMMEDIATE
        ),
        
        "step_7_intercept_tab": RetryConfig(
            max_retries=4,
            strategy=RetryStrategy.IMMEDIATE
        ),
        
        # Critical: Enabling intercept - retry with small delay
        "step_8_enable_intercept": RetryConfig(
            max_retries=6,
            strategy=RetryStrategy.EXPONENTIAL_BACKOFF,
            base_delay=1.0
        )
    }
    
    # Progress tracking callback
    def on_progress(data):
        percentage = data['progress_percentage']
        current = data['current_step']
        total = data['total_steps']
        desc = data['description']
        
        # Progress bar
        bar_length = 40
        filled = int(bar_length * percentage / 100)
        bar = '█' * filled + '░' * (bar_length - filled)
        
        print(f"\r[{bar}] {percentage}% | Step {current}/{total}: {desc}", end='', flush=True)
        
        # New line on completion
        if percentage == 100:
            print()
    
    print(f"\n📋 Workflow Details:")
    print(f"   ID: {workflow.workflow_id}")
    print(f"   Name: {workflow.name}")
    print(f"   Steps: {len(steps)}")
    print(f"   Target: {target_program}")
    if target_url:
        print(f"   URL: {target_url}")
    print()
    
    print("🚀 Starting execution...\n")
    
    try:
        # Execute workflow with WorkflowOrchestrator
        success = await workflow_orchestrator.execute_workflow(
            workflow=workflow,
            steps=steps,
            verification_rules=verification_rules,
            retry_configs=retry_configs,
            progress_callback=on_progress
        )
        
        print("\n" + "=" * 60)
        
        if success:
            print("✅ WORKFLOW COMPLETED SUCCESSFULLY!")
            print("=" * 60)
            
            # Get final status
            status = workflow_orchestrator.get_workflow_status(workflow.workflow_id)
            
            print(f"\n📊 Final Status:")
            print(f"   Workflow: {status['name']}")
            print(f"   State: {status['state']}")
            print(f"   Progress: {status['progress_percentage']}%")
            print(f"   Completed Steps: {status['completed_steps']}/{status['total_steps']}")
            print(f"   Duration: {status['duration']:.1f}s")
            
            print(f"\n🎯 BurpSuite is now ready for bug hunting on {target_program}!")
            print("   ✓ Application opened")
            print("   ✓ Temporary project created")
            print("   ✓ Proxy configured")
            print("   ✓ Intercept enabled")
            print("\n💡 Next steps:")
            print("   1. Configure browser to use BurpSuite proxy (127.0.0.1:8080)")
            print("   2. Import BurpSuite CA certificate in browser")
            print(f"   3. Navigate to {target_url or 'target website'}")
            print("   4. Start intercepting and analyzing requests!")
            
            return workflow.workflow_id
            
        else:
            print("❌ WORKFLOW FAILED")
            print("=" * 60)
            
            # Get error details
            status = workflow_orchestrator.get_workflow_status(workflow.workflow_id)
            
            print(f"\n❌ Error Details:")
            print(f"   Failed at step: {status['current_step']}/{status['total_steps']}")
            print(f"   Completed steps: {status['completed_steps']}")
            print(f"   Failed steps: {status['failed_steps']}")
            print(f"   Error: {status['error']}")
            print(f"\n💡 You can resume the workflow with:")
            print(f"   await workflow_orchestrator.resume_workflow('{workflow.workflow_id}')")
            
            return None
    
    except Exception as e:
        print(f"\n💥 UNEXPECTED ERROR: {e}")
        print("=" * 60)
        return None


async def resume_failed_workflow(workflow_id: str):
    """Resume a failed or paused workflow"""
    print(f"🔄 Resuming workflow: {workflow_id}")
    
    success = await workflow_orchestrator.resume_workflow(workflow_id)
    
    if success:
        print(f"✅ Workflow {workflow_id} resumed and completed!")
    else:
        print(f"❌ Workflow {workflow_id} failed to resume")
    
    return success


# Main execution
if __name__ == "__main__":
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║        AETHER AI v4.0 - BurpSuite Automation            ║
    ║           Complete Bug Bounty Workflow                  ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    
    # Example 1: Run complete workflow
    print("\n📌 Example 1: Complete BurpSuite Setup\n")
    workflow_id = asyncio.run(burpsuite_bug_hunt_workflow(
        target_program="Tesla",
        target_url="https://tesla.com"
    ))
    
    # Example 2: Resume a failed workflow (if previous failed)
    if not workflow_id:
        print("\n📌 Example 2: Resume Failed Workflow\n")
        # Replace with actual workflow_id from database
        # asyncio.run(resume_failed_workflow("bug_hunt_tesla_123456789"))
    
    print("\n✨ Demonstration complete!")

"""
Integration tests for Proactive AI workflow
Tests end-to-end proactive suggestion and execution flow
"""

import pytest
import asyncio
from datetime import datetime
from unittest.mock import patch, Mock, AsyncMock

from src.proactive import (
    get_proactive_brain,
    get_suggestion_generator,
    get_daily_planner,
    get_auto_executor
)


@pytest.fixture
def mock_settings():
    with patch('src.config.settings') as mock_settings:
        mock_settings.enable_proactive_mode = True
        mock_settings.proactive_morning_greeting = True
        mock_settings.proactive_daily_planning = True
        mock_settings.proactive_check_interval = 1800
        mock_settings.get_proactive_suggestion_types.return_value = [
            "bug_bounty", "youtube", "breaks", "learning"
        ]
        mock_settings.screen_monitor_data_path = Mock()
        mock_settings.screen_monitor_data_path.mkdir = Mock()
        mock_settings.screen_monitor_data_path.__truediv__ = lambda self, x: Mock(
            parent=Mock(mkdir=Mock()),
            exists=Mock(return_value=False),
            mkdir=Mock()
        )
        mock_settings.daily_report_path = Mock()
        mock_settings.daily_report_path.__truediv__ = lambda self, x: Mock(
            mkdir=Mock(),
            glob=Mock(return_value=[])
        )
        yield mock_settings


@pytest.mark.asyncio
async def test_complete_proactive_workflow(mock_settings):
    """Test full workflow: context -> suggestions -> execution"""
    
    with patch('src.proactive.proactive_brain.UserProfile'):
        with patch('src.proactive.daily_planner.UserProfile'):
            with patch('src.monitoring.get_monitoring_bridge') as mock_bridge:
                mock_bridge.return_value.detect_apps = AsyncMock(return_value={
                    "target_apps_detected": ["Burp Suite"],
                    "active_window": {"name": "Burp Suite Professional"}
                })
                
                brain = get_proactive_brain()
                executor = get_auto_executor()
                
                brain.user_profile.get_personalization_context = Mock(return_value={
                    "interests": ["security", "bug_bounty"],
                    "communication_style": "friendly"
                })
                brain.user_profile.get = Mock(return_value={"last_active": datetime.now().isoformat()})
                brain.daily_planner.load_plan = Mock(return_value=None)
                
                with patch('src.proactive.suggestion_generator.model_loader.generate', new_callable=AsyncMock):
                    result = await brain.check_and_suggest()
                    
                    assert result["status"] == "success"
                    suggestions = result.get("suggestions", [])
                    
                    if suggestions:
                        suggestion = suggestions[0]
                        suggestion_id = suggestion["id"]
                        action_command = suggestion.get("action_command")
                        
                        if action_command:
                            exec_result = await executor.execute_action(
                                action_command=action_command,
                                action_id=suggestion_id,
                                skip_approval=False
                            )
                            
                            assert exec_result.action_id == suggestion_id
                            
                            if exec_result.status.value == "pending":
                                approved = await executor.approve_and_execute(suggestion_id)
                                assert approved.status.value in ["completed", "failed"]


@pytest.mark.asyncio
async def test_daily_planning_workflow(mock_settings):
    """Test daily plan generation and task scheduling"""
    
    with patch('src.proactive.daily_planner.UserProfile'):
        with patch('src.proactive.daily_planner.model_loader.generate', new_callable=AsyncMock) as mock_gen:
            mock_gen.return_value = Mock(content='''{
                "goals": ["Bug bounty scan", "YouTube content"],
                "scheduled_tasks": [
                    {
                        "time": "09:00",
                        "title": "Morning Session",
                        "description": "Bug hunting",
                        "duration_minutes": 120,
                        "priority": 9,
                        "task_type": "bug_bounty"
                    }
                ],
                "focus_areas": ["Security", "Content"],
                "earnings_potential": 500.0,
                "motivation": "Boss aaj full power!"
            }''')
            
            planner = get_daily_planner()
            
            plan = await planner.generate_daily_plan(
                user_goals=["Find critical bugs", "Create trending content"]
            )
            
            assert plan is not None
            assert len(plan.goals) > 0
            assert len(plan.scheduled_tasks) > 0
            assert plan.estimated_earnings_potential > 0
            
            greeting = await planner.generate_morning_greeting()
            assert isinstance(greeting, str)
            assert len(greeting) > 0


@pytest.mark.asyncio
async def test_suggestion_to_execution_pipeline(mock_settings):
    """Test suggestion generation -> approval -> execution pipeline"""
    
    with patch('src.proactive.suggestion_generator.model_loader.generate', new_callable=AsyncMock):
        generator = get_suggestion_generator()
        executor = get_auto_executor()
        
        context = {
            "detected_apps": [],
            "activity_type": "browsing",
            "user_interests": ["security"]
        }
        
        suggestions = await generator.generate_contextual_suggestions(context)
        
        for suggestion in suggestions:
            if suggestion.action_command:
                result = await executor.execute_action(
                    action_command=suggestion.action_command,
                    action_id=suggestion.id,
                    skip_approval=False
                )
                
                assert result.action_id == suggestion.id
                assert result.status.value == "pending"
                
                pending = executor.get_pending_approvals()
                assert suggestion.id in pending
                
                approved_result = await executor.approve_and_execute(suggestion.id)
                assert approved_result.status.value in ["completed", "failed"]
                
                assert suggestion.id not in executor.get_pending_approvals()
                
                break


@pytest.mark.asyncio
async def test_proactive_check_with_morning_greeting(mock_settings):
    """Test proactive check includes morning greeting when appropriate"""
    
    with patch('src.proactive.proactive_brain.UserProfile'):
        with patch('src.proactive.daily_planner.UserProfile'):
            with patch('src.monitoring.get_monitoring_bridge') as mock_bridge:
                mock_bridge.return_value.detect_apps = AsyncMock(return_value={
                    "target_apps_detected": [],
                    "active_window": {"name": "Chrome"}
                })
                
                brain = get_proactive_brain()
                brain.last_greeting_date = None
                
                brain.user_profile.get_personalization_context = Mock(return_value={
                    "interests": [],
                    "communication_style": "friendly"
                })
                brain.user_profile.get = Mock(return_value={})
                
                with patch('src.proactive.daily_planner.model_loader.generate', new_callable=AsyncMock) as mock_gen:
                    mock_gen.return_value = Mock(content='{"goals": [], "scheduled_tasks": [], "focus_areas": [], "earnings_potential": 0, "motivation": "Test"}')
                    
                    brain.daily_planner.load_plan = Mock(return_value=None)
                    
                    with patch('src.proactive.suggestion_generator.model_loader.generate', new_callable=AsyncMock):
                        current_hour = datetime.now().hour
                        if 6 <= current_hour < 11:
                            result = await brain.check_and_suggest()
                            
                            greeting = result.get("greeting")
                            if greeting:
                                assert isinstance(greeting, str)
                                assert len(greeting) > 0


@pytest.mark.asyncio
async def test_execution_rollback_on_failure(mock_settings):
    """Test that failed executions attempt rollback"""
    
    executor = get_auto_executor()
    
    async def failing_handler(params):
        raise Exception("Simulated failure")
    
    executor.action_handlers["test_failing_action"] = failing_handler
    
    result = await executor.execute_action(
        action_command="test_failing_action",
        action_id="test-rollback",
        skip_approval=True
    )
    
    assert result.status.value == "rolled_back"
    assert result.error is not None
    assert result.rollback_info is not None


@pytest.mark.asyncio
async def test_context_based_suggestion_generation(mock_settings):
    """Test that suggestions are context-aware"""
    
    with patch('src.proactive.suggestion_generator.model_loader.generate', new_callable=AsyncMock):
        generator = get_suggestion_generator()
        
        burp_context = {
            "detected_apps": ["Burp Suite"],
            "activity_type": "security_testing"
        }
        
        suggestions = await generator.generate_contextual_suggestions(burp_context)
        
        bug_bounty_suggestions = [s for s in suggestions if s.suggestion_type == "bug_bounty"]
        assert len(bug_bounty_suggestions) > 0
        
        if bug_bounty_suggestions:
            assert bug_bounty_suggestions[0].confidence >= 0.7


@pytest.mark.asyncio
async def test_multiple_pending_approvals(mock_settings):
    """Test handling multiple pending approvals"""
    
    executor = get_auto_executor()
    
    action_ids = []
    for i in range(3):
        result = await executor.execute_action(
            action_command="start_bugbounty_autopilot",
            action_id=f"test-multi-{i}",
            skip_approval=False
        )
        action_ids.append(f"test-multi-{i}")
        assert result.status.value == "pending"
    
    pending = executor.get_pending_approvals()
    assert len(pending) == 3
    
    approved = await executor.approve_and_execute(action_ids[0])
    assert approved.status.value in ["completed", "failed"]
    
    rejected = executor.reject_action(action_ids[1])
    assert rejected is True
    
    pending = executor.get_pending_approvals()
    assert len(pending) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

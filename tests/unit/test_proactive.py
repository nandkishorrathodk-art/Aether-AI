"""
Unit tests for Proactive AI Brain & Daily Planning
"""

import pytest
import asyncio
from datetime import datetime, date
from unittest.mock import Mock, patch, AsyncMock, MagicMock
import json

from src.proactive.suggestion_generator import (
    SuggestionGenerator, ProactiveSuggestion, get_suggestion_generator
)
from src.proactive.daily_planner import (
    DailyPlanner, DailyPlan, ScheduledTask, get_daily_planner
)
from src.proactive.proactive_brain import ProactiveBrain, get_proactive_brain
from src.proactive.auto_executor import (
    AutoExecutor, ExecutionResult, ExecutionStatus, get_auto_executor
)


class TestSuggestionGenerator:
    @pytest.fixture
    def generator(self, tmp_path):
        with patch('src.proactive.suggestion_generator.settings') as mock_settings:
            mock_settings.screen_monitor_data_path = tmp_path
            mock_settings.get_proactive_suggestion_types.return_value = [
                "bug_bounty", "youtube", "breaks", "learning"
            ]
            return SuggestionGenerator()

    @pytest.mark.asyncio
    async def test_generate_contextual_suggestions(self, generator):
        context = {
            "detected_apps": ["Burp Suite"],
            "activity_type": "security_testing",
            "last_break_time": datetime.now().isoformat()
        }
        
        with patch.object(generator, '_generate_suggestion', new_callable=AsyncMock) as mock_gen:
            mock_suggestion = ProactiveSuggestion(
                id="test-123",
                timestamp=datetime.now().isoformat(),
                context="Test context",
                suggestion_type="bug_bounty",
                title="Test suggestion",
                description="Test description",
                action_command="test_action",
                confidence=0.9,
                requires_approval=True,
                priority=10
            )
            mock_gen.return_value = mock_suggestion
            
            suggestions = await generator.generate_contextual_suggestions(context)
            
            assert len(suggestions) > 0
            assert all(isinstance(s, ProactiveSuggestion) for s in suggestions)

    @pytest.mark.asyncio
    async def test_bug_bounty_suggestion_with_burp(self, generator):
        context = {
            "detected_apps": ["Burp Suite"],
            "activity_type": "security_testing"
        }
        
        suggestion = await generator._generate_bug_bounty_suggestion(context, "morning")
        
        assert suggestion is not None
        assert suggestion.suggestion_type == "bug_bounty"
        assert "Burp" in suggestion.title or "Burp" in suggestion.description
        assert suggestion.confidence >= 0.8

    @pytest.mark.asyncio
    async def test_bug_bounty_suggestion_morning(self, generator):
        context = {"detected_apps": []}
        
        suggestion = await generator._generate_bug_bounty_suggestion(context, "morning")
        
        assert suggestion is not None
        assert suggestion.suggestion_type == "bug_bounty"
        assert suggestion.priority >= 6

    def test_break_suggestion_needed(self, generator):
        context = {
            "last_break_time": (datetime.now().replace(hour=datetime.now().hour - 3)).isoformat()
        }
        current_time = datetime.now()
        
        suggestion = generator._generate_break_suggestion(context, current_time)
        
        assert suggestion is not None
        assert suggestion.suggestion_type == "breaks"
        assert suggestion.priority >= 8

    def test_break_suggestion_not_needed(self, generator):
        context = {
            "last_break_time": datetime.now().isoformat()
        }
        current_time = datetime.now()
        
        suggestion = generator._generate_break_suggestion(context, current_time)
        
        assert suggestion is None

    def test_get_time_of_day(self, generator):
        assert generator._get_time_of_day(datetime(2024, 1, 1, 8, 0)) == "morning"
        assert generator._get_time_of_day(datetime(2024, 1, 1, 14, 0)) == "afternoon"
        assert generator._get_time_of_day(datetime(2024, 1, 1, 19, 0)) == "evening"
        assert generator._get_time_of_day(datetime(2024, 1, 1, 22, 0)) == "night"

    def test_history_management(self, generator):
        suggestion = ProactiveSuggestion(
            id="test-123",
            timestamp=datetime.now().isoformat(),
            context="Test",
            suggestion_type="test",
            title="Test",
            description="Test",
            action_command=None,
            confidence=0.8,
            requires_approval=False
        )
        
        generator.suggestion_history.append(suggestion)
        recent = generator.get_recent_suggestions(limit=5)
        
        assert len(recent) > 0
        assert recent[-1].id == "test-123"

    def test_clear_history(self, generator):
        generator.suggestion_history.append(ProactiveSuggestion(
            id="test", timestamp="", context="", suggestion_type="test",
            title="", description="", action_command=None,
            confidence=0.8, requires_approval=False
        ))
        
        generator.clear_history()
        
        assert len(generator.suggestion_history) == 0


class TestDailyPlanner:
    @pytest.fixture
    def planner(self, tmp_path):
        with patch('src.proactive.daily_planner.settings') as mock_settings:
            mock_settings.daily_report_path = tmp_path
            with patch('src.proactive.daily_planner.UserProfile'):
                return DailyPlanner()

    @pytest.mark.asyncio
    async def test_generate_daily_plan(self, planner):
        with patch.object(planner, '_parse_plan_response') as mock_parse:
            mock_parse.return_value = {
                "goals": ["Goal 1", "Goal 2"],
                "scheduled_tasks": [
                    {
                        "time": "09:00",
                        "title": "Morning task",
                        "description": "Test task",
                        "duration_minutes": 60,
                        "priority": 8,
                        "task_type": "bug_bounty"
                    }
                ],
                "focus_areas": ["Bug Bounty"],
                "earnings_potential": 500.0,
                "motivation": "Test motivation"
            }
            
            with patch('src.proactive.daily_planner.model_loader.generate', new_callable=AsyncMock) as mock_gen:
                mock_gen.return_value = Mock(content='{"test": "data"}')
                
                plan = await planner.generate_daily_plan()
                
                assert isinstance(plan, DailyPlan)
                assert len(plan.goals) > 0
                assert len(plan.scheduled_tasks) > 0
                assert plan.estimated_earnings_potential > 0

    def test_create_default_plan(self, planner):
        today = date.today()
        current_time = datetime.now()
        
        plan = planner._create_default_plan(today, current_time)
        
        assert isinstance(plan, DailyPlan)
        assert plan.date == today.isoformat()
        assert len(plan.goals) >= 3
        assert len(plan.scheduled_tasks) >= 3
        assert any("break" in task.task_type.lower() for task in plan.scheduled_tasks)

    def test_save_and_load_plan(self, planner):
        today = date.today()
        plan = planner._create_default_plan(today, datetime.now())
        
        planner._save_plan(plan)
        loaded_plan = planner.load_plan(today.isoformat())
        
        assert loaded_plan is not None
        assert loaded_plan.date == plan.date
        assert len(loaded_plan.goals) == len(plan.goals)

    @pytest.mark.asyncio
    async def test_generate_morning_greeting(self, planner):
        with patch.object(planner, 'load_plan') as mock_load:
            mock_load.return_value = None
            
            with patch.object(planner, 'generate_daily_plan', new_callable=AsyncMock) as mock_gen:
                mock_plan = planner._create_default_plan(date.today(), datetime.now())
                mock_gen.return_value = mock_plan
                
                greeting = await planner.generate_morning_greeting()
                
                assert isinstance(greeting, str)
                assert len(greeting) > 0

    def test_get_current_task(self, planner):
        plan = planner._create_default_plan(date.today(), datetime.now())
        planner._save_plan(plan)
        
        current_task = planner.get_current_task()
        
        assert current_task is None or isinstance(current_task, ScheduledTask)


class TestProactiveBrain:
    @pytest.fixture
    def brain(self):
        with patch('src.proactive.proactive_brain.UserProfile'):
            with patch('src.proactive.proactive_brain.get_suggestion_generator') as mock_gen:
                with patch('src.proactive.proactive_brain.get_daily_planner') as mock_planner:
                    mock_gen.return_value = Mock()
                    mock_planner.return_value = Mock()
                    return ProactiveBrain()

    @pytest.mark.asyncio
    async def test_check_and_suggest(self, brain):
        brain.suggestion_generator.generate_contextual_suggestions = AsyncMock(return_value=[])
        
        with patch.object(brain, '_build_context', new_callable=AsyncMock) as mock_context:
            mock_context.return_value = {"test": "context"}
            
            with patch.object(brain, '_check_morning_greeting', new_callable=AsyncMock) as mock_greeting:
                mock_greeting.return_value = None
                
                result = await brain.check_and_suggest()
                
                assert result["status"] == "success"
                assert "suggestions" in result

    @pytest.mark.asyncio
    async def test_build_context(self, brain):
        with patch('src.monitoring.get_monitoring_bridge') as mock_bridge:
            mock_bridge.return_value.detect_apps = AsyncMock(return_value={
                "target_apps_detected": ["Test App"],
                "active_window": {"name": "Test Window"}
            })
            
            brain.user_profile.get_personalization_context = Mock(return_value={
                "interests": ["security"],
                "communication_style": "friendly"
            })
            brain.user_profile.get = Mock(return_value={"last_active": datetime.now().isoformat()})
            brain.daily_planner.load_plan = Mock(return_value=None)
            
            context = await brain._build_context()
            
            assert "detected_apps" in context
            assert "user_interests" in context

    @pytest.mark.asyncio
    async def test_morning_greeting_generated(self, brain):
        with patch('src.proactive.proactive_brain.settings') as mock_settings:
            mock_settings.proactive_morning_greeting = True
            
            brain.daily_planner.generate_morning_greeting = AsyncMock(return_value="Good morning!")
            brain.last_greeting_date = None
            
            current_hour = datetime.now().hour
            greeting = await brain._check_morning_greeting()
            
            if 6 <= current_hour < 11:
                assert greeting is not None
            else:
                assert greeting is None

    @pytest.mark.asyncio
    async def test_generate_daily_plan(self, brain):
        brain.daily_planner.generate_daily_plan = AsyncMock(return_value=Mock(to_dict=lambda: {"test": "plan"}))
        
        result = await brain.generate_daily_plan()
        
        assert result["status"] == "success"
        assert "plan" in result

    def test_get_statistics(self, brain):
        brain.suggestion_generator.suggestion_history = [Mock(), Mock()]
        
        with patch('src.proactive.proactive_brain.settings') as mock_settings:
            mock_settings.enable_proactive_mode = True
            mock_settings.proactive_morning_greeting = True
            
            stats = brain.get_statistics()
            
            assert "total_suggestions" in stats
            assert stats["total_suggestions"] == 2


class TestAutoExecutor:
    @pytest.fixture
    def executor(self, tmp_path):
        with patch('src.proactive.auto_executor.settings') as mock_settings:
            mock_settings.screen_monitor_data_path = tmp_path
            return AutoExecutor()

    @pytest.mark.asyncio
    async def test_execute_action_requires_approval(self, executor):
        result = await executor.execute_action(
            action_command="start_bugbounty_autopilot",
            action_id="test-123",
            skip_approval=False
        )
        
        assert result.status == ExecutionStatus.PENDING
        assert "test-123" in executor.pending_approvals

    @pytest.mark.asyncio
    async def test_execute_action_skip_approval(self, executor):
        result = await executor.execute_action(
            action_command="start_bugbounty_autopilot",
            action_id="test-123",
            skip_approval=True
        )
        
        assert result.status in [ExecutionStatus.COMPLETED, ExecutionStatus.FAILED]
        assert result.started_at is not None

    @pytest.mark.asyncio
    async def test_approve_and_execute(self, executor):
        await executor.execute_action(
            action_command="start_bugbounty_autopilot",
            action_id="test-approve",
            skip_approval=False
        )
        
        result = await executor.approve_and_execute("test-approve")
        
        assert result.status in [ExecutionStatus.COMPLETED, ExecutionStatus.FAILED]
        assert "test-approve" not in executor.pending_approvals

    def test_reject_action(self, executor):
        executor.pending_approvals["test-reject"] = {
            "action_command": "test_action",
            "parameters": {},
            "requested_at": datetime.now().isoformat()
        }
        
        success = executor.reject_action("test-reject")
        
        assert success is True
        assert "test-reject" not in executor.pending_approvals

    def test_get_pending_approvals(self, executor):
        executor.pending_approvals["test-1"] = {"action": "test1"}
        executor.pending_approvals["test-2"] = {"action": "test2"}
        
        pending = executor.get_pending_approvals()
        
        assert len(pending) == 2
        assert "test-1" in pending

    @pytest.mark.asyncio
    async def test_action_handlers(self, executor):
        result = await executor._handle_start_bugbounty({})
        assert "started" in result.lower() or "autopilot" in result.lower()
        
        with patch('webbrowser.open'):
            result = await executor._handle_open_dashboard({})
            assert "opened" in result.lower() or "dashboard" in result.lower()
        
        result = await executor._handle_schedule_break({"duration_minutes": 15})
        assert "15" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

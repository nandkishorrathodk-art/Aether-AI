"""
Daily Planner - Generates daily plans and schedules
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime, date, time as datetime_time
import json
from pathlib import Path

from src.cognitive.llm.model_loader import model_loader
from src.cognitive.llm.providers.base import TaskType
from src.cognitive.memory.user_profile import UserProfile
from src.utils.logger import get_logger
from src.config import settings

logger = get_logger(__name__)


@dataclass
class ScheduledTask:
    time: str
    title: str
    description: str
    duration_minutes: int
    priority: int
    task_type: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DailyPlan:
    date: str
    goals: List[str]
    scheduled_tasks: List[ScheduledTask]
    suggested_focus_areas: List[str]
    estimated_earnings_potential: Optional[float]
    motivation_message: str
    created_at: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "date": self.date,
            "goals": self.goals,
            "scheduled_tasks": [t.to_dict() for t in self.scheduled_tasks],
            "suggested_focus_areas": self.suggested_focus_areas,
            "estimated_earnings_potential": self.estimated_earnings_potential,
            "motivation_message": self.motivation_message,
            "created_at": self.created_at
        }


class DailyPlanner:
    def __init__(self, user_profile: Optional[UserProfile] = None):
        self.user_profile = user_profile or UserProfile()
        self.plans_dir = settings.daily_report_path / "plans"
        self.plans_dir.mkdir(parents=True, exist_ok=True)
        logger.info("DailyPlanner initialized")

    async def generate_daily_plan(
        self,
        user_goals: Optional[List[str]] = None,
        preferences: Optional[Dict[str, Any]] = None
    ) -> DailyPlan:
        today = date.today()
        current_time = datetime.now()
        
        user_context = self.user_profile.get_personalization_context()
        interests = user_context.get("interests", [])
        
        prompt = self._build_plan_prompt(
            today,
            user_goals or [],
            interests,
            preferences or {}
        )
        
        try:
            response = await model_loader.generate(
                prompt=prompt,
                task_type=TaskType.REASONING,
                system_prompt="You are a productivity and planning expert. Generate realistic, achievable daily plans. Respond with valid JSON only.",
                temperature=0.7,
                max_tokens=1000
            )
            
            plan_data = self._parse_plan_response(response.content)
            
            plan = DailyPlan(
                date=today.isoformat(),
                goals=plan_data.get("goals", ["Complete bug bounty scan", "YouTube content planning"]),
                scheduled_tasks=[
                    ScheduledTask(**task) for task in plan_data.get("scheduled_tasks", [])
                ],
                suggested_focus_areas=plan_data.get("focus_areas", ["Bug Bounty", "Content Creation"]),
                estimated_earnings_potential=plan_data.get("earnings_potential", 500.0),
                motivation_message=plan_data.get("motivation", "Boss aaj full power mein jaana hai! 🚀"),
                created_at=current_time.isoformat()
            )
            
            self._save_plan(plan)
            logger.info(f"Generated daily plan for {today}")
            return plan
            
        except Exception as e:
            logger.error(f"Failed to generate daily plan: {e}")
            return self._create_default_plan(today, current_time)

    def _build_plan_prompt(
        self,
        today: date,
        goals: List[str],
        interests: List[str],
        preferences: Dict[str, Any]
    ) -> str:
        weekday = today.strftime("%A")
        
        goals_str = ", ".join(goals) if goals else "bug bounty hunting, YouTube content"
        interests_str = ", ".join(interests) if interests else "cybersecurity, content creation"
        
        return f"""Create a daily plan for {weekday}, {today}.
User goals: {goals_str}
Interests: {interests_str}

Generate a JSON response with this structure:
{{
  "goals": ["goal1", "goal2", "goal3"],
  "scheduled_tasks": [
    {{"time": "09:00", "title": "Task name", "description": "Details", "duration_minutes": 60, "priority": 8, "task_type": "bug_bounty"}},
    {{"time": "11:00", "title": "Break", "description": "Rest", "duration_minutes": 15, "priority": 5, "task_type": "break"}}
  ],
  "focus_areas": ["Bug Bounty", "YouTube"],
  "earnings_potential": 500.0,
  "motivation": "Boss aaj kamaal ka din hai! Full energy 🔥"
}}

Include:
- Morning bug bounty session (if applicable)
- Breaks every 2 hours
- Evening content creation/planning
- Realistic time blocks
- Hindi-English mix motivation message"""

    def _parse_plan_response(self, response_content: str) -> Dict[str, Any]:
        import re
        
        match = re.search(r'\{.*\}', response_content, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError as e:
                logger.error(f"JSON parsing failed: {e}")
        
        return {}

    def _create_default_plan(self, today: date, current_time: datetime) -> DailyPlan:
        return DailyPlan(
            date=today.isoformat(),
            goals=[
                "Run bug bounty scan on target programs",
                "Check trending YouTube niches",
                "Review security research"
            ],
            scheduled_tasks=[
                ScheduledTask(
                    time="09:00",
                    title="Morning Bug Bounty Session",
                    description="Focus on Apple/Google programs. Run Burp Suite scans.",
                    duration_minutes=120,
                    priority=9,
                    task_type="bug_bounty"
                ),
                ScheduledTask(
                    time="11:00",
                    title="Break",
                    description="Coffee, stretch, fresh air",
                    duration_minutes=15,
                    priority=7,
                    task_type="break"
                ),
                ScheduledTask(
                    time="14:00",
                    title="YouTube Content Planning",
                    description="Research trending topics, script ideas",
                    duration_minutes=90,
                    priority=8,
                    task_type="youtube"
                ),
                ScheduledTask(
                    time="16:00",
                    title="Afternoon Break",
                    description="Walk, hydrate, eye rest",
                    duration_minutes=20,
                    priority=7,
                    task_type="break"
                ),
                ScheduledTask(
                    time="19:00",
                    title="Learning & Research",
                    description="New exploits, security papers, skill development",
                    duration_minutes=60,
                    priority=6,
                    task_type="learning"
                )
            ],
            suggested_focus_areas=["Bug Bounty", "YouTube Content", "Skill Development"],
            estimated_earnings_potential=500.0,
            motivation_message="Boss aaj full focus se jaana hai! Every task counts 🚀💪",
            created_at=current_time.isoformat()
        )

    def _save_plan(self, plan: DailyPlan):
        try:
            plan_file = self.plans_dir / f"plan_{plan.date}.json"
            with open(plan_file, 'w', encoding='utf-8') as f:
                json.dump(plan.to_dict(), f, indent=2, ensure_ascii=False)
            logger.debug(f"Saved daily plan: {plan_file}")
        except Exception as e:
            logger.error(f"Failed to save plan: {e}")

    def load_plan(self, plan_date: Optional[str] = None) -> Optional[DailyPlan]:
        if not plan_date:
            plan_date = date.today().isoformat()
        
        plan_file = self.plans_dir / f"plan_{plan_date}.json"
        
        if plan_file.exists():
            try:
                with open(plan_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    data["scheduled_tasks"] = [
                        ScheduledTask(**task) for task in data["scheduled_tasks"]
                    ]
                    return DailyPlan(**data)
            except Exception as e:
                logger.error(f"Failed to load plan: {e}")
        
        return None

    async def generate_morning_greeting(self) -> str:
        user_name = self.user_profile.get("personal_info.name", "Boss")
        
        current_time = datetime.now()
        hour = current_time.hour
        
        if 5 <= hour < 12:
            greeting = f"Good morning {user_name}! ☀️"
        elif 12 <= hour < 17:
            greeting = f"Good afternoon {user_name}!"
        else:
            greeting = f"Hey {user_name}!"
        
        plan = self.load_plan()
        if not plan:
            plan = await self.generate_daily_plan()
        
        message = f"""{greeting}

{plan.motivation_message}

**Aaj ke goals:**
"""
        for i, goal in enumerate(plan.goals[:3], 1):
            message += f"{i}. {goal}\n"
        
        message += f"\n**Earnings Potential:** ${plan.estimated_earnings_potential:.0f}+ 💰"
        message += f"\n**Focus:** {', '.join(plan.suggested_focus_areas)}"
        
        return message

    def get_current_task(self) -> Optional[ScheduledTask]:
        plan = self.load_plan()
        if not plan:
            return None
        
        current_time = datetime.now().time()
        
        for task in plan.scheduled_tasks:
            task_time = datetime.strptime(task.time, "%H:%M").time()
            if task_time <= current_time:
                continue
            return task
        
        return None


_planner: Optional[DailyPlanner] = None


def get_daily_planner() -> DailyPlanner:
    global _planner
    if _planner is None:
        _planner = DailyPlanner()
    return _planner

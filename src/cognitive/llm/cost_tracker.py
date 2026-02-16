import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from src.config import settings
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class CostEntry:
    timestamp: str
    provider: str
    model: str
    tokens_used: int
    cost_usd: float
    task_type: str
    latency_ms: float


class CostTracker:
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or Path("./data/costs.json")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.costs: List[CostEntry] = []
        self.load_costs()

    def load_costs(self):
        if self.db_path.exists():
            try:
                with open(self.db_path, 'r') as f:
                    data = json.load(f)
                    self.costs = [CostEntry(**entry) for entry in data]
                logger.info(f"Loaded {len(self.costs)} cost entries")
            except Exception as e:
                logger.error(f"Failed to load costs: {e}")
                self.costs = []
        else:
            self.costs = []

    def save_costs(self):
        try:
            with open(self.db_path, 'w') as f:
                json.dump([asdict(entry) for entry in self.costs], f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save costs: {e}")

    def track_request(
        self,
        provider: str,
        model: str,
        tokens_used: int,
        cost_usd: float,
        task_type: str = "unknown",
        latency_ms: float = 0.0
    ):
        entry = CostEntry(
            timestamp=datetime.now().isoformat(),
            provider=provider,
            model=model,
            tokens_used=tokens_used,
            cost_usd=cost_usd,
            task_type=task_type,
            latency_ms=latency_ms
        )
        self.costs.append(entry)
        self.save_costs()
        logger.debug(f"Tracked cost: ${cost_usd:.4f} for {provider}/{model}")

        if settings.enable_cost_tracking:
            self._check_daily_limit()

    def _check_daily_limit(self):
        today_cost = self.get_cost_for_period(hours=24)
        if today_cost >= settings.max_cost_per_day_usd:
            logger.warning(
                f"Daily cost limit reached: ${today_cost:.2f} / ${settings.max_cost_per_day_usd:.2f}"
            )

    def get_cost_for_period(self, hours: int = 24) -> float:
        cutoff = datetime.now() - timedelta(hours=hours)
        total = sum(
            entry.cost_usd
            for entry in self.costs
            if datetime.fromisoformat(entry.timestamp) >= cutoff
        )
        return total

    def get_total_cost(self) -> float:
        return sum(entry.cost_usd for entry in self.costs)

    def get_cost_by_provider(self, hours: Optional[int] = None) -> Dict[str, float]:
        costs = {}
        cutoff = datetime.now() - timedelta(hours=hours) if hours else None

        for entry in self.costs:
            if cutoff and datetime.fromisoformat(entry.timestamp) < cutoff:
                continue
            
            provider = entry.provider
            costs[provider] = costs.get(provider, 0.0) + entry.cost_usd

        return costs

    def get_cost_by_model(self, hours: Optional[int] = None) -> Dict[str, float]:
        costs = {}
        cutoff = datetime.now() - timedelta(hours=hours) if hours else None

        for entry in self.costs:
            if cutoff and datetime.fromisoformat(entry.timestamp) < cutoff:
                continue
            
            model_key = f"{entry.provider}/{entry.model}"
            costs[model_key] = costs.get(model_key, 0.0) + entry.cost_usd

        return costs

    def get_cost_by_task_type(self, hours: Optional[int] = None) -> Dict[str, float]:
        costs = {}
        cutoff = datetime.now() - timedelta(hours=hours) if hours else None

        for entry in self.costs:
            if cutoff and datetime.fromisoformat(entry.timestamp) < cutoff:
                continue
            
            task_type = entry.task_type
            costs[task_type] = costs.get(task_type, 0.0) + entry.cost_usd

        return costs

    def get_stats(self, hours: Optional[int] = 24) -> Dict:
        cutoff = datetime.now() - timedelta(hours=hours) if hours else None
        
        filtered_costs = [
            entry for entry in self.costs
            if not cutoff or datetime.fromisoformat(entry.timestamp) >= cutoff
        ]

        if not filtered_costs:
            return {
                "total_cost": 0.0,
                "total_tokens": 0,
                "total_requests": 0,
                "avg_cost_per_request": 0.0,
                "avg_latency_ms": 0.0,
                "by_provider": {},
                "by_model": {},
                "by_task_type": {}
            }

        total_cost = sum(e.cost_usd for e in filtered_costs)
        total_tokens = sum(e.tokens_used for e in filtered_costs)
        total_requests = len(filtered_costs)
        avg_latency = sum(e.latency_ms for e in filtered_costs) / total_requests

        return {
            "total_cost": round(total_cost, 4),
            "total_tokens": total_tokens,
            "total_requests": total_requests,
            "avg_cost_per_request": round(total_cost / total_requests, 4),
            "avg_latency_ms": round(avg_latency, 2),
            "by_provider": self.get_cost_by_provider(hours),
            "by_model": self.get_cost_by_model(hours),
            "by_task_type": self.get_cost_by_task_type(hours)
        }

    def get_most_cost_effective_provider(self, task_type: Optional[str] = None) -> Optional[str]:
        filtered_costs = self.costs
        if task_type:
            filtered_costs = [e for e in self.costs if e.task_type == task_type]

        if not filtered_costs:
            return None

        provider_metrics = {}
        for entry in filtered_costs:
            if entry.provider not in provider_metrics:
                provider_metrics[entry.provider] = {"cost": 0.0, "tokens": 0}
            
            provider_metrics[entry.provider]["cost"] += entry.cost_usd
            provider_metrics[entry.provider]["tokens"] += entry.tokens_used

        cost_per_token = {
            provider: metrics["cost"] / metrics["tokens"]
            for provider, metrics in provider_metrics.items()
            if metrics["tokens"] > 0
        }

        if not cost_per_token:
            return None

        return min(cost_per_token, key=cost_per_token.get)

    def clear_old_entries(self, days: int = 30):
        cutoff = datetime.now() - timedelta(days=days)
        original_count = len(self.costs)
        self.costs = [
            entry for entry in self.costs
            if datetime.fromisoformat(entry.timestamp) >= cutoff
        ]
        removed = original_count - len(self.costs)
        if removed > 0:
            self.save_costs()
            logger.info(f"Cleared {removed} cost entries older than {days} days")


cost_tracker = CostTracker()

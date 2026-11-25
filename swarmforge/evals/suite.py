"""Multi-strategy Eval Arena comparing Single-Shot, Plan-Execute, and Council+Judge."""

from __future__ import annotations

import uuid
from typing import Any

from swarmforge.engine.orchestrator import SwarmOrchestrator, compute_expected_recall
from swarmforge.models import (
    EvalCaseResult,
    EvalSuiteReport,
    MissionRequest,
    PolicyMode,
    ProviderName,
    StrategyMode,
)
from swarmforge.storage.db import SwarmDatabase
from swarmforge.tools.fixtures import MISSION_CATALOG


class EvalArena:
    """Runs benchmark suites across orchestration strategies and builds leaderboard metrics."""

    def __init__(self, db: SwarmDatabase) -> None:
        self.db = db
        self.orchestrator = SwarmOrchestrator(db)

    async def run_suite(
        self,
        policy_mode: PolicyMode = PolicyMode.STRICT,
        strategies: list[StrategyMode] | None = None,
        mission_ids: list[str] | None = None,
    ) -> EvalSuiteReport:
        chosen_strategies = strategies or [
            StrategyMode.SINGLE_SHOT,
            StrategyMode.PLAN_EXECUTE,
            StrategyMode.COUNCIL_JUDGE,
        ]
        chosen_missions = mission_ids or [
            mid for mid in MISSION_CATALOG.keys() if mid != "custom-target-audit"
        ]
        results: list[EvalCaseResult] = []

        for mid in chosen_missions:
            mission_def = MISSION_CATALOG[mid]
            for strategy in chosen_strategies:
                run = await self.orchestrator.execute_mission(
                    MissionRequest(
                        mission_id=mid,
                        strategy=strategy,
                        policy_mode=policy_mode,
                        provider=ProviderName.LOCAL,
                    ),
                    pace_ms=0,
                )
                events = self.db.get_events(run.run_id)
                last_fw_events = (events[-1].blackboard_snapshot or {}).get("firewall_events", []) if events else []
                has_inv = bool(events and (events[-1].blackboard_snapshot or {}).get("inventory", {}).get("file_count", 0) > 0)
                recall, _ = compute_expected_recall(
                    mission_def=mission_def,
                    findings=run.findings,
                    has_inventory=has_inv or (run.nodes and run.status == "completed"),
                    firewall_blocks=run.firewall_blocks,
                    firewall_redactions=run.firewall_redactions,
                    firewall_events=last_fw_events,
                )
                verdict = run.judge
                results.append(
                    EvalCaseResult(
                        mission_id=mid,
                        mission_title=mission_def["title"],
                        strategy=strategy,
                        passed=verdict.passed if verdict else False,
                        overall_score=verdict.overall_score if verdict else 0.0,
                        recall_score=recall,
                        policy_compliance=verdict.policy_compliance if verdict else 0.0,
                        groundedness=verdict.groundedness if verdict else 0.0,
                        firewall_catches=run.firewall_blocks + run.firewall_redactions,
                        self_heals=run.self_heals,
                        total_tokens=run.total_tokens,
                        total_cost_usd=run.total_cost_usd,
                        latency_ms=run.total_latency_ms,
                    )
                )

        leaderboard: list[dict[str, Any]] = []
        for strategy in chosen_strategies:
            group = [r for r in results if r.strategy == strategy]
            count = max(1, len(group))
            leaderboard.append(
                {
                    "strategy": strategy.value,
                    "pass_rate_pct": round(100.0 * sum(1 for r in group if r.passed) / count, 1),
                    "avg_score": round(sum(r.overall_score for r in group) / count, 1),
                    "avg_recall_pct": round(sum(r.recall_score for r in group) / count, 1),
                    "avg_policy_pct": round(sum(r.policy_compliance for r in group) / count, 1),
                    "total_firewall_catches": sum(r.firewall_catches for r in group),
                    "total_self_heals": sum(r.self_heals for r in group),
                    "avg_latency_ms": round(sum(r.latency_ms for r in group) / count, 1),
                    "avg_cost_usd": round(sum(r.total_cost_usd for r in group) / count, 6),
                }
            )
        leaderboard.sort(key=lambda row: row["avg_score"], reverse=True)

        report = EvalSuiteReport(
            suite_id=f"eval_{uuid.uuid4().hex[:8]}",
            policy_mode=policy_mode,
            results=results,
            leaderboard=leaderboard,
        )
        self.db.save_eval_suite(report)
        return report

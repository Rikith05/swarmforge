"""Tests for multi-agent DAG orchestration, streaming events, time-travel fork, and run diff."""

import asyncio
import tempfile
import unittest
from pathlib import Path

from swarmforge.engine.orchestrator import SwarmOrchestrator
from swarmforge.models import ForkRequest, MissionRequest, PolicyMode, ProviderName, StrategyMode
from swarmforge.storage.db import SwarmDatabase


class TestOrchestratorAndReplay(unittest.TestCase):
    def test_council_executes_with_firewall_self_heal_and_persists_timeline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = SwarmDatabase(Path(tmp) / "test.db")
            orch = SwarmOrchestrator(db)
            seen_events = []

            async def run_flow():
                run = await orch.execute_mission(
                    MissionRequest(
                        mission_id="agent-security-audit",
                        strategy=StrategyMode.COUNCIL_JUDGE,
                        policy_mode=PolicyMode.STRICT,
                        provider=ProviderName.LOCAL,
                    ),
                    on_event=lambda ev: seen_events.append(ev.event_type),
                    pace_ms=0,
                )
                return run

            run = asyncio.run(run_flow())
            self.assertEqual(run.status, "completed")
            self.assertEqual(len(run.nodes), 5)
            self.assertGreaterEqual(run.firewall_blocks, 1)
            self.assertGreaterEqual(run.self_heals, 1)
            self.assertIsNotNone(run.judge)
            self.assertTrue(run.judge.passed)
            self.assertIn("self_heal_triggered", seen_events)
            self.assertIn("judge_verdict", seen_events)

            events = db.get_events(run.run_id)
            self.assertGreater(len(events), 10)
            sliced = db.get_events(run.run_id, up_to_seq=4)
            self.assertEqual(len(sliced), 4)

            # Fork into single_shot & compare diff
            forked = asyncio.run(
                orch.fork_run(
                    ForkRequest(
                        source_run_id=run.run_id,
                        from_seq=4,
                        strategy=StrategyMode.SINGLE_SHOT,
                        policy_mode=PolicyMode.AUDIT,
                    ),
                    pace_ms=0,
                )
            )
            self.assertEqual(forked.parent_run_id, run.run_id)
            self.assertEqual(forked.forked_from_seq, 4)

            diff = db.diff_runs(forked.run_id, run.run_id)
            self.assertIsNotNone(diff)
            self.assertGreater(diff["metrics_delta"]["judge_score_delta"], 0.0)


if __name__ == "__main__":
    unittest.main()

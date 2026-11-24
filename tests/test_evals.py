"""Tests for the automated Eval Arena multi-strategy benchmark harness."""

import asyncio
import tempfile
import unittest
from pathlib import Path

from swarmforge.evals.suite import EvalArena
from swarmforge.models import PolicyMode, StrategyMode
from swarmforge.storage.db import SwarmDatabase


class TestEvalArena(unittest.TestCase):
    def test_council_judge_achieves_100_percent_pass_and_beats_single_shot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = SwarmDatabase(Path(tmp) / "evals.db")
            arena = EvalArena(db)
            report = asyncio.run(arena.run_suite(policy_mode=PolicyMode.STRICT))

            self.assertEqual(len(report.results), 12)
            by_strategy = {row["strategy"]: row for row in report.leaderboard}
            council = by_strategy[StrategyMode.COUNCIL_JUDGE.value]
            single = by_strategy[StrategyMode.SINGLE_SHOT.value]

            self.assertEqual(council["pass_rate_pct"], 100.0)
            self.assertGreater(council["avg_score"], single["avg_score"])
            self.assertGreater(council["total_self_heals"], 0)

            saved = db.list_eval_suites()
            self.assertEqual(len(saved), 1)
            self.assertEqual(saved[0].suite_id, report.suite_id)


if __name__ == "__main__":
    unittest.main()

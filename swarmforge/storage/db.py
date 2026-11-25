"""SQLite persistence for SwarmForge runs, event timelines, and eval suites."""

from __future__ import annotations

from contextlib import closing
import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import Any

from swarmforge.models import EvalSuiteReport, RunEvent, RunRecord


def default_db_path() -> Path:
    env_path = os.environ.get("SWARMFORGE_DB_PATH")
    if env_path:
        return Path(env_path)
    return Path.cwd() / ".swarmforge" / "swarmforge.db"


class SwarmDatabase:
    """Thread-safe SQLite repository storing runs, time-travel events, and eval suites."""

    def __init__(self, db_path: Path | str | None = None) -> None:
        self.db_path = Path(db_path) if db_path else default_db_path()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._lock, closing(self._connect()) as conn, conn:
            conn.executescript(
                """
                PRAGMA journal_mode=WAL;

                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    mission_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    strategy TEXT NOT NULL,
                    policy_mode TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    status TEXT NOT NULL,
                    parent_run_id TEXT,
                    forked_from_seq INTEGER,
                    created_at TEXT NOT NULL,
                    completed_at TEXT,
                    payload_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS run_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    node_id TEXT,
                    agent_role TEXT,
                    title TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    UNIQUE(run_id, seq)
                );

                CREATE INDEX IF NOT EXISTS idx_events_run_seq
                    ON run_events(run_id, seq);

                CREATE TABLE IF NOT EXISTS eval_suites (
                    suite_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    policy_mode TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );
                """
            )

    def save_run(self, run: RunRecord) -> None:
        payload = run.model_dump_json()
        with self._lock, closing(self._connect()) as conn, conn:
            conn.execute(
                """
                INSERT INTO runs (
                    run_id, mission_id, title, strategy, policy_mode,
                    provider, status, parent_run_id, forked_from_seq,
                    created_at, completed_at, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    status = excluded.status,
                    completed_at = excluded.completed_at,
                    payload_json = excluded.payload_json
                """,
                (
                    run.run_id,
                    run.mission_id,
                    run.title,
                    run.strategy.value,
                    run.policy_mode.value,
                    run.provider.value,
                    run.status,
                    run.parent_run_id,
                    run.forked_from_seq,
                    run.created_at,
                    run.completed_at,
                    payload,
                ),
            )

    def append_event(self, event: RunEvent) -> None:
        payload = event.model_dump_json()
        with self._lock, closing(self._connect()) as conn, conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO run_events (
                    run_id, seq, timestamp, event_type, node_id, agent_role, title, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.run_id,
                    event.seq,
                    event.timestamp,
                    event.event_type,
                    event.node_id,
                    event.agent_role,
                    event.title,
                    payload,
                ),
            )

    def get_run(self, run_id: str) -> RunRecord | None:
        with self._lock, closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT payload_json FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
        if not row:
            return None
        return RunRecord.model_validate_json(row["payload_json"])

    def list_runs(self, limit: int = 40) -> list[dict[str, Any]]:
        with self._lock, closing(self._connect()) as conn:
            rows = conn.execute(
                """
                SELECT payload_json FROM runs
                ORDER BY created_at DESC, rowid DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        summaries: list[dict[str, Any]] = []
        for row in rows:
            run = RunRecord.model_validate_json(row["payload_json"])
            summaries.append(
                {
                    "run_id": run.run_id,
                    "mission_id": run.mission_id,
                    "title": run.title,
                    "strategy": run.strategy.value,
                    "policy_mode": run.policy_mode.value,
                    "provider": run.provider.value,
                    "status": run.status,
                    "parent_run_id": run.parent_run_id,
                    "forked_from_seq": run.forked_from_seq,
                    "created_at": run.created_at,
                    "completed_at": run.completed_at,
                    "total_tokens": run.total_tokens,
                    "total_cost_usd": run.total_cost_usd,
                    "total_latency_ms": run.total_latency_ms,
                    "firewall_blocks": run.firewall_blocks,
                    "firewall_redactions": run.firewall_redactions,
                    "self_heals": run.self_heals,
                    "judge_score": run.judge.overall_score if run.judge else None,
                    "judge_passed": run.judge.passed if run.judge else None,
                }
            )
        return summaries

    def get_events(self, run_id: str, up_to_seq: int | None = None) -> list[RunEvent]:
        with self._lock, closing(self._connect()) as conn:
            if up_to_seq is not None:
                rows = conn.execute(
                    """
                    SELECT payload_json FROM run_events
                    WHERE run_id = ? AND seq <= ?
                    ORDER BY seq ASC
                    """,
                    (run_id, up_to_seq),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT payload_json FROM run_events
                    WHERE run_id = ?
                    ORDER BY seq ASC
                    """,
                    (run_id,),
                ).fetchall()
        return [RunEvent.model_validate_json(r["payload_json"]) for r in rows]

    def diff_runs(self, run_id_a: str, run_id_b: str) -> dict[str, Any] | None:
        run_a = self.get_run(run_id_a)
        run_b = self.get_run(run_id_b)
        if not run_a or not run_b:
            return None

        events_a = self.get_events(run_id_a)
        events_b = self.get_events(run_id_b)
        titles_a = {f"{f.get('severity','')}:{f.get('title','')}" for f in run_a.findings}
        titles_b = {f"{f.get('severity','')}:{f.get('title','')}" for f in run_b.findings}

        node_map_a = {n.id: n for n in run_a.nodes}
        node_map_b = {n.id: n for n in run_b.nodes}
        all_node_ids = list(dict.fromkeys([*node_map_a.keys(), *node_map_b.keys()]))
        node_comparison = []
        for nid in all_node_ids:
            na = node_map_a.get(nid)
            nb = node_map_b.get(nid)
            node_comparison.append(
                {
                    "node_id": nid,
                    "a_status": na.status.value if na else "absent",
                    "b_status": nb.status.value if nb else "absent",
                    "a_latency_ms": na.latency_ms if na else 0.0,
                    "b_latency_ms": nb.latency_ms if nb else 0.0,
                    "a_attempts": na.attempts if na else 0,
                    "b_attempts": nb.attempts if nb else 0,
                }
            )

        return {
            "run_a": run_a.model_dump(),
            "run_b": run_b.model_dump(),
            "metrics_delta": {
                "tokens_delta": run_b.total_tokens - run_a.total_tokens,
                "cost_delta_usd": round(run_b.total_cost_usd - run_a.total_cost_usd, 6),
                "latency_delta_ms": round(run_b.total_latency_ms - run_a.total_latency_ms, 2),
                "firewall_blocks_delta": run_b.firewall_blocks - run_a.firewall_blocks,
                "self_heals_delta": run_b.self_heals - run_a.self_heals,
                "judge_score_delta": round(
                    (run_b.judge.overall_score if run_b.judge else 0.0)
                    - (run_a.judge.overall_score if run_a.judge else 0.0),
                    2,
                ),
                "event_count_a": len(events_a),
                "event_count_b": len(events_b),
            },
            "findings_only_in_a": sorted(titles_a - titles_b),
            "findings_only_in_b": sorted(titles_b - titles_a),
            "shared_findings": sorted(titles_a & titles_b),
            "node_comparison": node_comparison,
        }

    def save_eval_suite(self, report: EvalSuiteReport) -> None:
        with self._lock, closing(self._connect()) as conn, conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO eval_suites (suite_id, created_at, policy_mode, payload_json)
                VALUES (?, ?, ?, ?)
                """,
                (
                    report.suite_id,
                    report.created_at,
                    report.policy_mode.value,
                    report.model_dump_json(),
                ),
            )

    def list_eval_suites(self, limit: int = 10) -> list[EvalSuiteReport]:
        with self._lock, closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT payload_json FROM eval_suites ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [EvalSuiteReport.model_validate_json(r["payload_json"]) for r in rows]

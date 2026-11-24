"""Rich CLI entry point for SwarmForge orchestration, scanning, evals, and Web Studio."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

import uvicorn
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from swarmforge import __version__
from swarmforge.engine.orchestrator import SwarmOrchestrator
from swarmforge.evals.suite import EvalArena
from swarmforge.models import MissionRequest, PolicyMode, ProviderName, StrategyMode
from swarmforge.server import create_app
from swarmforge.storage.db import SwarmDatabase

console = Console()


async def _run_mission_cli(args: argparse.Namespace) -> int:
    db = SwarmDatabase(db_path=args.db)
    orch = SwarmOrchestrator(db)
    req = MissionRequest(
        mission_id=args.mission,
        target_path=args.path,
        strategy=StrategyMode(args.strategy),
        policy_mode=PolicyMode(args.policy),
        provider=ProviderName(args.provider),
    )
    run = await orch.execute_mission(req, pace_ms=0)

    table = Table(title=f"SwarmForge Run {run.run_id} — {run.title}")
    table.add_column("Node", style="cyan")
    table.add_column("Role", style="magenta")
    table.add_column("Status", style="green")
    table.add_column("Latency", justify="right")
    table.add_column("Summary")
    for n in run.nodes:
        table.add_row(n.label, n.role, n.status.value, f"{n.latency_ms:.0f} ms", n.summary[:90])
    console.print(table)

    score = run.judge.overall_score if run.judge else 0.0
    console.print(
        Panel(
            f"Findings: [bold]{len(run.findings)}[/bold] | Patches: [bold]{len(run.patches)}[/bold] | "
            f"Firewall Blocks: [bold]{run.firewall_blocks}[/bold] | Self-Heals: [bold]{run.self_heals}[/bold] | "
            f"Judge Score: [bold]{score:.1f}/100[/bold]",
            title="Mission Summary",
        )
    )

    if args.export:
        out = Path(args.export)
        out.write_text(run.final_report_md, encoding="utf-8")
        console.print(f"[green]Exported Markdown report to {out}[/green]")
    return 0


async def _run_eval_cli(args: argparse.Namespace) -> int:
    db = SwarmDatabase(db_path=args.db)
    arena = EvalArena(db)
    report = await arena.run_suite(policy_mode=PolicyMode(args.policy))

    table = Table(title=f"SwarmForge Eval Arena ({report.suite_id}) — Policy: {report.policy_mode.value}")
    table.add_column("Strategy", style="cyan")
    table.add_column("Pass Rate", justify="right")
    table.add_column("Avg Score", justify="right", style="green")
    table.add_column("Avg Recall", justify="right")
    table.add_column("Policy Compliance", justify="right")
    table.add_column("Firewall Catches", justify="right")
    table.add_column("Self-Heals", justify="right")
    for row in report.leaderboard:
        table.add_row(
            row["strategy"],
            f"{row['pass_rate_pct']}%",
            f"{row['avg_score']}",
            f"{row['avg_recall_pct']}%",
            f"{row['avg_policy_pct']}%",
            str(row["total_firewall_catches"]),
            str(row["total_self_heals"]),
        )
    console.print(table)

    if args.export:
        out = Path(args.export)
        out.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        console.print(f"[green]Exported eval report to {out}[/green]")

    if args.strict:
        council_rows = [r for r in report.leaderboard if r["strategy"] == StrategyMode.COUNCIL_JUDGE.value]
        if not council_rows or council_rows[0]["pass_rate_pct"] < 100.0:
            console.print("[red]Strict eval gate failed: council_judge did not pass 100% of missions.[/red]")
            return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="swarmforge",
        description="SwarmForge — Multi-Agent DAG Orchestrator, Policy Firewall & Eval Studio",
    )
    parser.add_argument("--version", action="version", version=f"swarmforge {__version__}")
    parser.add_argument("--db", default=None, help="Optional path to SQLite database file.")
    sub = parser.add_subparsers(dest="command", required=True)

    serve_p = sub.add_parser("serve", help="Start the SwarmForge Web Studio and API server.")
    serve_p.add_argument("--host", default="127.0.0.1")
    serve_p.add_argument("--port", type=int, default=8765)

    run_p = sub.add_parser("run", help="Execute a multi-agent mission from CLI.")
    run_p.add_argument("--mission", default="agent-security-audit")
    run_p.add_argument("--path", default=None, help="Optional directory or file path to audit.")
    run_p.add_argument("--strategy", default="council_judge", choices=[s.value for s in StrategyMode])
    run_p.add_argument("--policy", default="strict", choices=[p.value for p in PolicyMode])
    run_p.add_argument("--provider", default="local-engine", choices=[p.value for p in ProviderName])
    run_p.add_argument("--export", default=None, help="Export Markdown report path.")

    scan_p = sub.add_parser("scan", help="Scan a local repository directory using the Council DAG.")
    scan_p.add_argument("path", help="Directory or file path to scan.")
    scan_p.add_argument("--policy", default="strict", choices=[p.value for p in PolicyMode])
    scan_p.add_argument("--export", default=None, help="Export Markdown report path.")

    eval_p = sub.add_parser("eval", help="Run the multi-strategy Eval Arena benchmark matrix.")
    eval_p.add_argument("--policy", default="strict", choices=[p.value for p in PolicyMode])
    eval_p.add_argument("--export", default=None, help="Export JSON benchmark report path.")
    eval_p.add_argument("--strict", action="store_true", help="Exit non-zero if council_judge pass rate < 100%%.")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "serve":
        app = create_app(db_path=args.db, seed_demo=True)
        console.print(f"[cyan]SwarmForge Studio[/cyan] listening at http://{args.host}:{args.port}")
        uvicorn.run(app, host=args.host, port=args.port, log_level="info")
        return 0

    if args.command == "scan":
        args.mission = "codebase-architecture-audit"
        args.strategy = "council_judge"
        args.provider = "local-engine"
        return asyncio.run(_run_mission_cli(args))

    if args.command == "run":
        return asyncio.run(_run_mission_cli(args))

    if args.command == "eval":
        return asyncio.run(_run_eval_cli(args))

    return 1


if __name__ == "__main__":
    sys.exit(main())

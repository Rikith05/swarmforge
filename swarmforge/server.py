"""FastAPI server providing REST, SSE live streaming, and the SwarmForge Web Studio."""

from __future__ import annotations

import asyncio
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from swarmforge import __version__
from swarmforge.engine.orchestrator import SwarmOrchestrator
from swarmforge.evals.suite import EvalArena
from swarmforge.firewall.policy import ROLE_CAPABILITIES, PolicyFirewall
from swarmforge.models import (
    FirewallTestRequest,
    ForkRequest,
    MissionRequest,
    PolicyMode,
    ProviderName,
    RunEvent,
    StrategyMode,
)
from swarmforge.storage.db import SwarmDatabase
from swarmforge.tools.fixtures import MISSION_CATALOG

WEB_DIR = Path(__file__).resolve().parent / "web"


def create_app(db_path: Path | str | None = None, seed_demo: bool = True) -> FastAPI:
    db = SwarmDatabase(db_path=db_path)
    orchestrator = SwarmOrchestrator(db)
    arena = EvalArena(db)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        if seed_demo and not db.list_runs(limit=1):
            # Seed two contrasting runs so Time-Travel Replay & Diff work immediately on first visit.
            await orchestrator.execute_mission(
                MissionRequest(
                    mission_id="agent-security-audit",
                    title="Baseline: Single-Shot Audit (Unverified)",
                    strategy=StrategyMode.SINGLE_SHOT,
                    policy_mode=PolicyMode.AUDIT,
                    provider=ProviderName.LOCAL,
                ),
                pace_ms=0,
            )
            await orchestrator.execute_mission(
                MissionRequest(
                    mission_id="agent-security-audit",
                    title="Baseline: Council + Policy Firewall + Judge",
                    strategy=StrategyMode.COUNCIL_JUDGE,
                    policy_mode=PolicyMode.STRICT,
                    provider=ProviderName.LOCAL,
                ),
                pace_ms=0,
            )
        yield

    app = FastAPI(
        title="SwarmForge Studio API",
        version=__version__,
        description="Autonomous Multi-Agent DAG Orchestrator, Policy Firewall & Eval Studio",
        lifespan=lifespan,
    )
    app.state.db = db
    app.state.orchestrator = orchestrator
    app.state.arena = arena

    if WEB_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")

    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(WEB_DIR / "index.html")

    @app.get("/api/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "version": __version__,
            "providers": {
                "local-engine": True,
                "gemini": bool(os.environ.get("GEMINI_API_KEY")),
                "openai": bool(os.environ.get("OPENAI_API_KEY")),
                "anthropic": bool(os.environ.get("ANTHROPIC_API_KEY")),
                "ollama": bool(os.environ.get("OLLAMA_BASE_URL")),
            },
        }

    @app.get("/api/missions")
    async def list_missions() -> dict[str, Any]:
        missions = []
        for mid, data in MISSION_CATALOG.items():
            missions.append(
                {
                    "mission_id": mid,
                    "title": data["title"],
                    "subtitle": data["subtitle"],
                    "objective": data["objective"],
                    "expected_findings": data.get("expected_findings", []),
                    "file_names": sorted((data.get("virtual_files") or {}).keys()),
                }
            )
        return {
            "missions": missions,
            "role_capabilities": {k: sorted(v) for k, v in ROLE_CAPABILITIES.items()},
        }

    @app.get("/api/runs")
    async def list_runs(limit: int = Query(default=40, ge=1, le=200)) -> dict[str, Any]:
        return {"runs": db.list_runs(limit=limit)}

    @app.post("/api/runs")
    async def create_run(req: MissionRequest) -> dict[str, Any]:
        run = await orchestrator.execute_mission(req, pace_ms=0)
        return {"run": run.model_dump()}

    @app.post("/api/runs/stream")
    async def stream_run(req: MissionRequest) -> StreamingResponse:
        queue: asyncio.Queue[tuple[str, str] | None] = asyncio.Queue()

        async def on_event(ev: RunEvent) -> None:
            await queue.put(("run_event", ev.model_dump_json()))

        async def runner() -> None:
            try:
                run = await orchestrator.execute_mission(req, on_event=on_event, pace_ms=55)
                await queue.put(("run_done", json.dumps({"run": run.model_dump()})))
            except Exception as exc:
                await queue.put(("run_error", json.dumps({"error": str(exc)})))
            finally:
                await queue.put(None)

        asyncio.create_task(runner())

        async def event_generator():
            while True:
                item = await queue.get()
                if item is None:
                    break
                ev_name, payload = item
                yield f"event: {ev_name}\ndata: {payload}\n\n"

        return StreamingResponse(event_generator(), media_type="text/event-stream")

    @app.get("/api/runs/diff/{run_id_a}/{run_id_b}")
    async def diff_runs(run_id_a: str, run_id_b: str) -> dict[str, Any]:
        diff = db.diff_runs(run_id_a, run_id_b)
        if not diff:
            raise HTTPException(status_code=404, detail="One or both run IDs were not found.")
        return diff

    @app.get("/api/runs/{run_id}")
    async def get_run(run_id: str) -> dict[str, Any]:
        run = db.get_run(run_id)
        if not run:
            raise HTTPException(status_code=404, detail="Run not found.")
        return {"run": run.model_dump()}

    @app.get("/api/runs/{run_id}/events")
    async def get_run_events(
        run_id: str, up_to_seq: int | None = Query(default=None, ge=1)
    ) -> dict[str, Any]:
        run = db.get_run(run_id)
        if not run:
            raise HTTPException(status_code=404, detail="Run not found.")
        events = db.get_events(run_id, up_to_seq=up_to_seq)
        return {"run_id": run_id, "events": [e.model_dump() for e in events]}

    @app.post("/api/runs/{run_id}/fork")
    async def fork_run(run_id: str, body: ForkRequest) -> dict[str, Any]:
        if body.source_run_id != run_id:
            body.source_run_id = run_id
        try:
            forked = await orchestrator.fork_run(body, pace_ms=0)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {"run": forked.model_dump()}

    @app.post("/api/firewall/test")
    async def test_firewall(req: FirewallTestRequest) -> dict[str, Any]:
        fw = PolicyFirewall(mode=req.policy_mode, rules=req.rules)
        decision = fw.evaluate(
            agent_role=req.agent_role,
            tool_name=req.tool_name,
            arguments=req.arguments,
        )
        return {"decision": decision.model_dump()}

    @app.get("/api/evals")
    async def list_evals() -> dict[str, Any]:
        suites = db.list_eval_suites(limit=10)
        return {"suites": [s.model_dump() for s in suites]}

    @app.post("/api/evals/run")
    async def run_evals(policy_mode: PolicyMode = PolicyMode.STRICT) -> dict[str, Any]:
        report = await arena.run_suite(policy_mode=policy_mode)
        return {"suite": report.model_dump()}

    return app


app = create_app()

"""Pydantic data models for SwarmForge orchestration, policy firewall, and evals."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


def utc_now_iso() -> str:
    """Return an ISO-8601 UTC timestamp string."""
    return datetime.now(timezone.utc).isoformat()


class StrategyMode(str, Enum):
    COUNCIL_JUDGE = "council_judge"
    PLAN_EXECUTE = "plan_execute"
    SINGLE_SHOT = "single_shot"


class PolicyMode(str, Enum):
    STRICT = "strict"
    BALANCED = "balanced"
    AUDIT = "audit"


class ProviderName(str, Enum):
    LOCAL = "local-engine"
    GEMINI = "gemini"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"


class NodeStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    BLOCKED = "blocked_by_policy"
    RETRYING = "retrying"
    VERIFIED = "verified"
    FAILED = "failed"


class FirewallAction(str, Enum):
    ALLOW = "allow"
    REDACT = "redact"
    BLOCK = "block"
    WARN = "warn"


class PolicyRuleConfig(BaseModel):
    """Toggleable guardrail engines inside the Policy Firewall."""

    capability_rbac: bool = True
    secret_dlp: bool = True
    prompt_injection_guard: bool = True
    filesystem_sandbox: bool = True
    loop_budget_breaker: bool = True


class MissionRequest(BaseModel):
    """Request payload to compile and execute a multi-agent DAG mission."""

    mission_id: str = "agent-security-audit"
    title: str | None = None
    objective: str | None = None
    target_path: str | None = None
    target_code: str | None = None
    strategy: StrategyMode = StrategyMode.COUNCIL_JUDGE
    policy_mode: PolicyMode = PolicyMode.STRICT
    rules: PolicyRuleConfig = Field(default_factory=PolicyRuleConfig)
    provider: ProviderName = ProviderName.LOCAL
    model: str | None = None
    api_key: str | None = Field(default=None, exclude=True)
    max_budget_usd: float = 0.25
    max_tool_hops: int = 18


class ForkRequest(BaseModel):
    """Request payload to fork and replay a historical run from a checkpoint step."""

    source_run_id: str
    from_seq: int = 1
    strategy: StrategyMode | None = None
    policy_mode: PolicyMode | None = None
    rules: PolicyRuleConfig | None = None
    provider: ProviderName | None = None


class FirewallTestRequest(BaseModel):
    """Interactive payload for testing the Policy Firewall directly."""

    agent_role: str = "red_team"
    tool_name: str = "shell_exec"
    arguments: dict[str, Any] = Field(default_factory=dict)
    policy_mode: PolicyMode = PolicyMode.STRICT
    rules: PolicyRuleConfig = Field(default_factory=PolicyRuleConfig)


class FirewallFinding(BaseModel):
    engine: str
    severity: str
    code: str
    message: str


class FirewallDecision(BaseModel):
    action: FirewallAction
    allowed: bool
    agent_role: str
    tool_name: str
    sanitized_args: dict[str, Any] = Field(default_factory=dict)
    findings: list[FirewallFinding] = Field(default_factory=list)
    latency_ms: float = 0.0


class DAGNode(BaseModel):
    id: str
    label: str
    role: str
    description: str
    layer: int
    depends_on: list[str] = Field(default_factory=list)
    allowed_tools: list[str] = Field(default_factory=list)
    status: NodeStatus = NodeStatus.QUEUED
    attempts: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    latency_ms: float = 0.0
    summary: str = ""
    artifacts: dict[str, Any] = Field(default_factory=dict)


class DAGEdge(BaseModel):
    source: str
    target: str
    kind: str = "dependency"


class RunEvent(BaseModel):
    seq: int
    run_id: str
    timestamp: str = Field(default_factory=utc_now_iso)
    event_type: str
    node_id: str | None = None
    agent_role: str | None = None
    title: str
    detail: dict[str, Any] = Field(default_factory=dict)
    blackboard_snapshot: dict[str, Any] | None = None


class JudgeVerdict(BaseModel):
    passed: bool
    overall_score: float
    groundedness: float
    policy_compliance: float
    completeness: float
    assertions: list[dict[str, Any]] = Field(default_factory=list)
    remediation_notes: list[str] = Field(default_factory=list)


class RunRecord(BaseModel):
    run_id: str
    mission_id: str
    title: str
    objective: str
    strategy: StrategyMode
    policy_mode: PolicyMode
    provider: ProviderName
    status: str = "running"
    parent_run_id: str | None = None
    forked_from_seq: int | None = None
    created_at: str = Field(default_factory=utc_now_iso)
    completed_at: str | None = None
    nodes: list[DAGNode] = Field(default_factory=list)
    edges: list[DAGEdge] = Field(default_factory=list)
    total_tokens: int = 0
    total_cost_usd: float = 0.0
    total_latency_ms: float = 0.0
    firewall_blocks: int = 0
    firewall_redactions: int = 0
    self_heals: int = 0
    judge: JudgeVerdict | None = None
    final_report_md: str = ""
    patches: list[dict[str, Any]] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)


class EvalCaseResult(BaseModel):
    mission_id: str
    mission_title: str
    strategy: StrategyMode
    passed: bool
    overall_score: float
    recall_score: float
    policy_compliance: float
    groundedness: float
    firewall_catches: int
    self_heals: int
    total_tokens: int
    total_cost_usd: float
    latency_ms: float


class EvalSuiteReport(BaseModel):
    suite_id: str
    created_at: str = Field(default_factory=utc_now_iso)
    policy_mode: PolicyMode
    results: list[EvalCaseResult] = Field(default_factory=list)
    leaderboard: list[dict[str, Any]] = Field(default_factory=list)

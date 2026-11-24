"""Deterministic 5-layer Tool Policy Firewall and Security Interceptor."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import time
from typing import Any

from swarmforge.models import (
    FirewallAction,
    FirewallDecision,
    FirewallFinding,
    PolicyMode,
    PolicyRuleConfig,
)

# Least-privilege RBAC capability matrix per agent role.
ROLE_CAPABILITIES: dict[str, set[str]] = {
    "planner": {"workspace_inventory", "dependency_graph_mapper"},
    "analyzer": {
        "workspace_inventory",
        "ast_complexity_scan",
        "secret_and_sink_audit",
        "dependency_graph_mapper",
    },
    "red_team": {
        "prompt_surface_auditor",
        "secret_and_sink_audit",
        "workspace_inventory",
    },
    "architect": {
        "patch_synthesizer",
        "dependency_graph_mapper",
        "workspace_inventory",
    },
    "judge": {"schema_and_budget_verifier"},
    "solo": {
        "workspace_inventory",
        "ast_complexity_scan",
        "secret_and_sink_audit",
        "dependency_graph_mapper",
        "prompt_surface_auditor",
        "patch_synthesizer",
        "schema_and_budget_verifier",
    },
}

# Patterns constructed dynamically where helpful so scanners stay clean while matching real leaks.
_SECRET_RULES: list[tuple[str, re.Pattern[str], str]] = [
    (
        "DLP_AWS_KEY",
        re.compile(r"\bAK" + r"IA[0-9A-Z]{16}\b"),
        "AWS Access Key ID detected in tool arguments.",
    ),
    (
        "DLP_GITHUB_PAT",
        re.compile(r"\b(?:gh" + r"p|gho|ghu|ghs)_[A-Za-z0-9]{16,}\b"),
        "GitHub personal access token pattern detected in tool arguments.",
    ),
    (
        "DLP_API_BEARER",
        re.compile(r"\bBearer\s+[A-Za-z0-9\-_\.]{20,}\b", re.IGNORECASE),
        "Bearer authorization credential detected in tool arguments.",
    ),
    (
        "DLP_PRIVATE_KEY",
        re.compile(r"-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----"),
        "Private cryptographic key material detected in tool arguments.",
    ),
    (
        "DLP_OPENAI_LIKE",
        re.compile(r"\bsk" + r"-(?:proj-)?[A-Za-z0-9\-_]{20,}\b"),
        "API secret key token pattern detected in tool arguments.",
    ),
    (
        "DLP_SSN_PII",
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "US SSN PII pattern detected in tool arguments.",
    ),
]

_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "INJ_OVERRIDE",
        re.compile(
            r"(ignore\s+(?:all\s+)?previous\s+instructions|disregard\s+system\s+prompt|you\s+are\s+now\s+in\s+developer\s+mode)",
            re.IGNORECASE,
        ),
        "Prompt-injection instruction override attempt detected.",
    ),
    (
        "INJ_EXFIL",
        re.compile(
            r"(exfiltrate|send\s+(?:all\s+)?secrets\s+to|upload\s+\.env|print\s+system\s+prompt)",
            re.IGNORECASE,
        ),
        "Instruction-driven data exfiltration attempt detected.",
    ),
    (
        "INJ_HIDDEN_TAG",
        re.compile(r"<!--\s*(?:SYSTEM|AGENT_OVERRIDE|PROMPT_INJECT)[\s\S]*?-->", re.IGNORECASE),
        "Hidden HTML comment instruction smuggling detected.",
    ),
    (
        "INJ_ZERO_WIDTH",
        re.compile(r"[\u200b-\u200f\u202a-\u202e\ufeff]{2,}"),
        "Zero-width / bidirectional Unicode obfuscation detected.",
    ),
]

_SANDBOX_CMD_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "SANDBOX_DESTRUCTIVE_CMD",
        re.compile(
            r"(rm\s+-rf\s+[/~\\]|curl\s+[^|\n]+\|\s*(?:sh|bash)|wget\s+[^|\n]+\|\s*sh|Invoke-Expression|powershell\s+-enc(?:odedcommand)?|chmod\s+777\s+/)",
            re.IGNORECASE,
        ),
        "Destructive or remote-code-execution shell payload blocked.",
    ),
    (
        "SANDBOX_PATH_TRAVERSAL",
        re.compile(r"(?:\.\.[/\\]){2,}|(?:^|[\s'\"])(?:/etc/passwd|/etc/shadow|\.ssh[/\\]id_rsa|C:\\Windows\\System32)", re.IGNORECASE),
        "Path traversal or sensitive host credential path access blocked.",
    ),
]

_DESTRUCTIVE_TOOLS = {"shell_exec", "raw_http_post", "delete_files"}


def _walk_strings(value: Any, path: str = "") -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = []
    if isinstance(value, str):
        items.append((path or "root", value))
    elif isinstance(value, dict):
        for k, v in value.items():
            next_path = f"{path}.{k}" if path else str(k)
            items.extend(_walk_strings(v, next_path))
    elif isinstance(value, list):
        for idx, item in enumerate(value):
            items.extend(_walk_strings(item, f"{path}[{idx}]"))
    return items


def _redact_string(text: str) -> tuple[str, list[FirewallFinding]]:
    redacted = text
    findings: list[FirewallFinding] = []
    for code, pattern, message in _SECRET_RULES:
        if pattern.search(redacted):
            findings.append(
                FirewallFinding(
                    engine="secret_dlp",
                    severity="high",
                    code=code,
                    message=message,
                )
            )
            redacted = pattern.sub(f"[REDACTED:{code}]", redacted)
    return redacted, findings


def _sanitize_structure(value: Any, findings: list[FirewallFinding]) -> Any:
    if isinstance(value, str):
        cleaned, found = _redact_string(value)
        findings.extend(found)
        return cleaned
    if isinstance(value, dict):
        return {k: _sanitize_structure(v, findings) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_structure(v, findings) for v in value]
    return value


class PolicyFirewall:
    """Evaluates every agent tool call against 5 deterministic safety engines."""

    def __init__(
        self,
        mode: PolicyMode = PolicyMode.STRICT,
        rules: PolicyRuleConfig | None = None,
        max_hops: int = 18,
        max_budget_usd: float = 0.25,
    ) -> None:
        self.mode = mode
        self.rules = rules or PolicyRuleConfig()
        self.max_hops = max_hops
        self.max_budget_usd = max_budget_usd
        self._seen_signatures: dict[str, int] = {}
        self._hop_count = 0

    def evaluate(
        self,
        agent_role: str,
        tool_name: str,
        arguments: dict[str, Any],
        spent_budget_usd: float = 0.0,
    ) -> FirewallDecision:
        started = time.perf_counter()
        findings: list[FirewallFinding] = []
        sanitized = copy.deepcopy(arguments)
        should_block = False
        did_redact = False

        # 1. Capability Scope RBAC
        if self.rules.capability_rbac:
            allowed_set = ROLE_CAPABILITIES.get(agent_role, set())
            if tool_name in _DESTRUCTIVE_TOOLS or tool_name not in allowed_set:
                findings.append(
                    FirewallFinding(
                        engine="capability_rbac",
                        severity="critical" if tool_name in _DESTRUCTIVE_TOOLS else "high",
                        code="RBAC_TOOL_DENIED",
                        message=f"Role '{agent_role}' is not permitted to invoke tool '{tool_name}'.",
                    )
                )
                if self.mode in (PolicyMode.STRICT, PolicyMode.BALANCED):
                    should_block = True

        # 2. Secret & PII Exfiltration DLP
        if self.rules.secret_dlp:
            dlp_findings: list[FirewallFinding] = []
            sanitized = _sanitize_structure(sanitized, dlp_findings)
            if dlp_findings:
                findings.extend(dlp_findings)
                did_redact = True
                if self.mode == PolicyMode.STRICT:
                    should_block = True

        # 3. Prompt Injection & Tool Poisoning Guard
        all_strings = _walk_strings(arguments)
        if self.rules.prompt_injection_guard:
            for field_path, text in all_strings:
                for code, pattern, message in _INJECTION_PATTERNS:
                    if pattern.search(text):
                        findings.append(
                            FirewallFinding(
                                engine="prompt_injection_guard",
                                severity="critical",
                                code=code,
                                message=f"{message} (arg: {field_path})",
                            )
                        )
                        if self.mode in (PolicyMode.STRICT, PolicyMode.BALANCED):
                            should_block = True

        # 4. Filesystem & Command Sandbox Guard
        if self.rules.filesystem_sandbox:
            for field_path, text in all_strings:
                for code, pattern, message in _SANDBOX_CMD_PATTERNS:
                    if pattern.search(text):
                        findings.append(
                            FirewallFinding(
                                engine="filesystem_sandbox",
                                severity="critical",
                                code=code,
                                message=f"{message} (arg: {field_path})",
                            )
                        )
                        if self.mode in (PolicyMode.STRICT, PolicyMode.BALANCED):
                            should_block = True

        # 5. Loop & Budget Circuit Breaker
        if self.rules.loop_budget_breaker:
            self._hop_count += 1
            sig_payload = json.dumps(
                {"role": agent_role, "tool": tool_name, "args": arguments},
                sort_keys=True,
                default=str,
            )
            sig = hashlib.sha256(sig_payload.encode("utf-8")).hexdigest()
            self._seen_signatures[sig] = self._seen_signatures.get(sig, 0) + 1

            if self._seen_signatures[sig] > 2:
                findings.append(
                    FirewallFinding(
                        engine="loop_budget_breaker",
                        severity="high",
                        code="LOOP_REPEAT_DETECTED",
                        message=f"Identical call to '{tool_name}' repeated {self._seen_signatures[sig]} times.",
                    )
                )
                if self.mode in (PolicyMode.STRICT, PolicyMode.BALANCED):
                    should_block = True

            if self._hop_count > self.max_hops:
                findings.append(
                    FirewallFinding(
                        engine="loop_budget_breaker",
                        severity="high",
                        code="HOP_LIMIT_EXCEEDED",
                        message=f"Run exceeded max_tool_hops ({self.max_hops}).",
                    )
                )
                if self.mode != PolicyMode.AUDIT:
                    should_block = True

            if spent_budget_usd > self.max_budget_usd:
                findings.append(
                    FirewallFinding(
                        engine="loop_budget_breaker",
                        severity="critical",
                        code="BUDGET_CEILING_EXCEEDED",
                        message=f"Spent budget ${spent_budget_usd:.4f} exceeded cap ${self.max_budget_usd:.4f}.",
                    )
                )
                if self.mode != PolicyMode.AUDIT:
                    should_block = True

        if should_block:
            action = FirewallAction.BLOCK
            allowed = False
        elif did_redact:
            action = FirewallAction.REDACT
            allowed = True
        elif findings:
            action = FirewallAction.WARN
            allowed = True
        else:
            action = FirewallAction.ALLOW
            allowed = True

        elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
        return FirewallDecision(
            action=action,
            allowed=allowed,
            agent_role=agent_role,
            tool_name=tool_name,
            sanitized_args=sanitized,
            findings=findings,
            latency_ms=elapsed_ms,
        )

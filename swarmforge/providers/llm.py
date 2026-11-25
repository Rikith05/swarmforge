"""Async inference adapter for local-engine, Gemini, OpenAI, Anthropic, and Ollama."""

from __future__ import annotations

import os
from typing import Any
import httpx

from swarmforge.models import ProviderName


def _estimate_tokens(text: str) -> int:
    return max(16, len(text) // 4)


class ProviderClient:
    """Routes agent synthesis either to local grounded reasoning or BYOK LLM endpoints."""

    def __init__(self, provider: ProviderName, model: str | None = None, api_key: str | None = None) -> None:
        self.provider = provider
        self.model = model
        self.api_key = api_key

    def _resolve_key(self) -> str | None:
        if self.api_key:
            return self.api_key
        env_map = {
            ProviderName.GEMINI: "GEMINI_API_KEY",
            ProviderName.OPENAI: "OPENAI_API_KEY",
            ProviderName.ANTHROPIC: "ANTHROPIC_API_KEY",
        }
        var = env_map.get(self.provider)
        return os.environ.get(var) if var else None

    async def synthesize(
        self,
        agent_role: str,
        objective: str,
        tool_evidence: dict[str, Any],
        fallback_summary: str,
    ) -> dict[str, Any]:
        prompt = (
            f"Role: {agent_role}\nObjective: {objective}\n"
            f"Evidence JSON: {str(tool_evidence)[:3200]}\n"
            "Summarize key verified findings concisely with file citations."
        )
        tokens_in = _estimate_tokens(prompt)

        if self.provider == ProviderName.LOCAL:
            tokens_out = _estimate_tokens(fallback_summary)
            return {
                "text": fallback_summary,
                "tokens_in": tokens_in,
                "tokens_out": tokens_out,
                "cost_usd": round((tokens_in + tokens_out) * 0.0000005, 6),
                "mode": "local-deterministic",
            }

        live_text, err_reason = await self._call_remote(prompt)
        if live_text:
            text = live_text
            mode = self.provider.value
        else:
            reason = err_reason or "provider unavailable"
            text = f"{fallback_summary} (fallback: {reason})"
            mode = "local-fallback"

        tokens_out = _estimate_tokens(text)
        rate = 0.0000025 if self.provider != ProviderName.OLLAMA else 0.0
        return {
            "text": text,
            "tokens_in": tokens_in,
            "tokens_out": tokens_out,
            "cost_usd": round((tokens_in + tokens_out) * rate, 6),
            "mode": mode,
        }

    async def _call_remote(self, prompt: str) -> tuple[str | None, str | None]:
        key = self._resolve_key()
        if self.provider != ProviderName.OLLAMA and not key:
            return None, "provider key not configured"

        try:
            async with httpx.AsyncClient(timeout=18.0) as client:
                if self.provider == ProviderName.GEMINI:
                    model = self.model or "gemini-2.5-flash"
                    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
                    resp = await client.post(
                        url,
                        params={"key": key},
                        json={"contents": [{"parts": [{"text": prompt}]}]},
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    return data["candidates"][0]["content"]["parts"][0]["text"], None

                if self.provider == ProviderName.OPENAI:
                    model = self.model or "gpt-4o-mini"
                    resp = await client.post(
                        "https://api.openai.com/v1/chat/completions",
                        headers={"Authorization": f"Bearer {key}"},
                        json={
                            "model": model,
                            "messages": [{"role": "user", "content": prompt}],
                            "max_tokens": 320,
                        },
                    )
                    resp.raise_for_status()
                    return resp.json()["choices"][0]["message"]["content"], None

                if self.provider == ProviderName.ANTHROPIC:
                    model = self.model or "claude-3-5-haiku-latest"
                    resp = await client.post(
                        "https://api.anthropic.com/v1/messages",
                        headers={
                            "x-api-key": key or "",
                            "anthropic-version": "2023-06-01",
                        },
                        json={
                            "model": model,
                            "max_tokens": 320,
                            "messages": [{"role": "user", "content": prompt}],
                        },
                    )
                    resp.raise_for_status()
                    return resp.json()["content"][0]["text"], None

                if self.provider == ProviderName.OLLAMA:
                    base = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
                    model = self.model or "llama3.2"
                    resp = await client.post(
                        f"{base}/api/generate",
                        json={"model": model, "prompt": prompt, "stream": False},
                    )
                    resp.raise_for_status()
                    return resp.json().get("response"), None
        except httpx.HTTPStatusError as exc:
            return None, f"HTTP {exc.response.status_code} from {self.provider.value}"
        except httpx.TimeoutException:
            return None, f"timeout calling {self.provider.value}"
        except Exception as exc:
            return None, f"{type(exc).__name__} calling {self.provider.value}"
        return None, "unsupported provider"

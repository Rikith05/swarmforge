"""Hybrid LLM provider adapters (local deterministic engine + optional BYOK APIs)."""

from .llm import ProviderClient

__all__ = ["ProviderClient"]

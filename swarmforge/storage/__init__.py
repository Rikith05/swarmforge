"""SQLite persistence layer for runs, time-travel snapshots, and eval reports."""

from .db import SwarmDatabase

__all__ = ["SwarmDatabase"]

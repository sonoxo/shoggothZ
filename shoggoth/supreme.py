"""Supreme Shoggoth governance and diagnostics layer.

This module is intentionally non-invasive. It exposes local-only helpers that
can be consumed by UI code without silently mutating projects or sending data.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class SupremeGateResult:
    allowed: bool
    reason: str
    requires_human_approval: bool = True


def governance_gate(action: str, *, user_approved: bool = False) -> SupremeGateResult:
    """Gate consequential actions behind explicit human approval."""
    safe_read_only = {
        "inspect_project",
        "inspect_plugins",
        "inspect_telemetry",
        "run_preflight",
        "run_diagnostics",
        "preview_export",
    }
    if action in safe_read_only:
        return SupremeGateResult(True, "read-only diagnostic action", False)
    if user_approved:
        return SupremeGateResult(True, "explicit human approval supplied", True)
    return SupremeGateResult(False, "human approval required", True)


def build_diagnostic_snapshot(
    *,
    project_name: str | None = None,
    card_count: int | None = None,
    telemetry_level: str | None = None,
    plugin_count: int | None = None,
    export_ready: bool | None = None,
) -> dict[str, Any]:
    """Return a small, serializable local diagnostic snapshot."""
    return {
        "schema": "supreme-shoggoth.diagnostics.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project_name": project_name,
        "card_count": card_count,
        "telemetry_level": telemetry_level,
        "plugin_count": plugin_count,
        "export_ready": export_ready,
        "governance": {
            "authority": "HUMAN_FIRST",
            "network_actions": "explicit_only",
            "mutations": "approval_required",
            "audit": "enabled",
        },
    }


def tev_check(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Minimal TEVV-style consistency check for the snapshot."""
    issues: list[str] = []
    if snapshot.get("card_count") is not None and snapshot["card_count"] < 0:
        issues.append("card_count cannot be negative")
    if snapshot.get("telemetry_level") not in {None, "off", "basic", "extended", "personal"}:
        issues.append("unknown telemetry level")
    if snapshot.get("plugin_count") is not None and snapshot["plugin_count"] < 0:
        issues.append("plugin_count cannot be negative")
    return {
        "passed": not issues,
        "issues": issues,
        "checked_schema": snapshot.get("schema"),
    }

"""Defensive security utilities for Supreme Shoggoth.

Local-first, read-only inspection helpers for integrity, privacy, evidence
manifests, and governance. No remote scanning, credential harvesting, process
injection, or offensive functionality is implemented here.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
from typing import Iterable

SECRET_PATTERNS = (
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("generic-api-key", re.compile(r"(?i)\b(?:api[_-]?key|secret|token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]")),
)

SENSITIVE_PATTERNS = (
    re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"),
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
)

HIGH_RISK_SUFFIXES = {".exe", ".dll", ".dylib", ".so", ".bat", ".cmd", ".ps1", ".scr"}
MAX_TEXT_BYTES = 1_000_000


@dataclass(frozen=True)
class SecurityFinding:
    severity: str
    category: str
    path: str
    message: str


@dataclass(frozen=True)
class IntegrityRecord:
    path: str
    size: int
    modified_utc: str
    sha256: str


def file_sha256(path: str | Path) -> str:
    """Compute a SHA-256 digest without modifying the file."""
    digest = sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_relative(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path.resolve())


def _text_findings(path: Path, rel: str) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    try:
        if path.stat().st_size > MAX_TEXT_BYTES:
            return findings
        data = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return findings

    for name, pattern in SECRET_PATTERNS:
        if pattern.search(data):
            findings.append(SecurityFinding(
                "high", "secret-exposure", rel,
                f"Potential {name} material detected; review before sharing or exporting.",
            ))
    return findings


def inspect_directory(root: str | Path, *, max_files: int = 2000) -> dict:
    """Perform a bounded, read-only local integrity/privacy inspection."""
    base = Path(root).expanduser().resolve()
    if not base.exists() or not base.is_dir():
        raise ValueError("scan root must be an existing directory")

    findings: list[SecurityFinding] = []
    records: list[IntegrityRecord] = []
    scanned = 0

    for path in base.rglob("*"):
        if scanned >= max_files:
            findings.append(SecurityFinding(
                "medium", "scan-limit", ".",
                f"Scan stopped at {max_files} files to keep the UI responsive.",
            ))
            break
        if not path.is_file():
            continue

        scanned += 1
        rel = _safe_relative(path, base)
        try:
            stat = path.stat()
        except OSError as exc:
            findings.append(SecurityFinding("low", "read-error", rel, str(exc)))
            continue

        if path.suffix.lower() in HIGH_RISK_SUFFIXES:
            findings.append(SecurityFinding(
                "medium", "executable-content", rel,
                "Executable or script-capable artifact present; verify provenance before distribution.",
            ))

        if path.is_symlink():
            try:
                path.resolve().relative_to(base)
            except ValueError:
                findings.append(SecurityFinding(
                    "high", "symlink-boundary", rel,
                    "Symbolic link resolves outside the inspected directory.",
                ))

        if os.name != "nt" and stat.st_mode & 0o002:
            findings.append(SecurityFinding(
                "medium", "permissions", rel,
                "File is world-writable.",
            ))

        findings.extend(_text_findings(path, rel))

        try:
            digest = file_sha256(path)
        except OSError as exc:
            findings.append(SecurityFinding("low", "hash-error", rel, str(exc)))
            continue

        records.append(IntegrityRecord(
            path=rel,
            size=stat.st_size,
            modified_utc=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            sha256=digest,
        ))

    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    score = 100
    for finding in findings:
        score -= {"high": 14, "medium": 6, "low": 2}.get(finding.severity, 0)
    score = max(0, min(100, score))

    return {
        "schema": "supreme-shoggoth.security-scan.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "root": str(base),
        "files_scanned": scanned,
        "posture_score": score,
        "findings": [asdict(item) for item in findings],
        "records": [asdict(item) for item in records],
        "severity_counts": {
            level: sum(1 for item in findings if item.severity == level)
            for level in ("high", "medium", "low")
        },
    }


def build_evidence_manifest(scan: dict) -> dict:
    """Build a portable chain-of-custody style manifest from a scan result."""
    return {
        "schema": "supreme-shoggoth.evidence-manifest.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_root": scan.get("root"),
        "files_scanned": scan.get("files_scanned", 0),
        "records": scan.get("records", []),
        "integrity": {
            "algorithm": "SHA-256",
            "record_count": len(scan.get("records", [])),
            "mutating_actions": "none",
        },
    }


def write_manifest(manifest: dict, destination: str | Path) -> Path:
    target = Path(destination).expanduser()
    target.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return target


def redact_sensitive_text(text: str) -> str:
    """Redact common contact/network identifiers from display/export text."""
    redacted = text
    for pattern in SENSITIVE_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def posture_label(score: int) -> str:
    if score >= 90:
        return "HARDENED"
    if score >= 75:
        return "GUARDED"
    if score >= 55:
        return "REVIEW"
    return "ACTION REQUIRED"

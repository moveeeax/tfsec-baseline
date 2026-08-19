#!/usr/bin/env python3
"""Audit centrally-declared IaC scanner suppressions.

The point of this tool is to make a `checkov` / `tfsec` waiver *accountable*.
Instead of scattering bare `#checkov:skip=CKV_AWS_18` comments that never
expire and name no one, teams declare every waiver in one YAML file where the
schema forces a justification, an owner and an expiry date. This module loads
that file, validates it, and fails CI when a waiver is malformed or stale.

It can also emit the non-expired waivers as a checkov `--skip-check` list, so
the same file that documents *why* a check is skipped is also what drives the
scanner. One source of truth, no drift.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from dataclasses import dataclass, field
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - dependency is declared in requirements.txt
    sys.stderr.write("suppression-audit: PyYAML is required (pip install pyyaml)\n")
    raise

# A justification shorter than this is treated as a non-answer ("wip", "n/a").
MIN_JUSTIFICATION_LEN = 15
CHECK_ID_PREFIXES = ("CKV", "CKV2", "AWS", "GCP", "AZU", "aws-", "google-", "azure-")


@dataclass
class Suppression:
    check_id: str
    paths: list[str]
    justification: str
    owner: str
    expires: str
    raw_index: int

    @property
    def expiry_date(self) -> dt.date | None:
        try:
            return dt.date.fromisoformat(self.expires)
        except (ValueError, TypeError):
            return None


@dataclass
class Problem:
    index: int
    check_id: str
    level: str  # "error" or "warning"
    message: str


@dataclass
class AuditResult:
    problems: list[Problem] = field(default_factory=list)
    active: list[Suppression] = field(default_factory=list)

    @property
    def errors(self) -> list[Problem]:
        return [p for p in self.problems if p.level == "error"]

    @property
    def warnings(self) -> list[Problem]:
        return [p for p in self.problems if p.level == "warning"]

    @property
    def ok(self) -> bool:
        return not self.errors


def _looks_like_check_id(value: str) -> bool:
    return isinstance(value, str) and value.startswith(CHECK_ID_PREFIXES)


def parse_suppressions(data: Any) -> list[Suppression]:
    """Turn raw parsed YAML into Suppression rows.

    Accepts either a top-level list or a mapping with a ``suppressions`` key.
    Malformed rows are still returned (with best-effort fields) so validation
    can report a precise problem rather than crashing.
    """
    if isinstance(data, dict):
        rows = data.get("suppressions", [])
    else:
        rows = data
    if rows is None:
        rows = []
    if not isinstance(rows, list):
        raise ValueError("suppressions must be a YAML list")

    out: list[Suppression] = []
    for i, row in enumerate(rows):
        row = row if isinstance(row, dict) else {}
        paths = row.get("paths", [])
        if isinstance(paths, str):
            paths = [paths]
        out.append(
            Suppression(
                check_id=str(row.get("id", "")),
                paths=[str(p) for p in paths] if isinstance(paths, list) else [],
                justification=str(row.get("justification", "") or ""),
                owner=str(row.get("owner", "") or ""),
                expires=str(row.get("expires", "") or ""),
                raw_index=i,
            )
        )
    return out


def validate(suppressions: list[Suppression], today: dt.date, warn_days: int = 30) -> AuditResult:
    """Validate every waiver; classify each into active / expired / broken."""
    result = AuditResult()
    for s in suppressions:
        row_errors: list[str] = []

        if not _looks_like_check_id(s.check_id):
            row_errors.append(f"'id' must be a scanner check id, got {s.check_id!r}")
        if not s.paths:
            row_errors.append("'paths' must list at least one file or directory")
        if len(s.justification.strip()) < MIN_JUSTIFICATION_LEN:
            row_errors.append(
                f"'justification' must explain the risk (>= {MIN_JUSTIFICATION_LEN} chars)"
            )
        if not s.owner.strip():
            row_errors.append("'owner' is required so a waiver has a name attached")

        expiry = s.expiry_date
        if expiry is None:
            row_errors.append(f"'expires' must be an ISO date (YYYY-MM-DD), got {s.expires!r}")

        for msg in row_errors:
            result.problems.append(Problem(s.raw_index, s.check_id or "?", "error", msg))

        if row_errors:
            continue  # a broken row can't be classified as active/expired

        assert expiry is not None
        if expiry < today:
            result.problems.append(
                Problem(
                    s.raw_index,
                    s.check_id,
                    "error",
                    f"waiver expired on {s.expires} — re-justify or fix the finding",
                )
            )
            continue

        days_left = (expiry - today).days
        if days_left <= warn_days:
            result.problems.append(
                Problem(
                    s.raw_index,
                    s.check_id,
                    "warning",
                    f"waiver expires in {days_left} day(s) on {s.expires}",
                )
            )
        result.active.append(s)
    return result


def load_file(path: str) -> list[Suppression]:
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    return parse_suppressions(data)


def to_sarif(result: AuditResult, source: str) -> dict:
    rules_seen: dict[str, int] = {}
    rules: list[dict] = []
    results: list[dict] = []
    for p in result.problems:
        rule_id = f"suppression-audit/{p.level}"
        if rule_id not in rules_seen:
            rules_seen[rule_id] = len(rules)
            rules.append({"id": rule_id, "name": rule_id, "shortDescription": {"text": rule_id}})
        results.append(
            {
                "ruleId": rule_id,
                "ruleIndex": rules_seen[rule_id],
                "level": p.level,
                "message": {"text": f"[{p.check_id}] {p.message}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": source},
                            "region": {"startLine": p.index + 1},
                        }
                    }
                ],
            }
        )
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "suppression-audit",
                        "informationUri": "https://github.com/moveeeax/tfsec-baseline",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def format_text(result: AuditResult) -> str:
    lines: list[str] = []
    for p in result.problems:
        marker = "ERROR" if p.level == "error" else "warn "
        lines.append(f"  {marker} row {p.index + 1} [{p.check_id}]: {p.message}")
    header = (
        f"suppression-audit: {len(result.active)} active waiver(s), "
        f"{len(result.errors)} error(s), {len(result.warnings)} warning(s)"
    )
    lines.insert(0, header)
    if result.ok:
        lines.append("OK: all waivers are justified, owned and unexpired.")
    return "\n".join(lines)


def emit_checkov_skips(result: AuditResult) -> str:
    """Print unique active check ids, ready for `checkov --skip-check`."""
    ids: list[str] = []
    for s in result.active:
        if s.check_id not in ids:
            ids.append(s.check_id)
    return ",".join(ids)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="suppression-audit",
        description="Validate accountable IaC scanner suppressions (justification + owner + expiry).",
    )
    parser.add_argument(
        "-f", "--file", default=".tfsec-baseline/suppressions.yaml",
        help="path to the suppressions YAML (default: %(default)s)",
    )
    parser.add_argument(
        "--today", default=None,
        help="override today's date (YYYY-MM-DD) for deterministic runs",
    )
    parser.add_argument(
        "--warn-days", type=int, default=30,
        help="warn when a waiver expires within this many days (default: %(default)s)",
    )
    parser.add_argument(
        "--format", choices=("text", "sarif"), default="text",
        help="output format (default: %(default)s)",
    )
    parser.add_argument(
        "--emit-checkov-skips", action="store_true",
        help="print the active check ids as a checkov --skip-check list and exit 0",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.today:
        try:
            today = dt.date.fromisoformat(args.today)
        except ValueError:
            sys.stderr.write(f"suppression-audit: --today must be YYYY-MM-DD, got {args.today!r}\n")
            return 2
    else:
        today = dt.date.today()

    try:
        suppressions = load_file(args.file)
    except FileNotFoundError:
        sys.stderr.write(f"suppression-audit: no such file: {args.file}\n")
        return 2
    except (ValueError, yaml.YAMLError) as exc:
        sys.stderr.write(f"suppression-audit: cannot parse {args.file}: {exc}\n")
        return 2

    result = validate(suppressions, today, warn_days=args.warn_days)

    if args.emit_checkov_skips:
        print(emit_checkov_skips(result))
        return 0

    if args.format == "sarif":
        print(json.dumps(to_sarif(result, args.file), indent=2))
    else:
        print(format_text(result))

    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

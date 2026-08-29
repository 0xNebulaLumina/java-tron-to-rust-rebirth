#!/usr/bin/env python3
"""Verify the reviewed C000 platform cells that have no native runtime surface."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "docs/architecture/platform-manifest.v1.json"
CELLS = ("native_resource", "ffi", "packaging", "smoke")
REQUIRED_REVIEWS = {"RV-0002", "RV-0003"}


def main() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    row = next(entry for entry in manifest["rows"] if entry["id"] == "P-LINUX-X64")
    outcomes = []
    failed = False
    for cell in CELLS:
        spec = row["cells"][cell]
        reviews = set(spec.get("review_bindings", []))
        passed = (
            spec.get("disposition") == "not_applicable"
            and bool(spec.get("reason"))
            and bool(spec.get("reopen_condition"))
            and REQUIRED_REVIEWS <= reviews
        )
        failed |= not passed
        outcomes.append({
            "case": cell,
            "outcome": "pass" if passed else "fail",
            "disposition": spec.get("disposition"),
            "reason": spec.get("reason"),
            "reopen_condition": spec.get("reopen_condition"),
            "review_bindings": sorted(reviews),
        })
    print(json.dumps({"schema_version": 1, "cell": "reviewed_not_applicable", "cases": outcomes}, sort_keys=True, separators=(",", ":")))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

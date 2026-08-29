#!/usr/bin/env python3
"""Validate and report the simple v2 porting tracker."""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
TRACKER = ROOT / "docs/PORTING_TRACKER.json"
CHUNK_STATUSES = {"todo", "active", "review", "blocked", "done"}
ITEM_STATUSES = {"todo", "doing", "done"}
GATE_STATUSES = {"unconfigured", "not_run", "failed", "passed"}
REVIEW_STATES = {"not_started", "in_review", "changes_requested", "approved"}
FINDING_STATUSES = {"open", "fixed", "closed"}
CHUNK_FIELDS = {"id", "title", "status", "owner", "updated", "resume", "items", "gate", "review", "blocker"}
ITEM_FIELDS = {"id", "description", "status", "note"}
GATE_FIELDS = {"id", "description", "status", "commands", "last_failure"}
COMMAND_FIELDS = {"name", "cwd", "argv", "timeout_seconds"}
REVIEW_FIELDS = {"state", "round", "findings"}
FINDING_FIELDS = {"id", "summary", "status", "resolution"}
BLOCKER_FIELDS = {"reason", "unblock_condition"}
SAFE_ENV = {"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", ""), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}


def load_tracker() -> dict[str, Any]:
    with TRACKER.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError("tracker root must be an object")
    return value


def exact_fields(value: Any, fields: set[str], where: str, errors: list[str]) -> bool:
    if not isinstance(value, dict):
        errors.append(f"{where}: must be an object")
        return False
    actual = set(value)
    if actual != fields:
        errors.append(f"{where}: fields must be exactly {sorted(fields)} (found {sorted(actual)})")
        return False
    return True


def text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def validate(data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if set(data) != {"schema_version", "chunks"}:
        errors.append("tracker: fields must be exactly schema_version and chunks")
    if data.get("schema_version") != 2:
        errors.append("tracker: schema_version must be 2")
    chunks = data.get("chunks")
    if not isinstance(chunks, list):
        return errors + ["tracker: chunks must be an array"]
    expected_ids = [f"C{i:03d}" for i in range(32)]
    if [chunk.get("id") if isinstance(chunk, dict) else None for chunk in chunks] != expected_ids:
        errors.append("tracker: chunks must be exactly C000 through C031 in order")
    seen_item_ids: set[str] = set()
    non_done_seen = False
    current_seen = False
    for index, chunk in enumerate(chunks):
        where = expected_ids[index] if index < len(expected_ids) else f"chunks[{index}]"
        if not exact_fields(chunk, CHUNK_FIELDS, where, errors):
            continue
        cid = chunk["id"]
        status = chunk["status"]
        if status not in CHUNK_STATUSES:
            errors.append(f"{cid}: invalid status {status!r}")
        if not text(chunk["title"]):
            errors.append(f"{cid}: title must be non-empty")
        if chunk["owner"] is not None and not text(chunk["owner"]):
            errors.append(f"{cid}: owner must be null or non-empty")
        if chunk["updated"] is not None and not text(chunk["updated"]):
            errors.append(f"{cid}: updated must be null or non-empty")
        if status in {"active", "review", "blocked"}:
            if not text(chunk["owner"]): errors.append(f"{cid}: {status} chunk requires owner")
            if not text(chunk["resume"]): errors.append(f"{cid}: {status} chunk requires a concrete resume action")
        elif chunk["resume"] is not None:
            errors.append(f"{cid}: {status} chunk must have null resume")
        if status == "done":
            if non_done_seen: errors.append(f"{cid}: completed chunks must form a contiguous prefix")
        else:
            non_done_seen = True
        if status in {"active", "review", "blocked"}:
            if current_seen: errors.append(f"{cid}: only the first unfinished chunk may be current")
            current_seen = True
        if non_done_seen and status == "todo" and current_seen:
            pass
        elif non_done_seen and status == "todo" and any(isinstance(c, dict) and c.get("status") in {"active", "review", "blocked"} for c in chunks[index + 1:]):
            errors.append(f"{cid}: a later chunk cannot be current")
        items = chunk["items"]
        if not isinstance(items, list) or not items:
            errors.append(f"{cid}: items must be a non-empty array")
            items = []
        for pos, item in enumerate(items):
            iw = f"{cid}.items[{pos}]"
            if not exact_fields(item, ITEM_FIELDS, iw, errors): continue
            iid = item["id"]
            if not isinstance(iid, str) or not re.fullmatch(re.escape(cid) + r"\.\d{2}[A-Z]?", iid): errors.append(f"{iw}: invalid item id")
            elif iid in seen_item_ids: errors.append(f"{iw}: duplicate item id {iid}")
            else: seen_item_ids.add(iid)
            if not text(item["description"]): errors.append(f"{iw}: description must be non-empty")
            if item["status"] not in ITEM_STATUSES: errors.append(f"{iw}: invalid item status")
            if item["note"] is not None and not text(item["note"]): errors.append(f"{iw}: note must be null or non-empty")
            if status == "todo" and item["status"] != "todo": errors.append(f"{iw}: future chunk items must be todo")
        gate = chunk["gate"]
        if exact_fields(gate, GATE_FIELDS, f"{cid}.gate", errors):
            if gate["id"] != f"{cid}.V": errors.append(f"{cid}.gate: id must be {cid}.V")
            if not text(gate["description"]): errors.append(f"{cid}.gate: description must be non-empty")
            if gate["status"] not in GATE_STATUSES: errors.append(f"{cid}.gate: invalid status")
            commands = gate["commands"]
            if not isinstance(commands, list): errors.append(f"{cid}.gate: commands must be an array"); commands = []
            if gate["status"] == "unconfigured" and commands: errors.append(f"{cid}.gate: unconfigured gate must have no commands")
            if gate["status"] != "unconfigured" and not commands: errors.append(f"{cid}.gate: configured gate requires commands")
            if any(isinstance(i, dict) and i.get("status") == "doing" for i in items) and not commands: errors.append(f"{cid}.gate: commands must be frozen before work starts")
            if status == "todo" and gate["status"] != "unconfigured": errors.append(f"{cid}.gate: future chunk gate must be unconfigured")
            for pos, command in enumerate(commands):
                cw = f"{cid}.gate.commands[{pos}]"
                if not exact_fields(command, COMMAND_FIELDS, cw, errors): continue
                if not text(command["name"]): errors.append(f"{cw}: name must be non-empty")
                cwd = command["cwd"]
                if not text(cwd): errors.append(f"{cw}: cwd must be non-empty")
                else:
                    resolved = (ROOT / cwd).resolve()
                    if resolved != ROOT and ROOT not in resolved.parents: errors.append(f"{cw}: cwd escapes repository")
                argv = command["argv"]
                if not isinstance(argv, list) or not argv or any(not text(arg) or "\x00" in arg for arg in argv): errors.append(f"{cw}: argv must be a non-empty string array")
                timeout = command["timeout_seconds"]
                if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 3600: errors.append(f"{cw}: timeout_seconds must be 1..3600")
            if gate["last_failure"] is not None and not text(gate["last_failure"]): errors.append(f"{cid}.gate: last_failure must be null or non-empty")
        review = chunk["review"]
        if exact_fields(review, REVIEW_FIELDS, f"{cid}.review", errors):
            if review["state"] not in REVIEW_STATES: errors.append(f"{cid}.review: invalid state")
            if not isinstance(review["round"], int) or isinstance(review["round"], bool) or review["round"] < 0: errors.append(f"{cid}.review: round must be a non-negative integer")
            findings = review["findings"]
            if not isinstance(findings, list): errors.append(f"{cid}.review: findings must be an array"); findings = []
            finding_ids: set[str] = set()
            for pos, finding in enumerate(findings):
                fw = f"{cid}.review.findings[{pos}]"
                if not exact_fields(finding, FINDING_FIELDS, fw, errors): continue
                fid = finding["id"]
                if not text(fid) or fid in finding_ids: errors.append(f"{fw}: finding id must be non-empty and unique")
                else: finding_ids.add(fid)
                if not text(finding["summary"]): errors.append(f"{fw}: summary must be non-empty")
                if finding["status"] not in FINDING_STATUSES: errors.append(f"{fw}: invalid status")
                if finding["resolution"] is not None and not text(finding["resolution"]): errors.append(f"{fw}: resolution must be null or non-empty")
                if finding["status"] == "fixed" and not text(finding["resolution"]): errors.append(f"{fw}: fixed finding requires resolution")
            if status == "todo" and (review["state"] != "not_started" or review["round"] != 0 or findings): errors.append(f"{cid}.review: future chunk review must be untouched")
        blocker = chunk["blocker"]
        if status == "blocked":
            if exact_fields(blocker, BLOCKER_FIELDS, f"{cid}.blocker", errors):
                if not text(blocker["reason"]) or not text(blocker["unblock_condition"]): errors.append(f"{cid}.blocker: fields must be non-empty")
        elif blocker is not None:
            errors.append(f"{cid}: blocker is allowed only for blocked chunks")
        if status == "done":
            if any(i.get("status") != "done" for i in items if isinstance(i, dict)): errors.append(f"{cid}: done chunk requires all items done")
            if gate.get("status") != "passed": errors.append(f"{cid}: done chunk requires passed gate")
            if review.get("state") != "approved": errors.append(f"{cid}: done chunk requires approved review")
            if any(f.get("status") != "closed" for f in review.get("findings", []) if isinstance(f, dict)): errors.append(f"{cid}: done chunk requires closed findings")
    return errors


def current_chunk(data: dict[str, Any]) -> dict[str, Any] | None:
    return next((chunk for chunk in data["chunks"] if chunk["status"] != "done"), None)


def print_status(data: dict[str, Any]) -> None:
    for chunk in data["chunks"]:
        gate = chunk["gate"]
        marker = " *" if chunk is current_chunk(data) else ""
        print(f"{chunk['id']} {chunk['status']:<7} gate={gate['status']}{marker} {chunk['title']}")


def print_next(data: dict[str, Any]) -> None:
    chunk = current_chunk(data)
    if chunk is None:
        print("All chunks are done.")
        return
    item = next((item for item in chunk["items"] if item["status"] != "done"), None)
    print(f"chunk: {chunk['id']} {chunk['title']}")
    if item: print(f"item: {item['id']} [{item['status']}] {item['description']}")
    if chunk["resume"]: print(f"resume: {chunk['resume']}")
    if chunk["blocker"]:
        print(f"blocker: {chunk['blocker']['reason']}")
        print(f"unblocks when: {chunk['blocker']['unblock_condition']}")
    print(f"gate: python3 tools/tracker/validate.py --gate {chunk['id']}")
    for command in chunk["gate"]["commands"]:
        print(f"  ({command['cwd']}) {' '.join(command['argv'])}")


def run_gate(data: dict[str, Any], chunk_id: str) -> int:
    chunk = next((value for value in data["chunks"] if value["id"] == chunk_id), None)
    if chunk is None:
        print(f"unknown chunk: {chunk_id}", file=sys.stderr); return 2
    commands = chunk["gate"]["commands"]
    if not commands:
        print(f"{chunk_id}: gate is unconfigured", file=sys.stderr); return 2
    for index, command in enumerate(commands, 1):
        print(f"[{index}/{len(commands)}] {command['name']}: ({command['cwd']}) {' '.join(command['argv'])}", flush=True)
        try:
            completed = subprocess.run(command["argv"], cwd=ROOT / command["cwd"], env=SAFE_ENV, timeout=command["timeout_seconds"])
        except (OSError, subprocess.TimeoutExpired) as error:
            print(f"FAIL {command['name']}: {error}", file=sys.stderr); return 1
        if completed.returncode:
            print(f"FAIL {command['name']}: exit {completed.returncode}", file=sys.stderr); return completed.returncode
        print(f"PASS {command['name']}")
    print(f"PASS {chunk_id} gate")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--status", action="store_true")
    modes.add_argument("--next", action="store_true")
    modes.add_argument("--check", action="store_true")
    modes.add_argument("--gate", metavar="Cnnn")
    args = parser.parse_args()
    try: data = load_tracker()
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"tracker error: {error}", file=sys.stderr); return 1
    errors = validate(data)
    if errors:
        for error in errors: print(f"ERROR: {error}", file=sys.stderr)
        return 1
    if args.status: print_status(data)
    elif args.next: print_next(data)
    elif args.gate: return run_gate(data, args.gate)
    else: print("PORTING_TRACKER.json: valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

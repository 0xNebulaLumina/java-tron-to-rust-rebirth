#!/usr/bin/env python3
"""Supported production launcher for exactly one C028 node mode."""
from __future__ import annotations

import os
import sys


MODES = {"full", "solidity"}


def compose_command(argv: list[str], environ: dict[str, str]) -> tuple[list[str], dict[str, str]]:
    if len(argv) != 1 or argv[0] not in MODES:
        raise ValueError("usage: c028_compose.py full|solidity")
    mode = argv[0]
    injected = environ.get("COMPOSE_PROFILES")
    if injected is not None and injected != mode:
        raise ValueError("COMPOSE_PROFILES must be unset or equal the selected mode")
    child_env = dict(environ)
    child_env["COMPOSE_PROFILES"] = mode
    return ["docker", "compose", "--profile", mode, "up", "--detach"], child_env


def main() -> int:
    try:
        command, child_env = compose_command(sys.argv[1:], dict(os.environ))
    except ValueError as error:
        print(error, file=sys.stderr)
        return 64
    os.execvpe(command[0], command, child_env)
    return 70


if __name__ == "__main__":
    raise SystemExit(main())

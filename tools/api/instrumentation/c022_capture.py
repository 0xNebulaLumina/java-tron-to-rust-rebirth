#!/usr/bin/env python3
import json

PREFIX = "C022_CAPTURE="


def parse(text):
    rows = [json.loads(line.split(PREFIX, 1)[1]) for line in text.splitlines() if PREFIX in line]
    if len(rows) != 1:
        raise ValueError(f"expected one C022 capture, found {len(rows)}")
    row = rows[0]
    if row.get("schema") != "c022-java-descriptor-v1":
        raise ValueError("unexpected C022 capture schema")
    return row

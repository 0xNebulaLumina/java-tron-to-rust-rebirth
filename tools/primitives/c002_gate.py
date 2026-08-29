#!/usr/bin/env python3
"""Validate C002 source coverage and deterministic boundary-vector contracts."""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COVERAGE = ROOT / "docs/oracles/common-primitives-coverage.v1.json"
VECTORS = ROOT / "docs/oracles/c002-java-boundary-vectors.v1.json"
FIXTURES = ROOT / "docs/oracles/c002-primitives-fixtures.v1.json"
CRATE = ROOT / "rust-tron/crates/tron-primitives/src"
REQUIRED_IDS = {f"C002.{index:02d}" for index in range(1, 8)}
REQUIRED_VECTOR_GROUPS = {
    "ids", "bytes_order_null", "bigint_fixed_bytes", "deterministic_math_surface", "math", "clocks", "merkle",
    "raw_hash_inputs", "block_id_inconsistency", "tapos", "market_comparator",
}
REQUIRED_FIXTURE_GROUPS = {
    "merkle", "tapos", "wire_hash_boundaries", "arithmetic", "unicode_keys",
    "block_id_comparators", "market", "bigint_fixed_bytes",
}
REQUIRED_SEAMS = {"C004", "C006", "C008"}
REQUIRED_UNICODE_CASES = {
    ("locale_root_lowercase_key", "ΟΣ", "ος"),
    ("locale_root_lowercase_key", "ΟΣΑ", "οσα"),
    ("locale_root_lowercase_key", "İ", "i\u0307"),
    ("locale_root_lowercase_key", "iIıİ", "iiıi\u0307"),
    ("locale_root_uppercase_key", "iIıİ", "IIIİ"),
    ("locale_root_uppercase_key", "ß", "SS"),
    ("locale_root_lowercase_key", "𐐀", "𐐨"),
    ("locale_root_uppercase_key", "𐐨", "𐐀"),
}
PINNED_MATH_WRAPPERS = {
    "java-tron/platform/src/main/java/x86/org/tron/common/math/MathWrapper.java",
    "java-tron/platform/src/main/java/arm/org/tron/common/math/MathWrapper.java",
}
ROW_SCHEMAS = {
    "ids": ({"accepted", "expected_prefix", "hex", "id", "kind"}, {"accepted", "hex", "id", "kind", "prefix"}, {"accepted", "id", "input_length", "kind"}),
    "bytes_order_null": ({"actual", "error", "id", "operation", "parts_hex", "width"}, {"bytes_hex", "id", "input", "operation", "output"}, {"end", "error", "id", "input_hex", "operation", "start"}, {"end", "id", "input_hex", "operation", "output_hex", "start"}, {"error", "id", "input", "operation"}, {"id", "input", "operation", "output"}, {"id", "input", "operation", "output_hex"}, {"id", "input_hex", "length", "offset", "operation", "output_hex"}, {"id", "left_hex", "operation", "ordering", "right_hex"}, {"id", "operation", "output_hex", "parts_hex", "width"}),
    "bigint_fixed_bytes": ({"boundary", "id", "input", "operation", "output_hex", "width"},),
    "deterministic_math_surface": ({"id", "input", "note", "operation", "output"}, {"id", "input", "operation", "output"}, {"id", "input", "operation", "output", "provider"}, {"id", "input", "operation", "output_bits_hex", "provider"}, {"id", "left", "operation", "output", "right"}, {"id", "operation", "reason", "status"}),
    "math": ({"allow_strict_math", "arithmetic_mode", "disable_java_lang_math", "id", "operation", "provider_method"}, {"error", "id", "left", "mode", "operation", "right"}, {"id", "left", "operation", "output", "right"}),
    "clocks": ({"advance_millis", "clock", "error", "id", "start_millis"}, {"advance_millis", "clock", "id", "output_millis", "start_millis"}, {"advance_nanos", "clock", "id", "output_nanos", "start_nanos"}, {"ambient_clock_reads", "clock", "id", "input_millis", "output_millis"}),
    "merkle": ({"duplicates_last", "hash_calls", "id", "leaves", "name", "odd_promotions", "pair_inputs_hex", "root"}, {"duplicates_last", "hash_calls", "id", "leaves_hex", "name", "odd_promotions", "pair_inputs_hex", "root_hex"}, {"hash_calls", "id", "leaves", "name", "odd_promotions", "pair_inputs_hex", "root"}, {"hash_calls", "id", "leaves", "name", "odd_promotions", "pair_inputs_hex", "root_hex"}, {"hash_calls", "id", "leaves_hex", "name", "odd_promotions", "pair_inputs_hex", "root_hex"}),
    "raw_hash_inputs": ({"calls_each", "expected_a_byte", "expected_b_byte", "id", "input_hex", "operation", "provider_a_byte", "provider_b_byte"}, {"calls_each", "expected_a_hex", "expected_a_suffix", "expected_b_hex", "expected_b_suffix", "height", "id", "input_hex", "operation", "provider_a_suffix", "provider_b_suffix"}, {"digest_calls", "digest_output_byte", "excluded_hex", "id", "input_hex", "operation", "result_hex"}, {"digest_calls", "digest_output_byte", "height", "id", "input_hex", "operation", "postprocess", "result_hex"}, {"digest_calls", "digest_output_byte", "id", "included", "input_hex", "operation", "result_hex"}),
    "wire_hash_boundaries": ({"calls_each", "expected_a_byte", "expected_b_byte", "id", "input_hex", "operation", "provider_a_byte", "provider_b_byte"}, {"calls_each", "expected_a_hex", "expected_a_suffix", "expected_b_hex", "expected_b_suffix", "height", "id", "input_hex", "operation", "provider_a_suffix", "provider_b_suffix"}, {"digest_calls", "digest_output_byte", "excluded_hex", "id", "input_hex", "operation", "result_hex"}, {"digest_calls", "digest_output_byte", "height", "id", "input_hex", "operation", "overlay", "result_hex"}, {"digest_calls", "digest_output_byte", "id", "includes_signatures", "input_hex", "operation", "result_hex"}),
    "block_id_inconsistency": ({"block_height", "block_suffix", "hash_height", "hash_suffix", "id", "operation", "ordering"}, {"equals", "id", "left_hash_suffix", "left_height", "operation", "ordering", "right_hash_suffix", "right_height"}, {"id", "left_hash_suffix", "left_height", "operation", "ordering", "right_hash_suffix", "right_height"}),
    "tapos": ({"block_id", "id", "ref_block_hash"}, {"block_id_hex", "id", "ref_block_hash_hex"}, {"height", "height_hex", "id", "ref_block_bytes_hex"}, {"height", "id", "ref_block_bytes"}, {"height", "id", "ref_block_bytes_hex"}),
    "market_comparator": ({"bytes_hex", "case", "id", "output"}, {"case", "error", "id", "length"}, {"case", "id", "left", "operation", "ordering", "right"}, {"case", "id", "left", "ordering", "right"}, {"case", "id", "left_pair_prefix_hex", "ordering", "right_pair_prefix_hex"}),
    "arithmetic": ({"allow_strict_math", "arithmetic_mode", "disable_java_lang_math", "id", "operation", "provider_method"}, {"error", "id", "left", "mode", "operation", "right"}),
    "unicode_keys": ({"id", "input", "operation", "output"},),
    "block_id_comparators": ({"id", "left_height", "left_suffix", "operation", "ordering", "right_height", "right_suffix"},),
    "market": ({"bytes", "id", "name", "result"}, {"id", "left", "name", "ordering", "right"}, {"id", "left_price", "name", "operation", "ordering", "right_price"}, {"id", "left_price", "name", "ordering", "path", "right_price"}),
}

def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fail(errors: list[str]) -> None:
    for error in errors:
        print(f"C002 gate: {error}", file=sys.stderr)
    raise SystemExit(1)


def validate_manifest(
    document: object,
    label: str,
    prefix: str,
    required_groups: set[str],
    errors: list[str],
) -> tuple[dict[str, list[dict[str, object]]], int]:
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        errors.append(f"{label} must be a schema_version 1 object")
        return {}, 0
    groups = document.get("vectors")
    if not isinstance(groups, dict):
        errors.append(f"{label}.vectors must be an object")
        return {}, 0
    actual_groups = set(groups)
    if actual_groups != required_groups:
        errors.append(f"{label} groups differ: missing={sorted(required_groups - actual_groups)} extra={sorted(actual_groups - required_groups)}")

    seen: set[str] = set()
    count = 0
    for group in sorted(required_groups):
        rows = groups.get(group)
        if not isinstance(rows, list) or not rows:
            errors.append(f"{label}.{group} must be a non-empty array")
            continue
        for index, row in enumerate(rows):
            count += 1
            location = f"{label}.{group}[{index}]"
            if not isinstance(row, dict):
                errors.append(f"{location} must be an object")
                continue
            case_id = row.get("id")
            if not isinstance(case_id, str) or re.fullmatch(rf"{re.escape(prefix)}\d{{3}}", case_id) is None:
                errors.append(f"{location} has invalid case ID: {case_id!r}")
            elif case_id in seen:
                errors.append(f"duplicate case ID in {label}: {case_id}")
            else:
                seen.add(case_id)
            schemas = ROW_SCHEMAS[group]
            actual_keys = set(row)
            if actual_keys not in schemas:
                errors.append(f"{location} has unconsumed/unexpected or missing fields: actual={sorted(actual_keys)} allowed={[sorted(schema) for schema in schemas]}")
    expected_ids = {f"{prefix}{index:03d}" for index in range(1, count + 1)}
    if seen != expected_ids:
        errors.append(f"{label} case IDs are not complete/contiguous: missing={sorted(expected_ids - seen)} extra={sorted(seen - expected_ids)}")
    return groups, count


def require_cases(groups: dict[str, list[dict[str, object]]], group: str, key: str, required: set[str], errors: list[str]) -> None:
    actual = {str(row.get(key)) for row in groups.get(group, []) if isinstance(row, dict)}
    missing = required - actual
    if missing:
        errors.append(f"{group} missing cases: {sorted(missing)}")


def main() -> None:
    errors: list[str] = []
    try:
        coverage = json.loads(COVERAGE.read_text())
        vectors = json.loads(VECTORS.read_text())
        fixtures = json.loads(FIXTURES.read_text())
    except (OSError, json.JSONDecodeError) as error:
        fail([f"cannot load manifest: {error}"])

    rows = coverage.get("coverage", []) if isinstance(coverage, dict) else []
    ids = {row.get("id") for row in rows if isinstance(row, dict)}
    if ids != REQUIRED_IDS:
        errors.append(f"coverage IDs differ: missing={sorted(REQUIRED_IDS - ids)} extra={sorted(ids - REQUIRED_IDS)}")
    pinned_sources: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            errors.append("coverage rows must be objects")
            continue
        rust_names = str(row.get("rust", "")).split(",")
        for name in rust_names:
            if not name or not (CRATE / name).is_file():
                errors.append(f"missing Rust primitive source for {row.get('id')}: {name!r}")
        sources = row.get("java_sources")
        if not isinstance(sources, list) or not sources:
            errors.append(f"{row.get('id')} has no Java source evidence")
            continue
        for source in sources:
            if not isinstance(source, dict) or set(source) != {"path", "sha256"}:
                errors.append(f"{row.get('id')} has malformed Java source evidence")
                continue
            path_value = source["path"]
            pinned_sources.add(path_value)
            path = ROOT / path_value
            if not path.is_file():
                errors.append(f"missing Java source: {path_value}")
            elif digest(path) != source["sha256"]:
                errors.append(f"Java source digest drift: {path_value}")
    missing_wrappers = PINNED_MATH_WRAPPERS - pinned_sources
    if missing_wrappers:
        errors.append(f"coverage does not pin both architecture MathWrapper sources: {sorted(missing_wrappers)}")

    seams = {row.get("chunk") for row in coverage.get("cross_chunk_seams", []) if isinstance(row, dict)}
    if seams != REQUIRED_SEAMS:
        errors.append(f"cross-chunk seams differ: missing={sorted(REQUIRED_SEAMS - seams)} extra={sorted(seams - REQUIRED_SEAMS)}")
    for row in coverage.get("cross_chunk_seams", []):
        boundary = str(row.get("boundary", ""))
        if "owns" not in boundary or "C002 supplies" not in boundary:
            errors.append(f"seam {row.get('chunk')} must distinguish supplied primitives from later ownership")

    groups, vector_count = validate_manifest(vectors, "java vectors", "C002.J.", REQUIRED_VECTOR_GROUPS, errors)
    fixture_groups, fixture_count = validate_manifest(fixtures, "fixtures", "C002.F.", REQUIRED_FIXTURE_GROUPS, errors)
    require_cases(groups, "math", "operation", {"add_i64", "subtract_i64", "multiply_i64", "policy"}, errors)
    require_cases(groups, "bytes_order_null", "operation", {"locale_root_lowercase_key", "locale_root_uppercase_key"}, errors)
    require_cases(groups, "bigint_fixed_bytes", "boundary", {"overlong_positive_preserves_source_start", "positive_leading_sign", "negative_leading_sign", "overlong_negative_preserves_source_start"}, errors)
    require_cases(groups, "bigint_fixed_bytes", "operation", {"bigint_to_fixed_bytes"}, errors)
    require_cases(groups, "raw_hash_inputs", "operation", {"transaction_provider_isolation", "block_provider_isolation"}, errors)
    require_cases(groups, "block_id_inconsistency", "operation", {"height_compare", "total_bytes_compare", "cmp_hash"}, errors)
    require_cases(groups, "market_comparator", "case", {"pair_first", "both_zero_price", "one_zero_price", "checked_cross_product", "big_integer_fallback", "positive_big_integer_long_truncation", "short_key"}, errors)
    require_cases(fixture_groups, "arithmetic", "operation", {"add_i64", "subtract_i64", "multiply_i64", "policy"}, errors)
    require_cases(fixture_groups, "wire_hash_boundaries", "operation", {"transaction_provider_isolation", "block_provider_isolation"}, errors)
    require_cases(fixture_groups, "block_id_comparators", "operation", {"height_compare", "total_bytes_compare"}, errors)
    require_cases(fixture_groups, "bigint_fixed_bytes", "boundary", {"overlong_positive_preserves_source_start", "positive_leading_sign", "negative_leading_sign", "overlong_negative_preserves_source_start"}, errors)
    require_cases(fixture_groups, "bigint_fixed_bytes", "operation", {"bigint_to_fixed_bytes"}, errors)
    require_cases(fixture_groups, "unicode_keys", "operation", {"locale_root_lowercase_key", "locale_root_uppercase_key"}, errors)
    for source_groups, label in ((groups, "java vectors"), (fixture_groups, "fixtures")):
        unicode_cases = {
            (row.get("operation"), row.get("input"), row.get("output"))
            for row in source_groups.get("unicode_keys", source_groups.get("bytes_order_null", []))
        }
        missing_unicode_cases = REQUIRED_UNICODE_CASES - unicode_cases
        if missing_unicode_cases:
            errors.append(f"{label} missing Unicode casing cases: {sorted(missing_unicode_cases)}")

    for source_groups, label in ((groups, "java vectors"), (fixture_groups, "fixtures")):
        for group, group_rows in source_groups.items():
            for row in group_rows:
                operation = row.get("operation")
                if operation in {"add_i64", "subtract_i64", "multiply_i64"} and row.get("error") != "overflow":
                    errors.append(f"{label} {row.get('id')} must encode overflow as an exception")

    if errors:
        fail(errors)
    print(f"C002 coverage: {len(ids)} IDs, {vector_count} Java vectors, {fixture_count} fixtures, {len(seams)} seams")


if __name__ == "__main__":
    main()

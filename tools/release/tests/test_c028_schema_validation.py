from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("c028_gate_schema_tests", ROOT / "tools/release/c028_gate.py")
assert SPEC is not None and SPEC.loader is not None
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class C028SchemaValidationTests(unittest.TestCase):
    def load(self, relative: str):
        return json.loads((ROOT / "docs/oracles" / relative).read_text(encoding="utf-8"))

    def test_every_c028_document_uses_valid_draft_2020_12_schema(self) -> None:
        self.assertEqual(GATE.verify_schemas(), {"validated_documents": 6, "json_schema_draft": "2020-12"})

    def test_nested_type_pattern_const_and_additional_properties_are_enforced(self) -> None:
        cases = []
        for document_name, schema_name in GATE.SCHEMAS.items():
            document = self.load(document_name)
            document["reviewer_extra"] = True
            cases.append((document_name, document, self.load("schemas/" + schema_name)))

        reconciliation = self.load("c028-production-reconciliation.v1.json")
        reconciliation["rows"][0]["source"]["sha256"] = "invalid"
        cases.append(("nested pattern", reconciliation, self.load("schemas/c028-production-reconciliation-v1.schema.json")))

        release = self.load("c028-release-contract.v1.json")
        release["platforms"][0]["platform_id"] = "P-OTHER"
        cases.append(("nested const", release, self.load("schemas/c028-release-contract-v1.schema.json")))

        busybox = self.load("c028-busybox-material.v1.json")
        busybox["elf"]["class"] = "64"
        cases.append(("nested type", busybox, self.load("schemas/c028-busybox-material-v1.schema.json")))

        for label, document, schema in cases:
            with self.subTest(label=label), self.assertRaises(RuntimeError):
                GATE.validate_document(document, schema, label)

    def test_workflow_metadata_rejects_every_field_mutation_missing_and_extra_field(self) -> None:
        document = self.load("c028-workflow-metadata.v1.json")
        schema = self.load("schemas/c028-workflow-metadata-v1.schema.json")
        mutations = []
        for field, value in document.items():
            mutated = copy.deepcopy(document)
            mutated[field] = 0 if isinstance(value, int) else ""
            mutations.append((field, mutated))
        missing = copy.deepcopy(document)
        missing.pop("repository")
        mutations.append(("missing", missing))
        extra = copy.deepcopy(document)
        extra["reviewer_extra"] = True
        mutations.append(("extra", extra))
        for label, mutated in mutations:
            with self.subTest(label=label), self.assertRaises(RuntimeError):
                GATE.validate_document(mutated, schema, label)

    def test_cross_document_execution_and_recovery_mutations_are_rejected(self) -> None:
        commands = self.load("c028-command-manifest.v1.json")
        recovery = self.load("c028-recovery-matrix.v1.json")
        mutations = []
        for field, value in (("platform_id", "P-OTHER"), ("owning_item", "C028.10"), ("expected_exit", 1), ("assertions", ["weaker"]), ("timeout_seconds", 1)):
            mutated = copy.deepcopy(commands)
            mutated["commands"][0][field] = value
            mutations.append((field, mutated, recovery))
        negative = copy.deepcopy(recovery)
        negative["negative_drill_ids"].pop()
        mutations.append(("negative ids", commands, negative))
        phases = copy.deepcopy(recovery)
        phases["fault_phases"].reverse()
        mutations.append(("fault phases", commands, phases))
        for label, command_value, recovery_value in mutations:
            with self.subTest(label=label), self.assertRaises(RuntimeError):
                GATE.verify_drills(command_value, recovery_value)


if __name__ == "__main__":
    unittest.main()

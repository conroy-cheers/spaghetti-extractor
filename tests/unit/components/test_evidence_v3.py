"""Candidate-only component evidence and qualification tests."""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.evidence import produce_component_evidence_v3
from spaghetti_extractor.components.formats import COMPONENT_CONTRACT_PACKAGE_V2_FORMAT
from spaghetti_extractor.components.qualification import qualify_lift_unit_v3
from spaghetti_extractor.components.source import build_component_source_package_v2
from spaghetti_extractor.reconstruction_ir import MACHINE_IR_FORMAT


class ComponentEvidenceV3Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.machine = self.root / "machine"
        self.machine.mkdir()
        self.contract = self.root / "contract"
        self.contract.mkdir()
        self.source_file = self.root / "component.c"
        self._write_machine()
        self._write_contract()
        self.verification = {
            "producer": "exhaustive-finite-domain-v1",
            "parameter_domains": [
                {
                    "parameter_id": "value",
                    "kind": "integer-range",
                    "minimum": 0,
                    "maximum": 255,
                }
            ],
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_exhaustive_evidence_qualifies_exact_logical_c(self) -> None:
        package = self._source("uint32_t identity(uint32_t value) { return value; }\n")
        evidence = produce_component_evidence_v3(
            contract=self.contract,
            implementation=package,
            machine_ir=self.machine,
            verification=self.verification,
            compiler=shutil.which("cc") or "cc",
            out=self.root / "evidence.json",
        )
        self.assertEqual(evidence["status"], "satisfied")
        self.assertEqual(evidence["coverage"]["cases"], 256)
        qualification = qualify_lift_unit_v3(
            contract=self.contract / "contract.json",
            implementation=package,
            evidence=evidence,
            machine_ir=self.machine,
            verification=self.verification,
            out=self.root / "qualification.json",
        )
        self.assertEqual(qualification["status"], "qualified")
        self.assertTrue(qualification["activation"]["authorized"])

    def test_counterexample_is_violated_and_source_mapped(self) -> None:
        package = self._source(
            "uint32_t identity(uint32_t value) { return value + 1U; }\n"
        )
        evidence = produce_component_evidence_v3(
            contract=self.contract,
            implementation=package,
            machine_ir=self.machine,
            verification=self.verification,
            compiler=shutil.which("cc") or "cc",
            out=self.root / "violated.json",
        )
        self.assertEqual(evidence["status"], "violated")
        counterexample = evidence["coverage"]["first_counterexample"]
        self.assertEqual(counterexample["arguments"], {"value": 0})
        self.assertEqual(counterexample["expected"], 0)
        self.assertEqual(counterexample["observed"], 1)

    def _source(self, text: str) -> Path:
        self.source_file.write_text(
            "#include <stdint.h>\n" + text,
            encoding="ascii",
        )
        package = self.root / ("source-" + hashlib.sha256(text.encode()).hexdigest()[:8])
        build_component_source_package_v2(
            lift_unit_id="identity",
            files={"component.c": self.source_file},
            shared_inputs={},
            entry={"abi": "logical-c-v1", "symbol": "identity"},
            out_dir=package,
        )
        return package

    def _write_machine(self) -> None:
        load_argument = {
            "op": "load",
            "width": 4,
            "address": {
                "op": "add32",
                "args": [
                    {"op": "const", "value": 4, "width": 32},
                    {"op": "reg", "name": "esp", "width": 32},
                ],
            },
        }
        unit = {
            "format": MACHINE_IR_FORMAT,
            "record_kind": "unit",
            "id": "unit:identity",
            "source": {
                "contract_sha256": "1" * 64,
                "instruction_bytes_sha256": "2" * 64,
                "original": {"rva_start": 0x1000, "rva_end": 0x1008},
            },
            "semantics": {
                "register_writes": [
                    {"register": "eax", "value": load_argument},
                    {
                        "register": "esp",
                        "value": {
                            "op": "add32",
                            "args": [
                                {"op": "const", "value": 4, "width": 32},
                                {"op": "reg", "name": "esp", "width": 32},
                            ],
                        },
                    },
                ],
                "flag_writes": [],
                "memory_events": [
                    {"kind": "read", "width": 4, "address": load_argument["address"]}
                ],
                "external_events": [],
                "faults": [],
                "outcome": {
                    "kind": "return",
                    "value": {
                        "op": "load",
                        "width": 4,
                        "address": {"op": "reg", "name": "esp", "width": 32},
                    },
                },
            },
        }
        ir = self.machine / "machine-ir.jsonl"
        ir.write_text(json.dumps(unit, sort_keys=True) + "\n", encoding="ascii")
        manifest = {
            "format": MACHINE_IR_FORMAT,
            "artifacts": {
                "machine_ir": {"path": ir.name, "sha256": _file_hash(ir)}
            },
            "binary": {"sha256": "3" * 64},
        }
        _write(self.machine / "machine-ir-manifest.json", manifest)

    def _write_contract(self) -> None:
        expression = json.loads(
            (self.machine / "machine-ir.jsonl").read_text(encoding="ascii")
        )["semantics"]["register_writes"][0]["value"]
        interface = {
            "parameters": [
                {
                    "id": "value",
                    "type": "uint32_t",
                    "machine_source": {
                        "kind": "expression",
                        "expression": expression,
                        "evidence": {
                            "unit_id": "unit:identity",
                            "json_pointer": "/semantics/register_writes/0/value",
                        },
                    },
                }
            ],
            "results": [
                {
                    "id": "result",
                    "kind": "return",
                    "type": "uint32_t",
                    "machine_source": {
                        "kind": "expression",
                        "expression": expression,
                        "evidence": {
                            "unit_id": "unit:identity",
                            "json_pointer": "/semantics/register_writes/0/value",
                        },
                    },
                    "effect_refs": [
                        {
                            "family": "register_write",
                            "unit_id": "unit:identity",
                            "index": 0,
                        }
                    ],
                }
            ],
            "objects": [],
            "services": [],
            "adapter_effects": [],
            "claims": [],
            "policy": {},
        }
        _write(self.contract / "reviewed-interface.json", interface)
        core = {
            "format": COMPONENT_CONTRACT_PACKAGE_V2_FORMAT,
            "status": "checked",
            "lift_unit": {
                "kind": "component",
                "id": "identity",
                "label": "Identity",
                "unit_ids": ["unit:identity"],
                "evidence_profile": "bounded-equivalence-v1",
            },
            "bindings": {},
            "authority": {},
            "review": {},
            "artifacts": {},
            "blockers": [],
        }
        _write(
            self.contract / "contract.json",
            {**core, "contract_sha256": _canonical_hash(core)},
        )


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="ascii")


def _file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


if __name__ == "__main__":
    unittest.main()

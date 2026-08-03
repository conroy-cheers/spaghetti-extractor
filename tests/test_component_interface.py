from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifact_formats import (
    COMPONENT_INTERFACE_REFINEMENT_FORMAT,
    COMPONENT_INTERFACE_SPEC_FORMAT,
    SEMANTIC_COMPONENT_CATALOG_FORMAT,
)
from spaghetti_extractor.component_interface import (
    check_component_interface,
    finalize_component_interface_spec,
    synthesize_component_interface_spec,
)
from spaghetti_extractor.reconstruction_ir import MACHINE_IR_FORMAT


class ComponentInterfaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_synthesized_compare_interface_is_checked(self) -> None:
        machine, catalog = self._package([_compare_unit()])

        spec = synthesize_component_interface_spec(
            catalog=catalog,
            machine_ir=machine,
            component_id="compare-route",
        )
        result = check_component_interface(
            catalog=catalog,
            machine_ir=machine,
            component_id="compare-route",
            interface_spec=spec,
        )

        self.assertEqual(spec["format"], COMPONENT_INTERFACE_SPEC_FORMAT)
        self.assertEqual(result["format"], COMPONENT_INTERFACE_REFINEMENT_FORMAT)
        self.assertEqual(result["status"], "checked")
        self.assertEqual(result["issues"], [])
        self.assertFalse(result["executes_original_binary"])
        self.assertEqual(
            result["component"],
            {"id": "compare-route", "sha256": self._component(catalog)["component_sha256"]},
        )
        self.assertNotIn("catalog_artifact_sha256", result["bindings"])
        self.assertTrue(result["coverage"]["complete"])
        self.assertEqual(result["logical_interface"]["parameters"], spec["parameters"])
        self.assertEqual(
            result["refinement_sha256"],
            _canonical_sha256(
                {
                    key: value
                    for key, value in result.items()
                    if key != "refinement_sha256"
                }
            ),
        )

    def test_synthesis_does_not_treat_architectural_pre_state_as_liveness(self) -> None:
        unit = _compare_unit()
        unit["semantics"]["pre_state"] = {
            "registers": {
                name: _reg(name)
                for name in (
                    "eax",
                    "ebx",
                    "ecx",
                    "edx",
                    "esi",
                    "edi",
                    "ebp",
                    "esp",
                )
            }
        }
        machine, catalog = self._package([unit])

        spec = synthesize_component_interface_spec(
            catalog=catalog,
            machine_ir=machine,
            component_id="compare-route",
        )

        self.assertEqual(
            [item["id"] for item in spec["parameters"]],
            ["input_eax", "input_ebx"],
        )

    def test_eax_edx_declaration_precisely_violates_ebx_eax_machine_sources(self) -> None:
        machine, catalog = self._package([_compare_unit()])
        spec = synthesize_component_interface_spec(
            catalog=catalog,
            machine_ir=machine,
            component_id="compare-route",
        )
        by_id = {item["id"]: item for item in spec["parameters"]}
        spec["parameters"] = [
            {
                "id": "left",
                "type": "uint32_t",
                "machine_source": {
                    **copy.deepcopy(by_id["input_ebx"]["machine_source"]),
                    "name": "eax",
                },
            },
            {
                "id": "right",
                "type": "uint32_t",
                "machine_source": {
                    **copy.deepcopy(by_id["input_eax"]["machine_source"]),
                    "name": "edx",
                },
            },
        ]
        spec = finalize_component_interface_spec(spec)

        result = check_component_interface(
            catalog=catalog,
            machine_ir=machine,
            component_id="compare-route",
            interface_spec=spec,
        )

        self.assertEqual(result["status"], "violated")
        mismatches = [
            issue
            for issue in result["issues"]
            if issue["code"] == "machine_source_expression_mismatch"
        ]
        self.assertEqual(len(mismatches), 2)
        self.assertEqual(mismatches[0]["json_location"], "/parameters/0/machine_source")
        self.assertEqual(mismatches[0]["unit_id"], "unit:compare")
        self.assertEqual(mismatches[0]["rva"], 0x1038)
        self.assertEqual(
            mismatches[0]["expected"], {"op": "reg", "name": "eax", "width": 32}
        )
        self.assertEqual(
            mismatches[0]["observed"], {"op": "reg", "name": "ebx", "width": 32}
        )
        self.assertEqual(
            mismatches[1]["expected"], {"op": "reg", "name": "edx", "width": 32}
        )
        self.assertEqual(
            mismatches[1]["observed"], {"op": "reg", "name": "eax", "width": 32}
        )
        self.assertTrue(all(issue["remediation"] for issue in mismatches))

    def test_omitted_memory_and_external_events_are_incomplete_despite_claims(self) -> None:
        machine, catalog = self._package([_io_unit()])
        spec = synthesize_component_interface_spec(
            catalog=catalog,
            machine_ir=machine,
            component_id="compare-route",
        )
        spec["objects"] = []
        spec["services"] = []
        spec["claims"] = [
            {
                "claim": "all memory effects and calls are represented",
                "status": "validated",
            }
        ]
        spec = finalize_component_interface_spec(spec)

        result = check_component_interface(
            catalog=catalog,
            machine_ir=machine,
            component_id="compare-route",
            interface_spec=spec,
        )

        self.assertEqual(result["status"], "incomplete")
        missing = [
            issue["expected"]["family"]
            for issue in result["issues"]
            if issue["code"] == "unrepresented_machine_effect"
        ]
        self.assertEqual(missing, ["memory_event", "external_event"])
        self.assertEqual(result["policy"]["english_claims_authority"], "none")
        self.assertEqual(result["coverage"]["unrepresented"], 2)

    def test_synthesized_object_and_service_bind_exact_machine_effects(self) -> None:
        machine, catalog = self._package([_io_unit()])
        spec = synthesize_component_interface_spec(
            catalog=catalog,
            machine_ir=machine,
            component_id="compare-route",
        )

        result = check_component_interface(
            catalog=catalog,
            machine_ir=machine,
            component_id="compare-route",
            interface_spec=spec,
        )

        self.assertEqual(result["status"], "checked")
        self.assertEqual(spec["objects"][0]["fields"][0]["width"], 4)
        self.assertEqual(
            spec["objects"][0]["fields"][0]["permissions"], ["write"]
        )
        self.assertEqual(
            spec["services"][0]["identity"],
            {
                "kind": "external_call",
                "dll": "kernel32.dll",
                "symbol": "WriteFile",
                "ordinal": None,
                "return_rva": 0x2010,
            },
        )
        self.assertEqual(spec["services"][0]["events"][0]["arguments"], [_reg("eax")])
        self.assertEqual(result["coverage"]["represented_once"], 3)

    def test_checked_internal_control_table_read_may_be_adapter_owned(self) -> None:
        address = {
            "op": "add32",
            "args": [
                _const(0x421B1C),
                {"op": "mul32", "args": [_reg("eax"), _const(4)]},
            ],
        }
        unit = _unit(
            "unit:dispatch",
            0x5898,
            0x589F,
            semantics={
                "register_writes": [],
                "flag_writes": [],
                "memory_events": [
                    {"kind": "read", "width": 4, "address": address}
                ],
                "external_events": [],
                "faults": [],
                "outcome": {
                    "kind": "indirect_jump",
                    "target": {"op": "load", "width": 4, "address": address},
                },
            },
        )
        machine, catalog = self._package([unit])
        catalog_payload = json.loads(catalog.read_text(encoding="utf-8"))
        component = catalog_payload["components"][0]
        component.pop("component_sha256")
        component["machine_boundary"] = {
            "exits": [],
            "internal_indirect_controls": [
                {
                    "kind": "indirect_jump",
                    "target_expression": {
                        "op": "load",
                        "width": 4,
                        "address": address,
                    },
                    "internal_target_unit_ids": ["unit:dispatch"],
                    "external_target_unit_ids": [],
                    "target_inventory": {
                        "status": "recovered",
                        "closure": "checked_finite_target_inventory",
                        "failure": None,
                    },
                }
            ]
        }
        component["component_sha256"] = _canonical_sha256(component)
        catalog_payload.pop("catalog_sha256")
        catalog_payload["catalog_sha256"] = _canonical_sha256(catalog_payload)
        _write_json(catalog, catalog_payload)
        spec = synthesize_component_interface_spec(
            catalog=catalog,
            machine_ir=machine,
            component_id="compare-route",
        )
        reference = spec["objects"][0]["fields"][0]["event_refs"][0]
        spec["objects"] = []
        spec["adapter_effects"].append(
            {
                "effect": reference,
                "reason": "internal_control_table_projection",
            }
        )
        spec = finalize_component_interface_spec(spec)

        result = check_component_interface(
            catalog=catalog,
            machine_ir=machine,
            component_id="compare-route",
            interface_spec=spec,
        )

        self.assertEqual(result["status"], "checked")
        self.assertEqual(result["coverage"]["represented_once"], 1)

    def test_stale_binding_is_violated(self) -> None:
        machine, catalog = self._package([_compare_unit()])
        spec = synthesize_component_interface_spec(
            catalog=catalog,
            machine_ir=machine,
            component_id="compare-route",
        )
        spec["bindings"]["machine_ir_sha256"] = "9" * 64
        spec = finalize_component_interface_spec(spec)

        result = check_component_interface(
            catalog=catalog,
            machine_ir=machine,
            component_id="compare-route",
            interface_spec=spec,
        )

        self.assertEqual(result["status"], "violated")
        issue = next(
            issue
            for issue in result["issues"]
            if issue["code"] == "interface_binding_mismatch"
            and issue["json_location"] == "/bindings/machine_ir_sha256"
        )
        self.assertNotEqual(issue["expected"], issue["observed"])
        self.assertIsNone(issue["unit_id"])
        self.assertIsNone(issue["rva"])

    def test_output_and_issue_ids_are_deterministic(self) -> None:
        machine, catalog = self._package([_compare_unit()])
        spec = synthesize_component_interface_spec(
            catalog=catalog,
            machine_ir=machine,
            component_id="compare-route",
        )
        spec["parameters"][0]["machine_source"]["name"] = "edx"
        spec = finalize_component_interface_spec(spec)

        first = check_component_interface(
            catalog=catalog,
            machine_ir=machine,
            component_id="compare-route",
            interface_spec=spec,
        )
        second = check_component_interface(
            catalog=catalog,
            machine_ir=machine,
            component_id="compare-route",
            interface_spec=spec,
        )

        self.assertEqual(first, second)
        self.assertEqual(
            [issue["id"] for issue in first["issues"]],
            [issue["id"] for issue in second["issues"]],
        )

    def _package(self, units: list[dict[str, object]]) -> tuple[Path, Path]:
        machine = self.root / "machine"
        machine.mkdir()
        ir_path = machine / "machine-ir.jsonl"
        ir_path.write_text(
            "".join(json.dumps(unit, sort_keys=True) + "\n" for unit in units),
            encoding="utf-8",
        )
        manifest = {
            "format": MACHINE_IR_FORMAT,
            "artifacts": {
                "machine_ir": {
                    "path": "machine-ir.jsonl",
                    "sha256": _file_sha256(ir_path),
                }
            },
            "binary": {"sha256": "1" * 64},
        }
        manifest_path = machine / "machine-ir-manifest.json"
        _write_json(manifest_path, manifest)

        component_core = {
            "id": "compare-route",
            "definition_status": "valid",
            "membership": {
                "resolved_unit_ids": [str(unit["id"]) for unit in units],
            },
            "logical_interface": {
                "status": "proposed",
                "parameters": [],
                "results": [],
                "objects": [],
                "services": [],
                "postconditions": [
                    {"claim": "this prose is intentionally non-authoritative"}
                ],
            },
        }
        component = {
            **component_core,
            "component_sha256": _canonical_sha256(component_core),
        }
        catalog_core = {
            "format": SEMANTIC_COMPONENT_CATALOG_FORMAT,
            "status": "incomplete",
            "definition_status": "valid",
            "bindings": {
                "machine_ir_sha256": _file_sha256(ir_path),
                "machine_ir_manifest_sha256": _file_sha256(manifest_path),
                "original_binary_sha256": "1" * 64,
            },
            "components": [component],
        }
        catalog_payload = {
            **catalog_core,
            "catalog_sha256": _canonical_sha256(catalog_core),
        }
        catalog_path = self.root / "catalog.json"
        _write_json(catalog_path, catalog_payload)
        return machine, catalog_path

    @staticmethod
    def _component(catalog: Path) -> dict[str, object]:
        return json.loads(catalog.read_text(encoding="utf-8"))["components"][0]


def _compare_unit() -> dict[str, object]:
    left = _reg("ebx")
    right = _reg("eax")
    difference = {"op": "sub32", "args": [left, right]}
    condition = {"op": "eq", "args": [difference, _const(0)]}
    return _unit(
        "unit:compare",
        0x1038,
        0x1040,
        semantics={
            "register_writes": [],
            "flag_writes": [{"flag": "zf", "value": condition}],
            "memory_events": [],
            "external_events": [],
            "faults": [],
            "outcome": {
                "kind": "branch",
                "condition": condition,
                "true_target_rva": 0x1118,
                "false_target_rva": 0x1040,
            },
        },
    )


def _io_unit() -> dict[str, object]:
    event = {
        "kind": "external_call",
        "dll": "kernel32.dll",
        "symbol": "WriteFile",
        "ordinal": None,
        "return_rva": 0x2010,
        "arguments": [_reg("eax")],
    }
    return _unit(
        "unit:io",
        0x2000,
        0x2010,
        semantics={
            "register_writes": [],
            "flag_writes": [],
            "memory_events": [
                {
                    "kind": "write",
                    "width": 4,
                    "address": _reg("eax"),
                    "value": _const(7),
                }
            ],
            "external_events": [event],
            "faults": [],
            "outcome": {
                "kind": "return",
                "value": {
                    "op": "load",
                    "width": 4,
                    "address": _reg("esp"),
                },
            },
        },
    )


def _unit(
    identity: str,
    start: int,
    end: int,
    *,
    semantics: dict[str, object],
) -> dict[str, object]:
    return {
        "format": MACHINE_IR_FORMAT,
        "record_kind": "unit",
        "id": identity,
        "source": {"original": {"rva_start": start, "rva_end": end}},
        "semantics": semantics,
    }


def _reg(name: str) -> dict[str, object]:
    return {"op": "reg", "name": name, "width": 32}


def _const(value: int) -> dict[str, object]:
    return {"op": "const", "value": value, "width": 32}


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


if __name__ == "__main__":
    unittest.main()

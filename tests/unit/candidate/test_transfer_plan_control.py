from __future__ import annotations

import json
from hashlib import sha256
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.transfer.model import TransferPlanError
from spaghetti_extractor.transfer.plan import (
    load_executable_transfer_plan,
    write_executable_transfer_plan,
)
from spaghetti_extractor.testkit.transfer_fixture import (
    as_machine_ir_unit as _test_machine_ir_unit,
    transfer_row as _row,
    write_fixture_transfer_plan as _write_transfer_plan,
)
from tests.unit.candidate.test_transfer_plan import _write_machine


class TransferPlanFiniteControlTests(unittest.TestCase):
    def test_checked_finite_routes_are_compiled_into_canonical_ir(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "machine-ir.jsonl"
            row = _row()
            index_expression = {"op": "reg", "name": "eax", "width": 32}
            target_expression = {
                "op": "load",
                "width": 4,
                "address": {
                    "op": "add32",
                    "args": [
                        {"op": "const", "value": 0x401800, "width": 32},
                        {
                            "op": "mul32",
                            "args": [
                                index_expression,
                                {"op": "const", "value": 4, "width": 32},
                            ],
                        },
                    ],
                },
            }
            row["outcome"] = {
                "kind": "indirect_jump",
                "target": target_expression,
            }
            targets = []
            for identity, start in (("target:a", 0x2000), ("target:b", 0x3000)):
                target = _row()
                target["id"] = identity
                target["original"] = {
                    "rva_start": start,
                    "rva_end": start + 1,
                    "size": 1,
                }
                target["register_writes"] = []
                target["outcome"] = {
                    "kind": "return",
                    "value": {"op": "const", "value": 0, "width": 32},
                }
                targets.append(_test_machine_ir_unit(target))
            _write_machine(machine, [_test_machine_ir_unit(row), *targets])
            _write_transfer_plan(machine)
            manifest = root / "machine-ir-transfer-manifest.json"
            manifest_payload = json.loads(manifest.read_text(encoding="utf-8"))
            manifest_payload["binary"].update(
                {"image_base": 0x400000, "size_of_image": 0x4000}
            )
            entry_bytes = [
                (0x402000).to_bytes(4, "little"),
                (0x403000).to_bytes(4, "little"),
            ]
            inventory_bytes = b"".join(
                index.to_bytes(4, "little") + raw
                for index, raw in enumerate(entry_bytes)
            )
            manifest_payload["control"] = {
                "recovered_indirect_targets": [{
                    "source_unit_id": "semantic-transfer:fixture",
                    "source_rva": 0x1000,
                    "status": "recovered",
                    "closure": "checked_finite_target_inventory",
                    "failure": None,
                    "target_expression": target_expression,
                    "index": {
                        "expression": index_expression,
                        "lower_inclusive": 0,
                        "upper_exclusive": 2,
                        "values": [0, 1],
                        "value_count": 2,
                        "dataflow_evidence": None,
                        "remap": None,
                        "bound_evidence": [{
                            "source_unit_id": "bound",
                            "upper_exclusive": 2,
                            "sources": ["guard"],
                        }],
                    },
                    "table": {
                        "address": 0x401800,
                        "address_model": "virtual_address",
                        "expression_form": "multiply_4",
                        "rva_start": 0x1800,
                        "rva_end": 0x1808,
                        "entry_width": 4,
                        "entry_count": 2,
                        "index_values": [0, 1],
                        "contiguous": True,
                        "section": ".rdata",
                        "bytes_sha256": sha256(b"".join(entry_bytes)).hexdigest(),
                        "inventory_sha256": sha256(inventory_bytes).hexdigest(),
                    },
                    "entries": [
                        {"index": 0, "entry_address": 0x401800,
                         "entry_rva": 0x1800, "bytes_le": list(entry_bytes[0]),
                         "target_rva": 0x2000, "target_address": 0x402000},
                        {"index": 1, "entry_address": 0x401804,
                         "entry_rva": 0x1804, "bytes_le": list(entry_bytes[1]),
                         "target_rva": 0x3000, "target_address": 0x403000},
                    ],
                }],
            }
            manifest.write_text(
                json.dumps(manifest_payload, sort_keys=True), encoding="utf-8"
            )
            output = root / "with-routes"
            payload = write_executable_transfer_plan(
                machine_ir=machine,
                machine_ir_manifest=manifest,
                out=output,
            )
            decoded, _transfers = load_executable_transfer_plan(
                output / "executable-transfer-plan.json", require_complete=True
            )

        self.assertEqual(decoded["finite_control_routes"], payload[
            "finite_control_routes"
        ])
        self.assertEqual(
            payload["finite_control_routes"][0]["index_provenance"],
            {"kind": "direct_index"},
        )
        self.assertEqual(
            payload["finite_control_routes"][0]["routes"],
            [
                {"selector_value": 0, "entry_address": 0x401800,
                 "entry_rva": 0x1800, "bytes_le": list(entry_bytes[0]),
                 "target_rva": 0x2000, "target_address": 0x402000},
                {"selector_value": 1, "entry_address": 0x401804,
                 "entry_rva": 0x1804, "bytes_le": list(entry_bytes[1]),
                 "target_rva": 0x3000, "target_address": 0x403000},
            ],
        )

    def test_checked_remapped_finite_routes_remain_closure_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "machine-ir.jsonl"
            source_expression = {"op": "reg", "name": "eax", "width": 32}
            remap_address = {
                "op": "add32",
                "args": [
                    {"op": "const", "value": 0x401900, "width": 32},
                    source_expression,
                ],
            }
            index_expression = {
                "op": "load",
                "width": 1,
                "address": remap_address,
            }
            target_expression = {
                "op": "load",
                "width": 4,
                "address": {
                    "op": "add32",
                    "args": [
                        {"op": "const", "value": 0x401800, "width": 32},
                        {
                            "op": "mul32",
                            "args": [
                                index_expression,
                                {"op": "const", "value": 4, "width": 32},
                            ],
                        },
                    ],
                },
            }
            row = _row()
            row["outcome"] = {
                "kind": "indirect_jump",
                "target": target_expression,
            }
            targets = []
            for identity, start in (("target:a", 0x2000), ("target:b", 0x3000)):
                target = _row()
                target["id"] = identity
                target["original"] = {
                    "rva_start": start,
                    "rva_end": start + 1,
                    "size": 1,
                }
                target["register_writes"] = []
                target["outcome"] = {
                    "kind": "return",
                    "value": {"op": "const", "value": 0, "width": 32},
                }
                targets.append(_test_machine_ir_unit(target))
            _write_machine(machine, [_test_machine_ir_unit(row), *targets])
            _write_transfer_plan(machine)
            manifest = root / "machine-ir-transfer-manifest.json"
            manifest_payload = json.loads(manifest.read_text(encoding="utf-8"))
            manifest_payload["binary"].update(
                {"image_base": 0x400000, "size_of_image": 0x4000}
            )
            entry_bytes = [
                (0x402000).to_bytes(4, "little"),
                (0x403000).to_bytes(4, "little"),
            ]
            remap_bytes = bytes((0, 1, 1))
            inventory_bytes = b"".join(
                index.to_bytes(4, "little") + raw
                for index, raw in enumerate(entry_bytes)
            )
            manifest_payload["control"] = {
                "recovered_indirect_targets": [{
                    "source_unit_id": "semantic-transfer:fixture",
                    "source_rva": 0x1000,
                    "status": "recovered",
                    "closure": "checked_finite_target_inventory",
                    "failure": None,
                    "target_expression": target_expression,
                    "index": {
                        "expression": index_expression,
                        "lower_inclusive": 0,
                        "upper_exclusive": 2,
                        "values": [0, 1],
                        "value_count": 2,
                        "dataflow_evidence": None,
                        "remap": {
                            "kind": "immutable_u8_lookup",
                            "expression_form": "base_plus_index",
                            "source_expression": source_expression,
                            "source_upper_exclusive": 3,
                            "address": 0x401900,
                            "address_model": "virtual_address",
                            "rva_start": 0x1900,
                            "rva_end": 0x1903,
                            "section": ".rdata",
                            "bytes_sha256": sha256(remap_bytes).hexdigest(),
                            "bytes_le": list(remap_bytes),
                            "possible_values": [0, 1],
                        },
                        "bound_evidence": [{
                            "source_unit_id": "bound",
                            "upper_exclusive": 3,
                            "sources": ["guard"],
                        }],
                    },
                    "table": {
                        "address": 0x401800,
                        "address_model": "virtual_address",
                        "expression_form": "multiply_4",
                        "rva_start": 0x1800,
                        "rva_end": 0x1808,
                        "entry_width": 4,
                        "entry_count": 2,
                        "index_values": [0, 1],
                        "contiguous": True,
                        "section": ".rdata",
                        "bytes_sha256": sha256(b"".join(entry_bytes)).hexdigest(),
                        "inventory_sha256": sha256(inventory_bytes).hexdigest(),
                    },
                    "entries": [
                        {"index": 0, "entry_address": 0x401800,
                         "entry_rva": 0x1800, "bytes_le": list(entry_bytes[0]),
                         "target_rva": 0x2000, "target_address": 0x402000},
                        {"index": 1, "entry_address": 0x401804,
                         "entry_rva": 0x1804, "bytes_le": list(entry_bytes[1]),
                         "target_rva": 0x3000, "target_address": 0x403000},
                    ],
                }],
            }
            manifest.write_text(
                json.dumps(manifest_payload, sort_keys=True), encoding="utf-8"
            )
            output = root / "with-remapped-routes"
            payload = write_executable_transfer_plan(
                machine_ir=machine,
                machine_ir_manifest=manifest,
                out=output,
            )
            decoded, _transfers = load_executable_transfer_plan(
                output / "executable-transfer-plan.json", require_complete=True
            )
            manifest_payload["control"]["recovered_indirect_targets"][0][
                "index"
            ]["remap"]["bytes_sha256"] = "0" * 64
            manifest.write_text(
                json.dumps(manifest_payload, sort_keys=True), encoding="utf-8"
            )
            with self.assertRaisesRegex(
                TransferPlanError, "remap evidence is stale or ambiguous"
            ):
                write_executable_transfer_plan(
                    machine_ir=machine,
                    machine_ir_manifest=manifest,
                    out=root / "stale-remapped-routes",
                )

        provenance = payload["finite_control_routes"][0]["index_provenance"]
        self.assertEqual(decoded["finite_control_routes"], payload[
            "finite_control_routes"
        ])
        self.assertEqual(provenance["kind"], "immutable_u8_remap")
        self.assertEqual(provenance["source_upper_exclusive"], 3)
        self.assertEqual(provenance["bytes_le"], [0, 1, 1])
        self.assertEqual(provenance["possible_values"], [0, 1])


if __name__ == "__main__":
    unittest.main()

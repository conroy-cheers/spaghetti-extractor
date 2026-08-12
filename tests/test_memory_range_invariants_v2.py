from __future__ import annotations

import copy
import unittest
from types import SimpleNamespace
from typing import cast

from spaghetti_extractor.memory_range_invariants_v2 import (
    CHECKED_MEMORY_ADDRESS_RANGE_V2_FORMAT,
    derive_memory_range_invariants_v2,
    validate_memory_range_invariants_v2,
)
from spaghetti_extractor.global_slot_analysis_v2 import analyze_global_slots_v2
from spaghetti_extractor.interprocedural_phase_v2 import (
    InterproceduralPhaseV2Error,
    derive_interprocedural_result_v2,
)
from spaghetti_extractor.stage_binary import StageABinary


def _reg(name: str) -> dict:
    return {"op": "reg", "name": name, "width": 32}


def _flag(name: str) -> dict:
    return {"op": "flag", "name": name}


def _const(value: int) -> dict:
    return {"op": "const", "value": value & 0xFFFFFFFF, "width": 32}


def _unit(
    name: str,
    rva: int,
    target_rvas: list[int],
    *,
    conditions: list[dict] | None = None,
    register_writes: list[dict] | None = None,
    flag_writes: list[dict] | None = None,
    memory_events: list[dict] | None = None,
) -> dict:
    edges = [
        {
            "target_rva": target,
            "condition": (
                {"op": "true"}
                if conditions is None
                else conditions[index]
            ),
        }
        for index, target in enumerate(target_rvas)
    ]
    return {
        "format": "stage-a-machine-ir-v2",
        "id": f"unit:{name}",
        "status": "qualified",
        "source": {
            "contract_sha256": "3" * 64,
            "instruction_bytes_sha256": "4" * 64,
            "original": {"rva_start": rva, "rva_end": rva + 2},
        },
        "semantics": {
            "outcome": {"kind": "jump", "target_rva": target_rvas[0]},
            "edge_conditions": edges,
            "register_writes": register_writes or [],
            "flag_writes": flag_writes or [],
            "memory_events": memory_events or [],
            "faults": [],
        },
        "control": {
            "direct_targets": list(target_rvas),
            "has_indirect_target": False,
        },
    }


def _counted_loop() -> list[dict]:
    base = 0x2000
    bound = 0x2080
    subtraction = {"op": "sub32", "args": [_reg("eax"), _const(bound)]}
    return [
        _unit(
            "entry",
            0x900,
            [0x1000],
            register_writes=[{"register": "eax", "value": _const(base)}],
        ),
        _unit(
            "header",
            0x1000,
            [0x1002],
            register_writes=[{
                "register": "ebx",
                "value": {"op": "add32", "args": [_reg("eax"), _const(-16)]},
            }],
            memory_events=[{
                "kind": "write",
                "width": 4,
                "address": {"op": "add32", "args": [_reg("eax"), _const(-16)]},
                "value": _const(0),
            }],
        ),
        _unit(
            "update",
            0x1002,
            [0x1004],
            register_writes=[
                {"register": "eax", "value": {
                    "op": "add32", "args": [_reg("eax"), _const(32)]
                }},
                {"register": "ebx", "value": _reg("eax")},
            ],
            memory_events=[{
                "kind": "write",
                "width": 4,
                "address": {"op": "add32", "args": [_reg("ebx"), _const(12)]},
                "value": _const(0),
            }],
        ),
        _unit(
            "compare",
            0x1004,
            [0x1006],
            flag_writes=[
                {"flag": "sf", "value": {"op": "msb", "args": [32, subtraction]}},
                {"flag": "of", "value": {
                    "op": "sub_overflow",
                    "args": [32, _reg("eax"), _const(bound), subtraction],
                }},
            ],
        ),
        _unit(
            "latch",
            0x1006,
            [0x1000, 0x1010],
            conditions=[
                {"op": "xor_bool", "args": [_flag("sf"), _flag("of")]},
                {"op": "not", "args": [{
                    "op": "xor_bool", "args": [_flag("sf"), _flag("of")]
                }]},
            ],
        ),
        _unit("exit", 0x1010, [0x1012]),
        _unit("terminal", 0x1012, [0x1012]),
    ]


def _returning_counted_loop() -> list[dict]:
    units = _counted_loop()
    terminal = next(row for row in units if row["id"] == "unit:terminal")
    terminal["semantics"]["outcome"] = {"kind": "return"}
    terminal["semantics"]["edge_conditions"] = []
    terminal["semantics"]["register_writes"] = [{
        "register": "esp",
        "value": {"op": "add32", "args": [_reg("esp"), _const(4)]},
    }]
    terminal["control"]["direct_targets"] = []
    return units


class MemoryRangeInvariantV2Tests(unittest.TestCase):
    def test_proves_counted_loop_address_ranges(self) -> None:
        report = derive_memory_range_invariants_v2(
            units=_counted_loop(),
            binary_sha256="1" * 64,
            machine_ir_sha256="2" * 64,
        )

        ranges = report["checked_address_ranges"]
        self.assertEqual(len(ranges), 2, report["issues"])
        self.assertTrue(all(
            row["format"] == CHECKED_MEMORY_ADDRESS_RANGE_V2_FORMAT
            and row["status"] == "complete"
            and row["invariant_authority_ids"]
            for row in ranges
        ))
        by_unit = {row["unit_id"]: row for row in ranges}
        self.assertEqual(
            (by_unit["unit:header"]["minimum_address"],
             by_unit["unit:header"]["maximum_address"]),
            (0x1FF0, 0x2050),
        )
        self.assertEqual(
            (by_unit["unit:update"]["minimum_address"],
             by_unit["unit:update"]["maximum_address"]),
            (0x1FFC, 0x205C),
        )
        self.assertEqual(report["counts"]["checked_sccs"], 1)
        checked = validate_memory_range_invariants_v2(
            report,
            units=_counted_loop(),
            binary_sha256="1" * 64,
            machine_ir_sha256="2" * 64,
        )
        self.assertEqual(len(checked), 2)

    def test_corrupt_checked_range_fails_closed(self) -> None:
        units = _counted_loop()
        report = derive_memory_range_invariants_v2(
            units=units,
            binary_sha256="1" * 64,
            machine_ir_sha256="2" * 64,
        )
        corrupt = copy.deepcopy(report)
        corrupt["checked_address_ranges"][0]["maximum_address"] += 4

        with self.assertRaisesRegex(ValueError, "digest is stale"):
            validate_memory_range_invariants_v2(
                corrupt,
                units=units,
                binary_sha256="1" * 64,
                machine_ir_sha256="2" * 64,
            )

    def test_interprocedural_phase_rejects_stale_range_artifact(self) -> None:
        units = _counted_loop()
        report = derive_memory_range_invariants_v2(
            units=units,
            binary_sha256="1" * 64,
            machine_ir_sha256="2" * 64,
        )
        report["checked_address_ranges"][0]["maximum_address"] += 4
        binary = cast(StageABinary, SimpleNamespace(
            sha256="1" * 64,
            image_base=0x400000,
            size_of_image=0x100000,
            imports=(),
            sections=(),
            pe=SimpleNamespace(get_data=lambda _rva, _size: b""),
        ))
        manifest = {
            "control": {
                "recovered_indirect_targets": [],
                "indirect_exits": [],
            },
        }
        graph = {"roots": ["unit:entry"], "direct_edges": []}

        with self.assertRaisesRegex(
            InterproceduralPhaseV2Error,
            "memory-range invariant artifact does not replay",
        ):
            derive_interprocedural_result_v2(
                manifest,
                units=units,
                graph=graph,
                binary=binary,
                machine_ir_sha256="2" * 64,
                memory_range_invariant_analysis=report,
                import_abis={},
                interface_profiles=(),
                operation_profiles=(),
                callable_profiles=(),
                internal_function_contracts={},
            )

    def test_interprocedural_phase_exports_checked_ranges_to_call_summary(
        self,
    ) -> None:
        units = _returning_counted_loop()
        report = derive_memory_range_invariants_v2(
            units=units,
            binary_sha256="1" * 64,
            machine_ir_sha256="2" * 64,
        )
        binary = cast(StageABinary, SimpleNamespace(
            sha256="1" * 64,
            image_base=0,
            size_of_image=0x10000,
            imports=(),
            sections=(),
            pe=SimpleNamespace(get_data=lambda _rva, size: b"\0" * size),
        ))
        result = derive_interprocedural_result_v2(
            {
                "control": {
                    "recovered_indirect_targets": [],
                    "indirect_exits": [],
                },
            },
            units=units,
            graph={"roots": ["unit:entry"], "direct_edges": []},
            binary=binary,
            machine_ir_sha256="2" * 64,
            memory_range_invariant_analysis=report,
            import_abis={},
            interface_profiles=(),
            operation_profiles=(),
            callable_profiles=(),
            internal_function_contracts={},
        )

        range_ids = {row["id"] for row in report["checked_address_ranges"]}
        summary = next(
            row
            for row in result["call_summaries"]["summaries"]
            if row["target_unit_id"] == "unit:entry"
        )
        self.assertEqual(result["fixed_point"]["status"], "complete", result)
        self.assertEqual(
            result["fixed_point"]["checked_memory_address_range_count"],
            2,
        )
        self.assertEqual(
            result["operation_provenance"]["checked_memory_address_ranges"],
            report["checked_address_ranges"],
        )
        self.assertTrue(range_ids <= set(summary["target_dependencies"]))
        self.assertEqual(summary["caller_memory_frame"]["status"], "complete")
        self.assertEqual(
            {
                row["id"]
                for row in result["fixed_point"]["dependencies"]
                if row["kind"] == "checked_memory_address_range"
            },
            range_ids,
        )

    def test_global_slot_replay_consumes_only_checked_ranges(self) -> None:
        units = _counted_loop()
        exit_unit = next(row for row in units if row["id"] == "unit:exit")
        exit_unit["semantics"]["memory_events"] = [{
            "kind": "read",
            "width": 4,
            "address": _const(0x3000),
        }]
        graph = {
            "format": "stage-a-rooted-control-graph-v2",
            "id": "counted-loop-graph",
            "status": "complete",
            "roots": ["unit:entry"],
            "direct_edges": [
                {"source_unit_id": source, "target_unit_id": target}
                for source, target in (
                    ("unit:entry", "unit:header"),
                    ("unit:header", "unit:update"),
                    ("unit:update", "unit:compare"),
                    ("unit:compare", "unit:latch"),
                    ("unit:latch", "unit:header"),
                    ("unit:latch", "unit:exit"),
                    ("unit:exit", "unit:terminal"),
                    ("unit:terminal", "unit:terminal"),
                )
            ],
            "indirect_exits": [],
        }
        ranges = derive_memory_range_invariants_v2(
            units=units,
            binary_sha256="1" * 64,
            machine_ir_sha256="2" * 64,
        )
        common = {
            "units": units,
            "graph": graph,
            "candidate_slot_addresses": [0x3000],
            "image_base": 0x1000,
            "size_of_image": 0x4000,
            "launch_initial_values": {0x3000: 0},
            "pe_sha256": "1" * 64,
            "machine_ir_sha256": "2" * 64,
        }

        unresolved = analyze_global_slots_v2(**common)
        resolved = analyze_global_slots_v2(
            **common,
            memory_range_invariant_analysis=ranges,
        )

        self.assertEqual(unresolved["status"], "incomplete")
        self.assertEqual(resolved["status"], "complete", resolved["issues"])
        dependencies = resolved["global_slot_evidence"][0]["dependencies"]
        self.assertEqual(
            sum(row["kind"] == "checked_memory_address_range" for row in dependencies),
            2,
        )

    def test_unknown_loop_shape_fails_closed(self) -> None:
        units = _counted_loop()
        latch = next(row for row in units if row["id"] == "unit:latch")
        latch["semantics"]["edge_conditions"][0]["condition"] = {"op": "true"}

        report = derive_memory_range_invariants_v2(
            units=units,
            binary_sha256="1" * 64,
            machine_ir_sha256="2" * 64,
        )

        self.assertEqual(report["checked_address_ranges"], [])
        self.assertEqual(report["status"], "incomplete")
        self.assertIn(
            "memory_loop_shape_not_recognized",
            {issue["code"] for issue in report["issues"]},
        )


if __name__ == "__main__":
    unittest.main()

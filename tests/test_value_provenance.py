from __future__ import annotations

import unittest

from spaghetti_extractor.import_abi import SelectedImportABI
from spaghetti_extractor.machine_abi import resolve_machine_call_abi
from spaghetti_extractor.machine_import_profiles import MachineImportIdentity
from spaghetti_extractor.value_provenance import (
    recover_indirect_targets_from_value_provenance,
)


IMAGE_BASE = 0x400000
IAT_RVA = 0x3000
REGISTERS = ("eax", "ebp", "ebx", "ecx", "edi", "edx", "esi", "esp")


def _reg(name: str) -> dict[str, object]:
    return {"op": "reg", "name": name, "width": 32}


def _const(value: int) -> dict[str, object]:
    return {"op": "const", "value": value, "width": 32}


def _load(address: int) -> dict[str, object]:
    return {"op": "load", "width": 4, "address": _const(address)}


def _unit(
    identity: str,
    rva: int,
    *,
    writes: list[dict[str, object]] | None = None,
    events: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "id": identity,
        "source": {"original": {"rva_start": rva, "rva_end": rva + 1}},
        "semantics": {
            "register_writes": writes or [],
            "external_events": events or [],
            "outcome": {"kind": "fallthrough", "target_rva": rva + 1},
        },
    }


def _call(kind: str, *, register: str = "esi", symbol: str = "ShowWindow") -> dict[str, object]:
    event: dict[str, object] = {
        "kind": kind,
        "register_inputs": {name: _reg(name) for name in REGISTERS},
        "return_rva": 0x1100,
    }
    if kind == "external_call":
        event.update({"dll": "user32.dll", "symbol": symbol, "ordinal": None})
    elif kind == "indirect_call":
        event["target"] = _reg(register)
    elif kind == "internal_call":
        event["target_rva"] = 0x1400
    return event


def _identity(symbol: str = "ShowWindow") -> MachineImportIdentity:
    return MachineImportIdentity("user32.dll", "symbol", symbol)


def _abi(symbol: str = "ShowWindow") -> SelectedImportABI:
    machine_abi = resolve_machine_call_abi("pe32-stdcall-v1")
    assert machine_abi is not None
    return SelectedImportABI(
        identity=_identity(symbol),
        abi=machine_abi,
        profile_id="fixture",
        profile_sha256="0" * 64,
        entry_key="machine_import_signatures",
        entry_index=0,
    )


def _run(
    units: list[dict[str, object]],
    direct_edges: list[dict[str, object]],
    exits: list[dict[str, object]],
    *,
    abis: dict[MachineImportIdentity, SelectedImportABI] | None = None,
    internal_edges: list[dict[str, object]] | None = None,
    internal_preservation: dict[int, frozenset[str]] | None = None,
) -> dict[str, object]:
    return recover_indirect_targets_from_value_provenance(
        units=units,
        roots=["root"],
        direct_edges=direct_edges,
        internal_call_edges=internal_edges or [],
        indirect_exits=exits,
        image_base=IMAGE_BASE,
        imports=[{
            "dll": "user32.dll",
            "symbol": "ShowWindow",
            "ordinal": None,
            "thunk_rva": IAT_RVA,
        }],
        import_abis=abis if abis is not None else {_identity(): _abi()},
        internal_call_preserved_registers=internal_preservation,
    )


def _exit(source: str, rva: int, *, event_index: int = 0) -> dict[str, object]:
    return {
        "id": f"exit:{source}",
        "source_unit_id": source,
        "source_rva": rva,
        "source_event_index": event_index,
        "kind": "indirect_call",
        "target_expression": _reg("esi"),
    }


class ValueProvenanceTests(unittest.TestCase):
    def test_iat_load_resolves_register_indirect_call(self) -> None:
        units = [
            _unit("root", 0x1000, writes=[{"register": "esi", "value": _load(IMAGE_BASE + IAT_RVA)}]),
            _unit("call", 0x1010, events=[_call("indirect_call")]),
        ]
        result = _run(
            units,
            [{"source_unit_id": "root", "target_unit_id": "call"}],
            [_exit("call", 0x1010)],
        )

        resolution = result["resolutions"][0]
        self.assertEqual(resolution["status"], "recovered")
        self.assertEqual(
            resolution["external_targets"][0]["import"],
            {"dll": "user32.dll", "symbol": "ShowWindow"},
        )

    def test_profiled_direct_import_preserves_nonvolatile_target(self) -> None:
        units = [
            _unit("root", 0x1000, writes=[{"register": "esi", "value": _load(IMAGE_BASE + IAT_RVA)}]),
            _unit("api", 0x1010, events=[_call("external_call", symbol="ShowWindow")]),
            _unit("call", 0x1020, events=[_call("indirect_call")]),
        ]
        edges = [
            {"source_unit_id": "root", "target_unit_id": "api"},
            {"source_unit_id": "api", "target_unit_id": "call"},
        ]

        recovered = _run(units, edges, [_exit("call", 0x1020)])
        missing = _run(units, edges, [_exit("call", 0x1020)], abis={})

        self.assertEqual(recovered["resolutions"][0]["status"], "recovered")
        self.assertEqual(missing["resolutions"][0]["status"], "incomplete")

    def test_profiled_indirect_import_preserves_target_for_later_calls(self) -> None:
        units = [
            _unit("root", 0x1000, writes=[{"register": "esi", "value": _load(IMAGE_BASE + IAT_RVA)}]),
            _unit("first", 0x1010, events=[_call("indirect_call")]),
            _unit("second", 0x1020, events=[_call("indirect_call")]),
        ]
        result = _run(
            units,
            [
                {"source_unit_id": "root", "target_unit_id": "first"},
                {"source_unit_id": "first", "target_unit_id": "second"},
            ],
            [_exit("first", 0x1010), _exit("second", 0x1020)],
        )

        self.assertEqual(
            [row["status"] for row in result["resolutions"]],
            ["recovered", "recovered"],
        )

    def test_volatile_register_is_not_carried_across_import(self) -> None:
        units = [
            _unit("root", 0x1000, writes=[{"register": "eax", "value": _load(IMAGE_BASE + IAT_RVA)}]),
            _unit("api", 0x1010, events=[_call("external_call")]),
            _unit("call", 0x1020, events=[_call("indirect_call", register="eax")]),
        ]
        result = _run(
            units,
            [
                {"source_unit_id": "root", "target_unit_id": "api"},
                {"source_unit_id": "api", "target_unit_id": "call"},
            ],
            [{**_exit("call", 0x1020), "target_expression": _reg("eax")}],
        )

        self.assertEqual(result["resolutions"][0]["status"], "incomplete")

    def test_internal_call_entry_receives_pre_call_register_origins(self) -> None:
        units = [
            _unit("root", 0x1000, writes=[{"register": "esi", "value": _load(IMAGE_BASE + IAT_RVA)}]),
            _unit("caller", 0x1010, events=[_call("internal_call")]),
            _unit("callee", 0x1400, events=[_call("indirect_call")]),
        ]
        result = _run(
            units,
            [{"source_unit_id": "root", "target_unit_id": "caller"}],
            [_exit("callee", 0x1400)],
            internal_edges=[{
                "source_unit_id": "caller",
                "target_unit_id": "callee",
                "source_event_index": 0,
            }],
        )

        self.assertEqual(result["resolutions"][0]["status"], "recovered")

    def test_complete_internal_summary_preserves_caller_register_origin(self) -> None:
        units = [
            _unit("root", 0x1000, writes=[{"register": "esi", "value": _load(IMAGE_BASE + IAT_RVA)}]),
            _unit("caller", 0x1010, events=[_call("internal_call")]),
            _unit("after", 0x1020, events=[_call("indirect_call")]),
            _unit("callee", 0x1400),
        ]
        edges = [
            {"source_unit_id": "root", "target_unit_id": "caller"},
            {"source_unit_id": "caller", "target_unit_id": "after"},
        ]
        internal_edges = [{
            "source_unit_id": "caller",
            "target_unit_id": "callee",
            "source_event_index": 0,
        }]

        recovered = _run(
            units,
            edges,
            [_exit("after", 0x1020)],
            internal_edges=internal_edges,
            internal_preservation={IMAGE_BASE + 0x1400: frozenset({"esi"})},
        )
        missing = _run(
            units,
            edges,
            [_exit("after", 0x1020)],
            internal_edges=internal_edges,
        )

        self.assertEqual(recovered["resolutions"][0]["status"], "recovered")
        self.assertEqual(missing["resolutions"][0]["status"], "incomplete")

    def test_exact_code_address_resolves_one_internal_target(self) -> None:
        units = [
            _unit("root", 0x1000, writes=[{"register": "eax", "value": _const(IMAGE_BASE + 0x1200)}]),
            _unit("jump", 0x1010),
            _unit("target", 0x1200),
        ]
        result = _run(
            units,
            [{"source_unit_id": "root", "target_unit_id": "jump"}],
            [{
                "id": "exit:jump",
                "source_unit_id": "jump",
                "source_rva": 0x1010,
                "kind": "indirect_jump",
                "target_expression": _reg("eax"),
            }],
        )

        self.assertEqual(result["resolutions"][0]["target_unit_ids"], ["target"])


if __name__ == "__main__":
    unittest.main()

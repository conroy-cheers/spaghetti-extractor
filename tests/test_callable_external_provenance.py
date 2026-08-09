from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.external_capabilities import (
    load_callable_external_profile,
)
from spaghetti_extractor.import_abi import SelectedImportABI
from spaghetti_extractor.interface_provenance import (
    recover_external_interface_targets,
)
from spaghetti_extractor.machine_abi import resolve_machine_call_abi
from spaghetti_extractor.machine_import_profiles import MachineImportIdentity


IMAGE_BASE = 0x400000
MODULE = 0x410000
SYMBOL = 0x410020
SLOT = 0x430000
GETPROC_IAT = IMAGE_BASE + 0x3000
REGISTERS = ("eax", "ebp", "ebx", "ecx", "edi", "edx", "esi", "esp")


def reg(name: str) -> dict[str, object]:
    return {"op": "reg", "name": name, "width": 32}


def const(value: int) -> dict[str, object]:
    return {"op": "const", "value": value, "width": 32}


def sub(left: object, right: object) -> dict[str, object]:
    return {"op": "sub32", "args": [left, right]}


def load(address: object) -> dict[str, object]:
    return {"op": "load", "width": 4, "address": address}


def unit(
    identifier: str,
    rva: int,
    *,
    writes: list[dict[str, object]] | None = None,
    memory: list[dict[str, object]] | None = None,
    events: list[dict[str, object]] | None = None,
    ordered: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "id": identifier,
        "source": {"original": {"rva_start": rva, "rva_end": rva + 1}},
        "instructions": [],
        "semantics": {
            "outcome": {"kind": "fallthrough", "target_rva": rva + 1},
            "register_writes": writes or [],
            "memory_events": memory or [],
            "external_events": events or [],
            "ordered_events": ordered or [],
        },
    }


def pushed_call(
    identifier: str,
    rva: int,
    *,
    arguments: list[object],
    kind: str,
    target: object | None = None,
    dll: str | None = None,
    symbol: str | None = None,
) -> dict[str, object]:
    esp: object = reg("esp")
    writes: list[dict[str, object]] = []
    for argument in reversed(arguments):
        esp = sub(esp, const(4))
        writes.append({"kind": "write", "width": 4, "address": esp, "value": argument})
    event: dict[str, object] = {
        "kind": kind,
        "instruction_rva": rva,
        "return_rva": rva + 1,
        "register_inputs": {name: reg(name) for name in REGISTERS},
    }
    event["register_inputs"]["esp"] = esp
    if target is not None:
        event["target"] = target
    if dll is not None:
        event.update({"dll": dll, "symbol": symbol, "ordinal": None})
    return unit(identifier, rva, memory=writes, events=[event], ordered=[*writes, event])


def selected(identity: MachineImportIdentity, words: int) -> SelectedImportABI:
    abi = resolve_machine_call_abi("pe32-stdcall-v1")
    assert abi is not None
    return SelectedImportABI(identity, abi, "fixture", "1" * 64, "entry", 0, words)


class CallableExternalProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = load_callable_external_profile(
            Path("profiles/pe32-kernel32-callable-resolvers-v1.json")
        )

    def _recover(self, symbol: bytes) -> dict[str, object]:
        loader = pushed_call(
            "loader", 0x1000,
            arguments=[const(MODULE)],
            kind="external_call",
            dll="kernel32.dll",
            symbol="LoadLibraryA",
        )
        preserve = unit(
            "preserve", 0x1010,
            writes=[{"register": "esi", "value": reg("eax")}],
        )
        resolver = pushed_call(
            "resolver", 0x1020,
            arguments=[reg("esi"), const(SYMBOL)],
            kind="indirect_call",
            target=load(const(GETPROC_IAT)),
        )
        store = unit(
            "store", 0x1030,
            memory=[{"kind": "write", "width": 4, "address": const(SLOT), "value": reg("eax")}],
        )
        invoke = pushed_call(
            "invoke", 0x1040,
            arguments=[],
            kind="indirect_call",
            target=load(const(SLOT)),
        )
        load_identity = MachineImportIdentity("kernel32.dll", "symbol", "LoadLibraryA")
        resolver_identity = MachineImportIdentity("kernel32.dll", "symbol", "GetProcAddress")
        static = {
            MODULE: b"user32.dll\0",
            SYMBOL: symbol + b"\0",
        }

        def reader(address: int, size: int) -> bytes | None:
            value = static.get(address)
            return value if value is not None and len(value) == size else None

        return recover_external_interface_targets(
            units=[loader, preserve, resolver, store, invoke],
            roots=["loader"],
            direct_edges=[
                {"source_unit_id": "loader", "target_unit_id": "preserve"},
                {"source_unit_id": "preserve", "target_unit_id": "resolver"},
                {"source_unit_id": "resolver", "target_unit_id": "store"},
                {"source_unit_id": "store", "target_unit_id": "invoke"},
            ],
            internal_call_edges=[],
            recovered_indirect_edges=[],
            indirect_exits=[{
                "id": "invoke:0",
                "source_unit_id": "invoke",
                "source_rva": 0x1040,
                "source_event_index": 0,
                "kind": "indirect_call",
                "target": load(const(SLOT)),
            }],
            profiles=[],
            callable_external_profiles=[self.profile],
            imports=[{
                "dll": "kernel32.dll",
                "symbol": "GetProcAddress",
                "ordinal": None,
                "thunk_rva": 0x3000,
            }],
            import_abis={
                load_identity: selected(load_identity, 1),
                resolver_identity: selected(resolver_identity, 2),
            },
            internal_call_preserved_registers={},
            image_base=IMAGE_BASE,
            static_data_reader=reader,
        )

    def test_static_getprocaddress_result_flows_through_writable_slot_to_call(self) -> None:
        report = self._recover(b"GetActiveWindow")
        self.assertEqual(report["status"], "complete")
        resolution = report["resolutions"][0]
        self.assertEqual(resolution["status"], "recovered")
        self.assertEqual(resolution["closure"], "checked_resolver_export_inventory")
        protocol = resolution["external_targets"][0]["external_protocol"]
        self.assertEqual(protocol["kind"], "pe32-resolved-export")
        self.assertEqual(protocol["target"], {
            "dll": "user32.dll", "symbol": "GetActiveWindow"
        })
        self.assertEqual(protocol["transfer_kind"], "call")
        self.assertEqual(report["counts"]["recovered_callable_exits"], 1)

    def test_unknown_static_export_name_fails_incomplete_at_resolver(self) -> None:
        report = self._recover(b"UnknownWindowAPI")
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["resolutions"][0]["status"], "incomplete")
        self.assertIn(
            "callable_resolver_identity_unknown_or_ambiguous",
            {issue["code"] for issue in report["issues"]},
        )


class CallableExternalProfileTests(unittest.TestCase):
    def test_profile_rejects_target_name_that_differs_from_static_identity(self) -> None:
        source = Path("profiles/pe32-kernel32-callable-resolvers-v1.json")
        payload = source.read_text(encoding="utf-8").replace(
            '"symbol": "MessageBoxA"},\n      "machine_contract"',
            '"symbol": "MessageBoxW"},\n      "machine_contract"',
            1,
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "profile.json"
            path.write_text(payload, encoding="utf-8")
            with self.assertRaisesRegex(Exception, "must exactly match"):
                load_callable_external_profile(path)


if __name__ == "__main__":
    unittest.main()

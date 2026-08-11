from __future__ import annotations

import unittest

from spaghetti_extractor.call_site_effects import CallSiteEffect, CallSiteId
from spaghetti_extractor.import_abi import SelectedImportABI
from spaghetti_extractor.interface_provenance import recover_external_interface_targets
from spaghetti_extractor.intrinsic_call_site_effects import (
    derive_intrinsic_import_call_site_effects,
    merge_intrinsic_call_site_effects,
)
from spaghetti_extractor.machine_abi import resolve_machine_call_abi
from spaghetti_extractor.machine_import_profiles import MachineImportIdentity


IMAGE_BASE = 0x400000


def _reg(name: str) -> dict[str, object]:
    return {"op": "reg", "name": name, "width": 32}


def _unit(
    identifier: str,
    rva: int,
    *,
    event: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "id": identifier,
        "source": {"original": {"rva_start": rva, "rva_end": rva + 1}},
        "instructions": [],
        "semantics": {
            "outcome": {"kind": "fallthrough", "target_rva": rva + 1},
            "register_writes": [],
            "memory_events": [],
            "external_events": [] if event is None else [event],
            "ordered_events": [] if event is None else [event],
        },
    }


def _event(identity: MachineImportIdentity) -> dict[str, object]:
    return {
        "kind": "external_call",
        "dll": identity.dll,
        identity.kind: identity.value,
        "return_rva": 0x1201,
        "register_inputs": {
            register: _reg(register)
            for register in ("eax", "ebp", "ebx", "ecx", "edi", "edx", "esi", "esp")
        },
    }


def _selected(
    identity: MachineImportIdentity,
    *,
    argument_words: int,
    contract: dict[str, object],
) -> SelectedImportABI:
    abi = resolve_machine_call_abi("pe32-stdcall-v1")
    assert abi is not None
    return SelectedImportABI(
        identity=identity,
        abi=abi,
        profile_id="fixture-imports-v1",
        profile_sha256="1" * 64,
        entry_key="machine_import_signatures",
        entry_index=0,
        argument_words=argument_words,
        contract=contract,
    )


class IntrinsicImportCallEffectTests(unittest.TestCase):
    def _run(
        self,
        call: dict[str, object],
        import_abis: dict[MachineImportIdentity, SelectedImportABI],
    ) -> dict[str, object]:
        return recover_external_interface_targets(
            units=[_unit("root", 0x1000), call],
            roots=["root"],
            direct_edges=[],
            internal_call_edges=[],
            recovered_indirect_edges=[],
            indirect_exits=[],
            profiles=[],
            import_abis=import_abis,
            internal_call_preserved_registers={},
            image_base=IMAGE_BASE,
        )

    def test_unreached_direct_import_keeps_state_independent_abi_families(self) -> None:
        identity = MachineImportIdentity("kernel32.dll", "symbol", "LCMapStringW")
        selected = _selected(
            identity,
            argument_words=6,
            contract={
                "memory_effect": "argumentRanges",
                "memory_footprints": [{
                    "access": "write",
                    "base_argument": 4,
                    "offset": 0,
                    "size": {"kind": "argument", "argument": 5, "scale": 2},
                    "nullable": True,
                }],
            },
        )

        result = self._run(
            _unit("unreached-import", 0x1200, event=_event(identity)),
            {identity: selected},
        )

        self.assertEqual(result["counts"]["reached_units"], 1)
        effect = result["call_site_effects"][0]
        self.assertEqual(effect["unit_id"], "unreached-import")
        self.assertEqual(effect["register_frame"]["status"], "complete")
        self.assertEqual(effect["stack_frame"], {
            "status": "complete",
            "stack_cleanup_bytes": 24,
        })
        self.assertEqual(effect["result_frame"]["status"], "incomplete")
        self.assertEqual(effect["memory_frame"]["status"], "incomplete")

    def test_unreached_read_only_import_has_a_complete_memory_frame(self) -> None:
        identity = MachineImportIdentity("kernel32.dll", "symbol", "GetOEMCP")
        selected = _selected(
            identity,
            argument_words=0,
            contract={"memory_effect": "none", "memory_footprints": []},
        )

        result = self._run(
            _unit("unreached-import", 0x1200, event=_event(identity)),
            {identity: selected},
        )

        effect = result["call_site_effects"][0]
        self.assertEqual(effect["memory_frame"], {
            "status": "complete",
            "preserved": True,
            "writes": [],
        })

    def test_unselected_direct_import_remains_explicitly_incomplete(self) -> None:
        identity = MachineImportIdentity("unknown.dll", "symbol", "Mystery")

        result = self._run(
            _unit("unreached-import", 0x1200, event=_event(identity)),
            {},
        )

        effect = result["call_site_effects"][0]
        self.assertEqual(effect["register_frame"]["status"], "incomplete")
        self.assertEqual(effect["stack_frame"]["status"], "incomplete")
        self.assertIn("external_call_abi_unresolved", effect["failure_codes"])

    def test_stateful_intrinsic_frame_disagreement_fails_closed(self) -> None:
        identity = MachineImportIdentity("kernel32.dll", "symbol", "CloseHandle")
        selected = _selected(
            identity,
            argument_words=1,
            contract={"memory_effect": "none", "memory_footprints": []},
        )
        call = _unit("call", 0x1200, event=_event(identity))
        intrinsic = derive_intrinsic_import_call_site_effects(
            [call], import_abis={identity: selected}
        )
        observed = CallSiteEffect(
            site=CallSiteId("call", 0),
            transfer_kind="external_call",
            status="incomplete",
            register_frame_status="complete",
            preserved_registers=frozenset(selected.abi.preserved_registers),
            stack_frame_status="complete",
            stack_cleanup_bytes=0,
            result_status="incomplete",
            outputs=(),
            memory_frame_status="complete",
            memory_preserved=True,
            memory_writes=(),
            abi=selected.abi,
            argument_words=1,
            failure_codes=("result_frame_unknown",),
        )

        merged, issues = merge_intrinsic_call_site_effects(
            intrinsic, [observed]
        )

        self.assertEqual(issues[0]["family"], "stack_frame")
        self.assertEqual(merged[0].stack_frame_status, "incomplete")
        self.assertEqual(
            merged[0].failure_codes,
            ("intrinsic_import_call_effect_conflict",),
        )


if __name__ == "__main__":
    unittest.main()

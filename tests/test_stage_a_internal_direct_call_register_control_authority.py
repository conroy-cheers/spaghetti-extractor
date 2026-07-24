from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

import pefile

from spaghetti_extractor.relational.lean.internal_direct_call_register_control_authority import (
    DirectCallCrossing,
    DirectCallRegisterControlAuthorityError,
    DirectCallRegisterControlLeanBindings,
    DirectCallSemanticProvenanceBinding,
    RegisterControlFrontierRequest,
    _StateRow,
    _binding_matches_exact_crossing,
    _crossings_for_site,
    _load_state_rows,
    _stable_contract_id,
    direct_call_register_control_authority_source,
    plan_direct_call_register_control_authorities,
)
from tests.pe_fixtures import pe32_image


TEXT_RVA = 0x1000
GNU_USES = (
    0x1847,
    0x18DB,
    0x18F4,
    0x1B4F,
    0x1B63,
    0x1B71,
    0x20C3,
    0x2978,
    0x14159,
)
GNU_ORIGINAL = Path(
    "/nix/store/iawh49a2apvibazhcdl5dl28idmwwwqp-"
    "stage-a-gnu-hello-original-i686-w64-mingw32-2.12.3/share/"
    "spaghetti-extractor/stage-a-gnu-hello-fixtures/original/hello.exe"
)
GNU_STATE = Path(
    "/nix/store/v8bfs133a3dwqhbhmxpdy18dlcfl3bjx-"
    "stage-a-gnu-hello-roundtrip-static-export/state-machine.jsonl"
)
GNU_MIXED = Path(
    "/nix/store/k2pmxsivl2b372zd9xqsp0s57a9fj5hj-"
    "stage-a-gnu-hello-roundtrip-mixed-original-lean/"
    "interpreter-mixed-original-plan.json"
)
GNU_IMPORTS = Path(
    "/nix/store/kb5sb9phbg0lf8x0hi8s2brz1h3nmr7a-"
    "stage-a-gnu-hello-roundtrip-static-machine-import-contracts-lean/"
    "machine-import-contract-report.json"
)


def _instruction(rva: int, raw: bytes) -> dict[str, object]:
    return {"bytes": raw.hex(), "rva": rva, "size": len(raw)}


def _row(
    rva: int,
    instructions: tuple[dict[str, object], ...],
    *,
    event: dict[str, object] | None = None,
) -> _StateRow:
    return _StateRow(
        rva,
        rva + sum(int(item["size"]) for item in instructions),
        instructions,
        () if event is None else (event,),
    )


def _use(source: int, instruction: int, register: str = "ebx") -> dict[str, object]:
    return {
        "instruction_rva": instruction,
        "register": register,
        "source_rva": source,
        "source_target_id": 1,
    }


def _call_edge(source: int = 0, target: int = 1) -> dict[str, object]:
    return {
        "edge_index": 7,
        "kind": "call_return",
        "machine_contract_id": None,
        "source_target_id": source,
        "target_target_id": target,
    }


def _call_site() -> dict[str, object]:
    return {
        "callsite_rva": TEXT_RVA + 5,
        "continuation_rva": TEXT_RVA + 10,
        "continuation_target_id": 1,
        "edge_index": 7,
        "source_rva": TEXT_RVA,
        "source_target_id": 0,
    }


def _direct_call_rows(
    *, event_kind: str = "internal_call"
) -> dict[int, _StateRow]:
    event: dict[str, object] = {
        "instruction_rva": TEXT_RVA + 5,
        "kind": event_kind,
    }
    if event_kind == "internal_call":
        event["target_rva"] = TEXT_RVA + 0x30
    return {
        TEXT_RVA: _row(
            TEXT_RVA,
            (
                _instruction(TEXT_RVA, b"\xbb\x30\x10\x40\x00"),
                _instruction(TEXT_RVA + 5, b"\xe8\x26\x00\x00\x00"),
            ),
            event=event,
        ),
        TEXT_RVA + 10: _row(
            TEXT_RVA + 10,
            (_instruction(TEXT_RVA + 10, b"\xff\xd3"),),
        ),
        TEXT_RVA + 0x30: _row(
            TEXT_RVA + 0x30,
            (_instruction(TEXT_RVA + 0x30, b"\xc3"),),
        ),
    }


class StageAInternalDirectCallRegisterControlAuthorityTests(unittest.TestCase):
    def test_recovers_exact_internal_call_crossing(self) -> None:
        crossings, residual, blockers = _crossings_for_site(
            use=_use(TEXT_RVA + 10, TEXT_RVA + 10),
            exact_edges=[_call_edge()],
            internal_sites=[_call_site()],
            state_rows=_direct_call_rows(),
            global_rvas={0: TEXT_RVA, 1: TEXT_RVA + 10, 2: TEXT_RVA + 0x30},
            call_contracts={},
        )

        self.assertEqual(blockers, [])
        self.assertEqual(residual, "immediate_value")
        self.assertEqual(len(crossings), 1)
        self.assertEqual(crossings[0].key(), (TEXT_RVA + 5, "ebx"))
        self.assertEqual(crossings[0].callee_target_id, 2)

    def test_missing_call_edge_fails_closed(self) -> None:
        crossings, _residual, blockers = _crossings_for_site(
            use=_use(TEXT_RVA + 10, TEXT_RVA + 10),
            exact_edges=[_call_edge()],
            internal_sites=[],
            state_rows=_direct_call_rows(),
            global_rvas={0: TEXT_RVA, 1: TEXT_RVA + 10, 2: TEXT_RVA + 0x30},
            call_contracts={},
        )

        self.assertEqual(crossings, ())
        self.assertIn("missing_internal_direct_call_edge", {
            blocker.category for blocker in blockers
        })

    def test_unsupported_external_effect_fails_closed(self) -> None:
        crossings, residual, blockers = _crossings_for_site(
            use=_use(TEXT_RVA + 10, TEXT_RVA + 10),
            exact_edges=[_call_edge()],
            internal_sites=[],
            state_rows=_direct_call_rows(event_kind="external_call"),
            global_rvas={0: TEXT_RVA, 1: TEXT_RVA + 10, 2: TEXT_RVA + 0x30},
            call_contracts={},
        )

        self.assertEqual(crossings, ())
        self.assertEqual(residual, "external_call")
        self.assertIn("unsupported_external_effect", {
            blocker.category for blocker in blockers
        })

    def test_unranked_cycle_fails_closed(self) -> None:
        rows = {
            TEXT_RVA: _row(TEXT_RVA, (_instruction(TEXT_RVA, b"\x90"),)),
            TEXT_RVA + 1: _row(
                TEXT_RVA + 1, (_instruction(TEXT_RVA + 1, b"\xff\xd3"),)
            ),
        }
        edges = [
            {
                "edge_index": 0,
                "kind": "direct",
                "machine_contract_id": None,
                "source_target_id": 0,
                "target_target_id": 1,
            },
            {
                "edge_index": 1,
                "kind": "direct",
                "machine_contract_id": None,
                "source_target_id": 1,
                "target_target_id": 0,
            },
        ]

        _crossings, residual, blockers = _crossings_for_site(
            use=_use(TEXT_RVA + 1, TEXT_RVA + 1),
            exact_edges=edges,
            internal_sites=[],
            state_rows=rows,
            global_rvas={0: TEXT_RVA, 1: TEXT_RVA + 1},
            call_contracts={},
        )

        self.assertEqual(residual, "unranked_cycle")
        self.assertIn("unranked_register_provenance_cycle", {
            blocker.category for blocker in blockers
        })

    def test_incompatible_predecessor_sources_are_ambiguous(self) -> None:
        rows = {
            TEXT_RVA: _row(
                TEXT_RVA,
                (_instruction(TEXT_RVA, b"\xbb\x30\x10\x40\x00"),),
            ),
            TEXT_RVA + 5: _row(
                TEXT_RVA + 5,
                (_instruction(TEXT_RVA + 5, b"\x8b\x5c\x24\x04"),),
            ),
            TEXT_RVA + 9: _row(
                TEXT_RVA + 9, (_instruction(TEXT_RVA + 9, b"\xff\xd3"),)
            ),
        }
        edges = [
            {
                "edge_index": index,
                "kind": "direct",
                "machine_contract_id": None,
                "source_target_id": source,
                "target_target_id": 2,
            }
            for index, source in enumerate((0, 1))
        ]

        _crossings, residual, blockers = _crossings_for_site(
            use={
                **_use(TEXT_RVA + 9, TEXT_RVA + 9),
                "source_target_id": 2,
            },
            exact_edges=edges,
            internal_sites=[],
            state_rows=rows,
            global_rvas={0: TEXT_RVA, 1: TEXT_RVA + 5, 2: TEXT_RVA + 9},
            call_contracts={},
        )

        self.assertEqual(residual, "ambiguous")
        self.assertIn("ambiguous_register_source", {
            blocker.category for blocker in blockers
        })

    def test_stale_state_machine_bytes_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe_path = root / "fixture.exe"
            pe_path.write_bytes(pe32_image(b"\x90\xc3"))
            state_path = root / "state-machine.jsonl"
            state_path.write_text(json.dumps({
                "instructions": [
                    {"bytes": "cc", "rva": TEXT_RVA, "size": 1}
                ],
                "ordered_events": [],
                "original": {
                    "rva_end": TEXT_RVA + 1,
                    "rva_start": TEXT_RVA,
                },
            }) + "\n", encoding="utf-8")
            pe = pefile.PE(str(pe_path), fast_load=False)
            try:
                with self.assertRaisesRegex(
                    DirectCallRegisterControlAuthorityError,
                    "do not match the exact PE",
                ):
                    _load_state_rows(state_path, pe)
            finally:
                pe.close()

    def test_wrong_semantic_target_inventory_is_rejected(self) -> None:
        crossing = DirectCallCrossing(
            "ebx", TEXT_RVA + 5, TEXT_RVA, TEXT_RVA + 10,
            TEXT_RVA + 0x30, 0, 1, 2, 7,
        )
        binding = DirectCallSemanticProvenanceBinding(
            TEXT_RVA + 5,
            TEXT_RVA + 0x31,
            TEXT_RVA + 10,
            "StageA.SemanticFixture",
            "StageA.SemanticFixture.provenance",
        )

        self.assertFalse(_binding_matches_exact_crossing(binding, crossing))

    def test_emits_stable_named_final_authority(self) -> None:
        crossing = DirectCallCrossing(
            "ebx", TEXT_RVA + 5, TEXT_RVA, TEXT_RVA + 10,
            TEXT_RVA + 0x30, 0, 1, 2, 7,
        )
        bindings = DirectCallRegisterControlLeanBindings(
            context="StageA.Fixture.context",
            source_invariant="StageA.Fixture.sourceInvariant",
            semantic_provenance="StageA.SemanticFixture.provenance",
            semantic_provenance_module="StageA.SemanticFixture",
            context_module="StageA.Fixture",
            namespace="StageA.Generated.Call00001005EBX",
        )

        source = direct_call_register_control_authority_source(
            crossing, contract_id=_stable_contract_id(crossing), bindings=bindings
        )

        self.assertIn(
            "def generatedCheckedDirectCallRegisterControlContract :\n"
            "    CheckedDirectCallRegisterControlContract generatedContext",
            source,
        )
        self.assertIn(
            "def generatedSourceInvariant : StateInvariant :=\n"
            "  StageA.Fixture.sourceInvariant 0",
            source,
        )
        self.assertIn("sourceInvariant := generatedSourceInvariant", source)
        self.assertIn("premises.structuralChecked", source)
        self.assertIn("certificate.graphClosed = true", source)
        self.assertIn("certificate.returns.isEmpty = false", source)
        self.assertNotIn("sorry", source)
        self.assertEqual(_stable_contract_id(crossing), _stable_contract_id(crossing))
        self.assertNotEqual(
            _stable_contract_id(crossing),
            _stable_contract_id(replace(crossing, register="esi")),
        )

    @unittest.skipUnless(
        all(path.exists() for path in (GNU_ORIGINAL, GNU_STATE, GNU_MIXED, GNU_IMPORTS)),
        "immutable GNU register-control artifacts are unavailable",
    )
    def test_batches_the_nine_gnu_frontiers_against_exact_artifacts(self) -> None:
        plan = plan_direct_call_register_control_authorities(
            original_pe=GNU_ORIGINAL,
            state_machine=GNU_STATE,
            mixed_original_plan=GNU_MIXED,
            machine_import_report=GNU_IMPORTS,
            requests=[RegisterControlFrontierRequest(rva) for rva in GNU_USES],
            lean_context="StageA.Generated.Gnu.context",
            lean_source_invariant="StageA.Generated.Gnu.sourceInvariant",
            lean_context_module="StageA.Generated.GnuContext",
        )

        self.assertEqual(tuple(site.use_instruction_rva for site in plan.sites), GNU_USES)
        self.assertEqual(
            {crossing.callsite_rva for crossing in plan.crossings},
            {0x1837, 0x18C0, 0x1913, 0x1FFC},
        )
        self.assertEqual(plan.modules, ())
        self.assertIn("semantic_direct_call_provenance_missing", {
            blocker.category for blocker in plan.blockers
        })
        self.assertIn("external_return_target_inventory_required", {
            blocker.category for blocker in plan.blockers
        })


if __name__ == "__main__":
    unittest.main()

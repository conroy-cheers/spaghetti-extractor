from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import pefile

from spaghetti_extractor.relational.lean.callable_external_proposal import (
    CallableResolverRouteEvidence,
)
from spaghetti_extractor.relational.lean.finite_static_word_provenance import (
    FiniteStaticWordProvenanceError,
    discover_finite_static_word_origins,
)
from spaghetti_extractor.relational.lean.interpreter_mixed_original import (
    InterpreterMixedOriginalPlan,
    InterpreterMixedOriginalSpec,
    OriginalCallableExternalRouteBinding,
    OriginalModuleBindings,
    OriginalRegion,
)
from tests.test_stage_a_nullable_code_pointer_table import (
    IMAGE_BASE,
    TEXT_RVA,
)
from tests.test_stage_a_reachable_static_pointer_slot_kernel import _fixture_pe
from tests.test_stage_a_relocated_writable_static_pointer_slot_proposal import (
    SLOT_RVA,
    SLOT_VA,
)


CALL_RVA = TEXT_RVA
BRANCH_RVA = TEXT_RVA + 2
RESOURCE_WRITE_RVA = TEXT_RVA + 6
FALLBACK_RVA = TEXT_RVA + 11
INITIAL_TARGET_RVA = TEXT_RVA + 0x30
FALLBACK_TARGET_RVA = TEXT_RVA + 0x40


def _condition() -> dict[str, object]:
    return {
        "op": "eq",
        "args": [
            {
                "op": "and32",
                "args": [
                    {"op": "reg", "name": "eax", "width": 32},
                    {"op": "reg", "name": "eax", "width": 32},
                ],
            },
            {"op": "const", "value": 0, "width": 32},
        ],
    }


def _fixture(root: Path, *, guarded: bool) -> tuple[pefile.PE, dict, object]:
    code = bytearray(b"\x90" * 0x60)
    code[0:2] = b"\xff\xd0"
    code[2:6] = b"\x85\xc0\x74\x00"
    code[6:11] = b"\xa3" + SLOT_VA.to_bytes(4, "little")
    fallback_va = IMAGE_BASE + FALLBACK_TARGET_RVA
    code[11:21] = (
        b"\xb8"
        + fallback_va.to_bytes(4, "little")
        + b"\xa3"
        + SLOT_VA.to_bytes(4, "little")
    )
    code[INITIAL_TARGET_RVA - TEXT_RVA] = 0xC3
    code[FALLBACK_TARGET_RVA - TEXT_RVA] = 0xC3
    path = root / "fixture.exe"
    path.write_bytes(
        _fixture_pe(
            code=bytes(code),
            slot_word=IMAGE_BASE + INITIAL_TARGET_RVA,
            relocation=True,
        )
    )
    regions = (
        OriginalRegion(
            target_id=0,
            rva=CALL_RVA,
            size=2,
            successor_ids=(1,),
            root=True,
        ),
        OriginalRegion(
            target_id=1,
            rva=BRANCH_RVA,
            size=4,
            successor_ids=(2, 3),
            root=False,
        ),
        OriginalRegion(
            target_id=2,
            rva=RESOURCE_WRITE_RVA,
            size=5,
            successor_ids=(),
            root=False,
        ),
        OriginalRegion(
            target_id=3,
            rva=FALLBACK_RVA,
            size=10,
            successor_ids=(),
            root=False,
        ),
        OriginalRegion(
            target_id=4,
            rva=INITIAL_TARGET_RVA,
            size=1,
            successor_ids=(),
            root=False,
        ),
        OriginalRegion(
            target_id=5,
            rva=FALLBACK_TARGET_RVA,
            size=1,
            successor_ids=(),
            root=False,
        ),
    )
    plan = InterpreterMixedOriginalPlan(
        spec=InterpreterMixedOriginalSpec(
            bindings=OriginalModuleBindings(
                module="StageA.GeneratedFiniteSlotFixture",
                namespace="StageA.GeneratedFiniteSlotFixture",
            ),
            entry_rva=CALL_RVA,
        ),
        state_machine_sha256="0" * 64,
        regions=regions,
        import_identities=(),
        reachable_target_ids=tuple(range(len(regions))),
        indirect_sites=(),
        blockers=(),
    )
    rows = {
        CALL_RVA: {
            "ordered_events": [],
            "outcome": {"kind": "fallthrough", "target_rva": BRANCH_RVA},
        },
        BRANCH_RVA: {
            "ordered_events": [],
            "outcome": (
                {
                    "kind": "branch",
                    "condition": _condition(),
                    "true_target_rva": FALLBACK_RVA,
                    "false_target_rva": RESOURCE_WRITE_RVA,
                }
                if guarded
                else {"kind": "fallthrough", "target_rva": RESOURCE_WRITE_RVA}
            ),
        },
        RESOURCE_WRITE_RVA: {
            "ordered_events": [
                {
                    "kind": "write",
                    "instruction_rva": RESOURCE_WRITE_RVA,
                    "address": {"op": "const", "value": SLOT_VA, "width": 32},
                    "value": {"op": "reg", "name": "eax", "width": 32},
                    "width": 4,
                }
            ],
        },
        FALLBACK_RVA: {
            "ordered_events": [
                {
                    "kind": "write",
                    "instruction_rva": FALLBACK_RVA + 5,
                    "address": {"op": "const", "value": SLOT_VA, "width": 32},
                    "value": {
                        "op": "const",
                        "value": fallback_va,
                        "width": 32,
                    },
                    "width": 4,
                }
            ],
        },
    }
    return pefile.PE(str(path), fast_load=False), rows, plan


class StageAFiniteStaticWordProvenanceTests(unittest.TestCase):
    def test_nonzero_resolver_and_fallback_form_exact_finite_inventory(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            pe, rows, plan = _fixture(Path(temporary), guarded=True)
            try:
                evidence = discover_finite_static_word_origins(
                    pe=pe,
                    image_base=IMAGE_BASE,
                    rows=rows,
                    plan=plan,
                    slot_rva=SLOT_RVA,
                    slot_va=SLOT_VA,
                    initial_target_id=4,
                    resolver_routes_by_instruction_rva={
                        CALL_RVA: CallableResolverRouteEvidence(
                            instruction_rva=CALL_RVA,
                            result_register="eax",
                            nullable=True,
                            route=OriginalCallableExternalRouteBinding(
                                resolver_contract_id=7,
                                capability_id=8,
                                abi_contract_id=9,
                                resource_id=10,
                            ),
                        )
                    },
                )
            finally:
                pe.close()

        self.assertEqual(evidence.internal_target_ids, (4, 5))
        self.assertEqual(
            tuple(route.resource_id for route in evidence.external_routes),
            (10,),
        )
        resource_write = evidence.writes[0]
        self.assertEqual(resource_write.internal_target_ids, ())
        self.assertEqual(resource_write.external_routes[0].resource_id, 10)

    def test_nullable_resolver_without_nonzero_guard_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            pe, rows, plan = _fixture(Path(temporary), guarded=False)
            try:
                with self.assertRaisesRegex(
                    FiniteStaticWordProvenanceError,
                    "without a nonzero guard",
                ):
                    discover_finite_static_word_origins(
                        pe=pe,
                        image_base=IMAGE_BASE,
                        rows=rows,
                        plan=plan,
                        slot_rva=SLOT_RVA,
                        slot_va=SLOT_VA,
                        initial_target_id=4,
                        resolver_routes_by_instruction_rva={
                            CALL_RVA: CallableResolverRouteEvidence(
                                instruction_rva=CALL_RVA,
                                result_register="eax",
                                nullable=True,
                                route=OriginalCallableExternalRouteBinding(
                                    resolver_contract_id=7,
                                    capability_id=8,
                                    abi_contract_id=9,
                                    resource_id=10,
                                ),
                            )
                        },
                    )
            finally:
                pe.close()


if __name__ == "__main__":
    unittest.main()

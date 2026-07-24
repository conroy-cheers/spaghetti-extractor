from __future__ import annotations

import dataclasses
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_mixed_original import (
    InterpreterMixedOriginalPlan,
    InterpreterMixedOriginalSpec,
    OriginalCallableExternalRouteBinding,
    OriginalGenerationBlocker,
    OriginalIndirectSite,
    OriginalModuleBindings,
    OriginalRegion,
)
from spaghetti_extractor.relational.lean.finite_static_word_provenance import (
    StaticWordWriteOriginEvidence,
)
from spaghetti_extractor.relational.lean.relocated_writable_static_pointer_slot_authority import (
    RelocatedWritableStaticPointerSlotAuthorityError,
    consume_relocated_writable_static_pointer_slot_authorities,
    load_relocated_writable_static_pointer_slot_authorities,
    sha256_file,
    write_decomposed_writable_static_pointer_slot_adapters,
)
from spaghetti_extractor.relational.lean.relocated_writable_static_pointer_slot_proposal import (
    LeanAuthorityBinding,
    construct_relocated_writable_static_pointer_slot_authorities,
    write_relocated_writable_static_pointer_slot_authorities,
)
from tests.test_stage_a_nullable_code_pointer_table import (
    DATA_RVA,
    IMAGE_BASE,
    TEXT_RVA,
)
from tests.test_stage_a_reachable_static_pointer_slot_kernel import _fixture_pe


SLOT_RVA = DATA_RVA + 0x20
SLOT_VA = IMAGE_BASE + SLOT_RVA
TARGET_RVA = TEXT_RVA + 0x10
TARGET_VA = IMAGE_BASE + TARGET_RVA


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fixture(
    root: Path,
    *,
    register_mediated: bool = False,
    register_late_write: bool = False,
    jump: bool = False,
) -> tuple[Path, Path, Path, InterpreterMixedOriginalPlan]:
    if jump and (register_mediated or register_late_write):
        raise ValueError("the jump fixture currently exercises direct slot control")
    if jump:
        encoded = b"\xff\x25" + SLOT_VA.to_bytes(4, "little")
        instruction_rva = TEXT_RVA
    elif register_late_write:
        register_mediated = True
        encoded = (
            b"\x53"
            + b"\xa1"
            + SLOT_VA.to_bytes(4, "little")
            + b"\x6a\x01"
            + b"\xff\xd0"
        )
        instruction_rva = TEXT_RVA + len(encoded) - 2
    elif register_mediated:
        encoded = b"\xa1" + SLOT_VA.to_bytes(4, "little") + b"\xff\xd0"
        instruction_rva = TEXT_RVA + 5
    else:
        encoded = b"\xff\x15" + SLOT_VA.to_bytes(4, "little")
        instruction_rva = TEXT_RVA
    continuation_rva = TEXT_RVA + len(encoded)
    code = bytearray(b"\x90" * 0x20)
    code[: len(encoded)] = encoded
    code[continuation_rva - TEXT_RVA] = 0xC3
    code[TARGET_RVA - TEXT_RVA] = 0xC3
    pe_path = root / "fixture.exe"
    pe_path.write_bytes(
        _fixture_pe(
            code=bytes(code),
            slot_word=TARGET_VA,
            relocation=True,
        )
    )
    state_path = root / "state-machine.jsonl"
    source_size = len(encoded)
    if register_late_write:
        instructions = [
            {
                "bytes": "53",
                "mnemonic": "push",
                "op_str": "ebx",
                "rva": TEXT_RVA,
                "size": 1,
            },
            {
                "bytes": encoded[1:6].hex(),
                "mnemonic": "mov",
                "op_str": f"eax, dword ptr [{SLOT_VA:#x}]",
                "rva": TEXT_RVA + 1,
                "size": 5,
            },
            {
                "bytes": encoded[6:8].hex(),
                "mnemonic": "push",
                "op_str": "1",
                "rva": TEXT_RVA + 6,
                "size": 2,
            },
            {
                "bytes": encoded[8:].hex(),
                "mnemonic": "call",
                "op_str": "eax",
                "rva": instruction_rva,
                "size": 2,
            },
        ]
    elif register_mediated:
        instructions = [
            {
                "bytes": encoded[:5].hex(),
                "mnemonic": "mov",
                "op_str": f"eax, dword ptr [{SLOT_VA:#x}]",
                "rva": TEXT_RVA,
                "size": 5,
            },
            {
                "bytes": encoded[5:].hex(),
                "mnemonic": "call",
                "op_str": "eax",
                "rva": instruction_rva,
                "size": 2,
            },
        ]
    elif jump:
        instructions = [
            {
                "bytes": encoded.hex(),
                "mnemonic": "jmp",
                "op_str": f"dword ptr [{SLOT_VA:#x}]",
                "rva": instruction_rva,
                "size": len(encoded),
            }
        ]
    else:
        instructions = [
            {
                "bytes": encoded.hex(),
                "mnemonic": "call",
                "op_str": f"dword ptr [{SLOT_VA:#x}]",
                "rva": instruction_rva,
                "size": len(encoded),
            }
        ]
    source_row = {
        "format": "stage-a-semantic-transfer-contract-v1",
        "instructions": instructions,
        "original": {
            "rva_start": TEXT_RVA,
            "rva_end": TEXT_RVA + source_size,
            "size": source_size,
        },
        "ordered_events": ([] if jump else ([
            {
                "address": {
                    "args": [
                        {"name": "esp", "op": "reg", "width": 32},
                        {"op": "const", "value": 4, "width": 32},
                    ],
                    "op": "sub32",
                    "width": 32,
                },
                "instruction_rva": TEXT_RVA,
                "kind": "write",
                "value": {"name": "ebx", "op": "reg", "width": 32},
                "width": 4,
            },
            {
                "address": {
                    "args": [
                        {"name": "esp", "op": "reg", "width": 32},
                        {"op": "const", "value": 8, "width": 32},
                    ],
                    "op": "sub32",
                    "width": 32,
                },
                "instruction_rva": TEXT_RVA + 6,
                "kind": "write",
                "value": {"op": "const", "value": 1, "width": 32},
                "width": 4,
            },
        ] if register_late_write else []) + [
            {
                "instruction_rva": instruction_rva,
                "kind": "indirect_call",
                "return_rva": continuation_rva,
                "target": {
                    "op": "load",
                    "width": 4,
                    "address": {
                        "op": "const",
                        "value": SLOT_VA,
                        "width": 32,
                    },
                },
            }
        ]),
    }
    if jump:
        source_row["outcome"] = {
            "kind": "indirect_jump",
            "target": {
                "op": "load",
                "width": 4,
                "address": {
                    "op": "const",
                    "value": SLOT_VA,
                    "width": 32,
                },
            },
        }
    state_path.write_text(
        json.dumps(source_row, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    machine_path = root / "machine-report.json"
    machine_path.write_text(
        json.dumps(
            {
                "inputs": {
                    "original_sha256": _sha256(pe_path),
                    "state_machine_sha256": _sha256(state_path),
                },
                "signatures": [
                    {"id": 0, "memory_effect": "none"},
                    {"id": 1, "memory_effect": "relationalState"},
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    site = OriginalIndirectSite(
        source_rva=TEXT_RVA,
        instruction_rva=instruction_rva,
        category="static_pointer_slot",
        detail="fixture unresolved writable slot",
        target_va=SLOT_VA,
        resolved_target_rva=None if register_mediated else TARGET_RVA,
        is_call=not jump,
        continuation_rva=None if jump else continuation_rva,
        target_expression={
            "op": "load",
            "width": 4,
            "address": {
                "op": "const",
                "value": SLOT_VA,
                "width": 32,
            },
        },
    )
    regions = (
        OriginalRegion(
            target_id=0,
            rva=TEXT_RVA,
            size=source_size,
            successor_ids=() if jump else (1,),
            root=True,
            indirect_sites=(site,),
        ),
        OriginalRegion(
            target_id=1,
            rva=continuation_rva,
            size=1,
            successor_ids=(),
            root=False,
        ),
        OriginalRegion(
            target_id=2,
            rva=TARGET_RVA,
            size=1,
            successor_ids=(),
            root=False,
        ),
    )
    plan = InterpreterMixedOriginalPlan(
        spec=InterpreterMixedOriginalSpec(
            bindings=OriginalModuleBindings(
                module="StageA.GeneratedFixture",
                namespace="StageA.GeneratedFixture",
            ),
            entry_rva=TEXT_RVA,
        ),
        state_machine_sha256=_sha256(state_path),
        regions=regions,
        import_identities=(),
        reachable_target_ids=(0, 2) if jump else (0, 1, 2),
        indirect_sites=(site,),
        blockers=(
            OriginalGenerationBlocker(
                reason_code="unresolved_indirect_control",
                rva=TEXT_RVA,
                detail=(
                    f"static_pointer_slot at 0x{instruction_rva:x}: "
                    "fixture frontier"
                ),
            ),
        ),
    )
    return pe_path, state_path, machine_path, plan


class StageARelocatedWritableStaticPointerSlotProposalTests(unittest.TestCase):
    def _construct_and_write(
        self,
        root: Path,
        *,
        register_mediated: bool = False,
        jump: bool = False,
    ):
        pe, state, machine, mixed = _fixture(
            root, register_mediated=register_mediated, jump=jump
        )
        proposal = (
            construct_relocated_writable_static_pointer_slot_authorities(
                original_pe=pe,
                state_machine=state,
                machine_import_report=machine,
                mixed_original_plan=mixed,
            )
        )
        report, sources = (
            write_relocated_writable_static_pointer_slot_authorities(
                root / "out",
                proposal,
                LeanAuthorityBinding(
                    dependency_modules=("StageA.GeneratedFixture",),
                    context_term="StageA.GeneratedFixture.originalContext",
                    carrier_term="StageA.GeneratedFixture.carrierContext",
                    decoded_authority_term=(
                        "StageA.GeneratedFixture.originalAuthority"
                    ),
                ),
            )
        )
        references = load_relocated_writable_static_pointer_slot_authorities(
            report,
            original_sha256=sha256_file(pe),
            state_machine_sha256=sha256_file(state),
            machine_import_report_sha256=sha256_file(machine),
            mixed_original_plan=mixed,
        )
        return pe, state, machine, mixed, proposal, report, sources, references

    def test_direct_slot_call_is_checked_and_consumed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = self._construct_and_write(Path(temporary))
            proposal, sources, references = result[4], result[6], result[7]
            self.assertEqual(proposal.blockers, ())
            self.assertEqual(len(proposal.bindings), 1)
            self.assertEqual(len(sources), 1)
            self.assertEqual(references[0].key.target_rva, TARGET_RVA)
            consumed = consume_relocated_writable_static_pointer_slot_authorities(
                result[3], references
            )

        self.assertEqual(consumed.blocker_count_before, 1)
        self.assertEqual(consumed.blocker_count_after, 0)
        source = consumed.plan.regions[0]
        self.assertEqual(source.successor_ids, (1, 2))
        self.assertIsNotNone(source.indirect_sites[0].static_binding)
        self.assertEqual(len(consumed.authorizing_terms), 1)
        with tempfile.TemporaryDirectory() as temporary:
            adapters = write_decomposed_writable_static_pointer_slot_adapters(
                temporary, consumed
            )
            adapter_source = adapters[0].path.read_text(encoding="utf-8")
        self.assertEqual(len(adapters), 1)
        self.assertIn(references[0].term.qualified, adapter_source)
        self.assertIn("consumedBindingValidChecked", adapter_source)

    def test_register_mediated_call_uses_the_same_slot_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = self._construct_and_write(
                Path(temporary), register_mediated=True
            )
            binding = result[4].bindings[0]
            self.assertEqual(binding.instruction_form, "register_indirect")
            self.assertTrue(binding.recovered_from_unresolved_target)
            consumed = consume_relocated_writable_static_pointer_slot_authorities(
                result[3], result[7]
            )

        site = consumed.plan.regions[0].indirect_sites[0]
        self.assertEqual(site.resolved_target_rva, TARGET_RVA)
        self.assertIsNotNone(site.static_binding)

    def test_direct_slot_jump_is_checked_and_consumed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = self._construct_and_write(Path(temporary), jump=True)
            binding = result[4].bindings[0]
            reference = result[7][0]
            self.assertEqual(binding.transfer_kind, "jump")
            self.assertIsNone(binding.continuation_target_id)
            self.assertEqual(reference.key.transfer_kind, "jump")
            consumed = consume_relocated_writable_static_pointer_slot_authorities(
                result[3], result[7]
            )

        source = consumed.plan.regions[0]
        self.assertEqual(consumed.blocker_count_after, 0)
        self.assertEqual(source.successor_ids, (2,))
        self.assertFalse(source.indirect_sites[0].is_call)
        self.assertIsNotNone(source.indirect_sites[0].static_binding)

    def test_finite_jump_report_is_checked_and_emits_callable_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe, state, machine, mixed = _fixture(root, jump=True)
            fixed = construct_relocated_writable_static_pointer_slot_authorities(
                original_pe=pe,
                state_machine=state,
                machine_import_report=machine,
                mixed_original_plan=mixed,
            )
            route = OriginalCallableExternalRouteBinding(
                resolver_contract_id=0,
                capability_id=0,
                abi_contract_id=0,
                resource_id=0,
            )
            evidence = StaticWordWriteOriginEvidence(
                source_target_id=0,
                source_rva=TEXT_RVA,
                instruction_rva=TEXT_RVA,
                internal_target_ids=(2,),
                external_routes=(route,),
            )
            finite = dataclasses.replace(
                fixed,
                bindings=(
                    dataclasses.replace(
                        fixed.bindings[0],
                        internal_target_ids=(2,),
                        external_routes=(route,),
                        write_origin_evidence=(evidence,),
                    ),
                ),
            )
            report, _sources = (
                write_relocated_writable_static_pointer_slot_authorities(
                    root / "finite",
                    finite,
                    LeanAuthorityBinding(
                        dependency_modules=("StageA.GeneratedFixture",),
                        context_term="StageA.GeneratedFixture.originalContext",
                        carrier_term="StageA.GeneratedFixture.carrierContext",
                        decoded_authority_term=(
                            "StageA.GeneratedFixture.originalAuthority"
                        ),
                    ),
                )
            )
            references = load_relocated_writable_static_pointer_slot_authorities(
                report,
                original_sha256=sha256_file(pe),
                state_machine_sha256=sha256_file(state),
                machine_import_report_sha256=sha256_file(machine),
                mixed_original_plan=mixed,
            )
            consumed = consume_relocated_writable_static_pointer_slot_authorities(
                mixed, references
            )
            adapters = write_decomposed_writable_static_pointer_slot_adapters(
                root / "adapters", consumed
            )
            source = adapters[0].path.read_text(encoding="utf-8")

            self.assertEqual(references[0].value_relation, "finite_origins")
            self.assertEqual(references[0].internal_target_ids, (2,))
            self.assertEqual(references[0].external_routes, (route,))
            self.assertIn("CheckedFiniteJumpAuthority", source)
            self.assertIn("CallableIndirectRuntimeResolution.of_staticWordOrigin", source)
            self.assertIn("consumedCallableIndirectExitCertificate.generic", source)

            payload = json.loads(report.read_text(encoding="utf-8"))
            payload["sites"][0]["write_origin_evidence"][0][
                "external_routes"
            ].append(
                {
                    "abi_contract_id": 1,
                    "capability_id": 1,
                    "resolver_contract_id": 1,
                    "resource_id": 1,
                }
            )
            report.write_text(
                json.dumps(payload, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                RelocatedWritableStaticPointerSlotAuthorityError,
                "write evidence escapes",
            ):
                load_relocated_writable_static_pointer_slot_authorities(
                    report,
                    original_sha256=sha256_file(pe),
                    state_machine_sha256=sha256_file(state),
                    machine_import_report_sha256=sha256_file(machine),
                    mixed_original_plan=mixed,
                )

    def test_call_authority_relabelled_as_jump_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = self._construct_and_write(Path(temporary))
            payload = json.loads(result[5].read_text(encoding="utf-8"))
            payload["sites"][0]["transfer_kind"] = "jump"
            result[5].write_text(
                json.dumps(payload, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(
                RelocatedWritableStaticPointerSlotAuthorityError
            ):
                load_relocated_writable_static_pointer_slot_authorities(
                    result[5],
                    original_sha256=sha256_file(result[0]),
                    state_machine_sha256=sha256_file(result[1]),
                    machine_import_report_sha256=sha256_file(result[2]),
                    mixed_original_plan=result[3],
                )

    def test_register_target_replay_stops_at_the_exact_slot_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe, state, machine, mixed = _fixture(
                root, register_late_write=True
            )
            proposal = construct_relocated_writable_static_pointer_slot_authorities(
                original_pe=pe,
                state_machine=state,
                machine_import_report=machine,
                mixed_original_plan=mixed,
            )

        self.assertEqual(proposal.blockers, ())
        self.assertEqual(len(proposal.bindings), 1)
        writes = proposal.bindings[0].writes
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0].register, "esp")
        self.assertEqual(writes[0].offset, 0xFFFFFFFC)
        self.assertEqual(writes[0].value["name"], "ebx")

    def test_external_stateful_effect_remains_an_explicit_frame(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = self._construct_and_write(Path(temporary))
            classes = {
                item.memory_effect: item.authority
                for item in result[4].external_preservation
            }

        self.assertEqual(classes["none"], "footprint frame: memory unchanged")
        self.assertIn("finite-set", classes["relationalState"])

    def test_hash_or_plan_drift_rejects_consumption(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = self._construct_and_write(Path(temporary))
            drifted = dataclasses.replace(
                result[3],
                reachable_target_ids=(0, 1),
            )
            with self.assertRaises(
                RelocatedWritableStaticPointerSlotAuthorityError
            ):
                load_relocated_writable_static_pointer_slot_authorities(
                    result[5],
                    original_sha256=sha256_file(result[0]),
                    state_machine_sha256=sha256_file(result[1]),
                    machine_import_report_sha256=sha256_file(result[2]),
                    mixed_original_plan=drifted,
                )

    def test_wrong_slot_value_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe, state, machine, mixed = _fixture(root)
            # Rebuild without a relocation-backed code address.
            pe.write_bytes(_fixture_pe(code=b"\xc3", slot_word=0, relocation=True))
            machine_payload = json.loads(machine.read_text(encoding="utf-8"))
            machine_payload["inputs"]["original_sha256"] = _sha256(pe)
            machine.write_text(
                json.dumps(machine_payload, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            plan = construct_relocated_writable_static_pointer_slot_authorities(
                original_pe=pe,
                state_machine=state,
                machine_import_report=machine,
                mixed_original_plan=mixed,
            )

        self.assertEqual(plan.bindings, ())
        self.assertEqual(len(plan.blockers), 1)
        self.assertIn("code address", plan.blockers[0].detail)


if __name__ == "__main__":
    unittest.main()

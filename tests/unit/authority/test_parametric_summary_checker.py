from __future__ import annotations

import unittest
from dataclasses import replace

from spaghetti_extractor.abi.model import AbiFactV1
from spaghetti_extractor.artifacts.artifact_set import CanonicalValueV3, RecordDependencyV3
from spaghetti_extractor.authority.catalog_call_contracts import CatalogCallContractV1
from spaghetti_extractor.authority.call_boundary_contracts import (
    CallBoundaryContractV3,
)
from spaghetti_extractor.authority.parametric_summary_checker import (
    PARAMETRIC_SCC_SUMMARIES_PHASE_V3,
    DirectCallEvidenceV3,
    ExternalCallEvidenceV3,
    CheckedIndirectTargetEvidenceV3,
    IndirectExpressionEvidenceV3,
    MemoryEffectEvidenceV3,
    ParametricSccEvidenceV3,
    StackAccessEvidenceV3,
    UnitSummaryEvidenceV3,
    check_parametric_scc_proposal_v3,
)
from spaghetti_extractor.authority.parametric_summary_records import (
    CallEffectV3,
    ParametricSccProposalV3,
    ParametricIndirectExitV3,
    RegisterRelationV3,
    ReturnBehaviorV3,
    StackAccessV3,
    StaticMemoryEffectV3,
    ValueFactV3,
    ValueOriginV3,
    parametric_scc_id_v3,
)
from spaghetti_extractor.authority.external_site_records import ExternalProfileV3
from spaghetti_extractor.authority.structural_targets import StructuralTargetProposalV3


PRESERVED_REGISTERS = ("ebp", "ebx", "edi", "esi")


def _dependencies() -> tuple[RecordDependencyV3, ...]:
    return (
        RecordDependencyV3("semantic_index", "unit:a"),
        RecordDependencyV3("transition_summaries", "unit:a"),
    )


def _unit(
    *,
    direct_calls: tuple[DirectCallEvidenceV3, ...] = (),
    returns: bool = True,
    external_calls: tuple[ExternalCallEvidenceV3, ...] = (),
    stack_accesses: tuple[StackAccessEvidenceV3, ...] = (),
) -> UnitSummaryEvidenceV3:
    return UnitSummaryEvidenceV3(
        unit_id="unit:a",
        pe_sha256="a" * 64,
        transition_summary_id="transition:a",
        rva_start=0x1000,
        input_registers=("eax", "ebx"),
        register_outputs=(("eax", {"op": "const", "value": 7, "width": 32}),),
        stack_net_bytes=12 if returns else None,
        return_cleanup_bytes=8 if returns else None,
        returns=returns,
        may_not_return=not returns,
        external_calls=external_calls,
        direct_calls=direct_calls,
        indirect_expressions=(),
        event_register_inputs=(),
        stack_accesses=stack_accesses,
    )


def _evidence(
    *,
    recursive: bool = False,
    direct_calls: tuple[DirectCallEvidenceV3, ...] = (),
    kills: tuple[str, ...] = (),
    memory_effects: tuple[MemoryEffectEvidenceV3, ...] = (),
    unversioned: tuple[str, ...] = (),
    external_calls: tuple[ExternalCallEvidenceV3, ...] = (),
    stack_accesses: tuple[StackAccessEvidenceV3, ...] = (),
    profiles: tuple[ExternalProfileV3, ...] = (),
    program_units: tuple[UnitSummaryEvidenceV3, ...] = (),
) -> ParametricSccEvidenceV3:
    return ParametricSccEvidenceV3(
        scc_id="scc:checked",
        member_unit_ids=("unit:a",),
        recursive=recursive,
        units=(
            _unit(
                direct_calls=direct_calls,
                external_calls=external_calls,
                stack_accesses=stack_accesses,
            ),
        ),
        unknown_kill_components=kills,
        memory_effects=memory_effects,
        unversioned_memory_access_ids=unversioned,
        structural_targets=(),
        external_profiles=profiles,
        expected_dependencies=_dependencies(),
        program_units=program_units,
    )


def _program_unit(
    unit_id: str,
    *,
    outputs: tuple[tuple[str, object], ...] = (),
    direct_targets: tuple[str, ...] = (),
    direct_calls: tuple[DirectCallEvidenceV3, ...] = (),
    external_calls: tuple[ExternalCallEvidenceV3, ...] = (),
    returns: bool = False,
    indirect: bool = False,
    unresolved_direct: tuple[int, ...] = (),
) -> UnitSummaryEvidenceV3:
    return UnitSummaryEvidenceV3(
        unit_id=unit_id,
        pe_sha256="a" * 64,
        transition_summary_id=f"transition:{unit_id}",
        rva_start=0x1000,
        input_registers=(),
        register_outputs=outputs,
        stack_net_bytes=4 if returns else None,
        return_cleanup_bytes=0 if returns else None,
        returns=returns,
        may_not_return=not returns,
        external_calls=external_calls,
        direct_calls=direct_calls,
        indirect_expressions=(
            IndirectExpressionEvidenceV3(
                f"exit:{unit_id}",
                None,
                "indirect_jump",
                {"op": "reg", "name": "eax", "width": 32},
                "f" * 64,
            ),
        )
        if indirect
        else (),
        event_register_inputs=(),
        direct_target_unit_ids=direct_targets,
        unresolved_direct_target_rvas=unresolved_direct,
    )


def _direct_call_effect(
    preserved_registers: tuple[str, ...] | None,
    *,
    target: str = "unit:b",
    catalog_contract_id: str | None = None,
) -> CallEffectV3:
    return CallEffectV3(
        "call:3",
        "unit:a",
        3,
        "direct_internal",
        (target,),
        None,
        (),
        None,
        preserved_registers,
        catalog_contract_id,
    )


def _partial_catalog_contract(
    *,
    preserved: tuple[str, ...] = PRESERVED_REGISTERS,
) -> CatalogCallContractV1:
    return CatalogCallContractV1.create(
        binary_sha256="a" * 64,
        match_id="match:unit-b",
        target_region_id="region:unit-b",
        target_entry_unit_id="unit:b",
        target_unit_ids=("unit:b",),
        catalog_id="catalog:test",
        catalog_sha256="b" * 64,
        catalog_function_id="catalog:function-b",
        certificate_id="certificate:function-b",
        exact_facts=(
            AbiFactV1.create(
                subject_id="catalog:function-b",
                field="preserved_state",
                status="exact",
                values=(list(preserved),),
            ),
            AbiFactV1.create(
                subject_id="catalog:function-b",
                field="stack_cleanup",
                status="exact",
                values=({"kind": "caller", "bytes": 0},),
            ),
        ),
    )


def _facts() -> tuple[ValueFactV3, ...]:
    return (
        ValueFactV3("fact:eax", "finite", (ValueOriginV3("exact_bits", exact_bits=7),)),
        ValueFactV3("fact:ebx", "finite", (ValueOriginV3("entry_register", "ebx", 0),)),
    )


def _proposal(
    evidence: ParametricSccEvidenceV3,
    *,
    value_budget: int = 4,
    base_paths: tuple[str, ...] = (),
    memory_effects: tuple[StaticMemoryEffectV3, ...] = (),
    stack_accesses: tuple[StackAccessV3, ...] = (),
    call_effects: tuple[CallEffectV3, ...] = (),
    dependencies: tuple[RecordDependencyV3, ...] | None = None,
    facts: tuple[ValueFactV3, ...] | None = None,
    indirect_exits: tuple[ParametricIndirectExitV3, ...] = (),
) -> ParametricSccProposalV3:
    return ParametricSccProposalV3.create(
        scc_id=evidence.scc_id,
        member_unit_ids=evidence.member_unit_ids,
        base_path_unit_ids=base_paths,
        value_budget=value_budget,
        value_facts=_facts() if facts is None else facts,
        register_relations=(
            RegisterRelationV3("relation:eax", "unit:a", "eax", "constant", "fact:eax"),
            RegisterRelationV3("relation:ebx", "unit:a", "ebx", "preserved", "fact:ebx"),
        ),
        stack_accesses=stack_accesses,
        stack_cleanup_bytes=8,
        return_address_preserved=True,
        memory_effects=memory_effects,
        call_effects=call_effects,
        returns=(ReturnBehaviorV3("unit:a", True, False, 8, True),),
        indirect_exits=indirect_exits,
        dependencies=evidence.expected_dependencies if dependencies is None else dependencies,
    )


class ParametricSummaryCheckerTests(unittest.TestCase):
    def test_phase_is_explicit_temporary_reduce_with_per_scc_checker_api(self) -> None:
        self.assertEqual(PARAMETRIC_SCC_SUMMARIES_PHASE_V3.form, "reduce")
        self.assertEqual(
            PARAMETRIC_SCC_SUMMARIES_PHASE_V3.output_artifact_kind,
            "parametric-scc-summaries-v3",
        )
        self.assertEqual(
            PARAMETRIC_SCC_SUMMARIES_PHASE_V3.required_inputs,
            (
                "call_boundary_contracts",
                "catalog_call_contracts",
                "external_profiles",
                "memory_versions",
                "parametric_proposals",
                "static_value_origins",
                "structural_targets",
                "unit_facts",
            ),
        )

    def test_preservation_constant_and_ret_n_are_checked(self) -> None:
        evidence = _evidence()
        result = check_parametric_scc_proposal_v3(_proposal(evidence), evidence)

        self.assertEqual(result.status, "complete")
        self.assertTrue(result.authorizing)
        self.assertTrue(result.preserves_register("unit:a", "ebx"))
        self.assertEqual(result.stack_cleanup_bytes, 8)

    def test_false_preservation_is_violated(self) -> None:
        evidence = _evidence()
        proposal = _proposal(evidence)
        proposal = ParametricSccProposalV3.create(
            **{
                **proposal.__dict__,
                "value_facts": (proposal.value_fact("fact:ebx"),),
                "register_relations": (
                    RegisterRelationV3("relation:eax", "unit:a", "eax", "preserved", "fact:ebx"),
                    proposal.register_relations[1],
                ),
            }
        )

        result = check_parametric_scc_proposal_v3(proposal, evidence)
        self.assertEqual(result.status, "violated")
        self.assertEqual(result.primary_blocker.code, "register_preservation_contradiction")

    def test_direct_internal_leaf_preservation_is_checked(self) -> None:
        direct = DirectCallEvidenceV3("unit:a", 3, "unit:b")
        evidence = _evidence(
            direct_calls=(direct,),
            program_units=(
                _program_unit("unit:a", direct_calls=(direct,)),
                _program_unit("unit:b", returns=True),
            ),
        )
        call = _direct_call_effect(PRESERVED_REGISTERS)

        checked_edge = check_parametric_scc_proposal_v3(
            _proposal(evidence, call_effects=(call,)), evidence
        )
        missing = check_parametric_scc_proposal_v3(_proposal(evidence), evidence)
        self.assertEqual(checked_edge.status, "complete")
        self.assertTrue(checked_edge.call_preserves_register("unit:a", 3, "ebx"))
        self.assertEqual(missing.status, "incomplete")
        self.assertEqual(missing.primary_blocker.code, "direct_call_effect_missing")

    def test_direct_internal_clobber_removes_only_that_register(self) -> None:
        direct = DirectCallEvidenceV3("unit:a", 3, "unit:b")
        exact = ("ebp", "edi", "esi")
        evidence = _evidence(
            direct_calls=(direct,),
            program_units=(
                _program_unit("unit:a", direct_calls=(direct,)),
                _program_unit(
                    "unit:b",
                    outputs=(("ebx", {"op": "const", "value": 7}),),
                    returns=True,
                ),
            ),
        )

        result = check_parametric_scc_proposal_v3(
            _proposal(evidence, call_effects=(_direct_call_effect(exact),)),
            evidence,
        )

        self.assertEqual(result.status, "complete")
        self.assertFalse(result.call_preserves_register("unit:a", 3, "ebx"))
        self.assertTrue(result.call_preserves_register("unit:a", 3, "esi"))

    def test_missing_checked_call_postcondition_is_localized_incomplete(self) -> None:
        direct = DirectCallEvidenceV3("unit:a", 3, "unit:b")
        evidence = _evidence(
            direct_calls=(direct,),
            program_units=(
                _program_unit("unit:a", direct_calls=(direct,)),
                _program_unit("unit:b", returns=True),
            ),
        )

        result = check_parametric_scc_proposal_v3(
            _proposal(evidence, call_effects=(_direct_call_effect(None),)),
            evidence,
        )

        self.assertEqual(result.status, "incomplete")
        self.assertEqual(
            result.primary_blocker.code,
            "call_preserved_register_postcondition_missing",
        )

    def test_call_memory_frame_composes_read_only_callee(self) -> None:
        direct = DirectCallEvidenceV3("unit:a", 3, "unit:b")
        local = MemoryEffectEvidenceV3("unit:a", "alias:global", "preserved")
        evidence = _evidence(
            direct_calls=(direct,),
            memory_effects=(local,),
            program_units=(
                _program_unit("unit:a", direct_calls=(direct,)),
                _program_unit("unit:b", returns=True),
            ),
        )
        evidence = replace(
            evidence,
            program_memory_effects=(
                local,
                MemoryEffectEvidenceV3(
                    "unit:b", "alias:global", "preserved"
                ),
            ),
        )
        effect = StaticMemoryEffectV3(
            "effect:a", "unit:a", "alias:global", "preserved", None, None
        )

        result = check_parametric_scc_proposal_v3(
            _proposal(
                evidence,
                memory_effects=(effect,),
                call_effects=(_direct_call_effect(PRESERVED_REGISTERS),),
            ),
            evidence,
        )

        self.assertEqual(result.status, "complete")

    def test_call_memory_frame_rejects_callee_write_overclaim(self) -> None:
        direct = DirectCallEvidenceV3("unit:a", 3, "unit:b")
        local = MemoryEffectEvidenceV3("unit:a", "alias:global", "preserved")
        evidence = _evidence(
            direct_calls=(direct,),
            memory_effects=(local,),
            program_units=(
                _program_unit("unit:a", direct_calls=(direct,)),
                _program_unit("unit:b", returns=True),
            ),
        )
        evidence = replace(
            evidence,
            program_memory_effects=(
                local,
                MemoryEffectEvidenceV3("unit:b", "alias:global", "write"),
            ),
        )
        effect = StaticMemoryEffectV3(
            "effect:a", "unit:a", "alias:global", "preserved", None, None
        )

        result = check_parametric_scc_proposal_v3(
            _proposal(
                evidence,
                memory_effects=(effect,),
                call_effects=(_direct_call_effect(PRESERVED_REGISTERS),),
            ),
            evidence,
        )

        self.assertEqual(result.status, "violated")
        self.assertEqual(
            result.primary_blocker.code,
            "call_memory_postcondition_overclaim",
        )

    def test_call_memory_frame_fails_closed_on_unversioned_callee_access(self) -> None:
        direct = DirectCallEvidenceV3("unit:a", 3, "unit:b")
        local = MemoryEffectEvidenceV3("unit:a", "alias:global", "preserved")
        evidence = _evidence(
            direct_calls=(direct,),
            memory_effects=(local,),
            program_units=(
                _program_unit("unit:a", direct_calls=(direct,)),
                _program_unit("unit:b", returns=True),
            ),
        )
        evidence = replace(
            evidence,
            program_memory_effects=(local,),
            program_unversioned_memory_unit_ids=("unit:b",),
        )
        effect = StaticMemoryEffectV3(
            "effect:a", "unit:a", "alias:global", "preserved", None, None
        )

        result = check_parametric_scc_proposal_v3(
            _proposal(
                evidence,
                memory_effects=(effect,),
                call_effects=(_direct_call_effect(PRESERVED_REGISTERS),),
            ),
            evidence,
        )

        self.assertEqual(result.status, "incomplete")
        self.assertEqual(
            result.primary_blocker.code,
            "call_memory_postcondition_summary_missing",
        )

    def test_direct_control_loop_uses_complete_finite_closure(self) -> None:
        direct = DirectCallEvidenceV3("unit:a", 3, "unit:b")
        evidence = _evidence(
            direct_calls=(direct,),
            program_units=(
                _program_unit("unit:a", direct_calls=(direct,)),
                _program_unit("unit:b", direct_targets=("unit:c",)),
                _program_unit(
                    "unit:c", direct_targets=("unit:b", "unit:d")
                ),
                _program_unit("unit:d", returns=True),
            ),
        )

        result = check_parametric_scc_proposal_v3(
            _proposal(
                evidence,
                call_effects=(_direct_call_effect(PRESERVED_REGISTERS),),
            ),
            evidence,
        )

        self.assertEqual(result.status, "complete")

    def test_nested_internal_call_postcondition_composes(self) -> None:
        outer = DirectCallEvidenceV3("unit:a", 3, "unit:b")
        nested = DirectCallEvidenceV3("unit:b", 1, "unit:e")
        evidence = _evidence(
            direct_calls=(outer,),
            program_units=(
                _program_unit("unit:a", direct_calls=(outer,)),
                _program_unit(
                    "unit:b",
                    direct_targets=("unit:d",),
                    direct_calls=(nested,),
                ),
                _program_unit("unit:d", returns=True),
                _program_unit("unit:e", returns=True),
            ),
        )

        result = check_parametric_scc_proposal_v3(
            _proposal(
                evidence,
                call_effects=(_direct_call_effect(PRESERVED_REGISTERS),),
            ),
            evidence,
        )

        self.assertEqual(result.status, "complete")

    def test_recursive_call_with_base_return_uses_inductive_preservation(self) -> None:
        outer = DirectCallEvidenceV3("unit:a", 3, "unit:b")
        recursive = DirectCallEvidenceV3("unit:d", 1, "unit:b")
        evidence = _evidence(
            direct_calls=(outer,),
            program_units=(
                _program_unit("unit:a", direct_calls=(outer,)),
                _program_unit(
                    "unit:b", direct_targets=("unit:c", "unit:d")
                ),
                _program_unit("unit:c", returns=True),
                _program_unit("unit:d", direct_calls=(recursive,)),
            ),
        )

        result = check_parametric_scc_proposal_v3(
            _proposal(
                evidence,
                call_effects=(_direct_call_effect(PRESERVED_REGISTERS),),
            ),
            evidence,
        )

        self.assertEqual(result.status, "complete")

    def test_unresolved_indirect_callee_target_is_incomplete(self) -> None:
        direct = DirectCallEvidenceV3("unit:a", 3, "unit:b")
        evidence = _evidence(
            direct_calls=(direct,),
            program_units=(
                _program_unit("unit:a", direct_calls=(direct,)),
                _program_unit("unit:b", returns=True, indirect=True),
            ),
        )

        result = check_parametric_scc_proposal_v3(
            _proposal(evidence, call_effects=(_direct_call_effect(None),)),
            evidence,
        )

        self.assertEqual(result.status, "incomplete")
        self.assertEqual(
            result.primary_blocker.code,
            "call_preserved_register_postcondition_unresolved",
        )
        overclaim = check_parametric_scc_proposal_v3(
            _proposal(
                evidence,
                call_effects=(_direct_call_effect(PRESERVED_REGISTERS),),
            ),
            evidence,
        )
        self.assertEqual(overclaim.status, "violated")
        self.assertEqual(
            overclaim.primary_blocker.code, "call_preserved_register_overclaim"
        )

    def test_normal_return_boundary_premise_closes_preservation_only(self) -> None:
        direct = DirectCallEvidenceV3("unit:a", 3, "unit:b")
        evidence = _evidence(
            direct_calls=(direct,),
            program_units=(
                _program_unit("unit:a", direct_calls=(direct,)),
                _program_unit("unit:b", returns=True, indirect=True),
            ),
        )
        contract = CallBoundaryContractV3(
            record_id="unit:b",
            contract_id="premise:unit:b",
            target_unit_sha256="b" * 64,
            target_rva=0x2000,
            premise_record_id="pe32-normal-return-nonvolatile-v1",
            premise_content_sha256="c" * 64,
            transfer_kind="internal_call",
            applies_when="call_returns_normally",
            preserved_registers=PRESERVED_REGISTERS,
            source_frame_count=1,
            status="complete",
            authorizing=True,
            failure_code=None,
        )
        evidence = replace(
            evidence,
            call_boundary_contracts=(contract,),
            expected_dependencies=tuple(
                sorted(
                    (
                        *evidence.expected_dependencies,
                        RecordDependencyV3("call_boundary_contracts", "unit:b"),
                    )
                )
            ),
        )

        result = check_parametric_scc_proposal_v3(
            _proposal(
                evidence,
                call_effects=(_direct_call_effect(PRESERVED_REGISTERS),),
            ),
            evidence,
        )

        self.assertEqual(result.status, "complete")
        self.assertTrue(result.call_preserves_register("unit:a", 3, "ebx"))

    def test_checked_import_thunk_composes_call_preservation(self) -> None:
        direct = DirectCallEvidenceV3("unit:a", 3, "unit:b")
        profile = ExternalProfileV3.create(
            profile_id="kernel32:Example:jump",
            profile_sha256="b" * 64,
            identity={"dll": "kernel32.dll", "symbol": "Example"},
            allowed_transfers=("jump",),
            allowed_dispositions=("returns",),
            argument_words=0,
            memory_effect="none",
            world_effect="none",
            callback_effect="none",
            machine_contract={"abi_template": "pe32-stdcall-v1"},
        )
        evidence = _evidence(
            direct_calls=(direct,),
            profiles=(profile,),
            program_units=(
                _program_unit("unit:a", direct_calls=(direct,)),
                _program_unit("unit:b", indirect=True),
            ),
        )
        evidence = replace(
            evidence,
            checked_indirect_targets=(
                CheckedIndirectTargetEvidenceV3(
                    "exit:unit:b",
                    (ValueOriginV3("import_target", profile.record_id, 0),),
                    (),
                    (profile.record_id,),
                    ("unit:b",),
                    (profile.record_id,),
                ),
            ),
        )

        result = check_parametric_scc_proposal_v3(
            _proposal(
                evidence,
                call_effects=(_direct_call_effect(PRESERVED_REGISTERS),),
            ),
            evidence,
        )

        self.assertEqual(result.status, "complete")

    def test_checked_internal_indirect_target_composes_call_preservation(self) -> None:
        direct = DirectCallEvidenceV3("unit:a", 3, "unit:b")
        evidence = _evidence(
            direct_calls=(direct,),
            program_units=(
                _program_unit("unit:a", direct_calls=(direct,)),
                _program_unit("unit:b", indirect=True),
                _program_unit("unit:c", returns=True),
            ),
        )
        evidence = replace(
            evidence,
            checked_indirect_targets=(
                CheckedIndirectTargetEvidenceV3(
                    "exit:unit:b",
                    (ValueOriginV3("static_code_target", "unit:c", 0),),
                    ("unit:c",),
                    (),
                    ("unit:b", "unit:c"),
                    (),
                ),
            ),
        )

        result = check_parametric_scc_proposal_v3(
            _proposal(
                evidence,
                call_effects=(_direct_call_effect(PRESERVED_REGISTERS),),
            ),
            evidence,
        )

        self.assertEqual(result.status, "complete")

    def test_exact_partial_catalog_contract_closes_only_preservation(self) -> None:
        direct = DirectCallEvidenceV3("unit:a", 3, "unit:b")
        contract = _partial_catalog_contract()
        evidence = _evidence(
            direct_calls=(direct,),
            program_units=(
                _program_unit("unit:a", direct_calls=(direct,)),
                _program_unit("unit:b", returns=True, indirect=True),
            ),
        )
        evidence = replace(
            evidence,
            catalog_call_contracts=(contract,),
            expected_dependencies=tuple(
                sorted(
                    (
                        *evidence.expected_dependencies,
                        RecordDependencyV3(
                            "catalog_call_contracts", contract.contract_id
                        ),
                    )
                )
            ),
        )

        result = check_parametric_scc_proposal_v3(
            _proposal(
                evidence,
                call_effects=(
                    _direct_call_effect(
                        PRESERVED_REGISTERS,
                        catalog_contract_id=contract.contract_id,
                    ),
                ),
            ),
            evidence,
        )

        self.assertEqual(result.status, "complete")
        self.assertTrue(result.call_preserves_register("unit:a", 3, "ebx"))

    def test_contradicted_partial_catalog_contract_is_violated(self) -> None:
        direct = DirectCallEvidenceV3("unit:a", 3, "unit:b")
        contract = _partial_catalog_contract()
        evidence = _evidence(
            direct_calls=(direct,),
            program_units=(
                _program_unit("unit:a", direct_calls=(direct,)),
                _program_unit("unit:b", returns=True),
            ),
        )
        evidence = replace(
            evidence,
            catalog_call_contracts=(contract,),
            invalid_catalog_call_contract_ids=(contract.contract_id,),
            expected_dependencies=tuple(
                sorted(
                    (
                        *evidence.expected_dependencies,
                        RecordDependencyV3(
                            "catalog_call_contracts", contract.contract_id
                        ),
                    )
                )
            ),
        )

        result = check_parametric_scc_proposal_v3(
            _proposal(
                evidence,
                call_effects=(_direct_call_effect(PRESERVED_REGISTERS),),
            ),
            evidence,
        )

        self.assertEqual(result.status, "violated")
        self.assertEqual(
            result.primary_blocker.code,
            "catalog_call_contract_machine_contradiction",
        )

    def test_nested_external_cdecl_and_stdcall_preserve_nonvolatile(self) -> None:
        outer = DirectCallEvidenceV3("unit:a", 3, "unit:b")
        for abi in ("pe32-cdecl-v1", "pe32-stdcall-v1"):
            with self.subTest(abi=abi):
                profile = ExternalProfileV3.create(
                    profile_id=f"kernel32:Example:{abi}",
                    profile_sha256="b" * 64,
                    identity={"dll": "kernel32.dll", "symbol": "Example"},
                    allowed_transfers=("call",),
                    allowed_dispositions=("returns",),
                    argument_words=0,
                    memory_effect="none",
                    world_effect="none",
                    callback_effect="none",
                    machine_contract={"abi_template": abi},
                )
                external = ExternalCallEvidenceV3(
                    7,
                    "call",
                    CanonicalValueV3.of(
                        {"dll": "kernel32.dll", "symbol": "Example"}
                    ),
                )
                evidence = _evidence(
                    direct_calls=(outer,),
                    profiles=(profile,),
                    program_units=(
                        _program_unit("unit:a", direct_calls=(outer,)),
                        _program_unit(
                            "unit:b", external_calls=(external,), returns=True
                        ),
                    ),
                )

                result = check_parametric_scc_proposal_v3(
                    _proposal(
                        evidence,
                        call_effects=(
                            _direct_call_effect(PRESERVED_REGISTERS),
                        ),
                    ),
                    evidence,
                )

                self.assertEqual(result.status, "complete")

    def test_preserved_register_overclaim_is_violated(self) -> None:
        direct = DirectCallEvidenceV3("unit:a", 3, "unit:b")
        evidence = _evidence(
            direct_calls=(direct,),
            program_units=(
                _program_unit("unit:a", direct_calls=(direct,)),
                _program_unit(
                    "unit:b",
                    outputs=(("ebx", {"op": "const", "value": 7}),),
                    returns=True,
                ),
            ),
        )

        result = check_parametric_scc_proposal_v3(
            _proposal(
                evidence,
                call_effects=(_direct_call_effect(PRESERVED_REGISTERS),),
            ),
            evidence,
        )

        self.assertEqual(result.status, "violated")
        self.assertEqual(
            result.primary_blocker.code, "call_preserved_register_overclaim"
        )

    def test_external_call_omission_is_incomplete(self) -> None:
        evidence = _evidence(
            external_calls=(
                ExternalCallEvidenceV3(5, "call", CanonicalValueV3.of({})),
            )
        )

        result = check_parametric_scc_proposal_v3(_proposal(evidence), evidence)
        self.assertEqual(result.status, "incomplete")
        self.assertEqual(result.primary_blocker.code, "external_call_effect_missing")

    def test_external_call_binds_exact_profile_identity_and_transfer(self) -> None:
        profile = ExternalProfileV3.create(
            profile_id="kernel32:Example",
            profile_sha256="b" * 64,
            identity={"dll": "KERNEL32.dll", "symbol": "Example"},
            allowed_transfers=("call",),
            allowed_dispositions=("returns",),
            argument_words=0,
            memory_effect="none",
            world_effect="none",
            callback_effect="none",
            machine_contract={"abi_template": "pe32-stdcall-v1"},
        )
        evidence = _evidence(
            external_calls=(
                ExternalCallEvidenceV3(
                    5,
                    "call",
                    CanonicalValueV3.of(
                        {"dll": "KERNEL32.dll", "symbol": "Example"}
                    ),
                ),
            )
        )
        evidence = replace(
            evidence,
            external_profiles=(profile,),
            expected_dependencies=tuple(
                sorted(
                    (*evidence.expected_dependencies, RecordDependencyV3("external_profiles", profile.record_id))
                )
            ),
        )
        call = CallEffectV3(
            "call:5",
            "unit:a",
            5,
            "external_profile",
            (),
            profile.record_id,
            (),
            None,
            ("ebp", "ebx", "edi", "esi"),
        )

        result = check_parametric_scc_proposal_v3(
            _proposal(evidence, call_effects=(call,)), evidence
        )
        self.assertEqual(result.status, "complete")

    def test_recursive_scc_requires_checked_base_path(self) -> None:
        evidence = _evidence(recursive=True)

        missing = check_parametric_scc_proposal_v3(_proposal(evidence), evidence)
        submitted = check_parametric_scc_proposal_v3(
            _proposal(evidence, base_paths=("unit:a",)), evidence
        )
        self.assertEqual(missing.status, "incomplete")
        self.assertEqual(missing.primary_blocker.code, "recursive_scc_base_path_missing")
        self.assertEqual(submitted.status, "complete")

    def test_indirect_target_origins_exactly_replay_finite_target_set(self) -> None:
        expression_sha256 = "d" * 64
        unit = replace(
            _unit(),
            indirect_expressions=(
                IndirectExpressionEvidenceV3(
                    "exit:0",
                    None,
                    "indirect_jump",
                    {"op": "const", "value": 0x401000, "width": 32},
                    expression_sha256,
                ),
            ),
        )
        structural = StructuralTargetProposalV3(
            "exit:0",
            "unit:a",
            0x1000,
            None,
            "indirect_jump",
            "recovered",
            ("unit:b",),
            (),
            "e" * 64,
            (),
        )
        evidence = replace(
            _evidence(),
            units=(unit,),
            structural_targets=(structural,),
            checked_indirect_targets=(
                CheckedIndirectTargetEvidenceV3(
                    "exit:0",
                    (ValueOriginV3("static_code_target", "unit:b", 0),),
                    ("unit:b",),
                    (),
                    ("unit:a", "unit:b"),
                    (),
                ),
            ),
        )
        exit_row = ParametricIndirectExitV3(
            "exit:0",
            "unit:a",
            expression_sha256,
            "fact:target",
            ("unit:b",),
            (),
        )
        exact_fact = ValueFactV3(
            "fact:target",
            "finite",
            (ValueOriginV3("static_code_target", "unit:b", 0),),
        )
        complete = check_parametric_scc_proposal_v3(
            _proposal(
                evidence,
                facts=(*_facts(), exact_fact),
                indirect_exits=(exit_row,),
            ),
            evidence,
        )
        extra_fact = ValueFactV3(
            "fact:target",
            "finite",
            (
                ValueOriginV3("static_code_target", "unit:b", 0),
                ValueOriginV3("static_code_target", "unit:c", 0),
            ),
        )
        contradicted = check_parametric_scc_proposal_v3(
            _proposal(
                evidence,
                facts=(*_facts(), extra_fact),
                indirect_exits=(exit_row,),
            ),
            evidence,
        )

        self.assertEqual(complete.status, "complete")
        self.assertEqual(contradicted.status, "violated")
        self.assertEqual(
            contradicted.primary_blocker.code,
            "indirect_target_origin_contradiction",
        )

    def test_unknown_alias_kill_rejects_preservation(self) -> None:
        evidence = _evidence(
            kills=("alias:global",),
            memory_effects=(
                MemoryEffectEvidenceV3("unit:a", "alias:global", "unknown_kill"),
            ),
        )
        preserved = StaticMemoryEffectV3(
            "memory:global", "unit:a", "alias:global", "preserved", None, None
        )
        killed = StaticMemoryEffectV3(
            "memory:global", "unit:a", "alias:global", "unknown_kill", None, None
        )

        contradiction = check_parametric_scc_proposal_v3(
            _proposal(evidence, memory_effects=(preserved,)), evidence
        )
        complete = check_parametric_scc_proposal_v3(
            _proposal(evidence, memory_effects=(killed,)), evidence
        )
        self.assertEqual(contradiction.status, "violated")
        self.assertEqual(contradiction.primary_blocker.code, "unknown_alias_kill_contradiction")
        self.assertEqual(complete.status, "complete")

    def test_checked_memory_effect_omission_is_incomplete(self) -> None:
        evidence = _evidence(
            memory_effects=(
                MemoryEffectEvidenceV3("unit:a", "alias:read", "preserved"),
            )
        )

        result = check_parametric_scc_proposal_v3(_proposal(evidence), evidence)
        self.assertEqual(result.status, "incomplete")
        self.assertEqual(result.primary_blocker.code, "checked_memory_effect_unrepresented")

    def test_exact_esp_relative_stack_access_is_replayed(self) -> None:
        exact = StackAccessEvidenceV3("access:stack", "unit:a", "write", -8, 4)
        evidence = _evidence(stack_accesses=(exact,))
        submitted = StackAccessV3("access:stack", "unit:a", "write", -8, 4, None)
        complete = check_parametric_scc_proposal_v3(
            _proposal(evidence, stack_accesses=(submitted,)), evidence
        )
        missing = check_parametric_scc_proposal_v3(_proposal(evidence), evidence)
        self.assertEqual(complete.status, "complete")
        self.assertEqual(missing.status, "incomplete")
        self.assertEqual(missing.primary_blocker.code, "stack_access_unrepresented")

    def test_invented_nonreturn_classification_is_violated(self) -> None:
        evidence = _evidence()
        proposal = _proposal(evidence)
        proposal = ParametricSccProposalV3.create(
            **{
                **proposal.__dict__,
                "returns": (ReturnBehaviorV3("unit:a", True, True, 8, True),),
            }
        )

        result = check_parametric_scc_proposal_v3(proposal, evidence)
        self.assertEqual(result.status, "violated")
        self.assertEqual(result.primary_blocker.code, "nonreturn_behavior_contradiction")

    def test_value_budget_overflow_is_incomplete(self) -> None:
        evidence = _evidence()
        wide = ValueFactV3(
            "fact:wide",
            "finite",
            (
                ValueOriginV3("exact_bits", exact_bits=7),
                ValueOriginV3("exact_bits", exact_bits=8),
            ),
        )
        result = check_parametric_scc_proposal_v3(
            _proposal(evidence, value_budget=1, facts=(*_facts(), wide)), evidence
        )
        self.assertEqual(result.status, "incomplete")
        self.assertEqual(result.primary_blocker.code, "parametric_value_budget_exceeded")

    def test_stale_dependencies_are_violated(self) -> None:
        evidence = _evidence()
        result = check_parametric_scc_proposal_v3(
            _proposal(
                evidence,
                dependencies=(RecordDependencyV3("semantic_index", "unit:stale"),),
            ),
            evidence,
        )
        self.assertEqual(result.status, "violated")
        self.assertEqual(result.primary_blocker.code, "parametric_summary_dependencies_stale")

    def test_missing_proposal_is_localized_incomplete(self) -> None:
        evidence = _evidence()
        result = check_parametric_scc_proposal_v3(None, evidence)

        self.assertEqual(result.status, "incomplete")
        self.assertEqual(result.member_unit_ids, ("unit:a",))
        self.assertFalse(result.authorizing)
        self.assertEqual(result.value_facts, ())

    def test_scc_identity_is_root_independent_and_edge_sensitive(self) -> None:
        first = parametric_scc_id_v3(("unit:a", "unit:b"), (("unit:a", "unit:b"),))
        reordered = parametric_scc_id_v3(("unit:b", "unit:a"), (("unit:a", "unit:b"),))
        changed = parametric_scc_id_v3(("unit:a", "unit:b"), (("unit:b", "unit:a"),))

        self.assertEqual(first, reordered)
        self.assertNotEqual(first, changed)
        self.assertNotIn("root", first)


if __name__ == "__main__":
    unittest.main()

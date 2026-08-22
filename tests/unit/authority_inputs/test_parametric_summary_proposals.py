from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from spaghetti_extractor.artifacts.artifact_set import (
    ArtifactBindingV3,
    ArtifactSetWriterV3,
    ArtifactV3Error,
    CanonicalValueV3,
)
from spaghetti_extractor.artifacts.io import ArtifactSetReaderV3
from spaghetti_extractor.authority.exact_units import (
    EXACT_UNIT_CODEC_V3,
    ExactUnitV3,
)
from spaghetti_extractor.authority.catalog_call_contracts import (
    CATALOG_CALL_CONTRACTS_ARTIFACT_KIND_V3,
)
from spaghetti_extractor.authority.external_site_records import (
    EXTERNAL_PROFILE_ARTIFACT_KIND_V3,
    EXTERNAL_PROFILE_ISSUE_CODEC_V3,
    ExternalProfileIssueV3,
)
from spaghetti_extractor.authority.memory_records import (
    MEMORY_VERSIONS_ARTIFACT_KIND_V3,
)
from spaghetti_extractor.authority.parametric_summary_checker import (
    PARAMETRIC_SCC_SUMMARIES_PHASE_V3,
    _checked_memory_effects_v3,
)
from spaghetti_extractor.authority.parametric_summary_records import (
    PARAMETRIC_SCC_SUMMARY_CODEC_V3,
    PARAMETRIC_SUMMARY_PROPOSALS_ARTIFACT_KIND_V3,
    PARAMETRIC_SUMMARY_PROPOSAL_CODEC_V3,
    PE32_CALLEE_PRESERVED_REGISTERS_V3,
)
from spaghetti_extractor.authority.parametric_unit_facts import (
    PARAMETRIC_UNIT_FACTS_PHASE_V3,
    _checked_successor_rvas,
    _successor_rvas,
    derive_parametric_unit_fact_v3,
)
from spaghetti_extractor.authority.semantic_index import (
    SEMANTIC_INDEX_CODEC_V3,
    SEMANTIC_INDEX_PHASE_V3,
)
from spaghetti_extractor.authority.static_value_records import (
    PE32_STATIC_IMAGE_CODEC_V3,
    STATIC_VALUE_ORIGINS_ARTIFACT_KIND_V3,
    PE32StaticImageV3,
)
from spaghetti_extractor.authority.structural_targets import (
    STRUCTURAL_TARGETS_PHASE_V3,
)
from spaghetti_extractor.authority.transition_records import (
    TRANSITION_SUMMARY_CODEC_V3,
)
from spaghetti_extractor.authority.transition_summaries import (
    TRANSITION_SUMMARIES_PHASE_V3,
)
from spaghetti_extractor.authority_inputs.parametric_summary_proposals import (
    _memory_effects,
    generate_parametric_summary_proposals_v3,
)


PE_SHA256 = "a" * 64
BINDING = ArtifactBindingV3("binary", "pe32", "fixture.exe", PE_SHA256)


def _register(name: str) -> dict[str, object]:
    return {"op": "reg", "name": name, "width": 32}


def _unit(
    unit_id: str = "unit:return",
    rva: int = 0x1000,
    *,
    internal_call_target: int | None = None,
) -> dict[str, object]:
    external_events = (
        []
        if internal_call_target is None
        else [
            {
                "kind": "internal_call",
                "target_rva": internal_call_target,
                "return_rva": rva + 4,
                "register_inputs": {},
            }
        ]
    )
    return {
        "format": "spaghetti-extractor-machine-ir-v3",
        "record_kind": "unit",
        "id": unit_id,
        "status": "qualified",
        "source": {
            "original": {"rva_start": rva, "rva_end": rva + 4},
            "instruction_bytes_sha256": "b" * 64,
        },
        "expression_model": "spaghetti-extractor-static-semantic-ir-v1",
        "instructions": [
            {
                "mnemonic": "ret",
                "rva_start": rva,
                "rva_end": rva + 4,
                "size": 4,
            }
        ],
        "semantics": {
            "pre_state": {
                "registers": {"eax": _register("eax")},
                "flags": {},
                "memory": {},
            },
            "register_writes": [],
            "flag_writes": [],
            "memory_events": [],
            "external_events": external_events,
            "faults": [],
            "ordered_events": [],
            "edge_conditions": [],
            "outcome": {"kind": "return"},
            "stack_delta": {
                "status": "derived",
                "net_bytes": 4,
                "expression": {
                    "op": "add32",
                    "args": [
                        _register("esp"),
                        {"op": "const", "value": 4, "width": 32},
                    ],
                },
            },
            "counts": {
                "register_writes": 0,
                "flag_writes": 0,
                "memory_events": 0,
                "external_events": len(external_events),
                "faults": 0,
                "ordered_events": 0,
                "edge_conditions": 0,
            },
        },
        "control": {
            "kind": "return",
            "direct_targets": [],
            "has_indirect_target": False,
        },
    }


def _empty(path: Path, kind: str) -> Path:
    ArtifactSetWriterV3(artifact_kind=kind, bindings=(BINDING,)).write(path, ())
    return path


def _static_values(path: Path) -> Path:
    image = PE32StaticImageV3.create(
        image_base=0x400000,
        size_of_image=0x10000,
    )
    ArtifactSetWriterV3(
        artifact_kind=STATIC_VALUE_ORIGINS_ARTIFACT_KIND_V3,
        bindings=(BINDING,),
    ).write(
        path,
        (PE32_STATIC_IMAGE_CODEC_V3.write(image.record_id, image),),
    )
    return path


class ParametricSummaryProposalTests(unittest.TestCase):
    def test_external_tail_jump_is_a_terminal_internal_path(self) -> None:
        outcome = SimpleNamespace(
            source_kind="outcome",
            exact_record=CanonicalValueV3.of(
                {"kind": "external_jump", "dll": "kernel32.dll"}
            ),
        )

        self.assertEqual(
            _successor_rvas(SimpleNamespace(exits=(outcome,))), ()
        )

    def test_external_disposition_owns_compact_successors(self) -> None:
        transition = SimpleNamespace(
            exits=(
                SimpleNamespace(
                    source_kind="outcome",
                    exact_record=CanonicalValueV3.of(
                        {"kind": "fallthrough", "target_rva": 0x1010}
                    ),
                ),
            )
        )

        self.assertEqual(
            _checked_successor_rvas(
                SimpleNamespace(direct_target_rvas=()),
                transition,
                has_external_transfer=True,
            ),
            (),
        )
        self.assertEqual(
            _checked_successor_rvas(
                SimpleNamespace(direct_target_rvas=(0x1010,)),
                transition,
                has_external_transfer=True,
            ),
            (0x1010,),
        )

    def test_compact_unit_fact_rejects_cross_artifact_binding_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            exact_values = (
                ExactUnitV3.create(_unit(), pe_sha256=PE_SHA256),
                ExactUnitV3.create(
                    _unit("unit:other", 0x2000), pe_sha256=PE_SHA256
                ),
            )
            exact = root / "exact"
            ArtifactSetWriterV3(
                artifact_kind="exact-units-v3", bindings=(BINDING,)
            ).write(
                exact,
                tuple(
                    EXACT_UNIT_CODEC_V3.write(value.record_id, value)
                    for value in exact_values
                ),
            )
            semantic_path = SEMANTIC_INDEX_PHASE_V3.run(
                output_directory=root / "semantic",
                inputs={"exact_units": exact},
                bindings=(BINDING,),
            ).output_directory
            transition_path = TRANSITION_SUMMARIES_PHASE_V3.run(
                output_directory=root / "transitions",
                inputs={"exact_units": exact},
                bindings=(BINDING,),
            ).output_directory
            semantics = {
                record.record_id: SEMANTIC_INDEX_CODEC_V3.read(record).value
                for record in ArtifactSetReaderV3(semantic_path).iter_records()
            }
            transitions = {
                record.record_id: TRANSITION_SUMMARY_CODEC_V3.read(record).value
                for record in ArtifactSetReaderV3(transition_path).iter_records()
            }

            with self.assertRaises(ArtifactV3Error) as raised:
                derive_parametric_unit_fact_v3(
                    semantics["unit:return"],
                    transitions["unit:other"],
                )
            self.assertEqual(
                raised.exception.code, "parametric_unit_binding_contradiction"
            )

    def test_memory_alias_dependencies_do_not_export_foreign_unit_effects(
        self,
    ) -> None:
        units = {
            "unit:member": SimpleNamespace(
                transition_summary_id="summary:member",
                nonstack_accesses=(
                    SimpleNamespace(
                        access_id="access:member",
                        kind="write",
                        epoch_call_index=None,
                    ),
                ),
            )
        }
        graph = SimpleNamespace(
            record_id="memory:shared",
            transition_summary_ids=("summary:member", "summary:foreign"),
            access_versions=(
                SimpleNamespace(
                    access_id="access:member", component_id="alias:shared"
                ),
            ),
            alias_components=(SimpleNamespace(component_id="alias:shared"),),
            unknown_write_kills=(
                SimpleNamespace(
                    binding=SimpleNamespace(
                        unit=SimpleNamespace(unit_id="unit:foreign")
                    ),
                    access_id="access:foreign",
                    affected_scope="all_components",
                    affected_component_ids=(),
                ),
            ),
        )

        relevant, effects = _memory_effects(
            ("unit:member",), units, (graph,)
        )

        self.assertEqual(relevant, (graph,))
        self.assertEqual(len(effects), 1)
        self.assertEqual(effects[0].unit_id, "unit:member")
        self.assertEqual(effects[0].kind, "write")

        checked_effects, checked_kills, unversioned = (
            _checked_memory_effects_v3(
                member_set={"unit:member"},
                relevant_memories=(graph,),
                nonstack_accesses={
                    "access:member": ("unit:member", "write", None)
                },
            )
        )
        self.assertEqual(
            tuple(
                (row.unit_id, row.alias_component_id, row.kind)
                for row in checked_effects
            ),
            (("unit:member", "alias:shared", "write"),),
        )
        self.assertEqual(checked_kills, ())
        self.assertEqual(unversioned, ())

    def test_pre_call_read_does_not_claim_post_call_memory_preservation(
        self,
    ) -> None:
        graph = SimpleNamespace(
            record_id="memory:read",
            transition_summary_ids=("summary:member",),
            access_versions=(
                SimpleNamespace(
                    access_id="access:read", component_id="alias:shared"
                ),
            ),
            alias_components=(SimpleNamespace(component_id="alias:shared"),),
            unknown_write_kills=(),
        )
        units = {
            "unit:member": SimpleNamespace(
                transition_summary_id="summary:member",
                nonstack_accesses=(
                    SimpleNamespace(
                        access_id="access:read",
                        kind="read",
                        epoch_call_index=None,
                    ),
                ),
            )
        }

        _relevant, proposed = _memory_effects(
            ("unit:member",), units, (graph,)
        )
        checked, _kills, unversioned = _checked_memory_effects_v3(
            member_set={"unit:member"},
            relevant_memories=(graph,),
            nonstack_accesses={
                "access:read": ("unit:member", "read", None)
            },
        )

        self.assertEqual(proposed, ())
        self.assertEqual(checked, ())
        self.assertEqual(unversioned, ())

    def test_post_call_read_requires_memory_preservation(self) -> None:
        graph = SimpleNamespace(
            record_id="memory:read",
            transition_summary_ids=("summary:member",),
            access_versions=(
                SimpleNamespace(
                    access_id="access:read", component_id="alias:shared"
                ),
            ),
            alias_components=(SimpleNamespace(component_id="alias:shared"),),
            unknown_write_kills=(),
        )
        units = {
            "unit:member": SimpleNamespace(
                transition_summary_id="summary:member",
                nonstack_accesses=(
                    SimpleNamespace(
                        access_id="access:read",
                        kind="read",
                        epoch_call_index=3,
                    ),
                ),
            )
        }

        _relevant, proposed = _memory_effects(
            ("unit:member",), units, (graph,)
        )
        checked, _kills, unversioned = _checked_memory_effects_v3(
            member_set={"unit:member"},
            relevant_memories=(graph,),
            nonstack_accesses={
                "access:read": ("unit:member", "read", 3)
            },
        )

        self.assertEqual(
            tuple((row.alias_component_id, row.kind) for row in proposed),
            (("alias:shared", "preserved"),),
        )
        self.assertEqual(
            tuple((row.alias_component_id, row.kind) for row in checked),
            (("alias:shared", "preserved"),),
        )
        self.assertEqual(unversioned, ())

    def test_generated_proposal_is_replayed_to_complete_authority(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            exact_value = ExactUnitV3.create(_unit(), pe_sha256=PE_SHA256)
            exact = root / "exact"
            ArtifactSetWriterV3(
                artifact_kind="exact-units-v3", bindings=(BINDING,)
            ).write(
                exact,
                (EXACT_UNIT_CODEC_V3.write(exact_value.record_id, exact_value),),
            )
            semantic = SEMANTIC_INDEX_PHASE_V3.run(
                output_directory=root / "semantic",
                inputs={"exact_units": exact},
                bindings=(BINDING,),
            ).output_directory
            transitions = TRANSITION_SUMMARIES_PHASE_V3.run(
                output_directory=root / "transitions",
                inputs={"exact_units": exact},
                bindings=(BINDING,),
            ).output_directory
            unit_facts = PARAMETRIC_UNIT_FACTS_PHASE_V3.run(
                output_directory=root / "unit-facts",
                inputs={
                    "semantic_index": semantic,
                    "transition_summaries": transitions,
                },
                bindings=(BINDING,),
            ).output_directory
            target_hints = _empty(root / "target-hints", "target-hints-v3")
            structural = STRUCTURAL_TARGETS_PHASE_V3.run(
                output_directory=root / "structural",
                inputs={
                    "semantic_index": semantic,
                    "target_hints": target_hints,
                },
                bindings=(BINDING,),
            ).output_directory
            memory = _empty(root / "memory", MEMORY_VERSIONS_ARTIFACT_KIND_V3)
            profiles = root / "profiles"
            issue = ExternalProfileIssueV3.create(
                profile_id="unrelated-profile",
                profile_sha256="c" * 64,
                identity={
                    "kind": "import",
                    "dll": "fixture.dll",
                    "symbol": "Missing",
                    "ordinal": None,
                },
                status="incomplete",
                code="fixture_profile_incomplete",
                detail="unrelated incomplete profile must remain non-authorizing",
            )
            ArtifactSetWriterV3(
                artifact_kind=EXTERNAL_PROFILE_ARTIFACT_KIND_V3,
                bindings=(BINDING,),
            ).write(
                profiles,
                (EXTERNAL_PROFILE_ISSUE_CODEC_V3.write(issue.record_id, issue),),
            )
            static_values = _static_values(root / "static-values")
            catalog_calls = _empty(
                root / "catalog-calls", CATALOG_CALL_CONTRACTS_ARTIFACT_KIND_V3
            )
            call_boundaries = _empty(
                root / "call-boundaries", "call-boundary-contracts-v3"
            )
            proposals = root / "proposals"
            generate_parametric_summary_proposals_v3(
                unit_facts_path=unit_facts,
                memory_versions_path=memory,
                structural_targets_path=structural,
                external_profiles_path=profiles,
                static_value_origins_path=static_values,
                output_directory=proposals,
            )

            proposal_reader = ArtifactSetReaderV3(proposals)
            self.assertEqual(
                proposal_reader.manifest.artifact_kind,
                PARAMETRIC_SUMMARY_PROPOSALS_ARTIFACT_KIND_V3,
            )
            self.assertEqual(len(tuple(proposal_reader.iter_records())), 1)

            checked = PARAMETRIC_SCC_SUMMARIES_PHASE_V3.run(
                output_directory=root / "checked",
                inputs={
                    "external_profiles": profiles,
                    "catalog_call_contracts": catalog_calls,
                    "call_boundary_contracts": call_boundaries,
                    "memory_versions": memory,
                    "parametric_proposals": proposals,
                    "unit_facts": unit_facts,
                    "static_value_origins": static_values,
                    "structural_targets": structural,
                },
                bindings=(BINDING,),
            ).output_directory
            records = tuple(ArtifactSetReaderV3(checked).iter_records())
            self.assertEqual(len(records), 1)
            summary = PARAMETRIC_SCC_SUMMARY_CODEC_V3.read(records[0]).value
            self.assertEqual(summary.status, "complete")
            self.assertTrue(summary.authorizing)
            self.assertTrue(summary.covers_unit(exact_value.record_id))
            self.assertTrue(summary.preserves_register(exact_value.record_id, "eax"))

    def test_provider_proposes_leaf_call_preservation_for_independent_replay(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            caller = ExactUnitV3.create(
                _unit("unit:caller", 0x1000, internal_call_target=0x2000),
                pe_sha256=PE_SHA256,
            )
            callee = ExactUnitV3.create(
                _unit("unit:callee", 0x2000), pe_sha256=PE_SHA256
            )
            exact = root / "exact"
            ArtifactSetWriterV3(
                artifact_kind="exact-units-v3", bindings=(BINDING,)
            ).write(
                exact,
                tuple(
                    EXACT_UNIT_CODEC_V3.write(row.record_id, row)
                    for row in (caller, callee)
                ),
            )
            semantic = SEMANTIC_INDEX_PHASE_V3.run(
                output_directory=root / "semantic",
                inputs={"exact_units": exact},
                bindings=(BINDING,),
            ).output_directory
            transitions = TRANSITION_SUMMARIES_PHASE_V3.run(
                output_directory=root / "transitions",
                inputs={"exact_units": exact},
                bindings=(BINDING,),
            ).output_directory
            unit_facts = PARAMETRIC_UNIT_FACTS_PHASE_V3.run(
                output_directory=root / "unit-facts",
                inputs={
                    "semantic_index": semantic,
                    "transition_summaries": transitions,
                },
                bindings=(BINDING,),
            ).output_directory
            structural = STRUCTURAL_TARGETS_PHASE_V3.run(
                output_directory=root / "structural",
                inputs={
                    "semantic_index": semantic,
                    "target_hints": _empty(
                        root / "target-hints", "target-hints-v3"
                    ),
                },
                bindings=(BINDING,),
            ).output_directory
            memory = _empty(
                root / "memory", MEMORY_VERSIONS_ARTIFACT_KIND_V3
            )
            profiles = _empty(
                root / "profiles", EXTERNAL_PROFILE_ARTIFACT_KIND_V3
            )
            static_values = _static_values(root / "static-values")
            catalog_calls = _empty(
                root / "catalog-calls", CATALOG_CALL_CONTRACTS_ARTIFACT_KIND_V3
            )
            call_boundaries = _empty(
                root / "call-boundaries", "call-boundary-contracts-v3"
            )
            proposals = root / "proposals"
            generate_parametric_summary_proposals_v3(
                unit_facts_path=unit_facts,
                memory_versions_path=memory,
                structural_targets_path=structural,
                external_profiles_path=profiles,
                static_value_origins_path=static_values,
                output_directory=proposals,
            )

            proposed_calls = tuple(
                call
                for record in ArtifactSetReaderV3(proposals).iter_records()
                for call in PARAMETRIC_SUMMARY_PROPOSAL_CODEC_V3.read(
                    record
                ).value.call_effects
                if call.kind == "direct_internal"
            )
            self.assertEqual(len(proposed_calls), 1)
            self.assertEqual(
                proposed_calls[0].preserved_registers,
                PE32_CALLEE_PRESERVED_REGISTERS_V3,
            )

            checked = PARAMETRIC_SCC_SUMMARIES_PHASE_V3.run(
                output_directory=root / "checked",
                inputs={
                    "external_profiles": profiles,
                    "catalog_call_contracts": catalog_calls,
                    "call_boundary_contracts": call_boundaries,
                    "memory_versions": memory,
                    "parametric_proposals": proposals,
                    "unit_facts": unit_facts,
                    "static_value_origins": static_values,
                    "structural_targets": structural,
                },
                bindings=(BINDING,),
            ).output_directory
            checked_calls = tuple(
                call
                for record in ArtifactSetReaderV3(checked).iter_records()
                for call in PARAMETRIC_SCC_SUMMARY_CODEC_V3.read(
                    record
                ).value.call_effects
                if call.kind == "direct_internal"
            )
            self.assertEqual(len(checked_calls), 1)
            self.assertEqual(
                checked_calls[0].preserved_registers,
                PE32_CALLEE_PRESERVED_REGISTERS_V3,
            )


if __name__ == "__main__":
    unittest.main()

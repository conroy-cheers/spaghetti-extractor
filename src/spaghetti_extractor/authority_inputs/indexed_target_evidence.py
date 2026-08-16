"""Checked indexed-PE-table target evidence for analysis v3.

This adapter is intentionally narrower than the structural recovery pass.  It
re-reads the exact PE, binds the exact machine-IR and native-v3 projections,
and accepts only a 32-bit immutable table load whose selector is bounded by
every direct predecessor.  Structural proposals and older evidence are veto
inputs only: they can expose a contradiction, but can never supply a target.

The existing target-evaluation evidence schema has no indexed-table method.
Until the target-certificate checker grows that method, the checked table
certificate identity is carried by the required memory/fact identifiers and
the complete proof is retained in the adjacent report.  Consequently these
records remain fail-closed when consumed by the current certificate checker.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pefile

from ..authority._schema import mapping
from ..authority.semantic_index import (
    SEMANTIC_INDEX_ARTIFACT_KIND_V3,
    SEMANTIC_INDEX_CODEC_V3,
    IndirectExitOccurrenceV3,
    SemanticIndexRecordV3,
)
from ..authority.external_site_records import (
    EXTERNAL_PROFILE_ARTIFACT_KIND_V3,
    EXTERNAL_PROFILE_CODEC_V3,
    EXTERNAL_PROFILE_RECORD_V3_SCHEMA,
    ExternalProfileV3,
)
from ..authority.parametric_summary_records import (
    PARAMETRIC_SCC_SUMMARIES_ARTIFACT_KIND_V3,
    PARAMETRIC_SCC_SUMMARY_CODEC_V3,
    ParametricSccSummaryV3,
)
from ..authority.structural_targets import (
    STRUCTURAL_TARGETS_ARTIFACT_KIND_V3,
    STRUCTURAL_TARGET_UNIT_CODEC_V3,
    StructuralTargetProposalV3,
)
from ..authority.target_certificate_records import (
    TARGET_EVALUATION_EVIDENCE_ARTIFACT_KIND_V3,
    TARGET_EVALUATION_EVIDENCE_CODEC_V3,
    TargetEvaluationEvidenceV3,
    _PE_STATIC_MEMORY_RECORD_NOT_APPLICABLE_V3,
    _PARAMETRIC_MEMORY_RECORD_NOT_APPLICABLE_V3,
)
from ..authority.transition_records import (
    TRANSITION_SUMMARIES_ARTIFACT_KIND_V3,
    TRANSITION_SUMMARY_CODEC_V3,
    TransitionSummaryRecordV3,
)
from ..artifacts.artifact_set import (
    ArtifactBindingV3,
    ArtifactDependencyV3,
    ArtifactRecordV3,
    ArtifactSetWriterV3,
    CanonicalValueV3,
    canonical_json_bytes_v3,
    canonical_sha256_v3,
)
from ..artifacts.formats import (
    MACHINE_IR_FORMAT as MACHINE_IR_FORMAT_V2,
    TARGET_HINTS_ARTIFACT_KIND as TARGET_HINTS_ARTIFACT_KIND_V3,
)
from ..artifacts.io import (
    ArtifactInputReaderV3,
    open_artifact_reader_v3,
)


INDEXED_TARGET_EVIDENCE_REPORT_V3 = (
    "spaghetti-extractor-indexed-target-evidence-report-v3"
)
_IMAGE_SCN_MEM_EXECUTE = 0x20000000
_IMAGE_SCN_MEM_READ = 0x40000000
_IMAGE_SCN_MEM_WRITE = 0x80000000
_MAX_TABLE_ENTRIES = 4096
_MAX_GUARD_BACKTRACK_DEPTH = 32
_MAX_GUARD_BACKTRACK_PATHS = 128


from .indexed_target_analysis import (
    IndexedTargetEvidenceV3Error,
    _BoundProof,
    _ImportSlot,
    _Issue,
    _Section,
    _binary_binding,
    _condition_bound,
    _constant,
    _dependency,
    _manifest_machine_ir_sha256,
    _parse_pe,
    _read_exact_rva,
    _read_json,
    _read_machine_ir,
    _section_for_rva,
    _sha256_file,
    _substitute_summary_outputs,
    _table_shape,
)


def _artifact_index(reader: ArtifactInputReaderV3, codec: Any) -> dict[str, Any]:
    return {
        record.record_id: codec.read(record).value
        for record in reader.iter_records()
    }


def _target_hint(reader: ArtifactInputReaderV3 | None, exit_id: str) -> Mapping[str, Any] | None:
    if reader is None:
        return None
    try:
        record = reader.get_record(exit_id)
    except KeyError:
        return None
    value = record.value.to_value()
    return value if isinstance(value, Mapping) else None


def _manifest_recovery(manifest: Mapping[str, Any], exit_id: str) -> tuple[Mapping[str, Any] | None, _Issue | None]:
    control = manifest.get("control")
    if not isinstance(control, Mapping):
        return None, None
    rows = control.get("recovered_indirect_targets")
    if rows is None:
        return None, None
    if not isinstance(rows, list):
        return None, _Issue("violated", "machine_manifest_target_inventory_malformed", "recovered_indirect_targets is not an array")
    matches = [row for row in rows if isinstance(row, Mapping) and row.get("id") == exit_id]
    if len(matches) > 1:
        return None, _Issue("violated", "machine_manifest_target_inventory_ambiguous", "machine manifest repeats the exact indirect exit")
    return (matches[0], None) if matches else (None, None)


def _machine_direct_targets(unit: Mapping[str, Any]) -> tuple[int, ...] | None:
    control = unit.get("control")
    if not isinstance(control, Mapping):
        return None
    values = control.get("direct_targets")
    if not isinstance(values, list) or any(
        not isinstance(value, int) or isinstance(value, bool) for value in values
    ):
        return None
    return tuple(sorted(set(values)))


def _checked_direct_predecessors(
    *,
    target_rva: int,
    machine_units: Mapping[str, Mapping[str, Any]],
    semantics: Mapping[str, SemanticIndexRecordV3],
    summaries: Mapping[str, TransitionSummaryRecordV3],
) -> tuple[
    tuple[tuple[SemanticIndexRecordV3, TransitionSummaryRecordV3], ...],
    _Issue | None,
]:
    predecessors: list[tuple[SemanticIndexRecordV3, TransitionSummaryRecordV3]] = []
    for unit_id, candidate in semantics.items():
        if target_rva not in candidate.direct_target_rvas:
            continue
        raw = machine_units.get(unit_id)
        summary = summaries.get(unit_id)
        if raw is None or summary is None:
            return (), _Issue(
                "violated",
                "indexed_predecessor_binding_missing",
                f"predecessor {unit_id} is absent from an exact input",
            )
        control = raw.get("control")
        if not isinstance(control, Mapping) or control.get("kind") not in {
            "branch",
            "direct_jump",
            "fallthrough",
            "jump",
        }:
            continue
        direct_targets = _machine_direct_targets(raw)
        if direct_targets is None or tuple(candidate.direct_target_rvas) != direct_targets:
            return (), _Issue(
                "violated",
                "indexed_predecessor_binding_contradiction",
                f"predecessor {unit_id} control inventory disagrees",
            )
        if (
            canonical_sha256_v3(raw) != candidate.unit_ir_sha256
            or summary.unit_ir_sha256 != candidate.unit_ir_sha256
        ):
            return (), _Issue(
                "violated",
                "indexed_predecessor_binding_contradiction",
                f"predecessor {unit_id} exact projections disagree",
            )
        predecessors.append((candidate, summary))
    return tuple(sorted(predecessors, key=lambda row: row[0].record_id)), None


def _bound_through_predecessor_chain(
    *,
    condition: Any,
    selector: Any,
    predecessor: SemanticIndexRecordV3,
    summary: TransitionSummaryRecordV3,
    machine_units: Mapping[str, Mapping[str, Any]],
    semantics: Mapping[str, SemanticIndexRecordV3],
    summaries: Mapping[str, TransitionSummaryRecordV3],
    depth: int = 0,
    visited: frozenset[str] = frozenset(),
    path_budget: list[int] | None = None,
) -> tuple[_BoundProof | None, _Issue | None]:
    """Prove one selector bound by replaying a finite direct-control prefix.

    The edge condition is stated over the predecessor's post-state. Replacing
    register and flag outputs rewrites it over the predecessor's input state;
    repeating that operation walks back to the instruction that established
    the compare operands. Every incoming direct path must establish the same
    bound, so a join cannot silently discard an alternative.
    """

    if path_budget is None:
        path_budget = [_MAX_GUARD_BACKTRACK_PATHS]
    if path_budget[0] <= 0:
        return None, _Issue(
            "incomplete",
            "indexed_selector_guard_path_budget_exceeded",
            "selector-bound proof exceeds the checked direct-path budget",
        )
    path_budget[0] -= 1
    if depth > _MAX_GUARD_BACKTRACK_DEPTH:
        return None, _Issue(
            "incomplete",
            "indexed_selector_guard_depth_exceeded",
            "selector-bound proof exceeds the checked predecessor depth",
        )
    if predecessor.record_id in visited:
        return None, _Issue(
            "incomplete",
            "indexed_selector_guard_cycle",
            f"selector-bound proof reaches cycle at {predecessor.record_id}",
        )

    rewritten_condition = _substitute_summary_outputs(condition, summary)
    rewritten_selector = _substitute_summary_outputs(selector, summary)
    bound = _condition_bound(rewritten_condition, rewritten_selector)
    if bound is not None:
        return (
            _BoundProof(
                upper_exclusive=bound,
                support_unit_ids=(predecessor.record_id,),
                support_summary_ids=(summary.summary_id,),
            ),
            None,
        )

    upstream, issue = _checked_direct_predecessors(
        target_rva=predecessor.rva_start,
        machine_units=machine_units,
        semantics=semantics,
        summaries=summaries,
    )
    if issue is not None:
        return None, issue
    if not upstream:
        return None, _Issue(
            "incomplete",
            "indexed_selector_guard_unsupported",
            f"no checked predecessor chain proves a bound before {predecessor.record_id}",
        )

    proofs: list[_BoundProof] = []
    next_visited = visited | {predecessor.record_id}
    for upstream_unit, upstream_summary in upstream:
        proof, issue = _bound_through_predecessor_chain(
            condition=rewritten_condition,
            selector=rewritten_selector,
            predecessor=upstream_unit,
            summary=upstream_summary,
            machine_units=machine_units,
            semantics=semantics,
            summaries=summaries,
            depth=depth + 1,
            visited=next_visited,
            path_budget=path_budget,
        )
        if issue is not None:
            return None, issue
        assert proof is not None
        proofs.append(proof)
    bounds = {proof.upper_exclusive for proof in proofs}
    if len(bounds) != 1:
        return None, _Issue(
            "incomplete",
            "indexed_selector_guard_ambiguous",
            f"predecessors of {predecessor.record_id} prove different bounds",
        )
    return (
        _BoundProof(
            upper_exclusive=next(iter(bounds)),
            support_unit_ids=tuple(
                sorted(
                    {
                        predecessor.record_id,
                        *(unit_id for proof in proofs for unit_id in proof.support_unit_ids),
                    }
                )
            ),
            support_summary_ids=tuple(
                sorted(
                    {
                        summary.summary_id,
                        *(summary_id for proof in proofs for summary_id in proof.support_summary_ids),
                    }
                )
            ),
        ),
        None,
    )


def _relevant_write_issue(
    summaries: Iterable[TransitionSummaryRecordV3],
    relevant_unit_ids: set[str],
    *,
    image_base: int,
    table_rva: int,
    table_size: int,
) -> _Issue | None:
    table_start = image_base + table_rva
    table_end = table_start + table_size
    for summary in summaries:
        if summary.unit_id not in relevant_unit_ids:
            continue
        for access in summary.memory_accesses:
            if access.memory_kind not in {"write", "read_write"}:
                continue
            address = _constant(access.address.to_value())
            if address is None:
                return _Issue(
                    "incomplete",
                    "indexed_table_write_alias_unknown",
                    f"{summary.unit_id} has a write whose address cannot be proved disjoint",
                )
            if address < table_end and table_start < address + access.width_bytes:
                return _Issue(
                    "violated",
                    "indexed_table_write_overlap",
                    f"{summary.unit_id} writes the purported immutable table",
                )
    return None


def _absolute_dword_load(value: Any) -> int | None:
    if not isinstance(value, Mapping) or value.get("op") != "load":
        return None
    if value.get("width") != 4:
        return None
    return _constant(value.get("address"))


def _external_target_for_import(slot: _ImportSlot) -> CanonicalValueV3:
    return CanonicalValueV3.of(
        {
            "import": {
                "dll": slot.dll,
                "symbol": slot.symbol,
                "ordinal": slot.ordinal,
                "thunk_rva": slot.slot_rva,
            },
            "iat_slot_va": slot.slot_va,
        }
    )


def _static_target_inventory_issue(
    *,
    proposal: StructuralTargetProposalV3 | None,
    semantic: SemanticIndexRecordV3,
    occurrence: IndirectExitOccurrenceV3,
    target_unit_ids: tuple[str, ...],
    external_targets: tuple[CanonicalValueV3, ...],
) -> _Issue | None:
    if proposal is None:
        return _Issue(
            "violated",
            "static_target_structural_inventory_missing",
            "structural target inventory omits the exact indirect exit",
        )
    if (
        proposal.source_unit_id != semantic.record_id
        or proposal.source_rva != semantic.rva_start
        or proposal.source_event_index != occurrence.event_index
        or proposal.transfer_kind != occurrence.transfer_kind
    ):
        return _Issue(
            "violated",
            "static_target_structural_binding_contradiction",
            "structural target proposal is bound to another exit",
        )
    if proposal.status == "violated":
        return _Issue(
            "violated",
            "static_target_structural_proposal_violated",
            "structural target proposal reports contradictory evidence",
        )
    if proposal.status != "recovered":
        return None
    proposed_external = tuple(
        sorted(
            (_external_target_identity(row) for row in proposal.external_targets),
            key=lambda row: row.data,
        )
    )
    exact_external = tuple(
        sorted(
            (_external_target_identity(row) for row in external_targets),
            key=lambda row: row.data,
        )
    )
    if proposal.target_unit_ids != target_unit_ids or proposed_external != exact_external:
        return _Issue(
            "violated",
            "static_target_structural_inventory_contradiction",
            "recovered structural targets differ from exact static targets",
        )
    return None


def _static_value_proof_for_exit(
    *,
    occurrence: IndirectExitOccurrenceV3,
    semantic: SemanticIndexRecordV3,
    proposal: StructuralTargetProposalV3 | None,
    semantics: Mapping[str, SemanticIndexRecordV3],
    profiles: Mapping[str, ExternalProfileV3],
    prior: TargetEvaluationEvidenceV3 | None,
    image_base: int,
    sections: tuple[_Section, ...],
    imports: tuple[_ImportSlot, ...],
) -> tuple[TargetEvaluationEvidenceV3 | None, dict[str, Any] | None]:
    """Prove exact code VAs and loader-bound IAT slot loads.

    The import case intentionally does not inspect the on-disk thunk value.
    Its value is supplied by the PE loader; the checked fact is the slot's
    unique import identity under the declared launch/IAT assumption.
    """

    expression = occurrence.target_expression.to_value()
    base_report: dict[str, Any] = {
        "exit_id": occurrence.exit_id,
        "source_unit_id": semantic.record_id,
        "source_rva": semantic.rva_start,
        "source_event_index": occurrence.event_index,
        "transfer_kind": occurrence.transfer_kind,
        "target_expression_sha256": canonical_sha256_v3(expression),
    }

    def failed(issue: _Issue) -> tuple[None, dict[str, Any]]:
        return None, {
            **base_report,
            "status": issue.status,
            "authorizing": False,
            "issue": issue.to_payload(),
        }

    variant: str
    value_va: int
    target_unit_ids: tuple[str, ...]
    external_targets: tuple[CanonicalValueV3, ...]
    profile_id: str | None = None
    import_slot_rva: int | None = None
    import_identity: dict[str, Any] | None = None

    exact_constant = _constant(expression)
    if exact_constant is not None:
        variant = "static_code_target"
        value_va = exact_constant
        if value_va < image_base:
            return failed(
                _Issue(
                    "incomplete",
                    "static_code_target_outside_image",
                    "constant target is below the PE image base",
                )
            )
        target_rva = value_va - image_base
        section = _section_for_rva(sections, target_rva)
        if section is None or not section.executable:
            return failed(
                _Issue(
                    "incomplete",
                    "static_code_target_not_executable",
                    "constant target does not resolve to executable PE bytes",
                )
            )
        matches = tuple(
            sorted(
                row.record_id
                for row in semantics.values()
                if row.rva_start == target_rva
            )
        )
        if len(matches) != 1:
            return failed(
                _Issue(
                    "violated" if matches else "incomplete",
                    (
                        "static_code_target_ambiguous"
                        if matches
                        else "static_code_target_unit_missing"
                    ),
                    f"constant target resolves to {len(matches)} semantic units",
                )
            )
        target_unit_ids = matches
        external_targets = ()
    else:
        slot_va = _absolute_dword_load(expression)
        if slot_va is None:
            return None, None
        matching_slots = tuple(row for row in imports if row.slot_va == slot_va)
        if not matching_slots:
            return None, None
        if len(matching_slots) != 1:
            return failed(
                _Issue(
                    "violated",
                    "static_import_slot_ambiguous",
                    "absolute load resolves to multiple PE import slots",
                )
            )
        slot = matching_slots[0]
        variant = "import_slot"
        value_va = slot.slot_va
        import_slot_rva = slot.slot_rva
        import_identity = {
            "kind": "import",
            "dll": slot.dll,
            "symbol": slot.symbol,
            "ordinal": slot.ordinal,
        }
        target = _external_target_for_import(slot)
        transfer = (
            "jump" if occurrence.transfer_kind == "indirect_jump" else "call"
        )
        matching_profiles = tuple(
            sorted(
                (
                    row
                    for row in profiles.values()
                    if transfer in row.allowed_transfers
                    and _profile_matches_external_target(row, target)
                ),
                key=lambda row: row.record_id,
            )
        )
        if len(matching_profiles) != 1:
            return failed(
                _Issue(
                    "violated" if len(matching_profiles) > 1 else "incomplete",
                    (
                        "static_import_profile_ambiguous"
                        if len(matching_profiles) > 1
                        else "static_import_profile_missing"
                    ),
                    f"PE import slot resolves to {len(matching_profiles)} external profiles",
                )
            )
        profile_id = matching_profiles[0].record_id
        target_unit_ids = ()
        external_targets = (target,)

    inventory_issue = _static_target_inventory_issue(
        proposal=proposal,
        semantic=semantic,
        occurrence=occurrence,
        target_unit_ids=target_unit_ids,
        external_targets=external_targets,
    )
    if inventory_issue is not None:
        return failed(inventory_issue)
    if prior is not None and (
        prior.source_unit_id != semantic.record_id
        or prior.source_rva != semantic.rva_start
        or prior.source_event_index != occurrence.event_index
        or prior.transfer_kind != occurrence.transfer_kind
        or prior.target_expression_sha256 != canonical_sha256_v3(expression)
        or prior.target_unit_ids != target_unit_ids
        or tuple(
            sorted(
                (_external_target_identity(row) for row in prior.external_targets),
                key=lambda row: row.data,
            )
        )
        != tuple(
            sorted(
                (_external_target_identity(row) for row in external_targets),
                key=lambda row: row.data,
            )
        )
    ):
        return failed(
            _Issue(
                "violated",
                "static_target_prior_evidence_contradiction",
                "prior target evidence differs from the exact static value proof",
            )
        )

    external_hash = (
        None
        if not external_targets
        else canonical_sha256_v3(external_targets[0].to_value())
    )
    certificate = {
        "kind": "checked-pe-static-value-v3",
        "variant": variant,
        "exit_id": occurrence.exit_id,
        "source_unit_id": semantic.record_id,
        "source_rva": semantic.rva_start,
        "source_event_index": occurrence.event_index,
        "transfer_kind": occurrence.transfer_kind,
        "target_expression_sha256": canonical_sha256_v3(expression),
        "image_base": image_base,
        "value_va": value_va,
        "target_unit_ids": list(target_unit_ids),
        "external_profile_record_id": profile_id,
        "external_target_sha256": external_hash,
        "import_slot_rva": import_slot_rva,
        "import_identity": import_identity,
    }
    evidence = TargetEvaluationEvidenceV3.create(
        record_id=occurrence.exit_id,
        source_unit_id=semantic.record_id,
        source_rva=semantic.rva_start,
        source_event_index=occurrence.event_index,
        transfer_kind=occurrence.transfer_kind,
        target_expression=expression,
        evaluation_method="checked_pe_static_value",
        memory_record_id=_PE_STATIC_MEMORY_RECORD_NOT_APPLICABLE_V3,
        inductive_fact_id=None,
        target_unit_ids=target_unit_ids,
        external_targets=(row.to_value() for row in external_targets),
        evaluation_certificate=certificate,
    )
    return evidence, {
        **base_report,
        "status": "complete",
        "authorizing": False,
        "method": "checked_pe_static_value",
        "variant": variant,
        "target_unit_ids": list(target_unit_ids),
        "external_targets": [row.to_value() for row in external_targets],
        "external_profile_record_id": profile_id,
        "evidence_sha256": evidence.evidence_sha256,
        "note": "checked provider evidence; target authority rechecks the compact binding",
    }


def _proof_for_exit(
    *,
    occurrence: IndirectExitOccurrenceV3,
    semantic: SemanticIndexRecordV3,
    proposal: StructuralTargetProposalV3 | None,
    machine_units: Mapping[str, Mapping[str, Any]],
    semantics: Mapping[str, SemanticIndexRecordV3],
    summaries: Mapping[str, TransitionSummaryRecordV3],
    hint: Mapping[str, Any] | None,
    prior: TargetEvaluationEvidenceV3 | None,
    manifest_recovery: Mapping[str, Any] | None,
    image_data: bytes,
    image_base: int,
    sections: tuple[_Section, ...],
    imports: tuple[_ImportSlot, ...],
    profiles: Mapping[str, ExternalProfileV3],
) -> tuple[TargetEvaluationEvidenceV3 | None, dict[str, Any]]:
    expression = occurrence.target_expression.to_value()
    base_report: dict[str, Any] = {
        "exit_id": occurrence.exit_id,
        "source_unit_id": semantic.record_id,
        "source_rva": semantic.rva_start,
        "source_event_index": occurrence.event_index,
        "transfer_kind": occurrence.transfer_kind,
        "target_expression_sha256": canonical_sha256_v3(expression),
    }

    def fail(status: str, code: str, detail: str) -> tuple[None, dict[str, Any]]:
        return None, {
            **base_report,
            "status": status,
            "authorizing": False,
            "issue": _Issue(status, code, detail).to_payload(),
        }

    static_evidence, static_report = _static_value_proof_for_exit(
        occurrence=occurrence,
        semantic=semantic,
        proposal=proposal,
        semantics=semantics,
        profiles=profiles,
        prior=prior,
        image_base=image_base,
        sections=sections,
        imports=imports,
    )
    if static_report is not None:
        return static_evidence, static_report

    shape = _table_shape(expression)
    if shape is None:
        return fail(
            "incomplete",
            "indexed_target_expression_unsupported",
            "target is not a checked 32-bit base + selector * 4 PE load",
        )
    if not image_base <= shape.table_va < image_base + (1 << 32):
        return fail("incomplete", "indexed_table_base_outside_image", "table base is not an in-image PE32 VA")
    table_rva = shape.table_va - image_base
    section = _section_for_rva(sections, table_rva)
    if section is None:
        return fail("incomplete", "indexed_table_section_missing", "table base does not resolve to one PE section")
    if not section.readable:
        return fail("incomplete", "indexed_table_section_unreadable", "table section is not readable")
    if section.writable:
        return fail("incomplete", "indexed_table_section_mutable", "table section is writable")

    source_summary = summaries.get(semantic.record_id)
    source_unit = machine_units.get(semantic.record_id)
    if source_summary is None or source_unit is None:
        return fail("violated", "indexed_source_binding_missing", "source unit is absent from an exact input")
    if source_summary.status != "complete":
        return fail("incomplete", "indexed_source_semantics_incomplete", "source transition summary is incomplete")
    if source_summary.unit_ir_sha256 != semantic.unit_ir_sha256 or canonical_sha256_v3(source_unit) != semantic.unit_ir_sha256:
        return fail("violated", "indexed_source_binding_contradiction", "machine IR, semantic index, and transition summary disagree")

    predecessors, predecessor_issue = _checked_direct_predecessors(
        target_rva=semantic.rva_start,
        machine_units=machine_units,
        semantics=semantics,
        summaries=summaries,
    )
    if predecessor_issue is not None:
        return fail(
            predecessor_issue.status,
            predecessor_issue.code,
            predecessor_issue.detail,
        )
    if not predecessors:
        return fail("incomplete", "indexed_selector_predecessor_missing", "dispatch has no checked direct predecessor")

    bounds: set[int] = set()
    predecessor_rows: list[dict[str, Any]] = []
    for predecessor, summary in sorted(predecessors, key=lambda row: row[0].record_id):
        matching_guards = []
        for guard in summary.guards:
            row = guard.exact_record.to_value()
            if not isinstance(row, Mapping) or row.get("target_rva") != semantic.rva_start:
                continue
            matching_guards.append(row)
        if len(matching_guards) != 1:
            return fail(
                "incomplete",
                "indexed_selector_guard_coverage_missing",
                f"predecessor {predecessor.record_id} does not have one exact guard for the dispatch edge",
            )
        condition = matching_guards[0].get("condition")
        proof, issue = _bound_through_predecessor_chain(
            condition=condition,
            selector=shape.selector,
            predecessor=predecessor,
            summary=summary,
            machine_units=machine_units,
            semantics=semantics,
            summaries=summaries,
        )
        if issue is not None:
            return fail(
                issue.status,
                issue.code,
                issue.detail,
            )
        assert proof is not None
        bound = proof.upper_exclusive
        bounds.add(bound)
        predecessor_rows.append(
            {
                "source_unit_id": predecessor.record_id,
                "guard_sha256": canonical_sha256_v3(matching_guards[0]),
                "upper_exclusive": bound,
                "support_unit_ids": list(proof.support_unit_ids),
                "support_summary_ids": list(proof.support_summary_ids),
            }
        )
    if len(bounds) != 1:
        return fail("incomplete", "indexed_selector_guard_ambiguous", "direct predecessors prove different selector bounds")
    entry_count = next(iter(bounds))
    table_size = entry_count * 4
    if not section.contains_raw(table_rva, table_size):
        return fail("incomplete", "indexed_table_span_out_of_range", "bounded table does not fit exact raw PE bytes")
    table_bytes = _read_exact_rva(image_data, section, table_rva, table_size)
    if table_bytes is None or len(table_bytes) != table_size:
        return fail("violated", "indexed_table_bytes_unreadable", "exact PE table bytes are truncated or corrupt")
    table_sha256 = hashlib.sha256(table_bytes).hexdigest()

    expected_table_sha256 = None
    if manifest_recovery is not None:
        raw_table = manifest_recovery.get("table")
        if isinstance(raw_table, Mapping):
            raw_sha = raw_table.get("bytes_sha256", raw_table.get("sha256"))
            if isinstance(raw_sha, str):
                expected_table_sha256 = raw_sha
        direct_sha = manifest_recovery.get("table_sha256")
        if isinstance(direct_sha, str):
            if expected_table_sha256 is not None and direct_sha != expected_table_sha256:
                return fail("violated", "indexed_table_sha256_proposal_contradiction", "machine manifest carries two different table hashes")
            expected_table_sha256 = direct_sha
    if expected_table_sha256 is not None and expected_table_sha256 != table_sha256:
        return fail("violated", "indexed_table_sha256_contradiction", "exact PE bytes differ from the bound table hash")

    relevant_ids = {
        semantic.record_id,
        *(
            unit_id
            for predecessor_row in predecessor_rows
            for unit_id in predecessor_row["support_unit_ids"]
        ),
    }
    write_issue = _relevant_write_issue(
        summaries.values(),
        relevant_ids,
        image_base=image_base,
        table_rva=table_rva,
        table_size=table_size,
    )
    if write_issue is not None:
        return fail(write_issue.status, write_issue.code, write_issue.detail)

    unit_by_rva: dict[int, list[str]] = {}
    for target in semantics.values():
        unit_by_rva.setdefault(target.rva_start, []).append(target.record_id)
    target_unit_ids: set[str] = set()
    entries: list[dict[str, Any]] = []
    for index in range(entry_count):
        target_va = int.from_bytes(table_bytes[index * 4 : index * 4 + 4], "little")
        if not image_base <= target_va < image_base + (1 << 32):
            return fail("incomplete", "indexed_table_target_out_of_range", f"table entry {index} is not an in-image PE32 VA")
        target_rva = target_va - image_base
        target_section = _section_for_rva(sections, target_rva)
        if target_section is None or not target_section.executable:
            return fail("incomplete", "indexed_table_target_not_executable", f"table entry {index} does not resolve to executable PE bytes")
        target_ids = unit_by_rva.get(target_rva, [])
        if len(target_ids) != 1:
            return fail(
                "violated" if len(target_ids) > 1 else "incomplete",
                "indexed_table_target_ambiguous" if len(target_ids) > 1 else "indexed_table_target_unit_missing",
                f"table entry {index} resolves to {len(target_ids)} exact structural units",
            )
        target_id = target_ids[0]
        target_unit_ids.add(target_id)
        entries.append(
            {
                "index": index,
                "entry_rva": table_rva + index * 4,
                "target_rva": target_rva,
                "target_unit_id": target_id,
            }
        )
    ordered_targets = tuple(sorted(target_unit_ids))

    if proposal is None:
        return fail("violated", "indexed_structural_proposal_missing", "structural target inventory omits the exact exit")
    if (
        proposal.source_unit_id != semantic.record_id
        or proposal.source_rva != semantic.rva_start
        or proposal.source_event_index != occurrence.event_index
        or proposal.transfer_kind != occurrence.transfer_kind
    ):
        return fail("violated", "indexed_structural_binding_contradiction", "structural proposal is bound to another exit")
    if proposal.status == "violated":
        return fail("violated", "indexed_structural_proposal_violated", "structural proposal reports contradictory evidence")
    if proposal.status == "recovered" and (
        proposal.target_unit_ids != ordered_targets or proposal.external_targets
    ):
        return fail("violated", "indexed_structural_inventory_contradiction", "structural proposal differs from exact table targets")

    if hint is not None and hint.get("status") == "recovered":
        hinted = hint.get("target_unit_ids")
        if not isinstance(hinted, list) or tuple(sorted(set(hinted))) != ordered_targets:
            return fail("violated", "indexed_target_hint_contradiction", "recovered target hint differs from exact table targets")
    if prior is not None:
        if (
            prior.source_unit_id != semantic.record_id
            or prior.source_rva != semantic.rva_start
            or prior.source_event_index != occurrence.event_index
            or prior.transfer_kind != occurrence.transfer_kind
            or prior.target_expression_sha256 != canonical_sha256_v3(expression)
            or prior.target_unit_ids != ordered_targets
            or prior.external_targets
        ):
            return fail("violated", "indexed_prior_evidence_contradiction", "current target evidence differs from exact indexed-table proof")

    proof_payload = {
        **base_report,
        "image_base": image_base,
        "table_rva": table_rva,
        "entry_width": 4,
        "entry_count": entry_count,
        "table_sha256": table_sha256,
        "table_section": section.name,
        "selector": shape.selector,
        "selector_sha256": canonical_sha256_v3(shape.selector),
        "predecessors": predecessor_rows,
        "entries": entries,
        "target_unit_ids": list(ordered_targets),
    }
    evaluation_certificate = {
        "kind": "checked-indexed-pe-table-v3",
        "exit_id": occurrence.exit_id,
        "source_unit_id": semantic.record_id,
        "source_rva": semantic.rva_start,
        "source_event_index": occurrence.event_index,
        "transfer_kind": occurrence.transfer_kind,
        "target_expression_sha256": canonical_sha256_v3(expression),
        "image_base": image_base,
        "table_rva": table_rva,
        "entry_width": 4,
        "entry_count": entry_count,
        "table_sha256": table_sha256,
        "selector_sha256": canonical_sha256_v3(shape.selector),
        "predecessors": predecessor_rows,
        "entries": entries,
        "target_unit_ids": list(ordered_targets),
    }
    proof_sha256 = canonical_sha256_v3(evaluation_certificate)
    evidence = TargetEvaluationEvidenceV3.create(
        record_id=occurrence.exit_id,
        source_unit_id=semantic.record_id,
        source_rva=semantic.rva_start,
        source_event_index=occurrence.event_index,
        transfer_kind=occurrence.transfer_kind,
        target_expression=expression,
        evaluation_method="checked_indexed_pe_table",
        memory_record_id=f"checked-indexed-pe-table:{proof_sha256}",
        inductive_fact_id=None,
        target_unit_ids=ordered_targets,
        evaluation_certificate=evaluation_certificate,
    )
    return evidence, {
        **proof_payload,
        "status": "complete",
        "authorizing": False,
        "evidence_sha256": evidence.evidence_sha256,
        "note": "checked provider evidence; the target-certificate phase rechecks its exact semantic bindings",
    }


def _external_target_identity(value: CanonicalValueV3) -> CanonicalValueV3:
    target = mapping(value.to_value(), "parametric external target")
    imported = target.get("import")
    source = imported if isinstance(imported, Mapping) else target
    dll = source.get("dll")
    symbol = source.get("symbol")
    ordinal = source.get("ordinal")
    if isinstance(dll, str) and dll and (
        (isinstance(symbol, str) and bool(symbol))
        != (isinstance(ordinal, int) and not isinstance(ordinal, bool))
    ):
        return CanonicalValueV3.of(
            {
                "kind": "import",
                "dll": dll.lower(),
                "symbol": symbol if isinstance(symbol, str) and symbol else None,
                "ordinal": (
                    ordinal
                    if isinstance(ordinal, int) and not isinstance(ordinal, bool)
                    else None
                ),
            }
        )
    protocol = source.get("external_protocol")
    if isinstance(protocol, Mapping) and protocol:
        return CanonicalValueV3.of(
            {"kind": "protocol", "protocol": dict(protocol)}
        )
    return CanonicalValueV3.of({})


def _profile_matches_external_target(
    profile: ExternalProfileV3, target: CanonicalValueV3
) -> bool:
    exact = mapping(
        _external_target_identity(target).to_value(),
        "normalized external target",
    )
    expected = mapping(profile.identity.to_value(), "external profile identity")
    return all(exact.get(key) == value for key, value in expected.items())


def _external_target_for_profile(
    profile: ExternalProfileV3,
) -> CanonicalValueV3 | None:
    identity = mapping(profile.identity.to_value(), "external profile identity")
    if identity.get("kind") == "import":
        dll = identity.get("dll")
        symbol = identity.get("symbol")
        ordinal = identity.get("ordinal")
        if not isinstance(dll, str) or not dll:
            return None
        if (isinstance(symbol, str) and bool(symbol)) == (
            isinstance(ordinal, int) and not isinstance(ordinal, bool)
        ):
            return None
        return CanonicalValueV3.of(
            {
                "import": {
                    "dll": dll.lower(),
                    "symbol": symbol if isinstance(symbol, str) else None,
                    "ordinal": (
                        ordinal
                        if isinstance(ordinal, int) and not isinstance(ordinal, bool)
                        else None
                    ),
                }
            }
        )
    if identity.get("kind") == "protocol" and isinstance(
        identity.get("protocol"), Mapping
    ):
        return CanonicalValueV3.of(
            {"external_protocol": dict(identity["protocol"])}
        )
    return None


def _parametric_evidence_for_exit(
    *,
    occurrence: IndirectExitOccurrenceV3,
    semantic: SemanticIndexRecordV3,
    proposal: StructuralTargetProposalV3 | None,
    summary: ParametricSccSummaryV3 | None,
    profiles: Mapping[str, ExternalProfileV3],
) -> tuple[TargetEvaluationEvidenceV3 | None, dict[str, Any] | None]:
    if summary is None or summary.status != "complete" or not summary.authorizing:
        return None, None
    exit_record = summary.indirect_exit(occurrence.exit_id)
    if exit_record is None:
        return None, None
    fact = summary.value_fact(exit_record.value_fact_id)
    if fact is None or fact.lattice != "finite":
        return None, None
    if (
        exit_record.source_unit_id != semantic.record_id
        or exit_record.expression_sha256
        != canonical_sha256_v3(occurrence.target_expression.to_value())
    ):
        return None, None

    profile_targets: list[tuple[str, CanonicalValueV3]] = []
    for profile_id in exit_record.external_profile_record_ids:
        profile = profiles.get(profile_id)
        target = None if profile is None else _external_target_for_profile(profile)
        if target is None:
            return None, None
        profile_targets.append((profile_id, target))
    profile_targets.sort(key=lambda row: row[0])
    canonical_external_targets = tuple(
        sorted({target for _profile_id, target in profile_targets}, key=lambda row: row.data)
    )
    if len(canonical_external_targets) != len(
        exit_record.external_profile_record_ids
    ):
        return None, None

    if proposal is not None and proposal.status == "recovered":
        proposed_external = tuple(
            sorted(
                (_external_target_identity(row) for row in proposal.external_targets),
                key=lambda row: row.data,
            )
        )
        checked_external = tuple(
            sorted(
                (_external_target_identity(row) for row in canonical_external_targets),
                key=lambda row: row.data,
            )
        )
        if (
            exit_record.target_unit_ids != proposal.target_unit_ids
            or checked_external != proposed_external
        ):
            return None, None

    external_bindings: list[dict[str, str]] = []
    for profile_id, target in profile_targets:
        if not _profile_matches_external_target(profiles[profile_id], target):
            return None, None
        external_bindings.append(
            {
                "external_profile_record_id": profile_id,
                "external_target_sha256": canonical_sha256_v3(
                    target.to_value()
                ),
            }
        )
    external_bindings.sort(
        key=lambda row: (
            row["external_profile_record_id"],
            row["external_target_sha256"],
        )
    )
    certificate = {
        "kind": "checked-parametric-target-fact-v3",
        "summary_record_id": summary.record_id,
        "exit_id": occurrence.exit_id,
        "source_unit_id": semantic.record_id,
        "source_rva": semantic.rva_start,
        "source_event_index": occurrence.event_index,
        "transfer_kind": occurrence.transfer_kind,
        "target_expression_sha256": canonical_sha256_v3(
            occurrence.target_expression.to_value()
        ),
        "value_fact_id": fact.fact_id,
        "external_target_bindings": external_bindings,
    }
    evidence = TargetEvaluationEvidenceV3.create(
        record_id=occurrence.exit_id,
        source_unit_id=semantic.record_id,
        source_rva=semantic.rva_start,
        source_event_index=occurrence.event_index,
        transfer_kind=occurrence.transfer_kind,
        target_expression=occurrence.target_expression.to_value(),
        evaluation_method="checked_parametric_summary",
        memory_record_id=_PARAMETRIC_MEMORY_RECORD_NOT_APPLICABLE_V3,
        inductive_fact_id=None,
        target_unit_ids=exit_record.target_unit_ids,
        external_targets=(
            row.to_value() for row in canonical_external_targets
        ),
        evaluation_certificate=certificate,
    )
    return evidence, {
        "exit_id": occurrence.exit_id,
        "source_unit_id": semantic.record_id,
        "status": "complete",
        "authorizing": False,
        "method": "checked_parametric_summary",
        "summary_record_id": summary.record_id,
        "value_fact_id": fact.fact_id,
        "target_unit_ids": list(exit_record.target_unit_ids),
        "external_targets": [
            target.to_value() for target in canonical_external_targets
        ],
        "evidence_sha256": evidence.evidence_sha256,
        "note": "checked summary evidence; target authority independently replays the fact",
    }


def generate_indexed_target_evidence_v3(
    *,
    binary_path: Path,
    machine_ir_path: Path,
    machine_ir_manifest_path: Path,
    semantic_index_path: Path,
    transition_summaries_path: Path,
    structural_targets_path: Path,
    output_directory: Path,
    parametric_summaries_path: Path | None = None,
    external_profiles_path: Path | None = None,
    target_hints_path: Path | None = None,
    target_evidence_path: Path | None = None,
) -> dict[str, Any]:
    """Generate deterministic checked evidence and a per-exit diagnostic report."""

    semantic_reader = open_artifact_reader_v3(semantic_index_path)
    transition_reader = open_artifact_reader_v3(transition_summaries_path)
    structural_reader = open_artifact_reader_v3(structural_targets_path)
    hints_reader = None if target_hints_path is None else open_artifact_reader_v3(target_hints_path)
    prior_reader = None if target_evidence_path is None else open_artifact_reader_v3(target_evidence_path)
    parametric_reader = (
        None
        if parametric_summaries_path is None
        else open_artifact_reader_v3(parametric_summaries_path)
    )
    profile_reader = (
        None
        if external_profiles_path is None
        else open_artifact_reader_v3(external_profiles_path)
    )
    readers = {
        "semantic_index": semantic_reader,
        "transition_summaries": transition_reader,
        "structural_targets": structural_reader,
    }
    if hints_reader is not None:
        readers["target_hints"] = hints_reader
    if prior_reader is not None:
        readers["target_evidence"] = prior_reader
    if parametric_reader is not None:
        readers["parametric_summaries"] = parametric_reader
    if profile_reader is not None:
        readers["external_profiles"] = profile_reader

    global_issues: list[_Issue] = []
    expected_kinds = {
        "semantic_index": SEMANTIC_INDEX_ARTIFACT_KIND_V3,
        "transition_summaries": TRANSITION_SUMMARIES_ARTIFACT_KIND_V3,
        "structural_targets": STRUCTURAL_TARGETS_ARTIFACT_KIND_V3,
        "target_hints": TARGET_HINTS_ARTIFACT_KIND_V3,
        "target_evidence": TARGET_EVALUATION_EVIDENCE_ARTIFACT_KIND_V3,
        "parametric_summaries": PARAMETRIC_SCC_SUMMARIES_ARTIFACT_KIND_V3,
        "external_profiles": EXTERNAL_PROFILE_ARTIFACT_KIND_V3,
    }
    bindings: dict[str, ArtifactBindingV3] = {}
    for name, reader in readers.items():
        if reader.manifest.artifact_kind != expected_kinds[name]:
            global_issues.append(_Issue("violated", "indexed_input_kind_contradiction", f"{name} has kind {reader.manifest.artifact_kind!r}"))
        try:
            bindings[name] = _binary_binding(reader, name)
        except IndexedTargetEvidenceV3Error as exc:
            global_issues.append(_Issue("violated", "indexed_binary_binding_missing", str(exc)))
        if reader.manifest.status == "violated":
            global_issues.append(_Issue("violated", "indexed_input_artifact_violated", f"{name} status is violated"))
        elif reader.manifest.status != "complete":
            global_issues.append(_Issue("incomplete", "indexed_input_artifact_incomplete", f"{name} status is {reader.manifest.status}"))
    unique_bindings = set(bindings.values())
    if len(unique_bindings) != 1:
        global_issues.append(_Issue("violated", "indexed_binary_binding_contradiction", "v3 inputs do not share one exact PE binding"))
    output_binding = bindings.get("semantic_index")
    if output_binding is None:
        raise IndexedTargetEvidenceV3Error("semantic index has no usable binary binding")

    actual_pe_sha256 = _sha256_file(binary_path)
    if actual_pe_sha256 != output_binding.sha256:
        global_issues.append(_Issue("violated", "indexed_pe_sha256_contradiction", "exact PE path does not match the v3 binary binding"))
    machine_manifest = _read_json(machine_ir_manifest_path, "machine-IR manifest")
    actual_machine_ir_sha256 = _sha256_file(machine_ir_path)
    manifest_machine_ir_sha256 = _manifest_machine_ir_sha256(machine_manifest)
    if manifest_machine_ir_sha256 is None:
        global_issues.append(_Issue("incomplete", "indexed_machine_ir_manifest_binding_missing", "machine-IR manifest has no artifact SHA-256"))
    elif manifest_machine_ir_sha256 != actual_machine_ir_sha256:
        global_issues.append(_Issue("violated", "indexed_machine_ir_manifest_contradiction", "machine-IR manifest does not bind the exact machine IR bytes"))

    try:
        image_data, image_base, sections, imports = _parse_pe(binary_path)
        machine_units = _read_machine_ir(machine_ir_path)
        semantics = _artifact_index(semantic_reader, SEMANTIC_INDEX_CODEC_V3)
        summaries = _artifact_index(transition_reader, TRANSITION_SUMMARY_CODEC_V3)
        structural_units = _artifact_index(structural_reader, STRUCTURAL_TARGET_UNIT_CODEC_V3)
        prior = {} if prior_reader is None else _artifact_index(prior_reader, TARGET_EVALUATION_EVIDENCE_CODEC_V3)
        parametric_by_unit: dict[str, ParametricSccSummaryV3] = {}
        if parametric_reader is not None:
            for source in parametric_reader.iter_records():
                summary = PARAMETRIC_SCC_SUMMARY_CODEC_V3.read(source).value
                for unit_id in summary.member_unit_ids:
                    if unit_id in parametric_by_unit:
                        raise IndexedTargetEvidenceV3Error(
                            f"parametric summaries cover unit {unit_id!r} more than once"
                        )
                    parametric_by_unit[unit_id] = summary
        profiles: dict[str, ExternalProfileV3] = {}
        if profile_reader is not None:
            for source in profile_reader.iter_records():
                payload = source.value.to_value()
                if (
                    isinstance(payload, Mapping)
                    and payload.get("schema") == EXTERNAL_PROFILE_RECORD_V3_SCHEMA
                ):
                    profile = EXTERNAL_PROFILE_CODEC_V3.read(source).value
                    profiles[profile.record_id] = profile
    except (IndexedTargetEvidenceV3Error, ValueError) as exc:
        global_issues.append(_Issue("violated", "indexed_input_decode_contradiction", str(exc)))
        image_data, image_base, sections, imports = b"", 0, (), ()
        machine_units, semantics, summaries, structural_units, prior = {}, {}, {}, {}, {}
        parametric_by_unit, profiles = {}, {}

    records: list[ArtifactRecordV3] = []
    exit_reports: list[dict[str, Any]] = []
    if not any(issue.status == "violated" for issue in global_issues):
        for unit_id, semantic in sorted(semantics.items()):
            structural = structural_units.get(unit_id)
            proposals = {} if structural is None else {row.record_id: row for row in structural.proposals}
            for occurrence in semantic.indirect_exits:
                evidence, report = _parametric_evidence_for_exit(
                    occurrence=occurrence,
                    semantic=semantic,
                    proposal=proposals.get(occurrence.exit_id),
                    summary=parametric_by_unit.get(unit_id),
                    profiles=profiles,
                )
                if evidence is not None:
                    assert report is not None
                    exit_reports.append(report)
                    records.append(
                        TARGET_EVALUATION_EVIDENCE_CODEC_V3.write(
                            evidence.record_id, evidence
                        )
                    )
                    continue
                recovery, recovery_issue = _manifest_recovery(machine_manifest, occurrence.exit_id)
                if recovery_issue is not None:
                    exit_reports.append({
                        "exit_id": occurrence.exit_id,
                        "source_unit_id": unit_id,
                        "status": recovery_issue.status,
                        "authorizing": False,
                        "issue": recovery_issue.to_payload(),
                    })
                    continue
                evidence, report = _proof_for_exit(
                    occurrence=occurrence,
                    semantic=semantic,
                    proposal=proposals.get(occurrence.exit_id),
                    machine_units=machine_units,
                    semantics=semantics,
                    summaries=summaries,
                    hint=_target_hint(hints_reader, occurrence.exit_id),
                    prior=prior.get(occurrence.exit_id),
                    manifest_recovery=recovery,
                    image_data=image_data,
                    image_base=image_base,
                    sections=sections,
                    imports=imports,
                    profiles=profiles,
                )
                exit_reports.append(report)
                if evidence is not None:
                    records.append(TARGET_EVALUATION_EVIDENCE_CODEC_V3.write(evidence.record_id, evidence))

    statuses = [issue.status for issue in global_issues] + [str(row["status"]) for row in exit_reports]
    status = "violated" if "violated" in statuses else "incomplete" if "incomplete" in statuses else "complete"
    dependencies = tuple(_dependency(name, reader) for name, reader in sorted(readers.items()))
    output_directory.mkdir(parents=True, exist_ok=False)
    manifest = ArtifactSetWriterV3(
        artifact_kind=TARGET_EVALUATION_EVIDENCE_ARTIFACT_KIND_V3,
        bindings=(output_binding,),
        dependencies=dependencies,
        status=status,
    ).write(
        output_directory / "artifact",
        sorted(records, key=lambda row: row.record_id),
    )
    report = {
        "format": INDEXED_TARGET_EVIDENCE_REPORT_V3,
        "status": status,
        "authorizing": False,
        "binary_binding": output_binding.to_payload(),
        "exact_pe_sha256": actual_pe_sha256,
        "machine_ir_sha256": actual_machine_ir_sha256,
        "machine_ir_manifest_sha256": canonical_sha256_v3(machine_manifest),
        "artifact_id": manifest.artifact_id,
        "artifact_manifest_sha256": hashlib.sha256(manifest.to_bytes()).hexdigest(),
        "counts": {
            "indirect_exits": len(exit_reports),
            "complete": sum(row["status"] == "complete" for row in exit_reports),
            "incomplete": sum(row["status"] == "incomplete" for row in exit_reports),
            "violated": sum(row["status"] == "violated" for row in exit_reports),
            "evidence_records": len(records),
        },
        "global_issues": [row.to_payload() for row in global_issues],
        "exits": sorted(exit_reports, key=lambda row: str(row["exit_id"])),
    }
    (output_directory / "indexed-target-evidence-report-v3.json").write_bytes(
        canonical_json_bytes_v3(report)
    )
    return report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate fail-closed checked indexed PE table target evidence"
    )
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--machine-ir", type=Path, required=True)
    parser.add_argument("--machine-ir-manifest", type=Path, required=True)
    parser.add_argument("--semantic-index", type=Path, required=True)
    parser.add_argument("--transition-summaries", type=Path, required=True)
    parser.add_argument("--structural-targets", type=Path, required=True)
    parser.add_argument("--parametric-summaries", type=Path)
    parser.add_argument("--external-profiles", type=Path)
    parser.add_argument("--target-hints", type=Path)
    parser.add_argument("--target-evidence", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    generate_indexed_target_evidence_v3(
        binary_path=arguments.binary,
        machine_ir_path=arguments.machine_ir,
        machine_ir_manifest_path=arguments.machine_ir_manifest,
        semantic_index_path=arguments.semantic_index,
        transition_summaries_path=arguments.transition_summaries,
        structural_targets_path=arguments.structural_targets,
        parametric_summaries_path=arguments.parametric_summaries,
        external_profiles_path=arguments.external_profiles,
        target_hints_path=arguments.target_hints,
        target_evidence_path=arguments.target_evidence,
        output_directory=arguments.out,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "INDEXED_TARGET_EVIDENCE_REPORT_V3",
    "IndexedTargetEvidenceV3Error",
    "generate_indexed_target_evidence_v3",
    "main",
]

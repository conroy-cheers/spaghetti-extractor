"""Generate checked GNU hello original-target preservation evidence seeds.

The state-machine JSON is an untrusted strategy input.  It partitions targets
by semantic/effect class, but cannot authorize preservation.  This producer
autonomously emits the two target-local checked objects already justified by
the exact upstream graph: ``CheckedOriginalTargetEffect`` and the matching
``ActiveTargetTransitionCertificate``.  It then reports the remaining typed
postcondition obligations needed to construct a
``CheckedOriginalTargetPreservationProvider``.

An externally supplied post-evidence inventory is deliberately not accepted.
In particular, declaration names, status fields, and whole-provider/family
terms cannot turn an obligation into a completed target.  A target is complete
only after this producer itself emits its structured post evidence from generic
checked combinators.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from spaghetti_extractor.errors import StageAInputError
from spaghetti_extractor.relational.lean.original_execution_evidence import LeanRef


GNU_HELLO_ORIGINAL_TARGET_PRESERVATION_FORMAT = (
    "stage-a-gnu-hello-original-target-preservation-v1"
)
GNU_HELLO_ORIGINAL_TARGET_PRESERVATION_DECLARATIONS_FORMAT = (
    "stage-a-gnu-hello-original-target-preservation-declarations-v1"
)
GNU_HELLO_ORIGINAL_TARGET_PRESERVATION_FRONTIER_FORMAT = (
    "stage-a-gnu-hello-original-target-preservation-frontier-v1"
)
GNU_HELLO_ORIGINAL_TARGET_PRESERVATION_NEEDS_FORMAT = (
    "stage-a-gnu-hello-original-target-preservation-needs-v1"
)
GNU_HELLO_ORIGINAL_TARGET_STEP_INDEX_FORMAT = (
    "stage-a-gnu-hello-original-target-step-index-v1"
)

_EFFECTS_FORMAT = "stage-a-gnu-hello-source-transition-index-declarations-v1"
_TRANSITION_FORMAT = "stage-a-gnu-hello-source-transition-index-v1"
_COMBINED_FORMAT = (
    "stage-a-original-combined-execution-inventory-declarations-v1"
)
_CONTEXT_FORMAT = "stage-a-original-execution-preservation-context-v1"
_MODULE_PREFIX = "GeneratedGnuHelloOriginalTargetPreservation"
_NAMESPACE = "StageA.GeneratedRelational.GnuHelloOriginalTargetPreservation"
_LEAN_LOCAL = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_FORBIDDEN_AUTHORITY_FIELDS = {
    "acceptance_authority",
    "authorizing_lean_term",
    "cases",
    "family",
    "preservation_authority",
    "preservation_cases",
    "preservation_family",
    "proof_authority",
    "status",
}
_CONTROL_KINDS = {
    "branch",
    "external_jump",
    "fallthrough",
    "indirect_jump",
    "jump",
    "return",
}
_INDIRECT_AUTHORITY_FORMATS = {
    "stage-a-original-stack-dynamic-control-closure-v1",
    "stage-a-register-indirect-control-authorities-v1",
    "stage-a-relocated-writable-static-pointer-slot-authorities-v2",
}
_RUNTIME_MEMORY_CHECK_INPUTS_FORMAT = (
    "stage-a-runtime-memory-partition-check-inputs-v1"
)
_RUNTIME_MEMORY_PROPOSAL_FORMAT = "stage-a-runtime-memory-access-proposal-v1"
_CONTROL_EVIDENCE_FORMAT = "stage-a-original-target-control-evidence-v1"
_CONTROL_DECLARATIONS_FORMAT = (
    "stage-a-original-target-control-evidence-declarations-v1"
)
_CONTROL_BLOCKERS_FORMAT = "stage-a-original-target-control-evidence-blockers-v1"


class GnuHelloOriginalTargetPreservationError(StageAInputError):
    """The preservation evidence graph is incomplete or inconsistent."""


@dataclass(frozen=True)
class TargetEffectRef:
    target_id: int
    source_rva: int
    kind: str
    ordinary_checked: LeanRef | None
    x87_facts: LeanRef | None
    x87_components: LeanRef | None
    certificate: LeanRef

    @property
    def imports(self) -> set[str]:
        refs = (
            self.ordinary_checked,
            self.x87_facts,
            self.x87_components,
            self.certificate,
        )
        return {ref.module for ref in refs if ref is not None}


@dataclass(frozen=True)
class TargetClass:
    semantic: str
    control: str
    memory: str
    frame: str
    external: bool
    indirect: bool
    successor_ids: tuple[int, ...] = ()

    @property
    def key(self) -> str:
        return ":".join(
            (
                self.semantic,
                self.control,
                self.memory,
                self.frame,
                "external" if self.external else "internal",
                "indirect" if self.indirect else "direct",
            )
        )

    @property
    def lean_suffix(self) -> str:
        words = re.split(r"[^A-Za-z0-9]+", self.key)
        return "".join(word[:1].upper() + word[1:] for word in words if word)


@dataclass(frozen=True)
class PreservationContext:
    source_program: LeanRef
    instruction_semantics_adequate: LeanRef


@dataclass(frozen=True)
class RuntimeWriteProposal:
    write_id: str
    width: int
    address_expression: Mapping[str, Any]
    provenance_class: str
    blocked_reasons: tuple[str, ...]


@dataclass(frozen=True)
class RuntimeTargetProposal:
    target_id: int
    source_rva: int
    writes: tuple[RuntimeWriteProposal, ...]
    ready_for_lean_check: bool
    blocked_reasons: tuple[str, ...]

    @property
    def memory_class(self) -> str:
        if not self.writes:
            return "none"
        classes = {write.provenance_class for write in self.writes}
        if classes == {"image_static_slot"}:
            return "static_writes"
        if classes == {"stack_range"}:
            return "stack_writes"
        if classes == {"dynamic_range"}:
            return "dynamic_writes"
        return "symbolic_writes"


@dataclass(frozen=True)
class RuntimeMemoryProposalInventory:
    check_inputs: Path
    proposal: Path
    targets: Mapping[int, RuntimeTargetProposal]


@dataclass(frozen=True)
class ControlTargetProposal:
    target_id: int
    source_rva: int
    control_class: str
    module: str
    checked_transition: str
    reachability_post: str
    call_frame_post: str
    blocker_reason: str | None


@dataclass(frozen=True)
class ControlProposalInventory:
    manifest: Path
    declarations: Path
    blockers: Path
    targets: Mapping[int, ControlTargetProposal]


@dataclass(frozen=True)
class GeneratedOriginalTargetPreservation:
    modules: tuple[Path, ...]
    declarations: Path
    manifest: Path
    frontier: Path
    needs: Path
    target_step_index: Path
    target_count: int
    checked_seed_count: int
    complete_count: int
    blocked_count: int
    shard_count: int


def _can_emit_no_write_provider(
    target: TargetEffectRef,
    classification: TargetClass,
    runtime: RuntimeTargetProposal | None,
    control: ControlTargetProposal | None,
) -> bool:
    return (
        target.kind == "ordinary"
        and classification.memory in {"none", "read_only"}
        and classification.control.split(":", 1)[0]
        in {"fallthrough", "jump"}
        and len(classification.successor_ids) == 1
        and runtime is not None
        and runtime.ready_for_lean_check
        and not runtime.writes
        and not runtime.blocked_reasons
        and control is not None
        and control.blocker_reason is None
    )


def generate_gnu_hello_original_target_preservation(
    out: Path | str,
    *,
    state_machine: Path | str,
    source_target_effect_declarations: Path | str,
    transition_index_manifest: Path | str,
    combined_inventory_manifest: Path | str,
    authority_artifacts: Mapping[str, Path | str] | None = None,
    shard_size: int = 64,
) -> GeneratedOriginalTargetPreservation:
    """Generate target-local checked seeds and exact post-evidence needs.

    ``authority_artifacts`` is name-to-file rather than a list so its canonical
    hash inventory is stable.  Recognized artifacts are the preservation
    context and existing indirect-control reports.  Unknown artifacts remain
    hash-bound inputs but grant no authority.  A structured post-evidence
    inventory is rejected because this producer, rather than a caller, owns
    construction of those proofs.
    """

    if (
        isinstance(shard_size, bool)
        or not isinstance(shard_size, int)
        or shard_size <= 0
    ):
        raise GnuHelloOriginalTargetPreservationError(
            "shard_size must be a positive integer"
        )
    root = Path(out)
    root.mkdir(parents=True, exist_ok=True)
    _remove_stale_outputs(root)

    paths = {
        "state_machine": Path(state_machine),
        "source_target_effect_declarations": Path(
            source_target_effect_declarations
        ),
        "transition_index_manifest": Path(transition_index_manifest),
        "combined_inventory_manifest": Path(combined_inventory_manifest),
    }
    authorities = {
        _authority_name(name): Path(path)
        for name, path in sorted((authority_artifacts or {}).items())
    }
    if set(paths) & set(authorities):
        raise GnuHelloOriginalTargetPreservationError(
            "authority artifact names collide with primary inputs"
        )
    hashes = {name: _sha256(path) for name, path in {**paths, **authorities}.items()}

    rows = _state_machine_rows(paths["state_machine"])
    effects = _load_object(
        paths["source_target_effect_declarations"],
        "source target-effect declarations",
    )
    transition = _load_object(
        paths["transition_index_manifest"], "transition-index manifest"
    )
    combined = _load_object(
        paths["combined_inventory_manifest"], "combined inventory manifest"
    )
    _require_format(effects, _EFFECTS_FORMAT, "source target-effect declarations")
    _require_format(transition, _TRANSITION_FORMAT, "transition-index manifest")
    _require_format(combined, _COMBINED_FORMAT, "combined inventory manifest")

    targets = _effect_targets(effects, transition)
    _validate_inventory_counts(combined, targets)
    _validate_transition_binding(
        transition,
        hashes["source_target_effect_declarations"],
        len(targets),
    )
    rows_by_rva = _rows_by_rva(rows)
    missing_rows = [
        target.source_rva
        for target in targets
        if target.source_rva not in rows_by_rva
    ]
    if missing_rows:
        raise GnuHelloOriginalTargetPreservationError(
            "state machine omits reachable source RVAs "
            + ", ".join(f"0x{rva:x}" for rva in missing_rows[:16])
        )

    authority_documents = {
        name: _load_object(path, f"authority artifact {name}")
        for name, path in authorities.items()
    }
    _reject_supplied_post_evidence(authority_documents)
    context = _transition_preservation_context(transition)
    if context is None:
        context = _preservation_context(authority_documents, hashes)
    runtime_memory = _runtime_memory_proposal_inventory(
        authorities,
        authority_documents,
        primary_hashes=hashes,
        targets=targets,
    )
    control = _control_proposal_inventory(
        authorities,
        authority_documents,
        primary_hashes=hashes,
        targets=targets,
    )
    authority_sites = _authority_sites(authority_documents)
    inventory_counts = _object(combined.get("counts"), "combined counts")
    classes = {
        target.target_id: _classify_target(
            target,
            rows_by_rva[target.source_rva],
            runtime=(
                runtime_memory.targets.get(target.target_id)
                if runtime_memory is not None
                else None
            ),
            control=(
                control.targets.get(target.target_id)
                if control is not None
                else None
            ),
            target_id_by_rva={value.source_rva: value.target_id for value in targets},
        )
        for target in targets
    }

    blockers: list[dict[str, Any]] = []
    target_rows: list[dict[str, Any]] = []
    complete_target_ids: set[int] = set()
    for target in targets:
        classification = classes[target.target_id]
        runtime_target = (
            runtime_memory.targets.get(target.target_id)
            if runtime_memory is not None
            else None
        )
        control_target = (
            control.targets.get(target.target_id) if control is not None else None
        )
        complete = context is not None and _can_emit_no_write_provider(
            target, classification, runtime_target, control_target
        )
        missing = _autonomous_evidence_needs(
            target,
            classification,
            context=context,
            counts=inventory_counts,
            authority_sites=authority_sites,
            runtime=runtime_target,
            control=control_target,
        )
        if complete:
            complete_target_ids.add(target.target_id)
            missing = []
        else:
            blockers.append(
                {
                    "reason_code": "autonomous_target_preservation_incomplete",
                    "target_id": target.target_id,
                    "source_rva": target.source_rva,
                    "semantic_class": classification.key,
                    "authority_kinds": sorted(
                        authority_sites.get(target.source_rva, set())
                    ),
                    "emitted_checked_evidence": _emitted_evidence(context, target),
                    "missing_checked_evidence": missing,
                    "next_action": _next_action(missing),
                }
            )
        target_rows.append(
            {
                "target_id": target.target_id,
                "source_rva": target.source_rva,
                "semantic_class": classification.key,
                "checked_seed_emitted": context is not None,
                "complete": complete,
                "emitted_checked_evidence": _emitted_evidence(context, target),
                "missing_checked_evidence": missing,
            }
        )

    modules: list[Path] = []
    declaration_targets: list[dict[str, Any]] = []
    if context is not None:
        data_path = root / "StageA" / f"{_MODULE_PREFIX}Data.lean"
        data_path.parent.mkdir(parents=True, exist_ok=True)
        _write_ascii(
            data_path,
            _data_source(
                context,
                combined,
                control=control,
            ),
        )
        modules.append(data_path)
        buckets: dict[
            str, list[tuple[TargetEffectRef, TargetClass]]
        ] = defaultdict(list)
        for target in targets:
            buckets[classes[target.target_id].key].append(
                (target, classes[target.target_id])
            )
        for classification_key in sorted(buckets):
            members = buckets[classification_key]
            suffix = members[0][1].lean_suffix
            for shard_index, start in enumerate(range(0, len(members), shard_size)):
                shard = members[start : start + shard_size]
                module = f"{_MODULE_PREFIX}{suffix}Shard{shard_index:04d}"
                path = root / "StageA" / f"{module}.lean"
                _write_ascii(
                    path,
                    _shard_source(
                        module,
                        shard,
                        runtime_memory=runtime_memory,
                        control=control,
                    ),
                )
                modules.append(path)
                for target, classification in shard:
                    prefix = f"{_NAMESPACE}.generatedTarget{target.target_id}"
                    declaration_targets.append(
                        {
                            "target_id": target.target_id,
                            "source_rva": target.source_rva,
                            "semantic_class": classification.key,
                            "module": f"StageA.{module}",
                            "checked_effect": f"{prefix}CheckedEffect",
                            "transition_certificate": f"{prefix}Certificate",
                            "runtime_memory_precondition": (
                                f"{prefix}RuntimeMemoryBefore"
                            ),
                            "runtime_memory_proposal": (
                                f"{prefix}RuntimeWriteProposals"
                                if (
                                    runtime_memory is not None
                                    and target.kind == "ordinary"
                                    and runtime_memory.targets[
                                        target.target_id
                                    ].ready_for_lean_check
                                )
                                else None
                            ),
                            "control_proposal": (
                                f"{prefix}ControlProposal"
                                if (
                                    control is not None
                                    and control.targets[
                                        target.target_id
                                    ].blocker_reason
                                    is None
                                )
                                else None
                            ),
                            "provider": None,
                            "family_preservation": None,
                        }
                    )
                    if target.target_id in complete_target_ids:
                        declaration_targets[-1]["provider"] = (
                            f"{prefix}Provider"
                        )
                        declaration_targets[-1]["family_preservation"] = (
                            f"{prefix}FamilyPreservation"
                        )

    declarations_path = root / "original-target-preservation-declarations.json"
    _write_json(
        declarations_path,
        {
            "format": GNU_HELLO_ORIGINAL_TARGET_PRESERVATION_DECLARATIONS_FORMAT,
            "namespace": _NAMESPACE,
            "module_prefix": _MODULE_PREFIX,
            "targets": declaration_targets,
        },
    )

    target_step_index_path = root / "original-target-step-index.json"
    completed_declarations = [
        {
            "target_id": row["target_id"],
            "source_rva": row["source_rva"],
            "module": row["module"],
            "provider": row["provider"],
            "family_preservation": row["family_preservation"],
            "transition_certificate": row["transition_certificate"],
        }
        for row in sorted(declaration_targets, key=lambda value: value["target_id"])
        if row["provider"] is not None
    ]
    _write_json(
        target_step_index_path,
        {
            "format": GNU_HELLO_ORIGINAL_TARGET_STEP_INDEX_FORMAT,
            "proof_authority": False,
            "acceptance_authority": False,
            "validation_required": "lean-kernel-check-and-detached-axiom-audit",
            "complete": len(complete_target_ids) == len(targets),
            "counts": {
                "targets": len(targets),
                "providers": len(complete_target_ids),
                "missing": len(targets) - len(complete_target_ids),
            },
            "providers": completed_declarations,
            "target_step_index": None,
        },
    )

    class_counts = Counter(classes[target.target_id].key for target in targets)
    missing_counts = Counter(
        family for blocker in blockers for family in blocker["missing_checked_evidence"]
    )
    memory_counts = Counter(
        classes[target.target_id].memory for target in targets
    )
    needs_path = root / "original-target-preservation-needs.json"
    _write_json(
        needs_path,
        _artifact_needs(
            targets=targets,
            classes=classes,
            inventory_counts=inventory_counts,
            missing_counts=missing_counts,
            runtime_memory=runtime_memory,
            control=control,
        ),
    )
    frontier_path = root / "original-target-preservation-frontier.json"
    _write_json(
        frontier_path,
        {
            "format": GNU_HELLO_ORIGINAL_TARGET_PRESERVATION_FRONTIER_FORMAT,
            "proof_authority": False,
            "acceptance_authority": False,
            "ready": not blockers,
            "executes_original_binary": False,
            "executes_candidate_binary": False,
            "counts": {
                "targets": len(targets),
                "checked_seeds": len(targets) if context is not None else 0,
                "complete": len(complete_target_ids),
                "blocked": len(blockers),
                "semantic_classes": dict(sorted(class_counts.items())),
                "memory_classes": dict(sorted(memory_counts.items())),
                "missing_by_family": dict(sorted(missing_counts.items())),
            },
            "artifact_needs": needs_path.name,
            "target_step_index": target_step_index_path.name,
            "blockers": blockers,
        },
    )

    manifest_path = root / "original-target-preservation.json"
    _write_json(
        manifest_path,
        {
            "format": GNU_HELLO_ORIGINAL_TARGET_PRESERVATION_FORMAT,
            "proof_authority": False,
            "acceptance_authority": False,
            "validation_required": "lean-kernel-check-and-detached-axiom-audit",
            "executes_original_binary": False,
            "executes_candidate_binary": False,
            "inputs": dict(sorted(hashes.items())),
            "counts": {
                "targets": len(targets),
                "checked_seeds": len(targets) if context is not None else 0,
                "complete": len(complete_target_ids),
                "blocked": len(blockers),
                "shards": max(0, len(modules) - (1 if context is not None else 0)),
            },
            "modules": [f"StageA.{path.stem}" for path in modules],
            "declarations": declarations_path.name,
            "frontier": frontier_path.name,
            "artifact_needs": needs_path.name,
            "targets": target_rows,
        },
    )
    return GeneratedOriginalTargetPreservation(
        modules=tuple(modules),
        declarations=declarations_path,
        manifest=manifest_path,
        frontier=frontier_path,
        needs=needs_path,
        target_step_index=target_step_index_path,
        target_count=len(targets),
        checked_seed_count=len(targets) if context is not None else 0,
        complete_count=len(complete_target_ids),
        blocked_count=len(blockers),
        shard_count=max(0, len(modules) - (1 if context is not None else 0)),
    )


def _effect_targets(
    effects: Mapping[str, Any], transition: Mapping[str, Any]
) -> list[TargetEffectRef]:
    namespace = _string(effects.get("namespace"), "effects.namespace")
    module_prefix = _string(effects.get("module_prefix"), "effects.module_prefix")
    shard_span = _positive(effects.get("shard_span"), "effects.shard_span")
    transition_modules = {
        _string(value, "transition modules[]")
        for value in _list(transition.get("modules"), "transition modules")
    }
    result: list[TargetEffectRef] = []
    for index, raw in enumerate(_list(effects.get("targets"), "effect targets")):
        row = _object(raw, f"effect targets[{index}]")
        target_id = _natural(row.get("target_id"), f"effect targets[{index}].target_id")
        source_rva = _word(row.get("source_rva"), f"effect targets[{index}].source_rva")
        kind = _string(row.get("kind"), f"effect targets[{index}].kind")
        evidence = _object(row.get("evidence"), f"effect targets[{index}].evidence")
        ordinary: LeanRef | None = None
        facts: LeanRef | None = None
        components: LeanRef | None = None
        if kind == "ordinary":
            ordinary = _lean_ref(evidence.get("checked_effect"), "checked effect")
        elif kind == "x87":
            facts = _lean_ref(evidence.get("facts"), "x87 facts")
            components = _lean_ref(
                evidence.get("successful_components"), "x87 components"
            )
        else:
            raise GnuHelloOriginalTargetPreservationError(
                f"target {target_id} has unsupported semantic kind {kind!r}"
            )
        shard = f"{module_prefix}Shard{target_id // shard_span:06d}"
        if shard not in transition_modules:
            raise GnuHelloOriginalTargetPreservationError(
                f"transition index omits certificate shard {shard}"
            )
        result.append(
            TargetEffectRef(
                target_id=target_id,
                source_rva=source_rva,
                kind=kind,
                ordinary_checked=ordinary,
                x87_facts=facts,
                x87_components=components,
                certificate=LeanRef.from_qualified(
                    f"StageA.{shard}",
                    f"{namespace}.generatedActiveTargetTransitionCertificate_{target_id}",
                ),
            )
        )
    ids = [target.target_id for target in result]
    rvas = [target.source_rva for target in result]
    if ids != sorted(set(ids)) or len(rvas) != len(set(rvas)):
        raise GnuHelloOriginalTargetPreservationError(
            "effect targets must be sorted and unique by target and source RVA"
        )
    if not result:
        raise GnuHelloOriginalTargetPreservationError(
            "effect target inventory must be nonempty"
        )
    return result


def _classify_target(
    target: TargetEffectRef,
    row: Mapping[str, Any],
    *,
    runtime: RuntimeTargetProposal | None,
    control: ControlTargetProposal | None,
    target_id_by_rva: Mapping[int, int],
) -> TargetClass:
    outcome = _object(row.get("outcome"), f"target {target.target_id} outcome")
    row_control = _string(
        outcome.get("kind"), f"target {target.target_id} outcome.kind"
    )
    if row_control not in _CONTROL_KINDS:
        raise GnuHelloOriginalTargetPreservationError(
            f"target {target.target_id} has unsupported control kind {row_control!r}"
        )
    memory_events = [
        _object(value, f"target {target.target_id} memory event")
        for value in _list(row.get("memory_events"), "memory_events")
    ]
    writes = [event for event in memory_events if event.get("kind") == "write"]
    if runtime is not None:
        memory = runtime.memory_class
    elif not memory_events:
        memory = "none"
    elif not writes:
        memory = "read_only"
    else:
        # Address provenance belongs to runtime_memory_access_proposal.py.
        # Without its exact check-input artifact writes remain unclassified.
        memory = "unclassified_writes"
    external_events = _list(row.get("external_events"), "external_events")
    control_class = control.control_class if control is not None else row_control
    control_kind = control_class.split(":", 1)[0]
    external = bool(external_events) or control_kind in {
        "external",
        "external_jump",
    }
    indirect = control_kind in {"indirect_call", "indirect_jump"}
    if control_kind == "return":
        frame = "return"
    elif external:
        frame = "external"
    elif indirect:
        frame = "indirect_control"
    else:
        frame = "local_control"
    successor_ids: tuple[int, ...] = ()
    if control_kind in {"fallthrough", "jump"}:
        target_rva = outcome.get("target_rva")
        if isinstance(target_rva, int) and not isinstance(target_rva, bool):
            mapped = target_id_by_rva.get(target_rva)
            if mapped is not None:
                successor_ids = (mapped,)
    elif control_kind == "branch":
        mapped_targets = tuple(
            target_id_by_rva.get(value)
            for value in (
                outcome.get("true_target_rva"),
                outcome.get("false_target_rva"),
            )
            if isinstance(value, int) and not isinstance(value, bool)
        )
        if len(mapped_targets) == 2 and all(value is not None for value in mapped_targets):
            successor_ids = tuple(int(value) for value in mapped_targets)
    return TargetClass(
        target.kind,
        control_class,
        memory,
        frame,
        external,
        indirect,
        successor_ids,
    )


def _autonomous_evidence_needs(
    target: TargetEffectRef,
    classification: TargetClass,
    *,
    context: PreservationContext | None,
    counts: Mapping[str, Any],
    authority_sites: Mapping[int, set[str]],
    runtime: RuntimeTargetProposal | None,
    control: ControlTargetProposal | None,
) -> list[str]:
    missing: list[str] = []
    if context is None:
        missing.append("preservation_context")
    if control is None:
        missing.append("control_check_input")
    elif control.blocker_reason is not None:
        missing.append(f"control:{control.blocker_reason}")
    else:
        missing.append("control_routing_lean_check")
    if target.kind == "x87":
        missing.append("normalized_transition_effects")
    missing.append("memory_post")
    if runtime is None and classification.memory == "unclassified_writes":
        missing.append("runtime_memory_check_input")
    elif runtime is not None:
        missing.extend(
            f"runtime_memory:{reason}" for reason in runtime.blocked_reasons
        )
    if classification.memory in {
        "stack_writes",
        "dynamic_writes",
        "symbolic_writes",
    }:
        missing.append("runtime_write_membership_lean_check")
    if classification.memory == "static_writes":
        missing.append("static_write_relation")
    missing.append("call_frames")
    if classification.external:
        missing.append("external_call_contract")
    if classification.indirect and not authority_sites.get(target.source_rva):
        missing.append("indirect_target_authority")
    family_counts = {
        "value_flows": "value_flow_facts",
        "register_targets": "register_requirements",
        "stack_dynamic_targets": "stack_dynamic_requirements",
    }
    for component, count_name in family_counts.items():
        count = _natural(counts.get(count_name, 0), f"combined counts.{count_name}")
        if count > 0:
            missing.append(component)
    return list(dict.fromkeys(missing))


def _emitted_evidence(
    context: PreservationContext | None, target: TargetEffectRef
) -> list[str]:
    if context is None:
        return []
    result = [
        "checked_target_effect",
        "active_transition_certificate",
        "checked_runtime_memory_precondition",
    ]
    if target.kind == "ordinary":
        result.append("checked_normalized_transition_effects")
    return result


def _next_action(missing: Sequence[str]) -> str:
    if "preservation_context" in missing:
        return "emit the exact preservation context bound to these proof inputs"
    if "runtime_memory_check_input" in missing:
        return (
            "run runtime_memory_access_proposal.py and supply its exact "
            "runtime-memory-partition-check-inputs artifact"
        )
    if "runtime_write_membership_lean_check" in missing:
        return (
            "prove each exact evaluated write is wholly contained in one active "
            "stack or dynamic range; the combined invariant now supplies the "
            "checked non-wrapping PE-disjoint runtime partition"
        )
    if "control_check_input" in missing:
        return (
            "run original_target_control_evidence.py and supply its exact "
            "control-evidence manifest"
        )
    if "indirect_target_authority" in missing:
        return "supply a checked finite indirect-target authority for this source RVA"
    return "generate checked post evidence from generic combinators: " + ", ".join(
        missing
    )


def _data_source(
    context: PreservationContext,
    combined: Mapping[str, Any],
    *,
    control: ControlProposalInventory | None,
) -> str:
    lean = _object(combined.get("lean"), "combined lean")
    combined_module = _string(lean.get("module"), "combined lean.module")
    inventory = _string(lean.get("inventory"), "combined lean.inventory")
    original_context = _string(
        lean.get("original_context"), "combined lean.original_context"
    )
    imports = sorted(
        {
            combined_module,
            context.source_program.module,
            context.instruction_semantics_adequate.module,
            "StageA.RelationalOriginalTargetPreservation",
            "StageA.RelationalOriginalNoWriteTargetPreservation",
            "StageA.RelationalOriginalProvenancePreservation",
            "StageA.RelationalOriginalRuntimeMemoryPartition",
            "StageA.RelationalOriginalTargetControlConstruction",
        }
    )
    return f"""{_imports(imports)}

namespace {_NAMESPACE}

open StageA.Relational
open StageA.Relational.InterpreterNormalization
open StageA.Relational.OriginalCombinedExecutionInvariant
open StageA.Relational.OriginalProvenancePreservation
open StageA.Relational.OriginalRuntimeMemoryPartition
open StageA.Relational.OriginalTargetPreservation
open StageA.Relational.SourceWorld.InterpreterKernel
open StageA.Relational.SourceWorld.OrdinaryTargetRouting
open StageA.Relational.ValueProvenance

noncomputable section

abbrev generatedSourceProgram : Program :=
  {context.source_program.declaration}
abbrev generatedOriginalContext : OriginalDecodedStaticContext :=
  {original_context}
abbrev generatedInventory : OriginalCombinedExecutionInventory
    generatedSourceProgram.worldProgram generatedOriginalContext :=
  {inventory}
theorem generatedInstructionSemanticsAdequate :
    generatedSourceProgram.worldProgram.InstructionSemanticsAdequate :=
  {context.instruction_semantics_adequate.declaration}

def generatedMirroredWrite (write : Prod Expr Expr) : PairedMemoryEffect := {{
  kind := .write
  width := 4
  originalAddress := write.1
  candidateAddress := write.1
  originalValue := some write.2
  candidateValue := some write.2
}}

def generatedMirroredRegister (register : Reg) (value : Expr) :
    PairedRegisterEffect := {{
  originalRegister := register
  candidateRegister := register
  originalValue := value
  candidateValue := value
}}

def generatedMirroredEffects (behavior : NormalizedSymbolicBehavior) :
    TransitionEffects := {{
  memory := behavior.writes.map generatedMirroredWrite
  registersWritten := [
    generatedMirroredRegister .eax behavior.registers.eax,
    generatedMirroredRegister .ebx behavior.registers.ebx,
    generatedMirroredRegister .ecx behavior.registers.ecx,
    generatedMirroredRegister .edx behavior.registers.edx,
    generatedMirroredRegister .esi behavior.registers.esi,
    generatedMirroredRegister .edi behavior.registers.edi,
    generatedMirroredRegister .ebp behavior.registers.ebp,
    generatedMirroredRegister .esp behavior.registers.esp]
  flagsWritten := []
  frameAction := .preserve
}}

theorem generatedMirroredEffectsChecked (behavior : NormalizedSymbolicBehavior) :
    (generatedMirroredEffects behavior).checked = true := by
  simp [generatedMirroredEffects, generatedMirroredWrite,
    generatedMirroredRegister, TransitionEffects.checked,
    PairedMemoryEffect.shapeChecked]

theorem generatedMirroredEffectsImplement
    (behavior : NormalizedSymbolicBehavior) (state : MachineState) :
    (generatedMirroredEffects behavior).OriginalRuntimeImplements state
      ((behavior.eval state).nextMachineState state) := by
  constructor
  case left =>
    simp [TransitionEffects.OriginalMemoryImplements,
      generatedMirroredEffects, generatedMirroredWrite,
      TransitionEffects.originalConcreteWrites, TransitionEffects.originalWrites,
      PairedMemoryEffect.originalWrite?, evalNormalizedWrites,
      RelationalBehavior.nextMachineState]
  case right =>
    intro register
    cases register <;>
      simp [TransitionEffects.OriginalRegistersImplement,
        TransitionEffects.originalRegisterEffect?, generatedMirroredEffects,
        generatedMirroredRegister, RelationalBehavior.nextMachineState,
        evalNormalizedRegisters]

def generatedOrdinaryEffects
    {{pe : PE32}} {{program : Program}} {{targetId sourceRva : Nat}}
    {{record : ProgramRecord}} {{path : ExactNormalizedTransferPath}}
    {{transfer : SemanticTransfer}} {{region : RegionRelation}}
    {{binding : ExactOrdinaryTargetBinding pe program targetId sourceRva record
      path transfer region}}
    {{decoded : ExactDecodedOrdinaryTargetEvaluator binding}}
    (_checked : CheckedOrdinaryTargetEffect binding decoded) (calls : List Nat) :
    TransitionEffects :=
  generatedMirroredEffects (decoded.normalized calls)

def generatedOrdinaryWrites
    {{pe : PE32}} {{program : Program}} {{targetId sourceRva : Nat}}
    {{record : ProgramRecord}} {{path : ExactNormalizedTransferPath}}
    {{transfer : SemanticTransfer}} {{region : RegionRelation}}
    {{binding : ExactOrdinaryTargetBinding pe program targetId sourceRva record
      path transfer region}}
    {{decoded : ExactDecodedOrdinaryTargetEvaluator binding}}
    (_checked : CheckedOrdinaryTargetEffect binding decoded) (calls : List Nat) :
    List (Prod Expr Expr) :=
  (decoded.normalized calls).writes

theorem generatedOrdinaryEffectsChecked
    {{pe : PE32}} {{program : Program}} {{targetId sourceRva : Nat}}
    {{record : ProgramRecord}} {{path : ExactNormalizedTransferPath}}
    {{transfer : SemanticTransfer}} {{region : RegionRelation}}
    {{binding : ExactOrdinaryTargetBinding pe program targetId sourceRva record
      path transfer region}}
    {{decoded : ExactDecodedOrdinaryTargetEvaluator binding}}
    (checked : CheckedOrdinaryTargetEffect binding decoded) (calls : List Nat) :
    (generatedOrdinaryEffects checked calls).checked = true :=
  generatedMirroredEffectsChecked (decoded.normalized calls)

theorem generatedOrdinaryEffectsImplement
    {{pe : PE32}} {{program : Program}} {{targetId sourceRva : Nat}}
    {{record : ProgramRecord}} {{path : ExactNormalizedTransferPath}}
    {{transfer : SemanticTransfer}} {{region : RegionRelation}}
    {{binding : ExactOrdinaryTargetBinding pe program targetId sourceRva record
      path transfer region}}
    {{decoded : ExactDecodedOrdinaryTargetEvaluator binding}}
    (checked : CheckedOrdinaryTargetEffect binding decoded) (calls : List Nat)
    (state : MachineState) :
    (generatedOrdinaryEffects checked calls).OriginalRuntimeImplements state
      (((decoded.normalized calls).eval state).nextMachineState state) :=
  generatedMirroredEffectsImplement (decoded.normalized calls) state

end
end {_NAMESPACE}
"""


def _shard_source(
    module: str,
    members: Sequence[tuple[TargetEffectRef, TargetClass]],
    *,
    runtime_memory: RuntimeMemoryProposalInventory | None,
    control: ControlProposalInventory | None,
) -> str:
    imports = {f"StageA.{_MODULE_PREFIX}Data"}
    for target, _classification in members:
        imports.update(target.imports)
        if control is not None:
            imports.add(control.targets[target.target_id].module)
    body = "\n\n".join(
        _target_seed_source(
            target,
            classification=classification,
            runtime=(
                runtime_memory.targets[target.target_id]
                if runtime_memory is not None
                else None
            ),
            control=(
                control.targets[target.target_id]
                if control is not None
                else None
            ),
        )
        for target, classification in members
    )
    return f"""{_imports(sorted(imports))}

namespace {_NAMESPACE}

open StageA.Relational
open StageA.Relational.OriginalCombinedTargetStepIndex
open StageA.Relational.OriginalNoWriteTargetPreservation
open StageA.Relational.OriginalProvenancePreservation
open StageA.Relational.OriginalRuntimeMemoryPartition
open StageA.Relational.OriginalTargetControlConstruction
open StageA.Relational.OriginalTargetControlPreservation
open StageA.Relational.OriginalTargetPreservation
open StageA.Relational.SourceWorld.OrdinaryTargetRouting
open StageA.Relational.SourceWorld.ProgramCertificate
open StageA.Relational.ValueProvenance

noncomputable section

{body}

end
end {_NAMESPACE}
"""


def _target_seed_source(
    target: TargetEffectRef,
    *,
    classification: TargetClass,
    runtime: RuntimeTargetProposal | None,
    control: ControlTargetProposal | None,
) -> str:
    prefix = f"generatedTarget{target.target_id}"
    if target.kind == "ordinary":
        assert target.ordinary_checked is not None
        checked = (
            "CheckedOriginalTargetEffect.ofOrdinary "
            f"{target.ordinary_checked.declaration} "
            "generatedInstructionSemanticsAdequate"
        )
        normalized = f"""

def {prefix}NormalizedEffects (calls : List Nat) : TransitionEffects :=
  generatedOrdinaryEffects {target.ordinary_checked.declaration} calls

theorem {prefix}NormalizedEffectsChecked (calls : List Nat) :
    ({prefix}NormalizedEffects calls).checked = true :=
  generatedOrdinaryEffectsChecked {target.ordinary_checked.declaration} calls

theorem {prefix}NormalizedEffectsImplement
    (invocation : OriginalTargetInvocation {target.target_id}) :
    ({prefix}NormalizedEffects invocation.calls).OriginalRuntimeImplements
      invocation.state
      (({prefix}CheckedEffect.components.decodedBehavior invocation.state
        invocation.calls).nextMachineState invocation.state) := by
  simpa [{prefix}CheckedEffect, {prefix}NormalizedEffects,
    CheckedOriginalTargetEffect.ofOrdinary,
    CheckedOrdinaryTargetEffect.toSuccessfulTargetEffectComponents,
    ExactDecodedOrdinaryTargetEvaluator.behavior] using
    (generatedOrdinaryEffectsImplement {target.ordinary_checked.declaration}
      invocation.calls invocation.state)
"""
    else:
        assert target.x87_facts is not None and target.x87_components is not None
        checked = (
            "CheckedOriginalTargetEffect.ofX87 "
            f"{target.x87_facts.declaration} "
            f"{target.x87_components.declaration} "
            "generatedInstructionSemanticsAdequate"
        )
        normalized = ""
    runtime_source = _runtime_target_proposal_source(prefix, target, runtime)
    control_source = _control_target_proposal_source(prefix, control)
    provider_source = _no_write_provider_source(
        prefix,
        target,
        classification=classification,
        runtime=runtime,
        control=control,
    )
    return f"""def {prefix}CheckedEffect :
    CheckedOriginalTargetEffect generatedSourceProgram {target.target_id} :=
  {checked}

abbrev {prefix}Certificate := {target.certificate.declaration}{normalized}

{runtime_source}

{control_source}

{provider_source}

theorem {prefix}RuntimeMemoryBefore
    (invocation : OriginalTargetInvocation {target.target_id})
    (holds : generatedInventory.Holds invocation.execution) :
    HoldsIn generatedSourceProgram.worldProgram.context invocation.world /\
      SuspendedHold generatedSourceProgram.worldProgram.context
        invocation.routingCallbacks :=
  activeRuntimeMemoryHolds invocation holds
"""


def _runtime_target_proposal_source(
    prefix: str,
    target: TargetEffectRef,
    runtime: RuntimeTargetProposal | None,
) -> str:
    if runtime is None:
        return f"-- {prefix}: no hash-bound runtime-memory check input"
    if runtime.blocked_reasons:
        return (
            f"-- {prefix}: runtime-memory proposal is fail-closed: "
            + ", ".join(runtime.blocked_reasons)
        )
    proposals: list[str] = []
    for write in runtime.writes:
        expression = _runtime_address_expr_lean(write.address_expression)
        classification = {
            "image_static_slot": ".imageStatic",
            "stack_range": ".stack",
            "dynamic_range": ".dynamic",
        }.get(write.provenance_class)
        if expression is None or classification is None:
            return (
                f"-- {prefix}: runtime-memory proposal is fail-closed; "
                "its address expression is outside the checked Lean grammar"
            )
        proposals.append(
            "{ address := "
            + expression
            + f", bytes := {write.width}, classification := {classification} }}"
        )
    source = (
        f"def {prefix}RuntimeWriteProposals : "
        "List OriginalRuntimeWriteCheckProposal := ["
        + ", ".join(proposals)
        + "]"
    )
    if target.kind != "ordinary":
        return source + (
            f"\n\n-- {prefix}: x87 physical stores require checked instruction "
            "replay rather than the ordinary-write checker"
        )
    assert target.ordinary_checked is not None
    return source + f"""

theorem {prefix}RuntimeWriteProposalsExact (calls : List Nat) :
    normalizedWriteProposalsChecked
      (generatedOrdinaryWrites {target.ordinary_checked.declaration} calls)
      {prefix}RuntimeWriteProposals = true := by
  rfl
"""


def _control_target_proposal_source(
    prefix: str, control: ControlTargetProposal | None
) -> str:
    if control is None:
        return f"-- {prefix}: no hash-bound control check input"
    if control.blocker_reason is not None:
        return (
            f"-- {prefix}: control proposal is fail-closed: "
            f"{control.blocker_reason}"
        )
    return f"""abbrev {prefix}ControlProposal :=
  @{control.checked_transition}
abbrev {prefix}ReachabilityProposal :=
  @{control.reachability_post}
abbrev {prefix}CallFrameProposal :=
  @{control.call_frame_post}
"""


def _no_write_provider_source(
    prefix: str,
    target: TargetEffectRef,
    *,
    classification: TargetClass,
    runtime: RuntimeTargetProposal | None,
    control: ControlTargetProposal | None,
) -> str:
    if not _can_emit_no_write_provider(
        target, classification, runtime, control
    ):
        return f"-- {prefix}: no closed generic no-write provider"
    assert target.ordinary_checked is not None
    ordinary = target.ordinary_checked.declaration
    next_target = classification.successor_ids[0]
    return f"""def {prefix}ControlEvidence :
    CheckedOriginalTargetControlEvidence generatedOriginalContext
      generatedInventory {prefix}CheckedEffect :=
  CheckedOriginalTargetControlEvidence.ofNoWriteJump
    (checked := {prefix}CheckedEffect)
    (nextTargetId := {next_target})
    (by intro state calls; rfl)
    (by
      intro state calls
      exact ordinaryNoWritesMemoryExact {ordinary} calls state
        (normalizedWriteProposalsChecked_empty
          (generatedOrdinaryWrites {ordinary} calls)
          ({prefix}RuntimeWriteProposalsExact calls)))
    (by decide)

def {prefix}NoWriteEvidence :
    CheckedOriginalNoWriteTargetEvidence generatedOriginalContext
      generatedInventory {prefix}Certificate where
  checked := {prefix}CheckedEffect
  control := {prefix}ControlEvidence
  noWrite invocation holds := by
    let control := {prefix}ControlEvidence.toPreservationCase invocation holds
    let afterState :=
      ({prefix}CheckedEffect.components.decodedBehavior invocation.state
        invocation.calls).nextMachineState invocation.state
    let normalized : CheckedOriginalNormalizedTransitionEffects
        invocation.state control.transition.successor := {{
      effects := {prefix}NormalizedEffects invocation.calls
      effectsChecked := {prefix}NormalizedEffectsChecked invocation.calls
      implements := by
        simpa [control, {prefix}ControlEvidence, afterState,
          CheckedOriginalTargetControlEvidence.ofNoWriteJump,
          CheckedOriginalTargetControlEvidence.toPreservationCase] using
          ({prefix}NormalizedEffectsImplement invocation)
    }}
    let effects : CheckedOriginalTargetProvenanceEffects
        control.transition := {{ normalized }}
    refine {{
      provenance := {{
        effects
        witness := ?_
      }}
      originalWritesEmpty := ?_
      worldFrame := ?_
    }}
    case provenance.witness =>
      simpa [control, {prefix}ControlEvidence,
        CheckedOriginalTargetControlEvidence.ofNoWriteJump,
        CheckedOriginalTargetControlEvidence.toPreservationCase,
        afterState] using
        (CheckedOriginalProvenancePostWitness.ofInertLocalResume
          (normalized := CheckedOriginalNormalizedTransitionEffects.ofResume
            invocation.state afterState
            ({prefix}NormalizedEffects invocation.calls)
            ({prefix}NormalizedEffectsChecked invocation.calls)
            ({prefix}NormalizedEffectsImplement invocation)
            invocation.routingCallbacks {next_target} invocation.calls
            invocation.eventIndex invocation.world)
          (by
            intro fact factMember endpoint
            simp_all [generatedInventory])
          (by
            intro requirement requirementMember
            simp_all [generatedInventory])
          (by
            intro requirement requirementMember
            simp_all [generatedInventory]))
    case originalWritesEmpty =>
      simp [effects, normalized, {prefix}NormalizedEffects,
        generatedOrdinaryEffects, generatedMirroredEffects,
        TransitionEffects.originalWrites,
        PairedMemoryEffect.originalWrite?]
    case worldFrame =>
      simp [control, {prefix}ControlEvidence,
        CheckedOriginalTargetControlEvidence.ofNoWriteJump,
        CheckedOriginalTargetControlEvidence.toPreservationCase,
        OriginalNoWriteWorldFrame]

def {prefix}Provider :
    CheckedOriginalTargetPreservationProvider generatedOriginalContext
      generatedInventory {prefix}Certificate :=
  {prefix}NoWriteEvidence.toProvider

def {prefix}FamilyPreservation :
    OriginalCombinedTargetFamilyPreservation generatedOriginalContext
      generatedInventory {prefix}Certificate :=
  {prefix}Provider.toFamilyPreservation
"""


def _runtime_address_expr_lean(expression: Mapping[str, Any]) -> str | None:
    operation = expression.get("op")
    if operation in {"reg", "input_reg"}:
        register = expression.get("name", expression.get("reg"))
        if register not in {
            "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
        }:
            return None
        return f"Expr.inputReg .{register}"
    if operation in {"const", "constant"}:
        value = expression.get("value")
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or not 0 <= value <= 0xFFFFFFFF
        ):
            return None
        return f"Expr.constant {value}"
    binary = {
        "add": "add",
        "add32": "add",
        "sub": "sub",
        "sub32": "sub",
        "subtract": "sub",
    }.get(operation)
    if binary is not None:
        arguments = expression.get("args")
        if (
            not isinstance(arguments, list)
            or len(arguments) != 2
            or not all(isinstance(argument, dict) for argument in arguments)
        ):
            return None
        left = _runtime_address_expr_lean(arguments[0])
        right = _runtime_address_expr_lean(arguments[1])
        if left is None or right is None:
            return None
        return f"Expr.{binary} ({left}) ({right})"
    if operation in {"load", "read32"}:
        address = expression.get("address")
        if address is None:
            arguments = expression.get("args")
            if isinstance(arguments, list) and len(arguments) == 1:
                address = arguments[0]
        if not isinstance(address, dict):
            return None
        nested = _runtime_address_expr_lean(address)
        return None if nested is None else f"Expr.read32 ({nested})"
    return None


def _runtime_memory_proposal_inventory(
    paths: Mapping[str, Path],
    documents: Mapping[str, Mapping[str, Any]],
    *,
    primary_hashes: Mapping[str, str],
    targets: Sequence[TargetEffectRef],
) -> RuntimeMemoryProposalInventory | None:
    matches = [
        (name, paths[name], document)
        for name, document in documents.items()
        if document.get("format") == _RUNTIME_MEMORY_CHECK_INPUTS_FORMAT
    ]
    if len(matches) > 1:
        raise GnuHelloOriginalTargetPreservationError(
            "multiple runtime-memory check-input artifacts were supplied"
        )
    if not matches:
        return None
    _name, check_path, check = matches[0]
    proposal_ref = _object(check.get("proposal"), "runtime check proposal")
    proposal_name = _string(proposal_ref.get("path"), "runtime proposal.path")
    proposal_path = check_path.parent / proposal_name
    expected_proposal_hash = _digest(
        proposal_ref.get("sha256"), "runtime proposal.sha256"
    )
    if _sha256(proposal_path) != expected_proposal_hash:
        raise GnuHelloOriginalTargetPreservationError(
            "runtime-memory check input does not bind its exact proposal"
        )
    proposal = _load_object(proposal_path, "runtime-memory proposal")
    _require_format(
        proposal, _RUNTIME_MEMORY_PROPOSAL_FORMAT, "runtime-memory proposal"
    )
    check_binding = _digest(
        check.get("artifact_binding_sha256"),
        "runtime check artifact_binding_sha256",
    )
    proposal_binding = _digest(
        proposal.get("artifact_binding_sha256"),
        "runtime proposal artifact_binding_sha256",
    )
    if check_binding != proposal_binding:
        raise GnuHelloOriginalTargetPreservationError(
            "runtime-memory check input and proposal have different bindings"
        )
    runtime_inputs = _object(proposal.get("inputs"), "runtime proposal inputs")
    _validate_proposal_primary_hashes(
        runtime_inputs,
        primary_hashes,
        "runtime-memory proposal",
    )
    rebound = {
        name: _digest(
            (_object(value, f"runtime proposal inputs.{name}").get("sha256")),
            f"runtime proposal inputs.{name}.sha256",
        )
        for name, value in runtime_inputs.items()
    }
    if _value_sha256(dict(sorted(rebound.items()))) != proposal_binding:
        raise GnuHelloOriginalTargetPreservationError(
            "runtime-memory artifact binding does not match its input hashes"
        )

    check_targets = {
        _natural(row.get("target_id"), "runtime check target_id"): row
        for row in (
            _object(value, "runtime check target")
            for value in _list(check.get("targets"), "runtime check targets")
        )
    }
    proposal_targets = {
        _natural(row.get("target_id"), "runtime proposal target_id"): row
        for row in (
            _object(value, "runtime proposal target")
            for value in _list(proposal.get("targets"), "runtime proposal targets")
        )
    }
    exact_ids = [target.target_id for target in targets]
    if sorted(check_targets) != exact_ids or sorted(proposal_targets) != exact_ids:
        raise GnuHelloOriginalTargetPreservationError(
            "runtime-memory artifacts do not cover the exact target inventory"
        )
    result: dict[int, RuntimeTargetProposal] = {}
    for target in targets:
        checked_row = check_targets[target.target_id]
        proposed_row = proposal_targets[target.target_id]
        for label, row in (("check", checked_row), ("proposal", proposed_row)):
            if _word(row.get("source_rva"), f"runtime {label} source_rva") != target.source_rva:
                raise GnuHelloOriginalTargetPreservationError(
                    f"runtime-memory {label} row {target.target_id} has the wrong source RVA"
                )
        requirement_hash = _digest(
            checked_row.get("requirement_sha256"),
            f"runtime check target {target.target_id} requirement_sha256",
        )
        if requirement_hash != _digest(
            proposed_row.get("requirement_sha256"),
            f"runtime proposal target {target.target_id} requirement_sha256",
        ):
            raise GnuHelloOriginalTargetPreservationError(
                f"runtime-memory target {target.target_id} has mismatched requirements"
            )
        target_blockers = [
            _object(value, f"runtime target {target.target_id} blocker")
            for value in _list(
                proposed_row.get("blockers"),
                f"runtime target {target.target_id} blockers",
            )
        ]
        reasons = tuple(
            sorted(
                {
                    _string(blocker.get("reason_code"), "runtime blocker reason")
                    for blocker in target_blockers
                }
            )
        )
        writes: list[RuntimeWriteProposal] = []
        for index, value in enumerate(
            _list(proposed_row.get("writes"), f"runtime target {target.target_id} writes")
        ):
            row = _object(value, f"runtime target {target.target_id} write {index}")
            write_id = _string(row.get("write_id"), "runtime write_id")
            address = _object(row.get("address_expression"), "runtime address_expression")
            if _digest(
                row.get("address_expression_sha256"),
                "runtime address_expression_sha256",
            ) != _value_sha256(address):
                raise GnuHelloOriginalTargetPreservationError(
                    f"runtime write {write_id} does not bind its address expression"
                )
            provenance = _object(row.get("provenance"), "runtime provenance")
            write_reasons = tuple(
                sorted(
                    {
                        _string(blocker.get("reason_code"), "runtime write blocker")
                        for blocker in target_blockers
                        if blocker.get("write_id") == write_id
                    }
                )
            )
            if _runtime_address_expr_lean(address) is None:
                write_reasons = tuple(
                    sorted(
                        set(write_reasons)
                        | {"unsupported_checked_address_expression"}
                    )
                )
                reasons = tuple(
                    sorted(set(reasons) | {"unsupported_checked_address_expression"})
                )
            width = _positive(
                row.get("width"), f"runtime write {write_id}.width"
            )
            if target.kind == "ordinary" and width != 4:
                write_reasons = tuple(
                    sorted(
                        set(write_reasons)
                        | {"ordinary_normalized_write_width_not_four"}
                    )
                )
                reasons = tuple(
                    sorted(
                        set(reasons)
                        | {"ordinary_normalized_write_width_not_four"}
                    )
                )
            writes.append(
                RuntimeWriteProposal(
                    write_id=write_id,
                    width=width,
                    address_expression=address,
                    provenance_class=_string(
                        provenance.get("class"), f"runtime write {write_id}.class"
                    ),
                    blocked_reasons=write_reasons,
                )
            )
        check_write_ids = [
            _string(value, "runtime check write_id")
            for value in _list(
                checked_row.get("write_ids"),
                f"runtime check target {target.target_id} write_ids",
            )
        ]
        if check_write_ids != [write.write_id for write in writes]:
            raise GnuHelloOriginalTargetPreservationError(
                f"runtime-memory target {target.target_id} write inventory differs"
            )
        declared_ready = _boolean(
            checked_row.get("ready_for_lean_check"),
            f"runtime check target {target.target_id} ready_for_lean_check",
        )
        proposal_ready = _boolean(
            proposed_row.get("ready_for_lean_check"),
            f"runtime proposal target {target.target_id} ready_for_lean_check",
        )
        if declared_ready != proposal_ready:
            raise GnuHelloOriginalTargetPreservationError(
                f"runtime-memory target {target.target_id} has inconsistent readiness"
            )
        result[target.target_id] = RuntimeTargetProposal(
            target_id=target.target_id,
            source_rva=target.source_rva,
            writes=tuple(writes),
            ready_for_lean_check=declared_ready and not reasons,
            blocked_reasons=reasons,
        )
    return RuntimeMemoryProposalInventory(check_path, proposal_path, result)


def _control_proposal_inventory(
    paths: Mapping[str, Path],
    documents: Mapping[str, Mapping[str, Any]],
    *,
    primary_hashes: Mapping[str, str],
    targets: Sequence[TargetEffectRef],
) -> ControlProposalInventory | None:
    matches = [
        (name, paths[name], document)
        for name, document in documents.items()
        if document.get("format") == _CONTROL_EVIDENCE_FORMAT
    ]
    if len(matches) > 1:
        raise GnuHelloOriginalTargetPreservationError(
            "multiple control-evidence manifests were supplied"
        )
    if not matches:
        return None
    _name, manifest_path, manifest = matches[0]
    _validate_proposal_primary_hashes(
        _object(manifest.get("inputs"), "control manifest inputs"),
        primary_hashes,
        "control-evidence manifest",
    )
    declarations_path = manifest_path.parent / _string(
        manifest.get("declarations"), "control manifest declarations"
    )
    blockers_path = manifest_path.parent / _string(
        manifest.get("blockers"), "control manifest blockers"
    )
    declarations = _load_object(declarations_path, "control declarations")
    blockers = _load_object(blockers_path, "control blockers")
    _require_format(
        declarations, _CONTROL_DECLARATIONS_FORMAT, "control declarations"
    )
    _require_format(blockers, _CONTROL_BLOCKERS_FORMAT, "control blockers")
    blocker_rows = [
        _object(value, "control blocker")
        for value in _list(blockers.get("blockers"), "control blockers.blockers")
    ]
    blockers_by_target: dict[int, str] = {}
    for row in blocker_rows:
        target_id = _natural(row.get("target_id"), "control blocker target_id")
        reason = _string(row.get("reason_code"), "control blocker reason_code")
        if target_id in blockers_by_target:
            raise GnuHelloOriginalTargetPreservationError(
                f"control evidence repeats blocker target {target_id}"
            )
        blockers_by_target[target_id] = reason
    declaration_rows = {
        _natural(row.get("target_id"), "control target_id"): row
        for row in (
            _object(value, "control declaration target")
            for value in _list(declarations.get("targets"), "control declaration targets")
        )
    }
    exact_ids = [target.target_id for target in targets]
    if sorted(declaration_rows) != exact_ids:
        raise GnuHelloOriginalTargetPreservationError(
            "control evidence does not cover the exact target inventory"
        )
    result: dict[int, ControlTargetProposal] = {}
    for target in targets:
        row = declaration_rows[target.target_id]
        if _word(row.get("source_rva"), "control source_rva") != target.source_rva:
            raise GnuHelloOriginalTargetPreservationError(
                f"control target {target.target_id} has the wrong source RVA"
            )
        module = _string(row.get("module"), "control module")
        declarations_checked = {
            field: _string(row.get(field), f"control {field}")
            for field in (
                "checked_transition",
                "reachability_post",
                "call_frame_post",
            )
        }
        for field, declaration in declarations_checked.items():
            _lean_ref(
                {"module": module, "declaration": declaration},
                f"control target {target.target_id}.{field}",
            )
        blocker_reason = blockers_by_target.get(target.target_id)
        row_reason = row.get("blocker_reason")
        if row_reason is not None and _string(row_reason, "control blocker_reason") != blocker_reason:
            raise GnuHelloOriginalTargetPreservationError(
                f"control target {target.target_id} blocker inventories differ"
            )
        result[target.target_id] = ControlTargetProposal(
            target_id=target.target_id,
            source_rva=target.source_rva,
            control_class=_string(row.get("control_class"), "control class"),
            module=module,
            checked_transition=declarations_checked["checked_transition"],
            reachability_post=declarations_checked["reachability_post"],
            call_frame_post=declarations_checked["call_frame_post"],
            blocker_reason=blocker_reason,
        )
    unknown_blockers = sorted(set(blockers_by_target) - set(result))
    if unknown_blockers:
        raise GnuHelloOriginalTargetPreservationError(
            f"control evidence blockers name unknown targets {unknown_blockers[:16]}"
        )
    return ControlProposalInventory(
        manifest_path, declarations_path, blockers_path, result
    )


def _validate_proposal_primary_hashes(
    inputs: Mapping[str, Any],
    primary_hashes: Mapping[str, str],
    label: str,
) -> None:
    aliases = {
        "state_machine": "state_machine",
        "source_target_effect_declarations": "source_target_effect_declarations",
        "transition_index_manifest": "transition_index_manifest",
        "combined_target_inventory": "combined_inventory_manifest",
        "combined_inventory_manifest": "combined_inventory_manifest",
    }
    required = {"state_machine", "source_target_effect_declarations"}
    matched: set[str] = set()
    for field, primary in aliases.items():
        if field not in inputs:
            continue
        value = inputs[field]
        digest = value.get("sha256") if isinstance(value, dict) else value
        if _digest(digest, f"{label} inputs.{field}") != primary_hashes[primary]:
            raise GnuHelloOriginalTargetPreservationError(
                f"{label} does not bind exact {primary}"
            )
        matched.add(primary)
    if not required <= matched:
        raise GnuHelloOriginalTargetPreservationError(
            f"{label} does not bind required inputs {sorted(required - matched)}"
        )


def _value_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


def _preservation_context(
    documents: Mapping[str, Mapping[str, Any]], hashes: Mapping[str, str]
) -> PreservationContext | None:
    matches = [
        document
        for document in documents.values()
        if document.get("format") == _CONTEXT_FORMAT
    ]
    if len(matches) > 1:
        raise GnuHelloOriginalTargetPreservationError(
            "multiple preservation contexts were supplied"
        )
    if not matches:
        return None
    context = matches[0]
    forbidden = set(context) & _FORBIDDEN_AUTHORITY_FIELDS
    if forbidden:
        raise GnuHelloOriginalTargetPreservationError(
            f"preservation context contains forbidden authority fields {sorted(forbidden)}"
        )
    inputs = _object(context.get("inputs"), "preservation context inputs")
    _validate_known_input_hashes(inputs, hashes, "preservation context")
    declarations = _object(context.get("declarations"), "preservation declarations")
    required = {"source_program", "instruction_semantics_adequate"}
    missing = required - set(declarations)
    if missing:
        raise GnuHelloOriginalTargetPreservationError(
            f"preservation context lacks declarations {sorted(missing)}"
        )
    return PreservationContext(
        source_program=_lean_ref(declarations["source_program"], "source_program"),
        instruction_semantics_adequate=_lean_ref(
            declarations["instruction_semantics_adequate"],
            "instruction_semantics_adequate",
        ),
    )


def _transition_preservation_context(
    transition: Mapping[str, Any],
) -> PreservationContext | None:
    exports_value = transition.get("exports")
    if exports_value is None:
        return None
    exports = _object(exports_value, "transition exports")
    required = {"exact_source_program", "instruction_semantics_adequate"}
    if not required <= set(exports):
        raise GnuHelloOriginalTargetPreservationError(
            "transition index must export exact_source_program and "
            "instruction_semantics_adequate together"
        )
    module = "StageA.GeneratedGnuHelloSourceTransitionIndex"
    source = _string(
        exports["exact_source_program"],
        "transition exports.exact_source_program",
    )
    adequate = _string(
        exports["instruction_semantics_adequate"],
        "transition exports.instruction_semantics_adequate",
    )
    for label, declaration in (("source program", source), ("adequacy", adequate)):
        if not declaration.startswith("StageA.") or _LEAN_LOCAL.fullmatch(
            declaration.rsplit(".", 1)[-1]
        ) is None:
            raise GnuHelloOriginalTargetPreservationError(
                f"transition {label} export is not a canonical Lean declaration"
            )
    return PreservationContext(
        source_program=LeanRef(module=module, declaration=source),
        instruction_semantics_adequate=LeanRef(
            module=module,
            declaration=adequate,
        ),
    )


def _reject_supplied_post_evidence(
    documents: Mapping[str, Mapping[str, Any]],
) -> None:
    for name, document in documents.items():
        artifact_format = document.get("format")
        rows = document.get("targets")
        has_components = isinstance(rows, list) and any(
            isinstance(row, dict) and "components" in row for row in rows
        )
        if (
            artifact_format == "stage-a-original-target-structured-post-evidence-v1"
            or has_components
        ):
            raise GnuHelloOriginalTargetPreservationError(
                f"authority artifact {name} supplies structured post evidence; "
                "the production generator must derive it autonomously"
            )


def _artifact_needs(
    *,
    targets: Sequence[TargetEffectRef],
    classes: Mapping[int, TargetClass],
    inventory_counts: Mapping[str, Any],
    missing_counts: Mapping[str, int],
    runtime_memory: RuntimeMemoryProposalInventory | None,
    control: ControlProposalInventory | None,
) -> dict[str, Any]:
    def selected(predicate: Callable[[TargetClass], bool]) -> list[int]:
        return [
            target.target_id
            for target in targets
            if predicate(classes[target.target_id])
        ]

    all_targets = [target.target_id for target in targets]
    write_targets = selected(lambda value: value.memory not in {"none", "read_only"})
    runtime_write_targets = selected(
        lambda value: value.memory
        in {"stack_writes", "dynamic_writes", "symbolic_writes"}
    )
    static_write_targets = selected(lambda value: value.memory == "static_writes")
    external_targets = selected(lambda value: value.external)
    indirect_targets = selected(lambda value: value.indirect)
    x87_targets = selected(lambda value: value.semantic == "x87")
    ordinary_count = len(targets) - len(x87_targets)
    return {
        "format": GNU_HELLO_ORIGINAL_TARGET_PRESERVATION_NEEDS_FORMAT,
        "proof_authority": False,
        "acceptance_authority": False,
        "goal": (
            "autonomously construct CheckedOriginalTargetPreservationProvider "
            "for every exact reachable target"
        ),
        "currently_emitted": {
            "checked_target_effects": len(targets),
            "active_transition_certificates": len(targets),
            "checked_normalized_transition_effects": ordinary_count,
            "checked_runtime_memory_preconditions": len(targets),
            "runtime_memory_check_inputs": (
                len(runtime_memory.targets) if runtime_memory is not None else 0
            ),
            "runtime_write_proposals_bound_to_normalized_effects": (
                sum(
                    target.kind == "ordinary"
                    and runtime_memory.targets[target.target_id].ready_for_lean_check
                    for target in targets
                )
                if runtime_memory is not None
                else 0
            ),
            "control_check_inputs": (
                len(control.targets) if control is not None else 0
            ),
            "control_proposals_without_input_blockers": (
                sum(
                    target.blocker_reason is None
                    for target in control.targets.values()
                )
                if control is not None
                else 0
            ),
            "structured_post_evidence": 0,
            "providers": 0,
        },
        "inventory_counts": {
            name: _natural(inventory_counts.get(name, 0), f"combined counts.{name}")
            for name in (
                "static_word_slots",
                "value_flow_facts",
                "register_requirements",
                "stack_dynamic_requirements",
            )
        },
        "missing_by_family": dict(sorted(missing_counts.items())),
        "required_artifacts": [
            {
                "id": "checked_normalized_transition_effects",
                "target_ids": x87_targets,
                "purpose": (
                    "bind x87 memory/register effects to each exact physical x87 "
                    "successor; ordinary summaries are emitted autonomously"
                ),
                "lean_consumer": (
                    "CheckedOriginalTargetProvenanceEffects and "
                    "CheckedOriginalTargetControlEvidence"
                ),
            },
            {
                "id": "checked_control_and_frame_routing",
                "target_ids": all_targets,
                "purpose": (
                    "derive exact direct, branch, call, return, external, and finite "
                    "indirect successors plus relational call-frame transitions"
                ),
                "lean_consumer": "CheckedOriginalTargetControlEvidence",
            },
            {
                "id": "checked_memory_effect_posts",
                "target_ids": all_targets,
                "write_target_ids": write_targets,
                "purpose": (
                    "emit the unchanged post for no-write transitions and cover every "
                    "protected static word on writes by checked disjointness or an "
                    "explicit related replacement"
                ),
                "lean_consumer": "OriginalMemoryEffectInventoryEvidence",
            },
            {
                "id": "checked_runtime_write_membership",
                "target_ids": runtime_write_targets,
                "purpose": (
                    "bind each exact evaluated write address and byte width to one "
                    "declared active stack or dynamic range; the combined invariant "
                    "already checks range partitioning, PE disjointness, and wraparound"
                ),
                "lean_consumer": (
                    "OriginalRuntimeAccessWitness and "
                    "normalizedWritesAvoidWordChecked_of_runtimePartition"
                ),
            },
            {
                "id": "checked_static_related_updates",
                "target_ids": static_write_targets,
                "purpose": (
                    "classify each concrete image write as disjoint or establish the "
                    "new finite value-origin relation"
                ),
                "lean_consumer": "OriginalWordEffectEvidence.relatedUpdate",
            },
            {
                "id": "machine_external_call_contracts",
                "target_ids": external_targets,
                "purpose": (
                    "bind import identity, ABI, bounded memory footprints, results, "
                    "world updates, and continuation routing"
                ),
                "lean_consumer": "CheckedOriginalExternalMemoryPreservationInputs",
            },
            {
                "id": "finite_indirect_exit_certificates",
                "target_ids": indirect_targets,
                "purpose": (
                    "prove target-expression evaluation and completeness of every "
                    "feasible indirect destination"
                ),
                "lean_consumer": "IndirectExitCertificate",
            },
            {
                "id": "checked_provenance_posts",
                "target_ids": all_targets,
                "purpose": (
                    "transport or establish every value-flow, register-target, and "
                    "stack/dynamic-target endpoint selected by the successor"
                ),
                "lean_consumer": "CheckedOriginalProvenancePostWitness",
            },
        ],
    }


def _authority_sites(
    documents: Mapping[str, Mapping[str, Any]],
) -> dict[int, set[str]]:
    result: dict[int, set[str]] = defaultdict(set)
    for document in documents.values():
        artifact_format = document.get("format")
        if artifact_format not in _INDIRECT_AUTHORITY_FORMATS:
            continue
        rows = document.get("sites")
        if not isinstance(rows, list):
            continue
        for raw in rows:
            if not isinstance(raw, dict):
                continue
            rva = raw.get("source_rva", raw.get("instruction_rva"))
            if (
                isinstance(rva, int)
                and not isinstance(rva, bool)
                and 0 <= rva <= 0xFFFFFFFF
            ):
                result[rva].add(artifact_format)
    return result


def _validate_known_input_hashes(
    inputs: Mapping[str, Any], hashes: Mapping[str, str], label: str
) -> None:
    aliases = {
        "state_machine": "state_machine",
        "state_machine_sha256": "state_machine",
        "source_target_effect_declarations": "source_target_effect_declarations",
        "source_target_effect_declarations_sha256": "source_target_effect_declarations",
        "transition_index_manifest": "transition_index_manifest",
        "transition_index_manifest_sha256": "transition_index_manifest",
        "combined_inventory_manifest": "combined_inventory_manifest",
        "combined_inventory_manifest_sha256": "combined_inventory_manifest",
    }
    matched: set[str] = set()
    for field, primary in aliases.items():
        if field not in inputs:
            continue
        value = inputs[field]
        digest = value.get("sha256") if isinstance(value, dict) else value
        if _digest(digest, f"{label} inputs.{field}") != hashes[primary]:
            raise GnuHelloOriginalTargetPreservationError(
                f"{label} does not bind exact {primary}"
            )
        matched.add(primary)
    required = {
        "source_target_effect_declarations",
        "transition_index_manifest",
        "combined_inventory_manifest",
    }
    if not required <= matched:
        raise GnuHelloOriginalTargetPreservationError(
            f"{label} does not bind required inputs {sorted(required - matched)}"
        )


def _validate_transition_binding(
    transition: Mapping[str, Any], declarations_hash: str, target_count: int
) -> None:
    inputs = _object(transition.get("inputs"), "transition inputs")
    declaration = _object(
        inputs.get("declaration_inventory"),
        "transition inputs.declaration_inventory",
    )
    if _digest(declaration.get("sha256"), "transition declaration hash") != declarations_hash:
        raise GnuHelloOriginalTargetPreservationError(
            "transition index does not bind exact target-effect declarations"
        )
    counts = _object(transition.get("counts"), "transition counts")
    if _natural(counts.get("targets"), "transition counts.targets") != target_count:
        raise GnuHelloOriginalTargetPreservationError(
            "transition target count differs from effect declarations"
        )


def _validate_inventory_counts(
    combined: Mapping[str, Any], targets: Sequence[TargetEffectRef]
) -> None:
    counts = _object(combined.get("counts"), "combined counts")
    if _natural(counts.get("reachable_targets"), "combined reachable_targets") != len(targets):
        raise GnuHelloOriginalTargetPreservationError(
            "combined inventory reachable-target count differs from effects"
        )
    lean = _object(combined.get("lean"), "combined lean")
    for field in ("module", "inventory", "original_context"):
        _string(lean.get(field), f"combined lean.{field}")


def _state_machine_rows(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise GnuHelloOriginalTargetPreservationError(
            f"cannot read state machine: {error}"
        ) from error
    rows: list[dict[str, Any]] = []
    for index, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            rows.append(_object(json.loads(line), f"state-machine row {index}"))
        except json.JSONDecodeError as error:
            raise GnuHelloOriginalTargetPreservationError(
                f"state-machine row {index} is invalid JSON: {error}"
            ) from error
    if not rows:
        raise GnuHelloOriginalTargetPreservationError("state machine is empty")
    return rows


def _rows_by_rva(rows: Sequence[Mapping[str, Any]]) -> dict[int, Mapping[str, Any]]:
    result: dict[int, Mapping[str, Any]] = {}
    for index, row in enumerate(rows):
        original = _object(row.get("original"), f"state row {index}.original")
        rva = _word(original.get("rva_start"), f"state row {index}.rva_start")
        if rva in result:
            raise GnuHelloOriginalTargetPreservationError(
                f"state machine repeats source RVA 0x{rva:x}"
            )
        result[rva] = row
    return result


def _address_uses_stack(expression: Mapping[str, Any]) -> bool:
    if expression.get("op") == "reg" and expression.get("name") in {"esp", "ebp"}:
        return True
    args = expression.get("args")
    return isinstance(args, list) and any(
        isinstance(arg, dict) and _address_uses_stack(arg) for arg in args
    )


def _authority_name(value: object) -> str:
    if not isinstance(value, str) or _LEAN_LOCAL.fullmatch(value) is None:
        raise GnuHelloOriginalTargetPreservationError(
            "authority artifact names must be Lean-style local identifiers"
        )
    return value


def _lean_ref(value: object, label: str) -> LeanRef:
    try:
        return LeanRef.from_json(value, label)
    except StageAInputError as error:
        raise GnuHelloOriginalTargetPreservationError(str(error)) from error


def _imports(modules: Sequence[str]) -> str:
    return "\n".join(f"import {module}" for module in modules)


def _load_object(path: Path, label: str) -> dict[str, Any]:
    try:
        return _object(json.loads(path.read_text(encoding="utf-8")), label)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise GnuHelloOriginalTargetPreservationError(
            f"cannot read {label}: {error}"
        ) from error


def _sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise GnuHelloOriginalTargetPreservationError(
            f"cannot hash input {path}: {error}"
        ) from error


def _remove_stale_outputs(root: Path) -> None:
    for name in (
        "original-target-preservation-declarations.json",
        "original-target-preservation-frontier.json",
        "original-target-preservation-needs.json",
        "original-target-preservation.json",
    ):
        path = root / name
        if path.exists():
            path.unlink()
    stage_a = root / "StageA"
    if stage_a.is_dir():
        for path in stage_a.glob(f"{_MODULE_PREFIX}*.lean"):
            path.unlink()


def _write_ascii(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="ascii")


def _write_json(path: Path, value: object) -> None:
    _write_ascii(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def _require_format(document: Mapping[str, Any], expected: str, label: str) -> None:
    if document.get("format") != expected:
        raise GnuHelloOriginalTargetPreservationError(
            f"{label} has unsupported format"
        )


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GnuHelloOriginalTargetPreservationError(f"{label} must be an object")
    return value


def _list(value: object, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise GnuHelloOriginalTargetPreservationError(f"{label} must be a list")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise GnuHelloOriginalTargetPreservationError(
            f"{label} must be a nonempty string"
        )
    return value


def _natural(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise GnuHelloOriginalTargetPreservationError(
            f"{label} must be a natural number"
        )
    return value


def _positive(value: object, label: str) -> int:
    result = _natural(value, label)
    if result == 0:
        raise GnuHelloOriginalTargetPreservationError(f"{label} must be positive")
    return result


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise GnuHelloOriginalTargetPreservationError(
            f"{label} must be a boolean"
        )
    return value


def _word(value: object, label: str) -> int:
    result = _natural(value, label)
    if result > 0xFFFFFFFF:
        raise GnuHelloOriginalTargetPreservationError(
            f"{label} must fit in a 32-bit word"
        )
    return result


def _digest(value: object, label: str) -> str:
    result = _string(value, label)
    if _SHA256.fullmatch(result) is None:
        raise GnuHelloOriginalTargetPreservationError(
            f"{label} must be a SHA-256 digest"
        )
    return result


__all__ = [
    "GNU_HELLO_ORIGINAL_TARGET_PRESERVATION_DECLARATIONS_FORMAT",
    "GNU_HELLO_ORIGINAL_TARGET_PRESERVATION_FORMAT",
    "GNU_HELLO_ORIGINAL_TARGET_PRESERVATION_FRONTIER_FORMAT",
    "GNU_HELLO_ORIGINAL_TARGET_PRESERVATION_NEEDS_FORMAT",
    "GeneratedOriginalTargetPreservation",
    "GnuHelloOriginalTargetPreservationError",
    "TargetClass",
    "generate_gnu_hello_original_target_preservation",
]

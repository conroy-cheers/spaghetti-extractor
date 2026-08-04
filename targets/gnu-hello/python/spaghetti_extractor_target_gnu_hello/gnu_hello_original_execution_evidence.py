"""Assemble GNU hello inputs for the generic original-execution producer.

The GNU-specific part of this module is limited to artifact plumbing: it
cross-checks the already generated finite inventories and the 31 diagnostic
frontier identities expected by the existing GNU source-execution adapter.
All transition, effect, preservation, external-response, and launch claims are
exact Lean declarations consumed by :mod:`original_execution_evidence`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .gnu_hello_source_execution import (
    GNU_HELLO_SOURCE_EXECUTION_EVIDENCE_FORMAT,
    assemble_gnu_hello_source_execution_spec,
)
from .gnu_hello_source_transition_index import (
    GNU_HELLO_SOURCE_TRANSITION_MODULE,
    GNU_HELLO_SOURCE_TRANSITION_OUTPUT_FORMAT,
)
from .gnu_hello_original_combined_inventory import (
    ORIGINAL_COMBINED_INVENTORY_MANIFEST_FORMAT,
)
from spaghetti_extractor.relational.lean.original_execution_evidence import (
    ORIGINAL_EXECUTION_PRESERVATION_INPUTS_FORMAT,
    FrontierProjection,
    GeneratedOriginalExecutionEvidence,
    LeanRef,
    OriginalExecutionEvidenceError,
    OriginalExecutionEvidenceSpec,
    TargetEffect,
    TargetPreservation,
    generate_original_execution_evidence,
    sha256_file,
)


GNU_HELLO_ORIGINAL_EXECUTION_EVIDENCE_FORMAT = (
    "stage-a-gnu-hello-original-execution-evidence-v1"
)
_TARGET_EFFECT_DECLARATIONS_FORMAT = (
    "stage-a-gnu-hello-source-transition-index-declarations-v1"
)


@dataclass(frozen=True)
class GeneratedGnuHelloOriginalExecutionEvidence:
    proof: GeneratedOriginalExecutionEvidence
    source_execution_evidence: Path
    manifest: Path


def generate_gnu_hello_original_execution_evidence(
    out: Path | str,
    *,
    combined_inventory_manifest: Path | str,
    source_target_effect_declarations: Path | str,
    transition_index_manifest: Path | str,
    preservation_inputs: Path | str,
    mixed_original_plan: Path | str,
    writable_authority_report: Path | str,
    register_authority_report: Path | str,
    stack_dynamic_authority_report: Path | str,
) -> GeneratedGnuHelloOriginalExecutionEvidence:
    """Generate checked target/external/launch evidence and compatibility data."""

    paths = {
        "combined_inventory_manifest": Path(combined_inventory_manifest),
        "source_target_effect_declarations": Path(
            source_target_effect_declarations
        ),
        "transition_index_manifest": Path(transition_index_manifest),
        "preservation_inputs": Path(preservation_inputs),
        "mixed_original_plan": Path(mixed_original_plan),
        "writable_authority_report": Path(writable_authority_report),
        "register_authority_report": Path(register_authority_report),
        "stack_dynamic_authority_report": Path(
            stack_dynamic_authority_report
        ),
    }
    documents = {name: _load(path, name) for name, path in paths.items()}
    hashes = {name: sha256_file(path) for name, path in paths.items()}

    combined = documents["combined_inventory_manifest"]
    effects = documents["source_target_effect_declarations"]
    transition = documents["transition_index_manifest"]
    authority = documents["preservation_inputs"]
    _format(
        combined,
        ORIGINAL_COMBINED_INVENTORY_MANIFEST_FORMAT,
        "combined inventory manifest",
    )
    _format(
        effects,
        _TARGET_EFFECT_DECLARATIONS_FORMAT,
        "source target-effect declarations",
    )
    _format(
        transition,
        GNU_HELLO_SOURCE_TRANSITION_OUTPUT_FORMAT,
        "transition-index manifest",
    )
    _format(
        authority,
        ORIGINAL_EXECUTION_PRESERVATION_INPUTS_FORMAT,
        "preservation inputs",
    )

    _validate_authority_bindings(authority, hashes)
    combined_refs = _combined_refs(combined)
    transition_refs = _transition_refs(transition)
    effects_by_target = _effects(effects)
    declarations = _declarations(authority)
    targets = _targets(authority, effects_by_target)
    frontiers = _frontiers(authority)

    combined_count = _count(combined, "reachable_targets", "combined inventory")
    transition_count = _count(transition, "targets", "transition index")
    if combined_count != transition_count or combined_count != len(targets):
        raise OriginalExecutionEvidenceError(
            "reachable target counts differ across combined inventory, "
            "transition index, effects, and preservation evidence"
        )

    spec = OriginalExecutionEvidenceSpec(
        namespace=_string(authority.get("namespace"), "namespace"),
        module_prefix=_string(authority.get("module_prefix"), "module_prefix"),
        shard_size=_positive(authority.get("shard_size"), "shard_size"),
        source_program=declarations["source_program"],
        original_context=combined_refs["original_context"],
        inventory=combined_refs["inventory"],
        exact_binding=transition_refs["exact_binding"],
        transition_index=transition_refs["transition_index"],
        target_ids_exact=declarations["target_ids_exact"],
        instruction_semantics_adequate=declarations[
            "instruction_semantics_adequate"
        ],
        protocol_responses=declarations["protocol_responses"],
        project=declarations["project"],
        launch_inventory_holds=declarations["launch_inventory_holds"],
        launch_realizable=declarations["launch_realizable"],
        compatibility_program_record_kernel_matches=declarations[
            "compatibility_program_record_kernel_matches"
        ],
        targets=targets,
        frontiers=frontiers,
        input_hashes=tuple(sorted(hashes.items())),
    )

    root = Path(out)
    root.mkdir(parents=True, exist_ok=True)
    proof = generate_original_execution_evidence(root, spec)
    proof_manifest = _load(proof.manifest, "generated proof manifest")
    exports = _object(proof_manifest.get("exports"), "proof exports")
    fact_names = {
        "project",
        "combined_invariant",
        "target_ids",
        "target_ids_unique",
        "reachability_projection",
        "target_round_trips",
        "invariant_at_launch",
        "exact_binding",
        "instruction_semantics_adequate",
        "program_record_kernel_matches",
        "launch_realizable",
    }
    if not fact_names.issubset(exports):
        raise OriginalExecutionEvidenceError(
            "generated proof exports omit source-execution facts"
        )

    source_inputs = {
        name: hashes[name]
        for name in (
            "mixed_original_plan",
            "writable_authority_report",
            "register_authority_report",
            "stack_dynamic_authority_report",
        )
    }
    acceptance_module = f"StageA.{spec.module_prefix}"
    source_evidence_value = {
        "format": GNU_HELLO_SOURCE_EXECUTION_EVIDENCE_FORMAT,
        "inputs": source_inputs,
        "facts": {
            name: LeanRef.from_json(exports[name], f"exports.{name}").to_fact_json()
            for name in sorted(fact_names)
        },
        "frontiers": [
            {
                "category": frontier.category,
                "source_rva": frontier.source_rva,
                "source_target_id": frontier.source_target_id,
                "static_authority": frontier.static_authority.to_fact_json(),
                "target_membership": _generated_fact(
                    acceptance_module,
                    spec.namespace,
                    f"generatedFrontier{index:04d}TargetMembership",
                ),
                "running_target_membership": _generated_fact(
                    acceptance_module,
                    spec.namespace,
                    f"generatedFrontier{index:04d}RunningTargetMembership",
                ),
                "callback_target_membership": _generated_fact(
                    acceptance_module,
                    spec.namespace,
                    f"generatedFrontier{index:04d}CallbackTargetMembership",
                ),
            }
            for index, frontier in enumerate(frontiers)
        ],
    }
    source_evidence = root / "gnu-hello-source-execution-evidence.json"
    _write_json(source_evidence, source_evidence_value)

    # Reuse the existing GNU adapter as an independent strict check of the 31
    # static authority identities and exact report hashes.
    assemble_gnu_hello_source_execution_spec(
        paths["mixed_original_plan"],
        paths["writable_authority_report"],
        paths["register_authority_report"],
        paths["stack_dynamic_authority_report"],
        source_evidence,
    )

    manifest = root / "gnu-hello-original-execution-evidence.json"
    _write_json(
        manifest,
        {
            "format": GNU_HELLO_ORIGINAL_EXECUTION_EVIDENCE_FORMAT,
            "proof_authority": False,
            "acceptance_authority": False,
            "validation_required": (
                "lean-kernel-check-and-detached-axiom-audit"
            ),
            "executes_original_binary": False,
            "executes_candidate_binary": False,
            "inputs": dict(sorted(hashes.items())),
            "counts": {
                "targets": len(targets),
                "frontiers": len(frontiers),
                "target_shards": proof.shard_count,
            },
            "proof_manifest": proof.manifest.name,
            "source_execution_evidence": source_evidence.name,
            "lean": {
                "proof_modules": [
                    f"StageA.{path.stem}" for path in proof.modules
                ],
                "audit_module": f"StageA.{proof.audit.stem}",
                "exports": exports,
            },
        },
    )
    return GeneratedGnuHelloOriginalExecutionEvidence(
        proof=proof,
        source_execution_evidence=source_evidence,
        manifest=manifest,
    )


def _validate_authority_bindings(
    authority: dict[str, Any], hashes: dict[str, str]
) -> None:
    expected_top = {
        "format",
        "namespace",
        "module_prefix",
        "shard_size",
        "inputs",
        "declarations",
        "targets",
        "frontiers",
    }
    _exact_keys(authority, expected_top, "preservation inputs")
    bindings = _object(authority["inputs"], "preservation inputs.inputs")
    expected_names = {
        "combined_inventory_manifest",
        "source_target_effect_declarations",
        "transition_index_manifest",
    }
    _exact_keys(bindings, expected_names, "preservation inputs.inputs")
    for name in expected_names:
        digest = _string(bindings[name], f"inputs.{name}")
        if digest != hashes[name]:
            raise OriginalExecutionEvidenceError(
                f"preservation inputs do not bind exact {name}"
            )


def _combined_refs(document: dict[str, Any]) -> dict[str, LeanRef]:
    lean = _object(document.get("lean"), "combined inventory lean exports")
    module = _string(lean.get("module"), "combined inventory module")
    return {
        name: LeanRef.from_qualified(
            module,
            _string(lean.get(name), f"combined inventory {name}"),
        )
        for name in ("inventory", "original_context")
    }


def _transition_refs(document: dict[str, Any]) -> dict[str, LeanRef]:
    exports = _object(document.get("exports"), "transition-index exports")
    modules = _list(document.get("modules"), "transition-index modules")
    expected_module = GNU_HELLO_SOURCE_TRANSITION_MODULE
    if expected_module not in modules:
        raise OriginalExecutionEvidenceError(
            "transition-index manifest omits its aggregate Lean module"
        )
    module = f"StageA.{expected_module}"
    return {
        "exact_binding": LeanRef.from_qualified(
            module,
            _string(exports.get("concrete_exact_binding"), "exact binding export"),
        ),
        "transition_index": LeanRef.from_qualified(
            module,
            _string(
                exports.get("active_target_transition_index"),
                "active target transition index export",
            ),
        ),
    }


def _effects(document: dict[str, Any]) -> dict[int, TargetEffect]:
    rows = _list(document.get("targets"), "target-effect declarations targets")
    result: dict[int, TargetEffect] = {}
    ordered: list[int] = []
    for index, value in enumerate(rows):
        row = _object(value, f"target effects[{index}]")
        target_id = _natural(row.get("target_id"), f"target effects[{index}].target_id")
        kind = _string(row.get("kind"), f"target effects[{index}].kind")
        evidence = _object(row.get("evidence"), f"target effects[{index}].evidence")
        if kind == "ordinary":
            if "checked_effect" not in evidence:
                raise OriginalExecutionEvidenceError(
                    f"ordinary target {target_id} omits checked effect evidence"
                )
            effect = TargetEffect(
                kind="ordinary",
                ordinary_checked=LeanRef.from_json(
                    evidence["checked_effect"],
                    f"target effects[{index}].checked_effect",
                ),
            )
        elif kind == "x87":
            required = {"facts", "successful_components"}
            if not required.issubset(evidence):
                raise OriginalExecutionEvidenceError(
                    f"x87 target {target_id} omits facts or successful components"
                )
            effect = TargetEffect(
                kind="x87",
                x87_facts=LeanRef.from_json(
                    evidence["facts"], f"target effects[{index}].facts"
                ),
                x87_components=LeanRef.from_json(
                    evidence["successful_components"],
                    f"target effects[{index}].successful_components",
                ),
            )
        else:
            raise OriginalExecutionEvidenceError(
                f"target {target_id} has unsupported effect kind {kind!r}"
            )
        if target_id in result:
            raise OriginalExecutionEvidenceError(
                f"duplicate target-effect evidence for {target_id}"
            )
        effect.validate(f"target effects[{index}]")
        result[target_id] = effect
        ordered.append(target_id)
    if ordered != sorted(ordered):
        raise OriginalExecutionEvidenceError(
            "target-effect declarations must be in target-id order"
        )
    return result


_DECLARATION_NAMES = {
    "source_program",
    "target_ids_exact",
    "instruction_semantics_adequate",
    "protocol_responses",
    "project",
    "launch_inventory_holds",
    "launch_realizable",
    "compatibility_program_record_kernel_matches",
}


def _declarations(document: dict[str, Any]) -> dict[str, LeanRef]:
    rows = _object(document.get("declarations"), "preservation declarations")
    _exact_keys(rows, _DECLARATION_NAMES, "preservation declarations")
    return {
        name: LeanRef.from_json(rows[name], f"declarations.{name}")
        for name in sorted(_DECLARATION_NAMES)
    }


def _targets(
    authority: dict[str, Any], effects: dict[int, TargetEffect]
) -> tuple[TargetPreservation, ...]:
    rows = _list(authority.get("targets"), "preservation targets")
    result: list[TargetPreservation] = []
    for index, value in enumerate(rows):
        row = _object(value, f"preservation targets[{index}]")
        _exact_keys(
            row,
            {"target_id", "certificate", "preservation_cases"},
            f"preservation targets[{index}]",
        )
        target_id = _natural(row["target_id"], f"targets[{index}].target_id")
        if target_id not in effects:
            raise OriginalExecutionEvidenceError(
                f"target {target_id} has preservation but no exact effect evidence"
            )
        target = TargetPreservation(
            target_id=target_id,
            effect=effects[target_id],
            certificate=LeanRef.from_json(
                row["certificate"], f"targets[{index}].certificate"
            ),
            cases=LeanRef.from_json(
                row["preservation_cases"],
                f"targets[{index}].preservation_cases",
            ),
        )
        target.validate(f"targets[{index}]")
        result.append(target)
    target_ids = [target.target_id for target in result]
    if target_ids != sorted(set(target_ids)):
        raise OriginalExecutionEvidenceError(
            "preservation targets must be sorted and duplicate-free"
        )
    missing = sorted(set(effects) - set(target_ids))
    if missing:
        raise OriginalExecutionEvidenceError(
            f"missing target preservation evidence for {missing}"
        )
    return tuple(result)


def _frontiers(authority: dict[str, Any]) -> tuple[FrontierProjection, ...]:
    rows = _list(authority.get("frontiers"), "frontier projections")
    result: list[FrontierProjection] = []
    for index, value in enumerate(rows):
        row = _object(value, f"frontiers[{index}]")
        expected = {
            "category",
            "source_rva",
            "source_target_id",
            "static_authority",
            "target_membership",
            "running_target_membership",
            "callback_target_membership",
        }
        _exact_keys(row, expected, f"frontiers[{index}]")
        frontier = FrontierProjection(
            category=_string(row["category"], f"frontiers[{index}].category"),
            source_rva=_natural(
                row["source_rva"], f"frontiers[{index}].source_rva", word=True
            ),
            source_target_id=_natural(
                row["source_target_id"],
                f"frontiers[{index}].source_target_id",
            ),
            static_authority=LeanRef.from_json(
                row["static_authority"], f"frontiers[{index}].static_authority"
            ),
            target_membership=LeanRef.from_json(
                row["target_membership"],
                f"frontiers[{index}].target_membership",
            ),
            running_target_membership=LeanRef.from_json(
                row["running_target_membership"],
                f"frontiers[{index}].running_target_membership",
            ),
            callback_target_membership=LeanRef.from_json(
                row["callback_target_membership"],
                f"frontiers[{index}].callback_target_membership",
            ),
        )
        frontier.validate(f"frontiers[{index}]")
        result.append(frontier)
    keys = [(row.category, row.source_rva) for row in result]
    if keys != sorted(set(keys)):
        raise OriginalExecutionEvidenceError(
            "frontier projections must be sorted and duplicate-free"
        )
    return tuple(result)


def _generated_fact(module: str, namespace: str, symbol: str) -> dict[str, str]:
    return {"module": module, "namespace": namespace, "symbol": symbol}


def _count(document: dict[str, Any], name: str, label: str) -> int:
    counts = _object(document.get("counts"), f"{label}.counts")
    return _natural(counts.get(name), f"{label}.counts.{name}")


def _format(document: dict[str, Any], expected: str, label: str) -> None:
    if document.get("format") != expected:
        raise OriginalExecutionEvidenceError(f"{label} has unsupported format")


def _load(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise OriginalExecutionEvidenceError(
            f"cannot read {label}: {error}"
        ) from error
    return _object(value, label)


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="ascii"
    )


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise OriginalExecutionEvidenceError(f"{label} must be an object")
    return value


def _list(value: object, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise OriginalExecutionEvidenceError(f"{label} must be a list")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise OriginalExecutionEvidenceError(f"{label} must be a non-empty string")
    return value


def _natural(value: object, label: str, *, word: bool = False) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise OriginalExecutionEvidenceError(f"{label} must be a natural number")
    if word and value > 0xFFFFFFFF:
        raise OriginalExecutionEvidenceError(f"{label} must fit in a 32-bit word")
    return value


def _positive(value: object, label: str) -> int:
    result = _natural(value, label)
    if result == 0:
        raise OriginalExecutionEvidenceError(f"{label} must be positive")
    return result


def _exact_keys(row: dict[str, Any], expected: set[str], label: str) -> None:
    if set(row) != expected:
        raise OriginalExecutionEvidenceError(
            f"{label} fields differ (missing={sorted(expected - set(row))}, "
            f"unexpected={sorted(set(row) - expected)})"
        )


__all__ = [
    "GNU_HELLO_ORIGINAL_EXECUTION_EVIDENCE_FORMAT",
    "GeneratedGnuHelloOriginalExecutionEvidence",
    "generate_gnu_hello_original_execution_evidence",
]

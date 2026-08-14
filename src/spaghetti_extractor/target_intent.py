"""Target-neutral boundary between reviewed intent and generated artifacts.

Files accepted by this module are handwritten declarations. They select facts
from a pinned binary but never contain generated proposal IDs, artifact hashes,
status values, inferred effects, or proof results. Resolution produces the
existing self-bound pipeline artifacts inside a Nix derivation.
"""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from .artifact_formats import (
    COMPONENT_INTERFACE_INTENT_FORMAT,
    GENERATED_ARTIFACT_PROVENANCE_FORMAT,
    LINKED_ISLAND_INTENT_FORMAT,
    LINKED_ISLAND_REVIEW_FORMAT,
    SOURCE_COMPONENT_EVIDENCE_INTENT_FORMAT,
    SOURCE_COMPONENT_EVIDENCE_PLAN_FORMAT,
    SOURCE_PROJECT_INTENT_FORMAT,
    TARGET_BUNDLE_FORMAT,
)
from .component_interface import finalize_component_interface_spec
from .linked_libraries import bind_linked_island_review
from .source_project import (
    bind_source_component_evidence_plan,
    bind_source_project_specification,
)
from .util import sha256_file, write_json


_IDENTIFIER = re.compile(r"[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")

_TARGET_PATH_KINDS = {
    "nix": "single",
    "components": "single",
    "linked_islands": "single",
    "source_projects": "multiple",
    "source_evidence": "multiple",
}

_GENERATED_FIELD_NAMES = frozenset(
    {
        "adapter_effects",
        "artifact_sha256",
        "bindings",
        "blocker_counts",
        "blockers",
        "counts",
        "interface_spec_sha256",
        "membership_bindings_sha256",
        "plan_sha256",
        "proposal_binding_sha256",
        "proposal_id",
        "proposal_set_sha256",
        "refinement_sha256",
        "report_sha256",
        "review_sha256",
        "selection_sha256",
        "specification_sha256",
        "status",
    }
)


class TargetIntentError(ValueError):
    """A handwritten target declaration is malformed or resolves ambiguously."""


@dataclass(frozen=True)
class TargetIdentity:
    target_id: str
    expected_sha256: str

    def validate(self) -> None:
        if _IDENTIFIER.fullmatch(self.target_id) is None:
            raise TargetIntentError("target id must be a lowercase stable identifier")
        if _SHA256.fullmatch(self.expected_sha256) is None:
            raise TargetIntentError("target expected_sha256 must be lowercase SHA-256")


@dataclass(frozen=True)
class TargetBundle:
    root: Path
    identity: TargetIdentity
    display_name: str
    paths: Mapping[str, object]


def load_target_bundle(path: Path | str) -> TargetBundle:
    """Load and validate one handwritten in-tree target bundle."""

    manifest = Path(path)
    if manifest.is_dir():
        manifest = manifest / "target.json"
    payload = _read_object(manifest, "target bundle")
    _require_exact_keys(
        payload,
        {"format", "id", "display_name", "input", "paths"},
        "target bundle",
    )
    if payload.get("format") != TARGET_BUNDLE_FORMAT:
        raise TargetIntentError("unsupported target bundle format")
    target_input = _object(payload.get("input"), "target input")
    _require_exact_keys(
        target_input,
        {"kind", "expected_sha256"},
        "target input",
    )
    if target_input.get("kind") not in {"pe32", "source-archive"}:
        raise TargetIntentError("target input kind must be pe32 or source-archive")
    identity = TargetIdentity(
        target_id=_string(payload.get("id"), "target id"),
        expected_sha256=_string(
            target_input.get("expected_sha256"), "target expected_sha256"
        ),
    )
    identity.validate()
    display_name = _string(payload.get("display_name"), "target display name")
    paths = _object(payload.get("paths"), "target paths")
    unknown_path_labels = sorted(set(paths) - set(_TARGET_PATH_KINDS))
    if unknown_path_labels:
        raise TargetIntentError(
            f"unsupported target path labels: {unknown_path_labels}"
        )
    for label, value in paths.items():
        expected_kind = _TARGET_PATH_KINDS[label]
        if expected_kind == "single" and isinstance(value, str):
            _validate_relative_path(manifest.parent, value, f"target path {label}")
        elif expected_kind == "multiple" and isinstance(value, list):
            for index, item in enumerate(value):
                _validate_relative_path(
                    manifest.parent,
                    _string(item, f"target path {label}[{index}]"),
                    f"target path {label}[{index}]",
                )
        else:
            expected = "a path" if expected_kind == "single" else "a path list"
            raise TargetIntentError(f"target path {label} must be {expected}")
    source_projects = paths.get("source_projects", [])
    source_evidence = paths.get("source_evidence", [])
    if source_evidence and not source_projects:
        raise TargetIntentError(
            "target source_evidence requires corresponding source_projects"
        )
    if len(source_evidence) != len(source_projects):
        raise TargetIntentError(
            "target source_projects and source_evidence must have equal lengths"
        )
    return TargetBundle(
        root=manifest.parent,
        identity=identity,
        display_name=display_name,
        paths=copy.deepcopy(paths),
    )


def validate_authored_intent(
    payload: Mapping[str, object], *, expected_format: str, context: str
) -> None:
    """Reject generated evidence embedded in an operator-authored document."""

    if payload.get("format") != expected_format:
        raise TargetIntentError(f"{context} has unsupported format")
    _reject_generated_fields(payload, context)


def apply_component_interface_intent(
    *, synthesized: Mapping[str, object], intent: Path | str
) -> dict[str, object]:
    """Apply reviewed logical overrides without accepting machine projections."""

    payload = _read_object(Path(intent), "component interface intent")
    validate_authored_intent(
        payload,
        expected_format=COMPONENT_INTERFACE_INTENT_FORMAT,
        context="component interface intent",
    )
    _require_exact_keys(
        payload,
        {"format", "component_id", "overrides"},
        "component interface intent",
    )
    if payload.get("component_id") != synthesized.get("component_id"):
        raise TargetIntentError("component interface intent targets another component")
    overrides = _object(payload.get("overrides"), "component interface overrides")
    allowed = {"parameters", "results", "objects", "services", "claims", "policy"}
    unknown = sorted(set(overrides) - allowed)
    if unknown:
        raise TargetIntentError(f"unsupported component interface overrides: {unknown}")
    result = copy.deepcopy(dict(synthesized))
    for key, value in overrides.items():
        result[key] = copy.deepcopy(value)
    return finalize_component_interface_spec(result)


def resolve_linked_island_intent(
    *, intent: Path | str, original_sha256: str, out: Path | str
) -> dict[str, object]:
    payload = _read_object(Path(intent), "linked-island intent")
    validate_authored_intent(
        payload,
        expected_format=LINKED_ISLAND_INTENT_FORMAT,
        context="linked-island intent",
    )
    intent_fields = {"format", "islands"}
    if "unclaimed_exact_units" in payload:
        intent_fields.add("unclaimed_exact_units")
    _require_exact_keys(payload, intent_fields, "linked-island intent")
    if "unclaimed_exact_units" in payload:
        _validate_unclaimed_exact_units_intent(payload["unclaimed_exact_units"])
    generated = bind_linked_island_review(
        {
            "format": LINKED_ISLAND_REVIEW_FORMAT,
            "original_binary_sha256": _sha256(original_sha256, "original SHA-256"),
            "islands": copy.deepcopy(payload["islands"]),
            **(
                {
                    "unclaimed_exact_units": copy.deepcopy(
                        payload["unclaimed_exact_units"]
                    )
                }
                if "unclaimed_exact_units" in payload
                else {}
            ),
        }
    )
    output = Path(out)
    write_json(output, generated)
    _write_provenance(
        output.with_name("linked-island-review.provenance.json"),
        artifact=output,
        producer="target-intent.resolve-linked-islands-v1",
        inputs=(Path(intent),),
        identities={"original_binary_sha256": original_sha256},
    )
    return generated


def _validate_unclaimed_exact_units_intent(value: object) -> None:
    policy = _object(value, "unclaimed exact-unit policy")
    fields = {
        "authority",
        "id",
        "kind",
        "operator_reviewed",
        "replacement_authorized",
        "review_rationale",
        "scope",
    }
    _require_exact_keys(policy, fields, "unclaimed exact-unit policy")
    _string(policy.get("id"), "unclaimed exact-unit policy id")
    if policy.get("kind") not in {
        "linked_dependency",
        "compiler_linker_support",
    }:
        raise TargetIntentError(
            "unclaimed exact-unit policy kind must be linked_dependency or "
            "compiler_linker_support"
        )
    if policy.get("authority") != "operator_reviewed_exact_complement":
        raise TargetIntentError(
            "unclaimed exact-unit policy must use operator-reviewed "
            "exact-complement authority"
        )
    if policy.get("scope") != "otherwise_unclaimed_exact_machine_units":
        raise TargetIntentError("unclaimed exact-unit policy has an unsupported scope")
    if policy.get("operator_reviewed") is not True:
        raise TargetIntentError(
            "unclaimed exact-unit policy must be visibly operator-reviewed"
        )
    rationale = _string(
        policy.get("review_rationale"),
        "unclaimed exact-unit policy review rationale",
    )
    if not rationale.strip():
        raise TargetIntentError(
            "unclaimed exact-unit policy review rationale must not be blank"
        )
    if policy.get("replacement_authorized") is not False:
        raise TargetIntentError(
            "unclaimed exact-unit policy may not authorize semantic replacement"
        )


def resolve_source_project_intent(
    *, intent: Path | str, original_sha256: str, out: Path | str
) -> dict[str, object]:
    payload = _read_object(Path(intent), "source-project intent")
    validate_authored_intent(
        payload,
        expected_format=SOURCE_PROJECT_INTENT_FORMAT,
        context="source-project intent",
    )
    allowed = {"format", "program_id", "sources", "coverage_scope", "islands"}
    _require_exact_keys(payload, allowed, "source-project intent")
    generated = bind_source_project_specification(
        {
            **copy.deepcopy(payload),
            "format": "stage-b-source-project-spec-v1",
            "original_binary_sha256": _sha256(
                original_sha256, "original SHA-256"
            ),
        }
    )
    output = Path(out)
    write_json(output, generated)
    _write_provenance(
        output.with_name("source-project.provenance.json"),
        artifact=output,
        producer="target-intent.resolve-source-project-v1",
        inputs=(Path(intent),),
        identities={"original_binary_sha256": original_sha256},
    )
    return generated


def resolve_source_component_evidence_intent(
    *, intent: Path | str, source_project_sha256: str, out: Path | str
) -> dict[str, object]:
    payload = _read_object(Path(intent), "source-component evidence intent")
    validate_authored_intent(
        payload,
        expected_format=SOURCE_COMPONENT_EVIDENCE_INTENT_FORMAT,
        context="source-component evidence intent",
    )
    generated = bind_source_component_evidence_plan(
        {
            **copy.deepcopy(payload),
            "format": SOURCE_COMPONENT_EVIDENCE_PLAN_FORMAT,
            "source_project_specification_sha256": _sha256(
                source_project_sha256, "source-project SHA-256"
            ),
        }
    )
    output = Path(out)
    write_json(output, generated)
    _write_provenance(
        output.with_name("source-component-evidence.provenance.json"),
        artifact=output,
        producer="target-intent.resolve-source-component-evidence-v1",
        inputs=(Path(intent),),
        identities={"source_project_specification_sha256": source_project_sha256},
    )
    return generated


def _proposal_matches(proposal: Mapping[str, object], selector: Mapping[str, object]) -> bool:
    allowed = {"entry_rva", "end_rva", "proposal_kind", "contains_rva"}
    unknown = sorted(set(selector) - allowed)
    if unknown:
        raise TargetIntentError(f"unsupported component selector fields: {unknown}")
    if not selector:
        raise TargetIntentError("component selector must not be empty")
    membership = _object(proposal.get("membership"), "proposal membership")
    if "entry_rva" in selector:
        if membership.get("rva_start") != _integer(selector["entry_rva"], "entry_rva"):
            return False
    if "end_rva" in selector:
        if membership.get("rva_end") != _integer(selector["end_rva"], "end_rva"):
            return False
    if "proposal_kind" in selector:
        proposal_kinds = _array(proposal.get("proposal_kinds"), "proposal kinds")
        if _string(selector["proposal_kind"], "proposal_kind") not in proposal_kinds:
            return False
    if "contains_rva" in selector:
        rva = _integer(selector["contains_rva"], "contains_rva")
        start = membership.get("rva_start")
        end = membership.get("rva_end")
        if not isinstance(start, int) or not isinstance(end, int) or not start <= rva < end:
            return False
    return True


def _reject_generated_fields(
    value: object, context: str, *, parent_key: str | None = None
) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            operator_review_status = key == "status" and parent_key == "logical_interface"
            if (
                not operator_review_status
                and (key in _GENERATED_FIELD_NAMES or key.endswith("_artifact_sha256"))
            ):
                raise TargetIntentError(
                    f"{context} contains generated-only field {key!r}"
                )
            _reject_generated_fields(child, context, parent_key=key)
    elif isinstance(value, list):
        for child in value:
            _reject_generated_fields(child, context, parent_key=parent_key)


def _write_provenance(
    path: Path,
    *,
    artifact: Path,
    producer: str,
    inputs: Sequence[Path],
    identities: Mapping[str, str] | None = None,
) -> None:
    write_json(
        path,
        {
            "format": GENERATED_ARTIFACT_PROVENANCE_FORMAT,
            "producer": producer,
            "artifact": {
                "path": artifact.name,
                "sha256": sha256_file(artifact),
            },
            "inputs": [
                {"path": source.name, "sha256": sha256_file(source)}
                for source in inputs
            ],
            "identities": dict(sorted((identities or {}).items())),
        },
    )


def _validate_relative_path(root: Path, value: str, label: str) -> None:
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or value in {"", "."}:
        raise TargetIntentError(f"{label} must be a normalized relative path")
    if not (root / Path(*path.parts)).exists():
        raise TargetIntentError(f"{label} does not exist: {value}")


def _canonical_sha256(value: object) -> str:
    return sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _read_object(path: Path, context: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise TargetIntentError(f"cannot read {context}: {error}") from error
    return dict(_object(value, context))


def _object(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise TargetIntentError(f"{context} must be an object")
    return value


def _array(value: object, context: str) -> list[object]:
    if not isinstance(value, list):
        raise TargetIntentError(f"{context} must be an array")
    return value


def _string(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise TargetIntentError(f"{context} must be a non-empty string")
    return value


def _integer(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise TargetIntentError(f"{context} must be a non-negative integer")
    return value


def _sha256(value: object, context: str) -> str:
    result = _string(value, context)
    if _SHA256.fullmatch(result) is None:
        raise TargetIntentError(f"{context} must be lowercase SHA-256")
    return result


def _require_exact_keys(
    value: Mapping[str, object], expected: set[str], context: str
) -> None:
    missing = sorted(expected - set(value))
    unknown = sorted(set(value) - expected)
    if missing or unknown:
        raise TargetIntentError(
            f"{context} fields differ: missing={missing}, unknown={unknown}"
        )


__all__ = [
    "TargetBundle",
    "TargetIdentity",
    "TargetIntentError",
    "apply_component_interface_intent",
    "load_target_bundle",
    "resolve_linked_island_intent",
    "resolve_source_component_evidence_intent",
    "resolve_source_project_intent",
    "validate_authored_intent",
]

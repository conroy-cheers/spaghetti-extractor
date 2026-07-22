from __future__ import annotations

import json
import re
import shutil
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Generic, Mapping, Sequence, TypeAlias, TypeVar

from ..relational.contract import stage_a_generate_relation_contract
from ..relational.mapping import stage_a_generate_map
from ..stage_binary import StageAInputError
from ..util import json_dumps, sha256_file, write_json
from .generator import (
    GeneratedCaseSpec,
    lowering_variant_for_spec,
    original_lowering_variant_for_spec,
)
from .lowering import (
    AssemblyLoweringVariant,
    LinkedPE32,
    build_gnu_pe32,
    build_llvm_msvc_pe32,
    lower_semantic_program_to_gnu_assembly,
    lower_semantic_program_to_llvm_msvc_assembly,
)
from .model import (
    CaseExpectation,
    CaseManifest,
    CorpusCaseRef,
    CorpusManifest,
    ExpectedCounts,
    ExpectedDisposition,
    NegativeMutation,
    ToolchainIdentity,
    artifact_refs,
    canonical_payload_sha256,
    load_case_manifest,
    write_case_manifest,
    write_corpus_manifest,
)
from .runner import run_roundtrip_corpus
from .semantic import (
    Branch,
    ExternalCall,
    InternalCall,
    Jump,
    SemanticBlock,
    SemanticProgram,
    StaticObject,
    ValueKind,
)


_ID_RE = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?")

MetadataScalar: TypeAlias = str | int | bool | None
Regenerated = TypeVar("Regenerated")

ARTIFACT_REDUCTION_RESULT_FORMAT = "stage-a-roundtrip-reduction-v1"
STRUCTURED_REDUCTION_GENERATOR_VERSION = "structured-semantic-reduction-v1"
_STABLE_PREDICATE_NAMES = frozenset({
    "unexpected-final-pass",
    "expected-positive-not-accepted",
    "expected-violated-without-checked-witness",
    "crash-or-internal-exception",
    "nondeterministic-artifact-hash",
    "cache-key-mismatch",
})
_SELECTED_PREDICATE_NAMES = frozenset({
    "violation-id",
    "violation-family",
    "mismatch-family",
    "proof-frontier",
    "phase-duration",
})
_COMPLETE_REGENERATION_ROLES = frozenset({
    "semantic_program",
    "candidate_semantic_program",
    "original_source",
    "candidate_source",
    "original_object",
    "candidate_object",
    "original_pe",
    "candidate_pe",
    "original_linker_map",
    "candidate_linker_map",
    "relation_proposal",
    "relation_contract",
})


def _stable_id(value: str, context: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise StageAInputError(f"{context} must be a stable lowercase identifier")
    return value


@dataclass(frozen=True)
class TransformationMetadata:
    """Typed, canonical metadata for one lowering transformation."""

    id: str
    family: str
    parameters: tuple[tuple[str, MetadataScalar], ...] = ()

    def __post_init__(self) -> None:
        _stable_id(self.id, "transformation id")
        _stable_id(self.family, "transformation family")
        keys = tuple(key for key, _value in self.parameters)
        for key in keys:
            _stable_id(key, "transformation parameter key")
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise StageAInputError(
                "transformation parameters must have unique, sorted keys"
            )
        for key, value in self.parameters:
            if not isinstance(value, (str, int, bool, type(None))):
                raise StageAInputError(
                    f"transformation parameter {key} must be a JSON scalar"
                )

    @classmethod
    def named(cls, transformation_id: str) -> "TransformationMetadata":
        return cls(id=transformation_id, family=transformation_id)

    @classmethod
    def parse(cls, payload: Mapping[str, Any]) -> "TransformationMetadata":
        expected = {"id", "family", "parameters"}
        missing = sorted(expected - set(payload))
        extra = sorted(set(payload) - expected)
        if missing or extra:
            raise StageAInputError(
                "transformation metadata fields do not match its schema: "
                f"missing={missing}, extra={extra}"
            )
        parameters = payload["parameters"]
        if not isinstance(parameters, Mapping):
            raise StageAInputError("transformation parameters must be an object")
        if any(not isinstance(key, str) for key in parameters):
            raise StageAInputError("transformation parameter keys must be strings")
        return cls(
            id=payload["id"],
            family=payload["family"],
            parameters=tuple(sorted(parameters.items())),
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.id,
            "family": self.family,
            "parameters": {key: value for key, value in self.parameters},
        }


@dataclass(frozen=True)
class ReductionStep:
    sequence: int
    action: str
    target: str
    before_sha256: str
    after_sha256: str

    def to_payload(self) -> dict[str, object]:
        return {
            "sequence": self.sequence,
            "action": self.action,
            "target": self.target,
            "before_sha256": self.before_sha256,
            "after_sha256": self.after_sha256,
        }


@dataclass(frozen=True)
class ReductionLineage:
    case_id: str
    parent_seed: int
    original_program_sha256: str
    predicate_id: str
    steps: tuple[ReductionStep, ...] = ()

    def to_payload(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "parent_seed": self.parent_seed,
            "original_program_sha256": self.original_program_sha256,
            "predicate_id": self.predicate_id,
            "steps": [step.to_payload() for step in self.steps],
        }


@dataclass(frozen=True)
class ReductionCandidate:
    program: SemanticProgram
    transformations: tuple[TransformationMetadata, ...]
    mutation: NegativeMutation | None
    lineage: ReductionLineage

    @property
    def sha256(self) -> str:
        return _candidate_sha256(
            self.program,
            self.transformations,
            self.mutation,
        )


@dataclass(frozen=True)
class DeterministicPredicate(Generic[Regenerated]):
    id: str
    evaluate: Callable[[Regenerated], bool]

    def __post_init__(self) -> None:
        _stable_id(self.id, "reduction predicate id")
        if not callable(self.evaluate):
            raise StageAInputError("reduction predicate evaluator must be callable")


@dataclass(frozen=True)
class ReductionResult(Generic[Regenerated]):
    candidate: ReductionCandidate
    regenerated: Regenerated
    attempts: int
    accepted_steps: int
    rejected_by_predicate: int
    rejected_by_regenerator: int

    def to_payload(self) -> dict[str, object]:
        return {
            "candidate_sha256": self.candidate.sha256,
            "semantic_program": self.candidate.program.to_payload(),
            "transformations": [
                transformation.to_payload()
                for transformation in self.candidate.transformations
            ],
            "mutation": (
                None
                if self.candidate.mutation is None
                else self.candidate.mutation.to_payload()
            ),
            "lineage": self.candidate.lineage.to_payload(),
            "attempts": self.attempts,
            "accepted_steps": self.accepted_steps,
            "rejected_by_predicate": self.rejected_by_predicate,
            "rejected_by_regenerator": self.rejected_by_regenerator,
        }


class ReductionCandidateRejected(Exception):
    """A regeneration callback may reject a proposal whose preconditions fail."""


class ReductionPredicateNotSatisfied(StageAInputError):
    pass


class NondeterministicReductionPredicate(StageAInputError):
    pass


@dataclass(frozen=True)
class PredicateObservation:
    """A stable, machine-readable observation made on regenerated artifacts."""

    satisfied: bool
    identity: str
    family: str
    details: Mapping[str, Any]

    def __post_init__(self) -> None:
        if type(self.satisfied) is not bool:
            raise StageAInputError("reduction predicate satisfaction must be bool")
        _nonempty_observation_id(self.identity, "reduction predicate observation identity")
        _nonempty_observation_id(self.family, "reduction predicate observation family")
        try:
            canonical = json.loads(json_dumps(dict(self.details)))
        except (TypeError, ValueError) as exc:
            raise StageAInputError(
                "reduction predicate observation details must be canonical JSON"
            ) from exc
        if not isinstance(canonical, dict):
            raise StageAInputError(
                "reduction predicate observation details must be an object"
            )

    def to_payload(self) -> dict[str, Any]:
        return {
            "satisfied": self.satisfied,
            "identity": self.identity,
            "family": self.family,
            "details": json.loads(json_dumps(dict(self.details))),
        }


@dataclass(frozen=True)
class StablePredicateSpec:
    """Versioned command-line predicate with a stable observation identity."""

    name: str
    selector: str | None = None
    threshold_seconds: float | None = None

    @classmethod
    def parse(cls, value: str) -> "StablePredicateSpec":
        if not isinstance(value, str) or not value:
            raise StageAInputError("reduction predicate must be a nonempty string")
        name, separator, argument = value.partition("=")
        if name in _STABLE_PREDICATE_NAMES:
            if separator:
                raise StageAInputError(
                    f"reduction predicate {name!r} does not accept a selector"
                )
            return cls(name=name)
        if name not in _SELECTED_PREDICATE_NAMES or not separator or not argument:
            supported = sorted(_STABLE_PREDICATE_NAMES | _SELECTED_PREDICATE_NAMES)
            raise StageAInputError(
                f"unsupported reduction predicate {value!r}; supported predicates are "
                f"{supported} (selected predicates use name=value)"
            )
        if name == "phase-duration":
            phase, comma, threshold = argument.rpartition(",")
            if not comma or not phase:
                raise StageAInputError(
                    "phase-duration predicate requires phase-id,seconds"
                )
            try:
                seconds = float(threshold)
            except ValueError as exc:
                raise StageAInputError(
                    "phase-duration threshold must be a finite positive number"
                ) from exc
            if seconds <= 0 or seconds == float("inf") or seconds != seconds:
                raise StageAInputError(
                    "phase-duration threshold must be a finite positive number"
                )
            _nonempty_observation_id(phase, "phase-duration phase id")
            return cls(name=name, selector=phase, threshold_seconds=seconds)
        _nonempty_observation_id(argument, f"{name} selector")
        return cls(name=name, selector=argument)

    @property
    def id(self) -> str:
        return self.name

    def to_argument(self) -> str:
        if self.name == "phase-duration":
            assert self.selector is not None and self.threshold_seconds is not None
            return f"{self.name}={self.selector},{self.threshold_seconds:g}"
        if self.selector is None:
            return self.name
        return f"{self.name}={self.selector}"


def _violation_preservation_requirements(
    specification: StablePredicateSpec,
) -> tuple[str | None, str | None]:
    """Translate explicit checked-violation selectors into hard reducer guards.

    Selecting a violation id or family is an instruction to preserve it. A
    mismatch-family selector is the explicit approval required to preserve a
    semantically equivalent checked mismatch when a byte-bound violation id
    changes after reduction.
    """

    if specification.name == "violation-id":
        return specification.selector, "checked-violation-id"
    if specification.name == "violation-family":
        return specification.selector, "checked-violation-family"
    if specification.name == "mismatch-family":
        return specification.selector, "checked-mismatch-family"
    return None, None


@dataclass(frozen=True)
class PredicateRun:
    result: Mapping[str, Any] | None = None
    repeated_result: Mapping[str, Any] | None = None
    artifact_hash_mismatch: bool | None = None
    artifact_hashes: tuple[str, str] | None = None


@dataclass(frozen=True)
class RegeneratedRoundtripCase:
    """One cleanly regenerated and hash-checked reduction attempt."""

    root: Path
    manifest_path: Path
    manifest: CaseManifest
    artifacts: Mapping[str, Path]
    candidate_sha256: str

    @property
    def reduction_program(self) -> SemanticProgram:
        return SemanticProgram.parse(_read_json_object(self.artifacts["semantic_program"]))


@dataclass(frozen=True)
class ArtifactPredicate:
    id: str
    evaluate: Callable[[RegeneratedRoundtripCase], PredicateObservation]
    required_identity: str | None = None
    required_family: str | None = None

    def __post_init__(self) -> None:
        _stable_id(self.id, "artifact reduction predicate id")
        if not callable(self.evaluate):
            raise StageAInputError("artifact reduction predicate evaluator must be callable")
        if self.required_identity is not None:
            _nonempty_observation_id(
                self.required_identity, "required predicate observation identity"
            )
        if self.required_family is not None:
            _nonempty_observation_id(
                self.required_family, "required predicate observation family"
            )


@dataclass(frozen=True)
class ArtifactReductionResult:
    reduction: ReductionResult[RegeneratedRoundtripCase]
    output_case_manifest: Path
    predicate_observation: PredicateObservation
    report: Mapping[str, Any]


ArtifactMaterializer: TypeAlias = Callable[[ReductionCandidate, Path], Path]


RegenerateCallback: TypeAlias = Callable[[ReductionCandidate], Regenerated]


@dataclass(frozen=True)
class _Proposal:
    action: str
    target: str
    program: SemanticProgram
    transformations: tuple[TransformationMetadata, ...]
    mutation: NegativeMutation | None


def reduce_roundtrip_case(
    *,
    case_id: str,
    parent_seed: int,
    program: SemanticProgram,
    transformations: Sequence[TransformationMetadata],
    mutation: NegativeMutation | None,
    regenerate: RegenerateCallback[Regenerated],
    predicate: DeterministicPredicate[Regenerated],
    max_accepted_steps: int = 10_000,
) -> ReductionResult[Regenerated]:
    """Minimize a typed case while preserving a deterministic predicate.

    The callback receives the complete prospective lineage and must regenerate
    every derived binary, mapping, and contract from the candidate's typed
    inputs. It may raise ``ReductionCandidateRejected`` for a proposal whose
    transformation or lowering preconditions no longer hold.
    """

    _stable_id(case_id, "reduction case id")
    if isinstance(parent_seed, bool) or not isinstance(parent_seed, int) or parent_seed < 0:
        raise StageAInputError("reduction parent seed must be a nonnegative integer")
    if (
        isinstance(max_accepted_steps, bool)
        or not isinstance(max_accepted_steps, int)
        or max_accepted_steps < 0
    ):
        raise StageAInputError("max_accepted_steps must be a nonnegative integer")
    if not callable(regenerate):
        raise StageAInputError("reduction regeneration callback must be callable")

    checked_program = _checked_program(program)
    checked_transformations = tuple(transformations)
    _check_transformations(checked_transformations)
    original_program_sha256 = _program_sha256(checked_program)
    lineage = ReductionLineage(
        case_id=case_id,
        parent_seed=parent_seed,
        original_program_sha256=original_program_sha256,
        predicate_id=predicate.id,
    )
    current = ReductionCandidate(
        program=checked_program,
        transformations=checked_transformations,
        mutation=mutation,
        lineage=lineage,
    )
    regenerated = regenerate(current)
    if not _predicate_holds(predicate, regenerated):
        raise ReductionPredicateNotSatisfied(
            f"initial case does not satisfy reduction predicate {predicate.id}"
        )

    attempts = 0
    accepted = 0
    predicate_rejections = 0
    regeneration_rejections = 0
    while accepted < max_accepted_steps:
        changed = False
        for proposal in _proposals(
            current.program, current.transformations, current.mutation,
        ):
            attempts += 1
            before_sha256 = current.sha256
            after_sha256 = _candidate_sha256(
                proposal.program,
                proposal.transformations,
                proposal.mutation,
            )
            if after_sha256 == before_sha256:
                continue
            step = ReductionStep(
                sequence=accepted + 1,
                action=proposal.action,
                target=proposal.target,
                before_sha256=before_sha256,
                after_sha256=after_sha256,
            )
            candidate = ReductionCandidate(
                program=proposal.program,
                transformations=proposal.transformations,
                mutation=proposal.mutation,
                lineage=ReductionLineage(
                    case_id=lineage.case_id,
                    parent_seed=lineage.parent_seed,
                    original_program_sha256=lineage.original_program_sha256,
                    predicate_id=lineage.predicate_id,
                    steps=current.lineage.steps + (step,),
                ),
            )
            try:
                proposal_regenerated = regenerate(candidate)
            except ReductionCandidateRejected:
                regeneration_rejections += 1
                continue
            if not _predicate_holds(predicate, proposal_regenerated):
                predicate_rejections += 1
                continue
            current = candidate
            regenerated = proposal_regenerated
            accepted += 1
            changed = True
            break
        if not changed:
            break

    return ReductionResult(
        candidate=current,
        regenerated=regenerated,
        attempts=attempts,
        accepted_steps=accepted,
        rejected_by_predicate=predicate_rejections,
        rejected_by_regenerator=regeneration_rejections,
    )


def transformation_metadata(
    transformation_ids: Sequence[str],
) -> tuple[TransformationMetadata, ...]:
    """Convert a manifest's transformation ids into typed metadata."""

    result = tuple(TransformationMetadata.named(item) for item in transformation_ids)
    _check_transformations(result)
    return result


def evaluate_stable_predicate(
    specification: StablePredicateSpec,
    run: PredicateRun,
) -> PredicateObservation:
    """Evaluate a built-in predicate from immutable Stage A result artifacts."""

    if specification.name == "nondeterministic-artifact-hash":
        hashes = run.artifact_hashes
        return PredicateObservation(
            satisfied=run.artifact_hash_mismatch is True,
            identity="nondeterministic-artifact-hash",
            family="artifact-determinism",
            details={
                "first_artifact_set_sha256": None if hashes is None else hashes[0],
                "second_artifact_set_sha256": None if hashes is None else hashes[1],
            },
        )

    if run.result is None:
        raise StageAInputError(
            f"reduction predicate {specification.name!r} requires a Stage A run result"
        )
    case = _single_case_result(run.result)
    expected = case.get("expected_disposition")
    actual = case.get("actual_disposition")
    violation = case.get("violation")
    violation_object = violation if isinstance(violation, Mapping) else {}
    frontiers = tuple(
        item for item in case.get("frontiers", []) if isinstance(item, Mapping)
    )
    phases = tuple(
        item for item in case.get("phases", []) if isinstance(item, Mapping)
    )

    if specification.name == "unexpected-final-pass":
        return PredicateObservation(
            satisfied=actual == "pass" and expected != "pass",
            identity="unexpected-final-pass",
            family="roundtrip-disposition",
            details={"expected": expected, "actual": actual},
        )
    if specification.name == "expected-positive-not-accepted":
        return PredicateObservation(
            satisfied=expected == "pass" and actual != "pass",
            identity="expected-positive-not-accepted",
            family="roundtrip-disposition",
            details={"expected": expected, "actual": actual},
        )
    if specification.name == "expected-violated-without-checked-witness":
        checked = _checked_violation_result(violation_object)
        return PredicateObservation(
            satisfied=expected == "violated" and not checked,
            identity="expected-violated-without-checked-witness",
            family="checked-violation",
            details={
                "expected": expected,
                "actual": actual,
                "violation_status": violation_object.get("status"),
            },
        )
    if specification.name == "violation-id":
        observed = violation_object.get("violation_id")
        return PredicateObservation(
            satisfied=(
                _checked_violation_result(violation_object)
                and observed == specification.selector
            ),
            identity=str(observed or "missing-violation-id"),
            family="checked-violation-id",
            details={"selected": specification.selector, "observed": observed},
        )
    if specification.name == "violation-family":
        observed = violation_object.get("family")
        return PredicateObservation(
            satisfied=(
                _checked_violation_result(violation_object)
                and observed == specification.selector
            ),
            identity=str(observed or "missing-violation-family"),
            family="checked-violation-family",
            details={"selected": specification.selector, "observed": observed},
        )
    if specification.name == "mismatch-family":
        observed = _mismatch_family(violation_object)
        return PredicateObservation(
            satisfied=(
                _checked_violation_result(violation_object)
                and observed == specification.selector
            ),
            identity=str(observed or "missing-mismatch-family"),
            family="checked-mismatch-family",
            details={"selected": specification.selector, "observed": observed},
        )
    if specification.name == "proof-frontier":
        selected = specification.selector
        matches = [
            item for item in frontiers
            if selected in {
                item.get("category"), item.get("reason_code"), item.get("phase")
            }
        ]
        return PredicateObservation(
            satisfied=bool(matches),
            identity=str(selected),
            family="proof-frontier",
            details={"matches": [dict(item) for item in matches]},
        )
    if specification.name == "crash-or-internal-exception":
        error = case.get("error")
        internal_frontiers = [
            item for item in frontiers
            if item.get("reason_code") == "internal_or_input_error"
        ]
        return PredicateObservation(
            satisfied=isinstance(error, str) and bool(error) or bool(internal_frontiers),
            identity="crash-or-internal-exception",
            family="runner-failure",
            details={"error": error, "frontiers": [dict(item) for item in internal_frontiers]},
        )
    if specification.name == "cache-key-mismatch":
        mismatch = _cache_key_mismatch(case, run.repeated_result)
        return PredicateObservation(
            satisfied=bool(mismatch),
            identity="cache-key-mismatch",
            family="phase-cache",
            details={"mismatches": mismatch},
        )
    if specification.name == "phase-duration":
        assert specification.selector is not None
        assert specification.threshold_seconds is not None
        selected_phases = [
            phase for phase in phases if phase.get("id") == specification.selector
        ]
        durations = [
            float(phase.get("duration_seconds", 0.0)) for phase in selected_phases
            if isinstance(phase.get("duration_seconds"), (int, float))
        ]
        maximum = max(durations, default=0.0)
        return PredicateObservation(
            satisfied=maximum > specification.threshold_seconds,
            identity=specification.selector,
            family="phase-duration",
            details={
                "maximum_seconds": maximum,
                "threshold_seconds": specification.threshold_seconds,
            },
        )
    raise AssertionError(f"unhandled stable predicate {specification.name}")


def _single_case_result(result: Mapping[str, Any]) -> Mapping[str, Any]:
    cases = result.get("cases")
    if not isinstance(cases, list) or len(cases) != 1 or not isinstance(cases[0], Mapping):
        raise StageAInputError("reduction predicate requires a one-case Stage A run result")
    return cases[0]


def _checked_violation_result(violation: Mapping[str, Any]) -> bool:
    if violation.get("status") != "violated":
        return False
    checks = violation.get("checks")
    return (
        isinstance(checks, Mapping)
        and bool(checks)
        and all(value is True for value in checks.values())
    )


def _mismatch_family(violation: Mapping[str, Any]) -> str | None:
    mismatch = violation.get("first_proved_mismatch")
    if not isinstance(mismatch, Mapping):
        return None
    relation = mismatch.get("relation_atom")
    if isinstance(relation, str) and relation:
        return relation
    kinds = sorted({
        effect.get("kind")
        for role in ("original_effect", "candidate_effect")
        if isinstance((effect := mismatch.get(role)), Mapping)
        and isinstance(effect.get("kind"), str)
    })
    return "+".join(kinds) if kinds else None


def _cache_key_mismatch(
    first_case: Mapping[str, Any],
    repeated_result: Mapping[str, Any] | None,
) -> list[dict[str, Any]]:
    if repeated_result is None:
        return [{"reason": "repeated-result-missing"}]
    second_case = _single_case_result(repeated_result)
    first = {
        phase.get("id"): phase for phase in first_case.get("phases", [])
        if isinstance(phase, Mapping) and isinstance(phase.get("id"), str)
    }
    second = {
        phase.get("id"): phase for phase in second_case.get("phases", [])
        if isinstance(phase, Mapping) and isinstance(phase.get("id"), str)
    }
    mismatches: list[dict[str, Any]] = []
    for phase_id in sorted(set(first) | set(second)):
        before = first.get(phase_id)
        after = second.get(phase_id)
        if before is None or after is None:
            mismatches.append({"phase": phase_id, "reason": "phase-set-changed"})
        elif before.get("cache_key") != after.get("cache_key"):
            mismatches.append({
                "phase": phase_id,
                "reason": "cache-key-changed",
                "before": before.get("cache_key"),
                "after": after.get("cache_key"),
            })
        elif after.get("cache_hit") is not True:
            mismatches.append({"phase": phase_id, "reason": "warm-cache-miss"})
    return mismatches


def _check_transformations(
    transformations: tuple[TransformationMetadata, ...],
) -> None:
    ids = tuple(transformation.id for transformation in transformations)
    if len(ids) != len(set(ids)):
        raise StageAInputError("reduction transformation ids must be unique")


def _predicate_holds(
    predicate: DeterministicPredicate[Regenerated],
    regenerated: Regenerated,
) -> bool:
    first = predicate.evaluate(regenerated)
    second = predicate.evaluate(regenerated)
    if type(first) is not bool or type(second) is not bool:
        raise StageAInputError("reduction predicate must return bool")
    if first != second:
        raise NondeterministicReductionPredicate(
            f"reduction predicate {predicate.id} changed for one regenerated result"
        )
    return first


def _program_sha256(program: SemanticProgram) -> str:
    return canonical_payload_sha256(program.to_payload())


def _candidate_sha256(
    program: SemanticProgram,
    transformations: tuple[TransformationMetadata, ...],
    mutation: NegativeMutation | None,
) -> str:
    return canonical_payload_sha256({
        "semantic_program": program.to_payload(),
        "transformations": [item.to_payload() for item in transformations],
        "mutation": None if mutation is None else mutation.to_payload(),
    })


def _checked_program(program: SemanticProgram) -> SemanticProgram:
    return SemanticProgram.parse(program.to_payload())


def _replace_program(
    program: SemanticProgram,
    *,
    blocks: tuple[SemanticBlock, ...] | None = None,
    static_objects: tuple[StaticObject, ...] | None = None,
) -> SemanticProgram:
    payload = program.to_payload()
    if blocks is not None:
        payload["blocks"] = [block.to_payload() for block in blocks]
    if static_objects is not None:
        payload["static_objects"] = [item.to_payload() for item in static_objects]
    return SemanticProgram.parse(payload)


def _proposals(
    program: SemanticProgram,
    transformations: tuple[TransformationMetadata, ...],
    mutation: NegativeMutation | None,
) -> tuple[_Proposal, ...]:
    proposals: list[_Proposal] = []
    reachable = _reachable_block_ids(program)
    unreachable = tuple(block.id for block in program.blocks if block.id not in reachable)
    if unreachable:
        proposals.append(_Proposal(
            action="remove_unreachable_blocks",
            target=",".join(unreachable),
            program=_replace_program(
                program,
                blocks=tuple(block for block in program.blocks if block.id in reachable),
            ),
            transformations=transformations,
            mutation=mutation,
        ))

    for index, transformation in enumerate(transformations):
        proposals.append(_Proposal(
            action="remove_transformation",
            target=transformation.id,
            program=program,
            transformations=transformations[:index] + transformations[index + 1 :],
            mutation=mutation,
        ))

    if mutation is not None:
        proposals.append(_Proposal(
            action="remove_negative_mutation",
            target=mutation.id,
            program=program,
            transformations=transformations,
            mutation=None,
        ))

    for block_index, block in enumerate(program.blocks):
        if isinstance(block.terminator, Branch):
            for branch_name, target in (
                ("true", block.terminator.true_target),
                ("false", block.terminator.false_target),
            ):
                replacement = SemanticBlock(
                    id=block.id,
                    operations=block.operations,
                    terminator=Jump(target=target),
                )
                blocks = (
                    program.blocks[:block_index]
                    + (replacement,)
                    + program.blocks[block_index + 1 :]
                )
                proposals.append(_Proposal(
                    action="collapse_branch",
                    target=f"{block.id}:{branch_name}",
                    program=_replace_program(program, blocks=blocks),
                    transformations=transformations,
                    mutation=mutation,
                ))
        for operation_index, _operation in enumerate(block.operations):
            replacement = SemanticBlock(
                id=block.id,
                operations=(
                    block.operations[:operation_index]
                    + block.operations[operation_index + 1 :]
                ),
                terminator=block.terminator,
            )
            blocks = (
                program.blocks[:block_index]
                + (replacement,)
                + program.blocks[block_index + 1 :]
            )
            proposals.append(_Proposal(
                action="remove_operation",
                target=f"{block.id}:{operation_index}",
                program=_replace_program(program, blocks=blocks),
                transformations=transformations,
                mutation=mutation,
            ))

    referenced_objects = _referenced_static_objects(program)
    for index, static_object in enumerate(program.static_objects):
        if static_object.id in referenced_objects:
            continue
        proposals.append(_Proposal(
            action="remove_unused_static_object",
            target=static_object.id,
            program=_replace_program(
                program,
                static_objects=(
                    program.static_objects[:index] + program.static_objects[index + 1 :]
                ),
            ),
            transformations=transformations,
            mutation=mutation,
        ))
    return tuple(proposals)


def _reachable_block_ids(program: SemanticProgram) -> frozenset[str]:
    by_id = {block.id: block for block in program.blocks}
    pending = [program.entry]
    reachable: set[str] = set()
    while pending:
        block_id = pending.pop()
        if block_id in reachable:
            continue
        reachable.add(block_id)
        terminator = by_id[block_id].terminator
        targets: tuple[str, ...]
        if isinstance(terminator, Jump):
            targets = (terminator.target,)
        elif isinstance(terminator, Branch):
            targets = (terminator.true_target, terminator.false_target)
        elif isinstance(terminator, InternalCall):
            targets = (terminator.target, terminator.continuation)
        elif isinstance(terminator, ExternalCall) and terminator.continuation is not None:
            targets = (terminator.continuation,)
        else:
            targets = ()
        pending.extend(reversed(targets))
    return frozenset(reachable)


def _referenced_static_objects(program: SemanticProgram) -> frozenset[str]:
    references: set[str] = set()
    for block in program.blocks:
        for operation in block.operations:
            value = getattr(operation, "value", None)
            if getattr(value, "kind", None) is ValueKind.STATIC_ADDRESS:
                references.add(str(value.value))
    return frozenset(references)


def reduce_roundtrip_case_artifacts(
    *,
    case_id: str,
    parent_seed: int,
    program: SemanticProgram,
    transformations: Sequence[TransformationMetadata],
    mutation: NegativeMutation | None,
    materialize: ArtifactMaterializer,
    predicate: ArtifactPredicate,
    out: Path,
    replay: Sequence[str],
    max_accepted_steps: int = 10_000,
    force: bool = False,
) -> ArtifactReductionResult:
    """Reduce a case while rebuilding and validating every derived artifact.

    ``materialize`` receives a typed candidate and a fresh empty directory. It
    must lower and build both binaries, generate fresh linker maps, run the
    public mapping and relation-contract APIs, and return the resulting
    ``case.json`` path. This wrapper verifies the complete artifact set and its
    PE/proposal/contract hash chain before the predicate can inspect the case.

    The callback boundary keeps lowering generic: a corpus can supply any
    declarative lowering without teaching the reducer fixture or target names.
    """

    if not callable(materialize):
        raise StageAInputError("artifact reduction materializer must be callable")
    replay_tuple = tuple(replay)
    if not replay_tuple or any(not isinstance(item, str) or not item for item in replay_tuple):
        raise StageAInputError("artifact reduction replay command must be nonempty strings")
    out = Path(out).resolve()
    if out.exists() and any(out.iterdir() if out.is_dir() else (out,)) and not force:
        raise StageAInputError(
            f"reduction output is not empty: {out}; use force to replace it"
        )
    out.parent.mkdir(parents=True, exist_ok=True)

    observations: dict[Path, str] = {}
    observation_values: dict[Path, PredicateObservation] = {}
    materializations: list[dict[str, Any]] = []
    materializations_by_root: dict[Path, dict[str, Any]] = {}
    with tempfile.TemporaryDirectory(
        prefix=f".{out.name}.reduce-", dir=out.parent,
    ) as temporary:
        attempts_root = Path(temporary) / "attempts"
        attempts_root.mkdir()

        def regenerate(candidate: ReductionCandidate) -> RegeneratedRoundtripCase:
            attempt_number = len(materializations)
            attempt_root = attempts_root / f"{attempt_number:06d}-{candidate.sha256[:16]}"
            attempt_root.mkdir()
            manifest_path = Path(materialize(candidate, attempt_root)).resolve()
            regenerated = _validate_regenerated_case(
                candidate=candidate,
                attempt_root=attempt_root,
                manifest_path=manifest_path,
            )
            materialization = {
                "sequence": attempt_number,
                "candidate_sha256": candidate.sha256,
                "case_manifest_sha256": sha256_file(manifest_path),
                "artifact_set_sha256": canonical_payload_sha256({
                    role: sha256_file(path)
                    for role, path in sorted(regenerated.artifacts.items())
                }),
                "predicate_replayed": False,
                "predicate_observation": None,
            }
            materializations.append(materialization)
            materializations_by_root[regenerated.root.resolve()] = materialization
            return regenerated

        def evaluate(regenerated: RegeneratedRoundtripCase) -> bool:
            observation = predicate.evaluate(regenerated)
            if not isinstance(observation, PredicateObservation):
                raise StageAInputError(
                    "artifact reduction predicate must return PredicateObservation"
                )
            encoded = json_dumps(observation.to_payload())
            attempt_key = regenerated.root.resolve()
            previous = observations.get(attempt_key)
            if previous is not None and previous != encoded:
                raise NondeterministicReductionPredicate(
                    f"reduction predicate {predicate.id} changed for regenerated "
                    f"attempt {attempt_key}"
                )
            observations[attempt_key] = encoded
            observation_values[attempt_key] = observation
            materialization = materializations_by_root[attempt_key]
            materialization["predicate_replayed"] = True
            materialization["predicate_observation"] = observation.to_payload()
            return bool(
                observation.satisfied
                and (
                    predicate.required_identity is None
                    or observation.identity == predicate.required_identity
                )
                and (
                    predicate.required_family is None
                    or observation.family == predicate.required_family
                )
            )

        reduction = reduce_roundtrip_case(
            case_id=case_id,
            parent_seed=parent_seed,
            program=program,
            transformations=transformations,
            mutation=mutation,
            regenerate=regenerate,
            predicate=DeterministicPredicate(id=predicate.id, evaluate=evaluate),
            max_accepted_steps=max_accepted_steps,
        )
        final_observation = observation_values[reduction.regenerated.root.resolve()]
        _require_replayed_accepted_reductions(reduction, materializations)

        staging = Path(temporary) / "output"
        case_output = staging / "case"
        shutil.copytree(reduction.regenerated.root, case_output)
        output_manifest = case_output / reduction.regenerated.manifest_path.name
        report = {
            "format": ARTIFACT_REDUCTION_RESULT_FORMAT,
            "status": "reduced",
            "reduction": reduction.to_payload(),
            "predicate": {
                "id": predicate.id,
                "required_identity": predicate.required_identity,
                "required_family": predicate.required_family,
                "observation": final_observation.to_payload(),
            },
            "output": {
                "case_manifest": "case/" + output_manifest.name,
                "case_manifest_sha256": sha256_file(output_manifest),
            },
            "materializations": materializations,
            "replay": list(replay_tuple),
            "trust": {
                "proof_authority": False,
                "closes_stage_a_proof": False,
                "contracts_regenerated_after_every_typed_change": True,
                "predicate_replayed_after_every_accepted_reduction": True,
            },
        }
        write_json(staging / "reduction-result.json", report)
        if out.exists():
            if out.is_dir():
                shutil.rmtree(out)
            else:
                out.unlink()
        shutil.copytree(staging, out)

    persisted_manifest = out / "case" / output_manifest.name
    persisted_case = _validate_regenerated_case(
        candidate=reduction.candidate,
        attempt_root=out / "case",
        manifest_path=persisted_manifest,
    )
    persisted_reduction = ReductionResult(
        candidate=reduction.candidate,
        regenerated=persisted_case,
        attempts=reduction.attempts,
        accepted_steps=reduction.accepted_steps,
        rejected_by_predicate=reduction.rejected_by_predicate,
        rejected_by_regenerator=reduction.rejected_by_regenerator,
    )
    return ArtifactReductionResult(
        reduction=persisted_reduction,
        output_case_manifest=persisted_manifest,
        predicate_observation=final_observation,
        report=report,
    )


def _require_replayed_accepted_reductions(
    reduction: ReductionResult[RegeneratedRoundtripCase],
    materializations: Sequence[Mapping[str, Any]],
) -> None:
    replayed_candidates = {
        materialization.get("candidate_sha256")
        for materialization in materializations
        if materialization.get("predicate_replayed") is True
    }
    required_candidates = {
        step.after_sha256 for step in reduction.candidate.lineage.steps
    }
    required_candidates.add(
        reduction.candidate.lineage.steps[0].before_sha256
        if reduction.candidate.lineage.steps
        else reduction.candidate.sha256
    )
    missing = sorted(required_candidates - replayed_candidates)
    if missing:
        raise StageAInputError(
            "accepted reduction lacks a predicate replay for regenerated artifacts: "
            f"{missing}"
        )


RoundtripRun: TypeAlias = Callable[..., Mapping[str, Any]]


def reduce_case_manifest(
    *,
    case: Path,
    predicate: str,
    out: Path,
    mode: str = "proof-core",
    toolchain: str | None = None,
    compiler: str | None = None,
    linker: str | None = None,
    flake: Path | None = None,
    builders_file: Path | None = None,
    max_accepted_steps: int = 10_000,
    force: bool = False,
    _run: RoundtripRun = run_roundtrip_corpus,
) -> dict[str, Any]:
    """Regenerate and reduce one structured case through public Stage A APIs."""

    case_path = Path(case).resolve()
    source_manifest = load_case_manifest(case_path)
    source_root = case_path.parent
    source_artifacts = source_manifest.verify_artifacts(source_root)
    original_program = SemanticProgram.parse(
        _read_json_object(source_artifacts["semantic_program"])
    )
    candidate_program = SemanticProgram.parse(
        _read_json_object(source_artifacts["candidate_semantic_program"])
    )
    delta = _semantic_delta(original_program, candidate_program)
    if source_manifest.mutation is None and delta:
        raise StageAInputError(
            "positive reduction case has a semantic candidate delta"
        )
    if source_manifest.mutation is not None and not delta:
        raise StageAInputError(
            "negative reduction case has no semantic candidate delta"
        )
    selected_toolchain = toolchain or _infer_toolchain(source_artifacts)
    if selected_toolchain not in {"gnu", "llvm-msvc"}:
        raise StageAInputError(
            f"unsupported reduction toolchain {selected_toolchain!r}"
        )
    specification = StablePredicateSpec.parse(predicate)
    artifact_determinism: dict[Path, tuple[str, str]] = {}
    predicate_observations: dict[Path, PredicateObservation] = {}
    required_identity, required_family = _violation_preservation_requirements(
        specification
    )
    preserve_initial_violation_id = (
        source_manifest.expectation.disposition is ExpectedDisposition.VIOLATED
        and specification.name not in {
            "violation-id",
            "mismatch-family",
            "expected-violated-without-checked-witness",
        }
    )
    initial_violation_id: str | None = None
    initial_violation_observed = False
    case_replay = _standalone_replay(
        case_id=source_manifest.id,
        mode=mode,
        flake=flake,
        builders_file=builders_file,
        corpus="corpus.json",
        out="run",
    )
    report_replay = _standalone_replay(
        case_id=source_manifest.id,
        mode=mode,
        flake=flake,
        builders_file=builders_file,
        corpus="case/corpus.json",
        out="replay-run",
    )

    def materialize(candidate: ReductionCandidate, root: Path) -> Path:
        manifest_path = _materialize_structured_case(
            candidate=candidate,
            source_manifest=source_manifest,
            candidate_delta=delta,
            root=root,
            toolchain=selected_toolchain,
            compiler=compiler,
            linker=linker,
            replay=case_replay,
        )
        if specification.name == "nondeterministic-artifact-hash":
            first = _manifest_artifact_set_sha256(manifest_path)
            shadow = root / ".determinism-check"
            shadow.mkdir()
            shadow_manifest = _materialize_structured_case(
                candidate=candidate,
                source_manifest=source_manifest,
                candidate_delta=delta,
                root=shadow,
                toolchain=selected_toolchain,
                compiler=compiler,
                linker=linker,
                replay=case_replay,
            )
            second = _manifest_artifact_set_sha256(shadow_manifest)
            artifact_determinism[root.resolve()] = (first, second)
            shutil.rmtree(shadow)
        return manifest_path

    def evaluate(regenerated: RegeneratedRoundtripCase) -> PredicateObservation:
        nonlocal initial_violation_id, initial_violation_observed
        attempt_key = regenerated.root.resolve()
        prior = predicate_observations.get(attempt_key)
        if prior is not None:
            return prior
        if specification.name == "nondeterministic-artifact-hash":
            hashes = artifact_determinism.get(attempt_key)
            run = PredicateRun(
                artifact_hash_mismatch=(hashes is not None and hashes[0] != hashes[1]),
                artifact_hashes=hashes,
            )
        else:
            run_root = regenerated.root.parent / (
                regenerated.root.name + "-predicate-run"
            )
            result = _run(
                corpus=regenerated.root / "corpus.json",
                mode=mode,
                out=run_root,
                flake=flake,
                builders_file=builders_file,
                case_ids=(regenerated.manifest.id,),
            )
            repeated = None
            if specification.name == "cache-key-mismatch":
                repeated = _run(
                    corpus=regenerated.root / "corpus.json",
                    mode=mode,
                    out=run_root,
                    flake=flake,
                    builders_file=builders_file,
                    case_ids=(regenerated.manifest.id,),
                )
            run = PredicateRun(result=result, repeated_result=repeated)
        observation = evaluate_stable_predicate(specification, run)
        if preserve_initial_violation_id and run.result is not None:
            case_result = _single_case_result(run.result)
            violation = case_result.get("violation")
            violation_object = violation if isinstance(violation, Mapping) else {}
            checked = _checked_violation_result(violation_object)
            actual = case_result.get("actual_disposition")
            observed_id = violation_object.get("violation_id")
            if not initial_violation_observed:
                initial_violation_observed = True
                if actual == "violated":
                    if not checked or not isinstance(observed_id, str) or not observed_id:
                        raise StageAInputError(
                            "initial violated reduction case lacks a stable checked "
                            "violation identity; select an approved mismatch-family "
                            "predicate if identity-preserving reduction is unsuitable"
                        )
                    initial_violation_id = observed_id
            if initial_violation_id is not None:
                preserved = checked and observed_id == initial_violation_id
                details = dict(observation.details)
                details["checked_violation_preservation"] = {
                    "mode": "stable-violation-id",
                    "required": initial_violation_id,
                    "observed": observed_id,
                    "preserved": preserved,
                }
                observation = PredicateObservation(
                    satisfied=observation.satisfied and preserved,
                    identity=observation.identity,
                    family=observation.family,
                    details=details,
                )
        predicate_observations[attempt_key] = observation
        return observation

    try:
        reduce_roundtrip_case_artifacts(
            case_id=source_manifest.id,
            parent_seed=source_manifest.parent_seed,
            program=original_program,
            transformations=transformation_metadata(source_manifest.transformations),
            mutation=source_manifest.mutation,
            materialize=materialize,
            predicate=ArtifactPredicate(
                id=specification.id,
                evaluate=evaluate,
                required_identity=required_identity,
                required_family=required_family,
            ),
            out=out,
            replay=report_replay,
            max_accepted_steps=max_accepted_steps,
            force=force,
        )
    except ReductionCandidateRejected as exc:
        raise StageAInputError(
            f"initial reduction case cannot be regenerated: {exc}"
        ) from exc
    report_path = Path(out).resolve() / "reduction-result.json"
    report = _read_json_object(report_path)
    report["predicate"]["argument"] = specification.to_argument()
    report["source"] = {
        "case_id": source_manifest.id,
        "case_manifest_sha256": sha256_file(case_path),
        "semantic_program_sha256": source_manifest.semantic_program_sha256,
    }
    report["reducer_replay"] = [
        "spaghetti-extractor", "stage-a-fuzz-reduce",
        "--case", "case/case.json",
        "--predicate", specification.to_argument(),
        "--mode", mode,
        "--max-accepted-steps", "0",
        "--out", "replay-reduction",
    ]
    if selected_toolchain != _infer_toolchain(source_artifacts):
        report["reducer_replay"].extend(("--toolchain", selected_toolchain))
    if compiler is not None:
        report["reducer_replay"].extend(("--compiler", compiler))
    if linker is not None:
        report["reducer_replay"].extend(("--linker", linker))
    if flake is not None:
        report["reducer_replay"].extend(("--flake", str(Path(flake).resolve())))
    if builders_file is not None:
        report["reducer_replay"].extend((
            "--builders-file", str(Path(builders_file).resolve())
        ))
    write_json(report_path, report)
    return report


@dataclass(frozen=True)
class _SemanticPatch:
    block_id: str
    path: tuple[str | int, ...]
    operation: str
    value: Any = None


def _semantic_delta(
    original: SemanticProgram,
    candidate: SemanticProgram,
) -> tuple[_SemanticPatch, ...]:
    original_payload = original.to_payload()
    candidate_payload = candidate.to_payload()
    original_payload["id"] = "program"
    candidate_payload["id"] = "program"
    original_blocks = {
        block["id"]: block for block in original_payload.pop("blocks")
    }
    candidate_blocks = {
        block["id"]: block for block in candidate_payload.pop("blocks")
    }
    if original_payload != candidate_payload:
        raise StageAInputError(
            "reducer supports semantic candidate deltas only inside existing blocks"
        )
    if set(original_blocks) != set(candidate_blocks):
        raise StageAInputError(
            "reducer does not support semantic candidate deltas that add or remove blocks"
        )
    patches: list[_SemanticPatch] = []
    for block_id in sorted(original_blocks):
        _diff_json(
            original_blocks[block_id], candidate_blocks[block_id],
            block_id=block_id, path=(), out=patches,
        )
    return tuple(patches)


def _diff_json(
    original: Any,
    candidate: Any,
    *,
    block_id: str,
    path: tuple[str | int, ...],
    out: list[_SemanticPatch],
) -> None:
    if type(original) is not type(candidate):
        out.append(_SemanticPatch(block_id, path, "replace", candidate))
        return
    if isinstance(original, Mapping):
        original_keys = set(original)
        candidate_keys = set(candidate)
        for key in sorted(original_keys - candidate_keys):
            out.append(_SemanticPatch(block_id, path + (str(key),), "remove"))
        for key in sorted(candidate_keys - original_keys):
            out.append(_SemanticPatch(
                block_id, path + (str(key),), "add", candidate[key]
            ))
        for key in sorted(original_keys & candidate_keys):
            _diff_json(
                original[key], candidate[key], block_id=block_id,
                path=path + (str(key),), out=out,
            )
        return
    if isinstance(original, list):
        common = min(len(original), len(candidate))
        for index in range(common):
            _diff_json(
                original[index], candidate[index], block_id=block_id,
                path=path + (index,), out=out,
            )
        for index in range(len(original) - 1, common - 1, -1):
            out.append(_SemanticPatch(block_id, path + (index,), "remove"))
        for index in range(common, len(candidate)):
            out.append(_SemanticPatch(
                block_id, path + (index,), "add", candidate[index]
            ))
        return
    if original != candidate:
        out.append(_SemanticPatch(block_id, path, "replace", candidate))


def _apply_semantic_delta(
    program: SemanticProgram,
    delta: Sequence[_SemanticPatch],
) -> SemanticProgram:
    payload = program.to_payload()
    blocks = {block["id"]: block for block in payload["blocks"]}
    try:
        for patch in delta:
            target = blocks[patch.block_id]
            _apply_json_patch(target, patch)
    except (KeyError, IndexError, TypeError) as exc:
        raise ReductionCandidateRejected(
            "semantic mutation no longer applies after structural reduction"
        ) from exc
    payload["blocks"] = [blocks[block.id] for block in program.blocks]
    payload["id"] = f"{program.id}-mutated"
    try:
        return SemanticProgram.parse(payload)
    except StageAInputError as exc:
        raise ReductionCandidateRejected(
            "semantic mutation produced an invalid reduced candidate"
        ) from exc


def _apply_json_patch(root: Any, patch: _SemanticPatch) -> None:
    if not patch.path:
        raise ReductionCandidateRejected("whole-block mutation replacement is unsupported")
    parent = root
    for component in patch.path[:-1]:
        parent = parent[component]
    key = patch.path[-1]
    if patch.operation == "replace":
        parent[key] = json.loads(json_dumps(patch.value))
    elif patch.operation == "remove":
        if isinstance(parent, list):
            parent.pop(int(key))
        else:
            del parent[key]
    elif patch.operation == "add":
        value = json.loads(json_dumps(patch.value))
        if isinstance(parent, list):
            parent.insert(int(key), value)
        else:
            parent[key] = value
    else:
        raise AssertionError(f"unknown semantic patch operation {patch.operation}")


def _materialize_structured_case(
    *,
    candidate: ReductionCandidate,
    source_manifest: CaseManifest,
    candidate_delta: Sequence[_SemanticPatch],
    root: Path,
    toolchain: str,
    compiler: str | None,
    linker: str | None,
    replay: Sequence[str],
) -> Path:
    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    original_program = SemanticProgram.parse(candidate.program.to_payload())
    candidate_program = (
        original_program
        if candidate.mutation is None
        else _apply_semantic_delta(original_program, candidate_delta)
    )
    original_variant, candidate_variant = _lowering_variants(
        source_manifest=source_manifest,
        program=candidate_program,
        transformations=candidate.transformations,
    )
    lower = (
        lower_semantic_program_to_gnu_assembly
        if toolchain == "gnu" else lower_semantic_program_to_llvm_msvc_assembly
    )
    original_semantic = root / "semantic-program.json"
    candidate_semantic = root / "candidate-semantic-program.json"
    original_source = root / "original.S"
    candidate_source = root / "candidate.S"
    write_json(original_semantic, original_program.to_payload())
    write_json(candidate_semantic, candidate_program.to_payload())
    original_source.write_text(
        lower(original_program, variant=original_variant), encoding="utf-8"
    )
    candidate_source.write_text(
        lower(candidate_program, variant=candidate_variant), encoding="utf-8"
    )
    original = _build_pe(
        toolchain=toolchain, source=original_source,
        binary=root / "original.exe", linker_map=root / "original.map",
        compiler=compiler, linker=linker,
    )
    rebuilt_candidate = _build_pe(
        toolchain=toolchain, source=candidate_source,
        binary=root / "candidate.exe", linker_map=root / "candidate.map",
        compiler=compiler, linker=linker,
    )
    proposal_path = root / "relation-proposal.json"
    layout_path = root / "layout-contract.json"
    proposal = stage_a_generate_map(
        original=original.binary,
        candidate=rebuilt_candidate.binary,
        linker_map_original=original.linker_map,
        linker_map_candidate=rebuilt_candidate.linker_map,
        out=proposal_path,
        layout_contract_out=layout_path,
        original_flags="semantic-reduction-original-v1",
        candidate_flags=(
            "semantic-reduction-candidate-v1 "
            + " ".join(item.id for item in candidate.transformations)
        ).rstrip(),
    )
    if proposal.get("status") != "pass":
        raise ReductionCandidateRejected(
            "reduced candidate no longer admits a complete relation proposal"
        )
    proposal_payload = _read_json_object(proposal_path)
    proposal_payload["original"]["path"] = "original.exe"
    proposal_payload["candidate"]["path"] = "candidate.exe"
    proposal_payload["linker_maps"] = {
        "original": "original.map", "candidate": "candidate.map",
    }
    write_json(proposal_path, proposal_payload)
    relation_path = root / "relation-contract.json"
    relation = stage_a_generate_relation_contract(
        original=original.binary,
        candidate=rebuilt_candidate.binary,
        mapping=proposal_path,
        out=relation_path,
    )
    if relation.get("status") != "generated":
        raise ReductionCandidateRejected(
            "reduced candidate no longer admits a relation contract"
        )
    relation_payload = _read_json_object(relation_path)
    relation_payload["provenance"] = {
        "kind": "untrusted_block_map_projection",
        "mapping_sha256": sha256_file(proposal_path),
    }
    write_json(relation_path, relation_payload)
    artifacts = artifact_refs(root=root, artifacts=(
        ("semantic_program", original_semantic),
        ("candidate_semantic_program", candidate_semantic),
        ("original_source", original_source),
        ("candidate_source", candidate_source),
        ("original_object", original.object),
        ("candidate_object", rebuilt_candidate.object),
        ("original_pe", original.binary),
        ("candidate_pe", rebuilt_candidate.binary),
        ("original_linker_map", original.linker_map),
        ("candidate_linker_map", rebuilt_candidate.linker_map),
        ("relation_proposal", proposal_path),
        ("relation_contract", relation_path),
    ))
    expectation = (
        CaseExpectation(ExpectedDisposition.PASS, None, None)
        if candidate.mutation is None else source_manifest.expectation
    )
    manifest = CaseManifest(
        id=source_manifest.id,
        semantic_program_sha256=sha256_file(original_semantic),
        parent_seed=candidate.lineage.parent_seed,
        template=source_manifest.template,
        transformations=tuple(item.id for item in candidate.transformations),
        expectation=expectation,
        mutation=candidate.mutation,
        capability_profile=source_manifest.capability_profile,
        capabilities=original_program.capabilities,
        proof_families=source_manifest.proof_families,
        artifacts=artifacts,
        replay=tuple(replay),
        shard=0,
    )
    manifest_path = root / "case.json"
    write_case_manifest(manifest_path, manifest)
    corpus = CorpusManifest(
        generator_version=STRUCTURED_REDUCTION_GENERATOR_VERSION,
        root_seed=candidate.lineage.parent_seed,
        capability_profile=source_manifest.capability_profile,
        toolchain=_toolchain_identity(original, toolchain=toolchain, linker=linker),
        cases=(CorpusCaseRef(
            id=manifest.id, path="case.json", sha256=sha256_file(manifest_path), shard=0,
        ),),
        expected_counts=ExpectedCounts(
            int(expectation.disposition is ExpectedDisposition.PASS),
            int(expectation.disposition is ExpectedDisposition.VIOLATED),
            int(expectation.disposition is ExpectedDisposition.INCOMPLETE),
        ),
        shard_count=1,
    )
    write_corpus_manifest(root / "corpus.json", corpus)
    corpus.load_cases(root)
    return manifest_path


def _lowering_variants(
    *,
    source_manifest: CaseManifest,
    program: SemanticProgram,
    transformations: Sequence[TransformationMetadata],
) -> tuple[AssemblyLoweringVariant, AssemblyLoweringVariant]:
    if not transformations:
        identity = AssemblyLoweringVariant("reduced-identity")
        return identity, identity
    original_variants: list[AssemblyLoweringVariant] = []
    candidate_variants: list[AssemblyLoweringVariant] = []
    for index, transformation in enumerate(transformations):
        spec = GeneratedCaseSpec(
            index=index,
            seed=source_manifest.parent_seed,
            template=source_manifest.template,
            transformation=transformation.id,
            negative_ordinal=None,
        )
        original_variants.append(original_lowering_variant_for_spec(spec))
        candidate_variants.append(lowering_variant_for_spec(spec, program))
    return (
        _merge_lowering_variants("reduced-original", original_variants),
        _merge_lowering_variants("reduced-candidate", candidate_variants),
    )


def _merge_lowering_variants(
    identifier: str,
    variants: Iterable[AssemblyLoweringVariant],
) -> AssemblyLoweringVariant:
    variants = tuple(variants)
    fields = tuple(
        name for name in AssemblyLoweringVariant.__dataclass_fields__ if name != "id"
    )
    values: dict[str, tuple[str, ...]] = {}
    for field in fields:
        rows = [tuple(getattr(variant, field)) for variant in variants]
        nonempty = [row for row in rows if row]
        if field == "block_order":
            if len(set(nonempty)) > 1:
                raise ReductionCandidateRejected(
                    "lowering transformations require incompatible block orders"
                )
            values[field] = nonempty[0] if nonempty else ()
        else:
            values[field] = tuple(dict.fromkeys(
                item for row in rows for item in row
            ))
    return AssemblyLoweringVariant(id=identifier, **values)


def _build_pe(
    *,
    toolchain: str,
    source: Path,
    binary: Path,
    linker_map: Path,
    compiler: str | None,
    linker: str | None,
) -> LinkedPE32:
    if toolchain == "gnu":
        return build_gnu_pe32(
            source=source, binary=binary, linker_map=linker_map,
            compiler=compiler or "i686-w64-mingw32-gcc",
        )
    return build_llvm_msvc_pe32(
        source=source, binary=binary, linker_map=linker_map,
        clang_cl=compiler or "clang-cl", linker=linker or "lld-link",
    )


def _toolchain_identity(
    linked: LinkedPE32,
    *,
    toolchain: str,
    linker: str | None,
) -> ToolchainIdentity:
    return ToolchainIdentity(
        id=(
            "pinned-mingw32-gnu-v1"
            if toolchain == "gnu" else "pinned-llvm-msvc-compatible-v1"
        ),
        target=(
            "i686-w64-mingw32"
            if toolchain == "gnu" else "i686-pc-windows-msvc"
        ),
        compiler=Path(linked.compiler).name,
        compiler_version=linked.compiler_version,
        linker=(
            "gnu-ld-via-gcc"
            if toolchain == "gnu" else Path(linker or "lld-link").name
        ),
        linker_version=linked.linker_version,
    )


def _infer_toolchain(artifacts: Mapping[str, Path]) -> str:
    return "llvm-msvc" if artifacts["original_object"].suffix == ".obj" else "gnu"


def _standalone_replay(
    *,
    case_id: str,
    mode: str,
    flake: Path | None,
    builders_file: Path | None,
    corpus: str,
    out: str,
) -> tuple[str, ...]:
    command = [
        "spaghetti-extractor", "stage-a-fuzz-run",
        "--corpus", corpus, "--mode", mode,
        "--case", case_id, "--out", out,
    ]
    if flake is not None:
        command.extend(("--flake", str(Path(flake).resolve())))
    if builders_file is not None:
        command.extend(("--builders-file", str(Path(builders_file).resolve())))
    return tuple(command)


def _manifest_artifact_set_sha256(manifest_path: Path) -> str:
    manifest = load_case_manifest(manifest_path)
    artifacts = manifest.verify_artifacts(manifest_path.parent)
    return canonical_payload_sha256({
        role: sha256_file(path) for role, path in sorted(artifacts.items())
    })


def _validate_regenerated_case(
    *,
    candidate: ReductionCandidate,
    attempt_root: Path,
    manifest_path: Path,
) -> RegeneratedRoundtripCase:
    attempt_root = attempt_root.resolve()
    if attempt_root != manifest_path and attempt_root not in manifest_path.parents:
        raise StageAInputError("reduction materializer returned a manifest outside its attempt")
    manifest = load_case_manifest(manifest_path)
    root = manifest_path.parent
    artifacts = manifest.verify_artifacts(root)
    missing = sorted(_COMPLETE_REGENERATION_ROLES - set(artifacts))
    if missing:
        raise StageAInputError(
            f"regenerated reduction case is missing complete artifacts {missing}"
        )
    if manifest.parent_seed != candidate.lineage.parent_seed:
        raise StageAInputError("regenerated case changed its parent seed lineage")
    if manifest.transformations != tuple(item.id for item in candidate.transformations):
        raise StageAInputError("regenerated case transformations do not match typed candidate")
    expected_mutation = None if candidate.mutation is None else candidate.mutation.to_payload()
    observed_mutation = None if manifest.mutation is None else manifest.mutation.to_payload()
    if observed_mutation != expected_mutation:
        raise StageAInputError("regenerated case mutation does not match typed candidate")
    if candidate.mutation is not None and candidate.mutation.location_id not in {
        block.id for block in candidate.program.blocks
    }:
        raise StageAInputError("typed reduction removed the declared mutation location")

    semantic_payload = _read_json_object(artifacts["semantic_program"])
    reparsed_program = SemanticProgram.parse(semantic_payload)
    if reparsed_program.to_payload() != candidate.program.to_payload():
        raise StageAInputError("regenerated semantic program does not match typed candidate")
    SemanticProgram.parse(_read_json_object(artifacts["candidate_semantic_program"]))

    proposal = _read_json_object(artifacts["relation_proposal"])
    original_binding = proposal.get("original")
    candidate_binding = proposal.get("candidate")
    if not isinstance(original_binding, Mapping) or not isinstance(candidate_binding, Mapping):
        raise StageAInputError("regenerated relation proposal lacks PE hash bindings")
    if original_binding.get("sha256") != sha256_file(artifacts["original_pe"]):
        raise StageAInputError("regenerated proposal has a stale original PE binding")
    if candidate_binding.get("sha256") != sha256_file(artifacts["candidate_pe"]):
        raise StageAInputError("regenerated proposal has a stale candidate PE binding")

    relation = _read_json_object(artifacts["relation_contract"])
    provenance = relation.get("provenance")
    if not isinstance(provenance, Mapping):
        raise StageAInputError("regenerated relation contract lacks mapping provenance")
    if provenance.get("mapping_sha256") != sha256_file(artifacts["relation_proposal"]):
        raise StageAInputError("regenerated relation contract has stale mapping provenance")
    return RegeneratedRoundtripCase(
        root=root,
        manifest_path=manifest_path,
        manifest=manifest,
        artifacts=artifacts,
        candidate_sha256=candidate.sha256,
    )


def _read_json_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"cannot read regenerated JSON artifact {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise StageAInputError(f"regenerated JSON artifact must be an object: {path}")
    return payload


def _nonempty_observation_id(value: str, context: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 512
        or any(ord(character) < 0x20 for character in value)
    ):
        raise StageAInputError(f"{context} must be a bounded nonempty string")
    return value


__all__ = [
    "ARTIFACT_REDUCTION_RESULT_FORMAT",
    "ArtifactMaterializer",
    "ArtifactPredicate",
    "ArtifactReductionResult",
    "DeterministicPredicate",
    "NondeterministicReductionPredicate",
    "PredicateObservation",
    "PredicateRun",
    "ReductionCandidate",
    "ReductionCandidateRejected",
    "ReductionLineage",
    "ReductionPredicateNotSatisfied",
    "ReductionResult",
    "ReductionStep",
    "RegeneratedRoundtripCase",
    "STRUCTURED_REDUCTION_GENERATOR_VERSION",
    "StablePredicateSpec",
    "TransformationMetadata",
    "evaluate_stable_predicate",
    "reduce_case_manifest",
    "reduce_roundtrip_case",
    "reduce_roundtrip_case_artifacts",
    "transformation_metadata",
]

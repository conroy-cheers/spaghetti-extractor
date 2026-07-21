from __future__ import annotations

import json
import shutil
import time
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable

from ..relational.build import stage_a_build_relational
from ..relational.interfaces import stage_a_interface_manifest
from ..relational.pipeline import stage_a_prepare_relational
from ..stage_binary import StageAInputError
from ..util import json_dumps, sha256_file, write_json
from .model import CaseManifest, ExpectedDisposition, load_corpus_manifest
from .violation import produce_checked_violation, validate_checked_violation


ROUNDTRIP_CASE_RESULT_FORMAT = "stage-a-roundtrip-case-result-v1"
ROUNDTRIP_RUN_RESULT_FORMAT = "stage-a-roundtrip-run-result-v1"


class RunMode(str, Enum):
    PROOF_CORE = "proof-core"
    DISCOVERY = "discovery"
    STAGE_B_ROUNDTRIP = "stage-b-roundtrip"


@dataclass(frozen=True)
class PhaseResult:
    id: str
    status: str
    cache_key: str
    cache_hit: bool
    duration_seconds: float
    artifact: str | None
    artifact_sha256: str | None
    reason_code: str | None

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "cache_key": self.cache_key,
            "cache_hit": self.cache_hit,
            "duration_seconds": self.duration_seconds,
            "artifact": self.artifact,
            "artifact_sha256": self.artifact_sha256,
            "reason_code": self.reason_code,
        }


@dataclass(frozen=True)
class CaseRunResult:
    case_id: str
    mode: RunMode
    expected: ExpectedDisposition
    actual: ExpectedDisposition
    expectation_matched: bool | None
    phases: tuple[PhaseResult, ...]
    acceptance_theorem: str | None
    acceptance_authority: str | None
    frontiers: tuple[dict[str, Any], ...]
    violation: dict[str, Any] | None
    error: str | None

    def to_payload(self) -> dict[str, Any]:
        return {
            "format": ROUNDTRIP_CASE_RESULT_FORMAT,
            "case_id": self.case_id,
            "mode": self.mode.value,
            "expected_disposition": self.expected.value,
            "actual_disposition": self.actual.value,
            "expectation_matched": self.expectation_matched,
            "phases": [phase.to_payload() for phase in self.phases],
            "acceptance": {
                "theorem": self.acceptance_theorem,
                "authority": self.acceptance_authority,
            },
            "frontiers": list(self.frontiers),
            "violation": self.violation,
            "error": self.error,
        }


PrepareFunction = Callable[..., dict[str, Any]]
BuildFunction = Callable[..., dict[str, Any]]


@dataclass(frozen=True)
class CheckedViolationReplay:
    result: dict[str, Any]
    cache_key: str
    cache_hit: bool
    duration_seconds: float
    artifact_sha256: str


def run_roundtrip_corpus(
    *,
    corpus: Path,
    mode: str,
    out: Path,
    flake: Path | None = None,
    builders_file: Path | None = None,
    case_ids: tuple[str, ...] | list[str] = (),
    stop_after_static_preflight: bool = False,
    _prepare: PrepareFunction = stage_a_prepare_relational,
    _build: BuildFunction = stage_a_build_relational,
) -> dict[str, Any]:
    corpus_path = Path(corpus).resolve()
    corpus_root = corpus_path.parent
    manifest = load_corpus_manifest(corpus_path)
    try:
        selected_mode = RunMode(mode)
    except ValueError as exc:
        raise StageAInputError(f"unsupported round-trip run mode {mode!r}") from exc
    if stop_after_static_preflight and selected_mode is not RunMode.PROOF_CORE:
        raise StageAInputError(
            "--stop-after-static-preflight currently requires --mode proof-core"
        )
    loaded = manifest.load_cases(corpus_root)
    selected_ids = tuple(case_ids)
    if len(selected_ids) != len(set(selected_ids)):
        raise StageAInputError("round-trip case selector contains duplicates")
    known_ids = {case.id for case, _root in loaded}
    missing = sorted(set(selected_ids) - known_ids)
    if missing:
        raise StageAInputError(f"round-trip corpus has no selected cases {missing}")
    if selected_ids:
        selected = [entry for entry in loaded if entry[0].id in set(selected_ids)]
    else:
        selected = list(loaded)
    out = Path(out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    results: list[CaseRunResult] = []
    started = time.monotonic()
    for case, case_root in selected:
        case_out = out / "cases" / case.id
        case_out.mkdir(parents=True, exist_ok=True)
        try:
            result = _run_case(
                case=case,
                case_root=case_root,
                mode=selected_mode,
                out=case_out,
                flake=flake,
                builders_file=builders_file,
                prepare=_prepare,
                build=_build,
                stop_after_static_preflight=stop_after_static_preflight,
            )
        except (OSError, StageAInputError, ValueError) as exc:
            result = CaseRunResult(
                case_id=case.id,
                mode=selected_mode,
                expected=case.expectation.disposition,
                actual=ExpectedDisposition.INCOMPLETE,
                expectation_matched=False,
                phases=(),
                acceptance_theorem=None,
                acceptance_authority=None,
                frontiers=({
                    "phase": "runner",
                    "reason_code": "internal_or_input_error",
                    "message": str(exc),
                },),
                violation=None,
                error=str(exc),
            )
        write_json(case_out / "result.json", result.to_payload())
        results.append(result)
    counts = {
        disposition.value: sum(result.actual is disposition for result in results)
        for disposition in ExpectedDisposition
    }
    expectation_mismatches = (
        []
        if stop_after_static_preflight
        else [
            result.case_id
            for result in results
            if result.expectation_matched is False
        ]
    )
    unexpected_passes = [
        result.case_id
        for result in results
        if result.expected is not ExpectedDisposition.PASS
        and result.actual is ExpectedDisposition.PASS
    ]
    if stop_after_static_preflight:
        static_preflight_failures = [
            result.case_id
            for result in results
            if not any(
                phase.id == "proof-preparation" and phase.status == "ready"
                for phase in result.phases
            )
        ]
        status = "pass" if not static_preflight_failures else "incomplete"
    else:
        static_preflight_failures = []
        status = (
            "pass"
            if not expectation_mismatches and not unexpected_passes
            else "incomplete"
        )
    payload = {
        "format": ROUNDTRIP_RUN_RESULT_FORMAT,
        "status": status,
        "mode": selected_mode.value,
        "corpus": {
            "path": str(corpus_path),
            "sha256": sha256_file(corpus_path),
            "format": manifest.format,
            "generator_version": manifest.generator_version,
        },
        "counts": {
            "cases": len(results),
            **counts,
            "expectation_mismatches": len(expectation_mismatches),
            "unexpected_passes": len(unexpected_passes),
        },
        "expectation_mismatch_case_ids": expectation_mismatches,
        "unexpected_pass_case_ids": unexpected_passes,
        "cases": [result.to_payload() for result in results],
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "trust": {
            "positive_pass_requires": "whole_program_lean",
            "negative_pass_is_fatal": True,
            "runner_has_proof_authority": False,
        },
    }
    if stop_after_static_preflight:
        payload.update({
            "stopped_after": "static-preflight",
            "expectations_evaluated": False,
            "static_preflight_failure_case_ids": static_preflight_failures,
        })
    write_json(out / "run-result.json", payload)
    return payload


def _run_case(
    *,
    case: CaseManifest,
    case_root: Path,
    mode: RunMode,
    out: Path,
    flake: Path | None,
    builders_file: Path | None,
    prepare: PrepareFunction,
    build: BuildFunction,
    stop_after_static_preflight: bool,
) -> CaseRunResult:
    if mode is not RunMode.PROOF_CORE:
        return CaseRunResult(
            case_id=case.id,
            mode=mode,
            expected=case.expectation.disposition,
            actual=ExpectedDisposition.INCOMPLETE,
            expectation_matched=(
                case.expectation.disposition is ExpectedDisposition.INCOMPLETE
                and case.expectation.reason_family == f"{mode.value}-not-implemented"
            ),
            phases=(PhaseResult(
                id="mode-preflight",
                status="incomplete",
                cache_key=sha256_file(case_root / "case.json"),
                cache_hit=False,
                duration_seconds=0.0,
                artifact=None,
                artifact_sha256=None,
                reason_code=f"{mode.value}-not-implemented",
            ),),
            acceptance_theorem=None,
            acceptance_authority=None,
            frontiers=({
                "phase": "mode-preflight",
                "reason_code": f"{mode.value}-not-implemented",
            },),
            violation=None,
            error=None,
        )
    artifacts = case.verify_artifacts(case_root)
    prepared = out / "prepared"
    prepared_manifest = prepared / "prepared-proof.json"
    prepare_key = _case_proof_input_key(case)
    prepare_cache_hit = _prepared_cache_matches(
        prepared=prepared,
        case=case,
    )
    prepare_started = time.monotonic()
    if prepare_cache_hit:
        prepare_result = json.loads(prepared_manifest.read_text(encoding="utf-8"))
    else:
        if prepared.exists():
            shutil.rmtree(prepared)
        prepare_result = prepare(
            original=artifacts["original_pe"],
            candidate=artifacts["candidate_pe"],
            relation_contract=artifacts["relation_contract"],
            out=prepared,
        )
        write_json(
            prepared / "roundtrip-input-binding.json",
            _input_binding_payload(case),
        )
    prepare_duration = round(time.monotonic() - prepare_started, 3)
    acceptance = prepare_result.get("acceptance")
    acceptance_ready = (
        isinstance(acceptance, dict) and acceptance.get("status") == "ready"
    )
    phases = [PhaseResult(
        id="proof-preparation",
        status="ready" if acceptance_ready else "incomplete",
        cache_key=prepare_key,
        cache_hit=prepare_cache_hit,
        duration_seconds=prepare_duration,
        artifact="prepared/prepared-proof.json" if prepared_manifest.is_file() else None,
        artifact_sha256=(
            sha256_file(prepared_manifest) if prepared_manifest.is_file() else None
        ),
        reason_code=(
            None if acceptance_ready else _first_acceptance_reason(prepare_result)
        ),
    )]
    if stop_after_static_preflight:
        return CaseRunResult(
            case_id=case.id,
            mode=mode,
            expected=case.expectation.disposition,
            actual=ExpectedDisposition.INCOMPLETE,
            expectation_matched=None,
            phases=tuple(phases),
            acceptance_theorem=None,
            acceptance_authority=None,
            frontiers=tuple(_acceptance_frontiers(prepare_result)),
            violation=None,
            error=None,
        )
    if not acceptance_ready:
        return _incomplete_case_result(
            case=case,
            case_root=case_root,
            mode=mode,
            phases=phases,
            prepare_result=prepare_result,
            prepared=prepared,
        )
    proof_out = out / "proof"
    proof_verdict = proof_out / "verdict.json"
    build_cache_hit = _proof_cache_matches(proof=proof_out, case=case)
    build_started = time.monotonic()
    if build_cache_hit:
        build_result = json.loads(proof_verdict.read_text(encoding="utf-8"))
    else:
        if proof_out.exists():
            shutil.rmtree(proof_out)
        try:
            build_result = build(
                prepared=prepared,
                out=proof_out,
                executor="nix",
                flake=flake,
                builders_file=builders_file,
            )
        except StageAInputError as error:
            phases.append(PhaseResult(
                id="proof-build-and-audit",
                status="incomplete",
                cache_key=(
                    sha256_file(prepared / "module-graph.json")
                    if (prepared / "module-graph.json").is_file()
                    else prepare_key
                ),
                cache_hit=False,
                duration_seconds=round(time.monotonic() - build_started, 3),
                artifact=None,
                artifact_sha256=None,
                reason_code="final_theorem_not_checked",
            ))
            violation_replay = _checked_violation_if_declared(
                case=case,
                case_root=case_root,
                prepared=prepared,
                out=out / "violation",
            )
            violation_result = (
                violation_replay.result if violation_replay is not None else None
            )
            if violation_result is not None and violation_result["status"] == "violated":
                phases.append(_violation_phase(replay=violation_replay))
                return CaseRunResult(
                    case_id=case.id,
                    mode=mode,
                    expected=case.expectation.disposition,
                    actual=ExpectedDisposition.VIOLATED,
                    expectation_matched=(
                        case.expectation.disposition is ExpectedDisposition.VIOLATED
                    ),
                    phases=tuple(phases),
                    acceptance_theorem=None,
                    acceptance_authority=None,
                    frontiers=tuple(_acceptance_frontiers(prepare_result)),
                    violation=violation_result,
                    error=None,
                )
            raise error
        write_json(
            proof_out / "roundtrip-input-binding.json",
            _input_binding_payload(case),
        )
    build_duration = round(time.monotonic() - build_started, 3)
    passed = (
        build_result.get("status") == "pass"
        and build_result.get("expected_final_theorem")
            == "StageA.GeneratedRelational.candidatePE32ProgramsEquivalent"
        and build_result.get("checks", {}).get("lean_trust_zero") is True
        and build_result.get("checks", {}).get("final_theorem_matches") is True
    )
    phases.append(PhaseResult(
        id="proof-build-and-audit",
        status="pass" if passed else "incomplete",
        cache_key=(
            sha256_file(prepared / "module-graph.json")
            if (prepared / "module-graph.json").is_file()
            else prepare_key
        ),
        cache_hit=build_cache_hit,
        duration_seconds=build_duration,
        artifact="proof/verdict.json" if proof_verdict.is_file() else None,
        artifact_sha256=sha256_file(proof_verdict) if proof_verdict.is_file() else None,
        reason_code=None if passed else "final_theorem_not_checked",
    ))
    actual = ExpectedDisposition.PASS if passed else ExpectedDisposition.INCOMPLETE
    violation_result = None
    if not passed:
        violation_replay = _checked_violation_if_declared(
            case=case,
            case_root=case_root,
            prepared=prepared,
            out=out / "violation",
        )
        violation_result = (
            violation_replay.result if violation_replay is not None else None
        )
        if violation_result is not None and violation_result["status"] == "violated":
            actual = ExpectedDisposition.VIOLATED
            phases.append(_violation_phase(replay=violation_replay))
    return CaseRunResult(
        case_id=case.id,
        mode=mode,
        expected=case.expectation.disposition,
        actual=actual,
        expectation_matched=actual is case.expectation.disposition,
        phases=tuple(phases),
        acceptance_theorem=(
            str(build_result.get("expected_final_theorem")) if passed else None
        ),
        acceptance_authority="whole_program_lean" if passed else None,
        frontiers=tuple(_acceptance_frontiers(prepare_result)),
        violation=violation_result,
        error=None,
    )


def _incomplete_case_result(
    *,
    case: CaseManifest,
    case_root: Path,
    mode: RunMode,
    phases: list[PhaseResult],
    prepare_result: dict[str, Any],
    prepared: Path,
) -> CaseRunResult:
    violation_replay = _checked_violation_if_declared(
        case=case,
        case_root=case_root,
        prepared=prepared,
        out=prepared.parent / "violation",
    )
    violation_result = (
        violation_replay.result if violation_replay is not None else None
    )
    actual = (
        ExpectedDisposition.VIOLATED
        if violation_result is not None and violation_result["status"] == "violated"
        else ExpectedDisposition.INCOMPLETE
    )
    if actual is ExpectedDisposition.VIOLATED:
        phases.append(_violation_phase(replay=violation_replay))
    return CaseRunResult(
        case_id=case.id,
        mode=mode,
        expected=case.expectation.disposition,
        actual=actual,
        expectation_matched=(
            actual is case.expectation.disposition
            and (
                actual is ExpectedDisposition.VIOLATED
                or case.expectation.reason_family
                    == _first_acceptance_reason(prepare_result)
            )
        ),
        phases=tuple(phases),
        acceptance_theorem=None,
        acceptance_authority=None,
        frontiers=tuple(_acceptance_frontiers(prepare_result)),
        violation=violation_result,
        error=None,
    )


def _checked_violation_if_declared(
    *,
    case: CaseManifest,
    case_root: Path,
    prepared: Path,
    out: Path,
) -> CheckedViolationReplay | None:
    roles = {artifact.role for artifact in case.artifacts}
    if "violation_witness" not in roles:
        return None
    started = time.monotonic()
    witness_path = case.artifact("violation_witness").verify(case_root)
    cache_inputs = _violation_replay_input_binding(
        case=case,
        prepared=prepared,
    )
    cache_key = sha256(json_dumps(cache_inputs).encode("utf-8")).hexdigest()
    cache_hit = _violation_cache_matches(out=out, inputs=cache_inputs)
    if cache_hit:
        audit_path = out / "audit.json"
    else:
        if out.exists():
            shutil.rmtree(out)
        production = produce_checked_violation(
            witness_path=witness_path,
            case=case,
            case_root=case_root,
            prepared=prepared,
            out=out,
        )
        audit_path = Path(production["audit"])
        source_path = Path(production["source"])
        write_json(out / "roundtrip-input-binding.json", {
            "format": "stage-a-roundtrip-violation-cache-binding-v1",
            "inputs": cache_inputs,
            "outputs": {
                "audit_sha256": sha256_file(audit_path),
                "source_sha256": sha256_file(source_path),
            },
        })
    result = validate_checked_violation(
        witness_path=witness_path,
        audit_path=audit_path,
        case=case,
        case_root=case_root,
        prepared=prepared,
    )
    return CheckedViolationReplay(
        result=result,
        cache_key=cache_key,
        cache_hit=cache_hit,
        duration_seconds=round(time.monotonic() - started, 6),
        artifact_sha256=sha256_file(audit_path),
    )


def _violation_phase(
    *, replay: CheckedViolationReplay,
) -> PhaseResult:
    return PhaseResult(
        id="checked-violation-replay",
        status="violated",
        cache_key=replay.cache_key,
        cache_hit=replay.cache_hit,
        duration_seconds=replay.duration_seconds,
        artifact="violation/audit.json",
        artifact_sha256=replay.artifact_sha256,
        reason_code=str(replay.result["family"]),
    )


def _violation_replay_input_binding(
    *, case: CaseManifest, prepared: Path,
) -> dict[str, Any]:
    relation_contract = prepared / "relation-contract.json"
    decoded_behaviors = prepared / "relational-decoded-behaviors.json"
    lean_dir = prepared / "lean"
    for path, description in (
        (relation_contract, "normalized relation contract"),
        (decoded_behaviors, "decoded behaviors"),
    ):
        if not path.is_file():
            raise StageAInputError(f"violation replay requires {description}: {path}")
    if not lean_dir.is_dir():
        raise StageAInputError(f"violation replay requires prepared Lean sources: {lean_dir}")
    return {
        "format": "stage-a-roundtrip-violation-replay-input-v1",
        "case_id": case.id,
        "witness_sha256": case.artifact("violation_witness").sha256,
        "original_sha256": case.artifact("original_pe").sha256,
        "candidate_sha256": case.artifact("candidate_pe").sha256,
        "relation_contract_sha256": sha256_file(relation_contract),
        "decoded_behaviors_sha256": sha256_file(decoded_behaviors),
        "prepared_lean_sha256": _directory_sha256(lean_dir),
        "capability_profile": case.capability_profile,
        "expected_witness_family": case.expectation.witness_family,
        "mutation": case.mutation.to_payload() if case.mutation is not None else None,
        "replay_implementation_sha256": _violation_replay_implementation_sha256(),
    }


def _violation_cache_matches(*, out: Path, inputs: dict[str, Any]) -> bool:
    binding_path = out / "roundtrip-input-binding.json"
    audit_path = out / "audit.json"
    source_path = out / "lean" / "StageA" / "RelationalCounterexample.lean"
    if not binding_path.is_file() or not audit_path.is_file() or not source_path.is_file():
        return False
    try:
        binding = json.loads(binding_path.read_text(encoding="utf-8"))
        audit = json.loads(audit_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(binding, dict) or not isinstance(audit, dict):
        return False
    outputs = binding.get("outputs")
    return (
        binding.get("format") == "stage-a-roundtrip-violation-cache-binding-v1"
        and binding.get("inputs") == inputs
        and isinstance(outputs, dict)
        and outputs.get("audit_sha256") == sha256_file(audit_path)
        and outputs.get("source_sha256") == sha256_file(source_path)
        and audit.get("format") == "stage-a-violation-check-v1"
        and audit.get("status") == "checked"
    )


def _directory_sha256(root: Path) -> str:
    digest = sha256()
    for path in sorted(candidate for candidate in root.rglob("*") if candidate.is_file()):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        contents = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(contents).to_bytes(8, "big"))
        digest.update(contents)
    return digest.hexdigest()


@lru_cache(maxsize=1)
def _violation_replay_implementation_sha256() -> str:
    digest = sha256()
    for value in (
        _preparation_implementation_sha256(),
        sha256_file(Path(__file__).with_name("violation.py")),
    ):
        digest.update(value.encode("ascii"))
    return digest.hexdigest()


def _case_proof_input_key(case: CaseManifest) -> str:
    values = [
        case.artifact(role).sha256
        for role in ("original_pe", "candidate_pe", "relation_contract")
    ]
    values.append(_preparation_implementation_sha256())
    return sha256("\0".join(values).encode("ascii")).hexdigest()


def _prepared_cache_matches(*, prepared: Path, case: CaseManifest) -> bool:
    manifest_path = prepared / "prepared-proof.json"
    interface_path = prepared / "stage-a-interface-manifest.json"
    binding_path = prepared / "roundtrip-input-binding.json"
    if (
        not manifest_path.is_file()
        or not interface_path.is_file()
        or not binding_path.is_file()
    ):
        return False
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        interface = json.loads(interface_path.read_text(encoding="utf-8"))
        binding = json.loads(binding_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return (
        manifest.get("format") == "stage-a-prepared-relational-v1"
        and manifest.get("original_sha256") == case.artifact("original_pe").sha256
        and manifest.get("candidate_sha256") == case.artifact("candidate_pe").sha256
        and interface == stage_a_interface_manifest()
        and binding == _input_binding_payload(case)
        and (prepared / "module-graph.json").is_file()
    )


def _proof_cache_matches(*, proof: Path, case: CaseManifest) -> bool:
    verdict_path = proof / "verdict.json"
    binding_path = proof / "roundtrip-input-binding.json"
    if not verdict_path.is_file() or not binding_path.is_file():
        return False
    try:
        verdict = json.loads(verdict_path.read_text(encoding="utf-8"))
        binding = json.loads(binding_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return (
        verdict.get("format") == "stage-a-relational-nix-build-v1"
        and verdict.get("status") == "pass"
        and verdict.get("original", {}).get("sha256") == case.artifact("original_pe").sha256
        and verdict.get("candidate", {}).get("sha256") == case.artifact("candidate_pe").sha256
        and binding == _input_binding_payload(case)
        and verdict.get("expected_final_theorem")
            == "StageA.GeneratedRelational.candidatePE32ProgramsEquivalent"
        and verdict.get("checks", {}).get("lean_trust_zero") is True
    )


def _input_binding_payload(case: CaseManifest) -> dict[str, Any]:
    return {
        "format": "stage-a-roundtrip-proof-input-binding-v1",
        "case_id": case.id,
        "original_sha256": case.artifact("original_pe").sha256,
        "candidate_sha256": case.artifact("candidate_pe").sha256,
        "relation_contract_input_sha256": case.artifact("relation_contract").sha256,
        "semantic_program_sha256": case.semantic_program_sha256,
        "preparation_implementation_sha256": _preparation_implementation_sha256(),
    }


@lru_cache(maxsize=1)
def _preparation_implementation_sha256() -> str:
    package_root = Path(__file__).resolve().parents[1]
    source_paths = [
        package_root / "stage_binary.py",
        package_root / "util.py",
        *sorted((package_root / "relational").rglob("*.py")),
        *sorted((package_root / "lean" / "StageA").glob("*.lean")),
    ]
    digest = sha256()
    for path in source_paths:
        if not path.is_file():
            raise StageAInputError(
                f"Stage A preparation implementation source is missing: {path}"
            )
        relative = path.relative_to(package_root).as_posix().encode("utf-8")
        contents = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(contents).to_bytes(8, "big"))
        digest.update(contents)
    return digest.hexdigest()


def _first_acceptance_reason(result: dict[str, Any]) -> str:
    acceptance = result.get("acceptance")
    blockers = acceptance.get("blockers") if isinstance(acceptance, dict) else None
    if isinstance(blockers, list) and blockers and isinstance(blockers[0], dict):
        code = blockers[0].get("code")
        if isinstance(code, str) and code:
            return code
    return "whole-program-acceptance-incomplete"


def _acceptance_frontiers(result: dict[str, Any]) -> list[dict[str, Any]]:
    acceptance = result.get("acceptance")
    acceptance_ready = (
        isinstance(acceptance, dict) and acceptance.get("status") == "ready"
    )
    progress = result.get("composition_progress")
    if not isinstance(progress, dict):
        return []
    frontiers = progress.get("frontiers")
    if not isinstance(frontiers, dict):
        return []
    rows: list[dict[str, Any]] = []
    for category, value in sorted(frontiers.items()):
        if value in (None, [], {}, 0):
            continue
        if (
            acceptance_ready
            and category == "affine_linked_control"
            and isinstance(value, dict)
            and value.get("acceptance_authority") is False
        ):
            # This optional proposal can guide later architecture work, but it
            # cannot block or authorize the ordinary whole-program theorem.
            continue
        rows.append({"category": category, "details": value})
    return rows

from __future__ import annotations

import json
import inspect
import shutil
import time
from dataclasses import dataclass, replace
from enum import Enum
from functools import lru_cache
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable

from ..artifact_formats import RELATIONAL_NIX_BUILD_REPORT_FORMAT
from ..relational.build import stage_a_build_relational
from ..relational.interfaces import stage_a_interface_manifest
from ..relational.nix_pipeline import stage_a_prepare_relational_nix
from ..relational.pipeline import stage_a_preflight_relational
from ..relational.schema import (
    RELATIONAL_FINAL_ACCEPTANCE_THEOREM,
    SchemaError,
    selected_relational_acceptance_theorem,
)
from ..stage_binary import StageAInputError
from ..util import json_dumps, sha256_file, write_json
from .discovery import (
    DiscoveryCaseResult,
    DiscoveryPhaseResult,
    execute_case_discovery,
)
from .model import CaseManifest, ExpectedDisposition, load_corpus_manifest
from .genericity import load_genericity_baseline, scan_acceptance_genericity
from .metrics import GenericityEvidence, aggregate_roundtrip_metrics
from .stage_b_roundtrip import run_static_opaque_stage_b_relational_roundtrip
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
    discovery: dict[str, Any] | None = None

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
            "discovery": self.discovery,
            "error": self.error,
        }


PrepareFunction = Callable[..., dict[str, Any]]
BuildFunction = Callable[..., dict[str, Any]]
PreflightFunction = Callable[..., dict[str, Any]]
DiscoveryFunction = Callable[..., DiscoveryCaseResult]


@dataclass(frozen=True)
class ProofInputs:
    original: Path
    candidate: Path
    relation_contract: Path
    relation_contract_sha256: str
    relation_origin: str
    layout_contract: Path | None = None
    layout_contract_sha256: str | None = None


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
    isa_kernel_qualification: Path | None = None,
    isa_semantic_kernel: Path | None = None,
    case_ids: tuple[str, ...] | list[str] = (),
    stop_after_static_preflight: bool = False,
    genericity_baseline: Path | None = None,
    _prepare: PrepareFunction = stage_a_prepare_relational_nix,
    _build: BuildFunction = stage_a_build_relational,
    _preflight: PreflightFunction = stage_a_preflight_relational,
    _discover: DiscoveryFunction = execute_case_discovery,
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
                isa_kernel_qualification=isa_kernel_qualification,
                isa_semantic_kernel=isa_semantic_kernel,
                prepare=_prepare,
                build=_build,
                preflight=_preflight,
                discover=_discover,
                stop_after_static_preflight=stop_after_static_preflight,
            )
            discovery_result_path = case_out / "discovery" / "result.json"
            if (
                selected_mode is RunMode.DISCOVERY
                and discovery_result_path.is_file()
            ):
                discovery_payload = json.loads(
                    discovery_result_path.read_text(encoding="utf-8")
                )
                if isinstance(discovery_payload, dict):
                    result = replace(result, discovery=discovery_payload)
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
                phase.id == "static-preflight" and phase.status == "ready"
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
    genericity = scan_acceptance_genericity(
        package_root=Path(__file__).resolve().parents[1],
        baseline=(
            None
            if genericity_baseline is None
            else load_genericity_baseline(genericity_baseline)
        ),
    )
    enriched_inventory = replace(
        genericity.current,
        structural_shapes=tuple(sorted({
            f"{case.template}|"
            f"{'+'.join(sorted(case.transformations)) or 'none'}|"
            f"{'none' if case.mutation is None else case.mutation.id}"
            for case, _case_root in selected
        })),
        semantic_constructors=tuple(sorted({
            capability
            for case, _case_root in selected
            for capability in case.capabilities
        })),
    )
    metrics = aggregate_roundtrip_metrics(
        cases=tuple(case for case, _case_root in selected),
        results=tuple(results),
        genericity=GenericityEvidence(
            current=enriched_inventory,
            baseline=genericity.baseline,
            forbidden_dispatch_hits=genericity.forbidden_dispatch_hits,
        ),
    ).to_payload()
    write_json(out / "metrics.json", metrics)
    payload["metrics"] = {
        "path": "metrics.json",
        "sha256": sha256_file(out / "metrics.json"),
        "proof_authority": False,
    }
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
    isa_kernel_qualification: Path | None,
    isa_semantic_kernel: Path | None,
    prepare: PrepareFunction,
    build: BuildFunction,
    preflight: PreflightFunction,
    discover: DiscoveryFunction,
    stop_after_static_preflight: bool,
) -> CaseRunResult:
    if mode is RunMode.STAGE_B_ROUNDTRIP:
        return _run_stage_b_case(
            case=case,
            case_root=case_root,
            mode=mode,
            out=out,
            flake=flake,
            builders_file=builders_file,
            isa_kernel_qualification=isa_kernel_qualification,
            isa_semantic_kernel=isa_semantic_kernel,
        )
    phases: list[PhaseResult] = []
    discovery_frontiers: list[dict[str, Any]] = []
    discovered_relation: Path | None = None
    discovered_layout: Path | None = None
    discovery_out = out / "discovery"
    if mode is RunMode.DISCOVERY:
        discovery_result = discover(
            case=case,
            case_root=case_root,
            out=discovery_out,
        )
        if not isinstance(discovery_result, DiscoveryCaseResult):
            raise StageAInputError(
                "round-trip discovery returned an unsupported result type"
            )
        phases.extend(
            _roundtrip_discovery_phase(phase, discovery_out)
            for phase in discovery_result.phases
        )
        discovery_frontiers.extend(discovery_result.frontiers)
        handoff_started = time.monotonic()
        try:
            discovered_relation = _verified_discovery_artifact(
                discovery_result,
                discovery_out,
                role="recovered_relation_contract",
            )
            discovered_layout = _verified_discovery_artifact(
                discovery_result,
                discovery_out,
                role="recovered_layout_contract",
                expected_format="stage-a-layout-contract-v1",
            )
        except StageAInputError as exc:
            handoff_key = sha256(
                json_dumps(discovery_result.to_payload()).encode("utf-8")
            ).hexdigest()
            phases.append(PhaseResult(
                id="discovery-proof-handoff",
                status="incomplete",
                cache_key=handoff_key,
                cache_hit=False,
                duration_seconds=round(time.monotonic() - handoff_started, 6),
                artifact=None,
                artifact_sha256=None,
                reason_code="recovered_contract_handoff_incomplete",
            ))
            discovery_frontiers.append({
                "phase": "discovery-proof-handoff",
                "reason_code": "recovered_contract_handoff_incomplete",
                "message": str(exc),
            })
            return CaseRunResult(
                case_id=case.id,
                mode=mode,
                expected=case.expectation.disposition,
                actual=ExpectedDisposition.INCOMPLETE,
                expectation_matched=(
                    case.expectation.disposition is ExpectedDisposition.INCOMPLETE
                ),
                phases=tuple(phases),
                acceptance_theorem=None,
                acceptance_authority=None,
                frontiers=tuple(discovery_frontiers),
                violation=None,
                error=None,
            )
        handoff_payload = {
            "format": "stage-a-roundtrip-discovery-proof-handoff-v1",
            "case_id": case.id,
            "relation_contract": {
                "path": discovered_relation.relative_to(discovery_out).as_posix(),
                "sha256": sha256_file(discovered_relation),
            },
            "layout_contract": {
                "path": discovered_layout.relative_to(discovery_out).as_posix(),
                "sha256": sha256_file(discovered_layout),
            },
            "trust": {
                "proof_authority": False,
                "ordinary_proof_core_required": True,
            },
        }
        handoff_path = discovery_out / "proof-handoff.json"
        write_json(handoff_path, handoff_payload)
        handoff_key = sha256(
            json_dumps(handoff_payload).encode("utf-8")
        ).hexdigest()
        phases.append(PhaseResult(
            id="discovery-proof-handoff",
            status="ready",
            cache_key=handoff_key,
            cache_hit=False,
            duration_seconds=round(time.monotonic() - handoff_started, 6),
            artifact="discovery/proof-handoff.json",
            artifact_sha256=sha256_file(handoff_path),
            reason_code=None,
        ))
    artifacts = case.verify_artifacts(case_root)
    proof_inputs = ProofInputs(
        original=artifacts["original_pe"],
        candidate=artifacts["candidate_pe"],
        relation_contract=(
            discovered_relation
            if discovered_relation is not None
            else artifacts["relation_contract"]
        ),
        relation_contract_sha256=(
            sha256_file(discovered_relation)
            if discovered_relation is not None
            else case.artifact("relation_contract").sha256
        ),
        relation_origin=(
            "discovery" if discovered_relation is not None else "corpus"
        ),
        layout_contract=discovered_layout,
        layout_contract_sha256=(
            sha256_file(discovered_layout)
            if discovered_layout is not None else None
        ),
    )
    static_path = out / "static-preflight.json"
    static_key = _case_static_preflight_key(case, proof_inputs)
    static_cache_hit = _static_preflight_cache_matches(
        path=static_path, cache_key=static_key,
    )
    static_started = time.monotonic()
    if static_cache_hit:
        static_result = json.loads(static_path.read_text(encoding="utf-8"))
    else:
        static_result = dict(preflight(
            original=proof_inputs.original,
            candidate=proof_inputs.candidate,
            relation_contract=proof_inputs.relation_contract,
        ))
        static_result["roundtrip_cache_key"] = static_key
        write_json(static_path, static_result)
    static_ready = static_result.get("status") == "ready"
    phases.append(PhaseResult(
        id="static-preflight",
        status="ready" if static_ready else "incomplete",
        cache_key=static_key,
        cache_hit=static_cache_hit,
        duration_seconds=round(time.monotonic() - static_started, 6),
        artifact="static-preflight.json",
        artifact_sha256=sha256_file(static_path),
        reason_code=(None if static_ready else str(
            static_result.get("reason_code") or "static_preflight_incomplete"
        )),
    ))
    if not static_ready or stop_after_static_preflight:
        return CaseRunResult(
            case_id=case.id,
            mode=mode,
            expected=case.expectation.disposition,
            actual=ExpectedDisposition.INCOMPLETE,
            expectation_matched=(
                None if stop_after_static_preflight else
                case.expectation.disposition is ExpectedDisposition.INCOMPLETE
            ),
            phases=tuple(phases),
            acceptance_theorem=None,
            acceptance_authority=None,
            frontiers=tuple(discovery_frontiers + [
                item for item in static_result.get("issues", [])
                if isinstance(item, dict)
            ]),
            violation=None,
            error=None,
        )
    prepared = out / "prepared"
    prepared_manifest = prepared / "prepared-proof.json"
    prepare_key = _case_proof_input_key(case, proof_inputs)
    prepare_cache_hit = _prepared_cache_matches(
        prepared=prepared,
        case=case,
        proof_inputs=proof_inputs,
    )
    prepare_started = time.monotonic()
    if prepare_cache_hit:
        prepare_result = json.loads(prepared_manifest.read_text(encoding="utf-8"))
    else:
        if prepared.exists():
            shutil.rmtree(prepared)
        prepare(
            original=proof_inputs.original,
            candidate=proof_inputs.candidate,
            relation_contract=proof_inputs.relation_contract,
            out=prepared,
            flake=flake,
            builders_file=builders_file,
        )
        prepare_result = json.loads(
            prepared_manifest.read_text(encoding="utf-8")
        )
        write_json(
            prepared / "roundtrip-input-binding.json",
            _input_binding_payload(case, proof_inputs),
        )
    prepare_duration = round(time.monotonic() - prepare_started, 3)
    acceptance = prepare_result.get("acceptance")
    selected_theorem: str | None = None
    acceptance_reason: str | None = None
    if isinstance(acceptance, dict) and acceptance.get("status") == "ready":
        try:
            selected_theorem = selected_relational_acceptance_theorem(acceptance)
        except SchemaError:
            acceptance_reason = "invalid_selected_acceptance_theorem"
    acceptance_ready = selected_theorem == RELATIONAL_FINAL_ACCEPTANCE_THEOREM
    phases.append(PhaseResult(
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
            None
            if acceptance_ready
            else acceptance_reason or _first_acceptance_reason(prepare_result)
        ),
    ))
    if not acceptance_ready:
        return _incomplete_case_result(
            case=case,
            case_root=case_root,
            mode=mode,
            phases=phases,
            prepare_result=prepare_result,
            prepared=prepared,
            initial_frontiers=discovery_frontiers,
            flake=flake,
            builders_file=builders_file,
        )
    proof_out = out / "proof"
    proof_verdict = proof_out / "verdict.json"
    build_started = time.monotonic()
    try:
        build_arguments: dict[str, Any] = {
            "prepared": prepared,
            "out": proof_out,
            "flake": flake,
            "builders_file": builders_file,
        }
        if isa_kernel_qualification is not None:
            build_arguments["isa_kernel_qualification"] = (
                isa_kernel_qualification
            )
        if isa_semantic_kernel is not None:
            build_arguments["isa_semantic_kernel"] = isa_semantic_kernel
        build_result = build(
            **build_arguments,
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
            artifact="proof/verdict.json" if proof_verdict.is_file() else None,
            artifact_sha256=(
                sha256_file(proof_verdict) if proof_verdict.is_file() else None
            ),
            reason_code="final_theorem_not_checked",
        ))
        violation_replay = _checked_violation_if_declared(
            case=case,
            case_root=case_root,
            prepared=prepared,
            out=out / "violation",
            flake=flake,
            builders_file=builders_file,
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
                frontiers=tuple(
                    discovery_frontiers + _acceptance_frontiers(prepare_result)
                ),
                violation=violation_result,
                error=None,
            )
        return CaseRunResult(
            case_id=case.id,
            mode=mode,
            expected=case.expectation.disposition,
            actual=ExpectedDisposition.INCOMPLETE,
            expectation_matched=False,
            phases=tuple(phases),
            acceptance_theorem=None,
            acceptance_authority=None,
            frontiers=tuple(
                discovery_frontiers
                + _acceptance_frontiers(prepare_result)
                + [{
                    "phase": "proof-build-and-audit",
                    "reason_code": "final_theorem_not_checked",
                    "message": str(error),
                }]
            ),
            violation=violation_result,
            error=str(error),
        )
    if not isinstance(build_result, dict):
        raise StageAInputError("relational proof build returned a non-object verdict")
    persisted_build_result: dict[str, Any] | None = None
    if proof_verdict.is_file():
        try:
            loaded_verdict = json.loads(proof_verdict.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            loaded_verdict = None
        if isinstance(loaded_verdict, dict):
            persisted_build_result = loaded_verdict
    prepared_relation = prepared / "relation-contract.json"
    write_json(
        proof_out / "roundtrip-input-binding.json",
        _input_binding_payload(case, proof_inputs),
    )
    build_duration = round(time.monotonic() - build_started, 3)
    passed = (
        persisted_build_result == build_result
        and build_result.get("format")
        == RELATIONAL_NIX_BUILD_REPORT_FORMAT
        and build_result.get("status") == "pass"
        and selected_theorem == RELATIONAL_FINAL_ACCEPTANCE_THEOREM
        and build_result.get("expected_final_theorem") == selected_theorem
        and build_result.get("acceptance") == acceptance
        and build_result.get("original", {}).get("sha256")
            == case.artifact("original_pe").sha256
        and build_result.get("candidate", {}).get("sha256")
            == case.artifact("candidate_pe").sha256
        and prepared_relation.is_file()
        and build_result.get("relation_contract_sha256")
            == sha256_file(prepared_relation)
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
        cache_hit=build_result.get("nix_work_reused") is True,
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
            flake=flake,
            builders_file=builders_file,
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
        frontiers=tuple(
            discovery_frontiers + _acceptance_frontiers(prepare_result)
        ),
        violation=violation_result,
        error=None,
    )


def _run_stage_b_case(
    *,
    case: CaseManifest,
    case_root: Path,
    mode: RunMode,
    out: Path,
    flake: Path | None,
    builders_file: Path | None,
    isa_kernel_qualification: Path | None,
    isa_semantic_kernel: Path | None,
) -> CaseRunResult:
    started = time.monotonic()
    stage_b_out = out / "stage-b-roundtrip"
    result = run_static_opaque_stage_b_relational_roundtrip(
        original_pe=case.artifact("original_pe").verify(case_root),
        original_linker_map=case.artifact("original_linker_map").verify(case_root),
        out=stage_b_out,
        flake=flake,
        builders_file=builders_file,
        isa_kernel_qualification=isa_kernel_qualification,
        isa_semantic_kernel=isa_semantic_kernel,
    )
    status = str(result.get("status") or "incomplete")
    actual = {
        "pass": ExpectedDisposition.PASS,
        "violated": ExpectedDisposition.VIOLATED,
    }.get(status, ExpectedDisposition.INCOMPLETE)
    proof = result.get("proof")
    proof = proof if isinstance(proof, dict) else {}
    final_theorem = proof.get("final_theorem")
    accepted = (
        actual is ExpectedDisposition.PASS
        and proof.get("lean_kernel_checked") is True
        and final_theorem == RELATIONAL_FINAL_ACCEPTANCE_THEOREM
    )
    if actual is ExpectedDisposition.PASS and not accepted:
        actual = ExpectedDisposition.INCOMPLETE
    result_path = stage_b_out / "proved-candidate" / "result.json"
    reason_codes = result.get("reason_codes")
    first_reason = (
        str(reason_codes[0])
        if isinstance(reason_codes, list) and reason_codes
        else None
    )
    return CaseRunResult(
        case_id=case.id,
        mode=mode,
        expected=case.expectation.disposition,
        actual=actual,
        expectation_matched=actual is case.expectation.disposition,
        phases=(PhaseResult(
            id="opaque-stage-b-roundtrip",
            status=actual.value,
            cache_key=sha256_file(case_root / "case.json"),
            cache_hit=False,
            duration_seconds=round(time.monotonic() - started, 3),
            artifact=(
                "stage-b-roundtrip/proved-candidate/result.json"
                if result_path.is_file()
                else None
            ),
            artifact_sha256=(
                sha256_file(result_path) if result_path.is_file() else None
            ),
            reason_code=first_reason,
        ),),
        acceptance_theorem=str(final_theorem) if accepted else None,
        acceptance_authority="whole_program_lean" if accepted else None,
        frontiers=tuple(
            item
            for item in proof.get("diagnostics", [])
            if isinstance(item, dict)
        ),
        violation=None,
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
    initial_frontiers: list[dict[str, Any]],
    flake: Path | None,
    builders_file: Path | None,
) -> CaseRunResult:
    violation_replay = _checked_violation_if_declared(
        case=case,
        case_root=case_root,
        prepared=prepared,
        out=prepared.parent / "violation",
        flake=flake,
        builders_file=builders_file,
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
        frontiers=tuple(initial_frontiers + _acceptance_frontiers(prepare_result)),
        violation=violation_result,
        error=None,
    )


def _checked_violation_if_declared(
    *,
    case: CaseManifest,
    case_root: Path,
    prepared: Path,
    out: Path,
    flake: Path | None,
    builders_file: Path | None,
) -> CheckedViolationReplay | None:
    roles = {artifact.role for artifact in case.artifacts}
    declared_witness = "violation_witness" in roles
    if (
        not declared_witness
        and case.expectation.disposition is not ExpectedDisposition.VIOLATED
    ):
        return None
    started = time.monotonic()
    witness_path = (
        case.artifact("violation_witness").verify(case_root)
        if declared_witness else None
    )
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
            flake=flake,
            builders_file=builders_file,
        )
        if production.get("status") != "checked":
            artifact = Path(str(production.get("derivation") or ""))
            return CheckedViolationReplay(
                result={
                    "format": "stage-a-checked-violation-result-v1",
                    "status": "incomplete",
                    "family": case.expectation.witness_family,
                    "reason_code": production.get("reason_code"),
                },
                cache_key=cache_key,
                cache_hit=False,
                duration_seconds=round(time.monotonic() - started, 6),
                artifact_sha256=(
                    sha256_file(artifact) if artifact.is_file() else "0" * 64
                ),
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
    effective_witness = witness_path if witness_path is not None else out / "witness.json"
    result = validate_checked_violation(
        witness_path=effective_witness,
        audit_path=audit_path,
        case=case,
        case_root=case_root,
        prepared=prepared,
        flake=flake,
        builders_file=builders_file,
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
        "witness_mode": (
            "declared" if any(
                artifact.role == "violation_witness" for artifact in case.artifacts
            ) else "automatic"
        ),
        "witness_sha256": (
            case.artifact("violation_witness").sha256
            if any(artifact.role == "violation_witness" for artifact in case.artifacts)
            else None
        ),
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


def _roundtrip_discovery_phase(
    phase: DiscoveryPhaseResult,
    discovery_out: Path,
) -> PhaseResult:
    if not isinstance(phase, DiscoveryPhaseResult):
        raise StageAInputError("round-trip discovery emitted an untyped phase")
    artifact = None
    artifact_sha256 = None
    if phase.artifact is not None:
        artifact_path = _contained_discovery_path(
            discovery_out,
            phase.artifact,
            context=f"discovery phase {phase.id!r} artifact",
        )
        if not artifact_path.is_file():
            raise StageAInputError(
                f"discovery phase {phase.id!r} artifact does not exist: "
                f"{artifact_path}"
            )
        artifact_sha256 = sha256_file(artifact_path)
        if artifact_sha256 != phase.artifact_sha256:
            raise StageAInputError(
                f"discovery phase {phase.id!r} artifact hash does not match"
            )
        artifact = f"discovery/{Path(phase.artifact).as_posix()}"
    elif phase.artifact_sha256 is not None:
        raise StageAInputError(
            f"discovery phase {phase.id!r} has a hash without an artifact"
        )
    return PhaseResult(
        id=phase.id,
        status=phase.status,
        cache_key=phase.cache_key,
        cache_hit=phase.cache_hit,
        duration_seconds=phase.duration_seconds,
        artifact=artifact,
        artifact_sha256=artifact_sha256,
        reason_code=phase.reason_code,
    )


def _verified_discovery_artifact(
    result: DiscoveryCaseResult,
    discovery_out: Path,
    *,
    role: str,
    expected_format: str | None = None,
) -> Path:
    matches = [artifact for artifact in result.artifacts if artifact.role == role]
    if len(matches) != 1:
        raise StageAInputError(
            f"round-trip discovery must publish exactly one {role!r} artifact"
        )
    artifact = matches[0]
    path = _contained_discovery_path(
        discovery_out,
        artifact.path,
        context=f"discovery artifact {role!r}",
    )
    if not path.is_file():
        raise StageAInputError(f"discovery artifact {role!r} does not exist: {path}")
    if sha256_file(path) != artifact.sha256:
        raise StageAInputError(f"discovery artifact {role!r} hash does not match")
    if expected_format is not None:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise StageAInputError(
                f"discovery artifact {role!r} is not valid JSON"
            ) from exc
        if not isinstance(payload, dict) or payload.get("format") != expected_format:
            raise StageAInputError(
                f"discovery artifact {role!r} does not have format "
                f"{expected_format!r}"
            )
    return path


def _contained_discovery_path(
    root: Path,
    relative: str,
    *,
    context: str,
) -> Path:
    relative_path = Path(relative)
    if relative_path.is_absolute():
        raise StageAInputError(f"{context} path must be relative")
    resolved_root = root.resolve()
    resolved = (resolved_root / relative_path).resolve()
    if resolved_root not in resolved.parents:
        raise StageAInputError(f"{context} escapes the discovery output")
    return resolved


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


def _case_proof_input_key(
    case: CaseManifest,
    proof_inputs: ProofInputs,
) -> str:
    values = [
        case.artifact("original_pe").sha256,
        case.artifact("candidate_pe").sha256,
        proof_inputs.relation_contract_sha256,
        proof_inputs.layout_contract_sha256 or "no-layout-contract",
        proof_inputs.relation_origin,
    ]
    values.append(_preparation_implementation_sha256())
    return sha256("\0".join(values).encode("ascii")).hexdigest()


def _case_static_preflight_key(
    case: CaseManifest,
    proof_inputs: ProofInputs,
) -> str:
    values = [
        case.artifact("original_pe").sha256,
        case.artifact("candidate_pe").sha256,
        proof_inputs.relation_contract_sha256,
        proof_inputs.layout_contract_sha256 or "no-layout-contract",
        proof_inputs.relation_origin,
    ]
    values.append(_static_preflight_implementation_sha256())
    return sha256("\0".join(values).encode("ascii")).hexdigest()


def _static_preflight_cache_matches(*, path: Path, cache_key: str) -> bool:
    if not path.is_file():
        return False
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return (
        isinstance(payload, dict)
        and payload.get("format") == "stage-a-relational-static-preflight-v1"
        and payload.get("roundtrip_cache_key") == cache_key
    )


@lru_cache(maxsize=1)
def _static_preflight_implementation_sha256() -> str:
    package_root = Path(__file__).resolve().parents[1]
    paths = (
        package_root / "stage_binary.py",
        package_root / "relational" / "contract.py",
        package_root / "relational" / "extraction.py",
        package_root / "relational" / "preflight.py",
        package_root / "relational" / "schema.py",
        package_root / "relational" / "x87_profile.py",
    )
    digest = sha256()
    digest.update(inspect.getsource(stage_a_preflight_relational).encode("utf-8"))
    for path in paths:
        digest.update(path.relative_to(package_root).as_posix().encode("utf-8"))
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _prepared_cache_matches(
    *,
    prepared: Path,
    case: CaseManifest,
    proof_inputs: ProofInputs,
) -> bool:
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
        manifest.get("format") in {
            "stage-a-prepared-relational-v1",
            "stage-a-prepared-relational-v2",
        }
        and manifest.get("original_sha256") == case.artifact("original_pe").sha256
        and manifest.get("candidate_sha256") == case.artifact("candidate_pe").sha256
        and interface == stage_a_interface_manifest()
        and binding == _input_binding_payload(case, proof_inputs)
        and (prepared / "module-graph.json").is_file()
        and (prepared / "relation-contract.json").is_file()
    )


def _input_binding_payload(
    case: CaseManifest,
    proof_inputs: ProofInputs,
) -> dict[str, Any]:
    return {
        "format": "stage-a-roundtrip-proof-input-binding-v2",
        "case_id": case.id,
        "original_sha256": case.artifact("original_pe").sha256,
        "candidate_sha256": case.artifact("candidate_pe").sha256,
        "relation_contract_input_sha256": proof_inputs.relation_contract_sha256,
        "relation_contract_origin": proof_inputs.relation_origin,
        "layout_contract_input_sha256": proof_inputs.layout_contract_sha256,
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

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

import pefile

from ..stage_b_c_backend import stage_b_generate_semantic_c_from_state_machine
from ..stage_b_state_machine import normalize_stage_a_semantic_transfer
from ..stage_binary import StageAInputError
from ..util import sha256_file, write_json
from ..relational.report import (
    NixBuildReport,
    STAGE_A_PROOF_HANDOFF_FORMAT,
)
from .provenance import (
    OpaqueStageBInput,
    is_stage_a_proof_only_manual_role,
    validate_opaque_stage_b_input_bundle,
)


__all__ = [
    "CANDIDATE_SOURCE_MANIFEST_FORMAT",
    "NATIVE_ENTRY_MANIFEST_FORMAT",
    "OPAQUE_STAGE_B_PROVENANCE_AUDIT_FORMAT",
    "OPAQUE_STAGE_B_ROUNDTRIP_FORMAT",
    "RELATIONAL_PROOF_HANDOFF_FORMAT",
    "RoundTripInput",
    "StageAProofCallback",
    "StageAProofRequest",
    "StageAProofResult",
    "StageBToolchainCallback",
    "StageBToolchainRequest",
    "StageBToolchainResult",
    "make_mingw_stage_b_toolchain_callback",
    "make_relational_v3_stage_a_proof_callback",
    "run_opaque_stage_b_roundtrip",
    "run_opaque_stage_b_relational_roundtrip",
    "run_static_opaque_stage_b_relational_roundtrip",
    "stage_a_proof_result_from_relational_report",
]


OPAQUE_STAGE_B_ROUNDTRIP_FORMAT = "stage-b-opaque-roundtrip-result-v1"
CANDIDATE_SOURCE_MANIFEST_FORMAT = "stage-b-opaque-candidate-source-v1"
NATIVE_ENTRY_MANIFEST_FORMAT = "stage-b-native-entry-lowering-v1"
OPAQUE_STAGE_B_PROVENANCE_AUDIT_FORMAT = "stage-b-opaque-roundtrip-provenance-audit-v1"
RELATIONAL_PROOF_HANDOFF_FORMAT = "stage-b-relational-proof-handoff-v1"

_PASS = "pass"
_INCOMPLETE = "incomplete"
_VIOLATED = "violated"
_PROOF_STATUSES = frozenset({_PASS, _INCOMPLETE, _VIOLATED})
_FORBIDDEN_STRUCTURED_KEYS = frozenset({
    "generator_semantic_program",
    "generator_semantics",
    "generator_seed",
    "ground_truth",
    "ground_truth_map",
    "original_runtime_trace",
    "original_source",
    "private_lowering_metadata",
    "source_labels",
    "transformation_history",
})
_FORBIDDEN_CLASS_VALUES = _FORBIDDEN_STRUCTURED_KEYS | frozenset({"original_pe"})


@dataclass(frozen=True)
class RoundTripInput:
    """A hash-bound input visible at one orchestration boundary."""

    role: str
    origin: str
    path: Path
    sha256: str
    bytes: int

    def to_payload(self, *, root: Path | None = None) -> dict[str, Any]:
        path = self.path
        if root is not None:
            path = path.relative_to(root)
        return {
            "role": self.role,
            "origin": self.origin,
            "path": path.as_posix(),
            "sha256": self.sha256,
            "bytes": self.bytes,
        }


@dataclass(frozen=True)
class StageBToolchainRequest:
    """Compiler-facing inputs. Toolchain binaries belong in result provenance."""

    out_dir: Path
    source_dir: Path
    source_manifest: Path
    source_map: Path
    implementation_manifest: Path
    generated_sources: tuple[Path, ...]
    generated_headers: tuple[Path, ...]
    manual_annotations: tuple[RoundTripInput, ...]
    native_entry_source: Path | None = None
    native_entry_symbol: str | None = None

    @property
    def allowed_semantic_inputs(self) -> tuple[Path, ...]:
        return (
            self.generated_sources
            + self.generated_headers
            + tuple(item.path for item in self.manual_annotations)
            + (self.source_manifest, self.source_map, self.implementation_manifest)
        )


@dataclass(frozen=True)
class StageBToolchainResult:
    status: str
    candidate_pe: Path | None
    linker_map: Path | None = None
    consumed_inputs: tuple[Path, ...] = ()
    provenance: Mapping[str, Any] = field(default_factory=dict)
    diagnostics: tuple[Mapping[str, Any], ...] = ()


@dataclass(frozen=True)
class StageAProofRequest:
    """Proof-facing inputs; no generator artifact or original runtime trace is exposed."""

    out_dir: Path
    reference_contract: Path
    static_inputs: tuple[RoundTripInput, ...]
    candidate_pe: Path
    linker_map: Path | None
    source_manifest: Path
    source_map: Path
    implementation_manifest: Path
    original_pe_sha256: str
    reference_contract_sha256: str
    state_machine_sha256: str
    original_pe: Path | None = None
    relation_contract: Path | None = None

    @property
    def allowed_inputs(self) -> tuple[Path, ...]:
        paths = tuple(item.path for item in self.static_inputs) + (
            self.candidate_pe,
            self.source_manifest,
            self.source_map,
            self.implementation_manifest,
        )
        optional = tuple(
            path
            for path in (self.original_pe, self.relation_contract, self.linker_map)
            if path is not None
        )
        return paths + optional


@dataclass(frozen=True)
class StageAProofResult:
    status: str
    report: Path
    consumed_inputs: tuple[Path, ...]
    provenance: Mapping[str, Any]
    final_theorem: str | None = None
    lean_kernel_checked: bool = False
    unchecked_markers: tuple[str, ...] = ()
    diagnostics: tuple[Mapping[str, Any], ...] = ()
    handoff: Mapping[str, Any] = field(default_factory=dict)


StageBToolchainCallback = Callable[[StageBToolchainRequest], StageBToolchainResult]
StageAProofCallback = Callable[[StageAProofRequest], StageAProofResult]


def make_mingw_stage_b_toolchain_callback(
    *,
    compiler: str = "i686-w64-mingw32-gcc",
) -> StageBToolchainCallback:
    """Return a deterministic MinGW callback for the generated semantic-C package."""

    compiler_path = shutil.which(compiler)
    if compiler_path is None:
        raise StageAInputError(f"MinGW compiler is unavailable: {compiler}")
    version = subprocess.run(
        [compiler_path, "--version"],
        check=True,
        text=True,
        capture_output=True,
    ).stdout.splitlines()[0]

    def compile_candidate(request: StageBToolchainRequest) -> StageBToolchainResult:
        native_entry = request.native_entry_source
        native_mode = native_entry is not None
        if native_mode:
            if native_entry not in request.generated_sources:
                raise StageAInputError(
                    "Stage B native entry source is not a generated compiler input"
                )
            if not request.native_entry_symbol or not re.fullmatch(
                r"[A-Za-z_][A-Za-z0-9_]*", request.native_entry_symbol
            ):
                raise StageAInputError("Stage B native entry symbol is malformed")
        candidate = request.out_dir / ("candidate.exe" if native_mode else "candidate.dll")
        linker_map = request.out_dir / "candidate.map"
        common_flags = [
            "-std=c11", "-O0", "-g0", "-fno-ident",
            "-fomit-frame-pointer",
            "-fno-asynchronous-unwind-tables", "-fno-stack-protector",
            "-Wl,--no-insert-timestamp", f"-Wl,-Map,{linker_map}",
        ]
        if native_mode:
            mode_flags = [
                "-nostdlib",
                f"-Wl,--entry,_{request.native_entry_symbol}",
                "-Wl,--subsystem,console",
                "-Wl,--exclude-all-symbols",
                "-Wl,--disable-dynamicbase",
                "-Wl,--image-base,0x400000",
                "-Wl,--section-alignment,0x1000",
                "-Wl,--file-alignment,0x400",
            ]
            compiler_sources = (native_entry,)
            link_tail = ("-lkernel32",)
        else:
            mode_flags = ["-shared"]
            compiler_sources = request.generated_sources
            link_tail = ()
        command = [
            compiler_path,
            *common_flags,
            *mode_flags,
            "-I", str(request.source_dir),
            "-o", str(candidate),
            *(str(path) for path in compiler_sources),
            *link_tail,
        ]
        completed = subprocess.run(
            command,
            text=True,
            capture_output=True,
            env={
                **os.environ,
                "LC_ALL": "C",
                "SOURCE_DATE_EPOCH": "1",
                "ZERO_AR_DATE": "1",
            },
        )
        consumed = (
            request.source_manifest,
            request.implementation_manifest,
            *compiler_sources,
        )
        provenance = {
            "format": "stage-b-mingw-toolchain-provenance-v1",
            "compiler": compiler_path,
            "compiler_sha256": sha256_file(Path(compiler_path)),
            "compiler_version": version,
            "target": "i686-w64-mingw32",
            "mode": "no-crt-native-entry" if native_mode else "semantic-runtime-dll",
            "entry_symbol": request.native_entry_symbol if native_mode else None,
            "flags": [*common_flags, *mode_flags],
            "source_manifest_sha256": sha256_file(request.source_manifest),
            "implementation_manifest_sha256": sha256_file(request.implementation_manifest),
        }
        if completed.returncode != 0:
            return StageBToolchainResult(
                status=_INCOMPLETE,
                candidate_pe=None,
                consumed_inputs=tuple(consumed),
                provenance=provenance,
                diagnostics=({
                    "category": "mingw_compile_failed",
                    "returncode": completed.returncode,
                    "stderr": completed.stderr[-8000:],
                },),
            )
        try:
            candidate_pe = pefile.PE(data=candidate.read_bytes(), fast_load=True)
            valid_pe32 = (
                int(candidate_pe.FILE_HEADER.Machine) == 0x14C
                and int(candidate_pe.OPTIONAL_HEADER.Magic) == 0x10B
            )
        except (OSError, pefile.PEFormatError):
            valid_pe32 = False
        if not candidate.is_file() or not valid_pe32:
            return StageBToolchainResult(
                status=_INCOMPLETE,
                candidate_pe=None,
                consumed_inputs=tuple(consumed),
                provenance=provenance,
                diagnostics=({"category": "mingw_output_is_not_pe"},),
            )
        return StageBToolchainResult(
            status=_PASS,
            candidate_pe=candidate,
            linker_map=linker_map,
            consumed_inputs=tuple(consumed),
            provenance=provenance,
        )

    return compile_candidate


def stage_a_proof_result_from_relational_report(
    *,
    report: Path,
    consumed_inputs: Sequence[Path],
    provenance: Mapping[str, Any],
    handoff: Mapping[str, Any] | None = None,
) -> StageAProofResult:
    """Adapt a canonical Nix proof report into the round-trip callback result."""

    report = Path(report)
    try:
        payload = json.loads(report.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"cannot read Stage A relational verdict: {exc}") from exc
    if not isinstance(payload, dict):
        raise StageAInputError("Stage A proof callback requires a Nix proof report")
    view = _relational_report_view(payload, report_root=report.parent)
    verdict = view["verdict"]
    status = {_PASS: _PASS, "fail": _VIOLATED, _INCOMPLETE: _INCOMPLETE}.get(verdict)
    if status is None:
        raise StageAInputError("Stage A relational verdict has an unsupported disposition")
    theorem = view["theorem"] if status == _PASS else None
    handoff_payload = _json_value(handoff or {})
    frontier = handoff_payload.get("frontier", [])
    diagnostics = tuple(frontier) if isinstance(frontier, list) else ()
    return StageAProofResult(
        status=status,
        report=report,
        consumed_inputs=tuple(Path(path) for path in consumed_inputs),
        provenance=provenance,
        final_theorem=theorem,
        lean_kernel_checked=bool(view["lean_kernel_checked"]),
        unchecked_markers=(),
        diagnostics=diagnostics,
        handoff=handoff_payload,
    )


def _relational_report_view(
    payload: Mapping[str, Any], *, report_root: Path | None = None
) -> dict[str, Any]:
    """Validate the sole authoritative Nix report without upgrading trust."""

    report = NixBuildReport.parse(payload)
    independently_checked = False
    if report.declares_checked_pass and report_root is not None:
        from ..relational.pipeline import stage_a_check_relational_proof

        try:
            replay = stage_a_check_relational_proof(report=report_root)
        except (OSError, StageAInputError, ValueError):
            replay = {}
        independently_checked = replay.get("status") == _PASS
    checked = report.declares_checked_pass and independently_checked
    return {
        "format": payload.get("format"),
        "verdict": (
            report.verdict
            if report.verdict != _PASS or checked
            else _INCOMPLETE
        ),
        "profile": payload.get("profile"),
        "acceptance_authority": "whole_program_lean" if checked else None,
        "claim_scope": payload.get("claim_scope"),
        "original": payload.get("original"),
        "candidate": payload.get("candidate"),
        "theorem": payload.get("expected_final_theorem") if checked else None,
        "lean_kernel_checked": checked,
    }


def _stage_a_proof_result_from_handoff(
    *,
    report: Path,
    consumed_inputs: Sequence[Path],
    provenance: Mapping[str, Any],
    handoff: Mapping[str, Any],
) -> StageAProofResult:
    payload = _read_optional_json(report)
    if (
        payload.get("format") != STAGE_A_PROOF_HANDOFF_FORMAT
        or payload.get("acceptance_authority") is not False
        or payload.get("status") != _INCOMPLETE
    ):
        raise StageAInputError("Stage A proof handoff diagnostic is malformed")
    handoff_payload = _json_value(handoff)
    frontier = handoff_payload.get("frontier", [])
    return StageAProofResult(
        status=_INCOMPLETE,
        report=report,
        consumed_inputs=tuple(Path(path) for path in consumed_inputs),
        provenance=provenance,
        final_theorem=None,
        lean_kernel_checked=False,
        unchecked_markers=(),
        diagnostics=tuple(frontier) if isinstance(frontier, list) else (),
        handoff=handoff_payload,
    )


def make_relational_v3_stage_a_proof_callback(
    *,
    original_pe: Path,
    flake: Path | None = None,
    builders_file: Path | None = None,
    execute_proof: bool = True,
) -> StageAProofCallback:
    """Create the ordinary relational-v3 proof handoff for an opaque Stage B build.

    The original PE is held by this Stage A-only closure. It is never included in
    the opaque bundle or a compiler request, and it is only parsed statically by
    the relational proof pipeline.
    """

    original_pe = Path(original_pe).resolve()
    if not original_pe.is_file() or original_pe.is_symlink():
        raise StageAInputError("Stage A original proof image must be a regular file")
    original_sha256 = sha256_file(original_pe)
    flake_path = Path(flake).resolve() if flake is not None else None
    builders_path = (
        Path(builders_file).resolve() if builders_file is not None else None
    )

    def prove(request: StageAProofRequest) -> StageAProofResult:
        if request.original_pe is None or request.original_pe.resolve() != original_pe:
            raise StageAInputError("Stage A proof request did not preserve its original image binding")
        if request.original_pe_sha256 != original_sha256:
            raise StageAInputError("Stage A original proof image disagrees with the reference contract")
        consumed = [request.reference_contract, original_pe, request.candidate_pe]
        relation_contract = request.relation_contract
        if relation_contract is None:
            handoff = _proof_handoff_without_relation_contract(request)
            report = _write_proof_handoff_report(
                request=request,
                handoff=handoff,
            )
            return _stage_a_proof_result_from_handoff(
                report=report,
                consumed_inputs=consumed,
                provenance=_stage_a_handoff_provenance(
                    original_pe=original_pe,
                    request=request,
                    relation_contract=None,
                    prepared=None,
                    built=None,
                ),
                handoff=handoff,
            )

        relation_contract = Path(relation_contract).resolve()
        consumed.append(relation_contract)
        prepared = request.out_dir / "prepared"
        built = request.out_dir / "built"
        from ..relational.nix_pipeline import stage_a_prepare_relational_nix

        try:
            stage_a_prepare_relational_nix(
                original=original_pe,
                candidate=request.candidate_pe,
                relation_contract=relation_contract,
                out=prepared,
                flake=flake_path,
                builders_file=builders_path,
            )
        except (OSError, StageAInputError, ValueError) as exc:
            handoff = _proof_handoff_for_exception(
                phase="prepare",
                category="relational_proof_preparation_failed",
                message=str(exc),
                next_action="repair the recorded relation contract or static proof inputs",
            )
            report = _write_proof_handoff_report(
                request=request, handoff=handoff
            )
            return _stage_a_proof_result_from_handoff(
                report=report,
                consumed_inputs=consumed,
                provenance=_stage_a_handoff_provenance(
                    original_pe=original_pe,
                    request=request,
                    relation_contract=relation_contract,
                    prepared=prepared if prepared.is_dir() else None,
                    built=None,
                ),
                handoff=handoff,
            )

        handoff = _proof_handoff_from_prepared(prepared, phase="prepared")
        prepared_ready = _prepared_acceptance_ready(prepared)
        if not prepared_ready or not execute_proof:
            if prepared_ready and not execute_proof:
                handoff = _append_handoff_frontier(
                    handoff,
                    category="relational_proof_build_deferred",
                    message="the relational graph is prepared but has not been built",
                    next_action="build the prepared graph with the pinned Nix executor",
                )
            prepared_report = _write_proof_handoff_report(
                request=request, handoff=handoff
            )
            return _stage_a_proof_result_from_handoff(
                report=prepared_report,
                consumed_inputs=consumed,
                provenance=_stage_a_handoff_provenance(
                    original_pe=original_pe,
                    request=request,
                    relation_contract=relation_contract,
                    prepared=prepared,
                    built=None,
                ),
                handoff=handoff,
            )

        from ..relational.build import stage_a_build_relational

        try:
            stage_a_build_relational(
                prepared=prepared,
                out=built,
                flake=flake_path,
                builders_file=builders_path,
            )
        except (OSError, StageAInputError, ValueError) as exc:
            handoff = _append_handoff_frontier(
                _proof_handoff_from_prepared(prepared, phase="build_failed"),
                category="relational_proof_build_failed",
                message=str(exc),
                next_action="inspect the Nix proof logs and retry the unchanged prepared graph",
            )
            report = _write_proof_handoff_report(
                request=request, handoff=handoff
            )
            return _stage_a_proof_result_from_handoff(
                report=report,
                consumed_inputs=consumed,
                provenance=_stage_a_handoff_provenance(
                    original_pe=original_pe,
                    request=request,
                    relation_contract=relation_contract,
                    prepared=prepared,
                    built=built if built.is_dir() else None,
                ),
                handoff=handoff,
            )
        else:
            report = built / "verdict.json"
            handoff = _proof_handoff_from_prepared(
                built if (built / "composition-progress.json").is_file() else prepared,
                phase="proved",
            )
            if not report.is_file():
                handoff = _append_handoff_frontier(
                    handoff,
                    category="relational_proof_verdict_missing",
                    message="the Nix proof build omitted its verdict",
                    next_action="repair the proof-build artifact handoff",
                )
                report = _write_proof_handoff_report(
                    request=request, handoff=handoff
                )
                return _stage_a_proof_result_from_handoff(
                    report=report,
                    consumed_inputs=consumed,
                    provenance=_stage_a_handoff_provenance(
                        original_pe=original_pe,
                        request=request,
                        relation_contract=relation_contract,
                        prepared=prepared,
                        built=built if built.is_dir() else None,
                    ),
                    handoff=handoff,
                )
        return stage_a_proof_result_from_relational_report(
            report=report,
            consumed_inputs=consumed,
            provenance=_stage_a_handoff_provenance(
                original_pe=original_pe,
                request=request,
                relation_contract=relation_contract,
                prepared=prepared,
                built=built if built.is_dir() else None,
            ),
            handoff=handoff,
        )

    return prove


def run_opaque_stage_b_relational_roundtrip(
    *,
    opaque_bundle_manifest: Path,
    original_pe: Path,
    out: Path,
    compiler: str = "i686-w64-mingw32-gcc",
    flake: Path | None = None,
    builders_file: Path | None = None,
    execute_proof: bool = True,
) -> dict[str, Any]:
    """Run the public opaque Stage B path through normal relational-v3 proof."""

    return run_opaque_stage_b_roundtrip(
        opaque_bundle_manifest=opaque_bundle_manifest,
        out=out,
        toolchain_callback=make_mingw_stage_b_toolchain_callback(
            compiler=compiler
        ),
        stage_a_proof_callback=make_relational_v3_stage_a_proof_callback(
            original_pe=original_pe,
            flake=flake,
            builders_file=builders_file,
            execute_proof=execute_proof,
        ),
        stage_a_original_pe=original_pe,
    )


def run_static_opaque_stage_b_relational_roundtrip(
    *,
    original_pe: Path,
    original_linker_map: Path,
    out: Path,
    compiler: str = "i686-w64-mingw32-gcc",
    flake: Path | None = None,
    builders_file: Path | None = None,
    execute_proof: bool = True,
) -> dict[str, Any]:
    """Exercise the complete opaque-static Stage A -> Stage B -> Stage A loop.

    Linker maps remain untrusted Stage A hints.  Neither the original image,
    either map, nor the candidate-specific relation contract crosses the
    Stage B generation or compiler boundaries.
    """

    from ..contract_tools import (
        stage_a_export_reference_contract,
        stage_a_generate_map,
    )
    from ..relational.contract import stage_a_generate_relation_contract
    from ..stage_b_state_machine import (
        write_stage_b_state_machine_from_stage_a_export,
    )
    from .provenance import build_opaque_stage_b_input_bundle

    original_pe = Path(original_pe).resolve()
    original_linker_map = Path(original_linker_map).resolve()
    out = Path(out).resolve()
    if not original_pe.is_file() or not original_linker_map.is_file():
        raise StageAInputError(
            "opaque Stage B static round trip requires an original PE and linker map"
        )
    if out.exists():
        shutil.rmtree(out)
    static_dir = out / "stage-a-static-export"
    static_dir.mkdir(parents=True)
    self_map = static_dir / "original-self-map.json"
    self_map_result = stage_a_generate_map(
        original=original_pe,
        candidate=original_pe,
        linker_map_original=original_linker_map,
        linker_map_candidate=original_linker_map,
        out=self_map,
        original_flags="opaque-static-original",
        candidate_flags="opaque-static-reference",
    )
    if self_map_result.get("status") != _PASS:
        raise StageAInputError("Stage A could not map the static original to itself")
    reference_contract = static_dir / "reference-contract.json"
    stage_a_export_reference_contract(
        original=original_pe,
        out=reference_contract,
        mapping=self_map,
        sidecar_dir=static_dir,
        unit_contract_dir=static_dir,
    )
    semantic_transfers = static_dir / "semantic-transfer-contracts.jsonl"
    state_machine = static_dir / "state-machine.jsonl"
    write_stage_b_state_machine_from_stage_a_export(
        reference_contract=reference_contract,
        semantic_transfer_contracts=semantic_transfers,
        original_pe=original_pe,
        out=state_machine,
    )
    bootstrap_bundle = out / "opaque-bootstrap-bundle"
    build_opaque_stage_b_input_bundle(
        out=bootstrap_bundle,
        original_pe=original_pe,
        reference_contract=reference_contract,
        semantic_transfer_contracts=semantic_transfers,
        state_machine=state_machine,
    )
    bootstrap_out = out / "bootstrap-candidate"
    bootstrap = run_opaque_stage_b_relational_roundtrip(
        opaque_bundle_manifest=bootstrap_bundle / "manifest.json",
        original_pe=original_pe,
        out=bootstrap_out,
        compiler=compiler,
        flake=flake,
        builders_file=builders_file,
        execute_proof=False,
    )
    compilation = bootstrap.get("compilation")
    if not isinstance(compilation, Mapping) or compilation.get("status") != _PASS:
        return bootstrap
    candidate_artifact = compilation.get("candidate_pe")
    candidate_map_artifact = compilation.get("linker_map")
    if not isinstance(candidate_artifact, Mapping) or not isinstance(
        candidate_map_artifact, Mapping
    ):
        raise StageAInputError("opaque Stage B bootstrap omitted candidate artifacts")
    bootstrap_candidate = bootstrap_out / str(candidate_artifact.get("path"))
    bootstrap_candidate_map = bootstrap_out / str(candidate_map_artifact.get("path"))
    relation_proposal = static_dir / "candidate-relation-proposal.json"
    proposal_result = stage_a_generate_map(
        original=original_pe,
        candidate=bootstrap_candidate,
        linker_map_original=original_linker_map,
        linker_map_candidate=bootstrap_candidate_map,
        out=relation_proposal,
        original_flags="opaque-static-original",
        candidate_flags="stage-b-generated-semantic-c",
    )
    if proposal_result.get("status") != _PASS:
        raise StageAInputError("Stage A could not map the generated candidate")
    relation_contract = static_dir / "candidate-relation-contract.json"
    relation_result = stage_a_generate_relation_contract(
        original=original_pe,
        candidate=bootstrap_candidate,
        mapping=relation_proposal,
        out=relation_contract,
    )
    if relation_result.get("status") != "generated":
        raise StageAInputError(
            "Stage A could not construct the generated candidate relation contract"
        )
    proved_bundle = out / "opaque-proved-bundle"
    build_opaque_stage_b_input_bundle(
        out=proved_bundle,
        original_pe=original_pe,
        reference_contract=reference_contract,
        semantic_transfer_contracts=semantic_transfers,
        state_machine=state_machine,
        manual_annotations=(("relational-proof-contract", relation_contract),),
    )
    result = run_opaque_stage_b_relational_roundtrip(
        opaque_bundle_manifest=proved_bundle / "manifest.json",
        original_pe=original_pe,
        out=out / "proved-candidate",
        compiler=compiler,
        flake=flake,
        builders_file=builders_file,
        execute_proof=execute_proof,
    )
    write_json(out / "static-roundtrip-bootstrap.json", {
        "format": "stage-b-static-roundtrip-bootstrap-v1",
        "status": "ready",
        "original_pe_sha256": sha256_file(original_pe),
        "bootstrap_candidate_sha256": sha256_file(bootstrap_candidate),
        "proved_candidate_sha256": result.get("compilation", {}).get(
            "candidate_pe", {}
        ).get("sha256"),
        "candidate_reproducible": (
            sha256_file(bootstrap_candidate)
            == result.get("compilation", {}).get("candidate_pe", {}).get("sha256")
        ),
        "relation_contract_sha256": sha256_file(relation_contract),
        "stage_b_saw_relation_contract": False,
        "stage_b_executed_original": False,
    })
    return result


def _proof_handoff_without_relation_contract(
    request: StageAProofRequest,
) -> dict[str, Any]:
    return {
        "format": RELATIONAL_PROOF_HANDOFF_FORMAT,
        "status": _INCOMPLETE,
        "phase": "relation_contract",
        "original_pe_sha256": request.original_pe_sha256,
        "candidate_pe_sha256": sha256_file(request.candidate_pe),
        "prepared_proof": None,
        "expected_final_theorem": None,
        "counts": {"frontier_items": 1},
        "frontier": [{
            "category": "recorded_relational_proof_contract_missing",
            "severity": "hard",
            "location": {"phase": "stage_a_relation_proposal"},
            "message": (
                "the opaque handoff has no candidate-specific relation contract"
            ),
            "next_action": (
                "record a manual-relational-proof-contract annotation produced "
                "from static original/candidate mapping evidence"
            ),
        }],
        "acceptance_authority": False,
    }


def _proof_handoff_for_exception(
    *, phase: str, category: str, message: str, next_action: str
) -> dict[str, Any]:
    return {
        "format": RELATIONAL_PROOF_HANDOFF_FORMAT,
        "status": _INCOMPLETE,
        "phase": phase,
        "prepared_proof": None,
        "expected_final_theorem": None,
        "counts": {"frontier_items": 1},
        "frontier": [{
            "category": category,
            "severity": "hard",
            "location": {"phase": phase},
            "message": message,
            "next_action": next_action,
        }],
        "acceptance_authority": False,
    }


def _proof_handoff_from_prepared(root: Path, *, phase: str) -> dict[str, Any]:
    root = Path(root)
    acceptance = _read_optional_json(root / "whole-program-acceptance.json")
    progress = _read_optional_json(root / "composition-progress.json")
    semantic = _read_optional_json(root / "semantic-gaps.json")
    manifest = _read_optional_json(root / "prepared-proof.json")
    graph = _read_optional_json(root / "module-graph.json")
    verdict = _read_optional_json(root / "verdict.json")
    frontier: list[dict[str, Any]] = []

    for issue in semantic.get("issues", []) if isinstance(semantic.get("issues"), list) else []:
        if not isinstance(issue, dict):
            continue
        frontier.append({
            "category": str(issue.get("category") or "unsupported_x86_semantics"),
            "severity": str(issue.get("severity") or "hard"),
            "location": _json_value(issue.get("location") or {"phase": "semantic_preflight"}),
            "message": str(issue.get("message") or issue.get("summary") or "semantic support is incomplete"),
            "next_action": str(issue.get("next_action") or "implement and qualify the missing reviewed semantics"),
        })
    blockers = acceptance.get("blockers")
    if not isinstance(blockers, list):
        progress_frontiers = progress.get("frontiers")
        blockers = (
            progress_frontiers.get("acceptance_blockers", [])
            if isinstance(progress_frontiers, dict)
            else []
        )
    for blocker in blockers:
        if not isinstance(blocker, dict):
            continue
        examples = blocker.get("examples")
        frontier.append({
            "category": str(blocker.get("code") or "whole_program_acceptance_incomplete"),
            "severity": "hard",
            "location": {
                "phase": "whole_program_composition",
                "examples": examples if isinstance(examples, list) else [],
            },
            "message": str(blocker.get("message") or "whole-program acceptance is incomplete"),
            "next_action": str(blocker.get("next_action") or "close the reported composition obligation"),
            "count": int(blocker.get("count") or 1),
        })
    acceptance_ready = acceptance.get("status") == "ready"
    if not frontier and not acceptance_ready and verdict.get("verdict") != _PASS:
        diagnostic = verdict.get("diagnostic")
        diagnostic = diagnostic if isinstance(diagnostic, dict) else {}
        frontier.append({
            "category": str(
                diagnostic.get("category")
                or "relational_proof_preparation_incomplete"
            ),
            "severity": str(diagnostic.get("severity") or "hard"),
            "location": {"phase": "relational_proof_preparation"},
            "message": str(
                diagnostic.get("summary")
                or verdict.get("blocker")
                or "relational proof preparation is incomplete"
            ),
            "next_action": str(
                diagnostic.get("next_action")
                or "repair the first incomplete proof-preparation obligation"
            ),
        })
    deduplicated: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in frontier:
        key = (item["category"], item["message"])
        if key not in seen:
            seen.add(key)
            deduplicated.append(item)
    frontier = deduplicated

    if not frontier and not acceptance_ready:
        frontier.append({
            "category": "whole_program_acceptance_not_ready",
            "severity": "hard",
            "location": {"phase": "whole_program_composition"},
            "message": "proof preparation did not produce an acceptance-ready graph",
            "next_action": "inspect the prepared verdict and composition progress",
        })
    expected_theorem = graph.get("expected_final_theorem")
    if not isinstance(expected_theorem, str):
        expected_theorem = manifest.get("expected_final_theorem")
    artifacts: dict[str, dict[str, Any]] = {}
    for name in (
        "prepared-proof.json",
        "module-graph.json",
        "whole-program-acceptance.json",
        "composition-progress.json",
        "semantic-gaps.json",
        "verdict.json",
    ):
        path = root / name
        if path.is_file():
            artifacts[name] = {
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
            }
    progress_counts = progress.get("counts")
    return {
        "format": RELATIONAL_PROOF_HANDOFF_FORMAT,
        "status": "ready" if acceptance_ready and not frontier else _INCOMPLETE,
        "phase": phase,
        "prepared_proof": {
            "path": str(root),
            "artifacts": artifacts,
        },
        "expected_final_theorem": expected_theorem,
        "counts": {
            "frontier_items": len(frontier),
            "composition": _json_value(progress_counts) if isinstance(progress_counts, dict) else {},
        },
        "frontier": frontier,
        "acceptance_authority": False,
    }


def _append_handoff_frontier(
    handoff: Mapping[str, Any], *, category: str, message: str, next_action: str
) -> dict[str, Any]:
    payload = _json_value(handoff)
    frontier = list(payload.get("frontier", []))
    frontier.append({
        "category": category,
        "severity": "hard",
        "location": {"phase": payload.get("phase")},
        "message": message,
        "next_action": next_action,
    })
    payload["status"] = _INCOMPLETE
    payload["frontier"] = frontier
    counts = payload.get("counts") if isinstance(payload.get("counts"), dict) else {}
    counts["frontier_items"] = len(frontier)
    payload["counts"] = counts
    return payload


def _prepared_acceptance_ready(prepared: Path) -> bool:
    acceptance = _read_optional_json(Path(prepared) / "whole-program-acceptance.json")
    graph = _read_optional_json(Path(prepared) / "module-graph.json")
    graph_acceptance = graph.get("acceptance")
    return (
        acceptance.get("status") == "ready"
        and isinstance(graph.get("expected_final_theorem"), str)
        and isinstance(graph_acceptance, dict)
        and graph_acceptance.get("status") == "ready"
    )


def _write_proof_handoff_report(
    *, request: StageAProofRequest, handoff: Mapping[str, Any]
) -> Path:
    report = request.out_dir / "handoff-verdict.json"
    report.parent.mkdir(parents=True, exist_ok=True)
    frontier = handoff.get("frontier") if isinstance(handoff.get("frontier"), list) else []
    first = frontier[0] if frontier and isinstance(frontier[0], dict) else {}
    write_json(report, {
        "format": STAGE_A_PROOF_HANDOFF_FORMAT,
        "status": _INCOMPLETE,
        "acceptance_authority": False,
        "profile": "x86-pe32-lean-relational-v3",
        "model": "x86-pe32-relational-v3",
        "claim_scope": {
            "kind": "whole_program_observational_equivalence",
            "whole_program_observational_equivalence": False,
            "acceptance_eligible": False,
        },
        "original": {"sha256": request.original_pe_sha256},
        "candidate": {"sha256": sha256_file(request.candidate_pe)},
        "diagnostic": {
            "category": first.get("category", "stage_a_proof_handoff_incomplete"),
            "severity": "hard",
            "next_action": first.get("next_action", "close the reported proof frontier"),
        },
    })
    return report


def _stage_a_handoff_provenance(
    *,
    original_pe: Path,
    request: StageAProofRequest,
    relation_contract: Path | None,
    prepared: Path | None,
    built: Path | None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "format": "stage-a-relational-proof-handoff-provenance-v1",
        "original_pe_sha256": sha256_file(original_pe),
        "candidate_pe_sha256": sha256_file(request.candidate_pe),
        "reference_contract_sha256": sha256_file(request.reference_contract),
        "relation_contract_sha256": (
            sha256_file(relation_contract) if relation_contract is not None else None
        ),
        "original_execution": False,
        "proof_pipeline": "stage-a-relational-v3",
    }
    for key, root, filename in (
        ("prepared_manifest_sha256", prepared, "prepared-proof.json"),
        ("nix_provenance_sha256", built, "nix-provenance.json"),
    ):
        path = root / filename if root is not None else None
        payload[key] = sha256_file(path) if path is not None and path.is_file() else None
    return payload


def _read_optional_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _generate_native_entry_source_from_state_machine(
    *, state_machine: Path, out_dir: Path
) -> tuple[Path | None, str | None, Path]:
    """Lower a deliberately small machine-state profile to a native C entry.

    This is a candidate-generation convenience, not proof evidence.  The
    profile is intentionally narrow because ordinary C has no portable way to
    name arbitrary incoming x86 registers.  Unsupported transfers remain in
    the general semantic runtime package and fail closed here.
    """

    state_machine = Path(state_machine)
    out_dir = Path(out_dir)
    manifest = out_dir / "state-machine-native-entry.json"
    source = out_dir / "state-machine-native-entry.c"
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(
        state_machine.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise StageAInputError(
                f"invalid state-machine JSON on line {line_number}: {exc}"
            ) from exc
        if not isinstance(raw, dict):
            raise StageAInputError(
                f"state-machine line {line_number} must be a JSON object"
            )
        rows.append(normalize_stage_a_semantic_transfer(raw))

    def esp_expression(value: Any) -> bool:
        return (
            isinstance(value, dict)
            and value.get("op") == "reg"
            and value.get("name") == "esp"
            and value.get("width") == 32
        )

    def esp_plus_four_expression(value: Any) -> bool:
        if not isinstance(value, dict) or value.get("op") != "add32":
            return False
        args = value.get("args")
        if not isinstance(args, list) or len(args) != 2:
            return False
        return any(esp_expression(item) for item in args) and any(
            isinstance(item, dict)
            and item.get("op") == "const"
            and item.get("width") == 32
            and item.get("value") == 4
            for item in args
        )

    blockers: list[str] = []
    row = rows[0] if len(rows) == 1 else None
    if row is None:
        blockers.append("native_entry_requires_one_transfer")
    else:
        if row.get("status") != "reimplementable" or row.get("reachable") is False:
            blockers.append("native_entry_transfer_not_reimplementable")
        if row.get("expression_model") != "stage-a-semantic-ir-v1":
            blockers.append("native_entry_expression_model_unsupported")
        outcome = row.get("outcome") if isinstance(row.get("outcome"), dict) else {}
        if outcome.get("kind") != "return":
            blockers.append("native_entry_outcome_not_return")
        for field in ("flag_writes", "external_events", "faults", "edge_conditions"):
            value = row.get(field)
            if value is not None and value != [] and value != ():
                blockers.append(f"native_entry_{field}_unsupported")
        if row.get("fpu_state") is not None:
            blockers.append("native_entry_fpu_state_unsupported")

    symbol: str | None = None
    result_value: int | None = None
    return_profile: str | None = None
    if row is not None:
        raw_symbol = str(row.get("function") or "")
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", raw_symbol):
            symbol = raw_symbol
        else:
            blockers.append("native_entry_function_identifier_unsupported")
        writes = row.get("register_writes")
        writes_list = writes if isinstance(writes, list) else []
        writes_by_register = {
            str(item.get("register")): item
            for item in writes_list
            if isinstance(item, dict)
        }
        if not isinstance(writes, list) or len(writes_by_register) != len(writes):
            blockers.append("native_entry_register_writes_malformed")
        eax_write = writes_by_register.get("eax", {})
        if eax_write:
            write = eax_write
            value = write.get("value") if isinstance(write.get("value"), dict) else {}
            if (
                value.get("op") != "const"
                or value.get("width") != 32
                or isinstance(value.get("value"), bool)
                or not isinstance(value.get("value"), int)
            ):
                blockers.append("native_entry_return_expression_unsupported")
            else:
                result_value = int(value["value"]) & 0xFFFFFFFF
        else:
            blockers.append("native_entry_return_expression_unsupported")

        memory_events = row.get("memory_events")
        ordered_events = row.get("ordered_events")
        stack_delta = row.get("stack_delta")
        outcome = row.get("outcome") if isinstance(row.get("outcome"), dict) else {}
        simple_return = (
            set(writes_by_register) == {"eax"}
            and stack_delta in (None, 0)
            and memory_events in (None, [])
            and ordered_events in (None, [])
            and set(outcome) == {"kind"}
        )
        esp_write = writes_by_register.get("esp", {})
        return_value = outcome.get("value") if isinstance(outcome.get("value"), dict) else {}
        machine_return = (
            set(writes_by_register) == {"eax", "esp"}
            and esp_plus_four_expression(esp_write.get("value"))
            and isinstance(stack_delta, dict)
            and stack_delta.get("status") == "derived"
            and stack_delta.get("net_bytes") == 4
            and esp_plus_four_expression(stack_delta.get("expression"))
            and isinstance(memory_events, list)
            and len(memory_events) == 1
            and memory_events[0].get("kind") == "read"
            and memory_events[0].get("width") == 4
            and esp_expression(memory_events[0].get("address"))
            and isinstance(ordered_events, list)
            and len(ordered_events) == 1
            and ordered_events[0].get("family") == "memory"
            and ordered_events[0].get("kind") == "read"
            and ordered_events[0].get("width") == 4
            and esp_expression(ordered_events[0].get("address"))
            and return_value.get("op") == "load"
            and return_value.get("width") == 4
            and esp_expression(return_value.get("address"))
        )
        if simple_return:
            return_profile = "abstract-return"
        elif machine_return:
            return_profile = "x86-stack-return"
        else:
            blockers.append("native_entry_return_protocol_unsupported")

    blockers = sorted(set(blockers))
    payload: dict[str, Any] = {
        "format": NATIVE_ENTRY_MANIFEST_FORMAT,
        "status": "ready" if not blockers else _INCOMPLETE,
        "profile": "single-transfer-constant-eax-return-v1",
        "return_profile": return_profile,
        "state_machine": {
            "sha256": sha256_file(state_machine),
            "transfers": len(rows),
        },
        "entry_symbol": symbol if not blockers else None,
        "transfer": (
            {
                "id": row.get("id"),
                "contract_sha256": row.get("contract_sha256"),
            }
            if row is not None
            else None
        ),
        "blockers": blockers,
        "authority": "candidate generation only; Stage A binary proof is required",
    }
    if blockers:
        write_json(manifest, payload)
        return None, None, manifest

    assert symbol is not None and result_value is not None
    source.write_text(
        "\n".join(
            [
                "#include <stdint.h>",
                "",
                "/* Generated from the opaque Stage A state-machine transfer. */",
                f"__attribute__((used)) uint32_t {symbol}(void) {{",
                f"  return 0x{result_value:08x}U;",
                "}",
                "",
            ]
        ),
        encoding="ascii",
    )
    payload["source"] = {
        "path": source.name,
        "sha256": sha256_file(source),
        "bytes": source.stat().st_size,
    }
    write_json(manifest, payload)
    return source, symbol, manifest


def run_opaque_stage_b_roundtrip(
    *,
    opaque_bundle_manifest: Path,
    out: Path,
    toolchain_callback: StageBToolchainCallback,
    stage_a_proof_callback: StageAProofCallback,
    stage_a_original_pe: Path | None = None,
) -> dict[str, Any]:
    """Generate, compile, and prove a candidate without exposing generator truth to Stage B."""

    manifest_path = Path(opaque_bundle_manifest).resolve()
    bundle_root = manifest_path.parent
    out = Path(out).resolve()
    _check_disjoint_roots(bundle_root, out)
    bundle_audit = validate_opaque_stage_b_input_bundle(manifest_path)
    provenance_chain = bundle_audit["provenance_chain"]
    bundle_inputs = _load_bundle_inputs(manifest_path)
    _audit_opaque_contents(bundle_inputs)

    if out.exists():
        shutil.rmtree(out)
    generation_dir = out / "generation"
    backend_dir = generation_dir / "semantic-c"
    compile_dir = out / "compile"
    proof_dir = out / "proof"
    backend_dir.mkdir(parents=True)
    compile_dir.mkdir(parents=True)
    proof_dir.mkdir(parents=True)

    inputs_by_role = {item.role: item for item in bundle_inputs}
    state_machine = inputs_by_role["state_machine"]
    reference_contract = inputs_by_role["reference_contract"]
    all_manual_annotations = tuple(
        item for item in bundle_inputs if item.origin == "manual_annotation"
    )
    manual_annotations = tuple(
        item
        for item in all_manual_annotations
        if not is_stage_a_proof_only_manual_role(item.role)
    )
    proof_annotations = tuple(
        item
        for item in all_manual_annotations
        if is_stage_a_proof_only_manual_role(item.role)
    )
    machine_call_catalog = inputs_by_role.get("manual-machine-call-catalog")
    relation_contract = inputs_by_role.get("manual-relational-proof-contract")
    original_proof_image = (
        Path(stage_a_original_pe).resolve()
        if stage_a_original_pe is not None
        else None
    )
    if original_proof_image is not None:
        if (
            not original_proof_image.is_file()
            or original_proof_image.is_symlink()
            or sha256_file(original_proof_image)
            != provenance_chain["original_pe_sha256"]
        ):
            raise StageAInputError(
                "Stage A original proof image is not the image bound by the opaque exports"
            )

    backend_report = stage_b_generate_semantic_c_from_state_machine(
        state_machine=state_machine.path,
        out_dir=backend_dir,
        machine_call_catalog=machine_call_catalog.path if machine_call_catalog is not None else None,
    )
    backend_artifacts = _backend_artifacts(backend_dir, backend_report)
    native_entry_source, native_entry_symbol, native_entry_manifest = (
        _generate_native_entry_source_from_state_machine(
            state_machine=state_machine.path,
            out_dir=backend_dir,
        )
    )
    backend_report = dict(backend_report)
    backend_report["native_entry"] = _read_optional_json(native_entry_manifest)
    source_map = backend_artifacts["source_map"]
    implementation_manifest = backend_artifacts["implementation_manifest"]
    generated_sources = tuple(
        sorted(
            (
                *(
                    item.path
                    for item in backend_artifacts.values()
                    if item.path.suffix.lower() == ".c"
                ),
                *((native_entry_source,) if native_entry_source is not None else ()),
            ),
            key=lambda path: path.name,
        )
    )
    generated_headers = tuple(
        sorted(
            (item.path for item in backend_artifacts.values() if item.path.suffix.lower() == ".h"),
            key=lambda path: path.name,
        )
    )
    if not generated_sources or not generated_headers:
        raise StageAInputError("Stage B semantic-C backend omitted compiler inputs")

    source_manifest = generation_dir / "candidate-source-manifest.json"
    source_manifest_payload = {
        "format": CANDIDATE_SOURCE_MANIFEST_FORMAT,
        "status": (
            "complete"
            if native_entry_source is not None
            else str(backend_report.get("status") or _INCOMPLETE)
        ),
        "authority": "opaque Stage A static exports plus recorded manual annotations",
        "opaque_bundle": {
            "manifest_sha256": bundle_audit["manifest_sha256"],
            "state_machine_sha256": state_machine.sha256,
            "reference_contract_sha256": reference_contract.sha256,
            "semantic_transfer_contracts_sha256": provenance_chain[
                "semantic_transfer_contracts_sha256"
            ],
            "original_pe_sha256": provenance_chain["original_pe_sha256"],
        },
        "backend": {
            "format": backend_report.get("format"),
            "status": backend_report.get("status"),
            "strict_candidate": backend_report.get("strict_candidate"),
        },
        "native_entry": {
            "status": "ready" if native_entry_source is not None else _INCOMPLETE,
            "symbol": native_entry_symbol,
            "manifest": _output_artifact_payload(
                native_entry_manifest,
                root=out,
                role="candidate-native-entry-manifest",
            ),
        },
        "generated_sources": [
            _output_artifact_payload(path, root=out, role="candidate-source")
            for path in generated_sources
        ],
        "generated_headers": [
            _output_artifact_payload(path, root=out, role="candidate-header")
            for path in generated_headers
        ],
        "source_map": _output_artifact_payload(source_map.path, root=out, role="source-map"),
        "implementation_manifest": _output_artifact_payload(
            implementation_manifest.path,
            root=out,
            role="implementation-manifest",
        ),
        "manual_annotations": [
            item.to_payload(root=bundle_root) for item in manual_annotations
        ],
        "acceptance": "only the Stage A whole-program theorem may authorize this candidate",
    }
    write_json(source_manifest, source_manifest_payload)

    compile_request = StageBToolchainRequest(
        out_dir=compile_dir,
        source_dir=backend_dir,
        source_manifest=source_manifest,
        source_map=source_map.path,
        implementation_manifest=implementation_manifest.path,
        generated_sources=generated_sources,
        generated_headers=generated_headers,
        manual_annotations=manual_annotations,
        native_entry_source=native_entry_source,
        native_entry_symbol=native_entry_symbol,
    )
    compile_snapshot = _snapshot(compile_request.allowed_semantic_inputs)
    toolchain_result = toolchain_callback(compile_request)
    _validate_toolchain_result(toolchain_result, compile_request, compile_snapshot)
    validate_opaque_stage_b_input_bundle(manifest_path)

    if toolchain_result.status != _PASS:
        result = _result_payload(
            status=_INCOMPLETE,
            reason_codes=("candidate_compilation_incomplete",),
            out=out,
            bundle_root=bundle_root,
            bundle_audit=bundle_audit,
            bundle_inputs=bundle_inputs,
            source_manifest=source_manifest,
            source_map=source_map.path,
            implementation_manifest=implementation_manifest.path,
            backend_report=backend_report,
            toolchain_result=toolchain_result,
            proof_result=None,
            stage_a_original_pe=original_proof_image,
        )
        write_json(out / "result.json", result)
        return result

    assert toolchain_result.candidate_pe is not None
    candidate_pe = Path(toolchain_result.candidate_pe).resolve()
    linker_map = (
        Path(toolchain_result.linker_map).resolve()
        if toolchain_result.linker_map is not None
        else None
    )
    proof_request = StageAProofRequest(
        out_dir=proof_dir,
        reference_contract=reference_contract.path,
        static_inputs=tuple(
            item for item in bundle_inputs if item.origin == "stage_a_static_export"
        ),
        candidate_pe=candidate_pe,
        linker_map=linker_map,
        source_manifest=source_manifest,
        source_map=source_map.path,
        implementation_manifest=implementation_manifest.path,
        original_pe_sha256=provenance_chain["original_pe_sha256"],
        reference_contract_sha256=provenance_chain["reference_contract_sha256"],
        state_machine_sha256=provenance_chain["state_machine_sha256"],
        original_pe=original_proof_image,
        relation_contract=(
            relation_contract.path if relation_contract is not None else None
        ),
    )
    proof_snapshot = _snapshot(proof_request.allowed_inputs)
    proof_result = stage_a_proof_callback(proof_request)
    proof_reason_codes = _validate_proof_result(proof_result, proof_request, proof_snapshot)
    validate_opaque_stage_b_input_bundle(manifest_path)

    status = proof_result.status
    if proof_reason_codes:
        status = _INCOMPLETE
    elif proof_result.status == _INCOMPLETE:
        proof_reason_codes = ("stage_a_final_proof_incomplete",)
    result = _result_payload(
        status=status,
        reason_codes=proof_reason_codes,
        out=out,
        bundle_root=bundle_root,
        bundle_audit=bundle_audit,
        bundle_inputs=bundle_inputs,
        source_manifest=source_manifest,
        source_map=source_map.path,
        implementation_manifest=implementation_manifest.path,
        backend_report=backend_report,
        toolchain_result=toolchain_result,
        proof_result=proof_result,
        stage_a_original_pe=original_proof_image,
    )
    write_json(out / "result.json", result)
    return result


def _load_bundle_inputs(manifest_path: Path) -> tuple[RoundTripInput, ...]:
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    root = manifest_path.parent
    rows: list[RoundTripInput] = []
    for index, raw in enumerate(payload["inputs"]):
        item = OpaqueStageBInput.parse(raw, context=f"opaque Stage B input {index}")
        unresolved = root / item.path
        if unresolved.is_symlink():
            raise StageAInputError(f"opaque Stage B input {item.id} must not be a symlink")
        rows.append(RoundTripInput(
            role=item.role,
            origin=item.origin,
            path=unresolved.resolve(),
            sha256=item.sha256,
            bytes=item.bytes,
        ))
    return tuple(rows)


def _audit_opaque_contents(inputs: Sequence[RoundTripInput]) -> None:
    state_machine = next(item for item in inputs if item.role == "state_machine")
    _audit_canonical_state_machine(state_machine.path)
    for item in inputs:
        normalized_role = item.role.lower().replace("-", "_")
        if normalized_role in _FORBIDDEN_CLASS_VALUES:
            raise StageAInputError(f"opaque Stage B input role is prohibited: {item.role}")
        _audit_structured_file(item.path, context=f"opaque Stage B input {item.role}")


def _audit_canonical_state_machine(path: Path) -> None:
    rows = 0
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise StageAInputError(
                f"opaque Stage B state machine line {line_number} is invalid JSON: {exc}"
            ) from exc
        if not isinstance(raw, dict):
            raise StageAInputError(f"opaque Stage B state machine line {line_number} is not an object")
        normalized = normalize_stage_a_semantic_transfer(raw)
        if raw != normalized:
            raise StageAInputError(
                f"opaque Stage B state machine line {line_number} is not canonical or contains undeclared fields"
            )
        rows += 1
    if rows == 0:
        raise StageAInputError("opaque Stage B state machine is empty")


def _audit_structured_file(path: Path, *, context: str) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return
    values: list[Any] = []
    try:
        values.append(json.loads(text))
    except json.JSONDecodeError:
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                values.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    for value in values:
        _reject_forbidden_structured_provenance(value, context=context)


def _reject_forbidden_structured_provenance(value: Any, *, context: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized_key = str(key).lower().replace("-", "_")
            if normalized_key in _FORBIDDEN_STRUCTURED_KEYS:
                raise StageAInputError(f"{context} contains prohibited provenance field {key!r}")
            if normalized_key in {"role", "kind", "origin", "provenance_class"} and isinstance(child, str):
                normalized_value = child.lower().replace("-", "_")
                if normalized_value in _FORBIDDEN_CLASS_VALUES:
                    raise StageAInputError(
                        f"{context} declares prohibited provenance class {child!r}"
                    )
            _reject_forbidden_structured_provenance(child, context=context)
    elif isinstance(value, list):
        for child in value:
            _reject_forbidden_structured_provenance(child, context=context)


def _backend_artifacts(
    backend_dir: Path,
    report: Mapping[str, Any],
) -> dict[str, RoundTripInput]:
    raw_artifacts = report.get("artifacts")
    if not isinstance(raw_artifacts, dict):
        raise StageAInputError("Stage B semantic-C report omitted artifacts")
    artifacts: dict[str, RoundTripInput] = {}
    for role, raw in raw_artifacts.items():
        if not isinstance(raw, dict) or set(raw) != {"path", "sha256"}:
            raise StageAInputError(f"Stage B semantic-C artifact {role!r} is malformed")
        path = _contained_file(backend_dir, backend_dir / str(raw["path"]), context=f"Stage B artifact {role}")
        digest = sha256_file(path)
        if digest != raw["sha256"]:
            raise StageAInputError(f"Stage B semantic-C artifact {role!r} has a stale binding")
        artifacts[str(role)] = RoundTripInput(
            role=str(role),
            origin="stage_b_generated",
            path=path,
            sha256=digest,
            bytes=path.stat().st_size,
        )
    for required in ("source_map", "implementation_manifest"):
        if required not in artifacts:
            raise StageAInputError(f"Stage B semantic-C report omitted {required}")
    return artifacts


def _validate_toolchain_result(
    result: StageBToolchainResult,
    request: StageBToolchainRequest,
    snapshot: Mapping[Path, tuple[int, str]],
) -> None:
    if not isinstance(result, StageBToolchainResult):
        raise StageAInputError("Stage B toolchain callback returned an unsupported result")
    if result.status not in {_PASS, _INCOMPLETE}:
        raise StageAInputError("Stage B toolchain status must be pass or incomplete")
    _json_object(result.provenance, "Stage B toolchain provenance", required=result.status == _PASS)
    _json_sequence(result.diagnostics, "Stage B toolchain diagnostics")
    _verify_snapshot(snapshot, context="Stage B toolchain")
    _validate_consumed_inputs(
        result.consumed_inputs,
        request.allowed_semantic_inputs,
        context="Stage B toolchain",
        required=(request.source_manifest, request.implementation_manifest)
        if result.status == _PASS
        else (),
    )
    if result.status == _PASS:
        consumed = {Path(path).resolve() for path in result.consumed_inputs}
        if not any(path.resolve() in consumed for path in request.generated_sources):
            raise StageAInputError("passing Stage B toolchain did not consume generated candidate source")
        if result.candidate_pe is None:
            raise StageAInputError("passing Stage B toolchain result omitted candidate PE")
        _contained_file(request.out_dir, result.candidate_pe, context="Stage B candidate PE")
        if result.linker_map is not None:
            _contained_file(request.out_dir, result.linker_map, context="Stage B candidate linker map")
    elif result.candidate_pe is not None or result.linker_map is not None:
        raise StageAInputError("incomplete Stage B toolchain result must not publish candidate artifacts")


def _validate_proof_result(
    result: StageAProofResult,
    request: StageAProofRequest,
    snapshot: Mapping[Path, tuple[int, str]],
) -> tuple[str, ...]:
    if not isinstance(result, StageAProofResult):
        raise StageAInputError("Stage A proof callback returned an unsupported result")
    if result.status not in _PROOF_STATUSES:
        raise StageAInputError("Stage A proof status is unsupported")
    _json_object(result.provenance, "Stage A proof provenance", required=True)
    _json_object(result.handoff, "Stage A proof handoff", required=False)
    _json_sequence(result.diagnostics, "Stage A proof diagnostics")
    _verify_snapshot(snapshot, context="Stage A proof")
    _validate_consumed_inputs(
        result.consumed_inputs,
        request.allowed_inputs,
        context="Stage A proof",
        required=tuple(
            path
            for path in (
                request.reference_contract,
                request.original_pe,
                request.relation_contract,
                request.candidate_pe,
            )
            if path is not None
        ),
    )
    _contained_file(request.out_dir, result.report, context="Stage A proof report")
    reasons: list[str] = []
    raw_report = _read_optional_json(result.report)
    report = (
        _load_proof_handoff_report(result.report)
        if (
            result.status == _INCOMPLETE
            and raw_report.get("format") == STAGE_A_PROOF_HANDOFF_FORMAT
        )
        else _load_relational_proof_report(result.report)
    )
    if report.get("verdict") != ({_PASS: _PASS, _INCOMPLETE: _INCOMPLETE, _VIOLATED: "fail"}[result.status]):
        reasons.append("stage_a_callback_status_disagrees_with_verdict")
    original = report.get("original") if isinstance(report.get("original"), dict) else {}
    candidate = report.get("candidate") if isinstance(report.get("candidate"), dict) else {}
    if original.get("sha256") != request.original_pe_sha256:
        reasons.append("stage_a_verdict_original_binding_mismatch")
    if candidate.get("sha256") != sha256_file(request.candidate_pe):
        reasons.append("stage_a_verdict_candidate_binding_mismatch")
    if result.status == _PASS:
        if report.get("acceptance_authority") != "whole_program_lean":
            reasons.append("stage_a_pass_without_whole_program_authority")
        if report.get("profile") != "x86-pe32-lean-relational-v3":
            reasons.append("stage_a_pass_without_relational_v3_profile")
        claim_scope = report.get("claim_scope") if isinstance(report.get("claim_scope"), dict) else {}
        if (
            claim_scope.get("whole_program_observational_equivalence") is not True
            or claim_scope.get("acceptance_eligible") is not True
        ):
            reasons.append("stage_a_pass_without_whole_program_claim_scope")
        if report.get("lean_kernel_checked") is not True:
            reasons.append("stage_a_pass_without_checked_relational_verdict")
        if not result.lean_kernel_checked:
            reasons.append("stage_a_pass_without_lean_kernel_check")
        from ..relational.schema import RELATIONAL_ACCEPTANCE_THEOREMS

        if result.final_theorem not in RELATIONAL_ACCEPTANCE_THEOREMS:
            reasons.append("stage_a_pass_without_whole_program_theorem")
        if report.get("theorem") != result.final_theorem:
            reasons.append("stage_a_pass_theorem_disagrees_with_verdict")
        if result.unchecked_markers:
            reasons.append("stage_a_pass_contains_unchecked_markers")
    elif result.status == _VIOLATED:
        if not result.lean_kernel_checked:
            reasons.append("stage_a_violation_without_lean_kernel_check")
        if result.unchecked_markers:
            reasons.append("stage_a_violation_contains_unchecked_markers")
    return tuple(reasons)


def _load_relational_proof_report(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"cannot read Stage A proof report: {exc}") from exc
    if not isinstance(payload, dict):
        raise StageAInputError("Stage A proof report must be a Nix proof report")
    view = _relational_report_view(payload, report_root=Path(path).parent)
    if view.get("profile") != "x86-pe32-lean-relational-v3":
        raise StageAInputError("Stage A proof report has an unsupported profile")
    return view


def _load_proof_handoff_report(path: Path) -> dict[str, Any]:
    payload = _read_optional_json(path)
    if (
        payload.get("format") != STAGE_A_PROOF_HANDOFF_FORMAT
        or payload.get("status") != _INCOMPLETE
        or payload.get("acceptance_authority") is not False
    ):
        raise StageAInputError("Stage A proof handoff diagnostic is malformed")
    return {
        "format": payload.get("format"),
        "verdict": _INCOMPLETE,
        "acceptance_authority": None,
        "profile": payload.get("profile"),
        "claim_scope": payload.get("claim_scope"),
        "original": payload.get("original"),
        "candidate": payload.get("candidate"),
        "theorem": None,
        "lean_kernel_checked": False,
    }


def _result_payload(
    *,
    status: str,
    reason_codes: Sequence[str],
    out: Path,
    bundle_root: Path,
    bundle_audit: Mapping[str, Any],
    bundle_inputs: Sequence[RoundTripInput],
    source_manifest: Path,
    source_map: Path,
    implementation_manifest: Path,
    backend_report: Mapping[str, Any],
    toolchain_result: StageBToolchainResult,
    proof_result: StageAProofResult | None,
    stage_a_original_pe: Path | None,
) -> dict[str, Any]:
    candidate_pe = (
        _output_artifact_payload(Path(toolchain_result.candidate_pe), root=out, role="candidate-pe")
        if toolchain_result.candidate_pe is not None
        else None
    )
    linker_map = (
        _output_artifact_payload(Path(toolchain_result.linker_map), root=out, role="candidate-linker-map")
        if toolchain_result.linker_map is not None
        else None
    )
    proof_payload = None
    if proof_result is not None:
        proof_payload = {
            "status": proof_result.status,
            "report": _output_artifact_payload(proof_result.report, root=out, role="stage-a-proof-report"),
            "final_theorem": proof_result.final_theorem,
            "lean_kernel_checked": proof_result.lean_kernel_checked,
            "unchecked_markers": list(proof_result.unchecked_markers),
            "consumed_inputs": [
                _phase_input_payload(
                    path,
                    out=out,
                    bundle_root=bundle_root,
                    bundle_inputs=bundle_inputs,
                    stage_a_original_pe=stage_a_original_pe,
                )
                for path in proof_result.consumed_inputs
            ],
            "provenance": _json_value(proof_result.provenance),
            "diagnostics": [_json_value(item) for item in proof_result.diagnostics],
            "handoff": _json_value(proof_result.handoff),
        }
    provenance_audit = {
        "format": OPAQUE_STAGE_B_PROVENANCE_AUDIT_FORMAT,
        "status": _PASS,
        "opaque_bundle_manifest_sha256": bundle_audit["manifest_sha256"],
        "provenance_chain": _json_value(bundle_audit["provenance_chain"]),
        "inputs": [item.to_payload(root=bundle_root) for item in bundle_inputs],
        "generator_inputs_exposed": [],
        "ground_truth_inputs_exposed": [],
        "original_runtime_inputs_exposed": [],
        "original_static_proof_input": (
            {
                "role": "original-pe",
                "origin": "stage_a_private_static_input",
                "sha256": sha256_file(stage_a_original_pe),
                "bytes": stage_a_original_pe.stat().st_size,
                "exposed_to_stage_b": False,
            }
            if stage_a_original_pe is not None
            else None
        ),
        "manual_annotations": [
            item.role for item in bundle_inputs if item.origin == "manual_annotation"
        ],
        "phase_boundaries": {
            "stage_b_generation": [
                item.to_payload(root=bundle_root)
                for item in bundle_inputs
                if item.role in {"state_machine", "manual-machine-call-catalog"}
            ],
            "candidate_compilation": [
                _phase_input_payload(
                    path,
                    out=out,
                    bundle_root=bundle_root,
                    bundle_inputs=bundle_inputs,
                    stage_a_original_pe=stage_a_original_pe,
                )
                for path in toolchain_result.consumed_inputs
            ],
            "stage_a_proof": (
                [
                    _phase_input_payload(
                        path,
                        out=out,
                        bundle_root=bundle_root,
                        bundle_inputs=bundle_inputs,
                        stage_a_original_pe=stage_a_original_pe,
                    )
                    for path in proof_result.consumed_inputs
                ]
                if proof_result is not None
                else []
            ),
        },
        "input_bindings_revalidated_after_callbacks": True,
    }
    return {
        "format": OPAQUE_STAGE_B_ROUNDTRIP_FORMAT,
        "status": status,
        "reason_codes": list(reason_codes),
        "authority": "Stage A Lean-kernel-checked whole-program theorem",
        "provenance_audit": provenance_audit,
        "generation": {
            "status": (
                "complete"
                if _read_optional_json(source_manifest).get("status") == "complete"
                else backend_report.get("status")
            ),
            "backend_format": backend_report.get("format"),
            "semantic_runtime_status": backend_report.get("status"),
            "native_entry": _json_value(backend_report.get("native_entry") or {}),
            "source_manifest": _output_artifact_payload(source_manifest, root=out, role="candidate-source-manifest"),
            "source_map": _output_artifact_payload(source_map, root=out, role="candidate-source-map"),
            "implementation_manifest": _output_artifact_payload(
                implementation_manifest,
                root=out,
                role="candidate-implementation-manifest",
            ),
            "strict_candidate": (
                {
                    "status": "ready",
                    "profile": "single-transfer-constant-eax-return-v1",
                    "blockers": [],
                }
                if isinstance(backend_report.get("native_entry"), dict)
                and backend_report["native_entry"].get("status") == "ready"
                else backend_report.get("strict_candidate")
            ),
        },
        "compilation": {
            "status": toolchain_result.status,
            "candidate_pe": candidate_pe,
            "linker_map": linker_map,
            "consumed_inputs": [
                _phase_input_payload(
                    path,
                    out=out,
                    bundle_root=bundle_root,
                    bundle_inputs=bundle_inputs,
                    stage_a_original_pe=stage_a_original_pe,
                )
                for path in toolchain_result.consumed_inputs
            ],
            "provenance": _json_value(toolchain_result.provenance),
            "diagnostics": [_json_value(item) for item in toolchain_result.diagnostics],
        },
        "proof": proof_payload,
    }


def _output_artifact_payload(path: Path, *, root: Path, role: str) -> dict[str, Any]:
    path = _contained_file(root, path, context=role)
    return {
        "role": role,
        "path": path.relative_to(root).as_posix(),
        "sha256": sha256_file(path),
        "bytes": path.stat().st_size,
    }


def _phase_input_payload(
    raw_path: Path,
    *,
    out: Path,
    bundle_root: Path,
    bundle_inputs: Sequence[RoundTripInput],
    stage_a_original_pe: Path | None,
) -> dict[str, Any]:
    path = Path(raw_path).resolve()
    for item in bundle_inputs:
        if item.path == path:
            payload = item.to_payload(root=bundle_root)
            payload["scope"] = "opaque_bundle"
            return payload
    if stage_a_original_pe is not None and path == stage_a_original_pe.resolve():
        return {
            "role": "original-pe",
            "origin": "stage_a_private_static_input",
            "scope": "stage_a_proof_only",
            "sha256": sha256_file(path),
            "bytes": path.stat().st_size,
        }
    try:
        relative = path.relative_to(out)
    except ValueError as exc:
        raise StageAInputError(f"audited phase input is outside declared roots: {path}") from exc
    return {
        "role": "derived-roundtrip-input",
        "origin": "roundtrip_output",
        "scope": "roundtrip_output",
        "path": relative.as_posix(),
        "sha256": sha256_file(path),
        "bytes": path.stat().st_size,
    }


def _snapshot(paths: Sequence[Path]) -> dict[Path, tuple[int, str]]:
    result: dict[Path, tuple[int, str]] = {}
    for raw_path in paths:
        unresolved = Path(raw_path)
        if unresolved.is_symlink():
            raise StageAInputError(f"callback input must not be a symlink: {unresolved}")
        path = unresolved.resolve()
        if path in result:
            continue
        if not path.is_file() or path.is_symlink():
            raise StageAInputError(f"callback input is not a regular non-symlink file: {path}")
        result[path] = (path.stat().st_size, sha256_file(path))
    return result


def _verify_snapshot(snapshot: Mapping[Path, tuple[int, str]], *, context: str) -> None:
    for path, (size, digest) in snapshot.items():
        if not path.is_file() or path.is_symlink():
            raise StageAInputError(f"{context} removed or replaced input {path}")
        if path.stat().st_size != size or sha256_file(path) != digest:
            raise StageAInputError(f"{context} mutated input {path}")


def _validate_consumed_inputs(
    consumed: Sequence[Path],
    allowed: Sequence[Path],
    *,
    context: str,
    required: Sequence[Path],
) -> None:
    consumed_paths = tuple(Path(path).resolve() for path in consumed)
    if len(consumed_paths) != len(set(consumed_paths)):
        raise StageAInputError(f"{context} consumed-input inventory contains duplicates")
    allowed_paths = {Path(path).resolve() for path in allowed}
    undeclared = sorted(str(path) for path in consumed_paths if path not in allowed_paths)
    if undeclared:
        raise StageAInputError(f"{context} consumed undeclared semantic inputs: {undeclared}")
    missing = sorted(str(Path(path).resolve()) for path in required if Path(path).resolve() not in consumed_paths)
    if missing:
        raise StageAInputError(f"{context} omitted required consumed inputs: {missing}")


def _contained_file(root: Path, raw_path: Path, *, context: str) -> Path:
    root = Path(root).resolve()
    unresolved = Path(raw_path)
    if unresolved.is_symlink():
        raise StageAInputError(f"{context} must not be a symlink")
    path = unresolved.resolve()
    if root != path and root not in path.parents:
        raise StageAInputError(f"{context} escapes its output root")
    if not path.is_file() or path.is_symlink():
        raise StageAInputError(f"{context} is not a regular non-symlink file")
    return path


def _check_disjoint_roots(bundle_root: Path, out: Path) -> None:
    if bundle_root == out or bundle_root in out.parents or out in bundle_root.parents:
        raise StageAInputError("opaque Stage B bundle and round-trip output roots must be disjoint")


def _json_object(value: Mapping[str, Any], context: str, *, required: bool) -> None:
    if not isinstance(value, Mapping) or (required and not value):
        raise StageAInputError(f"{context} must be a nonempty object")
    _json_value(value)


def _json_sequence(value: Sequence[Mapping[str, Any]], context: str) -> None:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise StageAInputError(f"{context} must be a sequence")
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            raise StageAInputError(f"{context}[{index}] must be an object")
        _json_value(item)


def _json_value(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value, sort_keys=True, separators=(",", ":")))
    except (TypeError, ValueError) as exc:
        raise StageAInputError(f"callback metadata is not JSON-serializable: {exc}") from exc

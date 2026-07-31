from __future__ import annotations

import json
import os
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

import pefile

from .artifact_formats import (
    C0_COMPILATION_ATTESTATION_FORMAT,
    C0_SOURCE_MANIFEST_FORMAT,
    C0_TOOLCHAIN_PROFILE_FORMAT,
    SOURCE_EQUIVALENCE_REPORT_FORMAT,
)
from .relational.lean.interpreter import relational_interpreter_program_source
from .relational.lean.interpreter_normalization import (
    relational_interpreter_normalization_bundle_sources,
)
from .relational.lean.interpreter_semantic_refinement import (
    relational_interpreter_semantic_refinement_bundle_sources,
)
from .relational.lean.pe_byte_packs import generate_pe_byte_pack_bundle
from .stage_b_interpreter_backend import (
    _ACTIONS,
    _WORD_OPS,
    compile_stage_b_interpreter_program,
)
from .stage_binary import StageAInputError
from .util import sha256_bytes, sha256_file, write_json


C0_DIALECT = "c0-v1"
C0_RENDERER_VERSION = "spaghetti-c0-canonical-renderer-v1"
C0_PROFILE_ID = "i686-mingw-freestanding-c0-v1"
_C0_RUNTIME_PROFILE = "spaghetti-c0-runtime-v1"
_C0_FLAGS = (
    "-std=c11",
    "-O0",
    "-ffreestanding",
    "-fno-builtin",
    "-fno-asynchronous-unwind-tables",
    "-nostdlib",
    "-Wl,--entry,_mainCRTStartup",
    "-Wl,--subsystem,console",
    "-Wl,--no-insert-timestamp",
)
_C0_POLICY = {
    "crt": False,
    "threads": False,
    "inline_assembly": False,
    "undefined_behavior": False,
    "windows_apis_are_external_events": True,
    "correctness_is_a_lean_theorem_parameter": True,
}
_C0_COMPILATION_ASSUMPTION = {
    "id": "correct-pinned-c0-compilation-v1",
    "scope": "C0 lowering, compiler, assembler, linker, ABI, and runtime profile",
    "lean_axiom": False,
}
SOURCE_ACCEPTANCE_THEOREM = (
    "StageA.Relational.Source.compiledArtifactEquivalentAssumingCorrectToolchain"
)
SOURCE_ACCEPTANCE_INSTANCE_THEOREM = (
    "StageA.GeneratedRelational.generatedOriginalCompiledEquivalent"
)
_DIGEST_LENGTH = 64


@dataclass(frozen=True)
class C0Artifact:
    path: str
    sha256: str
    size: int

    @classmethod
    def parse(cls, value: object, *, label: str) -> "C0Artifact":
        row = _object(value, label)
        _fields(row, {"path", "sha256", "size"}, label)
        path = _nonempty_string(row["path"], f"{label}.path")
        digest = _digest(row["sha256"], f"{label}.sha256")
        size = _nonnegative_int(row["size"], f"{label}.size")
        return cls(path=path, sha256=digest, size=size)

    def payload(self) -> dict[str, Any]:
        return {"path": self.path, "sha256": self.sha256, "size": self.size}


@dataclass(frozen=True)
class C0SourceManifest:
    status: str
    entry_rva: int
    state_machine_sha256: str
    renderer: str
    runtime_profile: str
    input_transfer_count: int
    transfer_count: int
    omitted_transfer_count: int
    transfer_bindings: tuple[dict[str, Any], ...]
    artifacts: tuple[C0Artifact, ...]
    blockers: tuple[dict[str, Any], ...]

    @classmethod
    def load(cls, path: Path) -> "C0SourceManifest":
        payload = _read_object(path, "C0 source manifest")
        _fields(
            payload,
            {
                "format", "status", "dialect", "entry_rva", "state_machine",
                "renderer", "runtime_profile", "transfer_count",
                "input_transfer_count", "omitted_transfer_count",
                "transfer_bindings", "artifacts", "blockers", "trust",
            },
            "C0 source manifest",
        )
        if payload["format"] != C0_SOURCE_MANIFEST_FORMAT:
            raise StageAInputError("unsupported C0 source manifest format")
        if payload["dialect"] != C0_DIALECT:
            raise StageAInputError("unsupported C0 source dialect")
        state_machine = _object(payload["state_machine"], "state_machine")
        _fields(state_machine, {"path", "sha256"}, "state_machine")
        bindings = _object_list(payload["transfer_bindings"], "transfer_bindings")
        artifacts = tuple(
            C0Artifact.parse(item, label=f"artifacts[{index}]")
            for index, item in enumerate(_list(payload["artifacts"], "artifacts"))
        )
        blockers = tuple(_object_list(payload["blockers"], "blockers"))
        transfer_count = _nonnegative_int(payload["transfer_count"], "transfer_count")
        input_transfer_count = _nonnegative_int(
            payload["input_transfer_count"], "input_transfer_count"
        )
        omitted_transfer_count = _nonnegative_int(
            payload["omitted_transfer_count"], "omitted_transfer_count"
        )
        if transfer_count != len(bindings):
            raise StageAInputError("C0 source transfer count does not match bindings")
        if input_transfer_count != transfer_count + omitted_transfer_count:
            raise StageAInputError("C0 source transfer accounting is inconsistent")
        status = _status(payload["status"])
        if status == "complete" and (blockers or omitted_transfer_count):
            raise StageAInputError(
                "complete C0 source manifest contains blockers or omitted transfers"
            )
        if status == "incomplete" and not blockers:
            raise StageAInputError(
                "incomplete C0 source manifest must identify at least one blocker"
            )
        return cls(
            status=status,
            entry_rva=_u32(payload["entry_rva"], "entry_rva"),
            state_machine_sha256=_digest(state_machine["sha256"], "state_machine.sha256"),
            renderer=_nonempty_string(payload["renderer"], "renderer"),
            runtime_profile=_nonempty_string(payload["runtime_profile"], "runtime_profile"),
            input_transfer_count=input_transfer_count,
            transfer_count=transfer_count,
            omitted_transfer_count=omitted_transfer_count,
            transfer_bindings=tuple(bindings),
            artifacts=artifacts,
            blockers=blockers,
        )

    def validate_files(self, root: Path) -> None:
        seen: set[str] = set()
        for artifact in self.artifacts:
            if artifact.path in seen:
                raise StageAInputError(f"duplicate C0 artifact path {artifact.path!r}")
            seen.add(artifact.path)
            candidate = _within(root, artifact.path)
            if not candidate.is_file() or candidate.is_symlink():
                raise StageAInputError(f"missing regular C0 artifact {artifact.path!r}")
            if candidate.stat().st_size != artifact.size:
                raise StageAInputError(f"C0 artifact size changed: {artifact.path}")
            if sha256_file(candidate) != artifact.sha256:
                raise StageAInputError(f"C0 artifact hash changed: {artifact.path}")


@dataclass(frozen=True)
class C0ToolchainProfile:
    identifier: str
    compiler: str
    assembler: str
    linker: str
    compiler_sha256: str
    assembler_sha256: str
    linker_sha256: str
    flags: tuple[str, ...]
    runtime_sha256: str

    @classmethod
    def load(cls, path: Path) -> "C0ToolchainProfile":
        payload = _read_object(path, "C0 toolchain profile")
        _fields(
            payload,
            {"format", "id", "target", "tools", "flags", "runtime", "policy"},
            "C0 toolchain profile",
        )
        if payload["format"] != C0_TOOLCHAIN_PROFILE_FORMAT:
            raise StageAInputError("unsupported C0 toolchain profile format")
        if payload["target"] != "i686-w64-mingw32":
            raise StageAInputError("C0 v1 requires the i686-w64-mingw32 target")
        identifier = _nonempty_string(payload["id"], "id")
        if identifier != C0_PROFILE_ID:
            raise StageAInputError("unsupported C0 v1 toolchain profile identifier")
        tools = _object(payload["tools"], "tools")
        _fields(tools, {"compiler", "assembler", "linker"}, "tools")

        def tool(name: str) -> tuple[str, str]:
            row = _object(tools[name], f"tools.{name}")
            _fields(row, {"path", "sha256"}, f"tools.{name}")
            return (
                _nonempty_string(row["path"], f"tools.{name}.path"),
                _digest(row["sha256"], f"tools.{name}.sha256"),
            )

        compiler, compiler_sha = tool("compiler")
        assembler, assembler_sha = tool("assembler")
        linker, linker_sha = tool("linker")
        runtime = _object(payload["runtime"], "runtime")
        _fields(runtime, {"profile", "sha256"}, "runtime")
        if runtime["profile"] != _C0_RUNTIME_PROFILE:
            raise StageAInputError("unsupported C0 v1 runtime profile")
        flags = tuple(
            _nonempty_string(flag, f"flags[{index}]")
            for index, flag in enumerate(_list(payload["flags"], "flags"))
        )
        if flags != _C0_FLAGS:
            raise StageAInputError("C0 v1 compiler flags differ from the pinned profile")
        policy = _object(payload["policy"], "policy")
        if policy != _C0_POLICY:
            raise StageAInputError("C0 v1 policy differs from the pinned profile")
        return cls(
            identifier=identifier,
            compiler=compiler,
            assembler=assembler,
            linker=linker,
            compiler_sha256=compiler_sha,
            assembler_sha256=assembler_sha,
            linker_sha256=linker_sha,
            flags=flags,
            runtime_sha256=_digest(runtime["sha256"], "runtime.sha256"),
        )


def generate_c0_source_project(
    *,
    state_machine: Path,
    entry_rva: int,
    out_dir: Path,
) -> dict[str, Any]:
    """Render canonical C0 program data and its checked-program Lean source."""

    state_machine = Path(state_machine).resolve()
    if not state_machine.is_file() or state_machine.is_symlink():
        raise StageAInputError("C0 state machine must be a regular file")
    entry_rva = _u32(entry_rva, "entry_rva")
    input_transfers = tuple(compile_stage_b_interpreter_program(state_machine))
    if not input_transfers:
        raise StageAInputError("C0 source program cannot be empty")
    transfers = tuple(
        transfer
        for transfer in input_transfers
        if not transfer.x87_nodes and not transfer.x87_replays
    )
    rvas = tuple(int(transfer.rva_start) for transfer in transfers)
    blockers: list[dict[str, Any]] = []
    if entry_rva not in rvas:
        blockers.append(_blocker("entry_not_in_transfer_inventory", entry_rva))
    duplicates = sorted(rva for rva, count in Counter(rvas).items() if count > 1)
    for rva in duplicates:
        blockers.append(_blocker("duplicate_transfer_rva", rva))
    for transfer in input_transfers:
        if transfer.x87_nodes or transfer.x87_replays:
            blockers.append(_blocker("c0_v1_x87_not_lowered", transfer.rva_start))
            continue
        if not _bootstrap_runtime_supports(transfer, entry_rva=entry_rva):
            blockers.append(
                _blocker("c0_v1_runtime_transfer_not_implemented", transfer.rva_start)
            )

    encoding = _encode_program(entry_rva, transfers)
    canonical_source = _canonical_c_source(encoding, entry_rva)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    source_path = out_dir / "c0-program.c"
    header_path = out_dir / "spaghetti-c0-runtime-v1.h"
    runtime_path = out_dir / "spaghetti-c0-runtime-v1.c"
    lean_path = out_dir / "GeneratedC0Program.lean"
    source_path.write_text(canonical_source, encoding="ascii", newline="")
    header_path.write_text(_runtime_header(), encoding="ascii", newline="")
    runtime_path.write_text(_runtime_source(), encoding="ascii", newline="")
    lean_program = relational_interpreter_program_source(transfers)
    lean_path.write_text(
        _generated_c0_lean_source(
            lean_program=lean_program,
            source=canonical_source,
            entry_rva=entry_rva,
        ),
        encoding="utf-8",
        newline="",
    )
    transfer_bindings = [
        {
            "id": transfer.identity,
            "contract_sha256": transfer.contract_sha256,
            "instruction_bytes_sha256": transfer.instruction_bytes_sha256,
            "source_rva": transfer.rva_start,
            "record_encoding_sha256": sha256_bytes(
                json.dumps(
                    _encode_record(transfer),
                    separators=(",", ":"),
                ).encode("ascii")
            ),
        }
        for transfer in transfers
    ]
    artifacts = tuple(
        _artifact(path)
        for path in (source_path, header_path, runtime_path, lean_path)
    )
    payload = {
        "format": C0_SOURCE_MANIFEST_FORMAT,
        "status": "complete" if not blockers else "incomplete",
        "dialect": C0_DIALECT,
        "entry_rva": entry_rva,
        "state_machine": {
            "path": state_machine.name,
            "sha256": sha256_file(state_machine),
        },
        "renderer": C0_RENDERER_VERSION,
        "runtime_profile": C0_PROFILE_ID,
        "input_transfer_count": len(input_transfers),
        "transfer_count": len(transfers),
        "omitted_transfer_count": len(input_transfers) - len(transfers),
        "transfer_bindings": transfer_bindings,
        "artifacts": [artifact.payload() for artifact in artifacts],
        "blockers": blockers,
        "trust": {
            "python_renderer_authoritative": False,
            "lean_exact_source_check_required": True,
            "original_instruction_bytes_embedded": False,
            "compiler_correctness_is_explicit_hypothesis": True,
        },
    }
    manifest_path = out_dir / "source-manifest.json"
    write_json(manifest_path, payload)
    return {**payload, "manifest": _artifact(manifest_path).payload()}


def attest_c0_compilation(
    *,
    source_manifest: Path,
    toolchain_profile: Path,
    candidate: Path,
    derivation: str | None,
    nar_hash: str | None,
    out: Path,
) -> dict[str, Any]:
    manifest_path = Path(source_manifest).resolve()
    manifest = C0SourceManifest.load(manifest_path)
    manifest.validate_files(manifest_path.parent)
    profile_path = Path(toolchain_profile).resolve()
    profile = C0ToolchainProfile.load(profile_path)
    if manifest.runtime_profile != profile.identifier:
        raise StageAInputError("source and toolchain runtime profiles differ")
    candidate = Path(candidate).resolve()
    _validate_pe32(candidate, "compiled candidate")
    for label, path, expected_sha256 in (
        ("compiler", profile.compiler, profile.compiler_sha256),
        ("assembler", profile.assembler, profile.assembler_sha256),
        ("linker", profile.linker, profile.linker_sha256),
    ):
        _validate_tool(path, expected_sha256, label=label)
    runtime = _manifest_artifact(manifest, "spaghetti-c0-runtime-v1.c")
    if runtime.sha256 != profile.runtime_sha256:
        raise StageAInputError(
            "C0 runtime source does not match the pinned toolchain profile"
        )
    store_root = _nix_store_root(candidate)
    path_info = _nix_path_info(store_root)
    registered_derivation = path_info.get("deriver")
    actual_nar_hash = path_info.get("narHash")
    selected_derivation = (
        _nix_derivation_identity(derivation, "derivation")
        if derivation is not None
        else _nix_derivation_identity(registered_derivation, "registered derivation")
    )
    if nar_hash is not None and actual_nar_hash != _nonempty_string(
        nar_hash, "nar_hash"
    ):
        raise StageAInputError("candidate NAR hash does not match attestation")
    payload = {
        "format": C0_COMPILATION_ATTESTATION_FORMAT,
        "status": "complete" if manifest.status == "complete" else "incomplete",
        "source_manifest": {
            "path": manifest_path.name,
            "sha256": sha256_file(manifest_path),
        },
        "toolchain_profile": {
            "path": str(profile_path),
            "sha256": sha256_file(profile_path),
            "id": profile.identifier,
        },
        "build": {
            "output": str(store_root),
            "derivation": selected_derivation,
            "registered_derivation": registered_derivation,
            "nar_hash": actual_nar_hash,
            "flags": list(profile.flags),
            "tools": {
                "compiler": {"path": profile.compiler, "sha256": profile.compiler_sha256},
                "assembler": {"path": profile.assembler, "sha256": profile.assembler_sha256},
                "linker": {"path": profile.linker, "sha256": profile.linker_sha256},
            },
            "runtime_sha256": profile.runtime_sha256,
        },
        "candidate": C0Artifact(
            path=str(candidate.relative_to(store_root)),
            sha256=sha256_file(candidate),
            size=candidate.stat().st_size,
        ).payload(),
        "assumption": dict(_C0_COMPILATION_ASSUMPTION),
    }
    write_json(out, payload)
    return payload


def build_source_equivalence_report(
    *,
    original: Path,
    source_manifest: Path,
    compilation_attestation: Path,
    lean_proof_bundle: Path,
    out: Path,
) -> dict[str, Any]:
    original = Path(original).resolve()
    _validate_pe32(original, "original")
    manifest_path = Path(source_manifest).resolve()
    manifest = C0SourceManifest.load(manifest_path)
    manifest.validate_files(manifest_path.parent)
    attestation_path = Path(compilation_attestation).resolve()
    attestation = _read_object(attestation_path, "compilation attestation")
    proof_root = _nix_store_root(Path(lean_proof_bundle).resolve())
    proof_info = _nix_path_info(proof_root)
    bundle_path = proof_root / "bundle.json"
    bundle = _read_object(bundle_path, "Lean source proof bundle")
    proof_binding_path = proof_root / "proof-binding.json"
    proof_binding = _read_object(proof_binding_path, "Lean source proof binding")
    issues: list[dict[str, Any]] = list(manifest.blockers)
    issues.extend(_validate_compilation_attestation(attestation, manifest_path, manifest))
    proof = _validate_lean_source_bundle(
        bundle, proof_binding, manifest_path, original, attestation
    )
    issues.extend(proof["issues"])
    if manifest.status != "complete":
        issues.append(_issue("incomplete", "source_manifest_incomplete", None))
    verdict = "conditional_pass"
    if any(issue["status"] == "violated" for issue in issues):
        verdict = "violated"
    elif issues:
        verdict = "incomplete"
    payload = {
        "format": SOURCE_EQUIVALENCE_REPORT_FORMAT,
        "verdict": verdict,
        "status": verdict,
        "theorem": SOURCE_ACCEPTANCE_THEOREM,
        "original": _artifact(original).payload(),
        "source_manifest": {
            "path": manifest_path.name,
            "sha256": sha256_file(manifest_path),
        },
        "compilation_attestation": {
            "path": attestation_path.name,
            "sha256": sha256_file(attestation_path),
        },
        "lean_proof": {
            "output": str(proof_root),
            "derivation": proof_info.get("deriver"),
            "nar_hash": proof_info.get("narHash"),
            "bundle_sha256": sha256_file(bundle_path),
            "binding_sha256": sha256_file(proof_binding_path),
            "checked_theorems": proof["checked_theorems"],
        },
        "issues": issues,
        "assumption": {
            "id": "correct-pinned-c0-compilation-v1",
            "conditional": True,
            "candidate_machine_code_proved_directly": False,
            "ordinary_stage_a_pass_authorized": False,
        },
        "runtime_tests": {
            "allowed": verdict == "conditional_pass",
            "original_execution_allowed": False,
            "wine_session": "headless-wayland-or-x",
        },
    }
    write_json(out, payload)
    return payload


def generate_c0_proof_sources(
    *,
    original: Path,
    candidate: Path,
    state_machine: Path,
    source_manifest: Path,
    toolchain_profile: Path,
    candidate_build_identity: str,
    out_dir: Path,
) -> dict[str, Any]:
    """Generate untrusted data modules for the exact conditional theorem."""

    original = Path(original).resolve()
    candidate = Path(candidate).resolve()
    _validate_pe32(original, "source-equivalence original")
    _validate_pe32(candidate, "source-equivalence candidate")
    manifest_path = Path(source_manifest).resolve()
    manifest = C0SourceManifest.load(manifest_path)
    manifest.validate_files(manifest_path.parent)
    profile_path = Path(toolchain_profile).resolve()
    profile = C0ToolchainProfile.load(profile_path)
    if manifest.status != "complete" or manifest.omitted_transfer_count:
        raise StageAInputError("incomplete C0 source cannot produce acceptance proof sources")
    if profile.identifier != manifest.runtime_profile:
        raise StageAInputError("source and proof toolchain profiles differ")
    original_pe = pefile.PE(data=original.read_bytes(), fast_load=True)
    if int(original_pe.OPTIONAL_HEADER.AddressOfEntryPoint) != manifest.entry_rva:
        raise StageAInputError(
            "C0 source entry RVA differs from the exact original PE entrypoint"
        )
    state_machine = Path(state_machine).resolve()
    if sha256_file(state_machine) != manifest.state_machine_sha256:
        raise StageAInputError("proof state machine differs from the C0 source manifest")
    rows = _read_jsonl_objects(state_machine)
    if len(rows) != manifest.input_transfer_count:
        raise StageAInputError("proof state machine transfer inventory changed")

    out_dir = Path(out_dir)
    stage_a = out_dir / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    original_inventory = generate_pe_byte_pack_bundle(
        pe_path=original,
        out_dir=out_dir,
        module_prefix="GeneratedSourceOriginal",
        namespace="StageA.GeneratedRelational",
        pack_size=8 * 1024,
        chunk_size=256,
        standalone=False,
        authoritative_module="GeneratedSourceOriginalPE",
        authoritative_bytes_name="originalBytes",
        authoritative_pe_name="originalPe",
        runtime_binding_prefix="original",
    )
    (out_dir / "pe-byte-packs.json").replace(
        out_dir / "original-pe-byte-packs.json"
    )
    candidate_inventory = generate_pe_byte_pack_bundle(
        pe_path=candidate,
        out_dir=out_dir,
        module_prefix="GeneratedC0Candidate",
        namespace="StageA.GeneratedRelational",
        pack_size=8 * 1024,
        chunk_size=256,
        standalone=False,
        authoritative_module="GeneratedC0CandidatePE",
        authoritative_bytes_name="compiledBytes",
        authoritative_pe_name="compiledPe",
        runtime_binding_prefix="compiled",
    )
    (out_dir / "pe-byte-packs.json").replace(
        out_dir / "candidate-pe-byte-packs.json"
    )
    normalization = relational_interpreter_normalization_bundle_sources(
        rows,
        source_module="StageA.GeneratedC0Program",
        pe_name="StageA.GeneratedRelational.originalPe",
        shard_size=48,
        semantic_refinement_module=(
            "StageA.GeneratedInterpreterSemanticRefinementBundle"
        ),
        emit_acceptance_inventory=False,
    )
    refinement = relational_interpreter_semantic_refinement_bundle_sources(
        rows,
        pe_module="StageA.GeneratedSourceOriginalPE",
        shard_size=48,
        emit_fused=False,
    )
    generated_modules = []
    for module, source in {**normalization, **refinement}.items():
        (stage_a / f"{module}.lean").write_text(source, encoding="utf-8")
        generated_modules.append(module)
    acceptance = _c0_acceptance_lean_source(
        transfer_count=manifest.transfer_count,
        profile=profile,
        candidate_build_identity=_nix_derivation_identity(
            candidate_build_identity, "candidate_build_identity"
        ),
    )
    (stage_a / "GeneratedC0SourceAcceptance.lean").write_text(
        acceptance, encoding="utf-8"
    )
    (stage_a / "GeneratedC0SourceAcceptanceAudit.lean").write_text(
        "import StageA.GeneratedC0SourceAcceptance\n\n"
        "#print axioms StageA.GeneratedRelational.generatedC0SourceExact\n"
        "#print axioms StageA.GeneratedRelational.generatedC0ProgramClosed\n"
        f"#print axioms {SOURCE_ACCEPTANCE_INSTANCE_THEOREM}\n",
        encoding="utf-8",
    )
    generated_modules.extend(
        ["GeneratedC0SourceAcceptance", "GeneratedC0SourceAcceptanceAudit"]
    )
    generated_modules.extend(row["name"] for row in original_inventory.modules)
    generated_modules.extend(row["name"] for row in candidate_inventory.modules)
    generated_modules = sorted(set(generated_modules))
    binding = {
        "format": "stage-a-c0-proof-binding-v1",
        "original_sha256": sha256_file(original),
        "candidate_sha256": sha256_file(candidate),
        "source_manifest_sha256": sha256_file(manifest_path),
        "toolchain_profile_sha256": sha256_file(profile_path),
        "candidate_build_identity": candidate_build_identity,
        "acceptance_theorem": SOURCE_ACCEPTANCE_INSTANCE_THEOREM,
    }
    write_json(out_dir / "proof-binding.json", binding)
    write_json(out_dir / "generated-modules.json", generated_modules)
    return {
        "format": "stage-a-c0-proof-sources-v1",
        "status": "ready",
        "generated_modules": generated_modules,
        "binding": binding,
    }


def _c0_acceptance_lean_source(
    *,
    transfer_count: int,
    profile: C0ToolchainProfile,
    candidate_build_identity: str,
) -> str:
    regions = ",\n  ".join(
        "{ path := exactNormalizedTransferPath"
        + str(index)
        + ", transfer := semanticInterpreterTransfer"
        + str(index)
        + ", sourceRvaExact := by rfl, certificate := "
        + "exactNormalizedTransferPath"
        + str(index)
        + "Certificate }"
        for index in range(transfer_count)
    )
    return f'''import StageA.RelationalSource
import StageA.GeneratedSourceOriginalPE
import StageA.GeneratedC0CandidatePE
import StageA.GeneratedC0Program
import StageA.GeneratedInterpreterNormalizationBundle

namespace StageA.GeneratedRelational

open StageA.Relational.Interpreter
open StageA.Relational.Source

def generatedOriginalImage : ExactOriginalImage := {{
  bytes := originalBytes
  pe := originalPe
  parsedExactly := originalPeParsed
}}

def generatedOriginalRegions : List (CheckedOriginalRegion originalPe) := [
  {regions}
]

def generatedSourceCertificate :
    OriginalSourceWholeProgramCertificate generatedOriginalImage
      generatedOriginalRegions generatedC0Program generatedC0Source := {{
  recordsExact := by rfl
  entryRvaExact := by rfl
  checkedSource := generatedCheckedC0Source
}}

def generatedPinnedToolchain : PinnedC0ToolchainProfile := {{
  identifier := {json.dumps(profile.identifier)}
  derivation := {json.dumps(candidate_build_identity)}
  compilerSha256 := {json.dumps(profile.compiler_sha256)}
  assemblerSha256 := {json.dumps(profile.assembler_sha256)}
  linkerSha256 := {json.dumps(profile.linker_sha256)}
  runtimeSha256 := {json.dumps(profile.runtime_sha256)}
}}

def generatedCompiledArtifact : CompiledArtifact := {{
  bytes := compiledBytes
  pe := compiledPe
  parsedExactly := compiledPeParsed
}}

theorem generatedOriginalCompiledEquivalent
    (compiledRun : StageA.Relational.Interpreter.Environment -> Nat ->
      WholeExecution -> WholeExecution)
    (compilerCorrect : CorrectPinnedCompilation generatedPinnedToolchain
      generatedC0Program generatedCompiledArtifact compiledRun) :
    OriginalCompiledObservationallyEquivalent generatedOriginalImage
      generatedOriginalRegions generatedC0Program compiledRun :=
  compiledArtifactEquivalentAssumingCorrectToolchain generatedSourceCertificate
    compilerCorrect

end StageA.GeneratedRelational
'''


def _read_jsonl_objects(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise StageAInputError(f"cannot read C0 proof state machine: {exc}") from exc
    for index, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise StageAInputError(
                f"invalid C0 proof state machine JSON on line {index}: {exc}"
            ) from exc
        rows.append(_object(value, f"state machine line {index}"))
    return rows


def _encode_program(entry_rva: int, transfers: Iterable[Any]) -> list[int]:
    rows = list(transfers)
    return [1, entry_rva, len(rows), *[word for row in rows for word in _encode_record(row)]]


def _bootstrap_runtime_supports(transfer: Any, *, entry_rva: int) -> bool:
    """Recognize exactly the transfer implemented by runtime profile v1.

    This intentionally follows the parser in ``_runtime_source``.  The
    compiler-correctness hypothesis cannot cover source that the selected C0
    runtime does not implement.
    """

    if (
        int(transfer.rva_start) != entry_rva
        or transfer.x87_nodes
        or transfer.x87_replays
        or transfer.calls
    ):
        return False
    nodes = tuple(
        (node.op, node.args, node.aux, node.immediate) for node in transfer.nodes
    )
    actions = tuple(
        (action.op, action.args, action.aux) for action in transfer.actions
    )
    synthetic_return = (
        nodes == (("const", (), 0, transfer.nodes[0].immediate),)
        if transfer.nodes
        else False
    ) and actions == (
        ("eval_word", (0,), 0),
        ("set_reg", (0,), 0),
        ("sync_eflags", (), 0),
        ("outcome_return", (0,), 0),
    )
    exact_stack_return = len(nodes) == 5 and nodes == (
        ("reg", (), 7, 0),
        ("load", (0,), 4, 0),
        ("const", (), 0, nodes[2][3]),
        ("const", (), 0, 4),
        ("add32", (3, 0), 0, 0),
    ) and actions == (
        ("eval_word", (0,), 0),
        ("eval_word", (1,), 0),
        ("eval_word", (2,), 0),
        ("eval_word", (3,), 0),
        ("eval_word", (4,), 0),
        ("set_reg", (2,), 0),
        ("set_reg", (4,), 7),
        ("sync_eflags", (), 0),
        ("outcome_return", (1,), 0),
    )
    return synthetic_return or exact_stack_return


def _encode_record(transfer: Any) -> list[int]:
    return [
        int(transfer.rva_start),
        *_encode_list(transfer.nodes, _encode_node),
        *_encode_list(transfer.x87_nodes, _encode_node),
        *_encode_list(transfer.calls, _encode_call),
        *_encode_list(transfer.actions, _encode_action),
    ]


def _encode_node(node: Any) -> list[int]:
    return [
        _WORD_OPS.index(node.op), len(node.args), int(node.aux),
        int(node.immediate), *_encode_list(node.args, lambda value: [int(value)]),
    ]


def _encode_call(call: Any) -> list[int]:
    kinds = {"external_call": 0, "internal_call": 1, "indirect_call": 2}
    return [
        kinds[call.kind], int(call.instruction_rva), int(call.call_index),
        *_encode_option(call.target_node, lambda value: [int(value)]),
        int(call.target_rva), int(call.return_rva),
        *_encode_option(call.dll, _encode_string),
        *_encode_option(call.symbol, _encode_string),
        *_encode_option(call.ordinal, lambda value: [int(value)]),
        *_encode_list(call.register_nodes, lambda value: [int(value)]),
        *_encode_list(call.flag_nodes, lambda value: [int(value)]),
        *_encode_list(call.argument_nodes, lambda value: [int(value)]),
        *_encode_list(
            call.stack_inputs,
            lambda value: [int(value[0]), int(value[1]), int(value[2])],
        ),
    ]


def _encode_action(action: Any) -> list[int]:
    return [
        _ACTIONS.index(action.op), len(action.args), int(action.aux),
        *_encode_list(action.args, lambda value: [int(value)]),
    ]


def _encode_list(values: Iterable[Any], encode: Any) -> list[int]:
    rows = list(values)
    return [len(rows), *[word for row in rows for word in encode(row)]]


def _encode_option(value: Any, encode: Any) -> list[int]:
    return [0] if value is None else [1, *encode(value)]


def _encode_string(value: str) -> list[int]:
    return _encode_list(value, lambda character: [ord(character)])


def _canonical_c_source(encoding: list[int], entry_rva: int) -> str:
    words = ", ".join(f"{value}u" for value in encoding)
    return (
        '#include <stdint.h>\n'
        '#include "spaghetti-c0-runtime-v1.h"\n\n'
        "static const uint32_t spaghetti_c0_program[] = {\n  "
        f"{words}\n"
        "};\n\n"
        "int mainCRTStartup(void) {\n"
        "  return spaghetti_c0_run(spaghetti_c0_program, "
        f"{len(encoding)}u, {entry_rva}u);\n"
        "}\n"
    )


def _runtime_header() -> str:
    return (
        "#ifndef SPAGHETTI_C0_RUNTIME_V1_H\n"
        "#define SPAGHETTI_C0_RUNTIME_V1_H\n"
        "#include <stdint.h>\n"
        "int spaghetti_c0_run(const uint32_t *program, uint32_t words, uint32_t entry_rva);\n"
        "#endif\n"
    )


def _runtime_source() -> str:
    # This bootstrap implements constant return and the exact IA-32 stack-return
    # shape emitted for the first no-call fixture.  Every accepted shape is
    # mirrored by _bootstrap_runtime_supports.
    return r'''#include "spaghetti-c0-runtime-v1.h"

static int take(const uint32_t *p, uint32_t n, uint32_t *at, uint32_t *out) {
  if (*at >= n) return 0;
  *out = p[(*at)++];
  return 1;
}

int spaghetti_c0_run(const uint32_t *p, uint32_t n, uint32_t entry) {
  uint32_t at = 0, version = 0, encoded_entry = 0, records = 0;
  if (!take(p, n, &at, &version) || version != 1u ||
      !take(p, n, &at, &encoded_entry) || encoded_entry != entry ||
      !take(p, n, &at, &records) || records != 1u) return 125;
  uint32_t rva = 0, node_count = 0;
  if (!take(p, n, &at, &rva) || rva != entry ||
      !take(p, n, &at, &node_count) || node_count > 5u) return 125;
  uint32_t op[5] = {0}, arity[5] = {0}, aux[5] = {0}, immediate[5] = {0};
  uint32_t argc[5] = {0}, arg0[5] = {0}, arg1[5] = {0};
  for (uint32_t i = 0; i < node_count; ++i) {
    if (!take(p, n, &at, &op[i]) || !take(p, n, &at, &arity[i]) ||
        !take(p, n, &at, &aux[i]) || !take(p, n, &at, &immediate[i]) ||
        !take(p, n, &at, &argc[i]) || argc[i] != arity[i] || argc[i] > 2u)
      return 125;
    if (argc[i] > 0u && !take(p, n, &at, &arg0[i])) return 125;
    if (argc[i] > 1u && !take(p, n, &at, &arg1[i])) return 125;
  }
  uint32_t x87 = 0, calls = 0, action_count = 0;
  if (!take(p, n, &at, &x87) || x87 != 0u ||
      !take(p, n, &at, &calls) || calls != 0u ||
      !take(p, n, &at, &action_count) || action_count > 9u) return 125;
  uint32_t aop[9] = {0}, aarity[9] = {0}, aaux[9] = {0};
  uint32_t aargc[9] = {0}, aarg0[9] = {0};
  for (uint32_t i = 0; i < action_count; ++i) {
    if (!take(p, n, &at, &aop[i]) || !take(p, n, &at, &aarity[i]) ||
        !take(p, n, &at, &aaux[i]) || !take(p, n, &at, &aargc[i]) ||
        aargc[i] != aarity[i] || aargc[i] > 1u) return 125;
    if (aargc[i] == 1u && !take(p, n, &at, &aarg0[i])) return 125;
  }
  if (at != n) return 125;

  if (node_count == 1u && op[0] == 0u && arity[0] == 0u && aux[0] == 0u &&
      action_count == 4u &&
      aop[0] == 0u && aarg0[0] == 0u && aaux[0] == 0u &&
      aop[1] == 6u && aarg0[1] == 0u && aaux[1] == 0u &&
      aop[2] == 18u && aarity[2] == 0u && aaux[2] == 0u &&
      aop[3] == 22u && aarg0[3] == 0u && aaux[3] == 0u)
    return (int)immediate[0];

  if (node_count == 5u &&
      op[0] == 1u && arity[0] == 0u && aux[0] == 7u &&
      op[1] == 9u && arity[1] == 1u && aux[1] == 4u && arg0[1] == 0u &&
      op[2] == 0u && arity[2] == 0u && aux[2] == 0u &&
      op[3] == 0u && arity[3] == 0u && aux[3] == 0u && immediate[3] == 4u &&
      op[4] == 15u && arity[4] == 2u && aux[4] == 0u &&
        arg0[4] == 3u && arg1[4] == 0u &&
      action_count == 9u &&
      aop[0] == 0u && aarg0[0] == 0u && aaux[0] == 0u &&
      aop[1] == 0u && aarg0[1] == 1u && aaux[1] == 0u &&
      aop[2] == 0u && aarg0[2] == 2u && aaux[2] == 0u &&
      aop[3] == 0u && aarg0[3] == 3u && aaux[3] == 0u &&
      aop[4] == 0u && aarg0[4] == 4u && aaux[4] == 0u &&
      aop[5] == 6u && aarg0[5] == 2u && aaux[5] == 0u &&
      aop[6] == 6u && aarg0[6] == 4u && aaux[6] == 7u &&
      aop[7] == 18u && aarity[7] == 0u && aaux[7] == 0u &&
      aop[8] == 22u && aarg0[8] == 1u && aaux[8] == 0u)
    return (int)immediate[2];
  return 125;
}
'''


def _generated_c0_lean_source(*, lean_program: str, source: str, entry_rva: int) -> str:
    body = lean_program.replace(
        "import StageA.RelationalInterpreter",
        "import StageA.RelationalC0",
        1,
    )
    marker = "end StageA.GeneratedRelational\n"
    if not body.endswith(marker):
        raise StageAInputError("generated interpreter Lean source has unexpected shape")
    suffix = f'''

open StageA.Relational.Source

def generatedC0Program : C0Program := {{
  entryRva := {entry_rva}
  records := semanticInterpreterProgramRecords
}}

def generatedC0Source : String := {json.dumps(source)}

theorem generatedC0SourceExact :
    generatedC0Source = generatedC0Program.canonicalSource := by
  decide +kernel

theorem generatedC0ProgramClosed : generatedC0Program.closed = true := by
  decide +kernel

def generatedCheckedC0Source :
    CheckedC0Source generatedC0Program generatedC0Source := {{
  programClosed := generatedC0ProgramClosed
  sourceExact := generatedC0SourceExact
}}
'''
    return body[: -len(marker)] + suffix + "\nend StageA.GeneratedRelational\n"


def _artifact(path: Path) -> C0Artifact:
    return C0Artifact(path=path.name, sha256=sha256_file(path), size=path.stat().st_size)


def _manifest_artifact(manifest: C0SourceManifest, path: str) -> C0Artifact:
    matches = [artifact for artifact in manifest.artifacts if artifact.path == path]
    if len(matches) != 1:
        raise StageAInputError(f"C0 source manifest must contain exactly one {path!r}")
    return matches[0]


def _validate_tool(path: str, expected_sha256: str, *, label: str) -> None:
    tool = Path(path)
    if not tool.is_file() or not os.access(tool, os.X_OK):
        raise StageAInputError(f"pinned C0 {label} is not an executable file")
    if sha256_file(tool) != expected_sha256:
        raise StageAInputError(f"pinned C0 {label} hash changed")


def _nix_store_root(path: Path) -> Path:
    path = path.resolve()
    store = Path("/nix/store")
    try:
        relative = path.relative_to(store)
    except ValueError as exc:
        raise StageAInputError("proof and candidate artifacts must be Nix store outputs") from exc
    if not relative.parts:
        raise StageAInputError("a Nix store output path is required")
    root = store / relative.parts[0]
    if not root.exists():
        raise StageAInputError("Nix store output is not realized")
    return root


def _nix_derivation_identity(value: object, label: str) -> str:
    identity = _nonempty_string(value, label)
    path = Path(identity)
    if path.parent != Path("/nix/store") or not path.name.endswith(".drv"):
        raise StageAInputError(f"{label} must be an absolute Nix derivation path")
    if not path.is_file() or path.is_symlink():
        raise StageAInputError(f"{label} is not a realized Nix derivation file")
    return identity


def _nix_path_info(path: Path) -> dict[str, Any]:
    nix = Path("/run/current-system/sw/bin/nix")
    if not nix.is_file():
        raise StageAInputError("Nix is required to validate source-equivalence provenance")
    try:
        completed = subprocess.run(
            [str(nix), "path-info", "--json", "--json-format", "1", str(path)],
            check=True,
            capture_output=True,
            text=True,
        )
        payload = json.loads(completed.stdout)
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"cannot validate Nix store output {path}: {exc}") from exc
    if not isinstance(payload, dict) or set(payload) != {str(path)}:
        raise StageAInputError("Nix path-info returned an unexpected output inventory")
    info = _object(payload[str(path)], "Nix path info")
    if not isinstance(info.get("deriver"), str) or not info["deriver"].endswith(".drv"):
        raise StageAInputError("Nix output has no realized derivation identity")
    if not isinstance(info.get("narHash"), str) or not info["narHash"].startswith(
        "sha256-"
    ):
        raise StageAInputError("Nix output has no SHA-256 NAR identity")
    return info


_APPROVED_LEAN_AXIOMS = frozenset({"propext", "Classical.choice", "Quot.sound"})


def _validate_compilation_attestation(
    attestation: Mapping[str, Any],
    manifest_path: Path,
    manifest: C0SourceManifest,
) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    try:
        if attestation.get("format") != C0_COMPILATION_ATTESTATION_FORMAT:
            raise StageAInputError("unsupported compilation attestation format")
        binding = _object(
            attestation.get("source_manifest"), "attestation source_manifest"
        )
        if binding.get("sha256") != sha256_file(manifest_path):
            issues.append(_issue("violated", "source_manifest_hash_mismatch", None))
        profile_binding = _object(
            attestation.get("toolchain_profile"), "attestation toolchain profile"
        )
        profile_path = Path(
            _nonempty_string(profile_binding.get("path"), "toolchain_profile.path")
        ).resolve()
        if profile_binding.get("sha256") != sha256_file(profile_path):
            issues.append(_issue("violated", "toolchain_profile_hash_mismatch", None))
        profile = C0ToolchainProfile.load(profile_path)
        if profile_binding.get("id") != profile.identifier:
            issues.append(_issue("violated", "toolchain_profile_id_mismatch", None))
        if profile.identifier != manifest.runtime_profile:
            issues.append(_issue("violated", "runtime_profile_mismatch", None))
        build = _object(attestation.get("build"), "attestation build")
        output = _nix_store_root(
            Path(_nonempty_string(build.get("output"), "build.output"))
        )
        info = _nix_path_info(output)
        try:
            _nix_derivation_identity(
                build.get("derivation"), "attested candidate derivation"
            )
        except StageAInputError:
            issues.append(_issue("violated", "candidate_derivation_invalid", None))
        if build.get("registered_derivation") != info["deriver"]:
            issues.append(
                _issue("violated", "candidate_registered_derivation_mismatch", None)
            )
        if build.get("nar_hash") != info["narHash"]:
            issues.append(_issue("violated", "candidate_nar_hash_mismatch", None))
        if build.get("flags") != list(profile.flags):
            issues.append(_issue("violated", "compiler_flags_mismatch", None))
        if build.get("runtime_sha256") != profile.runtime_sha256:
            issues.append(_issue("violated", "runtime_hash_mismatch", None))
        runtime = _manifest_artifact(manifest, "spaghetti-c0-runtime-v1.c")
        if runtime.sha256 != profile.runtime_sha256:
            issues.append(_issue("violated", "runtime_source_hash_mismatch", None))
        tools = _object(build.get("tools"), "attestation tools")
        expected_tools = {
            "compiler": (profile.compiler, profile.compiler_sha256),
            "assembler": (profile.assembler, profile.assembler_sha256),
            "linker": (profile.linker, profile.linker_sha256),
        }
        for label, (path, digest) in expected_tools.items():
            row = _object(tools.get(label), f"attestation tools.{label}")
            if row != {"path": path, "sha256": digest}:
                issues.append(_issue("violated", f"{label}_binding_mismatch", None))
            _validate_tool(path, digest, label=label)
        candidate = C0Artifact.parse(attestation.get("candidate"), label="candidate")
        candidate_path = _within(output, candidate.path)
        if (
            not candidate_path.is_file()
            or candidate_path.stat().st_size != candidate.size
            or sha256_file(candidate_path) != candidate.sha256
        ):
            issues.append(_issue("violated", "compiled_candidate_hash_mismatch", None))
        else:
            _validate_pe32(candidate_path, "attested compiled candidate")
        assumption = _object(attestation.get("assumption"), "attestation assumption")
        if assumption != _C0_COMPILATION_ASSUMPTION:
            issues.append(_issue("violated", "wrong_compiler_assumption", None))
        if attestation.get("status") != "complete":
            issues.append(_issue("incomplete", "compilation_attestation_incomplete", None))
    except (OSError, StageAInputError) as exc:
        issues.append(
            _issue(
                "violated",
                "invalid_compilation_attestation",
                {"detail": str(exc)},
            )
        )
    return issues


def _validate_lean_source_bundle(
    bundle: Mapping[str, Any],
    binding: Mapping[str, Any],
    manifest_path: Path,
    original: Path,
    attestation: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Inspect a Nix-produced Lean graph without granting status-field authority."""

    issues: list[dict[str, Any]] = []
    checked: list[str] = []
    if binding.get("format") != "stage-a-c0-proof-binding-v1":
        issues.append(_issue("violated", "invalid_lean_proof_binding", None))
    if binding.get("original_sha256") != sha256_file(original):
        issues.append(_issue("violated", "lean_original_binding_mismatch", None))
    if binding.get("source_manifest_sha256") != sha256_file(manifest_path):
        issues.append(_issue("violated", "lean_source_binding_mismatch", None))
    if binding.get("acceptance_theorem") != SOURCE_ACCEPTANCE_INSTANCE_THEOREM:
        issues.append(_issue("violated", "lean_acceptance_binding_mismatch", None))
    if attestation is not None:
        candidate = attestation.get("candidate")
        profile = attestation.get("toolchain_profile")
        build = attestation.get("build")
        if not isinstance(candidate, Mapping) or binding.get(
            "candidate_sha256"
        ) != candidate.get("sha256"):
            issues.append(_issue("violated", "lean_candidate_binding_mismatch", None))
        if not isinstance(profile, Mapping) or binding.get(
            "toolchain_profile_sha256"
        ) != profile.get("sha256"):
            issues.append(_issue("violated", "lean_toolchain_binding_mismatch", None))
        if not isinstance(build, Mapping) or binding.get(
            "candidate_build_identity"
        ) != build.get("derivation"):
            issues.append(_issue("violated", "lean_build_identity_mismatch", None))
    if bundle.get("format") != "stage-a-lean-target-bundle-v2":
        issues.append(_issue("violated", "invalid_lean_proof_bundle", None))
        return {
            "checked_theorems": checked,
            "issues": issues,
        }
    if bundle.get("lean_trust") != 0:
        issues.append(_issue("violated", "lean_trust_level_not_zero", None))
    requested: set[str] = set()
    inventories: dict[str, list[str]] = {}
    nodes = bundle.get("nodes")
    if not isinstance(nodes, list):
        issues.append(_issue("violated", "lean_proof_nodes_malformed", None))
        nodes = []
    for node_index, node_value in enumerate(nodes):
        node = _object(node_value, f"Lean proof node {node_index}")
        outputs = node.get("outputs")
        if not isinstance(outputs, list):
            issues.append(
                _issue("violated", "lean_proof_node_outputs_malformed", {"node": node_index})
            )
            continue
        for output_index, output_value in enumerate(outputs):
            output = _object(
                output_value, f"Lean proof node {node_index} output {output_index}"
            )
            audit = output.get("axiom_audit")
            if not isinstance(audit, dict) or audit.get("complete") is not True:
                continue
            raw_requested = audit.get("requested")
            raw_inventories = audit.get("inventories")
            if not isinstance(raw_requested, list) or not isinstance(raw_inventories, dict):
                issues.append(_issue("violated", "lean_axiom_audit_malformed", None))
                continue
            for theorem in raw_requested:
                if not isinstance(theorem, str) or theorem not in raw_inventories:
                    issues.append(_issue("violated", "lean_axiom_audit_malformed", None))
                    continue
                axioms = raw_inventories[theorem]
                if not isinstance(axioms, list) or not all(
                    isinstance(axiom, str) for axiom in axioms
                ):
                    issues.append(_issue("violated", "lean_axiom_audit_malformed", None))
                    continue
                requested.add(theorem)
                inventories.setdefault(theorem, []).extend(axioms)
    for theorem, axioms in sorted(inventories.items()):
        unsupported = sorted(set(axioms) - _APPROVED_LEAN_AXIOMS)
        if unsupported:
            issues.append(
                _issue(
                    "violated",
                    "unapproved_lean_axioms",
                    {"theorem": theorem, "axioms": unsupported},
                )
            )
        else:
            checked.append(theorem)

    # Exact rendering is useful intermediate evidence.  It is deliberately
    # insufficient for acceptance: the final theorem must be an instantiated
    # theorem that binds this original and this manifest, not the generic
    # theorem declaration from the stable kernel.
    required_source_checks = {
        "StageA.GeneratedRelational.generatedC0SourceExact",
        "StageA.GeneratedRelational.generatedC0ProgramClosed",
    }
    if not required_source_checks.issubset(requested):
        issues.append(_issue("incomplete", "lean_c0_source_attestation_missing", None))
    if SOURCE_ACCEPTANCE_INSTANCE_THEOREM not in requested:
        issues.append(
            _issue(
                "incomplete",
                "lean_original_source_whole_program_theorem_missing",
                {
                    "original_sha256": sha256_file(original),
                    "source_manifest_sha256": sha256_file(manifest_path),
                },
            )
        )
    return {"checked_theorems": checked, "issues": issues}


def _blocker(code: str, rva: int) -> dict[str, Any]:
    return {
        "status": "incomplete",
        "code": code,
        "location": {"rva": rva},
        "next_action": "extend the generic C0 profile and regenerate the source project",
    }


def _issue(status: str, code: str, location: object) -> dict[str, Any]:
    return {"status": status, "code": code, "location": location}


def _validate_pe32(path: Path, label: str) -> None:
    if not path.is_file() or path.is_symlink():
        raise StageAInputError(f"{label} must be a regular file")
    try:
        pe = pefile.PE(data=path.read_bytes(), fast_load=True)
    except (OSError, pefile.PEFormatError) as exc:
        raise StageAInputError(f"{label} is not a PE: {exc}") from exc
    if int(pe.FILE_HEADER.Machine) != 0x14C or int(pe.OPTIONAL_HEADER.Magic) != 0x10B:
        raise StageAInputError(f"{label} is not an i386 PE32 image")


def _within(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise StageAInputError(f"artifact path escapes source root: {relative!r}") from exc
    return candidate


def _read_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"cannot read {label}: {exc}") from exc
    return _object(value, label)


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise StageAInputError(f"{label} must be a JSON object")
    return value


def _list(value: object, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise StageAInputError(f"{label} must be a JSON array")
    return value


def _object_list(value: object, label: str) -> list[dict[str, Any]]:
    return [_object(item, f"{label}[{index}]") for index, item in enumerate(_list(value, label))]


def _fields(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        missing = sorted(expected - set(value))
        extra = sorted(set(value) - expected)
        raise StageAInputError(f"{label} schema drift: missing={missing}, extra={extra}")


def _nonempty_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise StageAInputError(f"{label} must be a non-empty string")
    return value


def _digest(value: object, label: str) -> str:
    digest = _nonempty_string(value, label)
    if len(digest) != _DIGEST_LENGTH or any(character not in "0123456789abcdef" for character in digest):
        raise StageAInputError(f"{label} must be a lowercase SHA-256 digest")
    return digest


def _nonnegative_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise StageAInputError(f"{label} must be a non-negative integer")
    return value


def _u32(value: object, label: str) -> int:
    result = _nonnegative_int(value, label)
    if result >= 2**32:
        raise StageAInputError(f"{label} must fit in 32 bits")
    return result


def _status(value: object) -> str:
    status = _nonempty_string(value, "status")
    if status not in {"complete", "incomplete"}:
        raise StageAInputError("source manifest status must be complete or incomplete")
    return status


__all__ = [
    "C0SourceManifest",
    "C0ToolchainProfile",
    "SOURCE_ACCEPTANCE_THEOREM",
    "SOURCE_ACCEPTANCE_INSTANCE_THEOREM",
    "attest_c0_compilation",
    "build_source_equivalence_report",
    "generate_c0_proof_sources",
    "generate_c0_source_project",
]

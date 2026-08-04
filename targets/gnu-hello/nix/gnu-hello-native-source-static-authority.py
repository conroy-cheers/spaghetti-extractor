#!/usr/bin/env python3
"""Emit exact static authority for the GNU hello source candidate.

The large PE byte tree, import certificate, and relocation inventory are
checked by the isolated interpreter-kernel-data graph.  This stdlib-only
adapter binds those facts to the exact candidate identity expected by the
native-source ``CompiledArtifact`` interface.  Runtime environments, callable
external behavior, and indirect-target inventories remain explicit inputs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


INVENTORY_FORMAT = "stage-a-interpreter-kernel-data-inventory-v9"
OUTPUT_MODULE = "GeneratedGnuHelloNativeSourceCandidateStaticAuthority"
NAMESPACE = "StageA.GeneratedRelational.GnuHelloNativeSourceCandidateStaticAuthority"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_object(path: Path, label: str) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _lean_source(candidate_sha256: str, candidate_size: int) -> str:
    return f"""import StageA.GeneratedInterpreterKernelCandidateAuthority
import StageA.GeneratedInterpreterKernelDataRelocationBundle
import StageA.RelationalNativeSource

namespace {NAMESPACE}

open StageA.Formal
open StageA.Relational
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.NativeSource
open StageA.GeneratedRelational.CandidatePEAuthority
open StageA.GeneratedRelational.InterpreterKernelData

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

/-- Exact identity of ``sourceCandidate/candidate.exe``.  The digest is
provenance; machine semantics remain tied to the checked byte tree. -/
def generatedCandidateIdentity : ArtifactIdentity := {{
  role := "compiled-candidate-pe32"
  sha256 := "{candidate_sha256}"
  byteLength := {candidate_size}
}}

theorem generatedCandidateIdentityValid : generatedCandidateIdentity.Valid := by
  unfold ArtifactIdentity.Valid generatedCandidateIdentity
  decide

abbrev generatedCandidateBytes : ByteTree := candidateBytes

abbrev generatedCandidatePe : PE32 := candidatePe

theorem generatedCandidateByteLengthExact :
    generatedCandidateIdentity.byteLength = generatedCandidateBytes.length := by
  decide +kernel

theorem generatedCandidatePeParsedExact :
    parsePE32Tree generatedCandidateBytes = some generatedCandidatePe :=
  candidateParsed

theorem generatedCandidatePeBytesExact :
    generatedCandidatePe.bytes = generatedCandidateBytes := by
  rfl

abbrev generatedCandidateImportCertificate : ImportTableCertificate :=
  importCertificate

theorem generatedCandidateImportsParsed :
    importTableValid generatedCandidatePe
      generatedCandidateImportCertificate = true :=
  importsChecked

abbrev generatedCandidateRelocations : List BaseRelocation :=
  generatedInterpreterKernelRelocations

theorem generatedCandidateRelocationsParsed :
    parseRelocations generatedCandidatePe =
      some generatedCandidateRelocations :=
  generatedInterpreterKernelRelocationsParsed

theorem generatedCandidateLoaderImageValid :
    preferredBaseLoaderImageValid generatedCandidatePe = true := by
  decide +kernel

/-- The exact compiled artifact with provenance identities supplied by the
source-project/toolchain assembly lane.  No runtime environment is embedded in
this static artifact. -/
def generatedCandidateArtifact
    (buildIdentity : NixRealizationIdentity)
    (sourceProjectNarHash toolchainNarHash : String) : CompiledArtifact := {{
  identity := generatedCandidateIdentity
  buildIdentity
  sourceProjectNarHash
  toolchainNarHash
  bytes := generatedCandidateBytes
  pe := generatedCandidatePe
  identityValid := generatedCandidateIdentityValid
  byteLengthExact := generatedCandidateByteLengthExact
  parsedExactly := generatedCandidatePeParsedExact
  peBytesExact := generatedCandidatePeBytesExact
}}

/-- Environment-parameterized assembly of the current machine-authority
interface.  ``indirectTargetsValid`` checks inventory shape only; callers must
separately prove reachable indirect-target completeness before acceptance. -/
def generatedCandidateMachineAuthority
    (buildIdentity : NixRealizationIdentity)
    (sourceProjectNarHash toolchainNarHash : String)
    (environment : NativeWorldEnvironment)
    (callableExternal : Option NativeCallableExternalConfig)
    (indirectTargets : NativeIndirectTargetInventory)
    (callableBound : forall config,
      callableExternal = some config ->
      config.BoundTo generatedCandidatePe
        generatedCandidateImportCertificate.imports)
    (indirectTargetsValid :
      indirectTargets.valid generatedCandidatePe = true) :
    ExactCompiledPE32Authority
      (generatedCandidateArtifact buildIdentity sourceProjectNarHash
        toolchainNarHash) := {{
  importCertificate := generatedCandidateImportCertificate
  relocations := generatedCandidateRelocations
  environment
  callableExternal
  indirectTargets
  importsParsed := generatedCandidateImportsParsed
  relocationsParsed := generatedCandidateRelocationsParsed
  loaderImageValid := generatedCandidateLoaderImageValid
  callableBound
  indirectTargetsValid
}}

end {NAMESPACE}
"""


def _main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--kernel-data-inventory", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    candidate = Path(args.candidate)
    inventory_path = Path(args.kernel_data_inventory)
    out = Path(args.out)
    inventory = _read_object(inventory_path, "kernel-data inventory")
    if inventory.get("format") != INVENTORY_FORMAT:
        raise ValueError("unsupported kernel-data inventory format")

    candidate_sha256 = _sha256(candidate)
    candidate_size = candidate.stat().st_size
    if inventory.get("candidate_sha256") != candidate_sha256:
        raise ValueError("kernel-data inventory binds a different candidate")
    if inventory.get("candidate_bytes") != candidate_size:
        raise ValueError("kernel-data inventory candidate size mismatch")

    modules = inventory.get("modules")
    if not isinstance(modules, list):
        raise ValueError("kernel-data inventory modules must be a list")
    roles = {
        row.get("role")
        for row in modules
        if isinstance(row, dict) and isinstance(row.get("role"), str)
    }
    required_roles = {"candidate-pe-binding", "candidate-relocation-bundle"}
    if not required_roles <= roles:
        missing = ", ".join(sorted(required_roles - roles))
        raise ValueError(f"kernel-data inventory lacks required roles: {missing}")

    counts = inventory.get("counts")
    if not isinstance(counts, dict):
        raise ValueError("kernel-data inventory counts must be an object")
    relocation_count = counts.get("relocation_packs")
    relocation_blocks = counts.get("relocation_blocks")
    if not isinstance(relocation_count, int) or relocation_count <= 0:
        raise ValueError("candidate relocation-pack inventory must be nonempty")
    if not isinstance(relocation_blocks, int) or relocation_blocks <= 0:
        raise ValueError("candidate relocation-block inventory must be nonempty")

    stage_a = out / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    module_path = stage_a / f"{OUTPUT_MODULE}.lean"
    module_path.write_text(
        _lean_source(candidate_sha256, candidate_size), encoding="ascii"
    )

    manifest = {
        "format": "stage-a-native-source-candidate-static-authority-v1",
        "phase": "native-source-candidate-static-authority",
        "status": "source-ready",
        "candidate": {
            "path": str(candidate),
            "sha256": candidate_sha256,
            "size": candidate_size,
        },
        "kernel_data": {
            "inventory": str(inventory_path),
            "format": inventory["format"],
            "relocation_packs": relocation_count,
            "relocation_blocks": relocation_blocks,
        },
        "module": OUTPUT_MODULE,
        "namespace": NAMESPACE,
        "compiled_identity_interface": {
            "compiled_identity": f"{NAMESPACE}.generatedCandidateIdentity",
            "compiled_identity_valid": (
                f"{NAMESPACE}.generatedCandidateIdentityValid"
            ),
            "compiled_bytes": f"{NAMESPACE}.generatedCandidateBytes",
            "compiled_pe": f"{NAMESPACE}.generatedCandidatePe",
            "compiled_byte_length_exact": (
                f"{NAMESPACE}.generatedCandidateByteLengthExact"
            ),
            "compiled_pe_parsed_exact": (
                f"{NAMESPACE}.generatedCandidatePeParsedExact"
            ),
            "compiled_pe_bytes_exact": (
                f"{NAMESPACE}.generatedCandidatePeBytesExact"
            ),
            "import_certificate": (
                f"{NAMESPACE}.generatedCandidateImportCertificate"
            ),
            "imports_parsed": (
                f"{NAMESPACE}.generatedCandidateImportsParsed"
            ),
            "relocations": f"{NAMESPACE}.generatedCandidateRelocations",
            "relocations_parsed": (
                f"{NAMESPACE}.generatedCandidateRelocationsParsed"
            ),
            "loader_image_valid": (
                f"{NAMESPACE}.generatedCandidateLoaderImageValid"
            ),
        },
        "constructors": {
            "compiled_artifact": f"{NAMESPACE}.generatedCandidateArtifact",
            "machine_authority": (
                f"{NAMESPACE}.generatedCandidateMachineAuthority"
            ),
        },
        "trust": {
            "executes_original_binary": False,
            "executes_candidate_binary": False,
            "exact_candidate_bytes_checked_in_lean": True,
            "imports_parsed_from_candidate_exe": True,
            "relocations_parsed_from_candidate_exe": True,
            "environment_parameterized": True,
            "indirect_target_shape_is_completeness": False,
            "indirect_target_completeness_proved": False,
            "whole_program_acceptance_authority": False,
        },
    }
    (out / "phase-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    _main()

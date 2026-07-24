#!/usr/bin/env python3
"""Bind exact GNU hello artifacts to the generic canonical relation core."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

from spaghetti_extractor.errors import StageAInputError
from spaghetti_extractor.relational.lean.interpreter_mixed_relation_core import (
    INTERPRETER_MIXED_RELATION_CORE_PLAN_FILENAME,
    InterpreterMixedRelationCoreSpec,
    write_interpreter_mixed_relation_core_bundle,
)
from spaghetti_extractor.util import sha256_file, write_json


PHASE_FORMAT = "stage-a-gnu-hello-canonical-relation-core-v1"
BINDING_MODULE = "GeneratedGnuHelloCanonicalRelationCoreBindings"
CORE_MODULE = "GeneratedGnuHelloCanonicalRelationCore"


class GnuHelloCanonicalRelationCoreError(StageAInputError):
    """Submitted exact artifacts do not belong to one proof instance."""


def _object(path: Path, label: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GnuHelloCanonicalRelationCoreError(
            f"unable to read {label}: {path}"
        ) from exc
    if not isinstance(value, dict):
        raise GnuHelloCanonicalRelationCoreError(f"{label} must be an object")
    return value


def _binding_source() -> str:
    return """import StageA.GeneratedRelationalInterpreterMixedOriginal
import StageA.GeneratedRelationalInterpreterMixedOriginalStaticReachability
import StageA.GeneratedRelationalInterpreterOriginalCarrierBinding
import StageA.GeneratedRelationalInterpreterMixedAuthority
import StageA.GeneratedRelationalInterpreterKernelABI

namespace StageA.GeneratedRelational.GnuHelloCanonicalRelationCoreBindings

open StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedProfile
open StageA.Relational.InterpreterNativeWorld

namespace Original := StageA.GeneratedRelational.InterpreterMixedOriginal
namespace Reachability :=
  StageA.GeneratedRelational.InterpreterMixedOriginalStaticReachability
namespace OriginalCarrier :=
  StageA.GeneratedRelational.InterpreterOriginalCarrierBinding
namespace Candidate := StageA.GeneratedRelational.InterpreterMixedAuthority
namespace KernelABI := StageA.GeneratedRelational.InterpreterKernelABI

structure Requirements where
  originalEnvironment : WorldExternalEnvironment
  originalProtocolEnvironment : WorldExternalProtocolEnvironment
  originalExternalCallSites : List ExternalCallSiteContract
  candidateEnvironment : NativeWorldEnvironment

def Requirements.originalProgram (requirements : Requirements) :
    DecodedWorldProgram :=
  Original.generatedOriginalDecodedProgram requirements.originalEnvironment
    requirements.originalProtocolEnvironment
    requirements.originalExternalCallSites

def Requirements.programBinding (requirements : Requirements) :
    ExactMixedProgramBinding Original.generatedOriginalStaticContext
      requirements.originalProgram := by
  simpa [Requirements.originalProgram] using
    OriginalCarrier.generatedOriginalExactMixedProgramBinding
      requirements.originalEnvironment
      requirements.originalProtocolEnvironment
      requirements.originalExternalCallSites

def Requirements.candidate (requirements : Requirements) :
    ExactNativeWorldProgram :=
  Candidate.generatedCandidateNativeWorldProgram requirements.candidateEnvironment

def Requirements.candidateAuthority (requirements : Requirements) :
    ExactNativeCandidateAuthority requirements.candidate := by
  simpa [Requirements.candidate] using
    Candidate.generatedExactNativeCandidateAuthority
      requirements.candidateEnvironment

def Requirements.concreteABI (requirements : Requirements) :
    ConcreteKernelABI requirements.candidate.pe requirements.candidate.imports
      requirements.candidateAuthority.relocations
      requirements.candidateAuthority.tableRva
      requirements.candidateAuthority.countRva
      requirements.candidateAuthority.semanticRecords := by
  simpa [Requirements.candidate, Requirements.candidateAuthority,
    Candidate.generatedExactNativeCandidateAuthority,
    Candidate.generatedCandidateNativeWorldProgram] using
      KernelABI.generatedConcreteInterpreterKernelABI

def generatedLaunchMemoryProfile : MixedPE32ConsoleLaunchMemoryProfile := {
  stackRangeId := 0
  tebRangeId := 1
  pebRangeId := 2
  processParametersRangeId := 3
  argvRangeId := 4
  environmentRangeId := 5
  tlsArrayRangeId := 6
}

end StageA.GeneratedRelational.GnuHelloCanonicalRelationCoreBindings
"""


def generate(
    *,
    mixed_original_plan: Path,
    static_reachability_plan: Path,
    kernel_data_inventory: Path,
    out: Path,
) -> None:
    mixed = _object(mixed_original_plan, "mixed original plan")
    reachability = _object(
        static_reachability_plan, "static reachability plan"
    )
    data = _object(kernel_data_inventory, "kernel data inventory")
    if mixed.get("format") != "stage-a-interpreter-mixed-original-v1":
        raise GnuHelloCanonicalRelationCoreError(
            "mixed original plan has an unsupported format"
        )
    if (
        reachability.get("format")
        != "stage-a-interpreter-mixed-original-static-reachability-v1"
    ):
        raise GnuHelloCanonicalRelationCoreError(
            "static reachability plan has an unsupported format"
        )
    if data.get("format") != "stage-a-interpreter-kernel-data-inventory-v7":
        raise GnuHelloCanonicalRelationCoreError(
            "kernel data inventory has an unsupported format"
        )
    if any(
        payload.get("acceptance_authority") is True
        for payload in (mixed, reachability, data)
    ):
        raise GnuHelloCanonicalRelationCoreError(
            "intermediate inputs must not claim acceptance authority"
        )
    state_machine_sha256 = mixed.get("state_machine_sha256")
    if not isinstance(state_machine_sha256, str) or (
        data.get("state_machine_sha256") != state_machine_sha256
    ):
        raise GnuHelloCanonicalRelationCoreError(
            "original and candidate artifacts bind different state machines"
        )
    reachability_inputs = reachability.get("inputs")
    if not isinstance(reachability_inputs, dict) or (
        reachability_inputs.get("state_machine_sha256")
        != state_machine_sha256
    ):
        raise GnuHelloCanonicalRelationCoreError(
            "reachability binds a different state machine"
        )
    mixed_input = reachability_inputs.get("mixed_original_plan")
    if not isinstance(mixed_input, dict) or mixed_input.get("sha256") != sha256_file(
        mixed_original_plan
    ):
        raise GnuHelloCanonicalRelationCoreError(
            "reachability does not bind the submitted mixed original plan"
        )

    stage_a = out / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    (stage_a / f"{BINDING_MODULE}.lean").write_text(
        _binding_source(), encoding="ascii"
    )
    write_interpreter_mixed_relation_core_bundle(
        stage_a,
        InterpreterMixedRelationCoreSpec(
            binding_module=f"StageA.{BINDING_MODULE}",
            namespace=(
                "StageA.GeneratedRelational.GnuHelloCanonicalRelationCore"
            ),
            output_module=CORE_MODULE,
            parameter_name="requirements",
            parameter_type=(
                "StageA.GeneratedRelational."
                "GnuHelloCanonicalRelationCoreBindings.Requirements"
            ),
            original_context=(
                "StageA.GeneratedRelational.InterpreterMixedOriginal."
                "generatedOriginalStaticContext"
            ),
            original_authority=(
                "StageA.GeneratedRelational.InterpreterMixedOriginal."
                "generatedExactOriginalDecodedAuthority"
            ),
            original_program="requirements.originalProgram",
            candidate="requirements.candidate",
            candidate_authority="requirements.candidateAuthority",
            program_binding="requirements.programBinding",
            concrete_abi="requirements.concreteABI",
            launch=(
                "StageA.GeneratedRelational.InterpreterMixedOriginal."
                "generatedOriginalLaunch"
            ),
            original_root=(
                "StageA.GeneratedRelational.InterpreterMixedOriginal."
                "generatedDirectExactOriginalDecodedLaunchRoot"
            ),
            reachability=(
                "StageA.GeneratedRelational."
                "InterpreterMixedOriginalStaticReachability."
                "generatedExactOriginalDecodedStaticReachability"
            ),
            launch_memory_profile=(
                "StageA.GeneratedRelational."
                "GnuHelloCanonicalRelationCoreBindings."
                "generatedLaunchMemoryProfile"
            ),
        ),
    )
    write_json(
        out / "phase-manifest.json",
        {
            "format": PHASE_FORMAT,
            "phase": "canonical-relation-core",
            "status": "source-ready",
            "acceptance_authority": False,
            "failure_mode": "incomplete",
            "state_machine_sha256": state_machine_sha256,
            "candidate_sha256": data.get("candidate_sha256"),
            "inputs": {
                "mixed_original_plan": sha256_file(mixed_original_plan),
                "static_reachability_plan": sha256_file(
                    static_reachability_plan
                ),
                "kernel_data_inventory": sha256_file(kernel_data_inventory),
            },
            "outputs": {
                "binding_module": f"StageA/{BINDING_MODULE}.lean",
                "core_module": f"StageA/{CORE_MODULE}.lean",
                "core_plan": INTERPRETER_MIXED_RELATION_CORE_PLAN_FILENAME,
            },
        },
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mixed-original-plan", type=Path, required=True)
    parser.add_argument("--static-reachability-plan", type=Path, required=True)
    parser.add_argument("--kernel-data-inventory", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    generate(
        mixed_original_plan=args.mixed_original_plan,
        static_reachability_plan=args.static_reachability_plan,
        kernel_data_inventory=args.kernel_data_inventory,
        out=args.out,
    )


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Bind GNU hello artifacts to generic checked mixed-source coverage."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

from spaghetti_extractor.errors import StageAInputError
from spaghetti_extractor.relational.lean.interpreter_mixed_source_coverage import (
    INTERPRETER_MIXED_SOURCE_COVERAGE_PLAN_FILENAME,
    InterpreterMixedSourceCoverageSpec,
    write_interpreter_mixed_source_coverage_bundle,
)
from spaghetti_extractor.util import sha256_file, write_json


MIXED_PLAN_FORMAT = "stage-a-interpreter-mixed-original-v1"
STATIC_REACHABILITY_FORMAT = (
    "stage-a-interpreter-mixed-original-static-reachability-v1"
)
KERNEL_DATA_FORMAT = "stage-a-interpreter-kernel-data-inventory-v7"
COMPILED_KERNEL_FORMAT = "stage-a-relational-interpreter-kernel-plan-v2"
PHASE_FORMAT = "stage-a-gnu-hello-constructive-source-coverage-v1"

BINDING_MODULE = "GeneratedGnuHelloConstructiveSourceCoverageBindings"
COVERAGE_MODULE = "GeneratedRelationalInterpreterMixedSourceCoverage"
RULES_MODULE = "GeneratedGnuHelloConstructiveSourceRules"


class GnuHelloConstructiveSourceCoverageError(StageAInputError):
    """The submitted generated artifacts do not describe one exact pair."""


def _read_object(path: Path, label: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GnuHelloConstructiveSourceCoverageError(
            f"unable to read {label}: {path}"
        ) from exc
    if not isinstance(value, dict):
        raise GnuHelloConstructiveSourceCoverageError(f"{label} must be an object")
    return value


def _nat(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise GnuHelloConstructiveSourceCoverageError(
            f"{label} must be a natural number"
        )
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise GnuHelloConstructiveSourceCoverageError(
            f"{label} must be a non-empty string"
        )
    return value


def _require_format(
    value: Mapping[str, Any], expected: str, label: str
) -> None:
    if value.get("format") != expected:
        raise GnuHelloConstructiveSourceCoverageError(
            f"{label} has an unsupported format"
        )
    if value.get("acceptance_authority") is True:
        raise GnuHelloConstructiveSourceCoverageError(
            f"{label} must not claim acceptance authority"
        )


def _operation_entry(kernel: Mapping[str, Any], role: str) -> int:
    functions = kernel.get("kernel_functions")
    if not isinstance(functions, list):
        raise GnuHelloConstructiveSourceCoverageError(
            "compiled kernel functions must be an array"
        )
    matches = [
        row
        for row in functions
        if isinstance(row, dict) and row.get("role") == role
    ]
    if len(matches) != 1:
        raise GnuHelloConstructiveSourceCoverageError(
            f"compiled kernel must expose exactly one {role} function"
        )
    return _nat(matches[0].get("rva_start"), f"{role} entry RVA")


def _binding_source() -> str:
    return """import StageA.GeneratedRelationalInterpreterMixedOriginal
import StageA.GeneratedRelationalInterpreterMixedOriginalStaticReachability
import StageA.GeneratedInterpreterKernelDataBundle
import StageA.GeneratedRelationalInterpreterMixedAuthority

namespace StageA.GeneratedRelational.GnuHelloConstructiveSourceCoverageBindings

open StageA.Relational.Interpreter
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterNativeWorld

structure Requirements where
  candidateEnvironment : NativeWorldEnvironment

def Requirements.candidate (requirements : Requirements) :
    ExactNativeWorldProgram :=
  StageA.GeneratedRelational.InterpreterMixedAuthority.generatedCandidateNativeWorldProgram
    requirements.candidateEnvironment

def Requirements.candidateAuthority (requirements : Requirements) :
    ExactNativeCandidateAuthority requirements.candidate := by
  simpa [Requirements.candidate] using
    StageA.GeneratedRelational.InterpreterMixedAuthority.generatedExactNativeCandidateAuthority
      requirements.candidateEnvironment

def Requirements.candidateSourceRvas (_ : Requirements) : List Nat :=
  StageA.GeneratedRelational.InterpreterKernelData.generatedInterpreterKernelSourceRvas

theorem Requirements.candidateSourceRvasExact (requirements : Requirements) :
    requirements.candidateAuthority.semanticRecords.map
        (fun record => record.sourceRva) = requirements.candidateSourceRvas := by
  simpa [Requirements.candidateAuthority, Requirements.candidate,
    Requirements.candidateSourceRvas,
    StageA.GeneratedRelational.InterpreterMixedAuthority.generatedExactNativeCandidateAuthority]
    using
      StageA.GeneratedRelational.InterpreterKernelData.semanticInterpreterProgramSourceRvasExact

end StageA.GeneratedRelational.GnuHelloConstructiveSourceCoverageBindings
"""


def _rules_source(*, candidate_root_rva: int, step_entry_rva: int) -> str:
    return f"""import StageA.GeneratedRelationalInterpreterMixedSourceCoverage
import StageA.GeneratedRelationalInterpreterKernel

namespace StageA.GeneratedRelational.GnuHelloConstructiveSourceRules

open StageA.Relational.InterpreterMixedConstructiveSourceClassifier
open StageA.Relational.InterpreterMixedContext
open StageA.GeneratedRelational.InterpreterKernel
open StageA.GeneratedRelational.InterpreterMixedSourceCoverage
open StageA.GeneratedRelational.GnuHelloConstructiveSourceCoverageBindings

def generatedInterpreterStepEntry :
    ExactCandidateKernelEntry generatedCompiledKernelProgram := {{
  operation := .interpreterStep
  entryRva := {step_entry_rva}
  entryExact := by decide +kernel
}}

noncomputable def generatedRules (requirements : Requirements) :=
  constructiveSemanticRulesWithLaunch (candidateRootRva := {candidate_root_rva})
    (generatedExactOriginalSemanticSourceCoverage requirements)
    generatedInterpreterStepEntry

noncomputable def generatedInvariant (requirements : Requirements)
    (contract : MixedRelationContract) :=
  constructiveMixedKernelInvariant
    StageA.GeneratedRelational.InterpreterMixedOriginal.generatedOriginalStaticContext
    StageA.GeneratedRelational.InterpreterMixedOriginal.generatedExactOriginalDecodedAuthority
    StageA.GeneratedRelational.InterpreterMixedOriginal.generatedOriginalLaunch
    StageA.GeneratedRelational.InterpreterMixedOriginal.generatedDirectExactOriginalDecodedLaunchRoot
    StageA.GeneratedRelational.InterpreterMixedOriginalStaticReachability.generatedExactOriginalDecodedStaticReachability
    requirements.candidate requirements.candidateAuthority
    generatedCompiledKernelProgram {candidate_root_rva} contract
    (generatedRules requirements)

noncomputable def generatedClassifier (requirements : Requirements)
    (contract : MixedRelationContract) :=
  constructiveMixedKernelSourceClassifier
    StageA.GeneratedRelational.InterpreterMixedOriginal.generatedOriginalStaticContext
    StageA.GeneratedRelational.InterpreterMixedOriginal.generatedExactOriginalDecodedAuthority
    StageA.GeneratedRelational.InterpreterMixedOriginal.generatedOriginalLaunch
    StageA.GeneratedRelational.InterpreterMixedOriginal.generatedDirectExactOriginalDecodedLaunchRoot
    StageA.GeneratedRelational.InterpreterMixedOriginalStaticReachability.generatedExactOriginalDecodedStaticReachability
    requirements.candidate requirements.candidateAuthority
    generatedCompiledKernelProgram {candidate_root_rva} contract
    (generatedRules requirements)

theorem generatedRulesTargetIds (requirements : Requirements) :
    (generatedRules requirements).map
        ConstructiveMixedKernelSourceRule.sourceTargetId =
      StageA.GeneratedRelational.InterpreterMixedOriginalStaticReachability.generatedExactOriginalDecodedStaticReachability.targetIds := by
  exact constructiveSemanticRulesWithLaunch_targetIds
    (candidateRootRva := {candidate_root_rva})
    (generatedExactOriginalSemanticSourceCoverage requirements)
    generatedInterpreterStepEntry

#print axioms generatedInterpreterStepEntry
#print axioms generatedRulesTargetIds
#print axioms generatedClassifier

end StageA.GeneratedRelational.GnuHelloConstructiveSourceRules
"""


def generate(
    *,
    mixed_original_plan: Path,
    static_reachability_plan: Path,
    kernel_data_inventory: Path,
    kernel_plan: Path,
    out: Path,
) -> None:
    mixed = _read_object(mixed_original_plan, "mixed original plan")
    reachability = _read_object(
        static_reachability_plan, "static reachability plan"
    )
    data = _read_object(kernel_data_inventory, "kernel data inventory")
    kernel = _read_object(kernel_plan, "compiled kernel plan")
    _require_format(mixed, MIXED_PLAN_FORMAT, "mixed original plan")
    _require_format(
        reachability, STATIC_REACHABILITY_FORMAT, "static reachability plan"
    )
    _require_format(data, KERNEL_DATA_FORMAT, "kernel data inventory")
    _require_format(kernel, COMPILED_KERNEL_FORMAT, "compiled kernel plan")

    state_machine_sha256 = _text(
        mixed.get("state_machine_sha256"), "mixed state-machine digest"
    )
    if data.get("state_machine_sha256") != state_machine_sha256:
        raise GnuHelloConstructiveSourceCoverageError(
            "mixed original and candidate kernel data bind different state machines"
        )
    reachability_inputs = reachability.get("inputs")
    if not isinstance(reachability_inputs, dict) or (
        reachability_inputs.get("state_machine_sha256") != state_machine_sha256
    ):
        raise GnuHelloConstructiveSourceCoverageError(
            "static reachability binds a different state machine"
        )
    mixed_input = reachability_inputs.get("mixed_original_plan")
    if not isinstance(mixed_input, dict) or (
        mixed_input.get("sha256") != sha256_file(mixed_original_plan)
    ):
        raise GnuHelloConstructiveSourceCoverageError(
            "static reachability does not bind the submitted mixed original plan"
        )

    candidate_sha256 = _text(
        data.get("candidate_sha256"), "kernel-data candidate digest"
    )
    candidate = kernel.get("candidate")
    if not isinstance(candidate, dict) or candidate.get("pe_sha256") != candidate_sha256:
        raise GnuHelloConstructiveSourceCoverageError(
            "kernel data and compiled kernel bind different candidate PEs"
        )
    records = _nat(
        (data.get("counts") or {}).get("records")
        if isinstance(data.get("counts"), dict)
        else None,
        "kernel-data record count",
    )
    program = kernel.get("program")
    if not isinstance(program, dict) or _nat(
        program.get("transfer_count"), "compiled-kernel transfer count"
    ) != records:
        raise GnuHelloConstructiveSourceCoverageError(
            "kernel data and compiled kernel disagree on semantic record count"
        )

    candidate_root_rva = _nat(mixed.get("entry_rva"), "candidate root RVA")
    step_entry_rva = _operation_entry(kernel, "interpreterStep")

    out.mkdir(parents=True, exist_ok=True)
    (out / "StageA").mkdir()
    (out / "StageA" / f"{BINDING_MODULE}.lean").write_text(
        _binding_source(), encoding="ascii"
    )
    coverage = write_interpreter_mixed_source_coverage_bundle(
        out=out / "StageA",
        spec=InterpreterMixedSourceCoverageSpec(
            binding_module=f"StageA.{BINDING_MODULE}",
            namespace=(
                "StageA.GeneratedRelational.InterpreterMixedSourceCoverage"
            ),
            parameter_name="requirements",
            parameter_type=(
                "StageA.GeneratedRelational."
                "GnuHelloConstructiveSourceCoverageBindings.Requirements"
            ),
            context=(
                "StageA.GeneratedRelational.InterpreterMixedOriginal."
                "generatedOriginalStaticContext"
            ),
            authority=(
                "StageA.GeneratedRelational.InterpreterMixedOriginal."
                "generatedExactOriginalDecodedAuthority"
            ),
            launch=(
                "StageA.GeneratedRelational.InterpreterMixedOriginal."
                "generatedOriginalLaunch"
            ),
            root=(
                "StageA.GeneratedRelational.InterpreterMixedOriginal."
                "generatedDirectExactOriginalDecodedLaunchRoot"
            ),
            reachability=(
                "StageA.GeneratedRelational."
                "InterpreterMixedOriginalStaticReachability."
                "generatedExactOriginalDecodedStaticReachability"
            ),
            candidate="requirements.candidate",
            candidate_authority="requirements.candidateAuthority",
            candidate_source_rvas="requirements.candidateSourceRvas",
            candidate_source_rvas_exact=(
                "requirements.candidateSourceRvasExact"
            ),
        ),
    )
    (out / "StageA" / f"{RULES_MODULE}.lean").write_text(
        _rules_source(
            candidate_root_rva=candidate_root_rva,
            step_entry_rva=step_entry_rva,
        ),
        encoding="ascii",
    )
    write_json(
        out / "phase-manifest.json",
        {
            "format": PHASE_FORMAT,
            "acceptance_authority": False,
            "phase": "constructive-source-coverage",
            "status": "source-ready",
            "failure_mode": "incomplete",
            "candidate_sha256": candidate_sha256,
            "state_machine_sha256": state_machine_sha256,
            "counts": {
                "candidate_records": records,
                "reachable_targets": _nat(
                    (reachability.get("counts") or {}).get("reachable_targets")
                    if isinstance(reachability.get("counts"), dict)
                    else None,
                    "reachable target count",
                ),
            },
            "entries": {
                "candidate_root_rva": candidate_root_rva,
                "interpreter_step_rva": step_entry_rva,
            },
            "coverage_plan": INTERPRETER_MIXED_SOURCE_COVERAGE_PLAN_FILENAME,
            "targets": [BINDING_MODULE, COVERAGE_MODULE, RULES_MODULE],
            "remaining_proof_premises": [
                premise
                for premise in coverage.payload()["remaining_proof_premises"]
                if premise != "constructive_source_classification"
            ],
        },
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mixed-original-plan", type=Path, required=True)
    parser.add_argument("--static-reachability-plan", type=Path, required=True)
    parser.add_argument("--kernel-data-inventory", type=Path, required=True)
    parser.add_argument("--kernel-plan", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    generate(
        mixed_original_plan=args.mixed_original_plan,
        static_reachability_plan=args.static_reachability_plan,
        kernel_data_inventory=args.kernel_data_inventory,
        kernel_plan=args.kernel_plan,
        out=args.out,
    )


if __name__ == "__main__":
    main()

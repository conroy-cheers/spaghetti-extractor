"""Isolated drivers for exact candidate proof-closure layers.

These phases consume immutable plans and emit typed Lean adapters.  Keeping
them outside the broad GNU hello orchestration driver gives each proof layer a
small Python invalidation boundary.
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_kernel_abstract_operation_transition import (
    INTERPRETER_KERNEL_ABSTRACT_OPERATION_TRANSITION_LEAN_FILENAME,
    write_relational_interpreter_kernel_abstract_operation_transition_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_operation_result_encoding import (
    INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_LEAN_FILENAME,
    write_relational_interpreter_kernel_operation_result_encoding_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_step_program_lookup_exact_computation import (
    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_EXACT_COMPUTATION_LEAN_FILENAME,
    write_relational_interpreter_kernel_step_program_lookup_exact_computation_bundle,
)
from spaghetti_extractor.util import sha256_file, write_json


def _finish(
    *,
    out: Path,
    phase: str,
    candidate: Path,
    input_name: str,
    input_path: Path,
    lean_filename: str,
    plan_payload: dict[str, object],
) -> None:
    stage_a = out / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    generated = out / lean_filename
    shutil.move(generated, stage_a / lean_filename)
    target = Path(lean_filename).stem
    write_json(
        out / "phase-manifest.json",
        {
            "format": "stage-a-relational-phase-v1",
            "phase": phase,
            "status": "source-ready",
            "proof_authority": False,
            "failure_mode": "incomplete",
            "executes_original_binary": False,
            "executes_candidate_binary": False,
            "inputs": {
                "candidate": {
                    "path": candidate.name,
                    "sha256": sha256_file(candidate),
                },
                input_name: {
                    "path": input_path.name,
                    "sha256": sha256_file(input_path),
                },
            },
            "frontier": plan_payload["frontier"]
            if "frontier" in plan_payload
            else "exact_step_program_lookup_computation",
            "remaining_proof_premises": plan_payload[
                "remaining_proof_premises"
            ],
            "targets": [target],
            "public_outputs": {
                "lean_module": f"StageA/{lean_filename}",
            },
        },
    )


def _step_exact(args: argparse.Namespace) -> None:
    out = Path(args.out)
    candidate = Path(args.candidate)
    closure = Path(args.closure_plan)
    plan = (
        write_relational_interpreter_kernel_step_program_lookup_exact_computation_bundle(
            candidate_pe=candidate,
            closure_plan=closure,
            out=out,
        )
    )
    _finish(
        out=out,
        phase="compiled-kernel-step-program-lookup-exact-computation",
        candidate=candidate,
        input_name="closure_plan",
        input_path=closure,
        lean_filename=(
            INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_EXACT_COMPUTATION_LEAN_FILENAME
        ),
        plan_payload=plan.payload(),
    )


def _operation_result(args: argparse.Namespace) -> None:
    out = Path(args.out)
    candidate = Path(args.candidate)
    external_payload = Path(args.external_payload_plan)
    plan = write_relational_interpreter_kernel_operation_result_encoding_bundle(
        candidate_pe=candidate,
        external_payload_plan=external_payload,
        out=out,
    )
    _finish(
        out=out,
        phase="compiled-kernel-operation-result-encoding",
        candidate=candidate,
        input_name="external_payload_plan",
        input_path=external_payload,
        lean_filename=INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_LEAN_FILENAME,
        plan_payload=plan.payload(),
    )


def _abstract_transition(args: argparse.Namespace) -> None:
    out = Path(args.out)
    candidate = Path(args.candidate)
    operation_result = Path(args.operation_result_plan)
    plan = (
        write_relational_interpreter_kernel_abstract_operation_transition_bundle(
            candidate_pe=candidate,
            operation_result_encoding_plan=operation_result,
            out=out,
        )
    )
    _finish(
        out=out,
        phase="compiled-kernel-abstract-operation-transition",
        candidate=candidate,
        input_name="operation_result_plan",
        input_path=operation_result,
        lean_filename=(
            INTERPRETER_KERNEL_ABSTRACT_OPERATION_TRANSITION_LEAN_FILENAME
        ),
        plan_payload=plan.payload(),
    )


def _main() -> None:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(required=True)

    step = commands.add_parser("step-program-lookup-exact-computation")
    step.add_argument("--candidate", required=True)
    step.add_argument("--closure-plan", required=True)
    step.add_argument("--out", required=True)
    step.set_defaults(run=_step_exact)

    result = commands.add_parser("operation-result-encoding")
    result.add_argument("--candidate", required=True)
    result.add_argument("--external-payload-plan", required=True)
    result.add_argument("--out", required=True)
    result.set_defaults(run=_operation_result)

    abstract = commands.add_parser("abstract-operation-transition")
    abstract.add_argument("--candidate", required=True)
    abstract.add_argument("--operation-result-plan", required=True)
    abstract.add_argument("--out", required=True)
    abstract.set_defaults(run=_abstract_transition)

    args = parser.parse_args()
    args.run(args)


if __name__ == "__main__":
    _main()

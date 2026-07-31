from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_x87_replay_bridge_runtime import (
    X87_REPLAY_FIXED_TEMPLATE_CERTIFICATE_PREMISES,
    X87_REPLAY_FIXED_TEMPLATE_CHECKS_TYPE,
    X87_REPLAY_FIXED_TEMPLATE_EXECUTOR_PREMISES,
    X87_REPLAY_FIXED_TEMPLATE_PROGRAM_BINDING_PREMISES,
    X87_REPLAY_FIXED_TEMPLATE_REMAINING_PREMISES,
    X87_REPLAY_FIXED_TEMPLATE_SOURCE_FRAME_ASSUMPTIONS,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
DRIVER = REPO_ROOT / "nix/gnu-hello-roundtrip-driver.py"
LANE = REPO_ROOT / "nix/gnu-hello-roundtrip.nix"
FLAKE = REPO_ROOT / "flake.nix"

REMAINING_PREMISES = list(X87_REPLAY_FIXED_TEMPLATE_REMAINING_PREMISES)
KERNEL_PREMISES = REMAINING_PREMISES


def _runtime_plan(path: Path, *, acceptance_authority: bool = False) -> None:
    path.write_text(
        json.dumps(
            {
                "format": (
                    "stage-a-relational-x87-replay-bridge-runtime-plan-v1"
                ),
                "status": "complete",
                "diagnostic_status": "kernel_execution_closed",
                "acceptance_authority": acceptance_authority,
                "static_evidence": True,
                "conditional_theorem": (
                    "StageA.Relational.InterpreterKernelX87Execution."
                    "executeKernelReduction"
                ),
                "remaining_proof_premises": REMAINING_PREMISES,
                "assumed_source_frame_fields": list(
                    X87_REPLAY_FIXED_TEMPLATE_SOURCE_FRAME_ASSUMPTIONS
                ),
                "remaining_program_binding_fields": list(
                    X87_REPLAY_FIXED_TEMPLATE_PROGRAM_BINDING_PREMISES
                ),
                "remaining_fixed_template_fields": list(
                    X87_REPLAY_FIXED_TEMPLATE_CERTIFICATE_PREMISES
                ),
                "remaining_executor_fields": list(
                    X87_REPLAY_FIXED_TEMPLATE_EXECUTOR_PREMISES
                ),
                "checked_execution_type": X87_REPLAY_FIXED_TEMPLATE_CHECKS_TYPE,
                "checked_bundle_inhabited": True,
                "required_checked_target_terms": [
                    f"checkedTarget{index}" for index in range(7)
                ],
                "candidate": {
                    "path": "candidate.exe",
                    "sha256": "ab" * 32,
                    "size": 4096,
                },
                "inputs": {
                    "target_plan_sha256": "cd" * 32,
                    "native_engine_plan_sha256": "ef" * 32,
                },
                "counts": {
                    "runtime_targets": 7,
                    "relocated_operands": 2,
                    "unbound_relocated_operands": 0,
                },
                "targets": [],
            }
        ),
        encoding="utf-8",
    )


def test_driver_emits_typed_x87_kernel_frontier_without_authority(
    tmp_path: Path,
) -> None:
    runtime_plan = tmp_path / "runtime-plan.json"
    _runtime_plan(runtime_plan)
    out = tmp_path / "out"

    subprocess.run(
        [
            sys.executable,
            str(DRIVER),
            "x87-kernel-execution-sources",
            "--runtime-plan",
            str(runtime_plan),
            "--out",
            str(out),
        ],
        cwd=REPO_ROOT,
        check=True,
    )

    manifest = json.loads(
        (out / "phase-manifest.json").read_text(encoding="utf-8")
    )
    frontier = json.loads(
        (out / "x87-kernel-execution-frontier.json").read_text(
            encoding="utf-8"
        )
    )
    source = (
        out
        / "StageA/GeneratedRelationalInterpreterKernelX87Execution.lean"
    ).read_text(encoding="ascii")

    assert manifest["diagnostic_status"] == "kernel_execution_closed"
    assert manifest["proof_authority"] is False
    assert manifest["failure_mode"] == "none"
    assert manifest["runtime_targets"] == 7
    assert manifest["remaining_proof_premises"] == KERNEL_PREMISES
    assert frontier["remaining_proof_premises"] == KERNEL_PREMISES
    assert frontier["assumed_source_frame_fields"] == list(
        X87_REPLAY_FIXED_TEMPLATE_SOURCE_FRAME_ASSUMPTIONS
    )
    assert frontier["remaining_program_binding_fields"] == list(
        X87_REPLAY_FIXED_TEMPLATE_PROGRAM_BINDING_PREMISES
    )
    assert frontier["remaining_fixed_template_fields"] == list(
        X87_REPLAY_FIXED_TEMPLATE_CERTIFICATE_PREMISES
    )
    assert frontier["remaining_authority"][
        "structurally_derived_program_binding_fields"
    ] == [
        "peExact",
        "importsExact",
        "targetInventory",
    ]
    assert frontier["remaining_authority"][
        "structurally_derived_handler_fields"
    ] == [
        "handlerInventory",
    ]
    assert frontier["remaining_authority"]["authority_fields"] == []
    assert frontier["remaining_authority"][
        "fixed_template_certificate_proof_fields"
    ] == []
    assert (
        "import StageA.GeneratedRelationalInterpreterX87ReplayBridgeRuntime"
        in source
    )
    assert "import StageA.RelationalInterpreterKernelX87Execution" in source
    assert "GeneratedX87ReplayBridgeFixedTemplateChecksGoal" in source
    assert "generatedX87ReplayBridgeKernelExecutionClosed" in source
    assert ".kernelExecution" in source
    assert "generatedX87ReplayBridgeKernelProgramBinding" in source
    assert "generatedX87ReplayBridgeHandlerInventoryCorrespondence" in source
    assert "def generatedX87ReplayBridgeKernelEndpointAuthority" not in source
    assert '"status"' not in source


def test_driver_rejects_runtime_plan_that_claims_acceptance_authority(
    tmp_path: Path,
) -> None:
    runtime_plan = tmp_path / "runtime-plan.json"
    _runtime_plan(runtime_plan, acceptance_authority=True)
    process = subprocess.run(
        [
            sys.executable,
            str(DRIVER),
            "x87-kernel-execution-sources",
            "--runtime-plan",
            str(runtime_plan),
            "--out",
            str(tmp_path / "out"),
        ],
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert process.returncode != 0
    assert "claims authority" in process.stderr


def test_nix_lane_exposes_granular_remote_x87_execution_graph() -> None:
    lane = LANE.read_text(encoding="utf-8")
    flake = FLAKE.read_text(encoding="utf-8")

    assert "x87KernelExecutionLean = mkPhase" in lane
    assert "x87-kernel-execution-sources" in lane
    assert "--source ${x87ReplayBridgeRuntimeLean}" in lane
    assert "--source ${x87KernelExecutionLean}" in lane
    assert "x87KernelExecutionProofSources = mkPhase" in lane
    assert "x87KernelExecutionFragments = mkLeanGraph" in lane
    assert (
        'targetNodes = [ "GeneratedRelationalInterpreterKernelX87Execution" ];'
        in lane
    )
    assert "contentAddressed = true;" in lane
    assert (
        "stage-a-gnu-hello-roundtrip-x87-kernel-execution-source" in flake
    )
    assert "stage-a-gnu-hello-roundtrip-x87-kernel-execution =" in flake

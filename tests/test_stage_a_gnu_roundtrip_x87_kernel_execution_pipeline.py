from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DRIVER = REPO_ROOT / "nix/gnu-hello-roundtrip-driver.py"
LANE = REPO_ROOT / "nix/gnu-hello-roundtrip.nix"
FLAKE = REPO_ROOT / "flake.nix"

REMAINING_PREMISES = [
    "program_binding.peExact",
    "program_binding.importsExact",
    "program_binding.targetInventory",
    "endpoint_certificate.handlerResult",
    "endpoint_certificate.callTarget",
    "endpoint_certificate.callRun",
    "endpoint_certificate.entryRun",
    "endpoint_certificate.instructionRun",
    "endpoint_certificate.captureRun",
    "endpoint_certificate.returnRun",
    "endpoint_certificate.frameEffect",
]


def _runtime_plan(path: Path, *, acceptance_authority: bool = False) -> None:
    path.write_text(
        json.dumps(
            {
                "format": (
                    "stage-a-relational-x87-replay-bridge-runtime-plan-v1"
                ),
                "status": "evidence_ready",
                "acceptance_authority": acceptance_authority,
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

    assert manifest["diagnostic_status"] == "semantic_premises_required"
    assert manifest["proof_authority"] is False
    assert manifest["failure_mode"] == "incomplete"
    assert manifest["runtime_targets"] == 7
    assert manifest["remaining_proof_premises"] == REMAINING_PREMISES
    assert frontier["remaining_proof_premises"] == REMAINING_PREMISES
    assert frontier["remaining_authority"]["program_binding_fields"] == [
        "peExact",
        "importsExact",
        "targetInventory",
    ]
    assert frontier["remaining_authority"][
        "endpoint_certificate_proof_fields"
    ] == [
        "handlerResult",
        "callTarget",
        "entryFuelPositive",
        "instructionFuelPositive",
        "captureFuelPositive",
        "returnFuelPositive",
        "callRun",
        "entryRun",
        "instructionRun",
        "captureRun",
        "returnRun",
        "frameEffect",
    ]
    assert (
        "import StageA.GeneratedRelationalInterpreterX87ReplayBridgeRuntime"
        in source
    )
    assert "import StageA.RelationalInterpreterKernelX87Execution" in source
    assert "GeneratedX87ReplayBridgeKernelEndpointAuthorityGoal" in source
    assert "exact authority.kernelExecution" in source
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
    assert "contentAddressed = false;" in lane
    assert (
        "stage-a-gnu-hello-roundtrip-x87-kernel-execution-source" in flake
    )
    assert "stage-a-gnu-hello-roundtrip-x87-kernel-execution =" in flake

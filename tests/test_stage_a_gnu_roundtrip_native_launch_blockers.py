from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
DRIVER_PATH = REPO_ROOT / "nix" / "gnu-hello-roundtrip-driver.py"


def _load_driver():
    spec = importlib.util.spec_from_file_location(
        "stage_a_gnu_roundtrip_driver_native_launch_test", DRIVER_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _FakePE:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


def _fake_candidate(*, immutable: bool = True) -> SimpleNamespace:
    return SimpleNamespace(
        machine="i386",
        bitness=32,
        entrypoint_rva=0x1000,
        tls_callback_rvas=[0x1100, 0x1200],
        tls_callback_parse_error=None,
        tls_callback_array_immutable=immutable,
        pe=_FakePE(),
    )


def _write_original_carrier_manifest(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "phase": "mixed-original-carrier-binding-lean",
                "status": "source-ready",
                "proof_authority": False,
                "targets": [
                    "GeneratedRelationalInterpreterOriginalCarrierBinding"
                ],
                "exact_mixed_binding": (
                    "StageA.GeneratedRelational."
                    "InterpreterOriginalCarrierBinding."
                    "generatedOriginalExactMixedProgramBinding"
                ),
            }
        ),
        encoding="utf-8",
    )


def _write_x87_kernel_execution_manifest(path: Path, driver) -> None:
    path.write_text(
        json.dumps(
            {
                "format": "stage-a-relational-phase-v1",
                "phase": "x87-kernel-execution-lean",
                "status": "source-ready",
                "diagnostic_status": "kernel_execution_closed",
                "proof_authority": False,
                "failure_mode": "none",
                "candidate_sha256": "cd" * 32,
                "runtime_targets": 3,
                "theorem": (
                    "StageA.GeneratedRelational.InterpreterKernelX87Execution."
                    "generatedX87ReplayBridgeKernelExecutionClosed"
                ),
                "remaining_authority": {
                    "lean_type": (
                        "ExactNativeX87ReplayKernelEndpointAuthority "
                        "inventory program handler sourceInvariant"
                    )
                },
                "remaining_proof_premises": list(
                    driver.X87_KERNEL_EXECUTION_REMAINING_PROOF_PREMISES
                ),
                "targets": [driver.X87_KERNEL_EXECUTION_LEAN_MODULE],
            }
        ),
        encoding="utf-8",
    )


def test_native_launch_request_is_hash_bound_and_non_authoritative(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _load_driver()
    candidate = tmp_path / "candidate.exe"
    candidate.write_bytes(b"exact-candidate")
    parsed = _fake_candidate()
    monkeypatch.setattr(driver, "_parse_stage_a_pe", lambda _: parsed)

    out = tmp_path / "out"
    driver._native_launch_request(
        SimpleNamespace(candidate=str(candidate), out=str(out))
    )

    payload = json.loads(
        (out / "native-launch-route-request.json").read_text(encoding="utf-8")
    )
    assert payload["status"] == "incomplete"
    assert payload["acceptance_authority"] is False
    assert payload["candidate_sha256"] == driver.sha256_file(candidate)
    assert payload["canonical_sources"] == [
        {"index": None, "kind": "entry", "rva": 0x1000},
        {"index": 0, "kind": "tls_callback", "rva": 0x1100},
        {"index": 1, "kind": "tls_callback", "rva": 0x1200},
    ]
    assert "candidate root identity as launch_chunk" in payload["forbidden_authority"]
    assert parsed.pe.closed


def test_native_launch_request_rejects_writable_tls_callback_array(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _load_driver()
    candidate = tmp_path / "candidate.exe"
    candidate.write_bytes(b"mutated-candidate")
    parsed = _fake_candidate(immutable=False)
    monkeypatch.setattr(driver, "_parse_stage_a_pe", lambda _: parsed)

    with pytest.raises(ValueError, match="TLS callback array is writable"):
        driver._native_launch_request(
            SimpleNamespace(candidate=str(candidate), out=str(tmp_path / "out"))
        )
    assert parsed.pe.closed


def test_acceptance_source_binds_generated_launch_graph_without_closing_runtime_obligations(
    tmp_path: Path,
) -> None:
    driver = _load_driver()
    kernel_manifest = tmp_path / "kernel.json"
    kernel_manifest.write_text(json.dumps({"targets": []}), encoding="utf-8")
    mixed_manifest = tmp_path / "mixed.json"
    frontiers = [
        {"kind": "register_control", "source_rva": 0x2000},
        {"kind": "writable_static_pointer_slot", "source_rva": 0x3000},
    ]
    mixed_manifest.write_text(
        json.dumps(
            {
                "phase": "mixed-original-final-lean",
                "proof_authority": False,
                "counts": {"blockers": len(frontiers)},
                "authorizing_lean_terms": [],
                "remaining_frontiers": frontiers,
            }
        ),
        encoding="utf-8",
    )
    native_request = tmp_path / "native.json"
    native_request.write_text(
        json.dumps(
            {
                "format": "stage-a-native-launch-route-request-v1",
                "status": "incomplete",
                "acceptance_authority": False,
                "candidate_sha256": "ab" * 32,
                "canonical_sources": [{"kind": "entry", "index": None, "rva": 0x1000}],
                "required_path_shapes": [
                    "entry stub -> payload entry -> native run -> first operation"
                ],
                "forbidden_authority": ["candidate root identity as launch_chunk"],
            }
        ),
        encoding="utf-8",
    )

    out = tmp_path / "acceptance"
    original_carrier_manifest = tmp_path / "original-carrier.json"
    _write_original_carrier_manifest(original_carrier_manifest)
    x87_kernel_execution_manifest = tmp_path / "x87-kernel-execution.json"
    _write_x87_kernel_execution_manifest(
        x87_kernel_execution_manifest, driver
    )
    driver._acceptance_sources(
        SimpleNamespace(
            out=str(out),
            kernel_block_manifest=str(kernel_manifest),
            mixed_original_manifest=str(mixed_manifest),
            original_carrier_manifest=str(original_carrier_manifest),
            native_launch_request=str(native_request),
            x87_kernel_execution_manifest=str(
                x87_kernel_execution_manifest
            ),
        )
    )

    requirements = (
        out / "StageA" / "GeneratedGnuHelloRoundTripRequirements.lean"
    ).read_text(encoding="utf-8")
    assert "ExactGnuHelloCandidateNativeLaunchRouteBinding" not in requirements
    assert (
        "import StageA.GeneratedRelationalInterpreterNativeLaunchGraph"
        in requirements
    )
    assert (
        "ExactCanonicalMixedLaunchWrapperRefinementBinding" in requirements
    )
    assert (
        "NativeLaunchGraph.generatedCheckedNativeLaunchGraph" in requirements
    )
    assert "core.launch_wrapper_refinements" in requirements
    assert "environmentRefines" in requirements
    assert "candidateNativeLaunchCertificate" not in requirements
    assert (
        "kernelABIExact : HEq core.concrete_abi" in requirements
        and "KernelABI.generatedConcreteInterpreterKernelABI" in requirements
    )
    assert "core.abi =" not in requirements
    assert "candidateNativeLaunchRouteBinding" in requirements
    assert "launch_wrapper_refinements : forall" in requirements
    assert "environment_compositions : forall" in requirements
    assert "UniversalGnuHelloPairedEnvironmentRefinement" not in requirements
    assert "launch_chunk :=" not in requirements

    acceptance_source = (
        out / "StageA" / "GeneratedRelationalInterpreterMixedKernelBinding.lean"
    ).read_text(encoding="utf-8")
    assert "generatedUniversalMixedWorldAcceptanceCertificate" in acceptance_source
    assert (
        "intro originalEnvironment candidateEnvironment environmentRefines"
        in acceptance_source
    )

    obligations = json.loads(
        (out / "acceptance-obligations.json").read_text(encoding="utf-8")
    )
    assert obligations["closed_acceptance"] is False
    assert obligations["report_authority"] is False
    assert len(obligations["remaining_original_control_frontiers"]) == 2
    assert [row["id"] for row in obligations["blocking_obligations"]] == [
        "mixed_original_exact_reachability_missing",
        "exact_candidate_native_launch_wrapper_missing",
        "universal_paired_environment_refinement_missing",
    ]
    matrix = {row["layer"]: row for row in obligations["authority_integration_matrix"]}
    assert (
        matrix["reachable_static_pointer_slot"]["normalized_internal_writes_only"]
        is True
    )
    assert matrix["direct_call_register_provenance"]["named_lean_terms_consumed"] == []
    assert matrix["generated_kernel_abi"]["named_lean_terms_consumed"] == [
        "KernelABI.generatedInterpreterKernelABIRelation"
    ]
    assert matrix["x87_replay_kernel_execution"][
        "remaining_proof_premises"
    ] == list(driver.X87_KERNEL_EXECUTION_REMAINING_PROOF_PREMISES)


def test_acceptance_source_rejects_authoritative_native_launch_report(
    tmp_path: Path,
) -> None:
    driver = _load_driver()
    native_request = tmp_path / "native.json"
    native_request.write_text(
        json.dumps(
            {
                "format": "stage-a-native-launch-route-request-v1",
                "status": "incomplete",
                "acceptance_authority": True,
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="claims authority"):
        original_carrier_manifest = tmp_path / "original-carrier.json"
        _write_original_carrier_manifest(original_carrier_manifest)
        driver._acceptance_sources(
            SimpleNamespace(
                out=str(tmp_path / "out"),
                kernel_block_manifest=str(tmp_path / "unused-kernel.json"),
                mixed_original_manifest=str(tmp_path / "unused-mixed.json"),
                original_carrier_manifest=str(original_carrier_manifest),
                native_launch_request=str(native_request),
            )
        )

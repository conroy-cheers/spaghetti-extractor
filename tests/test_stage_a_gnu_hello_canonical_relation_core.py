from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


def _driver():
    path = Path(__file__).parents[1] / "nix/gnu-hello-canonical-relation-core.py"
    spec = importlib.util.spec_from_file_location("gnu_hello_relation_core", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_inputs(root: Path) -> tuple[Path, Path, Path]:
    mixed = root / "mixed.json"
    mixed.write_text(
        json.dumps(
            {
                "format": "stage-a-interpreter-mixed-original-v1",
                "acceptance_authority": False,
                "state_machine_sha256": "11" * 32,
            }
        ),
        encoding="utf-8",
    )
    from spaghetti_extractor.util import sha256_file

    reachability = root / "reachability.json"
    reachability.write_text(
        json.dumps(
            {
                "format": (
                    "stage-a-interpreter-mixed-original-static-reachability-v1"
                ),
                "acceptance_authority": False,
                "inputs": {
                    "state_machine_sha256": "11" * 32,
                    "mixed_original_plan": {"sha256": sha256_file(mixed)},
                },
            }
        ),
        encoding="utf-8",
    )
    data = root / "data.json"
    data.write_text(
        json.dumps(
            {
                "format": "stage-a-interpreter-kernel-data-inventory-v7",
                "acceptance_authority": False,
                "state_machine_sha256": "11" * 32,
                "candidate_sha256": "22" * 32,
            }
        ),
        encoding="utf-8",
    )
    return mixed, reachability, data


def test_gnu_binding_uses_exact_generated_artifacts(tmp_path: Path) -> None:
    driver = _driver()
    mixed, reachability, data = _write_inputs(tmp_path)
    out = tmp_path / "out"
    driver.generate(
        mixed_original_plan=mixed,
        static_reachability_plan=reachability,
        kernel_data_inventory=data,
        out=out,
    )
    binding = (
        out / "StageA/GeneratedGnuHelloCanonicalRelationCoreBindings.lean"
    ).read_text(encoding="ascii")
    core = (
        out / "StageA/GeneratedGnuHelloCanonicalRelationCore.lean"
    ).read_text(encoding="ascii")
    manifest = json.loads((out / "phase-manifest.json").read_text())
    assert "generatedOriginalExactMixedProgramBinding" in binding
    assert "generatedExactNativeCandidateAuthority" in binding
    assert "generatedConcreteInterpreterKernelABI" in binding
    assert "canonicalMixedLaunchAnchors?" in core
    assert "generatedCanonicalMixedRelationCore" in core
    assert manifest["acceptance_authority"] is False
    assert manifest["candidate_sha256"] == "22" * 32


def test_gnu_binding_rejects_cross_artifact_state_machine(tmp_path: Path) -> None:
    driver = _driver()
    mixed, reachability, data = _write_inputs(tmp_path)
    payload = json.loads(data.read_text())
    payload["state_machine_sha256"] = "33" * 32
    data.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(driver.GnuHelloCanonicalRelationCoreError):
        driver.generate(
            mixed_original_plan=mixed,
            static_reachability_plan=reachability,
            kernel_data_inventory=data,
            out=tmp_path / "out",
        )

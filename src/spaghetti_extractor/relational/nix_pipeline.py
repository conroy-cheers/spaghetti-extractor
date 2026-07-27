from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from ..stage_binary import StageAInputError
from ..util import sha256_file, write_json
from .build import (
    _check_remote_ca_build_trace_compatibility,
    _content_addressed_derivations_requested,
    _find_relational_flake_root,
    _remove_relational_build_output,
    _relational_nix_build_command,
    _trusted_builder_public_keys,
    _validate_prepared_relational,
    stage_a_build_relational,
)


_ANALYSIS_EVALUATOR = "stage-a-relational-analysis-graph.nix"


def _relational_analysis_nix_evaluator() -> Path:
    candidates = [
        Path(__file__).resolve().parents[3] / "nix" / _ANALYSIS_EVALUATOR,
        Path(__file__).with_name("nix") / _ANALYSIS_EVALUATOR,
        *(
            parent / "share" / "spaghetti-extractor" / "nix" / _ANALYSIS_EVALUATOR
            for parent in Path(__file__).resolve().parents
        ),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise StageAInputError(
        f"cannot locate nix/{_ANALYSIS_EVALUATOR}"
    )


def _nix_path(path: Path, name: str) -> list[str]:
    return [
        "builtins.path {",
        f"  path = builtins.toPath {json.dumps(str(path))};",
        f"  name = {json.dumps(name)};",
        "}",
    ]


def _relational_analysis_nix_expression(
    *,
    original: Path,
    candidate: Path,
    relation_contract: Path,
    evaluator: Path,
    flake_root: Path,
) -> str:
    identity = (
        sha256_file(original)[:12]
        + "-"
        + sha256_file(candidate)[:12]
        + "-"
        + sha256_file(relation_contract)[:12]
    )
    original_path = "\n      ".join(
        _nix_path(original, "stage-a-original.pe")
    )
    candidate_path = "\n      ".join(
        _nix_path(candidate, "stage-a-candidate.pe")
    )
    contract_path = "\n    ".join(
        _nix_path(relation_contract, "stage-a-relation-contract.json")
    )
    flake_ref = f"git+file://{flake_root}"
    return "\n".join([
        "let",
        f"  flake = builtins.getFlake {json.dumps(flake_ref)};",
        "  system = builtins.currentSystem;",
        "  pkgs = import flake.inputs.nixpkgs { inherit system; config = {}; };",
        "  packages = flake.packages.${system};",
        f"  graph = import (builtins.toPath {json.dumps(str(evaluator))}) {{",
        "    inherit pkgs;",
        f"    name = {json.dumps('stage-a-dynamic-' + identity)};",
        "    original = {",
        f"      binary = {original_path};",
        "    };",
        "    candidate = {",
        f"      binary = {candidate_path};",
        "    };",
        f"    relationContract = {contract_path};",
        "    analysisKernelCache =",
        '      packages."stage-a-relational-analysis-kernel-cache";',
        "    tools = {",
        '      side = packages."spaghetti-extractor-side";',
        '      normalize = packages."spaghetti-extractor-normalize";',
        '      regionFacts = packages."spaghetti-extractor-region-facts";',
        '      proposal = packages."spaghetti-extractor-proposal";',
        '      semanticProducts = packages."spaghetti-extractor-semantic-products";',
        "      registerDataflowProblem =",
        '        packages."spaghetti-extractor-register-dataflow-problem";',
        '      dataflowPlan = packages."spaghetti-extractor-dataflow-plan";',
        '      dataflowWorker = packages."spaghetti-extractor-dataflow-worker";',
        '      dataflowAggregate = packages."spaghetti-extractor-dataflow-aggregate";',
        '      dataflowSummary = packages."spaghetti-extractor-dataflow-summary";',
        '      dataflowCompare = packages."spaghetti-extractor-dataflow-compare";',
        '      registerReplay = packages."spaghetti-extractor-register-replay";',
        '      memoryProducts = packages."spaghetti-extractor-memory-products";',
        '      compositionProducts = packages."spaghetti-extractor-composition-products";',
        '      analysis = packages."spaghetti-extractor-analysis";',
        '      preparation = packages."spaghetti-extractor-preparation";',
        "    };",
        "  };",
        "in graph.preparedProof",
    ])


def _realize_relational_preparation(
    *,
    original: Path,
    candidate: Path,
    relation_contract: Path,
    flake: Path | None,
    builders_file: Path | None,
    builder_trusted_public_keys_file: Path | None,
) -> tuple[Path, dict[str, Any]]:
    original = Path(original).resolve()
    candidate = Path(candidate).resolve()
    relation_contract = Path(relation_contract).resolve()
    for path, description in (
        (original, "original binary"),
        (candidate, "candidate binary"),
        (relation_contract, "relation contract"),
    ):
        if not path.is_file():
            raise StageAInputError(f"{description} does not exist: {path}")

    evaluator = _relational_analysis_nix_evaluator()
    flake_root = _find_relational_flake_root(flake)
    builders_path = (
        Path(builders_file).resolve() if builders_file is not None else None
    )
    if builders_path is not None and not builders_path.is_file():
        raise StageAInputError(
            f"Nix builders file does not exist: {builders_path}"
        )
    trusted_keys_path = (
        Path(builder_trusted_public_keys_file).resolve()
        if builder_trusted_public_keys_file is not None
        else None
    )
    _trusted_builder_public_keys(trusted_keys_path)
    if _content_addressed_derivations_requested():
        _check_remote_ca_build_trace_compatibility(builders_path)

    expression = _relational_analysis_nix_expression(
        original=original,
        candidate=candidate,
        relation_contract=relation_contract,
        evaluator=evaluator,
        flake_root=flake_root,
    )
    command = _relational_nix_build_command(
        expression, builders_path, trusted_keys_path
    )
    started = time.monotonic()
    environment = os.environ.copy()
    environment.pop("NIXPKGS_CONFIG", None)
    process = subprocess.run(
        command,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    elapsed = round(time.monotonic() - started, 3)
    if process.returncode != 0:
        raise StageAInputError(
            "Nix relational preparation failed:\n"
            + process.stderr[:4000]
            + ("\n...\n" if len(process.stderr) > 12000 else "")
            + process.stderr[-8000:]
        )
    try:
        outputs = json.loads(process.stdout)
        if not isinstance(outputs, list) or len(outputs) != 1:
            raise ValueError("expected exactly one Nix output")
        result_path = Path(outputs[0]["outputs"]["out"]).resolve(strict=True)
    except (
        IndexError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        raise StageAInputError(
            "Nix returned malformed relational preparation provenance"
        ) from exc
    prepared = result_path / "report" / "relational-v3"
    if not (prepared / "prepared-proof.json").is_file():
        raise StageAInputError(
            f"Nix relational preparation omitted {prepared / 'prepared-proof.json'}"
        )
    _validate_prepared_relational(prepared)
    provenance = {
        "format": "stage-a-relational-nix-preparation-v1",
        "status": "prepared",
        "flake": str(flake_root),
        "flake_lock_sha256": sha256_file(flake_root / "flake.lock"),
        "evaluator_sha256": sha256_file(evaluator),
        "result_path": str(result_path),
        "prepared_path": str(prepared),
        "drv_path": outputs[0].get("drvPath"),
        "elapsed_seconds": elapsed,
        "original_sha256": sha256_file(original),
        "candidate_sha256": sha256_file(candidate),
        "relation_contract_sha256": sha256_file(relation_contract),
    }
    return prepared, provenance


def stage_a_prepare_relational_nix(
    *,
    original: Path,
    candidate: Path,
    relation_contract: Path,
    out: Path,
    flake: Path | None = None,
    builders_file: Path | None = None,
    builder_trusted_public_keys_file: Path | None = None,
) -> dict[str, Any]:
    prepared, provenance = _realize_relational_preparation(
        original=original,
        candidate=candidate,
        relation_contract=relation_contract,
        flake=flake,
        builders_file=builders_file,
        builder_trusted_public_keys_file=builder_trusted_public_keys_file,
    )
    out = Path(out).resolve()
    _remove_relational_build_output(out)
    shutil.copytree(prepared, out, symlinks=True)
    out.chmod(out.stat().st_mode | 0o700)
    write_json(out / "nix-preparation-provenance.json", provenance)
    manifest = json.loads(
        (out / "prepared-proof.json").read_text(encoding="utf-8")
    )
    return {
        "format": "stage-a-relational-nix-preparation-result-v1",
        "status": "prepared",
        "prepared_format": manifest.get("format"),
        "acceptance_status": manifest.get("acceptance", {}).get("status"),
        "expected_final_theorem": manifest.get("expected_final_theorem"),
        "counts": manifest.get("counts", {}),
        "nix_preparation": provenance,
        "out": str(out),
    }


def stage_a_prove_relational_nix(
    *,
    original: Path,
    candidate: Path,
    relation_contract: Path,
    out: Path,
    flake: Path | None = None,
    builders_file: Path | None = None,
    builder_trusted_public_keys_file: Path | None = None,
) -> dict[str, Any]:
    prepared, preparation = _realize_relational_preparation(
        original=original,
        candidate=candidate,
        relation_contract=relation_contract,
        flake=flake,
        builders_file=builders_file,
        builder_trusted_public_keys_file=builder_trusted_public_keys_file,
    )
    result = stage_a_build_relational(
        prepared=prepared,
        out=out,
        flake=flake,
        builders_file=builders_file,
        builder_trusted_public_keys_file=builder_trusted_public_keys_file,
    )
    out = Path(out)
    write_json(out / "nix-preparation-provenance.json", preparation)
    result["nix_preparation_provenance_sha256"] = sha256_file(
        out / "nix-preparation-provenance.json"
    )
    write_json(out / "verdict.json", result)
    return result


__all__ = [
    "stage_a_prepare_relational_nix",
    "stage_a_prove_relational_nix",
]

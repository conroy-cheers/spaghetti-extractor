from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from ..build_support.nix_support import find_flake_root, nix_build_expression
from ..build_support.nix_invocation import select_builder_policy
from ..errors import ToolkitInputError
from ..util import sha256_file


_ISA_CONFORMANCE_EVALUATOR = "isa-conformance.nix"


def _isa_conformance_nix_evaluator() -> Path:
    candidates = [
        Path(__file__).resolve().parents[3]
        / "nix"
        / _ISA_CONFORMANCE_EVALUATOR,
        *(
            parent
            / "share"
            / "spaghetti-extractor"
            / "nix"
            / _ISA_CONFORMANCE_EVALUATOR
            for parent in Path(__file__).resolve().parents
        ),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise ToolkitInputError(
        f"cannot locate nix/{_ISA_CONFORMANCE_EVALUATOR}"
    )


def _nix_input(path: Path, name: str) -> str:
    return (
        "builtins.path { "
        f"path = builtins.toPath {json.dumps(str(path))}; "
        f"name = {json.dumps(name)}; "
        "}"
    )


def _isa_conformance_nix_expression(
    *,
    corpus: Path,
    backend: str,
    bochs_runner: Path | None,
    with_forms: bool,
    evaluator: Path,
    flake_root: Path,
    content_addressed: bool,
) -> str:
    identity = sha256_file(corpus)[:20]
    bochs = (
        "null"
        if bochs_runner is None
        else _nix_input(bochs_runner, "spaghetti-extractor-bochs-runner")
    )
    return "\n".join(
        [
            "let",
            f"  flake = builtins.getFlake {json.dumps(f'path:{flake_root}')};",
            "  system = builtins.currentSystem;",
            "  pkgs = import flake.inputs.nixpkgs { inherit system; config = {}; };",
            "  packages = flake.packages.${system};",
            f"  evaluator = builtins.toPath {json.dumps(str(evaluator))};",
            "in import evaluator {",
            "  inherit pkgs;",
            f"  name = {json.dumps(f'spaghetti-extractor-isa-{backend}-{identity}')};",
            '  spaghettiExtractor = packages."spaghetti-extractor";',
            (
                '  kernelCache = packages."isa-kernel";'
                if backend == "lean"
                else "  kernelCache = null;"
            ),
            f"  corpus = {_nix_input(corpus, 'spaghetti-extractor-isa-corpus.json')};",
            f"  backend = {json.dumps(backend)};",
            f"  bochsRunner = {bochs};",
            f"  withForms = {'true' if with_forms else 'false'};",
            (
                "  contentAddressed = "
                + ("true;" if content_addressed else "false;")
            ),
            "}",
        ]
    )


def spx_check_isa_conformance_nix(
    *,
    corpus: Path,
    backend: str,
    out: Path,
    forms_out: Path | None = None,
    bochs_runner: Path | None = None,
    flake: Path | None = None,
    builders_file: Path | None = None,
    builder_trusted_public_keys_file: Path | None = None,
) -> dict[str, Any]:
    if backend not in {"lean", "unicorn", "bochs"}:
        raise ToolkitInputError(
            f"unsupported ISA conformance backend {backend!r}"
        )
    if forms_out is not None and backend != "lean":
        raise ToolkitInputError(
            "--forms-out is valid only with --backend=lean"
        )
    if backend == "bochs" and bochs_runner is None:
        raise ToolkitInputError(
            "--bochs-runner is required when --backend=bochs"
        )

    corpus = Path(corpus).resolve()
    if not corpus.is_file():
        raise ToolkitInputError(f"ISA conformance corpus does not exist: {corpus}")
    runner = Path(bochs_runner).resolve() if bochs_runner is not None else None
    if runner is not None and not runner.is_file():
        raise ToolkitInputError(f"Bochs runner does not exist: {runner}")

    evaluator = _isa_conformance_nix_evaluator()
    flake_root = find_flake_root(flake)
    builder_policy = select_builder_policy(
        target_flake=str(flake_root),
        builders_file=builders_file,
        trusted_public_keys_file=builder_trusted_public_keys_file,
        cwd=flake_root,
    )
    content_addressed = True

    expression = _isa_conformance_nix_expression(
        corpus=corpus,
        backend=backend,
        bochs_runner=runner,
        with_forms=forms_out is not None,
        evaluator=evaluator,
        flake_root=flake_root,
        content_addressed=content_addressed,
    )
    command = nix_build_expression(
        expression,
        builder_policy=builder_policy,
    )
    environment = os.environ.copy()
    environment.pop("NIXPKGS_CONFIG", None)
    started = time.monotonic()
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
        raise ToolkitInputError(
            "Nix ISA conformance build failed:\n"
            + process.stderr[:4000]
            + ("\n...\n" if len(process.stderr) > 12000 else "")
            + process.stderr[-8000:]
        )
    try:
        outputs = json.loads(process.stdout)
        if not isinstance(outputs, list) or len(outputs) != 1:
            raise ValueError("expected exactly one Nix output")
        store_output = Path(outputs[0]["outputs"]["out"]).resolve(strict=True)
        result = json.loads(
            (store_output / "result.json").read_text(encoding="utf-8")
        )
    except (
        IndexError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        raise ToolkitInputError(
            "Nix returned malformed ISA conformance provenance"
        ) from exc

    out = Path(out).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(store_output / "report.json", out)
    result["out"] = str(out)
    if forms_out is not None:
        forms_out = Path(forms_out).resolve()
        forms_out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(store_output / "forms.json", forms_out)
        result["forms_out"] = str(forms_out)
        result["forms_sha256"] = sha256_file(forms_out)
    result["nix"] = {
        "format": "spaghetti-extractor-isa-conformance-nix-provenance-v1",
        "drv_path": outputs[0].get("drvPath"),
        "result_path": str(store_output),
        "evaluator_sha256": sha256_file(evaluator),
        "flake_lock_sha256": sha256_file(flake_root / "flake.lock"),
        "content_addressed": content_addressed,
        "elapsed_seconds": elapsed,
    }
    return result


__all__ = ["spx_check_isa_conformance_nix"]

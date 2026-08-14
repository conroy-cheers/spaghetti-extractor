"""Candidate authority receipt commands."""

from __future__ import annotations

import argparse

from ..candidate.authority import (
    build_candidate_authority,
    validate_candidate_authority,
)
from .common import Handler, path_argument


def _add_inputs(command: argparse.ArgumentParser) -> None:
    path_argument(command, "final_authority", required=True)
    path_argument(command, "machine_ir", required=True)
    path_argument(command, "machine_ir_manifest", required=True)
    path_argument(command, "fallback_coverage_receipt", required=True)
    path_argument(command, "component_runtime_package", required=True)


def _build(args: argparse.Namespace) -> dict[str, object]:
    receipt = build_candidate_authority(
        final_authority=args.final_authority,
        machine_ir=args.machine_ir,
        machine_ir_manifest=args.machine_ir_manifest,
        fallback_coverage_receipt=args.fallback_coverage_receipt,
        component_runtime_package=args.component_runtime_package,
    )
    args.out.write_bytes(receipt.to_bytes())
    return receipt.to_payload()


def _validate(args: argparse.Namespace) -> dict[str, object]:
    receipt = validate_candidate_authority(
        receipt=args.receipt,
        final_authority=args.final_authority,
        machine_ir=args.machine_ir,
        machine_ir_manifest=args.machine_ir_manifest,
        fallback_coverage_receipt=args.fallback_coverage_receipt,
        component_runtime_package=args.component_runtime_package,
        require_authorized=False,
    )
    if args.out is not None:
        args.out.write_bytes(receipt.to_bytes())
    return receipt.to_payload()


def configure_command(name: str, command: argparse.ArgumentParser) -> Handler:
    if name == "stage-b-build-candidate-authority":
        _add_inputs(command)
        path_argument(command, "out", required=True)
        return _build

    if name == "stage-b-validate-candidate-authority":
        path_argument(command, "receipt", required=True)
        _add_inputs(command)
        path_argument(command, "out")
        return _validate

    raise ValueError(f"unsupported authority command: {name}")


__all__ = ["configure_command"]

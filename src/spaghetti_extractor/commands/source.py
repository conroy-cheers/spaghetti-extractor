"""Portable-source binding and rendering commands."""

from __future__ import annotations

import argparse
import json

from ..external_operation_profiles import load_external_operation_profile
from ..source_operation_catalog import render_source_operations
from ..errors import StageAInputError
from .common import Handler, path_argument


def _render_source_operations(args: argparse.Namespace) -> dict[str, object]:
    profile = load_external_operation_profile(args.operation_profile)
    operations_payload = json.loads(args.operations.read_text(encoding="utf-8"))
    operations = (
        operations_payload.get("operations")
        if isinstance(operations_payload, dict)
        else None
    )
    if not isinstance(operations, list):
        raise StageAInputError("operation evidence must contain an operations array")
    result = render_source_operations(
        catalog=args.catalog,
        operation_profile_sha256=profile.sha256,
        operations=operations,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result


def configure_command(name: str, command: argparse.ArgumentParser) -> Handler:
    if name == "stage-b-render-source-operations":
        path_argument(command, "catalog", required=True)
        path_argument(command, "operation_profile", required=True)
        path_argument(command, "operations", required=True)
        path_argument(command, "out", required=True)
        return _render_source_operations

    raise ValueError(f"unsupported source command: {name}")


__all__ = ["configure_command"]

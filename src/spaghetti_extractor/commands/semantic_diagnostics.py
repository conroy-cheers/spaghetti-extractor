"""Non-authorizing views over one canonical linked semantic module."""

from __future__ import annotations

import argparse

from ..semantic_link.diagnostics import (
    semantic_cause_projection_v2,
    semantic_delta_projection_v2,
    semantic_invalidation_projection_v2,
    semantic_slice_projection_v2,
    semantic_status_projection_v2,
)
from .common import Handler, path_argument


def _rva(value: str) -> int:
    try:
        result = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("RVA must be an integer") from exc
    if result < 0:
        raise argparse.ArgumentTypeError("RVA must be nonnegative")
    return result


def _run(args: argparse.Namespace) -> dict:
    if args.view == "causes":
        if args.linked_semantic_module is None:
            raise ValueError("causes requires --linked-semantic-module")
        return semantic_cause_projection_v2(args.linked_semantic_module)
    if args.view == "status":
        if args.linked_semantic_module is None:
            raise ValueError("status requires --linked-semantic-module")
        return semantic_status_projection_v2(args.linked_semantic_module)
    if args.view == "slice":
        if args.linked_semantic_module is None or args.source_rva is None:
            raise ValueError(
                "slice requires --linked-semantic-module and --source-rva"
            )
        return semantic_slice_projection_v2(
            args.linked_semantic_module, source_rva=args.source_rva
        )
    if args.view == "invalidations":
        if args.linked_semantic_module is None:
            raise ValueError("invalidations requires --linked-semantic-module")
        return semantic_invalidation_projection_v2(
            args.linked_semantic_module
        )
    if args.before is None or args.after is None:
        raise ValueError("delta requires --before and --after")
    return semantic_delta_projection_v2(args.before, args.after)


def configure_command(name: str, command: argparse.ArgumentParser) -> Handler:
    if name != "semantic-diagnose":
        raise ValueError(f"unsupported semantic diagnostic command: {name}")
    command.add_argument(
        "--view",
        choices=("status", "causes", "slice", "invalidations", "delta"),
        required=True,
    )
    path_argument(command, "linked_semantic_module")
    path_argument(command, "before")
    path_argument(command, "after")
    command.add_argument("--source-rva", type=_rva)
    return _run


__all__ = ["configure_command"]

"""Non-authorizing views over retained semantic and machine-IR inputs."""

from __future__ import annotations

import argparse
import hashlib
import json

from ..machine_ir.entry_dependencies import analyze_entry_state_dependencies
from ..machine_ir.call_sites import direct_caller_sites
from ..semantic_link.diagnostics import (
    semantic_cause_projection_v2,
    semantic_delta_projection_v2,
    semantic_invalidation_projection_v2,
    semantic_slice_projection_v2,
    semantic_status_projection_v2,
)
from ..transfer.plan import adapt_exact_machine_ir_rows
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
    if args.view in {"entry-dependencies", "callers"}:
        if args.machine_ir is None or not args.entry_unit:
            raise ValueError(f"{args.view} requires --machine-ir and --entry-unit")
        if args.view == "entry-dependencies" and not args.register and not args.flag:
            raise ValueError("entry-dependencies requires --register or --flag")
        if args.view == "callers" and (args.register or args.flag):
            raise ValueError("callers returns call input expressions; --register and --flag belong to entry-dependencies")
        raw = args.machine_ir.read_bytes()
        rows = []
        row_lines = {}
        for number, line in enumerate(raw.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError(f"machine IR line {number} is not valid JSON") from exc
            if not isinstance(row, dict):
                raise ValueError(f"machine IR line {number} must be an object")
            rows.append(row)
            if isinstance(row.get("id"), str):
                row_lines[row["id"]] = number
        transfers = adapt_exact_machine_ir_rows(rows)
        if args.view == "callers":
            result = direct_caller_sites(transfers, entry_unit_ids=args.entry_unit,
                                        max_sites=args.max_sites)
            for site in result["sites"]:
                site["machine_ir_location"] = {
                    "file": str(args.machine_ir.resolve()),
                    "line": row_lines[site["caller_unit_id"]],
                    "json_pointer": "/semantics" + site["json_pointer"],
                }
        else:
            result = analyze_entry_state_dependencies(
                transfers, entry_unit_ids=args.entry_unit,
                locations=[{"family": family, "name": name}
                           for family, names in (("register", args.register), ("flag", args.flag))
                           for name in names], max_states=args.max_states,
            )
        return {**result, "machine_ir_sha256": hashlib.sha256(raw).hexdigest(),
                "status": "complete" if result["analysis_complete"] else "incomplete"}
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
        choices=("status", "causes", "slice", "invalidations", "delta", "entry-dependencies", "callers"),
        required=True,
    )
    path_argument(command, "linked_semantic_module")
    path_argument(command, "before")
    path_argument(command, "after")
    path_argument(command, "machine_ir")
    command.add_argument("--entry-unit", action="append", default=[])
    command.add_argument("--register", action="append", default=[])
    command.add_argument("--flag", action="append", default=[])
    command.add_argument("--max-states", type=int, default=256)
    command.add_argument("--max-sites", type=int, default=64,
                         help="maximum direct caller sites returned (callers; 1..4096)")
    command.add_argument("--source-rva", type=_rva)
    return _run


__all__ = ["configure_command"]

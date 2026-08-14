"""Public command dispatcher for the active reconstruction workflow."""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from collections.abc import Sequence

from .commands.common import Handler
from .commands.manifest import COMMANDS_BY_NAME, SUPPORTED_COMMANDS, CommandSpec


def _configure_command(
    spec: CommandSpec, parser: argparse.ArgumentParser
) -> Handler:
    module = importlib.import_module(spec.group)
    configure = getattr(module, "configure_command", None)
    if not callable(configure):
        raise RuntimeError(f"command group {spec.group!r} has no configure_command")
    handler = configure(spec.name, parser)
    if not callable(handler):
        raise RuntimeError(
            f"command group {spec.group!r} did not configure {spec.name!r}"
        )
    return handler


def _build_parser(
    *, selected_command: str | None = None, prog: str | None = None
) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=prog or "spaghetti-extractor")
    commands = parser.add_subparsers(dest="command", required=True)
    for spec in SUPPORTED_COMMANDS:
        command = commands.add_parser(spec.name, help=spec.help)
        if spec.name == selected_command:
            command.set_defaults(handler=_configure_command(spec, command))
    return parser


def _selected_command(argv: Sequence[str]) -> str | None:
    if not argv:
        return None
    candidate = argv[0]
    return candidate if candidate in COMMANDS_BY_NAME else None


def _exit_status(result: dict[str, object]) -> int:
    status = result.get("status", result.get("verdict"))
    return 0 if status in {
        None,
        "checked",
        "complete",
        "authorized",
        "generated",
        "pass",
        "qualified",
        "ready",
        "satisfied",
        "usable-incomplete",
    } else 1


def main(argv: list[str] | None = None, *, prog: str | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    parser = _build_parser(
        selected_command=_selected_command(arguments),
        prog=prog,
    )
    args = parser.parse_args(arguments)
    try:
        result = args.handler(args)
    except (OSError, ValueError) as exc:
        print(f"{parser.prog}: {exc}", file=sys.stderr)
        return 2
    if isinstance(result, int):
        return result
    if isinstance(result, dict):
        print(json.dumps(result, indent=2, sort_keys=True))
        return _exit_status(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

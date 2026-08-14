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
    handler = configure(spec.implementation_name, parser)
    if not callable(handler):
        raise RuntimeError(
            f"command group {spec.group!r} did not configure {spec.name!r}"
        )
    return handler


_NAMESPACE_HELP = {
    "project": "analyze and validate a registered target project",
    "component": "inspect and build independent component work units",
    "candidate": "build and test an authorized candidate",
    "expert": "invoke an individual pipeline leaf command",
}


def _build_parser(
    *, selected_command: str | None = None, prog: str | None = None
) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=prog or "spaghetti-extractor")
    namespaces = parser.add_subparsers(dest="namespace", required=True)
    namespace_parsers: dict[str, argparse._SubParsersAction[argparse.ArgumentParser]] = {}
    for spec in SUPPORTED_COMMANDS:
        namespace, name = spec.path
        commands = namespace_parsers.get(namespace)
        if commands is None:
            namespace_parser = namespaces.add_parser(
                namespace,
                help=_NAMESPACE_HELP[namespace],
            )
            commands = namespace_parser.add_subparsers(
                dest=f"{namespace}_command",
                required=True,
            )
            namespace_parsers[namespace] = commands
        command = commands.add_parser(name, help=spec.help)
        if spec.name == selected_command:
            command.set_defaults(handler=_configure_command(spec, command))
    return parser


def _selected_command(argv: Sequence[str]) -> str | None:
    if len(argv) < 2:
        return None
    candidate = " ".join(argv[:2])
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

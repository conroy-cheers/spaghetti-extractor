"""Operator workflows backed by target-SDK Nix artifacts."""

from __future__ import annotations

import argparse
import re
import subprocess
from collections.abc import Callable, Sequence

from .common import Handler


_TARGET_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_NIX_FEATURES = "nix-command flakes ca-derivations"


def _target_id(value: str) -> str:
    if _TARGET_ID.fullmatch(value) is None:
        raise argparse.ArgumentTypeError(
            "target must contain only letters, digits, '.', '_', or '-'"
        )
    return value


def _add_target_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("target", type=_target_id, help="registered target id")
    parser.add_argument(
        "--target-flake",
        default="./targets",
        metavar="REF",
        help="target corpus flake reference (default: ./targets)",
    )


def _nix_command(*arguments: str) -> list[str]:
    return [
        "nix",
        "--extra-experimental-features",
        _NIX_FEATURES,
        *arguments,
    ]


def _flake_installable(args: argparse.Namespace, attribute: str) -> str:
    target_flake = str(args.target_flake)
    if "#" in target_flake:
        raise ValueError("--target-flake must not include an output attribute")
    return f"{target_flake}#{attribute}"


def _run(command: Sequence[str]) -> int:
    return subprocess.run(list(command), check=False).returncode


def _build(attribute_prefix: str) -> Handler:
    def handler(args: argparse.Namespace) -> int:
        installable = _flake_installable(
            args,
            f"{attribute_prefix}-{args.target}",
        )
        return _run(_nix_command("build", installable))

    return handler


def _build_legacy(collection: str) -> Handler:
    def handler(args: argparse.Namespace) -> int:
        installable = _flake_installable(
            args,
            f"legacyPackages.x86_64-linux.{collection}.{args.target}",
        )
        return _run(_nix_command("build", installable))

    return handler


def _project_status(args: argparse.Namespace) -> int:
    installable = _flake_installable(
        args,
        f"lib.targetMetadata.{args.target}",
    )
    return _run(_nix_command("eval", "--json", installable))


def _project_check(args: argparse.Namespace) -> int:
    command = _nix_command(
        "run",
        _flake_installable(args, "test"),
        "--",
    )
    if args.acceptance:
        command.append("--acceptance")
    command.append(args.target)
    return _run(command)


_BUILD_HANDLERS: dict[str, Callable[[], Handler]] = {
    "project analyze": lambda: _build("project-analyze"),
    "component build": lambda: _build("component-build"),
    "candidate build": lambda: _build_legacy("candidateBuilds"),
    "candidate test": lambda: _build_legacy("candidateTests"),
}


def configure_command(name: str, parser: argparse.ArgumentParser) -> Handler:
    _add_target_arguments(parser)
    if name == "project status":
        return _project_status
    if name == "project check":
        parser.add_argument(
            "--acceptance",
            action="store_true",
            help="run the strict acceptance gate after regression checks",
        )
        return _project_check
    handler_factory = _BUILD_HANDLERS.get(name)
    if handler_factory is None:
        raise ValueError(f"unsupported operator workflow: {name}")
    return handler_factory()


__all__ = ["configure_command"]

"""Shared argument helpers for public command groups."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Callable


Handler = Callable[[argparse.Namespace], Any]


def path_argument(
    command: argparse.ArgumentParser, name: str, **kwargs: Any
) -> None:
    command.add_argument(
        f"--{name.replace('_', '-')}", dest=name, type=Path, **kwargs
    )


def many_path_arguments(command: argparse.ArgumentParser, name: str) -> None:
    command.add_argument(
        f"--{name.replace('_', '-')}",
        dest=name,
        type=Path,
        action="append",
        default=[],
    )


def keyed_paths(values: list[str]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        identity, separator, path = value.partition("=")
        if not separator or not identity or not path:
            raise ValueError("component artifact arguments must use <id>=<path>")
        if identity in result:
            raise ValueError(f"duplicate component artifact argument: {identity}")
        result[identity] = Path(path)
    return result


__all__ = ["Handler", "keyed_paths", "many_path_arguments", "path_argument"]

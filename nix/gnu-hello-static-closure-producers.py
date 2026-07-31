#!/usr/bin/env python3
"""Emit the artifact-free GNU hello closure modules."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Callable


def runtime_foundation(out: Path) -> None:
    from spaghetti_extractor.relational.lean.gnu_hello_runtime_foundation import (
        write_gnu_hello_runtime_foundation,
    )

    write_gnu_hello_runtime_foundation(out)


def launch_binding(out: Path) -> None:
    from spaghetti_extractor.relational.lean.gnu_hello_launch_binding import (
        write_gnu_hello_launch_binding,
    )

    write_gnu_hello_launch_binding(out)


def external_component(out: Path) -> None:
    from spaghetti_extractor.relational.lean.gnu_hello_external_component import (
        write_gnu_hello_external_component,
    )

    write_gnu_hello_external_component(out)


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    commands: tuple[tuple[str, Callable[[Path], None]], ...] = (
        ("runtime-foundation", runtime_foundation),
        ("launch-binding", launch_binding),
        ("external-component", external_component),
    )
    for name, producer in commands:
        command = subparsers.add_parser(name)
        command.add_argument("--out", type=Path, required=True)
        command.set_defaults(producer=producer)
    arguments = parser.parse_args()
    arguments.producer(arguments.out)


if __name__ == "__main__":
    main()

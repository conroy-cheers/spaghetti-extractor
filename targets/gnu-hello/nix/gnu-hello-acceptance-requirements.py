#!/usr/bin/env python3
"""Emit the cacheable concrete/static GNU hello acceptance requirements."""

from __future__ import annotations

import argparse
from pathlib import Path

from spaghetti_extractor_target_gnu_hello.gnu_hello_acceptance_requirements import (
    write_gnu_hello_acceptance_requirements,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    write_gnu_hello_acceptance_requirements(args.out)


if __name__ == "__main__":
    main()

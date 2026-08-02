#!/usr/bin/env python3
"""Project checked callable evidence into a candidate-only runtime contract."""

from __future__ import annotations

import argparse
from pathlib import Path

from spaghetti_extractor.callable_external_runtime import (
    write_callable_external_runtime_contract,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--proposal", required=True, type=Path)
    parser.add_argument("--capability", required=True, type=Path)
    parser.add_argument("--execution", required=True, type=Path)
    parser.add_argument("--writable-slot-authority", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    write_callable_external_runtime_contract(
        proposal=args.proposal,
        capability=args.capability,
        execution=args.execution,
        writable_slot_authority=args.writable_slot_authority,
        out=args.out,
    )


if __name__ == "__main__":
    main()

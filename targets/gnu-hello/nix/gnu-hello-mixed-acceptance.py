#!/usr/bin/env python3
"""Emit the fixed, closed GNU hello mixed-acceptance aggregation."""

from __future__ import annotations

import argparse
from pathlib import Path

from spaghetti_extractor_target_gnu_hello.gnu_hello_mixed_acceptance import (
    write_gnu_hello_mixed_acceptance,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args()
    plan = write_gnu_hello_mixed_acceptance(arguments.out)
    if not plan.complete:
        details = "\n".join(
            f"  {item.field} : {item.lean_type}\n"
            f"    blocker: {item.blocker}"
            for item in plan.missing
        )
        raise SystemExit(
            "GNU hello mixed acceptance is missing checked terms:\n"
            + details
        )


if __name__ == "__main__":
    main()

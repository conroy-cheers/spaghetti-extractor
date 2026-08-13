#!/usr/bin/env python3
"""Generate the checked local Python import graph consumed by Nix phases."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from spaghetti_extractor.python_module_index import render_python_module_index


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=Path(__file__).parents[1])
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).parents[1] / "nix" / "python-module-index.json",
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    repository = args.repository.resolve()
    output = args.out.resolve()
    rendered = render_python_module_index(repository)
    if args.check:
        if not output.is_file() or output.read_text(encoding="utf-8") != rendered:
            print(
                "Python module index is stale; run "
                "tools/update-python-module-index.py",
                file=sys.stderr,
            )
            return 1
        return 0
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

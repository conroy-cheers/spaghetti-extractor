#!/usr/bin/env python3
"""Generate the checked local Python import graph consumed by Nix phases."""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
import sys
from typing import Iterable


FORMAT = "spaghetti-extractor-python-module-index-v1"
PACKAGE = "spaghetti_extractor"


def _module_name(path: Path, source_root: Path) -> str:
    relative = path.relative_to(source_root)
    if relative.name == "__init__.py":
        relative = relative.parent
    else:
        relative = relative.with_suffix("")
    return ".".join(relative.parts)


def _candidate_paths(source_root: Path) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for path in sorted((source_root / PACKAGE).rglob("*.py")):
        result[_module_name(path, source_root)] = path
    return result


def _parent_modules(module: str) -> Iterable[str]:
    parts = module.split(".")
    for size in range(1, len(parts)):
        yield ".".join(parts[:size])


def _local_imports(
    *, module: str, path: Path
) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    current_package = module if path.name == "__init__.py" else module.rpartition(".")[0]
    result = set(_parent_modules(module))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            result.update(
                alias.name
                for alias in node.names
                if alias.name == PACKAGE or alias.name.startswith(f"{PACKAGE}.")
            )
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = current_package.split(".") if current_package else []
                trim = node.level - 1
                if trim > len(base):
                    raise ValueError(f"relative import escapes package in {path}")
                base = base[: len(base) - trim]
                if node.module:
                    base.extend(node.module.split("."))
                target = ".".join(base)
            else:
                target = node.module or ""
            if target == PACKAGE or target.startswith(f"{PACKAGE}."):
                result.add(target)
                # ``from . import module`` and ``from package import module``
                # load a sibling module rather than a name from an already
                # selected module.  Other from-imports depend on their base
                # module; imported attributes do not create extra DAG nodes.
                if node.module is None or target == PACKAGE:
                    result.update(
                        f"{target}.{alias.name}"
                        for alias in node.names
                        if alias.name != "*"
                    )
    result.discard(module)
    return result


def build_index(repository: Path) -> dict[str, object]:
    source_root = repository / "src"
    modules = _candidate_paths(source_root)
    rows = {
        module: {
            "path": path.relative_to(repository).as_posix(),
            "dependencies": sorted(_local_imports(module=module, path=path)),
        }
        for module, path in sorted(modules.items())
    }
    missing = sorted({
        dependency
        for row in rows.values()
        for dependency in row["dependencies"]
        if dependency not in modules
    })
    if missing:
        raise ValueError(f"local imports name missing modules: {missing!r}")
    return {"format": FORMAT, "modules": rows}


def _canonical_json(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


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
    rendered = _canonical_json(build_index(repository))
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

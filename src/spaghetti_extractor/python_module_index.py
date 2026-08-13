"""Generate the checked local Python import graph consumed by Nix phases."""

from __future__ import annotations

import ast
import json
from collections.abc import Iterable
from pathlib import Path, PurePosixPath


FORMAT = "spaghetti-extractor-python-module-index-v2"
PACKAGE = "spaghetti_extractor"
RESOURCE_DECLARATION = "PYTHON_RESOURCES"


def _module_name(path: Path, source_root: Path) -> str:
    relative = path.relative_to(source_root)
    relative = relative.parent if relative.name == "__init__.py" else relative.with_suffix("")
    return ".".join(relative.parts)


def _candidate_paths(source_root: Path) -> dict[str, Path]:
    return {
        _module_name(path, source_root): path
        for path in sorted((source_root / PACKAGE).rglob("*.py"))
    }


def _parent_modules(module: str) -> Iterable[str]:
    parts = module.split(".")
    for size in range(1, len(parts)):
        yield ".".join(parts[:size])


def _local_imports(*, module: str, path: Path) -> set[str]:
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
                if node.module is None or target == PACKAGE:
                    result.update(
                        f"{target}.{alias.name}"
                        for alias in node.names
                        if alias.name != "*"
                    )
    result.discard(module)
    return result


def declared_python_resources(
    repository: Path, path: Path, *, tree: ast.Module | None = None
) -> tuple[str, ...]:
    """Return literal package data owned by one Python module.

    Modules that open source-tree data at runtime declare it once with
    ``PYTHON_RESOURCES``.  Nix phase closures and isolated test shards both
    consume this same inventory.
    """

    parsed = tree or ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    value: object = ()
    for node in parsed.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if not any(
            isinstance(target, ast.Name)
            and target.id == RESOURCE_DECLARATION
            for target in targets
        ):
            continue
        try:
            value = ast.literal_eval(node.value)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"{RESOURCE_DECLARATION} in {path} must be a literal list or tuple"
            ) from exc
    if not isinstance(value, (list, tuple)) or any(
        not isinstance(item, str) for item in value
    ):
        raise ValueError(
            f"{RESOURCE_DECLARATION} in {path} must contain only strings"
        )
    result: list[str] = []
    for item in value:
        relative = PurePosixPath(item)
        if (
            relative.is_absolute()
            or not relative.parts
            or relative.parts[0] != "src"
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            raise ValueError(
                f"{RESOURCE_DECLARATION} in {path} contains unsafe source path {item!r}"
            )
        if not (repository / Path(*relative.parts)).exists():
            raise ValueError(
                f"{RESOURCE_DECLARATION} in {path} names missing path {item!r}"
            )
        result.append(relative.as_posix())
    return tuple(sorted(set(result)))


def build_python_module_index(repository: Path) -> dict[str, object]:
    source_root = repository / "src"
    modules = _candidate_paths(source_root)
    rows = {
        module: {
            "path": path.relative_to(repository).as_posix(),
            "dependencies": sorted(_local_imports(module=module, path=path)),
            "resources": list(declared_python_resources(repository, path)),
        }
        for module, path in sorted(modules.items())
    }
    missing = sorted(
        {
            dependency
            for row in rows.values()
            for dependency in row["dependencies"]  # type: ignore[union-attr]
            if dependency not in modules
        }
    )
    if missing:
        raise ValueError(f"local imports name missing modules: {missing!r}")
    return {"format": FORMAT, "modules": rows}


def render_python_module_index(repository: Path) -> str:
    return json.dumps(
        build_python_module_index(repository.resolve()), indent=2, sort_keys=True
    ) + "\n"


def refresh_python_module_index(repository: Path, output: Path) -> bool:
    """Write the canonical index and return whether its content changed."""

    rendered = render_python_module_index(repository)
    previous = output.read_text(encoding="utf-8") if output.is_file() else None
    if previous == rendered:
        return False
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")
    return True


__all__ = [
    "FORMAT",
    "build_python_module_index",
    "declared_python_resources",
    "refresh_python_module_index",
    "render_python_module_index",
]

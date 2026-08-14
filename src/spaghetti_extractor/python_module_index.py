"""Generate the checked local Python import graph consumed by Nix phases."""

from __future__ import annotations

import ast
import json
import re
import tomllib
from collections.abc import Iterable
from pathlib import Path, PurePosixPath


FORMAT = "spaghetti-extractor-python-module-index-v2"
PACKAGE = "spaghetti_extractor"
RESOURCE_DECLARATION = "PYTHON_RESOURCES"
COMMAND_MANIFEST_DECLARATION = "SUPPORTED_COMMAND_MANIFEST"
COMMAND_MANIFEST_PATH = Path("src/spaghetti_extractor/commands/manifest.py")
_MODULE_REFERENCE = re.compile(
    r'["\'](spaghetti_extractor(?:\.[A-Za-z0-9_]+)+)["\']'
)
_NIX_PYTHON_INVOCATION = re.compile(
    r"(?:(?:\bfrom|\bimport)\s+|(?:^|\s)-m\s+(?:\\\s*)?)"
    r"(spaghetti_extractor(?:\.[A-Za-z0-9_]+)+)"
)


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


def declared_public_command_modules(repository: Path) -> tuple[str, ...]:
    """Read the literal public-command roots without loading command backends."""

    path = repository / COMMAND_MANIFEST_PATH
    if not path.is_file():
        raise ValueError(f"public command manifest is missing: {COMMAND_MANIFEST_PATH}")
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    value: object | None = None
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if not any(
            isinstance(target, ast.Name)
            and target.id == COMMAND_MANIFEST_DECLARATION
            for target in targets
        ):
            continue
        try:
            value = ast.literal_eval(node.value)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"{COMMAND_MANIFEST_DECLARATION} in {path} must be literal data"
            ) from exc
    if not isinstance(value, (list, tuple)):
        raise ValueError(
            f"{COMMAND_MANIFEST_DECLARATION} in {path} must be a list or tuple"
        )
    modules: list[str] = []
    command_names: set[str] = set()
    for row in value:
        if not isinstance(row, dict) or set(row) != {"name", "group", "help"}:
            raise ValueError(f"public command manifest has a malformed row: {row!r}")
        name = row.get("name")
        group = row.get("group")
        help_text = row.get("help")
        if not all(isinstance(item, str) and item for item in (name, group, help_text)):
            raise ValueError(f"public command manifest has an invalid row: {row!r}")
        assert isinstance(name, str) and isinstance(group, str)
        if name in command_names:
            raise ValueError(f"public command manifest duplicates command {name!r}")
        if not group.startswith(f"{PACKAGE}.commands."):
            raise ValueError(f"public command group escapes commands package: {group!r}")
        command_names.add(name)
        modules.append(group)
    return tuple(sorted(set(modules)))


def nix_phase_module_roots(repository: Path) -> tuple[str, ...]:
    """Return package modules named by checked Nix phase definitions."""

    nix_paths = [repository / "flake.nix"]
    nix_paths.extend(sorted((repository / "nix").glob("**/*.nix")))
    nix_paths.extend(sorted((repository / "targets").glob("**/*.nix")))
    roots: set[str] = set()
    for path in nix_paths:
        if path.is_file():
            source = path.read_text(encoding="utf-8")
            roots.update(match.group(1) for match in _MODULE_REFERENCE.finditer(source))
            roots.update(
                match.group(1) for match in _NIX_PYTHON_INVOCATION.finditer(source)
            )
    return tuple(sorted(roots))


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
    cli_row = rows.get(f"{PACKAGE}.cli")
    if cli_row is not None:
        # The CLI loads exactly one command group through importlib.  Treat the
        # literal command manifest as the dynamic-import authority so Nix
        # closures remain complete without importing every backend at startup
        # or maintaining a second dependency inventory.
        cli_row["dependencies"] = sorted(
            {
                *cli_row["dependencies"],
                *declared_public_command_modules(repository),
            }
        )
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


def production_module_roots(
    repository: Path, index: dict[str, object] | None = None
) -> tuple[str, ...]:
    """Derive supported package roots from public entrypoints and Nix phases."""

    repository = repository.resolve()
    current = index or build_python_module_index(repository)
    modules = current.get("modules")
    if not isinstance(modules, dict):
        raise ValueError("Python module index has no module mapping")
    roots: set[str] = {
        module
        for module, row in modules.items()
        if isinstance(module, str)
        and isinstance(row, dict)
        and str(row.get("path", "")).endswith("/__main__.py")
    }
    project = tomllib.loads((repository / "pyproject.toml").read_text(encoding="utf-8"))
    scripts = project.get("project", {}).get("scripts", {})
    if not isinstance(scripts, dict):
        raise ValueError("pyproject project.scripts must be a table")
    for command, reference in scripts.items():
        if not isinstance(reference, str) or ":" not in reference:
            raise ValueError(f"installed script {command!r} has no module:function target")
        roots.add(reference.split(":", 1)[0])

    roots.update(declared_public_command_modules(repository))
    roots.update(nix_phase_module_roots(repository))
    missing = sorted(roots - set(modules))
    if missing:
        raise ValueError(f"production roots name missing modules: {missing!r}")
    return tuple(sorted(roots))


def production_module_closure(
    repository: Path, index: dict[str, object] | None = None
) -> tuple[str, ...]:
    """Return every module transitively used by a supported production root."""

    current = index or build_python_module_index(repository.resolve())
    modules = current.get("modules")
    if not isinstance(modules, dict):
        raise ValueError("Python module index has no module mapping")
    pending = list(production_module_roots(repository, current))
    selected: set[str] = set()
    while pending:
        module = pending.pop()
        if module in selected:
            continue
        selected.add(module)
        row = modules.get(module)
        if not isinstance(row, dict) or not isinstance(row.get("dependencies"), list):
            raise ValueError(f"Python module index record is malformed: {module}")
        pending.extend(str(value) for value in row["dependencies"])
    return tuple(sorted(selected))


def production_unreachable_modules(
    repository: Path, index: dict[str, object] | None = None
) -> tuple[str, ...]:
    """Find package code that can only be reached from tests or stale code."""

    current = index or build_python_module_index(repository.resolve())
    modules = current.get("modules")
    if not isinstance(modules, dict):
        raise ValueError("Python module index has no module mapping")
    reachable = set(production_module_closure(repository, current))
    return tuple(sorted(set(modules) - reachable))


def render_python_module_index(repository: Path) -> str:
    resolved = repository.resolve()
    index = build_python_module_index(resolved)
    # A fresh import graph is not sufficient if a public command or Nix phase
    # names a missing module. Validate all production roots before publishing it.
    production_module_roots(resolved, index)
    return json.dumps(index, indent=2, sort_keys=True) + "\n"


__all__ = [
    "FORMAT",
    "build_python_module_index",
    "declared_public_command_modules",
    "declared_python_resources",
    "nix_phase_module_roots",
    "production_module_closure",
    "production_module_roots",
    "production_unreachable_modules",
    "render_python_module_index",
]

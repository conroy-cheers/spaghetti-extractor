"""Convention-driven test discovery and import impact indexing."""

from __future__ import annotations

import ast
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Iterable, Mapping

from ..python_module_index import build_python_module_index, declared_python_resources

from .diagnostics import Diagnostic, TestkitError, fail_on_errors
from .model import (
    ImpactIndex,
    ModuleRecord,
    TestRecord,
    canonical_sha256,
    safe_relative_path,
)


HEAVY_CAPABILITIES = frozenset({"bochs", "compiler", "isa", "lean", "native", "nix", "wine"})
ALLOWED_DIRECTIVE_KEYS = frozenset({"capabilities", "dependencies", "fixtures", "resources", "subsystem"})
HEAVY_COMMANDS = {
    "bochs": "bochs-conformance",
    "cc": "compiler",
    "clang": "compiler",
    "clang-cl": "compiler",
    "gcc": "compiler",
    "i686-w64-mingw32-gcc": "compiler",
    "lake": "lean-isa-runner",
    "lean": "lean-isa-runner",
    "nix": "nix",
    "qemu-i386": "isa",
    "wine": "headless-wine",
    "wine64": "headless-wine",
}
CAPABILITY_FIXTURES = {
    "bochs": "bochs-conformance",
    "compiler": "compiler",
    "lean": "lean-isa-runner",
    "nix": "nix",
    "wine": "headless-wine",
}


@dataclass(frozen=True, slots=True)
class _SourceModule:
    name: str
    path: str
    aliases: tuple[str, ...]
    dependencies: tuple[str, ...]
    resources: tuple[str, ...]
    sha256: str
    tree: ast.Module


@dataclass(frozen=True, slots=True)
class _Directive:
    capabilities: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()
    fixtures: tuple[str, ...] = ()
    resources: tuple[str, ...] = ()
    subsystem: str | None = None


def _sha256(path: Path) -> str:
    if path.is_file():
        return hashlib.sha256(path.read_bytes()).hexdigest()
    digest = hashlib.sha256()
    for child in sorted(item for item in path.rglob("*") if item.is_file()):
        digest.update(child.relative_to(path).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(child.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _module_name(relative: PurePosixPath) -> tuple[str, tuple[str, ...]]:
    without_suffix = relative.with_suffix("")
    parts = without_suffix.parts
    if parts[-1] == "__init__":
        parts = parts[:-1]
    canonical = ".".join(parts)
    aliases: set[str] = {canonical}
    if relative.parts[0] == "src":
        canonical = ".".join(parts[1:])
        aliases = {canonical}
    elif relative.parts[0] == "tests" and len(parts) == 2:
        aliases.add(parts[-1])
    return canonical, tuple(sorted(alias for alias in aliases if alias))


def _resolve_from(module: str, path: str, node: ast.ImportFrom) -> str:
    if not node.level:
        return node.module or ""
    package = module if PurePosixPath(path).name == "__init__.py" else module.rpartition(".")[0]
    parts = package.split(".") if package else []
    trim = node.level - 1
    if trim > len(parts):
        return ""
    parts = parts[: len(parts) - trim]
    if node.module:
        parts.extend(node.module.split("."))
    return ".".join(parts)


def _import_candidates(module: str, path: str, tree: ast.Module) -> set[str]:
    result: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            result.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = _resolve_from(module, path, node)
            if base:
                result.add(base)
                result.update(
                    f"{base}.{alias.name}" for alias in node.names if alias.name != "*"
                )
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "importlib"
            and node.func.attr == "import_module"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            result.add(node.args[0].value)
    return result


def _literal_strings(value: object, *, path: str, key: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or any(not isinstance(item, str) for item in value):
        raise TestkitError(
            Diagnostic(
                "error",
                "invalid_testkit_directive",
                f"TESTKIT[{key!r}] must be a literal list or tuple of strings",
                location=path,
                remediation="Use a static TESTKIT dictionary so discovery remains deterministic.",
                example=f'TESTKIT = {{"{key}": ["value"]}}',
            )
        )
    return tuple(sorted(set(value)))


def _directive(tree: ast.Module, *, path: str) -> _Directive:
    value: object | None = None
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if not any(isinstance(target, ast.Name) and target.id == "TESTKIT" for target in targets):
            continue
        try:
            value = ast.literal_eval(node.value)
        except (ValueError, TypeError) as exc:
            raise TestkitError(
                Diagnostic(
                    "error",
                    "dynamic_testkit_directive",
                    "TESTKIT must be a literal dictionary",
                    location=path,
                    remediation="Replace computed metadata with a literal TESTKIT mapping.",
                )
            ) from exc
    if value is None:
        return _Directive()
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise TestkitError(Diagnostic("error", "invalid_testkit_directive", "TESTKIT must be a string-keyed dictionary", location=path))
    unknown = sorted(set(value) - ALLOWED_DIRECTIVE_KEYS)
    if unknown:
        raise TestkitError(
            Diagnostic(
                "error",
                "unknown_testkit_directive",
                f"unsupported TESTKIT fields: {', '.join(unknown)}",
                location=path,
                remediation=f"Use only: {', '.join(sorted(ALLOWED_DIRECTIVE_KEYS))}.",
            )
        )
    subsystem = value.get("subsystem")
    if subsystem is not None and (not isinstance(subsystem, str) or not subsystem):
        raise TestkitError(Diagnostic("error", "invalid_testkit_directive", "TESTKIT['subsystem'] must be a nonempty string", location=path))
    return _Directive(
        capabilities=_literal_strings(value.get("capabilities", ()), path=path, key="capabilities"),
        dependencies=_literal_strings(value.get("dependencies", ()), path=path, key="dependencies"),
        fixtures=_literal_strings(value.get("fixtures", ()), path=path, key="fixtures"),
        resources=tuple(
            safe_relative_path(item, field_name="TESTKIT resource")
            for item in _literal_strings(value.get("resources", ()), path=path, key="resources")
        ),
        subsystem=subsystem,
    )


def _classify(path: str, directive: _Directive) -> tuple[str, str, tuple[str, ...]]:
    parts = PurePosixPath(path).parts
    tail = parts[1:]
    capabilities: set[str] = set(directive.capabilities)
    if len(tail) >= 2 and tail[0] == "smoke":
        tier, subsystem = "smoke", "smoke"
    elif len(tail) >= 3 and tail[0] == "unit":
        tier, subsystem = "unit", tail[1]
    elif len(tail) >= 3 and tail[0] == "integration":
        tier, subsystem = "integration", tail[1]
        capabilities.add(tail[1])
    elif len(tail) >= 2 and tail[0] == "benchmark":
        tier, subsystem = "benchmark", "benchmark"
        capabilities.add("benchmark")
    elif len(tail) == 1:
        stem = PurePosixPath(path).stem.removeprefix("test_")
        tier, subsystem = "unit", stem.split("_", 1)[0] or "core"
    else:
        raise TestkitError(
            Diagnostic(
                "error",
                "unclassified_test_path",
                "test path does not match a supported convention",
                location=path,
                remediation="Move the test with the scaffolder: `nix run .#dev -- scaffold test <subsystem> <name>`.",
                example="tests/unit/control/test_branch_targets.py",
            )
        )
    if directive.subsystem:
        subsystem = directive.subsystem
    return tier, subsystem, tuple(sorted(capabilities))


def _constant_command(node: ast.Call) -> str | None:
    is_subprocess = (
        isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "subprocess"
        and node.func.attr in {"Popen", "call", "check_call", "check_output", "run"}
    )
    if not is_subprocess:
        return None
    if not node.args:
        return None
    first = node.args[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        words = first.value.split()
        return words[0] if words else None
    if isinstance(first, (ast.List, ast.Tuple)) and first.elts:
        value = first.elts[0]
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            return value.value
    return None


def _heavy_tool_diagnostics(tree: ast.Module, *, path: str) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        command = _constant_command(node)
        if command is None:
            continue
        tool = PurePosixPath(command).name
        fixture_id = HEAVY_COMMANDS.get(tool)
        if fixture_id is None:
            continue
        diagnostics.append(
            Diagnostic(
                "error",
                "direct_heavy_tool_invocation",
                f"test invokes {tool} directly, bypassing shared fixtures and execution policy",
                location=f"{path}:{getattr(node, 'lineno', 1)}",
                remediation=f'Use `fixture("{fixture_id}")`; inspect it with `nix run .#dev -- fixtures {fixture_id}`.',
                example=f'from spaghetti_extractor.testkit import fixture\nrunner = fixture("{fixture_id}")',
            )
        )
    return diagnostics


def _heavy_tool_capabilities(tree: ast.Module) -> set[str]:
    by_fixture = {
        "bochs-conformance": "bochs",
        "compiler": "compiler",
        "headless-wine": "wine",
        "lean-isa-runner": "lean",
        "nix": "nix",
    }
    result: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        command = _constant_command(node)
        if command is None and (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "shutil"
            and node.func.attr == "which"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            command = node.args[0].value
        if command is None:
            continue
        fixture_id = HEAVY_COMMANDS.get(PurePosixPath(command).name)
        if fixture_id in by_fixture:
            result.add(by_fixture[fixture_id])
    return result


def _source_files(repository: Path) -> list[Path]:
    files = list((repository / "src").rglob("*.py"))
    files.extend((repository / "tests").rglob("*.py"))
    return sorted(path for path in files if "__pycache__" not in path.parts)


def _scan_modules(repository: Path) -> tuple[dict[str, _SourceModule], dict[str, str]]:
    rows: list[tuple[Path, str, tuple[str, ...], ast.Module]] = []
    alias_paths: dict[str, str] = {}
    for path in _source_files(repository):
        relative = PurePosixPath(path.relative_to(repository).as_posix())
        module, aliases = _module_name(relative)
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative.as_posix())
        except (OSError, SyntaxError) as exc:
            raise TestkitError(
                Diagnostic(
                    "error",
                    "python_source_unreadable",
                    str(exc),
                    location=relative.as_posix(),
                    remediation="Fix the Python syntax before regenerating the impact index.",
                )
            ) from exc
        rows.append((path, module, aliases, tree))
        for alias in aliases:
            previous = alias_paths.setdefault(alias, relative.as_posix())
            if previous != relative.as_posix():
                raise TestkitError(Diagnostic("error", "ambiguous_module_alias", f"module alias {alias!r} names both {previous} and {relative.as_posix()}"))
    known = dict(alias_paths)
    try:
        production_index = build_python_module_index(repository)
    except ValueError as exc:
        raise TestkitError(
            Diagnostic(
                "error",
                "python_module_index_invalid",
                str(exc),
                remediation="Repair the production module graph before planning tests.",
            )
        ) from exc
    production_modules = production_index["modules"]
    assert isinstance(production_modules, dict)
    by_path: dict[str, _SourceModule] = {}
    for path, module, aliases, tree in rows:
        relative = path.relative_to(repository).as_posix()
        dependencies: set[str] = set()
        for candidate in _import_candidates(module, relative, tree):
            probe = candidate
            while probe:
                if probe in known:
                    dependencies.add(known[probe])
                    break
                probe = probe.rpartition(".")[0]
        production_row = production_modules.get(module)
        if isinstance(production_row, dict):
            for candidate in production_row.get("dependencies", ()):
                dependency = known.get(str(candidate))
                if dependency is None:
                    raise TestkitError(
                        Diagnostic(
                            "error",
                            "python_module_dependency_missing",
                            f"production dependency {candidate!r} has no testkit module",
                            location=relative,
                            remediation="Regenerate the Python module index after repairing the source graph.",
                        )
                    )
                dependencies.add(dependency)
        parent = module.rpartition(".")[0]
        while parent:
            parent_path = known.get(parent)
            if parent_path is not None:
                dependencies.add(parent_path)
            parent = parent.rpartition(".")[0]
        dependencies.discard(relative)
        by_path[relative] = _SourceModule(
            name=module,
            path=relative,
            aliases=aliases,
            dependencies=tuple(sorted(dependencies)),
            resources=declared_python_resources(repository, path, tree=tree),
            sha256=_sha256(path),
            tree=tree,
        )
    return by_path, alias_paths


def _transitive_paths(path: str, modules: Mapping[str, _SourceModule]) -> tuple[str, ...]:
    pending = list(modules[path].dependencies)
    selected: set[str] = set()
    while pending:
        dependency = pending.pop()
        if dependency in selected:
            continue
        selected.add(dependency)
        row = modules.get(dependency)
        if row is not None:
            pending.extend(row.dependencies)
    return tuple(sorted(selected))


_RESOURCE_METHODS = frozenset({
    "exists",
    "glob",
    "is_dir",
    "is_file",
    "iterdir",
    "open",
    "read_bytes",
    "read_text",
    "rglob",
})


def _attribute_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _attribute_name(node.value)
        return None if prefix is None else f"{prefix}.{node.attr}"
    return None


def _static_path(
    node: ast.AST,
    *,
    source_path: Path,
    symbols: Mapping[str, Path],
) -> Path | None:
    if isinstance(node, ast.Name):
        return symbols.get(node.id)
    if isinstance(node, ast.Attribute):
        named = _attribute_name(node)
        if named in symbols:
            return symbols[named]
        if named is not None and named.startswith(("self.", "cls.")):
            suffix = named.split(".", 1)[1]
            for prefix in ("self.", "cls."):
                if f"{prefix}{suffix}" in symbols:
                    return symbols[f"{prefix}{suffix}"]
        base = _static_path(node.value, source_path=source_path, symbols=symbols)
        if base is not None and node.attr == "parent":
            return base.parent
        return None
    if isinstance(node, ast.Call):
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "Path"
            and len(node.args) == 1
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == "__file__"
        ):
            return source_path
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "Path"
            and len(node.args) == 1
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            value = Path(node.args[0].value)
            if value.is_absolute():
                return value
            repository = symbols.get("@repository")
            return None if repository is None else repository / value
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"absolute", "resolve"}
            and not node.args
        ):
            return _static_path(node.func.value, source_path=source_path, symbols=symbols)
        return None
    if isinstance(node, ast.Subscript):
        if not isinstance(node.value, ast.Attribute) or node.value.attr != "parents":
            return None
        base = _static_path(node.value.value, source_path=source_path, symbols=symbols)
        index = node.slice
        if base is None or not isinstance(index, ast.Constant) or not isinstance(index.value, int):
            return None
        try:
            return base.parents[index.value]
        except IndexError:
            return None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        base = _static_path(node.left, source_path=source_path, symbols=symbols)
        if base is None or not isinstance(node.right, ast.Constant) or not isinstance(node.right.value, str):
            return None
        return base / node.right.value
    return None


def _inferred_resources(repository: Path, module: _SourceModule) -> tuple[str, ...]:
    """Infer checked repository inputs from ordinary pathlib expressions."""

    source_path = repository / module.path
    symbols: dict[str, Path] = {"@repository": repository}
    assignments = [
        node
        for node in ast.walk(module.tree)
        if isinstance(node, (ast.Assign, ast.AnnAssign))
    ]
    for _ in range(len(assignments) + 1):
        changed = False
        for node in assignments:
            value = _static_path(node.value, source_path=source_path, symbols=symbols)
            if value is None:
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                name = _attribute_name(target)
                if name is not None and symbols.get(name) != value:
                    symbols[name] = value
                    changed = True
        if not changed:
            break

    candidates: set[Path] = set()
    for node in ast.walk(module.tree):
        if not isinstance(node, ast.Call):
            continue
        candidate: Path | None = None
        if isinstance(node.func, ast.Attribute) and node.func.attr in _RESOURCE_METHODS:
            candidate = _static_path(node.func.value, source_path=source_path, symbols=symbols)
        elif isinstance(node.func, ast.Name) and node.func.id == "open" and node.args:
            candidate = _static_path(node.args[0], source_path=source_path, symbols=symbols)
        elif node.args:
            candidate = _static_path(node.args[0], source_path=source_path, symbols=symbols)
        if candidate is not None:
            candidates.add(candidate)
        arguments = [*node.args, *(keyword.value for keyword in node.keywords)]
        for argument in arguments:
            for nested in ast.walk(argument):
                nested_candidate = _static_path(
                    nested, source_path=source_path, symbols=symbols
                )
                if nested_candidate is not None and nested_candidate.is_file():
                    candidates.add(nested_candidate)

    resources: set[str] = set()
    resolved_repository = repository.resolve()
    for candidate in candidates:
        try:
            relative = candidate.resolve().relative_to(resolved_repository).as_posix()
        except (OSError, ValueError):
            continue
        if relative in {"", ".", module.path}:
            continue
        if (repository / relative).exists():
            resources.add(relative)
    return tuple(sorted(resources))


def _resource_dependency_closure(
    repository: Path, resources: Iterable[str]
) -> tuple[str, ...]:
    pending = list(resources)
    observed: set[str] = set()
    while pending:
        relative = pending.pop()
        if relative in observed:
            continue
        observed.add(relative)
        path = repository / relative
        if not path.is_file() or path.suffix.lower() != ".json":
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        strings: list[str] = []
        stack = [payload]
        while stack:
            value = stack.pop()
            if isinstance(value, str):
                strings.append(value)
            elif isinstance(value, list):
                stack.extend(value)
            elif isinstance(value, Mapping):
                stack.extend(value.values())
        for value in strings:
            candidates = (path.parent / value, repository / value)
            for candidate in candidates:
                if not candidate.exists():
                    continue
                try:
                    dependency = candidate.resolve().relative_to(repository.resolve()).as_posix()
                except (OSError, ValueError):
                    continue
                if dependency not in observed:
                    pending.append(dependency)
                break
    return tuple(sorted(observed))


def _stable_shard(
    test_id: str,
    *,
    tier: str,
    capabilities: tuple[str, ...],
    shard_count: int,
) -> str:
    digest = hashlib.sha256(test_id.encode("utf-8")).hexdigest()
    heavy = sorted(HEAVY_CAPABILITIES.intersection(capabilities))
    if tier == "smoke":
        return "smoke"
    if tier == "benchmark":
        return f"benchmark-{digest[:12]}"
    if heavy:
        return f"{heavy[0]}-{digest[:12]}"
    return f"pure-{digest[:12]}"


def build_impact_index(
    repository: Path,
    *,
    shard_count: int = 32,
    strict_policy: bool = True,
) -> ImpactIndex:
    repository = repository.resolve()
    if shard_count < 1 or shard_count > 256:
        raise TestkitError(Diagnostic("error", "invalid_shard_count", "shard count must be between 1 and 256"))
    if not (repository / "src" / "spaghetti_extractor").is_dir() or not (repository / "tests").is_dir():
        raise TestkitError(
            Diagnostic(
                "error",
                "repository_layout_missing",
                "repository must contain src/spaghetti_extractor and tests",
                location=str(repository),
                remediation="Run the command from the repository root or pass `--repository`.",
            )
        )
    modules, aliases = _scan_modules(repository)
    inferred_resource_cache: dict[str, tuple[str, ...]] = {}
    resource_hash_cache: dict[str, str] = {}

    def inferred_for(path: str) -> tuple[str, ...]:
        if path not in inferred_resource_cache:
            inferred_resource_cache[path] = tuple(sorted({
                *modules[path].resources,
                *_inferred_resources(repository, modules[path]),
            }))
        return inferred_resource_cache[path]

    def resource_sha256(path: str) -> str:
        if path not in resource_hash_cache:
            resource_hash_cache[path] = _sha256(repository / path)
        return resource_hash_cache[path]

    diagnostics: list[Diagnostic] = []
    tests: list[TestRecord] = []
    for path, module in sorted(modules.items()):
        if not path.startswith("tests/") or not PurePosixPath(path).name.startswith("test_"):
            continue
        directive = _directive(module.tree, path=path)
        tier, subsystem, classified_capabilities = _classify(path, directive)
        heavy_diagnostics = _heavy_tool_diagnostics(module.tree, path=path)
        diagnostics.extend(heavy_diagnostics)
        dependencies = set(_transitive_paths(path, modules))
        for dependency in directive.dependencies:
            resolved = aliases.get(dependency)
            if resolved is None and dependency in modules:
                resolved = dependency
            if resolved is None:
                raise TestkitError(
                    Diagnostic(
                        "error",
                        "unknown_test_dependency",
                        f"TESTKIT dependency {dependency!r} does not name a local module or path",
                        location=path,
                        remediation="Use a Python module name or repository-relative Python path.",
                    )
                )
            dependencies.add(resolved)
            dependencies.update(_transitive_paths(resolved, modules))
        capabilities = set(classified_capabilities)
        capabilities.update(_heavy_tool_capabilities(module.tree))
        direct_dependency_names = {
            modules[dependency].name for dependency in module.dependencies
        }
        if any(name.endswith("isa_conformance_lean") or ".lean_runner" in name for name in direct_dependency_names):
            capabilities.update(("isa", "lean"))
        if any("isa_conformance_bochs" in name for name in direct_dependency_names):
            capabilities.update(("bochs", "isa"))
        if any("native_build" in name or "pe_composer" in name for name in direct_dependency_names):
            capabilities.add("native")
        capabilities_tuple = tuple(sorted(capabilities))
        inferred_resources = set(inferred_for(path))
        for dependency in dependencies:
            inferred_resources.update(inferred_for(dependency))
        resources = _resource_dependency_closure(
            repository, set(directive.resources) | inferred_resources
        )
        missing_resources = [resource for resource in resources if not (repository / resource).exists()]
        if missing_resources:
            raise TestkitError(
                Diagnostic(
                    "error",
                    "missing_test_resource",
                    f"declared resources do not exist: {', '.join(missing_resources)}",
                    location=path,
                    remediation="Create the resource through the fixture scaffolder or correct TESTKIT['resources'].",
                )
            )
        input_rows = [
            {"path": dependency, "sha256": modules[dependency].sha256}
            for dependency in sorted(dependencies)
        ]
        input_rows.extend(
            {"path": resource, "sha256": resource_sha256(resource)}
            for resource in resources
        )
        test_id = path.removesuffix(".py")
        fixture_ids = tuple(
            sorted(
                set(directive.fixtures)
                | {CAPABILITY_FIXTURES[capability] for capability in capabilities if capability in CAPABILITY_FIXTURES}
            )
        )
        shard = _stable_shard(
            test_id,
            tier=tier,
            capabilities=capabilities_tuple,
            shard_count=shard_count,
        )
        tests.append(
            TestRecord(
                id=test_id,
                path=path,
                module=module.name,
                tier=tier,
                subsystem=subsystem,
                capabilities=capabilities_tuple,
                dependencies=tuple(sorted(modules[dependency].name for dependency in dependencies)),
                dependency_paths=tuple(sorted(dependencies)),
                fixtures=fixture_ids,
                resources=resources,
                sha256=module.sha256,
                input_sha256=canonical_sha256(
                    {"test": module.sha256, "inputs": input_rows, "fixtures": list(fixture_ids)}
                ),
                shard=shard,
            )
        )
    if not tests:
        raise TestkitError(
            Diagnostic(
                "error",
                "no_tests_discovered",
                "no test_*.py files were found",
                remediation="Create one with `nix run .#dev -- scaffold test <subsystem> <name>`.",
            )
        )
    if strict_policy:
        fail_on_errors(diagnostics)
    module_records = tuple(
        ModuleRecord(
            name=row.name,
            path=row.path,
            dependencies=tuple(modules[dependency].name for dependency in row.dependencies),
            resources=row.resources,
            sha256=row.sha256,
        )
        for row in sorted(modules.values(), key=lambda item: item.path)
    )
    return ImpactIndex(
        repository=".",
        modules=module_records,
        tests=tuple(sorted(tests, key=lambda item: item.id)),
        diagnostics=tuple(sorted(diagnostics)),
    )


__all__ = ["HEAVY_CAPABILITIES", "build_impact_index"]

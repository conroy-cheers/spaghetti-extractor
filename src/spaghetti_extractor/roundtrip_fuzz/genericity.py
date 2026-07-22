from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any, Iterable, Mapping

from ..stage_binary import StageAInputError
from .metrics import GenericityEvidence, GenericityInventory


_FORBIDDEN_LITERAL_RE = re.compile(r"(?:^|[^a-z])(jq|hello|phase0|spike)(?:[^a-z]|$)")
_FORBIDDEN_FIELD_NAMES = frozenset({
    "case_id",
    "corpus_id",
    "fixture",
    "fixture_id",
    "generator_seed",
    "parent_seed",
    "template",
    "template_id",
    "transformation",
    "transformations",
})
_FORBIDDEN_VARIABLE_NAMES = frozenset({
    "case_id",
    "corpus_id",
    "fixture_id",
    "parent_seed",
    "template_id",
})
_NON_ACCEPTANCE_MODULES = frozenset({"isa_qualification.py"})
_LEAN_DECLARATION_RE = re.compile(
    r"\s*(?:abbrev|class|def|inductive|instance|lemma|structure|theorem)\s+"
    r"([A-Za-z_][A-Za-z0-9_'.]*)"
)
_LEAN_PROOF_RULE_RE = re.compile(
    r"\s*(?:lemma|theorem)\s+([A-Za-z_][A-Za-z0-9_'.]*)"
)
_LEAN_INDUCTIVE_RE = re.compile(
    r"\s*inductive\s+([A-Za-z_][A-Za-z0-9_'.]*)"
)
_LEAN_CONSTRUCTOR_RE = re.compile(r"\s*\|\s*([A-Za-z_][A-Za-z0-9_']*)\b")
GENERICITY_BASELINE_FORMAT = "stage-a-roundtrip-genericity-baseline-v1"


def scan_acceptance_genericity(
    *,
    package_root: Path,
    baseline: GenericityInventory | None = None,
) -> GenericityEvidence:
    """Audit proof-authoritative sources for fixture-shaped dispatch.

    The scan is deliberately narrow and deterministic: diagnostic and corpus
    code may name fixtures, but the relational proof core and reviewed Lean
    model may not branch on those identities.
    """

    package_root = Path(package_root).resolve()
    python_root = package_root / "relational"
    lean_root = package_root / "lean" / "StageA"
    hits: list[str] = []
    source_lines = 0
    profile_branches: set[str] = set()
    special_cases: set[str] = set()
    for path in sorted(python_root.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        source_lines += len(source.splitlines())
        tree = ast.parse(source, filename=str(path))
        for scope in _python_scopes(tree):
            aliases = _identity_aliases(scope)
            for node, probes in _conditional_probes(scope):
                text = " | ".join(ast.unparse(probe) for probe in probes)
                identifiers = {
                    item.id
                    for probe in probes
                    for item in ast.walk(probe)
                    if isinstance(item, ast.Name)
                } | {
                    item.attr
                    for probe in probes
                    for item in ast.walk(probe)
                    if isinstance(item, ast.Attribute)
                }
                literals = {
                    item.value.lower()
                    for probe in probes
                    for item in ast.walk(probe)
                    if isinstance(item, ast.Constant) and isinstance(item.value, str)
                }
                relative = path.relative_to(package_root).as_posix()
                line = getattr(node, "lineno", 0)
                forbidden = (
                    path.name not in _NON_ACCEPTANCE_MODULES
                    and (
                        identifiers & _FORBIDDEN_VARIABLE_NAMES
                        or identifiers & aliases
                        or any(_selects_identity_field(probe) for probe in probes)
                    )
                ) or any(
                    _FORBIDDEN_LITERAL_RE.search(value) for value in literals
                )
                if forbidden:
                    hits.append(f"{relative}:{line}:{text}")
                    special_cases.add(f"{relative}:{_stable_probe_key(probes)}")
                if "profile" in identifiers:
                    profile_branches.add(
                        f"{relative}:{_stable_probe_key(probes)}"
                    )

    lean_constructors: set[str] = set()
    proof_rules: set[str] = set()
    for path in sorted(lean_root.glob("*.lean")):
        source = path.read_text(encoding="utf-8")
        source_lines += len(source.splitlines())
        relative = path.relative_to(package_root).as_posix()
        active_inductive: str | None = None
        for line_number, line in enumerate(source.splitlines(), start=1):
            code = line.split("/-", 1)[0].split("--", 1)[0]
            literal = _FORBIDDEN_LITERAL_RE.search(code.lower())
            if literal:
                hits.append(
                    f"{path.relative_to(package_root).as_posix()}:{line_number}:"
                    f"{literal.group(1)}"
                )
            inductive = _LEAN_INDUCTIVE_RE.match(code)
            declaration = _LEAN_DECLARATION_RE.match(code)
            if inductive:
                active_inductive = inductive.group(1)
            elif declaration:
                active_inductive = None
            theorem = _LEAN_PROOF_RULE_RE.match(code)
            if theorem and any(
                token in theorem.group(1).lower()
                for token in ("refinement", "related", "equivalent", "complete")
            ):
                proof_rules.add(f"{relative}::{theorem.group(1)}")
            constructor = _LEAN_CONSTRUCTOR_RE.match(code)
            if active_inductive is not None and constructor:
                lean_constructors.add(
                    f"{relative}::{active_inductive}.{constructor.group(1)}"
                )

    inventory = GenericityInventory(
        lean_constructors=tuple(sorted(lean_constructors)),
        proof_rules=tuple(sorted(proof_rules)),
        profile_branches=tuple(sorted(profile_branches)),
        special_case_conditionals=tuple(sorted(special_cases)),
        source_lines=source_lines,
    )
    return GenericityEvidence(
        current=inventory,
        baseline=baseline,
        forbidden_dispatch_hits=tuple(sorted(hits)),
    )


def load_genericity_baseline(path: Path) -> GenericityInventory:
    """Load a diagnostic inventory which has no proof authority."""

    path = Path(path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"invalid genericity baseline {path}: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise StageAInputError("genericity baseline must be a JSON object")
    if payload.get("format") != GENERICITY_BASELINE_FORMAT:
        raise StageAInputError("genericity baseline format is unsupported")
    inventory = payload.get("inventory")
    if not isinstance(inventory, Mapping):
        raise StageAInputError("genericity baseline inventory must be an object")
    return _inventory_from_payload(inventory)


def _inventory_from_payload(payload: Mapping[str, Any]) -> GenericityInventory:
    allowed = {
        "structural_shapes",
        "semantic_constructors",
        "lean_constructors",
        "proof_rules",
        "profile_branches",
        "special_case_conditionals",
        "source_lines",
    }
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise StageAInputError(
            f"genericity baseline inventory has unknown fields {unknown}"
        )

    def strings(field: str) -> tuple[str, ...]:
        value = payload.get(field, [])
        if not isinstance(value, list):
            raise StageAInputError(
                f"genericity baseline inventory {field} must be an array"
            )
        return tuple(value)

    return GenericityInventory(
        structural_shapes=strings("structural_shapes"),
        semantic_constructors=strings("semantic_constructors"),
        lean_constructors=strings("lean_constructors"),
        proof_rules=strings("proof_rules"),
        profile_branches=strings("profile_branches"),
        special_case_conditionals=strings("special_case_conditionals"),
        source_lines=payload.get("source_lines"),
    )


def _python_scopes(tree: ast.AST) -> Iterable[ast.AST]:
    yield tree
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            yield node


_PYTHON_SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)


def _walk_scope(scope: ast.AST) -> Iterable[ast.AST]:
    pending = [scope]
    while pending:
        node = pending.pop()
        yield node
        for child in ast.iter_child_nodes(node):
            if child is not scope and isinstance(child, _PYTHON_SCOPE_NODES):
                continue
            pending.append(child)


def _conditional_probes(
    scope: ast.AST,
) -> Iterable[tuple[ast.If | ast.IfExp | ast.Match, tuple[ast.AST, ...]]]:
    for node in _walk_scope(scope):
        if isinstance(node, (ast.If, ast.IfExp)):
            yield node, (node.test,)
        elif isinstance(node, ast.Match):
            probes: list[ast.AST] = [node.subject]
            for case in node.cases:
                probes.append(case.pattern)
                if case.guard is not None:
                    probes.append(case.guard)
            yield node, tuple(probes)


def _identity_aliases(scope: ast.AST) -> frozenset[str]:
    """Find local names derived from fixture identity selectors.

    This is intentionally a small syntactic taint analysis. It catches the
    common ``identity = payload[\"case_id\"]`` form without pretending to be a
    Python data-flow proof or flagging arbitrary string-valued branches.
    """

    assignments: list[tuple[set[str], ast.AST]] = []
    for node in _walk_scope(scope):
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            if node.value is None:
                continue
            if isinstance(node, ast.Assign):
                targets = {
                    name
                    for target in node.targets
                    for name in _assigned_names(target)
                }
            else:
                targets = {
                    name for name in _assigned_names(node.target)
                }
            assignments.append((targets, node.value))

    aliases: set[str] = set()
    changed = True
    while changed:
        changed = False
        for targets, value in assignments:
            value_names = {
                item.id for item in ast.walk(value) if isinstance(item, ast.Name)
            }
            if not (
                _selects_identity_field(value)
                or value_names & aliases
                or value_names & _FORBIDDEN_VARIABLE_NAMES
            ):
                continue
            before = len(aliases)
            aliases.update(targets)
            changed = changed or len(aliases) != before
    return frozenset(aliases)


def _assigned_names(target: ast.AST) -> Iterable[str]:
    if isinstance(target, ast.Name):
        yield target.id
    elif isinstance(target, (ast.List, ast.Tuple)):
        for element in target.elts:
            yield from _assigned_names(element)


def _selects_identity_field(node: ast.AST) -> bool:
    for item in ast.walk(node):
        if isinstance(item, ast.Subscript):
            value = _string_constant(item.slice)
            if value in _FORBIDDEN_FIELD_NAMES:
                return True
        if isinstance(item, ast.Call) and isinstance(item.func, ast.Attribute):
            if item.func.attr == "get" and item.args:
                value = _string_constant(item.args[0])
                if value in _FORBIDDEN_FIELD_NAMES:
                    return True
    return False


def _string_constant(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _stable_probe_key(probes: tuple[ast.AST, ...]) -> str:
    return "|".join(
        ast.dump(probe, annotate_fields=True, include_attributes=False)
        for probe in probes
    )


__all__ = [
    "GENERICITY_BASELINE_FORMAT",
    "load_genericity_baseline",
    "scan_acceptance_genericity",
]

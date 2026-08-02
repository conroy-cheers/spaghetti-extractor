"""Deterministic validation synthesis for normalized reconstruction contracts.

The solver boundary in this module is intentionally narrow.  It validates
explicit proposed output and control expressions in ``stage-a-semantic-ir-v1``
against reference expressions.  It does not parse, execute, or make a semantic
claim about arbitrary C source, generated adapters, or executable bytes.

Memory behavior is kept outside the straight-line claim checker.  Inferred
memory views are instead projected into concrete harness-case descriptors for
valid, faulting, and aliasing layouts.  Operations that need memory, external
responses, undefined-value policy, or x87 state therefore fail closed as an
``incomplete`` semantic claim.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from itertools import combinations
from typing import Any, Iterable, Mapping, Sequence

try:  # The project exposes solver support through its ``proof`` extra.
    import z3
except ImportError:  # pragma: no cover - exercised by callers without the extra
    z3 = None  # type: ignore[assignment]


VALIDATION_TRUST_BOUNDARY = (
    "only explicit normalized machine-IR output and control expressions are "
    "analyzed; arbitrary C source and executable behavior are outside this claim"
)

_WORD_BITS = 32
_WORD_MASK = (1 << _WORD_BITS) - 1
_BRANCH_OPS = frozenset(
    {"eq", "eq_bool", "ult32", "xor_bool", "not", "and_bool", "or_bool"}
)
_CONTROL_EXPRESSION_FIELDS = frozenset({"condition", "target", "value"})
_CONTROL_SCALAR_FIELDS = frozenset(
    {
        "kind",
        "target_rva",
        "true_target_rva",
        "false_target_rva",
        "target_rvas",
        "target_unit_ids",
    }
)


class ReconstructionValidationError(ValueError):
    """A validation input is not a finite normalized contract."""


class _UnsupportedExpression(Exception):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class SemanticClaimResult:
    """Result of an explicit output/control expression equivalence claim."""

    status: str
    checked_claims: tuple[str, ...]
    differing_claims: tuple[str, ...]
    counterexample_inputs: Mapping[str, int] | None
    reason_code: str | None
    detail: str
    trust_boundary: str = VALIDATION_TRUST_BOUNDARY

    def to_payload(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "checked_claims": list(self.checked_claims),
            "differing_claims": list(self.differing_claims),
            "counterexample_inputs": (
                None
                if self.counterexample_inputs is None
                else dict(sorted(self.counterexample_inputs.items()))
            ),
            "reason_code": self.reason_code,
            "detail": self.detail,
            "trust_boundary": self.trust_boundary,
        }


@dataclass(frozen=True)
class ValidationSynthesis:
    """Deterministic case inventory ready for a regional harness."""

    boundary_cases: tuple[Mapping[str, Any], ...]
    indirect_dispatch_cases: tuple[Mapping[str, Any], ...]
    memory_cases: tuple[Mapping[str, Any], ...]
    trust_boundary: str = VALIDATION_TRUST_BOUNDARY

    def to_payload(self) -> dict[str, Any]:
        return {
            "boundary_cases": [_json_copy(item) for item in self.boundary_cases],
            "indirect_dispatch_cases": [
                _json_copy(item) for item in self.indirect_dispatch_cases
            ],
            "memory_cases": [_json_copy(item) for item in self.memory_cases],
            "counts": {
                "boundary": len(self.boundary_cases),
                "indirect_dispatch": len(self.indirect_dispatch_cases),
                "memory": len(self.memory_cases),
            },
            "trust_boundary": self.trust_boundary,
        }


@dataclass
class _ExpressionFacts:
    widths: dict[str, int]
    constants: set[int]
    branches: dict[str, Any]


def synthesize_boundary_value_cases(
    expressions: Any,
    *,
    input_widths: Mapping[str, int] | None = None,
    branches: Sequence[Any] = (),
    solver_timeout_ms: int = 5_000,
) -> tuple[dict[str, Any], ...]:
    """Generate deterministic fixed-width boundary and branch cases.

    Inputs are discovered from ``reg``, ``flag``, and ``fs_base`` expression
    leaves.  Each input receives zero/one, signed boundaries, unsigned
    boundaries, and neighbors of every explicit ``const`` node.  Boolean
    expressions and ``ite`` conditions also contribute solver-selected true
    and false witnesses when the pure vocabulary can express them.
    """

    facts = _ExpressionFacts(widths={}, constants=set(), branches={})
    _collect_expression_facts(expressions, facts)
    for branch in branches:
        _collect_expression_facts(branch, facts)
        facts.branches.setdefault(_canonical_json(branch), branch)

    widths = dict(facts.widths)
    for name, width in sorted((input_widths or {}).items()):
        _validate_input_name(name)
        normalized_width = _validate_width(width, f"input {name!r}")
        existing = widths.get(name)
        if existing is not None and existing != normalized_width:
            raise ReconstructionValidationError(
                f"input {name!r} has conflicting widths {existing} and {normalized_width}"
            )
        widths[name] = normalized_width

    names = tuple(sorted(widths))
    cases: dict[tuple[tuple[str, int], ...], dict[str, Any]] = {}

    def add_case(values: Mapping[str, int], coverage: str) -> None:
        inputs = {
            name: int(values.get(name, 0)) & ((1 << widths[name]) - 1)
            for name in names
        }
        key = tuple(inputs.items())
        if key not in cases:
            cases[key] = {"inputs": inputs, "covers": set()}
        cases[key]["covers"].add(coverage)

    add_case({}, "all-inputs-zero")
    for name in names:
        width = widths[name]
        maximum = (1 << width) - 1
        sign = 1 << (width - 1)
        values = {0, 1, maximum}
        if maximum > 0:
            values.add(maximum - 1)
        values.update({sign - 1, sign})
        if sign < maximum:
            values.add(sign + 1)
        for constant in facts.constants:
            value = constant & maximum
            values.update({(value - 1) & maximum, value, (value + 1) & maximum})
        for value in sorted(values):
            add_case(
                {name: value},
                f"input:{name}:width-{width}:boundary-0x{value:x}",
            )

    for index, branch_key in enumerate(sorted(facts.branches)):
        branch = facts.branches[branch_key]
        for desired in (False, True):
            witness = _predicate_witness(
                branch,
                desired=desired,
                input_widths=widths,
                timeout_ms=solver_timeout_ms,
            )
            if witness is not None:
                add_case(
                    witness,
                    f"branch:{index:03d}:{'true' if desired else 'false'}",
                )

    result = []
    for item in cases.values():
        inputs = dict(item["inputs"])
        body = {
            "family": "boundary_value",
            "inputs": inputs,
            "covers": sorted(item["covers"]),
        }
        body["id"] = "boundary:" + _content_id(
            {"family": body["family"], "inputs": inputs}
        )
        result.append(body)
    return tuple(result)


def enumerate_finite_indirect_dispatch_cases(
    domain: Mapping[str, Any] | Sequence[Any],
    *,
    input_name: str = "indirect_target",
    input_width: int = 32,
) -> tuple[dict[str, Any], ...]:
    """Exhaustively expand a finite indirect-dispatch domain.

    Plain integer members bind the dispatch input directly to each target.
    Machine-IR jump-table target records may instead provide ``case_indices``
    (or ``selectors``/``dispatch_values``); every selector is then emitted with
    its associated target.  Ambiguous duplicate selectors are rejected.
    """

    _validate_input_name(input_name)
    width = _validate_width(input_width, "indirect dispatch input")
    rows = _domain_members(domain)
    if not rows:
        raise ReconstructionValidationError(
            "an exhaustive indirect-dispatch domain must not be empty"
        )

    expanded: dict[int, dict[str, Any]] = {}
    for index, raw in enumerate(rows):
        target, metadata, selectors = _indirect_member(raw, index=index)
        for selector in selectors:
            if selector < 0 or selector >= (1 << width):
                raise ReconstructionValidationError(
                    f"indirect selector {selector} does not fit width {width}"
                )
            comparable = {"target": target, "metadata": metadata}
            previous = expanded.get(selector)
            if previous is not None and _canonical_json(previous) != _canonical_json(
                comparable
            ):
                raise ReconstructionValidationError(
                    f"indirect selector {selector} maps to multiple targets"
                )
            expanded[selector] = comparable

    result = []
    for selector, item in sorted(expanded.items()):
        body = {
            "family": "indirect_dispatch",
            "inputs": {input_name: selector},
            "selector": selector,
            "target": _json_copy(item["target"]),
            "metadata": _json_copy(item["metadata"]),
        }
        body["id"] = "indirect:" + _content_id(body)
        result.append(body)
    return tuple(result)


def synthesize_memory_case_descriptors(
    memory_views: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    """Project inferred views into valid, fault, and alias harness layouts."""

    views = sorted(
        (_normalize_memory_view(view, index) for index, view in enumerate(memory_views)),
        key=lambda view: (view["id"], _canonical_json(view)),
    )
    identifiers = [str(view["id"]) for view in views]
    if len(set(identifiers)) != len(identifiers):
        raise ReconstructionValidationError("memory view ids must be unique")

    result: list[dict[str, Any]] = []
    for view in views:
        valid = {
            "family": "memory_layout",
            "scenario": "valid",
            "view_ids": [view["id"]],
            "placements": [
                {
                    "view_id": view["id"],
                    "mapping": "fully_mapped",
                    "base": _json_copy(view["base"]),
                    "length": _json_copy(view["length"]),
                }
            ],
            "expected": "no_memory_fault",
        }
        _append_case(result, "memory", valid)

        fault_positions: list[dict[str, Any]] = [
            {"kind": "byte_offset", "value": 0}
        ]
        length = view["length"]
        if length["kind"] == "constant" and int(length["bytes"]) > 1:
            fault_positions.append(
                {"kind": "byte_offset", "value": int(length["bytes"]) - 1}
            )
        elif length["kind"] == "expression":
            fault_positions.append(
                {
                    "kind": "final_byte",
                    "length_expression": length["expression"],
                }
            )
        for position in fault_positions:
            fault = {
                "family": "memory_layout",
                "scenario": "fault",
                "view_ids": [view["id"]],
                "placements": [
                    {
                        "view_id": view["id"],
                        "mapping": "unmapped_at",
                        "fault_position": position,
                        "base": _json_copy(view["base"]),
                        "length": _json_copy(view["length"]),
                    }
                ],
                "expected": "memory_fault",
            }
            _append_case(result, "memory", fault)

    for left, right in combinations(views, 2):
        exact = {
            "family": "memory_layout",
            "scenario": "alias_exact",
            "view_ids": [left["id"], right["id"]],
            "placements": [
                {
                    "relation": "same_base",
                    "left_view_id": left["id"],
                    "right_view_id": right["id"],
                }
            ],
            "expected": "preserve_ordered_memory_semantics",
        }
        _append_case(result, "memory", exact)

        if _can_partially_overlap(left) and _can_partially_overlap(right):
            partial = {
                "family": "memory_layout",
                "scenario": "alias_partial",
                "view_ids": [left["id"], right["id"]],
                "placements": [
                    {
                        "relation": "right_base_equals_left_base_plus",
                        "byte_offset": 1,
                        "left_view_id": left["id"],
                        "right_view_id": right["id"],
                    }
                ],
                "expected": "preserve_ordered_memory_semantics",
            }
            _append_case(result, "memory", partial)

    return tuple(result)


def synthesize_reconstruction_validation(
    *,
    expressions: Any,
    input_widths: Mapping[str, int] | None = None,
    branches: Sequence[Any] = (),
    indirect_domains: Sequence[Mapping[str, Any]] = (),
    memory_views: Sequence[Mapping[str, Any]] = (),
    solver_timeout_ms: int = 5_000,
) -> ValidationSynthesis:
    """Build one deterministic case inventory from normalized contract parts.

    Each indirect-domain item must contain ``domain`` and may name
    ``input_name`` and ``input_width``.  The explicit arguments keep this
    adapter independent of any one serialized regional-contract version.
    """

    boundary_cases = synthesize_boundary_value_cases(
        expressions,
        input_widths=input_widths,
        branches=branches,
        solver_timeout_ms=solver_timeout_ms,
    )
    indirect_cases: list[Mapping[str, Any]] = []
    for index, spec in enumerate(indirect_domains):
        if not isinstance(spec, Mapping) or "domain" not in spec:
            raise ReconstructionValidationError(
                f"indirect_domains[{index}] must contain a finite domain"
            )
        indirect_cases.extend(
            enumerate_finite_indirect_dispatch_cases(
                spec["domain"],
                input_name=str(spec.get("input_name", f"indirect_target_{index}")),
                input_width=int(spec.get("input_width", 32)),
            )
        )
    return ValidationSynthesis(
        boundary_cases=boundary_cases,
        indirect_dispatch_cases=tuple(indirect_cases),
        memory_cases=synthesize_memory_case_descriptors(memory_views),
    )


def check_straight_line_semantic_claim(
    reference_outputs: Mapping[str, Any] | Sequence[Mapping[str, Any]],
    proposed_outputs: Mapping[str, Any] | Sequence[Mapping[str, Any]],
    *,
    reference_control: Mapping[str, Any] | None = None,
    proposed_control: Mapping[str, Any] | None = None,
    input_widths: Mapping[str, int] | None = None,
    solver_timeout_ms: int = 5_000,
) -> SemanticClaimResult:
    """Prove or refute explicit straight-line output/control expressions.

    ``qualified`` means the expressions are equivalent for every fixed-width
    input admitted by ``input_widths``.  ``violated`` includes a deterministic,
    lexicographically minimized unsigned input assignment.  Unsupported or
    stateful expression forms, malformed claims, unavailable Z3, and solver
    ``unknown`` results are all reported as ``incomplete``.
    """

    if z3 is None:
        return _incomplete_result(
            "z3_unavailable",
            "Z3 is unavailable; install the project proof extra",
        )
    if isinstance(solver_timeout_ms, bool) or not isinstance(solver_timeout_ms, int):
        return _incomplete_result(
            "invalid_timeout", "solver_timeout_ms must be a positive integer"
        )
    if solver_timeout_ms <= 0:
        return _incomplete_result(
            "invalid_timeout", "solver_timeout_ms must be a positive integer"
        )

    try:
        widths = _normalize_input_widths(input_widths)
        expected = _normalize_outputs(reference_outputs, "reference outputs")
        proposed = _normalize_outputs(proposed_outputs, "proposed outputs")
        compiler = _Z3ExpressionCompiler(widths)
        differences: list[Any] = []
        labels: list[str] = []

        for name in sorted(set(expected) | set(proposed)):
            label = f"output:{name}"
            labels.append(label)
            if name not in expected or name not in proposed:
                differences.append(z3.BoolVal(True))
                continue
            left = compiler.compile(expected[name])
            right = compiler.compile(proposed[name])
            differences.append(left != right)

        control_differences, control_labels = _compile_control_claim(
            compiler, reference_control, proposed_control
        )
        differences.extend(control_differences)
        labels.extend(control_labels)
    except (ReconstructionValidationError, _UnsupportedExpression) as exc:
        code = (
            exc.code if isinstance(exc, _UnsupportedExpression) else "malformed_claim"
        )
        return _incomplete_result(code, str(exc))

    checked = tuple(labels)
    if not differences:
        return _incomplete_result(
            "empty_claim",
            "the claim contains no explicit output or control expressions",
            checked_claims=checked,
        )

    discrepancy = z3.Or(*differences)
    solver = z3.Solver()
    solver.set(timeout=solver_timeout_ms)
    solver.add(*compiler.constraints, discrepancy)
    outcome = solver.check()
    if outcome == z3.unsat:
        return SemanticClaimResult(
            status="qualified",
            checked_claims=checked,
            differing_claims=(),
            counterexample_inputs=None,
            reason_code=None,
            detail=(
                "Z3 proved the explicit output/control expressions equivalent "
                "over the declared fixed-width inputs"
            ),
        )
    if outcome != z3.sat:
        return _incomplete_result(
            "solver_unknown",
            f"Z3 could not decide the claim: {solver.reason_unknown()}",
            checked_claims=checked,
        )

    minimized = _minimized_model(
        compiler=compiler,
        predicate=discrepancy,
        timeout_ms=solver_timeout_ms,
    )
    if minimized is None:
        return _incomplete_result(
            "counterexample_minimization_unknown",
            "Z3 found a violation but could not minimize a concrete counterexample",
            checked_claims=checked,
        )
    model, concrete_inputs = minimized
    differing = tuple(
        label
        for label, difference in zip(labels, differences, strict=True)
        if z3.is_true(model.eval(difference, model_completion=True))
    )
    return SemanticClaimResult(
        status="violated",
        checked_claims=checked,
        differing_claims=differing,
        counterexample_inputs=concrete_inputs,
        reason_code="concrete_counterexample",
        detail="Z3 produced a minimized concrete input that violates the claim",
    )


def check_semantic_claim(
    reference_claim: Mapping[str, Any],
    proposed_claim: Mapping[str, Any],
    *,
    input_widths: Mapping[str, int] | None = None,
    solver_timeout_ms: int = 5_000,
) -> SemanticClaimResult:
    """Check structured ``outputs``/``control`` claims, never source text."""

    allowed = {"outputs", "control"}
    for label, claim in (("reference", reference_claim), ("proposed", proposed_claim)):
        if not isinstance(claim, Mapping):
            return _incomplete_result(
                "malformed_claim", f"{label} claim must be an object"
            )
        extras = sorted(str(key) for key in set(claim) - allowed)
        if extras:
            return _incomplete_result(
                "claim_outside_trust_boundary",
                f"{label} claim has unsupported fields: {extras}",
            )
    return check_straight_line_semantic_claim(
        reference_claim.get("outputs", {}),
        proposed_claim.get("outputs", {}),
        reference_control=reference_claim.get("control"),
        proposed_control=proposed_claim.get("control"),
        input_widths=input_widths,
        solver_timeout_ms=solver_timeout_ms,
    )


def _collect_expression_facts(value: Any, facts: _ExpressionFacts) -> set[str]:
    dependencies: set[str] = set()
    if isinstance(value, Mapping):
        op = value.get("op")
        if op == "reg" and isinstance(value.get("name"), str):
            name = str(value["name"])
            width = _fact_width(value.get("width", 32))
            _merge_fact_width(facts, name, width)
            dependencies.add(name)
        elif op == "flag" and isinstance(value.get("name"), str):
            name = str(value["name"])
            _merge_fact_width(facts, name, 1)
            dependencies.add(name)
        elif op == "fs_base":
            _merge_fact_width(facts, "fs_base", 32)
            dependencies.add("fs_base")
        elif op == "const" and _is_int(value.get("value")):
            facts.constants.add(int(value["value"]))

        args = value.get("args")
        if isinstance(args, list):
            for child in args:
                dependencies.update(_collect_expression_facts(child, facts))
            if op == "ite" and args:
                facts.branches.setdefault(_canonical_json(args[0]), args[0])
        for key, child in value.items():
            if key not in {"args", "op", "name", "width", "value"}:
                dependencies.update(_collect_expression_facts(child, facts))
        if op in _BRANCH_OPS:
            facts.branches.setdefault(_canonical_json(value), value)
    elif isinstance(value, (list, tuple)):
        for child in value:
            dependencies.update(_collect_expression_facts(child, facts))
    return dependencies


def _fact_width(value: Any) -> int:
    if not _is_int(value):
        return 32
    width = int(value)
    return width if 1 <= width <= 32 else 32


def _merge_fact_width(facts: _ExpressionFacts, name: str, width: int) -> None:
    existing = facts.widths.get(name)
    if existing is None:
        facts.widths[name] = width
    elif existing != width:
        raise ReconstructionValidationError(
            f"input {name!r} has conflicting inferred widths {existing} and {width}"
        )


def _predicate_witness(
    expression: Any,
    *,
    desired: bool,
    input_widths: Mapping[str, int],
    timeout_ms: int,
) -> dict[str, int] | None:
    if z3 is None:
        return None
    try:
        compiler = _Z3ExpressionCompiler(input_widths)
        value = compiler.compile(expression)
    except (ReconstructionValidationError, _UnsupportedExpression):
        return None
    predicate = (value != _bv(0)) if desired else (value == _bv(0))
    minimized = _minimized_model(
        compiler=compiler, predicate=predicate, timeout_ms=timeout_ms
    )
    return None if minimized is None else minimized[1]


def _domain_members(domain: Mapping[str, Any] | Sequence[Any]) -> list[Any]:
    if isinstance(domain, Mapping):
        for key in (
            "domain",
            "targets",
            "members",
            "checked_jump_table_targets",
        ):
            value = domain.get(key)
            if isinstance(value, list):
                return value
        raise ReconstructionValidationError(
            "indirect domain object must contain domain, targets, members, or "
            "checked_jump_table_targets"
        )
    if isinstance(domain, Sequence) and not isinstance(domain, (str, bytes, bytearray)):
        return list(domain)
    raise ReconstructionValidationError("indirect dispatch domain must be a finite array")


def _indirect_member(
    raw: Any, *, index: int
) -> tuple[dict[str, Any], dict[str, Any], tuple[int, ...]]:
    if _is_int(raw):
        value = int(raw)
        if not 0 <= value <= _WORD_MASK:
            raise ReconstructionValidationError(
                f"indirect domain member {index} is outside uint32"
            )
        return {"value": value, "target_rva": value}, {}, (value,)
    if not isinstance(raw, Mapping):
        raise ReconstructionValidationError(
            f"indirect domain member {index} must be an integer or object"
        )

    target_value: Any = None
    target_key: str | None = None
    for key in ("target_rva", "rva", "target", "value", "target_unit_id", "identity"):
        if key in raw:
            target_key = key
            target_value = raw[key]
            break
    if target_key is None or not isinstance(target_value, (str, int)) or isinstance(
        target_value, bool
    ):
        raise ReconstructionValidationError(
            f"indirect domain member {index} does not name a concrete target"
        )
    if isinstance(target_value, int) and not 0 <= target_value <= _WORD_MASK:
        raise ReconstructionValidationError(
            f"indirect domain target {target_value} is outside uint32"
        )

    target = {target_key: target_value}
    if isinstance(target_value, int) and target_key in {"rva", "target"}:
        target["target_rva"] = target_value
    for key in ("target_unit_id", "identity", "kind"):
        if key in raw and key not in target:
            target[key] = _json_copy(raw[key])

    selector_values: Any = None
    selector_key: str | None = None
    for key in ("case_indices", "selectors", "dispatch_values"):
        if key in raw:
            selector_key = key
            selector_values = raw[key]
            break
    if selector_key is None:
        if isinstance(target_value, int):
            selectors = (target_value,)
        else:
            raise ReconstructionValidationError(
                f"indirect domain member {index} needs finite selectors"
            )
    else:
        if not isinstance(selector_values, list) or not selector_values:
            raise ReconstructionValidationError(
                f"indirect domain member {index}.{selector_key} must be nonempty"
            )
        if any(not _is_int(item) for item in selector_values):
            raise ReconstructionValidationError(
                f"indirect domain member {index}.{selector_key} must contain integers"
            )
        selectors = tuple(sorted(set(int(item) for item in selector_values)))

    excluded = {
        "case_indices",
        "selectors",
        "dispatch_values",
        "target_rva",
        "rva",
        "target",
        "value",
        "target_unit_id",
        "identity",
        "kind",
    }
    metadata = {
        str(key): _json_copy(value)
        for key, value in sorted(raw.items(), key=lambda item: str(item[0]))
        if key not in excluded
    }
    return target, metadata, selectors


def _normalize_memory_view(view: Mapping[str, Any], index: int) -> dict[str, Any]:
    if not isinstance(view, Mapping):
        raise ReconstructionValidationError(f"memory view {index} must be an object")
    identity = view.get("id", f"memory:view-{index:02d}")
    if not isinstance(identity, str) or not identity:
        raise ReconstructionValidationError(f"memory view {index} has an invalid id")
    base = view.get("base_expression", view.get("address_expression"))
    if base is None:
        raise ReconstructionValidationError(f"memory view {identity!r} has no base")
    access = view.get("access")
    if access not in {"read", "write", "read_write"}:
        raise ReconstructionValidationError(
            f"memory view {identity!r} has unsupported access {access!r}"
        )
    byte_length = view.get("byte_length", view.get("width"))
    length_expression = view.get("length_expression")
    if byte_length is not None and length_expression is not None:
        raise ReconstructionValidationError(
            f"memory view {identity!r} has two length authorities"
        )
    if byte_length is not None:
        if not _is_int(byte_length) or int(byte_length) <= 0:
            raise ReconstructionValidationError(
                f"memory view {identity!r} byte length must be positive"
            )
        length = {"kind": "constant", "bytes": int(byte_length)}
    elif isinstance(length_expression, str) and length_expression:
        length = {"kind": "expression", "expression": length_expression}
    else:
        raise ReconstructionValidationError(
            f"memory view {identity!r} has no finite or symbolic length"
        )
    return {
        "id": identity,
        "base": _json_copy(base),
        "length": length,
        "access": access,
    }


def _can_partially_overlap(view: Mapping[str, Any]) -> bool:
    length = view["length"]
    return length["kind"] == "expression" or int(length["bytes"]) > 1


def _append_case(result: list[dict[str, Any]], prefix: str, body: dict[str, Any]) -> None:
    body["id"] = f"{prefix}:" + _content_id(body)
    result.append(body)


def _normalize_outputs(
    value: Mapping[str, Any] | Sequence[Mapping[str, Any]], context: str
) -> dict[str, Any]:
    if isinstance(value, Mapping):
        result = {}
        for raw_name, expression in value.items():
            if not isinstance(raw_name, str) or not raw_name:
                raise ReconstructionValidationError(
                    f"{context} names must be nonempty strings"
                )
            result[raw_name] = expression
        return result
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        result: dict[str, Any] = {}
        for index, item in enumerate(value):
            if not isinstance(item, Mapping):
                raise ReconstructionValidationError(
                    f"{context}[{index}] must be an object"
                )
            name = item.get("register", item.get("flag", item.get("name", item.get("id"))))
            if not isinstance(name, str) or not name:
                raise ReconstructionValidationError(
                    f"{context}[{index}] has no output name"
                )
            if name in result:
                raise ReconstructionValidationError(
                    f"{context} contains duplicate output {name!r}"
                )
            if "value" in item:
                expression = item["value"]
            elif "expression" in item:
                expression = item["expression"]
            else:
                raise ReconstructionValidationError(
                    f"{context}[{index}] has no explicit expression"
                )
            result[name] = expression
        return result
    raise ReconstructionValidationError(f"{context} must be an object or array")


def _compile_control_claim(
    compiler: "_Z3ExpressionCompiler",
    reference: Mapping[str, Any] | None,
    proposed: Mapping[str, Any] | None,
) -> tuple[list[Any], list[str]]:
    if reference is None and proposed is None:
        return [], []
    if reference is None or proposed is None:
        return [z3.BoolVal(True)], ["control:presence"]
    if not isinstance(reference, Mapping) or not isinstance(proposed, Mapping):
        raise ReconstructionValidationError("control claims must be objects or null")
    unsupported = (set(reference) | set(proposed)) - (
        _CONTROL_EXPRESSION_FIELDS | _CONTROL_SCALAR_FIELDS
    )
    if unsupported:
        raise _UnsupportedExpression(
            "unsupported_control_field",
            f"unsupported explicit control fields: {sorted(str(item) for item in unsupported)}",
        )

    differences = []
    labels = []
    for field in sorted(set(reference) | set(proposed)):
        label = f"control:{field}"
        labels.append(label)
        if field not in reference or field not in proposed:
            differences.append(z3.BoolVal(True))
        elif field in _CONTROL_EXPRESSION_FIELDS:
            differences.append(
                compiler.compile(reference[field]) != compiler.compile(proposed[field])
            )
        else:
            differences.append(
                z3.BoolVal(
                    _canonical_json(reference[field]) != _canonical_json(proposed[field])
                )
            )
    return differences, labels


class _Z3ExpressionCompiler:
    def __init__(self, input_widths: Mapping[str, int]) -> None:
        self.input_widths = dict(input_widths)
        self.variables: dict[str, Any] = {}
        self.widths: dict[str, int] = {}
        self.constraints: list[Any] = []

    def compile(self, raw: Any) -> Any:
        if isinstance(raw, bool):
            return _bv(1 if raw else 0)
        if _is_int(raw):
            return _bv(int(raw))
        if not isinstance(raw, Mapping):
            raise _UnsupportedExpression(
                "malformed_expression",
                f"expression leaf {raw!r} is not normalized machine IR",
            )
        op = raw.get("op")
        if not isinstance(op, str) or not op:
            raise _UnsupportedExpression(
                "malformed_expression", "expression object has no operation"
            )
        if op == "const":
            value = raw.get("value")
            if not _is_int(value):
                raise _UnsupportedExpression(
                    "malformed_expression", "const value must be an integer"
                )
            width = raw.get("width", 32)
            _validate_expression_width(width, "const")
            return _bv(int(value))
        if op == "reg":
            name = raw.get("name")
            if not isinstance(name, str) or not name:
                raise _UnsupportedExpression(
                    "malformed_expression", "reg expression has no name"
                )
            width = _validate_expression_width(raw.get("width", 32), "reg")
            return self._variable(name, width)
        if op == "flag":
            name = raw.get("name")
            if not isinstance(name, str) or not name:
                raise _UnsupportedExpression(
                    "malformed_expression", "flag expression has no name"
                )
            return self._variable(name, 1)
        if op == "fs_base":
            return self._variable("fs_base", 32)
        if op in {"true", "false"}:
            return _bv(op == "true")
        if op in {
            "undefined_bv",
            "undefined_flag",
            "call_response",
            "call_flag",
            "load",
        } or op.startswith("fpu_"):
            raise _UnsupportedExpression(
                "stateful_expression_unsupported",
                f"operation {op!r} is outside the straight-line claim boundary",
            )
        if op in {"shift_cf", "shift_of"}:
            return self._compile_shift_flag(op, raw)

        args = raw.get("args")
        if not isinstance(args, list):
            raise _UnsupportedExpression(
                "malformed_expression", f"operation {op!r} args must be an array"
            )
        values = [self.compile(arg) for arg in args]
        return self._compile_operation(op, args, values)

    def _variable(self, name: str, inferred_width: int) -> Any:
        _validate_input_name(name)
        declared = self.input_widths.get(name, inferred_width)
        if name in self.widths and self.widths[name] != declared:
            raise _UnsupportedExpression(
                "input_width_conflict",
                f"input {name!r} has conflicting widths {self.widths[name]} and {declared}",
            )
        if inferred_width != declared and inferred_width != 32:
            raise _UnsupportedExpression(
                "input_width_conflict",
                f"input {name!r} is a {inferred_width}-bit leaf, not {declared}-bit",
            )
        if name not in self.variables:
            variable = z3.BitVec(f"machine-ir-input::{name}", _WORD_BITS)
            self.variables[name] = variable
            self.widths[name] = declared
            if declared < _WORD_BITS:
                self.constraints.append(z3.ULE(variable, _bv((1 << declared) - 1)))
        return self.variables[name]

    def _compile_operation(
        self, op: str, raw_args: Sequence[Any], args: Sequence[Any]
    ) -> Any:
        arities: dict[str, int | tuple[int, int]] = {
            "sub32": 2,
            "ult32": 2,
            "eq": 2,
            "xor_bool": 2,
            "eq_bool": 2,
            "add32": (2, 4),
            "mul32": (2, 4),
            "xor32": (2, 4),
            "and32": (2, 4),
            "or32": (2, 4),
            "not32": 1,
            "neg32": 1,
            "shl32": 2,
            "lshr32": 2,
            "sar": 3,
            "sign_extend": 2,
            "ite": 3,
            "msb": (1, 2),
            "not": 1,
            "and_bool": (1, 5),
            "or_bool": (1, 5),
            "parity": 2,
            "bool_to_bit": 1,
            "add_overflow": 4,
            "sub_overflow": 4,
            "imul_low32": 2,
            "mul_low32": 2,
            "imul_high32": 2,
            "mul_high32": 2,
            "imul_overflow": 5,
            "mul_carry": 4,
            "udiv_quot32": 3,
            "udiv_rem32": 3,
            "udiv_valid32": 3,
            "bsr_index": 2,
            "tzcnt": 2,
            "sbb_borrow": 5,
            "sbb_overflow": 5,
            "adc_carry": 5,
            "adc_overflow": 5,
        }
        expected = arities.get(op)
        if expected is None:
            raise _UnsupportedExpression(
                "unsupported_operation", f"unsupported semantic operation {op!r}"
            )
        if not _arity_ok(len(args), expected):
            raise _UnsupportedExpression(
                "malformed_expression",
                f"operation {op!r} has {len(args)} arguments, expected {expected}",
            )

        if op == "sub32":
            return args[0] - args[1]
        if op == "ult32":
            return _bool_word(z3.ULT(args[0], args[1]))
        if op in {"eq", "eq_bool"}:
            return _bool_word(args[0] == args[1])
        if op == "xor_bool":
            return _bool_word(args[0] != args[1])
        if op == "add32":
            return _fold(args, lambda left, right: left + right)
        if op == "mul32":
            return _fold(args, lambda left, right: left * right)
        if op == "xor32":
            return _fold(args, lambda left, right: left ^ right)
        if op == "and32":
            return _fold(args, lambda left, right: left & right)
        if op == "or32":
            return _fold(args, lambda left, right: left | right)
        if op == "not32":
            return ~args[0]
        if op == "neg32":
            return -args[0]
        if op == "shl32":
            return args[0] << (args[1] & _bv(31))
        if op == "lshr32":
            return z3.LShR(args[0], args[1] & _bv(31))
        if op == "sar":
            width = _concrete_width(raw_args[0], "sar")
            extended = _sign_extend_low(args[1], width)
            return (extended >> (args[2] & _bv(31))) & _bv(_width_mask(width))
        if op == "sign_extend":
            width = _concrete_width(raw_args[0], "sign_extend")
            return _sign_extend_low(args[1], width)
        if op == "ite":
            return z3.If(args[0] != _bv(0), args[1], args[2])
        if op == "msb":
            width = 32 if len(args) == 1 else _concrete_width(raw_args[0], "msb")
            value = args[0] if len(args) == 1 else args[1]
            return z3.ZeroExt(31, z3.Extract(width - 1, width - 1, value))
        if op == "not":
            return _bool_word(args[0] == _bv(0))
        if op == "and_bool":
            return _bool_word(z3.And(*(arg != _bv(0) for arg in args)))
        if op == "or_bool":
            return _bool_word(z3.Or(*(arg != _bv(0) for arg in args)))
        if op == "parity":
            return _parity_word(args[1])
        if op == "bool_to_bit":
            return _bool_word(args[0] != _bv(0))
        if op in {"add_overflow", "sub_overflow"}:
            width = _concrete_width(raw_args[0], op)
            left, right, result = args[1], args[2], args[3]
            sign = _bv(1 << (width - 1))
            bits = (
                (~(left ^ right) & (left ^ result))
                if op == "add_overflow"
                else ((left ^ right) & (left ^ result))
            )
            return _bool_word((bits & sign) != _bv(0))
        if op in {"imul_low32", "mul_low32"}:
            return args[0] * args[1]
        if op == "imul_high32":
            product = z3.SignExt(32, args[0]) * z3.SignExt(32, args[1])
            return z3.Extract(63, 32, product)
        if op == "mul_high32":
            product = z3.ZeroExt(32, args[0]) * z3.ZeroExt(32, args[1])
            return z3.Extract(63, 32, product)
        if op == "imul_overflow":
            expected_high = z3.If(
                z3.Extract(31, 31, args[3]) == z3.BitVecVal(1, 1),
                _bv(_WORD_MASK),
                _bv(0),
            )
            return _bool_word(args[4] != expected_high)
        if op == "mul_carry":
            return _bool_word(args[3] != _bv(0))
        if op in {"udiv_quot32", "udiv_rem32", "udiv_valid32"}:
            high, low, divisor = args
            valid = z3.And(divisor != _bv(0), z3.ULT(high, divisor))
            if op == "udiv_valid32":
                return _bool_word(valid)
            dividend = z3.Concat(high, low)
            divisor64 = z3.ZeroExt(32, divisor)
            if op == "udiv_quot32":
                computed = z3.Extract(31, 0, z3.UDiv(dividend, divisor64))
            else:
                computed = z3.Extract(31, 0, z3.URem(dividend, divisor64))
            return z3.If(valid, computed, _bv(0))
        if op == "bsr_index":
            return _bit_scan_reverse(args[-1])
        if op == "tzcnt":
            return _trailing_zero_count(args[-1])
        if op == "sbb_borrow":
            width = _concrete_width(raw_args[0], op)
            mask = _bv(_width_mask(width))
            left = z3.ZeroExt(1, args[1] & mask)
            right = z3.ZeroExt(1, args[2] & mask)
            carry = z3.ZeroExt(1, args[3] & _bv(1))
            return _bool_word(z3.ULT(left, right + carry))
        if op == "sbb_overflow":
            width = _concrete_width(raw_args[0], op)
            mask = _bv(_width_mask(width))
            sign = _bv(1 << (width - 1))
            left, right, result = args[1] & mask, args[2] & mask, args[4] & mask
            return _bool_word(((left ^ right) & (left ^ result) & sign) != _bv(0))
        if op in {"adc_carry", "adc_overflow"}:
            return _compile_adc(op, raw_args, args)
        raise AssertionError(f"unhandled supported operation {op}")

    def _compile_shift_flag(self, op: str, raw: Mapping[str, Any]) -> Any:
        args = raw.get("args")
        expected = 4 if op == "shift_cf" else 5
        if not isinstance(args, list) or len(args) != expected:
            raise _UnsupportedExpression(
                "malformed_expression", f"operation {op!r} requires {expected} arguments"
            )
        kind = args[0]
        if kind not in {"shl", "sal", "shr", "sar", "shld", "shrd"}:
            raise _UnsupportedExpression(
                "malformed_expression", f"operation {op!r} has unsupported shift kind"
            )
        width = _concrete_width(args[1], op)
        value = self.compile(args[2])
        count = self.compile(args[3]) & _bv(31)
        left_kind = kind in {"shl", "sal", "shld"}
        carry = _bv(0)
        for amount in range(1, width + 1):
            bit = width - amount if left_kind else amount - 1
            selected = z3.ZeroExt(31, z3.Extract(bit, bit, value))
            carry = z3.If(count == _bv(amount), selected, carry)
        if op == "shift_cf":
            return carry
        result = self.compile(args[4])
        overflow = _bv(0)
        if left_kind:
            result_msb = z3.ZeroExt(31, z3.Extract(width - 1, width - 1, result))
            overflow = result_msb ^ carry
        elif kind in {"shr", "shrd"}:
            overflow = z3.ZeroExt(31, z3.Extract(width - 1, width - 1, value))
        return z3.If(count == _bv(1), overflow, _bv(0))


def _compile_adc(op: str, raw_args: Sequence[Any], args: Sequence[Any]) -> Any:
    width = _concrete_width(raw_args[0], op)
    mask_value = _width_mask(width)
    mask = _bv(mask_value)
    left, right = args[1] & mask, args[2] & mask
    carry = args[3] & _bv(1)
    result = args[4] & mask
    wide_sum = z3.ZeroExt(1, left) + z3.ZeroExt(1, right) + z3.ZeroExt(1, carry)
    valid = z3.And(
        z3.ULE(args[3], _bv(1)),
        z3.Extract(31, 0, wide_sum) & mask == result,
    )
    if op == "adc_carry":
        carry_out = z3.ZeroExt(31, z3.Extract(width, width, wide_sum))
        return z3.If(valid, carry_out, _bv(0))
    sign = _bv(1 << (width - 1))
    overflow = _bool_word((~(left ^ right) & (left ^ result) & sign) != _bv(0))
    return z3.If(valid, overflow, _bv(0))


def _minimized_model(
    *, compiler: _Z3ExpressionCompiler, predicate: Any, timeout_ms: int
) -> tuple[Any, dict[str, int]] | None:
    optimizer = z3.Optimize()
    optimizer.set(timeout=timeout_ms)
    optimizer.set(priority="lex")
    optimizer.add(*compiler.constraints, predicate)
    ordered = sorted(compiler.variables)
    if ordered:
        optimizer.minimize(
            z3.Sum(
                *(z3.If(compiler.variables[name] == _bv(0), 0, 1) for name in ordered)
            )
        )
        for name in ordered:
            optimizer.minimize(z3.BV2Int(compiler.variables[name], is_signed=False))
    outcome = optimizer.check()
    if outcome != z3.sat:
        return None
    model = optimizer.model()
    inputs = {
        name: model.eval(compiler.variables[name], model_completion=True).as_long()
        for name in ordered
    }
    return model, inputs


def _normalize_input_widths(value: Mapping[str, int] | None) -> dict[str, int]:
    result = {}
    for name, width in sorted((value or {}).items()):
        _validate_input_name(name)
        result[name] = _validate_width(width, f"input {name!r}")
    return result


def _validate_input_name(name: Any) -> None:
    if not isinstance(name, str) or not name:
        raise ReconstructionValidationError("input names must be nonempty strings")


def _validate_width(value: Any, context: str) -> int:
    if not _is_int(value) or not 1 <= int(value) <= _WORD_BITS:
        raise ReconstructionValidationError(
            f"{context} width must be between 1 and {_WORD_BITS}"
        )
    return int(value)


def _validate_expression_width(value: Any, op: str) -> int:
    if not _is_int(value) or not 1 <= int(value) <= _WORD_BITS:
        raise _UnsupportedExpression(
            "malformed_expression", f"operation {op!r} has invalid width {value!r}"
        )
    return int(value)


def _concrete_width(value: Any, op: str) -> int:
    if _is_int(value):
        width = int(value)
    elif (
        isinstance(value, Mapping)
        and value.get("op") == "const"
        and _is_int(value.get("value"))
    ):
        width = int(value["value"])
    else:
        raise _UnsupportedExpression(
            "nonconstant_width_unsupported",
            f"operation {op!r} requires a concrete bit width",
        )
    if not 1 <= width <= _WORD_BITS:
        raise _UnsupportedExpression(
            "malformed_expression", f"operation {op!r} has invalid width {width}"
        )
    return width


def _arity_ok(actual: int, expected: int | tuple[int, int]) -> bool:
    if isinstance(expected, int):
        return actual == expected
    return expected[0] <= actual <= expected[1]


def _fold(values: Sequence[Any], operation: Any) -> Any:
    result = values[0]
    for value in values[1:]:
        result = operation(result, value)
    return result


def _sign_extend_low(value: Any, width: int) -> Any:
    if width == _WORD_BITS:
        return value
    return z3.SignExt(_WORD_BITS - width, z3.Extract(width - 1, 0, value))


def _parity_word(value: Any) -> Any:
    bits = [z3.Extract(index, index, value) == 1 for index in range(8)]
    odd = bits[0]
    for bit in bits[1:]:
        odd = z3.Xor(odd, bit)
    return _bool_word(z3.Not(odd))


def _bit_scan_reverse(value: Any) -> Any:
    result = _bv(0)
    for index in range(_WORD_BITS):
        result = z3.If(z3.Extract(index, index, value) == 1, _bv(index), result)
    return result


def _trailing_zero_count(value: Any) -> Any:
    result = _bv(_WORD_BITS)
    for index in range(_WORD_BITS - 1, -1, -1):
        result = z3.If(z3.Extract(index, index, value) == 1, _bv(index), result)
    return result


def _bool_word(condition: Any) -> Any:
    return z3.If(condition, _bv(1), _bv(0))


def _bv(value: int | bool) -> Any:
    return z3.BitVecVal(int(value) & _WORD_MASK, _WORD_BITS)


def _width_mask(width: int) -> int:
    return (1 << width) - 1


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _incomplete_result(
    reason_code: str,
    detail: str,
    *,
    checked_claims: tuple[str, ...] = (),
) -> SemanticClaimResult:
    return SemanticClaimResult(
        status="incomplete",
        checked_claims=checked_claims,
        differing_claims=(),
        counterexample_inputs=None,
        reason_code=reason_code,
        detail=detail,
    )


def _content_id(value: Any) -> str:
    return sha256(_canonical_json(value).encode("ascii")).hexdigest()[:20]


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _json_copy(value: Any) -> Any:
    return json.loads(_canonical_json(value))


__all__ = [
    "ReconstructionValidationError",
    "SemanticClaimResult",
    "VALIDATION_TRUST_BOUNDARY",
    "ValidationSynthesis",
    "check_semantic_claim",
    "check_straight_line_semantic_claim",
    "enumerate_finite_indirect_dispatch_cases",
    "synthesize_boundary_value_cases",
    "synthesize_memory_case_descriptors",
    "synthesize_reconstruction_validation",
]

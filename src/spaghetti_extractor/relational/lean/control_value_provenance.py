"""Emit fail-closed local Lean replay certificates for control-value provenance.

The JSON document does not carry PE facts, imports, relocations, code targets,
or call-preservation assertions.  It names a generated canonical
``StaticProofContext`` instead; Lean reparses and checks that context.  Accepted
output proves local decoder/replay facts only, never end-to-end authority.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Literal

from ...errors import StageAInputError
from .expressions import _lean_semantic_bool_expr


CONTROL_VALUE_PROVENANCE_FORMAT = (
    "stage-a-control-value-provenance-local-certificate-v2"
)
CONTROL_VALUE_PROVENANCE_LEAN_FILENAME = (
    "GeneratedRelationalControlValueProvenance.lean"
)

_REGISTERS = {
    name: f".{name}"
    for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
}
_BLOCKERS = {
    "unknown": ".unknown",
    "unmodelled_alias": ".unmodelledAlias",
    "unmodelled_write": ".unmodelledWrite",
    "unmodelled_call": ".unmodelledCall",
    "ungrounded_claim": ".ungroundedClaim",
    "disjunction_overflow": ".disjunctionOverflow",
}
_EDGE_KINDS = {
    "direct": ".direct",
    "branch_taken": ".branchTaken",
    "branch_fallthrough": ".branchFallthrough",
    "call_return": ".callReturn",
}
_QUALIFIED_NAME = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)+\Z"
)
_ROOT_FIELDS = frozenset({
    "format",
    "context",
    "finite_disjunction_budget",
    "locations",
    "static_seeds",
    "regions",
    "edges",
    "call_references",
    "branch_guards",
    "sccs",
    "component_order",
})


class ControlValueProvenanceGenerationError(StageAInputError):
    """The input is outside the reviewed local-certificate schema."""


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ControlValueProvenanceGenerationError(
            f"{context} must be a JSON object"
        )
    if any(not isinstance(key, str) for key in value):
        raise ControlValueProvenanceGenerationError(
            f"{context} field names must be strings"
        )
    return value


def _fields(
    value: Mapping[str, Any], expected: frozenset[str], context: str
) -> None:
    missing = sorted(expected - set(value))
    unexpected = sorted(set(value) - expected)
    if missing:
        raise ControlValueProvenanceGenerationError(
            f"{context} is missing required fields: {', '.join(missing)}"
        )
    if unexpected:
        raise ControlValueProvenanceGenerationError(
            f"{context} has unexpected fields: {', '.join(unexpected)}"
        )


def _list(value: object, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise ControlValueProvenanceGenerationError(
            f"{context} must be a JSON array"
        )
    return value


def _nat(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ControlValueProvenanceGenerationError(
            f"{context} must be a natural number"
        )
    return value


def _word(value: object, context: str) -> int:
    result = _nat(value, context)
    if result >= 2**32:
        raise ControlValueProvenanceGenerationError(
            f"{context} must fit in a 32-bit word"
        )
    return result


def _bool(value: object, context: str) -> bool:
    if not isinstance(value, bool):
        raise ControlValueProvenanceGenerationError(
            f"{context} must be Boolean"
        )
    return value


def _string(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ControlValueProvenanceGenerationError(
            f"{context} must be a non-empty string"
        )
    return value


def _qualified_name(value: object, context: str) -> str:
    name = _string(value, context)
    if _QUALIFIED_NAME.fullmatch(name) is None:
        raise ControlValueProvenanceGenerationError(
            f"{context} must be a qualified Lean name"
        )
    return name


def _lean_list(rows: list[str]) -> str:
    return "[" + ", ".join(rows) + "]"


def _lean_bool(value: bool) -> str:
    return "true" if value else "false"


def _lean_register(value: object, context: str) -> str:
    register = _string(value, context)
    try:
        return _REGISTERS[register]
    except KeyError as error:
        raise ControlValueProvenanceGenerationError(
            f"{context} is not an IA-32 general register"
        ) from error


def _lean_adjustment(value: object, context: str) -> str:
    adjustment = _object(value, context)
    kind = _string(adjustment.get("kind"), f"{context}.kind")
    if kind == "identity":
        _fields(adjustment, frozenset({"kind"}), context)
        return ".identity"
    if kind in {"add", "subtract"}:
        _fields(adjustment, frozenset({"kind", "amount"}), context)
        return f".{kind} {_nat(adjustment['amount'], f'{context}.amount')}"
    raise ControlValueProvenanceGenerationError(
        f"{context}.kind is unsupported"
    )


def _lean_location(value: object, context: str) -> str:
    location = _object(value, context)
    kind = _string(location.get("kind"), f"{context}.kind")
    if kind == "register":
        _fields(location, frozenset({"kind", "register"}), context)
        return ".register " + _lean_register(
            location["register"], f"{context}.register"
        )
    if kind == "frame_word":
        _fields(
            location,
            frozenset({"kind", "base", "adjustment"}),
            context,
        )
        return (
            ".frameWord "
            + _lean_register(location["base"], f"{context}.base")
            + " ("
            + _lean_adjustment(
                location["adjustment"], f"{context}.adjustment"
            )
            + ")"
        )
    if kind == "static_word":
        _fields(location, frozenset({"kind", "address"}), context)
        return f".staticWord {_word(location['address'], f'{context}.address')}"
    raise ControlValueProvenanceGenerationError(
        f"{context}.kind is unsupported"
    )


def _lean_location_pair(value: object, context: str) -> str:
    pair = _object(value, context)
    _fields(pair, frozenset({"id", "original", "candidate"}), context)
    return (
        "{ id := "
        + str(_nat(pair["id"], f"{context}.id"))
        + ", original := "
        + _lean_location(pair["original"], f"{context}.original")
        + ", candidate := "
        + _lean_location(pair["candidate"], f"{context}.candidate")
        + " }"
    )


def _lean_byte_string(value: object, context: str) -> str:
    text = _string(value, context)
    return _lean_list([str(byte) for byte in text.encode("utf-8")])


def _lean_import_identity(value: object, context: str) -> str:
    identity = _object(value, context)
    has_symbol = "symbol" in identity
    has_ordinal = "ordinal" in identity
    if has_symbol == has_ordinal:
        raise ControlValueProvenanceGenerationError(
            f"{context} must contain exactly one of symbol or ordinal"
        )
    _fields(
        identity,
        frozenset({"dll", "symbol" if has_symbol else "ordinal"}),
        context,
    )
    if has_symbol:
        name = ".symbol " + _lean_byte_string(
            identity["symbol"], f"{context}.symbol"
        )
    else:
        name = f".ordinal {_nat(identity['ordinal'], f'{context}.ordinal')}"
    return (
        "{ dll := "
        + _lean_byte_string(identity["dll"], f"{context}.dll")
        + ", name := "
        + name
        + " }"
    )


def _lean_atom(value: object, context: str) -> str:
    atom = _object(value, context)
    kind = _string(atom.get("kind"), f"{context}.kind")
    if kind == "zero":
        _fields(atom, frozenset({"kind"}), context)
        return ".exactBits 0"
    if kind == "code_target":
        _fields(atom, frozenset({"kind", "target_id"}), context)
        return (
            f".staticCodeTarget "
            f"{_nat(atom['target_id'], f'{context}.target_id')} 0"
        )
    if kind == "import":
        _fields(atom, frozenset({"kind", "identity"}), context)
        return ".importTarget (" + _lean_import_identity(
            atom["identity"], f"{context}.identity"
        ) + ")"
    raise ControlValueProvenanceGenerationError(
        f"{context}.kind is unsupported"
    )


def _lean_value(value: object, context: str) -> str:
    provenance = _object(value, context)
    _fields(provenance, frozenset({"atoms", "blockers"}), context)
    atoms = [
        _lean_atom(row, f"{context}.atoms[{index}]")
        for index, row in enumerate(_list(provenance["atoms"], f"{context}.atoms"))
    ]
    blockers = []
    for index, row in enumerate(
        _list(provenance["blockers"], f"{context}.blockers")
    ):
        blocker = _string(row, f"{context}.blockers[{index}]")
        try:
            blockers.append(_BLOCKERS[blocker])
        except KeyError as error:
            raise ControlValueProvenanceGenerationError(
                f"{context}.blockers[{index}] is unsupported"
            ) from error
    return f"{{ atoms := {_lean_list(atoms)}, blockers := {_lean_list(blockers)} }}"


def _lean_state(value: object, context: str) -> str:
    rows = []
    for index, raw in enumerate(_list(value, context)):
        row_context = f"{context}[{index}]"
        row = _object(raw, row_context)
        _fields(row, frozenset({"location_id", "value"}), row_context)
        rows.append(
            "{ locationId := "
            + str(_nat(row["location_id"], f"{row_context}.location_id"))
            + ", value := "
            + _lean_value(row["value"], f"{row_context}.value")
            + " }"
        )
    return _lean_list(rows)


def _lean_optional_state(value: object, context: str) -> str:
    return "none" if value is None else "some " + _lean_state(value, context)


def _lean_bytes(value: object, context: str) -> str:
    rows = []
    for index, raw in enumerate(_list(value, context)):
        byte = _nat(raw, f"{context}[{index}]")
        if byte >= 256:
            raise ControlValueProvenanceGenerationError(
                f"{context}[{index}] must be a byte"
            )
        rows.append(str(byte))
    return _lean_list(rows)


def _lean_span(value: object, context: str) -> str:
    span = _object(value, context)
    _fields(span, frozenset({"start", "size"}), context)
    return (
        "{ start := "
        + str(_word(span["start"], f"{context}.start"))
        + ", size := "
        + str(_nat(span["size"], f"{context}.size"))
        + " }"
    )


def _lean_static_seed(value: object, context: str) -> str:
    seed = _object(value, context)
    _fields(seed, frozenset({"id", "location_id", "atom"}), context)
    return (
        "{ id := "
        + str(_nat(seed["id"], f"{context}.id"))
        + ", locationId := "
        + str(_nat(seed["location_id"], f"{context}.location_id"))
        + ", atom := "
        + _lean_atom(seed["atom"], f"{context}.atom")
        + " }"
    )


def _lean_action(value: object, context: str) -> str:
    action = _object(value, context)
    kind = _string(action.get("kind"), f"{context}.kind")
    if kind == "seed":
        _fields(action, frozenset({"kind", "output_id", "atom"}), context)
        return (
            ".seed "
            + str(_nat(action["output_id"], f"{context}.output_id"))
            + " ("
            + _lean_atom(action["atom"], f"{context}.atom")
            + ")"
        )
    if kind == "assign":
        _fields(
            action,
            frozenset({"kind", "output_id", "input_id"}),
            context,
        )
        return (
            ".assign "
            + str(_nat(action["output_id"], f"{context}.output_id"))
            + " "
            + str(_nat(action["input_id"], f"{context}.input_id"))
        )
    raise ControlValueProvenanceGenerationError(
        f"{context}.kind is unsupported"
    )


def _lean_region(value: object, context: str) -> str:
    region = _object(value, context)
    _fields(
        region,
        frozenset({
            "id",
            "entry",
            "target_id",
            "original_span",
            "candidate_span",
            "original_bytes",
            "candidate_bytes",
            "actions",
            "input",
            "output",
        }),
        context,
    )
    actions = [
        _lean_action(item, f"{context}.actions[{index}]")
        for index, item in enumerate(_list(region["actions"], f"{context}.actions"))
    ]
    return (
        "{ id := "
        + str(_nat(region["id"], f"{context}.id"))
        + ", entry := "
        + _lean_bool(_bool(region["entry"], f"{context}.entry"))
        + ", targetId := "
        + str(_nat(region["target_id"], f"{context}.target_id"))
        + ", originalSpan := "
        + _lean_span(region["original_span"], f"{context}.original_span")
        + ", candidateSpan := "
        + _lean_span(region["candidate_span"], f"{context}.candidate_span")
        + ", originalBytes := "
        + _lean_bytes(region["original_bytes"], f"{context}.original_bytes")
        + ", candidateBytes := "
        + _lean_bytes(region["candidate_bytes"], f"{context}.candidate_bytes")
        + ", actions := "
        + _lean_list(actions)
        + ", input := "
        + _lean_optional_state(region["input"], f"{context}.input")
        + ", output := "
        + _lean_optional_state(region["output"], f"{context}.output")
        + " }"
    )


def _lean_edge(value: object, context: str) -> str:
    edge = _object(value, context)
    _fields(
        edge,
        frozenset({
            "id",
            "source_region",
            "target_region",
            "kind",
            "call_reference_id",
        }),
        context,
    )
    kind = _string(edge["kind"], f"{context}.kind")
    try:
        lean_kind = _EDGE_KINDS[kind]
    except KeyError as error:
        raise ControlValueProvenanceGenerationError(
            f"{context}.kind is unsupported"
        ) from error
    reference = edge["call_reference_id"]
    reference_literal = (
        "none"
        if reference is None
        else "some " + str(_nat(reference, f"{context}.call_reference_id"))
    )
    return (
        "{ id := "
        + str(_nat(edge["id"], f"{context}.id"))
        + ", sourceRegion := "
        + str(_nat(edge["source_region"], f"{context}.source_region"))
        + ", targetRegion := "
        + str(_nat(edge["target_region"], f"{context}.target_region"))
        + ", kind := "
        + lean_kind
        + ", callReferenceId := "
        + reference_literal
        + " }"
    )


def _lean_call_reference(value: object, context: str) -> str:
    reference = _object(value, context)
    _fields(
        reference,
        frozenset({
            "id",
            "region_id",
            "external_site_id",
            "machine_contract_id",
        }),
        context,
    )
    return (
        "{ id := "
        + str(_nat(reference["id"], f"{context}.id"))
        + ", regionId := "
        + str(_nat(reference["region_id"], f"{context}.region_id"))
        + ", externalSiteId := "
        + str(_nat(reference["external_site_id"], f"{context}.external_site_id"))
        + ", machineContractId := "
        + str(_nat(reference["machine_contract_id"], f"{context}.machine_contract_id"))
        + " }"
    )


def _lean_guard(value: object, context: str) -> str:
    guard = _object(value, context)
    _fields(
        guard,
        frozenset({
            "id",
            "region_id",
            "location_id",
            "original_condition",
            "candidate_condition",
            "observed",
        }),
        context,
    )
    try:
        original = _lean_semantic_bool_expr(
            dict(_object(
                guard["original_condition"],
                f"{context}.original_condition",
            ))
        )
        candidate = _lean_semantic_bool_expr(
            dict(_object(
                guard["candidate_condition"],
                f"{context}.candidate_condition",
            ))
        )
    except (KeyError, TypeError, ValueError, StageAInputError) as error:
        raise ControlValueProvenanceGenerationError(
            f"{context} contains an unsupported branch condition"
        ) from error
    return (
        "{ id := "
        + str(_nat(guard["id"], f"{context}.id"))
        + ", regionId := "
        + str(_nat(guard["region_id"], f"{context}.region_id"))
        + ", locationId := "
        + str(_nat(guard["location_id"], f"{context}.location_id"))
        + ", originalCondition := "
        + original
        + ", candidateCondition := "
        + candidate
        + ", observed := "
        + _lean_value(guard["observed"], f"{context}.observed")
        + " }"
    )


def _lean_nat_list(value: object, context: str) -> str:
    return _lean_list([
        str(_nat(item, f"{context}[{index}]"))
        for index, item in enumerate(_list(value, context))
    ])


def _lean_scc(value: object, context: str) -> str:
    component = _object(value, context)
    _fields(
        component,
        frozenset({
            "id",
            "region_ids",
            "edge_ids",
            "predecessor_ids",
            "successor_ids",
            "cyclic",
        }),
        context,
    )
    return (
        "{ id := "
        + str(_nat(component["id"], f"{context}.id"))
        + ", regionIds := "
        + _lean_nat_list(component["region_ids"], f"{context}.region_ids")
        + ", edgeIds := "
        + _lean_nat_list(component["edge_ids"], f"{context}.edge_ids")
        + ", predecessorIds := "
        + _lean_nat_list(component["predecessor_ids"], f"{context}.predecessor_ids")
        + ", successorIds := "
        + _lean_nat_list(component["successor_ids"], f"{context}.successor_ids")
        + ", cyclic := "
        + _lean_bool(_bool(component["cyclic"], f"{context}.cyclic"))
        + " }"
    )


def _rows(
    payload: Mapping[str, Any],
    field: str,
    render: Callable[[object, str], str],
) -> str:
    return _lean_list([
        render(item, f"{field}[{index}]")
        for index, item in enumerate(_list(payload[field], field))
    ])


def control_value_provenance_source(
    certificate: Mapping[str, Any],
    *,
    expectation: Literal["accepted", "rejected"] = "accepted",
) -> str:
    """Render a kernel-decidable local replay verdict, never proof authority."""
    if expectation not in {"accepted", "rejected"}:
        raise ControlValueProvenanceGenerationError(
            "expectation must be accepted or rejected"
        )
    payload = _object(certificate, "control-value provenance certificate")
    _fields(payload, _ROOT_FIELDS, "control-value provenance certificate")
    if payload["format"] != CONTROL_VALUE_PROVENANCE_FORMAT:
        raise ControlValueProvenanceGenerationError(
            "unsupported control-value provenance certificate format"
        )

    context = _object(payload["context"], "context")
    _fields(
        context,
        frozenset({"module", "value", "call_semantic_dependency"}),
        "context",
    )
    module = _qualified_name(context["module"], "context.module")
    context_value = _qualified_name(context["value"], "context.value")
    if not context_value.startswith(module + "."):
        raise ControlValueProvenanceGenerationError(
            "context.value must be defined under context.module"
        )
    dependency_value = context["call_semantic_dependency"]
    if dependency_value is None:
        dependency = "none"
    else:
        dependency = "some (" + _qualified_name(
            dependency_value, "context.call_semantic_dependency"
        ) + ")"

    budget = _nat(
        payload["finite_disjunction_budget"], "finite_disjunction_budget"
    )
    definition = f"""abbrev generatedControlValueProvenanceContext : StaticProofContext :=
  {context_value}

def generatedControlValueProvenanceCallDependency :
    Option (CallSemanticDependency generatedControlValueProvenanceContext) :=
  {dependency}

def generatedControlValueProvenanceCertificate : Certificate := {{
  finiteDisjunctionBudget := {budget}
  locations := {_rows(payload, 'locations', _lean_location_pair)}
  staticSeeds := {_rows(payload, 'static_seeds', _lean_static_seed)}
  regions := {_rows(payload, 'regions', _lean_region)}
  edges := {_rows(payload, 'edges', _lean_edge)}
  callReferences := {_rows(payload, 'call_references', _lean_call_reference)}
  branchGuards := {_rows(payload, 'branch_guards', _lean_guard)}
  sccs := {_rows(payload, 'sccs', _lean_scc)}
  componentOrder := {_lean_nat_list(payload['component_order'], 'component_order')}
}}

/-- Generated certificates are local replay evidence, not acceptance authority. -/
def generatedControlValueProvenanceProofAuthority : Bool := false

/-- An integrator must supply `AcceptanceIntegrationPremise` separately. -/
def generatedControlValueProvenanceRequiresIntegrationPremise : Bool := true"""

    if expectation == "accepted":
        theorem = """theorem generatedControlValueProvenanceLocallyChecked :
    generatedControlValueProvenanceCertificate.localChecked
      generatedControlValueProvenanceContext
      generatedControlValueProvenanceCallDependency = true := by
  decide

theorem generatedControlValueProvenanceExactContext :
    ExactContextBinding generatedControlValueProvenanceContext :=
  (Certificate.localReplayFacts_of_checked
    generatedControlValueProvenanceLocallyChecked).exactContext

theorem generatedControlValueProvenanceLocalReplayFacts :
    generatedControlValueProvenanceCertificate.LocalReplayFacts
      generatedControlValueProvenanceContext
      generatedControlValueProvenanceCallDependency :=
  Certificate.localReplayFacts_of_checked
    generatedControlValueProvenanceLocallyChecked

#print axioms generatedControlValueProvenanceLocallyChecked
#print axioms generatedControlValueProvenanceExactContext
#print axioms generatedControlValueProvenanceLocalReplayFacts"""
    else:
        theorem = """theorem generatedControlValueProvenanceRejected :
    generatedControlValueProvenanceCertificate.localChecked
      generatedControlValueProvenanceContext
      generatedControlValueProvenanceCallDependency = false := by
  decide

#print axioms generatedControlValueProvenanceRejected"""

    return f"""import StageA.RelationalControlValueProvenance
import {module}

namespace StageA.GeneratedRelational.ControlValueProvenance

open StageA.Formal StageA.Relational
open StageA.Relational.ControlValueProvenance

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

{definition}

{theorem}

end StageA.GeneratedRelational.ControlValueProvenance
"""


def write_control_value_provenance_bundle(
    *,
    certificate: Mapping[str, Any],
    out: Path | str,
    expectation: Literal["accepted", "rejected"] = "accepted",
) -> Path:
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    destination = output / CONTROL_VALUE_PROVENANCE_LEAN_FILENAME
    destination.write_text(
        control_value_provenance_source(certificate, expectation=expectation),
        encoding="utf-8",
    )
    return destination


__all__ = [
    "CONTROL_VALUE_PROVENANCE_FORMAT",
    "CONTROL_VALUE_PROVENANCE_LEAN_FILENAME",
    "ControlValueProvenanceGenerationError",
    "control_value_provenance_source",
    "write_control_value_provenance_bundle",
]

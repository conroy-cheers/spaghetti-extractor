"""Generate Lean replay certificates for register-control provenance proposals."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal, Mapping, Protocol

from ...errors import StageAInputError


REGISTER_CONTROL_PROVENANCE_FORMAT = (
    "stage-a-register-control-provenance-witness-v1"
)
REGISTER_CONTROL_PROVENANCE_LEAN_FILENAME = (
    "GeneratedRelationalRegisterControlProvenance.lean"
)

_REGISTERS = {
    name: f".{name}"
    for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
}
_BLOCKERS = {
    "register_control_unknown_call": ".unknownCall",
    "register_control_ambiguous_writable_load": ".ambiguousWritableLoad",
    "register_control_finite_disjunction_budget_exceeded": (
        ".disjunctionBudgetExceeded"
    ),
    "register_control_unknown_or_clobbered": ".unknownOrClobbered",
    "register_control_register_pair_mismatch": ".registerPairMismatch",
    "register_control_fixed_point_not_converged": ".fixedPointNotConverged",
    "register_control_invalid_indirect_control_atom": (
        ".invalidIndirectControlAtom"
    ),
}


class _Witness(Protocol):
    def to_payload(self) -> dict[str, Any]: ...


class RegisterControlProvenanceGenerationError(StageAInputError):
    """The proposal cannot be represented by the reviewed Lean checker."""


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RegisterControlProvenanceGenerationError(
            f"{context} must be a JSON object"
        )
    return value


def _list(value: object, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise RegisterControlProvenanceGenerationError(
            f"{context} must be a JSON array"
        )
    return value


def _nat(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RegisterControlProvenanceGenerationError(
            f"{context} must be a natural number"
        )
    return value


def _bool(value: object, context: str) -> bool:
    if not isinstance(value, bool):
        raise RegisterControlProvenanceGenerationError(
            f"{context} must be Boolean"
        )
    return value


def _string(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise RegisterControlProvenanceGenerationError(
            f"{context} must be a non-empty string"
        )
    return value


def _lean_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _lean_bool(value: bool) -> str:
    return "true" if value else "false"


def _payload(witness: _Witness | Mapping[str, Any]) -> Mapping[str, Any]:
    if isinstance(witness, Mapping):
        payload = witness
    else:
        payload = witness.to_payload()
    payload = _object(payload, "register-control provenance witness")
    if payload.get("format") != REGISTER_CONTROL_PROVENANCE_FORMAT:
        raise RegisterControlProvenanceGenerationError(
            "unsupported register-control provenance witness format"
        )
    return payload


def _lean_register(value: object, context: str) -> str:
    name = _string(value, context).lower()
    try:
        return _REGISTERS[name]
    except KeyError as error:
        raise RegisterControlProvenanceGenerationError(
            f"{context} is not a supported x86 register"
        ) from error


def _lean_pair(value: object, context: str) -> str:
    pair = _object(value, context)
    original = _lean_register(pair.get("original"), f"{context}.original")
    candidate = _lean_register(pair.get("candidate"), f"{context}.candidate")
    return f"{{ original := {original}, candidate := {candidate} }}"


def _lean_import(value: object, context: str) -> str:
    imported = _object(value, context)
    dll = _lean_string(_string(imported.get("dll"), f"{context}.dll"))
    has_symbol = "symbol" in imported
    has_ordinal = "ordinal" in imported
    if has_symbol == has_ordinal:
        raise RegisterControlProvenanceGenerationError(
            f"{context} must contain exactly one of symbol or ordinal"
        )
    if has_symbol:
        selector = ".symbol " + _lean_string(
            _string(imported.get("symbol"), f"{context}.symbol")
        )
    else:
        selector = ".ordinal " + str(
            _nat(imported.get("ordinal"), f"{context}.ordinal")
        )
    return f"{{ dll := {dll}, selector := {selector} }}"


def _lean_atom(value: object, context: str) -> str:
    atom = _object(value, context)
    kind = _string(atom.get("kind"), f"{context}.kind")
    producer = _nat(
        atom.get("producer_region_index"),
        f"{context}.producer_region_index",
    )
    pair = _lean_pair(atom.get("register_pair"), f"{context}.register_pair")
    if kind in {"exact_code_pointer", "static_code_pointer"}:
        target = _nat(atom.get("target_id"), f"{context}.target_id")
        claim = _lean_string(
            _string(atom.get("claim_kind"), f"{context}.claim_kind")
        )
        constructor = (
            ".exactCodePointer"
            if kind == "exact_code_pointer"
            else ".staticCodePointer"
        )
        return f"{constructor} {producer} {target} {pair} {claim}"
    if kind != "import_return":
        raise RegisterControlProvenanceGenerationError(
            f"{context}.kind is unsupported"
        )
    contract = _nat(
        atom.get("machine_contract_id"),
        f"{context}.machine_contract_id",
    )
    imported = _lean_import(atom.get("import"), f"{context}.import")
    return f".importReturn {producer} {contract} {pair} {imported}"


def _lean_blocker(value: object, context: str) -> str:
    code = _string(value, context)
    try:
        return _BLOCKERS[code]
    except KeyError as error:
        raise RegisterControlProvenanceGenerationError(
            f"{context} is not a reviewed blocker code"
        ) from error


def _lean_list(rows: list[str]) -> str:
    return "[" + ", ".join(rows) + "]"


def _lean_value_parts(
    atoms: object,
    blockers: object,
    context: str,
) -> str:
    atom_rows = [
        _lean_atom(row, f"{context}.atoms[{index}]")
        for index, row in enumerate(_list(atoms, f"{context}.atoms"))
    ]
    blocker_rows = [
        _lean_blocker(row, f"{context}.blockers[{index}]")
        for index, row in enumerate(_list(blockers, f"{context}.blockers"))
    ]
    return (
        f"{{ atoms := {_lean_list(atom_rows)}, "
        f"blockers := {_lean_list(blocker_rows)} }}"
    )


def _lean_state(value: object, context: str) -> str:
    rows = _list(value, context)
    if not rows:
        return "none"
    entries = []
    for index, raw in enumerate(rows):
        row_context = f"{context}[{index}]"
        row = _object(raw, row_context)
        pair = _lean_pair(row.get("register_pair"), f"{row_context}.register_pair")
        evidence = _lean_value_parts(
            row.get("atoms"), row.get("blockers"), row_context
        )
        entries.append(f"{{ registerPair := {pair}, value := {evidence} }}")
    return f"some {_lean_list(entries)}"


def _lean_transfer(value: object, context: str) -> str:
    transfer = _object(value, context)
    copies = []
    for index, raw in enumerate(_list(transfer.get("copies"), f"{context}.copies")):
        row = _object(raw, f"{context}.copies[{index}]")
        copies.append(
            "{ output := "
            + _lean_pair(row.get("output"), f"{context}.copies[{index}].output")
            + ", source := "
            + _lean_pair(row.get("source"), f"{context}.copies[{index}].source")
            + " }"
        )
    producers = [
        _lean_atom(row, f"{context}.producers[{index}]")
        for index, row in enumerate(
            _list(transfer.get("producers"), f"{context}.producers")
        )
    ]
    blocked = []
    for index, raw in enumerate(
        _list(transfer.get("blocked_outputs"), f"{context}.blocked_outputs")
    ):
        row_context = f"{context}.blocked_outputs[{index}]"
        row = _object(raw, row_context)
        blocked.append(
            "{ output := "
            + _lean_pair(row.get("output"), f"{row_context}.output")
            + ", reason := "
            + _lean_blocker(row.get("reason_code"), f"{row_context}.reason_code")
            + " }"
        )
    return (
        "{ regionIndex := "
        + str(_nat(transfer.get("region_index"), f"{context}.region_index"))
        + f", copies := {_lean_list(copies)}"
        + f", producers := {_lean_list(producers)}"
        + f", blockedOutputs := {_lean_list(blocked)}"
        + ", preserveUnmentioned := "
        + _lean_bool(
            _bool(
                transfer.get("preserve_unmentioned"),
                f"{context}.preserve_unmentioned",
            )
        )
        + " }"
    )


def _lean_contract(value: object, context: str) -> str:
    contract = _object(value, context)
    preserved = [
        _lean_pair(row, f"{context}.preserved_registers[{index}]")
        for index, row in enumerate(
            _list(
                contract.get("preserved_registers"),
                f"{context}.preserved_registers",
            )
        )
    ]
    results = []
    for index, raw in enumerate(
        _list(contract.get("import_results"), f"{context}.import_results")
    ):
        row_context = f"{context}.import_results[{index}]"
        row = _object(raw, row_context)
        results.append(
            "{ registerPair := "
            + _lean_pair(row.get("register_pair"), f"{row_context}.register_pair")
            + ", identity := "
            + _lean_import(row.get("import"), f"{row_context}.import")
            + " }"
        )
    return (
        "{ contractId := "
        + str(_nat(contract.get("contract_id"), f"{context}.contract_id"))
        + f", preservedRegisters := {_lean_list(preserved)}"
        + f", importResults := {_lean_list(results)} }}"
    )


def _lean_edge(value: object, context: str) -> str:
    edge = _object(value, context)
    kind = _string(edge.get("kind"), f"{context}.kind")
    if kind not in {"direct", "call_return"}:
        raise RegisterControlProvenanceGenerationError(
            f"{context}.kind is unsupported"
        )
    raw_contract = edge.get("machine_contract_id")
    contract = (
        "none"
        if raw_contract is None
        else f"some {_nat(raw_contract, f'{context}.machine_contract_id')}"
    )
    return (
        "{ edgeIndex := "
        + str(_nat(edge.get("edge_index"), f"{context}.edge_index"))
        + ", sourceRegion := "
        + str(
            _nat(
                edge.get("source_region_index"),
                f"{context}.source_region_index",
            )
        )
        + ", targetRegion := "
        + str(
            _nat(
                edge.get("target_region_index"),
                f"{context}.target_region_index",
            )
        )
        + ", kind := "
        + (".direct" if kind == "direct" else ".callReturn")
        + f", machineContractId := {contract} }}"
    )


def _lean_region(value: object, context: str) -> str:
    region = _object(value, context)
    return (
        "{ regionIndex := "
        + str(_nat(region.get("region_index"), f"{context}.region_index"))
        + ", input := "
        + _lean_state(region.get("inputs"), f"{context}.inputs")
        + ", output := "
        + _lean_state(region.get("outputs"), f"{context}.outputs")
        + " }"
    )


def _lean_scc_state(value: object, context: str) -> str:
    state = _object(value, context)
    return (
        "{ regionIndex := "
        + str(_nat(state.get("region_index"), f"{context}.region_index"))
        + ", state := "
        + _lean_state(state.get("registers"), f"{context}.registers")
        + " }"
    )


def _lean_nat_list(value: object, context: str) -> str:
    return _lean_list([
        str(_nat(row, f"{context}[{index}]"))
        for index, row in enumerate(_list(value, context))
    ])


def _lean_scc(value: object, context: str) -> str:
    scc = _object(value, context)
    inputs = [
        _lean_scc_state(row, f"{context}.input_states[{index}]")
        for index, row in enumerate(
            _list(scc.get("input_states"), f"{context}.input_states")
        )
    ]
    outputs = [
        _lean_scc_state(row, f"{context}.output_states[{index}]")
        for index, row in enumerate(
            _list(scc.get("output_states"), f"{context}.output_states")
        )
    ]
    return (
        "{ componentId := "
        + str(_nat(scc.get("component_id"), f"{context}.component_id"))
        + ", regionIndices := "
        + _lean_nat_list(scc.get("region_indices"), f"{context}.region_indices")
        + ", predecessorComponentIds := "
        + _lean_nat_list(
            scc.get("predecessor_component_ids"),
            f"{context}.predecessor_component_ids",
        )
        + ", successorComponentIds := "
        + _lean_nat_list(
            scc.get("successor_component_ids"),
            f"{context}.successor_component_ids",
        )
        + ", edgeIndices := "
        + _lean_nat_list(scc.get("edge_indices"), f"{context}.edge_indices")
        + ", cyclic := "
        + _lean_bool(_bool(scc.get("cyclic"), f"{context}.cyclic"))
        + f", inputStates := {_lean_list(inputs)}"
        + f", outputStates := {_lean_list(outputs)} }}"
    )


def _lean_use(value: object, context: str) -> str:
    use = _object(value, context)
    purpose = _string(use.get("purpose"), f"{context}.purpose")
    if purpose not in {"register_state", "indirect_control"}:
        raise RegisterControlProvenanceGenerationError(
            f"{context}.purpose is unsupported"
        )
    observed = _lean_value_parts(
        use.get("atoms"), use.get("blockers"), context
    )
    return (
        "{ useIndex := "
        + str(_nat(use.get("use_index"), f"{context}.use_index"))
        + ", regionIndex := "
        + str(_nat(use.get("region_index"), f"{context}.region_index"))
        + ", registerPair := "
        + _lean_pair(use.get("register_pair"), f"{context}.register_pair")
        + ", purpose := "
        + (".registerState" if purpose == "register_state" else ".indirectControl")
        + f", observed := {observed} }}"
    )


def register_control_provenance_source(
    witness: _Witness | Mapping[str, Any],
    *,
    expectation: Literal["accepted", "rejected"] = "accepted",
) -> str:
    """Emit facts plus a kernel-decided acceptance or rejection theorem."""
    if expectation not in {"accepted", "rejected"}:
        raise RegisterControlProvenanceGenerationError(
            "expectation must be accepted or rejected"
        )
    payload = _payload(witness)
    register_pairs = [
        _lean_pair(row, f"register_pairs[{index}]")
        for index, row in enumerate(
            _list(payload.get("register_pairs"), "register_pairs")
        )
    ]
    transfers = [
        _lean_transfer(row, f"transfers[{index}]")
        for index, row in enumerate(_list(payload.get("transfers"), "transfers"))
    ]
    contracts = [
        _lean_contract(row, f"call_contracts[{index}]")
        for index, row in enumerate(
            _list(payload.get("call_contracts"), "call_contracts")
        )
    ]
    edges = [
        _lean_edge(row, f"edges[{index}]")
        for index, row in enumerate(_list(payload.get("edges"), "edges"))
    ]
    regions = [
        _lean_region(row, f"regions[{index}]")
        for index, row in enumerate(_list(payload.get("regions"), "regions"))
    ]
    sccs = [
        _lean_scc(row, f"sccs[{index}]")
        for index, row in enumerate(_list(payload.get("sccs"), "sccs"))
    ]
    uses = [
        _lean_use(row, f"uses[{index}]")
        for index, row in enumerate(_list(payload.get("uses"), "uses"))
    ]
    fixed_point = _object(payload.get("fixed_point"), "fixed_point")
    entries = _lean_nat_list(
        payload.get("entry_region_indices"), "entry_region_indices"
    )
    component_order = _lean_nat_list(
        fixed_point.get("component_order"), "fixed_point.component_order"
    )
    budget = _nat(
        payload.get("finite_disjunction_budget"), "finite_disjunction_budget"
    )
    converged = _lean_bool(
        _bool(fixed_point.get("converged"), "fixed_point.converged")
    )
    certificate = (
        "def generatedRegisterControlProvenanceCertificate : Certificate := {\n"
        f"  regionCount := {len(regions)}\n"
        f"  finiteDisjunctionBudget := {budget}\n"
        f"  fixedPointConverged := {converged}\n"
        f"  registerPairs := {_lean_list(register_pairs)}\n"
        f"  entryRegionIndices := {entries}\n"
        f"  transfers := {_lean_list(transfers)}\n"
        f"  callContracts := {_lean_list(contracts)}\n"
        f"  edges := {_lean_list(edges)}\n"
        f"  regions := {_lean_list(regions)}\n"
        f"  componentOrder := {component_order}\n"
        f"  sccs := {_lean_list(sccs)}\n"
        f"  uses := {_lean_list(uses)}\n"
        "}"
    )
    if expectation == "accepted":
        theorem = """theorem generatedRegisterControlProvenanceChecked :
    generatedRegisterControlProvenanceCertificate.checked = true := by
  decide

theorem generatedRegisterControlProvenanceSemanticallyValid :
    generatedRegisterControlProvenanceCertificate.SemanticallyValid :=
  generatedRegisterControlProvenanceCertificate.checked_sound
    generatedRegisterControlProvenanceChecked"""
    else:
        theorem = """theorem generatedRegisterControlProvenanceRejected :
    generatedRegisterControlProvenanceCertificate.checked = false := by
  decide"""
    return f"""import StageA.RelationalRegisterControlProvenance

namespace StageA.GeneratedRelational.RegisterControlProvenance

open StageA.Relational.RegisterControlProvenance

{certificate}

{theorem}

end StageA.GeneratedRelational.RegisterControlProvenance
"""


def write_register_control_provenance_bundle(
    *,
    witness: _Witness | Mapping[str, Any],
    out: Path | str,
    expectation: Literal["accepted", "rejected"] = "accepted",
) -> Path:
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    destination = output / REGISTER_CONTROL_PROVENANCE_LEAN_FILENAME
    destination.write_text(
        register_control_provenance_source(witness, expectation=expectation),
        encoding="utf-8",
    )
    return destination


__all__ = [
    "REGISTER_CONTROL_PROVENANCE_FORMAT",
    "REGISTER_CONTROL_PROVENANCE_LEAN_FILENAME",
    "RegisterControlProvenanceGenerationError",
    "register_control_provenance_source",
    "write_register_control_provenance_bundle",
]

#!/usr/bin/env python3
"""Check finite direct-call proposal closure without rerunning PE analysis."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping


PROPOSAL_FORMAT = "stage-a-mixed-original-direct-call-proposals-v1"
AUTHORITY_FORMAT = "stage-a-mixed-original-direct-call-authority-bindings-v2"
OUTPUT_FORMAT = "stage-a-direct-call-closure-fixed-point-v2"
STACK_DYNAMIC_FORMAT = "stage-a-stack-dynamic-control-ir-v1"


class FixedPointError(ValueError):
    pass


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise FixedPointError(f"{context} must be an object")
    return value


def _rows(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise FixedPointError(f"{context} must be a list")
    return value


def _load(path: Path, context: str) -> Mapping[str, Any]:
    try:
        return _mapping(json.loads(path.read_text(encoding="utf-8")), context)
    except (OSError, json.JSONDecodeError) as error:
        raise FixedPointError(f"cannot read {context}: {error}") from error


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _request_key(
    value: Any, context: str
) -> tuple[int, int, tuple[str, ...], tuple[int, ...]]:
    row = _mapping(value, context)
    callsite = row.get("callsite_rva")
    caller = row.get("caller_rva")
    registers = row.get("registers")
    frame_words = row.get("caller_frame_word_offsets", [])
    if (
        not isinstance(callsite, int)
        or isinstance(callsite, bool)
        or not isinstance(caller, int)
        or isinstance(caller, bool)
        or not isinstance(registers, list)
        or any(not isinstance(register, str) for register in registers)
        or not isinstance(frame_words, list)
        or any(
            not isinstance(offset, int)
            or isinstance(offset, bool)
            or not 0 <= offset < 2**32
            or offset % 4 != 0
            for offset in frame_words
        )
        or (not registers and not frame_words)
    ):
        raise FixedPointError(f"{context} is malformed")
    key = (callsite, caller, tuple(registers), tuple(frame_words))
    if not 0 <= callsite < 2**32 or not 0 <= caller < 2**32:
        raise FixedPointError(f"{context} is outside PE32")
    return key


def _contract_key(
    value: Any, context: str
) -> tuple[
    int,
    int,
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
    tuple[int, ...],
]:
    row = _mapping(value, context)
    callsite = row.get("callsite_rva")
    source = row.get("source_rva")
    premises = row.get("remaining_semantic_premises")
    register_fields = tuple(
        row.get(field_name)
        for field_name in (
            "preserved_registers",
            "callee_preserved_registers",
            "target_carried_registers",
        )
    )
    frame_words = row.get("preserved_caller_frame_word_offsets")
    if (
        not isinstance(callsite, int)
        or isinstance(callsite, bool)
        or not isinstance(source, int)
        or isinstance(source, bool)
        or any(not isinstance(registers, list) for registers in register_fields)
        or any(
            not isinstance(register, str)
            for registers in register_fields
            for register in registers
        )
        or not isinstance(frame_words, list)
        or any(
            not isinstance(offset, int)
            or isinstance(offset, bool)
            or not 0 <= offset < 2**32
            or offset % 4 != 0
            for offset in frame_words
        )
        or premises != []
    ):
        raise FixedPointError(f"{context} is malformed or remains conditional")
    source_preserved, callee_preserved, target_carried = register_fields
    return (
        callsite,
        source,
        tuple(source_preserved),
        tuple(callee_preserved),
        tuple(target_carried),
        tuple(frame_words),
    )


def check_fixed_point(
    proposal_path: Path,
    authority_path: Path,
    stack_dynamic_input_path: Path,
) -> dict[str, Any]:
    proposal = _load(proposal_path, "direct-call proposal report")
    authority = _load(authority_path, "direct-call authority report")
    if proposal.get("format") != PROPOSAL_FORMAT:
        raise FixedPointError("direct-call proposal report has the wrong format")
    if authority.get("format") != AUTHORITY_FORMAT:
        raise FixedPointError("direct-call authority report has the wrong format")
    proposal_authority = _mapping(
        proposal.get("authority"), "proposal authority policy"
    )
    if (
        proposal_authority.get("proposal_only") is not True
        or proposal_authority.get("standalone_acceptance_authority") is not False
        or proposal_authority.get("authorizing_lean_term") is not None
    ):
        raise FixedPointError("proposal report claims acceptance authority")
    if (
        authority.get("report_authority") is not False
        or authority.get("authority_source") != "named Lean terms only"
    ):
        raise FixedPointError("authority report has an invalid trust policy")

    request_plan = _mapping(
        proposal.get("request_plan"), "direct-call request plan"
    )
    proposal_inputs = _mapping(
        proposal.get("inputs"), "direct-call proposal inputs"
    )
    stack_dynamic_input = _load(
        stack_dynamic_input_path, "stack/dynamic control input"
    )
    if stack_dynamic_input.get("format") != STACK_DYNAMIC_FORMAT:
        raise FixedPointError("stack/dynamic control input has the wrong format")
    stack_inputs = _mapping(
        stack_dynamic_input.get("inputs"), "stack/dynamic control inputs"
    )
    if (
        stack_inputs.get("original_pe_sha256")
        != proposal_inputs.get("original_sha256")
        or stack_inputs.get("state_machine_sha256")
        != proposal_inputs.get("state_machine_sha256")
    ):
        raise FixedPointError(
            "stack/dynamic control input does not match the proposal"
        )
    stack_sites = {
        (
            row.get("source_rva"),
            row.get("instruction_rva"),
            row.get("continuation_rva"),
        )
        for row in (
            _mapping(value, f"stack/dynamic site {index}")
            for index, value in enumerate(_rows(
                stack_dynamic_input.get("indirect_sites"),
                "stack/dynamic indirect sites",
            ))
        )
        if row.get("is_call") is True
    }
    delegated_frontiers = tuple(
        _mapping(value, f"direct-call frontier {index}")
        for index, value in enumerate(
            _rows(request_plan.get("frontiers"), "direct-call frontiers")
        )
    )
    for index, frontier in enumerate(delegated_frontiers):
        reason = frontier.get("reason_code")
        if reason == "caller_frame_word_requires_finite_origin_entry_authority":
            delegated_site = (
                frontier.get("source_rva"),
                frontier.get("instruction_rva"),
                frontier.get("target_rva"),
            )
        elif reason == "finite_origin_entry_deferred_until_checked":
            frame_words = frontier.get("caller_frame_word_offsets")
            if (
                not isinstance(frame_words, list)
                or not frame_words
                or any(
                    not isinstance(offset, int)
                    or isinstance(offset, bool)
                    or not 0 <= offset < 2**32
                    or offset % 4 != 0
                    for offset in frame_words
                )
            ):
                raise FixedPointError(
                    f"direct-call frontier {index} has no checked caller "
                    "frame-word delegation"
                )
            delegated_site = next(
                (
                    site
                    for site in stack_sites
                    if site[0] == frontier.get("caller_rva")
                    and site[1] == frontier.get("callsite_rva")
                ),
                None,
            )
        else:
            delegated_site = None
        if delegated_site not in stack_sites:
            raise FixedPointError(
                f"direct-call frontier {index} is not delegated to the "
                "stack/dynamic control phase"
            )
    ordinary = tuple(
        _request_key(row, f"ordinary request {index}")
        for index, row in enumerate(
            _rows(request_plan.get("requests"), "ordinary requests")
        )
    )
    finite = tuple(
        _request_key(row, f"finite request {index}")
        for index, row in enumerate(_rows(
            request_plan.get("finite_origin_entry_requests"),
            "finite-origin entry requests",
        ))
    )
    requested = ordinary + finite
    if len(set(requested)) != len(requested):
        raise FixedPointError("direct-call request inventory is ambiguous")
    if len({request[0] for request in requested}) != len(requested):
        raise FixedPointError(
            "direct-call request inventory reuses one callsite"
        )

    planner = _mapping(proposal.get("planner"), "direct-call planner")
    if planner.get("blockers") != []:
        raise FixedPointError("direct-call planner has unresolved blockers")
    planned = tuple(
        _request_key(
            _mapping(row, f"planner proposal {index}").get("request"),
            f"planner proposal {index} request",
        )
        for index, row in enumerate(
            _rows(planner.get("proposals"), "planner proposals")
        )
    )
    if sorted(planned) != sorted(requested):
        raise FixedPointError(
            "direct-call planner does not cover the exact request inventory"
        )

    modules = tuple(
        _mapping(row, f"proposal module {index}")
        for index, row in enumerate(
            _rows(proposal.get("proposal_modules"), "proposal modules")
        )
    )
    module_by_callsite: dict[int, Mapping[str, Any]] = {}
    module_contract_ids: set[int] = set()
    module_edge_indices: set[int] = set()
    for index, row in enumerate(modules):
        callsite = row.get("callsite_rva")
        if not isinstance(callsite, int) or isinstance(callsite, bool):
            raise FixedPointError(
                f"proposal module {index} has no callsite RVA"
            )
        continuation = row.get("continuation_rva")
        source = row.get("source_rva")
        source_target = row.get("source_target_id")
        continuation_target = row.get("continuation_target_id")
        edge_index = row.get("edge_index")
        contract_id = row.get("contract_id")
        if (
            any(
                not isinstance(value, int) or isinstance(value, bool)
                for value in (
                    continuation,
                    source,
                    source_target,
                    continuation_target,
                    edge_index,
                )
            )
            or not all(
                0 <= value < 2**32
                for value in (callsite, continuation, source)
            )
            or source_target < 0
            or continuation_target < 0
            or edge_index < 0
            or not isinstance(contract_id, int)
            or isinstance(contract_id, bool)
            or not 0 <= contract_id < 2**32
        ):
            raise FixedPointError(
                f"proposal module {index} has malformed identifiers"
            )
        if callsite in module_by_callsite:
            raise FixedPointError("proposal modules reuse one callsite")
        if contract_id in module_contract_ids:
            raise FixedPointError("proposal modules reuse one contract ID")
        if edge_index in module_edge_indices:
            raise FixedPointError("proposal modules reuse one edge index")
        module_by_callsite[callsite] = row
        module_contract_ids.add(contract_id)
        module_edge_indices.add(edge_index)
    if set(module_by_callsite) != {key[0] for key in requested}:
        raise FixedPointError(
            "proposal modules do not cover the exact request callsites"
        )

    authority_inputs = _mapping(
        authority.get("inputs"), "direct-call authority inputs"
    )
    if authority_inputs.get("proposal_report_sha256") != _sha256(
        proposal_path
    ):
        raise FixedPointError(
            "direct-call authority report is not bound to the proposal report"
        )
    for proposal_name, authority_name in (
        ("original_sha256", "original_sha256"),
        ("state_machine_sha256", "state_machine_sha256"),
    ):
        if proposal_inputs.get(proposal_name) != authority_inputs.get(
            authority_name
        ):
            raise FixedPointError(
                f"direct-call authority {authority_name} does not match"
            )

    contracts = tuple(
        _mapping(row, f"contract {index}")
        for index, row in enumerate(
            _rows(authority.get("contracts"), "direct-call contracts")
        )
    )
    contract_by_callsite: dict[int, Mapping[str, Any]] = {}
    authorizing_terms: set[tuple[str, str, str]] = set()
    for index, contract in enumerate(contracts):
        (
            callsite,
            source,
            source_preserved,
            callee_preserved,
            target_carried,
            preserved_frame_words,
        ) = _contract_key(
            contract, f"contract {index}"
        )
        if callsite in contract_by_callsite:
            raise FixedPointError("direct-call contracts reuse one callsite")
        request = next(
            (item for item in requested if item[0] == callsite), None
        )
        if request is None or request[1] != source:
            raise FixedPointError(
                f"contract {index} does not match its exact request"
            )
        requested_registers = set(request[2])
        requested_frame_words = set(request[3])
        if request in finite:
            if not requested_registers.issubset(target_carried):
                raise FixedPointError(
                    f"contract {index} does not carry requested target registers"
                )
            if not requested_registers.issubset(callee_preserved):
                raise FixedPointError(
                    f"contract {index} does not preserve requested registers "
                    "inside the callee"
                )
            if not requested_frame_words.issubset(preserved_frame_words):
                raise FixedPointError(
                    f"contract {index} does not preserve requested caller "
                    "frame words"
                )
        else:
            if not requested_registers.issubset(source_preserved):
                raise FixedPointError(
                    f"contract {index} does not preserve requested source "
                    "registers"
                )
            if not requested_frame_words.issubset(preserved_frame_words):
                raise FixedPointError(
                    f"contract {index} does not preserve requested caller "
                    "frame words"
                )
        module = module_by_callsite[callsite]
        for field in (
            "continuation_rva",
            "continuation_target_id",
            "contract_id",
            "edge_index",
            "source_rva",
            "source_target_id",
        ):
            if contract.get(field) != module.get(field):
                raise FixedPointError(
                    f"contract {index} {field} disagrees with its proposal"
                )
        expected_origin = (
            (
                "checked_finite_origin_call_caller_frame_word_summary"
                if requested_frame_words
                else "checked_finite_origin_call_summary"
            )
            if request in finite
            else (
                "checked_direct_call_caller_frame_word_summary"
                if requested_frame_words
                else "checked_direct_call_summary"
            )
        )
        if contract.get("origin") != expected_origin:
            raise FixedPointError(
                f"contract {index} has the wrong semantic origin"
            )
        term = _mapping(
            contract.get("authorizing_lean_term"),
            f"contract {index} authorizing Lean term",
        )
        if not all(
            isinstance(term.get(field), str) and term.get(field)
            for field in ("module", "namespace", "symbol")
        ):
            raise FixedPointError(
                f"contract {index} has no named Lean authority"
            )
        term_key = (
            str(term["module"]),
            str(term["namespace"]),
            str(term["symbol"]),
        )
        if term_key in authorizing_terms:
            raise FixedPointError(
                "direct-call contracts reuse one authorizing Lean term"
            )
        authorizing_terms.add(term_key)
        contract_by_callsite[callsite] = contract
    if set(contract_by_callsite) != set(module_by_callsite):
        raise FixedPointError(
            "direct-call semantic contracts do not cover every proposal"
        )

    return {
        "format": OUTPUT_FORMAT,
        "status": "satisfied",
        "proof_authority": False,
        "acceptance_authority": False,
        "closure_basis": (
            "finite exact register-carry request inventory with one "
            "Lean-authorized semantic contract per request; exact unresolved "
            "stack/dynamic target frontiers are delegated to their checked "
            "downstream phase"
        ),
        "inputs": {
            "authority_report_sha256": _sha256(authority_path),
            "proposal_report_sha256": _sha256(proposal_path),
            "stack_dynamic_input_sha256": _sha256(stack_dynamic_input_path),
        },
        "counts": {
            "ordinary_requests": len(ordinary),
            "finite_origin_requests": len(finite),
            "proposal_modules": len(modules),
            "semantic_contracts": len(contracts),
            "delegated_stack_dynamic_frontiers": len(delegated_frontiers),
            "remaining_frontiers": 0,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--proposal-report", required=True)
    parser.add_argument("--authority-report", required=True)
    parser.add_argument("--stack-dynamic-input", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    result = check_fixed_point(
        Path(args.proposal_report),
        Path(args.authority_report),
        Path(args.stack_dynamic_input),
    )
    (out / "direct-call-fixed-point.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()

"""Emit independently cacheable direct-call semantic authority bundles.

This phase consumes already generated proposal data.  It deliberately avoids
the whole mixed-original planner so changes to one authority emitter do not
invalidate static extraction, mapping, or proposal generation.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from ...artifact_formats import RELATIONAL_PHASE_FORMAT
from ...util import sha256_file, write_json
from .internal_direct_call_mixed_original_integration import (
    INTERNAL_DIRECT_CALL_MIXED_ORIGINAL_INTEGRATION_FORMAT,
    DirectCallMixedOriginalAuthorityBinding,
    direct_call_mixed_original_integration_source,
)
from .internal_direct_call_register_control_authority import (
    DirectCallCallerFrameWordCrossing,
    DirectCallCallerFrameWordLeanBindings,
    DirectCallCrossing,
    DirectCallRegisterControlLeanBindings,
    FiniteOriginCallCallerFrameWordLeanBindings,
    FiniteOriginCallEntryLeanBindings,
    FiniteOriginCallRegisterControlLeanBindings,
    direct_call_caller_frame_word_authority_source,
    direct_call_register_control_authority_source,
    finite_origin_call_caller_frame_word_authority_source,
    finite_origin_call_entry_authority_source,
    finite_origin_call_register_control_authority_source,
)


DIRECT_CALL_SEMANTICS_FORMAT = (
    "stage-a-mixed-original-direct-call-authority-bindings-v2"
)
DIRECT_CALL_SEMANTIC_INPUTS_FORMAT = (
    "stage-a-mixed-original-direct-call-semantic-inputs-v1"
)
DIRECT_CALL_PROPOSALS_FORMAT = (
    "stage-a-mixed-original-direct-call-proposals-v1"
)
INTERPRETER_MIXED_ORIGINAL_BASE_MODULE = (
    "GeneratedRelationalInterpreterMixedOriginalBase"
)
_REGISTERS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp")


def direct_call_integration_module(
    callsite_rva: int,
    edge_index: int,
) -> str:
    """Return a stable module identity for one callsite/edge pair."""

    if (
        isinstance(callsite_rva, bool)
        or not isinstance(callsite_rva, int)
        or not 0 <= callsite_rva <= 0xFFFFFFFF
    ):
        raise ValueError("direct-call integration callsite RVA is invalid")
    if (
        isinstance(edge_index, bool)
        or not isinstance(edge_index, int)
        or not 0 <= edge_index <= 0xFFFFFFFF
    ):
        raise ValueError("direct-call integration edge index is invalid")
    return (
        "GeneratedRelationalInternalDirectCallMixedOriginalIntegration"
        f"{callsite_rva:08x}Edge{edge_index:08x}"
    )


def _load_semantic_authority_bindings(
    path: Path | None,
) -> dict[int, Mapping[str, Any]]:
    if path is None:
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping) or payload.get("format") != (
        DIRECT_CALL_SEMANTIC_INPUTS_FORMAT
    ):
        raise ValueError("direct-call semantic input has the wrong format")
    rows = payload.get("bindings")
    if not isinstance(rows, list):
        raise ValueError("direct-call semantic input bindings must be a list")
    result: dict[int, Mapping[str, Any]] = {}
    for index, row in enumerate(rows):
        if (
            not isinstance(row, Mapping)
            or not isinstance(row.get("callsite_rva"), int)
        ):
            raise ValueError(
                f"direct-call semantic binding {index} is malformed"
            )
        callsite = int(row["callsite_rva"])
        if callsite in result:
            raise ValueError(
                "direct-call semantic input has duplicate callsites"
            )
        result[callsite] = row
    return result


def _manifest(
    out: Path,
    *,
    original: Path,
    state_machine: Path,
    proposal_report: Path,
    contracts: list[dict[str, Any]],
    modules: list[str],
) -> None:
    write_json(
        out / "phase-manifest.json",
        {
            "format": RELATIONAL_PHASE_FORMAT,
            "phase": "mixed-original-direct-call-semantics",
            "executes_original_binary": False,
            "executes_candidate_binary": False,
            "inputs": {
                "original_pe": {
                    "path": original.name,
                    "sha256": sha256_file(original),
                },
                "proposal_report": {
                    "path": proposal_report.name,
                    "sha256": sha256_file(proposal_report),
                },
                "state_machine": {
                    "path": state_machine.name,
                    "sha256": sha256_file(state_machine),
                },
            },
            "status": (
                "semantic-terms-ready"
                if contracts
                and all(
                    not row["remaining_semantic_premises"]
                    for row in contracts
                )
                else "semantic-premises-pending"
            ),
            "proof_authority": False,
            "integration_format": (
                INTERNAL_DIRECT_CALL_MIXED_ORIGINAL_INTEGRATION_FORMAT
            ),
            "modules": modules,
            "counts": {
                "proposals": len(contracts),
                "authorized_terms": sum(
                    row["authorizing_lean_term"] is not None
                    for row in contracts
                ),
                "remaining_semantic_frontiers": sum(
                    bool(row["remaining_semantic_premises"])
                    for row in contracts
                ),
            },
        },
    )


def _kernel_check_for_term(
    out: Path,
    term: Mapping[str, Any],
    kernel_checks: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    if kernel_checks is None:
        return None
    module = term.get("module")
    if not isinstance(module, str) or not module.startswith("StageA."):
        return None
    module_name = module.removeprefix("StageA.")
    source = out / "StageA" / f"{module_name}.lean"
    row = kernel_checks.get(module)
    if not source.is_file() or not isinstance(row, Mapping):
        return None
    source_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
    olean_sha256 = row.get("olean_sha256")
    if (
        row.get("status") != "checked"
        or row.get("source_sha256") != source_sha256
        or row.get("term") != dict(term)
        or not isinstance(olean_sha256, str)
        or len(olean_sha256) != 64
        or any(character not in "0123456789abcdef" for character in olean_sha256)
    ):
        return None
    return {
        "module": module,
        "olean_sha256": olean_sha256,
        "source_sha256": source_sha256,
        "status": "checked",
        "term": dict(term),
    }


def write_mixed_original_direct_call_semantics(
    *,
    original: Path,
    state_machine: Path,
    proposal_report: Path,
    out: Path,
    semantic_input: Path | None = None,
    kernel_checks: Mapping[str, Any] | None = None,
) -> Mapping[str, Any]:
    """Emit checked-authority source adapters from a hash-bound proposal."""

    proposal_payload = json.loads(
        proposal_report.read_text(encoding="utf-8")
    )
    if (
        not isinstance(proposal_payload, Mapping)
        or proposal_payload.get("format") != DIRECT_CALL_PROPOSALS_FORMAT
    ):
        raise ValueError("direct-call proposal report has the wrong format")
    inputs = proposal_payload.get("inputs")
    if not isinstance(inputs, Mapping):
        raise ValueError("direct-call proposal report lacks hash-bound inputs")
    if inputs.get("original_sha256") != sha256_file(original):
        raise ValueError("direct-call proposal original PE hash changed")
    if inputs.get("state_machine_sha256") != sha256_file(state_machine):
        raise ValueError("direct-call proposal state-machine hash changed")

    semantic_bindings = _load_semantic_authority_bindings(semantic_input)
    module_rows = proposal_payload.get("proposal_modules")
    request_plan = proposal_payload.get("request_plan")
    chains = (
        request_plan.get("chains")
        if isinstance(request_plan, Mapping)
        else None
    )
    if not isinstance(module_rows, list) or not isinstance(chains, list):
        raise ValueError(
            "direct-call proposal report lacks module or chain rows"
        )

    sites: dict[int, Mapping[str, Any]] = {}
    registers_by_callsite: dict[int, set[str]] = {}
    for chain in chains:
        if not isinstance(chain, Mapping):
            continue
        register = chain.get("register")
        direct_calls = chain.get("required_internal_calls")
        finite_calls = chain.get("required_finite_origin_calls", [])
        if (
            not isinstance(register, str)
            or not isinstance(direct_calls, list)
            or not isinstance(finite_calls, list)
        ):
            continue
        for call_rows, entry_kind in (
            (direct_calls, "direct"),
            (finite_calls, "finite_origin_call"),
        ):
            for site in call_rows:
                if (
                    not isinstance(site, Mapping)
                    or not isinstance(site.get("callsite_rva"), int)
                ):
                    continue
                callsite = int(site["callsite_rva"])
                normalized = {**site, "entry_kind": entry_kind}
                prior = sites.get(callsite)
                if prior is not None and prior != normalized:
                    raise ValueError(
                        "direct-call proposal has ambiguous callsite metadata"
                    )
                sites[callsite] = normalized
                registers_by_callsite.setdefault(callsite, set()).add(register)

    modules_by_callsite = {
        int(row["callsite_rva"]): row
        for row in module_rows
        if (
            isinstance(row, Mapping)
            and isinstance(row.get("callsite_rva"), int)
        )
    }
    # Chains describe the eventual fixed-point inventory. A stratified proof
    # round emits semantics only for proposals whose entry authority is
    # available in that round; deferred chain members remain diagnostics in
    # the request plan and must not become conditional pseudo-contracts.
    sites = {
        callsite: site
        for callsite, site in sites.items()
        if callsite in modules_by_callsite
    }
    registers_by_callsite = {
        callsite: registers
        for callsite, registers in registers_by_callsite.items()
        if callsite in modules_by_callsite
    }
    frame_words_by_callsite: dict[int, tuple[int, ...]] = {}
    for callsite, module_row in modules_by_callsite.items():
        raw_offsets = module_row.get("caller_frame_word_offsets")
        if not isinstance(raw_offsets, list):
            raise ValueError(
                "direct-call proposal module lacks caller-frame word inventory"
            )
        offsets: list[int] = []
        for offset in raw_offsets:
            if (
                isinstance(offset, bool)
                or not isinstance(offset, int)
                or not 0 <= offset <= 65528
            ):
                raise ValueError(
                    "direct-call proposal has an invalid caller-frame word offset"
                )
            offsets.append(offset)
        if len(set(offsets)) != len(offsets):
            raise ValueError(
                "direct-call proposal duplicates a caller-frame word offset"
            )
        frame_words_by_callsite[callsite] = tuple(sorted(offsets))
        if offsets and callsite not in sites:
            sites[callsite] = module_row
    stage_a = out / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    contracts: list[dict[str, Any]] = []
    generated_modules: list[str] = []
    module_resources: dict[str, dict[str, Any]] = {}
    missing_fields = [
        "IntegratedSummaryPremises.callEntry",
        "IntegratedSummaryPremises.graphComplete",
        "IntegratedSummaryPremises.registerGrounded",
        "IntegratedSummaryPremises.loops",
        "IntegratedSummaryPremises.loopsComplete",
        "IntegratedSummaryPremises.invariant",
        "CallEntryRegistersPreserved",
    ]

    for index, callsite in enumerate(sorted(sites)):
        site = sites[callsite]
        registers = tuple(
            register
            for register in _REGISTERS
            if register in registers_by_callsite.get(callsite, set())
        )
        proposal_module = modules_by_callsite.get(callsite)
        contract_id_value = (
            proposal_module.get("contract_id")
            if isinstance(proposal_module, Mapping)
            else None
        )
        if (
            not isinstance(contract_id_value, int)
            or isinstance(contract_id_value, bool)
            or not 0 <= contract_id_value < 2**32
        ):
            contract_id_value = 0x80000000 + index
        contract_id = contract_id_value
        exact_site = (
            proposal_module
            if isinstance(proposal_module, Mapping)
            else site
        )
        row: dict[str, Any] = {
            "contract_id": contract_id,
            "source_target_id": exact_site.get("source_target_id"),
            "continuation_target_id": exact_site.get(
                "continuation_target_id"
            ),
            "edge_index": exact_site.get("edge_index"),
            "source_rva": exact_site.get("source_rva"),
            "callsite_rva": callsite,
            "continuation_rva": exact_site.get("continuation_rva"),
            "callee_target_id": exact_site.get("callee_target_id"),
            "callee_rva": exact_site.get("callee_rva"),
            "preserved_registers": (
                []
                if exact_site.get("entry_kind") == "finite_origin_call"
                else list(registers)
            ),
            "preserved_caller_frame_word_offsets": list(
                frame_words_by_callsite.get(callsite, ())
            ),
            "caller_frame_word_authorizing_lean_term": None,
            "callee_preserved_registers": list(registers),
            "target_carried_registers": (
                list(registers)
                if exact_site.get("entry_kind") == "finite_origin_call"
                else []
            ),
            "origin": (
                "checked_finite_origin_call_summary"
                if exact_site.get("entry_kind") == "finite_origin_call"
                else "checked_direct_call_summary"
            ),
            "finite_target_ids": (
                [int(exact_site["callee_target_id"])]
                if (
                    exact_site.get("entry_kind") == "finite_origin_call"
                    and isinstance(exact_site.get("callee_target_id"), int)
                    and not isinstance(
                        exact_site.get("callee_target_id"), bool
                    )
                )
                else []
            ),
            "authorizing_lean_term": None,
            "remaining_semantic_premises": list(missing_fields),
        }
        semantic = semantic_bindings.get(callsite)
        identity_registers = (
            proposal_module.get("identity_registers")
            if isinstance(proposal_module, Mapping)
            else None
        )
        stack_witnesses = (
            proposal_module.get("stack_witnesses")
            if isinstance(proposal_module, Mapping)
            else None
        )
        stack_witness = (
            next(
                (
                    witness
                    for witness in stack_witnesses
                    if (
                        isinstance(witness, Mapping)
                        and witness.get("register") == registers[0]
                        and witness.get("operational_path_supported") is True
                    )
                ),
                None,
            )
            if (
                len(registers) == 1
                and isinstance(stack_witnesses, list)
            )
            else None
        )
        frame_word_offsets = frame_words_by_callsite.get(callsite, ())

        if (
            semantic is None
            and proposal_module is not None
            and frame_word_offsets
            and not registers
            and proposal_module.get("entry_kind") in {
                "direct",
                "finite_origin_call",
            }
        ):
            module = direct_call_integration_module(
                callsite,
                int(exact_site["edge_index"]),
            )
            namespace = f"StageA.Generated.{module}"
            crossing = DirectCallCallerFrameWordCrossing(
                callsite_rva=callsite,
                source_rva=int(exact_site["source_rva"]),
                continuation_rva=int(exact_site["continuation_rva"]),
                callee_rva=int(exact_site["callee_rva"]),
                source_target_id=int(exact_site["source_target_id"]),
                continuation_target_id=int(
                    exact_site["continuation_target_id"]
                ),
                callee_target_id=int(exact_site["callee_target_id"]),
                edge_index=int(exact_site["edge_index"]),
                caller_frame_word_offsets=frame_word_offsets,
            )
            if proposal_module.get("entry_kind") == "finite_origin_call":
                authority_module = proposal_module.get(
                    "entry_authority_module"
                )
                authority_term = proposal_module.get(
                    "entry_authority_term"
                )
                authority_certificate_exact_term = proposal_module.get(
                    "entry_authority_certificate_exact_term"
                )
                if (
                    not isinstance(authority_module, str)
                    or not isinstance(authority_term, str)
                    or not isinstance(
                        authority_certificate_exact_term, str
                    )
                ):
                    raise ValueError(
                        "finite-origin caller-frame proposal lacks its named "
                        "Lean authority or certificate equality"
                    )
                entry_module = f"{module}EntryCertificate"
                entry_namespace = f"StageA.Generated.{entry_module}"
                entry_source = finite_origin_call_entry_authority_source(
                    crossing,
                    bindings=FiniteOriginCallEntryLeanBindings(
                        context=(
                            "StageA.GeneratedRelational."
                            "InterpreterMixedOriginalBase."
                            "generatedOriginalCarrierContext"
                        ),
                        summary_tree=str(proposal_module["summary_tree"]),
                        summary_checked=str(
                            proposal_module["summary_checked"]
                        ),
                        summary_certificate_exact=str(
                            proposal_module["summary_certificate_exact"]
                        ),
                        summary_tree_module=str(proposal_module["module"]),
                        context_module=(
                            "StageA."
                            f"{INTERPRETER_MIXED_ORIGINAL_BASE_MODULE}"
                            "ContextData"
                        ),
                        authority_module=authority_module,
                        authority_term=authority_term,
                        authority_certificate_exact_term=(
                            authority_certificate_exact_term
                        ),
                        namespace=entry_namespace,
                    ),
                )
                (stage_a / f"{entry_module}.lean").write_text(
                    entry_source,
                    encoding="utf-8",
                )
                generated_modules.append(entry_module)
                module_resources[entry_module] = {
                    "resource_class": "large-memory",
                    "estimated_memory_mb": 8192,
                }
                source = (
                    finite_origin_call_caller_frame_word_authority_source(
                        crossing,
                        bindings=(
                            FiniteOriginCallCallerFrameWordLeanBindings(
                                summary_certificate_exact=str(
                                    proposal_module[
                                        "summary_certificate_exact"
                                    ]
                                ),
                                entry_module=f"StageA.{entry_module}",
                                entry_namespace=entry_namespace,
                                namespace=namespace,
                            )
                        ),
                    )
                )
                authority_symbol = (
                    "generatedCheckedFiniteOriginCall"
                    "CallerFrameWordControlContract"
                )
                contract_origin = (
                    "checked_finite_origin_call_caller_frame_word_summary"
                )
            else:
                source = direct_call_caller_frame_word_authority_source(
                    crossing,
                    bindings=DirectCallCallerFrameWordLeanBindings(
                        context=(
                            "StageA.GeneratedRelational."
                            "InterpreterMixedOriginalBase."
                            "generatedOriginalCarrierContext"
                        ),
                        summary_tree=str(proposal_module["summary_tree"]),
                        summary_checked=str(
                            proposal_module["summary_checked"]
                        ),
                        summary_certificate_exact=str(
                            proposal_module["summary_certificate_exact"]
                        ),
                        summary_tree_module=str(proposal_module["module"]),
                        context_module=(
                            "StageA."
                            f"{INTERPRETER_MIXED_ORIGINAL_BASE_MODULE}"
                            "ContextData"
                        ),
                        namespace=namespace,
                    ),
                )
                authority_symbol = (
                    "generatedCheckedDirectCall"
                    "CallerFrameWordControlContract"
                )
                contract_origin = (
                    "checked_direct_call_caller_frame_word_summary"
                )
            (stage_a / f"{module}.lean").write_text(
                source,
                encoding="utf-8",
            )
            generated_modules.append(module)
            module_resources[module] = {
                "resource_class": "light",
                "estimated_memory_mb": 768,
            }
            authority_term = {
                "module": f"StageA.{module}",
                "namespace": namespace,
                "symbol": authority_symbol,
            }
            row["authorizing_lean_term"] = authority_term
            row["caller_frame_word_authorizing_lean_term"] = authority_term
            row["origin"] = contract_origin
            row["remaining_semantic_premises"] = []
        elif (
            semantic is None
            and proposal_module is not None
            and len(registers) == 1
            and (
                (
                    isinstance(identity_registers, list)
                    and registers[0] in identity_registers
                )
                or stack_witness is not None
            )
        ):
            module = direct_call_integration_module(
                callsite,
                int(exact_site["edge_index"]),
            )
            namespace = f"StageA.Generated.{module}"
            crossing = DirectCallCrossing(
                register=registers[0],
                callsite_rva=callsite,
                source_rva=int(exact_site["source_rva"]),
                continuation_rva=int(exact_site["continuation_rva"]),
                callee_rva=int(exact_site["callee_rva"]),
                source_target_id=int(exact_site["source_target_id"]),
                continuation_target_id=int(
                    exact_site["continuation_target_id"]
                ),
                callee_target_id=int(exact_site["callee_target_id"]),
                edge_index=int(exact_site["edge_index"]),
            )
            common = {
                "context": (
                    "StageA.GeneratedRelational."
                    "InterpreterMixedOriginalBase."
                    "generatedOriginalCarrierContext"
                ),
                "summary_tree": str(proposal_module["summary_tree"]),
                "summary_checked": str(proposal_module["summary_checked"]),
                "summary_certificate_exact": str(
                    proposal_module["summary_certificate_exact"]
                ),
                "summary_tree_module": str(proposal_module["module"]),
                "context_module": (
                    "StageA."
                    f"{INTERPRETER_MIXED_ORIGINAL_BASE_MODULE}ContextData"
                ),
                "namespace": namespace,
                "stack_witness": (
                    str(stack_witness["term"])
                    if stack_witness is not None
                    else None
                ),
                "stack_witness_member": (
                    str(stack_witness["member"])
                    if stack_witness is not None
                    else None
                ),
                "stack_witness_checked": (
                    str(stack_witness["checked"])
                    if stack_witness is not None
                    else None
                ),
            }
            if proposal_module.get("entry_kind") == "finite_origin_call":
                authority_module = proposal_module.get(
                    "entry_authority_module"
                )
                authority_term = proposal_module.get(
                    "entry_authority_term"
                )
                authority_certificate_exact_term = proposal_module.get(
                    "entry_authority_certificate_exact_term"
                )
                if (
                    not isinstance(authority_module, str)
                    or not isinstance(authority_term, str)
                    or not isinstance(
                        authority_certificate_exact_term, str
                    )
                ):
                    raise ValueError(
                        "finite-origin proposal lacks its named Lean "
                        "authority or certificate equality"
                    )
                entry_module = f"{module}EntryCertificate"
                entry_namespace = f"StageA.Generated.{entry_module}"
                entry_source = finite_origin_call_entry_authority_source(
                    crossing,
                    bindings=FiniteOriginCallEntryLeanBindings(
                        context=common["context"],
                        summary_tree=common["summary_tree"],
                        summary_checked=common["summary_checked"],
                        summary_certificate_exact=(
                            common["summary_certificate_exact"]
                        ),
                        summary_tree_module=common["summary_tree_module"],
                        context_module=common["context_module"],
                        authority_module=authority_module,
                        authority_term=authority_term,
                        authority_certificate_exact_term=(
                            authority_certificate_exact_term
                        ),
                        namespace=entry_namespace,
                    ),
                )
                (stage_a / f"{entry_module}.lean").write_text(
                    entry_source,
                    encoding="utf-8",
                )
                generated_modules.append(entry_module)
                module_resources[entry_module] = {
                    "resource_class": "large-memory",
                    "estimated_memory_mb": 8192,
                }
                source = (
                    finite_origin_call_register_control_authority_source(
                        crossing,
                        contract_id=contract_id,
                        bindings=(
                            FiniteOriginCallRegisterControlLeanBindings(
                                summary_certificate_exact=(
                                    common["summary_certificate_exact"]
                                ),
                                entry_module=f"StageA.{entry_module}",
                                entry_namespace=entry_namespace,
                                namespace=namespace,
                                stack_witness=common["stack_witness"],
                                stack_witness_member=(
                                    common["stack_witness_member"]
                                ),
                                stack_witness_checked=(
                                    common["stack_witness_checked"]
                                ),
                            )
                        ),
                    )
                )
                authority_symbol = (
                    "generatedCheckedFiniteOriginCallRegisterControlContract"
                )
                contract_origin = (
                    "checked_finite_origin_call_summary"
                )
            else:
                source = direct_call_register_control_authority_source(
                    crossing,
                    contract_id=contract_id,
                    bindings=DirectCallRegisterControlLeanBindings(
                        source_invariant=(
                            "StageA.GeneratedRelational."
                            "InterpreterMixedOriginalBase."
                            "generatedOriginalCarrierInvariantAt"
                        ),
                        **common,
                    ),
                )
                authority_symbol = (
                    "generatedCheckedDirectCallRegisterControlContract"
                )
                contract_origin = "checked_direct_call_summary"
            (stage_a / f"{module}.lean").write_text(
                source,
                encoding="utf-8",
            )
            generated_modules.append(module)
            module_resources[module] = {
                "resource_class": "light",
                "estimated_memory_mb": 768,
            }
            row["authorizing_lean_term"] = {
                "module": f"StageA.{module}",
                "namespace": namespace,
                "symbol": authority_symbol,
            }
            if frame_word_offsets:
                row["remaining_semantic_premises"] = [
                    "caller_frame_word_authority_requires_combined_contract"
                ]
            else:
                row["remaining_semantic_premises"] = []
            row["origin"] = contract_origin
        elif semantic is not None and proposal_module is not None:
            term = semantic.get("authority_term")
            if not isinstance(term, Mapping):
                raise ValueError("semantic binding lacks authority_term")
            external_module = str(term.get("module", ""))
            external_authority = (
                f"{term.get('namespace', '')}.{term.get('symbol', '')}"
            )
            module = direct_call_integration_module(
                callsite,
                int(exact_site["edge_index"]),
            )
            namespace = f"StageA.Generated.{module}"
            source = direct_call_mixed_original_integration_source(
                DirectCallMixedOriginalAuthorityBinding(
                    context=(
                        "StageA.GeneratedRelational."
                        "InterpreterMixedOriginalBase."
                        "generatedOriginalCarrierContext"
                    ),
                    authority_term=external_authority,
                    source_target_id=int(exact_site["source_target_id"]),
                    continuation_target_id=int(
                        exact_site["continuation_target_id"]
                    ),
                    edge_index=int(exact_site["edge_index"]),
                    contract_id=contract_id,
                    source_rva=int(exact_site["source_rva"]),
                    callsite_rva=callsite,
                    continuation_rva=int(
                        exact_site["continuation_rva"]
                    ),
                    registers=registers,
                    imports=(
                        "StageA."
                        f"{INTERPRETER_MIXED_ORIGINAL_BASE_MODULE}"
                        "ContextData",
                        str(proposal_module["module"]),
                        external_module,
                    ),
                    namespace=namespace,
                )
            )
            (stage_a / f"{module}.lean").write_text(
                source,
                encoding="utf-8",
            )
            generated_modules.append(module)
            module_resources[module] = {
                "resource_class": "light",
                "estimated_memory_mb": 768,
            }
            row["authorizing_lean_term"] = {
                "module": f"StageA.{module}",
                "namespace": namespace,
                "symbol": (
                    "generatedCheckedDirectCallRegisterControlContract"
                ),
            }
            row["remaining_semantic_premises"] = []
        term = row.get("authorizing_lean_term")
        if isinstance(term, Mapping) and not row["remaining_semantic_premises"]:
            kernel_check = _kernel_check_for_term(
                out, term, kernel_checks
            )
            if kernel_check is None:
                row["remaining_semantic_premises"] = [
                    "kernel_compile_required"
                ]
            else:
                row["kernel_check"] = kernel_check
        contracts.append(row)

    authority_payload = {
        "format": DIRECT_CALL_SEMANTICS_FORMAT,
        "inputs": {
            "original_sha256": sha256_file(original),
            "state_machine_sha256": sha256_file(state_machine),
            "proposal_report_sha256": sha256_file(proposal_report),
        },
        "contracts": contracts,
        "report_authority": False,
        "authority_source": "named Lean terms only",
    }
    write_json(
        out / "direct-call-authority-bindings.json",
        authority_payload,
    )
    write_json(
        out / "kernel-check-requests.json",
        {
            "format": "stage-a-lean-kernel-check-requests-v1",
            "requests": [
                {"term": dict(term)}
                for row in contracts
                if isinstance(
                    term := row.get("authorizing_lean_term"),
                    Mapping,
                )
                and row.get("remaining_semantic_premises")
                in ([], ["kernel_compile_required"])
            ],
        },
    )
    write_json(out / "module-resources.json", module_resources)
    _manifest(
        out,
        original=original,
        state_machine=state_machine,
        proposal_report=proposal_report,
        contracts=contracts,
        modules=generated_modules,
    )
    return authority_payload

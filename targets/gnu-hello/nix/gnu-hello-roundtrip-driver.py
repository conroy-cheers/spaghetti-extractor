#!/usr/bin/env python3
"""Deterministic build helpers for the GNU hello round-trip Nix lane.

The driver never executes either PE.  It only turns static Stage A exports,
Stage B packages, candidate bytes, and generated Lean sources into immutable
phase artifacts.  Nix owns phase scheduling and cache invalidation.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping

# Direct checkout invocations do not pass through the target's Nix phase
# wrapper. Make the adjacent target adapter package available in that mode;
# Nix store builds supply the same package through their explicit source
# closure and PYTHONPATH.
_CHECKOUT_TARGET_PYTHON = Path(__file__).resolve().parents[1] / "python"
if _CHECKOUT_TARGET_PYTHON.is_dir():
    sys.path.insert(0, str(_CHECKOUT_TARGET_PYTHON))

from spaghetti_extractor.contract_tools import (
    stage_a_export_reference_contract,
    stage_a_generate_map,
)
from spaghetti_extractor.relational.lean.definedness import (
    relational_definedness_preflight,
    relational_definedness_source,
)
from spaghetti_extractor.relational.lean.interpreter import (
    relational_interpreter_program_source,
)
from spaghetti_extractor.relational.lean.interpreter_kernel import (
    INTERPRETER_KERNEL_FUNCTION_MODULE_PREFIX,
    INTERPRETER_KERNEL_LEAN_FILENAME,
    write_relational_interpreter_kernel_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_block import (
    write_relational_interpreter_kernel_block_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_abi import (
    INTERPRETER_KERNEL_ABI_LEAN_FILENAME,
    INTERPRETER_KERNEL_ABI_PARAMETERS_LEAN_FILENAME,
    INTERPRETER_KERNEL_ABI_PLAN_FILENAME,
    abi_plan_payload_sha256,
    write_relational_interpreter_kernel_abi_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_callback import (
    propose_stage_b_interpreter_kernel_callback_contract,
    write_relational_interpreter_kernel_callback_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_indirect import (
    write_relational_interpreter_kernel_indirect_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_data import (
    generate_interpreter_kernel_data_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_loop import (
    write_relational_interpreter_kernel_loop_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_lookup_native import (
    INTERPRETER_KERNEL_LOOKUP_NATIVE_LEAN_FILENAME,
    write_relational_interpreter_kernel_lookup_native_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_program_lookup_operation import (
    INTERPRETER_KERNEL_PROGRAM_LOOKUP_OPERATION_LEAN_FILENAME,
    INTERPRETER_KERNEL_PROGRAM_LOOKUP_OPERATION_PLAN_FILENAME,
    INTERPRETER_KERNEL_PROGRAM_LOOKUP_OPERATION_THEOREM,
    write_relational_interpreter_kernel_program_lookup_operation_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_invoke import (
    INTERPRETER_KERNEL_INVOKE_LEAN_FILENAME,
    write_relational_interpreter_kernel_invoke_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_invoke_native import (
    INTERPRETER_KERNEL_INVOKE_NATIVE_LEAN_FILENAME,
    write_relational_interpreter_kernel_invoke_native_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_invoke_operation import (
    INTERPRETER_KERNEL_INVOKE_OPERATION_LEAN_FILENAME,
    INTERPRETER_KERNEL_INVOKE_OPERATION_PLAN_FILENAME,
    INTERPRETER_KERNEL_INVOKE_OPERATION_THEOREM,
    write_relational_interpreter_kernel_invoke_operation_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_run import (
    INTERPRETER_KERNEL_RUN_LEAN_FILENAME,
    write_relational_interpreter_kernel_run_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_run_native import (
    INTERPRETER_KERNEL_RUN_NATIVE_LEAN_FILENAME,
    write_relational_interpreter_kernel_run_native_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_run_operation import (
    INTERPRETER_KERNEL_RUN_OPERATION_LEAN_FILENAME,
    INTERPRETER_KERNEL_RUN_OPERATION_PLAN_FILENAME,
    INTERPRETER_KERNEL_RUN_OPERATION_THEOREM,
    write_relational_interpreter_kernel_run_operation_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_step import (
    INTERPRETER_KERNEL_STEP_LEAN_FILENAME,
    write_relational_interpreter_kernel_step_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_step_native import (
    INTERPRETER_KERNEL_STEP_NATIVE_LEAN_FILENAME,
    write_relational_interpreter_kernel_step_native_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_step_operation import (
    INTERPRETER_KERNEL_STEP_OPERATION_LEAN_FILENAME,
    INTERPRETER_KERNEL_STEP_OPERATION_PLAN_FILENAME,
    INTERPRETER_KERNEL_STEP_OPERATION_THEOREM,
    write_relational_interpreter_kernel_step_operation_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_operation_frame_parametric import (
    INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_LEAN_FILENAME,
    INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_PLAN_FILENAME,
    INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_THEOREM,
    write_relational_interpreter_kernel_operation_frame_parametric_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_frame_executor import (
    INTERPRETER_KERNEL_FRAME_EXECUTOR_LEAN_FILENAME,
    INTERPRETER_KERNEL_FRAME_EXECUTOR_PLAN_FILENAME,
    INTERPRETER_KERNEL_FRAME_EXECUTOR_THEOREM,
    write_relational_interpreter_kernel_frame_executor_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_cdecl_epilogue import (
    INTERPRETER_KERNEL_CDECL_EPILOGUE_LEAN_FILENAME,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_PLAN_FILENAME,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_REMAINING_PREMISES,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_THEOREM,
    write_relational_interpreter_kernel_cdecl_epilogue_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_cdecl_epilogue_symbolic_closure import (
    INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_CLOSED_PREMISES,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_LEAN_FILENAME,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_PLAN_FILENAME,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_REMAINING_PREMISES,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_THEOREM,
    write_relational_interpreter_kernel_cdecl_epilogue_symbolic_closure_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_cdecl_epilogue_static_preservation import (
    INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_CLOSED_PREMISES,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_LEAN_FILENAME,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_PLAN_FILENAME,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_REMAINING_PREMISES,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_THEOREM,
    write_relational_interpreter_kernel_cdecl_epilogue_static_preservation_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_cdecl_epilogue_external_payload import (
    INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_CLOSED_PREMISES,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_LEAN_FILENAME,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_PLAN_FILENAME,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_REMAINING_PREMISES,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_THEOREM,
    write_relational_interpreter_kernel_cdecl_epilogue_external_payload_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_step_program_lookup_call import (
    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_LEAN_FILENAME,
    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_PLAN_FILENAME,
    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_REMAINING_PREMISES,
    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_THEOREM,
    write_relational_interpreter_kernel_step_program_lookup_call_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_step_program_lookup_call_closure import (
    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_CLOSED_PREMISES,
    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_LEAN_FILENAME,
    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_PLAN_FILENAME,
    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_REMAINING_PREMISES,
    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_THEOREM,
    write_relational_interpreter_kernel_step_program_lookup_call_closure_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_x87_execution import (
    interpreter_kernel_x87_execution_lean_snippet,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_summary import (
    INTERPRETER_KERNEL_SUMMARY_LEAN_FILENAME,
    write_relational_interpreter_kernel_summary_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_mixed_authority import (
    INTERPRETER_MIXED_AUTHORITY_MODULE,
    InterpreterMixedAuthoritySpec,
    write_relational_interpreter_mixed_authority,
)
from spaghetti_extractor.relational.lean.interpreter_mixed_kernel_binding import (
    REQUIRED_INHABITANTS,
    InterpreterMixedKernelBindingSpec,
    plan_interpreter_mixed_kernel_binding,
    relational_interpreter_mixed_kernel_requirements_source,
    write_relational_interpreter_mixed_kernel_binding,
)
from spaghetti_extractor.relational.lean.interpreter_mixed_original import (
    INTERPRETER_MIXED_ORIGINAL_BASE_MODULE,
    INTERPRETER_MIXED_ORIGINAL_MODULE,
    InterpreterMixedOriginalSpec,
    OriginalMachineImportBoundaryBindings,
    OriginalMachineImportBoundarySiteProposal,
    OriginalModuleBindings,
    OriginalPERecoveryInput,
    OriginalRegisterControlCallContractProposal,
    OriginalRegisterStaticWordSeedAuthority,
    OriginalStaticWordSlotBinding,
    QualifiedLeanSymbol,
    augment_direct_call_summary_requests_from_runtime_value_carry_hints,
    derive_direct_call_summary_requests_from_register_authority,
    derive_mixed_original_direct_call_summary_requests,
    load_checked_direct_call_summary_contract_proposals,
    load_checked_stack_finite_origin_call_entry_authorities,
    load_original_iat_import_proposals,
    load_original_register_control_call_contract_proposals,
    plan_interpreter_mixed_original,
    stage_finite_origin_entry_requests,
    write_relational_interpreter_mixed_original,
    write_relational_interpreter_mixed_original_base,
    write_relational_interpreter_mixed_original_final,
    write_register_finite_origin_call_entry_authorities,
)
from spaghetti_extractor.relational.lean.callable_external_capability import (
    relational_callable_external_capability_source,
)
from spaghetti_extractor.relational.lean.callable_external_execution import (
    CALLABLE_EXTERNAL_PROGRAM_MODULE,
    relational_callable_external_execution_source,
    relational_callable_external_program_source,
)
from spaghetti_extractor.relational.lean.callable_external_proposal import (
    CallableExternalProposal,
    callable_external_artifact_payload,
    callable_resolver_routes_by_instruction_rva,
    callable_resource_ids_by_instruction_rva,
    discover_callable_external_proposal,
)
from spaghetti_extractor.relational.lean.interpreter_mixed_original_static_reachability import (
    INTERPRETER_MIXED_ORIGINAL_STATIC_REACHABILITY_LEAN_FILENAME,
    INTERPRETER_MIXED_ORIGINAL_STATIC_REACHABILITY_PLAN_FILENAME,
    INTERPRETER_MIXED_ORIGINAL_STATIC_REACHABILITY_THEOREM,
    write_interpreter_mixed_original_static_reachability_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_mixed_original_certificates import (
    decompose_interpreter_mixed_original_base,
)
from spaghetti_extractor.relational.lean.interpreter_original_carrier_binding import (
    ORIGINAL_CARRIER_BINDING_MODULE,
    ORIGINAL_CARRIER_BINDING_NAMESPACE,
    OriginalCarrierBindingSpec,
    generate_original_carrier_binding,
    write_original_carrier_binding,
)
from spaghetti_extractor.relational.lean.relocated_writable_static_pointer_slot_authority import (
    consume_relocated_writable_static_pointer_slot_authorities,
    load_relocated_writable_static_pointer_slot_authorities,
    write_decomposed_writable_static_pointer_slot_adapters,
)
from spaghetti_extractor.relational.lean.relocated_writable_static_pointer_slot_proposal import (
    AUTHORITY_FORMAT as RELOCATED_WRITABLE_STATIC_POINTER_SLOT_AUTHORITY_FORMAT,
    LeanAuthorityBinding as RelocatedWritableStaticPointerSlotLeanBinding,
    construct_relocated_writable_static_pointer_slot_authorities,
    write_relocated_writable_static_pointer_slot_authorities,
)
from spaghetti_extractor.relational.lean.register_indirect_control_authority import (
    consume_register_indirect_control_authorities,
    load_register_indirect_control_authorities,
)
from spaghetti_extractor.relational.lean.register_indirect_control_proposal import (
    LeanBindings as RegisterIndirectControlLeanBindings,
    construct_register_indirect_control_authorities,
    write_register_indirect_control_authorities,
)
from spaghetti_extractor.relational.lean.interpreter_mixed_terminal import (
    InterpreterMixedTerminalProposal,
    load_interpreter_mixed_terminal_proposals,
)
from spaghetti_extractor.relational.lean.interpreter_normalization import (
    is_x87_row,
    relational_interpreter_normalization_bundle_sources,
    relational_interpreter_normalization_inventory,
    relational_interpreter_normalization_module_inventory,
)
from spaghetti_extractor.relational.lean.native_source_program import (
    NativeSourceProgramSpec,
    write_native_source_program,
)
from spaghetti_extractor_target_gnu_hello.gnu_hello_source_execution import (
    write_gnu_hello_source_execution_from_artifacts,
)
from spaghetti_extractor_target_gnu_hello.gnu_hello_source_transition_index import (
    generate_gnu_hello_source_transition_index,
)
from spaghetti_extractor_target_gnu_hello.gnu_hello_source_target_effect_inputs import (
    generate_gnu_hello_source_target_effect_inputs,
)
from spaghetti_extractor_target_gnu_hello.gnu_hello_source_target_effects import (
    ArtifactSet as GnuHelloSourceTargetEffectArtifacts,
    generate_gnu_hello_source_target_effects,
)
from spaghetti_extractor_target_gnu_hello.gnu_hello_original_combined_declarations import (
    write_gnu_hello_original_combined_declarations,
)
from spaghetti_extractor_target_gnu_hello.gnu_hello_original_execution_evidence import (
    generate_gnu_hello_original_execution_evidence,
)
from spaghetti_extractor_target_gnu_hello.gnu_hello_original_target_preservation import (
    generate_gnu_hello_original_target_preservation,
)
from spaghetti_extractor_target_gnu_hello.gnu_hello_checked_response_family import (
    write_gnu_hello_checked_response_family,
)
from spaghetti_extractor_target_gnu_hello.gnu_hello_original_combined_inventory import (
    write_original_combined_inventory,
)
from spaghetti_extractor_target_gnu_hello.gnu_hello_original_target_control_evidence import (
    generate_original_target_control_evidence,
)
from spaghetti_extractor_target_gnu_hello.gnu_hello_original_source_launch_context import (
    generate_original_source_launch_context,
)
from spaghetti_extractor.relational.lean.runtime_memory_access_proposal import (
    generate_runtime_memory_access_proposal,
)
from spaghetti_extractor_target_gnu_hello.gnu_hello_native_source_compiled_authority_evidence import (
    NixRealizationIdentity,
    write_gnu_hello_native_source_compiled_authority_evidence,
)
from spaghetti_extractor_target_gnu_hello.gnu_hello_native_source_environment_family_inputs import (
    write_gnu_hello_native_source_environment_family_inputs,
)
from spaghetti_extractor_target_gnu_hello.gnu_hello_native_source_environment_family import (
    write_gnu_hello_native_source_environment_family,
)
from spaghetti_extractor.relational.lean.native_source_acceptance import (
    NativeSourceAcceptanceSpec,
    write_native_source_acceptance,
)
from spaghetti_extractor.relational.lean.native_source_nested_acceptance import (
    NativeSourceNestedAcceptanceSpec,
    write_native_source_nested_acceptance,
)
from spaghetti_extractor.relational.lean.native_source_nested_compiler_premise import (
    NativeSourceNestedCompilerPremiseSpec,
    write_native_source_nested_compiler_premise,
)
from spaghetti_extractor.relational.lean.native_source_compiled_authority import (
    NativeSourceCompiledAuthoritySpec,
    NixRealizationSpec,
    PinnedToolArtifactSpec,
    write_native_source_compiled_authority,
)
from spaghetti_extractor.relational.lean.interpreter_semantic_refinement import (
    relational_interpreter_semantic_refinement_bundle_sources,
    relational_interpreter_semantic_refinement_inventory,
)
from spaghetti_extractor.relational.lean.interpreter_x87 import (
    CandidateReplayProofSpec,
    relational_interpreter_x87_bundle_sources,
    relational_interpreter_x87_candidate_replay_inventory,
    relational_interpreter_x87_candidate_replay_sources,
    relational_interpreter_x87_module_inventory,
)
from spaghetti_extractor.relational.lean.interpreter_x87_replay_bridge_target import (
    X87_REPLAY_BRIDGE_TARGET_LEAN_BUNDLE,
    X87_REPLAY_BRIDGE_TARGET_PLAN_FILENAME,
    build_x87_replay_bridge_target_plan,
    x87_replay_bridge_target_lean_sources,
)
from spaghetti_extractor.relational.lean.interpreter_x87_replay_bridge_runtime import (
    X87_REPLAY_BRIDGE_RUNTIME_LEAN_BUNDLE,
    X87_REPLAY_BRIDGE_RUNTIME_PLAN_FORMAT,
    X87_REPLAY_BRIDGE_RUNTIME_PLAN_FILENAME,
    X87_REPLAY_FIXED_TEMPLATE_CERTIFICATE_PREMISES,
    X87_REPLAY_FIXED_TEMPLATE_CHECKS_TYPE,
    X87_REPLAY_FIXED_TEMPLATE_EXECUTOR_PREMISES,
    X87_REPLAY_FIXED_TEMPLATE_PROGRAM_BINDING_PREMISES,
    X87_REPLAY_FIXED_TEMPLATE_REMAINING_PREMISES,
    X87_REPLAY_FIXED_TEMPLATE_SOURCE_FRAME_ASSUMPTIONS,
    build_x87_replay_bridge_runtime_plan,
    x87_replay_bridge_runtime_lean_sources,
)
from spaghetti_extractor.relational.lean.pe_byte_packs import (
    generate_pe_byte_pack_bundle,
    load_pe_byte_pack_inventory,
)
from spaghetti_extractor.relational.lean.static_machine_import_contracts import (
    STATIC_MACHINE_IMPORT_FORMAT,
    STATIC_MACHINE_IMPORT_MODULE,
    StaticImportIdentity,
    StaticMachineImportLeanBindings,
    plan_static_machine_import_contracts,
    write_static_machine_import_contracts,
)
from spaghetti_extractor.relational.direct_call_proposal_ir import (
    direct_call_proposal_ir_from_plans,
    load_direct_call_proposal_ir,
)
from spaghetti_extractor.roundtrip_fuzz.image_contract import (
    write_stage_a_load_image_contract,
)
from spaghetti_extractor.stage_binary import _parse_stage_a_pe
from spaghetti_extractor.util import sha256_file, write_json


X87_KERNEL_EXECUTION_LEAN_MODULE = (
    "GeneratedRelationalInterpreterKernelX87Execution"
)
X87_KERNEL_EXECUTION_FRONTIER_FILENAME = (
    "x87-kernel-execution-frontier.json"
)
X87_KERNEL_EXECUTION_REMAINING_PROOF_PREMISES: tuple[str, ...] = ()
X87_KERNEL_EXECUTION_PREMISE_DETAILS: dict[str, tuple[str, ...]] = {}

NATIVE_SOURCE_COMPILED_AUTHORITY_DECLARATIONS_FORMAT = (
    "stage-a-gnu-hello-native-source-compiled-authority-declarations-v1"
)
NATIVE_SOURCE_ACCEPTANCE_DECLARATIONS_FORMAT = (
    "stage-a-native-source-acceptance-declarations-v1"
)
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


def _direct_call_integration_module(
    callsite_rva: int,
    edge_index: int,
) -> str:
    """Load the hot direct-call emitter only for phases that need it."""

    from spaghetti_extractor.relational.lean.internal_direct_call_semantics_bundle import (
        direct_call_integration_module,
    )

    return direct_call_integration_module(callsite_rva, edge_index)


def _jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{line_number}: expected a JSON object")
        rows.append(value)
    return rows


def _manifest(out: Path, phase: str, inputs: Mapping[str, Path], **extra: Any) -> None:
    write_json(
        out / "phase-manifest.json",
        {
            "format": "stage-a-relational-phase-v1",
            "phase": phase,
            "executes_original_binary": False,
            "executes_candidate_binary": False,
            "inputs": {
                role: {"path": path.name, "sha256": sha256_file(path)}
                for role, path in sorted(inputs.items())
            },
            **extra,
        },
    )


def _strict_json_object(
    path: Path, label: str, expected_keys: set[str]
) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read {label} {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    actual_keys = set(value)
    if actual_keys != expected_keys:
        missing = sorted(expected_keys - actual_keys)
        unexpected = sorted(actual_keys - expected_keys)
        raise ValueError(
            f"{label} has a non-canonical schema: missing={missing}, "
            f"unexpected={unexpected}"
        )
    return value


def _strict_mapping(
    value: object, label: str, expected_keys: set[str]
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an object")
    result = dict(value)
    if set(result) != expected_keys:
        missing = sorted(expected_keys - set(result))
        unexpected = sorted(set(result) - expected_keys)
        raise ValueError(
            f"{label} has a non-canonical schema: missing={missing}, "
            f"unexpected={unexpected}"
        )
    return result


def _strict_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or "\n" in value or "\r" in value:
        raise ValueError(f"{label} must be a non-empty single-line string")
    return value


def _strict_sha256(value: object, label: str) -> str:
    digest = _strict_string(value, label)
    if _SHA256_PATTERN.fullmatch(digest) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return digest


def _strict_natural(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{label} must be a natural number")
    return value


def _strict_string_tuple(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{label} must be a non-empty array")
    result = tuple(
        _strict_string(item, f"{label}[{index}]")
        for index, item in enumerate(value)
    )
    if len(set(result)) != len(result):
        raise ValueError(f"{label} must not contain duplicates")
    return result


def _canonical_json_sha256(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return sha256(encoded).hexdigest()


def _nix_realization_from_provenance(
    path: Path,
    label: str,
    *,
    expected_output: Path | None = None,
    expected_nar_hash: str | None = None,
) -> NixRealizationSpec:
    payload = _strict_json_object(
        path,
        label,
        {"output", "derivation", "registered_deriver", "nar_hash"},
    )
    output = Path(_strict_string(payload["output"], f"{label} output"))
    derivation = Path(
        _strict_string(payload["derivation"], f"{label} derivation")
    )
    registered = Path(
        _strict_string(
            payload["registered_deriver"], f"{label} registered deriver"
        )
    )
    nar_hash = _strict_string(payload["nar_hash"], f"{label} NAR hash")
    if not output.is_absolute() or not output.is_dir():
        raise ValueError(f"{label} output is not a realized absolute directory")
    if not derivation.is_absolute() or derivation.suffix != ".drv":
        raise ValueError(f"{label} derivation is not an absolute .drv path")
    if not derivation.is_file() or registered != derivation:
        raise ValueError(f"{label} planned and registered derivations differ")
    if expected_output is not None and output.resolve() != expected_output.resolve():
        raise ValueError(f"{label} output does not match the bound artifact")
    if expected_nar_hash is not None and nar_hash != expected_nar_hash:
        raise ValueError(f"{label} NAR hash does not match the bound artifact")
    spec = NixRealizationSpec(
        derivation_path=str(derivation.resolve()),
        derivation_sha256=sha256_file(derivation),
        output_path=str(output.resolve()),
        nar_hash=nar_hash,
    )
    spec.validate(label)
    return spec


def _candidate_import_inventory(binary: object) -> list[dict[str, object]]:
    return [
        {
            "dll": item.dll,
            "symbol": item.symbol,
            "ordinal": item.ordinal,
            "thunk_rva": item.thunk_rva,
        }
        for item in binary.imports
    ]


def _source_bundle_digests(bundle: Mapping[str, Any], path: Path) -> set[str]:
    digests = {
        sha256_file(path),
        _strict_sha256(
            bundle["hashes"]["source_bundle_sha256"],
            "source bundle closure digest",
        ),
        _strict_sha256(
            bundle["state_machine"]["sha256"], "state-machine digest"
        ),
        _strict_sha256(
            bundle["load_image_contract"]["artifact_sha256"],
            "load-image artifact digest",
        ),
    }
    for package in bundle["packages"].values():
        digests.add(_strict_sha256(package["manifest"]["sha256"], "package manifest"))
        for artifact in package["artifacts"]:
            digests.add(_strict_sha256(artifact["sha256"], "source artifact"))
    return digests


def _pinned_tool_spec(
    raw: object,
    label: str,
    *,
    allowed_digests: set[str],
) -> PinnedToolArtifactSpec:
    value = _strict_mapping(
        raw,
        label,
        {"identifier", "exact_artifact", "evidence_sha256"},
    )
    digest = _strict_sha256(value["evidence_sha256"], f"{label} evidence")
    if digest not in allowed_digests:
        raise ValueError(f"{label} evidence is outside the exact source/build closure")
    return PinnedToolArtifactSpec(
        identifier=_strict_string(value["identifier"], f"{label} identifier"),
        exact_artifact=_strict_string(
            value["exact_artifact"], f"{label} exact artifact"
        ),
    )


def _smoke(args: argparse.Namespace) -> None:
    original = Path(args.original)
    linker_map = Path(args.linker_map)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    binary = _parse_stage_a_pe(original)
    try:
        if binary.machine != "i386" or binary.bitness != 32:
            raise ValueError("GNU hello smoke input is not an i386 PE32 image")
        if not linker_map.is_file() or not linker_map.read_bytes():
            raise ValueError("GNU hello smoke input has no linker map")
        payload = {
            "format": "stage-a-gnu-hello-roundtrip-smoke-v1",
            "status": "pass",
            "static_only": True,
            "executes_original_binary": False,
            "executes_candidate_binary": False,
            "original": {
                "sha256": binary.sha256,
                "machine": binary.machine,
                "bitness": binary.bitness,
                "entry_rva": binary.entrypoint_rva,
                "sections": len(binary.sections),
            },
            "linker_map_sha256": sha256_file(linker_map),
        }
        write_json(out / "smoke.json", payload)
    finally:
        binary.pe.close()


def _native_launch_request(args: argparse.Namespace) -> None:
    """Record exact candidate roots while failing closed on missing routes."""

    candidate = Path(args.candidate)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    binary = _parse_stage_a_pe(candidate)
    try:
        if binary.machine != "i386" or binary.bitness != 32:
            raise ValueError("native launch requests require an x86 PE32 candidate")
        if binary.entrypoint_rva <= 0:
            raise ValueError("native launch candidate has no canonical entrypoint")
        if binary.tls_callback_rvas is None:
            detail = binary.tls_callback_parse_error or "unknown parse error"
            raise ValueError(
                f"native launch candidate TLS callbacks are ambiguous: {detail}"
            )
        if binary.tls_callback_array_immutable is not True:
            raise ValueError("native launch candidate TLS callback array is writable")
        canonical_sources = [
            {
                "kind": "entry",
                "index": None,
                "rva": binary.entrypoint_rva,
            },
            *[
                {"kind": "tls_callback", "index": index, "rva": rva}
                for index, rva in enumerate(binary.tls_callback_rvas)
            ],
        ]
    finally:
        binary.pe.close()

    payload = {
        "format": "stage-a-native-launch-route-request-v1",
        "status": "incomplete",
        "acceptance_authority": False,
        "candidate_sha256": sha256_file(candidate),
        "canonical_sources": canonical_sources,
        "required_path_shapes": [
            "entry stub -> payload entry -> native run -> first operation",
            "each exact TLS callback wrapper -> native run -> first operation",
            "each exact return wrapper -> returned",
            "each exact termination wrapper -> terminated",
        ],
        "missing_inputs": [
            "exact dispatch cutpoint inventory",
            "exact return-wrapper cutpoint inventory",
            "exact termination-wrapper cutpoint inventory",
            "finite decoded instruction routes for every required source",
            "named Lean route binding from the checked certificate to launch_chunk",
        ],
        "forbidden_authority": [
            "DirectExactCandidateNativeLaunchRoot",
            "candidate root identity as launch_chunk",
            "pre-populated engine-buffer state",
            "this JSON request or any standalone checker status",
        ],
    }
    request_path = out / "native-launch-route-request.json"
    write_json(request_path, payload)
    _manifest(
        out,
        "native-launch-route-request",
        {"candidate_pe": candidate},
        status="incomplete",
        proof_authority=False,
        acceptance_authority=False,
        request=request_path.name,
        counts={"canonical_sources": len(canonical_sources)},
        missing_inputs=payload["missing_inputs"],
    )


def _static_export(args: argparse.Namespace) -> None:
    from spaghetti_extractor.stage_b_state_machine import (
        write_stage_b_state_machine_from_stage_a_export,
    )

    original = Path(args.original)
    linker_map = Path(args.linker_map)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    self_map = out / "original-self-map.json"
    result = stage_a_generate_map(
        original=original,
        candidate=original,
        linker_map_original=linker_map,
        linker_map_candidate=linker_map,
        out=self_map,
        original_flags="opaque-static-original",
        candidate_flags="opaque-static-reference",
    )
    if result.get("status") != "pass":
        raise ValueError("Stage A could not map the GNU hello image to itself")
    reference = out / "reference-contract.json"
    stage_a_export_reference_contract(
        original=original,
        out=reference,
        mapping=self_map,
        sidecar_dir=out,
        unit_contract_dir=out,
    )
    semantic = out / "semantic-transfer-contracts.jsonl"
    state_machine = out / "state-machine.jsonl"
    write_stage_b_state_machine_from_stage_a_export(
        reference_contract=reference,
        semantic_transfer_contracts=semantic,
        original_pe=original,
        out=state_machine,
    )
    load_image = out / "load-image-contract.json"
    load_contract = write_stage_a_load_image_contract(
        original_pe=original, out=load_image
    )
    _manifest(
        out,
        "static-export",
        {"original_pe": original, "original_linker_map": linker_map},
        status="ready",
        public_outputs={
            "reference_contract": reference.name,
            "semantic_transfers": semantic.name,
            "state_machine": state_machine.name,
            "load_image_contract": load_image.name,
            "original_self_map": self_map.name,
        },
        counts={
            "transfers": len(_jsonl(state_machine)),
            "imports": sum(len(item.cells) for item in load_contract.imports),
            "tls_callbacks": (
                0 if load_contract.tls is None else len(load_contract.tls.callbacks)
            ),
        },
    )


def _original_pe_source(args: argparse.Namespace) -> None:
    original = Path(args.original)
    out = Path(args.out)
    inventory = generate_pe_byte_pack_bundle(
        pe_path=original,
        out_dir=out,
        module_prefix="GeneratedGnuHelloOriginal",
        namespace="StageA.GeneratedRelational",
        pack_size=8 * 1024,
        chunk_size=256,
        standalone=False,
        authoritative_module="GeneratedGnuHelloOriginalPE",
        authoritative_bytes_name="originalBytes",
        authoritative_pe_name="originalPe",
        runtime_binding_prefix="original",
    )
    _manifest(
        out,
        "original-pe-lean",
        {"original_pe": original},
        status="source-ready",
        modules=[row["name"] for row in inventory.modules],
        counts={"byte_packs": len(inventory.packs)},
    )


def _program_source(args: argparse.Namespace) -> None:
    from spaghetti_extractor.stage_b_interpreter_backend import (
        compile_stage_b_interpreter_program,
    )

    machine = Path(args.state_machine)
    out = Path(args.out)
    stage_a = out / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    raw_rows = _jsonl(machine)
    compiled = compile_stage_b_interpreter_program(machine)
    if len(compiled) != len(raw_rows):
        raise ValueError("compiled interpreter transfer inventory changed cardinality")
    ordinary = [
        transfer
        for row, transfer in zip(raw_rows, compiled, strict=True)
        if not is_x87_row(row)
    ]
    x87 = [
        transfer
        for row, transfer in zip(raw_rows, compiled, strict=True)
        if is_x87_row(row)
    ]
    # Keep ordinary indices stable because normalization shards name records by
    # this prefix.  x87 behavior belongs exclusively to the checked provider;
    # including synthetic replay records here would create a second authority.
    source = relational_interpreter_program_source(ordinary)
    destination = stage_a / "GeneratedSemanticInterpreterProgram.lean"
    destination.write_text(source, encoding="utf-8")
    _manifest(
        out,
        "semantic-program-lean",
        {"state_machine": machine},
        status="source-ready",
        modules=[destination.stem],
        counts={
            "transfers": len(compiled),
            "ordinary_transfers": len(ordinary),
            "x87_transfers": len(x87),
        },
    )


def _normalization_sources(args: argparse.Namespace) -> None:
    machine = Path(args.state_machine)
    out = Path(args.out)
    stage_a = out / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    ordinary = [row for row in _jsonl(machine) if not is_x87_row(row)]
    sources = relational_interpreter_normalization_bundle_sources(
        ordinary,
        source_module="StageA.GeneratedSemanticInterpreterProgram",
        pe_name="StageA.GeneratedRelational.originalPe",
        shard_size=args.shard_size,
        semantic_refinement_module=(
            "StageA.GeneratedInterpreterSemanticRefinementBundle"
        ),
        emit_acceptance_inventory=not args.source_bindings_only,
        emit_source_binding_inventory=args.source_bindings_only,
    )
    for module, source in sources.items():
        (stage_a / f"{module}.lean").write_text(source, encoding="utf-8")
    inventory = relational_interpreter_normalization_inventory(
        machine, shard_size=args.shard_size
    )
    module_inventory = relational_interpreter_normalization_module_inventory(
        sources, target="GeneratedInterpreterNormalizationBundle"
    )
    write_json(out / "normalization-inventory.json", inventory)
    write_json(out / "module-inventory.json", module_inventory)
    _manifest(
        out,
        "normalization-lean",
        {"state_machine": machine},
        status="source-ready",
        modules=sorted(sources),
        targets=["GeneratedInterpreterNormalizationBundle"],
        diagnostic_status=inventory["status"],
    )


def _semantic_refinement_sources(args: argparse.Namespace) -> None:
    machine = Path(args.state_machine)
    out = Path(args.out)
    stage_a = out / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    rows = _jsonl(machine)
    ordinary_count = sum(not is_x87_row(row) for row in rows)
    sources = relational_interpreter_semantic_refinement_bundle_sources(
        rows,
        pe_module="StageA.GeneratedGnuHelloOriginalPE",
        shard_size=args.shard_size,
    )
    for module, source in sources.items():
        (stage_a / f"{module}.lean").write_text(source, encoding="utf-8")
    inventory = relational_interpreter_semantic_refinement_inventory(
        sources, transfer_count=ordinary_count
    )
    write_json(out / "semantic-refinement-inventory.json", inventory)
    _manifest(
        out,
        "semantic-refinement-lean",
        {"state_machine": machine},
        status="source-ready",
        modules=sorted(sources),
        targets=[inventory["target"]],
        counts={
            "ordinary_transfers": ordinary_count,
            "semantic_refinement_theorems": inventory["theorem_count"],
            "shards": inventory["shard_count"],
        },
        proof_authority=False,
        validation_required="remote_nix_lean_graph",
    )


def _native_source_program(args: argparse.Namespace) -> None:
    out = Path(args.out)
    destination = write_native_source_program(
        out,
        NativeSourceProgramSpec(
            decoded_original_module="StageA.GeneratedGnuHelloOriginalPE",
            # These fixed-world declarations are unused in the polymorphic
            # form, but remain validated for one stable generator schema.
            decoded_original_program="StageA.GeneratedRelational.originalProgram",
            decoded_original_side="StageA.GeneratedRelational.originalProgramSide",
            original_pe="StageA.GeneratedRelational.originalPe",
            decoded_original_pe_exact=(
                "StageA.GeneratedRelational.originalProgramPeExact"
            ),
            semantic_program_module=(
                "StageA.GeneratedSemanticInterpreterProgram"
            ),
            semantic_program_records=(
                "StageA.GeneratedRelational.semanticInterpreterProgramRecords"
            ),
            semantic_program_records_unique=(
                "StageA.GeneratedRelational."
                "semanticInterpreterProgramSourceRvasUnique"
            ),
            normalization_module=(
                "StageA.GeneratedInterpreterNormalizationBundle"
            ),
            ordinary_record_bindings=(
                "StageA.GeneratedRelational."
                "exactNormalizedOrdinaryRecordBindings"
            ),
            x87_schedule_module=(
                "StageA.GeneratedInterpreterX87ScheduleBundle"
            ),
            x87_witnesses=(
                "StageA.GeneratedRelational."
                "checkedInterpreterX87ScheduleBundleWitnesses"
            ),
            x87_source_rvas=(
                "StageA.GeneratedRelational."
                "checkedInterpreterX87ScheduleBundleSourceRvas"
            ),
            x87_source_rvas_nodup=(
                "StageA.GeneratedRelational."
                "checkedInterpreterX87ScheduleBundleSourceRvasNodup"
            ),
            namespace=(
                "StageA.GeneratedRelational.GnuHelloNativeSourceProgram"
            ),
            output_module="GeneratedGnuHelloNativeSourceProgram",
            parameterize_world_program=True,
        ),
    )
    _manifest(
        out,
        "native-source-program",
        {},
        status="source-ready",
        modules=[destination.stem],
        targets=[destination.stem],
    )


def _native_source_compiled_authority(args: argparse.Namespace) -> None:
    """Assemble exact compiled authority from closed static evidence only."""

    from spaghetti_extractor.native_source_equivalence import (
        validate_native_source_bundle_manifest,
        validate_native_source_compilation_attestation,
    )

    source_bundle_path = Path(args.source_bundle)
    attestation_path = Path(args.compilation_attestation)
    declarations_path = Path(args.declarations)
    project_nix_path = Path(args.project_nix_provenance)
    profile_nix_path = Path(args.profile_nix_provenance)
    build_nix_path = Path(args.build_nix_provenance)
    out = Path(args.out)

    bundle = validate_native_source_bundle_manifest(source_bundle_path)
    attestation = validate_native_source_compilation_attestation(attestation_path)
    source_binding = _strict_mapping(
        attestation["source_bundle"],
        "compilation attestation source bundle",
        {"path", "size", "artifact_sha256", "source_bundle_sha256"},
    )
    if Path(source_binding["path"]).resolve() != source_bundle_path.resolve():
        raise ValueError("compilation attestation binds a different source bundle")
    if source_binding["artifact_sha256"] != sha256_file(source_bundle_path):
        raise ValueError("compilation attestation source-bundle hash mismatch")
    if source_binding["source_bundle_sha256"] != bundle["hashes"][
        "source_bundle_sha256"
    ]:
        raise ValueError("compilation attestation source closure mismatch")

    candidate_binding = _strict_mapping(
        attestation["candidate"],
        "compiled candidate binding",
        {"path", "sha256", "size"},
    )
    candidate = Path(_strict_string(candidate_binding["path"], "candidate path"))
    if (
        sha256_file(candidate)
        != _strict_sha256(candidate_binding["sha256"], "candidate SHA-256")
        or candidate.stat().st_size
        != _strict_natural(candidate_binding["size"], "candidate size")
    ):
        raise ValueError("compiled candidate bytes differ from the attestation")

    declaration_manifest = _strict_json_object(
        declarations_path,
        "native-source compiled-authority declarations",
        {"format", "bindings", "lean"},
    )
    if (
        declaration_manifest["format"]
        != NATIVE_SOURCE_COMPILED_AUTHORITY_DECLARATIONS_FORMAT
    ):
        raise ValueError("unsupported native-source compiled-authority declarations")
    bindings = _strict_mapping(
        declaration_manifest["bindings"],
        "compiled-authority bindings",
        {
            "source_bundle_sha256",
            "source_bundle_artifact_sha256",
            "attestation_core_sha256",
            "attestation_artifact_sha256",
            "candidate_sha256",
            "candidate_size",
            "candidate_entry_rva",
            "candidate_image_base",
            "candidate_imports",
            "relocation_inventory",
            "project_nar_hash",
            "profile_nar_hash",
            "build_nar_hash",
        },
    )
    exact_bindings = {
        "source_bundle_sha256": bundle["hashes"]["source_bundle_sha256"],
        "source_bundle_artifact_sha256": sha256_file(source_bundle_path),
        "attestation_core_sha256": attestation["hashes"][
            "attestation_core_sha256"
        ],
        "attestation_artifact_sha256": sha256_file(attestation_path),
        "candidate_sha256": candidate_binding["sha256"],
        "candidate_size": candidate_binding["size"],
    }
    for field, expected in exact_bindings.items():
        if bindings[field] != expected:
            raise ValueError(f"compiled-authority {field} binding mismatch")

    binary = _parse_stage_a_pe(candidate)
    try:
        if binary.machine != "i386" or binary.bitness != 32:
            raise ValueError("compiled authority requires an i386 PE32 candidate")
        if bindings["candidate_entry_rva"] != binary.entrypoint_rva:
            raise ValueError("compiled-authority candidate entry RVA mismatch")
        if bindings["candidate_image_base"] != binary.image_base:
            raise ValueError("compiled-authority candidate image-base mismatch")
        if bindings["candidate_imports"] != _candidate_import_inventory(binary):
            raise ValueError("compiled-authority candidate import inventory mismatch")
    finally:
        binary.pe.close()

    relocation = _strict_mapping(
        attestation["relocations"],
        "compilation attestation relocation inventory",
        {
            "path",
            "size",
            "sha256",
            "format",
            "canonical_sha256",
            "payload_sha256",
            "count",
            "complete",
        },
    )
    expected_relocation = {
        key: relocation[key]
        for key in (
            "sha256",
            "canonical_sha256",
            "payload_sha256",
            "count",
            "complete",
        )
    }
    if bindings["relocation_inventory"] != expected_relocation:
        raise ValueError("compiled-authority relocation inventory mismatch")
    if relocation["complete"] is not True:
        raise ValueError("compiled-authority relocation inventory is incomplete")

    project_nix = _nix_realization_from_provenance(
        project_nix_path,
        "native-source project Nix provenance",
        expected_output=source_bundle_path.parent,
        expected_nar_hash=_strict_string(
            bindings["project_nar_hash"], "project NAR binding"
        ),
    )
    profile_nix = _nix_realization_from_provenance(
        profile_nix_path,
        "native-source profile Nix provenance",
        expected_nar_hash=_strict_string(
            bindings["profile_nar_hash"], "profile NAR binding"
        ),
    )
    build_nix = _nix_realization_from_provenance(
        build_nix_path,
        "native-source build Nix provenance",
        expected_output=candidate.parent,
        expected_nar_hash=_strict_string(
            bindings["build_nar_hash"], "build NAR binding"
        ),
    )
    if (
        build_nix.derivation_path != attestation["nix"]["derivation"]
        or build_nix.output_path != attestation["nix"]["output"]
        or build_nix.nar_hash != attestation["nix"]["nar_hash"]
    ):
        raise ValueError("compiled-authority build Nix identity mismatch")

    lean = _strict_mapping(
        declaration_manifest["lean"],
        "compiled-authority Lean declarations",
        {
            "imports",
            "world_program",
            "checked_input",
            "checked_input_nonempty",
            "bundle_manifest_artifact",
            "renderer_input_artifact",
            "source_artifacts",
            "source_artifact_evidence_sha256s",
            "source_artifact_roles_nodup",
            "profile_identifier",
            "tools",
            "compiled_identity",
            "compiled_identity_valid",
            "compiled_bytes",
            "compiled_pe",
            "compiled_byte_length_exact",
            "compiled_pe_parsed_exact",
            "compiled_pe_bytes_exact",
            "import_certificate",
            "imports_parsed",
            "relocations",
            "relocations_parsed",
            "loader_image_valid",
            "environment",
            "indirect_targets",
            "indirect_targets_valid",
            "callable_external",
            "callable_bound",
            "namespace",
            "output_module",
            "audit_output_module",
        },
    )
    source_artifacts = _strict_string_tuple(
        lean["source_artifacts"], "source artifact declarations"
    )
    evidence = lean["source_artifact_evidence_sha256s"]
    if not isinstance(evidence, list) or len(evidence) != len(source_artifacts):
        raise ValueError("source artifact declarations and evidence differ in length")
    source_digests = _source_bundle_digests(bundle, source_bundle_path)
    source_evidence = tuple(
        _strict_sha256(value, f"source artifact evidence[{index}]")
        for index, value in enumerate(evidence)
    )
    if len(set(source_evidence)) != len(source_evidence):
        raise ValueError("source artifact evidence must be one-to-one")
    if any(digest not in source_digests for digest in source_evidence):
        raise ValueError("source artifact evidence is outside the source bundle")

    tool_rows = _strict_mapping(
        lean["tools"],
        "pinned tool declarations",
        {"renderer", "lowering", "runtime", "compiler", "assembler", "linker", "abi"},
    )
    attested_tools = {
        row["role"]: row["sha256"] for row in attestation["tools"]
    }
    allowed_tool_digests = source_digests | set(attested_tools.values())
    tools = {
        role: _pinned_tool_spec(
            tool_rows[role], role, allowed_digests=allowed_tool_digests
        )
        for role in tool_rows
    }
    for role in ("compiler", "assembler", "linker"):
        evidence_digest = tool_rows[role]["evidence_sha256"]
        if attested_tools.get(role) != evidence_digest:
            raise ValueError(f"{role} declaration does not bind the attested tool")

    callable_external = lean["callable_external"]
    callable_bound = lean["callable_bound"]
    if callable_external is not None:
        callable_external = _strict_string(callable_external, "callable external")
    if callable_bound is not None:
        callable_bound = _strict_string(callable_bound, "callable bound")

    spec = NativeSourceCompiledAuthoritySpec(
        imports=_strict_string_tuple(lean["imports"], "authority imports"),
        world_program=_strict_string(lean["world_program"], "world program"),
        checked_input=_strict_string(lean["checked_input"], "checked input"),
        checked_input_nonempty=_strict_string(
            lean["checked_input_nonempty"], "checked-input proof"
        ),
        bundle_manifest_artifact=_strict_string(
            lean["bundle_manifest_artifact"], "bundle-manifest artifact"
        ),
        renderer_input_artifact=_strict_string(
            lean["renderer_input_artifact"], "renderer-input artifact"
        ),
        source_artifacts=source_artifacts,
        source_artifact_roles_nodup=_strict_string(
            lean["source_artifact_roles_nodup"], "source-role uniqueness proof"
        ),
        project_nix=project_nix,
        profile_identifier=_strict_string(
            lean["profile_identifier"], "profile identifier"
        ),
        profile_nix=profile_nix,
        renderer=tools["renderer"],
        lowering=tools["lowering"],
        runtime=tools["runtime"],
        compiler=tools["compiler"],
        assembler=tools["assembler"],
        linker=tools["linker"],
        abi=tools["abi"],
        compiled_identity=_strict_string(
            lean["compiled_identity"], "compiled identity"
        ),
        compiled_identity_valid=_strict_string(
            lean["compiled_identity_valid"], "compiled identity proof"
        ),
        compiled_bytes=_strict_string(lean["compiled_bytes"], "compiled bytes"),
        compiled_pe=_strict_string(lean["compiled_pe"], "compiled PE"),
        compiled_byte_length_exact=_strict_string(
            lean["compiled_byte_length_exact"], "byte-length proof"
        ),
        compiled_pe_parsed_exact=_strict_string(
            lean["compiled_pe_parsed_exact"], "PE-parse proof"
        ),
        compiled_pe_bytes_exact=_strict_string(
            lean["compiled_pe_bytes_exact"], "PE-bytes proof"
        ),
        build_nix=build_nix,
        import_certificate=_strict_string(
            lean["import_certificate"], "import certificate"
        ),
        imports_parsed=_strict_string(lean["imports_parsed"], "imports proof"),
        relocations=_strict_string(lean["relocations"], "relocations"),
        relocations_parsed=_strict_string(
            lean["relocations_parsed"], "relocations proof"
        ),
        loader_image_valid=_strict_string(
            lean["loader_image_valid"], "loader-image proof"
        ),
        environment=_strict_string(lean["environment"], "environment"),
        indirect_targets=_strict_string(
            lean["indirect_targets"], "indirect-target inventory"
        ),
        indirect_targets_valid=_strict_string(
            lean["indirect_targets_valid"], "indirect-target proof"
        ),
        callable_external=callable_external,
        callable_bound=callable_bound,
        namespace=_strict_string(lean["namespace"], "authority namespace"),
        output_module=_strict_string(lean["output_module"], "authority module"),
        audit_output_module=_strict_string(
            lean["audit_output_module"], "authority audit module"
        ),
    )
    authority_path, audit_path = write_native_source_compiled_authority(out, spec)
    exports = {
        "profile": f"{spec.namespace}.{spec.profile_name}",
        "project": f"{spec.namespace}.{spec.project_name}",
        "artifact": f"{spec.namespace}.{spec.artifact_name}",
        "machine_authority": f"{spec.namespace}.{spec.authority_name}",
        "project_valid": f"{spec.namespace}.{spec.project_valid_name}",
        "profile_pinned": f"{spec.namespace}.{spec.profile_pinned_name}",
        "profile_matches": f"{spec.namespace}.{spec.profile_matches_name}",
        "built_from": f"{spec.namespace}.{spec.built_from_name}",
        "exact_compilation": f"{spec.namespace}.{spec.compilation_constructor_name}",
    }
    out.mkdir(parents=True, exist_ok=True)
    _manifest(
        out,
        "native-source-compiled-authority",
        {
            "source_bundle": source_bundle_path,
            "compilation_attestation": attestation_path,
            "declarations": declarations_path,
            "project_nix_provenance": project_nix_path,
            "profile_nix_provenance": profile_nix_path,
            "build_nix_provenance": build_nix_path,
            "authority_module": authority_path,
            "audit_module": audit_path,
        },
        proof_authority=False,
        acceptance_authority=False,
        modules=[authority_path.stem, audit_path.stem],
        exports=exports,
        bindings={
            "source_bundle_sha256": exact_bindings["source_bundle_sha256"],
            "attestation_core_sha256": exact_bindings["attestation_core_sha256"],
            "candidate_sha256": exact_bindings["candidate_sha256"],
            "candidate_entry_rva": bindings["candidate_entry_rva"],
            "candidate_imports_sha256": _canonical_json_sha256(
                bindings["candidate_imports"]
            ),
            "relocation_inventory_sha256": _canonical_json_sha256(
                expected_relocation
            ),
        },
    )


def _native_source_acceptance(args: argparse.Namespace) -> None:
    """Assemble environment-family acceptance without status metadata."""

    from spaghetti_extractor.native_source_equivalence import (
        validate_native_source_bundle_manifest,
        validate_native_source_compilation_attestation,
    )

    source_bundle_path = Path(args.source_bundle)
    attestation_path = Path(args.compilation_attestation)
    authority_manifest_path = Path(args.compiled_authority_manifest)
    declarations_path = Path(args.declarations)
    out = Path(args.out)

    bundle = validate_native_source_bundle_manifest(source_bundle_path)
    attestation = validate_native_source_compilation_attestation(attestation_path)
    authority_manifest = json.loads(
        authority_manifest_path.read_text(encoding="utf-8")
    )
    if not isinstance(authority_manifest, Mapping):
        raise ValueError("compiled-authority phase manifest must be an object")
    if (
        authority_manifest.get("format") != "stage-a-relational-phase-v1"
        or authority_manifest.get("phase") != "native-source-compiled-authority"
        or authority_manifest.get("proof_authority") is not False
        or authority_manifest.get("acceptance_authority") is not False
        or authority_manifest.get("executes_original_binary") is not False
        or authority_manifest.get("executes_candidate_binary") is not False
    ):
        raise ValueError("compiled-authority phase manifest has an invalid trust role")
    authority_bindings = _strict_mapping(
        authority_manifest.get("bindings"),
        "compiled-authority phase bindings",
        {
            "source_bundle_sha256",
            "attestation_core_sha256",
            "candidate_sha256",
            "candidate_entry_rva",
            "candidate_imports_sha256",
            "relocation_inventory_sha256",
        },
    )
    expected_authority_bindings = {
        "source_bundle_sha256": bundle["hashes"]["source_bundle_sha256"],
        "attestation_core_sha256": attestation["hashes"][
            "attestation_core_sha256"
        ],
        "candidate_sha256": attestation["candidate"]["sha256"],
    }
    for field, expected in expected_authority_bindings.items():
        if authority_bindings[field] != expected:
            raise ValueError(f"acceptance authority {field} mismatch")

    declaration_manifest = _strict_json_object(
        declarations_path,
        "native-source acceptance declarations",
        {"format", "bindings", "lean"},
    )
    if declaration_manifest["format"] != NATIVE_SOURCE_ACCEPTANCE_DECLARATIONS_FORMAT:
        raise ValueError("unsupported native-source acceptance declarations")
    bindings = _strict_mapping(
        declaration_manifest["bindings"],
        "native-source acceptance bindings",
        {
            "compiled_authority_manifest_sha256",
            "source_bundle_sha256",
            "attestation_core_sha256",
            "candidate_sha256",
            "source_entry_rva",
            "compiled_entry_rva",
        },
    )
    expected = {
        "compiled_authority_manifest_sha256": sha256_file(
            authority_manifest_path
        ),
        "source_bundle_sha256": bundle["hashes"]["source_bundle_sha256"],
        "attestation_core_sha256": attestation["hashes"][
            "attestation_core_sha256"
        ],
        "candidate_sha256": attestation["candidate"]["sha256"],
        "source_entry_rva": bundle["entry_rva"],
    }
    for field, value in expected.items():
        if bindings[field] != value:
            raise ValueError(f"native-source acceptance {field} mismatch")

    candidate = Path(attestation["candidate"]["path"])
    binary = _parse_stage_a_pe(candidate)
    try:
        if binary.machine != "i386" or binary.bitness != 32:
            raise ValueError("native-source acceptance requires i386 PE32")
        if bindings["compiled_entry_rva"] != binary.entrypoint_rva:
            raise ValueError("native-source acceptance compiled entry mismatch")
        if authority_bindings["candidate_entry_rva"] != binary.entrypoint_rva:
            raise ValueError("compiled authority and acceptance launch entries differ")
    finally:
        binary.pe.close()

    lean = _strict_mapping(
        declaration_manifest["lean"],
        "native-source acceptance Lean declarations",
        {
            "imports",
            "context",
            "sites",
            "static_compilation",
            "static_authority",
            "pair_relation",
            "admitted_pair_evidence",
            "toolchain_correct",
            "namespace",
            "output_module",
            "audit_output_module",
            "compilation_name",
            "environment_family_name",
            "theorem_name",
        },
    )
    _strict_mapping(
        authority_manifest.get("exports"),
        "compiled-authority exports",
        {
            "profile",
            "project",
            "artifact",
            "machine_authority",
            "project_valid",
            "profile_pinned",
            "profile_matches",
            "built_from",
            "exact_compilation",
        },
    )

    spec = NativeSourceAcceptanceSpec(
        imports=_strict_string_tuple(lean["imports"], "acceptance imports"),
        context=_strict_string(lean["context"], "static proof context"),
        sites=_strict_string(lean["sites"], "lockstep call sites"),
        static_compilation=_strict_string(
            lean["static_compilation"], "exact static compilation"
        ),
        static_authority=_strict_string(
            lean["static_authority"], "static environment-family authority"
        ),
        pair_relation=_strict_string(
            lean["pair_relation"], "admitted environment-pair relation"
        ),
        admitted_pair_evidence=_strict_string(
            lean["admitted_pair_evidence"], "checked admitted-pair evidence"
        ),
        toolchain_correct=_strict_string(
            lean["toolchain_correct"], "pair-indexed toolchain premise"
        ),
        namespace=_strict_string(lean["namespace"], "acceptance namespace"),
        output_module=_strict_string(lean["output_module"], "acceptance module"),
        audit_output_module=_strict_string(
            lean["audit_output_module"], "acceptance audit module"
        ),
        compilation_name=_strict_string(
            lean["compilation_name"], "compilation name"
        ),
        environment_family_name=_strict_string(
            lean["environment_family_name"], "environment-family name"
        ),
        theorem_name=_strict_string(lean["theorem_name"], "theorem name"),
    )
    acceptance_path, audit_path = write_native_source_acceptance(out, spec)
    out.mkdir(parents=True, exist_ok=True)
    _manifest(
        out,
        "native-source-conditional-acceptance",
        {
            "source_bundle": source_bundle_path,
            "compilation_attestation": attestation_path,
            "compiled_authority_manifest": authority_manifest_path,
            "declarations": declarations_path,
            "acceptance_module": acceptance_path,
            "audit_module": audit_path,
        },
        proof_authority=False,
        acceptance_authority=False,
        conditional_on=_strict_string(
            spec.toolchain_correct, "pair-indexed toolchain premise"
        ),
        modules=[acceptance_path.stem, audit_path.stem],
        theorem=f"{spec.namespace}.{spec.theorem_name}",
        bindings=expected,
    )


def _native_source_nested_compiler_premise(args: argparse.Namespace) -> None:
    """Emit the sole approved callback-capable compiler premise."""

    write_native_source_nested_compiler_premise(
        args.out,
        NativeSourceNestedCompilerPremiseSpec(
            response_family_module=args.response_family_module,
            premise_type=args.premise_type,
        ),
    )


def _native_source_nested_acceptance(args: argparse.Namespace) -> None:
    """Assemble callback-capable final acceptance from exact Lean terms."""

    write_native_source_nested_acceptance(
        args.out,
        NativeSourceNestedAcceptanceSpec(
            imports=tuple(args.imports),
            context=args.context,
            classified_sites=args.classified_sites,
            ordinary_sites=args.ordinary_sites,
            static_compilation=args.static_compilation,
            mixed_contract=args.mixed_contract,
            nested_frames=args.nested_frames,
            checked_response_family=args.checked_response_family,
            checked_response_family_completion=(
                args.checked_response_family_completion
            ),
            toolchain_correct=args.toolchain_correct,
        ),
    )


def _native_source_execution(args: argparse.Namespace) -> None:
    """Assemble the complete checked GNU hello source-launch family."""

    result = write_gnu_hello_source_execution_from_artifacts(
        args.out,
        args.mixed_original_plan,
        args.writable_authority_report,
        args.register_authority_report,
        args.stack_dynamic_authority_report,
        args.evidence_manifest,
    )
    if not result.launch_family_complete:
        raise ValueError(
            "GNU hello source execution family is incomplete; see "
            f"{result.manifest}"
        )


def _source_transition_index(args: argparse.Namespace) -> None:
    """Generate the exact original/source transition index."""

    generate_gnu_hello_source_transition_index(
        args.out,
        mixed_original_manifest=args.mixed_original_manifest,
        source_program_manifest=args.source_program_manifest,
        normalization_manifest=args.normalization_manifest,
        x87_manifest=args.x87_manifest,
        declaration_inventory=args.declaration_inventory,
    )


def _source_target_effect_inputs(args: argparse.Namespace) -> None:
    """Generate exact authority inputs for reachable GNU target effects."""

    generate_gnu_hello_source_target_effect_inputs(
        args.out,
        state_machine=args.state_machine,
        mixed_original_plan=args.mixed_original_plan,
        source_program_root=args.source_program_root,
        source_program_manifest=args.source_program_manifest,
        normalization_root=args.normalization_root,
        normalization_inventory=args.normalization_inventory,
        semantic_refinement_root=args.semantic_refinement_root,
        semantic_refinement_inventory=args.semantic_refinement_inventory,
        x87_root=args.x87_root,
        x87_inventory=args.x87_inventory,
        exact_original_root=args.exact_original_root,
        shard_span=args.shard_span,
    )


def _source_target_effects(args: argparse.Namespace) -> None:
    """Generate exact per-target transition effects for reachable GNU code."""

    generate_gnu_hello_source_target_effects(
        args.out,
        artifacts=GnuHelloSourceTargetEffectArtifacts(
            state_machine=Path(args.state_machine),
            mixed_plan=Path(args.mixed_original_plan),
            source_program_root=Path(args.source_program_root),
            source_program_manifest=Path(args.source_program_manifest),
            normalization_root=Path(args.normalization_root),
            normalization_inventory=Path(args.normalization_inventory),
            semantic_refinement_root=Path(args.semantic_refinement_root),
            semantic_refinement_inventory=Path(
                args.semantic_refinement_inventory
            ),
            x87_root=Path(args.x87_root),
            x87_inventory=Path(args.x87_inventory),
            exact_original_root=Path(args.exact_original_root),
        ),
        authority_inventory=Path(args.authority_inventory),
    )


def _original_combined_declarations(args: argparse.Namespace) -> None:
    """Derive hash-bound declaration inputs for the combined invariant."""

    write_gnu_hello_original_combined_declarations(
        mixed_original_plan=args.mixed_original_plan,
        mixed_original_manifest=args.mixed_original_manifest,
        static_reachability_plan=args.static_reachability_plan,
        static_reachability_manifest=args.static_reachability_manifest,
        carrier_binding_manifest=args.carrier_binding_manifest,
        direct_call_authority_report=args.direct_call_authority_report,
        stack_dynamic_authority_report=args.stack_dynamic_authority_report,
        stack_dynamic_authority_manifest=args.stack_dynamic_authority_manifest,
        stack_combined_evidence_report=args.stack_combined_evidence_report,
        value_provenance_ir=args.value_provenance_ir,
        value_provenance_report=args.value_provenance_report,
        out=args.out,
    )


def _original_combined_inventory(args: argparse.Namespace) -> None:
    """Generate the checked combined original-state inventory."""

    write_original_combined_inventory(
        Path(args.out),
        mixed_original_plan=Path(args.mixed_original_plan),
        writable_authority_report=Path(args.writable_authority_report),
        writable_authority_manifest=Path(args.writable_authority_manifest),
        register_authority_report=Path(args.register_authority_report),
        register_authority_manifest=Path(args.register_authority_manifest),
        stack_dynamic_authority_report=Path(args.stack_dynamic_authority_report),
        stack_dynamic_authority_manifest=Path(
            args.stack_dynamic_authority_manifest
        ),
        stack_combined_evidence_report=Path(args.stack_combined_evidence_report),
        reachability_declarations=Path(args.reachability_declarations),
        call_frame_declarations=Path(args.call_frame_declarations),
        value_flow_declarations=Path(args.value_flow_declarations),
        shard_size=args.shard_size,
    )


def _original_execution_evidence(args: argparse.Namespace) -> None:
    """Assemble target-complete original execution evidence."""

    generate_gnu_hello_original_execution_evidence(
        args.out,
        combined_inventory_manifest=args.combined_inventory_manifest,
        source_target_effect_declarations=args.source_target_effect_declarations,
        transition_index_manifest=args.transition_index_manifest,
        preservation_inputs=args.preservation_inputs,
        mixed_original_plan=args.mixed_original_plan,
        writable_authority_report=args.writable_authority_report,
        register_authority_report=args.register_authority_report,
        stack_dynamic_authority_report=args.stack_dynamic_authority_report,
    )


def _runtime_memory_access_proposal(args: argparse.Namespace) -> None:
    """Classify exact target writes for subsequent Lean checking."""

    generate_runtime_memory_access_proposal(
        args.out,
        state_machine=args.state_machine,
        mixed_original_plan=args.mixed_original_plan,
        source_target_effect_declarations=(
            args.source_target_effect_declarations
        ),
    )


def _original_target_control_evidence(args: argparse.Namespace) -> None:
    """Generate checked control adapters for every reachable target."""

    generate_original_target_control_evidence(
        args.out,
        source_target_effect_declarations=(
            args.source_target_effect_declarations
        ),
        transition_index_manifest=args.transition_index_manifest,
        state_machine=args.state_machine,
        combined_target_inventory=args.combined_target_inventory,
        shard_size=args.shard_size,
    )


def _named_paths(values: list[str], label: str) -> dict[str, str]:
    """Parse deterministic ``name=path`` arguments without silent overwrite."""

    result: dict[str, str] = {}
    for value in values:
        name, separator, path = value.partition("=")
        if not separator or not name or not path:
            raise ValueError(f"{label} must use name=path")
        if name in result:
            raise ValueError(f"duplicate {label} name {name!r}")
        result[name] = path
    return result


def _original_target_preservation(args: argparse.Namespace) -> None:
    """Generate exact target-local preservation providers and frontiers."""

    generate_gnu_hello_original_target_preservation(
        args.out,
        state_machine=args.state_machine,
        source_target_effect_declarations=(
            args.source_target_effect_declarations
        ),
        transition_index_manifest=args.transition_index_manifest,
        combined_inventory_manifest=args.combined_inventory_manifest,
        authority_artifacts=_named_paths(args.authority, "authority"),
        shard_size=args.shard_size,
    )


def _original_source_launch_context(args: argparse.Namespace) -> None:
    """Assemble the closed original/source launch context from checked terms."""

    generate_original_source_launch_context(
        args.out,
        combined_inventory_manifest=args.combined_inventory_manifest,
        transition_index_manifest=args.transition_index_manifest,
        compiled_authority_declarations=args.compiled_authority_declarations,
        runtime_foundation_manifest=args.runtime_foundation_manifest,
        target_step_manifest=args.target_step_manifest,
        protocol_responses_declarations=args.protocol_responses_declarations,
        preservation_inputs=_named_paths(
            args.preservation_input, "preservation-input"
        ),
    )


def _checked_response_family(args: argparse.Namespace) -> None:
    """Package the checked GNU external response admission family."""

    write_gnu_hello_checked_response_family(
        args.out, input_manifest=args.input_manifest
    )


def _source_equivalence_final_report(args: argparse.Namespace) -> None:
    from spaghetti_extractor.relational.lean.source_equivalence_final_report import (
        write_source_equivalence_final_report,
    )

    """Consolidate already checked proof and candidate-runtime evidence."""

    write_source_equivalence_final_report(
        out=args.out,
        checked_acceptance=args.checked_acceptance,
        detached_axiom_audit=args.detached_axiom_audit,
        source_bundle=args.source_bundle,
        compilation_attestation=args.compilation_attestation,
        candidate_pe_metadata=args.candidate_pe_metadata,
        functional_report=args.functional_report,
        approved_toolchain_axiom=args.approved_toolchain_axiom,
    )


def _native_source_compiled_authority_evidence(
    args: argparse.Namespace,
) -> None:
    """Generate exact declarations for the compiled-source authority phase."""

    write_gnu_hello_native_source_compiled_authority_evidence(
        source_bundle=args.source_bundle,
        compilation_attestation=args.compilation_attestation,
        project_declarations=args.project_declarations,
        candidate_static_authority=args.candidate_static_authority,
        runtime_declarations=args.runtime_declarations,
        project_realization=NixRealizationIdentity.from_json(
            args.project_realization
        ),
        profile_realization=NixRealizationIdentity.from_json(
            args.profile_realization
        ),
        build_realization=NixRealizationIdentity.from_json(args.build_realization),
        out=args.out,
    )


def _native_source_environment_family_inputs(
    args: argparse.Namespace,
) -> None:
    """Generate exact GNU hello environment-family inputs."""

    write_gnu_hello_native_source_environment_family_inputs(
        args.out,
        source_execution_manifest=args.source_execution_manifest,
        compiled_authority_manifest=args.compiled_authority_manifest,
        source_bundle_manifest=args.source_bundle_manifest,
        candidate_runtime_declarations=args.candidate_runtime_declarations,
        candidate_static_authority=args.candidate_static_authority,
    )


def _native_source_environment_family(args: argparse.Namespace) -> None:
    """Generate checked environment-family evidence and acceptance inputs."""

    write_gnu_hello_native_source_environment_family(
        args.out,
        compiled_authority_manifest=args.compiled_authority_manifest,
        source_execution_manifest=args.source_execution_manifest,
        source_bundle_manifest=args.source_bundle_manifest,
        environment_inputs=args.environment_inputs,
    )


def _x87_sources(args: argparse.Namespace) -> None:
    machine = Path(args.state_machine)
    original = Path(args.original)
    pack_manifest = Path(args.pe_byte_pack_inventory)
    out = Path(args.out)
    stage_a = out / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    pack_inventory = load_pe_byte_pack_inventory(
        pack_manifest, pe_path=original
    )
    sources = relational_interpreter_x87_bundle_sources(
        machine,
        source_module="StageA.GeneratedGnuHelloOriginalPE",
        pe_name="StageA.GeneratedRelational.originalPe",
        pe_byte_pack_inventory=pack_inventory,
        source_only=args.source_only,
    )
    for module, source in sources.items():
        (stage_a / f"{module}.lean").write_text(source, encoding="utf-8")
    inventory = relational_interpreter_x87_module_inventory(
        machine,
        source_module="StageA.GeneratedGnuHelloOriginalPE",
        pe_name="StageA.GeneratedRelational.originalPe",
        pe_byte_pack_inventory=pack_inventory,
        source_only=args.source_only,
    )
    write_json(out / "module-inventory.json", inventory)
    _manifest(
        out,
        "x87-lean",
        {
            "state_machine": machine,
            "original_pe": original,
            "pe_byte_pack_inventory": pack_manifest,
        },
        status="source-ready",
        modules=sorted(sources),
        targets=[inventory["targets"]["bundle_node"]],
    )


def _x87_candidate_replay_sources(args: argparse.Namespace) -> None:
    machine = Path(args.state_machine)
    table_inventory_path = Path(args.kernel_data_inventory)
    out = Path(args.out)
    stage_a = out / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    table_inventory = json.loads(table_inventory_path.read_text(encoding="utf-8"))
    shard_size = table_inventory.get("shard_size")
    if not isinstance(shard_size, int) or isinstance(shard_size, bool) or shard_size <= 0:
        raise ValueError("compiled kernel-data inventory has no positive shard_size")
    replay_layout: dict[str, str] = {}
    if table_inventory.get("format") == "stage-a-interpreter-kernel-data-inventory-v7":
        replay_layout = {
            "candidate_data_shard_module_prefix": (
                "GeneratedInterpreterKernelDataCertificatePack"
            ),
            "candidate_entries_prefix": (
                "generatedInterpreterKernelDataCertificatePack"
            ),
            "candidate_entries_suffix": "CompiledEntries",
            "candidate_shard_prefix": (
                "generatedInterpreterKernelDataCertificatePack"
            ),
            "candidate_shard_suffix": "Shard",
        }
    spec = CandidateReplayProofSpec(
        original_source_module="StageA.GeneratedGnuHelloOriginalPE",
        original_pe_name="StageA.GeneratedRelational.originalPe",
        table_shard_size=shard_size,
        **replay_layout,
    )
    sources = relational_interpreter_x87_candidate_replay_sources(
        machine, spec=spec
    )
    for module, source in sources.items():
        (stage_a / f"{module}.lean").write_text(source, encoding="utf-8")
    inventory = relational_interpreter_x87_candidate_replay_inventory(
        machine, spec=spec
    )
    write_json(out / "candidate-replay-inventory.json", inventory)
    _manifest(
        out,
        "x87-candidate-replay-lean",
        {
            "state_machine": machine,
            "kernel_data_inventory": table_inventory_path,
        },
        status="source-ready",
        proof_authority=False,
        modules=sorted(sources),
        targets=[inventory["targets"]["bundle_node"]],
        counts=inventory["counts"],
        native_bridge_status=inventory["native_bridge_status"],
    )


def _x87_replay_bridge_target_sources(args: argparse.Namespace) -> None:
    candidate = Path(args.candidate)
    build_manifest = Path(args.build_manifest)
    native_engine_plan = Path(args.native_engine_plan)
    out = Path(args.out)
    stage_a = out / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    plan = build_x87_replay_bridge_target_plan(
        candidate_pe=candidate,
        build_manifest=build_manifest,
        native_engine_plan=native_engine_plan,
        call_site_rva=args.call_site_rva,
    )
    write_json(out / X87_REPLAY_BRIDGE_TARGET_PLAN_FILENAME, plan.payload())
    if not plan.evidence_ready or plan.table is None:
        issue = plan.issues[0] if plan.issues else None
        detail = "unknown static frontier" if issue is None else (
            f"{issue.code}: {issue.message}"
        )
        raise ValueError(f"x87 replay bridge target generation incomplete: {detail}")
    sources = x87_replay_bridge_target_lean_sources(
        plan,
        candidate_data_module=args.candidate_data_module,
        pack_size=args.pack_size,
    )
    for filename, source in sources.items():
        (stage_a / filename).write_text(source, encoding="utf-8")
    _manifest(
        out,
        "x87-replay-bridge-target-lean",
        {
            "candidate": candidate,
            "build_manifest": build_manifest,
            "native_engine_plan": native_engine_plan,
        },
        status="source-ready",
        proof_authority=False,
        candidate_sha256=plan.candidate_sha256,
        modules=sorted(Path(filename).stem for filename in sources),
        targets=[X87_REPLAY_BRIDGE_TARGET_LEAN_BUNDLE],
        counts={
            "descriptors": len(plan.table.descriptors),
            "finite_targets": len(plan.table.descriptors),
            "dynamic_frame_mappings": len(plan.table.frame_mappings),
            "runtime_refinement_goals": len(plan.table.descriptors),
            "static_frontiers": 0,
        },
    )


def _x87_replay_bridge_runtime_sources(args: argparse.Namespace) -> None:
    candidate = Path(args.candidate)
    target_plan = Path(args.target_plan)
    native_engine_plan = Path(args.native_engine_plan)
    out = Path(args.out)
    stage_a = out / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    plan = build_x87_replay_bridge_runtime_plan(
        candidate_pe=candidate,
        target_plan=target_plan,
        native_engine_plan=native_engine_plan,
    )
    write_json(out / X87_REPLAY_BRIDGE_RUNTIME_PLAN_FILENAME, plan.payload())
    sources = x87_replay_bridge_runtime_lean_sources(
        plan,
        target_module=args.target_module,
        pack_size=args.pack_size,
    )
    for filename, source in sources.items():
        (stage_a / filename).write_text(source, encoding="ascii")
    _manifest(
        out,
        "x87-replay-bridge-runtime-lean",
        {
            "candidate": candidate,
            "target_plan": target_plan,
            "native_engine_plan": native_engine_plan,
        },
        status="source-ready",
        diagnostic_status="kernel_execution_closed",
        proof_authority=False,
        static_evidence=True,
        candidate_sha256=plan.candidate_sha256,
        conditional_theorem=(
            "StageA.Relational.InterpreterKernelX87Execution."
            "executeKernelReduction"
        ),
        remaining_proof_premises=list(
            X87_REPLAY_FIXED_TEMPLATE_REMAINING_PREMISES
        ),
        assumed_source_frame_fields=list(
            X87_REPLAY_FIXED_TEMPLATE_SOURCE_FRAME_ASSUMPTIONS
        ),
        remaining_program_binding_fields=list(
            X87_REPLAY_FIXED_TEMPLATE_PROGRAM_BINDING_PREMISES
        ),
        remaining_fixed_template_fields=list(
            X87_REPLAY_FIXED_TEMPLATE_CERTIFICATE_PREMISES
        ),
        remaining_executor_fields=list(
            X87_REPLAY_FIXED_TEMPLATE_EXECUTOR_PREMISES
        ),
        modules=sorted(Path(filename).stem for filename in sources),
        targets=[X87_REPLAY_BRIDGE_RUNTIME_LEAN_BUNDLE],
        counts={
            "runtime_targets": len(plan.targets),
            "relocated_operands": plan.relocated_operand_count,
            "unbound_relocated_operands": 0,
        },
    )


def _x87_kernel_execution_sources(args: argparse.Namespace) -> None:
    runtime_plan_path = Path(args.runtime_plan)
    runtime_plan = json.loads(runtime_plan_path.read_text(encoding="utf-8"))
    counts = runtime_plan.get("counts")
    if (
        runtime_plan.get("format") != X87_REPLAY_BRIDGE_RUNTIME_PLAN_FORMAT
        or runtime_plan.get("status") != "complete"
        or runtime_plan.get("diagnostic_status")
        != "kernel_execution_closed"
        or runtime_plan.get("acceptance_authority") is not False
        or runtime_plan.get("static_evidence") is not True
        or runtime_plan.get("conditional_theorem")
        != (
            "StageA.Relational.InterpreterKernelX87Execution."
            "executeKernelReduction"
        )
        or runtime_plan.get("remaining_proof_premises")
        != list(X87_REPLAY_FIXED_TEMPLATE_REMAINING_PREMISES)
        or runtime_plan.get("assumed_source_frame_fields")
        != list(X87_REPLAY_FIXED_TEMPLATE_SOURCE_FRAME_ASSUMPTIONS)
        or runtime_plan.get("remaining_program_binding_fields")
        != list(X87_REPLAY_FIXED_TEMPLATE_PROGRAM_BINDING_PREMISES)
        or runtime_plan.get("remaining_fixed_template_fields")
        != list(X87_REPLAY_FIXED_TEMPLATE_CERTIFICATE_PREMISES)
        or runtime_plan.get("remaining_executor_fields")
        != list(X87_REPLAY_FIXED_TEMPLATE_EXECUTOR_PREMISES)
        or runtime_plan.get("checked_execution_type")
        != X87_REPLAY_FIXED_TEMPLATE_CHECKS_TYPE
        or runtime_plan.get("checked_bundle_inhabited") is not True
        or not isinstance(counts, dict)
        or not isinstance(counts.get("runtime_targets"), int)
        or isinstance(counts.get("runtime_targets"), bool)
        or counts["runtime_targets"] <= 0
        or not isinstance(counts.get("relocated_operands"), int)
        or isinstance(counts.get("relocated_operands"), bool)
        or counts.get("unbound_relocated_operands") != 0
        or not isinstance(runtime_plan.get("required_checked_target_terms"), list)
        or len(runtime_plan["required_checked_target_terms"])
        != counts["runtime_targets"]
    ):
        raise ValueError(
            "x87 replay runtime plan is malformed, incomplete, or claims authority"
        )

    candidate = runtime_plan.get("candidate")
    if (
        not isinstance(candidate, dict)
        or not isinstance(candidate.get("sha256"), str)
        or len(candidate["sha256"]) != 64
    ):
        raise ValueError("x87 replay runtime plan has no exact candidate identity")

    out = Path(args.out)
    stage_a = out / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    source = f"""import StageA.{X87_REPLAY_BRIDGE_RUNTIME_LEAN_BUNDLE}
import StageA.RelationalInterpreterKernelX87Execution

namespace StageA.GeneratedRelational.InterpreterKernelX87Execution

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelData
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterX87
open StageA.Relational.InterpreterKernelX87Execution
open StageA.Relational.InterpreterX87ReplayBridgeTarget
open StageA.Relational.InterpreterX87ReplayBridgeRuntime
open StageA.GeneratedRelational.InterpreterKernelData
open StageA.GeneratedRelational.InterpreterX87ReplayBridgeTarget
open StageA.GeneratedRelational.InterpreterX87ReplayBridgeRuntime

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

{interpreter_kernel_x87_execution_lean_snippet()}

end StageA.GeneratedRelational.InterpreterKernelX87Execution
"""
    destination = stage_a / f"{X87_KERNEL_EXECUTION_LEAN_MODULE}.lean"
    destination.write_text(source, encoding="ascii")

    frontier = {
        "format": "stage-a-gnu-hello-x87-kernel-execution-frontier-v1",
        "status": "closed",
        "acceptance_authority": False,
        "candidate_sha256": candidate["sha256"],
        "runtime_targets": counts["runtime_targets"],
        "generated_goal": (
            "StageA.GeneratedRelational.InterpreterKernelX87Execution."
            "GeneratedX87ReplayBridgeKernelExecutionGoal"
        ),
        "generated_theorem": (
            "StageA.GeneratedRelational.InterpreterKernelX87Execution."
            "generatedX87ReplayBridgeKernelExecutionClosed"
        ),
        "remaining_authority": {
            "lean_type": (
                "GeneratedX87ReplayBridgeKernelExecutionGoal "
                "(generatedX87ReplayBridgeNestedProgram carrier)"
            ),
            "authority_fields": [],
            "structurally_derived_program_binding_fields": [
                "peExact",
                "importsExact",
                "targetInventory",
            ],
            "structurally_derived_handler_fields": ["handlerInventory"],
            "fixed_template_quantification": (
                "every checked runtime target, every caller and logical "
                "input, and every exact admitted source frame"
            ),
            "fixed_template_certificate_witness_fields": [],
            "fixed_template_certificate_proof_fields": [],
            "required_checked_target_terms": runtime_plan[
                "required_checked_target_terms"
            ],
        },
        "remaining_proof_premises": list(
            X87_KERNEL_EXECUTION_REMAINING_PROOF_PREMISES
        ),
        "premise_details": {
            family: list(details)
            for family, details in X87_KERNEL_EXECUTION_PREMISE_DETAILS.items()
        },
        "assumed_source_frame_fields": list(
            X87_REPLAY_FIXED_TEMPLATE_SOURCE_FRAME_ASSUMPTIONS
        ),
        "remaining_program_binding_fields": list(
            X87_REPLAY_FIXED_TEMPLATE_PROGRAM_BINDING_PREMISES
        ),
        "remaining_fixed_template_fields": list(
            X87_REPLAY_FIXED_TEMPLATE_CERTIFICATE_PREMISES
        ),
        "failure_mode": "none",
    }
    write_json(out / X87_KERNEL_EXECUTION_FRONTIER_FILENAME, frontier)
    write_json(
        out / "module-resources.json",
        {
            X87_KERNEL_EXECUTION_LEAN_MODULE: {
                "resource_class": "medium",
                "estimated_memory_mb": 4096,
            }
        },
    )
    _manifest(
        out,
        "x87-kernel-execution-lean",
        {"runtime_plan": runtime_plan_path},
        status="source-ready",
        diagnostic_status="kernel_execution_closed",
        proof_authority=False,
        candidate_sha256=candidate["sha256"],
        runtime_targets=counts["runtime_targets"],
        theorem=frontier["generated_theorem"],
        remaining_proof_premises=frontier["remaining_proof_premises"],
        remaining_authority=frontier["remaining_authority"],
        failure_mode="none",
        public_outputs={
            "frontier": X87_KERNEL_EXECUTION_FRONTIER_FILENAME,
            "lean_module": (
                f"StageA/{X87_KERNEL_EXECUTION_LEAN_MODULE}.lean"
            ),
            "module_resources": "module-resources.json",
        },
        modules=[X87_KERNEL_EXECUTION_LEAN_MODULE],
        targets=[X87_KERNEL_EXECUTION_LEAN_MODULE],
    )


def _definedness_source(args: argparse.Namespace) -> None:
    machine = Path(args.state_machine)
    out = Path(args.out)
    stage_a = out / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    preflight = relational_definedness_preflight(machine)
    destination = stage_a / "GeneratedRelationalDefinedness.lean"
    destination.write_text(relational_definedness_source(machine), encoding="utf-8")
    write_json(out / "definedness-inventory.json", preflight)
    _manifest(
        out,
        "definedness-lean",
        {"state_machine": machine},
        status="source-ready",
        diagnostic_status=preflight["status"],
        modules=[destination.stem],
        targets=[destination.stem],
    )


def _kernel(args: argparse.Namespace) -> None:
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    plan = write_relational_interpreter_kernel_bundle(
        out=out,
        candidate_data_module="StageA.GeneratedInterpreterKernelDataBase",
        candidate_data_namespace=(
            "StageA.GeneratedRelational.InterpreterKernelData"
        ),
        candidate_bytes_symbol="generatedInterpreterKernelCandidateBytes",
        candidate_pe_symbol="generatedInterpreterKernelCandidatePe",
        candidate_pe=args.candidate,
        linker_map=args.linker_map,
        interpreter_program_manifest=args.program_manifest,
        engine_layout=args.engine_layout,
        native_build_manifest=args.native_build_manifest,
        externalize_artifacts=True,
    )
    stage_a = out / "StageA"
    stage_a.mkdir(exist_ok=True)
    shutil.move(
        str(out / INTERPRETER_KERNEL_LEAN_FILENAME),
        str(stage_a / INTERPRETER_KERNEL_LEAN_FILENAME),
    )
    for source in sorted(
        out.glob(f"{INTERPRETER_KERNEL_FUNCTION_MODULE_PREFIX}*.lean")
    ):
        shutil.move(str(source), str(stage_a / source.name))
    modules = sorted(path.stem for path in stage_a.glob("*.lean"))
    function_modules = [
        module
        for module in modules
        if module.startswith(INTERPRETER_KERNEL_FUNCTION_MODULE_PREFIX)
    ]
    if len(function_modules) != len(plan.functions):
        raise RuntimeError(
            "compiled-kernel function module count does not match the plan"
        )
    _manifest(
        out,
        "compiled-kernel",
        {
            "candidate": Path(args.candidate),
            "linker_map": Path(args.linker_map),
            "program_manifest": Path(args.program_manifest),
            "engine_layout": Path(args.engine_layout),
            "native_build_manifest": Path(args.native_build_manifest),
        },
        status="source-ready",
        diagnostic_status=plan.payload().get("status", "semantic_proof_required"),
        modules=modules,
        targets=[Path(INTERPRETER_KERNEL_LEAN_FILENAME).stem],
        counts={
            "modules": len(modules),
            "function_modules": len(function_modules),
        },
    )


def _kernel_view(kernel_plan: Path, candidate: Path) -> SimpleNamespace:
    payload = json.loads(kernel_plan.read_text(encoding="utf-8"))
    functions = []
    for function in payload["kernel_functions"]:
        blocks = []
        for block in function["blocks"]:
            instructions = tuple(
                SimpleNamespace(
                    rva=row["rva"],
                    data=bytes.fromhex(row["bytes"]),
                    mnemonic=row["mnemonic"],
                )
                for row in block["instructions"]
            )
            blocks.append(
                SimpleNamespace(
                    entry_rva=block["entry_rva"],
                    instructions=instructions,
                    successors=tuple(block["successors"]),
                )
            )
        functions.append(
            SimpleNamespace(role=function["role"], blocks=tuple(blocks))
        )
    return SimpleNamespace(
        candidate_bytes=candidate.read_bytes(), functions=tuple(functions)
    )


def _kernel_block(args: argparse.Namespace) -> None:
    out = Path(args.out)
    candidate = Path(args.candidate)
    plan = _kernel_view(Path(args.kernel_plan), candidate)
    result = write_relational_interpreter_kernel_block_bundle(
        out=out,
        kernel_plan=plan,
        candidate_pe=candidate,
        shard_size=args.shard_size,
    )
    _manifest(
        out,
        "compiled-kernel-blocks",
        {"candidate": candidate, "kernel_plan": Path(args.kernel_plan)},
        status="source-ready",
        modules=sorted(path.stem for path in (out / "StageA").glob("*.lean")),
        targets=[result.context_module, *[f"{result.module_prefix}{i:04d}" for i in range(len(result.shards))]],
    )


def _kernel_data(args: argparse.Namespace) -> None:
    out = Path(args.out)
    inventory = generate_interpreter_kernel_data_bundle(
        candidate_pe=args.candidate,
        linker_map=args.linker_map,
        state_machine=args.state_machine,
        out_dir=out,
        shard_size=args.shard_size,
        lean_source_root=args.lean_source_root,
    )
    _manifest(
        out,
        "compiled-kernel-data",
        {
            "candidate": Path(args.candidate),
            "linker_map": Path(args.linker_map),
            "state_machine": Path(args.state_machine),
        },
        status="source-ready",
        modules=sorted(path.stem for path in (out / "StageA").glob("*.lean")),
        targets=["GeneratedInterpreterKernelDataBundle"],
        counts=inventory.payload()["counts"],
    )


def _kernel_abi(args: argparse.Namespace) -> None:
    out = Path(args.out)
    plan = write_relational_interpreter_kernel_abi_bundle(
        kernel_plan=args.kernel_plan,
        data_inventory=args.kernel_data_inventory,
        engine_layout=args.engine_layout,
        out=out,
    )
    modules = _move_generated_lean_to_stage_a(out)
    target = Path(INTERPRETER_KERNEL_ABI_LEAN_FILENAME).stem
    payload = plan.payload()
    _manifest(
        out,
        "compiled-kernel-abi",
        {
            "kernel_plan": Path(args.kernel_plan),
            "kernel_data_inventory": Path(args.kernel_data_inventory),
            "engine_layout": Path(args.engine_layout),
        },
        status="source-ready",
        proof_authority=False,
        proposal_format=payload["format"],
        failure_mode=payload["failure_mode"],
        candidate_sha256=plan.candidate_sha256,
        proposal_sha256=abi_plan_payload_sha256(plan),
        public_outputs={
            "plan": INTERPRETER_KERNEL_ABI_PLAN_FILENAME,
            "lean_module": f"StageA/{INTERPRETER_KERNEL_ABI_LEAN_FILENAME}",
            "parameters_lean_module": (
                "StageA/"
                f"{INTERPRETER_KERNEL_ABI_PARAMETERS_LEAN_FILENAME}"
            ),
        },
        modules=modules,
        targets=[target],
        operations=[role.role for role in plan.roles],
    )


def _launch_roots(load_image_contract: Path) -> tuple[int, tuple[int, ...]]:
    payload = json.loads(load_image_contract.read_text(encoding="utf-8"))
    identity = payload.get("identity")
    if not isinstance(identity, Mapping) or not isinstance(
        identity.get("entry_rva"), int
    ):
        raise ValueError("load-image contract has no integer entry RVA")
    tls = payload.get("tls")
    callbacks: list[int] = []
    if tls is not None:
        if not isinstance(tls, Mapping) or not isinstance(
            tls.get("callbacks"), list
        ):
            raise ValueError("load-image contract TLS inventory is malformed")
        for index, callback in enumerate(tls["callbacks"]):
            if not isinstance(callback, Mapping) or not isinstance(
                callback.get("rva"), int
            ):
                raise ValueError(
                    f"load-image TLS callback {index} has no integer RVA"
                )
            callbacks.append(callback["rva"])
    return identity["entry_rva"], tuple(callbacks)


def _machine_import_boundary_site_proposals(
    report: Path,
) -> tuple[OriginalMachineImportBoundarySiteProposal, ...]:
    payload = json.loads(report.read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping) or payload.get("format") != (
        STATIC_MACHINE_IMPORT_FORMAT
    ):
        raise ValueError("machine-import report has the wrong format")
    boundaries = payload.get("boundaries")
    if not isinstance(boundaries, list) or not boundaries:
        raise ValueError("machine-import report has no boundary inventory")
    size_field = {
        "direct": "source_size",
        "register_indirect": "source_size",
        "restored_register_indirect": "source_size",
        "via_thunk": "thunk_size",
        "framed_direct_tail": "tail_size",
        "framed_thunk_tail": "thunk_size",
    }
    proposals: list[OriginalMachineImportBoundarySiteProposal] = []
    for index, value in enumerate(boundaries):
        if not isinstance(value, Mapping):
            raise ValueError(f"machine-import boundary {index} is not an object")
        route = value.get("route")
        field = size_field.get(route)
        if field is None:
            raise ValueError(
                f"machine-import boundary {index} has unsupported route {route!r}"
            )
        fields = {
            "boundary_id": value.get("id"),
            "execution_source_rva": value.get("execution_source_rva"),
            "execution_size": value.get(field),
            "continuation_rva": value.get("continuation_rva"),
        }
        if any(
            not isinstance(item, int) or isinstance(item, bool)
            for item in fields.values()
        ):
            raise ValueError(
                f"machine-import boundary {index} has a malformed execution span"
            )
        proposals.append(OriginalMachineImportBoundarySiteProposal(**fields))
    return tuple(proposals)


def _static_import_symbol(symbol: str) -> QualifiedLeanSymbol:
    return QualifiedLeanSymbol(
        module=f"StageA.{STATIC_MACHINE_IMPORT_MODULE}",
        namespace="StageA.GeneratedRelational.StaticMachineImports",
        symbol=symbol,
    )


def _mixed_original_spec(
    *,
    original: Path,
    reference_contract: Path,
    load_image_contract: Path,
    with_boundary_bindings: bool,
    shard_size: int,
    terminal_boundary_proposals: tuple[
        InterpreterMixedTerminalProposal, ...
    ] = (),
    register_control_call_contracts: tuple[
        OriginalRegisterControlCallContractProposal, ...
    ] = (),
    machine_import_boundary_sites: tuple[
        OriginalMachineImportBoundarySiteProposal, ...
    ] = (),
    static_data_bindings=(),
    static_word_call_seed_authorities=(),
) -> InterpreterMixedOriginalSpec:
    entry_rva, tls_callback_rvas = _launch_roots(load_image_contract)
    contract_symbol = _static_import_symbol(
        "generatedMachineImportBoundaryContracts"
    )
    boundary_bindings = None
    if with_boundary_bindings:
        boundary_bindings = OriginalMachineImportBoundaryBindings(
            signatures=_static_import_symbol(
                "generatedMachineImportSignatures"
            ),
            boundaries=_static_import_symbol(
                "generatedMachineImportBoundaries"
            ),
            inventory=_static_import_symbol(
                "generatedMachineImportBoundaryCallContracts"
            ),
        )
    return InterpreterMixedOriginalSpec(
        bindings=OriginalModuleBindings(
            module="StageA.GeneratedGnuHelloOriginalPE",
            namespace="StageA.GeneratedRelational",
            pe_parsed="originalPeParsed",
            machine_import_call_contracts=contract_symbol,
            machine_import_boundaries=boundary_bindings,
        ),
        entry_rva=entry_rva,
        tls_callback_rvas=tls_callback_rvas,
        shard_size=shard_size,
        iat_imports=load_original_iat_import_proposals(reference_contract),
        recovery_pe=OriginalPERecoveryInput(original, sha256_file(original)),
        terminal_boundary_proposals=terminal_boundary_proposals,
        machine_import_boundary_sites=machine_import_boundary_sites,
        register_control_call_contracts=register_control_call_contracts,
        static_word_call_seed_authorities=tuple(
            static_word_call_seed_authorities
        ),
        static_data_bindings=tuple(static_data_bindings),
    )


def _callable_external_proposal(
    args: argparse.Namespace,
) -> CallableExternalProposal | None:
    profile = getattr(args, "callable_resolver_profile", None)
    if profile is None:
        return None
    proposal = discover_callable_external_proposal(
        original_pe=Path(args.original),
        state_machine=Path(args.state_machine),
        machine_import_report=Path(args.machine_import_report),
        profile=Path(profile),
    )
    if not proposal.complete:
        details = "; ".join(blocker.detail for blocker in proposal.blockers)
        raise ValueError(f"callable resolver proposal is incomplete: {details}")
    return proposal


def _static_machine_import_contracts(args: argparse.Namespace) -> None:
    original = Path(args.original)
    reference_contract = Path(args.reference_contract)
    state_machine = Path(args.state_machine)
    load_image_contract = Path(args.load_image_contract)
    profiles = tuple(Path(path) for path in args.profile)
    out = Path(args.out)

    rooted = plan_interpreter_mixed_original(
        state_machine,
        _mixed_original_spec(
            original=original,
            reference_contract=reference_contract,
            load_image_contract=load_image_contract,
            with_boundary_bindings=False,
            shard_size=args.shard_size,
        ),
    )
    required_imports = tuple(
        StaticImportIdentity(
            dll=identity.dll,
            symbol=identity.symbol,
            ordinal=identity.ordinal,
        )
        for identity in rooted.import_identities
    )
    reachable_source_rvas = tuple(
        rooted.regions[target_id].rva
        for target_id in rooted.reachable_target_ids
    )
    plan = plan_static_machine_import_contracts(
        original_pe=original,
        reference_contract=reference_contract,
        state_machine=state_machine,
        required_imports=required_imports,
        reachable_source_rvas=reachable_source_rvas,
        profile_paths=profiles,
    )
    lean_path, report_path = write_static_machine_import_contracts(
        out,
        plan,
        StaticMachineImportLeanBindings(
            module="StageA.GeneratedGnuHelloOriginalPE",
            namespace="StageA.GeneratedRelational",
        ),
    )
    _manifest(
        out,
        "rooted-static-machine-import-contracts",
        {
            "original_pe": original,
            "reference_contract": reference_contract,
            "state_machine": state_machine,
            "load_image_contract": load_image_contract,
            **{
                f"runtime_profile_{index:04d}": profile
                for index, profile in enumerate(profiles)
            },
        },
        status="source-ready" if plan.complete else "incomplete",
        proof_authority=False,
        plan_format=STATIC_MACHINE_IMPORT_FORMAT,
        public_outputs={
            "report": report_path.name,
            "lean_module": f"StageA/{lean_path.name}",
        },
        modules=[lean_path.stem],
        targets=[lean_path.stem],
        rooted_counts={
            "reachable_targets": len(rooted.reachable_target_ids),
            "required_imports": len(plan.required),
            "boundaries": len(plan.boundaries),
            "blockers": len(plan.blockers),
        },
    )


def _mixed_original(args: argparse.Namespace) -> None:
    original = Path(args.original)
    reference_contract = Path(args.reference_contract)
    state_machine = Path(args.state_machine)
    load_image_contract = Path(args.load_image_contract)
    machine_import_report = Path(args.machine_import_report)
    terminal_boundary_proposals = load_interpreter_mixed_terminal_proposals(
        machine_import_report,
        original_sha256=sha256_file(original),
        reference_contract_sha256=sha256_file(reference_contract),
        state_machine_sha256=sha256_file(state_machine),
    )
    register_control_call_contracts = (
        load_original_register_control_call_contract_proposals(
            machine_import_report,
            original_sha256=sha256_file(original),
            state_machine_sha256=sha256_file(state_machine),
        )
    )
    boundary_sites = _machine_import_boundary_site_proposals(
        machine_import_report
    )
    callable_proposal = _callable_external_proposal(args)

    plan = plan_interpreter_mixed_original(
        state_machine,
        _mixed_original_spec(
            original=original,
            reference_contract=reference_contract,
            load_image_contract=load_image_contract,
            with_boundary_bindings=True,
            shard_size=args.shard_size,
            terminal_boundary_proposals=terminal_boundary_proposals,
            machine_import_boundary_sites=boundary_sites,
            register_control_call_contracts=register_control_call_contracts,
            static_data_bindings=(
                ()
                if callable_proposal is None
                else callable_proposal.static_data_bindings
            ),
        ),
    )
    written = write_relational_interpreter_mixed_original(args.out, plan)
    modules = sorted(path.stem for path in written if path.suffix == ".lean")
    _manifest(
        Path(args.out),
        "mixed-original-lean",
        {
            "original_pe": original,
            "reference_contract": reference_contract,
            "state_machine": state_machine,
            "load_image_contract": load_image_contract,
            "machine_import_report": machine_import_report,
        },
        status="source-ready",
        proof_authority=False,
        modules=modules,
        targets=[INTERPRETER_MIXED_ORIGINAL_MODULE],
        counts={
            "regions": len(plan.regions),
            "reachable_targets": len(plan.reachable_target_ids),
            "blockers": len(plan.blockers),
        },
        qualified_machine_import_symbols=[
            "generatedMachineImportBoundaryContracts",
            "generatedMachineImportBoundaries",
            "generatedMachineImportBoundaryCallContracts",
        ],
    )


def _mixed_original_plan_layers(
    args: argparse.Namespace,
    direct_call_contracts: tuple[
        OriginalRegisterControlCallContractProposal, ...
    ] = (),
    *,
    baseline_plan=None,
    writable_references=None,
):
    original = Path(args.original)
    reference_contract = Path(args.reference_contract)
    state_machine = Path(args.state_machine)
    load_image_contract = Path(args.load_image_contract)
    machine_import_report = Path(args.machine_import_report)
    terminal_proposals = load_interpreter_mixed_terminal_proposals(
        machine_import_report,
        original_sha256=sha256_file(original),
        reference_contract_sha256=sha256_file(reference_contract),
        state_machine_sha256=sha256_file(state_machine),
    )
    machine_contracts = load_original_register_control_call_contract_proposals(
        machine_import_report,
        original_sha256=sha256_file(original),
        state_machine_sha256=sha256_file(state_machine),
    )
    boundary_sites = _machine_import_boundary_site_proposals(
        machine_import_report
    )
    callable_proposal = _callable_external_proposal(args)
    static_data_bindings = (
        ()
        if callable_proposal is None
        else callable_proposal.static_data_bindings
    )
    if baseline_plan is None:
        baseline_plan = plan_interpreter_mixed_original(
            state_machine,
            _mixed_original_spec(
                original=original,
                reference_contract=reference_contract,
                load_image_contract=load_image_contract,
                with_boundary_bindings=True,
                shard_size=args.shard_size,
                terminal_boundary_proposals=terminal_proposals,
                machine_import_boundary_sites=boundary_sites,
                register_control_call_contracts=machine_contracts,
                static_data_bindings=static_data_bindings,
            ),
        )
    authority_report = getattr(args, "writable_slot_authority_report", None)
    references = writable_references
    if references is None and authority_report is not None:
        references = load_relocated_writable_static_pointer_slot_authorities(
            authority_report,
            original_sha256=sha256_file(original),
            state_machine_sha256=sha256_file(state_machine),
            machine_import_report_sha256=sha256_file(machine_import_report),
            mixed_original_plan=baseline_plan,
        )
    if references is None:
        references = ()
    plan = baseline_plan
    if direct_call_contracts:
        static_word_call_seed_authorities = tuple(
            OriginalRegisterStaticWordSeedAuthority(
                source_rva=reference.key.source_rva,
                instruction_rva=reference.key.instruction_rva,
                binding=reference.static_binding,
            )
            for reference in references
            if isinstance(reference.static_binding, OriginalStaticWordSlotBinding)
        )
        plan = plan_interpreter_mixed_original(
            state_machine,
            _mixed_original_spec(
                original=original,
                reference_contract=reference_contract,
                load_image_contract=load_image_contract,
                with_boundary_bindings=True,
                shard_size=args.shard_size,
                terminal_boundary_proposals=terminal_proposals,
                machine_import_boundary_sites=boundary_sites,
                register_control_call_contracts=(
                    *machine_contracts,
                    *direct_call_contracts,
                ),
                static_data_bindings=static_data_bindings,
                static_word_call_seed_authorities=(
                    static_word_call_seed_authorities
                ),
            ),
        )
    if references:
        plan = consume_relocated_writable_static_pointer_slot_authorities(
            plan, references
        ).plan
    return baseline_plan, plan, references


def _mixed_original_plan_with_contracts(
    args: argparse.Namespace,
    direct_call_contracts: tuple[
        OriginalRegisterControlCallContractProposal, ...
    ] = (),
):
    return _mixed_original_plan_layers(args, direct_call_contracts)[1]


def _write_callable_external_artifacts(
    out: Path,
    proposal: CallableExternalProposal | None,
    plan: InterpreterMixedOriginalPlan,
) -> tuple[dict[str, str], dict[str, int] | None]:
    outputs: dict[str, str] = {}
    counts: dict[str, int] | None = None
    if proposal is None:
        return outputs, counts

    write_json(out / "callable-external-proposal.json", proposal.to_json())
    outputs["callable_proposal"] = "callable-external-proposal.json"
    counts = {
        "blockers": len(proposal.blockers),
        "sites": len(proposal.sites),
        "static_data_bindings": len(proposal.static_data_bindings),
    }
    if not proposal.sites:
        return outputs, counts

    capability, execution = callable_external_artifact_payload(proposal, plan)
    write_json(out / "callable-external-capability.json", capability)
    write_json(out / "callable-external-execution.json", execution)
    capability_path = out / "StageA" / "GeneratedCallableExternalCapability.lean"
    capability_path.write_text(
        relational_callable_external_capability_source(capability),
        encoding="utf-8",
    )
    execution_path = out / "StageA" / "GeneratedCallableExternalExecution.lean"
    execution_path.write_text(
        relational_callable_external_execution_source(execution),
        encoding="utf-8",
    )
    program_path = out / "StageA" / f"{CALLABLE_EXTERNAL_PROGRAM_MODULE}.lean"
    program_path.write_text(
        relational_callable_external_program_source(),
        encoding="utf-8",
    )
    outputs.update({
        "callable_capability": capability_path.name,
        "callable_execution": execution_path.name,
        "callable_program": program_path.name,
    })
    return outputs, counts


def _mixed_original_base(args: argparse.Namespace) -> None:
    plan = _mixed_original_plan_with_contracts(args)
    write_relational_interpreter_mixed_original_base(args.out, plan)
    decomposition = decompose_interpreter_mixed_original_base(args.out, plan)
    out = Path(args.out)
    callable_proposal = _callable_external_proposal(args)
    callable_outputs, callable_counts = _write_callable_external_artifacts(
        out, callable_proposal, plan
    )
    write_json(out / "module-resources.json", decomposition.resources)
    modules = sorted(path.stem for path in (out / "StageA").glob("*.lean"))
    _manifest(
        out,
        "mixed-original-base-lean",
        {
            "original_pe": Path(args.original),
            "reference_contract": Path(args.reference_contract),
            "state_machine": Path(args.state_machine),
            "load_image_contract": Path(args.load_image_contract),
            "machine_import_report": Path(args.machine_import_report),
        },
        status="base-source-ready",
        proof_authority=False,
        exact_reachability_emitted=False,
        public_outputs={
            "base_plan": "interpreter-mixed-original-base-plan.json",
            **callable_outputs,
        },
        callable_counts=callable_counts,
        modules=modules,
        targets=[INTERPRETER_MIXED_ORIGINAL_BASE_MODULE],
        counts={
            "regions": len(plan.regions),
            "addresses": len(plan.regions) + len(plan.recovered_aliases),
            "reachable_targets": len(plan.reachable_target_ids),
            "diagnostic_blockers": len(plan.blockers),
        },
    )


def _mixed_original_writable_slot_authority(
    args: argparse.Namespace,
) -> None:
    """Emit and consume exact relocated writable code-pointer authorities."""

    original = Path(args.original)
    state_machine = Path(args.state_machine)
    machine_import_report = Path(args.machine_import_report)
    base_plan_path, base_payload = _checked_mixed_original_base_plan(
        args.base_plan, state_machine
    )
    baseline_plan = _mixed_original_plan_with_contracts(args)
    if base_payload != baseline_plan.to_json():
        raise ValueError(
            "writable-slot authority baseline no longer matches its base plan"
        )

    out = Path(args.out)
    callable_proposal = _callable_external_proposal(args)
    proposal = construct_relocated_writable_static_pointer_slot_authorities(
        original_pe=original,
        state_machine=state_machine,
        machine_import_report=machine_import_report,
        mixed_original_plan=baseline_plan,
        resolver_routes_by_instruction_rva=(
            {}
            if callable_proposal is None
            else callable_resolver_routes_by_instruction_rva(
                callable_proposal,
                baseline_plan,
                transfer="jump",
            )
        ),
    )
    authority_report, authority_sources = (
        write_relocated_writable_static_pointer_slot_authorities(
            out,
            proposal,
            RelocatedWritableStaticPointerSlotLeanBinding(
                dependency_modules=(
                    "StageA."
                    f"{INTERPRETER_MIXED_ORIGINAL_BASE_MODULE}CarrierData",
                ),
                context_term=(
                    "StageA.GeneratedRelational."
                    "InterpreterMixedOriginalBase."
                    "generatedOriginalStaticContext"
                ),
                carrier_term=(
                    "StageA.GeneratedRelational."
                    "InterpreterMixedOriginalBase."
                    "generatedOriginalCarrierContext"
                ),
                decoded_authority_term=(
                    "StageA.GeneratedRelational."
                    "InterpreterMixedOriginalBase."
                    "generatedExactOriginalDecodedAuthority"
                ),
            ),
        )
    )
    references = load_relocated_writable_static_pointer_slot_authorities(
        authority_report,
        original_sha256=sha256_file(original),
        state_machine_sha256=sha256_file(state_machine),
        machine_import_report_sha256=sha256_file(machine_import_report),
        mixed_original_plan=baseline_plan,
    )
    consumed = consume_relocated_writable_static_pointer_slot_authorities(
        baseline_plan, references
    )
    write_relational_interpreter_mixed_original_base(out, consumed.plan)
    direct_call_proposal_ir = direct_call_proposal_ir_from_plans(
        authority_base_plan=baseline_plan,
        consumed_plan=consumed.plan,
        input_paths={
            "base_plan": (
                out / "interpreter-mixed-original-base-plan.json"
            ),
            "load_image_contract": Path(args.load_image_contract),
            "machine_import_report": machine_import_report,
            "original_pe": original,
            "reference_contract": Path(args.reference_contract),
            "state_machine": state_machine,
            "writable_slot_authority_report": authority_report,
        },
    )
    write_json(
        out / "direct-call-proposal-ir.json",
        direct_call_proposal_ir.to_json(),
    )
    write_json(
        out / "original-cutpoint-graph-ir.json",
        direct_call_proposal_ir.original_cutpoint_graph.to_json(),
    )
    decomposition = decompose_interpreter_mixed_original_base(
        out, consumed.plan
    )
    adapters = write_decomposed_writable_static_pointer_slot_adapters(
        out, consumed
    )
    callable_outputs, callable_counts = _write_callable_external_artifacts(
        out, callable_proposal, consumed.plan
    )
    facade = (
        out / "StageA" / f"{INTERPRETER_MIXED_ORIGINAL_BASE_MODULE}.lean"
    )
    facade_source = facade.read_text(encoding="utf-8")
    adapter_imports = "".join(
        f"import {adapter.module}\n" for adapter in adapters
    )
    facade.write_text(adapter_imports + facade_source, encoding="utf-8")

    resources = dict(decomposition.resources)
    for source in authority_sources:
        resources[source.stem] = {
            "resource_class": "medium",
            "estimated_memory_mb": 6144,
        }
    for adapter in adapters:
        resources[adapter.path.stem] = {
            "resource_class": "light",
            "estimated_memory_mb": 2048,
        }
    write_json(out / "module-resources.json", resources)
    modules = sorted(path.stem for path in (out / "StageA").glob("*.lean"))
    _manifest(
        out,
        "mixed-original-writable-slot-authority-lean",
        {
            "original_pe": original,
            "reference_contract": Path(args.reference_contract),
            "state_machine": state_machine,
            "load_image_contract": Path(args.load_image_contract),
            "machine_import_report": machine_import_report,
            "base_plan": base_plan_path,
        },
        status=(
            "source-ready"
            if not proposal.blockers
            else "incomplete"
        ),
        proof_authority=False,
        report_format=RELOCATED_WRITABLE_STATIC_POINTER_SLOT_AUTHORITY_FORMAT,
        failure_mode="incomplete",
        authorizing_lean_terms=list(consumed.authorizing_terms),
        adapter_terms=[adapter.valid_term for adapter in adapters],
        indirect_exit_certificate_terms=[
            adapter.indirect_exit_term for adapter in adapters
        ],
        public_outputs={
            "authority_report": authority_report.name,
            "base_plan": "interpreter-mixed-original-base-plan.json",
            "direct_call_proposal_ir": "direct-call-proposal-ir.json",
            "original_cutpoint_graph_ir": (
                "original-cutpoint-graph-ir.json"
            ),
            "base_module": (
                "StageA/"
                f"{INTERPRETER_MIXED_ORIGINAL_BASE_MODULE}.lean"
            ),
            "module_resources": "module-resources.json",
            **callable_outputs,
        },
        callable_counts=callable_counts,
        modules=modules,
        targets=[INTERPRETER_MIXED_ORIGINAL_BASE_MODULE],
        counts={
            "regions": len(consumed.plan.regions),
            "reachable_targets": len(consumed.plan.reachable_target_ids),
            "authority_terms": len(references),
            "authority_proposal_blockers": len(proposal.blockers),
            "decomposed_adapters": len(adapters),
            "blockers_before": consumed.blocker_count_before,
            "blockers_after": consumed.blocker_count_after,
        },
        remaining_frontiers=[
            blocker.to_json() for blocker in consumed.plan.blockers
        ],
    )


def _mixed_original_register_indirect_authority(
    args: argparse.Namespace,
) -> None:
    """Emit exact static certificates for every register-mediated frontier.

    The generated ``CheckedAuthority`` uses ``RuntimeClosure`` itself as its
    reachability predicate.  This keeps the static certificate executable and
    independently cacheable without claiming that an actually reachable
    source satisfies the closure.  Whole-program composition must prove that
    implication before it may remove any frontier.
    """

    original = Path(args.original)
    state_machine = Path(args.state_machine)
    machine_import_report = Path(args.machine_import_report)
    writable_report = Path(args.writable_slot_authority_report)
    base_plan_path, base_payload = _checked_mixed_original_base_plan(
        args.base_plan, state_machine
    )
    plan = _mixed_original_plan_with_contracts(args)
    if base_payload != plan.to_json():
        raise ValueError(
            "register-indirect authority baseline no longer matches its base plan"
        )

    proposal = construct_register_indirect_control_authorities(
        original=original,
        state_machine=state_machine,
        machine_import_report=machine_import_report,
        mixed_original_plan=plan,
        writable_slot_authority_report=writable_report,
        callable_resource_ids_by_instruction_rva=(
            {}
            if (callable_proposal := _callable_external_proposal(args)) is None
            else callable_resource_ids_by_instruction_rva(callable_proposal)
        ),
    )
    context_module = (
        "StageA."
        f"{INTERPRETER_MIXED_ORIGINAL_BASE_MODULE}CarrierData"
    )
    context_term = (
        "StageA.GeneratedRelational.InterpreterMixedOriginalBase."
        "generatedOriginalStaticContext"
    )
    exact_authority_term = (
        "StageA.GeneratedRelational.InterpreterMixedOriginalBase."
        "generatedExactOriginalDecodedAuthority"
    )
    bindings = {
        site.site_id: RegisterIndirectControlLeanBindings(
            context_module=context_module,
            context_term=context_term,
            exact_authority_term=exact_authority_term,
            runtime_premise_module=context_module,
            runtime_reachability_term=(
                "fun world sourceEip state => Nonempty "
                "(RuntimeClosure generatedContext generatedCertificate "
                "world sourceEip state)"
            ),
            runtime_premise_term=(
                "by\n"
                "  intro _world _sourceEip _state closure _atSource\n"
                "  exact Classical.choice closure"
            ),
        )
        for site in proposal.sites
    }
    out = Path(args.out)
    report = write_register_indirect_control_authorities(
        out, proposal, bindings
    )
    references = load_register_indirect_control_authorities(
        report,
        original_sha256=sha256_file(original),
        state_machine_sha256=sha256_file(state_machine),
        machine_import_report_sha256=sha256_file(machine_import_report),
        mixed_original_plan=plan,
        writable_slot_report_sha256=sha256_file(writable_report),
    )
    consumed = consume_register_indirect_control_authorities(plan, references)

    facade_name = "GeneratedRegisterIndirectControlAuthorities"
    facade = out / "StageA" / f"{facade_name}.lean"
    imports = "\n".join(
        f"import {module}" for module in consumed.imported_modules
    )
    checks = "\n".join(
        f"#check {term}" for term in consumed.authorizing_terms
    )
    facade.write_text(
        f"{imports}\n\n{checks}\n",
        encoding="utf-8",
    )
    resources = {
        path.stem: {
            "resource_class": "medium",
            "estimated_memory_mb": 6144,
        }
        for path in (out / "StageA").glob(
            "GeneratedRegisterIndirectControlAuthority[0-9]*.lean"
        )
    }
    resources[facade_name] = {
        "resource_class": "light",
        "estimated_memory_mb": 1024,
    }
    write_json(out / "module-resources.json", resources)
    modules = sorted(path.stem for path in (out / "StageA").glob("*.lean"))
    _manifest(
        out,
        "mixed-original-register-indirect-authority-lean",
        {
            "original_pe": original,
            "state_machine": state_machine,
            "machine_import_report": machine_import_report,
            "writable_slot_authority_report": writable_report,
            "base_plan": base_plan_path,
        },
        status="source-ready" if not proposal.blockers else "incomplete",
        proof_authority=False,
        runtime_closure_required=True,
        report_status_is_authority=False,
        modules=modules,
        targets=[facade_name],
        public_outputs={
            "authority_report": report.name,
            "module_resources": "module-resources.json",
        },
        counts={
            "static_authority_terms": len(references),
            "proposal_blockers": len(proposal.blockers),
            "register_frontiers_partitioned": len(
                consumed.authorized_blockers
            ),
            "runtime_frontiers_remaining": len(
                consumed.authorized_blockers
            ),
            "nonregister_frontiers": len(consumed.remaining_blockers),
        },
        runtime_frontiers=[
            blocker.to_json() for blocker in consumed.authorized_blockers
        ],
        remaining_frontiers=[
            blocker.to_json() for blocker in consumed.remaining_blockers
        ],
    )


def _checked_mixed_original_base_plan(
    path_value: str, state_machine: Path
) -> tuple[Path, Mapping[str, Any]]:
    path = Path(path_value)
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping) or payload.get("format") != (
        "stage-a-interpreter-mixed-original-v1"
    ):
        raise ValueError("mixed-original base plan has the wrong format")
    if payload.get("state_machine_sha256") != sha256_file(state_machine):
        raise ValueError("mixed-original base plan state-machine hash changed")
    return path, payload


def _internal_direct_call_summary_module_resource(
    source: str,
) -> dict[str, Any]:
    """Route summary nodes by measured compact-certificate Lean complexity."""

    source_bytes = len(source.encode("utf-8"))
    child_imports = source.count(
        "\nimport StageA.GeneratedRelationalInternalDirectCallSummaryNode"
    )
    if source_bytes >= 90 * 1024:
        return {
            "resource_class": "high-memory",
            "estimated_memory_mb": 76800,
        }
    if source_bytes >= 22 * 1024 or child_imports >= 4:
        return {
            "resource_class": "large-memory",
            "estimated_memory_mb": 24576,
        }
    if source_bytes >= 16 * 1024 or child_imports:
        return {
            "resource_class": "medium",
            "estimated_memory_mb": 4096,
        }
    return {
        "resource_class": "light",
        "estimated_memory_mb": 768,
    }


def _direct_call_contract_id(callsite_rva: int) -> int:
    if (
        not isinstance(callsite_rva, int)
        or isinstance(callsite_rva, bool)
        or not 0 <= callsite_rva < 2**32
    ):
        raise ValueError("direct-call contract callsite is outside PE32")
    digest = sha256(
        b"stage-a-direct-call-contract-v1\0"
        + callsite_rva.to_bytes(4, "big")
    ).digest()
    return 0x80000000 | (int.from_bytes(digest[:4], "big") & 0x7FFFFFFF)


def _mixed_original_plan_for_direct_contracts(
    args: argparse.Namespace,
    direct_call_contracts: tuple[
        OriginalRegisterControlCallContractProposal, ...
    ],
    writable_references,
):
    """Re-run only the authority-sensitive plan from a checked baseline IR."""

    if not direct_call_contracts:
        raise ValueError(
            "authority-sensitive direct-call replanning requires contracts"
        )
    original = Path(args.original)
    reference_contract = Path(args.reference_contract)
    state_machine = Path(args.state_machine)
    load_image_contract = Path(args.load_image_contract)
    machine_import_report = Path(args.machine_import_report)
    terminal_proposals = load_interpreter_mixed_terminal_proposals(
        machine_import_report,
        original_sha256=sha256_file(original),
        reference_contract_sha256=sha256_file(reference_contract),
        state_machine_sha256=sha256_file(state_machine),
    )
    machine_contracts = load_original_register_control_call_contract_proposals(
        machine_import_report,
        original_sha256=sha256_file(original),
        state_machine_sha256=sha256_file(state_machine),
    )
    boundary_sites = _machine_import_boundary_site_proposals(
        machine_import_report
    )
    callable_proposal = _callable_external_proposal(args)
    static_data_bindings = (
        ()
        if callable_proposal is None
        else callable_proposal.static_data_bindings
    )
    static_word_call_seed_authorities = tuple(
        OriginalRegisterStaticWordSeedAuthority(
            source_rva=reference.key.source_rva,
            instruction_rva=reference.key.instruction_rva,
            binding=reference.static_binding,
        )
        for reference in writable_references
        if isinstance(reference.static_binding, OriginalStaticWordSlotBinding)
    )
    plan = plan_interpreter_mixed_original(
        state_machine,
        _mixed_original_spec(
            original=original,
            reference_contract=reference_contract,
            load_image_contract=load_image_contract,
            with_boundary_bindings=True,
            shard_size=args.shard_size,
            terminal_boundary_proposals=terminal_proposals,
            machine_import_boundary_sites=boundary_sites,
            register_control_call_contracts=(
                *machine_contracts,
                *direct_call_contracts,
            ),
            static_data_bindings=static_data_bindings,
            static_word_call_seed_authorities=(
                static_word_call_seed_authorities
            ),
        ),
    )
    if writable_references:
        plan = consume_relocated_writable_static_pointer_slot_authorities(
            plan, writable_references
        ).plan
    return plan


def _mixed_original_direct_call_proposals(args: argparse.Namespace) -> None:
    from spaghetti_extractor.relational.lean.internal_direct_call_register_summary import (
        InternalDirectCallRegisterSummaryLeanBindings,
        LeanFiniteOriginTailTarget,
        internal_direct_call_register_summary_module_dag,
    )
    from spaghetti_extractor.relational.lean.internal_direct_call_summary_proposal import (
        FiniteOriginCallAuthorityBinding,
        FiniteOriginTailAuthorityBinding,
        construct_internal_direct_call_summary_proposals,
    )

    original = Path(args.original)
    state_machine = Path(args.state_machine)
    machine_import_report = Path(args.machine_import_report)
    register_indirect_authority_report = Path(
        args.register_indirect_authority_report
    )
    writable_slot_authority_report = Path(
        args.writable_slot_authority_report
    )
    base_plan, base_payload = _checked_mixed_original_base_plan(
        args.base_plan, state_machine
    )
    proposal_ir_path = Path(args.proposal_ir)
    proposal_ir = load_direct_call_proposal_ir(
        proposal_ir_path,
        expected_input_paths={
            "base_plan": base_plan,
            "load_image_contract": Path(args.load_image_contract),
            "machine_import_report": machine_import_report,
            "original_pe": original,
            "reference_contract": Path(args.reference_contract),
            "state_machine": state_machine,
            "writable_slot_authority_report": (
                writable_slot_authority_report
            ),
        },
    )
    prior_authority_report_value = getattr(
        args, "prior_direct_call_authority_report", None
    )
    prior_contracts: tuple[
        OriginalRegisterControlCallContractProposal, ...
    ] = ()
    prior_authority_report: Path | None = None
    if prior_authority_report_value is not None:
        prior_authority_report = Path(prior_authority_report_value)
        prior_contracts = load_checked_direct_call_summary_contract_proposals(
            prior_authority_report,
            original_sha256=sha256_file(original),
            state_machine_sha256=sha256_file(state_machine),
        )
    writable_references = (
        load_relocated_writable_static_pointer_slot_authorities(
            writable_slot_authority_report,
            original_sha256=sha256_file(original),
            state_machine_sha256=sha256_file(state_machine),
            machine_import_report_sha256=sha256_file(
                machine_import_report
            ),
            mixed_original_plan_sha256_expected=(
                proposal_ir.authority_base_plan_sha256
            ),
        )
    )
    consumed_plan = None
    if prior_contracts:
        consumed_plan = _mixed_original_plan_for_direct_contracts(
            args,
            prior_contracts,
            writable_references,
        )
    target_rvas = proposal_ir.target_rvas
    target_ids_by_rva = proposal_ir.target_ids_by_rva
    direct_call_sites_by_rva = proposal_ir.direct_call_sites_by_rva
    finite_origin_tail_authorities: list[
        FiniteOriginTailAuthorityBinding
    ] = []
    finite_origin_call_authorities: list[
        FiniteOriginCallAuthorityBinding
    ] = []
    for reference in writable_references:
        if (
            reference.key.transfer_kind == "call"
            and reference.value_relation == "fixed_code_pointer"
        ):
            if (
                reference.key.continuation_target_id is None
                or reference.key.continuation_rva is None
            ):
                raise ValueError(
                    "returning writable-slot call authority has no continuation"
                )
            missing_call_targets = [
                target_id
                for target_id in reference.internal_target_ids
                if target_id not in target_rvas
            ]
            if missing_call_targets:
                raise ValueError(
                    "writable-slot call authority names absent target IDs: "
                    + ", ".join(str(target_id) for target_id in missing_call_targets)
                )
            call_target_rvas = tuple(
                target_rvas[target_id]
                for target_id in reference.internal_target_ids
            )
            finite_origin_call_authorities.append(
                FiniteOriginCallAuthorityBinding(
                    source_rva=reference.key.source_rva,
                    instruction_rva=reference.key.instruction_rva,
                    continuation_rva=reference.key.continuation_rva,
                    continuation_target_id=(
                        reference.key.continuation_target_id
                    ),
                    internal_targets=tuple(
                        LeanFiniteOriginTailTarget(
                            target_id=target_id,
                            region_id=target_rva,
                        )
                        for target_id, target_rva in zip(
                            reference.internal_target_ids,
                            call_target_rvas,
                            strict=True,
                        )
                    ),
                    internal_target_rvas=call_target_rvas,
                    authority_module=reference.decomposed_adapter_module,
                    indirect_exit_authority_term=(
                        f"{reference.decomposed_adapter_namespace}."
                        "consumedIndirectExitCertificate"
                    ),
                    indirect_exit_certificate_exact_term=(
                        f"{reference.decomposed_adapter_namespace}."
                        "consumedIndirectExitCertificateExact"
                    ),
                )
            )
        if reference.value_relation != "finite_origins":
            continue
        missing_targets = [
            target_id
            for target_id in reference.internal_target_ids
            if target_id not in target_rvas
        ]
        if missing_targets:
            raise ValueError(
                "finite-origin writable-slot authority names absent target IDs: "
                + ", ".join(str(target_id) for target_id in missing_targets)
            )
        mapped_rvas = tuple(
            target_rvas[target_id]
            for target_id in reference.internal_target_ids
        )
        finite_origin_tail_authorities.append(
            FiniteOriginTailAuthorityBinding(
                source_rva=reference.key.source_rva,
                instruction_rva=reference.key.instruction_rva,
                internal_targets=tuple(
                    LeanFiniteOriginTailTarget(
                        target_id=target_id,
                        region_id=target_rva,
                    )
                    for target_id, target_rva in zip(
                        reference.internal_target_ids,
                        mapped_rvas,
                        strict=True,
                    )
                ),
                internal_target_rvas=mapped_rvas,
                authority_module=reference.decomposed_adapter_module,
                route_term=reference.callable_route_term,
                route_authority_term=(
                    reference.callable_route_authority_term
                ),
            )
        )
        for register_tail in reference.register_tail_authorities:
            missing_tail_targets = [
                target_id
                for target_id in register_tail.internal_target_ids
                if target_id not in target_rvas
            ]
            if missing_tail_targets:
                raise ValueError(
                    "finite-origin register-tail authority names absent target IDs: "
                    + ", ".join(
                        str(target_id) for target_id in missing_tail_targets
                    )
                )
            tail_target_rvas = tuple(
                target_rvas[target_id]
                for target_id in register_tail.internal_target_ids
            )
            finite_origin_tail_authorities.append(
                FiniteOriginTailAuthorityBinding(
                    source_rva=register_tail.source_rva,
                    instruction_rva=register_tail.instruction_rva,
                    internal_targets=tuple(
                        LeanFiniteOriginTailTarget(
                            target_id=target_id,
                            region_id=target_rva,
                        )
                        for target_id, target_rva in zip(
                            register_tail.internal_target_ids,
                            tail_target_rvas,
                            strict=True,
                        )
                    ),
                    internal_target_rvas=tail_target_rvas,
                    authority_module=register_tail.module,
                    route_term=register_tail.route_term,
                    route_authority_term=(
                        register_tail.route_authority_term
                    ),
                )
            )
    machine_import_payload = json.loads(
        machine_import_report.read_text(encoding="utf-8")
    )
    register_authority_payload = json.loads(
        register_indirect_authority_report.read_text(encoding="utf-8")
    )
    requests = derive_direct_call_summary_requests_from_register_authority(
        register_authority_payload,
        machine_import_payload,
        original_sha256=sha256_file(original),
        state_machine_sha256=str(base_payload["state_machine_sha256"]),
        machine_import_report_sha256=sha256_file(machine_import_report),
    )
    runtime_value_carry_hints_value = getattr(
        args, "runtime_value_carry_hints", None
    )
    checked_stack_entry_authority_value = getattr(
        args, "checked_stack_entry_authority", None
    )
    checked_stack_entry_authority: Mapping[str, Any] | None = None
    checked_stack_entry_authority_path: Path | None = None
    checked_stack_entry_authorities = ()
    if checked_stack_entry_authority_value is not None:
        checked_stack_entry_authority_path = Path(
            checked_stack_entry_authority_value
        )
        loaded_stack_authority = json.loads(
            checked_stack_entry_authority_path.read_text(encoding="utf-8")
        )
        if not isinstance(loaded_stack_authority, Mapping):
            raise ValueError(
                "checked stack entry authority is not an object"
            )
        checked_stack_entry_authority = loaded_stack_authority
        checked_stack_entry_authorities = (
            load_checked_stack_finite_origin_call_entry_authorities(
                checked_stack_entry_authority,
                original_sha256=sha256_file(original),
                state_machine_sha256=str(base_payload["state_machine_sha256"]),
            )
        )
    runtime_value_carry_hints: Path | None = None
    if runtime_value_carry_hints_value is not None:
        runtime_value_carry_hints = Path(runtime_value_carry_hints_value)
        hints_payload = json.loads(
            runtime_value_carry_hints.read_text(encoding="utf-8")
        )
        if not isinstance(hints_payload, Mapping):
            raise ValueError("runtime value-carry hints are not an object")
        requests = (
            augment_direct_call_summary_requests_from_runtime_value_carry_hints(
                requests,
                hints_payload,
                proposal_ir,
                original_sha256=sha256_file(original),
                checked_stack_entry_authority=(
                    checked_stack_entry_authority
                ),
            )
        )
    prebound_requests = {
        request.callsite_rva
        for request in requests.finite_origin_entry_requests
    }.intersection(
        proposal_ir.prebound_finite_origin_call_instruction_rvas
    )
    if consumed_plan is None and prebound_requests:
        _, consumed_plan, fallback_references = _mixed_original_plan_layers(
            args
        )
        if fallback_references != writable_references:
            raise ValueError(
                "direct-call proposal IR and fallback writable authorities differ"
            )
        if base_payload != consumed_plan.to_json():
            raise ValueError(
                "direct-call proposal fallback plan no longer matches its "
                "cached base plan"
            )
    if consumed_plan is not None:
        actual_regions = {
            region.target_id: region.rva for region in consumed_plan.regions
        }
        if actual_regions != target_rvas:
            raise ValueError(
                "authority-sensitive plan changed the canonical region map"
            )
    out = Path(args.out)
    stage_a = out / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    recovered_entry_authorities = (
        ()
        if consumed_plan is None
        else write_register_finite_origin_call_entry_authorities(
            out,
            consumed_plan,
            instruction_rvas=(
                request.callsite_rva
                for request in requests.finite_origin_entry_requests
            ),
        )
    )
    existing_finite_sites = {
        (authority.source_rva, authority.instruction_rva)
        for authority in finite_origin_call_authorities
    }
    for authority in checked_stack_entry_authorities:
        key = (authority.source_rva, authority.instruction_rva)
        if key in existing_finite_sites:
            raise ValueError(
                "checked stack finite-origin entry duplicates an existing "
                f"call authority at RVA 0x{authority.instruction_rva:x}"
            )
        missing_target_ids = [
            target_id
            for target_id in authority.target_ids
            if target_id not in target_rvas
        ]
        if missing_target_ids:
            raise ValueError(
                "checked stack finite-origin entry names absent target IDs: "
                + ", ".join(str(target_id) for target_id in missing_target_ids)
            )
        if authority.continuation_target_id not in target_rvas:
            raise ValueError(
                "checked stack finite-origin entry names an absent "
                f"continuation target ID {authority.continuation_target_id}"
            )
        if (
            target_rvas[authority.continuation_target_id]
            != authority.continuation_rva
        ):
            raise ValueError(
                "checked stack finite-origin entry continuation no longer "
                "matches the canonical target map"
            )
        target_rvas_for_authority = tuple(
            target_rvas[target_id] for target_id in authority.target_ids
        )
        finite_origin_call_authorities.append(
            FiniteOriginCallAuthorityBinding(
                source_rva=authority.source_rva,
                instruction_rva=authority.instruction_rva,
                continuation_rva=authority.continuation_rva,
                continuation_target_id=authority.continuation_target_id,
                internal_targets=tuple(
                    LeanFiniteOriginTailTarget(
                        target_id=target_id,
                        region_id=target_rva,
                    )
                    for target_id, target_rva in zip(
                        authority.target_ids,
                        target_rvas_for_authority,
                        strict=True,
                    )
                ),
                internal_target_rvas=target_rvas_for_authority,
                authority_module=authority.module,
                indirect_exit_authority_term=(
                    authority.indirect_exit_authority_term
                ),
                indirect_exit_certificate_exact_term=(
                    authority.indirect_exit_certificate_exact_term
                ),
            ).checked()
        )
        existing_finite_sites.add(key)
    for authority in recovered_entry_authorities:
        key = (authority.source_rva, authority.instruction_rva)
        if key in existing_finite_sites:
            continue
        target_rvas_for_authority = tuple(
            target_rvas[target_id] for target_id in authority.target_ids
        )
        finite_origin_call_authorities.append(
            FiniteOriginCallAuthorityBinding(
                source_rva=authority.source_rva,
                instruction_rva=authority.instruction_rva,
                continuation_rva=authority.continuation_rva,
                continuation_target_id=authority.continuation_target_id,
                internal_targets=tuple(
                    LeanFiniteOriginTailTarget(
                        target_id=target_id,
                        region_id=target_rva,
                    )
                    for target_id, target_rva in zip(
                        authority.target_ids,
                        target_rvas_for_authority,
                        strict=True,
                    )
                ),
                internal_target_rvas=target_rvas_for_authority,
                authority_module=authority.module,
                indirect_exit_authority_term=(
                    authority.indirect_exit_authority_term
                ),
                indirect_exit_certificate_exact_term=(
                    authority.indirect_exit_certificate_exact_term
                ),
            )
        )
        existing_finite_sites.add(key)
    requests = stage_finite_origin_entry_requests(
        requests,
        available_instruction_rvas=(
            authority.instruction_rva
            for authority in finite_origin_call_authorities
        ),
    )
    proposal_plan = None
    if requests.requests or requests.finite_origin_entry_requests:
        proposal_plan = construct_internal_direct_call_summary_proposals(
            original,
            state_machine,
            machine_import_report,
            requests.requests,
            finite_origin_entry_requests=(
                requests.finite_origin_entry_requests
            ),
            finite_origin_call_authorities=finite_origin_call_authorities,
            finite_origin_tail_authorities=finite_origin_tail_authorities,
        )
    module_rows: list[dict[str, Any]] = []
    contract_ids: dict[int, int] = {}
    module_resources: dict[str, dict[str, Any]] = {
        authority.module.removeprefix("StageA."): {
            "resource_class": "medium",
            "estimated_memory_mb": 6144,
        }
        for authority in recovered_entry_authorities
    }
    summary_node_modules: set[str] = set()
    summary_artifact_modules: set[str] = set()
    if proposal_plan is not None:
        support_module = (
            "GeneratedRelationalInternalDirectCallSummarySupport"
        )
        support_namespace = (
            "StageA.Generated.RelationalInternalDirectCallRegisterSummary"
        )
        static_namespace = (
            "StageA.GeneratedRelational.StaticMachineImports"
        )
        boundary_ids = sorted({
            boundary_id
            for proposal in proposal_plan.proposals
            for boundary_id in proposal.machine_import_boundary_ids
        })
        support_definitions = [
            "def generatedSummaryMachineImportRequired :=\n"
            f"  {static_namespace}.generatedRequiredImports",
            "def generatedSummaryMachineImportSignatures :=\n"
            f"  {static_namespace}.generatedMachineImportSignatures",
        ]
        support_definitions.extend(
            f"def generatedSummaryMachineImportBoundary{boundary_id} :\n"
            "    StageA.Relational.StaticMachineImportContracts."
            "StaticMachineImportBoundary :=\n"
            f"  ({static_namespace}.generatedMachineImportBoundaries.find? "
            f"(fun boundary => boundary.id == {boundary_id})).get (by decide)"
            for boundary_id in boundary_ids
        )
        support_source = (
            f"import StageA.{STATIC_MACHINE_IMPORT_MODULE}\n\n"
            f"namespace {support_namespace}\n\n"
            "open StageA.Relational.StaticMachineImportContracts\n\n"
            + "\n\n".join(support_definitions)
            + f"\n\nend {support_namespace}\n"
        )
        (stage_a / f"{support_module}.lean").write_text(
            support_source,
            encoding="utf-8",
        )
        module_resources[support_module] = {
            "resource_class": "light",
            "estimated_memory_mb": 768,
        }
        checker_bindings = InternalDirectCallRegisterSummaryLeanBindings(
            original_pe="StageA.GeneratedRelational.originalPe",
            candidate_pe="StageA.GeneratedRelational.originalPe",
            original_imports="StageA.GeneratedRelational.originalImports",
            candidate_imports="StageA.GeneratedRelational.originalImports",
            imports=(
                "StageA.GeneratedGnuHelloOriginalPE",
                f"StageA.{support_module}",
            ),
        )
        node_sources: dict[str, str] = {}
        node_resources: dict[str, dict[str, Any]] = {}
        for proposal in proposal_plan.proposals:
            module = (
                "GeneratedRelationalInternalDirectCallSummaryProposal"
                f"{proposal.request.callsite_rva:08x}"
            )
            namespace = f"StageA.Generated.{module}"
            dag = internal_direct_call_register_summary_module_dag(
                proposal.tree,
                checker_bindings,
                root_namespace=namespace,
            )
            summary_node_modules.update(
                node_module.module for node_module in dag.node_modules
            )
            summary_artifact_modules.update(
                artifact_module.module
                for artifact_module in dag.artifact_modules
            )
            destination = stage_a / f"{module}.lean"
            destination.write_text(dag.root_source, encoding="utf-8")
            module_resources[module] = {
                "resource_class": "medium",
                "estimated_memory_mb": 4096,
            }
            for node_module in dag.all_modules:
                prior = node_sources.get(node_module.module)
                if prior is not None and prior != node_module.source:
                    raise ValueError(
                        "one direct-call summary node module names "
                        "incompatible generated sources"
                    )
                node_sources[node_module.module] = node_module.source
                resource = {
                    "resource_class": node_module.resource_class,
                    "estimated_memory_mb": node_module.estimated_memory_mb,
                }
                prior_resource = node_resources.get(node_module.module)
                if (
                    prior_resource is not None
                    and prior_resource != resource
                ):
                    raise ValueError(
                        "one direct-call summary node module names "
                        "incompatible resource estimates"
                    )
                node_resources[node_module.module] = resource
            callee_rva = proposal.tree.certificate.callee_entry.original.start
            callee_target_id = target_ids_by_rva.get(callee_rva)
            entry_authority = proposal.entry_authority
            if entry_authority is None:
                site = direct_call_sites_by_rva.get(
                    proposal.request.callsite_rva
                )
                if site is None or callee_target_id is None:
                    raise ValueError(
                        "direct-call proposal has no canonical source, "
                        "continuation, or callee target"
                    )
                source_rva = site.source_rva
                source_target_id = site.source_target_id
                continuation_rva = site.continuation_rva
                continuation_target_id = site.continuation_target_id
                edge_index = site.edge_index
                entry_kind = "direct"
                entry_authority_module = None
                entry_authority_term = None
                entry_authority_certificate_exact_term = None
            else:
                if (
                    callee_target_id is None
                    or len(entry_authority.internal_targets) != 1
                    or entry_authority.internal_targets[0].target_id
                        != callee_target_id
                ):
                    raise ValueError(
                        "finite-origin entry proposal has no unique canonical "
                        "callee target"
                    )
                source_rva = entry_authority.source_rva
                source_target_id_value = target_ids_by_rva.get(source_rva)
                if source_target_id_value is None:
                    raise ValueError(
                        "finite-origin entry source has no canonical target"
                    )
                source_target_id = source_target_id_value
                continuation_rva = entry_authority.continuation_rva
                continuation_target_id = (
                    entry_authority.continuation_target_id
                )
                edge_index = proposal_ir.call_return_edge_index(
                    source_target_id, continuation_target_id
                )
                entry_kind = "finite_origin_call"
                entry_authority_module = (
                    entry_authority.authority_module
                )
                entry_authority_term = (
                    entry_authority.indirect_exit_authority_term
                )
                entry_authority_certificate_exact_term = (
                    entry_authority.indirect_exit_certificate_exact_term
                )
            contract_id = _direct_call_contract_id(
                proposal.request.callsite_rva
            )
            prior_callsite = contract_ids.get(contract_id)
            if (
                prior_callsite is not None
                and prior_callsite != proposal.request.callsite_rva
            ):
                raise ValueError(
                    "direct-call contract ID collision between callsites "
                    f"0x{prior_callsite:x} and "
                    f"0x{proposal.request.callsite_rva:x}"
                )
            contract_ids[contract_id] = proposal.request.callsite_rva
            module_rows.append({
                "callsite_rva": proposal.request.callsite_rva,
                "callee_rva": callee_rva,
                "callee_target_id": callee_target_id,
                "continuation_rva": continuation_rva,
                "continuation_target_id": continuation_target_id,
                "contract_id": contract_id,
                "edge_index": edge_index,
                "entry_kind": entry_kind,
                "entry_authority_module": entry_authority_module,
                "entry_authority_term": entry_authority_term,
                "entry_authority_certificate_exact_term": (
                    entry_authority_certificate_exact_term
                ),
                "identity_registers": [
                    register
                    for register in proposal.tree.certificate.requested_registers
                    if register != "esp"
                    and register not in {
                        witness.register
                        for witness in proposal.tree.certificate.stack_witnesses
                    }
                ],
                "caller_frame_word_offsets": list(
                    proposal.request.caller_frame_word_offsets
                ),
                "stack_witnesses": [
                    {
                        "checked": (
                            f"{namespace}."
                            "generatedInternalDirectCallRegisterSummary"
                            f"StackWitness{witness_index:04d}Checked"
                        ),
                        "member": (
                            f"{namespace}."
                            "generatedInternalDirectCallRegisterSummary"
                            f"StackWitness{witness_index:04d}Member"
                        ),
                        "operational_path_supported": True,
                        "register": witness.register,
                        "term": (
                            f"{namespace}."
                            "generatedInternalDirectCallRegisterSummary"
                            f"StackWitness{witness_index:04d}"
                        ),
                    }
                    for witness_index, witness in enumerate(
                        proposal.tree.certificate.stack_witnesses
                    )
                ],
                "module": f"StageA.{module}",
                "namespace": namespace,
                "source_rva": source_rva,
                "source_target_id": source_target_id,
                "summary_tree": (
                    f"{namespace}.generatedInternalDirectCallRegisterSummary"
                ),
                "summary_checked": (
                    f"{namespace}."
                    "generatedInternalDirectCallRegisterSummaryChecked"
                ),
                "summary_certificate_exact": (
                    f"{namespace}."
                    "generatedInternalDirectCallRegisterSummaryCertificateExact"
                ),
            })
        for module, source in sorted(node_sources.items()):
            relative = module.removeprefix("StageA.")
            (stage_a / f"{relative}.lean").write_text(
                source,
                encoding="utf-8",
            )
            module_resources[relative] = node_resources[module]
    write_json(out / "module-resources.json", module_resources)
    payload = {
        "format": "stage-a-mixed-original-direct-call-proposals-v1",
        "inputs": {
            "original_sha256": sha256_file(original),
            "state_machine_sha256": sha256_file(state_machine),
            "machine_import_report_sha256": sha256_file(machine_import_report),
            "register_indirect_authority_report_sha256": sha256_file(
                register_indirect_authority_report
            ),
            "writable_slot_authority_report_sha256": sha256_file(
                writable_slot_authority_report
            ),
            "base_plan_sha256": sha256_file(base_plan),
            "prior_direct_call_authority_report_sha256": (
                None
                if prior_authority_report is None
                else sha256_file(prior_authority_report)
            ),
            "runtime_value_carry_hints_sha256": (
                None
                if runtime_value_carry_hints is None
                else sha256_file(runtime_value_carry_hints)
            ),
            "checked_stack_entry_authority_sha256": (
                None
                if checked_stack_entry_authority_path is None
                else sha256_file(checked_stack_entry_authority_path)
            ),
        },
        "authority": {
            "proposal_only": True,
            "standalone_acceptance_authority": False,
            "authorizing_lean_term": None,
        },
        "request_plan": requests.to_json(),
        "planner": None if proposal_plan is None else proposal_plan.to_json(),
        "proposal_modules": module_rows,
    }
    write_json(out / "internal-direct-call-summary-proposals.json", payload)
    write_json(
        out / "stack-dynamic-control-input.json",
        proposal_ir.stack_dynamic_control.to_json(),
    )
    write_json(
        out / "original-cutpoint-graph-ir.json",
        proposal_ir.original_cutpoint_graph.to_json(),
    )
    _manifest(
        out,
        "mixed-original-direct-call-proposals",
        {
            "original_pe": original,
            "state_machine": state_machine,
            "machine_import_report": machine_import_report,
            "register_indirect_authority_report": (
                register_indirect_authority_report
            ),
            "writable_slot_authority_report": (
                writable_slot_authority_report
            ),
            "base_plan": base_plan,
            "proposal_ir": proposal_ir_path,
            **(
                {}
                if runtime_value_carry_hints is None
                else {
                    "runtime_value_carry_hints": runtime_value_carry_hints
                }
            ),
            **(
                {}
                if checked_stack_entry_authority_path is None
                else {
                    "checked_stack_entry_authority": (
                        checked_stack_entry_authority_path
                    )
                }
            ),
        },
        status="proposal-source-ready",
        proof_authority=False,
        public_outputs={
            "stack_dynamic_control_input": "stack-dynamic-control-input.json",
            "original_cutpoint_graph_ir": "original-cutpoint-graph-ir.json",
        },
        modules=[row["module"].removeprefix("StageA.") for row in module_rows],
        counts={
            "requests": len(requests.requests),
            "finite_origin_entry_requests": len(
                requests.finite_origin_entry_requests
            ),
            "complete_proposals": (
                0 if proposal_plan is None else len(proposal_plan.proposals)
            ),
            "proposal_blockers": (
                0 if proposal_plan is None else len(proposal_plan.blockers)
            ),
            "request_frontiers": len(requests.frontiers),
            "cacheable_summary_nodes": len(summary_node_modules),
            "cacheable_summary_artifacts": (
                len(summary_node_modules) + len(summary_artifact_modules)
            ),
            "structural_family_artifacts": len(summary_artifact_modules),
            "recovered_finite_origin_entry_authorities": len(
                recovered_entry_authorities
            ),
            "checked_stack_finite_origin_entry_authorities": len(
                checked_stack_entry_authorities
            ),
        },
    )


def _mixed_original_direct_call_semantics(args: argparse.Namespace) -> None:
    from spaghetti_extractor.relational.lean.internal_direct_call_semantics_bundle import (
        write_mixed_original_direct_call_semantics,
    )

    write_mixed_original_direct_call_semantics(
        original=Path(args.original),
        state_machine=Path(args.state_machine),
        proposal_report=Path(args.proposal_report),
        semantic_input=(
            None
            if args.semantic_input is None
            else Path(args.semantic_input)
        ),
        out=Path(args.out),
    )


def _checked_stack_dynamic_authority_report(
    path: Path,
    *,
    original_sha256: str,
    state_machine_sha256: str,
) -> Mapping[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping):
        raise ValueError("stack/dynamic authority report is not an object")
    inputs = payload.get("inputs")
    role = payload.get("artifact_role")
    counts = payload.get("counts")
    sites = payload.get("sites")
    if (
        payload.get("format")
        != "stage-a-original-stack-dynamic-control-closure-v1"
        or payload.get("status") != "incomplete"
        or not isinstance(inputs, Mapping)
        or inputs.get("original_pe_sha256") != original_sha256
        or inputs.get("state_machine_sha256") != state_machine_sha256
        or not isinstance(role, Mapping)
        or role.get("acceptance_authority") is not False
        or role.get("report_status_closes_obligations") is not False
        or role.get("runtime_premises_embedded") is not False
        or role.get("static_authority_generated") is not True
        or not isinstance(counts, Mapping)
        or not isinstance(sites, list)
        or counts.get("sites") != len(sites)
        or counts.get("static_authorities") != len(sites)
        or counts.get("runtime_premises_required") != len(sites)
        or not sites
    ):
        raise ValueError("stack/dynamic authority report is malformed")
    exact_sites: set[tuple[int, int]] = set()
    for index, site in enumerate(sites):
        if (
            not isinstance(site, Mapping)
            or site.get("static_authority") != "lean_checked"
            or site.get("premise_status") != "required"
            or not isinstance(site.get("stable_id"), str)
            or not isinstance(site.get("source_rva"), int)
            or not isinstance(site.get("instruction_rva"), int)
            or not isinstance(site.get("source_target_id"), int)
            or not isinstance(site.get("premise_type"), str)
        ):
            raise ValueError(
                f"stack/dynamic authority site {index} is malformed"
            )
        key = (site["source_rva"], site["instruction_rva"])
        if key in exact_sites:
            raise ValueError(
                "stack/dynamic authority report contains a duplicate exact site"
            )
        exact_sites.add(key)
    return payload


def _mixed_original_final(args: argparse.Namespace) -> None:
    original = Path(args.original)
    state_machine = Path(args.state_machine)
    base_plan, base_payload = _checked_mixed_original_base_plan(
        args.base_plan, state_machine
    )
    direct_contracts = load_checked_direct_call_summary_contract_proposals(
        args.direct_call_authority_report,
        original_sha256=sha256_file(original),
        state_machine_sha256=sha256_file(state_machine),
    )
    stack_dynamic_report_path = Path(args.stack_dynamic_authority_report)
    stack_dynamic_report = _checked_stack_dynamic_authority_report(
        stack_dynamic_report_path,
        original_sha256=sha256_file(original),
        state_machine_sha256=sha256_file(state_machine),
    )
    stack_dynamic_sites = stack_dynamic_report["sites"]
    plan = _mixed_original_plan_with_contracts(args, direct_contracts)
    if (
        base_payload.get("entry_rva") != plan.spec.entry_rva
        or base_payload.get("tls_callback_rvas") != list(plan.spec.tls_callback_rvas)
        or base_payload.get("reachable_target_ids") != list(plan.reachable_target_ids)
    ):
        raise ValueError("mixed-original final plan no longer matches its base context")
    written = write_relational_interpreter_mixed_original_final(args.out, plan)
    modules = sorted(path.stem for path in written if path.suffix == ".lean")
    authority_terms = sorted(
        proposal.authorizing_lean_term.qualified
        for proposal in direct_contracts
        if proposal.authorizing_lean_term is not None
    )
    _manifest(
        Path(args.out),
        "mixed-original-final-lean",
        {
            "original_pe": original,
            "reference_contract": Path(args.reference_contract),
            "state_machine": state_machine,
            "load_image_contract": Path(args.load_image_contract),
            "machine_import_report": Path(args.machine_import_report),
            "writable_slot_authority_report": Path(
                args.writable_slot_authority_report
            ),
            "direct_call_authority_report": Path(args.direct_call_authority_report),
            "stack_dynamic_authority_report": stack_dynamic_report_path,
            "base_plan": base_plan,
        },
        status="source-ready" if plan.complete else "incomplete",
        proof_authority=False,
        exact_reachability_emitted=plan.complete,
        authorizing_lean_terms=authority_terms,
        modules=modules,
        targets=[INTERPRETER_MIXED_ORIGINAL_MODULE],
        counts={
            "regions": len(plan.regions),
            "addresses": len(plan.regions) + len(plan.recovered_aliases),
            "reachable_targets": len(plan.reachable_target_ids),
            "authorized_direct_call_contracts": len(direct_contracts),
            "checked_stack_dynamic_static_authorities": len(
                stack_dynamic_sites
            ),
            "stack_dynamic_runtime_premises": len(stack_dynamic_sites),
            "blockers": len(plan.blockers),
        },
        stack_dynamic_runtime_frontiers=[
            {
                "stable_id": site["stable_id"],
                "source_rva": site["source_rva"],
                "instruction_rva": site["instruction_rva"],
                "source_target_id": site["source_target_id"],
                "premise_type": site["premise_type"],
            }
            for site in stack_dynamic_sites
        ],
        remaining_frontiers=[blocker.to_json() for blocker in plan.blockers],
    )


def _mixed_original_static_reachability(args: argparse.Namespace) -> None:
    out = Path(args.out)
    plan = write_interpreter_mixed_original_static_reachability_bundle(
        mixed_original_plan=args.mixed_original_plan,
        out=out,
    )
    modules = _move_generated_lean_to_stage_a(out)
    payload = plan.payload()
    _manifest(
        out,
        "mixed-original-static-reachability",
        {"mixed_original_plan": Path(args.mixed_original_plan)},
        status="typed-interface-ready",
        proof_authority=False,
        failure_mode="incomplete",
        theorem=INTERPRETER_MIXED_ORIGINAL_STATIC_REACHABILITY_THEOREM,
        modules=modules,
        targets=[
            Path(
                INTERPRETER_MIXED_ORIGINAL_STATIC_REACHABILITY_LEAN_FILENAME
            ).stem
        ],
        public_outputs={
            "plan": INTERPRETER_MIXED_ORIGINAL_STATIC_REACHABILITY_PLAN_FILENAME,
            "lean_module": (
                "StageA/"
                f"{INTERPRETER_MIXED_ORIGINAL_STATIC_REACHABILITY_LEAN_FILENAME}"
            ),
        },
        counts=payload["counts"],
        runtime_indirect_control=payload["runtime_indirect_control"],
    )


def _mixed_original_carrier_binding(args: argparse.Namespace) -> None:
    """Emit the independently cached exact one-sided carrier certificate."""

    mixed_original = Path(args.mixed_original)
    manifest_path = mixed_original / "phase-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    counts = manifest.get("counts")
    carrier_variants = {
        "mixed-original-base-lean": (
            INTERPRETER_MIXED_ORIGINAL_BASE_MODULE,
            "StageA.GeneratedRelational.InterpreterMixedOriginalBase",
        ),
        "mixed-original-final-lean": (
            INTERPRETER_MIXED_ORIGINAL_MODULE,
            "StageA.GeneratedRelational.InterpreterMixedOriginal",
        ),
    }
    variant = carrier_variants.get(manifest.get("phase"))
    if (
        variant is None
        or manifest.get("proof_authority") is not False
        or not isinstance(counts, Mapping)
    ):
        raise ValueError("mixed-original carrier input manifest is malformed")
    target_count = counts.get("regions")
    address_count = counts.get("addresses")
    if (
        not isinstance(target_count, int)
        or isinstance(target_count, bool)
        or target_count < 0
        or not isinstance(address_count, int)
        or isinstance(address_count, bool)
        or address_count < target_count
    ):
        raise ValueError("mixed-original carrier inventory counts are malformed")
    original_module, original_namespace = variant
    original_module_path = mixed_original / "StageA" / f"{original_module}.lean"
    if not original_module_path.is_file():
        raise ValueError("mixed-original carrier input module is missing")

    spec = OriginalCarrierBindingSpec(
        original_module=f"StageA.{original_module}",
        original_namespace=original_namespace,
        target_count=target_count,
        address_count=address_count,
    )
    generated = generate_original_carrier_binding(spec)
    written = write_original_carrier_binding(Path(args.out), spec)
    _manifest(
        Path(args.out),
        "mixed-original-carrier-binding-lean",
        {"mixed_original_manifest": manifest_path},
        status="source-ready",
        proof_authority=False,
        modules=[written.stem],
        targets=[generated.module],
        namespace=generated.namespace,
        exact_mixed_binding=(
            f"{generated.namespace}.{generated.terms.mixed_binding}"
        ),
        counts={
            "targets": target_count,
            "addresses": address_count,
        },
    )


def _kernel_loop(args: argparse.Namespace) -> None:
    out = Path(args.out)
    plan = write_relational_interpreter_kernel_loop_bundle(
        kernel_plan=args.kernel_plan, out=out
    )
    stage_a = out / "StageA"
    stage_a.mkdir(exist_ok=True)
    for source in out.glob("*.lean"):
        shutil.move(str(source), str(stage_a / source.name))
    _manifest(
        out,
        "compiled-kernel-loops",
        {"kernel_plan": Path(args.kernel_plan)},
        status="source-ready",
        diagnostic_status=plan.payload().get("status", "semantic_proof_required"),
        modules=sorted(path.stem for path in stage_a.glob("*.lean")),
        targets=["GeneratedRelationalInterpreterKernelLoop"],
    )


def _kernel_callback(args: argparse.Namespace) -> None:
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    candidate = Path(args.candidate)
    view = _kernel_view(Path(args.kernel_plan), candidate)
    contract = propose_stage_b_interpreter_kernel_callback_contract(
        candidate_pe=candidate,
        kernel_plan=view,
        linker_map=args.linker_map,
        native_engine_plan=args.native_engine_plan,
    )
    contract_path = out / "callback-classification-contract.json"
    write_json(contract_path, contract)
    plan = write_relational_interpreter_kernel_callback_bundle(
        candidate_pe=candidate,
        kernel_plan=view,
        classification_contract=contract,
        out_dir=out,
    )
    indirect_plan = write_relational_interpreter_kernel_indirect_bundle(
        candidate_pe=candidate,
        kernel_plan=Path(args.kernel_plan),
        callback_plan=plan,
        out_dir=out,
    )
    stage_a = out / "StageA"
    stage_a.mkdir(exist_ok=True)
    for source in out.glob("*.lean"):
        shutil.move(str(source), str(stage_a / source.name))
    _manifest(
        out,
        "compiled-kernel-callbacks",
        {
            "candidate": candidate,
            "kernel_plan": Path(args.kernel_plan),
            "linker_map": Path(args.linker_map),
            "native_engine_plan": Path(args.native_engine_plan),
        },
        status="source-ready",
        diagnostic_status=indirect_plan.payload()["classification_status"],
        modules=sorted(path.stem for path in stage_a.glob("*.lean")),
        targets=[
            "GeneratedRelationalInterpreterKernelCallback",
            "GeneratedRelationalInterpreterKernelIndirect",
        ],
        counts=indirect_plan.payload()["counts"],
    )


def _move_generated_lean_to_stage_a(out: Path) -> list[str]:
    stage_a = out / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    for source in sorted(out.glob("*.lean")):
        shutil.move(str(source), str(stage_a / source.name))
    return sorted(path.stem for path in stage_a.glob("*.lean"))


def _kernel_lookup(args: argparse.Namespace) -> None:
    out = Path(args.out)
    plan = write_relational_interpreter_kernel_summary_bundle(
        kernel_plan=args.kernel_plan,
        data_inventory=args.kernel_data_inventory,
        out=out,
    )
    modules = _move_generated_lean_to_stage_a(out)
    target = Path(INTERPRETER_KERNEL_SUMMARY_LEAN_FILENAME).stem
    _manifest(
        out,
        "compiled-kernel-program-lookup",
        {
            "kernel_plan": Path(args.kernel_plan),
            "kernel_data_inventory": Path(args.kernel_data_inventory),
        },
        status="source-ready",
        diagnostic_status=plan.payload().get("status", "semantic_proof_required"),
        modules=modules,
        targets=[target],
    )


def _kernel_lookup_native(args: argparse.Namespace) -> None:
    out = Path(args.out)
    plan = write_relational_interpreter_kernel_lookup_native_bundle(
        kernel_plan=args.kernel_plan,
        data_inventory=args.kernel_data_inventory,
        candidate_pe=args.candidate,
        out=out,
    )
    modules = _move_generated_lean_to_stage_a(out)
    target = Path(INTERPRETER_KERNEL_LOOKUP_NATIVE_LEAN_FILENAME).stem
    _manifest(
        out,
        "compiled-kernel-program-lookup-native",
        {
            "candidate": Path(args.candidate),
            "kernel_plan": Path(args.kernel_plan),
            "kernel_data_inventory": Path(args.kernel_data_inventory),
        },
        status="source-ready",
        diagnostic_status=plan.payload().get(
            "status", "local_semantics_required"
        ),
        modules=modules,
        targets=[target],
    )


def _kernel_lookup_operation(args: argparse.Namespace) -> None:
    out = Path(args.out)
    inputs = {
        "candidate": Path(args.candidate),
        "kernel_plan": Path(args.kernel_plan),
        "kernel_data_inventory": Path(args.kernel_data_inventory),
        "lookup_native_plan": Path(args.lookup_native_plan),
        "abi_plan": Path(args.abi_plan),
    }
    plan = write_relational_interpreter_kernel_program_lookup_operation_bundle(
        candidate_pe=inputs["candidate"],
        kernel_plan=inputs["kernel_plan"],
        data_inventory=inputs["kernel_data_inventory"],
        lookup_native_plan=inputs["lookup_native_plan"],
        abi_plan=inputs["abi_plan"],
        out=out,
    )
    payload = plan.payload()
    theorem = payload["result"]["theorem"]
    if theorem != INTERPRETER_KERNEL_PROGRAM_LOOKUP_OPERATION_THEOREM:
        raise ValueError(
            "programLookup operation emitter returned an unexpected theorem"
        )
    modules = _move_generated_lean_to_stage_a(out)
    target = Path(
        INTERPRETER_KERNEL_PROGRAM_LOOKUP_OPERATION_LEAN_FILENAME
    ).stem
    write_json(
        out / "module-resources.json",
        {
            target: {
                "resource_class": "high-memory",
                "estimated_memory_mb": 16384,
            }
        },
    )
    _manifest(
        out,
        "compiled-kernel-program-lookup-operation",
        inputs,
        status="source-ready",
        proof_authority=False,
        plan_format=payload["format"],
        failure_mode=payload["failure_mode"],
        remaining_proof_premises=payload["remaining_proof_premises"],
        theorem=theorem,
        public_outputs={
            "plan": INTERPRETER_KERNEL_PROGRAM_LOOKUP_OPERATION_PLAN_FILENAME,
            "lean_module": (
                "StageA/"
                f"{INTERPRETER_KERNEL_PROGRAM_LOOKUP_OPERATION_LEAN_FILENAME}"
            ),
            "module_resources": "module-resources.json",
        },
        modules=modules,
        targets=[target],
    )


def _kernel_step(args: argparse.Namespace) -> None:
    out = Path(args.out)
    plan = write_relational_interpreter_kernel_step_bundle(
        kernel_plan=args.kernel_plan,
        out=out,
    )
    modules = _move_generated_lean_to_stage_a(out)
    target = Path(INTERPRETER_KERNEL_STEP_LEAN_FILENAME).stem
    _manifest(
        out,
        "compiled-kernel-interpreter-step",
        {"kernel_plan": Path(args.kernel_plan)},
        status="source-ready",
        diagnostic_status=plan.payload().get("status", "semantic_proof_required"),
        modules=modules,
        targets=[target],
    )


def _kernel_step_native(args: argparse.Namespace) -> None:
    out = Path(args.out)
    plan = write_relational_interpreter_kernel_step_native_bundle(
        kernel_plan=args.kernel_plan,
        callback_plan=args.callback_plan,
        candidate_pe=args.candidate,
        out=out,
    )
    modules = _move_generated_lean_to_stage_a(out)
    target = Path(INTERPRETER_KERNEL_STEP_NATIVE_LEAN_FILENAME).stem
    _manifest(
        out,
        "compiled-kernel-interpreter-step-native",
        {
            "candidate": Path(args.candidate),
            "kernel_plan": Path(args.kernel_plan),
            "callback_plan": Path(args.callback_plan),
        },
        status="source-ready",
        diagnostic_status=plan.payload().get(
            "status", "local_semantics_required"
        ),
        modules=modules,
        targets=[target],
    )


def _kernel_step_operation(args: argparse.Namespace) -> None:
    out = Path(args.out)
    inputs = {
        "candidate": Path(args.candidate),
        "kernel_plan": Path(args.kernel_plan),
        "kernel_data_inventory": Path(args.kernel_data_inventory),
        "abi_plan": Path(args.abi_plan),
        "step_native_plan": Path(args.step_native_plan),
        "callback_plan": Path(args.callback_plan),
        "lookup_native_plan": Path(args.lookup_native_plan),
        "lookup_operation_plan": Path(args.lookup_operation_plan),
        "invoke_native_plan": Path(args.invoke_native_plan),
        "x87_replay_plan": Path(args.x87_replay_plan),
    }
    plan = write_relational_interpreter_kernel_step_operation_bundle(
        candidate_pe=inputs["candidate"],
        kernel_plan=inputs["kernel_plan"],
        data_inventory=inputs["kernel_data_inventory"],
        abi_plan=inputs["abi_plan"],
        step_native_plan=inputs["step_native_plan"],
        callback_plan=inputs["callback_plan"],
        lookup_native_plan=inputs["lookup_native_plan"],
        lookup_operation_plan=inputs["lookup_operation_plan"],
        invoke_native_plan=inputs["invoke_native_plan"],
        x87_replay_plan=inputs["x87_replay_plan"],
        out=out,
    )
    payload = plan.payload()
    theorem = payload["result"]["theorem"]
    if theorem != INTERPRETER_KERNEL_STEP_OPERATION_THEOREM:
        raise ValueError(
            "interpreterStep operation emitter returned an unexpected theorem"
        )
    modules = _move_generated_lean_to_stage_a(out)
    target = Path(INTERPRETER_KERNEL_STEP_OPERATION_LEAN_FILENAME).stem
    write_json(
        out / "module-resources.json",
        {
            target: {
                "resource_class": "high-memory",
                "estimated_memory_mb": 32768,
            }
        },
    )
    _manifest(
        out,
        "compiled-kernel-interpreter-step-operation",
        inputs,
        status="source-ready",
        proof_authority=False,
        plan_format=payload["format"],
        failure_mode=payload["failure_mode"],
        remaining_proof_premises=payload["remaining_proof_premises"],
        theorem=theorem,
        public_outputs={
            "plan": INTERPRETER_KERNEL_STEP_OPERATION_PLAN_FILENAME,
            "lean_module": (
                "StageA/"
                f"{INTERPRETER_KERNEL_STEP_OPERATION_LEAN_FILENAME}"
            ),
            "module_resources": "module-resources.json",
        },
        modules=modules,
        targets=[target],
    )


def _kernel_step_program_lookup_call(args: argparse.Namespace) -> None:
    out = Path(args.out)
    plan = write_relational_interpreter_kernel_step_program_lookup_call_bundle(
        candidate_pe=args.candidate,
        kernel_plan=args.kernel_plan,
        data_inventory=args.kernel_data_inventory,
        abi_plan=args.abi_plan,
        step_native_plan=args.step_native_plan,
        callback_plan=args.callback_plan,
        lookup_native_plan=args.lookup_native_plan,
        lookup_operation_plan=args.lookup_operation_plan,
        invoke_native_plan=args.invoke_native_plan,
        x87_replay_plan=args.x87_replay_plan,
        step_operation_plan=args.step_operation_plan,
        out=out,
    )
    modules = _move_generated_lean_to_stage_a(out)
    _manifest(
        out,
        "compiled-kernel-step-program-lookup-call",
        {
            "candidate": Path(args.candidate),
            "kernel_plan": Path(args.kernel_plan),
            "kernel_data_inventory": Path(args.kernel_data_inventory),
            "abi_plan": Path(args.abi_plan),
            "step_native_plan": Path(args.step_native_plan),
            "callback_plan": Path(args.callback_plan),
            "lookup_native_plan": Path(args.lookup_native_plan),
            "lookup_operation_plan": Path(args.lookup_operation_plan),
            "invoke_native_plan": Path(args.invoke_native_plan),
            "x87_replay_plan": Path(args.x87_replay_plan),
            "step_operation_plan": Path(args.step_operation_plan),
        },
        status="typed-interface-ready",
        proof_authority=False,
        failure_mode="incomplete",
        remaining_proof_premises=list(
            INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_REMAINING_PREMISES
        ),
        theorem=INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_THEOREM,
        modules=modules,
        targets=[Path(INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_LEAN_FILENAME).stem],
        public_outputs={
            "plan": INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_PLAN_FILENAME,
            "lean_module": (
                "StageA/"
                f"{INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_LEAN_FILENAME}"
            ),
        },
        checked_static_authority=plan.payload()["checked_static_authority"],
    )


def _kernel_step_program_lookup_call_closure(args: argparse.Namespace) -> None:
    out = Path(args.out)
    plan = (
        write_relational_interpreter_kernel_step_program_lookup_call_closure_bundle(
            candidate_pe=args.candidate,
            program_lookup_call_plan=args.program_lookup_call_plan,
            out=out,
        )
    )
    modules = _move_generated_lean_to_stage_a(out)
    _manifest(
        out,
        "compiled-kernel-step-program-lookup-call-closure",
        {
            "candidate": Path(args.candidate),
            "program_lookup_call_plan": Path(args.program_lookup_call_plan),
        },
        status="typed-interface-ready",
        proof_authority=False,
        failure_mode="incomplete",
        closed_premise_families=list(
            INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_CLOSED_PREMISES
        ),
        remaining_proof_premises=list(
            INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_REMAINING_PREMISES
        ),
        theorem=INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_THEOREM,
        modules=modules,
        targets=[
            Path(
                INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_LEAN_FILENAME
            ).stem
        ],
        public_outputs={
            "plan": (
                INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_PLAN_FILENAME
            ),
            "lean_module": (
                "StageA/"
                f"{INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_LEAN_FILENAME}"
            ),
        },
        checked_authority=plan.payload()["checked_authority"],
    )


def _kernel_cdecl_epilogue(args: argparse.Namespace) -> None:
    out = Path(args.out)
    plan = write_relational_interpreter_kernel_cdecl_epilogue_bundle(
        candidate_pe=args.candidate,
        step_operation_plan=args.step_operation_plan,
        run_operation_plan=args.run_operation_plan,
        step_epilogue_rva=args.step_epilogue_rva,
        step_return_rva=args.step_return_rva,
        step_epilogue_fuel=args.step_epilogue_fuel,
        run_epilogue_rva=args.run_epilogue_rva,
        run_return_rva=args.run_return_rva,
        run_epilogue_fuel=args.run_epilogue_fuel,
        out=out,
    )
    modules = _move_generated_lean_to_stage_a(out)
    _manifest(
        out,
        "compiled-kernel-cdecl-epilogue",
        {
            "candidate": Path(args.candidate),
            "step_operation_plan": Path(args.step_operation_plan),
            "run_operation_plan": Path(args.run_operation_plan),
        },
        status="typed-interface-ready",
        proof_authority=False,
        failure_mode="incomplete",
        remaining_proof_premises=list(
            INTERPRETER_KERNEL_CDECL_EPILOGUE_REMAINING_PREMISES
        ),
        theorem=INTERPRETER_KERNEL_CDECL_EPILOGUE_THEOREM,
        modules=modules,
        targets=[Path(INTERPRETER_KERNEL_CDECL_EPILOGUE_LEAN_FILENAME).stem],
        public_outputs={
            "plan": INTERPRETER_KERNEL_CDECL_EPILOGUE_PLAN_FILENAME,
            "lean_module": (
                f"StageA/{INTERPRETER_KERNEL_CDECL_EPILOGUE_LEAN_FILENAME}"
            ),
        },
        checked_static_authority=plan.payload()["checked_static_authority"],
    )


def _kernel_cdecl_epilogue_symbolic_closure(args: argparse.Namespace) -> None:
    out = Path(args.out)
    plan = write_relational_interpreter_kernel_cdecl_epilogue_symbolic_closure_bundle(
        candidate_pe=args.candidate,
        cdecl_epilogue_plan=args.cdecl_epilogue_plan,
        out=out,
    )
    modules = _move_generated_lean_to_stage_a(out)
    _manifest(
        out,
        "compiled-kernel-cdecl-epilogue-symbolic-closure",
        {
            "candidate": Path(args.candidate),
            "cdecl_epilogue_plan": Path(args.cdecl_epilogue_plan),
        },
        status="typed-interface-ready",
        proof_authority=False,
        failure_mode="incomplete",
        closed_premise_families=list(
            INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_CLOSED_PREMISES
        ),
        remaining_proof_premises=list(
            INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_REMAINING_PREMISES
        ),
        theorem=INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_THEOREM,
        modules=modules,
        targets=[
            Path(
                INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_LEAN_FILENAME
            ).stem
        ],
        public_outputs={
            "plan": INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_PLAN_FILENAME,
            "lean_module": (
                "StageA/"
                f"{INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_LEAN_FILENAME}"
            ),
        },
        checked_authority=plan.payload()["checked_authority"],
    )


def _kernel_cdecl_epilogue_static_preservation(args: argparse.Namespace) -> None:
    out = Path(args.out)
    plan = (
        write_relational_interpreter_kernel_cdecl_epilogue_static_preservation_bundle(
            candidate_pe=args.candidate,
            symbolic_closure_plan=args.symbolic_closure_plan,
            out=out,
        )
    )
    modules = _move_generated_lean_to_stage_a(out)
    _manifest(
        out,
        "compiled-kernel-cdecl-epilogue-static-preservation",
        {
            "candidate": Path(args.candidate),
            "symbolic_closure_plan": Path(args.symbolic_closure_plan),
        },
        status="typed-interface-ready",
        proof_authority=False,
        failure_mode="incomplete",
        closed_premise_families=list(
            INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_CLOSED_PREMISES
        ),
        remaining_proof_premises=list(
            INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_REMAINING_PREMISES
        ),
        theorem=INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_THEOREM,
        modules=modules,
        targets=[
            Path(
                INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_LEAN_FILENAME
            ).stem
        ],
        public_outputs={
            "plan": (
                INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_PLAN_FILENAME
            ),
            "lean_module": (
                "StageA/"
                f"{INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_LEAN_FILENAME}"
            ),
        },
        checked_authority=plan.payload()["checked_authority"],
    )


def _kernel_cdecl_epilogue_external_payload(args: argparse.Namespace) -> None:
    out = Path(args.out)
    plan = write_relational_interpreter_kernel_cdecl_epilogue_external_payload_bundle(
        candidate_pe=args.candidate,
        static_preservation_plan=args.static_preservation_plan,
        out=out,
    )
    modules = _move_generated_lean_to_stage_a(out)
    _manifest(
        out,
        "compiled-kernel-cdecl-epilogue-external-payload",
        {
            "candidate": Path(args.candidate),
            "static_preservation_plan": Path(args.static_preservation_plan),
        },
        status="typed-interface-ready",
        proof_authority=False,
        failure_mode="incomplete",
        closed_premise_families=list(
            INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_CLOSED_PREMISES
        ),
        remaining_proof_premises=list(
            INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_REMAINING_PREMISES
        ),
        theorem=INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_THEOREM,
        modules=modules,
        targets=[
            Path(
                INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_LEAN_FILENAME
            ).stem
        ],
        public_outputs={
            "plan": (
                INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_PLAN_FILENAME
            ),
            "lean_module": (
                "StageA/"
                f"{INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_LEAN_FILENAME}"
            ),
        },
        checked_authority=plan.payload()["checked_authority"],
    )


def _kernel_operation_frame_parametric(args: argparse.Namespace) -> None:
    out = Path(args.out)
    inputs = {
        "candidate": Path(args.candidate),
        "step_operation_plan": Path(args.step_operation_plan),
    }
    plan = write_relational_interpreter_kernel_operation_frame_parametric_bundle(
        candidate_pe=inputs["candidate"],
        step_operation_plan=inputs["step_operation_plan"],
        out=out,
    )
    payload = plan.payload()
    theorem = payload["result"]["theorem"]
    if theorem != INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_THEOREM:
        raise ValueError(
            "frame-parametric operation emitter returned an unexpected theorem"
        )
    modules = _move_generated_lean_to_stage_a(out)
    target = Path(
        INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_LEAN_FILENAME
    ).stem
    write_json(
        out / "module-resources.json",
        {target: {"resource_class": "medium", "estimated_memory_mb": 8192}},
    )
    _manifest(
        out,
        "compiled-kernel-operation-frame-parametric",
        inputs,
        status="source-ready",
        proof_authority=False,
        plan_format=payload["format"],
        failure_mode=payload["failure_mode"],
        remaining_proof_premises=payload["remaining_proof_premises"],
        theorem=theorem,
        public_outputs={
            "plan": INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_PLAN_FILENAME,
            "lean_module": (
                "StageA/"
                f"{INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_LEAN_FILENAME}"
            ),
            "module_resources": "module-resources.json",
        },
        modules=modules,
        targets=[target],
    )


def _kernel_frame_executor(args: argparse.Namespace) -> None:
    out = Path(args.out)
    inputs = {
        "candidate": Path(args.candidate),
        "frame_parametric_plan": Path(args.frame_parametric_plan),
    }
    plan = write_relational_interpreter_kernel_frame_executor_bundle(
        candidate_pe=inputs["candidate"],
        frame_parametric_plan=inputs["frame_parametric_plan"],
        out=out,
    )
    payload = plan.payload()
    theorem = payload["result"]["theorem"]
    if theorem != INTERPRETER_KERNEL_FRAME_EXECUTOR_THEOREM:
        raise ValueError("frame-executor emitter returned an unexpected theorem")
    modules = _move_generated_lean_to_stage_a(out)
    target = Path(INTERPRETER_KERNEL_FRAME_EXECUTOR_LEAN_FILENAME).stem
    write_json(
        out / "module-resources.json",
        {target: {"resource_class": "medium", "estimated_memory_mb": 8192}},
    )
    _manifest(
        out,
        "compiled-kernel-frame-executor",
        inputs,
        status="source-ready",
        proof_authority=False,
        plan_format=payload["format"],
        failure_mode=payload["failure_mode"],
        remaining_proof_premises=payload["remaining_proof_premises"],
        theorem=theorem,
        public_outputs={
            "plan": INTERPRETER_KERNEL_FRAME_EXECUTOR_PLAN_FILENAME,
            "lean_module": (
                "StageA/" f"{INTERPRETER_KERNEL_FRAME_EXECUTOR_LEAN_FILENAME}"
            ),
            "module_resources": "module-resources.json",
        },
        modules=modules,
        targets=[target],
    )


def _kernel_run(args: argparse.Namespace) -> None:
    out = Path(args.out)
    plan = write_relational_interpreter_kernel_run_bundle(
        kernel_plan=args.kernel_plan,
        candidate_pe=args.candidate,
        out=out,
    )
    modules = _move_generated_lean_to_stage_a(out)
    target = Path(INTERPRETER_KERNEL_RUN_LEAN_FILENAME).stem
    _manifest(
        out,
        "compiled-kernel-run-function",
        {
            "candidate": Path(args.candidate),
            "kernel_plan": Path(args.kernel_plan),
        },
        status="source-ready",
        diagnostic_status=plan.payload().get("status", "semantic_proof_required"),
        modules=modules,
        targets=[target],
    )


def _kernel_run_native(args: argparse.Namespace) -> None:
    out = Path(args.out)
    plan = write_relational_interpreter_kernel_run_native_bundle(
        kernel_plan=args.kernel_plan,
        candidate_pe=args.candidate,
        out=out,
    )
    modules = _move_generated_lean_to_stage_a(out)
    target = Path(INTERPRETER_KERNEL_RUN_NATIVE_LEAN_FILENAME).stem
    _manifest(
        out,
        "compiled-kernel-run-function-native",
        {
            "candidate": Path(args.candidate),
            "kernel_plan": Path(args.kernel_plan),
        },
        status="source-ready",
        diagnostic_status="semantic_premises_required",
        operation="runFunction",
        candidate_sha256=plan.candidate_sha256,
        modules=modules,
        targets=[target],
    )


def _kernel_run_operation(args: argparse.Namespace) -> None:
    out = Path(args.out)
    inputs = {
        "candidate": Path(args.candidate),
        "kernel_plan": Path(args.kernel_plan),
        "kernel_data_inventory": Path(args.kernel_data_inventory),
        "abi_plan": Path(args.abi_plan),
        "run_native_plan": Path(args.run_native_plan),
    }
    plan = write_relational_interpreter_kernel_run_operation_bundle(
        candidate_pe=inputs["candidate"],
        kernel_plan=inputs["kernel_plan"],
        data_inventory=inputs["kernel_data_inventory"],
        abi_plan=inputs["abi_plan"],
        run_native_plan=inputs["run_native_plan"],
        out=out,
    )
    payload = plan.payload()
    theorem = payload["result"]["theorem"]
    if theorem != INTERPRETER_KERNEL_RUN_OPERATION_THEOREM:
        raise ValueError("runFunction operation emitter returned an unexpected theorem")
    modules = _move_generated_lean_to_stage_a(out)
    target = Path(INTERPRETER_KERNEL_RUN_OPERATION_LEAN_FILENAME).stem
    write_json(
        out / "module-resources.json",
        {
            target: {
                "resource_class": "high-memory",
                "estimated_memory_mb": 32768,
            }
        },
    )
    _manifest(
        out,
        "compiled-kernel-run-function-operation",
        inputs,
        status="source-ready",
        proof_authority=False,
        plan_format=payload["format"],
        failure_mode=payload["failure_mode"],
        remaining_proof_premises=payload["remaining_proof_premises"],
        theorem=theorem,
        public_outputs={
            "plan": INTERPRETER_KERNEL_RUN_OPERATION_PLAN_FILENAME,
            "lean_module": (
                "StageA/"
                f"{INTERPRETER_KERNEL_RUN_OPERATION_LEAN_FILENAME}"
            ),
            "module_resources": "module-resources.json",
        },
        modules=modules,
        targets=[target],
    )


def _kernel_invoke(args: argparse.Namespace) -> None:
    out = Path(args.out)
    plan = write_relational_interpreter_kernel_invoke_bundle(
        kernel_plan=args.kernel_plan,
        candidate_pe=args.candidate,
        out=out,
    )
    modules = _move_generated_lean_to_stage_a(out)
    target = Path(INTERPRETER_KERNEL_INVOKE_LEAN_FILENAME).stem
    _manifest(
        out,
        "compiled-kernel-invoke-call",
        {
            "candidate": Path(args.candidate),
            "kernel_plan": Path(args.kernel_plan),
        },
        status="source-ready",
        diagnostic_status=plan.payload().get("status", "semantic_proof_required"),
        modules=modules,
        targets=[target],
    )


def _kernel_invoke_native(args: argparse.Namespace) -> None:
    out = Path(args.out)
    plan = write_relational_interpreter_kernel_invoke_native_bundle(
        kernel_plan=args.kernel_plan,
        callback_plan=args.callback_plan,
        candidate_pe=args.candidate,
        out=out,
    )
    modules = _move_generated_lean_to_stage_a(out)
    target = Path(INTERPRETER_KERNEL_INVOKE_NATIVE_LEAN_FILENAME).stem
    _manifest(
        out,
        "compiled-kernel-invoke-call-native",
        {
            "candidate": Path(args.candidate),
            "kernel_plan": Path(args.kernel_plan),
            "callback_plan": Path(args.callback_plan),
        },
        status="source-ready",
        diagnostic_status=plan.payload().get(
            "status", "semantic_proof_required"
        ),
        modules=modules,
        targets=[target],
    )


def _kernel_invoke_operation(args: argparse.Namespace) -> None:
    out = Path(args.out)
    inputs = {
        "candidate": Path(args.candidate),
        "kernel_plan": Path(args.kernel_plan),
        "kernel_data_inventory": Path(args.kernel_data_inventory),
        "abi_plan": Path(args.abi_plan),
        "callback_plan": Path(args.callback_plan),
        "invoke_native_plan": Path(args.invoke_native_plan),
        "run_operation_plan": Path(args.run_operation_plan),
    }
    plan = write_relational_interpreter_kernel_invoke_operation_bundle(
        candidate_pe=inputs["candidate"],
        kernel_plan=inputs["kernel_plan"],
        data_inventory=inputs["kernel_data_inventory"],
        abi_plan=inputs["abi_plan"],
        callback_plan=inputs["callback_plan"],
        invoke_native_plan=inputs["invoke_native_plan"],
        run_operation_plan=inputs["run_operation_plan"],
        out=out,
    )
    payload = plan.payload()
    theorem = payload["result"]["theorem"]
    if theorem != INTERPRETER_KERNEL_INVOKE_OPERATION_THEOREM:
        raise ValueError("invokeCall operation emitter returned an unexpected theorem")
    modules = _move_generated_lean_to_stage_a(out)
    target = Path(INTERPRETER_KERNEL_INVOKE_OPERATION_LEAN_FILENAME).stem
    write_json(
        out / "module-resources.json",
        {
            target: {
                "resource_class": "high-memory",
                "estimated_memory_mb": 24576,
            }
        },
    )
    _manifest(
        out,
        "compiled-kernel-invoke-call-operation",
        inputs,
        status="source-ready",
        proof_authority=False,
        plan_format=payload["format"],
        failure_mode=payload["failure_mode"],
        remaining_proof_premises=payload["remaining_proof_premises"],
        theorem=theorem,
        public_outputs={
            "plan": INTERPRETER_KERNEL_INVOKE_OPERATION_PLAN_FILENAME,
            "lean_module": (
                "StageA/"
                f"{INTERPRETER_KERNEL_INVOKE_OPERATION_LEAN_FILENAME}"
            ),
            "module_resources": "module-resources.json",
        },
        modules=modules,
        targets=[target],
    )


def _mixed_candidate_authority(args: argparse.Namespace) -> None:
    out = Path(args.out)
    source = write_relational_interpreter_mixed_authority(
        out,
        InterpreterMixedAuthoritySpec(),
    )
    _manifest(
        out,
        "mixed-exact-native-candidate-authority",
        {"kernel_data_inventory": Path(args.kernel_data_inventory)},
        status="source-ready",
        modules=[source.stem],
        targets=[INTERPRETER_MIXED_AUTHORITY_MODULE],
    )


_DIRECT_CALL_NODE_FAMILY = re.compile(
    r"^GeneratedRelationalInternalDirectCallSummaryNode([0-9a-f]{64}).*$"
)
# Keep one direct-call certificate family as one Nix scheduling unit. Lean
# compiles modules within the pack sequentially and the aggregator checks their
# topological order. Only exceptionally large families need another layer.
_DIRECT_CALL_BUILD_PACK_MAX_MODULES = 128
_DIRECT_CALL_BUILD_PACK_SPLIT_THRESHOLD = 128


def _direct_call_family_levels(
    family_id: str,
    modules: list[str],
    imports: Mapping[str, set[str]],
) -> dict[str, int]:
    members = set(modules)
    levels: dict[str, int] = {}
    active: set[str] = set()

    def visit(module: str) -> int:
        if module in levels:
            return levels[module]
        if module in active:
            raise ValueError(
                f"Lean build pack direct-call-{family_id} contains an "
                f"import cycle at {module}"
            )
        active.add(module)
        level = 1 + max(
            (visit(dependency) for dependency in imports[module] & members),
            default=-1,
        )
        active.remove(module)
        levels[module] = level
        return level

    for module in sorted(modules):
        visit(module)
    return levels


def _proof_build_pack_ids(
    modules: list[str],
    imports: Mapping[str, set[str]],
) -> dict[str, str]:
    result: dict[str, str] = {}
    direct_call_families: dict[str, list[str]] = {}
    for module in modules:
        if (family := _DIRECT_CALL_NODE_FAMILY.match(module)) is not None:
            direct_call_families.setdefault(family.group(1), []).append(module)
            continue
        result[module] = module
    for family_id, family_modules in sorted(direct_call_families.items()):
        base_pack_id = f"direct-call-{family_id}"
        if len(family_modules) <= _DIRECT_CALL_BUILD_PACK_SPLIT_THRESHOLD:
            for module in family_modules:
                result[module] = base_pack_id
            continue
        levels = _direct_call_family_levels(
            family_id,
            family_modules,
            imports,
        )
        modules_by_level: dict[int, list[str]] = {}
        for module, level in levels.items():
            modules_by_level.setdefault(level, []).append(module)
        for level, level_modules in sorted(modules_by_level.items()):
            for offset in range(
                0,
                len(level_modules),
                _DIRECT_CALL_BUILD_PACK_MAX_MODULES,
            ):
                pack_id = (
                    f"{base_pack_id}-layer-{level:02d}-part-"
                    f"{offset // _DIRECT_CALL_BUILD_PACK_MAX_MODULES:04d}"
                )
                for module in sorted(level_modules)[
                    offset:offset + _DIRECT_CALL_BUILD_PACK_MAX_MODULES
                ]:
                    result[module] = pack_id
    return result


def _topological_build_pack(
    pack_id: str,
    modules: list[str],
    imports: Mapping[str, set[str]],
) -> list[str]:
    """Order one stable pack so its internal imports compile first."""

    members = set(modules)
    ordered: list[str] = []
    complete: set[str] = set()
    active: set[str] = set()

    def visit(module: str) -> None:
        if module in complete:
            return
        if module in active:
            raise ValueError(
                f"Lean build pack {pack_id} contains an import cycle at "
                f"{module}"
            )
        active.add(module)
        for dependency in sorted(imports[module] & members):
            visit(dependency)
        active.remove(module)
        complete.add(module)
        ordered.append(module)

    for module in sorted(modules):
        visit(module)
    return ordered


def _aggregate(args: argparse.Namespace) -> None:
    out = Path(args.out)
    stage_a = out / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    sources = [Path(path) for path in args.source]
    declared_resources: dict[str, dict[str, object]] = {}
    for source_root in sources:
        for source in sorted(source_root.rglob("*.lean")):
            destination = stage_a / source.name
            if destination.exists():
                if destination.read_bytes() != source.read_bytes():
                    raise ValueError(f"conflicting Lean module {source.stem}")
                continue
            shutil.copyfile(source, destination)
        resource_manifest = source_root / "module-resources.json"
        if resource_manifest.is_file():
            payload = json.loads(resource_manifest.read_text(encoding="utf-8"))
            if not isinstance(payload, Mapping):
                raise ValueError(
                    f"module resource manifest is not an object: {resource_manifest}"
                )
            for module, resource in payload.items():
                if not isinstance(module, str) or not isinstance(resource, Mapping):
                    raise ValueError(
                        f"malformed module resource entry in {resource_manifest}"
                    )
                normalized = dict(resource)
                prior = declared_resources.get(module)
                if prior is not None and prior != normalized:
                    raise ValueError(
                        f"conflicting resource metadata for Lean module {module}"
                    )
                declared_resources[module] = normalized
    modules = sorted(path.stem for path in stage_a.glob("*.lean"))
    module_set = set(modules)
    targets: set[str] = set()
    for source_root in sources:
        manifest = source_root / "phase-manifest.json"
        if not manifest.is_file():
            continue
        payload = json.loads(manifest.read_text(encoding="utf-8"))
        targets.update(payload.get("targets", []))
    targets.update(args.target)
    missing_targets = sorted(targets - module_set)
    if missing_targets:
        raise ValueError(f"generated proof targets are absent: {missing_targets}")
    if args.target_closure_only:
        if not targets:
            raise ValueError(
                "target-closure-only aggregation requires at least one target"
            )
        closure: set[str] = set()
        pending = list(targets)
        while pending:
            module = pending.pop()
            if module in closure:
                continue
            closure.add(module)
            source = stage_a / f"{module}.lean"
            imports = re.findall(
                r"^import StageA\.([A-Za-z0-9_]+)$",
                source.read_text(encoding="utf-8"),
                re.MULTILINE,
            )
            missing_imports = sorted(set(imports) - module_set)
            if missing_imports:
                raise ValueError(
                    f"generated proof target closure for {module} has "
                    f"missing imports {missing_imports}"
                )
            pending.extend(imports)
        for module in module_set - closure:
            (stage_a / f"{module}.lean").unlink()
        modules = sorted(closure)
        module_set = closure
    resources = {
        module: declared_resources.get(module, (
            {"resource_class": "medium", "estimated_memory_mb": 4096}
            if module.startswith("GeneratedInterpreterX87Schedule")
            else
            {"resource_class": "medium", "estimated_memory_mb": 4096}
            if module.startswith("GeneratedGnuHelloOriginalBytePack")
            else
            {"resource_class": "high-memory", "estimated_memory_mb": 8192}
            if module in {
                "GeneratedGnuHelloOriginalPE",
                "GeneratedSemanticInterpreterProgram",
                "GeneratedRelationalInterpreterKernelBlockContext",
            }
            else {"resource_class": "high-memory", "estimated_memory_mb": 76800}
            if module in {
                "GeneratedRelationalInterpreterMixedOriginalBase",
                "GeneratedRelationalInterpreterMixedOriginal",
            }
            else {"resource_class": "high-memory", "estimated_memory_mb": 16384}
            if module == "GeneratedRelationalInterpreterOriginalCarrierBinding"
            else {"resource_class": "medium", "estimated_memory_mb": 2048}
            if module.startswith("GeneratedInterpreterNormalization")
            or module.startswith("GeneratedInterpreterKernelData")
            or module.startswith("GeneratedInterpreterX87CandidateReplay")
            or module.startswith("GeneratedRelationalInterpreterKernelBlockShard")
            else {"resource_class": "light", "estimated_memory_mb": 768}
        ))
        for module in modules
    }
    module_imports = {
        module: set(re.findall(
            r"^import StageA\.([A-Za-z0-9_]+)$",
            (stage_a / f"{module}.lean").read_text(encoding="utf-8"),
            re.MULTILINE,
        ))
        for module in modules
    }
    module_build_packs = _proof_build_pack_ids(modules, module_imports)
    build_packs: dict[str, list[str]] = {}
    for module, pack_id in module_build_packs.items():
        build_packs.setdefault(pack_id, []).append(module)
    build_packs = {
        pack_id: _topological_build_pack(
            pack_id, pack_modules, module_imports
        )
        for pack_id, pack_modules in build_packs.items()
    }
    write_json(out / "standalone-modules.json", modules)
    write_json(out / "proof-targets.json", sorted(targets))
    write_json(out / "module-resources.json", resources)
    build_pack_manifest = {
        "format": "stage-a-lean-build-packs-v1",
        "modules": module_build_packs,
        "packs": {
            pack_id: pack_modules
            for pack_id, pack_modules in sorted(build_packs.items())
        },
    }
    write_json(out / "module-build-packs.json", build_pack_manifest)
    write_json(stage_a / "module-build-packs.json", build_pack_manifest)
    _manifest(
        out,
        "proof-source-aggregate",
        {},
        status="source-ready",
        modules=modules,
        targets=sorted(targets),
        target_closure_only=args.target_closure_only,
        public_outputs={
            "module_build_packs": "module-build-packs.json",
        },
        counts={
            "build_packs": len(build_packs),
            "modules": len(modules),
            "targets": len(targets),
        },
    )


def _acceptance_manifest(
    path_value: str,
    label: str,
) -> tuple[Path, dict[str, Any]]:
    path = Path(path_value)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is unreadable or malformed: {path}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be a JSON object")
    return path, payload


def _acceptance_phase_manifest(
    path_value: str,
    label: str,
    *,
    format_name: str,
    phase: str,
    status: str,
    authority_field: str,
    failure_mode: str | None = None,
) -> tuple[Path, dict[str, Any]]:
    path, payload = _acceptance_manifest(path_value, label)
    if (
        payload.get("format") != format_name
        or payload.get("phase") != phase
        or payload.get("status") != status
        or payload.get(authority_field) is not False
        or payload.get("proof_authority") is True
        or payload.get("acceptance_authority") is True
        or payload.get("executes_original_binary") is True
        or payload.get("executes_candidate_binary") is True
        or (
            failure_mode is not None
            and payload.get("failure_mode") != failure_mode
        )
    ):
        raise ValueError(f"{label} is malformed or claims proof authority")
    return path, payload


def _acceptance_natural(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{label} must be a natural number")
    return value


def _acceptance_digest(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"[0-9a-f]{64}", value) is None
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _acceptance_string_list(value: object, label: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not all(isinstance(item, str) and item for item in value)
        or len(set(value)) != len(value)
    ):
        raise ValueError(f"{label} must be a duplicate-free array of strings")
    return value


def _acceptance_counts(
    payload: Mapping[str, Any],
    label: str,
) -> Mapping[str, Any]:
    counts = payload.get("counts")
    if not isinstance(counts, Mapping):
        raise ValueError(f"{label} counts are malformed")
    return counts


def _acceptance_candidate_input_digest(
    payload: Mapping[str, Any],
    label: str,
) -> str:
    inputs = payload.get("inputs")
    candidate = inputs.get("candidate") if isinstance(inputs, Mapping) else None
    if not isinstance(candidate, Mapping):
        raise ValueError(f"{label} candidate input is malformed")
    return _acceptance_digest(candidate.get("sha256"), f"{label} candidate")


def _acceptance_premise_blocker(
    *,
    manifest_path: Path,
    manifest: Mapping[str, Any],
    premise_field: str,
    premises: list[str],
) -> dict[str, Any] | None:
    if not premises:
        return None
    phase = str(manifest["phase"])
    return {
        "id": f"{phase.replace('-', '_')}_premises_remaining",
        "phase": phase,
        "source_manifest_sha256": sha256_file(manifest_path),
        "remaining_count": len(premises),
        premise_field: premises,
    }


def _acceptance_sources(args: argparse.Namespace) -> None:
    """Emit the fail-closed mixed-context acceptance interface for GNU hello."""

    out = Path(args.out)
    original_carrier_manifest_path = Path(args.original_carrier_manifest)
    original_carrier_manifest = json.loads(
        original_carrier_manifest_path.read_text(encoding="utf-8")
    )
    expected_carrier_binding = (
        f"{ORIGINAL_CARRIER_BINDING_NAMESPACE}."
        "generatedOriginalExactMixedProgramBinding"
    )
    if (
        original_carrier_manifest.get("phase")
        != "mixed-original-carrier-binding-lean"
        or original_carrier_manifest.get("status") != "source-ready"
        or original_carrier_manifest.get("proof_authority") is not False
        or original_carrier_manifest.get("targets")
        != [ORIGINAL_CARRIER_BINDING_MODULE]
        or original_carrier_manifest.get("exact_mixed_binding")
        != expected_carrier_binding
    ):
        raise ValueError("original carrier binding manifest is malformed")
    native_launch_request_path = Path(args.native_launch_request)
    native_launch_request = json.loads(
        native_launch_request_path.read_text(encoding="utf-8")
    )
    if (
        native_launch_request.get("format")
        != "stage-a-native-launch-route-request-v1"
        or native_launch_request.get("status") != "incomplete"
        or native_launch_request.get("acceptance_authority") is not False
    ):
        raise ValueError("native launch request is malformed or claims authority")
    (
        x87_kernel_execution_manifest_path,
        x87_kernel_execution_manifest,
    ) = _acceptance_phase_manifest(
        args.x87_kernel_execution_manifest,
        "x87 kernel execution manifest",
        format_name="stage-a-relational-phase-v1",
        phase="x87-kernel-execution-lean",
        status="source-ready",
        authority_field="proof_authority",
        failure_mode="none",
    )
    x87_remaining_premises = x87_kernel_execution_manifest.get(
        "remaining_proof_premises"
    )
    if (
        x87_kernel_execution_manifest.get("diagnostic_status")
        != "kernel_execution_closed"
        or x87_remaining_premises
        != list(X87_KERNEL_EXECUTION_REMAINING_PROOF_PREMISES)
        or x87_kernel_execution_manifest.get("targets")
        != [X87_KERNEL_EXECUTION_LEAN_MODULE]
    ):
        raise ValueError(
            "x87 kernel execution manifest is malformed or claims authority"
        )
    mixed_original_manifest_path = Path(args.mixed_original_manifest)
    mixed_original_manifest = json.loads(
        mixed_original_manifest_path.read_text(encoding="utf-8")
    )
    remaining_frontiers = mixed_original_manifest.get("remaining_frontiers")
    mixed_counts = mixed_original_manifest.get("counts")
    blocker_count = _acceptance_natural(
        mixed_counts.get("blockers") if isinstance(mixed_counts, Mapping) else None,
        "mixed-original blocker count",
    )
    authorizing_direct_call_terms = mixed_original_manifest.get(
        "authorizing_lean_terms"
    )
    if (
        mixed_original_manifest.get("phase") != "mixed-original-final-lean"
        or mixed_original_manifest.get("proof_authority") is not False
        or not isinstance(remaining_frontiers, list)
        or not all(isinstance(frontier, Mapping) for frontier in remaining_frontiers)
        or blocker_count != len(remaining_frontiers)
        or not isinstance(authorizing_direct_call_terms, list)
        or not all(
            isinstance(term, str) and term for term in authorizing_direct_call_terms
        )
    ):
        raise ValueError("mixed-original final manifest is malformed")
    (
        static_reachability_manifest_path,
        static_reachability_manifest,
    ) = _acceptance_phase_manifest(
        args.static_reachability_manifest,
        "static reachability manifest",
        format_name="stage-a-relational-phase-v1",
        phase="mixed-original-static-reachability",
        status="typed-interface-ready",
        authority_field="proof_authority",
        failure_mode="incomplete",
    )
    static_counts = _acceptance_counts(
        static_reachability_manifest, "static reachability manifest"
    )
    static_reachable_targets = _acceptance_natural(
        static_counts.get("reachable_targets"),
        "static reachability target count",
    )
    static_frontier_count = _acceptance_natural(
        static_counts.get("runtime_indirect_frontiers"),
        "static reachability runtime frontier count",
    )
    static_runtime_control = static_reachability_manifest.get(
        "runtime_indirect_control"
    )
    expected_runtime_status = (
        "satisfied" if static_frontier_count == 0 else "incomplete"
    )
    if (
        static_reachability_manifest.get("theorem")
        != INTERPRETER_MIXED_ORIGINAL_STATIC_REACHABILITY_THEOREM
        or static_reachability_manifest.get("targets")
        != [
            Path(
                INTERPRETER_MIXED_ORIGINAL_STATIC_REACHABILITY_LEAN_FILENAME
            ).stem
        ]
        or not isinstance(static_runtime_control, Mapping)
        or static_runtime_control.get("status") != expected_runtime_status
        or static_runtime_control.get("closed_by_this_artifact") is not False
        or static_runtime_control.get("required_at")
        != "mixed-component-composition"
        or static_frontier_count != blocker_count
    ):
        raise ValueError(
            "static reachability manifest is malformed or disagrees with "
            "mixed-original frontiers"
        )

    native_launch_graph_manifest_path, native_launch_graph_manifest = (
        _acceptance_phase_manifest(
            args.native_launch_graph_manifest,
            "native launch graph manifest",
            format_name="stage-a-gnu-hello-native-launch-graph-v1",
            phase="native-launch-graph",
            status="source-ready",
            authority_field="acceptance_authority",
            failure_mode="incomplete",
        )
    )
    native_launch_counts = _acceptance_counts(
        native_launch_graph_manifest, "native launch graph manifest"
    )
    native_canonical_roots = _acceptance_natural(
        native_launch_counts.get("canonical_roots"),
        "native launch canonical-root count",
    )
    for field in ("cutpoints", "routes", "decoded_nodes"):
        _acceptance_natural(
            native_launch_counts.get(field),
            f"native launch {field} count",
        )
    canonical_sources = native_launch_request.get("canonical_sources")
    if (
        not isinstance(canonical_sources, list)
        or not all(isinstance(source, Mapping) for source in canonical_sources)
        or native_canonical_roots != len(canonical_sources)
    ):
        raise ValueError(
            "native launch graph canonical roots disagree with the route request"
        )

    (
        universal_environment_manifest_path,
        universal_environment_manifest,
    ) = _acceptance_phase_manifest(
        args.universal_paired_external_environment_manifest,
        "universal paired external environment manifest",
        format_name="stage-a-relational-phase-v1",
        phase="universal-paired-external-environment",
        status="source-ready",
        authority_field="proof_authority",
    )
    universal_remaining_premises = _acceptance_string_list(
        universal_environment_manifest.get("remaining_premises"),
        "universal paired external environment remaining premises",
    )
    universal_counts = _acceptance_counts(
        universal_environment_manifest,
        "universal paired external environment manifest",
    )
    for field in (
        "required_imports",
        "machine_contracts",
        "candidate_pe_byte_packs",
    ):
        _acceptance_natural(
            universal_counts.get(field),
            f"universal paired external environment {field} count",
        )

    (
        constructive_source_coverage_manifest_path,
        constructive_source_coverage_manifest,
    ) = _acceptance_phase_manifest(
        args.constructive_source_coverage_manifest,
        "constructive source coverage manifest",
        format_name="stage-a-gnu-hello-constructive-source-coverage-v1",
        phase="constructive-source-coverage",
        status="source-ready",
        authority_field="acceptance_authority",
        failure_mode="incomplete",
    )
    constructive_remaining_premises = _acceptance_string_list(
        constructive_source_coverage_manifest.get("remaining_proof_premises"),
        "constructive source coverage remaining proof premises",
    )
    constructive_counts = _acceptance_counts(
        constructive_source_coverage_manifest,
        "constructive source coverage manifest",
    )
    constructive_records = _acceptance_natural(
        constructive_counts.get("candidate_records"),
        "constructive source coverage candidate-record count",
    )
    constructive_reachable_targets = _acceptance_natural(
        constructive_counts.get("reachable_targets"),
        "constructive source coverage reachable-target count",
    )
    constructive_candidate_sha256 = _acceptance_digest(
        constructive_source_coverage_manifest.get("candidate_sha256"),
        "constructive source coverage candidate",
    )
    constructive_state_machine_sha256 = _acceptance_digest(
        constructive_source_coverage_manifest.get("state_machine_sha256"),
        "constructive source coverage state machine",
    )
    if (
        constructive_records < constructive_reachable_targets
        or constructive_reachable_targets != static_reachable_targets
    ):
        raise ValueError(
            "constructive source coverage counts disagree with static reachability"
        )

    (
        canonical_relation_core_manifest_path,
        canonical_relation_core_manifest,
    ) = _acceptance_phase_manifest(
        args.canonical_relation_core_manifest,
        "canonical relation core manifest",
        format_name="stage-a-gnu-hello-canonical-relation-core-v1",
        phase="canonical-relation-core",
        status="source-ready",
        authority_field="acceptance_authority",
        failure_mode="incomplete",
    )
    canonical_core_inputs = canonical_relation_core_manifest.get("inputs")
    canonical_core_outputs = canonical_relation_core_manifest.get("outputs")
    if (
        not isinstance(canonical_core_inputs, Mapping)
        or not all(
            re.fullmatch(r"[0-9a-f]{64}", value) is not None
            for value in canonical_core_inputs.values()
            if isinstance(value, str)
        )
        or set(canonical_core_inputs)
        != {
            "mixed_original_plan",
            "static_reachability_plan",
            "kernel_data_inventory",
        }
        or not all(
            isinstance(value, str) for value in canonical_core_inputs.values()
        )
        or canonical_relation_core_manifest.get("candidate_sha256")
        != constructive_candidate_sha256
        or canonical_relation_core_manifest.get("state_machine_sha256")
        != constructive_state_machine_sha256
        or canonical_core_outputs
        != {
            "binding_module": (
                "StageA/GeneratedGnuHelloCanonicalRelationCoreBindings.lean"
            ),
            "core_module": "StageA/GeneratedGnuHelloCanonicalRelationCore.lean",
            "core_plan": "interpreter-mixed-relation-core-plan.json",
        }
    ):
        raise ValueError(
            "canonical relation core manifest is malformed or disagrees with "
            "constructive source coverage"
        )

    operation_specs = (
        (
            "kernel_program_lookup_operation_manifest",
            "kernel programLookup operation manifest",
            "compiled-kernel-program-lookup-operation",
            INTERPRETER_KERNEL_PROGRAM_LOOKUP_OPERATION_THEOREM,
        ),
        (
            "kernel_step_operation_manifest",
            "kernel interpreterStep operation manifest",
            "compiled-kernel-interpreter-step-operation",
            INTERPRETER_KERNEL_STEP_OPERATION_THEOREM,
        ),
        (
            "kernel_run_operation_manifest",
            "kernel runFunction operation manifest",
            "compiled-kernel-run-function-operation",
            INTERPRETER_KERNEL_RUN_OPERATION_THEOREM,
        ),
        (
            "kernel_invoke_operation_manifest",
            "kernel invokeCall operation manifest",
            "compiled-kernel-invoke-call-operation",
            INTERPRETER_KERNEL_INVOKE_OPERATION_THEOREM,
        ),
    )
    operation_manifests: list[
        tuple[str, Path, dict[str, Any], list[str]]
    ] = []
    for attribute, label, phase, theorem in operation_specs:
        manifest_path, manifest = _acceptance_phase_manifest(
            getattr(args, attribute),
            label,
            format_name="stage-a-relational-phase-v1",
            phase=phase,
            status="source-ready",
            authority_field="proof_authority",
            failure_mode="incomplete",
        )
        premises = _acceptance_string_list(
            manifest.get("remaining_proof_premises"),
            f"{label} remaining proof premises",
        )
        if manifest.get("theorem") != theorem:
            raise ValueError(f"{label} names an unexpected theorem")
        operation_manifests.append(
            (attribute, manifest_path, manifest, premises)
        )

    candidate_sha256 = _acceptance_digest(
        native_launch_request.get("candidate_sha256"),
        "native launch request candidate",
    )
    universal_inputs = universal_environment_manifest.get("inputs")
    candidate_digests = {
        "native launch graph": _acceptance_digest(
            native_launch_graph_manifest.get("candidate_sha256"),
            "native launch graph candidate",
        ),
        "universal paired external environment": _acceptance_digest(
            (
                universal_inputs.get("candidate_sha256")
                if isinstance(universal_inputs, Mapping)
                else None
            ),
            "universal paired external environment candidate",
        ),
        "constructive source coverage": constructive_candidate_sha256,
        "canonical relation core": _acceptance_digest(
            canonical_relation_core_manifest.get("candidate_sha256"),
            "canonical relation core candidate",
        ),
        "x87 kernel execution": _acceptance_digest(
            x87_kernel_execution_manifest.get("candidate_sha256"),
            "x87 kernel execution candidate",
        ),
        **{
            str(manifest["phase"]): _acceptance_candidate_input_digest(
                manifest, str(manifest["phase"])
            )
            for _role, _path, manifest, _premises in operation_manifests
        },
    }
    mismatched_candidates = sorted(
        label
        for label, digest in candidate_digests.items()
        if digest != candidate_sha256
    )
    if mismatched_candidates:
        raise ValueError(
            "acceptance phase manifests bind different candidate PEs: "
            + ", ".join(mismatched_candidates)
        )
    for field in ("required_path_shapes", "forbidden_authority"):
        _acceptance_string_list(
            native_launch_request.get(field),
            f"native launch request {field}",
        )
    x87_runtime_targets = _acceptance_natural(
        x87_kernel_execution_manifest.get("runtime_targets"),
        "x87 kernel execution runtime-target count",
    )

    semantic_blockers: list[dict[str, Any]] = []
    if static_frontier_count:
        semantic_blockers.append(
            {
                "id": (
                    f"{static_reachability_manifest['phase'].replace('-', '_')}"
                    "_runtime_frontiers_remaining"
                ),
                "phase": static_reachability_manifest["phase"],
                "source_manifest_sha256": sha256_file(
                    static_reachability_manifest_path
                ),
                "remaining_count": static_frontier_count,
                "remaining_frontiers": remaining_frontiers,
            }
        )
    premise_sources = [
        (
            universal_environment_manifest_path,
            universal_environment_manifest,
            "remaining_premises",
            universal_remaining_premises,
        ),
        (
            constructive_source_coverage_manifest_path,
            constructive_source_coverage_manifest,
            "remaining_proof_premises",
            constructive_remaining_premises,
        ),
        *[
            (
                manifest_path,
                manifest,
                "remaining_proof_premises",
                premises,
            )
            for _role, manifest_path, manifest, premises in operation_manifests
        ],
        (
            x87_kernel_execution_manifest_path,
            x87_kernel_execution_manifest,
            "remaining_proof_premises",
            x87_remaining_premises,
        ),
    ]
    for manifest_path, manifest, premise_field, premises in premise_sources:
        blocker = _acceptance_premise_blocker(
            manifest_path=manifest_path,
            manifest=manifest,
            premise_field=premise_field,
            premises=premises,
        )
        if blocker is not None:
            semantic_blockers.append(blocker)

    remaining_by_phase = {
        str(static_reachability_manifest["phase"]): static_frontier_count,
        str(universal_environment_manifest["phase"]): len(
            universal_remaining_premises
        ),
        str(constructive_source_coverage_manifest["phase"]): len(
            constructive_remaining_premises
        ),
        **{
            str(manifest["phase"]): len(premises)
            for _role, _path, manifest, premises in operation_manifests
        },
        str(x87_kernel_execution_manifest["phase"]): len(
            x87_remaining_premises
        ),
    }
    validated_phase_manifests = [
        {
            "role": role,
            "phase": manifest["phase"],
            "sha256": sha256_file(path),
            "reported_remaining_count": reported_remaining_count,
        }
        for role, path, manifest, reported_remaining_count in (
            (
                "static_reachability",
                static_reachability_manifest_path,
                static_reachability_manifest,
                static_frontier_count,
            ),
            (
                "native_launch_graph",
                native_launch_graph_manifest_path,
                native_launch_graph_manifest,
                None,
            ),
            (
                "universal_paired_external_environment",
                universal_environment_manifest_path,
                universal_environment_manifest,
                len(universal_remaining_premises),
            ),
            (
                "constructive_source_coverage",
                constructive_source_coverage_manifest_path,
                constructive_source_coverage_manifest,
                len(constructive_remaining_premises),
            ),
            (
                "canonical_relation_core",
                canonical_relation_core_manifest_path,
                canonical_relation_core_manifest,
                None,
            ),
            *[
                (
                    role.removesuffix("_manifest"),
                    path,
                    manifest,
                    len(premises),
                )
                for role, path, manifest, premises in operation_manifests
            ],
            (
                "x87_kernel_execution",
                x87_kernel_execution_manifest_path,
                x87_kernel_execution_manifest,
                len(x87_remaining_premises),
            ),
        )
    ]

    block_manifest = json.loads(
        Path(args.kernel_block_manifest).read_text(encoding="utf-8")
    )
    block_targets = sorted(
        target
        for target in block_manifest.get("targets", [])
        if isinstance(target, str)
    )
    stage_a = out / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    requirements_module = "GeneratedGnuHelloRoundTripRequirements"
    requirements_namespace = "StageA.GeneratedGnuHelloRoundTripRequirements"
    core_type = "MixedKernelBindingRequirements"
    exact_imports = [
        "StageA.GeneratedRelationalInterpreterMixedOriginal",
        "StageA.GeneratedRelationalInterpreterOriginalCarrierBinding",
        "StageA.GeneratedCallableExternalProgram",
        "StageA.GeneratedRelationalInterpreterMixedAuthority",
        "StageA.GeneratedRelationalInterpreterKernelABI",
        "StageA.GeneratedRelationalInterpreterNativeLaunchGraph",
        "StageA.RelationalCallableExternalMixedBridge",
        "StageA.RelationalInterpreterNativeLaunch",
    ]
    requirements_source = "\n".join(
        f"import {module}" for module in exact_imports
    )
    requirements_source += "\n" + (
        relational_interpreter_mixed_kernel_requirements_source(
            requirements_namespace, core_type
        )
    )
    requirements_source += f"""

namespace {requirements_namespace}

  open StageA.Relational
  open StageA.Relational.CallableExternalExecution
  open StageA.Relational.CallableExternalMixedBridge
  open StageA.Relational.Interpreter
  open StageA.Relational.InterpreterMixedWorldBridge
  open StageA.Relational.InterpreterNativeLaunch
  open StageA.Relational.InterpreterNativeWorld

  namespace Original := StageA.GeneratedRelational.InterpreterMixedOriginal
  namespace OriginalCarrier := StageA.GeneratedRelational.InterpreterOriginalCarrierBinding
  namespace Callable := StageA.GeneratedRelational.CallableExternalProgram
  namespace Candidate := StageA.GeneratedRelational.InterpreterMixedAuthority
  namespace KernelABI := StageA.GeneratedRelational.InterpreterKernelABI
  namespace NativeLaunchGraph :=
    StageA.GeneratedRelational.InterpreterNativeLaunchGraph

/- The generic mixed-kernel interface is wrapped with exact artifact pins.
The equalities have no status interpretation: constructing this value requires
Lean terms tying both operational carriers to the PE bytes parsed by the
independent original and candidate authority modules.  The concrete environment
fields pin carrier templates only; `core.launch_wrapper_refinements`,
and `core.environment_compositions` retain the whole-program quantification
over every exactly refining environment pair. -/
structure GnuHelloRoundTripRequiredTerms where
  core : {core_type}
  originalEnvironment : WorldExternalEnvironment
  originalProtocolEnvironment : WorldExternalProtocolEnvironment
  originalExternalCallSites : List ExternalCallSiteContract
  originalCallableEnvironment : OriginalCallableExternalEnvironment
  candidateEnvironment : NativeWorldEnvironment
  originalContextExact :
    core.original_context = Original.generatedOriginalStaticContext
  originalAuthorityExact : HEq core.original_authority
    Original.generatedExactOriginalDecodedAuthority
  originalProgramExact : core.original_program =
    decodedWorldProgramWithCallable
      (Original.generatedOriginalDecodedProgram originalEnvironment
        originalProtocolEnvironment originalExternalCallSites)
      Callable.originalCallableProgram originalCallableEnvironment
  originalProgramBindingExact : HEq core.program_binding
    ((OriginalCarrier.generatedOriginalExactMixedProgramBinding
      originalEnvironment originalProtocolEnvironment originalExternalCallSites
      ).withCallable Callable.originalCallableProgram
        originalCallableEnvironment)
  candidateProgramExact : core.candidate_program =
    Candidate.generatedCandidateNativeWorldProgram candidateEnvironment
  candidateAuthorityExact : HEq core.candidate_authority
    (Candidate.generatedExactNativeCandidateAuthority candidateEnvironment)
  kernelABIExact : HEq core.concrete_abi
    KernelABI.generatedConcreteInterpreterKernelABI
  candidateNativeLaunchRouteBinding :
    forall originalEnvironment candidateEnvironment
      (environmentRefines :
        ExactOneToOneMixedExternalEnvironmentsRefine
          (decodedWorldProgramWithProtocolEnvironment core.original_program
            originalEnvironment)
          (exactNativeWorldProgramWithEnvironment core.candidate_program
            candidateEnvironment)
          core.relation_core.contract core.external_frames),
      ExactCanonicalMixedLaunchWrapperRefinementBinding
        NativeLaunchGraph.generatedCheckedNativeLaunchGraph
        core.original_context
        (exactNativeWorldProgramWithEnvironment core.candidate_program
          candidateEnvironment)
        core.relation_core.contract core.launch
        (core.launch_wrapper_refinements originalEnvironment candidateEnvironment
          environmentRefines)

def GnuHelloRoundTripRequiredTerms.originalCallableBinding
    (requirements : GnuHelloRoundTripRequiredTerms) :
    ExactDecodedOriginalCallableProgramBinding
      requirements.core.original_program Callable.originalCallableProgram
      requirements.originalCallableEnvironment := by
  rw [requirements.originalProgramExact]
  exact ExactDecodedOriginalCallableProgramBinding.ofWithCallable
    (Original.generatedOriginalDecodedProgram requirements.originalEnvironment
      requirements.originalProtocolEnvironment
      requirements.originalExternalCallSites)
    Callable.originalCallableProgram requirements.originalCallableEnvironment
    rfl rfl Callable.originalCallableProgramValid

end {requirements_namespace}
"""
    (stage_a / f"{requirements_module}.lean").write_text(
        requirements_source, encoding="utf-8"
    )

    terms = {
        requirement.key: f"requirements.core.{requirement.key}"
        for requirement in REQUIRED_INHABITANTS
    }
    binding_plan = plan_interpreter_mixed_kernel_binding(
        InterpreterMixedKernelBindingSpec(
            binding_module=f"StageA.{requirements_module}",
            namespace="StageA.GeneratedGnuHelloRoundTripAcceptance",
            terms=terms,
            requirement_parameter="requirements",
            requirement_type=(
                f"{requirements_namespace}.GnuHelloRoundTripRequiredTerms"
            ),
        )
    )
    if not binding_plan.complete:
        raise ValueError("canonical GNU mixed-kernel binding plan is incomplete")
    generated = write_relational_interpreter_mixed_kernel_binding(
        out, binding_plan
    )
    acceptance_module = next(
        path.stem for path in generated if path.suffix == ".lean"
    )
    write_json(
        out / "acceptance-obligations.json",
        {
            "format": "stage-a-mixed-kernel-acceptance-obligations-v2",
            "closed_acceptance": False,
            "report_authority": False,
            "required_parameter": {
                "name": "requirements",
                "lean_type": (
                    f"{requirements_namespace}.GnuHelloRoundTripRequiredTerms"
                ),
            },
            "conditional_theorem": (
                "StageA.GeneratedGnuHelloRoundTripAcceptance."
                "generatedMixedWorldProgramsEquivalent"
            ),
            "remaining_original_control_frontiers": remaining_frontiers,
            "authority_integration_matrix": [
                {
                    "layer": "nullable_code_pointer_table_and_dispatch",
                    "final_authority_state": "blocked",
                    "named_lean_terms_consumed": [],
                    "blocker_policy": (
                        "retain nullable table/dispatch frontiers until exact "
                        "authority terms participate in decoded reachability"
                    ),
                },
                {
                    "layer": "stack_fixed_code_pointer",
                    "final_authority_state": "blocked",
                    "named_lean_terms_consumed": [],
                    "blocker_policy": (
                        "retain stack and dynamic pointer frontiers until exact "
                        "runtime membership authority is imported"
                    ),
                },
                {
                    "layer": "reachable_static_pointer_slot",
                    "final_authority_state": "blocked",
                    "named_lean_terms_consumed": [],
                    "normalized_internal_writes_only": True,
                    "missing_semantic_bridges": [
                        "checked external-call memory-footprint preservation",
                        "checked call-frame argument provenance",
                    ],
                },
                {
                    "layer": "callable_external_and_callback_capability",
                    "final_authority_state": "blocked",
                    "named_lean_terms_consumed": [],
                    "blocker_policy": (
                        "retain external and callback control frontiers until "
                        "exact capability terms are imported"
                    ),
                },
                {
                    "layer": "direct_call_register_provenance",
                    "final_authority_state": (
                        "term-gated" if authorizing_direct_call_terms else "blocked"
                    ),
                    "named_lean_terms_consumed": authorizing_direct_call_terms,
                    "authority_type": (
                        "CheckedDirectCallRegisterControlContract "
                        "generatedOriginalCarrierContext"
                    ),
                },
                {
                    "layer": "generated_kernel_abi",
                    "final_authority_state": "pinned",
                    "named_lean_terms_consumed": [
                        "KernelABI.generatedInterpreterKernelABIRelation"
                    ],
                },
                {
                    "layer": "x87_replay_kernel_execution",
                    "final_authority_state": "blocked",
                    "generated_interface": (
                        x87_kernel_execution_manifest["theorem"]
                    ),
                    "named_lean_terms_consumed": [],
                    "remaining_proof_premises": x87_remaining_premises,
                    "blocker_policy": (
                        "require exact candidate run equations and a checked "
                        "nested-frame effect for every admitted replay state"
                    ),
                },
                {
                    "layer": "exact_candidate_native_launch_wrappers",
                    "final_authority_state": "blocked",
                    "named_lean_terms_consumed": [],
                },
                {
                    "layer": "universal_paired_external_environment",
                    "final_authority_state": "blocked",
                    "named_lean_terms_consumed": [],
                },
            ],
            "validated_phase_manifests": validated_phase_manifests,
            "blocking_obligations": semantic_blockers,
        },
    )
    audit_module = "GeneratedGnuHelloRoundTripFinalAudit"
    audit_imports = [
        f"StageA.{acceptance_module}",
        "StageA.RelationalSymbolicSoundness",
        *[f"StageA.{module}" for module in block_targets],
    ]
    theorem = (
        "StageA.GeneratedGnuHelloRoundTripAcceptance."
        "generatedMixedWorldProgramsEquivalent"
    )
    audit_source = "\n".join(f"import {module}" for module in audit_imports)
    audit_source += f"""

namespace StageA.GeneratedGnuHelloRoundTripFinalAudit

#check {theorem}
#print axioms {theorem}

end StageA.GeneratedGnuHelloRoundTripFinalAudit
"""
    (stage_a / f"{audit_module}.lean").write_text(
        audit_source, encoding="utf-8"
    )
    _manifest(
        out,
        "whole-program-acceptance-lean",
        {
            "kernel_block_manifest": Path(args.kernel_block_manifest),
            "mixed_original_manifest": mixed_original_manifest_path,
            "original_carrier_manifest": original_carrier_manifest_path,
            "native_launch_request": native_launch_request_path,
            "static_reachability_manifest": static_reachability_manifest_path,
            "native_launch_graph_manifest": native_launch_graph_manifest_path,
            "universal_paired_external_environment_manifest": (
                universal_environment_manifest_path
            ),
            "constructive_source_coverage_manifest": (
                constructive_source_coverage_manifest_path
            ),
            "canonical_relation_core_manifest": (
                canonical_relation_core_manifest_path
            ),
            **{
                role: path
                for role, path, _manifest_payload, _premises in operation_manifests
            },
            "x87_kernel_execution_manifest": (
                x87_kernel_execution_manifest_path
            ),
        },
        status="proof-obligations-generated",
        diagnostic_status="incomplete",
        modules=[
            requirements_module,
            acceptance_module,
            audit_module,
        ],
        targets=[audit_module],
        acceptance_theorem=None,
        conditional_acceptance_theorem=theorem,
        acceptance_blocker={
            "id": "gnu_hello_round_trip_required_terms_uninhabited",
            "lean_type": (
                f"{requirements_namespace}.GnuHelloRoundTripRequiredTerms"
            ),
            "message": (
                "final acceptance requires a checked inhabitant of the exact "
                "mixed-context GNU hello binding type"
            ),
        },
        validated_phase_manifests=validated_phase_manifests,
        semantic_blockers=semantic_blockers,
        counts={
            "remaining_original_control_frontiers": blocker_count,
            "remaining_x87_kernel_execution_premises": len(
                x87_remaining_premises
            ),
            "x87_runtime_targets": x87_runtime_targets,
            "diagnostic_blockers": len(semantic_blockers),
            "remaining_diagnostic_items": sum(remaining_by_phase.values()),
            "remaining_diagnostic_items_by_phase": remaining_by_phase,
        },
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    command = sub.add_parser("smoke")
    command.add_argument("--original", required=True)
    command.add_argument("--linker-map", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_smoke)

    command = sub.add_parser("native-launch-request")
    command.add_argument("--candidate", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_native_launch_request)

    command = sub.add_parser("static-export")
    command.add_argument("--original", required=True)
    command.add_argument("--linker-map", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_static_export)

    command = sub.add_parser("original-pe-source")
    command.add_argument("--original", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_original_pe_source)

    command = sub.add_parser("program-source")
    command.add_argument("--state-machine", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_program_source)

    command = sub.add_parser("native-source-program")
    command.add_argument("--out", required=True)
    command.set_defaults(run=_native_source_program)

    command = sub.add_parser("native-source-compiled-authority")
    command.add_argument("--source-bundle", required=True)
    command.add_argument("--compilation-attestation", required=True)
    command.add_argument("--declarations", required=True)
    command.add_argument("--project-nix-provenance", required=True)
    command.add_argument("--profile-nix-provenance", required=True)
    command.add_argument("--build-nix-provenance", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_native_source_compiled_authority)

    command = sub.add_parser("native-source-execution")
    command.add_argument("--mixed-original-plan", required=True)
    command.add_argument("--writable-authority-report", required=True)
    command.add_argument("--register-authority-report", required=True)
    command.add_argument("--stack-dynamic-authority-report", required=True)
    command.add_argument("--evidence-manifest", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_native_source_execution)

    command = sub.add_parser("native-source-acceptance")
    command.add_argument("--source-bundle", required=True)
    command.add_argument("--compilation-attestation", required=True)
    command.add_argument("--compiled-authority-manifest", required=True)
    command.add_argument("--declarations", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_native_source_acceptance)

    command = sub.add_parser("native-source-nested-compiler-premise")
    command.add_argument("--response-family-module", required=True)
    command.add_argument("--premise-type", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_native_source_nested_compiler_premise)

    command = sub.add_parser("native-source-nested-acceptance")
    command.add_argument("--import", dest="imports", action="append", required=True)
    command.add_argument("--context", required=True)
    command.add_argument("--classified-sites", required=True)
    command.add_argument("--ordinary-sites", required=True)
    command.add_argument("--static-compilation", required=True)
    command.add_argument("--mixed-contract", required=True)
    command.add_argument("--nested-frames", required=True)
    command.add_argument("--checked-response-family", required=True)
    command.add_argument("--checked-response-family-completion", required=True)
    command.add_argument("--toolchain-correct", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_native_source_nested_acceptance)

    command = sub.add_parser("source-transition-index")
    command.add_argument("--mixed-original-manifest", required=True)
    command.add_argument("--source-program-manifest", required=True)
    command.add_argument("--normalization-manifest", required=True)
    command.add_argument("--x87-manifest", required=True)
    command.add_argument("--declaration-inventory", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_source_transition_index)

    command = sub.add_parser("source-target-effect-inputs")
    command.add_argument("--state-machine", required=True)
    command.add_argument("--mixed-original-plan", required=True)
    command.add_argument("--source-program-root", required=True)
    command.add_argument("--source-program-manifest", required=True)
    command.add_argument("--normalization-root", required=True)
    command.add_argument("--normalization-inventory", required=True)
    command.add_argument("--semantic-refinement-root", required=True)
    command.add_argument("--semantic-refinement-inventory", required=True)
    command.add_argument("--x87-root", required=True)
    command.add_argument("--x87-inventory", required=True)
    command.add_argument("--exact-original-root", required=True)
    command.add_argument("--shard-span", type=int, default=64)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_source_target_effect_inputs)

    command = sub.add_parser("source-target-effects")
    command.add_argument("--state-machine", required=True)
    command.add_argument("--mixed-original-plan", required=True)
    command.add_argument("--source-program-root", required=True)
    command.add_argument("--source-program-manifest", required=True)
    command.add_argument("--normalization-root", required=True)
    command.add_argument("--normalization-inventory", required=True)
    command.add_argument("--semantic-refinement-root", required=True)
    command.add_argument("--semantic-refinement-inventory", required=True)
    command.add_argument("--x87-root", required=True)
    command.add_argument("--x87-inventory", required=True)
    command.add_argument("--exact-original-root", required=True)
    command.add_argument("--authority-inventory", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_source_target_effects)

    command = sub.add_parser("original-combined-declarations")
    command.add_argument("--mixed-original-plan", required=True)
    command.add_argument("--mixed-original-manifest", required=True)
    command.add_argument("--static-reachability-plan", required=True)
    command.add_argument("--static-reachability-manifest", required=True)
    command.add_argument("--carrier-binding-manifest", required=True)
    command.add_argument("--direct-call-authority-report", required=True)
    command.add_argument("--stack-dynamic-authority-report", required=True)
    command.add_argument("--stack-dynamic-authority-manifest", required=True)
    command.add_argument("--stack-combined-evidence-report", required=True)
    command.add_argument("--value-provenance-ir", required=True)
    command.add_argument("--value-provenance-report", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_original_combined_declarations)

    command = sub.add_parser("original-combined-inventory")
    command.add_argument("--mixed-original-plan", required=True)
    command.add_argument("--writable-authority-report", required=True)
    command.add_argument("--writable-authority-manifest", required=True)
    command.add_argument("--register-authority-report", required=True)
    command.add_argument("--register-authority-manifest", required=True)
    command.add_argument("--stack-dynamic-authority-report", required=True)
    command.add_argument("--stack-dynamic-authority-manifest", required=True)
    command.add_argument("--stack-combined-evidence-report", required=True)
    command.add_argument("--reachability-declarations", required=True)
    command.add_argument("--call-frame-declarations", required=True)
    command.add_argument("--value-flow-declarations", required=True)
    command.add_argument("--shard-size", type=int, default=512)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_original_combined_inventory)

    command = sub.add_parser("original-execution-evidence")
    command.add_argument("--combined-inventory-manifest", required=True)
    command.add_argument("--source-target-effect-declarations", required=True)
    command.add_argument("--transition-index-manifest", required=True)
    command.add_argument("--preservation-inputs", required=True)
    command.add_argument("--mixed-original-plan", required=True)
    command.add_argument("--writable-authority-report", required=True)
    command.add_argument("--register-authority-report", required=True)
    command.add_argument("--stack-dynamic-authority-report", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_original_execution_evidence)

    command = sub.add_parser("runtime-memory-access-proposal")
    command.add_argument("--state-machine", required=True)
    command.add_argument("--mixed-original-plan", required=True)
    command.add_argument("--source-target-effect-declarations", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_runtime_memory_access_proposal)

    command = sub.add_parser("original-target-control-evidence")
    command.add_argument("--source-target-effect-declarations", required=True)
    command.add_argument("--transition-index-manifest", required=True)
    command.add_argument("--state-machine", required=True)
    command.add_argument("--combined-target-inventory", required=True)
    command.add_argument("--shard-size", type=int, default=64)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_original_target_control_evidence)

    command = sub.add_parser("original-target-preservation")
    command.add_argument("--state-machine", required=True)
    command.add_argument("--source-target-effect-declarations", required=True)
    command.add_argument("--transition-index-manifest", required=True)
    command.add_argument("--combined-inventory-manifest", required=True)
    command.add_argument("--authority", action="append", default=[])
    command.add_argument("--shard-size", type=int, default=64)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_original_target_preservation)

    command = sub.add_parser("original-source-launch-context")
    command.add_argument("--combined-inventory-manifest", required=True)
    command.add_argument("--transition-index-manifest", required=True)
    command.add_argument("--compiled-authority-declarations", required=True)
    command.add_argument("--runtime-foundation-manifest", required=True)
    command.add_argument("--target-step-manifest", required=True)
    command.add_argument("--protocol-responses-declarations", required=True)
    command.add_argument("--preservation-input", action="append", default=[])
    command.add_argument("--out", required=True)
    command.set_defaults(run=_original_source_launch_context)

    command = sub.add_parser("checked-response-family")
    command.add_argument("--input-manifest", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_checked_response_family)

    command = sub.add_parser("source-equivalence-final-report")
    command.add_argument("--checked-acceptance", required=True)
    command.add_argument("--detached-axiom-audit", required=True)
    command.add_argument("--source-bundle", required=True)
    command.add_argument("--compilation-attestation", required=True)
    command.add_argument("--candidate-pe-metadata", required=True)
    command.add_argument("--functional-report", required=True)
    command.add_argument("--approved-toolchain-axiom", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_source_equivalence_final_report)

    command = sub.add_parser("native-source-compiled-authority-evidence")
    command.add_argument("--source-bundle", required=True)
    command.add_argument("--compilation-attestation", required=True)
    command.add_argument("--project-declarations", required=True)
    command.add_argument("--candidate-static-authority", required=True)
    command.add_argument("--runtime-declarations", required=True)
    command.add_argument("--project-realization", required=True)
    command.add_argument("--profile-realization", required=True)
    command.add_argument("--build-realization", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_native_source_compiled_authority_evidence)

    command = sub.add_parser("native-source-environment-family-inputs")
    command.add_argument("--source-execution-manifest", required=True)
    command.add_argument("--compiled-authority-manifest", required=True)
    command.add_argument("--source-bundle-manifest", required=True)
    command.add_argument("--candidate-runtime-declarations", required=True)
    command.add_argument("--candidate-static-authority", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_native_source_environment_family_inputs)

    command = sub.add_parser("native-source-environment-family")
    command.add_argument("--compiled-authority-manifest", required=True)
    command.add_argument("--source-execution-manifest", required=True)
    command.add_argument("--source-bundle-manifest", required=True)
    command.add_argument("--environment-inputs", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_native_source_environment_family)

    for name, runner in (
        ("normalization-sources", _normalization_sources),
        ("semantic-refinement-sources", _semantic_refinement_sources),
        ("kernel-block", _kernel_block),
        ("kernel-data", _kernel_data),
    ):
        command = sub.add_parser(name)
        command.add_argument("--out", required=True)
        command.add_argument("--shard-size", type=int, default=48)
        command.set_defaults(run=runner)
        if name in {"normalization-sources", "semantic-refinement-sources"}:
            command.add_argument("--state-machine", required=True)
            if name == "normalization-sources":
                command.add_argument(
                    "--source-bindings-only", action="store_true"
                )
        elif name == "kernel-block":
            command.add_argument("--candidate", required=True)
            command.add_argument("--kernel-plan", required=True)
        else:
            command.add_argument("--candidate", required=True)
            command.add_argument("--linker-map", required=True)
            command.add_argument("--state-machine", required=True)
            command.add_argument("--lean-source-root", required=True)

    command = sub.add_parser("x87-sources")
    command.add_argument("--state-machine", required=True)
    command.add_argument("--original", required=True)
    command.add_argument("--pe-byte-pack-inventory", required=True)
    command.add_argument("--source-only", action="store_true")
    command.add_argument("--out", required=True)
    command.set_defaults(run=_x87_sources)

    command = sub.add_parser("x87-candidate-replay-sources")
    command.add_argument("--state-machine", required=True)
    command.add_argument("--kernel-data-inventory", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_x87_candidate_replay_sources)

    command = sub.add_parser("x87-replay-bridge-target-sources")
    command.add_argument("--candidate", required=True)
    command.add_argument("--build-manifest", required=True)
    command.add_argument("--native-engine-plan", required=True)
    command.add_argument("--call-site-rva", type=lambda value: int(value, 0))
    command.add_argument(
        "--candidate-data-module",
        default="GeneratedInterpreterKernelDataBase",
    )
    command.add_argument("--pack-size", type=int, default=32)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_x87_replay_bridge_target_sources)

    command = sub.add_parser("x87-replay-bridge-runtime-sources")
    command.add_argument("--candidate", required=True)
    command.add_argument("--target-plan", required=True)
    command.add_argument("--native-engine-plan", required=True)
    command.add_argument(
        "--target-module",
        default="GeneratedRelationalInterpreterX87ReplayBridgeTarget",
    )
    command.add_argument("--pack-size", type=int, default=32)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_x87_replay_bridge_runtime_sources)

    command = sub.add_parser("x87-kernel-execution-sources")
    command.add_argument("--runtime-plan", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_x87_kernel_execution_sources)

    command = sub.add_parser("definedness-source")
    command.add_argument("--state-machine", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_definedness_source)

    command = sub.add_parser("kernel")
    command.add_argument("--candidate", required=True)
    command.add_argument("--linker-map", required=True)
    command.add_argument("--program-manifest", required=True)
    command.add_argument("--engine-layout", required=True)
    command.add_argument("--native-build-manifest", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_kernel)

    command = sub.add_parser("kernel-loop")
    command.add_argument("--kernel-plan", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_kernel_loop)

    command = sub.add_parser("kernel-abi")
    command.add_argument("--kernel-plan", required=True)
    command.add_argument("--kernel-data-inventory", required=True)
    command.add_argument("--engine-layout", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_kernel_abi)

    command = sub.add_parser("static-machine-import-contracts")
    command.add_argument("--original", required=True)
    command.add_argument("--reference-contract", required=True)
    command.add_argument("--state-machine", required=True)
    command.add_argument("--load-image-contract", required=True)
    command.add_argument("--profile", action="append", required=True)
    command.add_argument("--shard-size", type=int, default=128)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_static_machine_import_contracts)

    command = sub.add_parser("mixed-original")
    command.add_argument("--original", required=True)
    command.add_argument("--reference-contract", required=True)
    command.add_argument("--state-machine", required=True)
    command.add_argument("--load-image-contract", required=True)
    command.add_argument("--machine-import-report", required=True)
    command.add_argument("--callable-resolver-profile")
    command.add_argument("--shard-size", type=int, default=128)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_mixed_original)

    for name, runner in (
        ("mixed-original-base", _mixed_original_base),
        (
            "mixed-original-writable-slot-authority",
            _mixed_original_writable_slot_authority,
        ),
        (
            "mixed-original-register-indirect-authority",
            _mixed_original_register_indirect_authority,
        ),
        (
            "mixed-original-direct-call-proposals",
            _mixed_original_direct_call_proposals,
        ),
        ("mixed-original-final", _mixed_original_final),
    ):
        command = sub.add_parser(name)
        command.add_argument("--original", required=True)
        command.add_argument("--reference-contract", required=True)
        command.add_argument("--state-machine", required=True)
        command.add_argument("--load-image-contract", required=True)
        command.add_argument("--machine-import-report", required=True)
        command.add_argument("--callable-resolver-profile")
        command.add_argument("--shard-size", type=int, default=128)
        command.add_argument("--out", required=True)
        if name == "mixed-original-writable-slot-authority":
            command.add_argument("--base-plan", required=True)
        if name == "mixed-original-register-indirect-authority":
            command.add_argument("--base-plan", required=True)
            command.add_argument(
                "--writable-slot-authority-report", required=True
            )
        if name == "mixed-original-final":
            command.add_argument("--direct-call-authority-report", required=True)
            command.add_argument(
                "--stack-dynamic-authority-report", required=True
            )
        if name in {
            "mixed-original-direct-call-proposals",
            "mixed-original-final",
        }:
            command.add_argument("--base-plan", required=True)
            command.add_argument(
                "--writable-slot-authority-report", required=True
            )
        if name == "mixed-original-direct-call-proposals":
            command.add_argument(
                "--register-indirect-authority-report", required=True
            )
            command.add_argument("--proposal-ir", required=True)
            command.add_argument(
                "--prior-direct-call-authority-report"
            )
            command.add_argument("--runtime-value-carry-hints")
            command.add_argument("--checked-stack-entry-authority")
        command.set_defaults(run=runner)

    command = sub.add_parser("mixed-original-direct-call-semantics")
    command.add_argument("--original", required=True)
    command.add_argument("--state-machine", required=True)
    command.add_argument("--proposal-report", required=True)
    command.add_argument("--semantic-input")
    command.add_argument("--out", required=True)
    command.set_defaults(run=_mixed_original_direct_call_semantics)

    command = sub.add_parser("mixed-original-carrier-binding")
    command.add_argument("--mixed-original", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_mixed_original_carrier_binding)

    command = sub.add_parser("mixed-original-static-reachability")
    command.add_argument("--mixed-original-plan", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_mixed_original_static_reachability)

    command = sub.add_parser("kernel-callback")
    command.add_argument("--candidate", required=True)
    command.add_argument("--kernel-plan", required=True)
    command.add_argument("--linker-map", required=True)
    command.add_argument("--native-engine-plan", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_kernel_callback)

    command = sub.add_parser("kernel-lookup")
    command.add_argument("--kernel-plan", required=True)
    command.add_argument("--kernel-data-inventory", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_kernel_lookup)

    command = sub.add_parser("kernel-lookup-native")
    command.add_argument("--candidate", required=True)
    command.add_argument("--kernel-plan", required=True)
    command.add_argument("--kernel-data-inventory", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_kernel_lookup_native)

    command = sub.add_parser("kernel-lookup-operation")
    command.add_argument("--candidate", required=True)
    command.add_argument("--kernel-plan", required=True)
    command.add_argument("--kernel-data-inventory", required=True)
    command.add_argument("--lookup-native-plan", required=True)
    command.add_argument("--abi-plan", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_kernel_lookup_operation)

    command = sub.add_parser("kernel-step")
    command.add_argument("--kernel-plan", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_kernel_step)

    command = sub.add_parser("kernel-step-native")
    command.add_argument("--candidate", required=True)
    command.add_argument("--kernel-plan", required=True)
    command.add_argument("--callback-plan", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_kernel_step_native)

    command = sub.add_parser("kernel-step-operation")
    command.add_argument("--candidate", required=True)
    command.add_argument("--kernel-plan", required=True)
    command.add_argument("--kernel-data-inventory", required=True)
    command.add_argument("--abi-plan", required=True)
    command.add_argument("--step-native-plan", required=True)
    command.add_argument("--callback-plan", required=True)
    command.add_argument("--lookup-native-plan", required=True)
    command.add_argument("--lookup-operation-plan", required=True)
    command.add_argument("--invoke-native-plan", required=True)
    command.add_argument("--x87-replay-plan", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_kernel_step_operation)

    command = sub.add_parser("kernel-step-program-lookup-call")
    command.add_argument("--candidate", required=True)
    command.add_argument("--kernel-plan", required=True)
    command.add_argument("--kernel-data-inventory", required=True)
    command.add_argument("--abi-plan", required=True)
    command.add_argument("--step-native-plan", required=True)
    command.add_argument("--callback-plan", required=True)
    command.add_argument("--lookup-native-plan", required=True)
    command.add_argument("--lookup-operation-plan", required=True)
    command.add_argument("--invoke-native-plan", required=True)
    command.add_argument("--x87-replay-plan", required=True)
    command.add_argument("--step-operation-plan", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_kernel_step_program_lookup_call)

    command = sub.add_parser("kernel-step-program-lookup-call-closure")
    command.add_argument("--candidate", required=True)
    command.add_argument("--program-lookup-call-plan", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_kernel_step_program_lookup_call_closure)

    command = sub.add_parser("kernel-operation-frame-parametric")
    command.add_argument("--candidate", required=True)
    command.add_argument("--step-operation-plan", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_kernel_operation_frame_parametric)

    command = sub.add_parser("kernel-frame-executor")
    command.add_argument("--candidate", required=True)
    command.add_argument("--frame-parametric-plan", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_kernel_frame_executor)

    command = sub.add_parser("kernel-run")
    command.add_argument("--candidate", required=True)
    command.add_argument("--kernel-plan", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_kernel_run)

    command = sub.add_parser("kernel-run-native")
    command.add_argument("--candidate", required=True)
    command.add_argument("--kernel-plan", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_kernel_run_native)

    command = sub.add_parser("kernel-run-operation")
    command.add_argument("--candidate", required=True)
    command.add_argument("--kernel-plan", required=True)
    command.add_argument("--kernel-data-inventory", required=True)
    command.add_argument("--abi-plan", required=True)
    command.add_argument("--run-native-plan", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_kernel_run_operation)

    command = sub.add_parser("kernel-cdecl-epilogue")
    command.add_argument("--candidate", required=True)
    command.add_argument("--step-operation-plan", required=True)
    command.add_argument("--run-operation-plan", required=True)
    command.add_argument("--step-epilogue-rva", type=int)
    command.add_argument("--step-return-rva", type=int)
    command.add_argument("--step-epilogue-fuel", type=int, required=True)
    command.add_argument("--run-epilogue-rva", type=int)
    command.add_argument("--run-return-rva", type=int)
    command.add_argument("--run-epilogue-fuel", type=int, required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_kernel_cdecl_epilogue)

    command = sub.add_parser("kernel-cdecl-epilogue-symbolic-closure")
    command.add_argument("--candidate", required=True)
    command.add_argument("--cdecl-epilogue-plan", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_kernel_cdecl_epilogue_symbolic_closure)

    command = sub.add_parser("kernel-cdecl-epilogue-static-preservation")
    command.add_argument("--candidate", required=True)
    command.add_argument("--symbolic-closure-plan", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_kernel_cdecl_epilogue_static_preservation)

    command = sub.add_parser("kernel-cdecl-epilogue-external-payload")
    command.add_argument("--candidate", required=True)
    command.add_argument("--static-preservation-plan", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_kernel_cdecl_epilogue_external_payload)

    command = sub.add_parser("kernel-invoke")
    command.add_argument("--candidate", required=True)
    command.add_argument("--kernel-plan", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_kernel_invoke)

    command = sub.add_parser("kernel-invoke-native")
    command.add_argument("--candidate", required=True)
    command.add_argument("--kernel-plan", required=True)
    command.add_argument("--callback-plan", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_kernel_invoke_native)

    command = sub.add_parser("kernel-invoke-operation")
    command.add_argument("--candidate", required=True)
    command.add_argument("--kernel-plan", required=True)
    command.add_argument("--kernel-data-inventory", required=True)
    command.add_argument("--abi-plan", required=True)
    command.add_argument("--callback-plan", required=True)
    command.add_argument("--invoke-native-plan", required=True)
    command.add_argument("--run-operation-plan", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_kernel_invoke_operation)

    command = sub.add_parser("mixed-candidate-authority")
    command.add_argument("--kernel-data-inventory", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_mixed_candidate_authority)

    command = sub.add_parser("aggregate")
    command.add_argument("--source", action="append", required=True)
    command.add_argument("--target", action="append", default=[])
    command.add_argument("--target-closure-only", action="store_true")
    command.add_argument("--out", required=True)
    command.set_defaults(run=_aggregate)

    command = sub.add_parser("acceptance-sources")
    command.add_argument("--kernel-block-manifest", required=True)
    command.add_argument("--mixed-original-manifest", required=True)
    command.add_argument("--original-carrier-manifest", required=True)
    command.add_argument("--native-launch-request", required=True)
    command.add_argument("--static-reachability-manifest", required=True)
    command.add_argument("--native-launch-graph-manifest", required=True)
    command.add_argument(
        "--universal-paired-external-environment-manifest",
        required=True,
    )
    command.add_argument(
        "--constructive-source-coverage-manifest",
        required=True,
    )
    command.add_argument("--canonical-relation-core-manifest", required=True)
    command.add_argument(
        "--kernel-program-lookup-operation-manifest",
        required=True,
    )
    command.add_argument("--kernel-step-operation-manifest", required=True)
    command.add_argument("--kernel-run-operation-manifest", required=True)
    command.add_argument("--kernel-invoke-operation-manifest", required=True)
    command.add_argument("--x87-kernel-execution-manifest", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_acceptance_sources)
    return parser


def main() -> None:
    args = _parser().parse_args()
    args.run(args)


if __name__ == "__main__":
    main()

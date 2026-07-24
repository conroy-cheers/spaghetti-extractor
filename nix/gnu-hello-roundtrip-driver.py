#!/usr/bin/env python3
"""Deterministic build helpers for the GNU hello round-trip Nix lane.

The driver never executes either PE.  It only turns static Stage A exports,
Stage B packages, candidate bytes, and generated Lean sources into immutable
phase artifacts.  Nix owns phase scheduling and cache invalidation.
"""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping

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
    INTERPRETER_KERNEL_LEAN_FILENAME,
    write_relational_interpreter_kernel_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_block import (
    write_relational_interpreter_kernel_block_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_abi import (
    INTERPRETER_KERNEL_ABI_LEAN_FILENAME,
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
    QualifiedLeanSymbol,
    derive_direct_call_summary_requests_from_register_authority,
    derive_mixed_original_direct_call_summary_requests,
    load_checked_direct_call_summary_contract_proposals,
    load_original_iat_import_proposals,
    load_original_register_control_call_contract_proposals,
    plan_interpreter_mixed_original,
    write_relational_interpreter_mixed_original,
    write_relational_interpreter_mixed_original_base,
    write_relational_interpreter_mixed_original_final,
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
from spaghetti_extractor.relational.lean.internal_direct_call_mixed_original_integration import (
    INTERNAL_DIRECT_CALL_MIXED_ORIGINAL_INTEGRATION_FORMAT,
    DirectCallMixedOriginalAuthorityBinding,
    direct_call_mixed_original_integration_source,
)
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
    relational_interpreter_normalization_bundle_sources,
    relational_interpreter_normalization_inventory,
    relational_interpreter_normalization_module_inventory,
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
from spaghetti_extractor.roundtrip_fuzz.image_contract import (
    write_stage_a_load_image_contract,
)
from spaghetti_extractor.stage_b_interpreter_backend import (
    compile_stage_b_interpreter_program,
)
from spaghetti_extractor.stage_b_state_machine import (
    write_stage_b_state_machine_from_stage_a_export,
)
from spaghetti_extractor.stage_binary import _parse_stage_a_pe
from spaghetti_extractor.util import sha256_file, write_json


X87_KERNEL_EXECUTION_LEAN_MODULE = (
    "GeneratedRelationalInterpreterKernelX87Execution"
)
X87_KERNEL_EXECUTION_FRONTIER_FILENAME = (
    "x87-kernel-execution-frontier.json"
)
X87_KERNEL_EXECUTION_REMAINING_PROOF_PREMISES = (
    "program_binding.peExact",
    "program_binding.importsExact",
    "program_binding.targetInventory",
    "endpoint_certificate.handlerResult",
    "endpoint_certificate.callTarget",
    "endpoint_certificate.callRun",
    "endpoint_certificate.entryRun",
    "endpoint_certificate.instructionRun",
    "endpoint_certificate.captureRun",
    "endpoint_certificate.returnRun",
    "endpoint_certificate.frameEffect",
)


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
            "format": "stage-a-gnu-hello-roundtrip-phase-v1",
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
        if row.get("fpu_state") is None
    ]
    source = relational_interpreter_program_source(ordinary)
    destination = stage_a / "GeneratedSemanticInterpreterProgram.lean"
    destination.write_text(source, encoding="utf-8")
    _manifest(
        out,
        "semantic-program-lean",
        {"state_machine": machine},
        status="source-ready",
        modules=[destination.stem],
        counts={"ordinary_transfers": len(ordinary)},
    )


def _normalization_sources(args: argparse.Namespace) -> None:
    machine = Path(args.state_machine)
    out = Path(args.out)
    stage_a = out / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    ordinary = [row for row in _jsonl(machine) if row.get("fpu_state") is None]
    sources = relational_interpreter_normalization_bundle_sources(
        ordinary,
        source_module="StageA.GeneratedSemanticInterpreterProgram",
        pe_name="StageA.GeneratedRelational.originalPe",
        shard_size=args.shard_size,
        semantic_refinement_module=(
            "StageA.GeneratedInterpreterSemanticRefinementBundle"
        ),
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
    ordinary_count = sum(row.get("fpu_state") is None for row in rows)
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
    )
    for module, source in sources.items():
        (stage_a / f"{module}.lean").write_text(source, encoding="utf-8")
    inventory = relational_interpreter_x87_module_inventory(
        machine,
        source_module="StageA.GeneratedGnuHelloOriginalPE",
        pe_name="StageA.GeneratedRelational.originalPe",
        pe_byte_pack_inventory=pack_inventory,
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
        proof_authority=False,
        candidate_sha256=plan.candidate_sha256,
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
        or runtime_plan.get("status") != "evidence_ready"
        or runtime_plan.get("acceptance_authority") is not False
        or not isinstance(counts, dict)
        or not isinstance(counts.get("runtime_targets"), int)
        or isinstance(counts.get("runtime_targets"), bool)
        or counts["runtime_targets"] <= 0
        or not isinstance(counts.get("relocated_operands"), int)
        or isinstance(counts.get("relocated_operands"), bool)
        or counts.get("unbound_relocated_operands") != 0
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
        "status": "semantic_premises_required",
        "acceptance_authority": False,
        "candidate_sha256": candidate["sha256"],
        "runtime_targets": counts["runtime_targets"],
        "generated_goal": (
            "StageA.GeneratedRelational.InterpreterKernelX87Execution."
            "GeneratedX87ReplayBridgeKernelExecutionGoal"
        ),
        "generated_theorem": (
            "StageA.GeneratedRelational.InterpreterKernelX87Execution."
            "generatedX87ReplayBridgeKernelExecution"
        ),
        "remaining_authority": {
            "lean_type": (
                "ExactNativeX87ReplayKernelEndpointAuthority "
                "generatedX87ReplayBridgeRuntimeInventory program handler "
                "sourceInvariant"
            ),
            "program_binding_fields": [
                "peExact",
                "importsExact",
                "targetInventory",
            ],
            "endpoint_quantification": (
                "every checked runtime target, every caller and logical input "
                "satisfying sourceInvariant"
            ),
            "endpoint_certificate_witness_fields": [
                "result",
                "calleeEntry",
                "instructionEntryState",
                "captureEntryState",
                "returnEntryState",
                "returned",
                "calls",
                "eventIndex",
                "events",
                "world",
                "externalFrames",
                "entryFuel",
                "instructionFuel",
                "captureFuel",
                "returnFuel",
            ],
            "endpoint_certificate_proof_fields": [
                "handlerResult",
                "callTarget",
                "entryFuelPositive",
                "instructionFuelPositive",
                "captureFuelPositive",
                "returnFuelPositive",
                "callRun",
                "entryRun",
                "instructionRun",
                "captureRun",
                "returnRun",
                "frameEffect",
            ],
        },
        "remaining_proof_premises": list(
            X87_KERNEL_EXECUTION_REMAINING_PROOF_PREMISES
        ),
        "failure_mode": "incomplete",
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
        diagnostic_status="semantic_premises_required",
        proof_authority=False,
        candidate_sha256=candidate["sha256"],
        runtime_targets=counts["runtime_targets"],
        theorem=frontier["generated_theorem"],
        remaining_proof_premises=frontier["remaining_proof_premises"],
        remaining_authority=frontier["remaining_authority"],
        failure_mode="incomplete",
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
    modules = sorted(path.stem for path in stage_a.glob("*.lean"))
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
        counts={"modules": len(modules)},
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
    references = ()
    if authority_report is not None:
        references = load_relocated_writable_static_pointer_slot_authorities(
            authority_report,
            original_sha256=sha256_file(original),
            state_machine_sha256=sha256_file(state_machine),
            machine_import_report_sha256=sha256_file(machine_import_report),
            mixed_original_plan=baseline_plan,
        )
    plan = baseline_plan
    if direct_call_contracts:
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


def _mixed_original_direct_call_proposals(args: argparse.Namespace) -> None:
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
    baseline_plan, consumed_plan, writable_references = (
        _mixed_original_plan_layers(args)
    )
    if base_payload != consumed_plan.to_json():
        raise ValueError(
            "direct-call proposal consumed plan no longer matches its base plan"
        )
    target_rvas = {
        region.target_id: region.rva for region in consumed_plan.regions
    }
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
    proposal_plan = None
    if requests.requests:
        proposal_plan = construct_internal_direct_call_summary_proposals(
            original,
            state_machine,
            machine_import_report,
            requests.requests,
            finite_origin_call_authorities=finite_origin_call_authorities,
            finite_origin_tail_authorities=finite_origin_tail_authorities,
        )
    out = Path(args.out)
    stage_a = out / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    module_rows: list[dict[str, Any]] = []
    module_resources: dict[str, dict[str, Any]] = {}
    summary_node_module_count = 0
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
        for index, proposal in enumerate(proposal_plan.proposals):
            module = f"GeneratedRelationalInternalDirectCallSummaryProposal{index:04d}"
            namespace = f"StageA.Generated.{module}"
            dag = internal_direct_call_register_summary_module_dag(
                proposal.tree,
                checker_bindings,
                root_namespace=namespace,
            )
            destination = stage_a / f"{module}.lean"
            destination.write_text(dag.root_source, encoding="utf-8")
            module_resources[module] = {
                "resource_class": "medium",
                "estimated_memory_mb": 4096,
            }
            for node_module in dag.node_modules:
                prior = node_sources.get(node_module.module)
                if prior is not None and prior != node_module.source:
                    raise ValueError(
                        "one direct-call summary node module names "
                        "incompatible generated sources"
                    )
                node_sources[node_module.module] = node_module.source
            module_rows.append({
                "callsite_rva": proposal.request.callsite_rva,
                "contract_id": 0x80000000 + index,
                "module": f"StageA.{module}",
                "namespace": namespace,
                "summary_tree": (
                    f"{namespace}.generatedInternalDirectCallRegisterSummary"
                ),
            })
        for module, source in sorted(node_sources.items()):
            relative = module.removeprefix("StageA.")
            (stage_a / f"{relative}.lean").write_text(
                source,
                encoding="utf-8",
            )
            module_resources[relative] = (
                _internal_direct_call_summary_module_resource(source)
            )
        summary_node_module_count = len(node_sources)
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
        },
        status="proposal-source-ready",
        proof_authority=False,
        modules=[row["module"].removeprefix("StageA.") for row in module_rows],
        counts={
            "requests": len(requests.requests),
            "complete_proposals": (
                0 if proposal_plan is None else len(proposal_plan.proposals)
            ),
            "proposal_blockers": (
                0 if proposal_plan is None else len(proposal_plan.blockers)
            ),
            "request_frontiers": len(requests.frontiers),
            "cacheable_summary_nodes": summary_node_module_count,
        },
    )


def _load_semantic_authority_bindings(path_value: str | None) -> dict[int, Mapping[str, Any]]:
    if path_value is None:
        return {}
    path = Path(path_value)
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping) or payload.get("format") != (
        "stage-a-mixed-original-direct-call-semantic-inputs-v1"
    ):
        raise ValueError("direct-call semantic input has the wrong format")
    rows = payload.get("bindings")
    if not isinstance(rows, list):
        raise ValueError("direct-call semantic input bindings must be a list")
    result: dict[int, Mapping[str, Any]] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping) or not isinstance(row.get("callsite_rva"), int):
            raise ValueError(f"direct-call semantic binding {index} is malformed")
        callsite = int(row["callsite_rva"])
        if callsite in result:
            raise ValueError("direct-call semantic input has duplicate callsites")
        result[callsite] = row
    return result


def _mixed_original_direct_call_semantics(args: argparse.Namespace) -> None:
    proposal_path = Path(args.proposal_report)
    proposal_payload = json.loads(proposal_path.read_text(encoding="utf-8"))
    if not isinstance(proposal_payload, Mapping) or proposal_payload.get("format") != (
        "stage-a-mixed-original-direct-call-proposals-v1"
    ):
        raise ValueError("direct-call proposal report has the wrong format")
    inputs = proposal_payload.get("inputs")
    if not isinstance(inputs, Mapping):
        raise ValueError("direct-call proposal report lacks hash-bound inputs")
    original = Path(args.original)
    state_machine = Path(args.state_machine)
    if inputs.get("original_sha256") != sha256_file(original):
        raise ValueError("direct-call proposal original PE hash changed")
    if inputs.get("state_machine_sha256") != sha256_file(state_machine):
        raise ValueError("direct-call proposal state-machine hash changed")
    semantic_bindings = _load_semantic_authority_bindings(args.semantic_input)
    module_rows = proposal_payload.get("proposal_modules")
    request_plan = proposal_payload.get("request_plan")
    chains = request_plan.get("chains") if isinstance(request_plan, Mapping) else None
    if not isinstance(module_rows, list) or not isinstance(chains, list):
        raise ValueError("direct-call proposal report lacks module or chain rows")
    sites: dict[int, Mapping[str, Any]] = {}
    registers_by_callsite: dict[int, set[str]] = {}
    for chain in chains:
        if not isinstance(chain, Mapping):
            continue
        register = chain.get("register")
        calls = chain.get("required_internal_calls")
        if not isinstance(register, str) or not isinstance(calls, list):
            continue
        for site in calls:
            if not isinstance(site, Mapping) or not isinstance(site.get("callsite_rva"), int):
                continue
            callsite = int(site["callsite_rva"])
            prior = sites.get(callsite)
            if prior is not None and prior != site:
                raise ValueError("direct-call proposal has ambiguous callsite metadata")
            sites[callsite] = site
            registers_by_callsite.setdefault(callsite, set()).add(register)
    modules_by_callsite = {
        int(row["callsite_rva"]): row
        for row in module_rows
        if isinstance(row, Mapping) and isinstance(row.get("callsite_rva"), int)
    }
    out = Path(args.out)
    stage_a = out / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    contracts: list[dict[str, Any]] = []
    generated_modules: list[str] = []
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
            register for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp")
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
        row: dict[str, Any] = {
            "contract_id": contract_id,
            "source_target_id": site.get("source_target_id"),
            "continuation_target_id": site.get("continuation_target_id"),
            "edge_index": site.get("edge_index"),
            "source_rva": site.get("source_rva"),
            "callsite_rva": callsite,
            "continuation_rva": site.get("continuation_rva"),
            "preserved_registers": list(registers),
            "authorizing_lean_term": None,
            "remaining_semantic_premises": list(missing_fields),
        }
        semantic = semantic_bindings.get(callsite)
        if semantic is not None and proposal_module is not None:
            term = semantic.get("authority_term")
            if not isinstance(term, Mapping):
                raise ValueError("semantic binding lacks authority_term")
            external = QualifiedLeanSymbol(
                module=str(term.get("module", "")),
                namespace=str(term.get("namespace", "")),
                symbol=str(term.get("symbol", "")),
            )
            external.validate("semantic authority term")
            module = (
                "GeneratedRelationalInternalDirectCallMixedOriginalIntegration"
                f"{index:04d}"
            )
            namespace = f"StageA.Generated.{module}"
            source = direct_call_mixed_original_integration_source(
                DirectCallMixedOriginalAuthorityBinding(
                    context=(
                        "StageA.GeneratedRelational.InterpreterMixedOriginalBase."
                        "generatedOriginalCarrierContext"
                    ),
                    authority_term=external.qualified,
                    source_target_id=int(site["source_target_id"]),
                    continuation_target_id=int(site["continuation_target_id"]),
                    edge_index=int(site["edge_index"]),
                    contract_id=contract_id,
                    source_rva=int(site["source_rva"]),
                    callsite_rva=callsite,
                    continuation_rva=int(site["continuation_rva"]),
                    registers=registers,
                    imports=(
                        f"StageA.{INTERPRETER_MIXED_ORIGINAL_BASE_MODULE}",
                        str(proposal_module["module"]),
                        external.module,
                    ),
                    namespace=namespace,
                )
            )
            (stage_a / f"{module}.lean").write_text(source, encoding="utf-8")
            generated_modules.append(module)
            row["authorizing_lean_term"] = {
                "module": f"StageA.{module}",
                "namespace": namespace,
                "symbol": "generatedCheckedDirectCallRegisterControlContract",
            }
            row["remaining_semantic_premises"] = []
        contracts.append(row)
    authority_payload = {
        "format": "stage-a-mixed-original-direct-call-authority-bindings-v1",
        "inputs": {
            "original_sha256": sha256_file(original),
            "state_machine_sha256": sha256_file(state_machine),
            "proposal_report_sha256": sha256_file(proposal_path),
        },
        "contracts": contracts,
        "report_authority": False,
        "authority_source": "named Lean terms only",
    }
    write_json(out / "direct-call-authority-bindings.json", authority_payload)
    _manifest(
        out,
        "mixed-original-direct-call-semantics",
        {
            "original_pe": original,
            "state_machine": state_machine,
            "proposal_report": proposal_path,
        },
        status=(
            "semantic-terms-ready"
            if contracts and all(not row["remaining_semantic_premises"] for row in contracts)
            else "semantic-premises-pending"
        ),
        proof_authority=False,
        integration_format=INTERNAL_DIRECT_CALL_MIXED_ORIGINAL_INTEGRATION_FORMAT,
        modules=generated_modules,
        counts={
            "proposals": len(contracts),
            "authorized_terms": sum(
                row["authorizing_lean_term"] is not None for row in contracts
            ),
            "remaining_semantic_frontiers": sum(
                bool(row["remaining_semantic_premises"]) for row in contracts
            ),
        },
    )


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
            "blockers": len(plan.blockers),
        },
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
    if (
        manifest.get("phase") != "mixed-original-final-lean"
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
    original_module_path = (
        mixed_original / "StageA" / f"{INTERPRETER_MIXED_ORIGINAL_MODULE}.lean"
    )
    if not original_module_path.is_file():
        raise ValueError("mixed-original carrier input module is missing")

    spec = OriginalCarrierBindingSpec(
        original_module=f"StageA.{INTERPRETER_MIXED_ORIGINAL_MODULE}",
        original_namespace=(
            "StageA.GeneratedRelational.InterpreterMixedOriginal"
        ),
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
        "step_operation_plan": Path(args.step_operation_plan),
    }
    plan = write_relational_interpreter_kernel_run_operation_bundle(
        candidate_pe=inputs["candidate"],
        kernel_plan=inputs["kernel_plan"],
        data_inventory=inputs["kernel_data_inventory"],
        abi_plan=inputs["abi_plan"],
        run_native_plan=inputs["run_native_plan"],
        step_operation_plan=inputs["step_operation_plan"],
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
    }
    plan = write_relational_interpreter_kernel_invoke_operation_bundle(
        candidate_pe=inputs["candidate"],
        kernel_plan=inputs["kernel_plan"],
        data_inventory=inputs["kernel_data_inventory"],
        abi_plan=inputs["abi_plan"],
        callback_plan=inputs["callback_plan"],
        invoke_native_plan=inputs["invoke_native_plan"],
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
    write_json(out / "standalone-modules.json", modules)
    write_json(out / "proof-targets.json", sorted(targets))
    write_json(out / "module-resources.json", resources)
    _manifest(
        out,
        "proof-source-aggregate",
        {},
        status="source-ready",
        modules=modules,
        targets=sorted(targets),
        counts={"modules": len(modules), "targets": len(targets)},
    )


def _acceptance_sources(args: argparse.Namespace) -> None:
    """Emit the canonical mixed-context acceptance interface for GNU hello."""

    out = Path(args.out)
    stage_a = out / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
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
    x87_kernel_execution_manifest_path = Path(
        args.x87_kernel_execution_manifest
    )
    x87_kernel_execution_manifest = json.loads(
        x87_kernel_execution_manifest_path.read_text(encoding="utf-8")
    )
    x87_remaining_premises = x87_kernel_execution_manifest.get(
        "remaining_proof_premises"
    )
    if (
        x87_kernel_execution_manifest.get("phase")
        != "x87-kernel-execution-lean"
        or x87_kernel_execution_manifest.get("status") != "source-ready"
        or x87_kernel_execution_manifest.get("diagnostic_status")
        != "semantic_premises_required"
        or x87_kernel_execution_manifest.get("proof_authority") is not False
        or x87_remaining_premises
        != list(X87_KERNEL_EXECUTION_REMAINING_PROOF_PREMISES)
        or x87_kernel_execution_manifest.get("failure_mode") != "incomplete"
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
    blocker_count = mixed_original_manifest.get("counts", {}).get("blockers")
    authorizing_direct_call_terms = mixed_original_manifest.get(
        "authorizing_lean_terms"
    )
    if (
        mixed_original_manifest.get("phase") != "mixed-original-final-lean"
        or mixed_original_manifest.get("proof_authority") is not False
        or not isinstance(remaining_frontiers, list)
        or blocker_count != len(remaining_frontiers)
        or not isinstance(authorizing_direct_call_terms, list)
        or not all(
            isinstance(term, str) and term for term in authorizing_direct_call_terms
        )
    ):
        raise ValueError("mixed-original final manifest is malformed")
    block_manifest = json.loads(
        Path(args.kernel_block_manifest).read_text(encoding="utf-8")
    )
    block_targets = sorted(
        target
        for target in block_manifest.get("targets", [])
        if isinstance(target, str)
    )
    requirements_module = "GeneratedGnuHelloRoundTripRequirements"
    requirements_namespace = "StageA.GeneratedGnuHelloRoundTripRequirements"
    core_type = "MixedKernelBindingRequirements"
    exact_imports = [
        "StageA.GeneratedRelationalInterpreterMixedOriginal",
        "StageA.GeneratedRelationalInterpreterOriginalCarrierBinding",
        "StageA.GeneratedCallableExternalProgram",
        "StageA.GeneratedRelationalInterpreterMixedAuthority",
        "StageA.GeneratedRelationalInterpreterKernelABI",
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

/- Deliberately uninhabited until a generated native-launch source phase binds
the exact candidate entry/TLS paths and outbound wrappers to `launch_chunk`.
Root identity alone is not a constructor for this proposition. -/
inductive ExactGnuHelloCandidateNativeLaunchRouteBinding : Prop

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
  candidateNativeLaunchCertificate : ExactNativeLaunchGraphCertificate
  candidateNativeLaunchCertificateStaticChecked :
    candidateNativeLaunchCertificate.staticChecked core.candidate_program.pe
      core.candidate_program.imports = true
  candidateNativeLaunchRouteBinding :
    ExactGnuHelloCandidateNativeLaunchRouteBinding

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
            "blocking_obligations": [
                {
                    "id": "mixed_original_exact_reachability_missing",
                    "frontier_count": blocker_count,
                    "authority": "named Lean terms consumed by exact reachability",
                },
                {
                    "id": "exact_candidate_native_launch_wrapper_missing",
                    "candidate_sha256": native_launch_request["candidate_sha256"],
                    "canonical_sources": native_launch_request["canonical_sources"],
                    "required_path_shapes": native_launch_request[
                        "required_path_shapes"
                    ],
                    "required_lean_fields": [
                        "candidateNativeLaunchCertificate",
                        "candidateNativeLaunchCertificateStaticChecked",
                        "candidateNativeLaunchRouteBinding",
                    ],
                    "forbidden_authority": native_launch_request[
                        "forbidden_authority"
                    ],
                },
                {
                    "id": "universal_paired_environment_refinement_missing",
                    "required_lean_fields": [
                        "core.launch_wrapper_refinements",
                        "core.environment_compositions",
                    ],
                    "scope": (
                        "every paired environment satisfying exact 1:1 import, "
                        "event, ABI, world, and external-protocol refinement"
                    ),
                    "forbidden_authority": [
                        "one favorable concrete OS response schedule",
                        "hand-crafted trivial environment functions",
                    ],
                },
                {
                    "id": "x87_replay_kernel_execution_premises_missing",
                    "candidate_sha256": x87_kernel_execution_manifest[
                        "candidate_sha256"
                    ],
                    "runtime_targets": x87_kernel_execution_manifest[
                        "runtime_targets"
                    ],
                    "generated_theorem": x87_kernel_execution_manifest[
                        "theorem"
                    ],
                    "remaining_proof_premises": x87_remaining_premises,
                    "required_authority": x87_kernel_execution_manifest[
                        "remaining_authority"
                    ],
                    "forbidden_authority": [
                        "submitted paths or endpoint states",
                        "Python status fields",
                        "solver status without checked semantic equations",
                    ],
                },
            ],
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
        semantic_blockers=[
            {
                "id": "mixed_original_exact_reachability_missing",
                "frontier_count": blocker_count,
            },
            {
                "id": "exact_candidate_native_launch_wrapper_missing",
                "candidate_sha256": native_launch_request["candidate_sha256"],
            },
            {
                "id": "universal_paired_environment_refinement_missing",
            },
            {
                "id": "x87_replay_kernel_execution_premises_missing",
                "runtime_targets": x87_kernel_execution_manifest[
                    "runtime_targets"
                ],
                "remaining_proof_premises": x87_remaining_premises,
            },
        ],
        counts={
            "remaining_original_control_frontiers": blocker_count,
            "remaining_x87_kernel_execution_premises": len(
                x87_remaining_premises
            ),
            "x87_runtime_targets": x87_kernel_execution_manifest[
                "runtime_targets"
            ],
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
    command.add_argument("--step-operation-plan", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_kernel_run_operation)

    command = sub.add_parser("kernel-cdecl-epilogue")
    command.add_argument("--candidate", required=True)
    command.add_argument("--step-operation-plan", required=True)
    command.add_argument("--run-operation-plan", required=True)
    command.add_argument("--step-epilogue-rva", type=int, required=True)
    command.add_argument("--step-return-rva", type=int, required=True)
    command.add_argument("--step-epilogue-fuel", type=int, required=True)
    command.add_argument("--run-epilogue-rva", type=int, required=True)
    command.add_argument("--run-return-rva", type=int, required=True)
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
    command.add_argument("--out", required=True)
    command.set_defaults(run=_kernel_invoke_operation)

    command = sub.add_parser("mixed-candidate-authority")
    command.add_argument("--kernel-data-inventory", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_mixed_candidate_authority)

    command = sub.add_parser("aggregate")
    command.add_argument("--source", action="append", required=True)
    command.add_argument("--target", action="append", default=[])
    command.add_argument("--out", required=True)
    command.set_defaults(run=_aggregate)

    command = sub.add_parser("acceptance-sources")
    command.add_argument("--kernel-block-manifest", required=True)
    command.add_argument("--mixed-original-manifest", required=True)
    command.add_argument("--original-carrier-manifest", required=True)
    command.add_argument("--native-launch-request", required=True)
    command.add_argument("--x87-kernel-execution-manifest", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(run=_acceptance_sources)
    return parser


def main() -> None:
    args = _parser().parse_args()
    args.run(args)


if __name__ == "__main__":
    main()

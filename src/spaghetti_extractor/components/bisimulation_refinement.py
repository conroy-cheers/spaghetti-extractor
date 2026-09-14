"""Direct CBMC bisimulation of exact Behavioral-C and Portable-C overlays.

The checker has no machine-path model. The exact side is the component-scoped
Behavioral-C rendering of checked transfers. The source side is ordinary
Portable-C behind its checked machine overlay. Both execute from the same
arbitrary state against paired memories and a record/replay environment.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Mapping, Sequence

from .bisimulation_readable_composition import (STRATEGY as IMAGE_READABLE_STRATEGY, MUTABLE_STRATEGY,
    image_readable_operations, image_readable_assertions, mutable_summary_bounds, mutable_summary_unwind_arguments)
from .bisimulation_exact_frame import frame_candidate, MACHINE_STATE_DESCRIPTION, CUT_MACHINE_STATE_DESCRIPTION
from .bisimulation_mutable_machine_frame import SPECS as MUTABLE_MACHINE_FRAMES
from .bisimulation_mutable_frame import mutable_frame_views
from .bisimulation_clobber_frame import clobber_specs, result_registers
from .bisimulation_shared_composition import (STRATEGY as SHARED_STRATEGY, FRAMED_STRATEGY,
    shared_boundary_operations, shared_entry_assertions, shared_summary_bounds)
from .bisimulation_shared_model import SHARED_CONTRACT_POLICY
from . import bisimulation_image_frame as image_frame

from .bisimulation_execution import (
    _cbmc_cover_queries,
    _run_bisimulation_obligation,
    property_checker_command as make_property_checker_command,
)

from ..artifacts.artifact_set import canonical_sha256_v3
from .bisimulation import BisimulationOperationV1, ComponentBisimulationIntentV1
from .bisimulation_continuation import continuation_assertions, continuation_model
from .bisimulation_connected import (
    connected_source_prefix,
    prepare_connected_models,
    render_connected_summary_wrapper,
)
from .bisimulation_reference_transport import (
    connected_readable_transport_assertions, readonly_connected_transport_source,
    readonly_overlay_transport_source, connected_mutable_transport_assertions,
    mutable_connected_transport_source, mutable_overlay_transport_source, shared_state_overlay_transport_source,
)
from .machine_overlay_services_v5 import _c_identifier
from .bisimulation_cut_state import collect_cut_local_state
from .capabilities import spx_portable_reference_runtime_v5_source
from .cbmc_backend import (
    CbmcBackendError,
    cbmc_version,
    discover_cbmc_assertions,
    discover_cbmc_loops,
    discover_cbmc_safety_properties,
    run_cbmc_cover,
    run_cbmc_properties,
)
from .inductive_refinement import _write_cbmc_stdint
from .interface_ir import ProofKernelComponentInterface
from .source import component_operation_symbols, load_component_source_package
from .semantic_induction import build_inductive_machine_shape
from .bisimulation_exact import (
    _compact_exact_temporaries as _compact_exact_temporaries,
    _c_function_call_site_count,
    _connected_service_unit_costs,
    _exact_stack_accesses,
    _exact_unit_costs,
    _maximum_acyclic_path_cost,
    _next_barrier_sync_ids,
    _obligation_exact_compilation_files,
    _obligation_functions,
    _render_proof_header,
    _segment_exact_unit_ids,
    _service_output_unit_costs,
    _source_service_unit_costs,
    _specialize_exact_function_source as _specialize_exact_function_source,
    _specialize_machine_overlay_for_proof as _specialize_machine_overlay_for_proof,
    _validate_exact_slice,
)
from .bisimulation_harness import (
    _cut_view_domain,
    _captured_parameter_view,
    _exit_comparisons as _exit_comparisons,
    _finite_control_proof_model,
    _nul_view_count,
    _private_stack_high_offset as _private_stack_high_offset,
    _render_harness,
    _render_source_expression as _render_source_expression,
    _source_shadow_bytes,
)
from .bisimulation_support import (
    BisimulationRefinementError,
    assertion_policy_option,
    PROOF_PRIVATE_STACK_ABOVE as PROOF_PRIVATE_STACK_ABOVE,
    PROOF_RELATION_WITNESS,
    UINT32_BYTES,
    include_path as _include_path,
    mapping as _mapping,
    property_entry_function as _property_entry_function,
    property_query_order as _property_query_order,
    rows as _rows,
    strings as _strings,
    unit_rva as _unit_rva,
)
from .bisimulation_typed_services import (
    _canonical_proof_service_bindings,
    _trusted_adapter_lowering_receipt,
    build_typed_proof_service_thunk_renderer as build_typed_proof_service_thunk_renderer,
)
from .bisimulation_world import _world_source as _world_source
from .bisimulation_projection import machine_fact_read_descriptions
from .bisimulation_view_extent import nul_view_parameters
from .bisimulation_query_evidence import proof_workspace as _proof_workspace, previous_proof_queries
from .bisimulation_native_views import native_view_specs
from .bisimulation_reference_authority import checked_reference_authority, reference_authority_unwind_arguments
from .bisimulation_allocation_classes import checked_allocation_requirements
from .bisimulation_lifetime_admission import uses_lifetime_services


def check_bisimulation_refinement(
    *,
    semantic_contract: Mapping[str, object],
    interface: ProofKernelComponentInterface,
    source_package: Path,
    source_profile: Mapping[str, object],
    intent: ComponentBisimulationIntentV1,
    exact_c_root: Path,
    exact_c_slice: Mapping[str, object],
    machine_overlay_source: str,
    trusted_proof_overlay_source: str | None = None,
    machine_overlay_entries: Sequence[Mapping[str, object]],
    machine_projections: Mapping[str, Mapping[str, object]],
    cbmc: Path,
    c_headers: Mapping[str, str],
    connected_components: Sequence[Mapping[str, object]] = (),
    relation_evidence: Sequence[Mapping[str, object]] = (),
    timeout_seconds: int = 300,
    source_entry_timeout_seconds: int | None = None,
    diagnostic_root: Path | None = None,
    proof_workspace: Path | None = None,
    previous_query_evidence: Path | None = None,
    reference_authority: Mapping[str, object] | None = None,
    reference_allocation_requirements: list[Mapping[str, object]] | None = None,
    smt_solver: Path | None = None,
    runtime_assurance: Mapping[str, object] | None = None,
    selected_obligations: list[dict[str, str]] | None = None,
) -> dict[str, object]:
    """Prove each operation entry and source sync by executing both C forms."""

    from .bisimulation_assurance import checked_implemented_runtime_assurance
    runtime_assurance = checked_implemented_runtime_assurance(runtime_assurance)
    if source_entry_timeout_seconds is not None and (
            type(source_entry_timeout_seconds) is not int or source_entry_timeout_seconds <= 0
            or runtime_assurance is None):
        raise BisimulationRefinementError('entry query timeout requires a positive integer and explicit conditional assurance')
    from .conditional_check_result import checked_obligation_selection, deferred_obligation
    selected_obligations = checked_obligation_selection(selected_obligations)
    if selected_obligations is not None and runtime_assurance is None:
        raise BisimulationRefinementError('focused region checks require explicit conditional assurance')
    assurance_metadata = ({"assurance": runtime_assurance, "authorizing": False}
                          if runtime_assurance is not None else {})
    if diagnostic_root is not None and Path(diagnostic_root).exists():
        raise BisimulationRefinementError("bisimulation diagnostic destination already exists")
    source_root = Path(source_package)
    previous_queries = previous_proof_queries(previous_query_evidence, runtime_assurance=runtime_assurance)
    authority = checked_reference_authority(reference_authority)
    reference_allocation_requirements = checked_allocation_requirements(authority, reference_allocation_requirements)
    reference_authority = None if authority is None else authority.to_payload()
    source = load_component_source_package(source_root)
    symbols = component_operation_symbols(source)
    component_id = str(semantic_contract.get("component_id", ""))
    if (
        component_id != intent.component_id
        or source.get("lift_unit_id") != component_id
    ):
        raise BisimulationRefinementError(
            "bisimulation inputs name different components"
        )
    if interface.identity != component_id.replace("-", "_"):
        raise BisimulationRefinementError(
            "bisimulation interface names another component"
        )
    if source_profile.get("status") != "satisfied" or _mapping(
        source_profile.get("bindings"), "source profile bindings"
    ).get("implementation_sha256") != source.get("implementation_sha256"):
        raise BisimulationRefinementError(
            "bisimulation source profile is incomplete or stale"
        )
    profile_core = dict(source_profile)
    profile_digest = profile_core.pop("receipt_sha256", None)
    if profile_digest != canonical_sha256_v3(profile_core):
        raise BisimulationRefinementError("bisimulation source profile digest is stale")
    operations = {
        str(row.get("operation_id")): row
        for row in _rows(semantic_contract.get("operations"), "semantic operations")
    }
    if set(intent.operation_index()) != set(symbols) or set(symbols) != set(operations):
        raise BisimulationRefinementError(
            "bisimulation operation inventory differs from source or semantics"
        )
    overlay_entries = {
        str(row.get("operation_id")): row for row in machine_overlay_entries
    }
    if set(overlay_entries) != set(operations):
        raise BisimulationRefinementError(
            "machine-overlay operation inventory is not total"
        )
    if set(machine_projections) != set(operations):
        raise BisimulationRefinementError(
            "machine-projection operation inventory is not total"
        )
    exact_root = Path(exact_c_root)
    _validate_exact_slice(exact_c_slice, exact_root, component_id, intent_sha256=intent.intent_sha256)
    exact_unit_rvas: dict[str, int] = {}
    for index, raw in enumerate(
        _rows(exact_c_slice.get("source_map", []), "exact-C source map")
    ):
        row = _mapping(raw, f"exact-C source-map row {index}")
        unit_id = str(row.get("unit_id", ""))
        rva = row.get("rva")
        if (
            not unit_id
            or not isinstance(rva, int)
            or isinstance(rva, bool)
            or not 0 <= rva <= 0xFFFFFFFF
            or (unit_id in exact_unit_rvas and exact_unit_rvas[unit_id] != rva)
        ):
            raise BisimulationRefinementError(
                "exact-C source map has an ambiguous unit RVA"
            )
        exact_unit_rvas[unit_id] = rva
    operation_functions = {authored.operation_id: _obligation_functions(authored,
        operations[authored.operation_id], entry_rva=int(overlay_entries[authored.operation_id]['entry_rva']),
        unit_rvas=exact_unit_rvas) for authored in intent.operations}
    selected_ids = None if selected_obligations is None else {
        (row['operation_id'], row['obligation_id']) for row in selected_obligations}
    known_ids = {(operation, function['obligation_id']) for operation, functions in operation_functions.items()
                 for function in functions}
    if selected_ids is not None and not selected_ids <= known_ids:
        raise BisimulationRefinementError('conditional region selection names unknown obligations: '
                                         + repr(sorted(selected_ids - known_ids)))
    try:
        version = cbmc_version(Path(cbmc))
    except CbmcBackendError as exc:
        raise BisimulationRefinementError(str(exc)) from exc
    goto_cc = Path(cbmc).with_name("goto-cc")
    if not goto_cc.is_file():
        raise BisimulationRefinementError("pinned CBMC package omits goto-cc")
    from .cbmc_backend import bind_smt_solver
    solver_binding = bind_smt_solver(smt_solver)

    package_root = source_root if source_root.is_dir() else source_root.parent
    source_files = [
        package_root / "sources" / str(row["path"])
        for row in source["files"]
        if isinstance(row, Mapping) and str(row.get("path", "")).endswith(".c")
    ]
    connected_models = prepare_connected_models(connected_components, component_id, runtime_assurance=runtime_assurance)
    parent_world = {"reference_authority": reference_authority,
                    "reference_allocation_requirements": reference_allocation_requirements,
                    "operation_models": list(operations.values())}
    for connected in connected_models:
        if image_readable_operations(connected["entry_contract"], parent_world) is not None:
            connected["summary_strategy"] = IMAGE_READABLE_STRATEGY
        elif image_readable_operations(connected["entry_contract"], parent_world, mutable=True) is not None:
            connected["summary_strategy"] = MUTABLE_STRATEGY
        elif shared_boundary_operations(connected['entry_contract'], parent_world) is not None:
            connected['summary_strategy'] = SHARED_STRATEGY
        elif shared_boundary_operations(connected['entry_contract'], parent_world, framed=True) is not None:
            connected['summary_strategy'] = FRAMED_STRATEGY
        elif (connected['entry_contract'] is not None and connected['entry_contract']['proof_system']['proof']['models']
              .get('source_summary_contracts', {}).get('certificate', {}).get('policy') == SHARED_CONTRACT_POLICY):
            raise BisimulationRefinementError('shared summary requires a compatible fixed image caller world')
        if (connected['entry_contract'] is not None
                and connected['entry_contract']['proof_system']['proof']['models']['connected_components']
                and connected['summary_strategy'] not in {IMAGE_READABLE_STRATEGY, MUTABLE_STRATEGY}):
            raise BisimulationRefinementError('transitive memory composition requires a checked body-free image world')
    _, mutable_summary_writes = mutable_summary_bounds(connected_models)
    shared_writes, shared_calls = shared_summary_bounds(connected_models)
    mutable_summary_writes += shared_writes
    from .bisimulation_private_frame import summary_write_count
    mutable_summary_writes += summary_write_count(connected_models)
    exact_files = [
        exact_root / str(row["path"])
        for row in _rows(exact_c_slice.get("files"), "exact-C files")
        if str(row.get("path", "")).endswith(".c")
    ]
    exact_unit_writes, exact_unit_calls, exact_internal_calls = _exact_unit_costs(
        exact_c_slice=exact_c_slice,
        exact_root=exact_root,
    )
    # Only caller-owned sites consume connected slots. Callee closure bodies
    # belong to their own proof and must not inflate the parent's model arrays.
    connected_summary_capacity = max(sum(
        exact_unit_calls.get(unit_id, 0)
        for unit_id in _strings(exact_c_slice.get("unit_ids"), "exact-C owned units")
    ), 1)
    next_connected_summary_id = 0
    for connected in connected_models:
        operation_ids = sorted(
            str(_mapping(row, "connected overlay entry").get("operation_id", ""))
            for row in connected["overlay_entries"]
        )
        if (
            not operation_ids
            or "" in operation_ids
            or len(operation_ids) != len(set(operation_ids))
            or set(operation_ids) != set(connected["operation_symbols"])
        ):
            raise BisimulationRefinementError(
                "connected component summary operation inventory is malformed"
            )
        connected["summary_ids"] = {
            operation_id: next_connected_summary_id + index
            for index, operation_id in enumerate(operation_ids)
        }
        connected["summary_capacity"] = connected_summary_capacity
        next_connected_summary_id += len(operation_ids)
    exact_unit_atomics: dict[str, int] = {}
    exact_source_cache: dict[str, list[str]] = {}
    for raw in _rows(exact_c_slice.get("source_map", []), "exact-C source map"):
        row = _mapping(raw, "exact-C source-map entry")
        unit_id = str(row.get("unit_id", ""))
        relative = str(row.get("file", ""))
        start = int(row.get("line_start", 0))
        end = int(row.get("line_end", 0))
        lines = exact_source_cache.setdefault(
            relative,
            (exact_root / relative).read_text(encoding="ascii").splitlines(),
        )
        if not unit_id or start <= 0 or end < start or end > len(lines):
            raise BisimulationRefinementError(
                "exact-C source-map range is malformed while costing atomics"
            )
        unit_source = "\n".join(lines[start - 1 : end])
        exact_unit_atomics[unit_id] = unit_source.count(
            "spx_runtime_atomic_compare_exchange("
        ) + unit_source.count("spx_runtime_atomic_exchange(")
    root_proof_service_bindings = [
        _mapping(raw, "proof overlay service binding")
        for entry in overlay_entries.values()
        for raw in _rows(entry.get("service_bindings", []), "overlay services")
    ]
    connected_proof_service_bindings = [
        _mapping(raw, "connected proof overlay service binding")
        for connected in connected_models
        for entry in connected["overlay_entries"]
        for raw in _rows(
            _mapping(entry, "connected overlay entry").get("service_bindings", []),
            "connected overlay services",
        )
    ]
    proof_service_bindings = _canonical_proof_service_bindings(
        root_proof_service_bindings,
        connected_proof_service_bindings,
        reference_authority=reference_authority, allocation_requirements=reference_allocation_requirements,
    )
    if uses_lifetime_services(proof_service_bindings) and any(
            row.get('summary_strategy') not in {'scalar-body-free-v1', FRAMED_STRATEGY} for row in connected_models):
        raise BisimulationRefinementError('connected allocation dependencies require transitive proof premises')
    proof_overlay_source = (
        machine_overlay_source
        if trusted_proof_overlay_source is None
        else trusted_proof_overlay_source
    )
    trusted_adapter_lowering = _trusted_adapter_lowering_receipt(
        interface=interface,
        service_bindings=root_proof_service_bindings,
        production_overlay_source=machine_overlay_source,
        proof_overlay_source=proof_overlay_source,
        relation_evidence=relation_evidence,
        reference_authority=reference_authority,
        allocation_requirements=reference_allocation_requirements,
    )
    source_atomic_call_sites = 0
    for path in source_files:
        source_text = path.read_text(encoding="ascii")
        source_atomic_call_sites += source_text.count(
            "spx_atomic_compare_exchange("
        ) + source_text.count("spx_atomic_exchange(")
    operation_costs: dict[str, dict[str, object]] = {}
    for authored in intent.operations:
        overlay_entry = overlay_entries[authored.operation_id]
        source_unit_writes, source_unit_calls = _source_service_unit_costs(
            overlay_sources=[
                proof_overlay_source,
                *(str(row["proof_overlay_source"]) for row in connected_models),
            ],
            overlay_entry=overlay_entry,
        )
        exact_outputs = _service_output_unit_costs(overlay_entry, reference_authority=reference_authority,
                                                  allocation_requirements=reference_allocation_requirements)
        exact_writes = {
            unit_id: exact_unit_writes.get(unit_id, 0)
            + exact_outputs.get(unit_id, 0)
            + UINT32_BYTES * exact_unit_calls.get(unit_id, 0)
            for unit_id in {
                *exact_unit_writes,
                *exact_outputs,
                *exact_unit_calls,
            }
        }
        source_exit_writes = UINT32_BYTES * _c_function_call_site_count(
            proof_overlay_source,
            str(overlay_entry.get("symbol", "")),
            "spx_component_write(",
        )
        operation_costs[authored.operation_id] = {
            "exact_writes": exact_writes,
            "exact_calls": exact_unit_calls,
            "exact_atomics": exact_unit_atomics,
            "source_writes": source_unit_writes,
            "source_calls": source_unit_calls,
            "connected_calls": _connected_service_unit_costs(overlay_entry, exact_internal_calls=exact_internal_calls),
            "source_atomics": source_atomic_call_sites,
            "source_exit_writes": source_exit_writes,
        }

    all_results: list[dict[str, object]] = []
    model_bindings: list[dict[str, object]] = []
    shard_bounds: list[dict[str, int]] = []
    with _proof_workspace(proof_workspace) as root:
        if runtime_assurance is not None:
            (root / "runtime-assurance.json").write_text(
                json.dumps(runtime_assurance, sort_keys=True, separators=(",", ":"), ensure_ascii=True),
                encoding="ascii")
        if reference_allocation_requirements is not None:
            (root / "allocation-class-requirements.json").write_text(
                json.dumps(reference_allocation_requirements, sort_keys=True, separators=(",", ":"), ensure_ascii=True),
                encoding="ascii")
        if reference_authority is not None:
            (root / "reference-authority.json").write_text(
                json.dumps({key: value for key, value in reference_authority.items() if key != "authority_sha256"},
                           sort_keys=True, separators=(",", ":"), ensure_ascii=True),
                encoding="ascii")
        _write_cbmc_stdint(root / "stdint.h")
        (root / "connected-proof-summary.h").write_text(
            "#ifndef SPX_CONNECTED_PROOF_SUMMARY_H\n"
            "#define SPX_CONNECTED_PROOF_SUMMARY_H\n"
            f"#define SPX_PROOF_CONNECTED_CAPACITY {connected_summary_capacity}\n"
            "#endif\n",
            encoding="ascii",
        )
        (root / "stddef.h").write_text(
            "#ifndef SPX_CBMC_STDDEF_H\n"
            "#define SPX_CBMC_STDDEF_H\n"
            "typedef unsigned int size_t; typedef signed int ptrdiff_t;\n"
            "#define NULL ((void *)0)\n"
            "#endif\n",
            encoding="ascii",
        )
        for name, content in c_headers.items():
            (root / name).write_text(content, encoding="ascii")
        (root / "state-machine-runtime.h").write_text(
            (exact_root / "state-machine-runtime.h").read_text(encoding="ascii"),
            encoding="ascii",
        )
        reference_runtime_tu = root / "portable-reference-runtime-v5.c"
        reference_runtime_tu.write_text(
            '#include "stdint.h"\n' + spx_portable_reference_runtime_v5_source(),
            encoding="ascii",
        )
        connected_compilation_files: list[Path] = []
        connected_included_files: list[Path] = []
        for connected_index, connected in enumerate(connected_models):
            connected_root = root / f"connected-{connected_index:04d}"
            connected_root.mkdir()
            for name, content in connected["headers"].items():
                (connected_root / str(name)).write_text(str(content), encoding="ascii")
            connected_source_root = Path(str(connected["source_root"]))
            connected_source = _mapping(connected["source"], "connected source package")
            operation_symbols = _mapping(
                connected["operation_symbols"], "connected operation symbols"
            )
            summary_ids = _mapping(
                connected["summary_ids"], "connected proof-summary identities"
            )
            rename_prefix = connected_source_prefix(
                {str(key): str(value) for key, value in operation_symbols.items()},
                {str(key): int(value) for key, value in summary_ids.items()},
            )
            connected_package_root = (
                connected_source_root
                if connected_source_root.is_dir()
                else connected_source_root.parent
            )
            for source_index, source_row in enumerate(
                _rows(connected_source.get("files"), "connected source files")
            ):
                if connected["summary_strategy"] in {"scalar-body-free-v1", IMAGE_READABLE_STRATEGY, MUTABLE_STRATEGY, SHARED_STRATEGY, FRAMED_STRATEGY}:
                    continue
                relative = str(source_row.get("path", ""))
                if not relative.endswith(".c"):
                    continue
                source_path = connected_package_root / "sources" / relative
                copied_source = connected_root / f"source-{source_index:04d}.c"
                copied_source.write_text(
                    rename_prefix + "\n" + source_path.read_text(encoding="ascii"),
                    encoding="ascii",
                )
                connected_compilation_files.append(copied_source)
            checked_mutable = connected.get("mutable_transport_policy") is not None
            inspector = f"__CPROVER_spx_{'mutable' if checked_mutable else 'readonly'}_overlay_{connected_index:04d}"
            checked_transport = connected["readable_transport_policy"] is not None or checked_mutable
            transport_source = (mutable_connected_transport_source([inspector], framed=connected['summary_strategy'] == FRAMED_STRATEGY,
                symbol=f"__CPROVER_spx_connected_mutable_transport_{_c_identifier(connected['compiled_interface'].interface.identity)}")
                if checked_mutable else readonly_connected_transport_source([inspector]) if checked_transport else "")
            overlay_transport = (shared_state_overlay_transport_source
                if checked_mutable and connected['compiled_interface'].interface.state
                else mutable_overlay_transport_source if checked_mutable else readonly_overlay_transport_source)
            connected_wrapper = connected_root / "proof-summary-wrapper.c"
            connected_wrapper.write_text(
                render_connected_summary_wrapper(
                    bundle=connected["compiled_interface"],
                    operation_symbols={
                        str(key): str(value) for key, value in operation_symbols.items()
                    },
                    summary_ids={
                        str(key): int(value) for key, value in summary_ids.items()
                    },
                    checked_readable_transport=checked_transport and not checked_mutable,
                    checked_mutable_transport=checked_mutable,
                    body_free_readonly=connected["summary_strategy"] == IMAGE_READABLE_STRATEGY,
                    body_free_mutable=connected["summary_strategy"] == MUTABLE_STRATEGY,
                    body_free_scalar=connected["summary_strategy"] == "scalar-body-free-v1",
                    scalar_postconditions=(connected["source_summary_certificate"]["postconditions"]
                        if connected["summary_strategy"] == "scalar-body-free-v1" else ()),
                    shared_contract=(connected['entry_contract']['proof_system']['proof']['models']['source_summary_contracts']['certificate']['shared_contract']
                        if connected['summary_strategy'] in {SHARED_STRATEGY, FRAMED_STRATEGY} else None),
                ) + transport_source,
                encoding="ascii",
            )
            connected_compilation_files.append(connected_wrapper)
            connected_overlay = connected_root / "machine-overlay.c"
            connected_overlay.write_text(
                str(connected["proof_overlay_source"]), encoding="ascii"
            )
            if checked_transport:
                inspector_tu = connected_root / "machine-overlay-transport.c"
                inspector_tu.write_text('#include "machine-overlay.c"\n' + overlay_transport(inspector), encoding="ascii")
                connected_compilation_files.append(inspector_tu)
                connected_included_files.append(connected_overlay)
            else:
                connected_compilation_files.append(connected_overlay)
        reference_runtime_symbols = (
            "spx_ref_derive(",
            "spx_ref_difference(",
            "spx_view_read_u8(",
            "spx_view_write_u8(",
        )
        reference_runtime_files = (
            [reference_runtime_tu]
            if any(
                symbol in path.read_text(encoding="ascii")
                for path in [*source_files, *connected_compilation_files, *connected_included_files]
                for symbol in reference_runtime_symbols
            )
            else []
        )
        cut_local_state = collect_cut_local_state(
            root=root, source_files=source_files, operations=intent.operations,
            include_root=package_root / "sources",
            operation_parameter_ids={op.identity: [value.identity for value in op.parameters]
                                     for op in interface.operations},
            operation_symbols=symbols, goto_cc=goto_cc,
            goto_instrument=cbmc.parent / "goto-instrument", timeout_seconds=timeout_seconds,
            prepare_entries=runtime_assurance is not None,
        )
        for operation_index, authored in enumerate(intent.operations):
            operation = operations[authored.operation_id]
            clobber_metadata = ({"machine_clobbers": list(authored.machine_clobbers),
                "machine_result_registers": list(result_registers(machine_projections[authored.operation_id]["operation"]))}
                if authored.machine_clobbers else {})
            if authored.private_stack_writes:
                clobber_metadata["private_stack_writes"] = authored.to_payload()["private_stack_writes"]
            if authored.private_stack_accesses is not None:
                clobber_metadata["private_stack_accesses"] = authored.to_payload()["private_stack_accesses"]
            if authored.reference_origin_capacity is not None:
                clobber_metadata["reference_origin_capacity"] = authored.reference_origin_capacity
            from .bisimulation_allocation_cuts import history_metadata
            clobber_metadata.update(history_metadata(authored))
            from . import bisimulation_memory_facts as memory_facts
            clobber_metadata.update(memory_facts.metadata(authored))
            from .bisimulation_stack_scope import scope_metadata
            clobber_metadata.update(scope_metadata(authored))
            from .bisimulation_projection import machine_fact_metadata
            clobber_metadata.update(machine_fact_metadata(authored))
            from . import bisimulation_local_views as local_views
            clobber_metadata.update(local_views.local_view_metadata(authored))
            clobber_metadata.update(assurance_metadata)
            overlay_entry = overlay_entries[authored.operation_id]
            local_view_codecs = local_views.local_view_specs(authored, component_id=interface.identity,
                overlay_entry=overlay_entry, authority=reference_authority,
                parameter_specs=native_view_specs(interface, authored.operation_id, overlay_entry, reference_authority,
                    machine_projections[authored.operation_id]["operation"]))
            if local_view_codecs is not None and local_view_codecs["symbol"] not in proof_overlay_source:
                raise BisimulationRefinementError("local view cut requires the generated proof overlay codec")
            machine_image = operation.get("machine_image")
            if not isinstance(machine_image, Mapping):
                raise BisimulationRefinementError(
                    "strong bisimulation requires a checked machine image"
                )
            common_context = continuation_model(operation)
            if common_context is not None and any(exact_unit_calls.get(unit, 0) for unit in common_context["unit_ids"]):
                raise BisimulationRefinementError("exact continuation calls require checked context call contracts")
            functions = operation_functions[authored.operation_id]
            overlay_file = root / f"overlay-{operation_index:04d}.c"
            overlay_file.write_text(proof_overlay_source, encoding="ascii")
            obligation_models: list[dict[str, object]] = []
            obligation_tasks: list[dict[str, object]] = []
            for function in functions:
                shard_index = int(function["start_code"])
                shard_root = root / (
                    f"operation-{operation_index:04d}-obligation-{shard_index:04d}"
                )
                shard_root.mkdir()
                exact_compilation_files, exact_model = (
                    _obligation_exact_compilation_files(
                        out_dir=shard_root,
                        exact_files=exact_files,
                        exact_root=exact_root,
                        exact_c_slice=exact_c_slice,
                        operation=operation,
                        authored=authored,
                        start_unit_id=str(function["start_unit_id"]),
                        connected=bool(connected_models),
                        summarized_entry_rvas=frozenset(
                            int(entry["entry_rva"])
                            for component in connected_models
                            if component["summary_strategy"] in {"scalar-body-free-v1", IMAGE_READABLE_STRATEGY, MUTABLE_STRATEGY, SHARED_STRATEGY, FRAMED_STRATEGY}
                            for entry in component["overlay_entries"]
                        ),
                    )
                )
                proof_selected_units = _segment_exact_unit_ids(
                    operation=operation,
                    authored=authored,
                    start_unit_id=str(function["start_unit_id"]),
                )
                exact_stack_accesses = _exact_stack_accesses(
                    exact_files=exact_compilation_files,
                    service_bindings=root_proof_service_bindings,
                    reference_authority=reference_authority, allocation_requirements=reference_allocation_requirements,
                    selected_unit_rvas={
                        _unit_rva(unit_id) for unit_id in proof_selected_units
                    },
                )
                exact_model = {
                    **exact_model,
                    "exact_stack_accesses": [
                        {"offset": offset, "width": width}
                        for offset, width in exact_stack_accesses
                    ],
                }
                selected_units = set(
                    _strings(
                        exact_model.get("selected_unit_ids"),
                        "obligation-local exact units",
                    )
                )
                exact_shape = build_inductive_machine_shape(operation)
                control_edges = [
                    _mapping(raw, "exact semantic control edge")
                    for raw in _rows(
                        exact_shape.get("control_edges"),
                        "exact semantic control edges",
                    )
                ]
                next_sync_ids = _next_barrier_sync_ids(
                    operation=operation,
                    authored=authored,
                    selected_unit_ids=proof_selected_units,
                )
                if function.get("sync_id") is not None:
                    # The entry shard establishes this authored relation and
                    # every predecessor shard preserves it at its barrier.
                    # Starting a cutpoint shard from the relation is therefore
                    # the inductive rule itself; replaying the complete entry
                    # prefix here would duplicate already-proved work and make
                    # late shards grow with operation length.
                    exact_model = {
                        **exact_model,
                        "inductive_cutpoint_live_in_relation": {
                            "kind": "universal_authored_relation_v1",
                            "target_unit_id": str(function["start_unit_id"]),
                            "bounded_prefix_assumptions": False,
                            "predecessor_barriers_checked": True,
                            "source": "authored_sync_invariant_and_captures",
                        },
                    }
                proof_header = shard_root / "component-bisimulation.h"
                proof_header.write_text(
                    _render_proof_header(
                        local_view_specs=local_view_codecs,
                        operation_projection=machine_projections[authored.operation_id]["operation"],
                        mutable_views=mutable_frame_views(interface, authored.operation_id, connected_models),
                        readable_machine_state=frame_candidate(interface, authored.operation_id, connected_models),
                        authored=authored,
                        image_base=int(machine_image["preferred_base"]),
                        unit_rvas=exact_unit_rvas,
                        active_start_sync_id=(
                            None
                            if function.get("sync_id") is None
                            else str(function["sync_id"])
                        ),
                        active_target_sync_ids=next_sync_ids,
                        local_havoc=cut_local_state.havoc.get(authored.operation_id, {}),
                        nul_view_ids=nul_view_parameters(interface, authored.operation_id),
                        native_specs=native_view_specs(interface, authored.operation_id, overlay_entry, reference_authority,
                            machine_projections[authored.operation_id]["operation"]),
                    ),
                    encoding="ascii",
                )
                wrappers: list[Path] = []
                for source_index, source_file in enumerate(source_files):
                    wrapper = shard_root / f"source-{source_index:04d}.c"
                    wrapper.write_text(
                        f'#include "{proof_header.name}"\n'
                        f'#include "{_include_path(source_file)}"\n',
                        encoding="ascii",
                    )
                    wrappers.append(wrapper)
                costs = operation_costs[authored.operation_id]
                exact_writes = _mapping(costs["exact_writes"], "exact write costs")
                exact_calls = _mapping(costs["exact_calls"], "exact call costs")
                source_writes = _mapping(costs["source_writes"], "source write costs")
                source_calls = _mapping(costs["source_calls"], "source call costs")
                exact_atomics = _mapping(costs["exact_atomics"], "exact atomic costs")
                source_atomics = int(costs["source_atomics"])
                reaches_exit = bool(
                    selected_units
                    & set(_strings(operation.get("exit_unit_ids"), "operation exits"))
                )
                finite_control_model = (
                    _finite_control_proof_model(
                        _mapping(
                            machine_projections[authored.operation_id].get("operation"),
                            "logical operation projection",
                        ),
                        machine_image=machine_image,
                    )
                    if reaches_exit
                    else None
                )
                if finite_control_model is not None:
                    exact_model = {
                        **exact_model,
                        "finite_control_route_inventory_sha256": str(
                            finite_control_model["route_inventory_sha256"]
                        ),
                    }
                witness_functions = sorted(
                    _strings(
                        finite_control_model["witness_functions"],
                        "finite-control witnesses",
                    )
                    if finite_control_model is not None
                    else (
                        [PROOF_RELATION_WITNESS]
                        if next_sync_ids or reaches_exit
                        else []
                    )
                )
                if not witness_functions:
                    raise BisimulationRefinementError(
                        "bisimulation obligation reaches no cutpoint or terminal cover"
                    )
                start_unit_id = str(function["start_unit_id"])
                barrier_unit_ids = frozenset(sync.exact_unit_id for sync in authored.syncs)
                exact_static_writes = _maximum_acyclic_path_cost(
                    start_unit_id=start_unit_id,
                    selected_unit_ids=selected_units,
                    control_edges=control_edges,
                    barrier_unit_ids=barrier_unit_ids,
                    costs=exact_writes,
                )
                declared_public_writes = _maximum_acyclic_path_cost(
                    start_unit_id=start_unit_id,
                    selected_unit_ids=selected_units,
                    control_edges=control_edges,
                    barrier_unit_ids=barrier_unit_ids,
                    costs=source_writes,
                ) + (int(costs["source_exit_writes"]) if reaches_exit else 0)
                static_writes = max(
                    exact_static_writes,
                    declared_public_writes,
                    1,
                )
                region_connected_calls = _maximum_acyclic_path_cost(
                    start_unit_id=start_unit_id,
                    selected_unit_ids=selected_units,
                    control_edges=control_edges,
                    barrier_unit_ids=barrier_unit_ids,
                    costs=_mapping(costs["connected_calls"], "connected call costs"),
                )
                static_writes += UINT32_BYTES * region_connected_calls * mutable_summary_writes
                if common_context is not None:
                    static_writes += common_context["maximum_steps"] * max(
                        exact_writes.get(unit, 0) for unit in common_context["unit_ids"])
                static_write_calls = max(
                    (static_writes + UINT32_BYTES - 1) // UINT32_BYTES,
                    1,
                )
                declared_public_write_calls = max(
                    (declared_public_writes + UINT32_BYTES - 1) // UINT32_BYTES,
                    1,
                )
                # Either history can receive a store whose address aliases a
                # partition boundary. Bound both by the full path inventory;
                # public-memory equality still checks undeclared changes.
                max_writes = static_write_calls
                max_calls = max(
                    _maximum_acyclic_path_cost(
                        start_unit_id=start_unit_id,
                        selected_unit_ids=selected_units,
                        control_edges=control_edges,
                        barrier_unit_ids=barrier_unit_ids,
                        costs=exact_calls,
                    ),
                    _maximum_acyclic_path_cost(
                        start_unit_id=start_unit_id,
                        selected_unit_ids=selected_units,
                        control_edges=control_edges,
                        barrier_unit_ids=barrier_unit_ids,
                        costs=source_calls,
                    ),
                    1,
                )
                max_calls += region_connected_calls * shared_calls
                from .bisimulation_call_entry import call_entry_assertions
                from .bisimulation_call_ranges import readable_range_descriptions
                from .bisimulation_typed_services import _proof_call_specs

                required_assertion_descriptions = _required_assertion_descriptions(
                    readable_range_assertions=readable_range_descriptions(_proof_call_specs(
                        proof_service_bindings, allow_lifetime_effects=reference_allocation_requirements is not None)),
                    readable_machine_state=frame_candidate(interface, authored.operation_id, connected_models),
                    mutable_machine_state=bool(mutable_frame_views(interface, authored.operation_id, connected_models)),
                    connected_entry_assertions=tuple(description for connected in connected_models
                        for description in [*call_entry_assertions(connected), *connected_readable_transport_assertions(connected), *connected_mutable_transport_assertions(connected), *image_readable_assertions(connected), *shared_entry_assertions(connected)]),
                    authored=authored,
                    continuation=common_context,
                    proof_function=str(function["symbol"]),
                    active_start_sync_id=(
                        None
                        if function.get("sync_id") is None
                        else str(function["sync_id"])
                    ),
                    next_sync_ids=next_sync_ids,
                    logical_projection=_mapping(
                        machine_projections[authored.operation_id].get("operation"),
                        "logical operation projection",
                    ),
                    continuous_acyclic=not authored.syncs,
                    typed_call_positions=(
                        range(max_calls) if proof_service_bindings else ()
                    ),
                    connected_summary_ids=tuple(
                        sorted(
                            int(summary_id)
                            for connected in connected_models
                            for summary_id in _mapping(
                                connected["summary_ids"],
                                "connected proof-summary identities",
                            ).values()
                        )
                    ),
                )
                if image_frame.candidate(interface=interface,
                        mutable_views=mutable_frame_views(interface, authored.operation_id, connected_models),
                        connected=connected_models, authority=reference_authority,
                        allocations=reference_allocation_requirements):
                    required_assertion_descriptions = sorted({*required_assertion_descriptions, image_frame.frame_spec(authored.private_stack_accesses).description})
                if authored.reference_origin_capacity is not None:
                    from .bisimulation_reference_origins import capacity_description
                    required_assertion_descriptions = sorted({*required_assertion_descriptions, capacity_description(authored.reference_origin_capacity)})
                from .bisimulation_runtime_dispatch import required_dispatch_assertions
                required_assertion_descriptions = sorted({*required_assertion_descriptions,
                    *required_dispatch_assertions(runtime_assurance)})
                required_assertion_descriptions_sha256 = canonical_sha256_v3(
                    required_assertion_descriptions
                )
                max_atomics = max(
                    _maximum_acyclic_path_cost(
                        start_unit_id=start_unit_id,
                        selected_unit_ids=selected_units,
                        control_edges=control_edges,
                        barrier_unit_ids=barrier_unit_ids,
                        costs=exact_atomics,
                    ),
                    source_atomics,
                    1,
                )
                if common_context is not None:
                    max_atomics += common_context["maximum_steps"] * max(
                        exact_atomics.get(unit, 0) for unit in common_context["unit_ids"])
                bounds = {
                    "static_byte_write_upper_bound": static_writes,
                    "static_memory_write_call_upper_bound": static_write_calls,
                    "declared_public_memory_write_call_upper_bound": (
                        declared_public_write_calls
                    ),
                    "maximum_calls": max_calls,
                    "maximum_atomics": max_atomics,
                    "exact_stack_cached_accesses": len(exact_stack_accesses),
                    "exact_stack_cached_bytes": len(
                        {
                            offset + byte
                            for offset, width in exact_stack_accesses
                            for byte in range(width)
                        }
                    ),
                }
                shard_bounds.append(bounds)
                exact_model = {**exact_model, "model_bounds": bounds}
                harness_arguments = {
                    "runtime_assurance": runtime_assurance,
                    "reference_authority": reference_authority,
                    "reference_allocation_requirements": reference_allocation_requirements,
                    "continuation": common_context,
                    "interface": interface,
                    "authored": authored,
                    "machine_image": machine_image,
                    "operation_projection": machine_projections[authored.operation_id],
                    "overlay_entry": overlay_entry,
                    "functions": [function],
                    "max_writes": max_writes,
                    "max_private_writes": static_write_calls,
                    "max_calls": max_calls,
                    "max_atomics": max_atomics,
                    "max_shadow_bytes": _source_shadow_bytes(
                        _mapping(
                            machine_projections[authored.operation_id].get("operation"),
                            "logical operation projection",
                        )
                    )
                    + (UINT32_BYTES if authored.syncs else 0),
                    "max_nul_views": _nul_view_count(interface, authored.operation_id),
                    "service_bindings": proof_service_bindings,
                    "reference_service_bindings": root_proof_service_bindings,
                    "connected_summaries": [
                        {
                            "component_id": connected["component_id"],
                            "summary_id": _mapping(
                                connected["summary_ids"],
                                "connected proof-summary identities",
                            )[
                                str(
                                    _mapping(entry, "connected overlay entry")[
                                        "operation_id"
                                    ]
                                )
                            ],
                            "summary_capacity": connected["summary_capacity"],
                            "summary_strategy": connected["summary_strategy"],
                            "entry_contract": connected["entry_contract"],
                            "readable_transport_policy": connected["readable_transport_policy"],
                            **({"mutable_transport_policy": connected["mutable_transport_policy"]} if "mutable_transport_policy" in connected else {}),
                            **dict(entry),
                        }
                        for connected in connected_models
                        for entry in connected["overlay_entries"]
                    ],
                    "cut_unsigned_words": cut_local_state.unsigned_words.get(authored.operation_id, {}),
                    "include_finite_control": reaches_exit,
                    "exact_stack_accesses": exact_stack_accesses,
                    "continuous_acyclic": not authored.syncs,
                    "unexpected_sync_ids": [sync.identity for sync in authored.syncs
                        if sync.identity != function.get("sync_id") and sync.identity not in next_sync_ids],
                    "continuous_exact_unit_rvas": [
                        exact_unit_rvas[unit_id]
                        if unit_id in exact_unit_rvas
                        else _unit_rva(unit_id)
                        for unit_id in sorted(proof_selected_units)
                    ],
                    "relation_evidence": relation_evidence,
                }
                harness = shard_root / "bisimulation.c"
                harness.write_text(
                    _render_harness(**harness_arguments),
                    encoding="ascii",
                )
                shared_proof_inputs = [
                    {
                        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                        "role": role,
                    }
                    for role, paths in (
                        ("exact_c", exact_compilation_files),
                        ("source_c", wrappers),
                        ("portable_reference_runtime_c", reference_runtime_files),
                        ("connected_provider_c", [*connected_compilation_files, *connected_included_files]),
                        (
                            "production_overlay_c"
                            if trusted_adapter_lowering is None
                            else "trusted_proof_overlay_c",
                            [overlay_file],
                        ),
                        ("proof_header", [proof_header]),
                        ("runtime_assurance", [root / "runtime-assurance.json"]
                         if runtime_assurance is not None else []),
                        ("reference_authority", [root / "reference-authority.json"]
                         if reference_authority is not None else []),
                        ("allocation_class_requirements", [root / "allocation-class-requirements.json"]
                         if reference_allocation_requirements is not None else []),
                        ("source_cut_storage_inventory", [root / "source-cut-locals" / "local-havoc.json"]
                         if authored.syncs else []),
                        ("source_parameter_binding_inventory", [root / "source-cut-locals" / "parameter-bindings.json"]
                         if authored.syncs else []),
                    )
                    for path in paths
                ]
                proof_inputs = [
                    *shared_proof_inputs,
                    {
                        "sha256": hashlib.sha256(harness.read_bytes()).hexdigest(),
                        "role": "harness",
                    },
                ]
                proof_model_sha256 = canonical_sha256_v3(proof_inputs)
                nonvacuity_proof_inputs = proof_inputs
                nonvacuity_proof_model_sha256 = proof_model_sha256
                exact_model = {
                    **exact_model,
                    **clobber_metadata,
                    "proof_function": str(function["symbol"]),
                    "nonvacuity_function": f"{function['symbol']}_relation",
                    "witness_functions": witness_functions,
                    "required_assertion_descriptions": (
                        required_assertion_descriptions
                    ),
                    "required_assertion_descriptions_sha256": (
                        required_assertion_descriptions_sha256
                    ),
                    "proof_inputs": proof_inputs,
                    "proof_model_sha256": proof_model_sha256,
                    "nonvacuity_proof_inputs": nonvacuity_proof_inputs,
                    "nonvacuity_proof_model_sha256": (nonvacuity_proof_model_sha256),
                }
                goto_model = shard_root / "model.goto"
                source_entry = cut_local_state.entries.get(authored.operation_id, {}).get(function.get("sync_id"))
                if source_entry is not None:
                    from .bisimulation_source_entry import preparation_summary
                    exact_model["source_entry_preparation"] = preparation_summary(source_entry)
                compile_command = [
                    str(goto_cc),
                    "--i386-win32",
                    "-I",
                    str(root),
                    "-I",
                    str(exact_root),
                    "-I",
                    str(package_root / "sources"),
                    *(str(path) for path in exact_compilation_files),
                    *(str(path) for path in wrappers),
                    *(str(path) for path in reference_runtime_files),
                    *(str(path) for path in connected_compilation_files),
                    str(overlay_file),
                    str(harness),
                    "-o",
                    str(goto_model),
                ]
                allocation_capacity = max_calls + clobber_metadata.get("maximum_input_allocations", 0)
                authority_unwind_arguments = mutable_summary_unwind_arguments(connected_models,
                    reference_authority_unwind_arguments(reference_authority,
                        allocation_capacity=allocation_capacity))
                property_checker_command = make_property_checker_command(authority_unwind_arguments,
                    source_unwind_limit=authored.source_unwind_limit, smt_solver=solver_binding,
                    application_first=runtime_assurance is not None)
                model_cover_queries = _cbmc_cover_queries(
                    reference_authority=reference_authority, connected_components=connected_models,
                    allocation_capacity=allocation_capacity,
                    cbmc=Path("cbmc"),
                    goto_model=Path("model.goto"),
                    proof_function=f"{function['symbol']}_relation",
                    witness_functions=witness_functions,
                    source_unwind_limit=authored.source_unwind_limit,
                    smt_solver=solver_binding,
                )
                nonvacuity_checker_command = {
                    "backend": "cbmc",
                    "goto_model_role": "shared_property_and_relation",
                    "strategy": (
                        "per_goal_formula_sliced_v1"
                        if len(witness_functions) <= 2
                        else "aggregate_formula_sliced_v1"
                    ),
                    "queries": [
                        {
                            "functions": query["expected_functions"],
                            "arguments": query["command"][2:],
                        }
                        for query in model_cover_queries
                    ],
                }
                property_checker_command_sha256 = canonical_sha256_v3(
                    property_checker_command
                )
                nonvacuity_checker_command_sha256 = canonical_sha256_v3(
                    nonvacuity_checker_command
                )
                exact_model = {
                    **exact_model,
                    "property_checker_command": property_checker_command,
                    "property_checker_command_sha256": (
                        property_checker_command_sha256
                    ),
                    "nonvacuity_checker_command": nonvacuity_checker_command,
                    "nonvacuity_checker_command_sha256": (
                        nonvacuity_checker_command_sha256
                    ),
                }
                obligation_tasks.append(
                    {
                        **clobber_metadata,
                        "compile_command": compile_command,
                        "source_entry_timeout_seconds": source_entry_timeout_seconds,
                        **({"source_entry_candidate": source_entry, "source_entry_wrappers": wrappers,
                            "goto_instrument": cbmc.parent / "goto-instrument"} if source_entry is not None else {}),
                        "compile_workspace": root,
                        "cbmc": cbmc,
                        "smt_solver": solver_binding,
                        "property_checker_command": property_checker_command,
                        "cover_queries": _cbmc_cover_queries(
                            reference_authority=reference_authority, connected_components=connected_models,
                            allocation_capacity=allocation_capacity,
                            cbmc=cbmc,
                            goto_model=goto_model,
                            proof_function=f"{function['symbol']}_relation",
                            witness_functions=witness_functions,
                            source_unwind_limit=authored.source_unwind_limit,
                            smt_solver=solver_binding,
                        ),
                        "goto_model": goto_model,
                        "diagnostic_timings": diagnostic_root is not None,
                        "retain_query_evidence": diagnostic_root is not None or previous_query_evidence is not None,
                        "previous_query_evidence": previous_queries.get((authored.operation_id, function["obligation_id"])),
                        "diagnostic_proof_root": root,
                        "proof_function": str(function["symbol"]),
                        "required_assertion_descriptions": (
                            required_assertion_descriptions
                        ),
                        "witness_functions": witness_functions,
                        "proof_model_sha256": proof_model_sha256,
                        "nonvacuity_proof_model_sha256": (
                            nonvacuity_proof_model_sha256
                        ),
                        "property_checker_command_sha256": (
                            property_checker_command_sha256
                        ),
                        "nonvacuity_checker_command_sha256": (
                            nonvacuity_checker_command_sha256
                        ),
                        "shard_id": (
                            f"{authored.operation_id}:{function['obligation_id']}"
                        ),
                        "operation_id": authored.operation_id,
                        "obligation_id": function["obligation_id"],
                    }
                )
                obligation_models.append(
                    {
                        "obligation_id": function["obligation_id"],
                        **exact_model,
                    }
                )
            # Assertion queries are already parallel within each obligation.
            # Keep obligations sequential so nested pools cannot multiply the
            # documented four-process solver budget into sixteen CBMC jobs.
            operation_results = [
                _run_bisimulation_obligation(task, timeout_seconds=timeout_seconds)
                if selected_ids is None or (task['operation_id'], task['obligation_id']) in selected_ids
                else deferred_obligation(task, runtime_assurance)
                for task in obligation_tasks
            ]
            all_results.extend(operation_results)
            result_by_obligation = {
                str(row["obligation_id"]): row for row in operation_results
            }
            obligation_models = [
                {
                    **model,
                    "goto_model_sha256": result_by_obligation[
                        str(model["obligation_id"])
                    ]["goto_model_sha256"],
                    "nonvacuity_goto_model_sha256": result_by_obligation[
                        str(model["obligation_id"])
                    ]["nonvacuity_goto_model_sha256"],
                    "execution_binding_sha256": result_by_obligation[
                        str(model["obligation_id"])
                    ]["execution_binding_sha256"],
                }
                for model in obligation_models
            ]
            model_bindings.append(
                {
                    **clobber_metadata,
                    "operation_id": authored.operation_id,
                    "exact_entry_rva": int(overlay_entry["entry_rva"]),
                    "overlay_symbol": str(overlay_entry["symbol"]),
                    "machine_image": dict(machine_image),
                    "shards": len(functions),
                    "obligation_models": obligation_models,
                }
            )

        # Successful models must remain inspectable too: receipt-bound C inputs
        # allow operators to reconstruct the GOTO inventory with the pinned tool.
        # These proof-only sources confer no execution authority.
        if diagnostic_root is not None:
            destination = Path(diagnostic_root)
            if destination.exists():
                raise BisimulationRefinementError(
                    "bisimulation diagnostic destination already exists"
                )
            shutil.copytree(
                root,
                destination,
                ignore=lambda _directory, names: [name for name in names if name.endswith(".goto") and name not in {
                    "exact-frame.goto", "exact-mutable-frame.goto", "exact-mutable-cut-frame.goto",
                    *(spec.artifact_stem + ".goto" for spec in MUTABLE_MACHINE_FRAMES),
                    "mutable-cut-clobber-frame.goto", "mutable-exit-clobber-frame.goto",
                    "private-write-frame.goto", "private-cut-frame.goto", image_frame.FRAME.artifact_stem + ".goto"}
                    and not (name == "model.goto" and (Path(_directory).name == "source-entry"
                        or any(c["summary_strategy"] in {IMAGE_READABLE_STRATEGY, MUTABLE_STRATEGY} for c in connected_models)))],
            )

    statuses = {str(row["status"]) for row in all_results}
    if solver_binding is not None and bind_smt_solver(smt_solver) != solver_binding:
        raise BisimulationRefinementError("external SMT solver changed during the proof")
    status = (
        "violated"
        if "violated" in statuses
        else "satisfied"
        if statuses == {"satisfied"}
        else "incomplete"
    )
    core: dict[str, object] = {
        **({'selected_obligations': selected_obligations} if selected_obligations is not None else {}),
        "status": status,
        **assurance_metadata,
        "activation_authorized": runtime_assurance is None and status == "satisfied" and not any(
            operation.entry_allocation_history is not None for operation in intent.operations),
        "component_id": intent.component_id,
        "bindings": {
            **assurance_metadata,
            "interface_sha256": interface.sha256,
            "semantic_contract_sha256": _semantic_contract_sha256(semantic_contract),
            "source_profile_sha256": profile_digest,
            "implementation_sha256": source["implementation_sha256"],
            "bisimulation_intent_sha256": intent.intent_sha256,
            "exact_c_slice_sha256": exact_c_slice["slice_sha256"],
            "machine_overlay_sha256": hashlib.sha256(
                machine_overlay_source.encode("ascii")
            ).hexdigest(),
            "proof_overlay_sha256": hashlib.sha256(
                proof_overlay_source.encode("ascii")
            ).hexdigest(),
            "trusted_adapter_lowering": trusted_adapter_lowering,
            "reference_authority": reference_authority,
            **({"reference_allocation_requirements": reference_allocation_requirements,
                "reference_allocation_requirements_sha256": canonical_sha256_v3(reference_allocation_requirements)}
               if reference_allocation_requirements is not None else {}),
            "operation_models": model_bindings,
            "connected_components": [
                {
                    "component_id": row["component_id"],
                    **({"assurance": row["assurance"], "authorizing": False} if "assurance" in row else {}),
                    "binding_intent_sha256": row["binding_intent_sha256"],
                    "implementation_sha256": _mapping(
                        row["source"], "connected source package"
                    )["implementation_sha256"],
                    "source_profile_sha256": row["source_profile_sha256"],
                    "qualification_sha256": row["qualification_sha256"],
                    "contextual_refinement_sha256": row["contextual_refinement_sha256"],
                    "proof_receipt_sha256": row["proof_receipt_sha256"],
                    "summary_strategy": row["summary_strategy"],
                    "source_summary_certificate": row["source_summary_certificate"],
                    "entry_contract": row["entry_contract"],
                    "readable_transport_policy": row["readable_transport_policy"],
                    **({"mutable_transport_policy": row["mutable_transport_policy"]} if "mutable_transport_policy" in row else {}),
                    "machine_overlay_sha256": hashlib.sha256(
                        str(row["production_overlay_source"]).encode("ascii")
                    ).hexdigest(),
                    "proof_overlay_sha256": hashlib.sha256(
                        str(row["proof_overlay_source"]).encode("ascii")
                    ).hexdigest(),
                    "trusted_adapter_lowering_receipt_sha256": (
                        None
                        if row["trusted_adapter_lowering"] is None
                        else _mapping(
                            row["trusted_adapter_lowering"],
                            "connected trusted adapter lowering",
                        )["receipt_sha256"]
                    ),
                    "machine_overlay_entries_sha256": canonical_sha256_v3(
                        row["overlay_entries"]
                    ),
                }
                for row in connected_models
            ],
        },
        "checker": {
            **({"smt_solver": solver_binding} if solver_binding is not None else {}),
            "id": "cbmc-goto-direct-c-bisimulation",
            "version": version,
            "cbmc_sha256": hashlib.sha256(Path(cbmc).read_bytes()).hexdigest(),
            "goto_cc_sha256": hashlib.sha256(goto_cc.read_bytes()).hexdigest(),
            "architecture": "i386-win32",
            "model_bounds": {
                "maximum_static_byte_write_upper_bound": max(
                    row["static_byte_write_upper_bound"] for row in shard_bounds
                ),
                "maximum_static_memory_write_call_upper_bound": max(
                    row["static_memory_write_call_upper_bound"] for row in shard_bounds
                ),
                "maximum_declared_public_memory_write_call_upper_bound": max(
                    row["declared_public_memory_write_call_upper_bound"]
                    for row in shard_bounds
                ),
                "maximum_calls_per_obligation": max(
                    row["maximum_calls"] for row in shard_bounds
                ),
                "maximum_atomics_per_obligation": max(
                    row["maximum_atomics"] for row in shard_bounds
                ),
                "maximum_exact_stack_cached_accesses": max(
                    row["exact_stack_cached_accesses"] for row in shard_bounds
                ),
                "maximum_exact_stack_cached_bytes": max(
                    row["exact_stack_cached_bytes"] for row in shard_bounds
                ),
                "derivation": "obligation_local_cutpoint_segment_capacity",
                "inductive_cutpoint_live_in_relation": (
                    "universal_authored_relation_without_entry_prefix_replay"
                ),
                "exact_capacity": "acyclic_unit_and_call_site_upper_bound",
                "localized_model_validity_assertions_fail_closed": True,
                "public_capacity": ("paired_local_capacity_assertions"),
                "pointer_topology": (
                    "generated_harness_owned_and_source_definedness_checked"
                ),
                "private_stack_disjoint_checked_image": True,
                "dynamic_allocation": "absent",
            },
            "timeout_seconds_per_shard": timeout_seconds,
            "maximum_parallel_shards": 1,
            "maximum_parallel_solver_processes": 4,
            "nested_solver_parallelism": False,
            "options": [
                "source-cuts=matched-terminal-v1",
                "object-bits=12",
                "symex-cache-dereferences",
                "smt-solver=z3" if solver_binding is not None else "sat-solver=cadical",
                "unwind=2",
                "unwinding-assertions",
                "reachability-slice-fb",
                "slice-formula",
                "stop-on-fail",
                assertion_policy_option({'operation_models': model_bindings}),
                "assertion-inventory=entry-reachability-sliced",
                "typed-service-fields=single-call-boundary-safe-prefix",
                "exact-stack=affine-word-cache-with-partial-overlap-invalidation",
                "language-safety=inventory-partitioned-paired-obligation-entry",
                "small-goal-nonvacuity=per-goal-formula-sliced",
                "large-goal-nonvacuity=aggregate-formula-sliced",
            ],
        },
        "checks": sorted(all_results, key=lambda row: str(row["shard_id"])),
        "issues": [
            {
                key: row.get(key)
                for key in (
                    "status",
                    "code",
                    "shard_id",
                    "operation_id",
                    "detail",
                    "source",
                    "counterexample",
                )
                if row.get(key) is not None
            }
            for row in all_results
            if row["status"] != "satisfied"
        ] + [{"status": "incomplete", "code": "bisimulation_entry_allocation_admission_required",
              "operation_id": operation.operation_id,
              "detail": "Incoming allocation history is a conditional local premise; actual caller admission and heap frame discharge are required before activation."}
             for operation in intent.operations if operation.entry_allocation_history is not None],
    }
    return {**core, "receipt_sha256": canonical_sha256_v3(core)}


def _required_assertion_descriptions(
    *,
    authored: BisimulationOperationV1,
    proof_function: str,
    active_start_sync_id: str | None,
    next_sync_ids: set[str],
    logical_projection: Mapping[str, object],
    continuous_acyclic: bool,
    typed_call_positions: Sequence[int],
    connected_summary_ids: Sequence[int] = (),
    connected_entry_assertions: Sequence[str] = (),
    readable_machine_state: bool = False,
    mutable_machine_state: bool = False,
    continuation: Mapping[str, object] | None = None,
    readable_range_assertions: Sequence[str] = (),
) -> list[str]:
    """Derive semantic goals independently of CBMC's property inventory."""

    from .bisimulation_local_views import byte_read_checks, input_owner_description
    from .bisimulation_memory_facts import description as memory_fact_description, coordinate_phases as memory_fact_coordinate_phases
    descriptions = {
        *readable_range_assertions,
        *(memory_fact_description(sync, fact, phase)
          for sync in authored.syncs if sync.identity == active_start_sync_id or sync.identity in next_sync_ids
          for fact in sync.memory_facts for phase in memory_fact_coordinate_phases(sync, fact)),
        *(memory_fact_description(sync, fact, phase)
          for sync in authored.syncs for fact in sync.memory_facts
          for phase in (("construction-order", "input-domain") if sync.identity == active_start_sync_id else ())
              + (("output-domain", "contents") if sync.identity in next_sync_ids else ())),
        *(f"spx-bisimulation-allocation-entry-{kind}:{authored.operation_id}"
          for kind in ("input", "admission")
          if active_start_sync_id is None and authored.entry_allocation_history is not None),
        *(description for sync in authored.syncs
          if sync.identity == active_start_sync_id or sync.identity in next_sync_ids
          for description in byte_read_checks(sync)),
        *(f"spx-bisimulation-native-view-input:{sync.identity}:{capture.identity}"
          for sync in authored.syncs if sync.identity == active_start_sync_id
          for capture in sync.captures if capture.mode == "native_view"),
        *(input_owner_description(sync.identity, capture.identity)
          for sync in authored.syncs if sync.identity == active_start_sync_id
          for capture in sync.captures if capture.mode == "native_view"),
        *(f"spx-bisimulation-capture-reference-memory:{sync.identity}:{capture.identity}"
          for sync in authored.syncs if sync.identity in next_sync_ids
          for capture in sync.captures if capture.mode == 'native_view' and capture.kind == 'parameter'),
        *(f"spx-bisimulation-allocation-history-input:{sync.identity}"
          for sync in authored.syncs if sync.identity == active_start_sync_id and sync.allocation_history is not None),
        *(f"spx-bisimulation-private-stack-scope:{sync.identity}"
          for sync in authored.syncs if sync.identity in next_sync_ids
          and any(item.private_stack_scope is not None for item in authored.syncs)),
        *(f"spx-bisimulation-private-stack-scope-input:{sync.identity}"
          for sync in authored.syncs if sync.identity == active_start_sync_id and sync.private_stack_scope is not None),
        *(description for sync in authored.syncs
          for direction, active in (("input", sync.identity == active_start_sync_id),
                                    ("output", sync.identity in next_sync_ids)) if active
          for description in machine_fact_read_descriptions(sync, direction)),
        *connected_entry_assertions,
        *([MACHINE_STATE_DESCRIPTION, CUT_MACHINE_STATE_DESCRIPTION] if readable_machine_state else []),
        *([spec.description for spec in MUTABLE_MACHINE_FRAMES] if mutable_machine_state else []),
        *(continuation_assertions(authored.operation_id, proof_function) if continuation is not None else []),
        f"spx-bisimulation-shared-view-inputs:{authored.operation_id}:{proof_function}",
        f"spx-bisimulation-source-frame-preservation:{authored.operation_id}:{proof_function}",
        f"spx-bisimulation-exit-control:{authored.operation_id}:{proof_function}",
        f"spx-bisimulation-exit-target:{authored.operation_id}:{proof_function}",
        f"spx-bisimulation-exit-value:{authored.operation_id}:{proof_function}",
        f"spx-bisimulation-exit-continuation-state:{authored.operation_id}:{proof_function}",
        f"spx-bisimulation-exit-world-calls:{authored.operation_id}:{proof_function}",
        f"spx-bisimulation-exit-world-atomics:{authored.operation_id}:{proof_function}",
        f"spx-bisimulation-exit-world-memory:{authored.operation_id}:{proof_function}",
        *(
            f"spx-bisimulation-exit-observable:{authored.operation_id}:{row['id']}"
            for row in _exit_comparisons(logical_projection)
        ),
        *(
            f"spx-bisimulation-typed-call-fields:{position}"
            for position in typed_call_positions
        ),
        *(
            f"spx-bisimulation-typed-call-public-memory:{position}"
            for position in typed_call_positions
        ),
        *(
            f"spx-bisimulation-connected-summary-input:{summary_id}"
            for summary_id in connected_summary_ids
        ),
        *(
            f"spx-bisimulation-connected-summary-prefix:{summary_id}"
            for summary_id in connected_summary_ids
        ),
        *(
            f"spx-bisimulation-connected-summary-memory:{summary_id}"
            for summary_id in connected_summary_ids
        ),
    }
    if connected_summary_ids:
        descriptions.add(
            "spx-bisimulation-connected-summary-cardinality:"
            f"{authored.operation_id}:{proof_function}"
        )
    if authored.machine_clobbers:
        descriptions.update(spec.description for spec in clobber_specs(
            authored.machine_clobbers, result_registers(logical_projection)))
    if authored.private_stack_writes:
        from .bisimulation_private_frame import specs
        descriptions.update(spec.description for spec in specs(authored.private_stack_writes))
    if continuous_acyclic:
        descriptions.add(
            "spx-bisimulation-continuous-exact-internal-transfer:"
            f"{authored.operation_id}:{proof_function}"
        )
    for sync in authored.syncs:
        if sync.identity != active_start_sync_id and sync.identity not in next_sync_ids:
            descriptions.add(f"spx-bisimulation-unexpected-sync:{sync.identity}")
        if sync.identity not in next_sync_ids:
            continue
        descriptions.update(
            {
                f"spx-bisimulation-invariant:{sync.identity}",
                f"spx-bisimulation-world-calls:{sync.identity}",
                f"spx-bisimulation-world-atomics:{sync.identity}",
                f"spx-bisimulation-world-memory:{sync.identity}",
                f"spx-bisimulation-allocation-cut-admission:{sync.identity}",
                f"spx-bisimulation-world-connected-calls:{sync.identity}",
                f"spx-bisimulation-sync-alignment:{sync.identity}",
                *(
                    f"spx-bisimulation-capture:{sync.identity}:{capture.identity}"
                    for capture in sync.captures
                ),
                *(
                    f"spx-bisimulation-capture-roundtrip:{sync.identity}:{capture.identity}"
                    for capture in sync.captures
                    if capture.kind == "source_state" and capture.mode == "machine_codec"
                ),
                *(
                    f"spx-bisimulation-resumed-view-admission:{sync.identity}:{capture.identity}"
                    for capture in sync.captures
                    if _cut_view_domain(capture, state="spx_proof_exact_output",
                                        read="spx_proof_exact_output_read") is not None
                ),
                *(
                    f"spx-bisimulation-capture-{kind}:{sync.identity}:{capture.identity}"
                    for capture in sync.captures
                    if _captured_parameter_view(capture) is not None
                    for kind in ("reference-memory", "methods", "metadata", "context", "extent")
                ),
                *(
                    f"spx-bisimulation-derived:{sync.identity}:{derived.identity}"
                    for derived in sync.derived
                ),
            }
        )
    return sorted(descriptions)


def _semantic_contract_sha256(value: Mapping[str, object]) -> str:
    digest = value.get("contract_sha256")
    if not isinstance(digest, str):
        raise BisimulationRefinementError("semantic contract digest is absent")
    return digest


__all__ = [
    "BisimulationRefinementError",
    "build_typed_proof_service_thunk_renderer",
    "check_bisimulation_refinement",
]

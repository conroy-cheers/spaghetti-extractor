# ruff: noqa: F401
"""Deterministic execution closure over canonical transfer-v2 semantics."""

from __future__ import annotations

from dataclasses import dataclass, replace
import heapq
import json
from pathlib import Path
import resource
import time
from typing import Any, Iterable, Mapping, MutableMapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..boundary import BoundarySchemaV1, TargetDataLayoutV1
from ..calls.frame import PhysicalCallFrameV3
from ..semantic_objects.object_authority import MachineObjectAuthorityV2
from ..external.formats import RESOLVED_EXTERNAL_ENVIRONMENT_FORMAT
from ..pe32.behavioral_roots import load_behavioral_roots
from ..pe32.module_interface import Pe32ModuleInterfaceV2
from ..util import sha256_file, write_json
from .formats import MODULE_EXECUTION_CLOSURE_FORMAT
from .exception_semantics import CheckedExceptionTransitionV1
from .model import TransferPlanError, _Call, _REGISTERS, _Transfer
from .operations import NATIVE_EXCEPTION_EFFECTS_V2
from .plan import load_executable_transfer_plan
from .provenance import (
    BOUNDED_SCALAR_ALTERNATIVE_LIMIT_V1,
    BOTTOM_REFERENCE_V1,
    CONFLICT_REFERENCE_V1,
    ExternalCallbackRuleV1,
    ExternalCallRuleV1,
    ExternalMemoryWriteV1,
    ExternalOutPointerV1,
    ObjectRangeV1,
    ReferenceAtomV1,
    UNKNOWN_SCALAR_REFERENCE_V1,
    ReferenceCatalogV1,
    ReferenceStateV1,
    ReferenceValueV1,
    STACK_REFERENCE_ALTERNATIVE_LIMIT_V1,
    adjust_reference_by_constant_v1,
    apply_reference_effects_v1,
    call_parameter_owner_v1,
    captured_stack_owner_v1,
    call_argument_values_v1,
    finite_reference_value_v1,
    is_call_parameter_object_v1,
    instantiate_call_parameter_identity_v1,
    join_reference_values_v1,
    refine_reference_state_for_branch_v1,
)
from .reference_facts import encode_reference_index_set_v1


_OBSERVATIONAL_CLOSURE_METRICS_V1 = frozenset({
    "elapsed_milliseconds", "peak_rss_kib", "worklist_steps",
})

# This is a qualification bound rather than a semantic promise. Reachable
# checked state beyond it produces an explicit fail-closed blocker below.
OUTGOING_STACK_PROJECTION_BYTE_LIMIT_V1 = 4096


from .closure_model import (
    ExecutionClosureContextV1,
    ExecutionFunctionContextV1,
    execution_closure_context_with_roots_v1,
    _reference_state_kernel_payload_v1,
    _execution_closure_kernel_context_payload_v1,
    _boundary_reference_state_v1,
    _effect_summary_state_v1,
    _state_object_identities_v1,
    _implicit_memory_value_v1,
    _normalize_reference_memory_v1,
    _reference_states_equal_v1,
    join_reference_states_v1,
)
from .closure_calls import (
    _direct_successors,
    _reference_targets,
    _external_reference_targets,
    _reference_target_resolution_v1,
    _external_tail_return_state_v1,
    _call_targets,
    _external_call_targets,
    _call_target_resolution,
    _call_argument_values,
    _callback_targets,
    _callback_root_state,
    _stack_frame_identity_v1,
    _expire_stack_frame_value_v1,
    _call_parameter_identity_v1,
    _parameterizable_call_value_v1,
    _explicit_outgoing_stack_cells_v1,
    _outgoing_stack_projection_exceeds_limit_v1,
    _raw_outgoing_stack_projection_v1,
    _parameterized_call_inputs_v1,
    _instantiate_parameter_value_v1,
    _instantiate_parameter_key_v1,
    _instantiate_parameter_range_v1,
    _return_state_for_caller_v1,
    _callee_state,
    _transfer_rpo_priorities_v1,
)
from .closure_fixed_point import (
    build_module_execution_closure_v1,
)
from .closure_context import (
    _canonical_external_transport_v1,
    _external_write_authority_selector_v1,
    derive_execution_closure_context_v1,
    _root_reference_state_v1,
    _initial_image_storage_v1,
    _external_function_iat_memory_v1,
)

def _json_object(path: Path, context: str) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise TransferPlanError(
            f"cannot read {context}: {exc}",
            code="malformed_module_execution_closure_input",
        ) from exc
    if not isinstance(value, dict):
        raise TransferPlanError(
            f"{context} must be an object",
            code="malformed_module_execution_closure_input",
        )
    return value


def _compact_reference_facts_v1(
    states: Mapping[tuple[int, Any], ReferenceStateV1],
    transfers: Sequence[_Transfer],
) -> dict[str, Any]:
    """Summarize final reference states without serializing the state lattice."""

    transfer_by_rva = {transfer.rva_start: transfer for transfer in transfers}
    grouped: dict[tuple[int, int], dict[str, Any]] = {}

    def value_payloads(
        destination: dict[str, dict[str, dict[str, Any]]],
        rows: Mapping[str, Any],
    ) -> None:
        for identity, value in rows.items():
            payload = value.payload()
            destination.setdefault(identity, {})[
                canonical_sha256_v3(payload)
            ] = payload

    for (rva, function_context), state in sorted(states.items()):
        transfer = transfer_by_rva.get(rva)
        if transfer is None:
            raise TransferPlanError(
                "reference fact state lies outside the exact transfer universe",
                code="reference_fact_exact_universe_mismatch",
            )
        key = (rva, int(function_context.root_rva))
        fact = grouped.setdefault(key, {
            "unit_id": transfer.identity,
            "rva": rva,
            "root_rva": int(function_context.root_rva),
            "state_contexts": 0,
            "reference_atoms": set(),
            "callback_bindings": {},
            "relational_object_bindings": {},
            "written_memory_keys": set(),
            "invalidated_memory_ranges": set(),
            "all_memory_invalidated": False,
            "effect_invalidated_memory_ranges": set(),
            "effect_all_memory_invalidated": False,
            "possible_allocation_identities": set(),
            "all_preserve_inherited_memory": True,
            "any_preserve_inherited_memory": False,
        })
        fact["state_contexts"] += 1
        values = (
            *state.registers,
            *state.flags,
            *state.memory.values(),
            *state.call_registers,
            *state.call_flags,
            *state.callback_registry.values(),
            *state.relational_object_bindings.values(),
        )
        fact["reference_atoms"].update(
            reference for value in values for reference in value.references
        )
        value_payloads(fact["callback_bindings"], state.callback_registry)
        value_payloads(
            fact["relational_object_bindings"],
            state.relational_object_bindings,
        )
        fact["written_memory_keys"].update(state.written_memory_keys)
        fact["invalidated_memory_ranges"].update(
            state.invalidated_memory_ranges
        )
        fact["all_memory_invalidated"] |= state.all_memory_invalidated
        fact["effect_invalidated_memory_ranges"].update(
            state.effect_invalidated_memory_ranges
        )
        fact["effect_all_memory_invalidated"] |= (
            state.effect_all_memory_invalidated
        )
        fact["possible_allocation_identities"].update(
            state.possible_allocation_identities
        )
        fact["all_preserve_inherited_memory"] &= (
            state.preserves_inherited_memory
        )
        fact["any_preserve_inherited_memory"] |= (
            state.preserves_inherited_memory
        )

    atom_catalog = sorted({
        (atom.kind, atom.identity, atom.offset)
        for fact in grouped.values() for atom in fact["reference_atoms"]
    })
    binding_catalog_by_digest: dict[str, dict[str, Any]] = {}
    for fact in grouped.values():
        for field in ("callback_bindings", "relational_object_bindings"):
            for identity, values in fact[field].items():
                binding = {
                    "identity": identity,
                    "values": [
                        payload for _digest, payload in sorted(values.items())
                    ],
                }
                binding_catalog_by_digest[
                    canonical_sha256_v3(binding)
                ] = binding
    binding_catalog = [
        binding_catalog_by_digest[digest]
        for digest in sorted(binding_catalog_by_digest)
    ]
    key_catalog = sorted({
        row for fact in grouped.values()
        for row in fact["written_memory_keys"]
    })
    range_catalog = sorted({
        row for fact in grouped.values()
        for field in (
            "invalidated_memory_ranges",
            "effect_invalidated_memory_ranges",
        )
        for row in fact[field]
    })
    allocation_catalog = sorted({
        identity for fact in grouped.values()
        for identity in fact["possible_allocation_identities"]
    })
    atom_index = {row: index for index, row in enumerate(atom_catalog)}
    binding_index = {
        canonical_sha256_v3(row): index
        for index, row in enumerate(binding_catalog)
    }
    key_index = {row: index for index, row in enumerate(key_catalog)}
    range_index = {row: index for index, row in enumerate(range_catalog)}
    allocation_index = {
        row: index for index, row in enumerate(allocation_catalog)
    }
    indexed_facts = []
    for key in sorted(grouped):
        fact = grouped[key]
        binding_indices: dict[str, list[int]] = {}
        for field in ("callback_bindings", "relational_object_bindings"):
            indices: set[int] = set()
            for identity, values in fact[field].items():
                binding = {
                    "identity": identity,
                    "values": [
                        payload for _digest, payload in sorted(values.items())
                    ],
                }
                indices.add(binding_index[canonical_sha256_v3(binding)])
            binding_indices[field] = sorted(indices)
        indexed_facts.append({
            **{
                field: fact[field]
                for field in (
                    "unit_id", "rva", "root_rva", "state_contexts",
                    "all_memory_invalidated", "effect_all_memory_invalidated",
                    "all_preserve_inherited_memory",
                    "any_preserve_inherited_memory",
                )
            },
            "reference_atom_indices": encode_reference_index_set_v1(sorted({
                atom_index[(row.kind, row.identity, row.offset)]
                for row in fact["reference_atoms"]
            })),
            "callback_binding_indices": encode_reference_index_set_v1(
                binding_indices["callback_bindings"]
            ),
            "relational_object_binding_indices": encode_reference_index_set_v1(
                binding_indices["relational_object_bindings"]
            ),
            "written_memory_key_indices": encode_reference_index_set_v1(sorted({
                key_index[row]
                for row in fact["written_memory_keys"]
            })),
            "invalidated_memory_range_indices": encode_reference_index_set_v1(sorted({
                range_index[row]
                for row in fact["invalidated_memory_ranges"]
            })),
            "effect_invalidated_memory_range_indices": encode_reference_index_set_v1(sorted({
                range_index[row]
                for row in fact["effect_invalidated_memory_ranges"]
            })),
            "possible_allocation_identity_indices": encode_reference_index_set_v1(sorted({
                allocation_index[row]
                for row in fact["possible_allocation_identities"]
            })),
        })
    return {
        "catalog": {
            "reference_atoms": [
                {"kind": kind, "identity": identity, "offset": offset}
                for kind, identity, offset in atom_catalog
            ],
            "bindings": binding_catalog,
            "memory_keys": [
                {
                    "kind": kind, "identity": identity,
                    "offset": offset, "width": width,
                }
                for kind, identity, offset, width in key_catalog
            ],
            "memory_ranges": [
                {
                    "kind": kind, "identity": identity,
                    "start": start, "end": end,
                }
                for kind, identity, start, end in range_catalog
            ],
            "allocation_identities": allocation_catalog,
        },
        "facts": indexed_facts,
    }


def _native_module_execution_closure_v1(
    *, transfer_plan: Path, context: ExecutionClosureContextV1,
) -> dict[str, Any]:
    """Run the sole production closure kernel over canonical transfer-v2.

    The returned authority artifact is deterministic.  Wall-clock and process
    observations belong to a separate veto-only performance check and must not
    enter a content-addressed receipt.
    """

    closure, _observations = _observed_native_module_execution_closure_v1(
        transfer_plan=transfer_plan,
        context=context,
    )
    return closure


def _native_semantic_link_kernel_v1(
    *, transfer_plan: Path, context: ExecutionClosureContextV1,
    semantic_link_input: Mapping[str, Any] | None,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any] | None]:
    """Run one native fixed point and its optional private semantic link."""

    try:
        import spaghetti_extractor_transfer_native as native
    except ImportError as exc:
        raise TransferPlanError(
            "the native semantic-link closure kernel is unavailable",
            code="native_module_execution_closure_unavailable",
        ) from exc
    evaluator = getattr(native, "evaluate_semantic_link_closure_receipt", None)
    if evaluator is None:
        raise TransferPlanError(
            "the native closure kernel lacks semantic-link provenance",
            code="native_module_execution_closure_unavailable",
        )
    plan_path = Path(transfer_plan)
    context_bytes = json.dumps(
        _execution_closure_kernel_context_payload_v1(context),
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    semantic_link_bytes = (
        b"null" if semantic_link_input is None else json.dumps(
            dict(semantic_link_input), separators=(",", ":"), sort_keys=True,
        ).encode("utf-8")
    )
    try:
        combined = json.loads(evaluator(
            plan_path.read_bytes(), context_bytes, semantic_link_bytes,
        ))
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        raise TransferPlanError(
            f"native semantic-link closure evaluation failed: {exc}",
            code="native_module_execution_closure_failed",
        ) from exc
    if not isinstance(combined, dict):
        raise TransferPlanError(
            "native semantic-link closure returned a non-object",
            code="native_module_execution_closure_failed",
        )
    closure = combined.get("closure")
    edge_rows = combined.get("edge_root_provenance")
    semantic_link = combined.get("semantic_link")
    if not isinstance(closure, dict) or not isinstance(edge_rows, list):
        raise TransferPlanError(
            "native semantic-link closure omitted its projections",
            code="native_module_execution_closure_failed",
        )
    metrics = closure.get("metrics")
    if not isinstance(metrics, dict):
        raise TransferPlanError(
            "native semantic-link closure omitted metrics",
            code="native_module_execution_closure_failed",
        )
    metrics["elapsed_milliseconds"] = 0
    metrics["peak_rss_kib"] = 0
    validate_module_execution_closure_v1(closure)
    normalized_edges: list[dict[str, Any]] = []
    previous: tuple[int, int, str] | None = None
    for raw in edge_rows:
        if not isinstance(raw, dict):
            raise TransferPlanError(
                "semantic-link edge provenance row is malformed",
                code="native_module_execution_closure_failed",
            )
        source_rva = raw.get("source_rva")
        target_rva = raw.get("target_rva")
        kind = raw.get("kind")
        roots = raw.get("root_rvas")
        if (
            not isinstance(source_rva, int) or isinstance(source_rva, bool)
            or not isinstance(target_rva, int) or isinstance(target_rva, bool)
            or not isinstance(kind, str) or not kind
            or not isinstance(roots, list)
            or any(
                not isinstance(root, int) or isinstance(root, bool) or root < 0
                for root in roots
            )
            or roots != sorted(set(roots))
            or not roots
        ):
            raise TransferPlanError(
                "semantic-link edge provenance row is malformed",
                code="native_module_execution_closure_failed",
            )
        identity = (source_rva, target_rva, kind)
        if previous is not None and identity <= previous:
            raise TransferPlanError(
                "semantic-link edge provenance is noncanonical",
                code="native_module_execution_closure_failed",
            )
        previous = identity
        normalized_edges.append(dict(raw))
    if [
        {
            "source_rva": row["source_rva"],
            "target_rva": row["target_rva"],
            "kind": row["kind"],
        }
        for row in normalized_edges
    ] != closure["reachable_edges"]:
        raise TransferPlanError(
            "semantic-link edge provenance contradicts the closure",
            code="native_module_execution_closure_failed",
        )
    if semantic_link_input is None:
        if semantic_link is not None:
            raise TransferPlanError(
                "native semantic-link closure returned an unsolicited link projection",
                code="native_module_execution_closure_failed",
            )
    elif not isinstance(semantic_link, dict):
        raise TransferPlanError(
            "native semantic-link closure omitted its link projection",
            code="native_module_execution_closure_failed",
        )
    return closure, normalized_edges, semantic_link


def _native_semantic_link_closure_v1(
    *, transfer_plan: Path, context: ExecutionClosureContextV1,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Run one native fixed point and retain exact edge-root witnesses."""

    closure, edges, semantic_link = _native_semantic_link_kernel_v1(
        transfer_plan=transfer_plan,
        context=context,
        semantic_link_input=None,
    )
    if semantic_link is not None:
        raise AssertionError("closure-only semantic kernel returned link facts")
    return closure, edges


def _observed_native_module_execution_closure_v1(
    *, transfer_plan: Path, context: ExecutionClosureContextV1,
) -> tuple[dict[str, Any], dict[str, int]]:
    """Evaluate the native kernel and return non-authorizing observations."""

    try:
        import spaghetti_extractor_transfer_native as native
    except ImportError as exc:
        raise TransferPlanError(
            "the native execution-closure kernel is unavailable",
            code="native_module_execution_closure_unavailable",
        ) from exc
    evaluator = getattr(native, "evaluate_reference_closure_receipt", None)
    if evaluator is None:
        raise TransferPlanError(
            "the native execution-closure kernel is missing its receipt API",
            code="native_module_execution_closure_unavailable",
        )
    plan_path = Path(transfer_plan)
    context_bytes = json.dumps(
        _execution_closure_kernel_context_payload_v1(context),
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    started = time.monotonic()
    usage_before = resource.getrusage(resource.RUSAGE_SELF)
    try:
        encoded = evaluator(plan_path.read_bytes(), context_bytes)
        closure = json.loads(encoded)
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        raise TransferPlanError(
            f"native execution-closure evaluation failed: {exc}",
            code="native_module_execution_closure_failed",
        ) from exc
    if not isinstance(closure, dict):
        raise TransferPlanError(
            "native execution-closure evaluation returned a non-object",
            code="native_module_execution_closure_failed",
        )
    metrics = closure.get("metrics")
    if not isinstance(metrics, dict):
        raise TransferPlanError(
            "native execution-closure evaluation omitted metrics",
            code="native_module_execution_closure_failed",
        )
    usage_after = resource.getrusage(resource.RUSAGE_SELF)
    observations = {
        "wall_milliseconds": int((time.monotonic() - started) * 1000),
        "cpu_milliseconds": int(
            (
                usage_after.ru_utime
                + usage_after.ru_stime
                - usage_before.ru_utime
                - usage_before.ru_stime
            )
            * 1000
        ),
        "peak_rss_kib": int(usage_after.ru_maxrss),
    }
    metrics["elapsed_milliseconds"] = 0
    metrics["peak_rss_kib"] = 0
    validate_module_execution_closure_v1(closure)
    return closure, observations


def benchmark_native_module_execution_closure_v1(
    *, transfer_plan: Path, context: ExecutionClosureContextV1,
) -> tuple[dict[str, Any], dict[str, int]]:
    """Return a deterministic receipt plus veto-only process observations."""

    return _observed_native_module_execution_closure_v1(
        transfer_plan=transfer_plan,
        context=context,
    )


def check_python_reference_closure_parity_v1(
    *,
    transfer_plan: Path,
    context: ExecutionClosureContextV1,
    native_receipt: Mapping[str, Any],
    native_edge_root_provenance: Sequence[Mapping[str, Any]] | None = None,
    native_reference_facts: Mapping[str, Any] | None = None,
) -> None:
    """Veto a native closure that diverges from the Python reference evaluator.

    Both evaluators consume the same validated transfer plan.  Timing, memory,
    and worklist scheduling are observations rather than semantic fields, so
    only those metrics are excluded from the comparison.
    """

    plan_path = Path(transfer_plan)
    _payload, transfers = load_executable_transfer_plan(
        plan_path, require_complete=True
    )
    diagnostic_edge_roots: dict[tuple[int, int, str], set[int]] = {}
    diagnostic_states: dict[tuple[int, Any], ReferenceStateV1] | None = (
        {} if native_reference_facts is not None else None
    )
    reference = build_module_execution_closure_v1(
        transfer_plan_sha256=sha256_file(plan_path),
        transfers=transfers,
        context=context,
        diagnostic_states=diagnostic_states,
        diagnostic_edge_roots=diagnostic_edge_roots,
    )
    validate_module_execution_closure_v1(native_receipt)

    def semantic(payload: Mapping[str, Any]) -> dict[str, Any]:
        metrics = payload.get("metrics")
        assert isinstance(metrics, Mapping)
        return {
            **dict(payload),
            "metrics": {
                key: value for key, value in metrics.items()
                if key not in _OBSERVATIONAL_CLOSURE_METRICS_V1
            },
        }

    if semantic(reference) != semantic(native_receipt):
        raise TransferPlanError(
            "native execution closure contradicts the Python reference evaluator",
            code="reference_execution_closure_semantic_divergence",
        )
    if native_edge_root_provenance is not None:
        expected_edge_root_provenance = [
            {
                "source_rva": source_rva,
                "target_rva": target_rva,
                "kind": kind,
                "root_rvas": sorted(diagnostic_edge_roots[
                    (source_rva, target_rva, kind)
                ]),
            }
            for source_rva, target_rva, kind in sorted(diagnostic_edge_roots)
        ]
        if [dict(row) for row in native_edge_root_provenance] != (
            expected_edge_root_provenance
        ):
            raise TransferPlanError(
                "native semantic edge provenance contradicts the Python "
                "reference evaluator",
                code="reference_semantic_edge_provenance_divergence",
            )
    if native_reference_facts is not None:
        assert diagnostic_states is not None
        expected_reference_facts = _compact_reference_facts_v1(
            diagnostic_states, transfers
        )
        if dict(native_reference_facts) != expected_reference_facts:
            native_catalog = native_reference_facts.get("catalog")
            expected_catalog = expected_reference_facts["catalog"]
            mismatch = "top-level reference facts differ"
            if isinstance(native_catalog, Mapping):
                for field in sorted(expected_catalog):
                    native_rows = native_catalog.get(field)
                    expected_rows = expected_catalog[field]
                    if native_rows != expected_rows:
                        mismatch = (
                            f"catalog {field} differs: native_sha256="
                            f"{canonical_sha256_v3(native_rows)} "
                            f"python_sha256={canonical_sha256_v3(expected_rows)}"
                        )
                        break
                else:
                    native_facts = native_reference_facts.get("facts")
                    expected_facts = expected_reference_facts["facts"]
                    if (
                        isinstance(native_facts, list)
                        and len(native_facts) == len(expected_facts)
                    ):
                        for native_fact, expected_fact in zip(
                            native_facts, expected_facts, strict=True
                        ):
                            if native_fact != expected_fact:
                                fields = sorted(
                                    set(native_fact) | set(expected_fact)
                                ) if isinstance(
                                    native_fact, Mapping
                                ) and isinstance(
                                    expected_fact, Mapping
                                ) else []
                                field = next((
                                    name for name in fields
                                    if native_fact.get(name)
                                    != expected_fact.get(name)
                                ), "unknown")
                                mismatch = (
                                    f"fact rva={expected_fact.get('rva')} "
                                    f"root_rva={expected_fact.get('root_rva')} "
                                    f"field={field} differs: native_sha256="
                                    f"{canonical_sha256_v3(native_fact.get(field))} "
                                    f"python_sha256="
                                    f"{canonical_sha256_v3(expected_fact.get(field))}"
                                )
                                break
                    else:
                        mismatch = (
                            "reference fact counts differ: "
                            f"native={len(native_facts) if isinstance(native_facts, list) else 'malformed'} "
                            f"python={len(expected_facts)}"
                        )
            raise TransferPlanError(
                "native semantic reference facts contradict the Python "
                f"reference evaluator: {mismatch}",
                code="reference_semantic_reference_fact_divergence",
            )


def write_module_execution_closure_v1(
    *, transfer_plan: Path, context: ExecutionClosureContextV1, out: Path,
) -> dict[str, Any]:
    payload, _transfers = load_executable_transfer_plan(
        Path(transfer_plan), require_complete=True
    )
    return write_bound_module_execution_closure_v1(
        transfer_plan=transfer_plan,
        runtime_provider_requirements=tuple(
            payload["runtime_provider_requirements"]
        ),
        context=context,
        out=out,
    )


def write_bound_module_execution_closure_v1(
    *, transfer_plan: Path, runtime_provider_requirements: Sequence[str],
    context: ExecutionClosureContextV1, out: Path,
) -> dict[str, Any]:
    """Evaluate a transfer member already validated by its enclosing object.

    The native kernel still parses and validates the serialized transfer plan.
    This entry point avoids constructing a redundant Python transfer model when
    a checked semantic object has already supplied the exact provider binding.
    """

    expected_providers = tuple(runtime_provider_requirements)
    if context.runtime_provider_requirements != expected_providers:
        raise TransferPlanError(
            "execution closure runtime providers contradict the transfer plan",
            code="stale_module_execution_closure",
        )
    closure = _native_module_execution_closure_v1(
        transfer_plan=Path(transfer_plan), context=context,
    )
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "module-execution-closure.json", closure)
    return closure


def write_bound_semantic_link_closure_v1(
    *, transfer_plan: Path, runtime_provider_requirements: Sequence[str],
    context: ExecutionClosureContextV1, out: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Write closure-v2 and return its same-pass semantic edge witnesses."""

    expected_providers = tuple(runtime_provider_requirements)
    if context.runtime_provider_requirements != expected_providers:
        raise TransferPlanError(
            "semantic-link closure providers contradict the transfer plan",
            code="stale_module_execution_closure",
        )
    closure, edge_root_provenance = _native_semantic_link_closure_v1(
        transfer_plan=Path(transfer_plan), context=context,
    )
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "module-execution-closure.json", closure)
    return closure, edge_root_provenance


def write_bound_semantic_link_kernel_v1(
    *, transfer_plan: Path, runtime_provider_requirements: Sequence[str],
    context: ExecutionClosureContextV1,
    semantic_link_input: Mapping[str, Any], out: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    """Write closure-v2 and return same-pass native semantic-link facts."""

    expected_providers = tuple(runtime_provider_requirements)
    if context.runtime_provider_requirements != expected_providers:
        raise TransferPlanError(
            "semantic-link kernel providers contradict the transfer plan",
            code="stale_module_execution_closure",
        )
    closure, edge_root_provenance, semantic_link = (
        _native_semantic_link_kernel_v1(
            transfer_plan=Path(transfer_plan),
            context=context,
            semantic_link_input=semantic_link_input,
        )
    )
    if semantic_link is None:
        raise TransferPlanError(
            "native semantic-link kernel omitted its link facts",
            code="native_module_execution_closure_failed",
        )
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "module-execution-closure.json", closure)
    return closure, edge_root_provenance, semantic_link


def check_module_execution_closure_v1(
    payload: Mapping[str, Any],
    *, transfer_plan: Path, context: ExecutionClosureContextV1,
) -> None:
    validate_module_execution_closure_v1(payload)
    transfer_payload, _transfers = load_executable_transfer_plan(
        Path(transfer_plan), require_complete=True
    )
    if context.runtime_provider_requirements != tuple(
        transfer_payload["runtime_provider_requirements"]
    ):
        raise TransferPlanError(
            "execution closure runtime providers contradict the transfer plan",
            code="stale_module_execution_closure",
        )
    expected = _native_module_execution_closure_v1(
        transfer_plan=Path(transfer_plan), context=context,
    )
    observed = dict(payload)
    expected = {
        **expected,
        "metrics": {
            key: item for key, item in expected["metrics"].items()
            if key not in _OBSERVATIONAL_CLOSURE_METRICS_V1
        },
    }
    observed = {
        **observed,
        "metrics": {
            key: item for key, item in observed["metrics"].items()
            if key not in _OBSERVATIONAL_CLOSURE_METRICS_V1
        },
    }
    if observed != expected:
        raise TransferPlanError(
            "module execution closure does not replay from its exact inputs",
            code="stale_module_execution_closure",
        )


def validate_module_execution_closure_v1(payload: Mapping[str, Any]) -> None:
    """Validate receipt identity and closed-world invariants without replay."""

    malformed = lambda message: TransferPlanError(
        message, code="malformed_module_execution_closure"
    )
    expected_fields = {
        "format", "status", "authorizes_execution", "bindings", "roots",
        "reachable_units", "reachable_edges", "indirect_targets",
        "external_contracts", "runtime_providers", "callback_escapes",
        "exception_continuations", "nonlocal_transitions",
        "lifecycle_effects", "witnesses",
        "blockers", "metrics", "analysis_policy", "authority",
        "closure_sha256",
    }
    if set(payload) != expected_fields:
        raise malformed("module execution closure fields are incomplete")
    if payload.get("format") != MODULE_EXECUTION_CLOSURE_FORMAT:
        raise malformed("module execution closure format is unsupported")
    blockers = payload.get("blockers")
    status = payload.get("status")
    authorizes = payload.get("authorizes_execution")
    if (
        not isinstance(blockers, list)
        or any(
            not isinstance(row, Mapping) or not isinstance(row.get("code"), str)
            for row in blockers
        )
        or status not in {"complete", "incomplete"}
        or not isinstance(authorizes, bool)
        or (status == "complete") != (not blockers)
        or authorizes != (not blockers)
    ):
        raise malformed("module execution closure authority state is inconsistent")
    canonical_blockers = sorted(
        {canonical_sha256_v3(dict(row)): dict(row) for row in blockers}.values(),
        key=canonical_sha256_v3,
    )
    if blockers != canonical_blockers:
        raise malformed(
            "module execution closure blockers are duplicated or noncanonical"
        )
    bindings = payload.get("bindings")
    if (
        not isinstance(bindings, Mapping)
        or "executable_transfer_plan_sha256" not in bindings
        or any(
            not isinstance(key, str)
            or not isinstance(value, str)
            or len(value) != 64
            for key, value in bindings.items()
        )
    ):
        raise malformed("module execution closure bindings are malformed")
    roots = payload.get("roots")
    units = payload.get("reachable_units")
    edges = payload.get("reachable_edges")
    indirect = payload.get("indirect_targets")
    external_contracts = payload.get("external_contracts")
    runtime_providers = payload.get("runtime_providers")
    callback_escapes = payload.get("callback_escapes")
    exception_continuations = payload.get("exception_continuations")
    nonlocal_transitions = payload.get("nonlocal_transitions")
    lifecycle_effects = payload.get("lifecycle_effects")
    witnesses = payload.get("witnesses")
    metrics = payload.get("metrics")
    analysis_policy = payload.get("analysis_policy")
    if not all(isinstance(value, list) for value in (
        roots, units, edges, indirect, external_contracts, runtime_providers,
        callback_escapes, exception_continuations, nonlocal_transitions,
        lifecycle_effects,
        witnesses,
    )) or not isinstance(metrics, Mapping):
        raise malformed("module execution closure inventory is malformed")
    if (
        not isinstance(analysis_policy, Mapping)
        or set(analysis_policy) != {
            "reference_alternative_limit",
            "call_string_limit",
            "maximum_worklist_steps",
            "boundary_exit_rvas",
        }
        or not isinstance(analysis_policy.get("boundary_exit_rvas"), list)
        or any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in analysis_policy.get("boundary_exit_rvas", [])
        )
        or analysis_policy["boundary_exit_rvas"]
        != sorted(set(analysis_policy["boundary_exit_rvas"]))
    ):
        raise malformed("module execution closure analysis policy is malformed")
    boundary_exit_rvas = set(analysis_policy["boundary_exit_rvas"])
    if any(not isinstance(root, int) or root < 0 for root in roots):
        raise malformed("module execution closure roots are malformed")
    if len(set(roots)) != len(roots):
        raise malformed("module execution closure roots are duplicate")
    unit_rvas: set[int] = set()
    unit_ids: set[str] = set()
    unit_id_by_rva: dict[int, str] = {}
    for row in units:
        if (
            not isinstance(row, Mapping)
            or not isinstance(row.get("rva"), int)
            or row["rva"] < 0
            or not isinstance(row.get("unit_id"), str)
            or row["rva"] in unit_rvas
            or row["unit_id"] in unit_ids
        ):
            raise malformed("module execution closure reachable units are malformed")
        unit_rvas.add(row["rva"])
        unit_ids.add(row["unit_id"])
        unit_id_by_rva[row["rva"]] = row["unit_id"]
    if not set(roots) <= unit_rvas:
        raise malformed("module execution closure omits a root")
    for row in edges:
        if (
            not isinstance(row, Mapping)
            or row.get("source_rva") not in unit_rvas
            or not isinstance(row.get("target_rva"), int)
            or not isinstance(row.get("kind"), str)
            or (status == "complete" and row["target_rva"] not in unit_rvas)
        ):
            raise malformed("module execution closure edges are malformed")
    for row in indirect:
        if (
            not isinstance(row, Mapping)
            or row.get("source_rva") not in unit_rvas
            or not isinstance(row.get("site"), str)
            or not isinstance(row.get("provenance"), list)
            or (
                row.get("targets") is not None
                and not isinstance(row.get("targets"), list)
            )
            or (
                row.get("external_targets") is not None
                and not isinstance(row.get("external_targets"), list)
            )
        ):
            raise malformed("module execution closure indirect targets are malformed")
        if status == "complete" and any(
            not isinstance(target, int)
            or (
                target not in unit_rvas
                and row.get("source_rva") not in boundary_exit_rvas
            )
            for target in row.get("targets", [])
        ):
            raise malformed("module execution closure indirect target is not reachable")
    external_keys: list[tuple[str, str]] = []
    for row in external_contracts:
        if (
            not isinstance(row, Mapping)
            or set(row) != {"dll", "identity"}
            or not isinstance(row.get("dll"), str)
            or not row["dll"]
            or not isinstance(row.get("identity"), str)
            or not row["identity"]
        ):
            raise malformed(
                "module execution closure external contracts are malformed"
            )
        external_keys.append((row["dll"], row["identity"]))
    if external_keys != sorted(set(external_keys)):
        raise malformed(
            "module execution closure external contracts are noncanonical"
        )
    if (
        any(not isinstance(item, str) or not item for item in runtime_providers)
        or runtime_providers != sorted(set(runtime_providers))
    ):
        raise malformed(
            "module execution closure runtime providers are noncanonical"
        )
    callback_keys: list[tuple[int, str, str, str]] = []
    callback_fields = {
        "instruction_rva", "dll", "identity", "protocol_id", "targets",
        "action", "lifetime", "delivery",
    }
    for row in callback_escapes:
        delivery = row.get("delivery") if isinstance(row, Mapping) else None
        targets = row.get("targets") if isinstance(row, Mapping) else None
        if (
            not isinstance(row, Mapping)
            or set(row) != callback_fields
            or not isinstance(row.get("instruction_rva"), int)
            or isinstance(row.get("instruction_rva"), bool)
            or row["instruction_rva"] < 0
            or any(
                not isinstance(row.get(field), str) or not row[field]
                for field in ("dll", "identity", "protocol_id", "action", "lifetime")
            )
            or not isinstance(delivery, Mapping)
            or set(delivery) != {"thread", "timing"}
            or any(
                not isinstance(delivery.get(field), str) or not delivery[field]
                for field in ("thread", "timing")
            )
            or (
                targets is not None
                and (
                    not isinstance(targets, list)
                    or any(
                        not isinstance(target, int) or isinstance(target, bool)
                        or target < 0
                        for target in targets
                    )
                    or targets != sorted(set(targets))
                )
            )
        ):
            raise malformed(
                "module execution closure callback escapes are malformed"
            )
        callback_keys.append((
            row["instruction_rva"], row["dll"], row["identity"],
            row["protocol_id"],
        ))
        if status == "complete" and targets is None:
            raise malformed(
                "complete module execution closure has an unresolved callback escape"
            )
        if isinstance(targets, list) and any(target not in unit_rvas for target in targets):
            raise malformed(
                "module execution closure callback target is not reachable"
            )
    if callback_keys != sorted(set(callback_keys)):
        raise malformed(
            "module execution closure callback escapes are noncanonical"
        )
    effect_root_rvas = set(roots) | {
        target
        for row in callback_escapes
        for target in (row.get("targets") or [])
        if isinstance(target, int) and not isinstance(target, bool)
    }
    exception_keys: list[tuple[int, int, str]] = []
    exception_fields = {
        "unit_id", "source_rva", "effect_index", "fault_index",
        "fault_sha256", "transition_id", "transition_sha256", "operation",
        "occurrence_kind", "call_index",
        "disposition", "handler_unit_id", "handler_rva",
        "resumption_unit_id", "resumption_rva", "unwind_unit_ids",
        "state_projection", "guard",
        "root_rvas",
    }
    exception_projection_fields = {
        "registers", "flags", "x87", "stack", "exception_record", "context",
    }
    for row in exception_continuations:
        handler_unit_id = row.get("handler_unit_id") if isinstance(
            row, Mapping
        ) else None
        handler_rva = row.get("handler_rva") if isinstance(row, Mapping) else None
        resumption_unit_id = row.get("resumption_unit_id") if isinstance(
            row, Mapping
        ) else None
        resumption_rva = row.get("resumption_rva") if isinstance(
            row, Mapping
        ) else None
        unwind_unit_ids = row.get("unwind_unit_ids") if isinstance(
            row, Mapping
        ) else None
        state_projection = row.get("state_projection") if isinstance(
            row, Mapping
        ) else None
        handled = isinstance(row, Mapping) and row.get("disposition") == "handled"
        checked_escape = (
            isinstance(row, Mapping)
            and row.get("disposition") == "terminates"
            and resumption_unit_id is not None
        )
        if (
            not isinstance(row, Mapping)
            or set(row) != exception_fields
            or row.get("unit_id") != unit_id_by_rva.get(row.get("source_rva"))
            or not isinstance(row.get("effect_index"), int)
            or isinstance(row.get("effect_index"), bool)
            or row["effect_index"] < 0
            or not isinstance(row.get("fault_index"), int)
            or isinstance(row.get("fault_index"), bool)
            or row["fault_index"] < 0
            or not isinstance(row.get("fault_sha256"), str)
            or len(row["fault_sha256"]) != 64
            or not isinstance(row.get("transition_id"), str)
            or not row["transition_id"].startswith("exceptional-transition-v3:")
            or not isinstance(row.get("transition_sha256"), str)
            or len(row["transition_sha256"]) != 64
            or any(
                character not in "0123456789abcdef"
                for character in row["transition_sha256"]
            )
            or row.get("operation") not in NATIVE_EXCEPTION_EFFECTS_V2
            or row.get("occurrence_kind") not in {"effect", "call"}
            or (
                (row.get("occurrence_kind") == "call")
                != (
                    isinstance(row.get("call_index"), int)
                    and not isinstance(row.get("call_index"), bool)
                    and row["call_index"] >= 0
                )
            )
            or row.get("disposition") not in {
                "handled", "infeasible", "terminates",
            }
            or row.get("guard") is None
            or not isinstance(row.get("root_rvas"), list)
            or row["root_rvas"] != sorted(set(row["root_rvas"]))
            or any(root not in effect_root_rvas for root in row["root_rvas"])
            or not row["root_rvas"]
            or handled != isinstance(handler_unit_id, str)
            or handled != isinstance(handler_rva, int)
            or (handled and unit_id_by_rva.get(handler_rva) != handler_unit_id)
            or (resumption_unit_id is None) != (resumption_rva is None)
            or (
                resumption_unit_id is not None
                and not (handled or checked_escape)
            )
            or (
                resumption_unit_id is not None
                and not isinstance(resumption_unit_id, str)
            )
            or (
                isinstance(resumption_unit_id, str)
                and (
                    not isinstance(resumption_rva, int)
                    or unit_id_by_rva.get(resumption_rva)
                    != resumption_unit_id
                )
            )
            or not isinstance(unwind_unit_ids, list)
            or any(
                not isinstance(identity, str) or not identity
                for identity in unwind_unit_ids
            )
            or len(set(unwind_unit_ids)) != len(unwind_unit_ids)
            or (not handled and bool(unwind_unit_ids))
            or (
                not (handled or checked_escape)
                and state_projection is not None
            )
            or (
                state_projection is not None
                and (
                    not isinstance(state_projection, Mapping)
                    or set(state_projection) != exception_projection_fields
                    or any(
                        not isinstance(values, list)
                        or values != sorted(set(values))
                        or any(
                            not isinstance(value, str) or not value
                            for value in values
                        )
                        for values in state_projection.values()
                    )
                )
            )
            or (
                status == "complete"
                and any(identity not in set(unit_id_by_rva.values())
                        for identity in unwind_unit_ids)
            )
        ):
            raise malformed(
                "module execution closure exception continuations are malformed"
            )
        exception_keys.append((
            row["source_rva"], row["effect_index"], row["operation"]
        ))
    if exception_keys != sorted(set(exception_keys)):
        raise malformed(
            "module execution closure exception continuations are noncanonical"
        )
    nonlocal_ids: list[str] = []
    nonlocal_fields = {
        "id", "source_unit_id", "source_rva", "source_context_id",
        "root_rva", "target_unit_id", "target_rva", "target_context_id",
        "target_function_entry_rva", "abandoned_frame_ids", "value",
        "cleanup",
    }
    reference_kinds = {
        "object", "object_view", "guest_code", "external_function",
        "loader_module",
    }
    for row in nonlocal_transitions:
        value = row.get("value") if isinstance(row, Mapping) else None
        cleanup = row.get("cleanup") if isinstance(row, Mapping) else None
        abandoned = (
            row.get("abandoned_frame_ids")
            if isinstance(row, Mapping) else None
        )
        transition_id = row.get("id") if isinstance(row, Mapping) else None
        core = (
            {key: item for key, item in row.items() if key != "id"}
            if isinstance(row, Mapping) else {}
        )
        scalars = value.get("scalars") if isinstance(value, Mapping) else None
        references = (
            value.get("references") if isinstance(value, Mapping) else None
        )
        canonical_references = []
        if isinstance(references, list):
            for reference in references:
                if not isinstance(reference, Mapping):
                    canonical_references = []
                    break
                canonical_references.append((
                    reference.get("kind"), reference.get("identity"),
                    reference.get("offset"),
                ))
        value_kind = value.get("kind") if isinstance(value, Mapping) else None
        finite_value = value_kind == "finite"
        value_shape_valid = (
            isinstance(scalars, list)
            and all(
                isinstance(scalar, int)
                and not isinstance(scalar, bool)
                and 0 <= scalar <= 0xFFFF_FFFF
                for scalar in scalars
            )
            and scalars == sorted(set(scalars))
            and isinstance(references, list)
            and all(
                isinstance(reference, Mapping)
                and set(reference) == {"kind", "identity", "offset"}
                and reference.get("kind") in reference_kinds
                and isinstance(reference.get("identity"), str)
                and bool(reference["identity"])
                and isinstance(reference.get("offset"), int)
                and not isinstance(reference.get("offset"), bool)
                and not (
                    reference.get("kind") == "object_view"
                    and reference.get("offset") != 0
                )
                for reference in references
            )
            and canonical_references == sorted(set(canonical_references))
            and (
                (finite_value and bool(scalars or references))
                or (
                    not finite_value
                    and not scalars
                    and not references
                )
            )
        )
        if (
            not isinstance(row, Mapping)
            or set(row) != nonlocal_fields
            or not isinstance(transition_id, str)
            or transition_id != (
                "checked-nonlocal-transition-v1:" + canonical_sha256_v3(core)
            )
            or row.get("source_unit_id")
            != unit_id_by_rva.get(row.get("source_rva"))
            or row.get("target_unit_id")
            != unit_id_by_rva.get(row.get("target_rva"))
            or row.get("root_rva") not in effect_root_rvas
            or not isinstance(row.get("source_context_id"), str)
            or not row["source_context_id"].startswith("execution-context:")
            or not isinstance(row.get("target_context_id"), str)
            or not row["target_context_id"].startswith("execution-context:")
            or not isinstance(row.get("target_function_entry_rva"), int)
            or row["target_function_entry_rva"] not in unit_rvas
            or not isinstance(abandoned, list)
            or not abandoned
            or len(set(abandoned)) != len(abandoned)
            or any(
                not isinstance(identity, str)
                or not identity.startswith(
                    "captured_stack_frame:execution-context:"
                )
                for identity in abandoned
            )
            or not isinstance(value, Mapping)
            or set(value) != {"kind", "scalars", "references"}
            or value_kind not in {
                "bottom", "finite", "unknown_scalar", "conflict",
            }
            or not value_shape_valid
            or not isinstance(cleanup, Mapping)
            or set(cleanup) != {"kind", "unwind_unit_ids"}
            or cleanup.get("kind") != "expire_abandoned_stack_frames"
            or cleanup.get("unwind_unit_ids") != []
        ):
            raise malformed(
                "module execution closure nonlocal transitions are malformed"
            )
        nonlocal_ids.append(transition_id)
    if (
        len(set(nonlocal_ids)) != len(nonlocal_ids)
        or nonlocal_transitions != sorted(
            nonlocal_transitions, key=canonical_sha256_v3
        )
    ):
        raise malformed(
            "module execution closure nonlocal transitions are noncanonical"
        )
    lifecycle_keys: list[tuple[int, str, str, str]] = []
    for row in lifecycle_effects:
        if (
            not isinstance(row, Mapping)
            or set(row) != {"kind", "source_rva", "dll", "identity"}
            or row.get("kind") != "external_termination"
            or row.get("source_rva") not in unit_rvas
            or not isinstance(row.get("dll"), str)
            or not row["dll"]
            or not isinstance(row.get("identity"), str)
            or not row["identity"]
        ):
            raise malformed(
                "module execution closure lifecycle effects are malformed"
            )
        lifecycle_keys.append((
            row["source_rva"], row["kind"], row["dll"], row["identity"],
        ))
    if lifecycle_keys != sorted(set(lifecycle_keys)):
        raise malformed(
            "module execution closure lifecycle effects are noncanonical"
        )
    witness_keys: set[tuple[int, str]] = set()
    witness_fields = {
        "unit_id", "rva", "context_id", "root_rva",
        "function_entry_rva", "call_string",
    }
    for row in witnesses:
        key = (
            row.get("rva") if isinstance(row, Mapping) else None,
            row.get("context_id") if isinstance(row, Mapping) else None,
        )
        if (
            not isinstance(row, Mapping)
            or set(row) != witness_fields
            or key[0] not in unit_rvas
            or not isinstance(key[1], str)
            or key in witness_keys
            or row.get("unit_id") != unit_id_by_rva.get(key[0])
            or row.get("root_rva") not in unit_rvas
            or row.get("function_entry_rva") not in unit_rvas
            or not isinstance(row.get("call_string"), list)
            or any(not isinstance(rva, int) for rva in row["call_string"])
        ):
            raise malformed("module execution closure witnesses are malformed")
        witness_keys.add(key)
    expected_counts = {
        "reachable_units": len(units),
        "reachable_edges": len(edges),
        "indirect_sites": len(indirect),
        "function_contexts": len({
            row.get("context_id") for row in witnesses
        }),
    }
    if any(metrics.get(key) != value for key, value in expected_counts.items()):
        raise malformed("module execution closure metrics contradict its inventory")
    closure_sha256 = payload.get("closure_sha256")
    if not isinstance(closure_sha256, str) or len(closure_sha256) != 64:
        raise malformed("module execution closure identity is malformed")
    semantic_core = {
        key: value for key, value in payload.items() if key != "closure_sha256"
    }
    semantic_core = {
        **semantic_core,
        "metrics": {
            key: value for key, value in metrics.items()
            if key not in _OBSERVATIONAL_CLOSURE_METRICS_V1
        },
    }
    if canonical_sha256_v3(semantic_core) != closure_sha256:
        raise malformed("module execution closure identity does not match its content")

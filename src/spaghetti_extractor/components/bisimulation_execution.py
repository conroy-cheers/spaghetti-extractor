"""Compile and execute bounded contextual proof obligations and their inventories."""

from __future__ import annotations

import hashlib
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from . import bisimulation_completion as completion
from .bisimulation_support import (
    BisimulationRefinementError,
    strings as _strings,
    property_entry_function as _property_entry_function,
    property_query_order as _property_query_order,
    safety_property_groups,
    SINGLE_ASSERTION_STRATEGIES, PACKED_SINGLE_STRATEGY, ASSERTION_QUERY_STRATEGIES, PACKED_SAFETY_STRATEGY, CUT_CONTROL_FIRST_STRATEGY,
)
from .bisimulation_diagnostics import ProofQueryTimings, timed_query
from .bisimulation_query_evidence import CbmcQueryEvidence
from .bisimulation_assurance import checked_runtime_assurance, runtime_assurance_defines
from .bisimulation_compilation import VIRTUAL_WORKSPACE, workspace_compile_command
from .bisimulation_exact_frame import run_exact_frame_probe
from .bisimulation_mutable_frame import run_mutable_frame_probe
from .bisimulation_image_frame import run_probe as run_image_frame_probe
from .bisimulation_mutable_machine_frame import run_mutable_machine_frame_probes
from .bisimulation_clobber_frame import run_clobber_probes
from .bisimulation_readable_entry import run_readable_entry_probe, run_mutable_entry_probe
from .cbmc_backend import (
    discover_cbmc_assertions, discover_cbmc_loops,
    discover_cbmc_safety_properties, run_cbmc_cover, run_cbmc_properties,
)

_LANGUAGE_SAFETY_PARTITION_CLASSES = {
    "bounds": ("array bounds",),
    "pointer": (
        "pointer",
        "pointer arithmetic",
        "pointer dereference",
        "pointer primitives",
    ),
    "division": ("division-by-zero",),
    "signed_overflow": ("overflow",),
    "undefined_shift": ("undefined-shift",),
    "unwinding": ("unwind",),
}


def _run_safety_query(query, *, timings, timeout_seconds):
    """Refine exhausted query groups while retaining their complete ID coverage.

    Keep the paired entry and instrumentation unchanged. Failed parent queries
    remain in the diagnostic timings; only complete child sets can discharge
    their properties. Unwinding has a separate baseline domain and stays whole.
    """
    partition, selected, command = query
    cached = (_cached_query_partition(selected, command, timings)
              if partition != 'unwinding' else None)
    if cached is not None:
        return [item for identities, arguments in cached
                for item in _run_safety_query((partition, identities, arguments),
                    timings=timings, timeout_seconds=timeout_seconds)]
    result = timed_query(timings, "safety:" + partition, run_cbmc_properties,
                         command=command, timeout_seconds=timeout_seconds)
    exhausted = result.get("status") == "incomplete" and (
        result.get("code") == "cbmc_timeout" or
        any(message in str(result.get("detail", "")).lower()
            for message in ("out of memory", "bad_alloc")))
    if not exhausted or partition == "unwinding" or len(selected) < 2:
        return [(query, result)]
    middle = len(selected) // 2
    children = [selected[:middle], selected[middle:]]
    completed = []
    for child in children:
        arguments, inserted, index = [], False, 0
        while index < len(command):
            if command[index] == "--property":
                if not inserted:
                    arguments.extend(argument for identity in child
                                     for argument in ("--property", identity))
                    inserted = True
                index += 2
            else:
                arguments.append(command[index])
                index += 1
        if not inserted:
            raise BisimulationRefinementError("safety query lacks its property selection")
        completed.extend(_run_safety_query((partition, child, arguments),
            timings=timings, timeout_seconds=timeout_seconds))
        if any(result.get("status") == "incomplete" for _query, result in completed):
            # A terminal exhausted child cannot discharge its parent. Return
            # the actual checked prefix so normal receipt/diagnostic copying
            # can finish; do not raise or invent outputs for the remaining IDs.
            break
    return completed


def _select_assertion_properties(command, identities):
    arguments, inserted, index = [], False, 0
    while index < len(command):
        if command[index] == '--property':
            if index + 1 >= len(command):
                raise BisimulationRefinementError('assertion query has a malformed property selection')
            if not inserted:
                arguments.extend(argument for identity in identities for argument in ('--property', identity))
                inserted = True
            index += 2
        else:
            arguments.append(command[index])
            index += 1
    if not inserted:
        raise BisimulationRefinementError('assertion query lacks its property selection')
    return arguments


def _assertion_query_batches(queries, assertions, *, enabled):
    owners = {row['property_id']: row['source_function'] for row in assertions}
    result = []
    for kind, identity, entry, command in queries:
        # Keep the first early-rejection query alone. Later groups retain the
        # exact query order and never combine different proof input worlds.
        if (enabled and len(result) > 1 and len(result[-1][1]) < 4
                and result[-1][2] == entry and owners[result[-1][1][0]] == owners[identity]
                and _select_assertion_properties(result[-1][3], ['$PROPERTY_ID'])
                    == _select_assertion_properties(command, ['$PROPERTY_ID'])):
            result[-1][1].append(identity)
            previous = result[-1]
            result[-1] = (previous[0], previous[1], entry, _select_assertion_properties(command, previous[1]))
        else:
            result.append((kind, [identity], entry, command))
    return result


def _cached_query_partition(selected, command, timings):
    """Reuse bound descendants within the existing binary subdivision.

    This only changes scheduling. Every selected child runs through the normal
    parser and receipt checks; no property, input world or instrumentation is
    removed. Uncached siblings remain fresh queries; a partial cache must not
    force completed expensive descendants through their parent query again.
    """
    evidence = None if timings is None else timings.query_evidence
    if len(selected) < 2 or evidence is None or evidence.previous_binding is None:
        return None
    probe = evidence.property_reuse_probe(command)
    if probe is None:
        return None

    def leaves(identities, arguments):
        if probe(arguments):
            return [(identities, arguments)]
        if len(identities) < 2:
            return None
        middle = len(identities) // 2
        children = []
        for child in (identities[:middle], identities[middle:]):
            child_arguments = _select_assertion_properties(arguments, child)
            children.append((child, child_arguments, leaves(child, child_arguments)))
        if all(found is None for _, _, found in children):
            return None
        return [leaf for child, child_arguments, found in children
                for leaf in ([(child, child_arguments)] if found is None else found)]

    result = leaves(selected, command)
    return result if result is not None and len(result) > 1 else None


def _run_assertion_query(query, *, timings, timeout_seconds):
    kind, selected, entry, command = query
    cached = _cached_query_partition(selected, command, timings)
    if cached is not None:
        return [item for identities, arguments in cached
                for item in _run_assertion_query((kind, identities, entry, arguments),
                    timings=timings, timeout_seconds=timeout_seconds)]
    result = timed_query(timings, 'assertion:' + ','.join(selected), run_cbmc_properties,
                         command=command, timeout_seconds=timeout_seconds)
    exhausted = result.get('status') == 'incomplete' and (
        result.get('code') == 'cbmc_timeout' or any(message in str(result.get('detail', '')).lower()
            for message in ('out of memory', 'bad_alloc')))
    if not exhausted or len(selected) < 2:
        return [(query, result)]
    middle = len(selected) // 2
    completed = []
    for child in (selected[:middle], selected[middle:]):
        completed.extend(_run_assertion_query((kind, child, entry, _select_assertion_properties(command, child)),
            timings=timings, timeout_seconds=timeout_seconds))
    return completed



def _run_partitioned_properties(
    *,
    cbmc: Path,
    goto_model: Path,
    command: Mapping[str, object],
    proof_function: str,
    required_assertion_descriptions: Sequence[str],
    timeout_seconds: int,
    timings: ProofQueryTimings | None = None,
    uniform_entry: bool = False,
    required_assertion_sites: Sequence[Mapping[str, str]] | None = None,
) -> dict[str, object]:
    """Check authored assertions and inventory-partitioned source definedness.

    Every query uses the same compiled GOTO model. Small authored assertion
    groups let CBMC slice away unrelated equality goals while sharing work; the
    paired-entry safety classes independently check bounds, pointer, division,
    overflow, shifts, and unwinding with authored assertions disabled.
    Exact execution first populates the same arbitrary response transcript
    consumed by the source, so successful service responses remain in the
    safety domain.
    """
    if uniform_entry and required_assertion_sites is None:
        raise BisimulationRefinementError("independent entry omits its compiled assertion sites")

    expected_fields = {
        "backend",
        "goto_model_role",
        "strategy",
        "maximum_parallel_queries",
        "discovery_arguments",
        "language_safety_discovery_arguments",
        "language_safety_baseline_discovery_arguments",
        "loop_discovery_arguments",
        "assertion_arguments",
        "entry_assertion_arguments",
        "language_safety_queries",
    }
    if "smt_solver" in command:
        from .cbmc_backend import validate_smt_solver_binding
        validate_smt_solver_binding(command["smt_solver"])
        expected_fields.add("smt_solver")
    if "completion_assertion_arguments" in command:
        expected_fields.add("completion_assertion_arguments")
        if command["completion_assertion_arguments"] != completion.sat_arguments(command["assertion_arguments"]):
            raise BisimulationRefinementError("completion lemma backend command differs")
    discovery_arguments = command.get("discovery_arguments")
    language_safety_discovery_arguments = command.get(
        "language_safety_discovery_arguments"
    )
    language_safety_baseline_discovery_arguments = command.get(
        "language_safety_baseline_discovery_arguments"
    )
    loop_discovery_arguments = command.get("loop_discovery_arguments")
    assertion_arguments = command.get("assertion_arguments")
    entry_assertion_arguments = command.get("entry_assertion_arguments")
    language_safety_queries = command.get("language_safety_queries")
    maximum_parallel = command.get("maximum_parallel_queries")
    if (
        set(command) != expected_fields
        or command.get("backend") != "cbmc"
        or command.get("goto_model_role") != "shared_partitioned_property_queries"
        or command.get("strategy")
        not in ASSERTION_QUERY_STRATEGIES
        or maximum_parallel != 4
        or not isinstance(proof_function, str)
        or not proof_function
        or any(
            not isinstance(arguments, list)
            or not arguments
            or any(not isinstance(item, str) for item in arguments)
            for arguments in (
                discovery_arguments,
                language_safety_discovery_arguments,
                language_safety_baseline_discovery_arguments,
                loop_discovery_arguments,
                assertion_arguments,
                entry_assertion_arguments,
            )
        )
        or not isinstance(language_safety_queries, list)
        or len(language_safety_queries) != 6
        or any(
            not isinstance(query, Mapping)
            or set(query) != {"partition", "classes", "arguments"}
            or query.get("partition") not in _LANGUAGE_SAFETY_PARTITION_CLASSES
            or query.get("classes")
            != list(_LANGUAGE_SAFETY_PARTITION_CLASSES[str(query.get("partition"))])
            or not isinstance(query.get("arguments"), list)
            or not query["arguments"]
            or any(not isinstance(item, str) for item in query["arguments"])
            or query["arguments"].count("$PROPERTY_FUNCTION") != 1
            or query["arguments"].count("$PROPERTY_IDS")
            != (0 if query.get("partition") == "unwinding" else 1)
            for query in language_safety_queries
        )
        or [str(query["partition"]) for query in language_safety_queries]
        != list(_LANGUAGE_SAFETY_PARTITION_CLASSES)
        or assertion_arguments.count("--unwinding-assertions") != 1
        or "--no-unwinding-assertions" in assertion_arguments
        or entry_assertion_arguments != [
            "--no-unwinding-assertions" if item == "--unwinding-assertions" else item
            for item in assertion_arguments]
        or assertion_arguments.count("$PROPERTY_ID") != 1
        or assertion_arguments.count("$PROPERTY_FUNCTION") != 1
        or discovery_arguments.count("$PROPERTY_FUNCTION") != 1
        or language_safety_discovery_arguments.count("$PROPERTY_FUNCTION") != 1
        or language_safety_baseline_discovery_arguments.count("$PROPERTY_FUNCTION") != 1
        or loop_discovery_arguments.count("$PROPERTY_FUNCTION") != 1
    ):
        raise BisimulationRefinementError(
            "partitioned CBMC property command is malformed"
        )
    inventory = timed_query(timings, "assertion_inventory", discover_cbmc_assertions,
        command=[
            str(cbmc),
            str(goto_model),
            *(
                proof_function if item == "$PROPERTY_FUNCTION" else item
                for item in discovery_arguments
            ),
        ],
        timeout_seconds=timeout_seconds,
    )
    if inventory.get("status") != "satisfied":
        return inventory
    raw_assertions = inventory.get("assertions")
    if (
        not isinstance(raw_assertions, list)
        or not raw_assertions
        or any(
            not isinstance(row, Mapping)
            or set(row) != {"property_id", "description", "source_function"}
            or not all(
                isinstance(row.get(key), str) and row.get(key)
                for key in ("property_id", "description", "source_function")
            )
            for row in raw_assertions
        )
    ):
        return {
            "status": "incomplete",
            "code": "cbmc_assertion_inventory_malformed",
            "detail": "compiled assertion metadata is incomplete",
            "output_sha256": str(inventory.get("output_sha256", "")),
        }
    if required_assertion_sites is not None and raw_assertions != list(required_assertion_sites):
        return {"status": "incomplete", "code": "cbmc_required_assertion_sites_mismatch",
                "detail": "compiled entry assertion sites differ from CBMC discovery",
                "output_sha256": str(inventory.get("output_sha256", ""))}
    assertion_inventory = [
        {
            **dict(row),
            "entry_function": proof_function if uniform_entry else _property_entry_function(
                proof_function=proof_function,
                description=str(row["description"]),
                source_function=str(row["source_function"]),
            ),
        }
        for row in raw_assertions
    ]
    discovered_descriptions = [str(row["description"]) for row in assertion_inventory]
    if (
        not required_assertion_descriptions
        or list(required_assertion_descriptions)
        != sorted(set(required_assertion_descriptions))
        or any(
            discovered_descriptions.count(description) != 1
            for description in required_assertion_descriptions
        )
    ):
        mismatches = [
            f"{description} ({discovered_descriptions.count(description)} sites)"
            for description in required_assertion_descriptions
            if discovered_descriptions.count(description) != 1
        ]
        return {
            "status": "incomplete",
            "code": "cbmc_required_assertion_inventory_mismatch",
            "detail": (
                "compiled model omits or duplicates a required semantic assertion: "
                + "; ".join(mismatches)
                if mismatches else "required semantic assertion manifest is empty, unordered or duplicated"
            ),
            "output_sha256": str(inventory.get("output_sha256", "")),
        }
    assertion_ids = [str(row["property_id"]) for row in assertion_inventory]
    if assertion_ids != sorted(set(assertion_ids)):
        return {
            "status": "incomplete",
            "code": "cbmc_assertion_inventory_malformed",
            "detail": "compiled assertion metadata is unordered or duplicated",
            "output_sha256": str(inventory.get("output_sha256", "")),
        }
    queries: list[tuple[str, str | None, str, list[str]]] = []
    if any(row["description"].startswith(completion.PREFIX) for row in assertion_inventory) and \
            "completion_assertion_arguments" not in command:
        raise BisimulationRefinementError("completion assertion omits its checked backend policy")
    scheduled_assertions = sorted(assertion_inventory,
        key=lambda assertion: _property_query_order(assertion, strategy=command["strategy"]))
    for assertion in scheduled_assertions:
        property_id = str(assertion["property_id"])
        entry_function = str(assertion["entry_function"])
        selected_arguments = (command["completion_assertion_arguments"]
            if assertion["description"].startswith(completion.PREFIX) else assertion_arguments)
        queries.append(
            (
                "authored_assertion",
                property_id,
                entry_function,
                [
                    str(cbmc),
                    str(goto_model),
                    *(
                        property_id
                        if item == "$PROPERTY_ID"
                        else entry_function
                        if item == "$PROPERTY_FUNCTION"
                        else item
                        for item in selected_arguments
                    ),
                ],
            )
        )

    safety_inventory_result = timed_query(timings, "safety_inventory", discover_cbmc_safety_properties,
        command=[
            str(cbmc),
            str(goto_model),
            *(
                proof_function if item == "$PROPERTY_FUNCTION" else item
                for item in language_safety_discovery_arguments
            ),
        ],
        timeout_seconds=timeout_seconds,
    )
    if safety_inventory_result.get("status") != "satisfied":
        return safety_inventory_result
    safety_baseline_result = timed_query(timings, "safety_baseline", discover_cbmc_safety_properties,
        command=[
            str(cbmc),
            str(goto_model),
            *(
                proof_function if item == "$PROPERTY_FUNCTION" else item
                for item in language_safety_baseline_discovery_arguments
            ),
        ],
        timeout_seconds=timeout_seconds,
    )
    if safety_baseline_result.get("status") != "satisfied":
        return safety_baseline_result
    loop_inventory_result = timed_query(timings, "loop_inventory", discover_cbmc_loops,
        command=[
            str(cbmc),
            str(goto_model),
            *(
                proof_function if item == "$PROPERTY_FUNCTION" else item
                for item in loop_discovery_arguments
            ),
        ],
        timeout_seconds=timeout_seconds,
    )
    if loop_inventory_result.get("status") != "satisfied":
        return loop_inventory_result
    raw_safety_inventory = safety_inventory_result.get("safety_properties")
    raw_safety_baseline = safety_baseline_result.get("safety_properties")
    raw_loops = loop_inventory_result.get("loops")
    unwinding_property_ids = loop_inventory_result.get("unwinding_property_ids")
    if (
        not isinstance(raw_safety_inventory, list)
        or any(
            not isinstance(row, Mapping)
            or set(row) != {"property_id", "class", "description", "source_function"}
            for row in raw_safety_inventory
        )
        or not isinstance(raw_safety_baseline, list)
        or any(
            not isinstance(row, Mapping)
            or set(row) != {"property_id", "class", "description", "source_function"}
            for row in raw_safety_baseline
        )
        or not isinstance(raw_loops, list)
        or any(
            not isinstance(row, Mapping) or set(row) != {"loop_id", "source_function"}
            for row in raw_loops
        )
        or not isinstance(unwinding_property_ids, list)
        or len(unwinding_property_ids) != len(raw_loops)
        or any(not isinstance(item, str) or not item for item in unwinding_property_ids)
    ):
        return {
            "status": "incomplete",
            "code": "cbmc_language_safety_inventory_malformed",
            "detail": "compiled safety or loop inventory is incomplete",
            "output_sha256": canonical_sha256_v3(
                {
                    "safety": safety_inventory_result,
                    "loops": loop_inventory_result,
                }
            ),
        }
    safety_inventory = [dict(row) for row in raw_safety_inventory]
    safety_baseline = [dict(row) for row in raw_safety_baseline]
    loops = [
        {
            **dict(row),
            "unwinding_property_id": property_id,
        }
        for row, property_id in zip(raw_loops, unwinding_property_ids, strict=True)
    ]
    class_to_partition = {
        property_class: partition
        for partition, classes in _LANGUAGE_SAFETY_PARTITION_CLASSES.items()
        if partition != "unwinding"
        for property_class in classes
    }
    unknown_classes = sorted(
        {
            str(row.get("class"))
            for row in [*safety_inventory, *safety_baseline]
            if row.get("class") not in class_to_partition
        }
    )
    # The baseline belongs only to the unsliced, no-standard-checks unwind
    # query. CBMC renumbers automatic function-pointer checks when standard
    # checks are enabled, so its IDs are not in the static safety ID domain.
    if unknown_classes:
        return {
            "status": "incomplete",
            "code": "cbmc_language_safety_class_unknown",
            "detail": ", ".join(unknown_classes),
            "output_sha256": str(safety_inventory_result.get("output_sha256", "")),
        }
    expected_safety_ids = {
        partition: sorted(
            str(row["property_id"])
            for row in safety_inventory
            if class_to_partition.get(str(row["class"])) == partition
        )
        for partition in _LANGUAGE_SAFETY_PARTITION_CLASSES
        if partition != "unwinding"
    }
    expected_safety_ids["unwinding"] = list(unwinding_property_ids)
    safety_baseline_ids = sorted(str(row["property_id"]) for row in safety_baseline)
    potential_language_safety_property_count = sum(
        len(property_ids) for property_ids in expected_safety_ids.values()
    )
    if potential_language_safety_property_count == 0:
        return {
            "status": "incomplete",
            "code": "cbmc_no_language_safety_properties",
            "detail": "compiled proof entry has no safety properties or loops",
            "output_sha256": canonical_sha256_v3(
                {
                    "safety": safety_inventory_result,
                    "loops": loop_inventory_result,
                }
            ),
        }
    safety_query_specs = [
        (
            str(query["partition"]),
            selected_ids,
            [
                str(cbmc),
                str(goto_model),
                *(
                    argument
                    for item in query["arguments"]
                    for argument in (
                        [argument for property_id in selected_ids
                         for argument in ("--property", property_id)]
                        if item == "$PROPERTY_IDS"
                        else [proof_function if item == "$PROPERTY_FUNCTION" else item]
                    )
                ),
            ],
        )
        for query in language_safety_queries
        for selected_ids in safety_property_groups(str(query["partition"]),
            expected_safety_ids[str(query["partition"])], safety_inventory, strategy=command['strategy'])
    ]
    safety_runs = []
    for offset in range(0, len(safety_query_specs), int(maximum_parallel)):
        batch = safety_query_specs[offset:offset + int(maximum_parallel)]
        with ThreadPoolExecutor(max_workers=len(batch)) as executor:
            safety_runs.extend(executor.map(
                lambda query: _run_safety_query(query,
                    timings=timings, timeout_seconds=timeout_seconds), batch,
            ))
        if any(result.get("status") == "incomplete"
               for run in safety_runs for _query, result in run):
            break
    safety_query_specs = [query for run in safety_runs for query, _result in run]
    safety_results = [result for run in safety_runs for _query, result in run]
    receipts: list[dict[str, object]] = []
    results: list[dict[str, object]] = []
    failed: dict[str, object] | None = None
    for (partition, expected_ids, _query), result in zip(
        safety_query_specs, safety_results, strict=True
    ):
        normalized = dict(result)
        observed_ids = result.get("property_ids")
        observed_id_set = set(observed_ids) if isinstance(observed_ids, list) else set()
        if result.get("status") == "satisfied" and (
            (partition != "unwinding" and not set(expected_ids) <= observed_id_set)
            or not observed_id_set <= set(expected_ids) | (
                set(safety_baseline_ids) if partition == "unwinding" else set()
            )
        ):
            normalized = {
                "status": "incomplete",
                "code": "cbmc_language_safety_partition_mismatch",
                "detail": (
                    f"{partition} expected {expected_ids!r}; observed {observed_ids!r}"
                ),
                "output_sha256": str(result.get("output_sha256", "")),
            }
        receipts.append(
            {
                "kind": "language_safety",
                "safety_partition": partition,
                "expected_property_ids": expected_ids,
                "property_ids": (
                    list(observed_ids) if isinstance(observed_ids, list) else []
                ),
                "status": str(normalized.get("status", "")),
                "code": str(normalized.get("code", "")),
                "properties": int(normalized.get("properties", 0)),
                "output_sha256": str(normalized.get("output_sha256", "")),
                **(
                    {"detail": str(normalized["detail"])}
                    if normalized.get("detail") is not None
                    else {}
                ),
            }
        )
        # Partial safety coverage is always incomplete, even if another
        # already-started group returned a counterexample. Keep both outputs.
        if ((failed is None and normalized.get("status") != "satisfied") or
                (normalized.get("status") == "incomplete" and failed.get("status") != "incomplete")):
            failed = normalized
    checked_unwinding_ids = {
        property_id
        for receipt in receipts
        if receipt.get("safety_partition") == "unwinding"
        for property_id in receipt.get("property_ids", [])
        if property_id in set(expected_safety_ids["unwinding"])
    }
    language_safety_property_count = len(safety_inventory) + len(checked_unwinding_ids)
    # An unsliced successful unwind query covers the same entry and all its
    # paths. Focused entries have different input worlds and keep their checks.
    # With no unwind receipt (including an empty loop inventory), keep checks:
    # recursion can introduce dynamic unwind assertions outside that inventory.
    if failed is None and any(row.get("safety_partition") == "unwinding" and
                              row.get("status") == "satisfied" for row in receipts):
        queries = [(kind, requested, entry, [str(cbmc), str(goto_model), *[
            requested if item == "$PROPERTY_ID" else entry if item == "$PROPERTY_FUNCTION" else item
            for item in (completion.sat_arguments(entry_assertion_arguments)
                if any(row["property_id"] == requested and row["description"].startswith(completion.PREFIX)
                       for row in assertion_inventory) else entry_assertion_arguments)]]) if entry == proof_function else
            (kind, requested, entry, query) for kind, requested, entry, query in queries]
    batching = command['strategy'] in ASSERTION_QUERY_STRATEGIES and command['strategy'] not in SINGLE_ASSERTION_STRATEGIES
    queries = _assertion_query_batches(queries, assertion_inventory, enabled=batching)
    offset = 0
    while failed is None and offset < len(queries):
        batch_width = 1 if offset == 0 else int(maximum_parallel)
        batch = queries[offset : offset + batch_width]
        with ThreadPoolExecutor(max_workers=len(batch)) as executor:
            batch_results = list(
                executor.map(
                    lambda query: _run_assertion_query(query, timings=timings, timeout_seconds=timeout_seconds),
                    batch,
                )
            )
        for (kind, requested, entry_function, _query), result in (
            item for completed in batch_results for item in completed
        ):
            normalized = dict(result)
            if requested is not None and result.get("status") == "satisfied":
                observed_property_ids = result.get("property_ids")
                if (
                    not isinstance(observed_property_ids, list)
                    or not set(requested) <= set(observed_property_ids)
                ):
                    normalized = {
                        "status": "incomplete",
                        "code": "cbmc_selected_assertion_not_checked",
                        "detail": (
                            f"requested {requested}; observed {observed_property_ids!r}"
                        ),
                        "output_sha256": str(result.get("output_sha256", "")),
                    }
                else:
                    # Unwinding assertions can remain alongside the selected
                    # authored assertions even under --no-standard-checks.
                    # Their complete source-side inventory is checked once by
                    # the dedicated safety entry.  This receipt records only
                    # the authored properties selected by this partition.
                    normalized = {
                        **normalized,
                        "properties": len(requested),
                        "property_ids": requested,
                    }
            results.append(normalized)
            receipts.append(
                {
                    "kind": kind,
                    **({'property_ids': requested} if batching else {'property_id': requested[0]}),
                    "entry_function": entry_function,
                    "status": str(normalized.get("status", "")),
                    "code": str(normalized.get("code", "")),
                    "properties": int(normalized.get("properties", 0)),
                    "output_sha256": str(normalized.get("output_sha256", "")),
                    **(
                        {"detail": str(normalized["detail"])}
                        if normalized.get("detail") is not None
                        else {}
                    ),
                }
            )
            if failed is None and normalized.get("status") != "satisfied":
                failed = normalized
        if failed is not None:
            break
        offset += len(batch)

    evidence = {
        **({"required_assertion_sites_sha256": canonical_sha256_v3(list(required_assertion_sites))}
           if required_assertion_sites is not None else {}),
        "strategy": command['strategy'],
        "assertion_inventory_output_sha256": str(inventory.get("output_sha256", "")),
        "language_safety_inventory_output_sha256": str(
            safety_inventory_result.get("output_sha256", "")
        ),
        "language_safety_baseline_inventory_output_sha256": str(
            safety_baseline_result.get("output_sha256", "")
        ),
        "loop_inventory_output_sha256": str(
            loop_inventory_result.get("output_sha256", "")
        ),
        "required_assertion_descriptions_sha256": canonical_sha256_v3(
            list(required_assertion_descriptions)
        ),
        "assertions": assertion_inventory,
        "language_safety_inventory": safety_inventory,
        "language_safety_baseline_inventory": safety_baseline,
        "loops": loops,
        "language_safety_properties": language_safety_property_count,
        "queries": receipts,
    }
    output_sha256 = canonical_sha256_v3(evidence)
    if failed is not None:
        return {
            **failed,
            "output_sha256": output_sha256,
            "partitioned_evidence": evidence,
        }
    property_ids = sorted(
        property_id
        for result in results
        for property_id in _strings(
            result.get("property_ids"), "partitioned CBMC result properties"
        )
    )
    if len(property_ids) != len(set(property_ids)):
        return {
            "status": "incomplete",
            "code": "cbmc_partitioned_property_overlap",
            "detail": "property queries returned duplicate property identifiers",
            "output_sha256": output_sha256,
            "partitioned_evidence": evidence,
        }
    return {
        "status": "satisfied",
        "code": "cbmc_properties_satisfied",
        "properties": len(property_ids),
        "property_ids": property_ids,
        "output_sha256": output_sha256,
        "partitioned_evidence": evidence,
    }



def _run_bisimulation_obligation(
    task: Mapping[str, object], *, timeout_seconds: int
) -> dict[str, object]:
    assurance = checked_runtime_assurance(task.get("assurance"))
    compile_command = task.get("compile_command")
    cbmc = task.get("cbmc")
    property_checker_command = task.get("property_checker_command")
    cover_queries = task.get("cover_queries")
    goto_model = task.get("goto_model")
    proof_function = task.get("proof_function")
    required_assertion_descriptions = task.get("required_assertion_descriptions")
    witness_functions = task.get("witness_functions")
    if (
        not isinstance(compile_command, list)
        or any(not isinstance(item, str) for item in compile_command)
        or not isinstance(cbmc, Path)
        or not isinstance(property_checker_command, Mapping)
        or not isinstance(cover_queries, list)
        or not cover_queries
        or any(
            not isinstance(query, Mapping)
            or set(query) != {"command", "expected_functions"}
            or not isinstance(query.get("command"), list)
            or any(not isinstance(item, str) for item in query["command"])
            or not isinstance(query.get("expected_functions"), list)
            or not query["expected_functions"]
            or any(
                not isinstance(item, str) or not item
                for item in query["expected_functions"]
            )
            for query in cover_queries
        )
        or not isinstance(goto_model, Path)
        or not isinstance(proof_function, str)
        or not proof_function
        or not isinstance(required_assertion_descriptions, list)
        or not required_assertion_descriptions
        or any(
            not isinstance(item, str) or not item
            for item in required_assertion_descriptions
        )
        or required_assertion_descriptions
        != sorted(set(required_assertion_descriptions))
        or not isinstance(witness_functions, list)
        or not witness_functions
        or any(not isinstance(item, str) or not item for item in witness_functions)
    ):
        raise BisimulationRefinementError("bisimulation obligation task is malformed")
    compile_command = [*compile_command, *runtime_assurance_defines(assurance)]
    # Auxiliary probes compile derived harnesses from this task too. They must
    # use the same explicit selection as the main model, without mutating the
    # caller's reusable preparation record.
    task = {**task, "compile_command": compile_command}
    query_evidence = (CbmcQueryEvidence(model=goto_model, checker=cbmc, compiler=Path(compile_command[0]),
        output=goto_model.parent / "query-evidence", previous=task.get("previous_query_evidence"),
        smt_solver=task.get("smt_solver"), assurance=assurance)
        if task.get("retain_query_evidence") is True else None)
    timings = (ProofQueryTimings(goto_model, {
        key: str(task.get(key, "")) for key in ("operation_id", "obligation_id", "proof_function")
    }, query_evidence=query_evidence) if task.get("diagnostic_timings") is True or query_evidence is not None else None)
    if timings is not None:
        timings.record_compile_inputs(compile_command, proof_root=task["diagnostic_proof_root"],
            compiler_workspace=VIRTUAL_WORKSPACE if task.get("compile_workspace") is not None else None)
    compiled = timed_query(timings, "compile", _run_compile,
                           command=compile_command, timeout_seconds=timeout_seconds,
                           workspace=task.get("compile_workspace"))
    from .bisimulation_source_entry import compile_source_entry
    source_entry = compile_source_entry(task, timeout_seconds=timeout_seconds) if compiled is None else None
    if source_entry is not None:
        from .bisimulation_entry_queries import run_entry_queries
        source_entry = run_entry_queries(task, source_entry,
            timeout_seconds=task.get("source_entry_timeout_seconds") or timeout_seconds)
    property_result = (
        _run_partitioned_properties(
            cbmc=cbmc,
            goto_model=goto_model,
            command=property_checker_command,
            proof_function=proof_function,
            required_assertion_descriptions=required_assertion_descriptions,
            timeout_seconds=timeout_seconds,
            timings=timings,
        )
        if compiled is None
        else compiled
    )
    if property_result.get("status") == "violated":
        # The counterexample itself proves that the unrestricted property
        # antecedent is inhabited.  Publish that fail-closed diagnostic without
        # spending a second solver run on an unrelated completion cover.
        witness = {
            "status": "satisfied",
            "code": "cbmc_counterexample_inhabits_property_model",
            "evidence": "property_counterexample",
            "expected_functions": list(witness_functions),
            "witnessed_functions": [],
            "output_sha256": str(property_result.get("output_sha256", "")),
        }
    else:
        witness = (
            _run_cover_queries(cover_queries, timeout_seconds=timeout_seconds, timings=timings)
            if compiled is None
            else compiled
        )
    # The cover query enters the relation-only function in the same compiled
    # model.  It stops at the selected source barrier immediately after the
    # authored invariant and capture assumptions, so it checks antecedent
    # inhabitation without re-executing either proof segment.  The property
    # entry retains every safety and equivalence assertion.
    result = (
        property_result
        if witness.get("status") == "satisfied"
        or property_result.get("status") == "violated"
        else witness
    )
    goto_model_sha256 = (
        hashlib.sha256(goto_model.read_bytes()).hexdigest()
        if compiled is None and goto_model.is_file()
        else None
    )
    nonvacuity_goto_model_sha256 = goto_model_sha256
    execution_binding = {
        "proof_model_sha256": str(task.get("proof_model_sha256", "")),
        "nonvacuity_proof_model_sha256": str(
            task.get("nonvacuity_proof_model_sha256", "")
        ),
        "property_checker_command_sha256": str(
            task.get("property_checker_command_sha256", "")
        ),
        "nonvacuity_checker_command_sha256": str(
            task.get("nonvacuity_checker_command_sha256", "")
        ),
        "goto_model_sha256": goto_model_sha256,
        "nonvacuity_goto_model_sha256": nonvacuity_goto_model_sha256,
        **({"assurance": assurance} if assurance is not None else {}),
    }
    frame = run_exact_frame_probe(task=task, ordinary_result=result, goto_sha256=goto_model_sha256,
                                  timeout_seconds=timeout_seconds, timings=timings)
    mutable_frames = run_mutable_frame_probe(task=task, ordinary_result=result, goto_sha256=goto_model_sha256,
                                             timeout_seconds=timeout_seconds, timings=timings)
    mutable_entry = run_mutable_entry_probe(task=task, frames=mutable_frames, timeout_seconds=timeout_seconds, timings=timings)
    checked = {
        **({"source_entry_model": source_entry} if source_entry is not None else {}),
        "shard_id": str(task.get("shard_id", "")),
        "operation_id": str(task.get("operation_id", "")),
        "obligation_id": str(task.get("obligation_id", "")),
        "proof_model_sha256": str(task.get("proof_model_sha256", "")),
        "nonvacuity_proof_model_sha256": str(
            task.get("nonvacuity_proof_model_sha256", "")
        ),
        "property_checker_command_sha256": execution_binding[
            "property_checker_command_sha256"
        ],
        "nonvacuity_checker_command_sha256": execution_binding[
            "nonvacuity_checker_command_sha256"
        ],
        "goto_model_sha256": goto_model_sha256,
        "nonvacuity_goto_model_sha256": nonvacuity_goto_model_sha256,
        "execution_binding_sha256": canonical_sha256_v3(execution_binding),
        "nonvacuity": witness,
        **frame,
        **mutable_frames,
        **mutable_entry,
        **run_image_frame_probe(entry=mutable_entry, task=task, ordinary_result=result,
            goto_sha256=goto_model_sha256, timeout_seconds=timeout_seconds, timings=timings),
        **run_mutable_machine_frame_probes(entry=mutable_entry, task=task, ordinary_result=result,
            goto_sha256=goto_model_sha256, timeout_seconds=timeout_seconds, timings=timings),
        **run_clobber_probes(entry=mutable_entry, task=task, ordinary_result=result,
            goto_sha256=goto_model_sha256, timeout_seconds=timeout_seconds, timings=timings),
        **run_readable_entry_probe(task=task, frame=frame.get("exact_memory_frame"),
                                   timeout_seconds=timeout_seconds, timings=timings),
        **result,
    }
    if assurance is not None:
        checked.update(authorizing=False, assurance=assurance)
        # A failed coverage query must not discard completed property evidence.
        # Keep both under the conditional receipt, without changing its status.
        checked['property_result'] = property_result
        # Auxiliary frame certificates are also conditional. Their strict
        # existing readers must not accept them after extraction from a shard.
        for key, value in list(checked.items()):
            if isinstance(value, Mapping) and "receipt_sha256" in value:
                core = {k: v for k, v in value.items() if k != "receipt_sha256"}
                core.update(authorizing=False, assurance=assurance)
                checked[key] = {**core, "receipt_sha256": canonical_sha256_v3(core)}
    return checked



def _run_cover_queries(
    queries: Sequence[Mapping[str, object]], *, timeout_seconds: int,
    timings: ProofQueryTimings | None = None,
) -> dict[str, object]:
    results = [
        timed_query(timings, "nonvacuity", run_cbmc_cover,
            command=query["command"],
            expected_functions=query["expected_functions"],
            timeout_seconds=timeout_seconds,
        )
        for query in queries
    ]
    receipts = [
        {
            "functions": list(query["expected_functions"]),
            "status": str(result.get("status", "")),
            "code": str(result.get("code", "")),
            "output_sha256": str(result.get("output_sha256", "")),
            **(
                {"detail": str(result["detail"])}
                if result.get("detail") is not None
                else {}
            ),
        }
        for query, result in zip(queries, results, strict=True)
    ]
    failed = next(
        (result for result in results if result.get("status") != "satisfied"),
        None,
    )
    return {
        "status": "satisfied" if failed is None else str(failed.get("status")),
        "code": (
            "cbmc_nonvacuity_witness"
            if failed is None
            else str(failed.get("code", "cbmc_nonvacuity_query_failed"))
        ),
        "properties": sum(int(result.get("properties", 0)) for result in results),
        "property_ids": sorted(
            property_id
            for result in results
            for property_id in result.get("property_ids", [])
        ),
        "expected_functions": sorted(
            {function for query in queries for function in query["expected_functions"]}
        ),
        "witnessed_functions": sorted(
            {
                function
                for result in results
                for function in result.get("witnessed_functions", [])
            }
        ),
        "output_sha256": canonical_sha256_v3(receipts),
        "queries": receipts,
        **(
            {"detail": str(failed["detail"])}
            if failed is not None and failed.get("detail") is not None
            else {}
        ),
    }



def _cbmc_cover_queries(
    *,
    reference_authority: Mapping[str, object] | None = None,
    allocation_capacity: int = 1,
    connected_components: Sequence[Mapping[str, object]] = (),
    cbmc: Path,
    goto_model: Path,
    proof_function: str,
    witness_functions: Sequence[str],
    source_unwind_limit: int | None = None,
    smt_solver: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    """Build a reachability query independent of the properties under proof.

    CBMC's coverage mode otherwise rewrites assertions into assumptions.  That
    makes a reachable shard with an always-failing equivalence assertion look
    vacuous and prevents publication of its non-authorizing counterexample.
    Safety and equivalence remain checked by the separate property command.
    """

    from .bisimulation_reference_authority import reference_authority_unwind_arguments
    from .bisimulation_readable_composition import mutable_summary_unwind_arguments
    from .cbmc_backend import solver_arguments

    unwind, progress_arguments = source_unwind_arguments(source_unwind_limit)
    command = [
        str(cbmc),
        str(goto_model),
        "--json-ui",
        "--function",
        proof_function,
        "--no-assertions",
        "--cover",
        "cover",
        "--symex-cache-dereferences",
        "--object-bits",
        "12",
        *solver_arguments(smt_solver),
        "--unwind",
        unwind,
        *progress_arguments,
        *mutable_summary_unwind_arguments(connected_components, reference_authority_unwind_arguments(
            reference_authority, allocation_capacity=allocation_capacity)),
    ]
    if len(witness_functions) <= 2:
        return [
            {
                "command": [
                    *command,
                    "--property",
                    f"{function}.coverage.1",
                    "--reachability-slice-fb",
                    "--slice-formula",
                ],
                "expected_functions": [function],
            }
            for function in witness_functions
        ]
    return [
        {
            # Other entry functions in the same model can contain unreachable
            # witnesses. Select this obligation's complete inventory explicitly;
            # the result reader still requires every selected goal to be reached.
            "command": [*command,
                        *(argument for function in witness_functions
                          for argument in ("--property", f"{function}.coverage.1")),
                        "--reachability-slice-fb", "--slice-formula"],
            "expected_functions": list(witness_functions),
        }
    ]



def _run_compile(
    command: Sequence[str], timeout_seconds: int, workspace: Path | None = None
) -> dict[str, object] | None:
    try:
        completed = subprocess.run(
            list(command) if workspace is None else workspace_compile_command(command, workspace),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "status": "incomplete",
            "code": "goto_cc_timeout",
            "detail": f"exceeded {timeout_seconds} seconds",
            "output_sha256": hashlib.sha256(
                ((exc.stdout or "") + (exc.stderr or "")).encode("utf-8")
            ).hexdigest(),
        }
    if completed.returncode == 0:
        return None
    return {
        "status": "incomplete",
        "code": "goto_cc_compile_failed",
        "detail": (completed.stderr or completed.stdout)[-4000:],
        "output_sha256": hashlib.sha256(
            (completed.stdout + "\0" + completed.stderr).encode("utf-8")
        ).hexdigest(),
    }


def source_unwind_arguments(limit):
    if limit is None:
        return "2", []
    from .bisimulation import parse_source_unwind_limit
    return str(parse_source_unwind_limit(limit)), ["--no-self-loops-to-assumptions"]


def property_checker_command(authority_unwind_arguments, *, source_unwind_limit=None, smt_solver=None,
                             application_first=False, completion_lemmas=False):
    """One command policy for production and retained regional checks."""
    from .cbmc_backend import solver_arguments
    if type(application_first) is not bool:
        raise BisimulationRefinementError("application-first scheduling must be Boolean")
    if type(completion_lemmas) is not bool:
        raise BisimulationRefinementError("completion-lemma scheduling must be Boolean")
    unwind, progress_arguments = source_unwind_arguments(source_unwind_limit)
    property_common_arguments = [
        "--json-ui",
        "--trace",
        "--stop-on-fail",
        "--function",
        "$PROPERTY_FUNCTION",
        "--symex-cache-dereferences",
        "--object-bits",
        "12",
        *solver_arguments(smt_solver),
        "--unwind",
        unwind,
        *progress_arguments,
        *authority_unwind_arguments,
        "--unwinding-assertions",
        "--reachability-slice-fb",
        "--slice-formula",
    ]
    language_safety_common_arguments = [
        "--json-ui",
        "--trace",
        "--stop-on-fail",
        "--function",
        "$PROPERTY_FUNCTION",
        "--no-unwinding-assertions",
        "--no-assertions",
        "--symex-cache-dereferences",
        "--object-bits",
        "12",
        *solver_arguments(smt_solver),
        "--unwind",
        unwind,
        *progress_arguments,
        *authority_unwind_arguments,
        "--reachability-slice-fb",
        "--slice-formula",
    ]
    property_checker_command = {
        **({"smt_solver": dict(smt_solver)} if smt_solver is not None else {}),
        "backend": "cbmc",
        "goto_model_role": "shared_partitioned_property_queries",
        # Word-level memory equalities can be cheap separately while their
        # disjunction overwhelms SMT. Keep authored goals separate while
        # packing safety IDs across helpers; SAT retains authored batches.
        "strategy": (PACKED_SINGLE_STRATEGY if smt_solver is not None else
                     CUT_CONTROL_FIRST_STRATEGY if application_first else PACKED_SAFETY_STRATEGY),
        "maximum_parallel_queries": 4,
        "discovery_arguments": [
            "--json-ui",
            "--function",
            "$PROPERTY_FUNCTION",
            "--reachability-slice-fb",
            "--show-properties",
        ],
        "language_safety_discovery_arguments": [
            "--json-ui",
            "--function",
            "$PROPERTY_FUNCTION",
            "--no-assertions",
            "--unwind",
            unwind,
            *progress_arguments,
            *authority_unwind_arguments,
            "--reachability-slice-fb",
            "--show-properties",
        ],
        "language_safety_baseline_discovery_arguments": [
            "--json-ui",
            "--function",
            "$PROPERTY_FUNCTION",
            "--no-standard-checks",
            "--no-assertions",
            "--unwind",
            unwind,
            *progress_arguments,
            *authority_unwind_arguments,
            "--show-properties",
        ],
        "loop_discovery_arguments": [
            "--json-ui",
            "--function",
            "$PROPERTY_FUNCTION",
            "--show-loops",
        ],
        "entry_assertion_arguments": [
            *("--no-unwinding-assertions" if item == "--unwinding-assertions" else item
              for item in property_common_arguments),
            "--no-standard-checks", "--property", "$PROPERTY_ID",
        ],
        "assertion_arguments": [
            *property_common_arguments,
            "--no-standard-checks",
            "--property",
            "$PROPERTY_ID",
        ],
        "language_safety_queries": [
            {
                "partition": "bounds",
                "classes": ["array bounds"],
                "arguments": [
                    *language_safety_common_arguments,
                    "$PROPERTY_IDS",
                ],
            },
            {
                "partition": "pointer",
                "classes": [
                    "pointer",
                    "pointer arithmetic",
                    "pointer dereference",
                    "pointer primitives",
                ],
                "arguments": [
                    *language_safety_common_arguments,
                    "$PROPERTY_IDS",
                ],
            },
            {
                "partition": "division",
                "classes": ["division-by-zero"],
                "arguments": [
                    *language_safety_common_arguments,
                    "$PROPERTY_IDS",
                ],
            },
            {
                "partition": "signed_overflow",
                "classes": ["overflow"],
                "arguments": [
                    *language_safety_common_arguments,
                    "$PROPERTY_IDS",
                ],
            },
            {
                "partition": "undefined_shift",
                "classes": ["undefined-shift"],
                "arguments": [
                    *language_safety_common_arguments,
                    "$PROPERTY_IDS",
                ],
            },
            {
                "partition": "unwinding",
                "classes": ["unwind"],
                "arguments": [
                    *(
                        item
                        for item in language_safety_common_arguments
                        if item not in {"--reachability-slice-fb", "--no-unwinding-assertions"}
                    ),
                    "--no-standard-checks",
                    "--unwinding-assertions",
                ],
            },
        ],
    }
    if completion_lemmas:
        property_checker_command["completion_assertion_arguments"] = completion.sat_arguments(
            property_checker_command["assertion_arguments"])
    return property_checker_command

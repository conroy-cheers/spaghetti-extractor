"""Validate partition inventories and their exact checker-query bindings."""
from __future__ import annotations

import re
from typing import Mapping
from ..artifacts.artifact_set import canonical_sha256_v3
from .bisimulation import ComponentBisimulationError
from .bisimulation_support import (
    property_entry_function as _property_entry_function,
    property_query_order as _property_query_order,
    safety_property_groups, safety_group_refinement,
    ASSERTION_QUERY_STRATEGIES, ASSERTION_SINGLE_STRATEGY, authored_query_ids,
)

def _sha256(value: object, context: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ComponentBisimulationError(f"{context} binding is not a SHA-256 digest")
    return value


def _validate_partitioned_property_evidence(*, shard, model, uniform_entry=False):
    """Share the complete partition reader with independent entry qualification.

    Ordinary contextual receipts retain their existing typed-barrier routing.
    Independent entry checks use one bound relation root for every property.
    """
    shard_status = shard.get("status")
    required_sites = model.get("required_assertion_sites")
    if uniform_entry and required_sites is None:
        raise ComponentBisimulationError("independent entry omits its compiled assertion sites")
    if shard_status in {"satisfied", "violated"} or "partitioned_evidence" in shard:
        partitioned = shard.get("partitioned_evidence")
        if (
            not isinstance(partitioned, Mapping)
            or set(partitioned)
            != {
                "strategy",
                "assertion_inventory_output_sha256",
                "language_safety_inventory_output_sha256",
                "language_safety_baseline_inventory_output_sha256",
                "loop_inventory_output_sha256",
                "required_assertion_descriptions_sha256",
                "assertions",
                "language_safety_inventory",
                "language_safety_baseline_inventory",
                "loops",
                "language_safety_properties",
                "queries",
            } | ({"required_assertion_sites_sha256"} if required_sites is not None else set())
            or partitioned.get("strategy") not in ASSERTION_QUERY_STRATEGIES
            or partitioned.get('strategy') != model['property_checker_command']['strategy']
            or canonical_sha256_v3(partitioned)
            != shard.get("output_sha256")
            or partitioned.get("required_assertion_descriptions_sha256")
            != model.get(
                "required_assertion_descriptions_sha256"
            )
        ):
            raise ComponentBisimulationError(
                "contextual shard partitioned property evidence is stale"
            )
        if required_sites is not None and (
                partitioned.get("required_assertion_sites_sha256") != canonical_sha256_v3(required_sites)
                or not isinstance(partitioned.get("assertions"), list)
                or [{key: value for key, value in row.items() if key != "entry_function"}
                    for row in partitioned["assertions"] if isinstance(row, Mapping)] != required_sites):
            raise ComponentBisimulationError("independent entry assertion sites differ from the compiled manifest")
        _sha256(
            partitioned.get("assertion_inventory_output_sha256"),
            "contextual assertion inventory output",
        )
        _sha256(
            partitioned.get("language_safety_inventory_output_sha256"),
            "contextual language-safety inventory output",
        )
        _sha256(
            partitioned.get(
                "language_safety_baseline_inventory_output_sha256"
            ),
            "contextual baseline language-safety inventory output",
        )
        _sha256(
            partitioned.get("loop_inventory_output_sha256"),
            "contextual loop inventory output",
        )
        assertions = partitioned.get("assertions")
        language_safety_inventory = partitioned.get(
            "language_safety_inventory"
        )
        language_safety_baseline_inventory = partitioned.get(
            "language_safety_baseline_inventory"
        )
        loops = partitioned.get("loops")
        queries = partitioned.get("queries")
        proof_function = str(model["proof_function"])
        if (
            not isinstance(assertions, list)
            or not assertions
            or any(
                not isinstance(assertion, Mapping)
                or set(assertion)
                != {
                    "property_id",
                    "description",
                    "source_function",
                    "entry_function",
                }
                or any(
                    not isinstance(assertion.get(field), str)
                    or not assertion.get(field)
                    for field in assertion
                )
                or assertion.get("entry_function")
                != (proof_function if uniform_entry else _property_entry_function(
                    proof_function=proof_function,
                    description=str(assertion.get("description", "")),
                    source_function=str(
                        assertion.get("source_function", "")
                    ),
                ))
                for assertion in assertions
            )
        ):
            raise ComponentBisimulationError(
                "contextual partitioned property inventory is malformed"
            )
        from .bisimulation_completion import PREFIX
        for assertion in assertions:
            if assertion["description"].startswith(PREFIX):
                symbol = "spx_proof_call_completion_" + assertion["description"][len(PREFIX):]
                if assertion["source_function"] != symbol or assertion["property_id"] != symbol + ".assertion.1":
                    raise ComponentBisimulationError("call completion assertion site differs")
        assertion_ids = [str(assertion["property_id"]) for assertion in assertions]
        discovered_descriptions = [
            str(assertion["description"]) for assertion in assertions
        ]
        required_assertion_descriptions = model[
            "required_assertion_descriptions"
        ]
        safety_classes = {
            "bounds": {"array bounds"},
            "pointer": {
                "pointer",
                "pointer arithmetic",
                "pointer dereference",
                "pointer primitives",
            },
            "division": {"division-by-zero"},
            "signed_overflow": {"overflow"},
            "undefined_shift": {"undefined-shift"},
            "unwinding": {"unwind"},
        }
        if (
            assertion_ids != sorted(set(assertion_ids))
            or any(
                discovered_descriptions.count(description) != 1
                for description in required_assertion_descriptions
            )
            or not isinstance(language_safety_inventory, list)
            or any(
                not isinstance(item, Mapping)
                or set(item)
                != {
                    "property_id",
                    "class",
                    "description",
                    "source_function",
                }
                or any(
                    not isinstance(item.get(field), str)
                    or not item.get(field)
                    for field in item
                )
                or item.get("class")
                not in set().union(*safety_classes.values()) - {"unwind"}
                for item in language_safety_inventory
            )
            or [
                str(item["property_id"])
                for item in language_safety_inventory
            ]
            != sorted({
                str(item["property_id"])
                for item in language_safety_inventory
            })
            or not isinstance(language_safety_baseline_inventory, list)
            or any(
                not isinstance(item, Mapping)
                or set(item)
                != {
                    "property_id",
                    "class",
                    "description",
                    "source_function",
                }
                or any(not isinstance(item.get(field), str) or not item.get(field)
                       for field in item)
                or item.get("class")
                not in set().union(*safety_classes.values()) - {"unwind"}
                for item in language_safety_baseline_inventory
            )
            or [
                str(item["property_id"])
                for item in language_safety_baseline_inventory
            ]
            != sorted({
                str(item["property_id"])
                for item in language_safety_baseline_inventory
            })
            or not isinstance(loops, list)
            or any(
                not isinstance(loop, Mapping)
                or set(loop)
                != {
                    "loop_id",
                    "source_function",
                    "unwinding_property_id",
                }
                or re.fullmatch(r".+\.[0-9]+", str(loop.get("loop_id", "")))
                is None
                or not isinstance(loop.get("source_function"), str)
                or not loop.get("source_function")
                or loop.get("unwinding_property_id")
                != re.sub(
                    r"\.([0-9]+)$",
                    r".unwind.\1",
                    str(loop.get("loop_id", "")),
                )
                for loop in loops
            )
            or [str(loop["loop_id"]) for loop in loops]
            != sorted({str(loop["loop_id"]) for loop in loops})
            or not isinstance(queries, list)
            or not queries
            or not isinstance(
                partitioned.get("language_safety_properties"), int
            )
            or isinstance(
                partitioned.get("language_safety_properties"), bool
            )
            or int(partitioned.get("language_safety_properties", 0)) <= 0
        ):
            raise ComponentBisimulationError(
                "contextual partitioned property inventory is malformed"
            )
        expected_safety_ids = {
            partition: sorted(
                str(item["property_id"])
                for item in language_safety_inventory
                if item["class"] in classes
            )
            for partition, classes in safety_classes.items()
            if partition != "unwinding"
        }
        expected_safety_ids["unwinding"] = [
            str(loop["unwinding_property_id"]) for loop in loops
        ]
        baseline_safety_ids = {
            str(item["property_id"])
            for item in language_safety_baseline_inventory
        }
        expected_safety_groups = [
            (partition, selected_ids)
            for partition in safety_classes
            for selected_ids in safety_property_groups(partition,
                expected_safety_ids[partition], language_safety_inventory, strategy=partitioned['strategy'])
        ]
        if (
            not expected_safety_groups
        ):
            raise ComponentBisimulationError(
                "contextual language-safety property inventory is stale"
            )
        safety_queries = [
            query for query in queries
            if isinstance(query, Mapping)
            and query.get("kind") == "language_safety"
        ]
        authored_queries = [
            query for query in queries
            if isinstance(query, Mapping)
            and query.get("kind") == "authored_assertion"
        ]
        checked_unwinding_ids = {
            str(property_id)
            for query in safety_queries
            if query.get("safety_partition") == "unwinding"
            for property_id in query.get("property_ids", [])
            if property_id in expected_safety_ids["unwinding"]
        }
        if (
            len(safety_queries) + len(authored_queries) != len(queries)
            or not safety_group_refinement(
                [(query.get("safety_partition"), query.get("expected_property_ids"))
                 for query in safety_queries], expected_safety_groups,
                complete=shard_status != "incomplete")
            or any(
                set(query)
                not in (
                    {
                        "kind",
                        "safety_partition",
                        "expected_property_ids",
                        "property_ids",
                        "status",
                        "code",
                        "properties",
                        "output_sha256",
                    },
                    {
                        "kind",
                        "safety_partition",
                        "expected_property_ids",
                        "property_ids",
                        "status",
                        "code",
                        "properties",
                        "output_sha256",
                        "detail",
                    },
                )
                or not isinstance(query.get("property_ids"), list)
                or query.get("property_ids")
                != sorted(set(query.get("property_ids", [])))
                or any(
                    not isinstance(property_id, str) or not property_id
                    for property_id in query.get("property_ids", [])
                )
                for query in safety_queries
            )
            or any(authored_query_ids(query, partitioned['strategy'],
                {row['property_id']: row for row in assertions}) is None for query in authored_queries)
            or any(
                not isinstance(query.get("status"), str)
                or not query.get("status")
                or not isinstance(query.get("code"), str)
                or not query.get("code")
                or not isinstance(query.get("properties"), int)
                or isinstance(query.get("properties"), bool)
                or int(query.get("properties", -1)) < 0
                or re.fullmatch(
                    r"[0-9a-f]{64}", str(query.get("output_sha256", ""))
                )
                is None
                or (
                    "detail" in query
                    and (
                        not isinstance(query.get("detail"), str)
                        or not query.get("detail")
                    )
                )
                for query in queries
            )
            or any(
                (
                    query.get("safety_partition") != "unwinding"
                    and not set(query.get("expected_property_ids", []))
                    <= set(query.get("property_ids", []))
                )
                or not set(query.get("property_ids", []))
                <= set(query.get("expected_property_ids", []))
                | (baseline_safety_ids
                   if query.get("safety_partition") == "unwinding" else set())
                for query in safety_queries
                if query.get("status") == "satisfied"
            )
            or partitioned.get("language_safety_properties")
            != len(language_safety_inventory) + len(checked_unwinding_ids)
        ):
            raise ComponentBisimulationError(
                "contextual partitioned property query evidence is malformed"
            )
        queried_assertions = [
            identity for query in authored_queries for identity in authored_query_ids(
                query, partitioned['strategy'], {row['property_id']: row for row in assertions})
        ]
        scheduled_assertion_ids = [
            str(assertion["property_id"])
            for assertion in sorted(assertions,
                key=lambda assertion: _property_query_order(assertion, strategy=partitioned["strategy"]))
        ]
        if queried_assertions != scheduled_assertion_ids[:len(queried_assertions)]:
            raise ComponentBisimulationError(
                "contextual assertion queries omit or reorder a scheduled prerequisite"
            )
        if shard_status == "satisfied" and (
            queried_assertions != scheduled_assertion_ids
            or any(query.get("status") != "satisfied" for query in queries)
            or any(
                query.get("properties")
                != len(query.get("property_ids", []))
                for query in safety_queries
            )
        ):
            raise ComponentBisimulationError(
                "satisfied contextual shard did not prove every property partition"
            )
        if shard_status == "violated" and not any(
            query.get("status") == "violated" for query in queries
        ):
            raise ComponentBisimulationError(
                "violated contextual shard has no violated property partition"
            )

"""Checked record values in the private semantic contract's call metadata.

Physical arguments stay explicit. Consumers without record expressions must
reject them; contextual bisimulation executes the checked typed adapters.
"""

from .aggregate_result_binding import normalize_aggregate_result_words
from .machine_binding import MachineProjectionV1
from .semantic_external_transducers import (
    ComponentSemanticContractError, checked_external_argument_words,
    checked_local_cell_result_projection,
)


def checked_word_record_fields(logical_type, logical_types):
    fields = getattr(logical_type, "fields", ())
    if getattr(logical_type, "kind", None) != "record" or not fields:
        raise ComponentSemanticContractError("call record requires a nonempty record type")
    for field in fields:
        value = logical_types[field.type_id]
        if value.kind not in {"scalar", "enum"} or value.c_type not in {"uint32_t", "int32_t"}:
            raise ComponentSemanticContractError("call record fields must each occupy one checked word")
    return fields


def normalize_external_aggregate_binding(*, provider, logical, logical_types, contract_row, payload):
    if not any(isinstance(row, dict) and row.get("kind") == "aggregate_result"
               for row in provider.get("argument_transducers", []) or []):
        return provider, payload
    result_type = logical_types.get(getattr(logical, "result_type_id", None))
    fields = checked_word_record_fields(result_type, logical_types)
    try:
        transducers, cells, memory, result = normalize_aggregate_result_words(
            field_ids=[field.identity for field in fields], provider=provider,
            payload=payload, contract_row=contract_row,
            argument_words=checked_external_argument_words(payload), context="semantic aggregate return")
    except ValueError as error:
        raise ComponentSemanticContractError(str(error)) from error
    return ({**provider, "argument_transducers": transducers, "result_projection": result},
            {**payload, "local_cells": cells, "caller_memory_frame": memory})


def checked_record_result_projection(value, *, logical_type, logical_types, **arguments):
    fields = checked_word_record_fields(logical_type, logical_types)
    expected = {field.identity for field in fields}
    if (not isinstance(value, dict) or set(value) != {"kind", "cell_id", "fields"} or
            value["kind"] != "local_cell_record" or not isinstance(value["fields"], list)):
        raise ComponentSemanticContractError("record result requires a checked local-cell field inventory")
    projections = []
    seen = set()
    for row in value["fields"]:
        if (not isinstance(row, dict) or set(row) != {"id", "word_index"} or
                not isinstance(row["id"], str) or row["id"] not in expected or row["id"] in seen):
            raise ComponentSemanticContractError("record result fields are missing, duplicated or unknown")
        seen.add(row["id"])
        projection, rule = checked_local_cell_result_projection(
            {"kind": "local_cell_word", "cell_id": value["cell_id"], "word_index": row["word_index"]},
            logical_kind="scalar", **arguments)
        if rule is not None:
            raise ComponentSemanticContractError("record result requires unconditional initialized output words")
        projections.append({"id": row["id"], "projection": projection})
    if seen != expected:
        raise ComponentSemanticContractError("record result does not cover every logical field")
    return MachineProjectionV1.parse({"kind": "record_view", "at": "call",
        "fields": sorted(projections, key=lambda row: row["id"])}, "semantic record result").to_payload(), None

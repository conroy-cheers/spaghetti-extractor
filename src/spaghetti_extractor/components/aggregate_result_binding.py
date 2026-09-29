"""Shared compiler-checked hidden return storage for word-record results."""

from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..boundary._canonical import BoundaryModelError, array, object_


def normalize_aggregate_result_words(*, field_ids: Sequence[str], provider: Mapping[str, object],
                                     payload: Mapping[str, object], contract_row: Mapping[str, object],
                                     argument_words: int, context: str):
    value = provider.get("argument_transducers")
    if (not isinstance(value, list) or type(argument_words) is not int or
            len(value) != argument_words or not field_ids or
            any(not isinstance(item, str) or not item for item in field_ids) or
            len(set(field_ids)) != len(field_ids)):
        raise BoundaryModelError(f"{context} aggregate-result inventory is invalid")
    aggregate_rows = [(index, item) for index, item in enumerate(value)
                      if isinstance(item, Mapping) and item.get("kind") == "aggregate_result"]
    if len(aggregate_rows) != 1 or provider.get("result_projection") is not None:
        raise BoundaryModelError(f"{context} aggregate result must have one derived projection")
    physical_index, transducer = aggregate_rows[0]
    cell_id = transducer.get("cell_id")
    if not isinstance(cell_id, str) or not cell_id:
        raise BoundaryModelError(f"{context} aggregate result cell id is invalid")
    boundary = object_(contract_row.get("boundary"), f"{context} boundary")
    frame = object_(
        boundary.get("physical_call_frame_v3"),
        f"{context} physical call frame",
    )
    transport = object_(frame.get("transport"), f"{context} physical transport")
    arguments = [
        object_(item, f"{context} physical argument")
        for item in array(transport.get("arguments"), f"{context} physical arguments")
    ]
    hidden = [item for item in arguments if item.get("role") == "hidden_sret"]
    physical_results = [
        object_(item, f"{context} physical result")
        for item in array(transport.get("results"), f"{context} physical results")
    ]
    if len(hidden) != 1 or len(physical_results) != 1:
        raise BoundaryModelError(
            f"{context} aggregate result lacks one compiler-lowered hidden return"
        )
    hidden_fragments = array(hidden[0].get("fragments"), f"{context} hidden return")
    result_fragments = array(
        physical_results[0].get("fragments"), f"{context} aggregate result"
    )
    if len(hidden_fragments) != 1 or len(result_fragments) != 1:
        raise BoundaryModelError(f"{context} aggregate result is fragmented")
    hidden_location = object_(
        object_(hidden_fragments[0], f"{context} hidden fragment").get("location"),
        f"{context} hidden location",
    )
    result_location = object_(
        object_(result_fragments[0], f"{context} result fragment").get("location"),
        f"{context} result location",
    )
    hidden_offset = hidden_location.get("stack_offset_bytes")
    derived_index = (
        (hidden_offset - 4) // 4
        if isinstance(hidden_offset, int)
        and not isinstance(hidden_offset, bool)
        and hidden_offset >= 4
        and hidden_offset % 4 == 0
        else -1
    )
    result_width = len(field_ids) * 32
    if (
        physical_index != derived_index
        or hidden_location.get("kind") != "stack"
        or hidden_location.get("width_bits") != 32
        or hidden[0].get("storage_bits") != 32
        or physical_results[0].get("pass_mode") != "indirect"
        or result_location.get("kind") != "memory"
        or result_location.get("memory_slot") != hidden[0].get("id")
        or result_location.get("width_bits") != result_width
        or physical_results[0].get("storage_bits") != result_width
    ):
        raise BoundaryModelError(
            f"{context} aggregate result disagrees with its compiler-lowered ABI"
        )
    relation = {
        "argument_index": physical_index,
        "extent_words": len(field_ids),
        "variants": [
            {
                "id": "aggregate_result",
                "discriminants": [],
                "input_word_indices": [],
                "output_word_indices": list(range(len(field_ids))),
                "output_condition": "always",
                "failure_preserved_word_indices": [],
                "failure_observed_word_indices": [],
            }
        ],
    }
    relation_sha256 = canonical_sha256_v3(relation)
    local_cells = list(array(payload.get("local_cells", []), f"{context} local cells"))
    if any(
        isinstance(item, Mapping)
        and item.get("argument_index") == physical_index
        for item in local_cells
    ):
        raise BoundaryModelError(f"{context} aggregate local cell is duplicated")
    local_cells.append(relation)
    normalized = [dict(object_(item, f"{context} argument transducer")) for item in value]
    normalized[physical_index] = {
        "kind": "local_cell",
        "cell_id": cell_id,
        "initial_words": [None] * len(field_ids),
        "local_cell_relation_sha256": relation_sha256,
    }
    raw_memory = payload.get("caller_memory_frame")
    if raw_memory is None:
        memory = {
            "status": "complete",
            "model": "compiler-derived-hidden-sret-v1",
            "arguments": [],
            "assumptions": [
                "hidden return storage is retained only during the call"
            ],
        }
    else:
        memory = dict(object_(raw_memory, f"{context} caller-memory frame"))
        memory["arguments"] = list(
            array(memory.get("arguments"), f"{context} caller-memory arguments")
        )
    if any(
        isinstance(item, Mapping) and item.get("argument_index") == physical_index
        for item in memory["arguments"]
    ):
        raise BoundaryModelError(f"{context} aggregate caller memory is duplicated")
    memory["arguments"].append(
        {
            "argument_index": physical_index,
            "role": "caller_memory",
            "access": "read_write",
            "extent": "enclosing_object",
            "retention": "during_call",
        }
    )
    memory["arguments"] = sorted(
        memory["arguments"], key=lambda item: int(item["argument_index"])
    )
    result_projection = {
        "kind": "local_cell_record",
        "cell_id": cell_id,
        "fields": [
            {"id": field_id, "word_index": index}
            for index, field_id in enumerate(field_ids)
        ],
    }
    return normalized, local_cells, memory, result_projection

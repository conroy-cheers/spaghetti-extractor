"""Conservative byte-terminator result relations, not first-NUL semantics.

Read-only services require a current input witness; writable services construct
an output witness within a checked destination. Both retain call-time memory
correspondence. Declarations prove neither external implementations nor source
summary composition.
"""

from collections.abc import Mapping

RELATION = "terminated_byte_offset"
WRITTEN_RELATION = "written_terminated_byte_count"


def checked_terminated_write(payload, *, argument_words):
    """A returning buffer service promises a zero at its returned byte count.

    This is an explicit environment contract, including count zero. It does not
    imply first-zero, string contents, API success, or external qualification.
    The one writable footprint makes the output constraint constructible for
    every admitted positive capacity, independently of incoming buffer bytes.
    """
    rows = payload.get("result_register_relations", [])
    if not isinstance(rows, list) or not any(
            isinstance(row, Mapping) and row.get("relation") == WRITTEN_RELATION for row in rows):
        return None
    if len(rows) != 1:
        raise ValueError("written terminated byte count requires one result relation")
    row = rows[0]
    if (type(argument_words) is not int or argument_words < 2 or
            set(row) != {"register", "relation", "base_argument", "capacity_argument"} or
            row["register"] != "eax" or
            any(type(row[key]) is not int or not 0 <= row[key] < argument_words
                for key in ("base_argument", "capacity_argument")) or
            row["base_argument"] == row["capacity_argument"]):
        raise ValueError("written terminated byte count result shape is unsupported")
    footprint = {"access": "write", "base_argument": row["base_argument"], "offset": 0,
                 "size": {"kind": "argument", "argument": row["capacity_argument"], "scale": 1},
                 "nullable": False}
    if (payload.get("memory_effect") != "argumentRanges" or
            payload.get("world_effect") not in {"none", "opaqueResources"} or
            payload.get("disposition") != "returns" or
            payload.get("memory_footprints") != [footprint] or
            payload.get("callback_effect") not in (None, "none") or
            any(payload.get(key, []) != [] for key in ("out_pointer_relations", "out_interface_relations")) or
            any(payload.get(key) is not None for key in (
                "world_effect_argument", "world_effect_release", "external_service_protocol", "effect_model"))):
        raise ValueError("written terminated byte count requires one returning writable buffer without other effects")
    # Python equality treats True as 1 and False as 0. Do not let that alias
    # malformed declarations to the canonical footprint accepted independently.
    actual = payload["memory_footprints"][0]
    if (type(actual["base_argument"]) is not int or type(actual["offset"]) is not int or
            type(actual["size"]["argument"]) is not int or type(actual["size"]["scale"]) is not int or
            type(actual["nullable"]) is not bool):
        raise ValueError("written terminated byte count footprint shape is unsupported")
    return dict(row)


def checked_terminated_read(payload, *, argument_words):
    rows = payload.get("result_register_relations", [])
    if not isinstance(rows, list) or not any(
            isinstance(row, Mapping) and row.get("relation") == RELATION for row in rows):
        return None
    if len(rows) != 1:
        raise ValueError("terminated byte offset requires one result relation")
    row = rows[0]
    if (type(argument_words) is not int or argument_words < 1 or
            set(row) != {"register", "relation", "base_argument", "nullable"} or
            row["register"] != "eax" or type(row["nullable"]) is not bool or
            type(row["base_argument"]) is not int or
            not 0 <= row["base_argument"] < argument_words):
        raise ValueError("terminated byte offset result shape is unsupported")
    if (payload.get("memory_effect") != "readOnly" or payload.get("world_effect") != "none" or
            payload.get("disposition") != "returns" or payload.get("memory_footprints", []) != [] or
            payload.get("callback_effect") not in (None, "none") or
            any(payload.get(key, []) != [] for key in ("out_pointer_relations", "out_interface_relations")) or
            any(payload.get(key) is not None for key in (
                "world_effect_argument", "world_effect_release", "external_service_protocol", "effect_model"))):
        raise ValueError("terminated byte offset requires a returning read-only service without other effects")
    return dict(row)

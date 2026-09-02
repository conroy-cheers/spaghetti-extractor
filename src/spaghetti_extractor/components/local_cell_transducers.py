"""One checked local-cell transducer shared by proof and C realization."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from ..external.interface_profiles import (
    ExternalInterfaceProfileError,
    parse_interface_local_cell_relation,
    select_interface_local_cell_variant,
)
from .machine_binding import MachineProjectionV1


class LocalCellTransducerError(ValueError):
    """A local-cell binding contradicts its checked boundary relation."""


@dataclass(frozen=True)
class CheckedLocalCellSelection:
    variant_id: str
    input_word_indices: frozenset[int]
    output_word_indices: frozenset[int]
    output_condition: str
    failure_preserved_word_indices: frozenset[int]
    failure_observed_word_indices: frozenset[int]


def checked_initial_words(
    value: object, *, context: str,
) -> tuple[int | None | Mapping[str, object], ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= 256:
        raise LocalCellTransducerError(f"{context} initial words are invalid")
    result: list[int | None | Mapping[str, object]] = []
    for index, raw in enumerate(value):
        if raw is None:
            result.append(None)
            continue
        if isinstance(raw, int) and not isinstance(raw, bool):
            if not 0 <= raw <= 0xFFFFFFFF:
                raise LocalCellTransducerError(
                    f"{context} initial word {index} exceeds a word"
                )
            result.append(raw)
            continue
        if not isinstance(raw, Mapping) or set(raw) != {
            "kind", "projection",
        } or raw.get("kind") != "entry_projection":
            raise LocalCellTransducerError(
                f"{context} initial word {index} is unsupported"
            )
        projection = MachineProjectionV1.parse(
            raw.get("projection"), f"{context} initial word {index} projection"
        )
        if (
            projection.kind not in {"constant", "register", "stack"}
            or projection.payload.get("width") != 32
            or (
                projection.kind != "constant"
                and projection.payload.get("at") != "entry"
            )
            or (
                projection.kind == "stack"
                and (
                    not isinstance(projection.payload.get("offset"), int)
                    or isinstance(projection.payload.get("offset"), bool)
                    or not 0 <= int(projection.payload["offset"]) <= 65532
                )
            )
        ):
            raise LocalCellTransducerError(
                f"{context} initial word {index} needs a 32-bit entry projection"
            )
        result.append({
            "kind": "entry_projection",
            "projection": projection.to_payload(),
        })
    return tuple(result)


def exact_initial_word_values(
    words: Sequence[int | None | Mapping[str, object]],
) -> dict[int, int]:
    result: dict[int, int] = {}
    for index, word in enumerate(words):
        if isinstance(word, int):
            result[index] = word
        elif isinstance(word, Mapping):
            projection = word.get("projection")
            if (
                isinstance(projection, Mapping)
                and projection.get("kind") == "constant"
                and isinstance(projection.get("value"), int)
                and not isinstance(projection.get("value"), bool)
            ):
                result[index] = int(projection["value"])
    return result


def checked_local_cell_selection(
    relation_value: object,
    *,
    physical_index: int,
    initial_words: Sequence[int | None | Mapping[str, object]],
    memory: Mapping[str, object],
    context: str,
) -> CheckedLocalCellSelection:
    try:
        relation = parse_interface_local_cell_relation(
            relation_value, context=f"{context} relation"
        )
        variant = select_interface_local_cell_variant(
            relation,
            exact_initial_word_values(initial_words),
            context=f"{context} relation",
        )
    except ExternalInterfaceProfileError as exc:
        raise LocalCellTransducerError(str(exc)) from exc
    if (
        relation.argument_index != physical_index
        or relation.extent_words != len(initial_words)
        or memory.get("role") != "caller_memory"
        or memory.get("retention") != "during_call"
        or memory.get("extent") not in {"fixed_word", "enclosing_object"}
        or (
            variant.output_word_indices
            and memory.get("access") != "read_write"
        )
        or any(initial_words[index] is None for index in variant.input_word_indices)
        or any(
            initial_words[index] is None
            for index in variant.failure_preserved_word_indices
        )
        or any(
            initial_words[index] is None
            for index in variant.failure_observed_word_indices
        )
    ):
        raise LocalCellTransducerError(
            f"{context} relation contradicts the checked caller-memory frame"
        )
    return CheckedLocalCellSelection(
        variant_id=variant.identity,
        input_word_indices=frozenset(variant.input_word_indices),
        output_word_indices=frozenset(variant.output_word_indices),
        output_condition=variant.output_condition,
        failure_preserved_word_indices=frozenset(
            variant.failure_preserved_word_indices
        ),
        failure_observed_word_indices=frozenset(
            variant.failure_observed_word_indices
        ),
    )


__all__ = [
    "CheckedLocalCellSelection",
    "LocalCellTransducerError",
    "checked_initial_words",
    "checked_local_cell_selection",
    "exact_initial_word_values",
]

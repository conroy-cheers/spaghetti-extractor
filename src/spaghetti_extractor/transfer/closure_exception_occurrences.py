"""Exception occurrence lookup for transfer execution closure."""

from __future__ import annotations

from typing import Mapping

from .exception_semantics import CheckedExceptionTransitionV1
from .model import _Call, _Transfer
from .operations import NATIVE_EXCEPTION_EFFECTS_V2

def _transfer_exception_occurrences_v1(
    transfer: _Transfer,
) -> tuple[tuple[int, str, _Call | None], ...]:
    """Return every canonical exception occurrence in effect order."""

    rows: list[tuple[int, str, _Call | None]] = []
    for effect_index, effect in enumerate(transfer.actions[:-1]):
        if effect.op in NATIVE_EXCEPTION_EFFECTS_V2:
            rows.append((effect_index, effect.op, None))
        elif effect.op == "call":
            call = transfer.calls[effect.args[0]]
            rows.extend(
                (effect_index, operation, call)
                for operation in call.native_exception_operations
            )
    return tuple(rows)


def _checked_exception_v1(
    rows: Mapping[tuple[str, int, str | None], CheckedExceptionTransitionV1],
    *,
    unit_id: str,
    effect_index: int,
    operation: str,
) -> CheckedExceptionTransitionV1 | None:
    return rows.get((unit_id, effect_index, operation)) or rows.get(
        (unit_id, effect_index, None)
    )

"""Input joins checked before the execution-closure fixed point."""

from __future__ import annotations

from typing import Mapping

from .closure_model import ExecutionClosureContextV1


def validate_checked_exception_targets_v1(
    context: ExecutionClosureContextV1,
    rva_by_identity: Mapping[str, int],
) -> None:
    """Require every authorizing handler, unwind, and resume unit to exist."""

    for transition in context.checked_exception_transitions:
        if not transition.authorizing:
            continue
        handler_invalid = (
            transition.disposition == "handled"
            and (
                transition.handler_unit_id is None
                or rva_by_identity.get(transition.handler_unit_id)
                != transition.handler_rva
                or any(
                    identity not in rva_by_identity
                    for identity in transition.unwind_unit_ids
                )
            )
        )
        resumption_invalid = (
            transition.resumption_unit_id is not None
            and rva_by_identity.get(transition.resumption_unit_id)
            != transition.resumption_rva
        )
        if handler_invalid or resumption_invalid:
            raise ValueError(
                "checked exception continuation names a non-transfer unit"
            )

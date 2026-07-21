from __future__ import annotations

from typing import Any

from .register_dataflow_solver import parse_register_dataflow_pack_result
from .register_dataflow_summary_format import (
    REGISTER_DATAFLOW_PACK_SUMMARY_FORMAT,
    parse_register_dataflow_pack_summary,
    register_dataflow_pack_summary_payload,
)


def summarize_register_dataflow_pack_result(
    payload: object,
) -> dict[str, Any]:
    result = parse_register_dataflow_pack_result(payload)
    return register_dataflow_pack_summary_payload(
        pack_id=result["pack_id"],
        status=result["status"],
        regions=result["regions"],
    )


__all__ = [
    "REGISTER_DATAFLOW_PACK_SUMMARY_FORMAT",
    "parse_register_dataflow_pack_summary",
    "summarize_register_dataflow_pack_result",
]

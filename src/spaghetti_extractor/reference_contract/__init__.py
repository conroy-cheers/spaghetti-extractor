"""Narrow public API for static reference-contract operations."""

from .common import REFERENCE_CONTRACT_MODEL_ID
from .reference_contract import (
    stage_a_diff_obligations,
    stage_a_explain_obligations,
    stage_a_export_reference_contract,
    stage_a_smoke_contract,
)


__all__ = [
    "REFERENCE_CONTRACT_MODEL_ID",
    "stage_a_diff_obligations",
    "stage_a_explain_obligations",
    "stage_a_export_reference_contract",
    "stage_a_smoke_contract",
]

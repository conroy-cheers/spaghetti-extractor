"""Reference-contract emission and diagnostics from relational v3 evidence."""

from .._contract_tools.reference_contract import (
    REFERENCE_CONTRACT_MODEL_ID,
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

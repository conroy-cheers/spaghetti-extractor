"""Fail-closed authority receipts for candidate reconstruction candidate generation."""

from .checker import (
    build_candidate_authority,
    require_candidate_authority,
    validate_candidate_authority,
)
from .io import parse_candidate_authority
from .model import (
    SPX_CANDIDATE_AUTHORITY_V3_FORMAT,
    SPX_CANDIDATE_AUTHORITY_V3_VERSION,
    CandidateAuthorityV3Error,
    CandidateAuthorityV3GateError,
    CandidateAuthorityV3Issue,
    CandidateAuthorityV3Receipt,
    CandidateAuthorityV3Status,
)


__all__ = [
    "SPX_CANDIDATE_AUTHORITY_V3_FORMAT",
    "SPX_CANDIDATE_AUTHORITY_V3_VERSION",
    "CandidateAuthorityV3Error",
    "CandidateAuthorityV3GateError",
    "CandidateAuthorityV3Issue",
    "CandidateAuthorityV3Receipt",
    "CandidateAuthorityV3Status",
    "build_candidate_authority",
    "parse_candidate_authority",
    "require_candidate_authority",
    "validate_candidate_authority",
]

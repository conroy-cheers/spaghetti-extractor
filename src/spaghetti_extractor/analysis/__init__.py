"""Static PE32 extraction and semantic qualification.

This package is the authoritative Stage A implementation used by the active
reconstruction pipeline.  It consumes binaries statically and emits evidence;
it does not implement binary-equivalence or source-equivalence proofs.
"""

from .schema import STATIC_ANALYSIS_MODEL_ID, STATIC_ANALYSIS_PROFILE_ID

__all__ = ["STATIC_ANALYSIS_MODEL_ID", "STATIC_ANALYSIS_PROFILE_ID"]

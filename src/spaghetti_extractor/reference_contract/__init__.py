"""Reference-contract model identity.

Generation and diagnostics are intentionally imported from their owning
modules.  Keeping this package facade data-only prevents every consumer from
acquiring the full extraction and diagnostic dependency graphs.
"""

from .common import REFERENCE_CONTRACT_MODEL_ID


__all__ = ["REFERENCE_CONTRACT_MODEL_ID"]

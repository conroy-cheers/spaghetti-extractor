"""Legacy package boundary for shared static semantic implementation.

The public binary-pair contract path has been removed. New artifact consumers
must use :mod:`spaghetti_extractor.static_program`.
"""

from .common import REFERENCE_CONTRACT_MODEL_ID


__all__ = ["REFERENCE_CONTRACT_MODEL_ID"]

"""Static relational analysis producer.

This module is the stable producer-side entrypoint.  Its implementation remains
in ``pipeline`` during the migration, but consumers must depend on this module
and the serialized analysis manifest rather than proof-generation internals.
"""

from .pipeline import stage_a_analyze_relational

__all__ = ["stage_a_analyze_relational"]

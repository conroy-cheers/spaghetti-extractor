"""Static relational analysis producer.

This module is the stable producer-side entrypoint. Consumers must depend on
these functions and serialized phase manifests rather than implementation
internals.
"""

from .pipeline import (
    stage_a_analyze_relational,
    stage_a_discover_relational_proposals,
)


def stage_a_assemble_relational_analysis(*args, **kwargs):
    """Load downstream assembly lazily so proposal producers do not depend on it."""

    from .assembly import stage_a_assemble_relational_analysis as assemble

    return assemble(*args, **kwargs)

__all__ = [
    "stage_a_analyze_relational",
    "stage_a_assemble_relational_analysis",
    "stage_a_discover_relational_proposals",
]

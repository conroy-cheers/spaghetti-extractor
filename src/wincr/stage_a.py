"""Compatibility import for the evidence-only Stage A v2 implementation.

Whole-program acceptance lives in :mod:`wincr.relational`. New code should
import :mod:`wincr.stage_a_legacy` only when it explicitly needs v2 evidence
or reference-contract tooling.
"""

from __future__ import annotations

import sys

from . import stage_a_legacy as _legacy


# Preserve existing imports and monkeypatch targets while keeping the legacy
# implementation physically and conceptually separate from v3 acceptance.
sys.modules[__name__] = _legacy

"""Public API for the faithful behavioral-C backend."""

from .formats import (
    BEHAVIORAL_C_COVERAGE_FORMAT,
    BEHAVIORAL_C_LAYOUT_INTENT_FORMAT,
    BEHAVIORAL_C_LOWERING_FORMAT,
    BEHAVIORAL_C_PACKAGE_FORMAT,
    BEHAVIORAL_C_PLAN_FORMAT,
)
from .behavioral_c_layout import build_behavioral_c_plan
from .behavioral_c_model import (
    BehavioralCFunction,
    BehavioralCLayoutIntent,
    BehavioralCPlan,
)
from .behavioral_c_package import (
    write_spx_behavioral_c_package,
    write_spx_behavioral_c_package_from_semantic_object,
)

__all__ = [
    "BEHAVIORAL_C_COVERAGE_FORMAT",
    "BEHAVIORAL_C_LAYOUT_INTENT_FORMAT",
    "BEHAVIORAL_C_LOWERING_FORMAT",
    "BEHAVIORAL_C_PACKAGE_FORMAT",
    "BEHAVIORAL_C_PLAN_FORMAT",
    "BehavioralCFunction",
    "BehavioralCLayoutIntent",
    "BehavioralCPlan",
    "build_behavioral_c_plan",
    "write_spx_behavioral_c_package",
    "write_spx_behavioral_c_package_from_semantic_object",
]

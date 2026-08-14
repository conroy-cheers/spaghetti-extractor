"""Composable, target-neutral component contracts and lift configurations."""

from .contracts import (
    build_lift_unit_contract_v2,
    load_component_boundary_review_v2,
)
from .configuration import compose_component_configuration_v2
from .intent import ComponentIntentError, load_component_catalog_intent_v2
from .resolution import resolve_component_catalog_v2
from .qualification import bind_component_evidence_v2, qualify_lift_unit_v2
from .source import build_component_source_package_v2

__all__ = [
    "ComponentIntentError",
    "build_lift_unit_contract_v2",
    "bind_component_evidence_v2",
    "build_component_source_package_v2",
    "compose_component_configuration_v2",
    "load_component_catalog_intent_v2",
    "load_component_boundary_review_v2",
    "qualify_lift_unit_v2",
    "resolve_component_catalog_v2",
]

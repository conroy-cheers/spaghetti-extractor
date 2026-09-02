"""Format ownership for external-environment intent and resolution."""

from __future__ import annotations

from ..artifacts.format_spec import FormatSpecV1


_OWNER = __name__

FORMAT_SPECS = (
    FormatSpecV1(
        literal="spaghetti-extractor-external-environment-intent-v1",
        version=1,
        owner=_OWNER,
        codec="spaghetti_extractor.external.environment",
        role="intent",
        state="active",
        symbol="EXTERNAL_ENVIRONMENT_INTENT_FORMAT",
    ),
    FormatSpecV1(
        literal=(
            "spaghetti-extractor-external-environment-analysis-projection-v1"
        ),
        version=1,
        owner=_OWNER,
        codec="spaghetti_extractor.external.environment",
        role="analysis_projection",
        state="active",
        symbol="EXTERNAL_ENVIRONMENT_ANALYSIS_PROJECTION_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-resolved-external-environment-v1",
        version=1,
        owner=_OWNER,
        codec="spaghetti_extractor.external.resolved",
        role="resolved_contract",
        state="active",
        symbol="RESOLVED_EXTERNAL_ENVIRONMENT_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-checked-external-service-protocol-v1",
        version=1,
        owner=_OWNER,
        codec="spaghetti_extractor.external.service_protocols",
        role="checked_service_protocol",
        state="active",
        symbol="CHECKED_EXTERNAL_SERVICE_PROTOCOL_FORMAT",
    ),
)

EXTERNAL_ENVIRONMENT_INTENT_FORMAT = FORMAT_SPECS[0].literal
EXTERNAL_ENVIRONMENT_ANALYSIS_PROJECTION_FORMAT = FORMAT_SPECS[1].literal
RESOLVED_EXTERNAL_ENVIRONMENT_FORMAT = FORMAT_SPECS[2].literal
CHECKED_EXTERNAL_SERVICE_PROTOCOL_FORMAT = FORMAT_SPECS[3].literal

__all__ = [spec.symbol for spec in FORMAT_SPECS] + ["FORMAT_SPECS"]

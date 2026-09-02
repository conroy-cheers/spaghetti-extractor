"""Format ownership for relocatable semantic-object artifacts."""

from __future__ import annotations

from ..artifacts.format_spec import FormatSpecV1


FORMAT_SPECS = (
    FormatSpecV1(
        literal="spaghetti-extractor-semantic-object-v1",
        version=1,
        owner=__name__,
        codec="spaghetti_extractor.semantic_objects.semantic_object",
        role="semantic_object",
        state="active",
        symbol="SEMANTIC_OBJECT_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-machine-object-authority-v2",
        version=2,
        owner=__name__,
        codec="spaghetti_extractor.semantic_objects.object_authority",
        role="authority",
        state="active",
        symbol="MACHINE_OBJECT_AUTHORITY_V2_FORMAT",
    ),
    # Retired authority-DAG exception formats remain declared here so the
    # registry can reject a production reader that tries to revive them. The
    # semantic object now derives exception definitions directly from
    # transfer-v2 plus the resolved environment.
    FormatSpecV1(
        literal="spaghetti-extractor-exception-evidence-record-v4",
        version=4,
        owner=__name__,
        codec=__name__,
        role="authority_evidence_record",
        state="retired",
        symbol="RETIRED_EXCEPTION_EVIDENCE_RECORD_V4_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-exceptional-transition-record-v5",
        version=5,
        owner=__name__,
        codec=__name__,
        role="authority_record",
        state="retired",
        symbol="RETIRED_EXCEPTIONAL_TRANSITION_RECORD_V5_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-exception-closure-certificate-v4",
        version=4,
        owner=__name__,
        codec=__name__,
        role="authority_certificate",
        state="retired",
        symbol="RETIRED_EXCEPTION_CLOSURE_CERTIFICATE_V4_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-exception-evidence-record-v3",
        version=3,
        owner=__name__,
        codec=__name__,
        role="authority_evidence_record",
        state="retired",
        symbol="RETIRED_EXCEPTION_EVIDENCE_RECORD_V3_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-exceptional-transition-record-v3",
        version=3,
        owner=__name__,
        codec=__name__,
        role="authority_record",
        state="retired",
        symbol="RETIRED_EXCEPTIONAL_TRANSITION_RECORD_V3_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-exceptional-transition-record-v4",
        version=4,
        owner=__name__,
        codec=__name__,
        role="authority_record",
        state="retired",
        symbol="RETIRED_EXCEPTIONAL_TRANSITION_RECORD_V4_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-exception-closure-certificate-v3",
        version=3,
        owner=__name__,
        codec=__name__,
        role="authority_certificate",
        state="retired",
        symbol="RETIRED_EXCEPTION_CLOSURE_CERTIFICATE_V3_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-authority-diagnostics-v3",
        version=3,
        owner=__name__,
        codec=__name__,
        role="operator_diagnostic",
        state="retired",
        symbol="RETIRED_AUTHORITY_DIAGNOSTICS_V3_FORMAT",
    ),
)

SEMANTIC_OBJECT_FORMAT = FORMAT_SPECS[0].literal
MACHINE_OBJECT_AUTHORITY_V2_FORMAT = FORMAT_SPECS[1].literal

__all__ = [spec.symbol for spec in FORMAT_SPECS] + ["FORMAT_SPECS"]

"""Internal formats owned by deterministic phase and receipt constructors."""

from __future__ import annotations

from .format_spec import FormatSpecV1


_OWNER = __name__

FORMAT_SPECS = (
    FormatSpecV1(
        literal="spaghetti-extractor-ca-phase-inputs-v1",
        version=1,
        owner=_OWNER,
        codec=_OWNER,
        role="build_input",
        state="active",
        symbol="CA_PHASE_INPUTS_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-ca-phase-manifest-v1",
        version=1,
        owner=_OWNER,
        codec="spaghetti_extractor.artifacts.build_manifest",
        role="build_manifest",
        state="active",
        symbol="CA_PHASE_MANIFEST_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-ca-receipt-gate-v1",
        version=1,
        owner=_OWNER,
        codec="spaghetti_extractor.artifacts.build_manifest",
        role="build_manifest",
        state="active",
        symbol="CA_RECEIPT_GATE_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-structural-executable-v2",
        version=2,
        owner=_OWNER,
        codec=_OWNER,
        role="execution_authority_receipt",
        state="retired",
        symbol="RETIRED_STRUCTURAL_EXECUTABLE_V2_FORMAT",
    ),
)

CA_PHASE_INPUTS_FORMAT = FORMAT_SPECS[0].literal
CA_PHASE_MANIFEST_FORMAT = FORMAT_SPECS[1].literal
CA_RECEIPT_GATE_FORMAT = FORMAT_SPECS[2].literal
RETIRED_STRUCTURAL_EXECUTABLE_V2_FORMAT = FORMAT_SPECS[3].literal

__all__ = [spec.symbol for spec in FORMAT_SPECS] + ["FORMAT_SPECS"]

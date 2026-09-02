"""Domain-owned formats for ISA qualification projections."""

from __future__ import annotations

from ..artifacts.format_spec import FormatSpecV1


FORMAT_SPECS = (
    FormatSpecV1(
        literal=(
            "spaghetti-extractor-isa-kernel-qualification-certificate-v1"
        ),
        version=1,
        owner=__name__,
        codec="spaghetti_extractor.isa.qualification_certificate",
        role="qualified_platform_evidence",
        state="active",
        symbol="ISA_KERNEL_QUALIFICATION_CERTIFICATE_FORMAT",
    ),
)

ISA_KERNEL_QUALIFICATION_CERTIFICATE_FORMAT = FORMAT_SPECS[0].literal

__all__ = [spec.symbol for spec in FORMAT_SPECS] + ["FORMAT_SPECS"]

"""Format ownership for the qualified platform release."""

from __future__ import annotations

from ..artifacts.format_spec import FormatSpecV1


FORMAT_SPECS = (
    FormatSpecV1(
        literal="spaghetti-extractor-qualified-platform-v1",
        version=1,
        owner=__name__,
        codec="spaghetti_extractor.qualified_platform.release",
        role="qualified_platform",
        state="active",
        symbol="QUALIFIED_PLATFORM_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-qualified-platform-migration-parity-v1",
        version=1,
        owner=__name__,
        codec="spaghetti_extractor.qualified_platform.migration_parity",
        role="diagnostic",
        state="active",
        symbol="QUALIFIED_PLATFORM_MIGRATION_PARITY_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-qualified-platform-isa-form-inventory-v1",
        version=1,
        owner=__name__,
        codec="spaghetti_extractor.qualified_platform.isa_form_inventory",
        role="qualified_platform_input",
        state="active",
        symbol="QUALIFIED_PLATFORM_ISA_FORM_INVENTORY_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-qualified-platform-isa-form-replay-v1",
        version=1,
        owner=__name__,
        codec="spaghetti_extractor.qualified_platform.isa_form_replay",
        role="qualified_platform_evidence",
        state="active",
        symbol="QUALIFIED_PLATFORM_ISA_FORM_REPLAY_FORMAT",
    ),
    FormatSpecV1(
        literal="spaghetti-extractor-isa-semantic-kernel-binding-v1",
        version=1,
        owner=__name__,
        codec="spaghetti_extractor.isa.qualification_worker",
        role="qualified_platform_input",
        state="active",
        symbol="ISA_SEMANTIC_KERNEL_BINDING_FORMAT",
    ),
)

QUALIFIED_PLATFORM_FORMAT = FORMAT_SPECS[0].literal
QUALIFIED_PLATFORM_MIGRATION_PARITY_FORMAT = FORMAT_SPECS[1].literal
QUALIFIED_PLATFORM_ISA_FORM_INVENTORY_FORMAT = FORMAT_SPECS[2].literal
QUALIFIED_PLATFORM_ISA_FORM_REPLAY_FORMAT = FORMAT_SPECS[3].literal
ISA_SEMANTIC_KERNEL_BINDING_FORMAT = FORMAT_SPECS[4].literal

__all__ = [
    "FORMAT_SPECS",
    "ISA_SEMANTIC_KERNEL_BINDING_FORMAT",
    "QUALIFIED_PLATFORM_FORMAT",
    "QUALIFIED_PLATFORM_ISA_FORM_INVENTORY_FORMAT",
    "QUALIFIED_PLATFORM_ISA_FORM_REPLAY_FORMAT",
    "QUALIFIED_PLATFORM_MIGRATION_PARITY_FORMAT",
]

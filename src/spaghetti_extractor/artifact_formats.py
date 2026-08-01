"""Canonical identifiers for artifacts shared across pipeline boundaries.

Keep this module dependency-free.  Producers and consumers in Stage A,
round-trip qualification, and Stage B must agree on these values without
importing one another's implementation modules.
"""

RELATIONAL_PHASE_FORMAT = "stage-a-relational-phase-v1"
STATIC_MACHINE_IMPORT_CONTRACTS_FORMAT = (
    "stage-a-static-machine-import-contracts-v1"
)
SEMANTIC_IR_FORMAT = "stage-a-semantic-ir-v1"
SEMANTIC_TRANSFER_CONTRACT_FORMAT = (
    "stage-a-semantic-transfer-contract-v1"
)
INSTRUCTION_ORDERED_EFFECT_SCHEDULE_FORMAT = (
    "stage-a-instruction-ordered-effect-schedule-v1"
)
NORMALIZED_BEHAVIOR_FORMAT = "stage-a-normalized-behavior-v1"
RELATIONAL_NIX_BUILD_REPORT_FORMAT = "stage-a-relational-nix-build-v1"
C0_SOURCE_MANIFEST_FORMAT = "stage-b-c0-source-manifest-v1"
C0_COMPILATION_ATTESTATION_FORMAT = "stage-a-c0-compilation-attestation-v1"
SOURCE_EQUIVALENCE_REPORT_FORMAT = "stage-a-source-equivalence-report-v1"
C0_TOOLCHAIN_PROFILE_FORMAT = "stage-a-c0-toolchain-profile-v1"
NATIVE_SOURCE_BUNDLE_FORMAT = "stage-b-native-interpreter-source-bundle-v1"
NATIVE_SOURCE_COMPILATION_ATTESTATION_FORMAT = (
    "stage-b-native-interpreter-compilation-attestation-v1"
)


__all__ = [
    "C0_COMPILATION_ATTESTATION_FORMAT",
    "C0_SOURCE_MANIFEST_FORMAT",
    "C0_TOOLCHAIN_PROFILE_FORMAT",
    "INSTRUCTION_ORDERED_EFFECT_SCHEDULE_FORMAT",
    "NORMALIZED_BEHAVIOR_FORMAT",
    "NATIVE_SOURCE_BUNDLE_FORMAT",
    "NATIVE_SOURCE_COMPILATION_ATTESTATION_FORMAT",
    "RELATIONAL_NIX_BUILD_REPORT_FORMAT",
    "RELATIONAL_PHASE_FORMAT",
    "SEMANTIC_IR_FORMAT",
    "SEMANTIC_TRANSFER_CONTRACT_FORMAT",
    "STATIC_MACHINE_IMPORT_CONTRACTS_FORMAT",
    "SOURCE_EQUIVALENCE_REPORT_FORMAT",
]

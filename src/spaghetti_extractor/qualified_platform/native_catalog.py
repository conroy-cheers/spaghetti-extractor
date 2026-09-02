"""Closed PE32 ABI and native-provider catalogs for qualified-platform-v1.

The ABI rows describe target-independent rules already implemented by the
independent IA-32 frame checker. Native rows are stable contracts; exact
generated source and object identities belong to provider qualification and
native realization, where implementation changes can be invalidated locally.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from ..artifacts.artifact_set import canonical_sha256_v3
from ..calls.dialects.ia32_profile import IA32_DIALECT_CALLING_CONVENTIONS
from ..util import sha256_file


PYTHON_RESOURCES = (
    "src/spaghetti_extractor/calls/dialects/ia32.py",
)
_TARGET = "i686-pc-windows-pe32"
_ISA_PROFILE = "pe32-i686-v1"
_DATA_LAYOUT = "pe32-ilp32-v1"


def _checker_source_sha256() -> str:
    # The generated module index treats PYTHON_RESOURCES as exact package
    # resources. Only the independent checker is admitted; candidate runtime
    # implementation modules are deliberately provider-owned.
    package_root = Path(__file__).resolve().parents[1]
    return sha256_file(
        package_root / PYTHON_RESOURCES[0].removeprefix(
            "src/spaghetti_extractor/"
        )
    )


def _calling_conventions() -> list[dict[str, Any]]:
    return [
        {
            "id": "cdecl",
            "argument_order": "right_to_left",
            "register_arguments": [],
            "stack_cleanup": "caller",
            "variadic": True,
        },
        {
            "id": "fastcall",
            "argument_order": "right_to_left_after_registers",
            "register_arguments": ["ecx", "edx"],
            "stack_cleanup": "callee",
            "variadic": False,
        },
        {
            "id": "stdcall",
            "argument_order": "right_to_left",
            "register_arguments": [],
            "stack_cleanup": "callee",
            "variadic": False,
        },
        {
            "id": "thiscall",
            "argument_order": "this_then_right_to_left",
            "register_arguments": ["ecx:this"],
            "stack_cleanup": "callee",
            "variadic": False,
        },
        {
            "id": "vectorcall",
            "argument_order": "classified_registers_then_right_to_left",
            "register_arguments": [
                "ecx", "edx", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4",
                "xmm5",
            ],
            "stack_cleanup": "callee",
            "variadic": False,
        },
    ]


def abi_profile_catalog_payload_v1() -> list[dict[str, Any]]:
    """Return the complete target ABI selection surface for IA-32 PE32."""

    conventions = _calling_conventions()
    convention_ids = frozenset(row["id"] for row in conventions)
    if any(
        supported != convention_ids
        for supported in IA32_DIALECT_CALLING_CONVENTIONS.values()
    ):
        raise RuntimeError(
            "qualified-platform ABI catalog differs from the IA-32 checker"
        )
    common = {
        "architecture": "x86",
        "cpu": "i686",
        "execution_mode": "protected-32",
        "environment": "pe32",
        "isa_profile": _ISA_PROFILE,
        "target": _TARGET,
        "data_layout": {
            "id": _DATA_LAYOUT,
            "byte_order": "little",
            "pointer_width_bits": 32,
            "machine_word_bits": 32,
            "natural_stack_slot_bytes": 4,
            "callee_entry_stack_coordinate": "callee-entry-esp-v1",
            "minimum_stack_alignment_bytes": 4,
            "packing": "natural",
        },
        "physical_frame": {
            "format": "spaghetti-extractor-physical-call-frame-v3",
            "checker": "IA32DialectCheckerV1",
            "preserved_state": ["ebp", "ebx", "edi", "esi", "esp"],
            "clobbered_state": [
                "eax", "ecx", "edx", "eflags", "st0", "st1", "xmm0",
                "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
            ],
            "integer_result": "eax_then_edx",
            "floating_result": "st0",
            "vector_result": "xmm0",
            "aggregate_result": "layout_classified_register_or_hidden_sret",
        },
        "calling_conventions": conventions,
        "unsupported_calling_conventions": ["custom"],
        "qualification": {
            "status": "checked_rule_implementation",
            "authority": "independent_frame_checker",
            "checker_source_sha256": _checker_source_sha256(),
        },
    }
    rows = [
        {
            **common,
            "profile_id": "pe32-i686-mingw32",
            "abi_dialect": "pe32-i386-gnu-v1",
            "compiler_family": "gnu",
        },
        {
            **common,
            "profile_id": "pe32-i686-msvc",
            "abi_dialect": "pe32-i386-ms-v1",
            "compiler_family": "microsoft",
        },
    ]
    # Avoid shared mutable nested values escaping this intrinsic registry.
    return copy.deepcopy(rows)


_NATIVE_DECLARATIONS: tuple[dict[str, Any], ...] = (
    {
        "provider_id": "native.pe32.ingress-bridge-v1",
        "features": [
            "physical_state_capture", "checked_private_stack",
            "same_thread_reentrancy", "physical_result_restore",
        ],
        "required_veto_gates": ["native-ingress-runtime", "native-module"],
    },
    {
        "provider_id": "native.pe32.seh-gateway-v1",
        "features": [
            "seh_gateway", "checked_context_projection", "unwind_cleanup",
            "continuation_portal", "exception_escape",
        ],
        "required_veto_gates": ["native-ingress-runtime", "native-module"],
    },
    {
        "provider_id": "native.pe32.tls-runtime-v1",
        "features": [
            "combined_pe_tls", "thread_context", "lifecycle_generations",
            "bounded_stack_slices", "loader_lock_safe_bootstrap",
        ],
        "required_veto_gates": ["native-ingress-runtime", "native-module"],
    },
    {
        "provider_id": "native.pe32.code-capability-registry-v1",
        "features": [
            "capability_generation", "capability_escape",
            "atomic_publication", "stable_bridge_identity",
        ],
        "required_veto_gates": ["native-ingress-runtime", "native-module"],
    },
    {
        "provider_id": "native.pe32.object-memory-v1",
        "features": [
            "mapped_object_resolution", "interior_pointer_resolution",
            "transactional_writeback", "access_violation_materialization",
        ],
        "required_veto_gates": ["native-ingress-runtime", "native-module"],
    },
    {
        "provider_id": "native.pe32.guest-atomics-v1",
        "features": ["atomic_compare_exchange", "atomic_exchange"],
        "required_veto_gates": ["native-module"],
    },
    {
        "provider_id": "native.pe32.x87-exact-replay-v1",
        "features": [
            "x87_state_import", "x87_state_export", "typed_x87_execution",
        ],
        "required_veto_gates": ["native-ingress-runtime", "native-module"],
    },
    {
        "provider_id": "native.pe32.outcome-routing-v1",
        "features": [
            "normal", "no_return", "exceptional", "declared_nonlocal",
            "process_termination",
        ],
        "required_veto_gates": ["native-ingress-runtime", "native-module"],
    },
)


def native_primitive_catalog_payload_v1() -> list[dict[str, Any]]:
    """Return reviewed native contracts and their veto obligations.

    These rows authorize the stable target-independent contract only. Exact
    generated sources, compiler inputs, and objects are bound later by the
    provider qualification and native-realization receipts.
    """

    rows: list[dict[str, Any]] = []
    for declaration in _NATIVE_DECLARATIONS:
        core = {
            "provider_id": declaration["provider_id"],
            "target": _TARGET,
            "isa_profile": _ISA_PROFILE,
            "features": sorted(declaration["features"]),
            "required_veto_gates": sorted(declaration["required_veto_gates"]),
        }
        declaration_sha256 = canonical_sha256_v3(core)
        review_core = {
            "provider_id": declaration["provider_id"],
            "declaration_sha256": declaration_sha256,
            "authority": "reviewed_native_primitive_contract",
            "required_veto_gates": core["required_veto_gates"],
            "test_results_authorizing": False,
        }
        rows.append({
            **core,
            "declaration_sha256": declaration_sha256,
            "qualification": {
                **review_core,
                "status": "complete",
                "review_sha256": canonical_sha256_v3(review_core),
            },
        })
    return sorted(rows, key=lambda row: row["provider_id"])


__all__ = [
    "abi_profile_catalog_payload_v1",
    "native_primitive_catalog_payload_v1",
]

"""Data model and constants for Stage B native runtime generation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..artifact_formats import NATIVE_RUNTIME_PACKAGE_FORMAT
from ..errors import StageAInputError
from .interpreter_model import STAGE_B_INTERPRETER_DEFINEDNESS_USE_FORMAT


NATIVE_RUNTIME_HEADER_FILENAME = "native-runtime.h"
NATIVE_RUNTIME_SOURCE_FILENAME = "native-runtime.c"
NATIVE_RUNTIME_BINDINGS_FILENAME = "native-runtime-bindings.c"
NATIVE_RUNTIME_MANIFEST_FILENAME = "native-runtime-package.json"
NATIVE_RUNTIME_EXTERNAL_PROFILE_FILENAME = "external-environment-profile.json"
DEFINEDNESS_USE_FORMAT = STAGE_B_INTERPRETER_DEFINEDNESS_USE_FORMAT

_INTERPRETER_MANIFEST_FILENAME = "state-machine-interpreter-package.json"
_NATIVE_ENGINE_MANIFEST_FILENAME = "native-engine-package.json"
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_STRICT_INPUT_MODE = "strict_exact_state_machine_v1"
_MACHINE_IR_INPUT_MODE = "sanitized_machine_ir_v2"
_CALLBACK_ADAPTER_RECEIPT_FORMAT = (
    "stage-b-native-callback-adapter-receipt-v1"
)
_IMPLEMENTATION_DISPATCH_RECEIPT_FORMAT = (
    "stage-b-native-implementation-dispatch-receipt-v3"
)


class StageBNativeRuntimeError(StageAInputError):
    """A native-runtime package input failed closed validation."""


@dataclass(frozen=True)
class _InterpreterTransferBinding:
    unit_id: str
    rva: int


@dataclass(frozen=True)
class NativeImplementationDispatch:
    unit_id: str
    rva: int
    implementation_class: str
    replacement_id: str | None
    cluster_id: str | None
    component_entry_rva: int | None

    @property
    def class_code(self) -> int:
        return {
            "machine_ir_fallback": 0,
            "selected_portable_component": 1,
            "selected_portable_component_member": 2,
        }[self.implementation_class]


@dataclass(frozen=True)
class NativeUndefinedPolicy:
    slot: int
    undefined_id: str
    classification: str
    witness_policy: str | None
    choice_kind: str
    input_location: str | None
    obligation_count: int
    use_count: int

    @property
    def faults(self) -> bool:
        return self.choice_kind == "unsupported"

    @property
    def policy_code(self) -> int:
        return {
            "noninterfering_zero": 0,
            "related_machine_input": 1,
            "unsupported": 2,
        }[self.choice_kind]

    @property
    def input_location_code(self) -> int:
        if self.input_location is None:
            return 0
        return {
            "eax": 0,
            "ebx": 1,
            "ecx": 2,
            "edx": 3,
            "esi": 4,
            "edi": 5,
            "ebp": 6,
            "esp": 7,
        }[self.input_location]

    def payload(self) -> dict[str, Any]:
        return {
            "slot": self.slot,
            "undefined_id": self.undefined_id,
            "classification": self.classification,
            "witness_policy": self.witness_policy,
            "choice_kind": self.choice_kind,
            "input_location": self.input_location,
            "obligation_count": self.obligation_count,
            "use_count": self.use_count,
        }


@dataclass(frozen=True)
class NativeExternalRangeRule:
    instruction_rva: int
    target_iat_rva: int | None
    action: str
    argument_base_offset: int
    argument_count: int
    register: str | None
    argument: int | None
    size_kind: str | None
    size_value: int
    size_argument: int | None
    size_right_argument: int | None
    minimum_size: int
    nullable: bool
    termination_unit_bytes: int
    termination_zero_units: int
    termination_max_units: int
    pointee_offset: int
    max_elements: int
    element_unit_bytes: int
    element_max_units: int
    contract_id: str

    def payload(self) -> dict[str, Any]:
        return {
            "instruction_rva": self.instruction_rva,
            "target_iat_rva": self.target_iat_rva,
            "action": self.action,
            "argument_base_offset": self.argument_base_offset,
            "argument_count": self.argument_count,
            "register": self.register,
            "argument": self.argument,
            "size_kind": self.size_kind,
            "size_value": self.size_value,
            "size_argument": self.size_argument,
            "size_right_argument": self.size_right_argument,
            "minimum_size": self.minimum_size,
            "nullable": self.nullable,
            "termination_unit_bytes": self.termination_unit_bytes,
            "termination_zero_units": self.termination_zero_units,
            "termination_max_units": self.termination_max_units,
            "pointee_offset": self.pointee_offset,
            "max_elements": self.max_elements,
            "element_unit_bytes": self.element_unit_bytes,
            "element_max_units": self.element_max_units,
            "contract_id": self.contract_id,
        }


@dataclass(frozen=True)
class NativeRuntimePlan:
    """Checked immutable inputs used to render one native runtime."""

    candidate_mode: str
    entry_rva: int
    transfer_rvas: tuple[int, ...]
    recovered_executable_data_ranges: tuple[tuple[int, int], ...]
    callback_abis: tuple[tuple[int, int], ...]
    callback_adapter_receipts: tuple[dict[str, Any], ...]
    implementation_dispatch_receipt: dict[str, Any]
    implementation_dispatches: tuple[NativeImplementationDispatch, ...]
    diagnostic_frontiers: tuple[dict[str, Any], ...]
    external_range_rules: tuple[NativeExternalRangeRule, ...]
    authorized_external_site_rvas: tuple[int, ...]
    blocked_external_sites: tuple[dict[str, Any], ...]
    diagnostic_writer_iat_rvas: tuple[int, int, int] | None
    external_profile_path: Path | None
    external_profile_sha256: str | None
    external_profile_graph: tuple[tuple[Path, str, str], ...]
    undefined_policies: tuple[NativeUndefinedPolicy, ...]
    definedness_metadata_sha256: str | None
    state_machine_sha256: str
    interpreter_manifest_path: Path
    interpreter_manifest_sha256: str
    interpreter_program_path: Path
    interpreter_program_sha256: str
    native_engine_manifest_path: Path
    native_engine_manifest_sha256: str
    native_engine_plan_path: Path
    native_engine_plan_sha256: str
    x87_handler_mode: str
    has_modeled_termination: bool

    @property
    def has_typed_x87_handler(self) -> bool:
        return self.x87_handler_mode == "typed"

    def payload(self) -> dict[str, Any]:
        return {
            "candidate_mode": self.candidate_mode,
            "entry_rva": self.entry_rva,
            "transfer_rvas": list(self.transfer_rvas),
            "recovered_executable_data_ranges": [
                {"rva_start": start, "rva_end": end}
                for start, end in self.recovered_executable_data_ranges
            ],
            "callback_abis": [
                {"rva": rva, "stack_cleanup_bytes": cleanup}
                for rva, cleanup in self.callback_abis
            ],
            "callback_adapter_receipts": [
                dict(receipt) for receipt in self.callback_adapter_receipts
            ],
            "implementation_dispatch_receipt": dict(
                self.implementation_dispatch_receipt
            ),
            "diagnostic_frontiers": [
                dict(frontier) for frontier in self.diagnostic_frontiers
            ],
            "external_range_contracts": {
                "profile": (
                    None
                    if self.external_profile_path is None
                    else {
                        "path": NATIVE_RUNTIME_EXTERNAL_PROFILE_FILENAME,
                        "sha256": self.external_profile_sha256,
                    }
                ),
                "profile_graph": [
                    {
                        "id": profile_id,
                        "path": (
                            NATIVE_RUNTIME_EXTERNAL_PROFILE_FILENAME
                            if self.external_profile_path is not None
                            and path == self.external_profile_path.resolve()
                            else str(path.relative_to(self.external_profile_path.resolve().parent))
                        ),
                        "sha256": sha256,
                    }
                    for path, profile_id, sha256 in self.external_profile_graph
                ],
                "rules": [rule.payload() for rule in self.external_range_rules],
            },
            "external_dispatch": {
                "authorized_instruction_rvas": list(
                    self.authorized_external_site_rvas
                ),
                "blocked_sites": [
                    dict(site) for site in self.blocked_external_sites
                ],
                "unknown_site_disposition": "fail-closed-before-call",
            },
            "diagnostic_writer": (
                None
                if self.diagnostic_writer_iat_rvas is None
                else {
                    "format": "stage-b-native-diagnostic-v4",
                    "transport": "existing-kernel32-iat-binary-file-v1",
                    "create_file_a_iat_rva": self.diagnostic_writer_iat_rvas[0],
                    "write_file_iat_rva": self.diagnostic_writer_iat_rvas[1],
                    "close_handle_iat_rva": self.diagnostic_writer_iat_rvas[2],
                }
            ),
            "definedness_use": {
                "format": DEFINEDNESS_USE_FORMAT,
                "metadata_sha256": self.definedness_metadata_sha256,
                "candidate_witness_scope": (
                    "candidate-only; Stage A must separately prove the original/candidate "
                    "undefined-value relation"
                ),
                "slots": [policy.payload() for policy in self.undefined_policies],
            },
            "state_machine_sha256": self.state_machine_sha256,
            "interpreter_manifest": {
                "path": self.interpreter_manifest_path.name,
                "sha256": self.interpreter_manifest_sha256,
            },
            "interpreter_program": {
                "path": self.interpreter_program_path.name,
                "sha256": self.interpreter_program_sha256,
            },
            "native_engine_manifest": {
                "path": self.native_engine_manifest_path.name,
                "sha256": self.native_engine_manifest_sha256,
            },
            "native_engine_plan": {
                "path": self.native_engine_plan_path.name,
                "sha256": self.native_engine_plan_sha256,
            },
            "runtime_abi": {
                "atomic_compare_exchange_handler": True,
                "atomic_exchange_handler": True,
                "typed_native_x87_handler": self.has_typed_x87_handler,
                "modeled_environment_termination":
                    self.has_modeled_termination,
            },
        }

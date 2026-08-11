"""Generate the fail-closed native runtime for the Stage B interpreter.

The emitted sources are candidate-generation inputs only.  They bind the
semantic interpreter and native engine packages by hash, but they do not add
acceptance authority to the resulting native candidate.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .artifact_formats import (
    NATIVE_ENGINE_PACKAGE_FORMAT,
    NATIVE_ENGINE_PLAN_FORMAT,
    NATIVE_RUNTIME_PACKAGE_FORMAT,
)
from .errors import StageAInputError
from .callable_external_runtime import (
    CallableExternalRuntimeContract,
    load_callable_external_runtime_contract,
)
from .checked_external_site_contract import (
    CheckedExternalSiteContract,
    CheckedExternalSiteContractError,
    ExternalSiteIdentity,
    parse_checked_external_site_contract,
    require_profile_match,
)
from .machine_import_profiles import (
    MachineImportIdentity,
    MachineImportProfileError,
    load_machine_import_profile_set,
)
from .stage_b_interpreter_backend import (
    STAGE_B_INTERPRETER_DEFINEDNESS_USE_FIELDS,
    STAGE_B_INTERPRETER_DEFINEDNESS_USE_FORMAT,
    STAGE_B_INTERPRETER_PACKAGE_FORMAT,
    STAGE_B_INTERPRETER_PROGRAM_FORMAT,
)
from .stage_b_candidate_modes import (
    STATIC_CLOSED_CANDIDATE_MODE,
    STRUCTURAL_DIAGNOSTIC_CANDIDATE_MODE,
    require_candidate_mode,
)
from .util import sha256_bytes, sha256_file, write_json


NATIVE_RUNTIME_HEADER_FILENAME = "native-runtime.h"
NATIVE_RUNTIME_SOURCE_FILENAME = "native-runtime.c"
NATIVE_RUNTIME_MANIFEST_FILENAME = "native-runtime-package.json"
NATIVE_RUNTIME_EXTERNAL_PROFILE_FILENAME = "external-environment-profile.json"
NATIVE_RUNTIME_CALLABLE_CONTRACT_FILENAME = "callable-external-runtime.json"
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
    "stage-b-native-implementation-dispatch-receipt-v2"
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

    @property
    def class_code(self) -> int:
        return {
            "machine_ir_fallback": 0,
            "selected_portable_component": 1,
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
    callable_external_contract: CallableExternalRuntimeContract | None
    callable_external_contract_path: Path | None
    callable_external_contract_sha256: str | None
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
    def has_x87_replay_handler(self) -> bool:
        """Compatibility accessor for legacy callers."""

        return self.x87_handler_mode == "legacy_replay"

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
            "callable_external": (
                None
                if self.callable_external_contract is None
                else {
                    "path": NATIVE_RUNTIME_CALLABLE_CONTRACT_FILENAME,
                    "sha256": self.callable_external_contract_sha256,
                    "identity": self.callable_external_contract.identity,
                    "resolver_sites": len(
                        self.callable_external_contract.resolvers
                    ),
                    "routes": len(self.callable_external_contract.routes),
                }
            ),
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
                "legacy_checked_x87_replay_handler": self.has_x87_replay_handler,
                "modeled_environment_termination":
                    self.has_modeled_termination,
            },
        }


def plan_stage_b_native_runtime(
    *,
    interpreter_package: Path | str,
    native_engine_package: Path | str,
    external_profile: Path | str | None = None,
    callable_external_contract: Path | str | None = None,
) -> NativeRuntimePlan:
    """Validate and bind exact interpreter and native-engine packages."""

    interpreter_manifest_path = _manifest_path(
        interpreter_package,
        _INTERPRETER_MANIFEST_FILENAME,
        "interpreter package",
    )
    native_manifest_path = _manifest_path(
        native_engine_package,
        _NATIVE_ENGINE_MANIFEST_FILENAME,
        "native-engine package",
    )
    interpreter = _read_json_object(
        interpreter_manifest_path, "interpreter package manifest"
    )
    native = _read_json_object(native_manifest_path, "native-engine package manifest")

    if interpreter.get("format") != STAGE_B_INTERPRETER_PACKAGE_FORMAT:
        raise StageBNativeRuntimeError(
            "interpreter package has an unsupported format"
        )
    if interpreter.get("status") != "ready":
        raise StageBNativeRuntimeError("interpreter package is not ready")
    input_mode, interpreter_state = _semantic_input_binding(
        interpreter, "interpreter package"
    )
    state_machine_sha256 = _required_sha256(
        interpreter_state.get("sha256"), "interpreter semantic-input SHA-256"
    )
    interpreter_sources = _verify_artifact_inventory(
        interpreter_manifest_path.parent,
        interpreter.get("sources"),
        "interpreter source",
        require_role=True,
    )
    runtime_header_path = interpreter_sources.get("runtime_header")
    if runtime_header_path is None:
        raise StageBNativeRuntimeError(
            "interpreter source inventory has no runtime_header role"
        )
    try:
        runtime_header = runtime_header_path.read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise StageBNativeRuntimeError(
            "cannot read the bound interpreter runtime header"
        ) from exc
    interpreter_has_typed_x87_abi = "execute_typed_x87_operation" in runtime_header
    interpreter_has_x87_replay_abi = "replay_checked_x87_command" in runtime_header
    if interpreter_has_typed_x87_abi and interpreter_has_x87_replay_abi:
        raise StageBNativeRuntimeError(
            "interpreter runtime header exposes conflicting x87 ABIs"
        )
    program_ref = _required_object(interpreter.get("program"), "interpreter program")
    program_path = _bound_artifact(
        interpreter_manifest_path.parent, program_ref, "interpreter program"
    )
    program = _read_json_object(program_path, "interpreter program manifest")
    (
        transfer_rvas,
        transfer_bindings,
        undefined_policies,
        definedness_metadata_sha256,
        interpreter_deferred,
    ) = (
        _validate_program_manifest(program, state_machine_sha256)
    )

    if native.get("format") != NATIVE_ENGINE_PACKAGE_FORMAT:
        raise StageBNativeRuntimeError(
            "native-engine package has an unsupported format"
        )
    if native.get("status") != "ready":
        raise StageBNativeRuntimeError("native-engine package is not ready")
    native_input_mode, native_input = _semantic_input_binding(
        native, "native-engine package"
    )
    if (
        native_input_mode != input_mode
        or _required_sha256(
            native_input.get("sha256"), "native-engine semantic-input SHA-256"
        ) != state_machine_sha256
    ):
        raise StageBNativeRuntimeError(
            "interpreter and native-engine packages bind different semantic inputs"
        )
    _verify_artifact_inventory(
        native_manifest_path.parent,
        native.get("sources"),
        "native-engine source",
        require_role=False,
    )
    plan_ref = _required_object(native.get("plan"), "native-engine plan")
    native_plan_path = _bound_artifact(
        native_manifest_path.parent, plan_ref, "native-engine plan"
    )
    native_plan = _read_json_object(native_plan_path, "native-engine plan")
    candidate_mode = require_candidate_mode(native_plan.get("candidate_mode"))
    native_policy = _required_object(native.get("policy"), "native-engine policy")
    if native_policy.get("candidate_mode") != candidate_mode:
        raise StageBNativeRuntimeError(
            "native-engine manifest and plan use different candidate modes"
        )
    if native.get("callback_adapter_receipts") != native_plan.get(
        "callback_adapter_receipts"
    ):
        raise StageBNativeRuntimeError(
            "native-engine manifest and plan bind different callback adapter receipts"
        )
    if native.get("implementation_dispatch_receipt") != native_plan.get(
        "implementation_dispatch_receipt"
    ):
        raise StageBNativeRuntimeError(
            "native-engine manifest and plan bind different implementation dispatch receipts"
        )
    native_deferred = _validate_deferred_transfer_inventory(
        native_plan,
        label="native-engine plan",
    )
    if native_deferred != interpreter_deferred:
        raise StageBNativeRuntimeError(
            "interpreter and native engine defer different machine-IR transfers"
        )
    callable_contract_path = (
        None
        if callable_external_contract is None
        else Path(callable_external_contract).resolve()
    )
    callable_contract = (
        None
        if callable_contract_path is None
        else load_callable_external_runtime_contract(callable_contract_path)
    )
    native_callable = native_plan.get("callable_external")
    manifest_callable = native.get("callable_external_contract")
    if callable_contract is None:
        if native_callable is not None or manifest_callable is not None:
            raise StageBNativeRuntimeError(
                "native engine requires a callable-external runtime contract"
            )
    else:
        if not isinstance(native_callable, dict) or not isinstance(
            manifest_callable, dict
        ):
            raise StageBNativeRuntimeError(
                "native engine omitted its callable-external binding"
            )
        contract_sha256 = sha256_file(callable_contract_path)
        if (
            native_callable.get("identity") != callable_contract.identity
            or native_callable.get("resolver_sites")
            != [site.payload() for site in callable_contract.resolvers]
            or native_callable.get("routes")
            != [route.payload() for route in callable_contract.routes]
            or manifest_callable.get("identity") != callable_contract.identity
            or manifest_callable.get("sha256") != contract_sha256
        ):
            raise StageBNativeRuntimeError(
                "native engine and runtime bind different callable-external evidence"
            )
    native_x87_operations = native_plan.get("x87_operations")
    native_x87_replays = native_plan.get("x87_replays")
    if native_x87_operations is not None and native_x87_replays is not None:
        raise StageBNativeRuntimeError(
            "native-engine plan mixes typed and legacy x87 inventories"
        )
    if native_x87_operations is not None:
        operations = _required_list(
            native_x87_operations, "native-engine typed x87 operations"
        )
        _validate_typed_x87_operations(operations)
        x87_handler_mode = "typed" if operations else "none"
    else:
        replays = _required_list(
            native_x87_replays if native_x87_replays is not None else [],
            "native-engine x87 replay sites",
        )
        x87_handler_mode = "legacy_replay" if replays else "none"
    if x87_handler_mode == "typed" and not interpreter_has_typed_x87_abi:
        raise StageBNativeRuntimeError(
            "native-engine typed x87 operations require the interpreter typed ABI"
        )
    if x87_handler_mode == "legacy_replay" and not interpreter_has_x87_replay_abi:
        raise StageBNativeRuntimeError(
            "native-engine x87 replay sites require the interpreter replay ABI"
        )
    (
        entry_rva,
        callback_abis,
        callback_adapter_receipts,
        implementation_dispatch_receipt,
        implementation_dispatches,
        recovered_executable_data_ranges,
    ) = _validate_native_plan(
        native_plan,
        candidate_mode=candidate_mode,
        deferred_transfer_ids=frozenset(
            str(row["transfer_id"]) for row in interpreter_deferred
        ),
        state_machine_sha256=state_machine_sha256,
        input_mode=input_mode,
        transfer_rvas=transfer_rvas,
        transfer_bindings=transfer_bindings,
    )
    has_modeled_termination = _validate_native_termination(
        native_plan.get("termination_import")
    )
    external_profile_path = (
        None if external_profile is None else Path(external_profile).resolve()
    )
    if external_profile_path is None:
        external_profile_graph: tuple[tuple[Path, str, str], ...] = ()
    else:
        try:
            profile_set = load_machine_import_profile_set([external_profile_path])
        except MachineImportProfileError as exc:
            raise StageBNativeRuntimeError(str(exc)) from exc
        profile_root = external_profile_path.parent
        graph: list[tuple[Path, str, str]] = []
        for profile in profile_set.profiles:
            try:
                profile.path.relative_to(profile_root)
            except ValueError as exc:
                raise StageBNativeRuntimeError(
                    "external profile includes must remain beneath the root profile directory"
                ) from exc
            graph.append((profile.path, profile.profile_id, profile.sha256))
        external_profile_graph = tuple(graph)
    (
        external_range_rules,
        authorized_external_site_rvas,
        blocked_external_sites,
    ) = _external_range_rules(
        native_plan,
        external_profile_path,
        candidate_mode=candidate_mode,
    )
    diagnostic_writer_iat_rvas = _diagnostic_writer_iat_rvas(native_plan)

    return NativeRuntimePlan(
        candidate_mode=candidate_mode,
        entry_rva=entry_rva,
        transfer_rvas=transfer_rvas,
        recovered_executable_data_ranges=recovered_executable_data_ranges,
        callback_abis=callback_abis,
        callback_adapter_receipts=callback_adapter_receipts,
        implementation_dispatch_receipt=implementation_dispatch_receipt,
        implementation_dispatches=implementation_dispatches,
        diagnostic_frontiers=tuple(
            dict(frontier)
            for frontier in _required_list(
                native_plan.get("diagnostic_frontiers"),
                "native-engine diagnostic frontiers",
            )
        ),
        callable_external_contract=callable_contract,
        callable_external_contract_path=callable_contract_path,
        callable_external_contract_sha256=(
            None
            if callable_contract_path is None
            else sha256_file(callable_contract_path)
        ),
        external_range_rules=external_range_rules,
        authorized_external_site_rvas=authorized_external_site_rvas,
        blocked_external_sites=blocked_external_sites,
        diagnostic_writer_iat_rvas=diagnostic_writer_iat_rvas,
        external_profile_path=external_profile_path,
        external_profile_sha256=(
            None
            if external_profile_path is None
            else sha256_file(external_profile_path)
        ),
        external_profile_graph=external_profile_graph,
        undefined_policies=undefined_policies,
        definedness_metadata_sha256=definedness_metadata_sha256,
        state_machine_sha256=state_machine_sha256,
        interpreter_manifest_path=interpreter_manifest_path,
        interpreter_manifest_sha256=sha256_file(interpreter_manifest_path),
        interpreter_program_path=program_path,
        interpreter_program_sha256=sha256_file(program_path),
        native_engine_manifest_path=native_manifest_path,
        native_engine_manifest_sha256=sha256_file(native_manifest_path),
        native_engine_plan_path=native_plan_path,
        native_engine_plan_sha256=sha256_file(native_plan_path),
        x87_handler_mode=x87_handler_mode,
        has_modeled_termination=has_modeled_termination,
    )


def write_stage_b_native_runtime_package(
    *,
    interpreter_package: Path | str,
    native_engine_package: Path | str,
    external_profile: Path | str | None = None,
    callable_external_contract: Path | str | None = None,
    out: Path | str,
) -> dict[str, Any]:
    """Write deterministic freestanding runtime sources and their manifest."""

    plan = plan_stage_b_native_runtime(
        interpreter_package=interpreter_package,
        native_engine_package=native_engine_package,
        external_profile=external_profile,
        callable_external_contract=callable_external_contract,
    )
    out_path = Path(out)
    out_path.mkdir(parents=True, exist_ok=True)
    header_path = out_path / NATIVE_RUNTIME_HEADER_FILENAME
    source_path = out_path / NATIVE_RUNTIME_SOURCE_FILENAME
    header_path.write_text(_native_runtime_header(), encoding="ascii")
    source_path.write_text(_native_runtime_source(plan), encoding="ascii")
    profile_source: dict[str, Any] | None = None
    callable_source: dict[str, Any] | None = None
    profile_dependencies: list[dict[str, Any]] = []
    if plan.external_profile_path is not None:
        profile_path = out_path / NATIVE_RUNTIME_EXTERNAL_PROFILE_FILENAME
        try:
            profile_path.write_bytes(plan.external_profile_path.read_bytes())
        except OSError as exc:
            raise StageBNativeRuntimeError(
                "cannot copy the external environment profile into the runtime package"
            ) from exc
        if sha256_file(profile_path) != plan.external_profile_sha256:
            raise StageBNativeRuntimeError(
                "copied external environment profile SHA-256 mismatch"
            )
        profile_source = {
            "role": "external_profile",
            "path": profile_path.name,
            "sha256": plan.external_profile_sha256,
        }
        profile_root = plan.external_profile_path.parent
        for index, (source, _profile_id, expected_sha256) in enumerate(
            plan.external_profile_graph
        ):
            if source == plan.external_profile_path:
                continue
            relative = source.relative_to(profile_root)
            target = out_path / relative
            if target.exists():
                raise StageBNativeRuntimeError(
                    f"included external profile collides with package artifact {relative}"
                )
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                target.write_bytes(source.read_bytes())
            except OSError as exc:
                raise StageBNativeRuntimeError(
                    "cannot copy an included external profile into the runtime package"
                ) from exc
            if sha256_file(target) != expected_sha256:
                raise StageBNativeRuntimeError(
                    "copied included external profile SHA-256 mismatch"
                )
            profile_dependencies.append({
                "role": f"external_profile_dependency_{index:03d}",
                "path": str(relative),
                "sha256": expected_sha256,
            })
    if plan.callable_external_contract_path is not None:
        callable_path = out_path / NATIVE_RUNTIME_CALLABLE_CONTRACT_FILENAME
        try:
            callable_path.write_bytes(
                plan.callable_external_contract_path.read_bytes()
            )
        except OSError as exc:
            raise StageBNativeRuntimeError(
                "cannot copy the callable-external contract into the runtime package"
            ) from exc
        if sha256_file(callable_path) != plan.callable_external_contract_sha256:
            raise StageBNativeRuntimeError(
                "copied callable-external contract SHA-256 mismatch"
            )
        callable_source = {
            "role": "callable_external_contract",
            "path": callable_path.name,
            "sha256": plan.callable_external_contract_sha256,
        }

    result = {
        "format": NATIVE_RUNTIME_PACKAGE_FORMAT,
        "status": "ready",
        "acceptance_authority": False,
        "inputs": plan.payload(),
        "sources": [
            {
                "role": "native_runtime_header",
                "path": header_path.name,
                "sha256": sha256_file(header_path),
            },
            {
                "role": "native_runtime_source",
                "path": source_path.name,
                "sha256": sha256_file(source_path),
            },
        ] + ([] if profile_source is None else [profile_source]) + (
            [] if callable_source is None else [callable_source]
        ) + profile_dependencies,
        "counts": {
            "transfers": len(plan.transfer_rvas),
            "implementation_dispatches": len(plan.implementation_dispatches),
            "diagnostic_frontiers": len(plan.diagnostic_frontiers),
            "authorized_external_sites": len(
                plan.authorized_external_site_rvas
            ),
            "blocked_external_sites": len(plan.blocked_external_sites),
            "callable_external_routes": (
                0
                if plan.callable_external_contract is None
                else len(plan.callable_external_contract.routes)
            ),
        },
        "policy": {
            "architecture": "i686-pe32",
            "candidate_mode": plan.candidate_mode,
            "freestanding": True,
            "static_hybrid_closure_receipt_required": (
                plan.candidate_mode == STATIC_CLOSED_CANDIDATE_MODE
            ),
            "implementation_dispatch": (
                "exact-linked-class-per-interpreter-transfer-v1"
            ),
            "flat_memory": "exact-little-endian-widths-1-2-4",
            "read_domains": (
                "checked-image-headers-and-sections; captured-stack; "
                "read-only-4KiB-teb-window-at-captured-fs-base; "
                "bounded-profile-derived-external-ranges"
            ),
            "undefined_values": (
                "hash-bound-zero-only-after-semantic-noninterference; "
                "synchronized-slots-use-a-checked-instruction-local-input-expression; "
                "unknown-or-unsupported-slots-latch-unimplemented"
            ),
            "code_targets": (
                "absolute-image-va-in-checked-transfer-table-or-"
                "resolver-issued-hash-bound-callable-route"
            ),
            "threads": "fail-closed-on-concurrent-entry",
            "engine_stack": (
                "dedicated-64KiB-private-stack-disjoint-from-modeled-program-stack"
            ),
            "executable_writes": (
                "only-checked-nonexecuting-image-sections, captured-stack, or "
                "bounded-profile-derived-external-ranges"
            ),
            "external_ranges": (
                "machine-call-profile-bound-result-and-release-rules; "
                "8192-live-range-limit; bounded-profile-declared-pointee-shapes; "
                "overflow-and-missing-arguments-fail-closed"
            ),
            "terminal_control": (
                "record-status-and-modeled-environment-termination"
                if plan.has_modeled_termination
                else "record-status-and-unsupported-native-halt"
            ),
        },
        "authority": "candidate generation only; candidate assurance remains required",
    }
    write_json(out_path / NATIVE_RUNTIME_MANIFEST_FILENAME, result)
    return result


def _validate_program_manifest(
    payload: dict[str, Any], state_machine_sha256: str
) -> tuple[
    tuple[int, ...],
    tuple[_InterpreterTransferBinding, ...],
    tuple[NativeUndefinedPolicy, ...],
    str | None,
    tuple[dict[str, Any], ...],
]:
    if payload.get("format") != STAGE_B_INTERPRETER_PROGRAM_FORMAT:
        raise StageBNativeRuntimeError("interpreter program has an unsupported format")
    if payload.get("state_machine_sha256") != state_machine_sha256:
        raise StageBNativeRuntimeError(
            "interpreter package and program bind different state machines"
        )
    if payload.get("status") != "ready" or payload.get("blockers") != []:
        raise StageBNativeRuntimeError("interpreter program is not runnable")
    deferred = _validate_deferred_transfer_inventory(
        payload,
        label="interpreter program",
    )
    transfers = _required_list(payload.get("transfers"), "interpreter transfers")
    rvas: list[int] = []
    bindings: list[_InterpreterTransferBinding] = []
    for index, raw in enumerate(transfers):
        transfer = _required_object(raw, f"interpreter transfer {index}")
        unit_id = _required_string(
            transfer.get("id"), f"interpreter transfer {index} id"
        )
        _required_sha256(
            transfer.get("contract_sha256"),
            f"interpreter transfer {index} contract SHA-256",
        )
        source_digest = transfer.get("source_span_sha256")
        if source_digest is None:
            source_digest = transfer.get("instruction_bytes_sha256")
        _required_sha256(
            source_digest,
            f"interpreter transfer {index} source-span SHA-256",
        )
        rva = _required_u32(
            transfer.get("rva_start"), f"interpreter transfer {index} RVA"
        )
        rvas.append(rva)
        bindings.append(_InterpreterTransferBinding(unit_id=unit_id, rva=rva))
    if not rvas:
        raise StageBNativeRuntimeError("interpreter transfer table is empty")
    if (
        rvas != sorted(rvas)
        or len(set(rvas)) != len(rvas)
        or len({binding.unit_id for binding in bindings}) != len(bindings)
    ):
        raise StageBNativeRuntimeError(
            "interpreter transfer table must be strictly sorted and unique"
        )
    counts = _required_object(payload.get("counts"), "interpreter counts")
    if _required_count(counts.get("transfers"), "interpreter transfer count") != len(rvas):
        raise StageBNativeRuntimeError(
            "interpreter transfer count does not match its inventory"
        )
    if (
        _required_count(
            counts.get("input_transfers"), "interpreter input-transfer count"
        )
        != len(rvas) + len(deferred)
        or _required_count(
            counts.get("blocked_transfers"), "interpreter blocked-transfer count"
        )
        != 0
        or _required_count(
            counts.get("deferred_transfers"), "interpreter deferred-transfer count"
        )
        != len(deferred)
    ):
        raise StageBNativeRuntimeError(
            "interpreter transfer scope does not match its inventory"
        )
    capability = _required_object(payload.get("capability"), "interpreter capability")
    word_ops = _required_list(capability.get("word_ops"), "interpreter word ops")
    has_undefined = any(op in {"undefined_bv", "undefined_flag"} for op in word_ops)
    policies, metadata_sha256 = _validate_definedness_use(
        payload,
        state_machine_sha256=state_machine_sha256,
        transfer_rows=transfers,
        transfer_ids={
            _required_string(
                _required_object(raw, f"interpreter transfer {index}").get("id"),
                f"interpreter transfer {index} id",
            )
            for index, raw in enumerate(transfers)
        },
        required=has_undefined,
    )
    return tuple(rvas), tuple(bindings), policies, metadata_sha256, deferred


def _validate_deferred_transfer_inventory(
    payload: Mapping[str, Any],
    *,
    label: str,
) -> tuple[dict[str, Any], ...]:
    rows = _required_list(payload.get("deferred_transfers"), f"{label} deferred transfers")
    coverage = _required_object(payload.get("semantic_coverage"), f"{label} coverage")
    policy = payload.get("execution_policy")
    expected_status = "incomplete" if rows else "complete"
    expected_policy = (
        "fail_closed_on_deferred_potential_transfer_v1"
        if rows
        else "complete_transfer_inventory_v1"
    )
    if (
        coverage.get("status") != expected_status
        or coverage.get("acceptance_authority") is not False
        or _required_count(
            coverage.get("deferred_transfers"), f"{label} deferred coverage count"
        )
        != len(rows)
        or policy != expected_policy
    ):
        raise StageBNativeRuntimeError(f"{label} deferred-transfer policy is malformed")
    normalized: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_rvas: set[int] = set()
    for index, raw in enumerate(rows):
        row = _required_object(raw, f"{label} deferred transfer {index}")
        transfer_id = _required_string(
            row.get("transfer_id"), f"{label} deferred transfer id"
        )
        rva = _required_u32(row.get("rva_start"), f"{label} deferred transfer RVA")
        if (
            row.get("code") != "machine_ir_semantics_incomplete"
            or row.get("failure_phase") != "semantic_qualification"
            or row.get("reachability") != "potential"
            or row.get("runtime_disposition")
            != "fail_closed_as_unimplemented_if_reached"
        ):
            raise StageBNativeRuntimeError(
                f"{label} deferred transfer {index} is not fail-closed potential code"
            )
        _required_string(row.get("message"), f"{label} deferred message")
        _required_string(row.get("next_action"), f"{label} deferred next action")
        if transfer_id in seen_ids or rva in seen_rvas:
            raise StageBNativeRuntimeError(f"{label} has duplicate deferred transfers")
        seen_ids.add(transfer_id)
        seen_rvas.add(rva)
        normalized.append(dict(row))
    return tuple(normalized)


def _semantic_input_binding(
    payload: dict[str, Any], label: str
) -> tuple[str, dict[str, Any]]:
    mode = payload.get("input_mode")
    state_machine = payload.get("state_machine")
    machine_ir = payload.get("machine_ir")
    if mode is None and state_machine is not None and machine_ir is None:
        mode = _STRICT_INPUT_MODE
    expected_key = {
        _STRICT_INPUT_MODE: "state_machine",
        _MACHINE_IR_INPUT_MODE: "machine_ir",
    }.get(mode)
    if (
        expected_key is None
        or (state_machine is None) == (machine_ir is None)
        or (expected_key == "state_machine") != (state_machine is not None)
    ):
        raise StageBNativeRuntimeError(
            f"{label} has an ambiguous or unsupported semantic input mode"
        )
    value = state_machine if expected_key == "state_machine" else machine_ir
    return str(mode), _required_object(value, f"{label} {expected_key}")


def _validate_typed_x87_operations(rows: list[Any]) -> None:
    rvas: list[int] = []
    for index, raw in enumerate(rows):
        row = _required_object(raw, f"typed x87 operation {index}")
        if _contains_key(row, "instruction_bytes"):
            raise StageBNativeRuntimeError(
                "typed x87 operation contains a forbidden instruction payload"
            )
        if row.get("format") != "stage-b-typed-native-x87-operation-v1":
            raise StageBNativeRuntimeError("typed x87 operation has an unsupported format")
        start = _required_u32(row.get("rva_start"), f"typed x87 operation {index} RVA")
        end = _required_u32(row.get("rva_end"), f"typed x87 operation {index} end RVA")
        if end <= start:
            raise StageBNativeRuntimeError("typed x87 operation has an empty source span")
        operation = _required_object(
            row.get("operation"), f"typed x87 operation {index} descriptor"
        )
        if operation.get("format") != "stage-b-typed-native-x87-operation-v1":
            raise StageBNativeRuntimeError("typed x87 descriptor has an unsupported format")
        identity = _required_sha256(
            operation.get("identity"), f"typed x87 operation {index} identity"
        )
        source_size = _required_count(
            operation.get("source_size"), f"typed x87 operation {index} source size"
        )
        if source_size == 0 or source_size != end - start:
            raise StageBNativeRuntimeError("typed x87 operation source span is inconsistent")
        _required_string(operation.get("mnemonic"), "typed x87 mnemonic")
        _required_object(operation.get("operand"), "typed x87 operand")
        address_binding = _required_object(
            row.get("address_binding"), f"typed x87 operation {index} address binding"
        )
        binding_kind = address_binding.get("kind")
        if binding_kind == "fixed_image_base":
            if (
                _required_u32(
                    address_binding.get("image_base"), "fixed x87 image base"
                )
                != _required_u32(row.get("image_base"), "typed x87 image base")
            ):
                raise StageBNativeRuntimeError(
                    "fixed x87 address binding differs from its operation image base"
                )
            _required_u32(address_binding.get("target_rva"), "fixed x87 target RVA")
            if row.get("base_relocation") is not None:
                raise StageBNativeRuntimeError(
                    "fixed x87 address binding unexpectedly carries relocation evidence"
                )
        elif binding_kind == "pe32_highlow_relocation":
            _required_object(row.get("base_relocation"), "typed x87 base relocation")
            _required_u32(address_binding.get("target_rva"), "relocated x87 target RVA")
        elif binding_kind == "position_independent":
            if row.get("base_relocation") is not None:
                raise StageBNativeRuntimeError(
                    "position-independent x87 operation carries relocation evidence"
                )
        else:
            raise StageBNativeRuntimeError(
                "typed x87 operation has an unsupported address binding"
            )
        if not identity:
            raise StageBNativeRuntimeError("typed x87 operation identity is empty")
        rvas.append(start)
    if rvas != sorted(rvas) or len(set(rvas)) != len(rvas):
        raise StageBNativeRuntimeError(
            "typed x87 operation RVAs must be strictly sorted and unique"
        )


def _contains_key(value: Any, key: str) -> bool:
    if isinstance(value, dict):
        return key in value or any(_contains_key(item, key) for item in value.values())
    if isinstance(value, list):
        return any(_contains_key(item, key) for item in value)
    return False


def _validate_definedness_use(
    payload: dict[str, Any],
    *,
    state_machine_sha256: str,
    transfer_rows: list[Any],
    transfer_ids: set[str],
    required: bool,
) -> tuple[tuple[NativeUndefinedPolicy, ...], str | None]:
    raw_metadata = payload.get("definedness_use")
    if raw_metadata is None:
        if required:
            raise StageBNativeRuntimeError(
                "interpreter program uses undefined_bv/undefined_flag but has no "
                f"complete {DEFINEDNESS_USE_FORMAT} metadata"
            )
        return (), None
    metadata = _required_object(raw_metadata, "interpreter definedness_use")
    if set(metadata) != STAGE_B_INTERPRETER_DEFINEDNESS_USE_FIELDS:
        raise StageBNativeRuntimeError(
            "interpreter definedness_use fields do not match the v1 schema"
        )
    if (
        metadata.get("format") != DEFINEDNESS_USE_FORMAT
        or metadata.get("status") != "complete"
        or metadata.get("proof_authority") is not False
        or metadata.get("state_machine_sha256") != state_machine_sha256
    ):
        raise StageBNativeRuntimeError(
            "interpreter definedness_use metadata is not complete and hash-bound"
        )
    _required_sha256(
        metadata.get("definedness_evidence_sha256"),
        "definedness evidence SHA-256",
    )
    transfer_digest = sha256_bytes(
        json.dumps(
            transfer_rows,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    )
    if metadata.get("transfer_inventory_sha256") != transfer_digest:
        raise StageBNativeRuntimeError(
            "interpreter definedness_use transfer inventory SHA-256 mismatch"
        )
    metadata_digest = _required_sha256(
        metadata.get("metadata_sha256"), "definedness metadata SHA-256"
    )
    metadata_body = dict(metadata)
    del metadata_body["metadata_sha256"]
    actual_metadata_digest = sha256_bytes(
        json.dumps(
            metadata_body,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    )
    if metadata_digest != actual_metadata_digest:
        raise StageBNativeRuntimeError("definedness metadata SHA-256 mismatch")
    undefined_node_count = _required_count(
        metadata.get("undefined_node_count"), "definedness undefined-node count"
    )
    counts = _required_object(payload.get("counts"), "interpreter counts")
    if "undefined_nodes" not in counts:
        raise StageBNativeRuntimeError(
            "interpreter counts omit undefined_nodes required for completeness"
        )
    if _required_count(counts.get("undefined_nodes"), "interpreter undefined-node count") != (
        undefined_node_count
    ):
        raise StageBNativeRuntimeError(
            "definedness metadata does not cover the interpreter undefined-node count"
        )
    raw_slots = _required_list(metadata.get("slots"), "definedness slots")
    evidence_slot_count = _required_count(
        metadata.get("evidence_slot_count"), "definedness evidence-slot count"
    )
    unused_evidence_slot_count = _required_count(
        metadata.get("unused_evidence_slot_count"),
        "definedness unused-evidence-slot count",
    )
    if evidence_slot_count != len(raw_slots) + unused_evidence_slot_count:
        raise StageBNativeRuntimeError(
            "definedness evidence-slot accounting is inconsistent"
        )
    policies: list[NativeUndefinedPolicy] = []
    seen_slots: set[int] = set()
    seen_uses: set[tuple[str, int]] = set()
    use_count = 0
    for index, raw in enumerate(raw_slots):
        slot_row = _required_object(raw, f"definedness slot {index}")
        if set(slot_row) != {
            "slot",
            "undefined_id",
            "classification",
            "witness_policy",
            "choice_source",
            "proof_obligations",
            "uses",
        }:
            raise StageBNativeRuntimeError(
                f"definedness slot {index} fields do not match the v1 schema"
            )
        slot = _required_u32(slot_row.get("slot"), f"definedness slot {index} id")
        if slot in seen_slots:
            raise StageBNativeRuntimeError("definedness metadata contains duplicate slots")
        seen_slots.add(slot)
        undefined_id = _required_string(
            slot_row.get("undefined_id"), f"definedness slot {index} undefined id"
        )
        classification = _required_string(
            slot_row.get("classification"), f"definedness slot {index} classification"
        )
        witness_policy = slot_row.get("witness_policy")
        raw_choice_source = slot_row.get("choice_source")
        obligations = _required_list(
            slot_row.get("proof_obligations"),
            f"definedness slot {index} proof obligations",
        )
        choice_kind = "unsupported"
        input_location: str | None = None
        if classification in {
            "unconstrained_noninterfering",
            "unconstrained_conditionally_noninterfering",
        }:
            choice_source = _required_object(
                raw_choice_source, f"definedness slot {index} choice source"
            )
            expected_choice_fields = {
                "format",
                "kind",
                "slot",
                "undefined_id",
                "requires_semantic_obligations",
            }
            if set(choice_source) != expected_choice_fields or (
                choice_source.get("format") != "stage-a-definedness-choice-source-v1"
                or choice_source.get("kind") != "noninterfering_zero"
                or choice_source.get("slot") != slot
                or choice_source.get("undefined_id") != undefined_id
                or choice_source.get("requires_semantic_obligations")
                is not bool(obligations)
            ):
                raise StageBNativeRuntimeError(
                    "noninterfering undefined slot has invalid zero-choice evidence"
                )
            if witness_policy != "zero":
                raise StageBNativeRuntimeError(
                    "noninterfering undefined slots require the checked zero witness policy"
                )
            if (
                classification == "unconstrained_noninterfering" and obligations
            ) or (
                classification == "unconstrained_conditionally_noninterfering"
                and not obligations
            ):
                raise StageBNativeRuntimeError(
                    "definedness conditional classification disagrees with obligations"
                )
            choice_kind = "noninterfering_zero"
        elif classification == "synchronized_behavior_relevant":
            choice_source = _required_object(
                raw_choice_source, f"definedness slot {index} choice source"
            )
            common_choice_fields = {
                "format",
                "kind",
                "slot",
                "undefined_id",
                "profile",
                "instruction_rva",
                "location",
                "input_expression",
                "input_expression_sha256",
            }
            choice_format = choice_source.get("format")
            exact_bytes_fields = common_choice_fields | {"instruction_bytes"}
            typed_ir_fields = common_choice_fields | {
                "instruction_sha256",
                "instruction_model",
            }
            if (
                (choice_format == "stage-a-definedness-choice-source-v3"
                 and set(choice_source) != exact_bytes_fields)
                or (choice_format == "stage-a-definedness-choice-source-v4"
                    and set(choice_source) != typed_ir_fields)
                or choice_format not in {
                    "stage-a-definedness-choice-source-v3",
                    "stage-a-definedness-choice-source-v4",
                }
                or choice_source.get("kind") != "related_machine_input"
                or choice_source.get("slot") != slot
                or choice_source.get("undefined_id") != undefined_id
                or choice_source.get("profile")
                != "ia32-bsr-zero-preserves-destination-v1"
            ):
                raise StageBNativeRuntimeError(
                    "synchronized undefined slot has invalid machine-input evidence"
                )
            _required_u32(
                choice_source.get("instruction_rva"),
                f"definedness slot {index} BSR instruction RVA",
            )
            if choice_format == "stage-a-definedness-choice-source-v3":
                instruction_bytes = choice_source.get("instruction_bytes")
                if (
                    not isinstance(instruction_bytes, str)
                    or re.fullmatch(r"[0-9a-f]+", instruction_bytes) is None
                    or len(instruction_bytes) % 2
                ):
                    raise StageBNativeRuntimeError(
                        "synchronized undefined slot has invalid BSR instruction bytes"
                    )
            elif (
                choice_source.get("instruction_model")
                != "sanitized_typed_machine_ir_v2"
            ):
                raise StageBNativeRuntimeError(
                    "synchronized undefined slot has invalid typed instruction model"
                )
            else:
                _required_sha256(
                    choice_source.get("instruction_sha256"),
                    f"definedness slot {index} BSR instruction SHA-256",
                )
            input_expression = _required_object(
                choice_source.get("input_expression"),
                f"definedness slot {index} input expression",
            )
            expected_expression_sha256 = _required_sha256(
                choice_source.get("input_expression_sha256"),
                f"definedness slot {index} input expression SHA-256",
            )
            if sha256_bytes(
                json.dumps(
                    input_expression,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                ).encode("ascii")
            ) != expected_expression_sha256:
                raise StageBNativeRuntimeError(
                    "synchronized undefined slot input expression digest differs"
                )
            location = _required_object(
                choice_source.get("location"),
                f"definedness slot {index} input location",
            )
            if set(location) != {"family", "name"} or location.get("family") != "register":
                raise StageBNativeRuntimeError(
                    "synchronized undefined slot input location is not a register"
                )
            input_location = _required_string(
                location.get("name"),
                f"definedness slot {index} input register",
            )
            if input_location not in {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}:
                raise StageBNativeRuntimeError(
                    "synchronized undefined slot input register is unsupported"
                )
            if witness_policy != "synchronized":
                raise StageBNativeRuntimeError(
                    "synchronized undefined slot requires an input-derived witness policy"
                )
            choice_kind = "related_machine_input"
        elif classification == "unknown":
            if witness_policy is not None:
                raise StageBNativeRuntimeError(
                    "unknown slots cannot declare a candidate witness"
                )
            if raw_choice_source is not None or obligations:
                raise StageBNativeRuntimeError(
                    "unknown slots cannot declare choice or semantic evidence"
                )
        else:
            raise StageBNativeRuntimeError(
                f"definedness slot {index} has an unsupported classification"
            )
        uses = _required_list(slot_row.get("uses"), f"definedness slot {index} uses")
        if not uses:
            raise StageBNativeRuntimeError(f"definedness slot {index} has no uses")
        for use_index, raw_use in enumerate(uses):
            use = _required_object(
                raw_use, f"definedness slot {index} use {use_index}"
            )
            base_use_fields = {"transfer_id", "node_index", "op"}
            use_fields = frozenset(use)
            if use_fields not in {
                frozenset(base_use_fields),
                frozenset((*base_use_fields, "defined_value_node")),
            }:
                raise StageBNativeRuntimeError(
                    f"definedness slot {index} use {use_index} fields are invalid"
                )
            transfer_id = _required_string(
                use.get("transfer_id"), "definedness use transfer id"
            )
            node_index = _required_count(
                use.get("node_index"), "definedness use node index"
            )
            if choice_kind == "related_machine_input" and "defined_value_node" not in use:
                raise StageBNativeRuntimeError(
                    "synchronized definedness use omits its input-expression node"
                )
            if "defined_value_node" in use:
                _required_count(
                    use.get("defined_value_node"),
                    "definedness use input-expression node index",
                )
            if transfer_id not in transfer_ids:
                raise StageBNativeRuntimeError(
                    "definedness use references an unknown interpreter transfer"
                )
            if use.get("op") not in {"undefined_bv", "undefined_flag"}:
                raise StageBNativeRuntimeError(
                    "definedness use must identify undefined_bv or undefined_flag"
                )
            if (transfer_id, node_index) in seen_uses:
                raise StageBNativeRuntimeError(
                    "definedness metadata contains a duplicate transfer/node use"
                )
            seen_uses.add((transfer_id, node_index))
            use_count += 1
        policies.append(
            NativeUndefinedPolicy(
                slot=slot,
                undefined_id=undefined_id,
                classification=classification,
                witness_policy=witness_policy,
                choice_kind=choice_kind,
                input_location=input_location,
                obligation_count=len(obligations),
                use_count=len(uses),
            )
        )
    if use_count != undefined_node_count or required != (undefined_node_count != 0):
        raise StageBNativeRuntimeError(
            "definedness metadata is incomplete for the interpreter undefined nodes"
        )
    return tuple(sorted(policies, key=lambda item: item.slot)), metadata_digest


def _canonical_json_sha256(value: Any) -> str:
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    except (TypeError, UnicodeEncodeError) as exc:
        raise StageBNativeRuntimeError(
            "native receipt is not canonical JSON"
        ) from exc
    return sha256_bytes(encoded)


def _validate_implementation_dispatch_receipt(
    payload: dict[str, Any],
    *,
    candidate_mode: str,
    deferred_transfer_ids: frozenset[str],
    state_machine_sha256: str,
    transfer_bindings: tuple[_InterpreterTransferBinding, ...],
) -> tuple[dict[str, Any], tuple[NativeImplementationDispatch, ...]]:
    """Validate exact dispatch coverage independently of engine generation."""

    raw = _required_object(
        payload.get("implementation_dispatch_receipt"),
        "native-engine implementation dispatch receipt",
    )
    expected_fields = {
        "format",
        "status",
        "semantic_input_sha256",
        "machine_ir_manifest_sha256",
        "reachability",
        "policy",
        "counts",
        "entries",
        "targets",
        "blockers",
        "receipt_sha256",
    }
    if (
        set(raw) != expected_fields
        or raw.get("format") != _IMPLEMENTATION_DISPATCH_RECEIPT_FORMAT
        or raw.get("semantic_input_sha256") != state_machine_sha256
    ):
        raise StageBNativeRuntimeError(
            "native-engine implementation dispatch receipt is not canonically bound"
        )
    body = {
        key: raw[key]
        for key in expected_fields
        if key not in {"format", "receipt_sha256"}
    }
    if (
        _required_sha256(
            raw.get("receipt_sha256"), "implementation dispatch receipt SHA-256"
        )
        != _canonical_json_sha256(body)
    ):
        raise StageBNativeRuntimeError(
            "native-engine implementation dispatch receipt hash is invalid"
        )
    if _required_list(raw.get("blockers"), "implementation dispatch blockers"):
        raise StageBNativeRuntimeError(
            "ready native-engine plan has incomplete implementation dispatch"
        )
    policy = _required_object(
        raw.get("policy"), "implementation dispatch policy"
    )
    expected_policy = {
        "candidate_mode": candidate_mode,
        "one_implementation_class_per_transfer": True,
        "rooted_targets_require_implementation": (
            candidate_mode == STATIC_CLOSED_CANDIDATE_MODE
        ),
        "runtime_code_target_lookup": "exact-active-transfer-rva",
        "unresolved_dispatch": "fail-closed-as-unimplemented",
        "portable_component_fallback_on_unimplemented": False,
        "static_hybrid_closure_receipt_required_for_candidate": (
            candidate_mode == STATIC_CLOSED_CANDIDATE_MODE
        ),
        "acceptance_authority": False,
    }
    if policy != expected_policy:
        raise StageBNativeRuntimeError(
            "native-engine implementation dispatch policy is unsupported"
        )

    reachability = _required_object(
        raw.get("reachability"), "implementation dispatch reachability"
    )
    if set(reachability) != {
        "status",
        "roots",
        "reachable_unit_ids",
        "potential_unit_ids",
        "confirmed_unreachable_unit_ids",
        "frontiers",
    }:
        raise StageBNativeRuntimeError(
            "implementation dispatch reachability fields are not canonical"
        )
    roots = _required_list(reachability.get("roots"), "implementation roots")
    reachable = _required_list(
        reachability.get("reachable_unit_ids"), "implementation reachable units"
    )
    potential = _required_list(
        reachability.get("potential_unit_ids"), "implementation potential units"
    )
    unreachable = _required_list(
        reachability.get("confirmed_unreachable_unit_ids"),
        "implementation confirmed-unreachable units",
    )
    frontiers = _required_list(
        reachability.get("frontiers"), "implementation reachability frontiers"
    )
    inventories = roots + reachable + potential + unreachable
    if (
        any(not isinstance(value, str) or not value for value in inventories)
        or roots != sorted(set(roots))
        or reachable != sorted(set(reachable))
        or potential != sorted(set(potential))
        or unreachable != sorted(set(unreachable))
        or not set(roots) <= set(reachable)
        or set(reachable) & set(potential)
        or set(reachable) & set(unreachable)
        or set(potential) & set(unreachable)
        or any(not isinstance(frontier, Mapping) for frontier in frontiers)
    ):
        raise StageBNativeRuntimeError(
            "implementation dispatch rooted reachability is malformed"
        )
    reachability_status = reachability.get("status")
    receipt_status = raw.get("status")
    manifest_sha256 = raw.get("machine_ir_manifest_sha256")
    if reachability_status == "complete":
        if (
            receipt_status != "complete"
            or not roots
            or not reachable
            or potential
            or frontiers
            or _SHA256_RE.fullmatch(str(manifest_sha256 or "")) is None
        ):
            raise StageBNativeRuntimeError(
                "complete implementation dispatch lacks rooted manifest evidence"
            )
    elif (
        reachability_status == "incomplete"
        and candidate_mode == STRUCTURAL_DIAGNOSTIC_CANDIDATE_MODE
    ):
        if (
            receipt_status != "diagnostic"
            or not roots
            or not reachable
            or _SHA256_RE.fullmatch(str(manifest_sha256 or "")) is None
        ):
            raise StageBNativeRuntimeError(
                "structural diagnostic dispatch lacks bound reachability evidence"
            )
    elif reachability_status == "not_bound":
        if receipt_status != "unbound" or roots or reachable:
            raise StageBNativeRuntimeError(
                "unbound implementation dispatch claims rooted coverage"
            )
        if manifest_sha256 is not None:
            _required_sha256(
                manifest_sha256, "implementation dispatch manifest SHA-256"
            )
    else:
        raise StageBNativeRuntimeError(
            "ready native-engine implementation reachability is incomplete"
        )

    entries = _required_list(raw.get("entries"), "implementation dispatch entries")
    active_unit_ids = {binding.unit_id for binding in transfer_bindings}
    partition_unit_ids = set(reachable) | set(potential) | set(unreachable)
    if (
        reachability_status != "not_bound"
        and partition_unit_ids != active_unit_ids | set(deferred_transfer_ids)
    ):
        raise StageBNativeRuntimeError(
            "implementation reachability does not partition active and deferred transfers"
        )
    if (
        reachability_status != "not_bound"
        and not deferred_transfer_ids <= set(potential)
    ):
        raise StageBNativeRuntimeError(
            "implementation dispatch defers a non-potential transfer"
        )
    entry_fields = {
        "unit_id",
        "rva",
        "transfer_sha256",
        "reachability",
        "implementation_class",
        "dispatch_lookup",
        "replacement_id",
        "cluster_id",
        "component_manifest_sha256",
        "fallback_on_unimplemented",
        "entry_sha256",
    }
    if len(entries) != len(transfer_bindings):
        raise StageBNativeRuntimeError(
            "implementation dispatch omits or adds interpreter transfers"
        )
    dispatches: list[NativeImplementationDispatch] = []
    entry_by_id: dict[str, NativeImplementationDispatch] = {}
    for index, (raw_entry, binding) in enumerate(
        zip(entries, transfer_bindings, strict=True)
    ):
        entry = _required_object(raw_entry, f"implementation dispatch entry {index}")
        if set(entry) != entry_fields:
            raise StageBNativeRuntimeError(
                "implementation dispatch entry fields are not canonical"
            )
        entry_body = {
            key: entry[key] for key in entry_fields if key != "entry_sha256"
        }
        if (
            _required_sha256(
                entry.get("entry_sha256"),
                f"implementation dispatch entry {index} SHA-256",
            )
            != _canonical_json_sha256(entry_body)
        ):
            raise StageBNativeRuntimeError(
                "implementation dispatch entry hash is invalid"
            )
        unit_id = _required_string(
            entry.get("unit_id"), f"implementation dispatch entry {index} unit id"
        )
        rva = _required_u32(
            entry.get("rva"), f"implementation dispatch entry {index} RVA"
        )
        _required_sha256(
            entry.get("transfer_sha256"),
            f"implementation dispatch entry {index} transfer SHA-256",
        )
        if unit_id != binding.unit_id or rva != binding.rva or unit_id in entry_by_id:
            raise StageBNativeRuntimeError(
                "implementation dispatch is duplicate, reordered, or mismatched"
            )
        reachability_class = entry.get("reachability")
        expected_reachability = (
            "root"
            if unit_id in roots
            else "reachable"
            if unit_id in reachable
            else "potential"
            if unit_id in potential
            else "confirmed_unreachable"
            if unit_id in unreachable
            else "unbound"
        )
        if reachability_class != expected_reachability:
            raise StageBNativeRuntimeError(
                "implementation dispatch reachability class is inconsistent"
            )
        implementation_class = entry.get("implementation_class")
        replacement_id = entry.get("replacement_id")
        cluster_id = entry.get("cluster_id")
        component_sha256 = entry.get("component_manifest_sha256")
        if entry.get("fallback_on_unimplemented") is not False:
            raise StageBNativeRuntimeError(
                "implementation dispatch permits a second fallback class"
            )
        if implementation_class == "machine_ir_fallback":
            if (
                entry.get("dispatch_lookup") != "stage_b_program_lookup"
                or replacement_id is not None
                or cluster_id is not None
                or component_sha256 is not None
            ):
                raise StageBNativeRuntimeError(
                    "machine-IR fallback dispatch carries portable metadata"
                )
        elif implementation_class == "selected_portable_component":
            if entry.get("dispatch_lookup") != "stage_b_region_override_lookup":
                raise StageBNativeRuntimeError(
                    "portable component dispatch uses the wrong lookup"
                )
            replacement_id = _required_portable_identity(
                replacement_id, "portable component replacement id"
            )
            cluster_id = _required_portable_identity(
                cluster_id, "portable component cluster id"
            )
            _required_sha256(
                component_sha256, "portable component manifest SHA-256"
            )
        else:
            raise StageBNativeRuntimeError(
                "implementation dispatch has an unsupported implementation class"
            )
        dispatch = NativeImplementationDispatch(
            unit_id=unit_id,
            rva=rva,
            implementation_class=str(implementation_class),
            replacement_id=replacement_id,
            cluster_id=cluster_id,
        )
        entry_by_id[unit_id] = dispatch
        dispatches.append(dispatch)

    targets = _required_list(raw.get("targets"), "implementation dispatch targets")
    target_fields = {
        "kind",
        "source_unit_id",
        "source_rva",
        "source_event_index",
        "target_unit_id",
        "target_rva",
        "target_sha256",
    }
    seen_targets: set[tuple[str, str, int | None, str]] = set()
    for index, raw_target in enumerate(targets):
        target = _required_object(
            raw_target, f"implementation dispatch target {index}"
        )
        if set(target) != target_fields:
            raise StageBNativeRuntimeError(
                "implementation dispatch target fields are not canonical"
            )
        target_body = {
            key: target[key] for key in target_fields if key != "target_sha256"
        }
        if (
            _required_sha256(
                target.get("target_sha256"),
                f"implementation dispatch target {index} SHA-256",
            )
            != _canonical_json_sha256(target_body)
        ):
            raise StageBNativeRuntimeError(
                "implementation dispatch target hash is invalid"
            )
        kind = _required_string(
            target.get("kind"), f"implementation dispatch target {index} kind"
        )
        if kind not in {
            "direct_control",
            "internal_call",
            "call_continuation",
            "indirect_internal",
        }:
            raise StageBNativeRuntimeError(
                "implementation dispatch target kind is unsupported"
            )
        source_unit_id = _required_string(
            target.get("source_unit_id"), "implementation target source unit"
        )
        target_unit_id = _required_string(
            target.get("target_unit_id"), "implementation target unit"
        )
        event_index = target.get("source_event_index")
        if event_index is not None:
            event_index = _required_count(
                event_index, "implementation target source event index"
            )
        source_dispatch = entry_by_id.get(source_unit_id)
        target_dispatch = entry_by_id.get(target_unit_id)
        key = (kind, source_unit_id, event_index, target_unit_id)
        if (
            reachability_status != "complete"
            or source_dispatch is None
            or target_dispatch is None
            or source_unit_id not in reachable
            or target_unit_id not in reachable
            or _required_u32(
                target.get("source_rva"), "implementation target source RVA"
            )
            != source_dispatch.rva
            or _required_u32(
                target.get("target_rva"), "implementation target RVA"
            )
            != target_dispatch.rva
            or key in seen_targets
        ):
            raise StageBNativeRuntimeError(
                "implementation target has no unique rooted executable dispatch"
            )
        seen_targets.add(key)
    if reachability_status != "complete" and targets:
        raise StageBNativeRuntimeError(
            "non-closed implementation dispatch contains rooted target claims"
        )

    counts = _required_object(raw.get("counts"), "implementation dispatch counts")
    expected_counts = {
        "dispatch_entries": len(entries),
        "rooted_reachable_units": len(reachable),
        "rooted_targets": len(targets),
        "machine_ir_fallback": sum(
            dispatch.implementation_class == "machine_ir_fallback"
            for dispatch in dispatches
        ),
        "selected_portable_component": sum(
            dispatch.implementation_class == "selected_portable_component"
            for dispatch in dispatches
        ),
        "blockers": 0,
    }
    if counts != expected_counts:
        raise StageBNativeRuntimeError(
            "implementation dispatch counts differ from their inventories"
        )
    return dict(raw), tuple(dispatches)


def _validate_callback_adapter_receipts(
    payload: dict[str, Any],
    *,
    callback_abis: list[Any],
) -> tuple[dict[str, Any], ...]:
    """Require an exact receipt for every generated registration adapter."""

    callback_by_rva: dict[int, dict[str, Any]] = {}
    for index, raw in enumerate(callback_abis):
        callback = _required_object(raw, f"native-engine callback ABI {index}")
        rva = _required_u32(callback.get("rva"), "callback ABI RVA")
        if rva in callback_by_rva:
            raise StageBNativeRuntimeError(
                "native-engine callback ABI inventory contains duplicates"
            )
        callback_by_rva[rva] = callback

    adapters = _required_list(
        payload.get("callback_adapters"), "native-engine callback adapters"
    )
    normalized_adapters: list[dict[str, Any]] = []
    adapter_by_site: dict[tuple[int, int], list[dict[str, Any]]] = {}
    adapter_keys: set[tuple[int, int, int, int]] = set()
    expected_adapter_fields = {
        "id",
        "instruction_rva",
        "argument_index",
        "original_rva",
        "callback_rva",
        "symbol",
        "matching",
    }
    for index, raw in enumerate(adapters):
        adapter = _required_object(raw, f"native-engine callback adapter {index}")
        if set(adapter) != expected_adapter_fields:
            raise StageBNativeRuntimeError(
                "native-engine callback adapter fields are not canonical"
            )
        adapter_id = _required_count(adapter.get("id"), "callback adapter id")
        instruction_rva = _required_u32(
            adapter.get("instruction_rva"), "callback adapter instruction RVA"
        )
        argument_index = _required_count(
            adapter.get("argument_index"), "callback adapter argument index"
        )
        original_rva = _required_u32(
            adapter.get("original_rva"), "callback adapter original RVA"
        )
        callback_rva = _required_u32(
            adapter.get("callback_rva"), "callback adapter callback RVA"
        )
        key = (instruction_rva, argument_index, original_rva, callback_rva)
        if (
            adapter_id != index
            or key in adapter_keys
            or original_rva != callback_rva
            or adapter.get("matching") != "runtime-image-base-plus-rva"
            or adapter.get("symbol")
            != f"stage_b_payload_callback_{callback_rva:08x}"
            or callback_rva not in callback_by_rva
        ):
            raise StageBNativeRuntimeError(
                "native-engine callback adapter is duplicate or mismatched"
            )
        adapter_keys.add(key)
        normalized = dict(adapter)
        normalized_adapters.append(normalized)
        adapter_by_site.setdefault((instruction_rva, argument_index), []).append(
            normalized
        )

    explicit_sites: dict[
        tuple[int, str, int, int],
        tuple[dict[str, Any], CheckedExternalSiteContract],
    ] = {}
    for site_index, raw in enumerate(
        _required_list(payload.get("external_sites"), "native-engine external sites")
    ):
        site = _required_object(raw, f"native-engine external site {site_index}")
        raw_contract = site.get("checked_external_contract")
        if not isinstance(raw_contract, Mapping):
            continue
        try:
            contract = parse_checked_external_site_contract(
                raw_contract,
                context=f"native-engine external site {site_index}",
            )
        except CheckedExternalSiteContractError as exc:
            raise StageBNativeRuntimeError(str(exc)) from exc
        if contract.callback_effect != "explicit":
            continue
        adapter_contract = contract.callback_adapter
        if adapter_contract is None:
            raise StageBNativeRuntimeError(
                "explicit callback contract has no normalized adapter"
            )
        site_id = _required_count(site.get("id"), "external site id")
        transfer_id = _required_string(
            site.get("transfer_id"), "external site transfer id"
        )
        event_index = _required_count(
            site.get("event_index"), "external site event index"
        )
        instruction_rva = _required_u32(
            site.get("instruction_rva"), "external site instruction RVA"
        )
        key = (site_id, transfer_id, event_index, instruction_rva)
        if key in explicit_sites:
            raise StageBNativeRuntimeError(
                "native-engine explicit callback sites are duplicated"
            )
        explicit_sites[key] = (site, contract)

    receipts = _required_list(
        payload.get("callback_adapter_receipts"),
        "native-engine callback adapter receipts",
    )
    expected_receipt_fields = {
        "format",
        "site_id",
        "transfer_id",
        "event_index",
        "instruction_rva",
        "checked_external_contract_sha256",
        "source",
        "abi",
        "lifetime",
        "invocation",
        "target_rvas",
        "adapter_entries",
        "receipt_sha256",
    }
    seen_sites: set[tuple[int, str, int, int]] = set()
    consumed_adapter_ids: set[int] = set()
    normalized_receipts: list[dict[str, Any]] = []
    for index, raw in enumerate(receipts):
        receipt = _required_object(
            raw, f"native-engine callback adapter receipt {index}"
        )
        if (
            set(receipt) != expected_receipt_fields
            or receipt.get("format") != _CALLBACK_ADAPTER_RECEIPT_FORMAT
        ):
            raise StageBNativeRuntimeError(
                "native-engine callback adapter receipt fields are not canonical"
            )
        site_key = (
            _required_count(receipt.get("site_id"), "callback receipt site id"),
            _required_string(
                receipt.get("transfer_id"), "callback receipt transfer id"
            ),
            _required_count(
                receipt.get("event_index"), "callback receipt event index"
            ),
            _required_u32(
                receipt.get("instruction_rva"),
                "callback receipt instruction RVA",
            ),
        )
        site_binding = explicit_sites.get(site_key)
        if site_binding is None or site_key in seen_sites:
            raise StageBNativeRuntimeError(
                "native-engine callback adapter receipt has no unique checked site"
            )
        seen_sites.add(site_key)
        site, contract = site_binding
        adapter_contract = contract.callback_adapter
        assert adapter_contract is not None
        body = {
            key: receipt[key]
            for key in expected_receipt_fields
            if key not in {"format", "receipt_sha256"}
        }
        if (
            _required_sha256(
                receipt.get("receipt_sha256"), "callback receipt SHA-256"
            ) != _canonical_json_sha256(body)
            or receipt.get("checked_external_contract_sha256")
            != _canonical_json_sha256(contract.payload())
            or receipt.get("source") != adapter_contract.source
            or receipt.get("abi") != adapter_contract.abi
            or receipt.get("lifetime") != adapter_contract.lifetime
            or receipt.get("invocation") != adapter_contract.invocation
            or receipt.get("target_rvas") != list(adapter_contract.target_rvas)
        ):
            raise StageBNativeRuntimeError(
                "native-engine callback adapter receipt differs from its checked contract"
            )
        source = adapter_contract.source
        abi = adapter_contract.abi
        if not isinstance(source, Mapping) or not isinstance(abi, Mapping):
            raise StageBNativeRuntimeError(
                "native-engine callback receipt source or ABI is malformed"
            )
        source_kind = source.get("kind")
        argument_index = _required_count(
            source.get("argument"), "callback receipt source argument"
        )
        pointee_offset = (
            _required_count(source.get("offset"), "callback receipt pointee offset")
            if source_kind == "argument_pointee"
            else 0
        )
        registration = _required_object(
            site.get("callback_registration"),
            "native-engine callback registration",
        )
        nullable = abi.get("nullable")
        if (
            source_kind not in {"argument_word", "argument_pointee"}
            or not isinstance(nullable, bool)
            or registration
            != {
                "source_kind": source_kind,
                "argument_index": argument_index,
                "stack_offset": contract.argument_base_offset
                + argument_index * 4,
                "pointee_offset": pointee_offset,
                "nullable": nullable,
            }
        ):
            raise StageBNativeRuntimeError(
                "native-engine callback registration differs from its receipt"
            )
        expected_entries = adapter_by_site.get(
            (site_key[3], argument_index), []
        )
        raw_entries = _required_list(
            receipt.get("adapter_entries"), "callback receipt adapter entries"
        )
        if raw_entries != expected_entries or [
            entry.get("callback_rva") for entry in expected_entries
        ] != list(adapter_contract.target_rvas):
            raise StageBNativeRuntimeError(
                "native-engine callback receipt adapter inventory is incomplete or extra"
            )
        expected_kind = abi.get("kind")
        expected_cleanup = abi.get("stack_cleanup_bytes")
        for entry in expected_entries:
            callback = callback_by_rva[int(entry["callback_rva"])]
            if (
                callback.get("kind") != expected_kind
                or callback.get("stack_cleanup_bytes") != expected_cleanup
            ):
                raise StageBNativeRuntimeError(
                    "native-engine callback receipt ABI differs from its target"
                )
            adapter_id = int(entry["id"])
            if adapter_id in consumed_adapter_ids:
                raise StageBNativeRuntimeError(
                    "native-engine callback adapter is covered by multiple receipts"
                )
            consumed_adapter_ids.add(adapter_id)
        normalized_receipts.append(dict(receipt))

    if seen_sites != set(explicit_sites) or consumed_adapter_ids != {
        int(adapter["id"]) for adapter in normalized_adapters
    }:
        raise StageBNativeRuntimeError(
            "native-engine callback adapter receipt coverage is incomplete"
        )
    return tuple(normalized_receipts)


def _validate_native_plan(
    payload: dict[str, Any],
    *,
    candidate_mode: str,
    deferred_transfer_ids: frozenset[str],
    state_machine_sha256: str,
    input_mode: str,
    transfer_rvas: tuple[int, ...],
    transfer_bindings: tuple[_InterpreterTransferBinding, ...],
) -> tuple[
    int,
    tuple[tuple[int, int], ...],
    tuple[dict[str, Any], ...],
    dict[str, Any],
    tuple[NativeImplementationDispatch, ...],
    tuple[tuple[int, int], ...],
]:
    if payload.get("format") != NATIVE_ENGINE_PLAN_FORMAT:
        raise StageBNativeRuntimeError("native-engine plan has an unsupported format")
    if payload.get("candidate_mode") != candidate_mode:
        raise StageBNativeRuntimeError(
            "native-engine plan candidate mode changed during validation"
        )
    if payload.get("status") != "ready":
        raise StageBNativeRuntimeError("native-engine plan is not ready")
    if payload.get("state_machine_sha256") != state_machine_sha256:
        raise StageBNativeRuntimeError(
            "interpreter and native-engine packages bind different state machines"
        )
    if payload.get("input_mode", _STRICT_INPUT_MODE) != input_mode:
        raise StageBNativeRuntimeError(
            "native-engine plan and packages bind different semantic input modes"
        )
    if _required_list(payload.get("blockers"), "native-engine blockers"):
        raise StageBNativeRuntimeError("ready native-engine plan contains blockers")
    diagnostic_frontiers = _required_list(
        payload.get("diagnostic_frontiers"),
        "native-engine diagnostic frontiers",
    )
    if any(
        not isinstance(frontier, Mapping)
        or frontier.get("severity") != "diagnostic"
        for frontier in diagnostic_frontiers
    ):
        raise StageBNativeRuntimeError(
            "native-engine diagnostic frontier inventory is malformed"
        )
    if (
        candidate_mode == STATIC_CLOSED_CANDIDATE_MODE
        and diagnostic_frontiers
    ):
        raise StageBNativeRuntimeError(
            "static-closed native engine contains diagnostic frontiers"
        )
    implementation_dispatch_receipt, implementation_dispatches = (
        _validate_implementation_dispatch_receipt(
            payload,
            candidate_mode=candidate_mode,
            deferred_transfer_ids=deferred_transfer_ids,
            state_machine_sha256=state_machine_sha256,
            transfer_bindings=transfer_bindings,
        )
    )
    callback_targets = tuple(
        _required_u32(value, "native-engine callback RVA")
        for value in _required_list(
            payload.get("callback_targets"), "native-engine callbacks"
        )
    )
    if callback_targets != tuple(sorted(set(callback_targets))):
        raise StageBNativeRuntimeError(
            "native-engine callback RVAs must be sorted and unique"
        )
    if any(target not in transfer_rvas for target in callback_targets):
        raise StageBNativeRuntimeError(
            "native-engine callback lacks a checked interpreter transfer"
        )
    recovered_data = _required_object(
        payload.get("recovered_executable_data"),
        "native-engine recovered executable data",
    )
    if recovered_data.get("dispatch_policy") != "fail_closed_as_noncode":
        raise StageBNativeRuntimeError(
            "native-engine recovered executable data is not fail-closed"
        )
    recovered_ranges: list[tuple[int, int]] = []
    for index, raw in enumerate(
        _required_list(
            recovered_data.get("ranges"),
            "native-engine recovered executable-data ranges",
        )
    ):
        row = _required_object(raw, f"recovered executable-data range {index}")
        _required_string(row.get("id"), f"recovered executable-data range {index} id")
        _required_sha256(
            row.get("bytes_sha256"),
            f"recovered executable-data range {index} SHA-256",
        )
        start = _required_u32(
            row.get("rva_start"), f"recovered executable-data range {index} start"
        )
        end = _required_u32(
            row.get("rva_end"), f"recovered executable-data range {index} end"
        )
        if end <= start:
            raise StageBNativeRuntimeError(
                "native-engine recovered executable-data range is empty"
            )
        if recovered_ranges and start < recovered_ranges[-1][1]:
            raise StageBNativeRuntimeError(
                "native-engine recovered executable-data ranges overlap or are unsorted"
            )
        recovered_ranges.append((start, end))
    entry_rva = _required_u32(payload.get("entry_rva"), "native-engine entry RVA")
    if any(
        start <= target < end
        for target in (entry_rva, *callback_targets)
        for start, end in recovered_ranges
    ):
        raise StageBNativeRuntimeError(
            "native entry or callback target overlaps recovered executable data"
        )
    callback_abis = _required_list(
        payload.get("callback_abis"), "native-engine callback ABIs"
    )
    if len(callback_abis) != len(callback_targets):
        raise StageBNativeRuntimeError(
            "native-engine callback ABI inventory differs from callback targets"
        )
    for index, (raw, target) in enumerate(
        zip(callback_abis, callback_targets, strict=True)
    ):
        callback = _required_object(raw, f"native-engine callback ABI {index}")
        if _required_u32(callback.get("rva"), "callback ABI RVA") != target:
            raise StageBNativeRuntimeError(
                "native-engine callback ABI RVA differs from its target"
            )
        expected_symbol = f"stage_b_payload_callback_{target:08x}"
        if _required_string(callback.get("symbol"), "callback ABI symbol") != expected_symbol:
            raise StageBNativeRuntimeError(
                "native-engine callback ABI symbol is not the canonical RVA anchor"
            )
        _required_string(callback.get("transfer_id"), "callback ABI transfer id")
        _required_sha256(
            callback.get("transfer_sha256"), "callback ABI transfer SHA-256"
        )
        kind = _required_string(callback.get("kind"), "callback ABI kind")
        cleanup = _required_count(
            callback.get("stack_cleanup_bytes"), "callback ABI stack cleanup"
        )
        if kind == "tls_callback":
            if cleanup != 12:
                raise StageBNativeRuntimeError(
                    "PE32 TLS callback ABI must clean exactly 12 stack bytes"
                )
        elif kind != "generic_callback":
            raise StageBNativeRuntimeError(
                "native-engine callback ABI kind is unsupported"
            )
    callback_adapter_receipts = _validate_callback_adapter_receipts(
        payload, callback_abis=callback_abis
    )
    passthroughs = _required_list(
        payload.get("callback_passthroughs"),
        "native-engine callback passthroughs",
    )
    seen_passthroughs: set[tuple[int, int]] = set()
    for index, raw in enumerate(passthroughs):
        passthrough = _required_object(
            raw, f"native-engine callback passthrough {index}"
        )
        key = (
            _required_u32(
                passthrough.get("instruction_rva"), "callback passthrough call RVA"
            ),
            _required_count(
                passthrough.get("argument_index"), "callback passthrough argument"
            ),
        )
        _required_u32(
            passthrough.get("storage_va"), "callback passthrough storage VA"
        )
        if (
            passthrough.get("origin") != "previous_registered_callback"
            or passthrough.get("storage_invariant") not in {
                "dominating_previous_registered_callback",
                "initial_zero_or_previous_registered_callback",
            }
            or passthrough.get("runtime_action")
            != "pass_through_environment_pointer"
            or key in seen_passthroughs
        ):
            raise StageBNativeRuntimeError(
                "native-engine callback passthrough is malformed or duplicate"
            )
        seen_passthroughs.add(key)
    if entry_rva not in transfer_rvas:
        raise StageBNativeRuntimeError(
            "native-engine entry RVA is absent from the interpreter transfer table"
        )
    counts = _required_object(payload.get("counts"), "native-engine counts")
    if _required_count(counts.get("transfers"), "native-engine transfer count") != len(
        transfer_rvas
    ):
        raise StageBNativeRuntimeError(
            "native-engine and interpreter transfer counts differ"
        )
    if _required_count(
        counts.get("callback_adapters"),
        "native-engine callback adapter count",
    ) != len(_required_list(
        payload.get("callback_adapters"), "native-engine callback adapters"
    )):
        raise StageBNativeRuntimeError(
            "native-engine callback adapter count differs from its inventory"
        )
    if _required_count(
        counts.get("callback_adapter_receipts"),
        "native-engine callback adapter receipt count",
    ) != len(callback_adapter_receipts):
        raise StageBNativeRuntimeError(
            "native-engine callback adapter receipt count differs from its inventory"
        )
    if _required_count(
        counts.get("callback_passthroughs"),
        "native-engine callback passthrough count",
    ) != len(passthroughs):
        raise StageBNativeRuntimeError(
            "native-engine callback passthrough count differs from its inventory"
        )
    return entry_rva, tuple(
        (
            _required_u32(
                _required_object(raw, f"native-engine callback ABI {index}").get("rva"),
                "callback ABI RVA",
            ),
            _required_count(
                _required_object(raw, f"native-engine callback ABI {index}").get(
                    "stack_cleanup_bytes"
                ),
                "callback ABI stack cleanup",
            ),
        )
        for index, raw in enumerate(callback_abis)
    ), callback_adapter_receipts, implementation_dispatch_receipt, (
        implementation_dispatches
    ), tuple(recovered_ranges)


def _validate_native_termination(value: Any) -> bool:
    if value is None:
        return False
    payload = _required_object(value, "native-engine termination import")
    _required_string(payload.get("dll"), "termination import DLL")
    symbol = payload.get("symbol")
    ordinal = payload.get("ordinal")
    if (symbol is None) == (ordinal is None):
        raise StageBNativeRuntimeError(
            "termination import must provide exactly one symbol or ordinal"
        )
    if symbol is not None:
        _required_string(symbol, "termination import symbol")
    else:
        _required_u32(ordinal, "termination import ordinal")
    _required_u32(payload.get("iat_va"), "termination import IAT VA")
    if (
        payload.get("transfer") != "tail_jump"
        or payload.get("argument_source") != "cdecl-stack-word-0-from-eax"
        or payload.get("required_disposition") != "terminates"
    ):
        raise StageBNativeRuntimeError(
            "native-engine termination import policy is unsupported"
        )
    return True


def _diagnostic_writer_iat_rvas(
    native_plan: dict[str, Any],
) -> tuple[int, int, int] | None:
    required = ("CreateFileA", "WriteFile", "CloseHandle")
    found: dict[str, int] = {}
    for site_index, raw_site in enumerate(
        _required_list(native_plan.get("external_sites"), "native-engine external sites")
    ):
        site = _required_object(raw_site, f"native-engine external site {site_index}")
        imported = site.get("import")
        if not isinstance(imported, dict):
            continue
        if str(imported.get("dll", "")).lower() != "kernel32.dll":
            continue
        symbol = imported.get("symbol")
        if symbol not in required:
            continue
        iat_va = _required_u32(site.get("iat_va"), f"{symbol} IAT VA")
        previous = found.setdefault(symbol, iat_va)
        if previous != iat_va:
            raise StageBNativeRuntimeError(
                f"native-engine external sites disagree on the {symbol} IAT VA"
            )
    if any(symbol not in found for symbol in required):
        return None
    image_policy = _required_object(
        native_plan.get("image_base_policy"), "native-engine image-base policy"
    )
    if image_policy.get("kind") != "fixed":
        return None
    image_base = _required_u32(
        image_policy.get("image_base"), "native-engine fixed image base"
    )
    if any(found[symbol] < image_base for symbol in required):
        raise StageBNativeRuntimeError(
            "diagnostic writer IAT VA precedes the fixed image base"
        )
    return (
        found["CreateFileA"] - image_base,
        found["WriteFile"] - image_base,
        found["CloseHandle"] - image_base,
    )


def _external_range_rules(
    native_plan: dict[str, Any],
    profile_path: Path | None,
    *,
    candidate_mode: str,
) -> tuple[
    tuple[NativeExternalRangeRule, ...],
    tuple[int, ...],
    tuple[dict[str, Any], ...],
]:
    if profile_path is None:
        profile_set = None
        selected_contracts = {}
    else:
        try:
            profile_set = load_machine_import_profile_set([profile_path])
        except MachineImportProfileError as exc:
            raise StageBNativeRuntimeError(str(exc)) from exc
        selected_contracts = profile_set.by_identity()

    bindings: dict[tuple[str, str, str | int], dict[str, Any]] = {}
    for binding_index, raw_binding in enumerate(
        _required_list(native_plan.get("import_bindings", []), "native-engine import bindings")
    ):
        binding = _required_object(
            raw_binding, f"native-engine import binding {binding_index}"
        )
        dll = _required_string(binding.get("dll"), "import binding DLL").lower()
        symbol = binding.get("symbol")
        ordinal = binding.get("ordinal")
        identity = (
            dll,
            "symbol" if isinstance(symbol, str) else "ordinal",
            symbol if isinstance(symbol, str) else ordinal,
        )
        _required_u32(binding.get("iat_va"), "import binding IAT VA")
        iat_rva = _required_u32(binding.get("iat_rva"), "import binding IAT RVA")
        if iat_rva == 0 or identity in bindings:
            raise StageBNativeRuntimeError(
                "native-engine import bindings are duplicate or use RVA zero"
            )
        bindings[identity] = dict(binding)

    expanded_sites: list[
        tuple[dict[str, Any], int | None, dict[str, Any], int, str]
    ] = []
    authorized_sites: set[int] = set()
    blocked_sites: list[dict[str, Any]] = []
    dispatch_receipt = _required_object(
        native_plan.get("implementation_dispatch_receipt"),
        "native-engine implementation dispatch receipt",
    )
    dispatch_reachability = _required_object(
        dispatch_receipt.get("reachability"),
        "native-engine implementation reachability",
    )
    strict_closed_scope = (
        candidate_mode == STATIC_CLOSED_CANDIDATE_MODE
        and dispatch_reachability.get("status") == "complete"
    )

    def block_site(
        *, site_index: int, site: Mapping[str, Any], category: str, detail: str
    ) -> None:
        if strict_closed_scope:
            raise StageBNativeRuntimeError(detail)
        instruction_rva = _required_u32(
            site.get("instruction_rva"),
            f"native-engine external site {site_index} instruction RVA",
        )
        blocked_sites.append({
            "category": category,
            "severity": "diagnostic",
            "site_index": site_index,
            "instruction_rva": instruction_rva,
            "detail": detail,
            "runtime_disposition": "fail-closed-as-unimplemented-before-call",
        })

    for site_index, raw_site in enumerate(
        _required_list(native_plan.get("external_sites"), "native-engine external sites")
    ):
        site = _required_object(raw_site, f"native-engine external site {site_index}")
        is_external = (
            isinstance(site.get("import"), Mapping)
            or isinstance(site.get("external_protocol"), Mapping)
        )
        if not is_external:
            block_site(
                site_index=site_index,
                site=site,
                category="uncontracted_dynamic_external_target",
                detail=(
                    f"native-engine external site {site_index} has no checked "
                    "import, interface, or callable target identity"
                ),
            )
            continue
        raw_contract = site.get("checked_external_contract")
        if not isinstance(raw_contract, Mapping):
            required = site.get("checked_external_contract_required", False)
            if not isinstance(required, bool):
                raise StageBNativeRuntimeError(
                    f"native-engine external site {site_index} has invalid contract policy"
                )
            if required or isinstance(site.get("external_protocol"), Mapping):
                block_site(
                    site_index=site_index,
                    site=site,
                    category="checked_external_contract_missing",
                    detail=(
                        f"native-engine external site {site_index} has no checked "
                        "external contract"
                    ),
                )
                continue
            imported = site.get("import")
            if not isinstance(imported, Mapping) or profile_set is None:
                block_site(
                    site_index=site_index,
                    site=site,
                    category="external_profile_missing",
                    detail=(
                        f"legacy external site {site_index} has no selected exact profile"
                    ),
                )
                continue
            try:
                outer_identity = ExternalSiteIdentity.imported(
                    imported,
                    context=f"native-engine external site {site_index}",
                )
            except CheckedExternalSiteContractError as exc:
                raise StageBNativeRuntimeError(str(exc)) from exc
            profile_identity = MachineImportIdentity(
                dll=str(outer_identity.dll),
                kind="symbol" if outer_identity.symbol is not None else "ordinal",
                value=(
                    str(outer_identity.symbol)
                    if outer_identity.symbol is not None
                    else int(outer_identity.ordinal)
                ),
            )
            selected = selected_contracts.get(profile_identity)
            if selected is None:
                block_site(
                    site_index=site_index,
                    site=site,
                    category="external_profile_missing",
                    detail=(
                        f"legacy external site {site_index} has no selected exact profile"
                    ),
                )
                continue
            callback_effect = selected.contract.get("callback_effect")
            if (
                callback_effect not in {None, "none"}
                or selected.contract.get("world_effect") == "callbackRegistration"
            ):
                block_site(
                    site_index=site_index,
                    site=site,
                    category="callback_adapter_contract_missing",
                    detail=(
                        f"legacy external site {site_index} may register or invoke a "
                        "callback without a checked adapter"
                    ),
                )
                continue
            binding_identity = (
                profile_identity.dll,
                profile_identity.kind,
                profile_identity.value,
            )
            binding = bindings.get(binding_identity)
            if binding is None and site.get("site_kind") == "dynamic_target":
                raise StageBNativeRuntimeError(
                    f"legacy external site {site_index} has no exact import binding"
                )
            target_iat_rva = (
                _required_u32(binding.get("iat_rva"), "import binding IAT RVA")
                if site.get("site_kind") == "dynamic_target" and binding is not None
                else None
            )
            disposition = site.get("disposition")
            if disposition not in {"returns_here", "tail_jump"}:
                raise StageBNativeRuntimeError(
                    f"legacy external site {site_index} has invalid disposition"
                )
            expanded_sites.append((
                dict(site),
                target_iat_rva,
                dict(selected.contract),
                4 if disposition == "tail_jump" else 0,
                str(selected.contract.get("id")),
            ))
            authorized_sites.add(
                _required_u32(site.get("instruction_rva"), "external site RVA")
            )
            continue
        try:
            checked = parse_checked_external_site_contract(
                raw_contract,
                context=f"native-engine external site {site_index}",
            )
        except CheckedExternalSiteContractError as exc:
            raise StageBNativeRuntimeError(str(exc)) from exc

        imported_site = site.get("import")
        if isinstance(imported_site, Mapping):
            try:
                outer_identity = ExternalSiteIdentity.imported(
                    imported_site,
                    context=f"native-engine external site {site_index}",
                )
            except CheckedExternalSiteContractError as exc:
                raise StageBNativeRuntimeError(str(exc)) from exc
            if checked.identity != outer_identity:
                raise StageBNativeRuntimeError(
                    f"native-engine external site {site_index} identity differs from its checked contract"
                )

        target_iat_rva: int | None = None
        if checked.identity.kind == "import":
            profile_identity = MachineImportIdentity(
                dll=str(checked.identity.dll),
                kind="symbol" if checked.identity.symbol is not None else "ordinal",
                value=(
                    str(checked.identity.symbol)
                    if checked.identity.symbol is not None
                    else int(checked.identity.ordinal)
                ),
            )
            selected = selected_contracts.get(profile_identity)
            if selected is None:
                raise StageBNativeRuntimeError(
                    f"native-engine external site {site_index} has no selected exact profile"
                )
            try:
                require_profile_match(
                    checked,
                    profile_contract=selected.contract,
                    profile_id=selected.profile_id,
                    profile_sha256=selected.profile_sha256,
                    entry_key=selected.entry_key,
                    entry_index=selected.entry_index,
                    context=f"native-engine external site {site_index}",
                )
            except CheckedExternalSiteContractError as exc:
                raise StageBNativeRuntimeError(str(exc)) from exc
            binding_identity = (
                profile_identity.dll,
                profile_identity.kind,
                profile_identity.value,
            )
            binding = bindings.get(binding_identity)
            if binding is None and site.get("site_kind") == "dynamic_target":
                raise StageBNativeRuntimeError(
                    f"native-engine external site {site_index} has no exact import binding"
                )
            if site.get("site_kind") == "dynamic_target" and binding is not None:
                target_iat_rva = _required_u32(
                    binding.get("iat_rva"), "import binding IAT RVA"
                )
        expanded_sites.append((
            dict(site),
            target_iat_rva,
            checked.profile_effect_payload(),
            checked.argument_base_offset,
            checked.contract_id,
        ))
        authorized_sites.add(
            _required_u32(site.get("instruction_rva"), "external site RVA")
        )

    rules: list[NativeExternalRangeRule] = []
    for (
        site,
        target_iat_rva,
        contract,
        argument_base_offset,
        contract_id,
    ) in expanded_sites:
        instruction_rva = _required_u32(
            site.get("instruction_rva"), "external site instruction RVA"
        )
        argument_count = _required_count(
            contract.get("argument_words"),
            f"machine-call contract {contract_id} argument count",
        )
        if argument_count > 256:
            raise StageBNativeRuntimeError(
                f"machine-call contract {contract_id} has too many arguments"
            )
        disposition = site.get("disposition")
        if disposition not in {"returns_here", "tail_jump"}:
            raise StageBNativeRuntimeError(
                f"external site {instruction_rva:#x} has an unsupported disposition"
            )
        relations = contract.get("result_register_relations", [])
        if not isinstance(relations, list):
            raise StageBNativeRuntimeError(
                f"machine-call contract {contract_id} has invalid result relations"
            )
        for relation_index, raw_relation in enumerate(relations):
            relation = _required_object(
                raw_relation,
                f"machine-call contract {contract_id} result {relation_index}",
            )
            if relation.get("relation") != "dynamic_range_base":
                continue
            register = _required_string(
                relation.get("register"), "dynamic-range result register"
            ).lower()
            if register not in {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}:
                raise StageBNativeRuntimeError(
                    f"machine-call contract {contract_id} uses an unsupported result register"
                )
            size = _required_object(
                relation.get("size"), "dynamic-range result size"
            )
            kind = _required_string(size.get("kind"), "dynamic-range size kind")
            size_value = 0
            size_argument: int | None = None
            size_right_argument: int | None = None
            termination_unit_bytes = 0
            termination_zero_units = 0
            termination_max_units = 0
            if kind == "fixed":
                size_value = _required_count(
                    size.get("bytes"), "fixed dynamic-range size"
                )
            elif kind == "argument":
                size_argument = _required_count(
                    size.get("argument"), "dynamic-range size argument"
                )
                size_value = _required_count(
                    size.get("scale", 1), "dynamic-range size scale"
                )
            elif kind == "product":
                size_argument = _required_count(
                    size.get("left_argument"), "dynamic-range left size argument"
                )
                size_right_argument = _required_count(
                    size.get("right_argument"), "dynamic-range right size argument"
                )
            elif kind == "bounded_zero_run":
                termination_unit_bytes = _required_count(
                    size.get("unit_bytes"), "terminated range unit size"
                )
                termination_zero_units = _required_count(
                    size.get("zero_units"), "terminated range zero-run length"
                )
                termination_max_units = _required_count(
                    size.get("max_units"), "terminated range unit limit"
                )
                if (
                    termination_unit_bytes not in {1, 2, 4}
                    or termination_zero_units == 0
                    or termination_zero_units > 16
                    or termination_max_units < termination_zero_units
                    or termination_max_units > 1048576
                ):
                    raise StageBNativeRuntimeError(
                        f"machine-call contract {contract_id} has an invalid terminated range size"
                    )
            else:
                raise StageBNativeRuntimeError(
                    f"machine-call contract {contract_id} has unsupported range size {kind!r}"
                )
            for size_index in (size_argument, size_right_argument):
                if size_index is not None and size_index >= argument_count:
                    raise StageBNativeRuntimeError(
                        f"machine-call contract {contract_id} range size argument is out of bounds"
                    )
            minimum_size = _required_count(
                relation.get("minimum_size", 0), "dynamic-range minimum size"
            )
            nullable = relation.get("nullable")
            if not isinstance(nullable, bool):
                raise StageBNativeRuntimeError(
                    f"machine-call contract {contract_id} has invalid nullability"
                )
            rules.append(
                NativeExternalRangeRule(
                    instruction_rva=instruction_rva,
                    target_iat_rva=target_iat_rva,
                    action="add_result_range",
                    argument_base_offset=argument_base_offset,
                    argument_count=argument_count,
                    register=register,
                    argument=None,
                    size_kind=kind,
                    size_value=size_value,
                    size_argument=size_argument,
                    size_right_argument=size_right_argument,
                    minimum_size=minimum_size,
                    nullable=nullable,
                    termination_unit_bytes=termination_unit_bytes,
                    termination_zero_units=termination_zero_units,
                    termination_max_units=termination_max_units,
                    pointee_offset=0,
                    max_elements=0,
                    element_unit_bytes=0,
                    element_max_units=0,
                    contract_id=contract_id,
                )
            )
            required_words = relation.get("required_words", [])
            if not isinstance(required_words, list):
                raise StageBNativeRuntimeError(
                    f"machine-call contract {contract_id} has invalid required words"
                )
            for word_index, raw_word in enumerate(required_words):
                word = _required_object(
                    raw_word,
                    f"machine-call contract {contract_id} required word {word_index}",
                )
                shape = word.get("pointee_shape")
                if shape is None:
                    continue
                if word.get("relation") != "nullable_dynamic_pointer":
                    raise StageBNativeRuntimeError(
                        f"machine-call contract {contract_id} gives a shape to a non-pointer word"
                    )
                shape = _required_object(shape, "dynamic-pointer pointee shape")
                if shape.get("kind") != "null_terminated_pointer_vector":
                    raise StageBNativeRuntimeError(
                        f"machine-call contract {contract_id} has an unsupported pointee shape"
                    )
                pointee_offset = _required_count(
                    word.get("offset"), "dynamic-pointer word offset"
                )
                if pointee_offset % 4 != 0 or pointee_offset + 4 > minimum_size:
                    raise StageBNativeRuntimeError(
                        f"machine-call contract {contract_id} has an out-of-range pointer word"
                    )
                max_elements = _required_count(
                    shape.get("max_elements"), "pointer-vector element limit"
                )
                if max_elements == 0 or max_elements > 65536:
                    raise StageBNativeRuntimeError(
                        f"machine-call contract {contract_id} has an invalid pointer-vector limit"
                    )
                element = _required_object(
                    shape.get("element"), "pointer-vector element shape"
                )
                if element.get("kind") != "bounded_terminated":
                    raise StageBNativeRuntimeError(
                        f"machine-call contract {contract_id} has an unsupported vector element shape"
                    )
                element_unit_bytes = _required_count(
                    element.get("unit_bytes"), "terminated-element unit size"
                )
                if element_unit_bytes not in {1, 2, 4}:
                    raise StageBNativeRuntimeError(
                        f"machine-call contract {contract_id} has an unsupported element unit"
                    )
                sentinel = element.get("sentinel")
                if sentinel != [0] * element_unit_bytes:
                    raise StageBNativeRuntimeError(
                        f"machine-call contract {contract_id} has an unsupported element sentinel"
                    )
                element_max_units = _required_count(
                    element.get("max_units"), "terminated-element unit limit"
                )
                if element_max_units == 0 or element_max_units > 1048576:
                    raise StageBNativeRuntimeError(
                        f"machine-call contract {contract_id} has an invalid element unit limit"
                    )
                rules.append(
                    NativeExternalRangeRule(
                        instruction_rva=instruction_rva,
                        target_iat_rva=target_iat_rva,
                        action="add_result_pointee_ranges",
                        argument_base_offset=argument_base_offset,
                        argument_count=argument_count,
                        register=register,
                        argument=None,
                        size_kind=None,
                        size_value=0,
                        size_argument=None,
                        size_right_argument=None,
                        minimum_size=0,
                        nullable=True,
                        termination_unit_bytes=0,
                        termination_zero_units=0,
                        termination_max_units=0,
                        pointee_offset=pointee_offset,
                        max_elements=max_elements,
                        element_unit_bytes=element_unit_bytes,
                        element_max_units=element_max_units,
                        contract_id=contract_id,
                    )
                )
        out_pointer_relations = contract.get("out_pointer_relations", [])
        if not isinstance(out_pointer_relations, list):
            raise StageBNativeRuntimeError(
                f"machine-call contract {contract_id} has invalid out-pointer relations"
            )
        for out_index, raw_out in enumerate(out_pointer_relations):
            out_relation = _required_object(
                raw_out,
                f"machine-call contract {contract_id} out pointer {out_index}",
            )
            if out_relation.get("relation") != "nullable_dynamic_pointer":
                raise StageBNativeRuntimeError(
                    f"machine-call contract {contract_id} has an unsupported out-pointer relation"
                )
            argument = _required_count(
                out_relation.get("argument"), "out-pointer argument"
            )
            if argument >= argument_count:
                raise StageBNativeRuntimeError(
                    f"machine-call contract {contract_id} out-pointer argument is out of bounds"
                )
            pointee_offset = _required_count(
                out_relation.get("offset", 0), "out-pointer offset"
            )
            shape = _required_object(
                out_relation.get("pointee_shape"), "out-pointer pointee shape"
            )
            if shape.get("kind") != "null_terminated_pointer_vector":
                raise StageBNativeRuntimeError(
                    f"machine-call contract {contract_id} has an unsupported out-pointer shape"
                )
            max_elements = _required_count(
                shape.get("max_elements"), "out-pointer vector limit"
            )
            if max_elements == 0 or max_elements > 65536:
                raise StageBNativeRuntimeError(
                    f"machine-call contract {contract_id} has an invalid out-pointer vector limit"
                )
            element = _required_object(
                shape.get("element"), "out-pointer vector element shape"
            )
            if element.get("kind") != "bounded_terminated":
                raise StageBNativeRuntimeError(
                    f"machine-call contract {contract_id} has an unsupported out-pointer element shape"
                )
            element_unit_bytes = _required_count(
                element.get("unit_bytes"), "out-pointer element unit size"
            )
            sentinel = element.get("sentinel")
            if (
                element_unit_bytes not in {1, 2, 4}
                or sentinel != [0] * element_unit_bytes
            ):
                raise StageBNativeRuntimeError(
                    f"machine-call contract {contract_id} has an unsupported out-pointer sentinel"
                )
            element_max_units = _required_count(
                element.get("max_units"), "out-pointer element unit limit"
            )
            if element_max_units == 0 or element_max_units > 1048576:
                raise StageBNativeRuntimeError(
                    f"machine-call contract {contract_id} has an invalid out-pointer element limit"
                )
            rules.append(
                NativeExternalRangeRule(
                    instruction_rva=instruction_rva,
                    target_iat_rva=target_iat_rva,
                    action="add_argument_pointee_ranges",
                    argument_base_offset=argument_base_offset,
                    argument_count=argument_count,
                    register=None,
                    argument=argument,
                    size_kind=None,
                    size_value=0,
                    size_argument=None,
                    size_right_argument=None,
                    minimum_size=0,
                    nullable=True,
                    termination_unit_bytes=0,
                    termination_zero_units=0,
                    termination_max_units=0,
                    pointee_offset=pointee_offset,
                    max_elements=max_elements,
                    element_unit_bytes=element_unit_bytes,
                    element_max_units=element_max_units,
                    contract_id=contract_id,
                )
            )
        out_interface_relations = contract.get("out_interface_relations", [])
        if not isinstance(out_interface_relations, list):
            raise StageBNativeRuntimeError(
                f"machine-call contract {contract_id} has invalid out-interface relations"
            )
        for out_index, raw_out in enumerate(out_interface_relations):
            out_relation = _required_object(
                raw_out,
                f"machine-call contract {contract_id} out interface {out_index}",
            )
            argument = _required_count(
                out_relation.get("argument_index"), "out-interface argument"
            )
            if argument >= argument_count:
                raise StageBNativeRuntimeError(
                    f"machine-call contract {contract_id} out-interface argument is out of bounds"
                )
            pointee_offset = _required_count(
                out_relation.get("offset", 0), "out-interface offset"
            )
            object_size = _required_count(
                out_relation.get("object_size"), "out-interface object size"
            )
            vtable_size = _required_count(
                out_relation.get("vtable_size"), "out-interface vtable size"
            )
            nullable = out_relation.get("nullable")
            if (
                out_relation.get("write_width") != 4
                or object_size < 4
                or vtable_size < 4
                or vtable_size % 4 != 0
                or not isinstance(nullable, bool)
                or out_relation.get("success_condition")
                != "hresult_succeeded_eax"
            ):
                raise StageBNativeRuntimeError(
                    f"machine-call contract {contract_id} has an invalid out-interface shape"
                )
            rules.append(
                NativeExternalRangeRule(
                    instruction_rva=instruction_rva,
                    target_iat_rva=target_iat_rva,
                    action="add_argument_interface_ranges",
                    argument_base_offset=argument_base_offset,
                    argument_count=argument_count,
                    register=None,
                    argument=argument,
                    size_kind="fixed",
                    size_value=vtable_size,
                    size_argument=None,
                    size_right_argument=None,
                    minimum_size=object_size,
                    nullable=nullable,
                    termination_unit_bytes=0,
                    termination_zero_units=0,
                    termination_max_units=0,
                    pointee_offset=pointee_offset,
                    max_elements=0,
                    element_unit_bytes=0,
                    element_max_units=0,
                    contract_id=contract_id,
                )
            )
        if contract.get("world_effect") == "dynamicRangeRelease":
            argument = _required_count(
                contract.get("world_effect_argument"),
                "dynamic-range release argument",
            )
            if argument >= argument_count:
                raise StageBNativeRuntimeError(
                    f"machine-call contract {contract_id} release argument is out of bounds"
                )
            rules.append(
                NativeExternalRangeRule(
                    instruction_rva=instruction_rva,
                    target_iat_rva=target_iat_rva,
                    action="release_argument_range",
                    argument_base_offset=argument_base_offset,
                    argument_count=argument_count,
                    register=None,
                    argument=argument,
                    size_kind=None,
                    size_value=0,
                    size_argument=None,
                    size_right_argument=None,
                    minimum_size=0,
                    nullable=True,
                    termination_unit_bytes=0,
                    termination_zero_units=0,
                    termination_max_units=0,
                    pointee_offset=0,
                    max_elements=0,
                    element_unit_bytes=0,
                    element_max_units=0,
                    contract_id=contract_id,
                )
            )
    sorted_rules = tuple(
        sorted(
            rules,
            key=lambda item: (
                item.instruction_rva,
                item.target_iat_rva or 0,
                {
                    "add_result_range": 0,
                    "add_result_pointee_ranges": 1,
                    "add_argument_pointee_ranges": 2,
                    "add_argument_interface_ranges": 3,
                    "release_argument_range": 4,
                }[item.action],
                item.contract_id,
            ),
        )
    )
    return (
        sorted_rules,
        tuple(sorted(authorized_sites)),
        tuple(sorted(
            blocked_sites,
            key=lambda item: (
                int(item["instruction_rva"]),
                str(item["category"]),
            ),
        )),
    )


def _native_runtime_header() -> str:
    return r'''#ifndef STAGE_B_NATIVE_RUNTIME_H
#define STAGE_B_NATIVE_RUNTIME_H

#include "state-machine-interpreter.h"

typedef enum stage_b_native_terminal_kind {
  STAGE_B_NATIVE_TERMINAL_RETURNED = 0,
  STAGE_B_NATIVE_TERMINAL_UNIMPLEMENTED = 1,
  STAGE_B_NATIVE_TERMINAL_DIVIDE_ERROR = 2,
  STAGE_B_NATIVE_TERMINAL_MEMORY_FAULT = 3,
  STAGE_B_NATIVE_TERMINAL_EXTERNAL_FAULT = 4,
  STAGE_B_NATIVE_TERMINAL_UNDEFINED_VALUE = 5,
  STAGE_B_NATIVE_TERMINAL_INVALID_IMAGE = 6,
  STAGE_B_NATIVE_TERMINAL_CONCURRENT_ENTRY = 7
} stage_b_native_terminal_kind;

extern const char stage_b_native_interpreter_manifest_sha256[65];
extern const char stage_b_native_engine_manifest_sha256[65];
extern const char stage_b_native_state_machine_sha256[65];
extern volatile stage_b_native_terminal_kind stage_b_native_terminal_status;
extern volatile stage_b_call_status stage_b_native_terminal_call_status;
extern stage_b_machine_state stage_b_native_terminal_state;
extern stage_b_runtime stage_b_native_runtime_instance;
void stage_b_native_terminate(stage_b_native_terminal_kind status)
    __attribute__((noreturn));

stage_b_call_status stage_b_native_runtime_run_at_rva(
    uint32_t entry_rva, const stage_b_machine_state *input,
    stage_b_machine_state *output);
stage_b_call_status stage_b_native_runtime_run_nested_callback(
    uint32_t callback_rva, uint32_t stack_cleanup_bytes,
    const stage_b_machine_state *input, stage_b_machine_state *output);
stage_b_call_status stage_b_native_runtime_run_captured(
    const stage_b_machine_state *captured, stage_b_machine_state *output);
void stage_b_native_runtime_coordinate(
    const stage_b_machine_state *captured) __attribute__((noreturn));
#ifdef STAGE_B_NATIVE_DIAGNOSTIC_FAILURE_TRAP
void stage_b_native_runtime_write_diagnostic(
    uint32_t status, uint32_t failure_rva,
    const stage_b_machine_state *state);
#endif

#endif
'''


def _native_runtime_source(plan: NativeRuntimePlan) -> str:
    transfer_rows = "\n".join(
        f"  0x{rva:08x}U," for rva in plan.transfer_rvas
    )
    implementation_rows = "\n".join(
        "  {{ 0x{rva:08x}U, {class_code}U, {replacement}, {cluster} }},".format(
            rva=dispatch.rva,
            class_code=dispatch.class_code,
            replacement=(
                "0"
                if dispatch.replacement_id is None
                else json.dumps(dispatch.replacement_id, ensure_ascii=True)
            ),
            cluster=(
                "0"
                if dispatch.cluster_id is None
                else json.dumps(dispatch.cluster_id, ensure_ascii=True)
            ),
        )
        for dispatch in plan.implementation_dispatches
    )
    portable_dispatch_count = sum(
        dispatch.implementation_class == "selected_portable_component"
        for dispatch in plan.implementation_dispatches
    )
    recovered_data_rows = "\n".join(
        f"  {{ 0x{start:08x}U, 0x{end:08x}U }},"
        for start, end in plan.recovered_executable_data_ranges
    ) or "  { 0U, 0U },"
    callback_rows = "\n".join(
        f"  {{ 0x{rva:08x}U, {cleanup}U }},"
        for rva, cleanup in plan.callback_abis
    ) or "  { 0U, 0U },"
    undefined_rows = "\n".join(
        f"  {{ 0x{policy.slot:08x}U, {policy.policy_code}U, "
        f"{policy.input_location_code}U }},"
        for policy in plan.undefined_policies
    ) or "  { 0U, 2U, 0U },"
    register_codes = {
        name: index
        for index, name in enumerate(
            ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
        )
    }
    callable_resolver_rows: list[str] = []
    callable_route_rows: list[str] = []
    callable_argument_rows: list[str] = []
    callable_footprint_rows: list[str] = []
    if plan.callable_external_contract is not None:
        for resolver in plan.callable_external_contract.resolvers:
            callable_resolver_rows.append(
                "  {{ 0x{instruction:08x}U, {capability}U, {register}U, "
                "{nullable}U }},".format(
                    instruction=resolver.instruction_rva,
                    capability=resolver.capability_id,
                    register=register_codes[resolver.result_register],
                    nullable=1 if resolver.nullable else 0,
                )
            )
        argument_kind_codes = {"register": 0, "stack_word": 1, "constant": 2}
        access_codes = {"read": 0, "write": 1}
        for route in plan.callable_external_contract.routes:
            argument_offset = len(callable_argument_rows)
            for source in route.argument_sources:
                callable_argument_rows.append(
                    "  {{ {kind}U, {register}U, {value}U }},".format(
                        kind=argument_kind_codes[source.kind],
                        register=register_codes.get(source.register or "", 0),
                        value=(
                            source.offset
                            if source.kind == "stack_word"
                            else source.value
                            if source.kind == "constant"
                            else 0
                        ),
                    )
                )
            footprint_offset = len(callable_footprint_rows)
            for footprint in route.memory_footprints:
                callable_footprint_rows.append(
                    "  {{ {access}U, {base}U, 0x{offset:08x}U, "
                    "{size}U, {nullable}U }},".format(
                        access=access_codes[footprint.access],
                        base=footprint.base_argument,
                        offset=footprint.offset,
                        size=footprint.bytes,
                        nullable=1 if footprint.nullable else 0,
                    )
                )
            preserved_mask = sum(
                1 << register_codes[register]
                for register in route.preserved_registers
            )
            callable_route_rows.append(
                "  {{ 0x{source:08x}U, 0x{instruction:08x}U, {capability}U, "
                "{abi}U, {delta}U, 0x{preserved:02x}U, {argument_offset}U, "
                "{argument_count}U, {footprint_offset}U, {footprint_count}U }},".format(
                    source=route.source_rva,
                    instruction=route.instruction_rva,
                    capability=route.capability_id,
                    abi=route.abi_contract_id,
                    delta=route.stack_result_delta,
                    preserved=preserved_mask,
                    argument_offset=argument_offset,
                    argument_count=len(route.argument_sources),
                    footprint_offset=footprint_offset,
                    footprint_count=len(route.memory_footprints),
                )
            )
    callable_resolver_table = "\n".join(callable_resolver_rows) or (
        "  { 0U, 0U, 0U, 0U },"
    )
    callable_route_table = "\n".join(callable_route_rows) or (
        "  { 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U },"
    )
    callable_argument_table = "\n".join(callable_argument_rows) or (
        "  { 0U, 0U, 0U },"
    )
    callable_footprint_table = "\n".join(callable_footprint_rows) or (
        "  { 0U, 0U, 0U, 0U, 0U },"
    )
    callable_binding_count = len(callable_resolver_rows)
    action_codes = {
        "add_result_range": 1,
        "release_argument_range": 2,
        "add_result_pointee_ranges": 3,
        "add_argument_pointee_ranges": 4,
        "add_argument_interface_ranges": 5,
    }
    size_codes = {
        None: 0,
        "fixed": 1,
        "argument": 2,
        "product": 3,
        "bounded_zero_run": 4,
    }
    diagnostic_iat_rvas = plan.diagnostic_writer_iat_rvas or (0, 0, 0)
    diagnostic_writer_available = 1 if plan.diagnostic_writer_iat_rvas else 0
    authorized_external_site_rows = "\n".join(
        f"  0x{rva:08x}U," for rva in plan.authorized_external_site_rvas
    ) or "  0U,"
    external_range_rows = "\n".join(
        "  {{ 0x{rva:08x}U, 0x{target_iat_rva:08x}U, {action}U, {argument_base_offset}U, "
        "{argument_count}U, {register}U, {argument}U, "
        "{size_kind}U, {size_value}U, {size_argument}U, "
        "{size_right_argument}U, {minimum_size}U, {nullable}U, "
        "{termination_unit_bytes}U, {termination_zero_units}U, "
        "{termination_max_units}U, "
        "{pointee_offset}U, {max_elements}U, {element_unit_bytes}U, "
        "{element_max_units}U }},".format(
            rva=rule.instruction_rva,
            target_iat_rva=rule.target_iat_rva or 0,
            action=action_codes[rule.action],
            argument_base_offset=rule.argument_base_offset,
            argument_count=rule.argument_count,
            register=register_codes.get(rule.register or "", 0),
            argument=rule.argument or 0,
            size_kind=size_codes[rule.size_kind],
            size_value=rule.size_value,
            size_argument=rule.size_argument or 0,
            size_right_argument=rule.size_right_argument or 0,
            minimum_size=rule.minimum_size,
            nullable=1 if rule.nullable else 0,
            termination_unit_bytes=rule.termination_unit_bytes,
            termination_zero_units=rule.termination_zero_units,
            termination_max_units=rule.termination_max_units,
            pointee_offset=rule.pointee_offset,
            max_elements=rule.max_elements,
            element_unit_bytes=rule.element_unit_bytes,
            element_max_units=rule.element_max_units,
        )
        for rule in plan.external_range_rules
    ) or (
        "  { 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, "
        "0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U },"
    )
    x87_declaration = (
        r'''extern stage_b_call_status stage_b_native_execute_typed_x87_operation(
    stage_b_runtime *runtime, const stage_b_typed_x87_operation *program,
    const stage_b_machine_state *input, stage_b_machine_state *output);
'''
        if plan.has_typed_x87_handler
        else r'''extern stage_b_call_status stage_b_native_replay_checked_x87_command(
    stage_b_runtime *runtime, const stage_b_x87_replay_program *program,
    const stage_b_machine_state *input, stage_b_machine_state *output);
'''
        if plan.has_x87_replay_handler
        else ""
    )
    x87_initializer = (
        ",\n  .execute_typed_x87_operation = "
        "stage_b_native_execute_typed_x87_operation"
        if plan.has_typed_x87_handler
        else ",\n  .replay_checked_x87_command = "
        "stage_b_native_replay_checked_x87_command"
        if plan.has_x87_replay_handler
        else ""
    )
    return f'''#include "native-runtime.h"

#include <stdint.h>

#define STAGE_B_NATIVE_IMAGE_SCN_MEM_EXECUTE 0x20000000U
#define STAGE_B_NATIVE_MAX_PE_SECTIONS 96U
#define STAGE_B_NATIVE_MAX_EXTERNAL_RANGES 8192U
#define STAGE_B_NATIVE_MAX_EXTERNAL_LIFECYCLE_EVENTS 64U
#define STAGE_B_NATIVE_MAX_EXTERNAL_TRACE_EVENTS 128U
#define STAGE_B_NATIVE_MAX_TRANSFER_TRACE_EVENTS 1024U
#define STAGE_B_NATIVE_DIAGNOSTIC_WRITER_AVAILABLE {diagnostic_writer_available}U
#define STAGE_B_NATIVE_DIAGNOSTIC_CREATE_FILE_IAT_RVA 0x{diagnostic_iat_rvas[0]:08x}U
#define STAGE_B_NATIVE_DIAGNOSTIC_WRITE_FILE_IAT_RVA 0x{diagnostic_iat_rvas[1]:08x}U
#define STAGE_B_NATIVE_DIAGNOSTIC_CLOSE_HANDLE_IAT_RVA 0x{diagnostic_iat_rvas[2]:08x}U

extern const unsigned char __ImageBase[];
volatile uint32_t stage_b_native_diagnostic_reason;
volatile uint32_t stage_b_native_diagnostic_value;
volatile uint32_t stage_b_native_diagnostic_aux;
volatile uint32_t stage_b_native_diagnostic_detail;
extern stage_b_call_status stage_b_dispatch_external_call(
    stage_b_runtime *runtime, const stage_b_call_event *event,
    const stage_b_machine_state *input, stage_b_machine_state *output);
extern const stage_b_region_override *stage_b_region_override_lookup(
    uint32_t entry_rva) __attribute__((weak));
extern const stage_b_region_override stage_b_region_overrides[]
    __attribute__((weak));
extern const uint32_t stage_b_region_override_count __attribute__((weak));
extern const uint32_t stage_b_program_transfer_count __attribute__((weak));
{x87_declaration}

_Static_assert(sizeof(uintptr_t) == 4U, "native runtime requires i686 pointers");

const char stage_b_native_interpreter_manifest_sha256[65] =
    "{plan.interpreter_manifest_sha256}";
const char stage_b_native_engine_manifest_sha256[65] =
    "{plan.native_engine_manifest_sha256}";
const char stage_b_native_state_machine_sha256[65] =
    "{plan.state_machine_sha256}";

volatile stage_b_native_terminal_kind stage_b_native_terminal_status =
    STAGE_B_NATIVE_TERMINAL_UNIMPLEMENTED;
volatile stage_b_call_status stage_b_native_terminal_call_status =
    STAGE_B_CALL_UNIMPLEMENTED;
stage_b_machine_state stage_b_native_terminal_state;

static const uint32_t stage_b_native_transfer_rvas[] = {{
{transfer_rows}
}};
static const uint32_t stage_b_native_transfer_count = {len(plan.transfer_rvas)}U;

typedef struct stage_b_native_implementation_dispatch {{
  uint32_t rva, implementation_class;
  const char *replacement_id, *cluster_id;
}} stage_b_native_implementation_dispatch;
static const stage_b_native_implementation_dispatch
stage_b_native_implementation_dispatches[] = {{
{implementation_rows}
}};
static const uint32_t stage_b_native_implementation_dispatch_count =
    {len(plan.implementation_dispatches)}U;
static const uint32_t stage_b_native_portable_dispatch_count =
    {portable_dispatch_count}U;

typedef struct stage_b_native_noncode_range {{
  uint32_t rva_start, rva_end;
}} stage_b_native_noncode_range;
static const stage_b_native_noncode_range stage_b_native_noncode_ranges[] = {{
{recovered_data_rows}
}};
static const uint32_t stage_b_native_noncode_range_count = {len(plan.recovered_executable_data_ranges)}U;

typedef struct stage_b_native_callback_abi {{
  uint32_t rva, stack_cleanup_bytes;
}} stage_b_native_callback_abi;
static const stage_b_native_callback_abi stage_b_native_callback_abis[] = {{
{callback_rows}
}};
static const uint32_t stage_b_native_callback_abi_count = {len(plan.callback_abis)}U;

typedef struct stage_b_native_undefined_policy {{
  uint32_t slot, policy, input_location;
}} stage_b_native_undefined_policy;
static const stage_b_native_undefined_policy stage_b_native_undefined_policies[] = {{
{undefined_rows}
}};
static const uint32_t stage_b_native_undefined_policy_count = {len(plan.undefined_policies)}U;

static const uint32_t stage_b_native_authorized_external_sites[] = {{
{authorized_external_site_rows}
}};
static const uint32_t stage_b_native_authorized_external_site_count = {len(plan.authorized_external_site_rvas)}U;

typedef struct stage_b_native_external_range_rule {{
  uint32_t instruction_rva, target_iat_rva, action;
  uint32_t argument_base_offset, argument_count;
  uint32_t register_index, argument;
  uint32_t size_kind, size_value, size_argument, size_right_argument;
  uint32_t minimum_size, nullable;
  uint32_t termination_unit_bytes, termination_zero_units, termination_max_units;
  uint32_t pointee_offset, max_elements, element_unit_bytes, element_max_units;
}} stage_b_native_external_range_rule;
static const stage_b_native_external_range_rule stage_b_native_external_range_rules[] = {{
{external_range_rows}
}};
static const uint32_t stage_b_native_external_range_rule_count = {len(plan.external_range_rules)}U;

typedef struct stage_b_native_callable_resolver {{
  uint32_t instruction_rva, capability_id, result_register, nullable;
}} stage_b_native_callable_resolver;
static const stage_b_native_callable_resolver stage_b_native_callable_resolvers[] = {{
{callable_resolver_table}
}};
static const uint32_t stage_b_native_callable_resolver_count = {len(callable_resolver_rows)}U;

typedef struct stage_b_native_callable_argument {{
  uint32_t kind, register_index, value;
}} stage_b_native_callable_argument;
static const stage_b_native_callable_argument stage_b_native_callable_arguments[] = {{
{callable_argument_table}
}};
static const uint32_t stage_b_native_callable_argument_count = {len(callable_argument_rows)}U;

typedef struct stage_b_native_callable_footprint {{
  uint32_t access, base_argument, offset, size, nullable;
}} stage_b_native_callable_footprint;
static const stage_b_native_callable_footprint stage_b_native_callable_footprints[] = {{
{callable_footprint_table}
}};
static const uint32_t stage_b_native_callable_footprint_count = {len(callable_footprint_rows)}U;

typedef struct stage_b_native_callable_route {{
  uint32_t source_rva, instruction_rva, capability_id, abi_contract_id;
  uint32_t stack_result_delta, preserved_register_mask;
  uint32_t argument_offset, argument_count;
  uint32_t footprint_offset, footprint_count;
}} stage_b_native_callable_route;
static const stage_b_native_callable_route stage_b_native_callable_routes[] = {{
{callable_route_table}
}};
static const uint32_t stage_b_native_callable_route_count = {len(callable_route_rows)}U;

typedef struct stage_b_native_callable_binding {{
  uint32_t capability_id, target_word, bound;
}} stage_b_native_callable_binding;

typedef struct stage_b_native_external_range {{
  uint32_t start, size, producer_rva, producer_action, generation;
}} stage_b_native_external_range;

typedef struct stage_b_native_external_lifecycle_event {{
  uint32_t sequence, operation, status, instruction_rva;
  uint32_t start, size, producer_rva, producer_action, generation;
}} stage_b_native_external_lifecycle_event;

typedef struct stage_b_native_external_trace_event {{
  uint32_t sequence, phase, instruction_rva, target_rva, target_iat_rva;
  uint32_t kind, status, eax, esp, eflags;
}} stage_b_native_external_trace_event;

typedef struct stage_b_native_transfer_trace_event {{
  uint32_t sequence, rva, df, esp;
}} stage_b_native_transfer_trace_event;

typedef struct stage_b_native_context {{
  uint32_t image_base;
  uint32_t image_size;
  uint32_t headers_size;
  uint32_t section_table;
  uint32_t section_count;
  uint32_t stack_low;
  uint32_t stack_high;
  volatile uint32_t active;
  uint32_t initialized;
  uint32_t process_world_initialized;
  uint32_t owner_fs_base;
  uint32_t nested_depth;
  uint32_t undefined_fault;
  uint32_t undefined_fault_slot;
  uint32_t undefined_fault_rva;
  uint32_t last_undefined_fault;
  stage_b_native_external_range external_ranges[STAGE_B_NATIVE_MAX_EXTERNAL_RANGES];
  uint32_t external_range_count;
  stage_b_native_external_lifecycle_event external_lifecycle_events[
      STAGE_B_NATIVE_MAX_EXTERNAL_LIFECYCLE_EVENTS];
  uint32_t external_lifecycle_count;
  uint32_t external_lifecycle_next;
  uint32_t external_lifecycle_sequence;
  stage_b_native_external_trace_event external_trace_events[
      STAGE_B_NATIVE_MAX_EXTERNAL_TRACE_EVENTS];
  uint32_t external_trace_count;
  uint32_t external_trace_next;
  uint32_t external_trace_sequence;
  stage_b_native_transfer_trace_event transfer_trace_events[
      STAGE_B_NATIVE_MAX_TRANSFER_TRACE_EVENTS];
  uint32_t transfer_trace_count;
  uint32_t transfer_trace_next;
  uint32_t transfer_trace_sequence;
  stage_b_native_callable_binding callable_bindings[{max(1, callable_binding_count)}U];
}} stage_b_native_context;

#define STAGE_B_NATIVE_THREAD_ENVIRONMENT_BYTES 0x1000U

static stage_b_native_context stage_b_native_context_value;

static uint16_t stage_b_native_u16(uint32_t address) {{
  const volatile uint8_t *p = (const volatile uint8_t *)(uintptr_t)address;
  return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}}

static uint32_t stage_b_native_u32(uint32_t address) {{
  const volatile uint8_t *p = (const volatile uint8_t *)(uintptr_t)address;
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
      ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}}

static uint32_t stage_b_native_range_end(
    uint32_t start, uint32_t width, uint32_t *end) {{
  if (width == 0U || start > 0xffffffffU - width) return 0U;
  *end = start + width;
  return 1U;
}}

static uint32_t stage_b_native_inside(
    uint32_t start, uint32_t end, uint32_t region_start, uint32_t region_size) {{
  uint32_t region_end;
  if (region_size == 0U ||
      !stage_b_native_range_end(region_start, region_size, &region_end))
    return 0U;
  return start >= region_start && end <= region_end;
}}

static uint32_t stage_b_native_inside_external_range(
    const stage_b_native_context *context, uint32_t start, uint32_t end) {{
  uint32_t i;
  for (i = 0U; i < context->external_range_count; ++i)
    if (stage_b_native_inside(
            start, end, context->external_ranges[i].start,
            context->external_ranges[i].size))
      return 1U;
  return 0U;
}}

static void stage_b_native_diagnose_external_range(
    const stage_b_native_context *context, uint32_t address) {{
  uint32_t i, nearest_start = 0U, nearest_end = 0U, has_preceding = 0U;
  if (context == 0) return;
  for (i = 0U; i < context->external_range_count; ++i) {{
    uint32_t start = context->external_ranges[i].start;
    uint32_t end;
    if (!stage_b_native_range_end(
            start, context->external_ranges[i].size, &end))
      continue;
    if ((start <= address &&
         (has_preceding == 0U || start > nearest_start)) ||
        (start > address && has_preceding == 0U &&
         (nearest_start == 0U || start < nearest_start))) {{
      nearest_start = start;
      nearest_end = end;
      has_preceding = start <= address;
    }}
  }}
  stage_b_native_diagnostic_aux = nearest_start;
  stage_b_native_diagnostic_detail = nearest_end;
}}

#ifdef STAGE_B_NATIVE_DIAGNOSTIC_FAILURE_TRAP
typedef uint32_t (__attribute__((stdcall)) *stage_b_native_create_file_a_fn)(
    const char *, uint32_t, uint32_t, void *, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__attribute__((stdcall)) *stage_b_native_write_file_fn)(
    uint32_t, const void *, uint32_t, uint32_t *, void *);
typedef uint32_t (__attribute__((stdcall)) *stage_b_native_close_handle_fn)(
    uint32_t);

typedef struct stage_b_native_diagnostic_header {{
  uint32_t magic, version, status, failure_rva;
  uint32_t reason, value, aux, detail;
  uint32_t external_range_count, external_lifecycle_count;
  uint32_t external_lifecycle_next, external_lifecycle_sequence;
  uint32_t external_trace_count, external_trace_next, external_trace_sequence;
  uint32_t transfer_trace_count, transfer_trace_next, transfer_trace_sequence;
  uint32_t eax, ebx, ecx, edx, esi, edi, ebp, esp, eflags, fs_base;
  uint32_t stack_word_count;
  uint32_t stack_words[16];
}} stage_b_native_diagnostic_header;

static uint32_t stage_b_native_diagnostic_iat_target(uint32_t iat_rva) {{
  const stage_b_native_context *context = &stage_b_native_context_value;
  if (iat_rva > context->image_size || context->image_size - iat_rva < 4U ||
      context->image_base > 0xffffffffU - iat_rva)
    return 0U;
  return stage_b_native_u32(context->image_base + iat_rva);
}}

static uint32_t stage_b_native_diagnostic_write(
    stage_b_native_write_file_fn write_file, uint32_t handle,
    const void *data, uint32_t size) {{
  uint32_t written = 0U;
  return write_file != 0 &&
      write_file(handle, data, size, &written, 0) != 0U && written == size;
}}

void stage_b_native_runtime_write_diagnostic(
    uint32_t status, uint32_t failure_rva,
    const stage_b_machine_state *state) {{
  const stage_b_native_context *context = &stage_b_native_context_value;
  stage_b_native_create_file_a_fn create_file;
  stage_b_native_write_file_fn write_file;
  stage_b_native_close_handle_fn close_handle;
  stage_b_native_diagnostic_header header;
  uint32_t handle, range_bytes, lifecycle_bytes, external_trace_bytes;
  uint32_t transfer_trace_bytes;
  if (STAGE_B_NATIVE_DIAGNOSTIC_WRITER_AVAILABLE == 0U) return;
  create_file = (stage_b_native_create_file_a_fn)(uintptr_t)
      stage_b_native_diagnostic_iat_target(
          STAGE_B_NATIVE_DIAGNOSTIC_CREATE_FILE_IAT_RVA);
  write_file = (stage_b_native_write_file_fn)(uintptr_t)
      stage_b_native_diagnostic_iat_target(
          STAGE_B_NATIVE_DIAGNOSTIC_WRITE_FILE_IAT_RVA);
  close_handle = (stage_b_native_close_handle_fn)(uintptr_t)
      stage_b_native_diagnostic_iat_target(
          STAGE_B_NATIVE_DIAGNOSTIC_CLOSE_HANDLE_IAT_RVA);
  if (create_file == 0 || write_file == 0 || close_handle == 0) return;
  handle = create_file(
      "spaghetti-extractor-diagnostic.bin", 0x40000000U, 0U, 0,
      2U, 0x00000080U, 0U);
  if (handle == 0U || handle == 0xffffffffU) return;
  header.magic = 0x31444553U;
  header.version = 4U;
  header.status = status;
  header.failure_rva = failure_rva;
  header.reason = stage_b_native_diagnostic_reason;
  header.value = stage_b_native_diagnostic_value;
  header.aux = stage_b_native_diagnostic_aux;
  header.detail = stage_b_native_diagnostic_detail;
  header.external_range_count = context->external_range_count;
  header.external_lifecycle_count = context->external_lifecycle_count;
  header.external_lifecycle_next = context->external_lifecycle_next;
  header.external_lifecycle_sequence = context->external_lifecycle_sequence;
  header.external_trace_count = context->external_trace_count;
  header.external_trace_next = context->external_trace_next;
  header.external_trace_sequence = context->external_trace_sequence;
  header.transfer_trace_count = context->transfer_trace_count;
  header.transfer_trace_next = context->transfer_trace_next;
  header.transfer_trace_sequence = context->transfer_trace_sequence;
  header.eax = state != 0 ? state->eax : 0U;
  header.ebx = state != 0 ? state->ebx : 0U;
  header.ecx = state != 0 ? state->ecx : 0U;
  header.edx = state != 0 ? state->edx : 0U;
  header.esi = state != 0 ? state->esi : 0U;
  header.edi = state != 0 ? state->edi : 0U;
  header.ebp = state != 0 ? state->ebp : 0U;
  header.esp = state != 0 ? state->esp : 0U;
  header.eflags = state != 0 ? state->eflags : 0U;
  header.fs_base = state != 0 ? state->fs_base : 0U;
  header.stack_word_count = 0U;
  if (state != 0) {{
    uint32_t i;
    for (i = 0U; i < 16U; ++i) {{
      uint32_t offset = i * 4U;
      uint32_t address, end;
      if (state->esp > 0xffffffffU - offset) break;
      address = state->esp + offset;
      if (!stage_b_native_range_end(address, 4U, &end) ||
          address < context->stack_low || end > context->stack_high)
        break;
      header.stack_words[i] = stage_b_native_u32(address);
      ++header.stack_word_count;
    }}
    for (i = header.stack_word_count; i < 16U; ++i)
      header.stack_words[i] = 0U;
  }} else {{
    uint32_t i;
    for (i = 0U; i < 16U; ++i) header.stack_words[i] = 0U;
  }}
  range_bytes = context->external_range_count *
      (uint32_t)sizeof(stage_b_native_external_range);
  lifecycle_bytes = context->external_lifecycle_count *
      (uint32_t)sizeof(stage_b_native_external_lifecycle_event);
  external_trace_bytes = context->external_trace_count *
      (uint32_t)sizeof(stage_b_native_external_trace_event);
  transfer_trace_bytes = context->transfer_trace_count *
      (uint32_t)sizeof(stage_b_native_transfer_trace_event);
  if (!stage_b_native_diagnostic_write(
          write_file, handle, &header, (uint32_t)sizeof(header)) ||
      (range_bytes != 0U && !stage_b_native_diagnostic_write(
          write_file, handle, context->external_ranges, range_bytes)) ||
      (lifecycle_bytes != 0U && !stage_b_native_diagnostic_write(
          write_file, handle, context->external_lifecycle_events,
          lifecycle_bytes)) ||
      (external_trace_bytes != 0U && !stage_b_native_diagnostic_write(
          write_file, handle, context->external_trace_events,
          external_trace_bytes)) ||
      (transfer_trace_bytes != 0U && !stage_b_native_diagnostic_write(
          write_file, handle, context->transfer_trace_events,
          transfer_trace_bytes))) {{
    close_handle(handle);
    return;
  }}
  close_handle(handle);
}}

void stage_b_native_runtime_write_external_probe(
    const stage_b_call_event *event,
    const stage_b_machine_state *state) {{
  uint32_t saved_last_error;
  uint32_t saved_reason = stage_b_native_diagnostic_reason;
  uint32_t saved_value = stage_b_native_diagnostic_value;
  uint32_t saved_aux = stage_b_native_diagnostic_aux;
  uint32_t saved_detail = stage_b_native_diagnostic_detail;
  if (event == 0 || state == 0) return;
  __asm__ volatile ("movl %%fs:0x34, %0" : "=r" (saved_last_error));
  stage_b_native_diagnostic_reason = 0x4001U;
  stage_b_native_diagnostic_value = event->target_rva;
  stage_b_native_diagnostic_aux = (uint32_t)event->kind;
  stage_b_native_diagnostic_detail = event->return_rva;
  stage_b_native_runtime_write_diagnostic(
      (uint32_t)STAGE_B_CALL_OK, event->instruction_rva, state);
  stage_b_native_diagnostic_reason = saved_reason;
  stage_b_native_diagnostic_value = saved_value;
  stage_b_native_diagnostic_aux = saved_aux;
  stage_b_native_diagnostic_detail = saved_detail;
  __asm__ volatile ("movl %0, %%fs:0x34" : : "r" (saved_last_error) : "memory");
}}
#endif

static uint32_t stage_b_native_inside_thread_environment(
    const stage_b_native_context *context, uint32_t start, uint32_t end) {{
  uint32_t teb_end;
  return context->owner_fs_base != 0U &&
      stage_b_native_range_end(
          context->owner_fs_base,
          STAGE_B_NATIVE_THREAD_ENVIRONMENT_BYTES,
          &teb_end) &&
      start >= context->owner_fs_base && end <= teb_end;
}}

static uint32_t stage_b_native_validate_image(stage_b_native_context *context) {{
  uint32_t base = (uint32_t)(uintptr_t)&__ImageBase;
  uint32_t pe_offset, pe, optional, section_table, section_bytes, section_end;
  uint32_t image_size, headers_size;
  uint16_t section_count, optional_size;
  if (base == 0U || base > 0xffffffffU - 0x40U ||
      stage_b_native_u16(base) != 0x5a4dU)
    return 0U;
  pe_offset = stage_b_native_u32(base + 0x3cU);
  if (pe_offset < 0x40U || pe_offset > 0x00100000U ||
      base > 0xffffffffU - pe_offset ||
      base + pe_offset > 0xffffffffU - 24U)
    return 0U;
  pe = base + pe_offset;
  if (stage_b_native_u32(pe) != 0x00004550U) return 0U;
  section_count = stage_b_native_u16(pe + 6U);
  optional_size = stage_b_native_u16(pe + 20U);
  if (section_count == 0U || section_count > STAGE_B_NATIVE_MAX_PE_SECTIONS ||
      optional_size < 64U)
    return 0U;
  optional = pe + 24U;
  if (optional > 0xffffffffU - 64U) return 0U;
  if (stage_b_native_u16(optional) != 0x010bU) return 0U;
  image_size = stage_b_native_u32(optional + 56U);
  headers_size = stage_b_native_u32(optional + 60U);
  if (image_size == 0U || headers_size == 0U || headers_size > image_size ||
      base > 0xffffffffU - image_size)
    return 0U;
  if (optional > 0xffffffffU - optional_size) return 0U;
  section_table = optional + optional_size;
  section_bytes = (uint32_t)section_count * 40U;
  if (!stage_b_native_range_end(section_table, section_bytes, &section_end) ||
      section_end > base + headers_size)
    return 0U;
  context->image_base = base;
  context->image_size = image_size;
  context->headers_size = headers_size;
  context->section_table = section_table;
  context->section_count = section_count;
  return 1U;
}}

static uint32_t stage_b_native_validate_stack(
    stage_b_native_context *context, const stage_b_machine_state *captured) {{
  uint32_t teb = captured->fs_base;
  uint32_t stack_high, stack_low;
  if (teb == 0U || teb > 0xffffffffU - 12U) return 0U;
  stack_high = stage_b_native_u32(teb + 4U);
  stack_low = stage_b_native_u32(teb + 8U);
  if (stack_low >= stack_high || captured->esp < stack_low ||
      captured->esp > stack_high)
    return 0U;
  context->stack_low = stack_low;
  context->stack_high = stack_high;
  return 1U;
}}

static uint32_t stage_b_native_string_equal(
    const char *left, const char *right) {{
  if (left == 0 || right == 0) return left == right;
  while (*left != '\\0' && *left == *right) {{ ++left; ++right; }}
  return *left == *right;
}}

static uint32_t stage_b_native_override_table_valid(void) {{
  uint32_t i, matched = 0U;
  if ((uintptr_t)&stage_b_region_override_count == 0U ||
      (uintptr_t)stage_b_region_overrides == 0U)
    return stage_b_native_portable_dispatch_count == 0U;
  if (stage_b_region_override_count != stage_b_native_portable_dispatch_count)
    return 0U;
  for (i = 0U; i < stage_b_region_override_count; ++i) {{
    const stage_b_region_override *observed = &stage_b_region_overrides[i];
    uint32_t j, found = 0U;
    for (j = 0U; j < stage_b_native_implementation_dispatch_count; ++j) {{
      const stage_b_native_implementation_dispatch *expected =
          &stage_b_native_implementation_dispatches[j];
      if (expected->implementation_class != 1U || expected->rva != observed->entry_rva)
        continue;
      if (found != 0U || observed->function == 0 ||
          observed->fallback_on_unimplemented != 0U ||
          !stage_b_native_string_equal(
              observed->replacement_id, expected->replacement_id) ||
          !stage_b_native_string_equal(
              observed->cluster_id, expected->cluster_id))
        return 0U;
      found = 1U;
    }}
    if (found == 0U) return 0U;
    ++matched;
  }}
  return matched == stage_b_native_portable_dispatch_count;
}}

static uint32_t stage_b_native_transfer_table_valid(void) {{
  uint32_t i;
  if ((uintptr_t)&stage_b_program_transfer_count == 0U ||
      stage_b_program_transfer_count != stage_b_native_transfer_count ||
      stage_b_native_transfer_count == 0U ||
      stage_b_native_implementation_dispatch_count !=
          stage_b_native_transfer_count ||
      !stage_b_native_override_table_valid())
    return 0U;
  for (i = 0U; i < stage_b_native_transfer_count; ++i) {{
    uint32_t rva = stage_b_native_transfer_rvas[i];
    const stage_b_native_implementation_dispatch *expected =
        &stage_b_native_implementation_dispatches[i];
    const stage_b_region_override *override;
    if ((i != 0U && stage_b_native_transfer_rvas[i - 1U] >= rva) ||
        expected->rva != rva ||
        rva >= stage_b_native_context_value.image_size ||
        stage_b_program_lookup(rva) == 0)
      return 0U;
    override = (
        stage_b_region_override_lookup == 0
        ? (const stage_b_region_override *)0
        : stage_b_region_override_lookup(rva));
    if (expected->implementation_class == 0U) {{
      if (override != 0 || expected->replacement_id != 0 ||
          expected->cluster_id != 0)
        return 0U;
    }} else if (expected->implementation_class == 1U) {{
      if (override == 0 || override->entry_rva != rva ||
          override->function == 0 || override->fallback_on_unimplemented != 0U ||
          !stage_b_native_string_equal(
              override->replacement_id, expected->replacement_id) ||
          !stage_b_native_string_equal(
              override->cluster_id, expected->cluster_id))
        return 0U;
    }} else {{
      return 0U;
    }}
  }}
  return stage_b_program_lookup(0x{plan.entry_rva:08x}U) != 0;
}}

static uint32_t stage_b_native_write_allowed(uint32_t address, uint32_t width) {{
  stage_b_native_context *context = &stage_b_native_context_value;
  uint32_t end, image_end, i, matched = 0U;
  if (!stage_b_native_range_end(address, width, &end) ||
      !stage_b_native_range_end(context->image_base, context->image_size, &image_end))
    return 0U;
  if (stage_b_native_inside_external_range(context, address, end)) return 1U;
  if (stage_b_native_inside_thread_environment(context, address, end)) return 1U;
  if (end <= context->image_base || address >= image_end)
    return address >= context->stack_low && end <= context->stack_high;
  for (i = 0U; i < context->section_count; ++i) {{
    uint32_t section = context->section_table + i * 40U;
    uint32_t virtual_size = stage_b_native_u32(section + 8U);
    uint32_t raw_size = stage_b_native_u32(section + 16U);
    uint32_t rva = stage_b_native_u32(section + 12U);
    uint32_t size = virtual_size > raw_size ? virtual_size : raw_size;
    uint32_t section_start;
    if (rva > 0xffffffffU - context->image_base) return 0U;
    section_start = context->image_base + rva;
    if (stage_b_native_inside(address, end, section_start, size)) {{
      if ((stage_b_native_u32(section + 36U) &
          STAGE_B_NATIVE_IMAGE_SCN_MEM_EXECUTE) != 0U)
        return 0U;
      matched = 1U;
    }}
  }}
  return matched;
}}

static uint32_t stage_b_native_read_allowed(uint32_t address, uint32_t width) {{
  stage_b_native_context *context = &stage_b_native_context_value;
  uint32_t end, image_end, i;
  if (!stage_b_native_range_end(address, width, &end) ||
      !stage_b_native_range_end(context->image_base, context->image_size, &image_end))
    return 0U;
  if (address >= context->stack_low && end <= context->stack_high)
    return 1U;
  if (stage_b_native_inside_external_range(context, address, end)) return 1U;
  if (stage_b_native_inside_thread_environment(context, address, end)) return 1U;
  if (address < context->image_base || end > image_end)
    return 0U;
  if (end <= context->image_base + context->headers_size)
    return 1U;
  for (i = 0U; i < context->section_count; ++i) {{
    uint32_t section = context->section_table + i * 40U;
    uint32_t virtual_size = stage_b_native_u32(section + 8U);
    uint32_t raw_size = stage_b_native_u32(section + 16U);
    uint32_t rva = stage_b_native_u32(section + 12U);
    uint32_t size = virtual_size > raw_size ? virtual_size : raw_size;
    uint32_t section_start;
    if (rva > 0xffffffffU - context->image_base) return 0U;
    section_start = context->image_base + rva;
    if (stage_b_native_inside(address, end, section_start, size)) return 1U;
  }}
  return 0U;
}}

static uint32_t stage_b_native_state_register(
    const stage_b_machine_state *state, uint32_t index, uint32_t *value) {{
  if (state == 0 || value == 0) return 0U;
  switch (index) {{
    case 0U: *value = state->eax; return 1U;
    case 1U: *value = state->ebx; return 1U;
    case 2U: *value = state->ecx; return 1U;
    case 3U: *value = state->edx; return 1U;
    case 4U: *value = state->esi; return 1U;
    case 5U: *value = state->edi; return 1U;
    case 6U: *value = state->ebp; return 1U;
    case 7U: *value = state->esp; return 1U;
    default: return 0U;
  }}
}}

static stage_b_native_callable_binding *stage_b_native_callable_binding_for(
    uint32_t capability_id) {{
  stage_b_native_context *context = &stage_b_native_context_value;
  uint32_t i;
  for (i = 0U; i < stage_b_native_callable_resolver_count; ++i)
    if (context->callable_bindings[i].capability_id == capability_id)
      return &context->callable_bindings[i];
  return (stage_b_native_callable_binding *)0;
}}

static stage_b_call_status stage_b_native_record_callable_result(
    const stage_b_call_event *event, const stage_b_machine_state *output) {{
  stage_b_native_context *context = &stage_b_native_context_value;
  uint32_t i;
  for (i = 0U; i < stage_b_native_callable_resolver_count; ++i) {{
    const stage_b_native_callable_resolver *resolver =
        &stage_b_native_callable_resolvers[i];
    stage_b_native_callable_binding *binding;
    uint32_t target, image_end;
    if (resolver->instruction_rva != event->instruction_rva) continue;
    if (!stage_b_native_state_register(
            output, resolver->result_register, &target))
      return STAGE_B_CALL_UNIMPLEMENTED;
    if (target == 0U)
      return resolver->nullable != 0U
          ? STAGE_B_CALL_OK : STAGE_B_CALL_UNIMPLEMENTED;
    if (!stage_b_native_range_end(
            context->image_base, context->image_size, &image_end) ||
        (target >= context->image_base && target < image_end))
      return STAGE_B_CALL_UNIMPLEMENTED;
    binding = stage_b_native_callable_binding_for(resolver->capability_id);
    if (binding == 0) return STAGE_B_CALL_UNIMPLEMENTED;
    if (binding->bound != 0U && binding->target_word != target)
      return STAGE_B_CALL_UNIMPLEMENTED;
    binding->target_word = target;
    binding->bound = 1U;
  }}
  return STAGE_B_CALL_OK;
}}

static uint32_t stage_b_native_external_range_rule_matches(
    const stage_b_native_external_range_rule *rule,
    const stage_b_call_event *event) {{
  const stage_b_native_context *context = &stage_b_native_context_value;
  uint32_t iat_address, target;
  if (rule == 0 || event == 0 ||
      rule->instruction_rva != event->instruction_rva)
    return 0U;
  if (rule->target_iat_rva == 0U) return 1U;
  if (event->kind != STAGE_B_CALL_INDIRECT ||
      rule->target_iat_rva > context->image_size ||
      context->image_base > 0xffffffffU - rule->target_iat_rva)
    return 0U;
  iat_address = context->image_base + rule->target_iat_rva;
  target = stage_b_native_u32(iat_address);
  return target != 0U && event->target_rva == target;
}}

#ifdef STAGE_B_NATIVE_DIAGNOSTIC_FAILURE_TRAP
static void stage_b_native_record_external_trace(
    uint32_t phase, const stage_b_call_event *call,
    const stage_b_external_call_snapshot *snapshot,
    const stage_b_machine_state *state, stage_b_call_status status) {{
  stage_b_native_context *context = &stage_b_native_context_value;
  stage_b_native_external_trace_event *event;
  uint32_t index;
  if (call == 0 || snapshot == 0 || state == 0) return;
  index = context->external_trace_next;
  event = &context->external_trace_events[index];
  if (context->external_trace_sequence != 0xffffffffU)
    ++context->external_trace_sequence;
  event->sequence = context->external_trace_sequence;
  event->phase = phase;
  event->instruction_rva = call->instruction_rva;
  event->target_rva = call->target_rva;
  event->target_iat_rva = snapshot->target_iat_rva;
  event->kind = (uint32_t)call->kind;
  event->status = (uint32_t)status;
  event->eax = state->eax;
  event->esp = state->esp;
  event->eflags = state->eflags;
  context->external_trace_next =
      (index + 1U) % STAGE_B_NATIVE_MAX_EXTERNAL_TRACE_EVENTS;
  if (context->external_trace_count < STAGE_B_NATIVE_MAX_EXTERNAL_TRACE_EVENTS)
    ++context->external_trace_count;
}}
#endif

static uint32_t stage_b_native_external_site_authorized(uint32_t rva) {{
  uint32_t low = 0U, high = stage_b_native_authorized_external_site_count;
  while (low < high) {{
    uint32_t middle = low + (high - low) / 2U;
    if (stage_b_native_authorized_external_sites[middle] < rva)
      low = middle + 1U;
    else
      high = middle;
  }}
  return low < stage_b_native_authorized_external_site_count &&
      stage_b_native_authorized_external_sites[low] == rva;
}}

stage_b_call_status stage_b_native_runtime_capture_external_call(
    const stage_b_call_event *event, const stage_b_machine_state *input,
    stage_b_external_call_snapshot *snapshot) {{
  uint32_t i, found = 0U, direct_binding_seen = 0U;
  if (event == 0 || input == 0 || snapshot == 0 ||
      stage_b_native_context_value.initialized == 0U) {{
    stage_b_native_diagnostic_reason = 0x2003U;
    return STAGE_B_CALL_UNIMPLEMENTED;
  }}
  if (!stage_b_native_external_site_authorized(event->instruction_rva)) {{
    stage_b_native_diagnostic_reason = 0x2009U;
    stage_b_native_diagnostic_value = event->instruction_rva;
    stage_b_native_diagnostic_aux = event->target_rva;
    return STAGE_B_CALL_UNIMPLEMENTED;
  }}
  if (event->kind == STAGE_B_CALL_INDIRECT &&
      event->target_rva >= stage_b_native_context_value.image_base &&
      event->target_rva - stage_b_native_context_value.image_base <
          stage_b_native_context_value.image_size) {{
    stage_b_native_diagnostic_reason = 0x200aU;
    stage_b_native_diagnostic_value = event->instruction_rva;
    stage_b_native_diagnostic_aux = event->target_rva;
    return STAGE_B_CALL_UNIMPLEMENTED;
  }}
  snapshot->instruction_rva = event->instruction_rva;
  snapshot->target_iat_rva = 0U;
  snapshot->argument_base_offset = 0U;
  snapshot->argument_count = 0U;
  for (i = 0U; i < stage_b_native_external_range_rule_count; ++i) {{
    const stage_b_native_external_range_rule *rule =
        &stage_b_native_external_range_rules[i];
    if (!stage_b_native_external_range_rule_matches(rule, event)) continue;
    if ((rule->target_iat_rva == 0U && snapshot->target_iat_rva != 0U) ||
        (rule->target_iat_rva != 0U && direct_binding_seen != 0U) ||
        (rule->target_iat_rva != 0U && snapshot->target_iat_rva != 0U &&
         snapshot->target_iat_rva != rule->target_iat_rva)) {{
      stage_b_native_diagnostic_reason = 0x2008U;
      stage_b_native_diagnostic_value = event->target_rva;
      stage_b_native_diagnostic_aux = snapshot->target_iat_rva;
      stage_b_native_diagnostic_detail = rule->target_iat_rva;
      return STAGE_B_CALL_UNIMPLEMENTED;
    }}
    if (rule->target_iat_rva == 0U)
      direct_binding_seen = 1U;
    else
      snapshot->target_iat_rva = rule->target_iat_rva;
    if (rule->argument_count > STAGE_B_MAX_EXTERNAL_ARGUMENTS ||
        (found != 0U &&
         (snapshot->argument_base_offset != rule->argument_base_offset ||
          snapshot->argument_count != rule->argument_count))) {{
      stage_b_native_diagnostic_reason = 0x2004U;
      return STAGE_B_CALL_UNIMPLEMENTED;
    }}
    snapshot->argument_base_offset = rule->argument_base_offset;
    snapshot->argument_count = rule->argument_count;
    found = 1U;
  }}
  for (i = 0U; i < snapshot->argument_count; ++i) {{
    uint32_t offset, address, value;
    if (i > 0x3fffffffU) {{
      stage_b_native_diagnostic_reason = 0x2005U;
      return STAGE_B_CALL_UNIMPLEMENTED;
    }}
    offset = i * 4U;
    if (snapshot->argument_base_offset > 0xffffffffU - offset ||
        input->esp >
            0xffffffffU - (snapshot->argument_base_offset + offset)) {{
      stage_b_native_diagnostic_reason = 0x2005U;
      return STAGE_B_CALL_UNIMPLEMENTED;
    }}
    address = input->esp + snapshot->argument_base_offset + offset;
    if (!stage_b_native_read_allowed(address, 4U)) {{
      stage_b_native_diagnostic_reason = 0x2005U;
      return STAGE_B_CALL_UNIMPLEMENTED;
    }}
    value = stage_b_native_u32(address);
    if (event->arguments != 0 && i < event->argument_count &&
        event->arguments[i] != value) {{
      stage_b_native_diagnostic_reason = 0x2006U;
      return STAGE_B_CALL_UNIMPLEMENTED;
    }}
    snapshot->arguments[i] = value;
  }}
#ifdef STAGE_B_NATIVE_DIAGNOSTIC_FAILURE_TRAP
  stage_b_native_record_external_trace(
      1U, event, snapshot, input, STAGE_B_CALL_OK);
#endif
  return STAGE_B_CALL_OK;
}}

static uint32_t stage_b_native_external_argument(
    const stage_b_native_external_range_rule *rule,
    const stage_b_call_event *event,
    const stage_b_external_call_snapshot *snapshot,
    uint32_t index, uint32_t *value) {{
  if (rule == 0 || event == 0 || snapshot == 0 || value == 0 ||
      snapshot->instruction_rva != event->instruction_rva ||
      snapshot->target_iat_rva != rule->target_iat_rva ||
      snapshot->argument_base_offset != rule->argument_base_offset ||
      snapshot->argument_count != rule->argument_count ||
      index >= snapshot->argument_count)
    return 0U;
  if (event->arguments != 0 && index < event->argument_count &&
      event->arguments[index] != snapshot->arguments[index])
    return 0U;
  *value = snapshot->arguments[index];
  return 1U;
}}

static uint32_t stage_b_native_zero_run_extent(
    uint32_t start, uint32_t unit_bytes, uint32_t zero_units,
    uint32_t max_units, uint32_t *extent) {{
  uint32_t index, run = 0U;
  if (start == 0U || extent == 0 ||
      (unit_bytes != 1U && unit_bytes != 2U && unit_bytes != 4U) ||
      zero_units == 0U || zero_units > max_units)
    return 0U;
  for (index = 0U; index < max_units; ++index) {{
    uint32_t offset, address, value;
    if (index > 0xffffffffU / unit_bytes) return 0U;
    offset = index * unit_bytes;
    if (start > 0xffffffffU - offset) return 0U;
    address = start + offset;
    value = unit_bytes == 1U
        ? (uint32_t)*(const volatile uint8_t *)(uintptr_t)address
        : unit_bytes == 2U
        ? (uint32_t)stage_b_native_u16(address)
        : stage_b_native_u32(address);
    run = value == 0U ? run + 1U : 0U;
    if (run == zero_units) {{
      if (index == 0xffffffffU / unit_bytes) return 0U;
      *extent = (index + 1U) * unit_bytes;
      return 1U;
    }}
  }}
  return 0U;
}}

static uint32_t stage_b_native_range_size(
    const stage_b_native_external_range_rule *rule,
    const stage_b_call_event *event,
    const stage_b_external_call_snapshot *snapshot,
    uint32_t pointer, uint32_t *size) {{
  uint32_t left, right;
  if (rule == 0 || event == 0 || size == 0) return 0U;
  if (rule->size_kind == 1U) {{
    *size = rule->size_value;
  }} else if (rule->size_kind == 2U) {{
    if (!stage_b_native_external_argument(
            rule, event, snapshot, rule->size_argument, &left))
      return 0U;
    if (rule->size_value != 0U && left > 0xffffffffU / rule->size_value)
      return 0U;
    *size = left * rule->size_value;
  }} else if (rule->size_kind == 3U) {{
    if (!stage_b_native_external_argument(
            rule, event, snapshot, rule->size_argument, &left) ||
        !stage_b_native_external_argument(
            rule, event, snapshot, rule->size_right_argument, &right))
      return 0U;
    if (right != 0U && left > 0xffffffffU / right) return 0U;
    *size = left * right;
  }} else if (rule->size_kind == 4U) {{
    if (pointer == 0U) return rule->nullable != 0U;
    if (!stage_b_native_zero_run_extent(
            pointer, rule->termination_unit_bytes,
            rule->termination_zero_units, rule->termination_max_units, size))
      return 0U;
  }} else {{
    return 0U;
  }}
  return *size >= rule->minimum_size;
}}

static uint32_t stage_b_native_next_external_lifecycle_sequence(
    stage_b_native_context *context) {{
  if (context->external_lifecycle_sequence != 0xffffffffU)
    ++context->external_lifecycle_sequence;
  return context->external_lifecycle_sequence;
}}

static void stage_b_native_record_external_lifecycle(
    stage_b_native_context *context, uint32_t operation,
    stage_b_call_status status, uint32_t instruction_rva,
    uint32_t start, uint32_t size, uint32_t producer_rva,
    uint32_t producer_action, uint32_t generation) {{
  stage_b_native_external_lifecycle_event *event;
  if (context == 0) return;
  event = &context->external_lifecycle_events[context->external_lifecycle_next];
  event->sequence = stage_b_native_next_external_lifecycle_sequence(context);
  event->operation = operation;
  event->status = (uint32_t)status;
  event->instruction_rva = instruction_rva;
  event->start = start;
  event->size = size;
  event->producer_rva = producer_rva;
  event->producer_action = producer_action;
  event->generation = generation;
  context->external_lifecycle_next =
      (context->external_lifecycle_next + 1U) %
      STAGE_B_NATIVE_MAX_EXTERNAL_LIFECYCLE_EVENTS;
  if (context->external_lifecycle_count <
      STAGE_B_NATIVE_MAX_EXTERNAL_LIFECYCLE_EVENTS)
    ++context->external_lifecycle_count;
}}

static stage_b_call_status stage_b_native_add_external_range(
    uint32_t start, uint32_t size, uint32_t producer_rva,
    uint32_t producer_action) {{
  stage_b_native_context *context = &stage_b_native_context_value;
  uint32_t end, generation, i;
  if (!stage_b_native_range_end(start, size, &end)) {{
    stage_b_native_record_external_lifecycle(
        context, 1U, STAGE_B_CALL_UNIMPLEMENTED, producer_rva,
        start, size, producer_rva, producer_action, 0U);
    return STAGE_B_CALL_UNIMPLEMENTED;
  }}
  generation = context->external_lifecycle_sequence == 0xffffffffU
      ? 0xffffffffU : context->external_lifecycle_sequence + 1U;
  for (i = 0U; i < context->external_range_count; ++i) {{
    if (context->external_ranges[i].start == start) {{
      context->external_ranges[i].size = size;
      context->external_ranges[i].producer_rva = producer_rva;
      context->external_ranges[i].producer_action = producer_action;
      context->external_ranges[i].generation = generation;
      stage_b_native_record_external_lifecycle(
          context, 2U, STAGE_B_CALL_OK, producer_rva,
          start, size, producer_rva, producer_action, generation);
      return STAGE_B_CALL_OK;
    }}
  }}
  if (context->external_range_count == STAGE_B_NATIVE_MAX_EXTERNAL_RANGES) {{
    stage_b_native_record_external_lifecycle(
        context, 1U, STAGE_B_CALL_UNIMPLEMENTED, producer_rva,
        start, size, producer_rva, producer_action, generation);
    return STAGE_B_CALL_UNIMPLEMENTED;
  }}
  context->external_ranges[context->external_range_count].start = start;
  context->external_ranges[context->external_range_count].size = size;
  context->external_ranges[context->external_range_count].producer_rva = producer_rva;
  context->external_ranges[context->external_range_count].producer_action =
      producer_action;
  context->external_ranges[context->external_range_count].generation = generation;
  ++context->external_range_count;
  stage_b_native_record_external_lifecycle(
      context, 1U, STAGE_B_CALL_OK, producer_rva,
      start, size, producer_rva, producer_action, generation);
  return STAGE_B_CALL_OK;
}}

static stage_b_call_status stage_b_native_release_external_range(
    uint32_t start, uint32_t instruction_rva) {{
  stage_b_native_context *context = &stage_b_native_context_value;
  uint32_t i, operation = 4U;
  if (start == 0U) return STAGE_B_CALL_OK;
  for (i = 0U; i < context->external_range_count; ++i) {{
    if (context->external_ranges[i].start == start) {{
      stage_b_native_external_range released = context->external_ranges[i];
      --context->external_range_count;
      context->external_ranges[i] =
          context->external_ranges[context->external_range_count];
      stage_b_native_record_external_lifecycle(
          context, 3U, STAGE_B_CALL_OK, instruction_rva,
          released.start, released.size, released.producer_rva,
          released.producer_action, released.generation);
      return STAGE_B_CALL_OK;
    }}
  }}
  for (i = 0U; i < context->external_range_count; ++i) {{
    uint32_t end;
    if (stage_b_native_range_end(
            context->external_ranges[i].start,
            context->external_ranges[i].size, &end) &&
        start > context->external_ranges[i].start && start < end) {{
      operation = 5U;
      stage_b_native_diagnostic_aux = context->external_ranges[i].start;
      stage_b_native_diagnostic_detail = end;
      break;
    }}
  }}
  if (operation == 4U) {{
    uint32_t offset;
    for (offset = 0U; offset < context->external_lifecycle_count; ++offset) {{
      uint32_t index =
          (context->external_lifecycle_next +
           STAGE_B_NATIVE_MAX_EXTERNAL_LIFECYCLE_EVENTS - 1U - offset) %
          STAGE_B_NATIVE_MAX_EXTERNAL_LIFECYCLE_EVENTS;
      const stage_b_native_external_lifecycle_event *event =
          &context->external_lifecycle_events[index];
      if (event->start != start) continue;
      if (event->operation == 3U) operation = 6U;
      stage_b_native_diagnostic_aux = event->instruction_rva;
      stage_b_native_diagnostic_detail = event->producer_rva;
      break;
    }}
  }}
  stage_b_native_record_external_lifecycle(
      context, operation, STAGE_B_CALL_UNIMPLEMENTED, instruction_rva,
      start, 0U, 0U, 0U, 0U);
  stage_b_native_diagnostic_value = start;
  stage_b_native_diagnostic_reason =
      operation == 5U ? 0x2204U : operation == 6U ? 0x2203U : 0x2202U;
  return STAGE_B_CALL_UNIMPLEMENTED;
}}

static uint32_t stage_b_native_terminated_extent(
    uint32_t start, uint32_t unit_bytes, uint32_t max_units,
    uint32_t *extent) {{
  uint32_t index;
  if (start == 0U || extent == 0 ||
      (unit_bytes != 1U && unit_bytes != 2U && unit_bytes != 4U))
    return 0U;
  for (index = 0U; index < max_units; ++index) {{
    uint32_t offset, address, value;
    if (index > 0xffffffffU / unit_bytes) return 0U;
    offset = index * unit_bytes;
    if (start > 0xffffffffU - offset) return 0U;
    address = start + offset;
    value = unit_bytes == 1U
        ? (uint32_t)*(const volatile uint8_t *)(uintptr_t)address
        : unit_bytes == 2U
        ? (uint32_t)stage_b_native_u16(address)
        : stage_b_native_u32(address);
    if (value == 0U) {{
      if (index == 0xffffffffU / unit_bytes) return 0U;
      *extent = (index + 1U) * unit_bytes;
      return 1U;
    }}
  }}
  return 0U;
}}

static stage_b_call_status stage_b_native_add_external_pointee_ranges(
    const stage_b_native_external_range_rule *rule,
    uint32_t cell) {{
  uint32_t vector, index;
  if (rule == 0 || cell == 0U ||
      cell > 0xffffffffU - rule->pointee_offset)
    return STAGE_B_CALL_UNIMPLEMENTED;
  vector = stage_b_native_u32(cell + rule->pointee_offset);
  if (vector == 0U) return STAGE_B_CALL_OK;
  for (index = 0U; index < rule->max_elements; ++index) {{
    uint32_t offset, element, extent;
    stage_b_call_status status;
    if (index > 0x3fffffffU) return STAGE_B_CALL_UNIMPLEMENTED;
    offset = index * 4U;
    if (vector > 0xffffffffU - offset) return STAGE_B_CALL_UNIMPLEMENTED;
    element = stage_b_native_u32(vector + offset);
    if (element == 0U) {{
      if (index == 0x3fffffffU) return STAGE_B_CALL_UNIMPLEMENTED;
      return stage_b_native_add_external_range(
          vector, (index + 1U) * 4U,
          rule->instruction_rva, rule->action);
    }}
    if (!stage_b_native_terminated_extent(
            element, rule->element_unit_bytes, rule->element_max_units,
            &extent))
      return STAGE_B_CALL_UNIMPLEMENTED;
    status = stage_b_native_add_external_range(
        element, extent, rule->instruction_rva, rule->action);
    if (status != STAGE_B_CALL_OK) return status;
  }}
  return STAGE_B_CALL_UNIMPLEMENTED;
}}

static stage_b_call_status stage_b_native_add_external_interface_ranges(
    const stage_b_native_external_range_rule *rule, uint32_t cell) {{
  uint32_t object, vtable;
  stage_b_call_status status;
  if (rule == 0 || cell == 0U ||
      cell > 0xffffffffU - rule->pointee_offset)
    return STAGE_B_CALL_UNIMPLEMENTED;
  object = stage_b_native_u32(cell + rule->pointee_offset);
  if (object == 0U)
    return rule->nullable != 0U
        ? STAGE_B_CALL_OK : STAGE_B_CALL_UNIMPLEMENTED;
  status = stage_b_native_add_external_range(
      object, rule->minimum_size, rule->instruction_rva, rule->action);
  if (status != STAGE_B_CALL_OK) return status;
  vtable = stage_b_native_u32(object);
  if (vtable == 0U) return STAGE_B_CALL_UNIMPLEMENTED;
  return stage_b_native_add_external_range(
      vtable, rule->size_value, rule->instruction_rva, rule->action);
}}

stage_b_call_status stage_b_native_runtime_record_external_result(
    const stage_b_call_event *event,
    const stage_b_external_call_snapshot *snapshot,
    const stage_b_machine_state *output) {{
  uint32_t i;
  if (event == 0 || snapshot == 0 || output == 0 ||
      snapshot->instruction_rva != event->instruction_rva ||
      stage_b_native_context_value.initialized == 0U) {{
    stage_b_native_diagnostic_reason = 0x2001U;
    return STAGE_B_CALL_UNIMPLEMENTED;
  }}
#ifdef STAGE_B_NATIVE_DIAGNOSTIC_FAILURE_TRAP
  stage_b_native_record_external_trace(
      2U, event, snapshot, output, STAGE_B_CALL_OK);
#endif
  if (stage_b_native_record_callable_result(event, output) != STAGE_B_CALL_OK) {{
    stage_b_native_diagnostic_reason = 0x2002U;
    return STAGE_B_CALL_UNIMPLEMENTED;
  }}
  for (i = 0U; i < stage_b_native_external_range_rule_count; ++i) {{
    const stage_b_native_external_range_rule *rule =
        &stage_b_native_external_range_rules[i];
    stage_b_call_status status;
    uint32_t pointer, size;
    if (!stage_b_native_external_range_rule_matches(rule, event) ||
        rule->target_iat_rva != snapshot->target_iat_rva)
      continue;
    if (rule->action == 1U) {{
      if (!stage_b_native_state_register(output, rule->register_index, &pointer) ||
          (!rule->nullable && pointer == 0U) ||
          !stage_b_native_range_size(rule, event, snapshot, pointer, &size)) {{
        stage_b_native_diagnostic_reason = 0x2101U;
        return STAGE_B_CALL_UNIMPLEMENTED;
      }}
      if (pointer == 0U || size == 0U) continue;
      status = stage_b_native_add_external_range(
          pointer, size, rule->instruction_rva, rule->action);
    }} else if (rule->action == 2U) {{
      if (!stage_b_native_external_argument(
              rule, event, snapshot, rule->argument, &pointer)) {{
        stage_b_native_diagnostic_reason = 0x2201U;
        return STAGE_B_CALL_UNIMPLEMENTED;
      }}
      status = stage_b_native_release_external_range(
          pointer, rule->instruction_rva);
    }} else if (rule->action == 3U) {{
      if (!stage_b_native_state_register(
              output, rule->register_index, &pointer)) {{
        stage_b_native_diagnostic_reason = 0x2301U;
        return STAGE_B_CALL_UNIMPLEMENTED;
      }}
      status = stage_b_native_add_external_pointee_ranges(rule, pointer);
    }} else if (rule->action == 4U) {{
      if (!stage_b_native_external_argument(
              rule, event, snapshot, rule->argument, &pointer)) {{
        stage_b_native_diagnostic_reason = 0x2401U;
        return STAGE_B_CALL_UNIMPLEMENTED;
      }}
      status = stage_b_native_add_external_pointee_ranges(
          rule, pointer);
    }} else if (rule->action == 5U) {{
      if ((int32_t)output->eax < 0) continue;
      if (!stage_b_native_external_argument(
              rule, event, snapshot, rule->argument, &pointer)) {{
        stage_b_native_diagnostic_reason = 0x2501U;
        return STAGE_B_CALL_UNIMPLEMENTED;
      }}
      status = stage_b_native_add_external_interface_ranges(rule, pointer);
    }} else {{
      stage_b_native_diagnostic_reason = 0x2f01U;
      return STAGE_B_CALL_UNIMPLEMENTED;
    }}
    if (status != STAGE_B_CALL_OK) {{
      if (rule->action == 2U && stage_b_native_diagnostic_reason == 0U) {{
        stage_b_native_diagnostic_value =
            stage_b_native_context_value.external_range_count;
        stage_b_native_diagnostic_aux = pointer;
        stage_b_native_diagnostic_detail =
            stage_b_native_context_value.external_range_count != 0U
            ? stage_b_native_context_value.external_ranges[
                stage_b_native_context_value.external_range_count - 1U].start
            : 0U;
      }}
      if (stage_b_native_diagnostic_reason == 0U)
        stage_b_native_diagnostic_reason =
            0x2000U + rule->action * 0x100U + 2U;
      return status;
    }}
  }}
  return STAGE_B_CALL_OK;
}}

static uint32_t stage_b_native_flat_read(
    void *opaque, uint32_t address, uint32_t width, uint32_t *fault) {{
  const volatile uint8_t *p;
  uint32_t end, value = 0U, i;
  stage_b_native_context *context = (stage_b_native_context *)opaque;
  if (fault == 0) return 0U;
  *fault = 1U;
  if (context == 0 || context->initialized == 0U ||
      (width != 1U && width != 2U && width != 4U) ||
      !stage_b_native_range_end(address, width, &end) ||
      !stage_b_native_read_allowed(address, width)) {{
    stage_b_native_diagnostic_reason = 0x3001U;
    stage_b_native_diagnostic_value = address;
    stage_b_native_diagnose_external_range(context, address);
    return 0U;
  }}
  (void)end;
  p = (const volatile uint8_t *)(uintptr_t)address;
  for (i = 0U; i < width; ++i) value |= (uint32_t)p[i] << (i * 8U);
  *fault = 0U;
  return value;
}}

static void stage_b_native_flat_write(
    void *opaque, uint32_t address, uint32_t width, uint32_t value,
    uint32_t *fault) {{
  volatile uint8_t *p;
  uint32_t i;
  stage_b_native_context *context = (stage_b_native_context *)opaque;
  if (fault == 0) return;
  *fault = 1U;
  if (context == 0 || context->initialized == 0U ||
      (width != 1U && width != 2U && width != 4U) ||
      !stage_b_native_write_allowed(address, width)) {{
    stage_b_native_diagnostic_reason = 0x3002U;
    stage_b_native_diagnostic_value = address;
    stage_b_native_diagnose_external_range(context, address);
    return;
  }}
  p = (volatile uint8_t *)(uintptr_t)address;
  for (i = 0U; i < width; ++i) p[i] = (uint8_t)(value >> (i * 8U));
  *fault = 0U;
}}

static void stage_b_native_atomic_compare_exchange(
    void *opaque, uint32_t address, uint32_t width,
    uint32_t expected, uint32_t desired,
    uint32_t *observed, uint32_t *exchanged, uint32_t *fault) {{
  stage_b_native_context *context = (stage_b_native_context *)opaque;
  uint32_t end;
  if (fault == 0) return;
  *fault = 1U;
  if (observed == 0 || exchanged == 0 || context == 0 ||
      context->initialized == 0U ||
      (width != 1U && width != 2U && width != 4U) ||
      !stage_b_native_range_end(address, width, &end) ||
      !stage_b_native_read_allowed(address, width) ||
      !stage_b_native_write_allowed(address, width))
    return;
  (void)end;
  if (width == 1U) {{
    uint8_t prior = (uint8_t)expected;
    *exchanged = __atomic_compare_exchange_n(
        (volatile uint8_t *)(uintptr_t)address, &prior, (uint8_t)desired,
        0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    *observed = prior;
  }} else if (width == 2U) {{
    uint16_t prior = (uint16_t)expected;
    *exchanged = __atomic_compare_exchange_n(
        (volatile uint16_t *)(uintptr_t)address, &prior, (uint16_t)desired,
        0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    *observed = prior;
  }} else {{
    uint32_t prior = expected;
    *exchanged = __atomic_compare_exchange_n(
        (volatile uint32_t *)(uintptr_t)address, &prior, desired,
        0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    *observed = prior;
  }}
  *fault = 0U;
}}

static void stage_b_native_atomic_exchange(
    void *opaque, uint32_t address, uint32_t width,
    uint32_t desired, uint32_t *observed, uint32_t *fault) {{
  stage_b_native_context *context = (stage_b_native_context *)opaque;
  uint32_t end;
  if (fault == 0) return;
  *fault = 1U;
  if (observed == 0 || context == 0 || context->initialized == 0U ||
      (width != 1U && width != 2U && width != 4U) ||
      !stage_b_native_range_end(address, width, &end) ||
      !stage_b_native_read_allowed(address, width) ||
      !stage_b_native_write_allowed(address, width))
    return;
  (void)end;
  if (width == 1U)
    *observed = __atomic_exchange_n(
        (volatile uint8_t *)(uintptr_t)address, (uint8_t)desired,
        __ATOMIC_SEQ_CST);
  else if (width == 2U)
    *observed = __atomic_exchange_n(
        (volatile uint16_t *)(uintptr_t)address, (uint16_t)desired,
        __ATOMIC_SEQ_CST);
  else
    *observed = __atomic_exchange_n(
        (volatile uint32_t *)(uintptr_t)address, desired, __ATOMIC_SEQ_CST);
  *fault = 0U;
}}

void stage_b_runtime_atomic_compare_exchange(
    stage_b_runtime *runtime, uint32_t address, uint32_t width,
    uint32_t expected, uint32_t desired,
    uint32_t *observed, uint32_t *exchanged, uint32_t *fault) {{
  if (fault == 0) return;
  *fault = 1U;
  if (runtime == 0) return;
  stage_b_native_atomic_compare_exchange(
      runtime->context, address, width, expected, desired,
      observed, exchanged, fault);
}}

void stage_b_runtime_atomic_exchange(
    stage_b_runtime *runtime, uint32_t address, uint32_t width,
    uint32_t desired, uint32_t *observed, uint32_t *fault) {{
  if (fault == 0) return;
  *fault = 1U;
  if (runtime == 0) return;
  stage_b_native_atomic_exchange(
      runtime->context, address, width, desired, observed, fault);
}}

static uint32_t stage_b_native_undefined_value(
    void *opaque, uint32_t slot, const stage_b_machine_state *input,
    uint32_t defined_value) {{
  stage_b_native_context *context = (stage_b_native_context *)opaque;
  uint32_t low = 0U, high = stage_b_native_undefined_policy_count;
  if (context == 0 || context->initialized == 0U) return 0U;
  while (low < high) {{
    uint32_t middle = low + (high - low) / 2U;
    if (stage_b_native_undefined_policies[middle].slot < slot) low = middle + 1U;
    else high = middle;
  }}
  if (low == stage_b_native_undefined_policy_count ||
      stage_b_native_undefined_policies[low].slot != slot) {{
    if (context->undefined_fault == 0U) {{
      context->undefined_fault_slot = slot;
      context->undefined_fault_rva = input != 0 ? input->original_rva : 0U;
    }}
    context->undefined_fault = 1U;
    return 0U;
  }}
  if (stage_b_native_undefined_policies[low].policy == 0U) return 0U;
  if (stage_b_native_undefined_policies[low].policy == 1U)
    return defined_value;
  if (context->undefined_fault == 0U) {{
    context->undefined_fault_slot = slot;
    context->undefined_fault_rva = input != 0 ? input->original_rva : 0U;
  }}
  context->undefined_fault = 1U;
  return 0U;
}}

static uint32_t stage_b_native_resolve_code_target(
    stage_b_runtime *runtime, uint32_t target_word, uint32_t *target_rva) {{
  stage_b_native_context *context;
  uint32_t rva, low = 0U, high = stage_b_native_transfer_count;
  if (runtime == 0 || target_rva == 0 || runtime->context == 0) return 1U;
  context = (stage_b_native_context *)runtime->context;
  if (context->initialized == 0U || target_word < context->image_base)
    return 1U;
  rva = target_word - context->image_base;
  {{
    uint32_t range_low = 0U, range_high = stage_b_native_noncode_range_count;
    while (range_low < range_high) {{
      uint32_t middle = range_low + (range_high - range_low) / 2U;
      if (stage_b_native_noncode_ranges[middle].rva_end <= rva)
        range_low = middle + 1U;
      else
        range_high = middle;
    }}
    if (range_low < stage_b_native_noncode_range_count &&
        stage_b_native_noncode_ranges[range_low].rva_start <= rva &&
        rva < stage_b_native_noncode_ranges[range_low].rva_end)
      return 1U;
  }}
  while (low < high) {{
    uint32_t middle = low + (high - low) / 2U;
    if (stage_b_native_transfer_rvas[middle] < rva) low = middle + 1U;
    else high = middle;
  }}
  if (low == stage_b_native_transfer_count ||
      stage_b_native_transfer_rvas[low] != rva || stage_b_program_lookup(rva) == 0)
    return 1U;
  *target_rva = rva;
  return 0U;
}}

static uint32_t stage_b_native_callable_argument_value(
    const stage_b_native_callable_argument *source,
    const stage_b_machine_state *input, uint32_t *value) {{
  uint32_t address;
  if (source == 0 || input == 0 || value == 0) return 0U;
  if (source->kind == 0U)
    return stage_b_native_state_register(input, source->register_index, value);
  if (source->kind == 1U) {{
    if (input->esp > 0xffffffffU - source->value) return 0U;
    address = input->esp + source->value;
    if (!stage_b_native_read_allowed(address, 4U)) return 0U;
    *value = stage_b_native_u32(address);
    return 1U;
  }}
  if (source->kind == 2U) {{
    *value = source->value;
    return 1U;
  }}
  return 0U;
}}

static uint32_t stage_b_native_callable_footprints_valid(
    const stage_b_native_callable_route *route,
    const uint32_t *arguments) {{
  uint32_t i;
  if (route == 0 ||
      route->footprint_offset > stage_b_native_callable_footprint_count ||
      route->footprint_count >
          stage_b_native_callable_footprint_count - route->footprint_offset)
    return 0U;
  for (i = 0U; i < route->footprint_count; ++i) {{
    const stage_b_native_callable_footprint *footprint =
        &stage_b_native_callable_footprints[route->footprint_offset + i];
    uint32_t start, end;
    if (arguments == 0 || footprint->base_argument >= route->argument_count)
      return 0U;
    start = arguments[footprint->base_argument];
    if (start == 0U) {{
      if (footprint->nullable != 0U) continue;
      return 0U;
    }}
    if (start > 0xffffffffU - footprint->offset ||
        !stage_b_native_range_end(
            start + footprint->offset, footprint->size, &end))
      return 0U;
    start += footprint->offset;
    if (footprint->access == 0U) {{
      if (!stage_b_native_read_allowed(start, footprint->size)) return 0U;
    }} else if (footprint->access == 1U) {{
      if (!stage_b_native_write_allowed(start, footprint->size)) return 0U;
    }} else {{
      return 0U;
    }}
    (void)end;
  }}
  return 1U;
}}

static uint32_t stage_b_native_callable_preserved(
    uint32_t mask, const stage_b_machine_state *input,
    const stage_b_machine_state *output) {{
  uint32_t index;
  for (index = 0U; index < 8U; ++index) {{
    uint32_t before, after;
    if ((mask & (1U << index)) == 0U) continue;
    if (!stage_b_native_state_register(input, index, &before) ||
        !stage_b_native_state_register(output, index, &after) || before != after)
      return 0U;
  }}
  return 1U;
}}

static stage_b_call_status stage_b_native_invoke_callable_external_jump(
    stage_b_runtime *runtime, uint32_t source_rva, uint32_t target_word,
    const stage_b_machine_state *input, stage_b_machine_state *output) {{
  uint32_t route_index;
  if (runtime != &stage_b_native_runtime_instance || input == 0 || output == 0)
    return STAGE_B_CALL_UNIMPLEMENTED;
  for (route_index = 0U;
       route_index < stage_b_native_callable_route_count; ++route_index) {{
    const stage_b_native_callable_route *route =
        &stage_b_native_callable_routes[route_index];
    stage_b_native_callable_binding *binding;
    stage_b_call_event event = {{0}};
    uint32_t arguments[64];
    uint32_t argument_index;
    stage_b_call_status status;
    if (route->source_rva != source_rva) continue;
    binding = stage_b_native_callable_binding_for(route->capability_id);
    if (binding == 0 || binding->bound == 0U ||
        binding->target_word != target_word)
      continue;
    if (route->argument_count > 64U ||
        route->argument_offset > stage_b_native_callable_argument_count ||
        route->argument_count >
            stage_b_native_callable_argument_count - route->argument_offset)
      return STAGE_B_CALL_UNIMPLEMENTED;
    for (argument_index = 0U;
         argument_index < route->argument_count; ++argument_index)
      if (!stage_b_native_callable_argument_value(
              &stage_b_native_callable_arguments[
                  route->argument_offset + argument_index],
              input, &arguments[argument_index]))
        return STAGE_B_CALL_UNIMPLEMENTED;
    if (!stage_b_native_callable_footprints_valid(route, arguments))
      return STAGE_B_CALL_UNIMPLEMENTED;
    event.kind = STAGE_B_CALL_INDIRECT;
    event.instruction_rva = route->instruction_rva;
    event.call_index = route->abi_contract_id;
    event.target_rva = target_word;
    event.arguments = arguments;
    event.argument_count = route->argument_count;
    *output = *input;
    status = stage_b_dispatch_external_call(runtime, &event, input, output);
    if (status != STAGE_B_CALL_OK) return status;
    if (input->esp > 0xffffffffU - route->stack_result_delta ||
        output->esp != input->esp + route->stack_result_delta ||
        !stage_b_native_callable_preserved(
            route->preserved_register_mask, input, output))
      return STAGE_B_CALL_UNIMPLEMENTED;
    return STAGE_B_CALL_OK;
  }}
  return STAGE_B_CALL_UNIMPLEMENTED;
}}

#ifdef STAGE_B_NATIVE_DIAGNOSTIC_FAILURE_TRAP
static void stage_b_native_trace_transfer(
    void *raw_context, uint32_t rva,
    const stage_b_machine_state *state) {{
  stage_b_native_context *context = (stage_b_native_context *)raw_context;
  stage_b_native_transfer_trace_event *event;
  uint32_t index;
  if (context != &stage_b_native_context_value || state == 0) return;
  index = context->transfer_trace_next;
  event = &context->transfer_trace_events[index];
  event->sequence = ++context->transfer_trace_sequence;
  event->rva = rva;
  event->df = state->df;
  event->esp = state->esp;
  context->transfer_trace_next =
      (index + 1U) % STAGE_B_NATIVE_MAX_TRANSFER_TRACE_EVENTS;
  if (context->transfer_trace_count < STAGE_B_NATIVE_MAX_TRANSFER_TRACE_EVENTS)
    ++context->transfer_trace_count;
}}
#endif

stage_b_runtime stage_b_native_runtime_instance = {{
  .context = &stage_b_native_context_value,
  .read = stage_b_native_flat_read,
  .write = stage_b_native_flat_write,
  .atomic_compare_exchange = stage_b_native_atomic_compare_exchange,
  .atomic_exchange = stage_b_native_atomic_exchange,
  .undefined_value = stage_b_native_undefined_value,
  .external_call_fallback = stage_b_dispatch_external_call,
#ifdef STAGE_B_NATIVE_DIAGNOSTIC_FAILURE_TRAP
  .trace_transfer = stage_b_native_trace_transfer,
#else
  .trace_transfer = 0,
#endif
  .resolve_code_target = stage_b_native_resolve_code_target{x87_initializer}
  , .invoke_callable_external_jump =
      stage_b_native_invoke_callable_external_jump
}};

static void stage_b_native_unpack_flags(stage_b_machine_state *state) {{
  uint32_t flags = state->eflags;
  state->cf = (flags >> 0) & 1U;
  state->pf = (flags >> 2) & 1U;
  state->zf = (flags >> 6) & 1U;
  state->sf = (flags >> 7) & 1U;
  state->df = (flags >> 10) & 1U;
  state->of = (flags >> 11) & 1U;
}}

static stage_b_native_terminal_kind stage_b_native_terminal_for(
    stage_b_call_status status, uint32_t undefined_fault) {{
  if (undefined_fault != 0U)
    return STAGE_B_NATIVE_TERMINAL_UNDEFINED_VALUE;
  if (status == STAGE_B_CALL_OK) return STAGE_B_NATIVE_TERMINAL_RETURNED;
  if (status == STAGE_B_CALL_DIVIDE_ERROR)
    return STAGE_B_NATIVE_TERMINAL_DIVIDE_ERROR;
  if (status == STAGE_B_CALL_MEMORY_FAULT)
    return STAGE_B_NATIVE_TERMINAL_MEMORY_FAULT;
  if (status == STAGE_B_CALL_EXTERNAL_FAULT)
    return STAGE_B_NATIVE_TERMINAL_EXTERNAL_FAULT;
  return STAGE_B_NATIVE_TERMINAL_UNIMPLEMENTED;
}}

static uint32_t stage_b_native_has_transfer(uint32_t rva) {{
  uint32_t low = 0U, high = stage_b_native_transfer_count;
  uint32_t range_low = 0U, range_high = stage_b_native_noncode_range_count;
  while (range_low < range_high) {{
    uint32_t middle = range_low + (range_high - range_low) / 2U;
    if (stage_b_native_noncode_ranges[middle].rva_end <= rva)
      range_low = middle + 1U;
    else
      range_high = middle;
  }}
  if (range_low < stage_b_native_noncode_range_count &&
      stage_b_native_noncode_ranges[range_low].rva_start <= rva &&
      rva < stage_b_native_noncode_ranges[range_low].rva_end)
    return 0U;
  while (low < high) {{
    uint32_t middle = low + (high - low) / 2U;
    if (stage_b_native_transfer_rvas[middle] < rva) low = middle + 1U;
    else high = middle;
  }}
  return low != stage_b_native_transfer_count &&
      stage_b_native_transfer_rvas[low] == rva && stage_b_program_lookup(rva) != 0;
}}

static uint32_t stage_b_native_callback_matches(
    uint32_t rva, uint32_t stack_cleanup_bytes) {{
  uint32_t i;
  for (i = 0U; i < stage_b_native_callback_abi_count; ++i)
    if (stage_b_native_callback_abis[i].rva == rva &&
        stage_b_native_callback_abis[i].stack_cleanup_bytes == stack_cleanup_bytes)
      return 1U;
  return 0U;
}}

static stage_b_call_status stage_b_native_run_initialized(
    uint32_t entry_rva, const stage_b_machine_state *input,
    stage_b_machine_state *output) {{
  stage_b_call_status status;
  stage_b_native_context *context = &stage_b_native_context_value;
  if (input == 0 || output == 0 || context->initialized == 0U ||
      !stage_b_native_has_transfer(entry_rva))
    return STAGE_B_CALL_UNIMPLEMENTED;
  *output = *input;
  stage_b_native_unpack_flags(output);
  output->original_rva = entry_rva;
  status = stage_b_run_function(
      &stage_b_native_runtime_instance, entry_rva, output, output);
  if (context->undefined_fault != 0U) {{
    stage_b_native_diagnostic_reason = 0x5001U;
    stage_b_native_diagnostic_value = context->undefined_fault_slot;
    stage_b_native_diagnostic_aux = context->undefined_fault_rva;
    stage_b_native_diagnostic_detail = entry_rva;
    return STAGE_B_CALL_UNIMPLEMENTED;
  }}
  return status;
}}

stage_b_call_status stage_b_native_runtime_run_at_rva(
    uint32_t entry_rva, const stage_b_machine_state *input,
    stage_b_machine_state *output) {{
  stage_b_call_status status = STAGE_B_CALL_UNIMPLEMENTED;
  stage_b_native_context *context = &stage_b_native_context_value;
  uint32_t i;
  if (input == 0 || output == 0) return STAGE_B_CALL_UNIMPLEMENTED;
  *output = *input;
  if (__sync_lock_test_and_set(&context->active, 1U) != 0U) {{
    return STAGE_B_CALL_UNIMPLEMENTED;
  }}
  context->initialized = 0U;
  context->undefined_fault = 0U;
  context->undefined_fault_slot = 0U;
  context->undefined_fault_rva = 0U;
  context->last_undefined_fault = 0U;
  context->nested_depth = 0U;
  if (!stage_b_native_validate_image(context) ||
      !stage_b_native_validate_stack(context, input) ||
      !stage_b_native_transfer_table_valid() || !stage_b_native_has_transfer(entry_rva))
    goto release;
  if (context->process_world_initialized == 0U) {{
    context->external_range_count = 0U;
    context->external_lifecycle_count = 0U;
    context->external_lifecycle_next = 0U;
    context->external_lifecycle_sequence = 0U;
    context->external_trace_count = 0U;
    context->external_trace_next = 0U;
    context->external_trace_sequence = 0U;
    context->transfer_trace_count = 0U;
    context->transfer_trace_next = 0U;
    context->transfer_trace_sequence = 0U;
    for (i = 0U; i < stage_b_native_callable_resolver_count; ++i) {{
      context->callable_bindings[i].capability_id =
          stage_b_native_callable_resolvers[i].capability_id;
      context->callable_bindings[i].target_word = 0U;
      context->callable_bindings[i].bound = 0U;
    }}
    context->process_world_initialized = 1U;
  }}
  context->owner_fs_base = input->fs_base;
  context->initialized = 1U;
  status = stage_b_native_run_initialized(entry_rva, input, output);
release:
  context->last_undefined_fault = context->undefined_fault;
  context->owner_fs_base = 0U;
  context->nested_depth = 0U;
  context->initialized = 0U;
  __sync_lock_release(&context->active);
  return status;
}}

stage_b_call_status stage_b_native_runtime_run_nested_callback(
    uint32_t callback_rva, uint32_t stack_cleanup_bytes,
    const stage_b_machine_state *input, stage_b_machine_state *output) {{
  stage_b_call_status status;
  stage_b_native_context *context = &stage_b_native_context_value;
  if (input == 0 || output == 0 || context->active != 1U ||
      context->initialized == 0U || input->fs_base != context->owner_fs_base ||
      context->nested_depth == 0xffffffffU ||
      !stage_b_native_callback_matches(callback_rva, stack_cleanup_bytes))
    return STAGE_B_CALL_UNIMPLEMENTED;
  ++context->nested_depth;
  status = stage_b_native_run_initialized(callback_rva, input, output);
  --context->nested_depth;
  if (status == STAGE_B_CALL_OK &&
      output->esp != input->esp + 4U + stack_cleanup_bytes)
    return STAGE_B_CALL_UNIMPLEMENTED;
  return status;
}}

stage_b_call_status stage_b_native_runtime_run_captured(
    const stage_b_machine_state *captured, stage_b_machine_state *output) {{
  stage_b_native_context *context = &stage_b_native_context_value;
  stage_b_call_status status;
  stage_b_native_terminal_call_status = STAGE_B_CALL_UNIMPLEMENTED;
  stage_b_native_terminal_status = STAGE_B_NATIVE_TERMINAL_UNIMPLEMENTED;
  if (captured == 0 || output == 0) return STAGE_B_CALL_UNIMPLEMENTED;
  status = stage_b_native_runtime_run_at_rva(
      0x{plan.entry_rva:08x}U, captured, output);
  stage_b_native_terminal_call_status = status;
  stage_b_native_terminal_status = stage_b_native_terminal_for(
      status, context->last_undefined_fault);
  stage_b_native_terminal_state = *output;
  return status;
}}

void stage_b_native_runtime_coordinate(
    const stage_b_machine_state *captured) {{
  stage_b_machine_state output;
  stage_b_call_status status =
      stage_b_native_runtime_run_captured(captured, &output);
  stage_b_native_terminal_call_status = status;
  if (captured != 0) stage_b_native_terminal_state = output;
  stage_b_native_terminate(stage_b_native_terminal_status);
}}
'''


def _manifest_path(
    value: Path | str, filename: str, label: str
) -> Path:
    path = Path(value)
    if path.is_dir():
        path = path / filename
    if not path.is_file():
        raise StageBNativeRuntimeError(f"{label} manifest does not exist: {path}")
    return path


def _bound_artifact(root: Path, value: dict[str, Any], label: str) -> Path:
    name = _required_relative_path(value.get("path"), f"{label} path")
    expected = _required_sha256(value.get("sha256"), f"{label} SHA-256")
    path = root / name
    if not path.is_file():
        raise StageBNativeRuntimeError(f"{label} does not exist: {path}")
    if sha256_file(path) != expected:
        raise StageBNativeRuntimeError(f"{label} SHA-256 mismatch")
    return path


def _verify_artifact_inventory(
    root: Path, value: Any, label: str, *, require_role: bool
) -> dict[str, Path]:
    rows = _required_list(value, f"{label} inventory")
    if not rows:
        raise StageBNativeRuntimeError(f"{label} inventory is empty")
    seen: set[str] = set()
    result: dict[str, Path] = {}
    for index, raw in enumerate(rows):
        row = _required_object(raw, f"{label} {index}")
        key: str
        if require_role:
            key = _required_string(row.get("role"), f"{label} {index} role")
            if key in result:
                raise StageBNativeRuntimeError(
                    f"{label} inventory has duplicate roles"
                )
        name = _required_relative_path(row.get("path"), f"{label} {index} path")
        if name in seen:
            raise StageBNativeRuntimeError(f"{label} inventory has duplicate paths")
        seen.add(name)
        path = _bound_artifact(root, row, f"{label} {index}")
        result[key if require_role else name] = path
    return result


def _read_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StageBNativeRuntimeError(f"cannot read {label}: {path}") from exc
    return _required_object(value, label)


def _required_object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise StageBNativeRuntimeError(f"{field} must be an object")
    return value


def _required_list(value: Any, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise StageBNativeRuntimeError(f"{field} must be a list")
    return value


def _required_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise StageBNativeRuntimeError(f"{field} must be a non-empty string")
    return value


def _required_portable_identity(value: Any, field: str) -> str:
    text = _required_string(value, field)
    try:
        encoded = text.encode("ascii")
    except UnicodeEncodeError as exc:
        raise StageBNativeRuntimeError(f"{field} must be printable ASCII") from exc
    if any(byte < 0x20 or byte > 0x7E for byte in encoded):
        raise StageBNativeRuntimeError(f"{field} must be printable ASCII")
    return text


def _required_relative_path(value: Any, field: str) -> str:
    text = _required_string(value, field)
    path = Path(text)
    if path.is_absolute() or ".." in path.parts or len(path.parts) != 1:
        raise StageBNativeRuntimeError(f"{field} must be a local artifact name")
    return text


def _required_sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise StageBNativeRuntimeError(f"{field} must be a lowercase SHA-256")
    return value


def _required_u32(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**32:
        raise StageBNativeRuntimeError(f"{field} must be a 32-bit unsigned integer")
    return value


def _required_count(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise StageBNativeRuntimeError(f"{field} must be a nonnegative integer")
    return value


__all__ = [
    "DEFINEDNESS_USE_FORMAT",
    "NATIVE_RUNTIME_HEADER_FILENAME",
    "NATIVE_RUNTIME_MANIFEST_FILENAME",
    "NATIVE_RUNTIME_PACKAGE_FORMAT",
    "NATIVE_RUNTIME_SOURCE_FILENAME",
    "NativeRuntimePlan",
    "NativeUndefinedPolicy",
    "StageBNativeRuntimeError",
    "plan_stage_b_native_runtime",
    "write_stage_b_native_runtime_package",
]

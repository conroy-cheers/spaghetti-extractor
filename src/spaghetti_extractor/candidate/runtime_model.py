"""Data model and constants for candidate reconstruction native runtime generation."""

from __future__ import annotations

from ..external.range_release import RangeRelease
from ..external.range_ownership import RangeOwnership
from ..external.range_allocation import RangeAllocation

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..errors import ToolkitInputError
from ..transfer.formats import TRANSFER_DEFINEDNESS_USE_FORMAT


NATIVE_RUNTIME_HEADER_FILENAME = "shared-module-runtime.h"
NATIVE_RUNTIME_SOURCE_FILENAME = "shared-module-runtime.c"
NATIVE_RUNTIME_BINDINGS_FILENAME = "shared-module-runtime-bindings.c"
NATIVE_RUNTIME_MANIFEST_FILENAME = "shared-module-runtime-package.json"
NATIVE_RUNTIME_EXTERNAL_PROFILE_FILENAME = "external-environment-profile.json"
NATIVE_RUNTIME_OBJECT_AUTHORITY_FILENAME = "machine-object-authority.json"
DEFINEDNESS_USE_FORMAT = TRANSFER_DEFINEDNESS_USE_FORMAT

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_MACHINE_IR_INPUT_MODE = "sanitized_machine_ir_v3"
_TRANSFER_PLAN_INPUT_MODE = "executable_transfer_plan_v2"
INTERFACE_METHOD_TARGET_TAG = 0x80000000


class CandidateRuntimeError(ToolkitInputError):
    """A native-runtime package input failed closed validation."""


def loader_target_catalog(
    domains: Iterable["NativeGuestDispatchDomain"],
) -> tuple[tuple[dict[str, Any], ...], dict[str, int]]:
    """Return the one content-addressed checked loader-code catalog."""

    by_sha256: dict[str, dict[str, Any]] = {}
    for domain in domains:
        for raw in domain.external_loader_targets:
            target = dict(raw)
            identity = target.get("identity")
            if not isinstance(identity, Mapping):
                raise CandidateRuntimeError(
                    "runtime callable domain has a malformed external identity"
                )
            dll = identity.get("dll")
            symbol = identity.get("symbol")
            ordinal = identity.get("ordinal")
            if (
                not isinstance(dll, str)
                or not dll
                or (
                    (not isinstance(symbol, str) or not symbol)
                    == (
                        not isinstance(ordinal, int)
                        or isinstance(ordinal, bool)
                        or not 0 <= ordinal <= 0xFFFF
                    )
                )
            ):
                raise CandidateRuntimeError(
                    "runtime callable domain has a malformed external identity"
                )
            digest = canonical_sha256_v3(target)
            prior = by_sha256.get(digest)
            if prior is not None and prior != target:
                raise CandidateRuntimeError(
                    "runtime loader-target content identity is ambiguous"
                )
            by_sha256[digest] = target
    ordered_sha256s = sorted(by_sha256)
    return (
        tuple(by_sha256[digest] for digest in ordered_sha256s),
        {digest: index + 1 for index, digest in enumerate(ordered_sha256s)},
    )


def interface_method_target_catalog(
    domains: Iterable["NativeGuestDispatchDomain"],
) -> tuple[tuple[dict[str, Any], ...], dict[str, int]]:
    """Return the one content-addressed checked interface-method catalog."""

    by_sha256: dict[str, dict[str, Any]] = {}
    for domain in domains:
        for raw in domain.external_interface_targets:
            target = dict(raw)
            declared = target.get("method_contract_sha256")
            core = {
                key: value for key, value in target.items()
                if key != "method_contract_sha256"
            }
            if (
                not isinstance(declared, str)
                or declared != canonical_sha256_v3(core)
            ):
                raise CandidateRuntimeError(
                    "runtime interface-method target identity is stale"
                )
            prior = by_sha256.get(declared)
            if prior is not None and prior != target:
                raise CandidateRuntimeError(
                    "runtime interface-method target identity is ambiguous"
                )
            by_sha256[declared] = target
    ordered = sorted(by_sha256)
    return (
        tuple(by_sha256[digest] for digest in ordered),
        {digest: index + 1 for index, digest in enumerate(ordered)},
    )


def interface_class_catalog(
    domains: Iterable["NativeGuestDispatchDomain"],
) -> tuple[tuple[tuple[str, str, str], ...], dict[tuple[str, str], int]]:
    """Return stable profile/interface classes admitted by callable domains."""

    classes: dict[tuple[str, str], str] = {}
    for target in interface_method_target_catalog(domains)[0]:
        profile_id = target.get("profile_id")
        profile_sha256 = target.get("profile_sha256")
        interface_id = target.get("interface_id")
        if not all(isinstance(value, str) and value for value in (
            profile_id, profile_sha256, interface_id,
        )):
            raise CandidateRuntimeError(
                "runtime interface-method class identity is malformed"
            )
        key = (str(profile_sha256), str(interface_id))
        prior = classes.get(key)
        if prior is not None and prior != profile_id:
            raise CandidateRuntimeError(
                "runtime interface-method class identity is ambiguous"
            )
        classes[key] = str(profile_id)
    ordered = tuple(
        (profile_sha256, interface_id, classes[(profile_sha256, interface_id)])
        for profile_sha256, interface_id in sorted(classes)
    )
    return ordered, {
        (profile_sha256, interface_id): index + 1
        for index, (profile_sha256, interface_id, _profile_id) in enumerate(ordered)
    }


@dataclass(frozen=True)
class _TransferBinding:
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
            "generated_behavioral_c": 0,
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
    target_catalog_index: int | None
    interface_class_index: int | None
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
    release: RangeRelease | None = None
    contract_identity_sha256: str | None = None
    ownership: RangeOwnership | None = None
    allocation: RangeAllocation | None = None

    def payload(self) -> dict[str, Any]:
        return {
            "instruction_rva": self.instruction_rva,
            "target_iat_rva": self.target_iat_rva,
            "target_catalog_index": self.target_catalog_index,
            "interface_class_index": self.interface_class_index,
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
            "contract_identity_sha256": self.contract_identity_sha256,
            **({"allocation": self.allocation.payload()} if self.allocation is not None else {}),
            **({"ownership": self.ownership.payload()} if self.ownership is not None else {}),
            **({"release": self.release.payload()} if self.release is not None else {}),
        }


@dataclass(frozen=True)
class NativeGuestDispatchDomain:
    """One shared finite admitted dispatch domain.

    The historical class name remains internal during the V4 clean cut, but a
    callable V2 contract carries both guest capabilities and checked
    loader-written external targets.  Consumers must use this same contract;
    they may not derive a parallel external-target inventory.
    """

    domain_sha256: str
    contract: dict[str, Any]
    authority: str

    @property
    def target_rvas(self) -> tuple[int, ...]:
        raw = self.contract.get(
            "guest_transfer_entry_rvas", self.contract.get("targets", ())
        )
        return tuple(raw)

    @property
    def external_loader_targets(self) -> tuple[dict[str, Any], ...]:
        raw = self.contract.get("external_loader_targets", ())
        return tuple(dict(row) for row in raw)

    @property
    def external_interface_targets(self) -> tuple[dict[str, Any], ...]:
        raw = self.contract.get("external_interface_targets", ())
        return tuple(dict(row) for row in raw)

    def payload(self) -> dict[str, Any]:
        return {
            "domain_sha256": self.domain_sha256,
            "contract": dict(self.contract),
            "authority": self.authority,
        }


@dataclass(frozen=True)
class NativeGuestDispatchSite:
    """One computed guest control-transfer site bound to a shared domain."""

    site: str
    kind: str
    source_rva: int
    instruction_rva: int | None
    event_index: int | None
    domain_sha256: str

    @property
    def kind_code(self) -> int:
        return {"indirect_call": 0, "indirect_jump": 1}[self.kind]

    def payload(self) -> dict[str, Any]:
        return {
            "site": self.site,
            "kind": self.kind,
            "source_rva": self.source_rva,
            "instruction_rva": self.instruction_rva,
            "event_index": self.event_index,
            "domain_sha256": self.domain_sha256,
        }


@dataclass(frozen=True)
class NativeNonlocalTransition:
    """One closure-authorized transfer to an active ancestor call frame."""

    identity: str
    source_rva: int
    target_rva: int
    target_function_entry_rva: int

    def payload(self) -> dict[str, Any]:
        return {
            "id": self.identity,
            "source_rva": self.source_rva,
            "target_rva": self.target_rva,
            "target_function_entry_rva": self.target_function_entry_rva,
        }


@dataclass(frozen=True)
class NativeObjectAuthorityRule:
    """One exact runtime realization of a machine-object-authority-v2 rule."""

    identity: str
    domain: int
    object_id: int
    generation: int
    extent: int
    permissions: int
    lifetime: str
    locator_kind: str
    locator_identity: str
    locator_offset: int
    locator_subject_rva: int
    interior_pointers: bool
    extent_mode: str = "fixed"

    @property
    def extent_mode_code(self) -> int:
        if self.extent_mode == "fixed":
            return 0
        if self.extent_mode == "instance_remainder" and self.locator_kind in {"external_allocation", "resource"}:
            return 1
        raise CandidateRuntimeError("native object authority extent mode is invalid")

    @property
    def locator_code(self) -> int:
        return {
            "image_rva": 1,
            "tls_offset": 2,
            "resolved_data_import": 3,
            "captured_stack": 4,
            "external_allocation": 5,
            "resource": 6,
        }.get(self.locator_kind, 0)

    def payload(self) -> dict[str, Any]:
        return {
            "id": self.identity,
            "domain": self.domain,
            "object": self.object_id,
            "generation": self.generation,
            "extent": self.extent,
            "permissions": self.permissions,
            "lifetime": self.lifetime,
            "locator": {
                "kind": self.locator_kind,
                "identity": self.locator_identity,
                "offset": self.locator_offset,
                "subject_rva": self.locator_subject_rva,
            },
            "interior_pointers": self.interior_pointers,
            **({"extent_mode": self.extent_mode} if self.extent_mode != "fixed" else {}),
        }


@dataclass(frozen=True)
class SharedModuleRuntimePlan:
    """Checked immutable inputs used to render one native runtime."""

    transfer_rvas: tuple[int, ...]
    guest_dispatch_domains: tuple[NativeGuestDispatchDomain, ...]
    guest_dispatch_sites: tuple[NativeGuestDispatchSite, ...]
    nonlocal_transitions: tuple[NativeNonlocalTransition, ...]
    recovered_executable_data_ranges: tuple[tuple[int, int], ...]
    implementation_dispatch_receipt: dict[str, Any]
    implementation_dispatches: tuple[NativeImplementationDispatch, ...]
    external_range_rules: tuple[NativeExternalRangeRule, ...]
    authorized_external_site_rvas: tuple[int, ...]
    blocked_external_sites: tuple[dict[str, Any], ...]
    external_profile_path: Path | None
    external_profile_sha256: str | None
    external_profile_graph: tuple[tuple[Path, str, str], ...]
    undefined_policies: tuple[NativeUndefinedPolicy, ...]
    definedness_metadata_sha256: str | None
    state_machine_sha256: str
    semantic_backend_kind: str
    semantic_backend_manifest_path: Path
    semantic_backend_manifest_sha256: str
    executable_plan_path: Path
    executable_plan_sha256: str
    module_runtime_plan_path: Path
    module_runtime_plan_sha256: str
    native_ingress_plan_path: Path
    native_ingress_plan_sha256: str
    ingress_descriptors: tuple[dict[str, Any], ...]
    ingress_tls_layout: dict[str, Any]
    ingress_runtime_features: tuple[str, ...]
    x87_handler_mode: str
    has_modeled_termination: bool
    execution_closure_path: Path | None
    execution_closure_sha256: str
    linked_semantic_module_sha256: str | None
    resolved_environment_path: Path
    resolved_environment_sha256: str
    object_authority_path: Path
    object_authority_sha256: str
    object_authority_id: str
    object_authority_rules: tuple[NativeObjectAuthorityRule, ...]
    object_authority_blockers: tuple[dict[str, Any], ...]

    @property
    def has_typed_x87_handler(self) -> bool:
        return self.x87_handler_mode == "typed"

    def payload(self) -> dict[str, Any]:
        return {
            "transfer_rvas": list(self.transfer_rvas),
            "guest_dispatch": {
                "policy": "content_addressed_admitted_domains_v2",
                "unknown_site": "fail_closed",
                "domains": [
                    domain.payload() for domain in self.guest_dispatch_domains
                ],
                "sites": [site.payload() for site in self.guest_dispatch_sites],
            },
            "nonlocal_control": {
                "policy": "exact_active_ancestor_transition_v1",
                "unknown_transition": "fail_closed",
                "transitions": [
                    transition.payload()
                    for transition in self.nonlocal_transitions
                ],
            },
            "recovered_executable_data_ranges": [
                {"rva_start": start, "rva_end": end}
                for start, end in self.recovered_executable_data_ranges
            ],
            "implementation_dispatch_receipt": dict(
                self.implementation_dispatch_receipt
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
            "definedness_use": {
                "format": DEFINEDNESS_USE_FORMAT,
                "metadata_sha256": self.definedness_metadata_sha256,
                "candidate_witness_scope": (
                    "candidate-only; static analysis must separately prove the original/candidate "
                    "undefined-value relation"
                ),
                "slots": [policy.payload() for policy in self.undefined_policies],
            },
            "state_machine_sha256": self.state_machine_sha256,
            "semantic_backend": {
                "kind": self.semantic_backend_kind,
                "manifest": self.semantic_backend_manifest_path.name,
                "manifest_sha256": self.semantic_backend_manifest_sha256,
            },
            "executable_plan": {
                "path": self.executable_plan_path.name,
                "sha256": self.executable_plan_sha256,
            },
            "module_runtime_plan": {
                "path": self.module_runtime_plan_path.name,
                "sha256": self.module_runtime_plan_sha256,
            },
            "native_ingress_plan": {
                "path": self.native_ingress_plan_path.name,
                "sha256": self.native_ingress_plan_sha256,
                "ingresses": [dict(row) for row in self.ingress_descriptors],
                "tls_layout": dict(self.ingress_tls_layout),
                "runtime_features": list(self.ingress_runtime_features),
            },
            "canonical_inputs": {
                **({
                    "linked_semantic_module": {
                        "sha256": self.linked_semantic_module_sha256,
                        **({
                            "source_execution_closure_sha256": (
                                self.execution_closure_sha256
                            ),
                        } if self.execution_closure_sha256 != (
                            self.linked_semantic_module_sha256
                        ) else {}),
                    },
                } if self.linked_semantic_module_sha256 is not None else {
                    "module_execution_closure": {
                        "path": self.execution_closure_path.name,
                        "sha256": self.execution_closure_sha256,
                    },
                }),
                "resolved_external_environment": {
                    "path": self.resolved_environment_path.name,
                    "sha256": self.resolved_environment_sha256,
                },
                "machine_object_authority": {
                    "path": NATIVE_RUNTIME_OBJECT_AUTHORITY_FILENAME,
                    "sha256": self.object_authority_sha256,
                    "authority_sha256": self.object_authority_id,
                    "rules": [
                        rule.payload() for rule in self.object_authority_rules
                    ],
                },
            },
            "runtime_abi": {
                "atomic_compare_exchange_handler": True,
                "atomic_exchange_handler": True,
                "typed_native_x87_handler": self.has_typed_x87_handler,
                "modeled_environment_termination":
                    self.has_modeled_termination,
            },
        }

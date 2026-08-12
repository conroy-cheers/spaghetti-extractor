"""Exact-artifact authority for PE32 external-call profiles.

Profile IDs and hashes copied into a recovered call target are only claims.  This
module constructs an immutable index from the actual profile bytes and replays a
checked external-site contract against the selected entry.  The index is generic
across the external target families understood by the reconstruction pipeline;
it does not inspect target-specific source code or runtime traces.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Mapping, Sequence

from .checked_external_site_contract import (
    CheckedExternalSiteContract,
    CheckedExternalSiteContractError,
    ExternalSiteIdentity,
    parse_checked_external_site_contract,
    require_profile_match,
)
from .external_capabilities import (
    CALLABLE_EXTERNAL_PROFILE_FORMAT,
    CallableExternalProfile,
    load_callable_external_profile,
)
from .external_interface_profiles import (
    EXTERNAL_INTERFACE_PROFILE_FORMAT,
    ExternalInterfaceProfile,
    load_external_interface_profile,
)
from .external_operation_profiles import (
    EXTERNAL_OPERATION_PROFILE_FORMAT,
    CallbackSelector,
    ExternalOperationProfile,
    load_external_operation_profile,
)
from .machine_import_profiles import (
    MACHINE_IMPORT_PROFILE_FORMATS,
    MachineImportProfileSet,
    SelectedMachineImportContract,
    load_machine_import_profile_set,
)


EXTERNAL_PROFILE_AUTHORITY_V2_FORMAT = (
    "spaghetti-extractor-external-profile-authority-v2"
)
ExternalProfileFamily = Literal[
    "machine_import",
    "interface_factory",
    "interface_method",
    "external_operation",
    "callable_resolver",
    "callable_target",
    "callback",
]
ReplayStatus = Literal["complete", "incomplete", "violated"]


class ExternalProfileAuthorityV2Error(ValueError):
    """Exact external-profile evidence is malformed or ambiguous."""


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise ExternalProfileAuthorityV2Error(
            "external-profile evidence is not canonical JSON"
        ) from exc


def _canonical_value(value: Any) -> Any:
    return json.loads(_canonical_bytes(value))


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _nonempty(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ExternalProfileAuthorityV2Error(f"{context} must be nonempty")
    return value


@dataclass(frozen=True)
class ExactExternalProfileArtifact:
    """One immutable profile artifact, including the exact bytes that were parsed."""

    source: str
    format: str
    profile_id: str
    artifact_sha256: str
    exact_bytes: bytes

    def __post_init__(self) -> None:
        _nonempty(self.source, "external-profile source")
        _nonempty(self.format, "external-profile format")
        _nonempty(self.profile_id, "external-profile id")
        if not _digest(self.artifact_sha256):
            raise ExternalProfileAuthorityV2Error(
                "external-profile artifact digest is malformed"
            )
        if _sha256(self.exact_bytes) != self.artifact_sha256:
            raise ExternalProfileAuthorityV2Error(
                "external-profile artifact digest does not bind its exact bytes"
            )

    def payload(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "format": self.format,
            "profile_id": self.profile_id,
            "artifact_sha256": self.artifact_sha256,
            "exact_bytes_base64": base64.b64encode(self.exact_bytes).decode("ascii"),
        }


@dataclass(frozen=True)
class ExternalProfileEntry:
    """One deterministic, profile-controlled call-boundary contract."""

    entry_id: str
    family: ExternalProfileFamily
    profile_id: str
    profile_sha256: str
    artifact_sha256: str
    entry_key: str
    entry_index: int
    identity_json: str
    contract_json: str
    allowed_transfers: tuple[str, ...]
    complete: bool
    failure_reason: str | None = None

    def __post_init__(self) -> None:
        if not _digest(self.entry_id):
            raise ExternalProfileAuthorityV2Error("profile entry ID is malformed")
        _nonempty(self.profile_id, "profile entry profile id")
        if not _digest(self.profile_sha256) or not _digest(self.artifact_sha256):
            raise ExternalProfileAuthorityV2Error(
                "profile entry has a malformed artifact binding"
            )
        _nonempty(self.entry_key, "profile entry key")
        if self.entry_index < 0:
            raise ExternalProfileAuthorityV2Error(
                "profile entry index must be nonnegative"
            )
        if not self.allowed_transfers or any(
            transfer not in {"call", "jump"} for transfer in self.allowed_transfers
        ):
            raise ExternalProfileAuthorityV2Error(
                "profile entry transfer inventory is malformed"
            )
        if self.complete == (self.failure_reason is not None):
            raise ExternalProfileAuthorityV2Error(
                "profile entry completion and failure reason disagree"
            )
        # Reject noncanonical or non-object serialized contracts at construction.
        if not isinstance(json.loads(self.identity_json), Mapping):
            raise ExternalProfileAuthorityV2Error("profile entry identity is malformed")
        if not isinstance(json.loads(self.contract_json), Mapping):
            raise ExternalProfileAuthorityV2Error("profile entry contract is malformed")

    @property
    def identity(self) -> Mapping[str, Any]:
        value = json.loads(self.identity_json)
        assert isinstance(value, Mapping)
        return value

    @property
    def contract(self) -> Mapping[str, Any]:
        value = json.loads(self.contract_json)
        assert isinstance(value, Mapping)
        return value

    @property
    def profile_binding(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "profile_id": self.profile_id,
            "profile_sha256": self.profile_sha256,
        }
        if self.family == "machine_import":
            result.update({
                "entry_key": self.entry_key,
                "entry_index": self.entry_index,
            })
        receiver_resource = self.contract.get("receiver_resource")
        if receiver_resource is not None:
            result["receiver_resource"] = _canonical_value(receiver_resource)
        return result

    def payload(self) -> dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "family": self.family,
            "profile_id": self.profile_id,
            "profile_sha256": self.profile_sha256,
            "artifact_sha256": self.artifact_sha256,
            "entry_key": self.entry_key,
            "entry_index": self.entry_index,
            "identity": _canonical_value(self.identity),
            "contract": _canonical_value(self.contract),
            "allowed_transfers": list(self.allowed_transfers),
            "complete": self.complete,
            "failure_reason": self.failure_reason,
        }


@dataclass(frozen=True)
class ExternalProfileReplayResult:
    status: ReplayStatus
    reason_code: str | None
    message: str | None
    entry: ExternalProfileEntry | None


@dataclass(frozen=True)
class ExternalProfileAuthorityV2:
    artifacts: tuple[ExactExternalProfileArtifact, ...]
    entries: tuple[ExternalProfileEntry, ...]
    root_sources: tuple[str, ...]
    authority_id: str

    def __post_init__(self) -> None:
        artifact_ids = [artifact.artifact_sha256 for artifact in self.artifacts]
        if len(artifact_ids) != len(set(artifact_ids)):
            raise ExternalProfileAuthorityV2Error(
                "external-profile artifacts are duplicated"
            )
        entry_ids = [entry.entry_id for entry in self.entries]
        if len(entry_ids) != len(set(entry_ids)):
            raise ExternalProfileAuthorityV2Error(
                "external-profile entry identities are duplicated"
            )
        artifacts = set(artifact_ids)
        if any(entry.artifact_sha256 not in artifacts for entry in self.entries):
            raise ExternalProfileAuthorityV2Error(
                "external-profile entry references an absent exact artifact"
            )
        sources = {artifact.source for artifact in self.artifacts}
        if (
            not self.root_sources
            or len(self.root_sources) != len(set(self.root_sources))
            or any(source not in sources for source in self.root_sources)
        ):
            raise ExternalProfileAuthorityV2Error(
                "external-profile root source inventory is malformed"
            )
        expected = _sha256(_canonical_bytes({
            "format": EXTERNAL_PROFILE_AUTHORITY_V2_FORMAT,
            "root_sources": list(self.root_sources),
            "artifacts": [artifact.payload() for artifact in self.artifacts],
            "entries": [entry.payload() for entry in self.entries],
        }))
        if self.authority_id != expected:
            raise ExternalProfileAuthorityV2Error(
                "external-profile authority ID does not replay"
            )

    def payload(self) -> dict[str, Any]:
        return {
            "format": EXTERNAL_PROFILE_AUTHORITY_V2_FORMAT,
            "authority_id": self.authority_id,
            "root_sources": list(self.root_sources),
            "artifacts": [artifact.payload() for artifact in self.artifacts],
            "entries": [entry.payload() for entry in self.entries],
        }

    def replay_lookup(
        self,
        site: CheckedExternalSiteContract | Mapping[str, Any],
        *,
        context: str = "checked external site",
    ) -> ExternalProfileReplayResult:
        """Replay one site's profile-controlled fields against exact bytes."""

        if isinstance(site, Mapping) and site.get("abi_template") is None:
            return ExternalProfileReplayResult(
                "incomplete",
                "external_site_abi_missing",
                "site has no exact machine ABI template",
                None,
            )
        try:
            contract = (
                site
                if isinstance(site, CheckedExternalSiteContract)
                else parse_checked_external_site_contract(site, context=context)
            )
        except CheckedExternalSiteContractError as exc:
            return ExternalProfileReplayResult(
                "violated", "external_site_contract_corrupt", str(exc), None
            )
        binding = contract.profile_binding
        if not isinstance(binding, Mapping):
            return ExternalProfileReplayResult(
                "incomplete", "external_profile_binding_missing",
                "site has no exact external-profile binding", None,
            )
        profile_id = binding.get("profile_id")
        profile_sha256 = binding.get("profile_sha256")
        if not isinstance(profile_id, str) or not profile_id or not _digest(profile_sha256):
            return ExternalProfileReplayResult(
                "incomplete", "external_profile_binding_missing",
                "site has no complete profile id and digest", None,
            )
        same_id = [entry for entry in self.entries if entry.profile_id == profile_id]
        exact_profile = [
            entry for entry in same_id if entry.profile_sha256 == profile_sha256
        ]
        if not exact_profile:
            if same_id:
                return ExternalProfileReplayResult(
                    "violated", "external_profile_hash_mismatch",
                    "site profile digest differs from the indexed exact artifact", None,
                )
            return ExternalProfileReplayResult(
                "incomplete", "external_profile_evidence_missing",
                "no exact profile artifact is indexed for this site", None,
            )

        entry_key = binding.get("entry_key")
        entry_index = binding.get("entry_index")
        if entry_key is not None or entry_index is not None:
            if (
                not isinstance(entry_key, str)
                or not isinstance(entry_index, int)
                or isinstance(entry_index, bool)
                or entry_index < 0
            ):
                return ExternalProfileReplayResult(
                    "violated", "external_profile_entry_binding_corrupt",
                    "site profile entry key/index is malformed", None,
                )
            selected = [
                entry for entry in exact_profile
                if entry.entry_key == entry_key and entry.entry_index == entry_index
            ]
            if not selected:
                return ExternalProfileReplayResult(
                    "violated", "external_profile_entry_mismatch",
                    "site names an entry absent from the exact profile artifact", None,
                )
        else:
            site_identity = _canonical_bytes(contract.identity.payload())
            selected = [
                entry for entry in exact_profile
                if _canonical_bytes(entry.identity) == site_identity
            ]
            if contract.identity.operation:
                selected = [
                    entry for entry in selected
                    if entry.contract.get("contract_id") == contract.contract_id
                    or entry.identity.get("operation") == contract.identity.operation
                ]

        selected = [
            entry for entry in selected
            if contract.transfer_kind in entry.allowed_transfers
        ]
        if not selected:
            return ExternalProfileReplayResult(
                "violated", "external_profile_identity_mismatch",
                "site identity or transfer is absent from the selected profile entry", None,
            )
        if len(selected) != 1:
            return ExternalProfileReplayResult(
                "violated", "external_profile_entry_ambiguous",
                "site matches multiple entries in the exact profile index", None,
            )
        entry = selected[0]
        if not entry.complete:
            return ExternalProfileReplayResult(
                "incomplete", "external_profile_entry_incomplete",
                entry.failure_reason, entry,
            )
        try:
            _require_entry_match(contract, entry, context=context)
        except CheckedExternalSiteContractError as exc:
            return ExternalProfileReplayResult(
                "violated", "external_profile_contract_mismatch", str(exc), entry
            )
        return ExternalProfileReplayResult("complete", None, None, entry)


def _identity_payload(
    *,
    kind: str,
    dll: str | None = None,
    symbol: str | None = None,
    ordinal: int | None = None,
    protocol: str | None = None,
    profile_id: str | None = None,
    profile_sha256: str | None = None,
    operation: str | None = None,
) -> dict[str, Any]:
    return ExternalSiteIdentity(
        kind=kind,
        dll=dll,
        symbol=symbol,
        ordinal=ordinal,
        protocol=protocol,
        profile_id=profile_id,
        profile_sha256=profile_sha256,
        operation=operation,
    ).payload()


def _import_identity(identity: Any) -> dict[str, Any]:
    return _identity_payload(
        kind="import",
        dll=identity.dll,
        symbol=str(identity.value) if identity.kind == "symbol" else None,
        ordinal=int(identity.value) if identity.kind == "ordinal" else None,
    )


def _profile_contract(
    *,
    identity: Mapping[str, Any],
    contract_id: str,
    abi_template: Any,
    argument_words: Any,
    profile_binding: Mapping[str, Any],
    disposition: Any = "returns",
    result_register_relations: Any = (),
    memory_effect: Any,
    memory_footprints: Any = (),
    world_effect: Any,
    callback_effect: Any,
    out_pointer_relations: Any = (),
    out_interface_relations: Any = (),
    receiver_resource: Any = None,
    callback_profile: Any = None,
    source_contract: Any = None,
) -> dict[str, Any]:
    result = {
        "identity": identity,
        "contract_id": contract_id,
        "abi_template": abi_template,
        "argument_words": argument_words,
        "profile_disposition": disposition,
        "profile_binding": profile_binding,
        "result_register_relations": list(result_register_relations),
        "memory_effect": memory_effect,
        "memory_footprints": list(memory_footprints),
        "world_effect": world_effect,
        "callback_effect": callback_effect,
        "out_pointer_relations": list(out_pointer_relations),
        "out_interface_relations": list(out_interface_relations),
        "callback_profile": callback_profile,
        "source_contract": source_contract,
    }
    if receiver_resource is not None:
        result["receiver_resource"] = receiver_resource
    return _canonical_value(result)


def _entry(
    *,
    family: ExternalProfileFamily,
    profile_id: str,
    profile_sha256: str,
    artifact_sha256: str,
    entry_key: str,
    entry_index: int,
    identity: Mapping[str, Any],
    contract: Mapping[str, Any],
    allowed_transfers: Sequence[str] = ("call",),
    complete: bool = True,
    failure_reason: str | None = None,
) -> ExternalProfileEntry:
    body = {
        "family": family,
        "profile_id": profile_id,
        "profile_sha256": profile_sha256,
        "artifact_sha256": artifact_sha256,
        "entry_key": entry_key,
        "entry_index": entry_index,
        "identity": identity,
        "contract": contract,
        "allowed_transfers": sorted(set(allowed_transfers)),
        "complete": complete,
        "failure_reason": failure_reason,
    }
    return ExternalProfileEntry(
        entry_id=_sha256(_canonical_bytes(body)),
        family=family,
        profile_id=profile_id,
        profile_sha256=profile_sha256,
        artifact_sha256=artifact_sha256,
        entry_key=entry_key,
        entry_index=entry_index,
        identity_json=_canonical_bytes(identity).decode("ascii"),
        contract_json=_canonical_bytes(contract).decode("ascii"),
        allowed_transfers=tuple(body["allowed_transfers"]),
        complete=complete,
        failure_reason=failure_reason,
    )


def _machine_entry(selected: SelectedMachineImportContract) -> ExternalProfileEntry:
    raw = selected.contract
    arity = raw.get("arity")
    words = (
        arity.get("words") if isinstance(arity, Mapping)
        else raw.get("argument_words")
    )
    callback_effect = raw.get("callback_effect")
    if callback_effect is None and raw.get("world_effect") == "callbackRegistration":
        callback_effect = "explicit"
    identity = _import_identity(selected.identity)
    binding = {
        "profile_id": selected.profile_id,
        "profile_sha256": selected.profile_sha256,
        "entry_key": selected.entry_key,
        "entry_index": selected.entry_index,
    }
    contract = _profile_contract(
        identity=identity,
        contract_id=str(raw.get("id")),
        abi_template=raw.get("abi_template"),
        argument_words=words,
        profile_binding=binding,
        disposition=raw.get("disposition", "returns"),
        result_register_relations=raw.get("result_register_relations", []),
        memory_effect=raw.get("memory_effect"),
        memory_footprints=raw.get("memory_footprints", []),
        world_effect=raw.get("world_effect"),
        callback_effect=callback_effect,
        out_pointer_relations=raw.get("out_pointer_relations", []),
        out_interface_relations=raw.get("out_interface_relations", []),
        source_contract=raw,
    )
    complete = (
        isinstance(contract["abi_template"], str)
        and isinstance(contract["argument_words"], int)
        and isinstance(contract["memory_effect"], str)
        and isinstance(contract["world_effect"], str)
        and contract["callback_effect"] in {"none", "explicit"}
    )
    return _entry(
        family="machine_import",
        profile_id=selected.profile_id,
        profile_sha256=selected.profile_sha256,
        artifact_sha256=selected.profile_sha256,
        entry_key=selected.entry_key,
        entry_index=selected.entry_index,
        identity=identity,
        contract=contract,
        allowed_transfers=("call", "jump"),
        complete=complete,
        failure_reason=(
            None if complete
            else "machine import profile entry lacks an exact ABI/effect contract"
        ),
    )


def _machine_callback_entry(
    selected: SelectedMachineImportContract,
) -> ExternalProfileEntry | None:
    raw = selected.contract
    callback_effect = raw.get("callback_effect")
    if callback_effect is None and raw.get("world_effect") == "callbackRegistration":
        callback_effect = "explicit"
    if callback_effect != "explicit":
        return None
    callback_abi = raw.get("callback_abi")
    callback_words = (
        callback_abi.get("argument_words")
        if isinstance(callback_abi, Mapping)
        else None
    )
    contract_id = str(raw.get("id"))
    identity = _identity_payload(
        kind="callback",
        protocol="pe32-previous-callback",
        profile_id=selected.profile_id,
        profile_sha256=selected.profile_sha256,
        operation=contract_id,
    )
    complete = (
        isinstance(callback_words, int)
        and isinstance(raw.get("callback_source"), Mapping)
        and isinstance(raw.get("callback_lifetime"), (str, Mapping))
    )
    return _entry(
        family="callback",
        profile_id=selected.profile_id,
        profile_sha256=selected.profile_sha256,
        artifact_sha256=selected.profile_sha256,
        entry_key=f"{selected.entry_key}.callbacks",
        entry_index=selected.entry_index,
        identity=identity,
        contract=_profile_contract(
            identity=identity,
            contract_id=contract_id,
            abi_template="pe32-stdcall-v1",
            argument_words=callback_words,
            profile_binding={
                "profile_id": selected.profile_id,
                "profile_sha256": selected.profile_sha256,
            },
            memory_effect="sameProcessCallbackCallthrough",
            world_effect="sameProcessCallbackCallthrough",
            callback_effect="none",
            callback_profile={
                "source": raw.get("callback_source"),
                "abi": callback_abi,
                "lifetime": raw.get("callback_lifetime"),
            },
            source_contract=raw,
        ),
        complete=complete,
        failure_reason=(
            None if complete
            else "callback registration lacks exact source, ABI, or lifetime evidence"
        ),
    )
def _interface_entries(
    profile: ExternalInterfaceProfile,
    *,
    artifact_sha256: str,
) -> list[ExternalProfileEntry]:
    result: list[ExternalProfileEntry] = []
    for index, factory in enumerate(profile.factories):
        effects = None if factory.effects is None else factory.effects.as_json()
        identity = _import_identity(factory.identity)
        binding = {
            "profile_id": profile.profile_id,
            "profile_sha256": profile.sha256,
        }
        result.append(_entry(
            family="interface_factory",
            profile_id=profile.profile_id,
            profile_sha256=profile.sha256,
            artifact_sha256=artifact_sha256,
            entry_key="factories",
            entry_index=index,
            identity=identity,
            contract=_profile_contract(
                identity=identity,
                contract_id=f"{factory.identity.dll}!{factory.identity.value}",
                abi_template=factory.abi.template,
                argument_words=factory.argument_words,
                profile_binding=binding,
                memory_effect=None if effects is None else effects["memory_effect"],
                memory_footprints=[] if effects is None else effects["memory_footprints"],
                world_effect=None if effects is None else effects["world_effect"],
                callback_effect=None if effects is None else effects["callback_effect"],
                out_interface_relations=[value.as_json() for value in factory.outputs],
            ),
            complete=effects is not None,
            failure_reason=(
                None if effects is not None
                else "interface factory lacks a reviewed same-library ABI/effect contract"
            ),
        ))
    for interface in profile.interfaces:
        for method in interface.methods:
            effects = None if method.effects is None else method.effects.as_json()
            operation = f"{method.interface_id}::{method.name}"
            identity = _identity_payload(
                kind="interface",
                protocol="pe32-interface-method",
                profile_id=profile.profile_id,
                profile_sha256=profile.sha256,
                operation=operation,
            )
            receiver_resource = method.receiver_resource.as_json()
            binding = {
                "profile_id": profile.profile_id,
                "profile_sha256": profile.sha256,
                "receiver_resource": receiver_resource,
            }
            callback_profile = None
            if effects is not None and effects["callback_effect"] == "explicit":
                callback_profile = {
                    "source": effects.get("callback_source"),
                    "abi": effects.get("callback_abi"),
                    "lifetime": effects.get("callback_lifetime"),
                }
            result.append(_entry(
                family="interface_method",
                profile_id=profile.profile_id,
                profile_sha256=profile.sha256,
                artifact_sha256=artifact_sha256,
                entry_key=f"interfaces.{interface.interface_id}.methods",
                entry_index=method.slot,
                identity=identity,
                contract=_profile_contract(
                    identity=identity,
                    contract_id=operation,
                    abi_template=method.abi.template,
                    argument_words=method.argument_words,
                    profile_binding=binding,
                    memory_effect=None if effects is None else effects["memory_effect"],
                    memory_footprints=[] if effects is None else effects["memory_footprints"],
                    world_effect=None if effects is None else effects["world_effect"],
                    callback_effect=None if effects is None else effects["callback_effect"],
                    out_interface_relations=[value.as_json() for value in method.outputs],
                    receiver_resource=receiver_resource,
                    callback_profile=callback_profile,
                ),
                complete=(
                    effects is not None
                    and (
                        effects["callback_effect"] == "none"
                        or effects.get("callback_contract_status") == "complete"
                    )
                ),
                failure_reason=(
                    None
                    if effects is not None and (
                        effects["callback_effect"] == "none"
                        or effects.get("callback_contract_status") == "complete"
                    )
                    else "interface method lacks a complete ABI/effect/callback contract"
                ),
            ))
            if callback_profile is not None:
                callback_abi = callback_profile.get("abi")
                callback_words = (
                    callback_abi.get("argument_words")
                    if isinstance(callback_abi, Mapping)
                    else None
                )
                callback_identity = _identity_payload(
                    kind="callback",
                    protocol="pe32-previous-callback",
                    profile_id=profile.profile_id,
                    profile_sha256=profile.sha256,
                    operation=operation,
                )
                callback_complete = (
                    effects is not None
                    and effects.get("callback_contract_status") == "complete"
                    and isinstance(callback_words, int)
                )
                result.append(_entry(
                    family="callback",
                    profile_id=profile.profile_id,
                    profile_sha256=profile.sha256,
                    artifact_sha256=artifact_sha256,
                    entry_key=f"interfaces.{interface.interface_id}.callbacks",
                    entry_index=method.slot,
                    identity=callback_identity,
                    contract=_profile_contract(
                        identity=callback_identity,
                        contract_id=operation,
                        abi_template="pe32-stdcall-v1",
                        argument_words=callback_words,
                        profile_binding={
                            "profile_id": profile.profile_id,
                            "profile_sha256": profile.sha256,
                        },
                        memory_effect="sameProcessCallbackCallthrough",
                        world_effect="sameProcessCallbackCallthrough",
                        callback_effect="none",
                        callback_profile=callback_profile,
                    ),
                    complete=callback_complete,
                    failure_reason=(
                        None if callback_complete
                        else "interface callback lacks exact source, ABI, or lifetime evidence"
                    ),
                ))
    return result


def _operation_entries(
    profile: ExternalOperationProfile,
    *,
    artifact_sha256: str,
) -> list[ExternalProfileEntry]:
    result: list[ExternalProfileEntry] = []
    selectors = profile.selectors_by_operation_id()
    contracts = profile.contracts_by_id()
    for index, operation in enumerate(profile.operations):
        environment = contracts[operation.environment_contract_id]
        identity = _identity_payload(
            kind="interface",
            protocol="pe32-operation",
            profile_id=profile.profile_id,
            profile_sha256=profile.sha256,
            operation=operation.operation_id,
        )
        environment_payload = environment.as_json()
        environment_id = _sha256(_canonical_bytes(environment_payload))
        receiver_resource = (
            None
            if operation.receiver_resource is None
            else operation.receiver_resource.as_json()
        )
        binding = {
            "profile_id": profile.profile_id,
            "profile_sha256": profile.sha256,
        }
        if receiver_resource is not None:
            binding["receiver_resource"] = receiver_resource
        callbacks = [
            selector for selector in selectors[operation.operation_id]
            if isinstance(selector, CallbackSelector)
        ]
        result.append(_entry(
            family="external_operation",
            profile_id=profile.profile_id,
            profile_sha256=profile.sha256,
            artifact_sha256=artifact_sha256,
            entry_key="operations",
            entry_index=index,
            identity=identity,
            contract=_profile_contract(
                identity=identity,
                contract_id=operation.operation_id,
                abi_template=operation.abi.template,
                argument_words=operation.argument_words,
                profile_binding=binding,
                memory_effect=f"external-operation:{environment_id}",
                memory_footprints=[value.as_json() for value in environment.memory_footprints],
                world_effect=f"external-operation:{environment_id}",
                callback_effect="explicit" if callbacks else "none",
                out_pointer_relations=[value.as_json() for value in operation.output_rules],
                receiver_resource=receiver_resource,
                source_contract=environment_payload,
            ),
            complete=environment.status == "complete",
            failure_reason=(
                None if environment.status == "complete"
                else "external operation has an incomplete environment contract"
            ),
        ))
        for callback_index, callback in enumerate(callbacks):
            callback_identity = _identity_payload(
                kind="callback",
                protocol="pe32-operation",
                profile_id=profile.profile_id,
                profile_sha256=profile.sha256,
                operation=operation.operation_id,
            )
            result.append(_entry(
                family="callback",
                profile_id=profile.profile_id,
                profile_sha256=profile.sha256,
                artifact_sha256=artifact_sha256,
                entry_key=f"operations.{operation.operation_id}.callbacks",
                entry_index=callback_index,
                identity=callback_identity,
                contract=_profile_contract(
                    identity=callback_identity,
                    contract_id=operation.operation_id,
                    abi_template=operation.abi.template,
                    argument_words=operation.argument_words,
                    profile_binding={
                        "profile_id": profile.profile_id,
                        "profile_sha256": profile.sha256,
                    },
                    memory_effect=f"external-operation:{environment_id}",
                    memory_footprints=[
                        value.as_json() for value in environment.memory_footprints
                    ],
                    world_effect=f"external-operation:{environment_id}",
                    callback_effect="none",
                    out_pointer_relations=[
                        value.as_json() for value in operation.output_rules
                    ],
                    source_contract={
                        "selector": callback.as_json(),
                        "environment": environment_payload,
                    },
                ),
                complete=environment.status == "complete",
                failure_reason=(
                    None if environment.status == "complete"
                    else "callback operation has an incomplete environment contract"
                ),
            ))
    return result


def _callable_entries(
    profile: CallableExternalProfile,
    *,
    artifact_sha256: str,
) -> list[ExternalProfileEntry]:
    result: list[ExternalProfileEntry] = []
    for index, resolver in enumerate(profile.resolvers):
        identity = _import_identity(resolver.identity)
        result.append(_entry(
            family="callable_resolver",
            profile_id=profile.profile_id,
            profile_sha256=profile.sha256,
            artifact_sha256=artifact_sha256,
            entry_key="resolvers",
            entry_index=index,
            identity=identity,
            contract=_profile_contract(
                identity=identity,
                contract_id=f"resolver:{resolver.id}",
                abi_template=None,
                argument_words=None,
                profile_binding={
                    "profile_id": profile.profile_id,
                    "profile_sha256": profile.sha256,
                },
                memory_effect=None,
                world_effect=None,
                callback_effect=None,
            ),
            complete=False,
            failure_reason=(
                "callable resolver profile does not itself contain a machine ABI/effect contract"
            ),
        ))
    resolver_by_id = profile.resolver_by_id()
    for index, target in enumerate(profile.targets):
        raw = target.machine_contract
        arity = raw.get("arity")
        words = arity.get("words") if isinstance(arity, Mapping) else None
        identity = _identity_payload(
            kind="resolved_export",
            dll=target.identity.dll,
            symbol=str(target.identity.value) if target.identity.kind == "symbol" else None,
            ordinal=int(target.identity.value) if target.identity.kind == "ordinal" else None,
            protocol="pe32-resolved-export",
            profile_id=profile.profile_id,
            profile_sha256=profile.sha256,
        )
        binding = {
            "profile_id": profile.profile_id,
            "profile_sha256": profile.sha256,
        }
        result.append(_entry(
            family="callable_target",
            profile_id=profile.profile_id,
            profile_sha256=profile.sha256,
            artifact_sha256=artifact_sha256,
            entry_key="targets",
            entry_index=index,
            identity=identity,
            contract=_profile_contract(
                identity=identity,
                contract_id=str(raw.get("id")),
                abi_template=raw.get("abi_template"),
                argument_words=words,
                profile_binding=binding,
                disposition=raw.get("disposition", "returns"),
                result_register_relations=raw.get("result_register_relations", []),
                memory_effect=raw.get("memory_effect"),
                memory_footprints=raw.get("memory_footprints", []),
                world_effect=raw.get("world_effect"),
                callback_effect=raw.get("callback_effect"),
                source_contract=raw,
            ),
            allowed_transfers=target.transfers,
        ))
        if target.resolver_id not in resolver_by_id:
            raise ExternalProfileAuthorityV2Error(
                "callable target references an absent resolver"
            )
    return result


def _artifact(path: Path, payload: Mapping[str, Any]) -> ExactExternalProfileArtifact:
    raw = path.read_bytes()
    return ExactExternalProfileArtifact(
        source=str(path),
        format=_nonempty(payload.get("format"), f"{path} format"),
        profile_id=_nonempty(payload.get("id"), f"{path} profile id"),
        artifact_sha256=_sha256(raw),
        exact_bytes=raw,
    )


def build_external_profile_authority_v2(
    profile_paths: Sequence[Path | str],
) -> ExternalProfileAuthorityV2:
    """Build an exact replay index from pinned profile artifact files."""

    paths = tuple(sorted({Path(path).resolve() for path in profile_paths}, key=str))
    payload_by_path: dict[Path, Mapping[str, Any]] = {}
    for path in paths:
        try:
            value = json.loads(path.read_bytes())
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ExternalProfileAuthorityV2Error(
                f"cannot read external profile {path}: {exc}"
            ) from exc
        if not isinstance(value, Mapping):
            raise ExternalProfileAuthorityV2Error(
                f"external profile {path} is not an object"
            )
        payload_by_path[path] = value

    machine_paths = [
        path for path, payload in payload_by_path.items()
        if payload.get("format") in MACHINE_IMPORT_PROFILE_FORMATS
    ]
    machine_set: MachineImportProfileSet | None = None
    if machine_paths:
        try:
            machine_set = load_machine_import_profile_set(machine_paths)
        except Exception as exc:
            raise ExternalProfileAuthorityV2Error(str(exc)) from exc
        for loaded in machine_set.profiles:
            payload_by_path.setdefault(loaded.path, loaded.payload)

    artifacts_by_sha: dict[str, ExactExternalProfileArtifact] = {}
    artifact_by_path: dict[Path, ExactExternalProfileArtifact] = {}
    for path, payload in sorted(payload_by_path.items(), key=lambda item: str(item[0])):
        artifact = _artifact(path, payload)
        prior = artifacts_by_sha.get(artifact.artifact_sha256)
        if prior is not None and prior.exact_bytes != artifact.exact_bytes:
            raise ExternalProfileAuthorityV2Error(
                "external-profile SHA-256 collision"
            )
        artifacts_by_sha.setdefault(artifact.artifact_sha256, artifact)
        artifact_by_path[path] = artifacts_by_sha[artifact.artifact_sha256]

    entries: list[ExternalProfileEntry] = []
    if machine_set is not None:
        for selected in machine_set.contracts:
            entries.append(_machine_entry(selected))
            callback_entry = _machine_callback_entry(selected)
            if callback_entry is not None:
                entries.append(callback_entry)

    for path in paths:
        payload = payload_by_path[path]
        format_name = payload.get("format")
        artifact_sha = artifact_by_path[path].artifact_sha256
        try:
            if format_name == EXTERNAL_INTERFACE_PROFILE_FORMAT:
                entries.extend(_interface_entries(
                    load_external_interface_profile(path),
                    artifact_sha256=artifact_sha,
                ))
            elif format_name == EXTERNAL_OPERATION_PROFILE_FORMAT:
                entries.extend(_operation_entries(
                    load_external_operation_profile(path),
                    artifact_sha256=artifact_sha,
                ))
            elif format_name == CALLABLE_EXTERNAL_PROFILE_FORMAT:
                entries.extend(_callable_entries(
                    load_callable_external_profile(path),
                    artifact_sha256=artifact_sha,
                ))
            elif format_name not in MACHINE_IMPORT_PROFILE_FORMATS:
                raise ExternalProfileAuthorityV2Error(
                    f"unsupported external-profile format {format_name!r} in {path}"
                )
        except ExternalProfileAuthorityV2Error:
            raise
        except Exception as exc:
            raise ExternalProfileAuthorityV2Error(str(exc)) from exc

    ordered_artifacts = tuple(sorted(
        artifacts_by_sha.values(), key=lambda value: value.artifact_sha256
    ))
    ordered_entries = tuple(sorted(entries, key=lambda value: value.entry_id))
    body = {
        "format": EXTERNAL_PROFILE_AUTHORITY_V2_FORMAT,
        "root_sources": [str(path) for path in paths],
        "artifacts": [artifact.payload() for artifact in ordered_artifacts],
        "entries": [entry.payload() for entry in ordered_entries],
    }
    return ExternalProfileAuthorityV2(
        artifacts=ordered_artifacts,
        entries=ordered_entries,
        root_sources=tuple(str(path) for path in paths),
        authority_id=_sha256(_canonical_bytes(body)),
    )


def parse_external_profile_authority_v2(
    value: Mapping[str, Any],
) -> ExternalProfileAuthorityV2:
    """Parse and independently rebuild an exact-artifact profile authority."""

    expected_keys = {
        "format", "authority_id", "root_sources", "artifacts", "entries",
    }
    if not isinstance(value, Mapping) or set(value) != expected_keys:
        raise ExternalProfileAuthorityV2Error(
            "external-profile authority has unexpected or missing fields"
        )
    if value.get("format") != EXTERNAL_PROFILE_AUTHORITY_V2_FORMAT:
        raise ExternalProfileAuthorityV2Error(
            "external-profile authority has an unsupported format"
        )
    raw_roots = value.get("root_sources")
    raw_artifacts = value.get("artifacts")
    raw_entries = value.get("entries")
    if (
        not isinstance(raw_roots, list)
        or not isinstance(raw_artifacts, list)
        or not isinstance(raw_entries, list)
    ):
        raise ExternalProfileAuthorityV2Error(
            "external-profile authority inventories are malformed"
        )
    roots = tuple(
        _nonempty(source, f"external-profile root {index}")
        for index, source in enumerate(raw_roots)
    )
    artifacts = tuple(
        _parse_artifact(row, index)
        for index, row in enumerate(raw_artifacts)
    )
    entries = tuple(
        _parse_entry(row, index)
        for index, row in enumerate(raw_entries)
    )
    authority_id = value.get("authority_id")
    if not _digest(authority_id):
        raise ExternalProfileAuthorityV2Error(
            "external-profile authority ID is malformed"
        )
    parsed = ExternalProfileAuthorityV2(
        artifacts=artifacts,
        entries=entries,
        root_sources=roots,
        authority_id=str(authority_id),
    )
    rebuilt = _rebuild_embedded_authority(parsed)
    if (
        [entry.payload() for entry in rebuilt.entries]
        != [entry.payload() for entry in parsed.entries]
        or {
            (artifact.format, artifact.profile_id, artifact.artifact_sha256)
            for artifact in rebuilt.artifacts
        }
        != {
            (artifact.format, artifact.profile_id, artifact.artifact_sha256)
            for artifact in parsed.artifacts
        }
    ):
        raise ExternalProfileAuthorityV2Error(
            "external-profile entries do not replay from their embedded exact bytes"
        )
    return parsed


def load_external_profile_authority_v2(
    path: Path | str,
) -> ExternalProfileAuthorityV2:
    source = Path(path)
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ExternalProfileAuthorityV2Error(
            f"cannot read external-profile authority {source}: {exc}"
        ) from exc
    if not isinstance(value, Mapping):
        raise ExternalProfileAuthorityV2Error(
            "external-profile authority file is not an object"
        )
    return parse_external_profile_authority_v2(value)


def _parse_artifact(value: Any, index: int) -> ExactExternalProfileArtifact:
    expected = {
        "source", "format", "profile_id", "artifact_sha256",
        "exact_bytes_base64",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ExternalProfileAuthorityV2Error(
            f"external-profile artifact {index} is malformed"
        )
    encoded = value.get("exact_bytes_base64")
    if not isinstance(encoded, str):
        raise ExternalProfileAuthorityV2Error(
            f"external-profile artifact {index} has no exact bytes"
        )
    try:
        exact_bytes = base64.b64decode(encoded, validate=True)
    except ValueError as exc:
        raise ExternalProfileAuthorityV2Error(
            f"external-profile artifact {index} bytes are not canonical base64"
        ) from exc
    if base64.b64encode(exact_bytes).decode("ascii") != encoded:
        raise ExternalProfileAuthorityV2Error(
            f"external-profile artifact {index} bytes are not canonical base64"
        )
    return ExactExternalProfileArtifact(
        source=_nonempty(value.get("source"), f"artifact {index} source"),
        format=_nonempty(value.get("format"), f"artifact {index} format"),
        profile_id=_nonempty(
            value.get("profile_id"), f"artifact {index} profile id"
        ),
        artifact_sha256=_nonempty(
            value.get("artifact_sha256"), f"artifact {index} digest"
        ),
        exact_bytes=exact_bytes,
    )


def _parse_entry(value: Any, index: int) -> ExternalProfileEntry:
    expected = {
        "entry_id", "family", "profile_id", "profile_sha256",
        "artifact_sha256", "entry_key", "entry_index", "identity",
        "contract", "allowed_transfers", "complete", "failure_reason",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ExternalProfileAuthorityV2Error(
            f"external-profile entry {index} is malformed"
        )
    family = value.get("family")
    families = {
        "machine_import", "interface_factory", "interface_method",
        "external_operation", "callable_resolver", "callable_target",
        "callback",
    }
    if family not in families:
        raise ExternalProfileAuthorityV2Error(
            f"external-profile entry {index} family is unsupported"
        )
    transfers = value.get("allowed_transfers")
    if not isinstance(transfers, list) or any(
        not isinstance(item, str) for item in transfers
    ):
        raise ExternalProfileAuthorityV2Error(
            f"external-profile entry {index} transfers are malformed"
        )
    complete = value.get("complete")
    entry_index = value.get("entry_index")
    if not isinstance(complete, bool) or not isinstance(entry_index, int) or isinstance(entry_index, bool):
        raise ExternalProfileAuthorityV2Error(
            f"external-profile entry {index} status or index is malformed"
        )
    rebuilt = _entry(
        family=family,
        profile_id=_nonempty(value.get("profile_id"), f"entry {index} profile id"),
        profile_sha256=_nonempty(
            value.get("profile_sha256"), f"entry {index} profile digest"
        ),
        artifact_sha256=_nonempty(
            value.get("artifact_sha256"), f"entry {index} artifact digest"
        ),
        entry_key=_nonempty(value.get("entry_key"), f"entry {index} key"),
        entry_index=entry_index,
        identity=(
            value["identity"] if isinstance(value.get("identity"), Mapping)
            else {}
        ),
        contract=(
            value["contract"] if isinstance(value.get("contract"), Mapping)
            else {}
        ),
        allowed_transfers=transfers,
        complete=complete,
        failure_reason=value.get("failure_reason"),
    )
    if rebuilt.payload() != dict(value):
        raise ExternalProfileAuthorityV2Error(
            f"external-profile entry {index} derived fields do not replay"
        )
    return rebuilt


def _rebuild_embedded_authority(
    authority: ExternalProfileAuthorityV2,
) -> ExternalProfileAuthorityV2:
    sources = [artifact.source for artifact in authority.artifacts]
    try:
        common = Path(os.path.commonpath(sources))
    except ValueError as exc:
        raise ExternalProfileAuthorityV2Error(
            "external-profile sources do not share a reproducible root"
        ) from exc
    if common in {Path(source) for source in sources}:
        common = common.parent
    with tempfile.TemporaryDirectory(prefix="external-profile-authority-v2-") as raw:
        root = Path(raw)
        remapped: dict[str, Path] = {}
        for artifact in authority.artifacts:
            source = Path(artifact.source)
            try:
                relative = source.relative_to(common)
            except ValueError as exc:
                raise ExternalProfileAuthorityV2Error(
                    "external-profile source escapes its common root"
                ) from exc
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(artifact.exact_bytes)
            remapped[artifact.source] = destination
        try:
            roots = [remapped[source] for source in authority.root_sources]
        except KeyError as exc:
            raise ExternalProfileAuthorityV2Error(
                "external-profile root is absent from embedded artifacts"
            ) from exc
        return build_external_profile_authority_v2(roots)


def _require_entry_match(
    site: CheckedExternalSiteContract,
    entry: ExternalProfileEntry,
    *,
    context: str,
) -> None:
    expected = entry.contract
    if entry.family == "machine_import":
        source = expected.get("source_contract")
        if not isinstance(source, Mapping):
            raise CheckedExternalSiteContractError(
                f"{context} indexed machine-import contract is malformed"
            )
        require_profile_match(
            site,
            profile_contract=source,
            profile_id=entry.profile_id,
            profile_sha256=entry.profile_sha256,
            entry_key=entry.entry_key,
            entry_index=entry.entry_index,
            context=context,
        )
        return
    observed = {
        "identity": site.identity.payload(),
        "contract_id": site.contract_id,
        "abi_template": site.abi_template,
        "argument_words": site.argument_words,
        "profile_disposition": site.profile_disposition,
        "profile_binding": site.profile_binding,
        "result_register_relations": list(site.result_register_relations),
        "memory_effect": site.memory_effect,
        "memory_footprints": list(site.memory_footprints),
        "world_effect": site.world_effect,
        "callback_effect": site.callback_effect,
        "out_pointer_relations": list(site.out_pointer_relations),
        "out_interface_relations": list(site.out_interface_relations),
    }
    controlled_fields = tuple(observed)
    expected_projection = {field: expected.get(field) for field in controlled_fields}
    if _canonical_bytes(observed) != _canonical_bytes(expected_projection):
        differing = [
            field for field in controlled_fields
            if _canonical_bytes(observed[field])
            != _canonical_bytes(expected_projection[field])
        ]
        raise CheckedExternalSiteContractError(
            f"{context} differs from exact profile entry in: {', '.join(differing)}"
        )
    callback_profile = expected.get("callback_profile")
    if callback_profile is not None:
        adapter = site.callback_adapter
        if adapter is None:
            raise CheckedExternalSiteContractError(
                f"{context} has no checked callback adapter"
            )
        observed_callback = {
            "source": adapter.source,
            "abi": adapter.abi,
            "lifetime": adapter.lifetime,
        }
        if _canonical_bytes(observed_callback) != _canonical_bytes(callback_profile):
            raise CheckedExternalSiteContractError(
                f"{context} callback ABI/source/lifetime differs from its profile"
            )


__all__ = [
    "EXTERNAL_PROFILE_AUTHORITY_V2_FORMAT",
    "ExactExternalProfileArtifact",
    "ExternalProfileAuthorityV2",
    "ExternalProfileAuthorityV2Error",
    "ExternalProfileEntry",
    "ExternalProfileReplayResult",
    "build_external_profile_authority_v2",
    "load_external_profile_authority_v2",
    "parse_external_profile_authority_v2",
]

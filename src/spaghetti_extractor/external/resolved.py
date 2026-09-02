"""Closed codec for resolved external semantic declarations."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..artifacts.formats import LAUNCH_ASSUMPTION_TEMPLATE_FORMAT
from ..boundary import BoundarySchemaV1, TargetDataLayoutV1
from ..calls.frame import (
    PhysicalCallFrameV3,
    physical_frame_abi_sha256_v1,
)
from ..errors import ToolkitInputError
from .boundary_bindings import (
    schema_callback_links_v1,
    schema_frame_machine_bindings_v1,
)
from .formats import RESOLVED_EXTERNAL_ENVIRONMENT_FORMAT
from .machine_callback_boundary import (
    MachineCallbackBoundaryError,
    interface_callback_boundary_catalog_v1,
    machine_callback_boundary_catalog_v1,
)


_PE32_ABIS = frozenset({"pe32-i686-msvc", "pe32-i686-mingw32"})
_PE32_LAYOUTS = frozenset({"pe32-ilp32-v1"})
_FIELDS = {
    "format", "status", "bindings", "target", "launch_policy",
    "canonical_boundaries",
    "interface_method_catalogs", "machine_import_contracts",
    "original_semantic_imports", "generated_runtime_support_imports",
    "loader_service_contracts", "static_authority_bindings",
    "checked_exception_protocols", "blockers",
    "authority", "resolved_environment_sha256",
}
_CHECKED_EXCEPTION_PROTOCOL_FIELDS = {
    "schema", "protocol_id", "protocol_sha256", "occurrence", "handler",
    "resumption", "unwind_unit_ids", "state_projection",
}
_CHECKED_EXCEPTION_OCCURRENCE_FIELDS = {
    "unit_id", "source_rva", "effect_index", "fault_index", "fault_sha256",
    "occurrence_kind", "operation", "call_index",
}
_CHECKED_EXCEPTION_TARGET_FIELDS = {"unit_id", "rva"}
_CHECKED_EXCEPTION_PROJECTION_FIELDS = {
    "registers", "flags", "x87", "stack", "exception_record", "context",
}
_LAUNCH_POLICY_FIELDS = {
    "filename", "format", "id", "kind", "payload", "payload_sha256",
    "sha256",
}
_BINDING_FIELDS = {
    "module_interface_sha256", "module_pe_sha256",
    "environment_intent_sha256", "runtime_profile_pack_sha256s",
    "interface_profile_pack_sha256s",
}


class ExternalEnvironmentError(ToolkitInputError):
    """The external environment is malformed, stale, or ambiguous."""


def _mapping(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ExternalEnvironmentError(f"{context} must be an object")
    return value


def _rows(value: object, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise ExternalEnvironmentError(f"{context} must be an array")
    return value


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ExternalEnvironmentError(f"{context} must be nonempty text")
    return value


def _sha256(value: object, context: str) -> str:
    text = _text(value, context)
    if len(text) != 64 or any(
        character not in "0123456789abcdef" for character in text
    ):
        raise ExternalEnvironmentError(f"{context} must be lowercase SHA-256")
    return text


def bind_launch_policy_v1(
    payload: Mapping[str, Any],
    *,
    source_sha256: str,
    filename: str,
) -> dict[str, Any]:
    """Bind the exact launch policy as a resolved semantic input."""

    policy = dict(payload)
    if (
        policy.get("format") != LAUNCH_ASSUMPTION_TEMPLATE_FORMAT
        or policy.get("schema_version") != 1
    ):
        raise ExternalEnvironmentError("launch-policy identity is unsupported")
    return {
        "filename": _text(filename, "launch-policy filename"),
        "format": LAUNCH_ASSUMPTION_TEMPLATE_FORMAT,
        "id": "launch",
        "kind": "launch_policy",
        "payload": policy,
        "payload_sha256": canonical_sha256_v3(policy),
        "sha256": _sha256(source_sha256, "launch-policy source binding"),
    }


def bind_checked_exception_protocol_v1(
    *, occurrence: Mapping[str, Any], handler: Mapping[str, Any] | None,
    resumption: Mapping[str, Any] | None, unwind_unit_ids: list[str],
    state_projection: Mapping[str, Any],
) -> dict[str, Any]:
    """Content-bind one environment-owned checked-exception protocol.

    The protocol deliberately contains no executable guard or native exception
    metadata.  Those remain properties of the exact transfer-v2 occurrence;
    this declaration supplies only the guest handler or external continuation,
    unwind, and physical-state projection contract.
    """

    if handler is None and resumption is None:
        raise ExternalEnvironmentError(
            "checked exception protocol requires a handler or resumption"
        )

    core = {
        "schema": "spaghetti-extractor-checked-exception-protocol-v1",
        "occurrence": dict(occurrence),
        "handler": None if handler is None else dict(handler),
        "resumption": None if resumption is None else dict(resumption),
        "unwind_unit_ids": list(unwind_unit_ids),
        "state_projection": {
            str(key): list(value) for key, value in state_projection.items()
        },
    }
    digest = canonical_sha256_v3(core)
    return {
        **core,
        "protocol_id": f"checked-exception-protocol-v1:{digest}",
        "protocol_sha256": digest,
    }


def _checked_exception_protocol(
    value: object, context: str,
) -> dict[str, Any]:
    row = dict(_mapping(value, context))
    if set(row) != _CHECKED_EXCEPTION_PROTOCOL_FIELDS:
        raise ExternalEnvironmentError(
            f"{context} fields are incomplete"
        )
    if row.get("schema") != (
        "spaghetti-extractor-checked-exception-protocol-v1"
    ):
        raise ExternalEnvironmentError(f"{context} schema is unsupported")
    protocol_sha256 = _sha256(
        row.get("protocol_sha256"), f"{context} digest"
    )
    if row.get("protocol_id") != (
        f"checked-exception-protocol-v1:{protocol_sha256}"
    ):
        raise ExternalEnvironmentError(f"{context} identity is stale")
    core = {
        key: item for key, item in row.items()
        if key not in {"protocol_id", "protocol_sha256"}
    }
    if canonical_sha256_v3(core) != protocol_sha256:
        raise ExternalEnvironmentError(f"{context} self hash is stale")

    occurrence = _mapping(row.get("occurrence"), f"{context} occurrence")
    if set(occurrence) != _CHECKED_EXCEPTION_OCCURRENCE_FIELDS:
        raise ExternalEnvironmentError(
            f"{context} occurrence fields are incomplete"
        )
    _text(occurrence.get("unit_id"), f"{context} occurrence unit")
    _sha256(occurrence.get("fault_sha256"), f"{context} occurrence fault")
    for field in ("source_rva", "effect_index", "fault_index"):
        item = occurrence.get(field)
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise ExternalEnvironmentError(
                f"{context} occurrence {field} must be a nonnegative integer"
            )
    if occurrence.get("occurrence_kind") not in {"effect", "call"}:
        raise ExternalEnvironmentError(
            f"{context} occurrence kind is unsupported"
        )
    _text(occurrence.get("operation"), f"{context} occurrence operation")
    call_index = occurrence.get("call_index")
    if (
        (occurrence.get("occurrence_kind") == "call")
        != (isinstance(call_index, int) and not isinstance(call_index, bool)
            and call_index >= 0)
    ):
        raise ExternalEnvironmentError(
            f"{context} occurrence call index is inconsistent"
        )

    def target(value: object, label: str, *, optional: bool) -> None:
        if optional and value is None:
            return
        selected = _mapping(value, f"{context} {label}")
        if set(selected) != _CHECKED_EXCEPTION_TARGET_FIELDS:
            raise ExternalEnvironmentError(
                f"{context} {label} fields are incomplete"
            )
        _text(selected.get("unit_id"), f"{context} {label} unit")
        rva = selected.get("rva")
        if isinstance(rva, bool) or not isinstance(rva, int) or rva < 0:
            raise ExternalEnvironmentError(
                f"{context} {label} RVA must be a nonnegative integer"
            )

    target(row.get("handler"), "handler", optional=True)
    target(row.get("resumption"), "resumption", optional=True)
    if row.get("handler") is None and row.get("resumption") is None:
        raise ExternalEnvironmentError(
            f"{context} requires a handler or resumption"
        )
    unwind = _rows(row.get("unwind_unit_ids"), f"{context} unwind units")
    if (
        any(not isinstance(item, str) or not item for item in unwind)
        or unwind != sorted(set(unwind))
    ):
        raise ExternalEnvironmentError(
            f"{context} unwind units are noncanonical"
        )
    projection = _mapping(
        row.get("state_projection"), f"{context} state projection"
    )
    if set(projection) != _CHECKED_EXCEPTION_PROJECTION_FIELDS:
        raise ExternalEnvironmentError(
            f"{context} state projection fields are incomplete"
        )
    for field in sorted(_CHECKED_EXCEPTION_PROJECTION_FIELDS):
        values = _rows(projection.get(field), f"{context} {field} projection")
        if (
            any(not isinstance(item, str) or not item for item in values)
            or values != sorted(set(values))
        ):
            raise ExternalEnvironmentError(
                f"{context} {field} projection is noncanonical"
            )
    return row


@dataclass(frozen=True)
class ResolvedExternalEnvironmentV1:
    """Content-bound external declarations selected for one original module."""

    payload: Mapping[str, Any]

    @property
    def identity(self) -> str:
        return str(self.payload["resolved_environment_sha256"])

    @classmethod
    def parse(
        cls,
        value: object,
        *,
        module_interface: Mapping[str, Any] | None = None,
    ) -> "ResolvedExternalEnvironmentV1":
        payload = dict(_mapping(value, "resolved external environment"))
        if set(payload) != _FIELDS:
            raise ExternalEnvironmentError(
                "resolved-external-environment fields are incomplete"
            )
        if payload.get("format") != RESOLVED_EXTERNAL_ENVIRONMENT_FORMAT:
            raise ExternalEnvironmentError(
                "resolved-external-environment format is unsupported"
            )
        declared = _sha256(
            payload.get("resolved_environment_sha256"),
            "resolved-external-environment identity",
        )
        core = {
            key: item for key, item in payload.items()
            if key != "resolved_environment_sha256"
        }
        if canonical_sha256_v3(core) != declared:
            raise ExternalEnvironmentError(
                "resolved-external-environment self hash is stale"
            )
        blockers = [
            dict(_mapping(row, "resolved-environment blocker"))
            for row in _rows(payload.get("blockers"), "blockers")
        ]
        status = payload.get("status")
        if (
            status not in {"complete", "incomplete"}
            or (status == "complete") != (not blockers)
            or payload.get("authority") != (
                "checked_static_environment" if not blockers else "none"
            )
        ):
            raise ExternalEnvironmentError(
                "resolved-external-environment authority state is inconsistent"
            )
        bindings = _mapping(payload.get("bindings"), "bindings")
        if set(bindings) != _BINDING_FIELDS:
            raise ExternalEnvironmentError(
                "resolved-external-environment bindings are incomplete"
            )
        for field in (
            "module_interface_sha256", "module_pe_sha256",
            "environment_intent_sha256",
        ):
            _sha256(bindings.get(field), f"resolved binding {field}")
        for field in (
            "runtime_profile_pack_sha256s",
            "interface_profile_pack_sha256s",
        ):
            rows = _rows(bindings.get(field), f"resolved binding {field}")
            if rows != sorted(set(rows)):
                raise ExternalEnvironmentError(
                    f"resolved binding {field} is noncanonical"
                )
            for index, item in enumerate(rows):
                _sha256(item, f"resolved binding {field}[{index}]")
        target = _mapping(payload.get("target"), "resolved target")
        if (
            set(target) != {"abi", "data_layout"}
            or target.get("abi") not in _PE32_ABIS
            or target.get("data_layout") not in _PE32_LAYOUTS
        ):
            raise ExternalEnvironmentError(
                "resolved-external-environment target is unsupported"
            )
        launch_policy = _mapping(
            payload.get("launch_policy"), "resolved launch policy"
        )
        if set(launch_policy) != _LAUNCH_POLICY_FIELDS:
            raise ExternalEnvironmentError(
                "resolved launch-policy fields are incomplete"
            )
        launch_payload = _mapping(
            launch_policy.get("payload"), "resolved launch-policy payload"
        )
        if (
            launch_policy.get("kind") != "launch_policy"
            or launch_policy.get("id") != "launch"
            or launch_policy.get("format")
            != LAUNCH_ASSUMPTION_TEMPLATE_FORMAT
            or launch_payload.get("format")
            != LAUNCH_ASSUMPTION_TEMPLATE_FORMAT
            or launch_payload.get("schema_version") != 1
        ):
            raise ExternalEnvironmentError(
                "resolved launch-policy identity is unsupported"
            )
        _sha256(launch_policy.get("sha256"), "launch-policy source binding")
        if _sha256(
            launch_policy.get("payload_sha256"),
            "launch-policy payload binding",
        ) != canonical_sha256_v3(launch_payload):
            raise ExternalEnvironmentError(
                "resolved launch-policy payload hash is stale"
            )
        arrays = {
            name: _rows(payload.get(name), f"resolved {name}")
            for name in (
                "canonical_boundaries", "interface_method_catalogs",
                "machine_import_contracts", "original_semantic_imports",
                "generated_runtime_support_imports",
                "loader_service_contracts", "static_authority_bindings",
                "checked_exception_protocols",
            )
        }
        for name, rows in arrays.items():
            for row in rows:
                _mapping(row, f"resolved {name} row")
        if arrays["original_semantic_imports"] != arrays["machine_import_contracts"]:
            raise ExternalEnvironmentError(
                "original semantic imports diverge from machine-import contracts"
            )
        machine_imports = [
            dict(_mapping(row, "resolved machine-import contract"))
            for row in arrays["machine_import_contracts"]
        ]
        callback_abi_dialect = {
            "pe32-i686-mingw32": "pe32-i386-gnu-v1",
            "pe32-i686-msvc": "pe32-i386-ms-v1",
        }[str(target["abi"])]
        authored_callback_subjects = {
            "callback:" + str(
                catalog.get("artifacts", {})
                .get("physical_call_frame_v3", {})
                .get("payload", {})
                .get("transport", {})
                .get("subject", {})
                .get("id")
            )
            for raw in arrays["canonical_boundaries"]
            for catalog in (_mapping(raw, "resolved canonical boundary"),)
            if catalog.get("kind") == "checked_protocol"
            and isinstance(
                catalog.get("artifacts", {})
                .get("physical_call_frame_v3", {})
                .get("payload", {})
                .get("transport", {})
                .get("subject", {})
                .get("id"),
                str,
            )
            and catalog.get("artifacts", {})
            .get("physical_call_frame_v3", {})
            .get("payload", {})
            .get("transport", {})
            .get("subject", {})
            .get("kind") == "callback"
        }
        expected_machine_callbacks: dict[str, dict[str, Any]] = {}
        for raw in (
            *machine_imports,
            *[
                dict(_mapping(row, "resolved runtime-support import"))
                for row in arrays["generated_runtime_support_imports"]
            ],
        ):
            try:
                callback = machine_callback_boundary_catalog_v1(
                    raw, abi_dialect=callback_abi_dialect
                )
            except (MachineCallbackBoundaryError, ValueError) as exc:
                raise ExternalEnvironmentError(str(exc)) from exc
            if (
                callback is None
                or callback["subject"] in authored_callback_subjects
            ):
                continue
            subject = str(callback["subject"])
            previous = expected_machine_callbacks.get(subject)
            if previous is not None and previous != callback:
                raise ExternalEnvironmentError(
                    f"machine callback subject {subject!r} is ambiguous"
                )
            expected_machine_callbacks[subject] = callback
        observed_machine_callbacks = {
            str(catalog.get("subject")): dict(catalog)
            for raw in arrays["canonical_boundaries"]
            for catalog in (_mapping(raw, "resolved canonical boundary"),)
            if catalog.get("kind") == "checked_machine_callback"
        }
        if observed_machine_callbacks != expected_machine_callbacks:
            raise ExternalEnvironmentError(
                "checked machine callback catalog differs from selected profiles"
            )
        expected_interface_callbacks: dict[str, dict[str, Any]] = {}
        for raw_interface in arrays["interface_method_catalogs"]:
            interface = _mapping(
                raw_interface, "resolved interface method catalog"
            )
            methods = _rows(
                interface.get("methods"), "resolved interface methods"
            )
            for raw_method in methods:
                method = _mapping(raw_method, "resolved interface method")
                target_core = {
                    "profile_id": interface.get("profile_id"),
                    "profile_sha256": interface.get("profile_sha256"),
                    "interface_id": interface.get("interface_id"),
                    "method": dict(method),
                }
                target = {
                    **target_core,
                    "method_contract_sha256": canonical_sha256_v3(
                        target_core
                    ),
                }
                try:
                    callback = interface_callback_boundary_catalog_v1(
                        target, abi_dialect=callback_abi_dialect
                    )
                except (MachineCallbackBoundaryError, ValueError) as exc:
                    raise ExternalEnvironmentError(str(exc)) from exc
                if callback is None:
                    continue
                subject = str(callback["subject"])
                previous = expected_interface_callbacks.get(subject)
                if previous is not None and previous != callback:
                    raise ExternalEnvironmentError(
                        f"interface callback subject {subject!r} is ambiguous"
                    )
                expected_interface_callbacks[subject] = callback
        observed_interface_callbacks = {
            str(catalog.get("subject")): dict(catalog)
            for raw in arrays["canonical_boundaries"]
            for catalog in (_mapping(raw, "resolved canonical boundary"),)
            if catalog.get("kind") == "checked_interface_callback"
        }
        if observed_interface_callbacks != expected_interface_callbacks:
            raise ExternalEnvironmentError(
                "checked interface callback catalog differs from selected profiles"
            )
        for index, raw in enumerate(arrays["canonical_boundaries"]):
            catalog = _mapping(raw, f"resolved canonical boundary {index}")
            if catalog.get("kind") == "checked_module_export":
                if set(catalog) != {
                    "subject", "kind", "logical_image_id", "target_rva",
                    "aliases", "physical_abi_sha256",
                    "checked_call_protocol_id", "contract_bindings",
                    "artifacts", "status_sha256",
                }:
                    raise ExternalEnvironmentError(
                        "checked module-export boundary fields are incomplete"
                    )
                subject = _text(
                    catalog.get("subject"),
                    "checked module-export boundary subject",
                )
                image_id = _text(
                    catalog.get("logical_image_id"),
                    "checked module-export logical image",
                )
                target_rva = catalog.get("target_rva")
                if (
                    isinstance(target_rva, bool)
                    or not isinstance(target_rva, int)
                    or target_rva < 0
                ):
                    raise ExternalEnvironmentError(
                        "checked module-export target RVA is malformed"
                    )
                aliases = [
                    dict(_mapping(item, "checked module-export alias"))
                    for item in _rows(
                        catalog.get("aliases"),
                        "checked module-export aliases",
                    )
                ]
                if not aliases:
                    raise ExternalEnvironmentError(
                        "checked module-export boundary has no aliases"
                    )
                for alias in aliases:
                    name = alias.get("name")
                    ordinal = alias.get("ordinal")
                    if (
                        set(alias) != {"name", "ordinal"}
                        or (name is not None and (
                            not isinstance(name, str) or not name
                        ))
                        or isinstance(ordinal, bool)
                        or not isinstance(ordinal, int)
                        or ordinal < 0
                    ):
                        raise ExternalEnvironmentError(
                            "checked module-export alias is malformed"
                        )
                expected_aliases = sorted(
                    aliases,
                    key=lambda row: (
                        int(row["ordinal"]),
                        "" if row["name"] is None else str(row["name"]),
                    ),
                )
                if aliases != expected_aliases or len({
                    (row["name"], row["ordinal"]) for row in aliases
                }) != len(aliases):
                    raise ExternalEnvironmentError(
                        "checked module-export aliases are noncanonical"
                    )
                contract_bindings = [
                    _mapping(item, "checked module-export contract binding")
                    for item in _rows(
                        catalog.get("contract_bindings"),
                        "checked module-export contract bindings",
                    )
                ]
                if not contract_bindings:
                    raise ExternalEnvironmentError(
                        "checked module-export boundary has no contract binding"
                    )
                for binding in contract_bindings:
                    if set(binding) != {
                        "identity", "profile_id", "profile_sha256",
                        "entry_key", "entry_index",
                    }:
                        raise ExternalEnvironmentError(
                            "checked module-export contract binding is malformed"
                        )
                    identity = _mapping(
                        binding.get("identity"),
                        "checked module-export contract identity",
                    )
                    if set(identity) != {"dll", "symbol", "ordinal"}:
                        raise ExternalEnvironmentError(
                            "checked module-export contract identity is malformed"
                        )
                    _text(
                        identity.get("dll"),
                        "checked module-export contract DLL",
                    )
                    has_symbol = isinstance(identity.get("symbol"), str) and bool(
                        identity.get("symbol")
                    )
                    has_ordinal = (
                        isinstance(identity.get("ordinal"), int)
                        and not isinstance(identity.get("ordinal"), bool)
                        and int(identity["ordinal"]) >= 0
                    )
                    if has_symbol == has_ordinal:
                        raise ExternalEnvironmentError(
                            "checked module-export contract identity is ambiguous"
                        )
                    _text(
                        binding.get("profile_id"),
                        "checked module-export profile ID",
                    )
                    _sha256(
                        binding.get("profile_sha256"),
                        "checked module-export profile binding",
                    )
                    _text(
                        binding.get("entry_key"),
                        "checked module-export entry key",
                    )
                    entry_index = binding.get("entry_index")
                    if (
                        isinstance(entry_index, bool)
                        or not isinstance(entry_index, int)
                        or entry_index < 0
                    ):
                        raise ExternalEnvironmentError(
                            "checked module-export entry index is malformed"
                        )
                artifacts = _mapping(
                    catalog.get("artifacts"),
                    "checked module-export artifacts",
                )
                if set(artifacts) != {
                    "boundary_schema", "target_data_layout",
                    "physical_call_frame_v3",
                }:
                    raise ExternalEnvironmentError(
                        "checked module-export artifacts are incomplete"
                    )
                artifact_rows = {
                    name: _mapping(
                        artifacts.get(name),
                        f"checked module-export {name} artifact",
                    )
                    for name in artifacts
                }
                if any(
                    set(artifact) != {"sha256", "payload"}
                    for artifact in artifact_rows.values()
                ):
                    raise ExternalEnvironmentError(
                        "checked module-export artifact binding is malformed"
                    )
                schema = BoundarySchemaV1.parse(
                    artifact_rows["boundary_schema"]["payload"]
                )
                layout = TargetDataLayoutV1.parse(
                    artifact_rows["target_data_layout"]["payload"],
                    schema=schema,
                )
                frame_payload = _mapping(
                    artifact_rows["physical_call_frame_v3"]["payload"],
                    "checked module-export physical frame",
                )
                frame = PhysicalCallFrameV3.parse(
                    frame_payload, schema=schema, layout=layout
                )
                if (
                    artifact_rows["boundary_schema"].get("sha256")
                    != schema.schema_sha256
                    or artifact_rows["target_data_layout"].get("sha256")
                    != layout.layout_sha256
                    or artifact_rows["physical_call_frame_v3"].get("sha256")
                    != canonical_sha256_v3(frame_payload)
                    or frame.transport.subject.kind != "export"
                    or frame.transport.subject.identity
                    != subject.removeprefix("export:")
                    or frame.transport.subject.image_selector != image_id
                    or frame.transport.transfer_kind != "export"
                ):
                    raise ExternalEnvironmentError(
                        "checked module-export artifact binding is stale"
                    )
                physical_abi = _sha256(
                    catalog.get("physical_abi_sha256"),
                    "checked module-export physical ABI",
                )
                if (
                    physical_abi != physical_frame_abi_sha256_v1(frame_payload)
                    or catalog.get("checked_call_protocol_id")
                    != f"machine-call-protocol-v1:{physical_abi}"
                ):
                    raise ExternalEnvironmentError(
                        "checked module-export protocol identity is stale"
                    )
                claimed_status = _sha256(
                    catalog.get("status_sha256"),
                    "checked module-export status binding",
                )
                if claimed_status != canonical_sha256_v3({
                    key: value for key, value in catalog.items()
                    if key != "status_sha256"
                }):
                    raise ExternalEnvironmentError(
                        "checked module-export status binding is stale"
                    )
                continue
            if catalog.get("kind") != "checked_schema":
                continue
            if set(catalog) != {
                "subject", "kind", "status_sha256", "artifacts",
                "physical_frames", "callback_links",
            }:
                raise ExternalEnvironmentError(
                    "checked schema boundary fields are incomplete"
                )
            _text(catalog.get("subject"), "checked schema boundary subject")
            _sha256(
                catalog.get("status_sha256"),
                "checked schema boundary status binding",
            )
            artifacts = _mapping(
                catalog.get("artifacts"), "checked schema boundary artifacts"
            )
            schema_artifact = _mapping(
                artifacts.get("boundary_schema"),
                "checked schema boundary schema artifact",
            )
            layout_artifact = _mapping(
                artifacts.get("target_data_layout"),
                "checked schema boundary layout artifact",
            )
            for label, artifact in (
                ("schema", schema_artifact), ("layout", layout_artifact),
            ):
                if set(artifact) != {"sha256", "payload"}:
                    raise ExternalEnvironmentError(
                        f"checked schema boundary {label} artifact is malformed"
                    )
                _sha256(
                    artifact.get("sha256"),
                    f"checked schema boundary {label} source binding",
                )
            schema = BoundarySchemaV1.parse(schema_artifact.get("payload"))
            layout = TargetDataLayoutV1.parse(
                layout_artifact.get("payload"), schema=schema
            )
            physical_frames = _rows(
                catalog.get("physical_frames"),
                "checked schema physical frames",
            )
            frame_names: list[str] = []
            parsed_frames: dict[str, PhysicalCallFrameV3] = {}
            bindings_by_frame: dict[str, list[dict[str, Any]]] = {}
            for frame_index, raw_frame in enumerate(physical_frames):
                frame_row = _mapping(
                    raw_frame,
                    f"checked schema physical frame {frame_index}",
                )
                if set(frame_row) != {
                    "frame_name", "frame_sha256", "physical_frame",
                    "machine_bindings",
                }:
                    raise ExternalEnvironmentError(
                        "checked schema physical-frame fields are incomplete"
                    )
                frame_names.append(_text(
                    frame_row.get("frame_name"),
                    "checked schema physical-frame name",
                ))
                _sha256(
                    frame_row.get("frame_sha256"),
                    "checked schema physical-frame source binding",
                )
                frame = PhysicalCallFrameV3.parse(
                    frame_row.get("physical_frame"),
                    schema=schema,
                    layout=layout,
                )
                claimed = [
                    dict(_mapping(item, "checked schema machine binding"))
                    for item in _rows(
                        frame_row.get("machine_bindings"),
                        "checked schema machine bindings",
                    )
                ]
                expected = schema_frame_machine_bindings_v1(
                    frame, machine_imports=machine_imports
                )
                if claimed != expected:
                    raise ExternalEnvironmentError(
                        "checked schema machine binding differs from the "
                        "selected environment contracts"
                    )
                parsed_frames[frame_names[-1]] = frame
                bindings_by_frame[frame_names[-1]] = claimed
                if len(expected) != 1 and status == "complete":
                    raise ExternalEnvironmentError(
                        "complete resolved environment has an unbound or "
                        "ambiguous checked schema frame"
                    )
            if frame_names != sorted(set(frame_names)):
                raise ExternalEnvironmentError(
                    "checked schema physical frames are duplicated or "
                    "noncanonical"
                )
            callback_links = [
                dict(_mapping(item, "checked schema callback link"))
                for item in _rows(
                    catalog.get("callback_links"),
                    "checked schema callback links",
                )
            ]
            expected_links, expected_link_issues = schema_callback_links_v1(
                schema=schema,
                layout=layout,
                frames=parsed_frames,
                frame_bindings=bindings_by_frame,
                machine_imports=machine_imports,
            )
            if callback_links != expected_links:
                raise ExternalEnvironmentError(
                    "checked schema callback links differ from their frame "
                    "and machine-contract relationships"
                )
            expected_link_blockers = [{
                "subject": catalog["subject"],
                **issue,
            } for issue in expected_link_issues]
            if any(row not in blockers for row in expected_link_blockers):
                raise ExternalEnvironmentError(
                    "checked schema callback relationship blocker is missing"
                )
            if expected_link_issues and status == "complete":
                raise ExternalEnvironmentError(
                    "complete resolved environment has an unresolved "
                    "checked callback relationship"
                )
        checked_protocols = [
            _checked_exception_protocol(
                row, f"resolved checked_exception_protocols[{index}]"
            )
            for index, row in enumerate(arrays["checked_exception_protocols"])
        ]
        protocol_ids = [str(row["protocol_id"]) for row in checked_protocols]
        occurrence_keys = [
            canonical_sha256_v3(row["occurrence"])
            for row in checked_protocols
        ]
        if (
            protocol_ids != sorted(set(protocol_ids))
            or len(occurrence_keys) != len(set(occurrence_keys))
        ):
            raise ExternalEnvironmentError(
                "resolved checked-exception protocols are duplicated or noncanonical"
            )
        if module_interface is not None:
            identity = _mapping(
                module_interface.get("identity"), "module-interface identity"
            )
            if (
                bindings["module_interface_sha256"]
                != module_interface.get("interface_sha256")
                or bindings["module_pe_sha256"] != identity.get("pe_sha256")
            ):
                raise ExternalEnvironmentError(
                    "resolved external environment is stale for its module"
                )
        return cls(payload)

    @classmethod
    def load(
        cls,
        path: Path,
        *,
        module_interface: Mapping[str, Any] | None = None,
    ) -> "ResolvedExternalEnvironmentV1":
        try:
            value = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ExternalEnvironmentError(
                f"cannot read resolved external environment: {exc}"
            ) from exc
        return cls.parse(value, module_interface=module_interface)


def resolved_interface_method_index_v1(
    environment: ResolvedExternalEnvironmentV1,
) -> dict[str, dict[str, Any]]:
    """Return the one content-bound interface-method catalog.

    Consumers must not independently assign identities to interface methods.
    The resolved environment owns the catalog and this projection gives the
    semantic linker, component checker, and native realization the same key.
    """

    result: dict[str, dict[str, Any]] = {}
    for catalog_index, raw_catalog in enumerate(
        environment.payload["interface_method_catalogs"]
    ):
        catalog = _mapping(
            raw_catalog, f"resolved interface-method catalog {catalog_index}"
        )
        profile_id = catalog.get("profile_id")
        profile_sha256 = catalog.get("profile_sha256")
        interface_id = catalog.get("interface_id")
        methods = _rows(
            catalog.get("methods"),
            f"resolved interface-method catalog {catalog_index} methods",
        )
        for method_index, raw_method in enumerate(methods):
            method = _mapping(
                raw_method,
                f"resolved interface method {catalog_index}:{method_index}",
            )
            core = {
                "profile_id": profile_id,
                "profile_sha256": profile_sha256,
                "interface_id": interface_id,
                "method": dict(method),
            }
            identity = canonical_sha256_v3(core)
            if identity in result:
                raise ExternalEnvironmentError(
                    "resolved interface-method contract is duplicated"
                )
            result[identity] = core
    return result


__all__ = [
    "ExternalEnvironmentError",
    "ResolvedExternalEnvironmentV1",
    "bind_checked_exception_protocol_v1",
    "bind_launch_policy_v1",
    "resolved_interface_method_index_v1",
]

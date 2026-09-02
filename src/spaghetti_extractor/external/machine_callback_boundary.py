"""Canonical checked callback boundaries derived from selected runtime profiles.

Runtime profiles already carry the word-exact callback ABI used by an imported
registration function.  This module lowers that authority through the ordinary
boundary kernel so native ingress does not require an operator-authored copy of
the same physical protocol.
"""

from __future__ import annotations

from typing import Any, Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..artifacts.callback_protocols import CALLBACK_PROTOCOL_FORMAT
from ..boundary import (
    BoundaryEvidenceReceiptV1,
    BoundaryFactSetV1,
    BoundaryFactV1,
    BoundaryLifecycleReceiptV1,
    BoundaryLifecycleV1,
    BoundaryRequirementV1,
    BoundarySchemaV1,
    BoundarySubjectV1,
    TargetDataLayoutV1,
)
from ..calls.dialects.ia32 import IA32DialectCheckerV1
from ..calls.evidence import TRANSPORT_FIELDS, validate_pe32_callback_protocol_frame_v1
from ..calls.protocol_v2 import CheckedCallProtocolV2
from ..errors import ToolkitInputError


class MachineCallbackBoundaryError(ToolkitInputError):
    """A selected machine-import callback cannot form one checked boundary."""


def _mapping(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise MachineCallbackBoundaryError(f"{context} must be an object")
    return value


def _artifact(payload: Mapping[str, Any], identity: str | None = None) -> dict[str, Any]:
    return {
        "sha256": identity or canonical_sha256_v3(dict(payload)),
        "payload": dict(payload),
    }


def machine_callback_boundary_catalog_v1(
    row: Mapping[str, Any], *, abi_dialect: str,
) -> dict[str, Any] | None:
    """Lower one selected import row's optional callback protocol.

    The selected profile is checked external-environment authority.  Its exact
    callback frame is represented by the same BoundarySchemaV1,
    PhysicalCallFrameV3, lifecycle, evidence, and CheckedCallProtocolV2 codecs
    as an authored boundary.  Registration lifetime and publication policy
    remain in ``callback_protocol`` and are consumed by the semantic module.
    """

    raw_contract = row.get("contract")
    if raw_contract is None:
        # The resolved-environment catalog also contains loader-service and
        # otherwise unmatched imports.  Absence of a selected profile contract
        # means there is no profile-owned callback ABI to lower; it is not a
        # malformed callback declaration.  A present but malformed contract
        # still fails closed below.
        return None
    contract = _mapping(raw_contract, "machine callback contract")
    payload = _mapping(contract.get("payload"), "machine callback payload")
    raw_protocol = payload.get("callback_protocol")
    if raw_protocol is None:
        return None
    protocol = _mapping(raw_protocol, "machine callback protocol")
    protocol_id = protocol.get("id")
    signature = _mapping(
        protocol.get("signature"), "machine callback signature"
    )
    argument_words = signature.get("argument_words")
    cleanup_bytes = signature.get("stack_cleanup_bytes")
    result = _mapping(signature.get("result"), "machine callback result")
    convention = {
        "pe32-cdecl-v1": "cdecl",
        "pe32-stdcall-v1": "stdcall",
    }.get(signature.get("abi_template"))
    if (
        not isinstance(protocol_id, str) or not protocol_id
        or not isinstance(argument_words, int)
        or isinstance(argument_words, bool) or argument_words < 0
        or not isinstance(cleanup_bytes, int)
        or isinstance(cleanup_bytes, bool) or cleanup_bytes < 0
        or convention is None
        or result.get("kind") not in {"void", "word"}
        or (
            result.get("kind") == "word"
            and result.get("register") != "eax"
        )
    ):
        raise MachineCallbackBoundaryError(
            f"callback protocol {protocol_id!r} has an unsupported PE32 signature"
        )
    expected_cleanup = 0 if convention == "cdecl" else argument_words * 4
    if cleanup_bytes != expected_cleanup:
        raise MachineCallbackBoundaryError(
            f"callback protocol {protocol_id!r} stack cleanup contradicts its ABI"
        )

    identity = _mapping(row.get("identity"), "machine callback import identity")
    binding = {
        key: contract.get(key)
        for key in ("profile_id", "profile_sha256", "entry_key", "entry_index")
    }
    profile_sha256 = binding.get("profile_sha256")
    if not isinstance(profile_sha256, str):
        raise MachineCallbackBoundaryError(
            "machine callback contract omits its selected profile binding"
        )
    schema_key = canonical_sha256_v3({
        "protocol": dict(protocol),
        "contract_binding": binding,
        "abi_dialect": abi_dialect,
    })[:20]
    schema = BoundarySchemaV1.create(
        schema_id=f"machine-callback-{schema_key}",
        types=[
            {"id": "unit", "kind": "void"},
            {"id": "u32", "kind": "integer", "width_bits": 32, "signed": False},
            {
                "id": "callback-function",
                "kind": "function",
                "result_type_id": "unit" if result["kind"] == "void" else "u32",
                "parameter_type_ids": ["u32"] * argument_words,
                "variadic": False,
                "calling_convention": convention,
            },
        ],
        signatures=[{
            "id": "invoke",
            "function_type_id": "callback-function",
            "parameters": [
                {
                    "id": f"argument-{index}", "type_id": "u32",
                    "interpretation": "value", "nullable": False,
                    "access": "none",
                    "extent": {"kind": "none", "bytes": None, "value_id": None},
                    "resource_kind": None, "provider_domain": None,
                }
                for index in range(argument_words)
            ],
            "results": [] if result["kind"] == "void" else [{
                "id": "result", "type_id": "u32",
                "interpretation": "value", "nullable": False,
                "access": "none",
                "extent": {"kind": "none", "bytes": None, "value_id": None},
                "resource_kind": None, "provider_domain": None,
            }],
        }],
    )
    layout = TargetDataLayoutV1.create(
        target="i686-pc-windows-pe32",
        abi_dialect=abi_dialect,
        byte_order="little",
        pointer_width_bits=32,
        packing="natural",
        schema=schema,
        layouts=[{
            "type_id": "u32", "size_bits": 32, "alignment_bits": 32,
            "value_bits": 32, "abi_class": "integer", "fields": [],
            "padding": [],
        }],
    )
    frame = IA32DialectCheckerV1(abi_dialect).lower_boundary(
        subject={"kind": "callback", "id": protocol_id, "image_selector": None},
        schema=schema,
        layout=layout,
        signature_id="invoke",
        transfer_kind="callback",
        outcomes=("normal",),
    )
    validate_pe32_callback_protocol_frame_v1(
        frame.transport, protocol=protocol
    )

    transport = frame.transport.to_payload()
    subject = BoundarySubjectV1.parse(transport["subject"])
    requirements = tuple(
        BoundaryRequirementV1.create(
            key=f"call-frame.{key}",
            legal_values=[transport[key]],
            rule_ids=[f"selected-runtime-profile.callback.{key}"],
            requires_observation=True,
        )
        for key in sorted(TRANSPORT_FIELDS)
    )
    fact_set = BoundaryFactSetV1.create(
        producer_class="checked_authority",
        producer_id="selected-runtime-profile-callback",
        subject=subject,
        binary_sha256=profile_sha256,
        facts=tuple(
            BoundaryFactV1.create(
                key=f"call-frame.{key}", state="exact", values=[transport[key]]
            )
            for key in sorted(TRANSPORT_FIELDS)
        ),
        dependency_ids=(str(binding.get("profile_id")), protocol_id),
    )
    evidence = BoundaryEvidenceReceiptV1.reconcile(
        subject=subject,
        binary_sha256=profile_sha256,
        requirements=requirements,
        fact_sets=(fact_set,),
    )
    lifecycle = BoundaryLifecycleV1.create(
        schema=schema, signature_id="invoke", bindings=()
    )
    lifecycle_receipt = BoundaryLifecycleReceiptV1.check(
        lifecycle, checked_interaction_contract_ids=()
    )
    checked = CheckedCallProtocolV2.create(
        schema=schema,
        layout=layout,
        signature_id="invoke",
        frame=frame,
        evidence_receipt=evidence,
        lifecycle=lifecycle,
        lifecycle_receipt=lifecycle_receipt,
    )
    if checked.status != "complete":  # pragma: no cover - closed construction
        raise MachineCallbackBoundaryError(
            f"callback protocol {protocol_id!r} did not produce a complete boundary"
        )

    schema_payload = schema.to_payload()
    layout_payload = layout.to_payload()
    frame_payload = frame.to_payload()
    evidence_payload = evidence.to_payload()
    lifecycle_payload = lifecycle.to_payload()
    lifecycle_receipt_payload = lifecycle_receipt.to_payload()
    checked_payload = checked.to_payload()
    catalog: dict[str, Any] = {
        "subject": f"callback:{protocol_id}",
        "kind": "checked_machine_callback",
        "roles": [str(row.get("import_kind", "ordinary"))],
        "identity": dict(identity),
        "contract_binding": binding,
        "callback_protocol": dict(protocol),
        "artifacts": {
            "boundary_schema": _artifact(schema_payload, schema.schema_sha256),
            "target_data_layout": _artifact(layout_payload, layout.layout_sha256),
            "physical_call_frame_v3": _artifact(frame_payload),
            "boundary_evidence_receipt": _artifact(evidence_payload),
            "boundary_lifecycle": _artifact(
                lifecycle_payload, lifecycle.lifecycle_sha256
            ),
            "boundary_lifecycle_receipt": _artifact(
                lifecycle_receipt_payload, lifecycle_receipt.receipt_sha256
            ),
            "checked_call_protocol": _artifact(checked_payload),
        },
    }
    catalog["status_sha256"] = canonical_sha256_v3(catalog)
    return catalog


def interface_callback_boundary_catalog_v1(
    target: Mapping[str, Any], *, abi_dialect: str,
) -> dict[str, Any] | None:
    """Lower one checked interface method's callback through the same kernel.

    Interface profiles are pinned-header authority for the callback's source,
    physical ABI, result, lifetime, and typed interface arguments.  This
    adapter only presents those existing facts to the ordinary callback
    boundary builder; it does not invent another callback protocol system.
    """

    method = _mapping(target.get("method"), "interface callback method")
    effect = method.get("callback_effect")
    if effect == "none":
        return None
    if effect != "explicit" or method.get("callback_contract_status") != "complete":
        raise MachineCallbackBoundaryError(
            "interface callback method has no complete callback contract"
        )
    method_sha256 = target.get("method_contract_sha256")
    core = {
        key: value for key, value in target.items()
        if key != "method_contract_sha256"
    }
    source = _mapping(method.get("callback_source"), "interface callback source")
    abi = _mapping(method.get("callback_abi"), "interface callback ABI")
    result = _mapping(abi.get("result"), "interface callback result")
    lifetime = method.get("callback_lifetime")
    protocol_method = _mapping(
        method.get("external_protocol"), "interface callback protocol"
    )
    argument_words = abi.get("argument_words")
    cleanup_bytes = abi.get("stack_cleanup_bytes")
    nullable = abi.get("nullable")
    if (
        not isinstance(method_sha256, str)
        or method_sha256 != canonical_sha256_v3(core)
        or source.get("kind") != "argument_word"
        or not isinstance(source.get("argument"), int)
        or isinstance(source.get("argument"), bool)
        or not isinstance(argument_words, int)
        or isinstance(argument_words, bool)
        or not 0 <= argument_words <= 64
        or cleanup_bytes != argument_words * 4
        or not isinstance(nullable, bool)
        or result.get("kind") not in {"void", "word"}
        or (
            result.get("kind") == "word" and result.get("register") != "eax"
        )
        or not isinstance(lifetime, str)
        or not lifetime
        or not isinstance(protocol_method.get("method"), str)
    ):
        raise MachineCallbackBoundaryError(
            "interface callback method authority is malformed"
        )
    callback_core = {
        "abi": dict(abi),
        "arguments": list(method.get("callback_arguments", [])),
        "lifetime": lifetime,
        "source": dict(source),
    }
    callback_sha256 = canonical_sha256_v3(callback_core)
    protocol_id = f"interface-callback-v1:{callback_sha256}"
    protocol = {
        "format": CALLBACK_PROTOCOL_FORMAT,
        "id": protocol_id,
        "action": "register",
        "source": {
            **dict(source),
            "sentinels": (
                [{"kind": "null", "word": 0}]
                if nullable else []
            ),
        },
        "signature": {
            "abi_template": "pe32-stdcall-v1",
            "argument_words": argument_words,
            "stack_cleanup_bytes": cleanup_bytes,
            "result": dict(result),
        },
        "lifetime": {"kind": lifetime, "end_event": None},
        "delivery": {
            "thread": "external_concurrent",
            "timing": "nested",
        },
        "cardinality": {
            "minimum": 0,
            "maximum": None,
            "scope": "method_invocation_generation",
        },
        "instance": {
            "kind": "interface_method_invocation",
            "argument": int(
                _mapping(
                    method.get("receiver_resource"),
                    "interface callback receiver",
                )["argument_index"]
            ),
            "callback_argument": None,
        },
        "previous_result": None,
        "provider_behavior": {
            "instance_relation": "checked_interface_method_invocation",
        },
    }
    profile_id = target.get("profile_id")
    profile_sha256 = target.get("profile_sha256")
    interface_id = target.get("interface_id")
    if not all(
        isinstance(value, str) and value
        for value in (profile_id, profile_sha256, interface_id)
    ):
        raise MachineCallbackBoundaryError(
            "interface callback profile identity is malformed"
        )
    row = {
        "identity": {
            "callback_contract_sha256": callback_sha256,
        },
        "import_kind": "interface_method",
        "contract": {
            "profile_id": "checked-interface-callback-v1",
            "profile_sha256": callback_sha256,
            "entry_key": "interface_callback_contracts",
            "entry_index": 0,
            "payload": {"callback_protocol": protocol},
        },
    }
    catalog = machine_callback_boundary_catalog_v1(
        row, abi_dialect=abi_dialect
    )
    assert catalog is not None
    catalog.update({
        "kind": "checked_interface_callback",
        "identity": dict(row["identity"]),
        "contract_binding": dict(catalog["contract_binding"]),
        "callback_arguments": list(method.get("callback_arguments", [])),
    })
    catalog["status_sha256"] = canonical_sha256_v3({
        key: value for key, value in catalog.items()
        if key != "status_sha256"
    })
    return catalog


__all__ = [
    "MachineCallbackBoundaryError", "interface_callback_boundary_catalog_v1",
    "machine_callback_boundary_catalog_v1",
]

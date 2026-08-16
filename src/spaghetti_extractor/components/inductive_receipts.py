"""Checked authority envelopes for inductive machine and source evidence."""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from typing import Mapping, Sequence

from ..artifacts.artifact_set import CanonicalValueV3, canonical_sha256_v3
from .semantic_induction import (
    INDUCTIVE_MACHINE_SHAPE_V1,
    INDUCTIVE_SEGMENT_INVENTORY_V1,
    build_inductive_machine_shape,
    build_inductive_segment_inventory,
)


INDUCTIVE_MACHINE_RECEIPT_V1 = (
    "spaghetti-extractor-inductive-machine-receipt-v1"
)
INDUCTIVE_SOURCE_RECEIPT_V1 = (
    "spaghetti-extractor-inductive-source-refinement-receipt-v1"
)
INDUCTIVE_REFINEMENT_RECEIPT_V1 = (
    "spaghetti-extractor-inductive-refinement-receipt-v1"
)

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.:-]*[A-Za-z0-9])?\Z")


class InductiveReceiptError(ValueError):
    """An induction authority receipt is malformed or contradictory."""


def _object(value: object, fields: set[str], context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise InductiveReceiptError(
            f"{context} must contain exactly {sorted(fields)!r}"
        )
    return value


def _mapping(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise InductiveReceiptError(f"{context} must be an object")
    return value


def _rows(value: object, context: str) -> list[Mapping[str, object]]:
    if not isinstance(value, list) or any(not isinstance(row, Mapping) for row in value):
        raise InductiveReceiptError(f"{context} must be an array of objects")
    return list(value)


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise InductiveReceiptError(f"{context} must be a nonempty string")
    return value


def _identifier(value: object, context: str) -> str:
    result = _text(value, context)
    if _ID.fullmatch(result) is None:
        raise InductiveReceiptError(f"{context} is not canonical")
    return result


def _digest(value: object, context: str) -> str:
    result = _text(value, context)
    if _DIGEST.fullmatch(result) is None:
        raise InductiveReceiptError(f"{context} must be a SHA-256 digest")
    return result


def _strings(value: object, context: str, *, nonempty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise InductiveReceiptError(f"{context} must be an array")
    result = tuple(_identifier(item, context) for item in value)
    if nonempty and not result:
        raise InductiveReceiptError(f"{context} must not be empty")
    if list(result) != sorted(result) or len(result) != len(set(result)):
        raise InductiveReceiptError(f"{context} must be ordered and unique")
    return result


def _identity_sequence(
    value: object, context: str, *, nonempty: bool = False
) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise InductiveReceiptError(f"{context} must be an array")
    result = tuple(_identifier(item, context) for item in value)
    if nonempty and not result:
        raise InductiveReceiptError(f"{context} must not be empty")
    if len(result) != len(set(result)):
        raise InductiveReceiptError(f"{context} contains duplicates")
    return result


def _texts(value: object, context: str, *, nonempty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise InductiveReceiptError(f"{context} must be an array")
    result = tuple(_text(item, context) for item in value)
    if nonempty and not result:
        raise InductiveReceiptError(f"{context} must not be empty")
    if list(result) != sorted(result) or len(result) != len(set(result)):
        raise InductiveReceiptError(f"{context} must be ordered and unique")
    return result


@dataclass(frozen=True)
class CheckedInductiveMachineReceiptV1:
    operation_id: str
    semantic_contract_sha256: str
    operation_sha256: str
    shape: CanonicalValueV3
    segment_inventory: CanonicalValueV3
    receipt_sha256: str

    @classmethod
    def parse(
        cls,
        value: object,
        *,
        exact_operation: Mapping[str, object] | None = None,
    ) -> "CheckedInductiveMachineReceiptV1":
        row = _object(
            value,
            {
                "format",
                "status",
                "operation_id",
                "semantic_contract_sha256",
                "operation_sha256",
                "machine_shape",
                "segment_inventory",
                "policy",
                "receipt_sha256",
            },
            "inductive machine receipt",
        )
        if row["format"] != INDUCTIVE_MACHINE_RECEIPT_V1 or row["status"] != "checked":
            raise InductiveReceiptError("inductive machine receipt is not checked V1")
        operation_id = _identifier(row["operation_id"], "machine receipt operation")
        operation_sha256 = _digest(
            row["operation_sha256"], "machine receipt operation digest"
        )
        shape = _validate_shape(row["machine_shape"], operation_id)
        inventory = _validate_inventory(row["segment_inventory"], shape)
        policy = _object(
            row["policy"],
            {
                "exact_machine_operation_replayed",
                "operator_edges_accepted",
                "bounded_unrolling_used",
            },
            "inductive machine receipt policy",
        )
        if policy != {
            "exact_machine_operation_replayed": True,
            "operator_edges_accepted": False,
            "bounded_unrolling_used": False,
        }:
            raise InductiveReceiptError("inductive machine receipt policy is unsafe")
        core = copy.deepcopy(dict(row))
        observed = _digest(core.pop("receipt_sha256"), "machine receipt digest")
        if canonical_sha256_v3(core) != observed:
            raise InductiveReceiptError("inductive machine receipt digest is stale")
        if exact_operation is not None:
            if canonical_sha256_v3(exact_operation) != operation_sha256:
                raise InductiveReceiptError(
                    "inductive machine receipt operation binding is stale"
                )
            expected_shape = build_inductive_machine_shape(exact_operation)
            expected_inventory = build_inductive_segment_inventory(
                exact_operation,
                cutpoint_unit_ids=tuple(inventory["cutpoint_unit_ids"]),
            )
            if expected_shape != shape or expected_inventory != inventory:
                raise InductiveReceiptError(
                    "inductive machine receipt differs from exact replay"
                )
        return cls(
            operation_id,
            _digest(
                row["semantic_contract_sha256"],
                "machine receipt semantic contract digest",
            ),
            operation_sha256,
            CanonicalValueV3.of(shape),
            CanonicalValueV3.of(inventory),
            observed,
        )

    def to_payload(self) -> dict[str, object]:
        core: dict[str, object] = {
            "format": INDUCTIVE_MACHINE_RECEIPT_V1,
            "status": "checked",
            "operation_id": self.operation_id,
            "semantic_contract_sha256": self.semantic_contract_sha256,
            "operation_sha256": self.operation_sha256,
            "machine_shape": self.shape.to_value(),
            "segment_inventory": self.segment_inventory.to_value(),
            "policy": {
                "exact_machine_operation_replayed": True,
                "operator_edges_accepted": False,
                "bounded_unrolling_used": False,
            },
        }
        return {**core, "receipt_sha256": self.receipt_sha256}


def build_inductive_machine_receipt(
    *,
    operation: Mapping[str, object],
    semantic_contract_sha256: str,
    cutpoint_unit_ids: Sequence[str],
) -> CheckedInductiveMachineReceiptV1:
    shape = build_inductive_machine_shape(operation)
    inventory = build_inductive_segment_inventory(
        operation, cutpoint_unit_ids=cutpoint_unit_ids
    )
    core: dict[str, object] = {
        "format": INDUCTIVE_MACHINE_RECEIPT_V1,
        "status": "checked",
        "operation_id": shape["operation_id"],
        "semantic_contract_sha256": _digest(
            semantic_contract_sha256, "semantic contract digest"
        ),
        "operation_sha256": canonical_sha256_v3(operation),
        "machine_shape": shape,
        "segment_inventory": inventory,
        "policy": {
            "exact_machine_operation_replayed": True,
            "operator_edges_accepted": False,
            "bounded_unrolling_used": False,
        },
    }
    return CheckedInductiveMachineReceiptV1.parse(
        {**core, "receipt_sha256": canonical_sha256_v3(core)},
        exact_operation=operation,
    )


@dataclass(frozen=True)
class InductiveSourceObligationV1:
    identity: str
    kind: str
    segment_ids: tuple[str, ...]
    source_symbol: str
    property_ids: tuple[str, ...]

    @classmethod
    def parse(cls, value: object, context: str) -> "InductiveSourceObligationV1":
        row = _object(
            value,
            {
                "obligation_id",
                "kind",
                "status",
                "segment_ids",
                "source_symbol",
                "property_ids",
            },
            context,
        )
        kind = _text(row["kind"], f"{context} kind")
        if kind not in {
            "initialization",
            "preservation",
            "bridge",
            "decrease",
            "exit",
            "completion",
        }:
            raise InductiveReceiptError(f"{context} kind is unsupported")
        if row["status"] != "satisfied":
            raise InductiveReceiptError(f"{context} is not satisfied")
        return cls(
            _identifier(row["obligation_id"], f"{context} id"),
            kind,
            _strings(row["segment_ids"], f"{context} segments"),
            _identifier(row["source_symbol"], f"{context} source symbol"),
            _texts(row["property_ids"], f"{context} properties", nonempty=True),
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "obligation_id": self.identity,
            "kind": self.kind,
            "status": "satisfied",
            "segment_ids": list(self.segment_ids),
            "source_symbol": self.source_symbol,
            "property_ids": list(self.property_ids),
        }


@dataclass(frozen=True)
class CheckedInductiveSourceReceiptV1:
    component_id: str
    interface_sha256: str
    operation_id: str
    semantic_contract_sha256: str
    source_profile_sha256: str
    source_plan_sha256: str
    relation_sha256: str
    implementation_sha256: str
    machine_receipt_sha256: str
    obligations: tuple[InductiveSourceObligationV1, ...]
    receipt_sha256: str
    payload: CanonicalValueV3

    @classmethod
    def parse(cls, value: object) -> "CheckedInductiveSourceReceiptV1":
        row = _object(
            value,
            {
                "format",
                "status",
                "component_id",
                "operation_id",
                "bindings",
                "checker",
                "obligations",
                "issues",
                "model",
                "policy",
                "receipt_sha256",
            },
            "inductive source receipt",
        )
        if row["format"] != INDUCTIVE_SOURCE_RECEIPT_V1 or row["status"] != "satisfied":
            raise InductiveReceiptError("inductive source receipt is not satisfied V1")
        bindings = _object(
            row["bindings"],
            {
                "interface_sha256",
                "semantic_contract_sha256",
                "source_profile_sha256",
                "source_plan_sha256",
                "relation_sha256",
                "implementation_sha256",
                "machine_receipt_sha256",
            },
            "inductive source receipt bindings",
        )
        checker = _object(
            row["checker"],
            {"id", "version", "executable_sha256", "output_sha256"},
            "inductive source checker",
        )
        if checker["id"] != "cbmc":
            raise InductiveReceiptError("inductive source checker must be CBMC")
        _text(checker["version"], "inductive source checker version")
        _digest(checker["executable_sha256"], "inductive source checker digest")
        _digest(checker["output_sha256"], "inductive source checker output digest")
        obligations = tuple(
            InductiveSourceObligationV1.parse(item, f"source obligation {index}")
            for index, item in enumerate(_rows(row["obligations"], "source obligations"))
        )
        obligation_ids = [item.identity for item in obligations]
        if not obligations or obligation_ids != sorted(obligation_ids) or len(obligation_ids) != len(set(obligation_ids)):
            raise InductiveReceiptError(
                "source obligations must be nonempty, ordered, and unique"
            )
        if row["issues"] != []:
            raise InductiveReceiptError(
                "satisfied inductive source receipt must not contain issues"
            )
        model = _object(
            row["model"],
            {"sha256", "segment_count", "cutpoint_count"},
            "inductive source model",
        )
        _digest(model["sha256"], "inductive source model digest")
        for field in ("segment_count", "cutpoint_count"):
            if (
                not isinstance(model[field], int)
                or isinstance(model[field], bool)
                or model[field] <= 0
            ):
                raise InductiveReceiptError(
                    f"inductive source model {field} is invalid"
                )
        policy = _object(
            row["policy"],
            {
                "original_binary_executed",
                "behavior_examples_used",
                "bounded_unwinding_used",
                "all_properties_satisfied",
            },
            "inductive source receipt policy",
        )
        if policy != {
            "original_binary_executed": False,
            "behavior_examples_used": False,
            "bounded_unwinding_used": False,
            "all_properties_satisfied": True,
        }:
            raise InductiveReceiptError("inductive source receipt policy is unsafe")
        core = copy.deepcopy(dict(row))
        observed = _digest(core.pop("receipt_sha256"), "source receipt digest")
        if canonical_sha256_v3(core) != observed:
            raise InductiveReceiptError("inductive source receipt digest is stale")
        return cls(
            _identifier(row["component_id"], "source receipt component"),
            _digest(bindings["interface_sha256"], "source interface digest"),
            _identifier(row["operation_id"], "source receipt operation"),
            _digest(bindings["semantic_contract_sha256"], "source semantic digest"),
            _digest(bindings["source_profile_sha256"], "source-profile digest"),
            _digest(bindings["source_plan_sha256"], "source-plan digest"),
            _digest(bindings["relation_sha256"], "cutpoint relation digest"),
            _digest(bindings["implementation_sha256"], "source implementation digest"),
            _digest(bindings["machine_receipt_sha256"], "machine receipt digest"),
            obligations,
            observed,
            CanonicalValueV3.of(row),
        )

    def to_payload(self) -> dict[str, object]:
        value = self.payload.to_value()
        assert isinstance(value, dict)
        return value


@dataclass(frozen=True)
class CheckedInductiveRefinementReceiptV1:
    component_id: str
    operation_id: str
    bindings: CanonicalValueV3
    artifacts: CanonicalValueV3
    receipt_sha256: str
    payload: CanonicalValueV3

    @classmethod
    def parse(cls, value: object) -> "CheckedInductiveRefinementReceiptV1":
        row = _object(
            value,
            {
                "format",
                "status",
                "component_id",
                "operation_id",
                "bindings",
                "artifacts",
                "issues",
                "assurance",
                "policy",
                "activation_authorized",
                "receipt_sha256",
            },
            "inductive refinement receipt",
        )
        if (
            row["format"] != INDUCTIVE_REFINEMENT_RECEIPT_V1
            or row["status"] != "satisfied"
            or row["activation_authorized"] is not True
        ):
            raise InductiveReceiptError(
                "inductive refinement receipt is not satisfied V1"
            )
        bindings = _object(
            row["bindings"],
            {
                "interface_sha256",
                "implementation_sha256",
                "semantic_contract_sha256",
                "source_profile_sha256",
                "source_plan_sha256",
                "relation_sha256",
                "machine_receipt_sha256",
                "certificate_sha256",
            },
            "inductive refinement bindings",
        )
        for name, digest in bindings.items():
            _digest(digest, f"inductive refinement binding {name}")
        artifacts = _object(
            row["artifacts"],
            {
                "machine_receipt_sha256",
                "source_receipt_sha256",
                "certificate_check_sha256",
            },
            "inductive refinement artifacts",
        )
        for name, digest in artifacts.items():
            _digest(digest, f"inductive refinement artifact {name}")
        if row["issues"] != []:
            raise InductiveReceiptError(
                "satisfied inductive refinement receipt has issues"
            )
        assurance = _object(
            row["assurance"],
            {
                "certificate_inventory_checked",
                "source_semantics_checked",
                "machine_semantics_checked",
                "receipt_contents_replayed_by_this_checker",
                "unsupported_constructs_fail_closed",
            },
            "inductive refinement assurance",
        )
        if assurance != {
            "certificate_inventory_checked": True,
            "source_semantics_checked": True,
            "machine_semantics_checked": True,
            "receipt_contents_replayed_by_this_checker": True,
            "unsupported_constructs_fail_closed": True,
        }:
            raise InductiveReceiptError(
                "inductive refinement assurance is insufficient"
            )
        policy = _object(
            row["policy"],
            {
                "original_binary_executed",
                "behavior_examples_used",
                "bounded_unwinding_used",
                "activation_authorized",
            },
            "inductive refinement policy",
        )
        if policy != {
            "original_binary_executed": False,
            "behavior_examples_used": False,
            "bounded_unwinding_used": False,
            "activation_authorized": True,
        }:
            raise InductiveReceiptError("inductive refinement policy is unsafe")
        core = copy.deepcopy(dict(row))
        observed = _digest(core.pop("receipt_sha256"), "refinement receipt digest")
        if canonical_sha256_v3(core) != observed:
            raise InductiveReceiptError("inductive refinement receipt digest is stale")
        return cls(
            _identifier(row["component_id"], "inductive refinement component"),
            _identifier(row["operation_id"], "inductive refinement operation"),
            CanonicalValueV3.of(bindings),
            CanonicalValueV3.of(artifacts),
            observed,
            CanonicalValueV3.of(row),
        )

    def to_payload(self) -> dict[str, object]:
        value = self.payload.to_value()
        assert isinstance(value, dict)
        return value


def build_inductive_refinement_receipt(
    *,
    certificate: object,
    certificate_check: object,
    machine_receipt: CheckedInductiveMachineReceiptV1,
    source_receipt: CheckedInductiveSourceReceiptV1,
) -> CheckedInductiveRefinementReceiptV1:
    from .inductive_contract import (
        InductiveOperationCertificateV1,
        InductiveOperationCheckV1,
    )

    checked_certificate = (
        certificate
        if isinstance(certificate, InductiveOperationCertificateV1)
        else InductiveOperationCertificateV1.parse(certificate)
    )
    checked_result = (
        certificate_check
        if isinstance(certificate_check, InductiveOperationCheckV1)
        else InductiveOperationCheckV1.parse(certificate_check)
    )
    bindings = checked_certificate.bindings
    if (
        checked_result.status != "complete"
        or checked_result.certificate_sha256
        != checked_certificate.certificate_sha256
        or source_receipt.operation_id != bindings.operation_id
        or source_receipt.interface_sha256 != bindings.interface_sha256
        or source_receipt.semantic_contract_sha256
        != bindings.machine_semantic_contract_sha256
        or source_receipt.source_plan_sha256 != bindings.source_plan_sha256
        or source_receipt.relation_sha256 != bindings.cutpoint_relation_sha256
        or source_receipt.implementation_sha256 != bindings.implementation_sha256
        or source_receipt.machine_receipt_sha256 != machine_receipt.receipt_sha256
    ):
        raise InductiveReceiptError(
            "inductive refinement artifacts do not close one exact certificate"
        )
    assurance_value = checked_result.assurance.to_value()
    assert isinstance(assurance_value, dict)
    assurance = {
        key: assurance_value[key]
        for key in (
            "certificate_inventory_checked",
            "source_semantics_checked",
            "machine_semantics_checked",
            "receipt_contents_replayed_by_this_checker",
            "unsupported_constructs_fail_closed",
        )
    }
    core: dict[str, object] = {
        "format": INDUCTIVE_REFINEMENT_RECEIPT_V1,
        "status": "satisfied",
        "component_id": source_receipt.component_id,
        "operation_id": source_receipt.operation_id,
        "bindings": {
            "interface_sha256": source_receipt.interface_sha256,
            "implementation_sha256": source_receipt.implementation_sha256,
            "semantic_contract_sha256": source_receipt.semantic_contract_sha256,
            "source_profile_sha256": source_receipt.source_profile_sha256,
            "source_plan_sha256": source_receipt.source_plan_sha256,
            "relation_sha256": source_receipt.relation_sha256,
            "machine_receipt_sha256": source_receipt.machine_receipt_sha256,
            "certificate_sha256": checked_certificate.certificate_sha256,
        },
        "artifacts": {
            "machine_receipt_sha256": machine_receipt.receipt_sha256,
            "source_receipt_sha256": source_receipt.receipt_sha256,
            "certificate_check_sha256": checked_result.check_sha256,
        },
        "issues": [],
        "assurance": assurance,
        "policy": {
            "original_binary_executed": False,
            "behavior_examples_used": False,
            "bounded_unwinding_used": False,
            "activation_authorized": True,
        },
        "activation_authorized": True,
    }
    return CheckedInductiveRefinementReceiptV1.parse(
        {**core, "receipt_sha256": canonical_sha256_v3(core)}
    )


def finalize_inductive_refinement_receipt(
    *,
    certificate: object,
    certificate_check: object,
    machine_receipt: CheckedInductiveMachineReceiptV1,
    source_receipt: object,
) -> dict[str, object]:
    """Return an authorizing receipt or a checked diagnostic receipt.

    A failed source proof remains useful operator feedback.  It must not make
    the derivation disappear, but it also cannot be parsed as checked
    activation authority.
    """

    from .inductive_contract import (
        InductiveOperationCertificateV1,
        InductiveOperationCheckV1,
    )

    checked_certificate = (
        certificate
        if isinstance(certificate, InductiveOperationCertificateV1)
        else InductiveOperationCertificateV1.parse(certificate)
    )
    checked_result = (
        certificate_check
        if isinstance(certificate_check, InductiveOperationCheckV1)
        else InductiveOperationCheckV1.parse(certificate_check)
    )
    if isinstance(source_receipt, CheckedInductiveSourceReceiptV1):
        source_payload = source_receipt.to_payload()
    elif isinstance(source_receipt, Mapping):
        source_payload = copy.deepcopy(dict(source_receipt))
    else:
        raise InductiveReceiptError("inductive source receipt must be an object")

    source_core = copy.deepcopy(source_payload)
    source_digest = _digest(
        source_core.pop("receipt_sha256", None), "source receipt digest"
    )
    if canonical_sha256_v3(source_core) != source_digest:
        raise InductiveReceiptError("inductive source receipt digest is stale")
    if source_payload.get("format") != INDUCTIVE_SOURCE_RECEIPT_V1:
        raise InductiveReceiptError("inductive source receipt has an unsupported format")
    source_status = source_payload.get("status")
    if source_status == "satisfied":
        return build_inductive_refinement_receipt(
            certificate=checked_certificate,
            certificate_check=checked_result,
            machine_receipt=machine_receipt,
            source_receipt=CheckedInductiveSourceReceiptV1.parse(source_payload),
        ).to_payload()
    if source_status not in {"incomplete", "violated"}:
        raise InductiveReceiptError("inductive source receipt status is invalid")

    bindings = _mapping(source_payload.get("bindings"), "source receipt bindings")
    certificate_bindings = checked_certificate.bindings
    expected_bindings = {
        "interface_sha256": certificate_bindings.interface_sha256,
        "implementation_sha256": certificate_bindings.implementation_sha256,
        "semantic_contract_sha256": (
            certificate_bindings.machine_semantic_contract_sha256
        ),
        "source_plan_sha256": certificate_bindings.source_plan_sha256,
        "relation_sha256": certificate_bindings.cutpoint_relation_sha256,
        "machine_receipt_sha256": machine_receipt.receipt_sha256,
    }
    for name, expected in expected_bindings.items():
        if bindings.get(name) != expected:
            raise InductiveReceiptError(
                f"diagnostic source receipt {name} binding is stale"
            )
    source_profile_sha256 = _digest(
        bindings.get("source_profile_sha256"), "source-profile digest"
    )
    if (
        checked_result.certificate_sha256
        != checked_certificate.certificate_sha256
        or machine_receipt.semantic_contract_sha256
        != certificate_bindings.machine_semantic_contract_sha256
    ):
        raise InductiveReceiptError(
            "diagnostic induction artifacts do not close one exact certificate"
        )

    source_issues = source_payload.get("issues")
    if not isinstance(source_issues, list) or not source_issues:
        raise InductiveReceiptError(
            "non-satisfied source receipt must contain diagnostic issues"
        )
    check_payload = checked_result.to_payload()
    check_issues = check_payload.get("issues")
    if not isinstance(check_issues, list):
        raise InductiveReceiptError("inductive certificate issues are malformed")
    assurance = checked_result.assurance.to_value()
    assert isinstance(assurance, dict)
    core: dict[str, object] = {
        "format": INDUCTIVE_REFINEMENT_RECEIPT_V1,
        "status": source_status,
        "component_id": _identifier(
            source_payload.get("component_id"), "source receipt component"
        ),
        "operation_id": _identifier(
            source_payload.get("operation_id"), "source receipt operation"
        ),
        "bindings": {
            **expected_bindings,
            "source_profile_sha256": source_profile_sha256,
            "certificate_sha256": checked_certificate.certificate_sha256,
        },
        "artifacts": {
            "machine_receipt_sha256": machine_receipt.receipt_sha256,
            "source_receipt_sha256": source_digest,
            "certificate_check_sha256": checked_result.check_sha256,
        },
        "issues": copy.deepcopy(source_issues) + copy.deepcopy(check_issues),
        "assurance": assurance,
        "policy": {
            "original_binary_executed": False,
            "behavior_examples_used": False,
            "bounded_unwinding_used": False,
            "activation_authorized": False,
        },
        "activation_authorized": False,
    }
    return {**core, "receipt_sha256": canonical_sha256_v3(core)}


def _validate_shape(value: object, operation_id: str) -> dict[str, object]:
    shape = copy.deepcopy(dict(_mapping(value, "inductive machine shape")))
    if shape.get("format") != INDUCTIVE_MACHINE_SHAPE_V1:
        raise InductiveReceiptError("machine shape has an unsupported format")
    if shape.get("operation_id") != operation_id:
        raise InductiveReceiptError("machine shape operation differs")
    observed = _digest(shape.get("shape_sha256"), "machine shape digest")
    core = dict(shape)
    core.pop("shape_sha256")
    if canonical_sha256_v3(core) != observed:
        raise InductiveReceiptError("machine shape digest is stale")
    units = _rows(shape.get("semantic_units"), "machine shape units")
    unit_ids = [_identifier(row.get("unit_id"), "machine shape unit id") for row in units]
    if not units or len(unit_ids) != len(set(unit_ids)):
        raise InductiveReceiptError("machine shape unit inventory is invalid")
    unit_set = set(unit_ids)
    edges = _rows(shape.get("control_edges"), "machine shape edges")
    for edge in edges:
        if edge.get("source_unit_id") not in unit_set or edge.get("target_unit_id") not in unit_set:
            raise InductiveReceiptError("machine shape edge leaves its unit inventory")
        _mapping(edge.get("condition"), "machine shape edge condition")
    scc_units: set[str] = set()
    for scc in _rows(shape.get("cyclic_sccs"), "machine cyclic SCCs"):
        members = set(
            _identity_sequence(
                scc.get("member_unit_ids"),
                "machine SCC members",
                nonempty=True,
            )
        )
        if not members <= unit_set or members & scc_units:
            raise InductiveReceiptError("machine cyclic SCC membership is invalid")
        scc_units |= members
    return shape


def _validate_inventory(
    value: object, shape: Mapping[str, object]
) -> dict[str, object]:
    inventory = copy.deepcopy(dict(_mapping(value, "inductive segment inventory")))
    if inventory.get("format") != INDUCTIVE_SEGMENT_INVENTORY_V1:
        raise InductiveReceiptError("segment inventory has an unsupported format")
    if inventory.get("operation_id") != shape.get("operation_id"):
        raise InductiveReceiptError("segment inventory operation differs")
    if inventory.get("machine_shape_sha256") != shape.get("shape_sha256"):
        raise InductiveReceiptError("segment inventory shape binding is stale")
    observed = _digest(inventory.get("inventory_sha256"), "segment inventory digest")
    core = dict(inventory)
    core.pop("inventory_sha256")
    if canonical_sha256_v3(core) != observed:
        raise InductiveReceiptError("segment inventory digest is stale")
    exact_edges = {
        (
            edge.get("source_unit_id"),
            edge.get("target_unit_id"),
            canonical_sha256_v3(edge.get("condition")),
        )
        for edge in _rows(shape.get("control_edges"), "machine shape edges")
    }
    covered: set[tuple[object, object, str]] = set()
    segment_ids: list[str] = []
    for segment in _rows(inventory.get("segments"), "machine segments"):
        segment_id = _identifier(segment.get("segment_id"), "machine segment id")
        segment_ids.append(segment_id)
        core_segment = {
            "source": copy.deepcopy(segment.get("source")),
            "target": copy.deepcopy(segment.get("target")),
            "unit_ids": copy.deepcopy(segment.get("unit_ids")),
            "edges": copy.deepcopy(segment.get("edges")),
        }
        expected_id = "component-segment-v1:" + canonical_sha256_v3(
            {"operation_id": inventory["operation_id"], **core_segment}
        )
        if segment_id != expected_id:
            raise InductiveReceiptError("machine segment identity is stale")
        for edge in _rows(segment.get("edges"), "machine segment edges"):
            covered.add(
                (
                    edge.get("source_unit_id"),
                    edge.get("target_unit_id"),
                    canonical_sha256_v3(edge.get("condition")),
                )
            )
    if len(segment_ids) != len(set(segment_ids)) or covered != exact_edges:
        raise InductiveReceiptError("machine segment edge closure is incomplete")
    if inventory.get("control_edge_count") != len(exact_edges) or inventory.get("covered_control_edge_count") != len(covered):
        raise InductiveReceiptError("machine segment edge counts are stale")
    return inventory


__all__ = [
    "INDUCTIVE_MACHINE_RECEIPT_V1",
    "INDUCTIVE_REFINEMENT_RECEIPT_V1",
    "INDUCTIVE_SOURCE_RECEIPT_V1",
    "CheckedInductiveMachineReceiptV1",
    "CheckedInductiveRefinementReceiptV1",
    "CheckedInductiveSourceReceiptV1",
    "InductiveReceiptError",
    "InductiveSourceObligationV1",
    "build_inductive_machine_receipt",
    "build_inductive_refinement_receipt",
    "finalize_inductive_refinement_receipt",
]

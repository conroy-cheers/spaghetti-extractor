"""Layered compatibility for checked call protocols."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from ..artifacts.formats import CALL_PROTOCOL_COMPATIBILITY_V1_FORMAT
from ._canonical import CallProtocolError, content_id
from .frame import PhysicalCallFrameV2
from .lifecycle import CallLifecycleV1
from .types import PortableTypeGraphV1, TargetLayoutSetV1


@dataclass(frozen=True)
class CallProtocolCompatibilityV1:
    compatibility_id: str
    status: str
    physical: str
    typed: str
    behavioral: str
    reasons: tuple[str, ...]

    @classmethod
    def check(
        cls,
        *,
        observed_frame: PhysicalCallFrameV2,
        expected_frame: PhysicalCallFrameV2,
        observed_graph: PortableTypeGraphV1,
        expected_graph: PortableTypeGraphV1,
        observed_function_type_id: str,
        expected_function_type_id: str,
        observed_layouts: TargetLayoutSetV1,
        expected_layouts: TargetLayoutSetV1,
        observed_lifecycle: CallLifecycleV1,
        expected_lifecycle: CallLifecycleV1,
    ) -> "CallProtocolCompatibilityV1":
        reasons: list[str] = []
        physical = "exact" if _frame_transport(observed_frame) == _frame_transport(expected_frame) else "incompatible"
        if physical == "incompatible":
            reasons.append("physical call transports differ")
        typed = _typed_compatibility(
            observed_graph,
            expected_graph,
            observed_function_type_id,
            expected_function_type_id,
            observed_layouts,
            expected_layouts,
        )
        if typed == "incompatible":
            reasons.append("faithful function types lack a constructive layout-preserving adapter")
        behavioral = "refines" if _lifecycle_refines(observed_lifecycle, expected_lifecycle) else "incompatible"
        if behavioral == "incompatible":
            reasons.append("observed lifecycle does not refine the expected lifecycle")
        status = "complete" if physical != "incompatible" and typed != "incompatible" and behavioral != "incompatible" else "violated"
        reasons_tuple = tuple(sorted(reasons))
        core = {"format": CALL_PROTOCOL_COMPATIBILITY_V1_FORMAT, "status": status, "physical": physical, "typed": typed, "behavioral": behavioral, "reasons": list(reasons_tuple)}
        return cls(content_id("call-protocol-compatibility-v1", core), status, physical, typed, behavioral, reasons_tuple)

    def to_payload(self) -> dict[str, object]:
        return {"format": CALL_PROTOCOL_COMPATIBILITY_V1_FORMAT, "id": self.compatibility_id, "status": self.status, "physical": self.physical, "typed": self.typed, "behavioral": self.behavioral, "reasons": list(self.reasons)}


def _frame_transport(frame: PhysicalCallFrameV2) -> Mapping[str, object]:
    payload = frame.to_payload()
    return {key: value for key, value in payload.items() if key not in {"format", "id", "subject"}}


def _typed_compatibility(
    observed: PortableTypeGraphV1,
    expected: PortableTypeGraphV1,
    observed_function: str,
    expected_function: str,
    observed_layouts: TargetLayoutSetV1,
    expected_layouts: TargetLayoutSetV1,
) -> str:
    seen: set[tuple[str, str]] = set()

    def compatible(left_id: str, right_id: str) -> bool:
        key = (left_id, right_id)
        if key in seen:
            return True
        seen.add(key)
        left = observed.index.get(left_id)
        right = expected.index.get(right_id)
        if left is None or right is None or left.kind != right.kind:
            return False
        if left.kind in {"void"}:
            return True
        if left.kind in {"bool", "integer", "float", "opaque"}:
            return dict(left.body) == dict(right.body)
        if left.kind == "pointer":
            return tuple(left.body["qualifiers"]) == tuple(right.body["qualifiers"]) and compatible(str(left.body["pointee_type_id"]), str(right.body["pointee_type_id"]))
        if left.kind in {"array", "vector"}:
            return left.body["element_count"] == right.body["element_count"] and compatible(str(left.body["element_type_id"]), str(right.body["element_type_id"]))
        if left.kind == "complex":
            return compatible(str(left.body["element_type_id"]), str(right.body["element_type_id"]))
        if left.kind == "enum":
            return left.body["enumerators"] == right.body["enumerators"] and compatible(str(left.body["underlying_type_id"]), str(right.body["underlying_type_id"]))
        if left.kind in {"record", "union"}:
            left_fields = list(left.body["fields"])
            right_fields = list(right.body["fields"])
            return len(left_fields) == len(right_fields) and all(
                one["bit_width"] == two["bit_width"]
                and compatible(str(one["type_id"]), str(two["type_id"]))
                for one, two in zip(left_fields, right_fields, strict=True)
            ) and _same_layout(observed_layouts, expected_layouts, left_id, right_id)
        if left.kind == "function":
            left_parameters = list(left.body["parameter_type_ids"])
            right_parameters = list(right.body["parameter_type_ids"])
            return (
                left.body["calling_convention"] == right.body["calling_convention"]
                and left.body["variadic"] == right.body["variadic"]
                and len(left_parameters) == len(right_parameters)
                and compatible(str(left.body["result_type_id"]), str(right.body["result_type_id"]))
                and all(compatible(str(one), str(two)) for one, two in zip(left_parameters, right_parameters, strict=True))
            )
        raise CallProtocolError(f"typed compatibility omitted type kind {left.kind!r}")

    if not compatible(observed_function, expected_function):
        return "incompatible"
    return "exact" if observed.graph_id == expected.graph_id and observed_function == expected_function else "constructive-adapter"


def _same_layout(left: TargetLayoutSetV1, right: TargetLayoutSetV1, left_id: str, right_id: str) -> bool:
    one = left.index.get(left_id)
    two = right.index.get(right_id)
    if one is None or two is None:
        return False
    return (
        one.size_bits == two.size_bits
        and one.alignment_bits == two.alignment_bits
        and one.value_bits == two.value_bits
        and [(item.offset_bits, item.storage_bits, item.value_bits) for item in one.fields]
        == [(item.offset_bits, item.storage_bits, item.value_bits) for item in two.fields]
    )


def _lifecycle_refines(observed: CallLifecycleV1, expected: CallLifecycleV1) -> bool:
    observed_bindings = {
        (item.path.key, item.transition, item.resource_kind, item.provider_domain, item.service_id)
        for item in observed.bindings
    }
    expected_bindings = {
        (item.path.key, item.transition, item.resource_kind, item.provider_domain, item.service_id)
        for item in expected.bindings
    }
    return expected_bindings <= observed_bindings and set(expected.interaction_contract_ids) <= set(observed.interaction_contract_ids)


__all__ = ["CallProtocolCompatibilityV1"]

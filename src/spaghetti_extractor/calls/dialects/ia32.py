"""Independent PE32 IA-32 GNU and Microsoft call-frame checker.

This module is intentionally independent of Clang/GCC proposal extraction.  It
computes the canonical transport allowed by a checked type graph and layout
set; compiler output and decoded machine facts are compared with its result by
the proposal layer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from ...artifacts.formats import IA32_DIALECT_RECEIPT_V1_FORMAT
from ...boundary import BoundarySchemaV1, TargetDataLayoutV1
from .._canonical import CallProtocolError, array, content_id, digest, exact, identifier, object_, text
from ..frame import CallSubjectV1, PhysicalCallFrameV2, PhysicalCallFrameV3
from ..evidence import MachineCallEvidenceV1
from ..boundary_adapter import reconcile_machine_call_evidence_v1
from ..types import PortableTypeGraphV1, PortableTypeNodeV1, TargetLayoutSetV1, TypeLayoutV1
from .ia32_profile import IA32_DIALECT_CALLING_CONVENTIONS, IA32_DIALECTS


@dataclass(frozen=True)
class IA32DialectReceiptV1:
    receipt_id: str
    status: str
    abi_dialect: str
    type_graph_sha256: str
    layout_set_sha256: str
    expected_frame_sha256: str | None
    proposed_frame_sha256: str | None
    machine_evidence_ids: tuple[str, ...]
    issues: tuple[str, ...]

    @classmethod
    def create(
        cls,
        *,
        status: str,
        abi_dialect: str,
        type_graph_sha256: str,
        layout_set_sha256: str,
        expected_frame_sha256: str | None,
        proposed_frame_sha256: str | None,
        machine_evidence_ids: Sequence[str],
        issues: Sequence[str],
    ) -> "IA32DialectReceiptV1":
        if status not in {"complete", "incomplete", "violated"}:
            raise CallProtocolError("IA-32 dialect receipt status is unsupported")
        issue_values = tuple(sorted(set(text(item, "IA-32 dialect issue") for item in issues)))
        if status == "complete" and issue_values:
            raise CallProtocolError("complete IA-32 dialect receipt cannot retain issues")
        if status != "complete" and not issue_values:
            raise CallProtocolError("non-complete IA-32 dialect receipt must explain its issues")
        evidence = tuple(sorted(set(identifier(item, "machine evidence id") for item in machine_evidence_ids)))
        core = {
            "format": IA32_DIALECT_RECEIPT_V1_FORMAT,
            "status": status,
            "abi_dialect": abi_dialect,
            "type_graph_sha256": digest(type_graph_sha256, "type graph digest"),
            "layout_set_sha256": digest(layout_set_sha256, "layout set digest"),
            "expected_frame_sha256": None if expected_frame_sha256 is None else digest(expected_frame_sha256, "expected frame digest"),
            "proposed_frame_sha256": None if proposed_frame_sha256 is None else digest(proposed_frame_sha256, "proposed frame digest"),
            "machine_evidence_ids": list(evidence),
            "issues": list(issue_values),
        }
        return cls(content_id("ia32-dialect-receipt-v1", core), status, abi_dialect, str(core["type_graph_sha256"]), str(core["layout_set_sha256"]), core["expected_frame_sha256"], core["proposed_frame_sha256"], evidence, issue_values)

    @classmethod
    def parse(cls, value: object) -> "IA32DialectReceiptV1":
        row = object_(value, "IA-32 dialect receipt")
        exact(row, {"format", "id", "status", "abi_dialect", "type_graph_sha256", "layout_set_sha256", "expected_frame_sha256", "proposed_frame_sha256", "machine_evidence_ids", "issues"}, "IA-32 dialect receipt")
        if row["format"] != IA32_DIALECT_RECEIPT_V1_FORMAT:
            raise CallProtocolError("unsupported IA-32 dialect receipt format")
        result = cls.create(status=str(row["status"]), abi_dialect=str(row["abi_dialect"]), type_graph_sha256=str(row["type_graph_sha256"]), layout_set_sha256=str(row["layout_set_sha256"]), expected_frame_sha256=None if row["expected_frame_sha256"] is None else str(row["expected_frame_sha256"]), proposed_frame_sha256=None if row["proposed_frame_sha256"] is None else str(row["proposed_frame_sha256"]), machine_evidence_ids=[str(item) for item in array(row["machine_evidence_ids"], "machine evidence ids")], issues=[str(item) for item in array(row["issues"], "IA-32 dialect issues")])
        if row["id"] != result.receipt_id:
            raise CallProtocolError("IA-32 dialect receipt id does not bind its contents")
        return result

    def to_payload(self) -> dict[str, object]:
        return {
            "format": IA32_DIALECT_RECEIPT_V1_FORMAT,
            "id": self.receipt_id,
            "status": self.status,
            "abi_dialect": self.abi_dialect,
            "type_graph_sha256": self.type_graph_sha256,
            "layout_set_sha256": self.layout_set_sha256,
            "expected_frame_sha256": self.expected_frame_sha256,
            "proposed_frame_sha256": self.proposed_frame_sha256,
            "machine_evidence_ids": list(self.machine_evidence_ids),
            "issues": list(self.issues),
        }


class IA32DialectCheckerV1:
    def __init__(self, abi_dialect: str) -> None:
        if abi_dialect not in IA32_DIALECTS:
            raise CallProtocolError(f"unsupported IA-32 dialect {abi_dialect!r}")
        self.abi_dialect = abi_dialect

    def lower(
        self,
        *,
        subject: CallSubjectV1 | Mapping[str, object],
        function_type_id: str,
        type_graph: PortableTypeGraphV1,
        layout_set: TargetLayoutSetV1,
        transfer_kind: str = "direct",
        outcomes: Sequence[str] = ("normal",),
    ) -> PhysicalCallFrameV2:
        if layout_set.target != "i686-pc-windows-pe32" or layout_set.pointer_width_bits != 32 or layout_set.byte_order != "little":
            raise CallProtocolError("IA-32 PE checker requires little-endian i686 PE32 layouts")
        if layout_set.abi_dialect != self.abi_dialect:
            raise CallProtocolError("IA-32 checker dialect differs from its layout set")
        function = type_graph.index.get(function_type_id)
        if function is None or function.kind != "function":
            raise CallProtocolError("IA-32 call lowering requires a function type")
        convention = str(function.body["calling_convention"])
        variadic = bool(function.body["variadic"])
        if convention not in IA32_DIALECT_CALLING_CONVENTIONS[self.abi_dialect]:
            raise CallProtocolError(
                f"IA-32 dialect {self.abi_dialect!r} does not define "
                f"calling convention {convention!r}"
            )
        if variadic and convention != "cdecl":
            raise CallProtocolError("IA-32 non-cdecl variadic calls are unsupported by the selected dialect")
        parameters = [type_graph.index[str(item)] for item in function.body["parameter_type_ids"]]
        result_type = type_graph.index[str(function.body["result_type_id"])]
        layouts = layout_set.index
        args: list[Mapping[str, object]] = []
        results: list[Mapping[str, object]] = []
        stack_offset = 4
        register_queue: list[tuple[str, str]] = []
        if not variadic and convention == "fastcall":
            register_queue = [("gpr", "ecx"), ("gpr", "edx")]
        elif not variadic and convention == "thiscall":
            register_queue = [("gpr", "ecx")]
        vector_gprs = [("gpr", "ecx"), ("gpr", "edx")]
        vector_xmms = [("xmm", f"xmm{index}") for index in range(6)]

        result_layout = _layout(result_type, layouts)
        indirect_result = result_type.kind in {"record", "union", "array"} and not _aggregate_register_return(result_layout, self.abi_dialect)
        if indirect_result:
            hidden, stack_offset = _argument_slot(
                identity="hidden_sret",
                role="hidden_sret",
                node=None,
                layout=_pointer_layout(),
                convention=convention,
                stack_offset=stack_offset,
                register_queue=register_queue,
                vector_gprs=vector_gprs,
                vector_xmms=vector_xmms,
            )
            args.append(hidden)

        for index, node in enumerate(parameters):
            role = "this" if convention == "thiscall" and index == 0 else "parameter"
            slot, stack_offset = _argument_slot(
                identity=f"arg{index}",
                role=role,
                node=node,
                layout=_layout(node, layouts),
                convention=convention,
                stack_offset=stack_offset,
                register_queue=register_queue,
                vector_gprs=vector_gprs,
                vector_xmms=vector_xmms,
            )
            args.append(slot)

        if result_type.kind != "void":
            results.append(_result_slot(result_type, result_layout, indirect=indirect_result))

        stack_argument_bytes = stack_offset - 4
        cleanup = "caller" if convention == "cdecl" or variadic else "callee"
        cleanup_bytes = stack_argument_bytes if cleanup == "callee" else 0
        preserved = ("ebp", "ebx", "edi", "esi", "esp")
        clobbered = ("eax", "ecx", "edx", "eflags", "st0", "st1", *(f"xmm{index}" for index in range(8)))
        return PhysicalCallFrameV2.create(
            subject=subject,
            transfer_kind=transfer_kind,
            target=layout_set.target,
            abi_dialect=self.abi_dialect,
            calling_convention=convention,
            arguments=args,
            results=results,
            stack={"coordinate": "callee-entry-esp-v1", "alignment_bytes": 4, "cleanup": cleanup, "cleanup_bytes": cleanup_bytes, "reserved_bytes": 0},
            preserved_state=preserved,
            clobbered_state=clobbered,
            outcomes=outcomes,
        )

    def lower_boundary(
        self,
        *,
        subject: CallSubjectV1 | Mapping[str, object],
        schema: BoundarySchemaV1,
        layout: TargetDataLayoutV1,
        signature_id: str,
        transfer_kind: str = "direct",
        outcomes: Sequence[str] = ("normal",),
    ) -> PhysicalCallFrameV3:
        """Lower canonical boundary values without reconstructing a V1 type graph."""

        if (
            layout.target != "i686-pc-windows-pe32"
            or layout.pointer_width_bits != 32
            or layout.byte_order != "little"
            or layout.abi_dialect != self.abi_dialect
            or layout.schema_sha256 != schema.schema_sha256
        ):
            raise CallProtocolError(
                "IA-32 PE checker requires a matching little-endian i686 PE32 layout"
            )
        signature = schema.signature_index.get(signature_id)
        if signature is None:
            raise CallProtocolError("IA-32 boundary lowering requires a signature")
        function = schema.type_index[signature.function_type_id]
        convention = str(function.body["calling_convention"])
        variadic = bool(function.body["variadic"])
        if convention not in IA32_DIALECT_CALLING_CONVENTIONS[self.abi_dialect]:
            raise CallProtocolError(
                f"IA-32 dialect {self.abi_dialect!r} does not define "
                f"calling convention {convention!r}"
            )
        if variadic and convention != "cdecl":
            raise CallProtocolError(
                "IA-32 non-cdecl variadic calls are unsupported by the selected dialect"
            )
        parameters = [schema.type_index[item.type_id] for item in signature.parameters]
        result_value = signature.results[0] if signature.results else None
        result_type = (
            schema.type_index[result_value.type_id]
            if result_value is not None
            else schema.type_index[str(function.body["result_type_id"])]
        )
        args: list[Mapping[str, object]] = []
        results: list[Mapping[str, object]] = []
        bindings: list[Mapping[str, object]] = []
        stack_offset = 4
        register_queue: list[tuple[str, str]] = []
        if not variadic and convention == "fastcall":
            register_queue = [("gpr", "ecx"), ("gpr", "edx")]
        elif not variadic and convention == "thiscall":
            register_queue = [("gpr", "ecx")]
        vector_gprs = [("gpr", "ecx"), ("gpr", "edx")]
        vector_xmms = [("xmm", f"xmm{index}") for index in range(6)]
        result_layout = _layout(result_type, layout.index)
        aggregate_result = result_type.kind in {"record", "union", "array"}
        indirect_result = aggregate_result and not _classified_aggregate_register_return(
            result_layout
        )
        if indirect_result:
            hidden, stack_offset = _argument_slot(
                identity="hidden_sret", role="hidden_sret", node=None,
                layout=_pointer_layout(), convention=convention,
                stack_offset=stack_offset, register_queue=register_queue,
                vector_gprs=vector_gprs, vector_xmms=vector_xmms,
            )
            args.append(hidden)
            if result_value is None:
                raise CallProtocolError("hidden aggregate result lacks a canonical result")
            bindings.append({
                "slot_id": "hidden_sret",
                "path": {"root": "result", "value_id": result_value.identity, "fields": []},
                "transport": "hidden_return_address",
            })
        for index, (value, node) in enumerate(zip(signature.parameters, parameters)):
            role = "this" if convention == "thiscall" and index == 0 else "parameter"
            slot, stack_offset = _argument_slot(
                identity=f"arg{index}", role=role, node=node,
                layout=_layout(node, layout.index), convention=convention,
                stack_offset=stack_offset, register_queue=register_queue,
                vector_gprs=vector_gprs, vector_xmms=vector_xmms,
            )
            args.append(slot)
            bindings.append({
                "slot_id": f"arg{index}",
                "path": {"root": "parameter", "value_id": value.identity, "fields": []},
                "transport": "semantic",
            })
        if result_value is not None:
            results.append(
                _result_slot(result_type, result_layout, indirect=indirect_result)
            )
            bindings.append({
                "slot_id": "result0",
                "path": {"root": "result", "value_id": result_value.identity, "fields": []},
                "transport": "semantic",
            })
        stack_argument_bytes = stack_offset - 4
        cleanup = "caller" if convention == "cdecl" or variadic else "callee"
        transport = PhysicalCallFrameV2.create(
            subject=subject,
            transfer_kind=transfer_kind,
            target=layout.target,
            abi_dialect=self.abi_dialect,
            calling_convention=convention,
            arguments=args,
            results=results,
            stack={
                "coordinate": "callee-entry-esp-v1", "alignment_bytes": 4,
                "cleanup": cleanup,
                "cleanup_bytes": stack_argument_bytes if cleanup == "callee" else 0,
                "reserved_bytes": 0,
            },
            preserved_state=("ebp", "ebx", "edi", "esi", "esp"),
            clobbered_state=(
                "eax", "ecx", "edx", "eflags", "st0", "st1",
                *(f"xmm{index}" for index in range(8)),
            ),
            outcomes=outcomes,
        )
        classification_rule = (
            f"{self.abi_dialect}.aggregate.{result_layout.abi_class}"
            if aggregate_result
            else f"{self.abi_dialect}.scalar-result"
        )
        return PhysicalCallFrameV3.create(
            schema=schema,
            layout=layout,
            signature_id=signature_id,
            transport=transport,
            bindings=bindings,
            dialect_rule_ids=(
                f"{self.abi_dialect}.call-frame", classification_rule,
            ),
        )

    def check(
        self,
        *,
        proposed: PhysicalCallFrameV2,
        subject: CallSubjectV1 | Mapping[str, object],
        function_type_id: str,
        type_graph: PortableTypeGraphV1,
        layout_set: TargetLayoutSetV1,
        machine_evidence: Sequence[MachineCallEvidenceV1],
    ) -> IA32DialectReceiptV1:
        graph_digest = type_graph.graph_id.split(":", 1)[1]
        layout_digest = layout_set.layout_id.split(":", 1)[1]
        evidence_ids = tuple(item.evidence_id for item in machine_evidence)
        try:
            expected = self.lower(subject=subject, function_type_id=function_type_id, type_graph=type_graph, layout_set=layout_set, transfer_kind=proposed.transfer_kind, outcomes=proposed.outcomes)
        except CallProtocolError as exc:
            return IA32DialectReceiptV1.create(status="incomplete", abi_dialect=self.abi_dialect, type_graph_sha256=graph_digest, layout_set_sha256=layout_digest, expected_frame_sha256=None, proposed_frame_sha256=proposed.frame_id.split(":", 1)[1], machine_evidence_ids=evidence_ids, issues=(str(exc),))
        expected_digest = expected.frame_id.split(":", 1)[1]
        proposed_digest = proposed.frame_id.split(":", 1)[1]
        issues: list[str] = []
        incomplete = False
        if expected.to_payload() != proposed.to_payload():
            issues.append("compiler or operator frame disagrees with the independent IA-32 dialect checker")
        try:
            boundary_receipt = reconcile_machine_call_evidence_v1(
                expected=expected, evidence=machine_evidence
            )
        except (CallProtocolError, ValueError) as exc:
            issues.append(f"machine call evidence cannot be reconciled: {exc}")
            incomplete = True
        else:
            for obligation in boundary_receipt.obligations:
                if obligation.status == "violated":
                    issues.append(
                        f"machine evidence contradicts canonical {obligation.key}"
                    )
                elif obligation.status != "checked":
                    issues.append(
                        f"machine evidence leaves {obligation.key} unobserved"
                    )
                    incomplete = True
        status = "violated" if any("contradict" in item or "disagrees" in item or "another call" in item for item in issues) else "incomplete" if incomplete else "complete"
        return IA32DialectReceiptV1.create(status=status, abi_dialect=self.abi_dialect, type_graph_sha256=graph_digest, layout_set_sha256=layout_digest, expected_frame_sha256=expected_digest, proposed_frame_sha256=proposed_digest, machine_evidence_ids=evidence_ids, issues=issues)


def _layout(node: PortableTypeNodeV1, layouts: Mapping[str, TypeLayoutV1]) -> TypeLayoutV1:
    if node.kind == "void":
        return TypeLayoutV1(node.identity, 0, 8, 0, None, (), ())
    try:
        return layouts[node.identity]
    except KeyError as exc:
        raise CallProtocolError(f"IA-32 layout set omits type {node.identity!r}") from exc


def _pointer_layout() -> TypeLayoutV1:
    return TypeLayoutV1("__implicit_pointer", 32, 32, 32, None, (), ())


def _aggregate_register_return(layout: TypeLayoutV1, dialect: str) -> bool:
    # Both selected PE32 dialects use EAX/EDX for these trivial aggregate sizes.
    # Nontrivial C++ records are excluded before reaching this C ABI checker.
    return layout.size_bits in {8, 16, 32, 64}


def _classified_aggregate_register_return(layout: object) -> bool:
    abi_class = getattr(layout, "abi_class", None)
    if abi_class == "aggregate-register":
        return True
    if abi_class == "aggregate-memory":
        return False
    raise CallProtocolError(
        "canonical aggregate result layout must classify aggregate-register or aggregate-memory"
    )


def _argument_slot(
    *,
    identity: str,
    role: str,
    node: PortableTypeNodeV1 | None,
    layout: TypeLayoutV1,
    convention: str,
    stack_offset: int,
    register_queue: list[tuple[str, str]],
    vector_gprs: list[tuple[str, str]],
    vector_xmms: list[tuple[str, str]],
) -> tuple[Mapping[str, object], int]:
    aggregate = node is not None and node.kind in {"record", "union", "array"}
    floating = node is not None and node.kind in {"float", "complex", "vector"}
    register: tuple[str, str] | None = None
    if convention == "vectorcall":
        if floating and layout.size_bits <= 128 and vector_xmms:
            register = vector_xmms.pop(0)
        elif not aggregate and layout.size_bits <= 32 and vector_gprs:
            register = vector_gprs.pop(0)
    elif register_queue and not aggregate and layout.size_bits <= 32:
        register = register_queue.pop(0)
    if register is not None:
        bank, name = register
        location_width = 128 if bank == "xmm" else 32
        fragment_width = layout.size_bits
        mode = "extended" if fragment_width < location_width else "direct"
        representation = "zero_extend" if mode == "extended" else "identity"
        return ({"id": identity, "role": role, "storage_bits": layout.size_bits, "value_bits": layout.value_bits, "pass_mode": mode, "logical_path": [], "fragments": [{"logical_offset_bits": 0, "width_bits": fragment_width, "location_offset_bits": 0, "representation": representation, "specified": True, "location": {"kind": "register", "phase": "callee_entry", "width_bits": location_width, "bank": bank, "name": name, "stack_base": None, "stack_offset_bytes": None, "memory_slot": None}}]}, stack_offset)
    slot_bytes = max(4, (layout.size_bits + 31) // 32 * 4)
    result = {"id": identity, "role": role, "storage_bits": layout.size_bits, "value_bits": layout.value_bits, "pass_mode": "direct", "logical_path": [], "fragments": [{"logical_offset_bits": 0, "width_bits": layout.size_bits, "location_offset_bits": 0, "representation": "identity", "specified": True, "location": {"kind": "stack", "phase": "callee_entry", "width_bits": slot_bytes * 8, "bank": None, "name": None, "stack_base": "callee-entry-esp-v1", "stack_offset_bytes": stack_offset, "memory_slot": None}}]}
    return result, stack_offset + slot_bytes


def _result_slot(node: PortableTypeNodeV1, layout: TypeLayoutV1, *, indirect: bool) -> Mapping[str, object]:
    if indirect:
        location = {"kind": "memory", "phase": "callee_exit", "width_bits": layout.size_bits, "bank": None, "name": None, "stack_base": None, "stack_offset_bytes": None, "memory_slot": "hidden_sret"}
        return {"id": "result0", "role": "result", "storage_bits": layout.size_bits, "value_bits": layout.value_bits, "pass_mode": "indirect", "logical_path": [], "fragments": [{"logical_offset_bits": 0, "width_bits": layout.size_bits, "location_offset_bits": 0, "representation": "identity", "specified": True, "location": location}]}
    if node.kind == "float":
        width = int(node.body["value_bits"])
        location = {"kind": "register", "phase": "callee_exit", "width_bits": 80, "bank": "x87", "name": "st0", "stack_base": None, "stack_offset_bytes": None, "memory_slot": None}
        return {"id": "result0", "role": "result", "storage_bits": layout.size_bits, "value_bits": layout.value_bits, "pass_mode": "coerced" if width < 80 else "direct", "logical_path": [], "fragments": [{"logical_offset_bits": 0, "width_bits": width, "location_offset_bits": 0, "representation": "x87_storage" if width < 80 else "identity", "specified": True, "location": location}]}
    if node.kind == "vector":
        location = {"kind": "register", "phase": "callee_exit", "width_bits": 128, "bank": "xmm", "name": "xmm0", "stack_base": None, "stack_offset_bytes": None, "memory_slot": None}
        return {"id": "result0", "role": "result", "storage_bits": layout.size_bits, "value_bits": layout.value_bits, "pass_mode": "direct", "logical_path": [], "fragments": [{"logical_offset_bits": 0, "width_bits": layout.size_bits, "location_offset_bits": 0, "representation": "identity", "specified": True, "location": location}]}
    fragments = []
    remaining = layout.size_bits
    offset = 0
    for name in ("eax", "edx"):
        if remaining <= 0:
            break
        width = min(32, remaining)
        fragments.append({"logical_offset_bits": offset, "width_bits": width, "location_offset_bits": 0, "representation": "identity", "specified": True, "location": {"kind": "register", "phase": "callee_exit", "width_bits": 32, "bank": "gpr", "name": name, "stack_base": None, "stack_offset_bytes": None, "memory_slot": None}})
        remaining -= width
        offset += width
    if remaining:
        raise CallProtocolError("IA-32 direct result exceeds EAX:EDX transport")
    return {"id": "result0", "role": "result", "storage_bits": layout.size_bits, "value_bits": layout.value_bits, "pass_mode": "split" if len(fragments) > 1 else "direct", "logical_path": [], "fragments": fragments}


__all__ = [
    "IA32DialectCheckerV1", "IA32DialectReceiptV1",
    "IA32_DIALECT_CALLING_CONVENTIONS", "IA32_DIALECTS",
]

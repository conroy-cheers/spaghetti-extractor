"""Expert leaves for building checked typed call protocols."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..calls.dialects.ia32 import IA32DialectCheckerV1
from ..calls.boundary_adapter import (
    layout_from_call_v1,
    lifecycle_from_call_v1,
    reconcile_machine_call_evidence_v1,
    schema_from_call_v1,
)
from ..calls.compiler_proposal import CompilerCallProposalV1
from ..calls.frame import PhysicalCallFrameV2
from ..calls.evidence import MachineCallEvidenceV1
from ..calls.intent import CallProtocolIntentV1
from ..calls.lifecycle import CallLifecycleReceiptV1, CallLifecycleV1
from ..calls.protocol import CheckedCallProtocolV1
from ..calls.protocol_v2 import CheckedCallProtocolV2
from ..calls.relation import CallFrameRelationReceiptV1, CallFrameRelationV1
from ..calls.source import SourceNamingV1, render_call_header
from ..calls.types import TargetLayoutSetV1
from ..boundary import (
    BoundaryLifecycleReceiptV1,
    BoundaryProjectionReceiptV1,
    BoundaryProjectionV1,
)
from ..util import sha256_file
from .common import Handler


def _load(path: Path, context: str) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read {context}: {exc}") from exc


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _source_naming(intent: CallProtocolIntentV1) -> SourceNamingV1:
    row = intent.source_names
    types = row.get("types", {})
    values = row.get("values", {})
    field_rows = row.get("fields", [])
    if not isinstance(types, dict) or not isinstance(values, dict) or not isinstance(field_rows, list):
        raise ValueError("call intent source_names must contain types, fields, and values")
    fields: dict[tuple[str, str], str] = {}
    for item in field_rows:
        if not isinstance(item, dict) or set(item) != {"type_id", "field_id", "name"}:
            raise ValueError("call intent source field name is malformed")
        fields[(str(item["type_id"]), str(item["field_id"]))] = str(item["name"])
    return SourceNamingV1.create(
        type_names={str(key): str(value) for key, value in types.items()},
        field_names=fields,
        value_names={str(key): str(value) for key, value in values.items()},
    )


def _check(args: argparse.Namespace) -> dict[str, object]:
    intent = CallProtocolIntentV1.parse(_load(args.intent, "call protocol intent"))
    graph = intent.type_graph
    layouts = TargetLayoutSetV1.parse(_load(args.layouts, "call layouts"), type_graph=graph)
    checker = IA32DialectCheckerV1(intent.abi_dialect)
    frame = (
        checker.lower(
            subject=intent.subject,
            function_type_id=intent.faithful_function_type_id,
            type_graph=graph,
            layout_set=layouts,
            transfer_kind=(
                "callback" if intent.subject.kind == "callback" else "import"
                if intent.subject.kind == "import" else "export"
                if intent.subject.kind == "export" else "direct"
            ),
        )
        if args.frame is None
        else PhysicalCallFrameV2.parse(_load(args.frame, "physical call frame"))
    )
    machine_evidence = tuple(
        MachineCallEvidenceV1.parse(_load(path, "machine call evidence"))
        for path in args.machine_evidence
    )
    if args.callback_authority is not None:
        if args.callback_protocol_id is None or args.binary is None:
            raise ValueError(
                "callback authority evidence requires --callback-protocol-id and --binary"
            )
        from ..artifacts.io import open_artifact_reader_v3
        from ..authority.callbacks import (
            CALLBACK_AUTHORITY_ARTIFACT_KIND_V4,
            CALLBACK_AUTHORITY_CODEC_V4,
        )

        reader = open_artifact_reader_v3(args.callback_authority)
        if reader.manifest.artifact_kind != CALLBACK_AUTHORITY_ARTIFACT_KIND_V4:
            raise ValueError("callback evidence input is not callback-authority-v4")
        callbacks = tuple(
            callback
            for source in reader.iter_records()
            for record in (CALLBACK_AUTHORITY_CODEC_V4.read(source).value,)
            for callback in record.callbacks
            if record.status == "complete" and record.authorizing
        )
        selected = next(
            (
                item
                for item in callbacks
                if item.protocol is not None
                and item.protocol.to_value().get("id")
                == args.callback_protocol_id
            ),
            None,
        )
        if selected is None:
            raise ValueError(
                f"callback authority has no protocol {args.callback_protocol_id!r}"
            )
        generated_evidence = MachineCallEvidenceV1.from_pe32_callback_authority(
            frame,
            authority={
                "id": selected.callback_id,
                "status": selected.status,
                "authorizing": selected.authorizing,
                "entry_state": selected.entry_state.to_value(),
                "protocol": selected.protocol.to_value(),
            },
            binary_sha256=sha256_file(args.binary),
            dependency_ids=(reader.manifest.artifact_id, reader.manifest_sha256),
        )
        machine_evidence = (*machine_evidence, generated_evidence)
    compiler_proposal = (
        None
        if args.compiler_proposal is None
        else CompilerCallProposalV1.parse(
            _load(args.compiler_proposal, "compiler call proposal")
        )
    )
    if compiler_proposal is not None and compiler_proposal.abi_dialect != intent.abi_dialect:
        raise ValueError(
            "compiler call proposal does not describe the selected call intent"
        )
    dialect = checker.check(
        proposed=frame,
        subject=intent.subject,
        function_type_id=intent.faithful_function_type_id,
        type_graph=graph,
        layout_set=layouts,
        machine_evidence=machine_evidence,
    )
    relation = CallFrameRelationV1.create(
        type_graph=graph,
        layout_set=layouts,
        frame=frame,
        machine_ir_sha256=sha256_file(args.machine_ir),
    )
    relation_receipt = CallFrameRelationReceiptV1.check(relation)
    lifecycle = CallLifecycleV1.create(
        intent.lifecycle,
        interaction_contract_ids=args.interaction_contract_id,
    )
    lifecycle_receipt = CallLifecycleReceiptV1.check(lifecycle)
    boundary_schema = schema_from_call_v1(
        graph,
        function_type_id=intent.faithful_function_type_id,
        schema_id=intent.intent_id,
    )
    boundary_layout = layout_from_call_v1(layouts, schema=boundary_schema)
    boundary_frame = checker.lower_boundary(
        subject=intent.subject,
        schema=boundary_schema,
        layout=boundary_layout,
        signature_id=intent.faithful_function_type_id,
        transfer_kind=frame.transfer_kind,
        outcomes=frame.outcomes,
    )
    if boundary_frame.transport != frame:
        raise ValueError(
            "legacy frame cannot migrate losslessly to canonical physical call frame V3"
        )
    boundary_evidence = reconcile_machine_call_evidence_v1(
        expected=frame, evidence=machine_evidence
    )
    boundary_lifecycle = lifecycle_from_call_v1(
        schema=boundary_schema,
        signature_id=intent.faithful_function_type_id,
        frame=boundary_frame,
        lifecycle=lifecycle,
    )
    boundary_lifecycle_receipt = BoundaryLifecycleReceiptV1.check(
        boundary_lifecycle,
        checked_interaction_contract_ids=lifecycle.interaction_contract_ids,
    )
    signature = boundary_schema.signature_index[intent.faithful_function_type_id]
    boundary_projection = BoundaryProjectionV1.create(
        component_id=intent.intent_id,
        operation_id="faithful-call",
        schema=boundary_schema,
        signature_id=signature.identity,
        source_values=(*signature.parameters, *signature.results),
        entries=[
            {
                "source_id": item.identity,
                "target": {
                    "root": "parameter" if item in signature.parameters else "result",
                    "value_id": item.identity,
                    "fields": [],
                },
            }
            for item in (*signature.parameters, *signature.results)
        ],
    )
    boundary_projection_receipt = BoundaryProjectionReceiptV1.check(
        boundary_projection, schema=boundary_schema
    )
    issues = [*dialect.issues]
    if relation_receipt.status != "complete":
        issues.append("call frame relation laws are incomplete or violated")
    status = "complete" if not issues else "violated"
    output = args.out.resolve()
    output.mkdir(parents=True, exist_ok=True)
    _write(output / "portable-type-graph.json", graph.to_payload())
    _write(output / "target-layout-set.json", layouts.to_payload())
    _write(output / "physical-call-frame.json", frame.to_payload())
    _write(output / "ia32-dialect-receipt.json", dialect.to_payload())
    _write(output / "call-frame-relation.json", relation.to_payload())
    _write(output / "call-frame-relation-receipt.json", relation_receipt.to_payload())
    _write(output / "call-lifecycle.json", lifecycle.to_payload())
    _write(
        output / "call-lifecycle-receipt.json", lifecycle_receipt.to_payload()
    )
    _write(output / "boundary-schema.json", boundary_schema.to_payload())
    _write(output / "target-data-layout.json", boundary_layout.to_payload())
    _write(output / "physical-call-frame-v3.json", boundary_frame.to_payload())
    _write(
        output / "boundary-evidence-receipt.json", boundary_evidence.to_payload()
    )
    _write(output / "boundary-lifecycle.json", boundary_lifecycle.to_payload())
    _write(
        output / "boundary-lifecycle-receipt.json",
        boundary_lifecycle_receipt.to_payload(),
    )
    _write(output / "boundary-projection.json", boundary_projection.to_payload())
    _write(
        output / "boundary-projection-receipt.json",
        boundary_projection_receipt.to_payload(),
    )
    naming = _source_naming(intent)
    _write(output / "source-naming.json", naming.to_payload())
    if compiler_proposal is not None:
        _write(output / "compiler-call-proposal.json", compiler_proposal.to_payload())
    (output / "faithful-call.h").write_text(
        render_call_header(
            type_graph=graph,
            naming=naming,
            function_type_id=intent.faithful_function_type_id,
            function_name="spx_checked_call",
        ),
        encoding="utf-8",
    )
    protocol = None
    legacy_protocol = None
    if status == "complete":
        legacy_protocol = CheckedCallProtocolV1.create(
            status="complete",
            faithful_function_type_id=intent.faithful_function_type_id,
            type_graph=graph,
            layout_set=layouts,
            frame=frame,
            frame_relation_receipt=relation_receipt,
            lifecycle=lifecycle,
            lifecycle_receipt=lifecycle_receipt,
            dialect_receipt_sha256=dialect.receipt_id.split(":", 1)[1],
            evidence_ids=[
                *(item.evidence_id for item in machine_evidence),
                *(
                    ()
                    if compiler_proposal is None
                    else (compiler_proposal.proposal_id,)
                ),
            ],
        )
        _write(
            output / "checked-call-protocol-v1.json", legacy_protocol.to_payload()
        )
        protocol = CheckedCallProtocolV2.create(
            schema=boundary_schema,
            layout=boundary_layout,
            signature_id=signature.identity,
            frame=boundary_frame,
            evidence_receipt=boundary_evidence,
            lifecycle=boundary_lifecycle,
            lifecycle_receipt=boundary_lifecycle_receipt,
            projection=boundary_projection,
            projection_receipt=boundary_projection_receipt,
        )
        _write(output / "checked-call-protocol.json", protocol.to_payload())
    result = {
        "format": "spaghetti-extractor-call-protocol-check-result-v1",
        "status": status,
        "subject": intent.subject.to_payload(),
        "layers": {
            "types": "complete",
            "transport": dialect.status,
            "relation": relation_receipt.status,
            "lifecycle": "complete",
            "idiomatic_view": "not-selected",
        },
        "protocol_id": None if protocol is None else protocol.protocol_id,
        "issues": sorted(set(issues)),
    }
    _write(
        output / "call-inspection.json",
        {
            **result,
            "abi_dialect": frame.abi_dialect,
            "calling_convention": frame.calling_convention,
            "faithful_prototype": "faithful-call.h",
            "idiomatic_prototype": None,
            "physical_frame": frame.to_payload(),
            "lifecycle": lifecycle.to_payload(),
            "dialect_receipt": dialect.to_payload(),
            "relation_receipt": relation_receipt.to_payload(),
        },
    )
    _write(output / "call-status.json", result)
    return result


def configure_command(name: str, parser: argparse.ArgumentParser) -> Handler:
    if name != "call-protocol-check":
        raise ValueError(f"unsupported call-protocol command: {name}")
    parser.add_argument("--intent", required=True, type=Path)
    parser.add_argument("--layouts", required=True, type=Path)
    parser.add_argument("--frame", type=Path)
    parser.add_argument("--compiler-proposal", type=Path)
    parser.add_argument("--machine-ir", required=True, type=Path)
    parser.add_argument("--interaction-contract-id", action="append", default=[])
    parser.add_argument("--machine-evidence", action="append", default=[], type=Path)
    parser.add_argument("--callback-authority", type=Path)
    parser.add_argument("--callback-protocol-id")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--out", required=True, type=Path)
    return _check


__all__ = ["configure_command"]

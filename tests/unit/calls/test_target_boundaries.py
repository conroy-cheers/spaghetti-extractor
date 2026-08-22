from __future__ import annotations

import json
import unittest
from pathlib import Path

from spaghetti_extractor.boundary import (
    BoundaryLifecycleReceiptV1,
    BoundaryLifecycleV1,
    BoundaryProjectionReceiptV1,
    BoundaryProjectionV1,
    BoundarySchemaV1,
    TargetDataLayoutV1,
)
from spaghetti_extractor.calls.boundary_adapter import reconcile_machine_call_evidence_v1
from spaghetti_extractor.calls.callback_v3 import CallbackProtocolV3
from spaghetti_extractor.calls.dialects.ia32 import IA32DialectCheckerV1
from spaghetti_extractor.calls.evidence import MachineCallEvidenceV1
from spaghetti_extractor.calls.protocol_v2 import CheckedCallProtocolV2


TESTKIT = {
    "resources": (
        "targets/dxball/intent/boundaries.json",
        "targets/jq/intent/boundaries.json",
    )
}

REPOSITORY = Path(__file__).parents[3]


def _load(target: str) -> tuple[BoundarySchemaV1, TargetDataLayoutV1]:
    row = json.loads(
        (REPOSITORY / "targets" / target / "intent" / "boundaries.json").read_text(
            encoding="utf-8"
        )
    )
    schema = BoundarySchemaV1.create(
        schema_id=row["schema_id"], types=row["types"], signatures=row["signatures"]
    )
    layout = TargetDataLayoutV1.create(schema=schema, **row["layout"])
    return schema, layout


def _checked(
    *,
    schema: BoundarySchemaV1,
    layout: TargetDataLayoutV1,
    signature_id: str,
    subject_id: str,
    subject_kind: str,
    transfer_kind: str,
) -> CheckedCallProtocolV2:
    checker = IA32DialectCheckerV1(layout.abi_dialect)
    frame = checker.lower_boundary(
        subject={"kind": subject_kind, "id": subject_id, "image_selector": "main-image"},
        schema=schema, layout=layout, signature_id=signature_id,
        transfer_kind=transfer_kind,
    )
    evidence = reconcile_machine_call_evidence_v1(
        expected=frame.transport,
        evidence=(MachineCallEvidenceV1.from_frame(
            frame.transport, producer=f"fixture-{signature_id}",
            binary_sha256="f" * 64,
        ),),
    )
    lifecycle = BoundaryLifecycleV1.create(
        schema=schema, signature_id=signature_id, bindings=[]
    )
    lifecycle_receipt = BoundaryLifecycleReceiptV1.check(
        lifecycle, checked_interaction_contract_ids=[]
    )
    signature = schema.signature_index[signature_id]
    values = (*signature.parameters, *signature.results)
    projection = BoundaryProjectionV1.create(
        component_id=f"fixture-{signature_id}", operation_id=signature_id,
        schema=schema, signature_id=signature_id, source_values=values,
        entries=[{
            "source_id": item.identity,
            "target": {
                "root": "parameter" if item in signature.parameters else "result",
                "value_id": item.identity, "fields": [],
            },
        } for item in values],
    )
    projection_receipt = BoundaryProjectionReceiptV1.check(
        projection, schema=schema
    )
    return CheckedCallProtocolV2.create(
        schema=schema, layout=layout, signature_id=signature_id, frame=frame,
        evidence_receipt=evidence, lifecycle=lifecycle,
        lifecycle_receipt=lifecycle_receipt, projection=projection,
        projection_receipt=projection_receipt,
    )


class TargetBoundaryCallbackTests(unittest.TestCase):
    def test_jq_math_handler_registration_and_callback_share_one_typed_schema(self) -> None:
        schema, layout = _load("jq")
        registration = _checked(
            schema=schema, layout=layout, signature_id="set-math-handler",
            subject_id="msvcrt.__setusermatherr", subject_kind="import",
            transfer_kind="import",
        )
        invocation = _checked(
            schema=schema, layout=layout, signature_id="math-handler",
            subject_id="msvcrt-user-math-error-handler", subject_kind="callback",
            transfer_kind="callback",
        )
        callback = CallbackProtocolV3.create(
            action="replace", registration_protocol=registration,
            invocation_protocol=invocation, registration_schema=schema,
            invocation_schema=schema,
            source_path={"root": "parameter", "value_id": "handler", "fields": []},
            instance_kind="singleton", instance_paths=[],
            previous_disposition="returned",
            previous_result_path={"root": "result", "value_id": "previous", "fields": []},
            lifetime={"kind": "until_replaced", "end_event": None},
            delivery={"timing": "deferred", "thread_relation": "external_concurrent", "reentrancy": "allowed"},
            cardinality={"minimum": 0, "maximum": None, "scope": "registration-generation"},
            interaction_contract_id="msvcrt.set-user-matherr.v1",
            evidence_receipt_id=invocation.evidence_receipt_id,
        )
        self.assertEqual(callback.registration_protocol_id, registration.protocol_id)
        self.assertEqual(callback.invocation_protocol_id, invocation.protocol_id)
        self.assertEqual(
            CallbackProtocolV3.parse(
                callback.to_payload(),
                protocols={
                    registration.protocol_id: registration,
                    invocation.protocol_id: invocation,
                },
                schemas_by_sha256={schema.schema_sha256: schema},
            ),
            callback,
        )

    def test_dxball_register_class_reaches_wndproc_through_struct_reference(self) -> None:
        schema, layout = _load("dxball")
        registration = _checked(
            schema=schema, layout=layout, signature_id="register-class",
            subject_id="user32.RegisterClassA", subject_kind="import",
            transfer_kind="import",
        )
        invocation = _checked(
            schema=schema, layout=layout, signature_id="wndproc-callback",
            subject_id="win32-window-procedure", subject_kind="callback",
            transfer_kind="callback",
        )
        callback = CallbackProtocolV3.create(
            action="register", registration_protocol=registration,
            invocation_protocol=invocation, registration_schema=schema,
            invocation_schema=schema,
            source_path={"root": "parameter", "value_id": "class", "fields": ["lpfnWndProc"]},
            instance_kind="value",
            instance_paths=[{"root": "parameter", "value_id": "class", "fields": ["lpszClassName"]}],
            previous_disposition="none", previous_result_path=None,
            lifetime={"kind": "until_process_exit", "end_event": None},
            delivery={"timing": "nested_or_deferred", "thread_relation": "external_concurrent", "reentrancy": "allowed"},
            cardinality={"minimum": 0, "maximum": None, "scope": "window-class"},
            interaction_contract_id="user32.register-class.v1",
            evidence_receipt_id=invocation.evidence_receipt_id,
        )
        self.assertEqual(callback.source_path.fields, ("lpfnWndProc",))


if __name__ == "__main__":
    unittest.main()

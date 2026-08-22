"""Checked conditional ABI contracts for exact internal-call entry points."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..artifacts.artifact_set import ArtifactRecordV3, RecordDependencyV3
from ..artifacts.io import ArtifactSetReaderV3
from ..artifacts.phases import PhaseContextV3, RecordCodecV3, reduce
from ._schema import (
    boolean,
    digest,
    fail,
    require_record_ids,
    sequence,
    sorted_records,
    strict_object,
    text,
    uint,
)
from .incoming_call_frames import (
    INCOMING_CALL_FRAME_CODEC_V3,
    INCOMING_CALL_FRAMES_ARTIFACT_KIND_V3,
)
from .normal_call_abi import (
    NORMAL_CALL_ABI_PREMISE_CODEC_V3,
    NORMAL_CALL_ABI_PREMISES_ARTIFACT_KIND_V3,
    NormalCallABIPremiseRecordV3,
)


CALL_BOUNDARY_CONTRACT_RECORD_V3_SCHEMA = (
    "spaghetti-extractor-call-boundary-contract-record-v3"
)
CALL_BOUNDARY_CONTRACTS_ARTIFACT_KIND_V3 = "call-boundary-contracts-v3"


def _canonical_strings(value: Any, context: str) -> tuple[str, ...]:
    rows = tuple(text(item, context, maximum=64) for item in sequence(value, context))
    if rows != tuple(sorted(set(rows))):
        fail(
            "noncanonical_record_order",
            f"{context} is not sorted and unique",
            "sort and deduplicate the inventory",
        )
    return rows


@dataclass(frozen=True)
class CallBoundaryContractV3:
    record_id: str
    contract_id: str
    target_unit_sha256: str
    target_rva: int
    premise_record_id: str
    premise_content_sha256: str
    transfer_kind: str
    applies_when: str
    preserved_registers: tuple[str, ...]
    source_frame_count: int
    status: str
    authorizing: bool
    failure_code: str | None

    def __post_init__(self) -> None:
        text(self.record_id, "call-boundary target unit ID")
        text(self.contract_id, "call-boundary contract ID")
        digest(self.target_unit_sha256, "call-boundary target unit SHA-256")
        uint(self.target_rva, "call-boundary target RVA")
        text(self.premise_record_id, "call-boundary premise ID")
        digest(self.premise_content_sha256, "call-boundary premise SHA-256")
        if self.transfer_kind != "internal_call":
            fail(
                "record_schema_mismatch",
                "call-boundary contract has an unsupported transfer kind",
                "use internal_call",
            )
        if self.applies_when != "call_returns_normally":
            fail(
                "record_schema_mismatch",
                "call-boundary contract has an unsupported condition",
                "use call_returns_normally",
            )
        if self.preserved_registers != tuple(
            sorted(set(self.preserved_registers))
        ):
            fail(
                "noncanonical_record_order",
                "call-boundary preserved registers are not sorted and unique",
                "sort and deduplicate the register inventory",
            )
        uint(self.source_frame_count, "call-boundary source-frame count")
        if self.source_frame_count == 0:
            fail(
                "record_schema_mismatch",
                "call-boundary contract has no exact incoming frame",
                "emit contracts only for exact internal-call entry points",
            )
        if self.status not in {"complete", "incomplete", "violated"}:
            fail(
                "record_schema_mismatch",
                "call-boundary contract status is unsupported",
                "use complete, incomplete, or violated",
            )
        if self.authorizing != (self.status == "complete"):
            fail(
                "record_schema_mismatch",
                "call-boundary authorization contradicts its status",
                "authorize only complete contracts",
            )
        if (self.failure_code is None) != self.authorizing:
            fail(
                "record_schema_mismatch",
                "call-boundary failure code contradicts authorization",
                "omit failure_code only for an authorizing contract",
            )


def _encode(value: CallBoundaryContractV3) -> dict[str, Any]:
    return {
        "schema": CALL_BOUNDARY_CONTRACT_RECORD_V3_SCHEMA,
        "id": value.record_id,
        "contract_id": value.contract_id,
        "target_unit_sha256": value.target_unit_sha256,
        "target_rva": value.target_rva,
        "premise_record_id": value.premise_record_id,
        "premise_content_sha256": value.premise_content_sha256,
        "transfer_kind": value.transfer_kind,
        "applies_when": value.applies_when,
        "preserved_registers": list(value.preserved_registers),
        "source_frame_count": value.source_frame_count,
        "status": value.status,
        "authorizing": value.authorizing,
        "failure_code": value.failure_code,
    }


def _decode(value: Any) -> CallBoundaryContractV3:
    row = strict_object(
        value,
        {
            "schema",
            "id",
            "contract_id",
            "target_unit_sha256",
            "target_rva",
            "premise_record_id",
            "premise_content_sha256",
            "transfer_kind",
            "applies_when",
            "preserved_registers",
            "source_frame_count",
            "status",
            "authorizing",
            "failure_code",
        },
        "call-boundary contract",
    )
    if row["schema"] != CALL_BOUNDARY_CONTRACT_RECORD_V3_SCHEMA:
        fail(
            "wrong_record_schema",
            "record is not a call-boundary contract v3 record",
            "use CALL_BOUNDARY_CONTRACT_CODEC_V3",
        )
    failure = row["failure_code"]
    return CallBoundaryContractV3(
        record_id=text(row["id"], "call-boundary target unit ID"),
        contract_id=text(row["contract_id"], "call-boundary contract ID"),
        target_unit_sha256=digest(
            row["target_unit_sha256"], "call-boundary target SHA-256"
        ),
        target_rva=uint(row["target_rva"], "call-boundary target RVA"),
        premise_record_id=text(
            row["premise_record_id"], "call-boundary premise ID"
        ),
        premise_content_sha256=digest(
            row["premise_content_sha256"], "call-boundary premise SHA-256"
        ),
        transfer_kind=text(row["transfer_kind"], "call-boundary transfer kind"),
        applies_when=text(row["applies_when"], "call-boundary condition"),
        preserved_registers=_canonical_strings(
            row["preserved_registers"], "call-boundary preserved registers"
        ),
        source_frame_count=uint(
            row["source_frame_count"], "call-boundary source-frame count"
        ),
        status=text(row["status"], "call-boundary status"),
        authorizing=boolean(row["authorizing"], "call-boundary authorization"),
        failure_code=(
            None if failure is None else text(failure, "call-boundary failure code")
        ),
    )


CALL_BOUNDARY_CONTRACT_CODEC_V3 = RecordCodecV3[CallBoundaryContractV3](
    decode=_decode,
    encode=_encode,
)


def _premise(context: PhaseContextV3) -> NormalCallABIPremiseRecordV3:
    rows = tuple(
        row.value
        for row in context.typed_records(
            "normal_call_abi_premises", NORMAL_CALL_ABI_PREMISE_CODEC_V3
        )
    )
    if len(rows) != 1:
        fail(
            "normal_call_abi_premise_inventory_invalid",
            f"expected one normal-call ABI premise, found {len(rows)}",
            "supply exactly one reviewed, binary-bound premise",
        )
    return rows[0]


def _derive(context: PhaseContextV3) -> tuple[ArtifactRecordV3, ...]:
    premise = _premise(context)
    supports_internal = "internal_call" in premise.transfer_kinds
    result: list[ArtifactRecordV3] = []
    for source in sorted_records(context.records("incoming_call_frames")):
        incoming = INCOMING_CALL_FRAME_CODEC_V3.read(source).value
        if not incoming.frames:
            continue
        complete_frames = all(
            frame.source_status == "complete" for frame in incoming.frames
        )
        status = "complete" if supports_internal and complete_frames else "incomplete"
        failure = (
            None
            if status == "complete"
            else (
                "normal_call_abi_transfer_unsupported"
                if not supports_internal
                else "incoming_call_frame_incomplete"
            )
        )
        contract_id = f"{premise.record_id}:{incoming.record_id}"
        contract = CallBoundaryContractV3(
            record_id=incoming.record_id,
            contract_id=contract_id,
            target_unit_sha256=incoming.unit_sha256,
            target_rva=incoming.rva_start,
            premise_record_id=premise.record_id,
            premise_content_sha256=premise.content_sha256,
            transfer_kind="internal_call",
            applies_when="call_returns_normally",
            preserved_registers=premise.preserved_registers,
            source_frame_count=len(incoming.frames),
            status=status,
            authorizing=status == "complete",
            failure_code=failure,
        )
        result.append(
            CALL_BOUNDARY_CONTRACT_CODEC_V3.write(
                contract.record_id,
                contract,
                dependencies=(
                    RecordDependencyV3("incoming_call_frames", incoming.record_id),
                    RecordDependencyV3(
                        "normal_call_abi_premises", premise.record_id
                    ),
                ),
            )
        )
    return tuple(result)


def check_call_boundary_contracts_completeness_v3(
    reader: ArtifactSetReaderV3,
    context: PhaseContextV3,
) -> None:
    expected = _derive(context)
    submitted = tuple(sorted_records(reader.iter_records()))
    require_record_ids(
        submitted,
        (row.record_id for row in expected),
        "call-boundary contracts",
    )
    for actual, wanted in zip(submitted, expected, strict=True):
        if actual != wanted:
            fail(
                "call_boundary_contract_contradiction",
                f"call-boundary contract {actual.record_id!r} is stale",
                "regenerate it from the exact incoming-call index and premise",
            )


CALL_BOUNDARY_CONTRACTS_PHASE_V3 = reduce(
    name="call-boundary-contracts-v3",
    version="1",
    input_artifact_kinds={
        "incoming_call_frames": INCOMING_CALL_FRAMES_ARTIFACT_KIND_V3,
        "normal_call_abi_premises": NORMAL_CALL_ABI_PREMISES_ARTIFACT_KIND_V3,
    },
    output_artifact_kind=CALL_BOUNDARY_CONTRACTS_ARTIFACT_KIND_V3,
    transform=_derive,
    completeness=check_call_boundary_contracts_completeness_v3,
    dependency_scope="artifact",
    output_value_codec="plain-json-v1",
)


__all__ = [
    "CALL_BOUNDARY_CONTRACT_CODEC_V3",
    "CALL_BOUNDARY_CONTRACT_RECORD_V3_SCHEMA",
    "CALL_BOUNDARY_CONTRACTS_ARTIFACT_KIND_V3",
    "CALL_BOUNDARY_CONTRACTS_PHASE_V3",
    "CallBoundaryContractV3",
    "check_call_boundary_contracts_completeness_v3",
]

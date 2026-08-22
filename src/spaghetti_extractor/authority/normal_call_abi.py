"""Content-bound authority input for conditional normal-call ABI premises."""

from __future__ import annotations

import argparse
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..artifacts.artifact_set import ArtifactBindingV3, ArtifactSetWriterV3
from ..artifacts.phases import RecordCodecV3
from ..artifacts.machine_abi import load_normal_call_abi_premise
from ._schema import digest, fail, sequence, strict_object, text


NORMAL_CALL_ABI_PREMISE_RECORD_V3_SCHEMA = (
    "spaghetti-extractor-normal-call-abi-premise-record-v3"
)
NORMAL_CALL_ABI_PREMISES_ARTIFACT_KIND_V3 = "normal-call-abi-premises-v3"


def _canonical_registers(value: Any, context: str) -> tuple[str, ...]:
    rows = tuple(text(item, context, maximum=8) for item in sequence(value, context))
    if rows != tuple(sorted(set(rows))):
        fail(
            "noncanonical_record_order",
            f"{context} is not sorted and unique",
            "sort and deduplicate the register inventory",
        )
    return rows


@dataclass(frozen=True)
class NormalCallABIPremiseRecordV3:
    record_id: str
    content_sha256: str
    preserved_registers: tuple[str, ...]
    clobbered_registers: tuple[str, ...]
    transfer_kinds: tuple[str, ...]

    def __post_init__(self) -> None:
        text(self.record_id, "normal-call ABI premise ID")
        digest(self.content_sha256, "normal-call ABI premise SHA-256")
        for rows, label in (
            (self.preserved_registers, "preserved registers"),
            (self.clobbered_registers, "clobbered registers"),
            (self.transfer_kinds, "transfer kinds"),
        ):
            if rows != tuple(sorted(set(rows))):
                fail(
                    "noncanonical_record_order",
                    f"normal-call ABI {label} are not sorted and unique",
                    f"sort and deduplicate {label}",
                )


def _encode(value: NormalCallABIPremiseRecordV3) -> dict[str, Any]:
    return {
        "schema": NORMAL_CALL_ABI_PREMISE_RECORD_V3_SCHEMA,
        "id": value.record_id,
        "content_sha256": value.content_sha256,
        "preserved_registers": list(value.preserved_registers),
        "clobbered_registers": list(value.clobbered_registers),
        "transfer_kinds": list(value.transfer_kinds),
    }


def _decode(value: Any) -> NormalCallABIPremiseRecordV3:
    row = strict_object(
        value,
        {
            "schema",
            "id",
            "content_sha256",
            "preserved_registers",
            "clobbered_registers",
            "transfer_kinds",
        },
        "normal-call ABI premise record",
    )
    if row["schema"] != NORMAL_CALL_ABI_PREMISE_RECORD_V3_SCHEMA:
        fail(
            "wrong_record_schema",
            "record is not a normal-call ABI premise v3 record",
            "use NORMAL_CALL_ABI_PREMISE_CODEC_V3",
        )
    return NormalCallABIPremiseRecordV3(
        record_id=text(row["id"], "normal-call ABI premise ID"),
        content_sha256=digest(
            row["content_sha256"], "normal-call ABI premise SHA-256"
        ),
        preserved_registers=_canonical_registers(
            row["preserved_registers"], "normal-call preserved registers"
        ),
        clobbered_registers=_canonical_registers(
            row["clobbered_registers"], "normal-call clobbered registers"
        ),
        transfer_kinds=tuple(
            sorted(
                text(item, "normal-call transfer kind", maximum=32)
                for item in sequence(
                    row["transfer_kinds"], "normal-call transfer kinds"
                )
            )
        ),
    )


NORMAL_CALL_ABI_PREMISE_CODEC_V3 = RecordCodecV3[NormalCallABIPremiseRecordV3](
    decode=_decode,
    encode=_encode,
)


def build_normal_call_abi_premise_artifact_v3(
    *,
    profile: Path,
    binary: Path,
    binary_identity: str,
    output_directory: Path,
) -> NormalCallABIPremiseRecordV3:
    premise = load_normal_call_abi_premise(profile)
    binary_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()
    record = NormalCallABIPremiseRecordV3(
        record_id=premise.premise_id,
        content_sha256=premise.content_sha256,
        preserved_registers=tuple(sorted(premise.preserved_registers)),
        clobbered_registers=tuple(sorted(premise.clobbered_registers)),
        transfer_kinds=tuple(sorted(premise.transfer_kinds)),
    )
    ArtifactSetWriterV3(
        artifact_kind=NORMAL_CALL_ABI_PREMISES_ARTIFACT_KIND_V3,
        bindings=(
            ArtifactBindingV3(
                "binary", "pe32", text(binary_identity, "binary identity"), binary_sha256
            ),
        ),
        status="complete",
    ).write(
        output_directory,
        (NORMAL_CALL_ABI_PREMISE_CODEC_V3.write(record.record_id, record),),
    )
    return record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--binary-identity", required=True)
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args(argv)
    build_normal_call_abi_premise_artifact_v3(
        profile=arguments.profile,
        binary=arguments.binary,
        binary_identity=arguments.binary_identity,
        output_directory=arguments.out,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "NORMAL_CALL_ABI_PREMISE_CODEC_V3",
    "NORMAL_CALL_ABI_PREMISE_RECORD_V3_SCHEMA",
    "NORMAL_CALL_ABI_PREMISES_ARTIFACT_KIND_V3",
    "NormalCallABIPremiseRecordV3",
    "build_normal_call_abi_premise_artifact_v3",
]

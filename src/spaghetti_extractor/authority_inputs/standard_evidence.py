"""Generate conservative, target-independent proposal inputs for analysis v3.

This adapter is deliberately not an authority checker.  It turns exact
machine-IR discoveries and checked launch-root records into the two proposal
artifacts needed by the native v3 phases.  Structural targeting and inductive
analysis must still replay and check every claim before final authority can
consume it.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from ..authority._schema import mapping, sequence, text
from ..authority.inductive_records import (
    INDUCTIVE_INPUT_CODEC_V3,
    CutpointInvariantV3,
    EntryFactsV3,
    InductiveConfigV3,
    InductiveCutpointV3,
    InvariantBudgetsV3,
)
from ..authority.root_closure import LAUNCH_ROOT_EVIDENCE_CODEC_V3
from ..artifact_set_v3 import (
    ArtifactBindingV3,
    ArtifactRecordV3,
    ArtifactSetReaderV3,
    ArtifactSetWriterV3,
    canonical_json_bytes_v3,
    canonical_sha256_v3,
)


STANDARD_EVIDENCE_FORMAT_V3 = "spaghetti-extractor-standard-evidence-v3"
TARGET_HINTS_ARTIFACT_KIND_V3 = "target-hints-v3"
INDUCTIVE_INPUTS_ARTIFACT_KIND_V3 = "inductive-inputs-v3"


class StandardEvidenceV3Error(ValueError):
    """The proposal source is malformed or contradicts checked input."""


def _load_manifest(path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StandardEvidenceV3Error(
            f"cannot read machine-IR manifest {path}: {exc}"
        ) from exc
    return mapping(value, "machine-IR manifest")


def _target_hint_records(
    machine_manifest: Mapping[str, Any],
) -> tuple[ArtifactRecordV3, ...]:
    control = mapping(machine_manifest.get("control"), "machine-IR control")
    recoveries = sequence(
        control.get("recovered_indirect_targets"),
        "machine-IR recovered indirect targets",
    )
    records: list[ArtifactRecordV3] = []
    for value in recoveries:
        recovery = mapping(value, "machine-IR indirect-target recovery")
        record_id = text(recovery.get("id"), "indirect-exit ID")
        raw_targets = recovery.get("target_unit_ids", [])
        if not isinstance(raw_targets, list) or any(
            not isinstance(item, str) or not item for item in raw_targets
        ):
            raise StandardEvidenceV3Error(
                f"indirect exit {record_id!r} has malformed target_unit_ids"
            )
        target_unit_ids = sorted(set(raw_targets))
        recovered = (
            recovery.get("status") == "complete"
            and recovery.get("closure") == "closed"
            and bool(target_unit_ids)
            and recovery.get("failure") is None
        )
        # Older machine-IR exporters used recovered/recovered for the same
        # successfully closed state.  Accept the spelling only as a proposal;
        # the structural checker still binds it to the exact exit.
        recovered = recovered or (
            recovery.get("status") == "recovered"
            and recovery.get("closure")
            in {"checked_finite_target_inventory", "closed", "recovered"}
            and bool(target_unit_ids)
            and recovery.get("failure") is None
        )
        payload = {
            "id": record_id,
            "source_unit_id": text(
                recovery.get("source_unit_id"), "indirect source unit ID"
            ),
            "source_rva": recovery.get("source_rva"),
            "source_event_index": recovery.get("source_event_index"),
            "kind": text(recovery.get("kind"), "indirect transfer kind"),
            "status": "recovered" if recovered else "incomplete",
            "target_unit_ids": target_unit_ids if recovered else [],
            "external_targets": [],
            "failure": None if recovered else recovery.get("failure"),
        }
        records.append(ArtifactRecordV3.create(record_id, payload))
    records.sort(key=lambda row: row.record_id)
    if len({row.record_id for row in records}) != len(records):
        raise StandardEvidenceV3Error(
            "machine-IR manifest repeats an indirect-exit ID"
        )
    return tuple(records)


def _inductive_input_records(
    launch_roots: ArtifactSetReaderV3,
) -> tuple[ArtifactRecordV3, ...]:
    roots = tuple(
        LAUNCH_ROOT_EVIDENCE_CODEC_V3.read(record).value
        for record in launch_roots.iter_records()
    )
    complete_roots = tuple(
        sorted((root for root in roots if root.status == "complete"), key=lambda row: row.record_id)
    )
    root_unit_ids = tuple(sorted({root.unit_id for root in complete_roots}))
    entries = tuple(
        EntryFactsV3(
            entry_id=f"root-entry:{root.record_id}",
            kind="root",
            target_cutpoint=root.unit_id,
            transition_id=None,
            facts=(),
        )
        for root in complete_roots
    )
    profile_sha256 = canonical_sha256_v3(
        {
            "launch_root_artifact_id": launch_roots.manifest.artifact_id,
            "launch_root_manifest_sha256": launch_roots.manifest_sha256,
            "root_record_ids": [root.record_id for root in complete_roots],
        }
    )
    config = InductiveConfigV3(
        record_id="inductive-config",
        profile_sha256=profile_sha256,
        root_unit_ids=root_unit_ids,
        root_entry_facts=entries,
        required_exports=(),
        dependency_discharges=(),
        budgets=InvariantBudgetsV3(
            maximum_members=16384,
            maximum_transitions=65536,
            maximum_facts_per_cutpoint=128,
            maximum_finite_values=64,
            maximum_resource_states=32,
            maximum_dependencies=16384,
        ),
    )
    records = [INDUCTIVE_INPUT_CODEC_V3.write(config.record_id, config)]
    # Empty invariants mean true at each root.  Emitting the root cutpoints
    # explicitly makes the input reviewable while keeping initiation sound.
    records.extend(
        INDUCTIVE_INPUT_CODEC_V3.write(
            unit_id,
            InductiveCutpointV3(
                unit_id, CutpointInvariantV3(unit_id, ())
            ),
        )
        for unit_id in root_unit_ids
    )
    return tuple(sorted(records, key=lambda row: row.record_id))


def emit_standard_evidence_v3(
    *,
    machine_ir_manifest: Path,
    launch_roots_path: Path,
    output_directory: Path,
) -> dict[str, Any]:
    """Emit conservative proposal artifacts for the standard v3 workflow."""

    machine_manifest = _load_manifest(machine_ir_manifest)
    launch_roots = ArtifactSetReaderV3(launch_roots_path)
    binary_bindings = tuple(
        binding
        for binding in launch_roots.manifest.bindings
        if binding.name == "binary" and binding.kind == "pe32"
    )
    if len(binary_bindings) != 1:
        raise StandardEvidenceV3Error(
            "launch-root evidence must contain exactly one PE32 binary binding"
        )
    bindings: tuple[ArtifactBindingV3, ...] = binary_bindings
    target_records = _target_hint_records(machine_manifest)
    inductive_records = _inductive_input_records(launch_roots)

    output_directory.mkdir(parents=True, exist_ok=False)
    target_manifest = ArtifactSetWriterV3(
        artifact_kind=TARGET_HINTS_ARTIFACT_KIND_V3,
        bindings=bindings,
    ).write(output_directory / "target-hints", target_records)
    inductive_manifest = ArtifactSetWriterV3(
        artifact_kind=INDUCTIVE_INPUTS_ARTIFACT_KIND_V3,
        bindings=bindings,
    ).write(output_directory / "inductive-inputs", inductive_records)
    metadata = {
        "format": STANDARD_EVIDENCE_FORMAT_V3,
        "binary_binding": binary_bindings[0].to_payload(),
        "machine_ir_manifest_sha256": canonical_sha256_v3(machine_manifest),
        "launch_root_artifact_id": launch_roots.manifest.artifact_id,
        "target_hints": {
            "artifact_id": target_manifest.artifact_id,
            "artifact_kind": target_manifest.artifact_kind,
            "record_ids": [row.record_id for row in target_records],
        },
        "inductive_inputs": {
            "artifact_id": inductive_manifest.artifact_id,
            "artifact_kind": inductive_manifest.artifact_kind,
            "record_ids": [row.record_id for row in inductive_records],
        },
    }
    (output_directory / "metadata.json").write_bytes(
        canonical_json_bytes_v3(metadata)
    )
    return metadata


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Emit conservative standard proposal evidence for analysis v3"
    )
    parser.add_argument("--machine-ir-manifest", type=Path, required=True)
    parser.add_argument("--launch-roots", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    emit_standard_evidence_v3(
        machine_ir_manifest=arguments.machine_ir_manifest,
        launch_roots_path=arguments.launch_roots,
        output_directory=arguments.out,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

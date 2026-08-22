"""Generate exact-bound callback entry proposals from canonical ABI contracts."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from ..artifacts.artifact_set import (
    ArtifactBindingV3,
    ArtifactDependencyV3,
    ArtifactSetWriterV3,
    RecordDependencyV3,
)
from ..artifacts.io import ArtifactInputReaderV3, open_artifact_reader_v3
from ..authority.callbacks import (
    CALLBACK_EVIDENCE_ARTIFACT_KIND_V3,
    CALLBACK_EVIDENCE_CODEC_V3,
    CallbackEvidenceV3,
    derive_callback_entry_state_v3,
)
from ..authority.authority_common import PrimaryBlockerV3
from ..authority.external_site_records import (
    CANONICAL_EXTERNAL_SITE_CODEC_V3,
    CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
)
from ..authority.incoming_call_frames import (
    INCOMING_CALL_FRAME_CODEC_V3,
    INCOMING_CALL_FRAMES_ARTIFACT_KIND_V3,
)


class StandardCallbackEvidenceV3Error(ValueError):
    """Canonical sites and exact callback targets cannot be reconciled."""


def _require_kind(
    reader: ArtifactInputReaderV3, expected: str, label: str
) -> None:
    if reader.manifest.artifact_kind != expected:
        raise StandardCallbackEvidenceV3Error(
            f"{label} has artifact kind {reader.manifest.artifact_kind!r}, "
            f"expected {expected!r}"
        )


def _binary_binding(
    reader: ArtifactInputReaderV3, label: str
) -> ArtifactBindingV3:
    bindings = tuple(
        row
        for row in reader.manifest.bindings
        if row.name == "binary" and row.kind == "pe32"
    )
    if len(bindings) != 1:
        raise StandardCallbackEvidenceV3Error(
            f"{label} must contain exactly one binary/pe32 binding"
        )
    return bindings[0]


def _dependency(
    name: str, reader: ArtifactInputReaderV3
) -> ArtifactDependencyV3:
    return ArtifactDependencyV3(
        name=name,
        artifact_kind=reader.manifest.artifact_kind,
        artifact_id=reader.manifest.artifact_id,
        manifest_sha256=reader.manifest_sha256,
    )


def generate_standard_callback_evidence_v3(
    *,
    canonical_external_sites_path: Path,
    incoming_call_frames_path: Path,
    output_directory: Path,
) -> object:
    external_sites = open_artifact_reader_v3(canonical_external_sites_path)
    incoming_frames = open_artifact_reader_v3(incoming_call_frames_path)
    _require_kind(
        external_sites,
        CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
        "canonical external sites",
    )
    _require_kind(
        incoming_frames,
        INCOMING_CALL_FRAMES_ARTIFACT_KIND_V3,
        "incoming call frames",
    )
    bindings = (
        _binary_binding(external_sites, "canonical external sites"),
        _binary_binding(incoming_frames, "incoming call frames"),
    )
    if bindings[0] != bindings[1]:
        raise StandardCallbackEvidenceV3Error(
            "callback evidence inputs bind different PE32 binaries"
        )

    records = []
    seen: set[str] = set()
    for source in external_sites.iter_records():
        external = CANONICAL_EXTERNAL_SITE_CODEC_V3.read(source).value
        for site in external.sites:
            if site.status != "complete" or site.contract is None:
                continue
            for requirement in site.contract.callbacks:
                if requirement.callback_id in seen:
                    raise StandardCallbackEvidenceV3Error(
                        f"callback ID {requirement.callback_id!r} is duplicated"
                    )
                seen.add(requirement.callback_id)
                target_source = incoming_frames.find_record(
                    requirement.target_unit_id
                )
                target_sha256 = "0" * 64
                if target_source is None:
                    entry_state = None
                    blocker = PrimaryBlockerV3(
                        "violated", "callback_target_unit_missing"
                    )
                else:
                    target = INCOMING_CALL_FRAME_CODEC_V3.read(target_source).value
                    target_sha256 = target.unit_sha256
                    if target.rva_start != requirement.target_rva:
                        entry_state = None
                        blocker = PrimaryBlockerV3(
                            "violated", "callback_target_rva_contradiction"
                        )
                    else:
                        entry_state, blocker = derive_callback_entry_state_v3(
                            external_site_id=site.site_id,
                            requirement=requirement,
                            machine_contract=site.contract.machine_contract,
                        )
                status = "complete" if blocker is None else blocker.status
                evidence = CallbackEvidenceV3(
                    record_id=requirement.callback_id,
                    external_site_id=site.site_id,
                    target_unit_id=requirement.target_unit_id,
                    target_unit_sha256=target_sha256,
                    target_rva=requirement.target_rva,
                    abi_sha256=requirement.abi_sha256,
                    lifetime=requirement.lifetime,
                    status=status,
                    entry_state=entry_state,
                    primary_blocker=blocker,
                )
                records.append(
                    CALLBACK_EVIDENCE_CODEC_V3.write(
                        evidence.record_id,
                        evidence,
                        dependencies=(
                            RecordDependencyV3(
                                "canonical_external_sites", external.record_id
                            ),
                            RecordDependencyV3(
                                "incoming_call_frames",
                                requirement.target_unit_id,
                            ),
                        ),
                    )
                )

    return ArtifactSetWriterV3(
        artifact_kind=CALLBACK_EVIDENCE_ARTIFACT_KIND_V3,
        bindings=(bindings[0],),
        dependencies=(
            _dependency("canonical_external_sites", external_sites),
            _dependency("incoming_call_frames", incoming_frames),
        ),
        # Individual records retain exact fail-closed diagnostics.
        status="complete",
    ).write(output_directory, sorted(records, key=lambda row: row.record_id))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate exact callback entry evidence from canonical ABI contracts"
    )
    parser.add_argument("--canonical-external-sites", type=Path, required=True)
    parser.add_argument("--incoming-call-frames", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    generate_standard_callback_evidence_v3(
        canonical_external_sites_path=arguments.canonical_external_sites,
        incoming_call_frames_path=arguments.incoming_call_frames,
        output_directory=arguments.out,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "StandardCallbackEvidenceV3Error",
    "generate_standard_callback_evidence_v3",
    "main",
]

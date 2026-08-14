"""Candidate-only projection of canonical v3 external-site authority."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..artifact_set_v3 import ArtifactSetReaderV3
from ..authority.external_site_records import (
    CANONICAL_EXTERNAL_SITE_CODEC_V3,
    CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
)
from ..errors import StageAInputError
from .contracts import (
    CheckedExternalSiteContract,
    checked_external_site_contract_from_authority,
)


@dataclass(frozen=True)
class AuthoritativeExternalSite:
    site_id: str
    unit_id: str
    unit_sha256: str
    event_index: int
    alternative_index: int
    event_sha256: str
    target_sha256: str
    contract: CheckedExternalSiteContract


@dataclass(frozen=True)
class AuthoritativeExternalSiteIndex:
    artifact_id: str
    manifest_sha256: str
    sites: tuple[AuthoritativeExternalSite, ...]

    def by_event(self) -> dict[tuple[str, int], tuple[AuthoritativeExternalSite, ...]]:
        grouped: dict[tuple[str, int], list[AuthoritativeExternalSite]] = {}
        for site in self.sites:
            grouped.setdefault((site.unit_id, site.event_index), []).append(site)
        return {
            key: tuple(sorted(values, key=lambda row: row.alternative_index))
            for key, values in grouped.items()
        }


def load_authoritative_external_sites(
    path: Path | str,
) -> AuthoritativeExternalSiteIndex:
    """Load only complete, authorizing canonical v3 site records."""

    reader = ArtifactSetReaderV3(path)
    if reader.manifest.artifact_kind != CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3:
        raise StageAInputError(
            "external runtime projection requires canonical-external-sites-v3"
        )
    sites: list[AuthoritativeExternalSite] = []
    for artifact_record in reader.iter_records():
        record = CANONICAL_EXTERNAL_SITE_CODEC_V3.decode(
            artifact_record.value.to_value()
        )
        if record.status != "complete" or not record.authorizing:
            raise StageAInputError(
                f"canonical external-site record {record.record_id!r} is not authorizing"
            )
        for site in record.sites:
            if site.status != "complete" or not site.authorizing or site.contract is None:
                raise StageAInputError(
                    f"canonical external site {site.site_id!r} is not authorizing"
                )
            sites.append(
                AuthoritativeExternalSite(
                    site_id=site.site_id,
                    unit_id=site.unit_id,
                    unit_sha256=record.unit_sha256,
                    event_index=site.event_index,
                    alternative_index=site.alternative_index,
                    event_sha256=site.event_sha256,
                    target_sha256=site.target_sha256,
                    contract=checked_external_site_contract_from_authority(
                        site.contract,
                        context=f"canonical external site {site.site_id}",
                    ),
                )
            )
    ordered = tuple(
        sorted(sites, key=lambda row: (row.unit_id, row.event_index, row.alternative_index))
    )
    if len({site.site_id for site in ordered}) != len(ordered):
        raise StageAInputError("canonical external-site projection contains duplicate IDs")
    return AuthoritativeExternalSiteIndex(
        artifact_id=reader.manifest.artifact_id,
        manifest_sha256=reader.manifest_sha256,
        sites=ordered,
    )


__all__ = [
    "AuthoritativeExternalSite",
    "AuthoritativeExternalSiteIndex",
    "load_authoritative_external_sites",
]

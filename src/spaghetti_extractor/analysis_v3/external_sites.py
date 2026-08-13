"""Canonical external-site authority over exact unit-local transitions."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from ..artifact_set_v3 import (
    ArtifactRecordV3,
    ArtifactSetReaderV3,
    ArtifactV3Error,
    CanonicalValueV3,
    RecordDependencyV3,
    canonical_sha256_v3,
)
from ..phase_framework_v3 import PhaseContextV3, RecordCodecV3, map_units
from ._schema import (
    canonical_strings,
    digest,
    fail,
    mapping,
    require_record_ids,
    require_stable_id,
    sequence,
    sorted_records,
    stable_id,
    strict_object,
    text,
    uint,
)
from .authority_common import (
    PrimaryBlockerV3,
    aggregate_blockers_v3,
    blocker_payload_v3,
    canonical_dependencies_v3,
    decode_dependencies_v3,
    encode_dependencies_v3,
    manifest_blocker_v3,
    validate_authority_decision_v3,
)
from .identities import indirect_exit_id_v3
from .semantic_index import SEMANTIC_INDEX_CODEC_V3, SemanticIndexRecordV3
from .structural_targets import (
    STRUCTURAL_TARGET_UNIT_CODEC_V3,
)
from .transition_records import (
    TRANSITION_SUMMARY_CODEC_V3,
    TransitionSummaryRecordV3,
)


EXTERNAL_SITE_EVIDENCE_RECORD_V3_SCHEMA = (
    "spaghetti-extractor-external-site-evidence-record-v3"
)
EXTERNAL_SITE_EVIDENCE_ARTIFACT_KIND_V3 = "external-site-evidence-v3"
EXTERNAL_PROFILE_RECORD_V3_SCHEMA = (
    "spaghetti-extractor-external-profile-record-v3"
)
EXTERNAL_PROFILE_ARTIFACT_KIND_V3 = "external-profile-authority-v3"
CANONICAL_EXTERNAL_SITE_RECORD_V3_SCHEMA = (
    "spaghetti-extractor-canonical-external-site-record-v3"
)
CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3 = "canonical-external-sites-v3"


@dataclass(frozen=True)
class ExternalProfileV3:
    record_id: str
    profile_id: str
    profile_sha256: str
    identity: CanonicalValueV3
    allowed_transfers: tuple[str, ...]
    allowed_dispositions: tuple[str, ...]
    argument_words: int
    memory_effect: str
    world_effect: str
    callback_effect: str

    def __post_init__(self) -> None:
        text(self.profile_id, "external profile ID")
        digest(self.profile_sha256, "external profile SHA-256")
        mapping(self.identity.to_value(), "external profile identity")
        if (
            not self.allowed_transfers
            or set(self.allowed_transfers) - {"call", "jump"}
            or self.allowed_transfers != tuple(sorted(set(self.allowed_transfers)))
        ):
            fail(
                "record_schema_mismatch",
                "external profile transfers are empty, unsupported, or noncanonical",
                "emit sorted unique call/jump transfers",
            )
        if (
            not self.allowed_dispositions
            or set(self.allowed_dispositions)
            - {"returns", "tail_jump", "noreturn"}
            or self.allowed_dispositions
            != tuple(sorted(set(self.allowed_dispositions)))
        ):
            fail(
                "record_schema_mismatch",
                "external profile dispositions are empty, unsupported, or noncanonical",
                "emit sorted unique supported dispositions",
            )
        uint(self.argument_words, "external profile argument words", maximum=256)
        text(self.memory_effect, "external profile memory effect")
        text(self.world_effect, "external profile world effect")
        if self.callback_effect not in {"none", "registers"}:
            fail(
                "record_schema_mismatch",
                f"external profile callback effect is {self.callback_effect!r}",
                "use none or registers",
            )
        require_stable_id(
            self.record_id,
            "external-profile-v3",
            self.binding_payload,
            "external profile",
        )

    @property
    def binding_payload(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "profile_sha256": self.profile_sha256,
            "identity": self.identity.to_value(),
        }

    @property
    def identity_payload(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "profile_sha256": self.profile_sha256,
            "identity": self.identity.to_value(),
            "allowed_transfers": list(self.allowed_transfers),
            "allowed_dispositions": list(self.allowed_dispositions),
            "argument_words": self.argument_words,
            "memory_effect": self.memory_effect,
            "world_effect": self.world_effect,
            "callback_effect": self.callback_effect,
        }

    @classmethod
    def create(
        cls,
        *,
        profile_id: str,
        profile_sha256: str,
        identity: Mapping[str, Any],
        allowed_transfers: Sequence[str],
        allowed_dispositions: Sequence[str],
        argument_words: int,
        memory_effect: str,
        world_effect: str,
        callback_effect: str,
    ) -> "ExternalProfileV3":
        canonical_identity = CanonicalValueV3.of(identity)
        transfers = tuple(sorted(set(allowed_transfers)))
        dispositions = tuple(sorted(set(allowed_dispositions)))
        return cls(
            stable_id(
                "external-profile-v3",
                {
                    "profile_id": profile_id,
                    "profile_sha256": profile_sha256,
                    "identity": canonical_identity.to_value(),
                },
            ),
            profile_id,
            profile_sha256,
            canonical_identity,
            transfers,
            dispositions,
            argument_words,
            memory_effect,
            world_effect,
            callback_effect,
        )


def _encode_external_profile(value: ExternalProfileV3) -> dict[str, Any]:
    return {
        "schema": EXTERNAL_PROFILE_RECORD_V3_SCHEMA,
        "id": value.record_id,
        **value.identity_payload,
    }


def _decode_external_profile(value: Any) -> ExternalProfileV3:
    row = strict_object(
        value,
        {
            "schema",
            "id",
            "profile_id",
            "profile_sha256",
            "identity",
            "allowed_transfers",
            "allowed_dispositions",
            "argument_words",
            "memory_effect",
            "world_effect",
            "callback_effect",
        },
        "external profile",
    )
    if row["schema"] != EXTERNAL_PROFILE_RECORD_V3_SCHEMA:
        fail(
            "wrong_record_schema",
            "record is not external-profile-record-v3",
            "use EXTERNAL_PROFILE_CODEC_V3 with external-profile-authority-v3",
        )
    return ExternalProfileV3(
        record_id=text(row["id"], "external profile record ID"),
        profile_id=text(row["profile_id"], "external profile ID"),
        profile_sha256=digest(
            row["profile_sha256"], "external profile SHA-256"
        ),
        identity=CanonicalValueV3.of(row["identity"]),
        allowed_transfers=canonical_strings(
            row["allowed_transfers"], "external profile transfers"
        ),
        allowed_dispositions=canonical_strings(
            row["allowed_dispositions"], "external profile dispositions"
        ),
        argument_words=uint(
            row["argument_words"], "external profile argument words", maximum=256
        ),
        memory_effect=text(row["memory_effect"], "external profile memory effect"),
        world_effect=text(row["world_effect"], "external profile world effect"),
        callback_effect=text(
            row["callback_effect"], "external profile callback effect"
        ),
    )


EXTERNAL_PROFILE_CODEC_V3 = RecordCodecV3[ExternalProfileV3](
    decode=_decode_external_profile,
    encode=_encode_external_profile,
)


@dataclass(frozen=True, order=True)
class CallbackRequirementV3:
    callback_id: str
    ordinal: int
    target_unit_id: str
    target_rva: int
    abi_sha256: str
    lifetime: str

    def __post_init__(self) -> None:
        text(self.callback_id, "callback requirement ID")
        uint(self.ordinal, "callback requirement ordinal")
        text(self.target_unit_id, "callback target unit ID")
        uint(self.target_rva, "callback target RVA")
        digest(self.abi_sha256, "callback ABI SHA-256")
        text(self.lifetime, "callback lifetime")

    @classmethod
    def create(
        cls,
        *,
        site_id: str,
        ordinal: int,
        target_unit_id: str,
        target_rva: int,
        abi_sha256: str,
        lifetime: str,
    ) -> "CallbackRequirementV3":
        identity = {
            "site_id": site_id,
            "ordinal": ordinal,
            "target_unit_id": target_unit_id,
            "target_rva": target_rva,
            "abi_sha256": abi_sha256,
            "lifetime": lifetime,
        }
        return cls(
            stable_id("callback-v3", identity),
            ordinal,
            target_unit_id,
            target_rva,
            abi_sha256,
            lifetime,
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.callback_id,
            "ordinal": self.ordinal,
            "target_unit_id": self.target_unit_id,
            "target_rva": self.target_rva,
            "abi_sha256": self.abi_sha256,
            "lifetime": self.lifetime,
        }

    @classmethod
    def parse(cls, value: Any, *, site_id: str) -> "CallbackRequirementV3":
        row = strict_object(
            value,
            {
                "id",
                "ordinal",
                "target_unit_id",
                "target_rva",
                "abi_sha256",
                "lifetime",
            },
            "external callback requirement",
        )
        result = cls(
            callback_id=text(row["id"], "callback requirement ID"),
            ordinal=uint(row["ordinal"], "callback requirement ordinal"),
            target_unit_id=text(row["target_unit_id"], "callback target unit ID"),
            target_rva=uint(row["target_rva"], "callback target RVA"),
            abi_sha256=digest(row["abi_sha256"], "callback ABI SHA-256"),
            lifetime=text(row["lifetime"], "callback lifetime"),
        )
        expected = cls.create(
            site_id=site_id,
            ordinal=result.ordinal,
            target_unit_id=result.target_unit_id,
            target_rva=result.target_rva,
            abi_sha256=result.abi_sha256,
            lifetime=result.lifetime,
        )
        if result.callback_id != expected.callback_id:
            fail(
                "stale_record_id",
                f"callback requirement {result.callback_id!r} has a stale identity",
                f"recreate it as {expected.callback_id!r}",
            )
        return result


@dataclass(frozen=True)
class ExternalContractV3:
    contract_id: str
    identity: CanonicalValueV3
    transfer_kind: str
    disposition: str
    profile_id: str
    profile_sha256: str
    argument_words: int
    memory_effect: str
    world_effect: str
    callback_effect: str
    callbacks: tuple[CallbackRequirementV3, ...]

    def __post_init__(self) -> None:
        text(self.contract_id, "external contract ID")
        mapping(self.identity.to_value(), "external contract identity")
        if self.transfer_kind not in {"call", "jump"}:
            fail(
                "record_schema_mismatch",
                f"external contract has transfer {self.transfer_kind!r}",
                "use call or jump",
            )
        if self.disposition not in {"returns", "tail_jump", "noreturn"}:
            fail(
                "record_schema_mismatch",
                f"external contract has disposition {self.disposition!r}",
                "use returns, tail_jump, or noreturn",
            )
        text(self.profile_id, "external profile ID")
        digest(self.profile_sha256, "external profile SHA-256")
        uint(self.argument_words, "external argument word count", maximum=256)
        text(self.memory_effect, "external memory effect")
        text(self.world_effect, "external world effect")
        if self.callback_effect not in {"none", "registers"}:
            fail(
                "record_schema_mismatch",
                f"external callback effect is {self.callback_effect!r}",
                "use none or registers",
            )
        if self.callbacks != tuple(sorted(set(self.callbacks))):
            fail(
                "noncanonical_record_order",
                "external callback requirements are duplicated or unsorted",
                "sort and deduplicate callback requirements",
            )
        if (self.callback_effect == "none") != (not self.callbacks):
            fail(
                "external_callback_contradiction",
                "external callback effect disagrees with callback requirements",
                "supply requirements exactly when callback_effect is registers",
            )
        require_stable_id(
            self.contract_id,
            "external-contract-v3",
            self.identity_payload,
            "external contract",
        )

    @property
    def identity_payload(self) -> dict[str, Any]:
        return {
            "identity": self.identity.to_value(),
            "transfer_kind": self.transfer_kind,
            "disposition": self.disposition,
            "profile_id": self.profile_id,
            "profile_sha256": self.profile_sha256,
            "argument_words": self.argument_words,
            "memory_effect": self.memory_effect,
            "world_effect": self.world_effect,
            "callback_effect": self.callback_effect,
            "callbacks": [row.to_payload() for row in self.callbacks],
        }

    @classmethod
    def create(
        cls,
        *,
        identity: Mapping[str, Any],
        transfer_kind: str,
        disposition: str,
        profile_id: str,
        profile_sha256: str,
        argument_words: int,
        memory_effect: str,
        world_effect: str,
        callback_effect: str,
        callbacks: Sequence[CallbackRequirementV3] = (),
    ) -> "ExternalContractV3":
        canonical_identity = CanonicalValueV3.of(identity)
        ordered_callbacks = tuple(sorted(set(callbacks)))
        payload = {
            "identity": canonical_identity.to_value(),
            "transfer_kind": transfer_kind,
            "disposition": disposition,
            "profile_id": profile_id,
            "profile_sha256": profile_sha256,
            "argument_words": argument_words,
            "memory_effect": memory_effect,
            "world_effect": world_effect,
            "callback_effect": callback_effect,
            "callbacks": [row.to_payload() for row in ordered_callbacks],
        }
        return cls(
            stable_id("external-contract-v3", payload),
            canonical_identity,
            transfer_kind,
            disposition,
            profile_id,
            profile_sha256,
            argument_words,
            memory_effect,
            world_effect,
            callback_effect,
            ordered_callbacks,
        )

    def to_payload(self) -> dict[str, Any]:
        return {"id": self.contract_id, **self.identity_payload}

    @classmethod
    def parse(cls, value: Any, *, site_id: str) -> "ExternalContractV3":
        row = strict_object(
            value,
            {
                "id",
                "identity",
                "transfer_kind",
                "disposition",
                "profile_id",
                "profile_sha256",
                "argument_words",
                "memory_effect",
                "world_effect",
                "callback_effect",
                "callbacks",
            },
            "external contract",
        )
        callbacks = tuple(
            CallbackRequirementV3.parse(item, site_id=site_id)
            for item in sequence(row["callbacks"], "external callback requirements")
        )
        return cls(
            contract_id=text(row["id"], "external contract ID"),
            identity=CanonicalValueV3.of(row["identity"]),
            transfer_kind=text(row["transfer_kind"], "external transfer kind"),
            disposition=text(row["disposition"], "external disposition"),
            profile_id=text(row["profile_id"], "external profile ID"),
            profile_sha256=digest(row["profile_sha256"], "external profile SHA-256"),
            argument_words=uint(
                row["argument_words"], "external argument words", maximum=256
            ),
            memory_effect=text(row["memory_effect"], "external memory effect"),
            world_effect=text(row["world_effect"], "external world effect"),
            callback_effect=text(row["callback_effect"], "external callback effect"),
            callbacks=callbacks,
        )


@dataclass(frozen=True)
class ExternalSiteEvidenceV3:
    record_id: str
    unit_id: str
    unit_sha256: str
    event_index: int
    event_sha256: str
    alternative_index: int
    target_sha256: str
    identity: CanonicalValueV3
    status: str
    contract: ExternalContractV3 | None
    primary_blocker: PrimaryBlockerV3 | None

    def __post_init__(self) -> None:
        text(self.unit_id, "external-site evidence unit ID")
        digest(self.unit_sha256, "external-site evidence unit SHA-256")
        uint(self.event_index, "external-site evidence event index")
        digest(self.event_sha256, "external-site evidence event SHA-256")
        uint(self.alternative_index, "external-site evidence alternative index")
        digest(self.target_sha256, "external-site evidence target SHA-256")
        mapping(self.identity.to_value(), "external-site evidence identity")
        require_stable_id(
            self.record_id,
            "external-site-v3",
            _site_identity_payload(
                self.unit_id,
                self.event_index,
                self.alternative_index,
                self.target_sha256,
            ),
            "external-site evidence",
        )
        if self.status not in {"complete", "incomplete", "violated"}:
            fail(
                "record_schema_mismatch",
                f"external-site evidence status is {self.status!r}",
                "use complete, incomplete, or violated",
            )
        if self.status == "complete":
            if self.contract is None or self.primary_blocker is not None:
                fail(
                    "fail_open_external_evidence",
                    "complete external-site evidence lacks a contract or has a blocker",
                    "bind one contract and clear the blocker",
                )
        elif self.contract is not None or self.primary_blocker is None:
            fail(
                "fail_open_external_evidence",
                "non-complete external-site evidence retains a contract or lacks a blocker",
                "clear the contract and provide the matching blocker",
            )
        if self.primary_blocker is not None and self.primary_blocker.status != self.status:
            fail(
                "fail_open_external_evidence",
                "external-site evidence blocker disagrees with its status",
                "use one matching fail-closed status",
            )


def _encode_external_evidence(value: ExternalSiteEvidenceV3) -> dict[str, Any]:
    return {
        "schema": EXTERNAL_SITE_EVIDENCE_RECORD_V3_SCHEMA,
        "id": value.record_id,
        "unit_id": value.unit_id,
        "unit_sha256": value.unit_sha256,
        "event_index": value.event_index,
        "event_sha256": value.event_sha256,
        "alternative_index": value.alternative_index,
        "target_sha256": value.target_sha256,
        "identity": value.identity.to_value(),
        "status": value.status,
        "contract": None if value.contract is None else value.contract.to_payload(),
        "primary_blocker": blocker_payload_v3(value.primary_blocker),
    }


def _decode_external_evidence(value: Any) -> ExternalSiteEvidenceV3:
    row = strict_object(
        value,
        {
            "schema",
            "id",
            "unit_id",
            "unit_sha256",
            "event_index",
            "event_sha256",
            "alternative_index",
            "target_sha256",
            "identity",
            "status",
            "contract",
            "primary_blocker",
        },
        "external-site evidence",
    )
    if row["schema"] != EXTERNAL_SITE_EVIDENCE_RECORD_V3_SCHEMA:
        fail(
            "wrong_record_schema",
            "record is not external-site-evidence-record-v3",
            "use EXTERNAL_SITE_EVIDENCE_CODEC_V3 with matching evidence",
        )
    record_id = text(row["id"], "external-site evidence ID")
    return ExternalSiteEvidenceV3(
        record_id=record_id,
        unit_id=text(row["unit_id"], "external-site evidence unit ID"),
        unit_sha256=digest(row["unit_sha256"], "external-site evidence unit SHA-256"),
        event_index=uint(row["event_index"], "external-site evidence event index"),
        event_sha256=digest(row["event_sha256"], "external-site evidence event SHA-256"),
        alternative_index=uint(
            row["alternative_index"], "external-site evidence alternative index"
        ),
        target_sha256=digest(
            row["target_sha256"], "external-site evidence target SHA-256"
        ),
        identity=CanonicalValueV3.of(row["identity"]),
        status=text(row["status"], "external-site evidence status"),
        contract=(
            None
            if row["contract"] is None
            else ExternalContractV3.parse(row["contract"], site_id=record_id)
        ),
        primary_blocker=(
            None
            if row["primary_blocker"] is None
            else PrimaryBlockerV3.parse(row["primary_blocker"])
        ),
    )


EXTERNAL_SITE_EVIDENCE_CODEC_V3 = RecordCodecV3[ExternalSiteEvidenceV3](
    decode=_decode_external_evidence,
    encode=_encode_external_evidence,
)


@dataclass(frozen=True)
class CanonicalExternalSiteV3:
    site_id: str
    unit_id: str
    event_index: int
    alternative_index: int
    event_sha256: str
    target_sha256: str
    identity: CanonicalValueV3
    status: str
    authorizing: bool
    contract: ExternalContractV3 | None
    primary_blocker: PrimaryBlockerV3 | None

    def __post_init__(self) -> None:
        require_stable_id(
            self.site_id,
            "external-site-v3",
            _site_identity_payload(
                self.unit_id,
                self.event_index,
                self.alternative_index,
                self.target_sha256,
            ),
            "canonical external site",
        )
        digest(self.event_sha256, "canonical external event SHA-256")
        mapping(self.identity.to_value(), "canonical external identity")
        validate_authority_decision_v3(
            status=self.status,
            authorizing=self.authorizing,
            primary_blocker=self.primary_blocker,
            dependencies=(
                ()
                if self.primary_blocker is None
                or self.primary_blocker.dependency is None
                else (self.primary_blocker.dependency,)
            ),
            context=f"canonical external site {self.site_id!r}",
        )
        if (self.status == "complete") != (self.contract is not None):
            fail(
                "fail_open_external_site",
                "canonical external-site status disagrees with contract authority",
                "retain a contract only for a complete site",
            )


@dataclass(frozen=True)
class CanonicalExternalSiteRecordV3:
    record_id: str
    unit_sha256: str
    status: str
    authorizing: bool
    sites: tuple[CanonicalExternalSiteV3, ...]
    primary_blocker: PrimaryBlockerV3 | None
    dependencies: tuple[RecordDependencyV3, ...]

    def __post_init__(self) -> None:
        text(self.record_id, "canonical external-site unit ID")
        digest(self.unit_sha256, "canonical external-site unit SHA-256")
        if self.sites != tuple(sorted(set(self.sites), key=lambda row: row.site_id)):
            fail(
                "noncanonical_record_order",
                "canonical external sites are duplicated or unsorted",
                "sort and deduplicate sites by stable ID",
            )
        if any(site.unit_id != self.record_id for site in self.sites):
            fail(
                "external_site_unit_contradiction",
                "canonical external-site inventory mixes source units",
                "place each site under its exact source unit record",
            )
        validate_authority_decision_v3(
            status=self.status,
            authorizing=self.authorizing,
            primary_blocker=self.primary_blocker,
            dependencies=self.dependencies,
            context=f"external-site inventory {self.record_id!r}",
        )


def _site_payload(value: CanonicalExternalSiteV3) -> dict[str, Any]:
    return {
        "id": value.site_id,
        "unit_id": value.unit_id,
        "event_index": value.event_index,
        "alternative_index": value.alternative_index,
        "event_sha256": value.event_sha256,
        "target_sha256": value.target_sha256,
        "identity": value.identity.to_value(),
        "status": value.status,
        "authorizing": value.authorizing,
        "contract": None if value.contract is None else value.contract.to_payload(),
        "primary_blocker": blocker_payload_v3(value.primary_blocker),
    }


def _parse_site(value: Any) -> CanonicalExternalSiteV3:
    row = strict_object(
        value,
        {
            "id",
            "unit_id",
            "event_index",
            "alternative_index",
            "event_sha256",
            "target_sha256",
            "identity",
            "status",
            "authorizing",
            "contract",
            "primary_blocker",
        },
        "canonical external site",
    )
    site_id = text(row["id"], "canonical external-site ID")
    authorizing = row["authorizing"]
    if not isinstance(authorizing, bool):
        fail(
            "record_schema_mismatch",
            "canonical external-site authorizing field is not Boolean",
            "emit true or false",
        )
    return CanonicalExternalSiteV3(
        site_id=site_id,
        unit_id=text(row["unit_id"], "canonical external-site unit ID"),
        event_index=uint(row["event_index"], "canonical external-site event index"),
        alternative_index=uint(
            row["alternative_index"], "canonical external-site alternative index"
        ),
        event_sha256=digest(
            row["event_sha256"], "canonical external event SHA-256"
        ),
        target_sha256=digest(
            row["target_sha256"], "canonical external target SHA-256"
        ),
        identity=CanonicalValueV3.of(row["identity"]),
        status=text(row["status"], "canonical external-site status"),
        authorizing=authorizing,
        contract=(
            None
            if row["contract"] is None
            else ExternalContractV3.parse(row["contract"], site_id=site_id)
        ),
        primary_blocker=(
            None
            if row["primary_blocker"] is None
            else PrimaryBlockerV3.parse(row["primary_blocker"])
        ),
    )


def _encode_external_sites(value: CanonicalExternalSiteRecordV3) -> dict[str, Any]:
    return {
        "schema": CANONICAL_EXTERNAL_SITE_RECORD_V3_SCHEMA,
        "id": value.record_id,
        "unit_sha256": value.unit_sha256,
        "status": value.status,
        "authorizing": value.authorizing,
        "sites": [_site_payload(row) for row in value.sites],
        "primary_blocker": blocker_payload_v3(value.primary_blocker),
        "dependencies": encode_dependencies_v3(value.dependencies),
    }


def _decode_external_sites(value: Any) -> CanonicalExternalSiteRecordV3:
    row = strict_object(
        value,
        {
            "schema",
            "id",
            "unit_sha256",
            "status",
            "authorizing",
            "sites",
            "primary_blocker",
            "dependencies",
        },
        "canonical external-site record",
    )
    if row["schema"] != CANONICAL_EXTERNAL_SITE_RECORD_V3_SCHEMA:
        fail(
            "wrong_record_schema",
            "record is not canonical-external-site-record-v3",
            "use CANONICAL_EXTERNAL_SITE_CODEC_V3 with matching artifacts",
        )
    authorizing = row["authorizing"]
    if not isinstance(authorizing, bool):
        fail(
            "record_schema_mismatch",
            "canonical external-site inventory authorizing field is not Boolean",
            "emit true or false",
        )
    return CanonicalExternalSiteRecordV3(
        record_id=text(row["id"], "canonical external-site unit ID"),
        unit_sha256=digest(
            row["unit_sha256"], "canonical external-site unit SHA-256"
        ),
        status=text(row["status"], "canonical external-site inventory status"),
        authorizing=authorizing,
        sites=tuple(
            _parse_site(item)
            for item in sequence(row["sites"], "canonical external sites")
        ),
        primary_blocker=(
            None
            if row["primary_blocker"] is None
            else PrimaryBlockerV3.parse(row["primary_blocker"])
        ),
        dependencies=decode_dependencies_v3(row["dependencies"]),
    )


CANONICAL_EXTERNAL_SITE_CODEC_V3 = RecordCodecV3[CanonicalExternalSiteRecordV3](
    decode=_decode_external_sites,
    encode=_encode_external_sites,
)


@dataclass(frozen=True)
class _ExpectedSite:
    site_id: str
    unit_id: str
    event_index: int
    alternative_index: int
    event_sha256: str
    target_sha256: str
    identity: CanonicalValueV3
    transfer_kind: str
    event: Mapping[str, Any]
    callbacks: tuple[CallbackRequirementV3, ...]
    forced_blocker: PrimaryBlockerV3 | None = None


def _site_identity_payload(
    unit_id: str, event_index: int, alternative_index: int, target_sha256: str
) -> dict[str, Any]:
    return {
        "unit_id": unit_id,
        "event_index": event_index,
        "alternative_index": alternative_index,
        "target_sha256": target_sha256,
    }


def external_site_id_v3(
    unit_id: str, event_index: int, alternative_index: int, target: Any
) -> str:
    return stable_id(
        "external-site-v3",
        _site_identity_payload(
            unit_id,
            event_index,
            alternative_index,
            canonical_sha256_v3(target),
        ),
    )


def _identity(value: Mapping[str, Any]) -> Mapping[str, Any]:
    imported = value.get("import")
    candidate = imported if isinstance(imported, Mapping) else value
    dll = candidate.get("dll")
    symbol = candidate.get("symbol")
    ordinal = candidate.get("ordinal")
    if isinstance(dll, str) and bool(dll):
        has_symbol = isinstance(symbol, str) and bool(symbol)
        has_ordinal = isinstance(ordinal, int) and not isinstance(ordinal, bool)
        if has_symbol != has_ordinal:
            return {
                "kind": "import",
                "dll": dll.lower(),
                "symbol": symbol if has_symbol else None,
                "ordinal": ordinal if has_ordinal else None,
            }
    protocol = value.get("external_protocol")
    if isinstance(protocol, Mapping) and protocol:
        return {"kind": "protocol", "protocol": dict(protocol)}
    fail(
        "external_identity_missing",
        "external event or target has no canonical import/protocol identity",
        "bind exactly one import symbol/ordinal or an external_protocol object",
    )


def _expected_callbacks(
    event: Mapping[str, Any], *, site_id: str
) -> tuple[CallbackRequirementV3, ...]:
    raw = event.get("callback_requirements", [])
    if not isinstance(raw, list):
        fail(
            "record_schema_mismatch",
            "external event callback requirements are not an array",
            "emit exact callback requirement objects",
        )
    result: list[CallbackRequirementV3] = []
    for ordinal, item in enumerate(raw):
        row = strict_object(
            item,
            {"target_unit_id", "target_rva", "abi_sha256", "lifetime"},
            "machine callback requirement",
        )
        result.append(
            CallbackRequirementV3.create(
                site_id=site_id,
                ordinal=ordinal,
                target_unit_id=text(row["target_unit_id"], "callback target unit ID"),
                target_rva=uint(row["target_rva"], "callback target RVA"),
                abi_sha256=digest(row["abi_sha256"], "callback ABI SHA-256"),
                lifetime=text(row["lifetime"], "callback lifetime"),
            )
        )
    return tuple(result)


def _expected_site(
    *,
    exact: SemanticIndexRecordV3,
    event: Mapping[str, Any],
    event_index: int,
    alternative_index: int,
    target: Mapping[str, Any],
    transfer_kind: str,
) -> _ExpectedSite:
    event_sha256 = canonical_sha256_v3(event)
    target_sha256 = canonical_sha256_v3(target)
    site_id = stable_id(
        "external-site-v3",
        _site_identity_payload(
            exact.record_id, event_index, alternative_index, target_sha256
        ),
    )
    try:
        identity = CanonicalValueV3.of(_identity(target))
        callbacks = _expected_callbacks(event, site_id=site_id)
        blocker = None
    except ArtifactV3Error as exc:
        identity = CanonicalValueV3.of({"kind": "invalid", "target_sha256": target_sha256})
        callbacks = ()
        blocker = PrimaryBlockerV3("violated", exc.code)
    return _ExpectedSite(
        site_id,
        exact.record_id,
        event_index,
        alternative_index,
        event_sha256,
        target_sha256,
        identity,
        transfer_kind,
        event,
        callbacks,
        blocker,
    )


def _indirect_exit_id(
    exact: SemanticIndexRecordV3, event: Mapping[str, Any], index: int
) -> str:
    return indirect_exit_id_v3(
        {
            "source_unit_id": exact.record_id,
            "source_rva": exact.rva_start,
            "source_event_index": index,
            "kind": event.get("kind"),
            "target_expression": event.get("target"),
        }
    )


def _record_or_none(
    context: PhaseContextV3, input_name: str, record_id: str
) -> ArtifactRecordV3 | None:
    try:
        return context.record(input_name, record_id)
    except ArtifactV3Error as exc:
        if exc.code == "missing_record":
            return None
        raise


def _expected_sites(
    context: PhaseContextV3,
    exact: SemanticIndexRecordV3,
    summary: TransitionSummaryRecordV3,
) -> tuple[
    tuple[_ExpectedSite, ...],
    tuple[PrimaryBlockerV3, ...],
    tuple[RecordDependencyV3, ...],
]:
    events = tuple(
        row.exact_record.to_value()
        for row in summary.exits
        if row.source_kind == "external_event"
    )
    expected: list[_ExpectedSite] = []
    blockers: list[PrimaryBlockerV3] = []
    dependencies: list[RecordDependencyV3] = []
    for event_index, raw in enumerate(events):
        if not isinstance(raw, Mapping):
            blockers.append(
                PrimaryBlockerV3("violated", "external_event_malformed")
            )
            continue
        event = raw
        kind = event.get("kind")
        if kind in {"external_call", "external_jump"}:
            expected.append(
                _expected_site(
                    exact=exact,
                    event=event,
                    event_index=event_index,
                    alternative_index=0,
                    target=event,
                    transfer_kind="jump" if kind == "external_jump" else "call",
                )
            )
        elif kind in {"indirect_call", "indirect_jump"}:
            exit_id = _indirect_exit_id(exact, event, event_index)
            dependency = RecordDependencyV3("structural_targets", exact.record_id)
            dependencies.append(dependency)
            manifest_blocker = manifest_blocker_v3(
                context,
                dependency.input_name,
                "structural_target_artifact_not_complete",
                dependency,
            )
            if manifest_blocker is not None:
                blockers.append(manifest_blocker)
                continue
            source = _record_or_none(
                context, "structural_targets", exact.record_id
            )
            if source is None:
                blockers.append(
                    PrimaryBlockerV3(
                        "incomplete",
                        "structural_target_missing",
                        dependency.input_name,
                        dependency.record_id,
                    )
                )
                continue
            target_set = STRUCTURAL_TARGET_UNIT_CODEC_V3.read(source).value
            target = next(
                (
                    proposal
                    for proposal in target_set.proposals
                    if proposal.record_id == exit_id
                ),
                None,
            )
            if target is None:
                blockers.append(
                    PrimaryBlockerV3(
                        "incomplete",
                        "structural_target_missing",
                        dependency.input_name,
                        dependency.record_id,
                    )
                )
                continue
            if (
                target.source_unit_id != exact.record_id
                or target.source_event_index != event_index
                or target.transfer_kind != kind
            ):
                blockers.append(
                    PrimaryBlockerV3(
                        "violated",
                        "structural_target_binding_contradiction",
                        dependency.input_name,
                        dependency.record_id,
                    )
                )
                continue
            if target.status != "recovered":
                blockers.append(
                    PrimaryBlockerV3(
                        "violated" if target.status == "violated" else "incomplete",
                        "structural_target_not_recovered",
                        dependency.input_name,
                        dependency.record_id,
                    )
                )
                continue
            for alternative_index, external in enumerate(target.external_targets):
                target_row = mapping(
                    external.to_value(), "recovered external target"
                )
                expected.append(
                    _expected_site(
                        exact=exact,
                        event=event,
                        event_index=event_index,
                        alternative_index=alternative_index,
                        target=target_row,
                        transfer_kind="jump" if kind == "indirect_jump" else "call",
                    )
                )
    return (
        tuple(sorted(expected, key=lambda row: row.site_id)),
        tuple(blockers),
        canonical_dependencies_v3(dependencies),
    )


def _contract_blocker(
    expected: _ExpectedSite, contract: ExternalContractV3
) -> PrimaryBlockerV3 | None:
    if contract.identity != expected.identity or contract.transfer_kind != expected.transfer_kind:
        return PrimaryBlockerV3("violated", "external_contract_identity_contradiction")
    abi = expected.event.get("abi_contract")
    if isinstance(abi, Mapping):
        words = abi.get("argument_words")
        if isinstance(words, int) and not isinstance(words, bool):
            if contract.argument_words != words:
                return PrimaryBlockerV3("violated", "external_contract_abi_contradiction")
        binding = abi.get("profile_binding")
        if isinstance(binding, Mapping) and (
            contract.profile_id != binding.get("profile_id")
            or contract.profile_sha256 != binding.get("profile_sha256")
        ):
            return PrimaryBlockerV3(
                "violated", "external_contract_profile_contradiction"
            )
        callback_effect = abi.get("callback_effect")
        if callback_effect is None and abi.get("world_effect") == "callbackRegistration":
            callback_effect = "registers"
        if callback_effect == "explicit":
            callback_effect = "registers"
        if callback_effect is not None and contract.callback_effect != callback_effect:
            return PrimaryBlockerV3(
                "violated", "external_contract_callback_contradiction"
            )
    if contract.callbacks != expected.callbacks:
        return PrimaryBlockerV3(
            "violated", "external_contract_callback_requirement_contradiction"
        )
    return None


def _profile_dependency(contract: ExternalContractV3) -> RecordDependencyV3:
    return RecordDependencyV3(
        "external_profiles",
        stable_id(
            "external-profile-v3",
            {
                "profile_id": contract.profile_id,
                "profile_sha256": contract.profile_sha256,
                "identity": contract.identity.to_value(),
            },
        ),
    )


def _profile_blocker(
    contract: ExternalContractV3, profile: ExternalProfileV3
) -> PrimaryBlockerV3 | None:
    if (
        profile.profile_id != contract.profile_id
        or profile.profile_sha256 != contract.profile_sha256
        or profile.identity != contract.identity
        or contract.transfer_kind not in profile.allowed_transfers
        or contract.disposition not in profile.allowed_dispositions
        or profile.argument_words != contract.argument_words
        or profile.memory_effect != contract.memory_effect
        or profile.world_effect != contract.world_effect
        or profile.callback_effect != contract.callback_effect
    ):
        return PrimaryBlockerV3(
            "violated", "external_profile_contract_contradiction"
        )
    return None


def _checked_site(
    context: PhaseContextV3,
    exact: SemanticIndexRecordV3,
    expected: _ExpectedSite,
) -> tuple[CanonicalExternalSiteV3, tuple[RecordDependencyV3, ...]]:
    dependency = RecordDependencyV3("external_site_evidence", expected.site_id)
    if expected.forced_blocker is not None:
        blocker = PrimaryBlockerV3(
            expected.forced_blocker.status,
            expected.forced_blocker.code,
            dependency.input_name,
            dependency.record_id,
        )
        return (
            CanonicalExternalSiteV3(
                expected.site_id,
                expected.unit_id,
                expected.event_index,
                expected.alternative_index,
                expected.event_sha256,
                expected.target_sha256,
                expected.identity,
                blocker.status,
                False,
                None,
                blocker,
            ),
            (dependency,),
        )
    source = _record_or_none(context, dependency.input_name, dependency.record_id)
    if source is None:
        blocker = PrimaryBlockerV3(
            "incomplete",
            "external_site_evidence_missing",
            dependency.input_name,
            dependency.record_id,
        )
        return (
            CanonicalExternalSiteV3(
                expected.site_id,
                expected.unit_id,
                expected.event_index,
                expected.alternative_index,
                expected.event_sha256,
                expected.target_sha256,
                expected.identity,
                "incomplete",
                False,
                None,
                blocker,
            ),
            (dependency,),
        )
    manifest_blocker = manifest_blocker_v3(
        context,
        dependency.input_name,
        "external_site_evidence_artifact_not_complete",
        dependency,
    )
    if manifest_blocker is not None:
        return (
            CanonicalExternalSiteV3(
                expected.site_id,
                expected.unit_id,
                expected.event_index,
                expected.alternative_index,
                expected.event_sha256,
                expected.target_sha256,
                expected.identity,
                manifest_blocker.status,
                False,
                None,
                manifest_blocker,
            ),
            (dependency,),
        )
    evidence = EXTERNAL_SITE_EVIDENCE_CODEC_V3.read(source).value
    binding_matches = (
        evidence.record_id == expected.site_id
        and evidence.unit_id == expected.unit_id
        and evidence.unit_sha256 == exact.unit_sha256
        and evidence.event_index == expected.event_index
        and evidence.event_sha256 == expected.event_sha256
        and evidence.alternative_index == expected.alternative_index
        and evidence.target_sha256 == expected.target_sha256
        and evidence.identity == expected.identity
    )
    if not binding_matches:
        blocker = PrimaryBlockerV3(
            "violated",
            "external_site_evidence_binding_contradiction",
            dependency.input_name,
            dependency.record_id,
        )
    elif evidence.status != "complete":
        blocker = PrimaryBlockerV3(
            "violated" if evidence.status == "violated" else "incomplete",
            (
                evidence.primary_blocker.code
                if evidence.primary_blocker is not None
                else "external_site_evidence_incomplete"
            ),
            dependency.input_name,
            dependency.record_id,
        )
    else:
        assert evidence.contract is not None
        proposed = _contract_blocker(expected, evidence.contract)
        if proposed is not None:
            blocker = PrimaryBlockerV3(
                proposed.status,
                proposed.code,
                dependency.input_name,
                dependency.record_id,
            )
        else:
            profile_dependency = _profile_dependency(evidence.contract)
            profile_source = _record_or_none(
                context,
                profile_dependency.input_name,
                profile_dependency.record_id,
            )
            if profile_source is None:
                blocker = PrimaryBlockerV3(
                    "incomplete",
                    "external_profile_missing",
                    profile_dependency.input_name,
                    profile_dependency.record_id,
                )
            elif (
                manifest_blocker := manifest_blocker_v3(
                    context,
                    profile_dependency.input_name,
                    "external_profile_artifact_not_complete",
                    profile_dependency,
                )
            ) is not None:
                blocker = manifest_blocker
            else:
                profile = EXTERNAL_PROFILE_CODEC_V3.read(profile_source).value
                proposed = _profile_blocker(evidence.contract, profile)
                blocker = (
                    None
                    if proposed is None
                    else PrimaryBlockerV3(
                        proposed.status,
                        proposed.code,
                        profile_dependency.input_name,
                        profile_dependency.record_id,
                    )
                )
    complete = blocker is None
    exact_dependencies = [dependency]
    if evidence.contract is not None and binding_matches and evidence.status == "complete":
        exact_dependencies.append(_profile_dependency(evidence.contract))
    return (
        CanonicalExternalSiteV3(
            expected.site_id,
            expected.unit_id,
            expected.event_index,
            expected.alternative_index,
            expected.event_sha256,
            expected.target_sha256,
            expected.identity,
            "complete" if complete else blocker.status,
            complete,
            evidence.contract if complete else None,
            blocker,
        ),
        canonical_dependencies_v3(exact_dependencies),
    )


def _derive_external_record(
    context: PhaseContextV3, source: ArtifactRecordV3
) -> CanonicalExternalSiteRecordV3:
    exact = SEMANTIC_INDEX_CODEC_V3.read(source).value
    summary_source = context.record("transition_summaries", exact.record_id)
    summary = TRANSITION_SUMMARY_CODEC_V3.read(summary_source).value
    dependencies = [
        RecordDependencyV3("semantic_index", exact.record_id),
        RecordDependencyV3("transition_summaries", summary.record_id),
    ]
    blockers: list[PrimaryBlockerV3] = []
    for input_name, dependency, code in (
        (
            "semantic_index",
            dependencies[0],
            "semantic_index_artifact_not_complete",
        ),
        (
            "transition_summaries",
            dependencies[1],
            "transition_summary_artifact_not_complete",
        ),
    ):
        manifest_blocker = manifest_blocker_v3(
            context, input_name, code, dependency
        )
        if manifest_blocker is not None:
            blockers.append(manifest_blocker)
    if summary.unit_sha256 != exact.unit_sha256:
        blockers.append(
            PrimaryBlockerV3(
                "violated",
                "transition_summary_unit_contradiction",
                "transition_summaries",
                summary.record_id,
            )
        )
    elif summary.status != "complete":
        blockers.append(
            PrimaryBlockerV3(
                "incomplete",
                "transition_summary_incomplete",
                "transition_summaries",
                summary.record_id,
            )
        )
    expected, structural_blockers, structural_dependencies = _expected_sites(
        context, exact, summary
    )
    blockers.extend(structural_blockers)
    dependencies.extend(structural_dependencies)
    sites: list[CanonicalExternalSiteV3] = []
    for row in expected:
        site, site_dependencies = _checked_site(context, exact, row)
        sites.append(site)
        dependencies.extend(site_dependencies)
        if site.primary_blocker is not None:
            blockers.append(site.primary_blocker)
    primary = aggregate_blockers_v3(blockers)
    status = "complete" if primary is None else primary.status
    return CanonicalExternalSiteRecordV3(
        record_id=exact.record_id,
        unit_sha256=exact.unit_sha256,
        status=status,
        authorizing=status == "complete",
        sites=tuple(sorted(sites, key=lambda row: row.site_id)),
        primary_blocker=primary,
        dependencies=canonical_dependencies_v3(dependencies),
    )


def _transform_external_sites(
    context: PhaseContextV3, source: ArtifactRecordV3
) -> ArtifactRecordV3:
    value = _derive_external_record(context, source)
    return CANONICAL_EXTERNAL_SITE_CODEC_V3.write(
        source.record_id, value, dependencies=value.dependencies
    )


def check_canonical_external_sites_completeness_v3(
    reader: ArtifactSetReaderV3, context: PhaseContextV3
) -> None:
    exact_records = sorted_records(context.records("semantic_index"))
    outputs = sorted_records(reader.iter_records())
    require_record_ids(
        outputs,
        (row.record_id for row in exact_records),
        "canonical external-site inventories",
    )
    expected_evidence_ids: set[str] = set()
    for source, output in zip(exact_records, outputs, strict=True):
        expected = _derive_external_record(context, source)
        submitted = CANONICAL_EXTERNAL_SITE_CODEC_V3.read(output).value
        if submitted != expected:
            fail(
                "canonical_external_site_contradiction",
                f"external-site inventory {output.record_id!r} is stale",
                "rerun canonical external-site analysis from exact inputs",
            )
        if output.dependencies != expected.dependencies:
            fail(
                "incomplete_record_dependencies",
                f"external-site inventory {output.record_id!r} has stale dependencies",
                "let CANONICAL_EXTERNAL_SITES_PHASE_V3 attach exact dependencies",
            )
        expected_evidence_ids.update(site.site_id for site in expected.sites)
    evidence_records = sorted_records(context.records("external_site_evidence"))
    unknown = sorted({row.record_id for row in evidence_records} - expected_evidence_ids)
    if unknown:
        fail(
            "unknown_external_site_evidence",
            f"external-site evidence names absent exact sites {unknown!r}",
            "remove stale evidence or regenerate it from exact external events",
        )


CANONICAL_EXTERNAL_SITES_PHASE_V3 = map_units(
    name="canonical-external-sites-v3",
    version="2",
    source_input="semantic_index",
    input_artifact_kinds={
        "external_profiles": EXTERNAL_PROFILE_ARTIFACT_KIND_V3,
        "external_site_evidence": EXTERNAL_SITE_EVIDENCE_ARTIFACT_KIND_V3,
        "semantic_index": "semantic-index-v3",
        "structural_targets": "structural-target-proposals-v3",
        "transition_summaries": "transition-summaries-v3",
    },
    output_artifact_kind=CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
    transform=_transform_external_sites,
    completeness=check_canonical_external_sites_completeness_v3,
    unit_aligned_inputs=("structural_targets", "transition_summaries"),
)


__all__ = [
    "CANONICAL_EXTERNAL_SITE_CODEC_V3",
    "CANONICAL_EXTERNAL_SITE_RECORD_V3_SCHEMA",
    "CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3",
    "CANONICAL_EXTERNAL_SITES_PHASE_V3",
    "CanonicalExternalSiteRecordV3",
    "CanonicalExternalSiteV3",
    "CallbackRequirementV3",
    "EXTERNAL_SITE_EVIDENCE_CODEC_V3",
    "EXTERNAL_SITE_EVIDENCE_ARTIFACT_KIND_V3",
    "EXTERNAL_SITE_EVIDENCE_RECORD_V3_SCHEMA",
    "EXTERNAL_PROFILE_ARTIFACT_KIND_V3",
    "EXTERNAL_PROFILE_CODEC_V3",
    "EXTERNAL_PROFILE_RECORD_V3_SCHEMA",
    "ExternalContractV3",
    "ExternalProfileV3",
    "ExternalSiteEvidenceV3",
    "check_canonical_external_sites_completeness_v3",
    "external_site_id_v3",
]

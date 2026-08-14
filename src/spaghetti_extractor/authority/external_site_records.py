"""External-site wire schemas, immutable records, identities, and codecs."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from ..artifact_set_v3 import (
    CanonicalValueV3,
    RecordDependencyV3,
    canonical_sha256_v3,
)
from ..phase_framework_v3 import RecordCodecV3
from ._schema import (
    canonical_strings,
    digest,
    fail,
    mapping,
    require_stable_id,
    sequence,
    stable_id,
    strict_object,
    text,
    uint,
)
from .authority_common import (
    PrimaryBlockerV3,
    blocker_payload_v3,
    decode_dependencies_v3,
    encode_dependencies_v3,
    validate_authority_decision_v3,
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
    machine_contract: CanonicalValueV3

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
        mapping(self.machine_contract.to_value(), "external profile machine contract")
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
            "machine_contract": self.machine_contract.to_value(),
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
        machine_contract: Mapping[str, Any] | None = None,
    ) -> "ExternalProfileV3":
        canonical_identity = CanonicalValueV3.of(identity)
        transfers = tuple(sorted(set(allowed_transfers)))
        dispositions = tuple(sorted(set(allowed_dispositions)))
        canonical_machine_contract = CanonicalValueV3.of(
            machine_contract
            if machine_contract is not None
            else {
                "argument_words": argument_words,
                "disposition": (
                    dispositions[0] if len(dispositions) == 1 else list(dispositions)
                ),
                "memory_effect": memory_effect,
                "world_effect": world_effect,
                "callback_effect": callback_effect,
            }
        )
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
            canonical_machine_contract,
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
            "machine_contract",
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
        machine_contract=CanonicalValueV3.of(row["machine_contract"]),
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
    arguments: tuple[CanonicalValueV3, ...]
    memory_effect: str
    world_effect: str
    callback_effect: str
    machine_contract: CanonicalValueV3
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
        if len(self.arguments) != self.argument_words:
            fail(
                "external_argument_inventory_contradiction",
                "external argument expressions disagree with the ABI word count",
                "emit one exact expression per machine argument word",
            )
        text(self.memory_effect, "external memory effect")
        text(self.world_effect, "external world effect")
        if self.callback_effect not in {"none", "registers"}:
            fail(
                "record_schema_mismatch",
                f"external callback effect is {self.callback_effect!r}",
                "use none or registers",
            )
        mapping(self.machine_contract.to_value(), "external machine contract")
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
            "arguments": [row.to_value() for row in self.arguments],
            "memory_effect": self.memory_effect,
            "world_effect": self.world_effect,
            "callback_effect": self.callback_effect,
            "machine_contract": self.machine_contract.to_value(),
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
        arguments: Sequence[Mapping[str, Any]],
        memory_effect: str,
        world_effect: str,
        callback_effect: str,
        machine_contract: Mapping[str, Any] | None = None,
        callbacks: Sequence[CallbackRequirementV3] = (),
    ) -> "ExternalContractV3":
        canonical_identity = CanonicalValueV3.of(identity)
        ordered_callbacks = tuple(sorted(set(callbacks)))
        canonical_machine_contract = CanonicalValueV3.of(
            machine_contract
            if machine_contract is not None
            else {
                "argument_words": argument_words,
                "disposition": disposition,
                "memory_effect": memory_effect,
                "world_effect": world_effect,
                "callback_effect": callback_effect,
            }
        )
        canonical_arguments = tuple(CanonicalValueV3.of(row) for row in arguments)
        payload = {
            "identity": canonical_identity.to_value(),
            "transfer_kind": transfer_kind,
            "disposition": disposition,
            "profile_id": profile_id,
            "profile_sha256": profile_sha256,
            "argument_words": argument_words,
            "arguments": [row.to_value() for row in canonical_arguments],
            "memory_effect": memory_effect,
            "world_effect": world_effect,
            "callback_effect": callback_effect,
            "machine_contract": canonical_machine_contract.to_value(),
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
            canonical_arguments,
            memory_effect,
            world_effect,
            callback_effect,
            canonical_machine_contract,
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
                "arguments",
                "memory_effect",
                "world_effect",
                "callback_effect",
                "machine_contract",
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
            arguments=tuple(
                CanonicalValueV3.of(item)
                for item in sequence(row["arguments"], "external arguments")
            ),
            memory_effect=text(row["memory_effect"], "external memory effect"),
            world_effect=text(row["world_effect"], "external world effect"),
            callback_effect=text(row["callback_effect"], "external callback effect"),
            machine_contract=CanonicalValueV3.of(row["machine_contract"]),
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


__all__ = [
    "CANONICAL_EXTERNAL_SITE_CODEC_V3",
    "CANONICAL_EXTERNAL_SITE_RECORD_V3_SCHEMA",
    "CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3",
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
    "external_site_id_v3",
]

"""Strict, binary-bound PE32 launch assumptions for static hybrid authority.

The launch profile is deliberately conditional.  It records the exact loader
and process-state assumptions under which static closure is claimed; it does
not pretend to prove a complete Windows loader.  Exact PE roots are imported
from the independently checked behavioral-root artifact.  Runtime callback
roots are admitted only through an exact registration-event binding and a v2
entry-state contract reference.

Missing evidence produces ``incomplete``.  Contradictory bindings and corrupt
evidence produce ``violated``.  A canonical, complete profile exposes a
``launch_invariants`` mapping that can be passed directly to
``construct_entry_state_analysis_v2``.
"""

from __future__ import annotations

import copy
import hashlib
import re
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Mapping, Sequence

from .behavioral_roots import BEHAVIORAL_ROOTS_FORMAT, behavioral_roots_sha256
from .entry_state_analysis_v2 import (
    EntryStateAnalysisV2Error,
    parse_callback_entry_state_contracts_v2,
)
from .authority_bindings_v2 import (
    AuthorityDataError,
    CanonicalJson,
    EventBinding,
    canonical_json_bytes,
)


LAUNCH_PROFILE_V2_FORMAT = "spaghetti-extractor-pe32-launch-profile-v2"
PE32_LAUNCH_PROFILE_V2_FORMAT = LAUNCH_PROFILE_V2_FORMAT
LAUNCH_ASSUMPTION_TEMPLATE_V1_FORMAT = (
    "spaghetti-extractor-pe32-launch-assumption-template-v1"
)

_AUTHORITY = "conditional_exact_pe32_launch_profile_v2"
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_ENTRY_CONTRACT_RE = re.compile(
    r"hybrid-authority-v2:entry_state_contract:[0-9a-f]{64}\Z"
)
_REQUIRED_ASSUMPTIONS = (
    "initial_stack",
    "argv",
    "environment",
    "fs",
    "iat",
    "relocations",
)
_UNSUPPORTED_FEATURES = (
    "threads",
    "unmodelled_seh",
    "direct_syscalls",
    "executable_writes",
    "unknown_async_callbacks",
)
_STATIC_ROOT_KINDS = frozenset(
    {"pe_entrypoint", "pe_export", "pe_tls_callback"}
)
_ROOT_ORDER = {
    "pe_entrypoint": 0,
    "pe_export": 1,
    "pe_tls_callback": 2,
    "event_callback": 3,
}


class LaunchProfileV2Error(ValueError):
    """A launch-profile value is structurally malformed or noncanonical."""


class LaunchProfileStatus(str, Enum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    VIOLATED = "violated"


@dataclass(frozen=True)
class LaunchAssumptionTemplateV1:
    """Non-authorizing assumptions awaiting an exact PE/root binding."""

    assumptions: tuple[LaunchAssumption, ...]
    feature_inventory: tuple[tuple[str, tuple[CanonicalJson, ...]], ...]

    def __post_init__(self) -> None:
        if tuple(item.kind for item in self.assumptions) != _REQUIRED_ASSUMPTIONS:
            raise LaunchProfileV2Error(
                "launch template assumptions are incomplete or out of order"
            )
        if tuple(kind for kind, _items in self.feature_inventory) != _UNSUPPORTED_FEATURES:
            raise LaunchProfileV2Error(
                "launch template feature inventory is incomplete or out of order"
            )

    @property
    def assumption_map(self) -> dict[str, Any]:
        return {item.kind: item.value.to_value() for item in self.assumptions}

    @property
    def feature_map(self) -> dict[str, list[Any]]:
        return {
            kind: [item.to_value() for item in items]
            for kind, items in self.feature_inventory
        }

    def to_payload(self) -> dict[str, Any]:
        return {
            "format": LAUNCH_ASSUMPTION_TEMPLATE_V1_FORMAT,
            "schema_version": 1,
            "assumptions": self.assumption_map,
            "feature_inventory": self.feature_map,
        }


def parse_launch_assumption_template_v1(
    value: Any,
) -> LaunchAssumptionTemplateV1:
    """Strictly parse authored launch assumptions without granting authority."""

    row = _object(
        value,
        {"format", "schema_version", "assumptions", "feature_inventory"},
        "launch assumption template",
    )
    if (
        row["format"] != LAUNCH_ASSUMPTION_TEMPLATE_V1_FORMAT
        or row["schema_version"] != 1
    ):
        raise LaunchProfileV2Error("launch assumption template is unsupported")
    assumptions = _object(
        row["assumptions"], set(_REQUIRED_ASSUMPTIONS), "launch assumptions"
    )
    features = _object(
        row["feature_inventory"],
        set(_UNSUPPORTED_FEATURES),
        "launch feature inventory",
    )
    result = LaunchAssumptionTemplateV1(
        assumptions=tuple(
            LaunchAssumption.of(kind, assumptions[kind])
            for kind in _REQUIRED_ASSUMPTIONS
        ),
        feature_inventory=tuple(
            (
                kind,
                tuple(
                    CanonicalJson.of(item)
                    for item in _array(
                        features[kind], f"launch feature inventory {kind}"
                    )
                ),
            )
            for kind in _UNSUPPORTED_FEATURES
        ),
    )
    if result.to_payload() != _json_clone(row):
        raise LaunchProfileV2Error("launch assumption template is noncanonical")
    return result


@dataclass(frozen=True, order=True)
class PE32LaunchBinding:
    pe_sha256: str
    image_base: int
    size_of_image: int

    def __post_init__(self) -> None:
        _digest(self.pe_sha256, "PE SHA-256")
        _uint32(self.image_base, "PE image base")
        _positive_uint32(self.size_of_image, "PE image size")
        if self.image_base + self.size_of_image > 1 << 32:
            raise LaunchProfileV2Error("PE image exceeds the PE32 address space")

    def to_payload(self) -> dict[str, Any]:
        return {
            "pe_sha256": self.pe_sha256,
            "machine": "i386",
            "bitness": 32,
            "image_base": self.image_base,
            "size_of_image": self.size_of_image,
        }

    @classmethod
    def parse(cls, value: Any) -> "PE32LaunchBinding":
        row = _object(
            value,
            {"pe_sha256", "machine", "bitness", "image_base", "size_of_image"},
            "PE32 launch binding",
        )
        if row["machine"] != "i386" or row["bitness"] != 32:
            raise LaunchProfileV2Error("launch binding is not PE32 i386")
        return cls(
            pe_sha256=_digest(row["pe_sha256"], "PE SHA-256"),
            image_base=_uint32(row["image_base"], "PE image base"),
            size_of_image=_positive_uint32(
                row["size_of_image"], "PE image size"
            ),
        )


@dataclass(frozen=True, order=True)
class LaunchAssumption:
    kind: str
    value: CanonicalJson

    def __post_init__(self) -> None:
        if self.kind not in _REQUIRED_ASSUMPTIONS:
            raise LaunchProfileV2Error("launch assumption kind is unsupported")
        if not isinstance(self.value, CanonicalJson):
            raise LaunchProfileV2Error("launch assumption value is not immutable JSON")
        if not isinstance(self.value.to_value(), dict) or not self.value.to_value():
            raise LaunchProfileV2Error(
                "launch assumption value must be a nonempty object"
            )

    def to_payload(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "source": "explicit_profile_assumption",
            "value": self.value.to_value(),
        }

    @classmethod
    def of(cls, kind: str, value: Any) -> "LaunchAssumption":
        return cls(kind=kind, value=CanonicalJson.of(value))

    @classmethod
    def parse(cls, value: Any) -> "LaunchAssumption":
        row = _object(value, {"kind", "source", "value"}, "launch assumption")
        if row["source"] != "explicit_profile_assumption":
            raise LaunchProfileV2Error("launch assumption source is not explicit")
        return cls.of(_text(row["kind"], "launch assumption kind"), row["value"])


@dataclass(frozen=True, order=True)
class StaticLaunchRoot:
    kind: str
    identity: str
    rva: int
    metadata: CanonicalJson

    def __post_init__(self) -> None:
        if self.kind not in _STATIC_ROOT_KINDS:
            raise LaunchProfileV2Error("static launch-root kind is unsupported")
        _text(self.identity, "static launch-root identity")
        _positive_uint32(self.rva, "static launch-root RVA")
        if not isinstance(self.metadata, CanonicalJson):
            raise LaunchProfileV2Error("static launch-root metadata is malformed")

    def to_payload(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "identity": self.identity,
            "rva": self.rva,
            "metadata": self.metadata.to_value(),
        }

    @classmethod
    def parse(cls, value: Any) -> "StaticLaunchRoot":
        row = _object(
            value, {"kind", "identity", "rva", "metadata"}, "static launch root"
        )
        return cls(
            kind=_text(row["kind"], "static launch-root kind"),
            identity=_text(row["identity"], "static launch-root identity"),
            rva=_positive_uint32(row["rva"], "static launch-root RVA"),
            metadata=CanonicalJson.of(row["metadata"]),
        )


@dataclass(frozen=True, order=True)
class CallbackLaunchRoot:
    identity: str
    rva: int
    registration_event: EventBinding
    entry_contract_content_id: str

    def __post_init__(self) -> None:
        _text(self.identity, "callback launch-root identity")
        _positive_uint32(self.rva, "callback launch-root RVA")
        if not isinstance(self.registration_event, EventBinding):
            raise LaunchProfileV2Error(
                "callback launch root requires an exact registration event"
            )
        if _ENTRY_CONTRACT_RE.fullmatch(self.entry_contract_content_id) is None:
            raise LaunchProfileV2Error(
                "callback launch root requires a v2 entry-state contract reference"
            )

    def to_payload(self) -> dict[str, Any]:
        return {
            "kind": "event_callback",
            "identity": self.identity,
            "rva": self.rva,
            "registration_event": self.registration_event.to_payload(),
            "entry_contract_content_id": self.entry_contract_content_id,
        }

    @classmethod
    def parse(cls, value: Any) -> "CallbackLaunchRoot":
        row = _object(
            value,
            {
                "kind",
                "identity",
                "rva",
                "registration_event",
                "entry_contract_content_id",
            },
            "callback launch root",
        )
        if row["kind"] != "event_callback":
            raise LaunchProfileV2Error("callback launch-root kind is invalid")
        try:
            event = EventBinding.parse(row["registration_event"])
        except AuthorityDataError as exc:
            raise LaunchProfileV2Error(
                f"callback registration event is malformed: {exc}"
            ) from exc
        return cls(
            identity=_text(row["identity"], "callback launch-root identity"),
            rva=_positive_uint32(row["rva"], "callback launch-root RVA"),
            registration_event=event,
            entry_contract_content_id=_text(
                row["entry_contract_content_id"],
                "callback entry-contract content ID",
            ),
        )


@dataclass(frozen=True, order=True)
class LaunchProfileIssue:
    status: LaunchProfileStatus
    code: str
    subject: str
    detail: str

    def __post_init__(self) -> None:
        if self.status is LaunchProfileStatus.COMPLETE:
            raise LaunchProfileV2Error("a launch-profile issue cannot be complete")
        _token(self.code, "launch-profile issue code")
        _text(self.subject, "launch-profile issue subject")
        _text(self.detail, "launch-profile issue detail")

    def to_payload(self) -> dict[str, str]:
        return {
            "status": self.status.value,
            "code": self.code,
            "subject": self.subject,
            "detail": self.detail,
        }

    @classmethod
    def parse(cls, value: Any) -> "LaunchProfileIssue":
        row = _object(
            value, {"status", "code", "subject", "detail"}, "launch-profile issue"
        )
        try:
            status = LaunchProfileStatus(row["status"])
        except (TypeError, ValueError) as exc:
            raise LaunchProfileV2Error("launch-profile issue status is invalid") from exc
        return cls(
            status=status,
            code=_token(row["code"], "launch-profile issue code"),
            subject=_text(row["subject"], "launch-profile issue subject"),
            detail=_text(row["detail"], "launch-profile issue detail"),
        )


@dataclass(frozen=True)
class PE32LaunchProfileV2:
    binary: PE32LaunchBinding
    behavioral_roots_sha256: str | None
    static_roots: tuple[StaticLaunchRoot, ...]
    callback_roots: tuple[CallbackLaunchRoot, ...]
    assumptions: tuple[LaunchAssumption, ...]
    feature_inventory: tuple[tuple[str, tuple[CanonicalJson, ...]], ...]
    issues: tuple[LaunchProfileIssue, ...]
    profile_sha256: str
    content_sha256: str
    format: str = LAUNCH_PROFILE_V2_FORMAT

    @property
    def status(self) -> LaunchProfileStatus:
        return _status(self.issues)

    @property
    def usable(self) -> bool:
        return self.status is LaunchProfileStatus.COMPLETE

    @property
    def launch_invariants(self) -> dict[str, list[dict[str, Any]]]:
        return _launch_invariants(self)

    def to_payload(self) -> dict[str, Any]:
        core = _artifact_core(self)
        return {**core, "content_sha256": self.content_sha256}


@dataclass(frozen=True)
class LaunchProfileV2Check:
    status: LaunchProfileStatus
    profile: PE32LaunchProfileV2 | None
    issues: tuple[LaunchProfileIssue, ...]

    @property
    def usable(self) -> bool:
        return self.status is LaunchProfileStatus.COMPLETE and self.profile is not None

    def to_payload(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "usable": self.usable,
            "profile_sha256": (
                None if self.profile is None else self.profile.profile_sha256
            ),
            "issues": [issue.to_payload() for issue in self.issues],
        }


def build_launch_profile_v2(
    *,
    pe_sha256: str,
    image_base: int,
    size_of_image: int,
    behavioral_roots: Mapping[str, Any] | None,
    assumptions: Mapping[str, Any] | None,
    callback_roots: Sequence[Mapping[str, Any]] | None,
    feature_inventory: Mapping[str, Sequence[Mapping[str, Any]]] | None,
) -> PE32LaunchProfileV2:
    """Build one conditional launch profile for an exact PE32 image."""

    return _build_launch_profile_v2(
        pe_sha256=pe_sha256,
        image_base=image_base,
        size_of_image=size_of_image,
        behavioral_roots=behavioral_roots,
        assumptions=assumptions,
        callback_roots=callback_roots,
        feature_inventory=feature_inventory,
        additional_issues=(
            _issue(
                LaunchProfileStatus.INCOMPLETE,
                "callback_entry_state_unchecked",
                "callback_roots",
                "raw callback roots are diagnostic-only; finalize from checked callback contracts",
            ),
        ),
    )


def finalize_launch_profile_v2(
    *,
    pe_sha256: str,
    image_base: int,
    size_of_image: int,
    behavioral_roots: Mapping[str, Any] | None,
    assumptions: Mapping[str, Any] | None,
    callback_entry_state: Mapping[str, Any] | None,
    feature_inventory: Mapping[str, Sequence[Mapping[str, Any]]] | None,
) -> PE32LaunchProfileV2:
    """Finalize event roots from independently checked callback contracts."""

    issues: list[LaunchProfileIssue] = []
    callback_roots: Sequence[Mapping[str, Any]] = ()
    if callback_entry_state is None:
        issues.append(_issue(
            LaunchProfileStatus.INCOMPLETE,
            "callback_entry_state_missing",
            "callback_entry_state",
            "checked callback entry-state contracts are missing",
        ))
    else:
        try:
            callback = parse_callback_entry_state_contracts_v2(
                callback_entry_state
            )
        except (EntryStateAnalysisV2Error, TypeError, ValueError) as exc:
            issues.append(_issue(
                LaunchProfileStatus.VIOLATED,
                "callback_entry_state_corrupt",
                "callback_entry_state",
                str(exc),
            ))
        else:
            binary = callback["binary"]
            expected = {
                "pe_sha256": pe_sha256,
                "image_base": image_base,
                "size_of_image": size_of_image,
            }
            if {field: binary[field] for field in expected} != expected:
                issues.append(_issue(
                    LaunchProfileStatus.VIOLATED,
                    "callback_entry_state_binary_mismatch",
                    "callback_entry_state",
                    "callback contracts bind a different PE32 image",
                ))
            callback_status = callback["status"]
            if callback_status == "incomplete":
                issues.append(_issue(
                    LaunchProfileStatus.INCOMPLETE,
                    "callback_entry_state_incomplete",
                    "callback_entry_state",
                    "callback entry-state evidence is incomplete",
                ))
            elif callback_status == "violated":
                issues.append(_issue(
                    LaunchProfileStatus.VIOLATED,
                    "callback_entry_state_violated",
                    "callback_entry_state",
                    "callback entry-state evidence is contradictory",
                ))
            callback_roots = callback["callback_roots"]

    return _build_launch_profile_v2(
        pe_sha256=pe_sha256,
        image_base=image_base,
        size_of_image=size_of_image,
        behavioral_roots=behavioral_roots,
        assumptions=assumptions,
        callback_roots=callback_roots,
        feature_inventory=feature_inventory,
        additional_issues=issues,
    )


def _build_launch_profile_v2(
    *,
    pe_sha256: str,
    image_base: int,
    size_of_image: int,
    behavioral_roots: Mapping[str, Any] | None,
    assumptions: Mapping[str, Any] | None,
    callback_roots: Sequence[Mapping[str, Any]] | None,
    feature_inventory: Mapping[str, Sequence[Mapping[str, Any]]] | None,
    additional_issues: Sequence[LaunchProfileIssue],
) -> PE32LaunchProfileV2:
    """Assemble and hash a canonical launch profile."""

    binary = PE32LaunchBinding(pe_sha256, image_base, size_of_image)
    issues: list[LaunchProfileIssue] = list(additional_issues)
    root_digest, static_roots = _checked_behavioral_roots(
        behavioral_roots, binary=binary, issues=issues
    )
    normalized_assumptions = _checked_assumptions(assumptions, issues=issues)
    callbacks = _checked_callback_roots(
        callback_roots, binary=binary, issues=issues
    )
    features = _checked_feature_inventory(feature_inventory, issues=issues)
    ordered_issues = tuple(sorted(set(issues), key=_issue_key))
    provisional = PE32LaunchProfileV2(
        binary=binary,
        behavioral_roots_sha256=root_digest,
        static_roots=static_roots,
        callback_roots=callbacks,
        assumptions=normalized_assumptions,
        feature_inventory=features,
        issues=ordered_issues,
        profile_sha256="0" * 64,
        content_sha256="0" * 64,
    )
    profile_sha = hashlib.sha256(
        canonical_json_bytes(_profile_identity_core(provisional))
    ).hexdigest()
    with_profile = replace(provisional, profile_sha256=profile_sha)
    content_sha = hashlib.sha256(
        canonical_json_bytes(_artifact_core(with_profile))
    ).hexdigest()
    result = replace(with_profile, content_sha256=content_sha)
    return parse_launch_profile_v2(result.to_payload())


def parse_launch_profile_v2(value: Any) -> PE32LaunchProfileV2:
    """Strictly parse and replay one canonical launch-profile artifact."""

    row = _object(
        value,
        {
            "format",
            "schema_version",
            "authority",
            "status",
            "usable",
            "binary",
            "behavioral_roots_sha256",
            "static_roots",
            "callback_roots",
            "assumptions",
            "feature_inventory",
            "issues",
            "profile_sha256",
            "launch_invariants",
            "counts",
            "content_sha256",
        },
        "PE32 launch profile",
    )
    if (
        row["format"] != LAUNCH_PROFILE_V2_FORMAT
        or row["schema_version"] != 2
        or row["authority"] != _AUTHORITY
    ):
        raise LaunchProfileV2Error("unsupported PE32 launch-profile authority")
    binary = PE32LaunchBinding.parse(row["binary"])
    roots_digest = row["behavioral_roots_sha256"]
    if roots_digest is not None:
        roots_digest = _digest(roots_digest, "behavioral-roots SHA-256")
    static_roots = tuple(
        StaticLaunchRoot.parse(item)
        for item in _array(row["static_roots"], "static launch-root inventory")
    )
    callback_roots = tuple(
        CallbackLaunchRoot.parse(item)
        for item in _array(row["callback_roots"], "callback launch-root inventory")
    )
    assumptions = tuple(
        LaunchAssumption.parse(item)
        for item in _array(row["assumptions"], "launch assumption inventory")
    )
    feature_rows = _object(
        row["feature_inventory"], set(_UNSUPPORTED_FEATURES), "feature inventory"
    )
    features = tuple(
        (
            kind,
            tuple(
                CanonicalJson.of(item)
                for item in _array(feature_rows[kind], f"feature inventory {kind}")
            ),
        )
        for kind in _UNSUPPORTED_FEATURES
    )
    issues = tuple(
        LaunchProfileIssue.parse(item)
        for item in _array(row["issues"], "launch-profile issues")
    )
    result = PE32LaunchProfileV2(
        binary=binary,
        behavioral_roots_sha256=roots_digest,
        static_roots=static_roots,
        callback_roots=callback_roots,
        assumptions=assumptions,
        feature_inventory=features,
        issues=issues,
        profile_sha256=_digest(row["profile_sha256"], "launch profile SHA-256"),
        content_sha256=_digest(row["content_sha256"], "launch content SHA-256"),
    )
    expected_profile_sha = hashlib.sha256(
        canonical_json_bytes(_profile_identity_core(result))
    ).hexdigest()
    if result.profile_sha256 != expected_profile_sha:
        raise LaunchProfileV2Error("launch profile identity hash is stale")
    expected_content_sha = hashlib.sha256(
        canonical_json_bytes(_artifact_core(result))
    ).hexdigest()
    if result.content_sha256 != expected_content_sha:
        raise LaunchProfileV2Error("launch profile content hash is stale")
    if result.to_payload() != _json_clone(row):
        raise LaunchProfileV2Error(
            "launch profile status, ordering, counts, or derived invariants are stale"
        )
    return result


def validate_launch_profile_v2(
    value: Any,
    *,
    pe_sha256: str | None = None,
    image_base: int | None = None,
    size_of_image: int | None = None,
    behavioral_roots: Mapping[str, Any] | None = None,
    callback_entry_state: Mapping[str, Any] | None = None,
) -> LaunchProfileV2Check:
    """Validate an artifact and optional independently supplied exact inputs."""

    try:
        profile = parse_launch_profile_v2(value)
    except (AuthorityDataError, LaunchProfileV2Error, TypeError, ValueError) as exc:
        issue = _issue(
            LaunchProfileStatus.VIOLATED,
            "launch_profile_corrupt",
            "launch_profile",
            str(exc),
        )
        return LaunchProfileV2Check(
            status=LaunchProfileStatus.VIOLATED,
            profile=None,
            issues=(issue,),
        )

    validation_issues = list(profile.issues)
    expected_values = {
        "pe_sha256": pe_sha256,
        "image_base": image_base,
        "size_of_image": size_of_image,
    }
    observed_values = {
        "pe_sha256": profile.binary.pe_sha256,
        "image_base": profile.binary.image_base,
        "size_of_image": profile.binary.size_of_image,
    }
    for field, expected in expected_values.items():
        if expected is not None and observed_values[field] != expected:
            validation_issues.append(_issue(
                LaunchProfileStatus.VIOLATED,
                "exact_pe_binding_mismatch",
                field,
                f"expected {expected!r}, observed {observed_values[field]!r}",
            ))
    if behavioral_roots is not None:
        try:
            observed_digest = behavioral_roots_sha256(behavioral_roots)
        except (TypeError, ValueError) as exc:
            validation_issues.append(_issue(
                LaunchProfileStatus.VIOLATED,
                "behavioral_roots_corrupt",
                "behavioral_roots",
                str(exc),
            ))
        else:
            if profile.behavioral_roots_sha256 != observed_digest:
                validation_issues.append(_issue(
                    LaunchProfileStatus.VIOLATED,
                    "behavioral_roots_binding_mismatch",
                    "behavioral_roots",
                    "the supplied behavioral-root artifact does not match the profile",
                ))
    if callback_entry_state is not None:
        try:
            callback = parse_callback_entry_state_contracts_v2(
                callback_entry_state
            )
        except (EntryStateAnalysisV2Error, TypeError, ValueError) as exc:
            validation_issues.append(_issue(
                LaunchProfileStatus.VIOLATED,
                "callback_entry_state_corrupt",
                "callback_entry_state",
                str(exc),
            ))
        else:
            callback_binary = callback["binary"]
            callback_roots = [
                CallbackLaunchRoot.parse({
                    "kind": "event_callback",
                    "identity": (
                        f"event-callback:rva:{row['rva']}:source:"
                        f"{row['registration_event']['unit']['unit_id']}:"
                        f"{row['registration_event']['event_index']}"
                    ),
                    **row,
                })
                for row in callback["callback_roots"]
            ]
            if (
                callback_binary["pe_sha256"] != profile.binary.pe_sha256
                or callback_binary["image_base"] != profile.binary.image_base
                or callback_binary["size_of_image"] != profile.binary.size_of_image
                or tuple(sorted(callback_roots, key=_root_key))
                != profile.callback_roots
            ):
                validation_issues.append(_issue(
                    LaunchProfileStatus.VIOLATED,
                    "callback_entry_state_binding_mismatch",
                    "callback_entry_state",
                    "the supplied callback-entry artifact does not match the profile",
                ))
    ordered = tuple(sorted(set(validation_issues), key=_issue_key))
    return LaunchProfileV2Check(
        status=_status(ordered), profile=profile, issues=ordered
    )


def launch_invariants_for_entry_state(
    profile: PE32LaunchProfileV2 | Mapping[str, Any],
) -> dict[str, list[dict[str, Any]]]:
    """Return detached explicit invariants accepted by entry-state analysis v2."""

    parsed = (
        profile
        if isinstance(profile, PE32LaunchProfileV2)
        else parse_launch_profile_v2(profile)
    )
    return copy.deepcopy(parsed.launch_invariants)


def _checked_behavioral_roots(
    value: Mapping[str, Any] | None,
    *,
    binary: PE32LaunchBinding,
    issues: list[LaunchProfileIssue],
) -> tuple[str | None, tuple[StaticLaunchRoot, ...]]:
    if value is None:
        issues.append(_issue(
            LaunchProfileStatus.INCOMPLETE,
            "behavioral_roots_missing",
            "behavioral_roots",
            "exact PE entry, export, and TLS roots are missing",
        ))
        return None, ()
    if not isinstance(value, Mapping):
        issues.append(_issue(
            LaunchProfileStatus.VIOLATED,
            "behavioral_roots_corrupt",
            "behavioral_roots",
            "behavioral roots must be an object",
        ))
        return None, ()
    try:
        digest = behavioral_roots_sha256(value)
        supplied_digest = _digest(
            value.get("contract_sha256"), "behavioral-roots contract SHA-256"
        )
        if digest != supplied_digest:
            raise LaunchProfileV2Error("behavioral-roots self-hash is stale")
        if value.get("format") != BEHAVIORAL_ROOTS_FORMAT:
            raise LaunchProfileV2Error("behavioral-roots format is unsupported")
        if value.get("status") != "complete":
            raise LaunchProfileV2Error("behavioral-root extraction is not complete")
        pe = _mapping(value.get("pe"), "behavioral-roots PE binding")
        observed_binding = (
            _digest(pe.get("sha256"), "behavioral-roots PE SHA-256"),
            _uint32(pe.get("image_base"), "behavioral-roots image base"),
            _positive_uint32(
                pe.get("size_of_image"), "behavioral-roots image size"
            ),
        )
        expected_binding = (
            binary.pe_sha256,
            binary.image_base,
            binary.size_of_image,
        )
        if pe.get("machine") != "i386" or pe.get("bitness") != 32:
            raise LaunchProfileV2Error("behavioral roots do not describe PE32 i386")
        if observed_binding != expected_binding:
            raise LaunchProfileV2Error(
                "behavioral roots contradict the exact PE32 launch binding"
            )
        raw_roots = _array(value.get("roots"), "behavioral-root inventory")
        roots = tuple(sorted(
            (_static_root(item, size_of_image=binary.size_of_image) for item in raw_roots),
            key=_root_key,
        ))
        if len({root.identity for root in roots}) != len(roots):
            raise LaunchProfileV2Error("behavioral roots repeat an identity")
        entrypoint_rva = _uint32(
            pe.get("entrypoint_rva"), "behavioral-roots entrypoint RVA"
        )
        entries = [root for root in roots if root.kind == "pe_entrypoint"]
        if entrypoint_rva == 0 and entries:
            raise LaunchProfileV2Error("zero PE entrypoint has a submitted root")
        if entrypoint_rva != 0 and (
            len(entries) != 1 or entries[0].rva != entrypoint_rva
        ):
            raise LaunchProfileV2Error("PE entrypoint root contradicts PE metadata")
        return digest, roots
    except (AuthorityDataError, LaunchProfileV2Error, TypeError, ValueError) as exc:
        issues.append(_issue(
            LaunchProfileStatus.VIOLATED,
            "behavioral_roots_corrupt",
            "behavioral_roots",
            str(exc),
        ))
        return None, ()


def _static_root(value: Any, *, size_of_image: int) -> StaticLaunchRoot:
    row = _mapping(value, "behavioral root")
    kind = _text(row.get("kind"), "behavioral-root kind")
    identity = _text(row.get("identity"), "behavioral-root identity")
    rva = _positive_uint32(row.get("rva"), "behavioral-root RVA")
    if kind not in _STATIC_ROOT_KINDS:
        raise LaunchProfileV2Error("behavioral-root kind is unsupported")
    if rva >= size_of_image:
        raise LaunchProfileV2Error("behavioral root is outside the PE image")
    expected_fields = {"kind", "identity", "rva"}
    metadata: dict[str, Any] = {}
    if kind == "pe_entrypoint":
        if identity != "pe-entrypoint":
            raise LaunchProfileV2Error("PE entrypoint identity is inconsistent")
    elif kind == "pe_export":
        expected_fields.update({"ordinal", "name"})
        ordinal = _uint32(row.get("ordinal"), "PE export ordinal")
        name = row.get("name")
        if name is not None:
            name = _text(name, "PE export name")
        expected_identity = (
            f"pe-export:ordinal:{ordinal}:name:"
            f"{name if name is not None else '<ordinal-only>'}"
        )
        if identity != expected_identity:
            raise LaunchProfileV2Error("PE export identity is inconsistent")
        metadata = {"ordinal": ordinal, "name": name}
    else:
        expected_fields.add("callback_index")
        index = _uint32(row.get("callback_index"), "PE TLS callback index")
        if identity != f"pe-tls-callback:index:{index}":
            raise LaunchProfileV2Error("PE TLS callback identity is inconsistent")
        metadata = {"callback_index": index}
    if set(row) != expected_fields:
        raise LaunchProfileV2Error("behavioral root has noncanonical fields")
    return StaticLaunchRoot(kind, identity, rva, CanonicalJson.of(metadata))


def _checked_assumptions(
    value: Mapping[str, Any] | None,
    *,
    issues: list[LaunchProfileIssue],
) -> tuple[LaunchAssumption, ...]:
    if value is None:
        for kind in _REQUIRED_ASSUMPTIONS:
            issues.append(_issue(
                LaunchProfileStatus.INCOMPLETE,
                "launch_assumption_missing",
                kind,
                f"explicit {kind} launch assumption is missing",
            ))
        return ()
    if not isinstance(value, Mapping):
        issues.append(_issue(
            LaunchProfileStatus.VIOLATED,
            "launch_assumption_inventory_corrupt",
            "assumptions",
            "launch assumptions must be an object",
        ))
        return ()
    extras = sorted(set(value) - set(_REQUIRED_ASSUMPTIONS))
    if extras:
        issues.append(_issue(
            LaunchProfileStatus.VIOLATED,
            "launch_assumption_unknown",
            "assumptions",
            f"unsupported launch assumptions: {extras}",
        ))
    result: list[LaunchAssumption] = []
    for kind in _REQUIRED_ASSUMPTIONS:
        if kind not in value or value[kind] is None:
            issues.append(_issue(
                LaunchProfileStatus.INCOMPLETE,
                "launch_assumption_missing",
                kind,
                f"explicit {kind} launch assumption is missing",
            ))
            continue
        try:
            result.append(LaunchAssumption.of(kind, value[kind]))
        except (AuthorityDataError, LaunchProfileV2Error, TypeError, ValueError) as exc:
            issues.append(_issue(
                LaunchProfileStatus.VIOLATED,
                "launch_assumption_corrupt",
                kind,
                str(exc),
            ))
    return tuple(sorted(result))


def _checked_callback_roots(
    value: Sequence[Mapping[str, Any]] | None,
    *,
    binary: PE32LaunchBinding,
    issues: list[LaunchProfileIssue],
) -> tuple[CallbackLaunchRoot, ...]:
    if value is None:
        issues.append(_issue(
            LaunchProfileStatus.INCOMPLETE,
            "callback_root_inventory_missing",
            "callback_roots",
            "event-derived callback-root inventory is missing",
        ))
        return ()
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        issues.append(_issue(
            LaunchProfileStatus.VIOLATED,
            "callback_root_inventory_corrupt",
            "callback_roots",
            "callback-root inventory must be an array",
        ))
        return ()
    result: list[CallbackLaunchRoot] = []
    for index, item in enumerate(value):
        try:
            row = _object(
                item,
                {"rva", "registration_event", "entry_contract_content_id"},
                f"callback root {index}",
            )
            rva = _positive_uint32(row["rva"], f"callback root {index} RVA")
            if rva >= binary.size_of_image:
                raise LaunchProfileV2Error("callback target is outside the PE image")
            event = EventBinding.parse(row["registration_event"])
            if event.unit.binary.pe_sha256 != binary.pe_sha256:
                raise LaunchProfileV2Error(
                    "callback registration event binds a different PE"
                )
            entry_id = _text(
                row["entry_contract_content_id"],
                f"callback root {index} entry contract",
            )
            identity = (
                f"event-callback:rva:{rva}:source:"
                f"{event.unit.unit_id}:{event.event_index}"
            )
            result.append(CallbackLaunchRoot(identity, rva, event, entry_id))
        except (AuthorityDataError, LaunchProfileV2Error, TypeError, ValueError) as exc:
            issues.append(_issue(
                LaunchProfileStatus.VIOLATED,
                "callback_root_corrupt",
                f"callback_roots[{index}]",
                str(exc),
            ))
    ordered = tuple(sorted(result, key=_root_key))
    identities = [row.identity for row in ordered]
    if len(set(identities)) != len(identities):
        issues.append(_issue(
            LaunchProfileStatus.VIOLATED,
            "callback_root_duplicated",
            "callback_roots",
            "callback-root inventory repeats an exact registration binding",
        ))
        return ()
    return ordered


def _checked_feature_inventory(
    value: Mapping[str, Sequence[Mapping[str, Any]]] | None,
    *,
    issues: list[LaunchProfileIssue],
) -> tuple[tuple[str, tuple[CanonicalJson, ...]], ...]:
    if value is None:
        for kind in _UNSUPPORTED_FEATURES:
            issues.append(_issue(
                LaunchProfileStatus.INCOMPLETE,
                "feature_inventory_missing",
                kind,
                f"reachable {kind} inventory is missing",
            ))
        return tuple((kind, ()) for kind in _UNSUPPORTED_FEATURES)
    if not isinstance(value, Mapping):
        issues.append(_issue(
            LaunchProfileStatus.VIOLATED,
            "feature_inventory_corrupt",
            "feature_inventory",
            "unsupported-feature inventory must be an object",
        ))
        return tuple((kind, ()) for kind in _UNSUPPORTED_FEATURES)
    extras = sorted(set(value) - set(_UNSUPPORTED_FEATURES))
    if extras:
        issues.append(_issue(
            LaunchProfileStatus.VIOLATED,
            "feature_inventory_unknown",
            "feature_inventory",
            f"unsupported feature categories: {extras}",
        ))
    result: list[tuple[str, tuple[CanonicalJson, ...]]] = []
    for kind in _UNSUPPORTED_FEATURES:
        if kind not in value:
            issues.append(_issue(
                LaunchProfileStatus.INCOMPLETE,
                "feature_inventory_missing",
                kind,
                f"reachable {kind} inventory is missing",
            ))
            result.append((kind, ()))
            continue
        raw_sites = value[kind]
        if not isinstance(raw_sites, Sequence) or isinstance(raw_sites, (str, bytes)):
            issues.append(_issue(
                LaunchProfileStatus.VIOLATED,
                "feature_inventory_corrupt",
                kind,
                f"reachable {kind} inventory must be an array",
            ))
            result.append((kind, ()))
            continue
        sites: list[CanonicalJson] = []
        for index, site in enumerate(raw_sites):
            try:
                frozen = CanonicalJson.of(site)
                if not isinstance(frozen.to_value(), dict) or not frozen.to_value():
                    raise LaunchProfileV2Error("feature site must be a nonempty object")
                sites.append(frozen)
            except (AuthorityDataError, LaunchProfileV2Error, TypeError, ValueError) as exc:
                issues.append(_issue(
                    LaunchProfileStatus.VIOLATED,
                    "feature_site_corrupt",
                    f"{kind}[{index}]",
                    str(exc),
                ))
        unique_sites = tuple(sorted(set(sites)))
        if len(unique_sites) != len(sites):
            issues.append(_issue(
                LaunchProfileStatus.VIOLATED,
                "feature_site_duplicated",
                kind,
                f"reachable {kind} inventory repeats a site",
            ))
        if unique_sites:
            issues.append(_issue(
                LaunchProfileStatus.INCOMPLETE,
                f"unsupported_{kind}",
                kind,
                f"{len(unique_sites)} reachable {kind} site(s) require a richer profile",
            ))
        result.append((kind, unique_sites))
    return tuple(result)


def _launch_invariants(profile: PE32LaunchProfileV2) -> dict[str, list[dict[str, Any]]]:
    assumptions = {row.kind: row.value.to_value() for row in profile.assumptions}
    result: dict[str, list[dict[str, Any]]] = {}
    for root in profile.static_roots:
        common = {
            "profile_sha256": profile.profile_sha256,
            "pe_sha256": profile.binary.pe_sha256,
            "image_base": profile.binary.image_base,
            "size_of_image": profile.binary.size_of_image,
            "root": root.to_payload(),
        }
        result[root.identity] = [
            {
                "kind": f"pe32_{kind}",
                "value": {**common, "assumption": copy.deepcopy(value)},
                "source": "explicit",
            }
            for kind, value in sorted(assumptions.items())
        ]
    for root in profile.callback_roots:
        result[root.identity] = [{
            "kind": "pe32_event_callback_entry",
            "value": {
                "profile_sha256": profile.profile_sha256,
                "pe_sha256": profile.binary.pe_sha256,
                "root": root.to_payload(),
                "entry_contract_content_id": root.entry_contract_content_id,
            },
            "source": "explicit",
        }]
    return {identity: result[identity] for identity in sorted(result)}


def _profile_identity_core(profile: PE32LaunchProfileV2) -> dict[str, Any]:
    return {
        "format": profile.format,
        "schema_version": 2,
        "authority": _AUTHORITY,
        "binary": profile.binary.to_payload(),
        "behavioral_roots_sha256": profile.behavioral_roots_sha256,
        "static_roots": [root.to_payload() for root in profile.static_roots],
        "callback_roots": [root.to_payload() for root in profile.callback_roots],
        "assumptions": [row.to_payload() for row in profile.assumptions],
        "feature_inventory": {
            kind: [site.to_value() for site in sites]
            for kind, sites in profile.feature_inventory
        },
        "issues": [issue.to_payload() for issue in profile.issues],
    }


def _artifact_core(profile: PE32LaunchProfileV2) -> dict[str, Any]:
    counts = {
        "static_roots": len(profile.static_roots),
        "callback_roots": len(profile.callback_roots),
        "assumptions": len(profile.assumptions),
        "frontiers": sum(len(sites) for _, sites in profile.feature_inventory),
        "issues": len(profile.issues),
    }
    return {
        **_profile_identity_core(profile),
        "status": profile.status.value,
        "usable": profile.usable,
        "profile_sha256": profile.profile_sha256,
        "launch_invariants": profile.launch_invariants,
        "counts": counts,
    }


def _status(issues: Sequence[LaunchProfileIssue]) -> LaunchProfileStatus:
    statuses = {issue.status for issue in issues}
    if LaunchProfileStatus.VIOLATED in statuses:
        return LaunchProfileStatus.VIOLATED
    if LaunchProfileStatus.INCOMPLETE in statuses:
        return LaunchProfileStatus.INCOMPLETE
    return LaunchProfileStatus.COMPLETE


def _issue(
    status: LaunchProfileStatus,
    code: str,
    subject: str,
    detail: str,
) -> LaunchProfileIssue:
    return LaunchProfileIssue(status, code, subject, detail)


def _issue_key(issue: LaunchProfileIssue) -> tuple[int, str, str, str]:
    return (
        0 if issue.status is LaunchProfileStatus.VIOLATED else 1,
        issue.subject,
        issue.code,
        issue.detail,
    )


def _root_key(root: StaticLaunchRoot | CallbackLaunchRoot) -> tuple[int, int, str]:
    kind = root.kind if isinstance(root, StaticLaunchRoot) else "event_callback"
    return (_ROOT_ORDER[kind], root.rva, root.identity)


def _object(value: Any, fields: set[str], context: str) -> Mapping[str, Any]:
    row = _mapping(value, context)
    if set(row) != fields or any(not isinstance(key, str) for key in row):
        raise LaunchProfileV2Error(f"{context} has noncanonical fields")
    return row


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise LaunchProfileV2Error(f"{context} must be an object")
    return value


def _array(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise LaunchProfileV2Error(f"{context} must be an array")
    return value


def _digest(value: Any, context: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise LaunchProfileV2Error(f"{context} must be a lowercase SHA-256 digest")
    return value


def _text(value: Any, context: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 512
        or any(ord(character) < 0x20 for character in value)
    ):
        raise LaunchProfileV2Error(f"{context} must be nonempty bounded text")
    return value


def _token(value: Any, context: str) -> str:
    text = _text(value, context)
    if re.fullmatch(r"[a-z][a-z0-9_]{0,63}", text) is None:
        raise LaunchProfileV2Error(f"{context} must be a lowercase identifier")
    return text


def _uint32(value: Any, context: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value < 1 << 32
    ):
        raise LaunchProfileV2Error(f"{context} must be an unsigned 32-bit integer")
    return value


def _positive_uint32(value: Any, context: str) -> int:
    result = _uint32(value, context)
    if result == 0:
        raise LaunchProfileV2Error(f"{context} must be positive")
    return result


def _json_clone(value: Any) -> Any:
    try:
        return CanonicalJson.of(value).to_value()
    except AuthorityDataError as exc:
        raise LaunchProfileV2Error(str(exc)) from exc

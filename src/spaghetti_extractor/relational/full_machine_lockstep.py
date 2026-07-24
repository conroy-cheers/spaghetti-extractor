"""Strict contract artifact for prototype-free lockstep import assumptions."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from ..errors import StageAInputError
from ..stage_binary import StageABinary, StageAImport, _parse_stage_a_pe
from ..util import sha256_bytes
from .schema import STAGE_A_RELATIONAL_MODEL_ID, STAGE_A_RELATIONAL_PROFILE_ID


FULL_MACHINE_LOCKSTEP_ARTIFACT_FORMAT = (
    "stage-a-full-machine-lockstep-imports-v1"
)
FULL_MACHINE_LOCKSTEP_ARTIFACT_STATUS = (
    "theorem_assumption_requires_paired_stateful_environment"
)
# Short aliases keep the public names consistent with older artifact modules.
FULL_MACHINE_LOCKSTEP_FORMAT = FULL_MACHINE_LOCKSTEP_ARTIFACT_FORMAT
FULL_MACHINE_LOCKSTEP_STATUS = FULL_MACHINE_LOCKSTEP_ARTIFACT_STATUS

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_TOP_LEVEL_FIELDS = {
    "format",
    "profile",
    "model",
    "status",
    "acceptance_authority",
    "original_sha256",
    "candidate_sha256",
    "original_imports",
    "candidate_imports",
    "common_imports",
    "selection",
    "theorem_assumption",
    "artifact_sha256",
}
_SELECTION_FIELDS = {"mode", "imports"}
_THEOREM_ASSUMPTION_FIELDS = {
    "same_site",
    "same_order",
    "same_import",
    "complete_related_machine_boundary",
    "paired_stateful_environment_must_reestablish",
}
_PE_DIRECTORY_BOUND_IMPORT = 11
_PE_DIRECTORY_DELAY_IMPORT = 13


class FullMachineLockstepSelectionMode(str, Enum):
    ALL_COMMON = "all-common"
    SELECTED = "selected"


@dataclass(frozen=True)
class FullMachineLockstepImportIdentity:
    dll: str
    symbol: str | None = None
    ordinal: int | None = None

    def to_payload(self) -> dict[str, Any]:
        identity = _normalize_identity(
            self.dll,
            self.symbol,
            self.ordinal,
            context="full-machine lockstep import identity",
            require_canonical_dll=True,
        )
        if identity.symbol is not None:
            return {"dll": identity.dll, "symbol": identity.symbol}
        return {"dll": identity.dll, "ordinal": identity.ordinal}

    @classmethod
    def parse(
        cls, payload: Any, *, context: str = "full-machine lockstep import"
    ) -> "FullMachineLockstepImportIdentity":
        row = _object(payload, context)
        has_symbol = "symbol" in row
        has_ordinal = "ordinal" in row
        expected = {"dll", "symbol"} if has_symbol else {"dll", "ordinal"}
        if has_symbol == has_ordinal:
            raise StageAInputError(
                f"{context} must contain exactly one of symbol or ordinal"
            )
        _exact_fields(row, expected, context)
        return _normalize_identity(
            row["dll"],
            row.get("symbol"),
            row.get("ordinal"),
            context=context,
            require_canonical_dll=True,
        )


@dataclass(frozen=True)
class FullMachineLockstepSelection:
    mode: FullMachineLockstepSelectionMode
    imports: tuple[FullMachineLockstepImportIdentity, ...]

    def to_payload(self) -> dict[str, Any]:
        return {
            "mode": self.mode.value,
            "imports": [identity.to_payload() for identity in self.imports],
        }


@dataclass(frozen=True)
class FullMachineLockstepTheoremAssumption:
    same_site: bool = True
    same_order: bool = True
    same_import: bool = True
    complete_related_machine_boundary: bool = True
    paired_stateful_environment_must_reestablish: str = "StateRel"

    def to_payload(self) -> dict[str, Any]:
        return {
            "same_site": self.same_site,
            "same_order": self.same_order,
            "same_import": self.same_import,
            "complete_related_machine_boundary": (
                self.complete_related_machine_boundary
            ),
            "paired_stateful_environment_must_reestablish": (
                self.paired_stateful_environment_must_reestablish
            ),
        }

    @classmethod
    def parse(cls, payload: Any) -> "FullMachineLockstepTheoremAssumption":
        context = "full-machine lockstep theorem assumption"
        row = _object(payload, context)
        _exact_fields(row, _THEOREM_ASSUMPTION_FIELDS, context)
        boolean_fields = _THEOREM_ASSUMPTION_FIELDS - {
            "paired_stateful_environment_must_reestablish"
        }
        if any(row[name] is not True for name in boolean_fields) or (
            row["paired_stateful_environment_must_reestablish"] != "StateRel"
        ):
            raise StageAInputError(
                "full-machine lockstep theorem assumption does not match"
            )
        return cls()


@dataclass(frozen=True)
class FullMachineLockstepArtifact:
    original_sha256: str
    candidate_sha256: str
    original_imports: tuple[FullMachineLockstepImportIdentity, ...]
    candidate_imports: tuple[FullMachineLockstepImportIdentity, ...]
    common_imports: tuple[FullMachineLockstepImportIdentity, ...]
    selection: FullMachineLockstepSelection
    theorem_assumption: FullMachineLockstepTheoremAssumption
    artifact_sha256: str
    format: str = field(
        default=FULL_MACHINE_LOCKSTEP_ARTIFACT_FORMAT, init=False
    )
    profile: str = field(default=STAGE_A_RELATIONAL_PROFILE_ID, init=False)
    model: str = field(default=STAGE_A_RELATIONAL_MODEL_ID, init=False)
    status: str = field(
        default=FULL_MACHINE_LOCKSTEP_ARTIFACT_STATUS, init=False
    )
    acceptance_authority: bool = field(default=False, init=False)

    def to_payload(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "profile": self.profile,
            "model": self.model,
            "status": self.status,
            "acceptance_authority": self.acceptance_authority,
            "original_sha256": self.original_sha256,
            "candidate_sha256": self.candidate_sha256,
            "original_imports": [
                identity.to_payload() for identity in self.original_imports
            ],
            "candidate_imports": [
                identity.to_payload() for identity in self.candidate_imports
            ],
            "common_imports": [
                identity.to_payload() for identity in self.common_imports
            ],
            "selection": self.selection.to_payload(),
            "theorem_assumption": self.theorem_assumption.to_payload(),
            "artifact_sha256": self.artifact_sha256,
        }

    @classmethod
    def parse(
        cls,
        payload: Any,
        *,
        expected_original: BinaryInput | None = None,
        expected_candidate: BinaryInput | None = None,
    ) -> "FullMachineLockstepArtifact":
        return parse_full_machine_lockstep_artifact(
            payload,
            expected_original=expected_original,
            expected_candidate=expected_candidate,
        )


BinaryInput = StageABinary | str | os.PathLike[str]
ImportSelection = (
    FullMachineLockstepImportIdentity | StageAImport | Mapping[str, Any]
)


@dataclass(frozen=True)
class _BinarySnapshot:
    sha256: str
    imports: tuple[FullMachineLockstepImportIdentity, ...]


def _object(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{context} must be an object")
    if any(not isinstance(key, str) for key in value):
        raise StageAInputError(f"{context} field names must be strings")
    return value


def _exact_fields(
    payload: Mapping[str, Any], expected: set[str], context: str
) -> None:
    actual = set(payload)
    if actual == expected:
        return
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    details: list[str] = []
    if missing:
        details.append(f"missing fields {missing}")
    if unexpected:
        details.append(f"unexpected fields {unexpected}")
    raise StageAInputError(f"{context} has " + " and ".join(details))


def _sha256(value: Any, context: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise StageAInputError(f"{context} must be 64 lowercase hex characters")
    return value


def _identity_text(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise StageAInputError(f"{context} must be a nonempty string")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise StageAInputError(f"{context} contains control characters")
    return value


def _normalize_identity(
    dll: Any,
    symbol: Any,
    ordinal: Any,
    *,
    context: str,
    require_canonical_dll: bool,
) -> FullMachineLockstepImportIdentity:
    normalized_dll = _identity_text(dll, f"{context}.dll").lower()
    if require_canonical_dll and dll != normalized_dll:
        raise StageAInputError(f"{context}.dll must be lowercase canonical text")
    if (symbol is None) == (ordinal is None):
        raise StageAInputError(
            f"{context} must select exactly one of symbol or ordinal"
        )
    if symbol is not None:
        normalized_symbol = _identity_text(symbol, f"{context}.symbol")
        return FullMachineLockstepImportIdentity(
            dll=normalized_dll, symbol=normalized_symbol
        )
    if (
        isinstance(ordinal, bool)
        or not isinstance(ordinal, int)
        or not 0 <= ordinal <= 0xFFFF
    ):
        raise StageAInputError(f"{context}.ordinal must fit in 16 bits")
    return FullMachineLockstepImportIdentity(
        dll=normalized_dll, ordinal=ordinal
    )


def _identity_key(
    identity: FullMachineLockstepImportIdentity,
) -> tuple[str, int, str, int]:
    return (
        identity.dll,
        0 if identity.symbol is not None else 1,
        identity.symbol or "",
        -1 if identity.ordinal is None else identity.ordinal,
    )


def _parse_import_list(
    value: Any, context: str
) -> tuple[FullMachineLockstepImportIdentity, ...]:
    if not isinstance(value, list):
        raise StageAInputError(f"{context} must be a list")
    identities = tuple(
        FullMachineLockstepImportIdentity.parse(
            row, context=f"{context}[{index}]"
        )
        for index, row in enumerate(value)
    )
    if len(identities) != len(set(identities)):
        raise StageAInputError(f"{context} contains duplicate import identities")
    if identities != tuple(sorted(identities, key=_identity_key)):
        raise StageAInputError(f"{context} is not in canonical order")
    return identities


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return sha256_bytes(encoded)


def _directory_present(binary: StageABinary, index: int) -> bool:
    try:
        directory = binary.pe.OPTIONAL_HEADER.DATA_DIRECTORY[index]
        return int(directory.VirtualAddress) != 0 or int(directory.Size) != 0
    except (AttributeError, IndexError, TypeError, ValueError) as exc:
        raise StageAInputError(
            f"{binary.path} lacks a complete PE data-directory inventory"
        ) from exc


def _reject_unsupported_import_mechanisms(binary: StageABinary) -> None:
    if _directory_present(binary, _PE_DIRECTORY_DELAY_IMPORT) or (
        getattr(binary.pe, "DIRECTORY_ENTRY_DELAY_IMPORT", None)
    ):
        raise StageAInputError(
            f"{binary.path} uses unsupported delay imports"
        )
    if _directory_present(binary, _PE_DIRECTORY_BOUND_IMPORT) or (
        getattr(binary.pe, "DIRECTORY_ENTRY_BOUND_IMPORT", None)
    ):
        raise StageAInputError(
            f"{binary.path} uses unsupported bound-import forwarders"
        )
    for index, descriptor in enumerate(
        getattr(binary.pe, "DIRECTORY_ENTRY_IMPORT", ()) or ()
    ):
        try:
            forwarder_chain = int(descriptor.struct.ForwarderChain)
        except (AttributeError, TypeError, ValueError) as exc:
            raise StageAInputError(
                f"{binary.path} import descriptor {index} has no readable "
                "forwarder chain"
            ) from exc
        if forwarder_chain not in {0, 0xFFFFFFFF}:
            raise StageAInputError(
                f"{binary.path} import descriptor {index} uses an unsupported "
                "forwarder chain"
            )


def _coerce_binary(value: BinaryInput, context: str) -> StageABinary:
    if isinstance(value, StageABinary):
        binary = value
    elif isinstance(value, (str, os.PathLike)):
        binary = _parse_stage_a_pe(Path(value))
    else:
        raise StageAInputError(f"{context} must be a StageABinary or PE path")
    if binary.machine != "i386" or binary.bitness != 32:
        raise StageAInputError(f"{context} must use the x86 PE32 relational model")
    _sha256(binary.sha256, f"{context} SHA-256")
    _reject_unsupported_import_mechanisms(binary)
    return binary


def _binary_snapshot(value: BinaryInput, context: str) -> _BinarySnapshot:
    binary = _coerce_binary(value, context)
    identities = tuple(
        sorted(
            (
                _normalize_identity(
                    imported.dll,
                    imported.symbol,
                    imported.ordinal,
                    context=f"{context} import {index}",
                    require_canonical_dll=False,
                )
                for index, imported in enumerate(binary.imports)
            ),
            key=_identity_key,
        )
    )
    if len(identities) != len(set(identities)):
        raise StageAInputError(
            f"{context} contains duplicate import identities"
        )
    return _BinarySnapshot(sha256=binary.sha256, imports=identities)


def _selection_identity(
    value: ImportSelection, index: int
) -> FullMachineLockstepImportIdentity:
    context = f"full-machine lockstep selected import {index}"
    if isinstance(value, FullMachineLockstepImportIdentity):
        return _normalize_identity(
            value.dll,
            value.symbol,
            value.ordinal,
            context=context,
            require_canonical_dll=False,
        )
    if isinstance(value, StageAImport):
        return _normalize_identity(
            value.dll,
            value.symbol,
            value.ordinal,
            context=context,
            require_canonical_dll=False,
        )
    row = _object(value, context)
    has_symbol = "symbol" in row
    has_ordinal = "ordinal" in row
    expected = {"dll", "symbol"} if has_symbol else {"dll", "ordinal"}
    if has_symbol == has_ordinal:
        raise StageAInputError(
            f"{context} must contain exactly one of symbol or ordinal"
        )
    _exact_fields(row, expected, context)
    return _normalize_identity(
        row["dll"],
        row.get("symbol"),
        row.get("ordinal"),
        context=context,
        require_canonical_dll=False,
    )


def _normalize_selected_imports(
    selected_imports: Iterable[ImportSelection],
) -> tuple[FullMachineLockstepImportIdentity, ...]:
    if isinstance(selected_imports, (str, bytes, Mapping)):
        raise StageAInputError(
            "full-machine lockstep selected imports must be an iterable of identities"
        )
    try:
        values = list(selected_imports)
    except TypeError as exc:
        raise StageAInputError(
            "full-machine lockstep selected imports must be iterable"
        ) from exc
    identities = tuple(
        sorted(
            (
                _selection_identity(value, index)
                for index, value in enumerate(values)
            ),
            key=_identity_key,
        )
    )
    if len(identities) != len(set(identities)):
        raise StageAInputError(
            "full-machine lockstep selection contains duplicate import identities"
        )
    return identities


def _selection_mode(
    value: FullMachineLockstepSelectionMode | str | None,
    *,
    selected_imports_present: bool,
) -> FullMachineLockstepSelectionMode:
    if value is None:
        return (
            FullMachineLockstepSelectionMode.SELECTED
            if selected_imports_present
            else FullMachineLockstepSelectionMode.ALL_COMMON
        )
    try:
        return FullMachineLockstepSelectionMode(value)
    except (TypeError, ValueError) as exc:
        raise StageAInputError(
            "full-machine lockstep selection mode is invalid"
        ) from exc


def _validate_selection(
    selection: FullMachineLockstepSelection,
    common_imports: tuple[FullMachineLockstepImportIdentity, ...],
) -> None:
    common = set(common_imports)
    selected = set(selection.imports)
    if not selected <= common:
        mismatched = sorted(selected - common, key=_identity_key)
        rendered = ", ".join(
            json.dumps(identity.to_payload(), sort_keys=True)
            for identity in mismatched
        )
        raise StageAInputError(
            "full-machine lockstep selected import mismatch: identities are not "
            f"present exactly once in both binaries: {rendered}"
        )
    if selection.mode is FullMachineLockstepSelectionMode.ALL_COMMON:
        if selection.imports != common_imports:
            raise StageAInputError(
                "full-machine lockstep all-common selection must contain every "
                "common import"
            )


def build_full_machine_lockstep_artifact(
    original: BinaryInput,
    candidate: BinaryInput,
    *,
    mode: FullMachineLockstepSelectionMode | str | None = None,
    selected_imports: Iterable[ImportSelection] | None = None,
) -> FullMachineLockstepArtifact:
    original_snapshot = _binary_snapshot(original, "original binary")
    candidate_snapshot = _binary_snapshot(candidate, "candidate binary")
    common_imports = tuple(
        sorted(
            set(original_snapshot.imports) & set(candidate_snapshot.imports),
            key=_identity_key,
        )
    )
    selected_mode = _selection_mode(
        mode, selected_imports_present=selected_imports is not None
    )
    if selected_mode is FullMachineLockstepSelectionMode.ALL_COMMON:
        if selected_imports is not None:
            raise StageAInputError(
                "full-machine lockstep all-common mode does not accept an "
                "explicit selection"
            )
        selected = common_imports
    else:
        if selected_imports is None:
            raise StageAInputError(
                "full-machine lockstep selected mode requires selected imports"
            )
        selected = _normalize_selected_imports(selected_imports)
    selection = FullMachineLockstepSelection(
        mode=selected_mode, imports=selected
    )
    _validate_selection(selection, common_imports)

    body = {
        "format": FULL_MACHINE_LOCKSTEP_ARTIFACT_FORMAT,
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "status": FULL_MACHINE_LOCKSTEP_ARTIFACT_STATUS,
        "acceptance_authority": False,
        "original_sha256": original_snapshot.sha256,
        "candidate_sha256": candidate_snapshot.sha256,
        "original_imports": [
            identity.to_payload() for identity in original_snapshot.imports
        ],
        "candidate_imports": [
            identity.to_payload() for identity in candidate_snapshot.imports
        ],
        "common_imports": [
            identity.to_payload() for identity in common_imports
        ],
        "selection": selection.to_payload(),
        "theorem_assumption": (
            FullMachineLockstepTheoremAssumption().to_payload()
        ),
    }
    payload = {**body, "artifact_sha256": _canonical_sha256(body)}
    return parse_full_machine_lockstep_artifact(
        payload,
        expected_original=original,
        expected_candidate=candidate,
    )


def parse_full_machine_lockstep_artifact(
    payload: Any,
    *,
    expected_original: BinaryInput | None = None,
    expected_candidate: BinaryInput | None = None,
) -> FullMachineLockstepArtifact:
    context = "full-machine lockstep artifact"
    artifact = _object(payload, context)
    _exact_fields(artifact, _TOP_LEVEL_FIELDS, context)
    constants = {
        "format": FULL_MACHINE_LOCKSTEP_ARTIFACT_FORMAT,
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "status": FULL_MACHINE_LOCKSTEP_ARTIFACT_STATUS,
    }
    for name, expected in constants.items():
        if artifact[name] != expected:
            raise StageAInputError(
                f"full-machine lockstep artifact {name} does not match"
            )
    if artifact["acceptance_authority"] is not False:
        raise StageAInputError(
            "full-machine lockstep artifact acceptance_authority must be false"
        )

    original_sha256 = _sha256(
        artifact["original_sha256"],
        "full-machine lockstep original_sha256",
    )
    candidate_sha256 = _sha256(
        artifact["candidate_sha256"],
        "full-machine lockstep candidate_sha256",
    )
    original_imports = _parse_import_list(
        artifact["original_imports"],
        "full-machine lockstep original_imports",
    )
    candidate_imports = _parse_import_list(
        artifact["candidate_imports"],
        "full-machine lockstep candidate_imports",
    )
    common_imports = _parse_import_list(
        artifact["common_imports"],
        "full-machine lockstep common_imports",
    )
    expected_common = tuple(
        sorted(set(original_imports) & set(candidate_imports), key=_identity_key)
    )
    if common_imports != expected_common:
        raise StageAInputError(
            "full-machine lockstep common imports do not exactly match the "
            "side inventories"
        )

    selection_row = _object(
        artifact["selection"], "full-machine lockstep selection"
    )
    _exact_fields(
        selection_row, _SELECTION_FIELDS, "full-machine lockstep selection"
    )
    selected_mode = _selection_mode(
        selection_row["mode"], selected_imports_present=True
    )
    selected = _parse_import_list(
        selection_row["imports"],
        "full-machine lockstep selection imports",
    )
    selection = FullMachineLockstepSelection(
        mode=selected_mode, imports=selected
    )
    _validate_selection(selection, common_imports)
    theorem_assumption = FullMachineLockstepTheoremAssumption.parse(
        artifact["theorem_assumption"]
    )

    artifact_sha256 = _sha256(
        artifact["artifact_sha256"],
        "full-machine lockstep artifact_sha256",
    )
    body = {
        key: value for key, value in artifact.items() if key != "artifact_sha256"
    }
    if artifact_sha256 != _canonical_sha256(body):
        raise StageAInputError(
            "full-machine lockstep artifact digest does not match"
        )

    parsed = FullMachineLockstepArtifact(
        original_sha256=original_sha256,
        candidate_sha256=candidate_sha256,
        original_imports=original_imports,
        candidate_imports=candidate_imports,
        common_imports=common_imports,
        selection=selection,
        theorem_assumption=theorem_assumption,
        artifact_sha256=artifact_sha256,
    )
    expected_inputs = (
        ("original", expected_original, original_sha256, original_imports),
        ("candidate", expected_candidate, candidate_sha256, candidate_imports),
    )
    for side, expected_input, expected_hash, expected_imports in expected_inputs:
        if expected_input is None:
            continue
        snapshot = _binary_snapshot(expected_input, f"expected {side} binary")
        if snapshot.sha256 != expected_hash:
            raise StageAInputError(
                f"full-machine lockstep {side} binary hash mismatch"
            )
        if snapshot.imports != expected_imports:
            raise StageAInputError(
                f"full-machine lockstep {side} import inventory mismatch"
            )
    return parsed


def serialize_full_machine_lockstep_artifact(
    artifact: FullMachineLockstepArtifact,
) -> dict[str, Any]:
    if not isinstance(artifact, FullMachineLockstepArtifact):
        raise StageAInputError(
            "full-machine lockstep serializer requires a typed artifact"
        )
    return parse_full_machine_lockstep_artifact(artifact.to_payload()).to_payload()


def full_machine_lockstep_payload(
    original: BinaryInput,
    candidate: BinaryInput,
    *,
    mode: FullMachineLockstepSelectionMode | str | None = None,
    selected_imports: Iterable[ImportSelection] | None = None,
) -> dict[str, Any]:
    return serialize_full_machine_lockstep_artifact(
        build_full_machine_lockstep_artifact(
            original,
            candidate,
            mode=mode,
            selected_imports=selected_imports,
        )
    )


def full_machine_lockstep_artifact_sha256(
    artifact: FullMachineLockstepArtifact | Mapping[str, Any],
) -> str:
    parsed = (
        parse_full_machine_lockstep_artifact(artifact)
        if isinstance(artifact, Mapping)
        else parse_full_machine_lockstep_artifact(artifact.to_payload())
        if isinstance(artifact, FullMachineLockstepArtifact)
        else None
    )
    if parsed is None:
        raise StageAInputError(
            "full-machine lockstep digest requires an artifact or payload"
        )
    return parsed.artifact_sha256


__all__ = [
    "FULL_MACHINE_LOCKSTEP_ARTIFACT_FORMAT",
    "FULL_MACHINE_LOCKSTEP_ARTIFACT_STATUS",
    "FULL_MACHINE_LOCKSTEP_FORMAT",
    "FULL_MACHINE_LOCKSTEP_STATUS",
    "FullMachineLockstepArtifact",
    "FullMachineLockstepImportIdentity",
    "FullMachineLockstepSelection",
    "FullMachineLockstepSelectionMode",
    "FullMachineLockstepTheoremAssumption",
    "build_full_machine_lockstep_artifact",
    "full_machine_lockstep_artifact_sha256",
    "full_machine_lockstep_payload",
    "parse_full_machine_lockstep_artifact",
    "serialize_full_machine_lockstep_artifact",
]

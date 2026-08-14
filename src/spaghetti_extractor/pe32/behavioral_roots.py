"""Deterministic behavioral roots extracted from exact PE metadata."""

from __future__ import annotations

import copy
import json
import re
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, Sequence

from .stage_binary import StageABinary, StageAInputError, _parse_stage_a_pe


BEHAVIORAL_ROOTS_FORMAT = "stage-a-behavioral-roots-v1"

_AUTHORITY = "independent_exact_pe_metadata"
_ROOT_KINDS = ("pe_entrypoint", "pe_export", "pe_tls_callback")
_ROOT_KIND_ORDER = {kind: index for index, kind in enumerate(_ROOT_KINDS)}
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_TOP_LEVEL_FIELDS = frozenset(
    {
        "format",
        "status",
        "authority",
        "pe",
        "roots",
        "counts",
        "constraints",
        "contract_sha256",
    }
)
_PE_FIELDS = frozenset(
    {
        "sha256",
        "file_size",
        "machine",
        "bitness",
        "image_base",
        "size_of_image",
        "entrypoint_rva",
    }
)
_CONSTRAINTS = {
    "original_binary_executed": False,
    "strict_export_parsing_required": True,
    "strict_tls_parsing_required": True,
    "tls_callback_inventory_immutable": True,
    "roots_in_exactly_one_executable_section": True,
}


class BehavioralRootsError(StageAInputError):
    """The behavioral-root artifact or its exact PE binding is invalid."""


def generate_behavioral_roots(original_pe: Path | str) -> dict[str, Any]:
    """Extract and self-hash the complete static root surface of an exact PE."""

    binary = _parse_stage_a_pe(Path(original_pe))
    core = _behavioral_roots_core(binary)
    return {**core, "contract_sha256": behavioral_roots_sha256(core)}


def load_behavioral_roots(
    path: Path | str, *, original_pe: Path | str
) -> dict[str, Any]:
    """Load an artifact and validate it against a fresh parse of its exact PE."""

    artifact_path = Path(path)
    try:
        payload = json.loads(
            artifact_path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except BehavioralRootsError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BehavioralRootsError(
            f"cannot load behavioral-roots artifact {artifact_path}: {exc}"
        ) from exc
    if not isinstance(payload, Mapping):
        raise BehavioralRootsError("behavioral-roots artifact must be an object")
    return validate_behavioral_roots(payload, original_pe=original_pe)


def validate_behavioral_roots(
    payload: Mapping[str, Any], *, original_pe: Path | str
) -> dict[str, Any]:
    """Strictly validate schema, self-hash, and the independently parsed PE."""

    artifact = _copy_mapping(payload, "behavioral-roots artifact")
    if set(artifact) != _TOP_LEVEL_FIELDS:
        raise BehavioralRootsError(
            "behavioral-roots artifact has noncanonical top-level fields"
        )
    if artifact.get("format") != BEHAVIORAL_ROOTS_FORMAT:
        raise BehavioralRootsError("unsupported behavioral-roots artifact format")

    observed_hash = _digest(
        artifact.get("contract_sha256"), "behavioral-roots contract SHA-256"
    )
    if observed_hash != behavioral_roots_sha256(artifact):
        raise BehavioralRootsError("behavioral-roots artifact self-hash is stale")

    core = copy.deepcopy(artifact)
    core.pop("contract_sha256")
    _validate_core_schema(core)

    expected = generate_behavioral_roots(original_pe)
    if artifact != expected:
        raise BehavioralRootsError(
            "behavioral-roots artifact does not match the exact supplied PE"
        )
    return expected


def canonical_behavioral_roots_payload(payload: Mapping[str, Any]) -> bytes:
    """Return the canonical UTF-8 JSON encoding used by the artifact hash."""

    value = _copy_mapping(payload, "behavioral-roots payload")
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise BehavioralRootsError(
            "behavioral-roots payload is not canonical JSON"
        ) from exc


def behavioral_roots_sha256(payload: Mapping[str, Any]) -> str:
    """Hash the canonical artifact body, excluding any supplied self-hash."""

    core = _copy_mapping(payload, "behavioral-roots payload")
    core.pop("contract_sha256", None)
    return sha256(canonical_behavioral_roots_payload(core)).hexdigest()


def _behavioral_roots_core(binary: StageABinary) -> dict[str, Any]:
    if binary.exports is None or binary.export_parse_error is not None:
        raise BehavioralRootsError(
            "strict PE export parsing failed: "
            + (binary.export_parse_error or "export inventory is unavailable")
        )
    if binary.tls_callback_rvas is None or binary.tls_callback_parse_error is not None:
        raise BehavioralRootsError(
            "strict PE TLS parsing failed: "
            + (
                binary.tls_callback_parse_error
                or "TLS callback inventory is unavailable"
            )
        )
    if binary.tls_callback_array_immutable is not True:
        raise BehavioralRootsError(
            "strict PE TLS parsing is ambiguous because the callback inventory is mutable"
        )

    roots: list[dict[str, Any]] = []
    if binary.entrypoint_rva != 0:
        _require_executable_root(binary, binary.entrypoint_rva, "PE entrypoint")
        roots.append(
            {
                "kind": "pe_entrypoint",
                "identity": "pe-entrypoint",
                "rva": binary.entrypoint_rva,
            }
        )

    for exported in binary.exports:
        if exported.kind == "forwarder":
            if not exported.forwarder:
                raise BehavioralRootsError(
                    "strict PE export parsing produced a malformed forwarder"
                )
            continue
        if exported.forwarder is not None:
            raise BehavioralRootsError(
                "strict PE export parsing produced an ambiguous export kind"
            )
        matches = _executable_sections(binary, exported.rva)
        if len(matches) > 1:
            raise BehavioralRootsError(
                f"PE export ordinal {exported.ordinal} has ambiguous executable bounds"
            )
        if not matches:
            continue
        roots.append(
            {
                "kind": "pe_export",
                "identity": _export_identity(exported.ordinal, exported.name),
                "rva": exported.rva,
                "ordinal": exported.ordinal,
                "name": exported.name,
            }
        )

    for index, rva in enumerate(binary.tls_callback_rvas):
        _require_executable_root(binary, rva, f"PE TLS callback {index}")
        roots.append(
            {
                "kind": "pe_tls_callback",
                "identity": f"pe-tls-callback:index:{index}",
                "rva": rva,
                "callback_index": index,
            }
        )

    roots.sort(key=_root_sort_key)
    _validate_roots(roots, size_of_image=binary.size_of_image)
    counts = {kind: 0 for kind in _ROOT_KINDS}
    for root in roots:
        counts[str(root["kind"])] += 1
    return {
        "format": BEHAVIORAL_ROOTS_FORMAT,
        "status": "complete",
        "authority": _AUTHORITY,
        "pe": {
            "sha256": binary.sha256,
            "file_size": binary.size,
            "machine": binary.machine,
            "bitness": binary.bitness,
            "image_base": binary.image_base,
            "size_of_image": binary.size_of_image,
            "entrypoint_rva": binary.entrypoint_rva,
        },
        "roots": roots,
        "counts": {"roots": len(roots), **counts},
        "constraints": copy.deepcopy(_CONSTRAINTS),
    }


def _validate_core_schema(core: Mapping[str, Any]) -> None:
    if core.get("status") != "complete" or core.get("authority") != _AUTHORITY:
        raise BehavioralRootsError(
            "behavioral-roots artifact has a noncanonical status or authority"
        )
    pe = _mapping(core.get("pe"), "behavioral-roots PE binding")
    if set(pe) != _PE_FIELDS:
        raise BehavioralRootsError(
            "behavioral-roots PE binding has noncanonical fields"
        )
    _digest(pe.get("sha256"), "behavioral-roots PE SHA-256")
    _positive_int(pe.get("file_size"), "behavioral-roots PE file size")
    machine = pe.get("machine")
    bitness = pe.get("bitness")
    if (machine, bitness) not in {("i386", 32), ("x86_64", 64)}:
        raise BehavioralRootsError(
            "behavioral-roots PE machine and bitness are inconsistent"
        )
    _uint(pe.get("image_base"), 64, "behavioral-roots PE image base")
    size_of_image = _positive_uint(
        pe.get("size_of_image"), 32, "behavioral-roots PE image size"
    )
    entrypoint_rva = _uint(
        pe.get("entrypoint_rva"), 32, "behavioral-roots PE entrypoint RVA"
    )
    if entrypoint_rva >= size_of_image and entrypoint_rva != 0:
        raise BehavioralRootsError(
            "behavioral-roots PE entrypoint is outside the image"
        )

    roots = core.get("roots")
    if not isinstance(roots, list):
        raise BehavioralRootsError("behavioral-roots inventory must be a list")
    _validate_roots(roots, size_of_image=size_of_image)
    if roots != sorted(roots, key=_root_sort_key):
        raise BehavioralRootsError("behavioral roots are not canonically sorted")

    expected_counts = {kind: 0 for kind in _ROOT_KINDS}
    for root in roots:
        expected_counts[str(root["kind"])] += 1
    expected_counts = {"roots": len(roots), **expected_counts}
    counts = _mapping(core.get("counts"), "behavioral-roots counts")
    if dict(counts) != expected_counts:
        raise BehavioralRootsError("behavioral-roots counts are inconsistent")
    constraints = _mapping(
        core.get("constraints"), "behavioral-roots constraints"
    )
    if dict(constraints) != _CONSTRAINTS:
        raise BehavioralRootsError(
            "behavioral-roots constraints are not fail-closed"
        )


def _validate_roots(roots: Sequence[Any], *, size_of_image: int) -> None:
    identities: set[str] = set()
    kind_identities: set[tuple[str, str]] = set()
    for index, raw in enumerate(roots):
        root = _mapping(raw, f"behavioral root {index}")
        kind = root.get("kind")
        identity = root.get("identity")
        if kind not in _ROOT_KIND_ORDER:
            raise BehavioralRootsError(f"behavioral root {index} has an invalid kind")
        if not isinstance(identity, str) or not identity:
            raise BehavioralRootsError(
                f"behavioral root {index} has a malformed identity"
            )
        key = (str(kind), identity)
        if identity in identities or key in kind_identities:
            raise BehavioralRootsError(
                f"behavioral root {index} duplicates a kind or identity"
            )
        identities.add(identity)
        kind_identities.add(key)
        rva = _positive_uint(root.get("rva"), 32, f"behavioral root {index} RVA")
        if rva >= size_of_image:
            raise BehavioralRootsError(
                f"behavioral root {index} is outside the PE image"
            )

        expected_fields = {"kind", "identity", "rva"}
        if kind == "pe_entrypoint":
            expected_identity = "pe-entrypoint"
        elif kind == "pe_export":
            expected_fields.update({"ordinal", "name"})
            ordinal = _uint(
                root.get("ordinal"), 32, f"behavioral root {index} export ordinal"
            )
            name = root.get("name")
            if name is not None and (not isinstance(name, str) or not name):
                raise BehavioralRootsError(
                    f"behavioral root {index} has a malformed export name"
                )
            expected_identity = _export_identity(ordinal, name)
        else:
            expected_fields.add("callback_index")
            callback_index = _uint(
                root.get("callback_index"),
                32,
                f"behavioral root {index} TLS callback index",
            )
            expected_identity = f"pe-tls-callback:index:{callback_index}"
        if set(root) != expected_fields:
            raise BehavioralRootsError(
                f"behavioral root {index} has noncanonical fields"
            )
        if identity != expected_identity:
            raise BehavioralRootsError(
                f"behavioral root {index} identity is inconsistent"
            )


def _require_executable_root(binary: StageABinary, rva: int, label: str) -> None:
    matches = _executable_sections(binary, rva)
    if len(matches) != 1:
        reason = "ambiguous" if matches else "outside executable bounds"
        raise BehavioralRootsError(f"{label} is {reason}: RVA 0x{rva:x}")


def _executable_sections(binary: StageABinary, rva: int) -> list[Any]:
    if not 0 < rva < binary.size_of_image:
        return []
    return [
        section
        for section in binary.sections
        if section.executable and section.rva_start <= rva < section.rva_end
    ]


def _root_sort_key(root: Mapping[str, Any]) -> tuple[int, int, str]:
    kind = str(root.get("kind"))
    if kind == "pe_export":
        secondary = root.get("ordinal")
    elif kind == "pe_tls_callback":
        secondary = root.get("callback_index")
    else:
        secondary = 0
    return (
        _ROOT_KIND_ORDER.get(kind, len(_ROOT_KIND_ORDER)),
        secondary if isinstance(secondary, int) and not isinstance(secondary, bool) else -1,
        str(root.get("identity") or ""),
    )


def _export_identity(ordinal: int, name: str | None) -> str:
    label = name if name is not None else "<ordinal-only>"
    return f"pe-export:ordinal:{ordinal}:name:{label}"


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BehavioralRootsError(
                f"behavioral-roots JSON repeats object field {key!r}"
            )
        result[key] = value
    return result


def _copy_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise BehavioralRootsError(f"{label} must be an object")
    return copy.deepcopy(dict(value))


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise BehavioralRootsError(f"{label} must be an object")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise BehavioralRootsError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _positive_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise BehavioralRootsError(f"{label} must be a positive integer")
    return value


def _uint(value: Any, bits: int, label: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value < 1 << bits
    ):
        raise BehavioralRootsError(f"{label} must be an unsigned {bits}-bit integer")
    return value


def _positive_uint(value: Any, bits: int, label: str) -> int:
    result = _uint(value, bits, label)
    if result == 0:
        raise BehavioralRootsError(f"{label} must be positive")
    return result

"""Optional Rust-backed sparse retrieval for ABI-first library matching."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from .abi_records import canonical_sha256


def _abi_key(profile: Mapping[str, Any]) -> str:
    # Profile IDs are catalog-local names.  The partition is the actual ABI.
    return canonical_sha256(
        {key: value for key, value in profile.items() if key != "id"}
    )


def _feature_hash(kind: str, value: object) -> str:
    return canonical_sha256({"kind": kind, "value": value})


def _record(
    function: Mapping[str, Any],
    *,
    abi_key: str,
) -> dict[str, object]:
    exact = function.get("exact_bytes_sha256")
    normalized = function.get("normalized_bytes_sha256")
    structural: list[str] = []
    for field in ("unit_merkle_sha256", "cfg_sha256"):
        value = function.get(field)
        if isinstance(value, str) and value:
            structural.append(_feature_hash(field, value))
    for field in ("imports", "strings", "constants"):
        values = function.get(field)
        if isinstance(values, list):
            structural.extend(
                _feature_hash(field, value)
                for value in values
                if isinstance(value, (str, int)) and not isinstance(value, bool)
            )
    return {
        "record_id": str(function["id"]),
        "abi_key": abi_key,
        "fixed_anchor_hashes": [exact] if isinstance(exact, str) else [],
        "normalized_hashes": (
            [normalized] if isinstance(normalized, str) else []
        ),
        "structural_feature_hashes": sorted(set(structural)),
    }


class NativeLibraryCandidateBackend:
    """Adapter around the proposal-only PyO3 inverted index.

    Records without complete ABI profiles are intentionally omitted.  The
    caller must retain its fail-closed Python fallback for those records.
    """

    def __init__(self, native_module: Any) -> None:
        if getattr(native_module, "LIBRARY_INDEX_API_VERSION", None) != 1:
            raise RuntimeError("unsupported native library-index API")
        self._native = native_module

    def generate_library_candidates(
        self,
        target_graph: Mapping[str, Any],
        search_index: Mapping[str, Any],
    ) -> Iterable[tuple[str, str]]:
        profiles = {
            str(row["id"]): row
            for row in search_index.get("abi_profiles", [])
            if isinstance(row, Mapping) and isinstance(row.get("id"), str)
        }
        catalog_records = []
        for function in search_index.get("functions", []):
            if not isinstance(function, Mapping):
                continue
            profile_id = function.get("abi_profile_id")
            profile = profiles.get(str(profile_id))
            if profile is None:
                continue
            catalog_records.append(
                _record(function, abi_key=_abi_key(profile))
            )
        target_records = []
        for function in target_graph.get("functions", []):
            if not isinstance(function, Mapping):
                continue
            profile = function.get("abi_profile")
            if not isinstance(profile, Mapping):
                continue
            target_records.append(
                _record(function, abi_key=_abi_key(profile))
            )
        if not catalog_records or not target_records:
            return ()
        witnesses = self._native.retrieve_library_candidates(
            catalog_records, target_records
        )
        return tuple(
            (
                str(row["target_record_id"]),
                str(row["catalog_record_id"]),
            )
            for row in witnesses
            if isinstance(row, Mapping)
        )


def optional_native_library_backend() -> NativeLibraryCandidateBackend | None:
    """Return the pinned accelerator when available, otherwise pure Python."""

    try:
        import spaghetti_extractor_native as native
    except ImportError:
        return None
    return NativeLibraryCandidateBackend(native)


__all__ = [
    "NativeLibraryCandidateBackend",
    "optional_native_library_backend",
]

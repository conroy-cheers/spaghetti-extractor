from __future__ import annotations

import hashlib
import os
import random
import time
import unittest
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

import spaghetti_extractor_native as native
from spaghetti_extractor.libraries.native_index import (
    NativeLibraryCandidateBackend,
)


_KINDS = (
    ("fixed_anchor_hashes", "fixed_anchor_hash", "fixed-anchor"),
    ("normalized_hashes", "normalized_hash", "normalized"),
    (
        "structural_feature_hashes",
        "structural_feature_hash",
        "structural",
    ),
)


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _record(
    record_id: str,
    *,
    abi: str = "i686-cdecl-v1",
    anchors: Iterable[str] = (),
    normalized: Iterable[str] = (),
    structural: Iterable[str] = (),
) -> dict[str, Any]:
    return {
        "record_id": record_id,
        "abi_key": abi,
        "fixed_anchor_hashes": list(anchors),
        "normalized_hashes": list(normalized),
        "structural_feature_hashes": list(structural),
    }


def _reference_retrieval(
    catalog: Sequence[Mapping[str, Any]],
    targets: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for target in targets:
        for candidate in catalog:
            if target["abi_key"] != candidate["abi_key"]:
                continue
            witnesses: list[dict[str, str]] = []
            for field, output_kind, witness_prefix in _KINDS:
                for feature_hash in sorted(
                    set(target[field]).intersection(candidate[field])
                ):
                    witnesses.append(
                        {
                            "kind": output_kind,
                            "feature_hash": feature_hash,
                            "witness_id": f"{witness_prefix}:{feature_hash}",
                        }
                    )
            if not witnesses:
                continue
            result.append(
                {
                    "format": "spaghetti-extractor-library-candidate-witness-v1",
                    "authority": "proposal_only",
                    "target_record_id": target["record_id"],
                    "catalog_record_id": candidate["record_id"],
                    "abi_key": target["abi_key"],
                    "witnesses": witnesses,
                    "witness_count": len(witnesses),
                }
            )
    return sorted(
        result,
        key=lambda row: (
            row["target_record_id"],
            row["catalog_record_id"],
            row["abi_key"],
        ),
    )


class NativeLibraryIndexTests(unittest.TestCase):
    def test_native_adapter_partitions_by_semantics_not_profile_name(self) -> None:
        digest = _hash("adapter-exact-body")
        profile = {
            "id": "catalog-local-name",
            "architecture": "x86",
            "object_format": "pe32",
            "calling_convention": "cdecl",
        }
        target_profile = {**profile, "id": "target-local-name"}
        function = {
            "id": "catalog:function",
            "abi_profile_id": profile["id"],
            "exact_bytes_sha256": digest,
            "normalized_bytes_sha256": None,
            "unit_merkle_sha256": None,
            "cfg_sha256": _hash("catalog-cfg"),
            "imports": [],
            "strings": [],
            "constants": [],
        }
        target = {
            **function,
            "id": "target:function",
            "abi_profile": target_profile,
        }
        pairs = tuple(
            NativeLibraryCandidateBackend(native).generate_library_candidates(
                {"functions": [target]},
                {"abi_profiles": [profile], "functions": [function]},
            )
        )
        self.assertEqual(pairs, (("target:function", "catalog:function"),))

    def test_native_adapter_omits_unknown_abi_for_checked_fallback(self) -> None:
        digest = _hash("unknown-abi-body")
        function = {
            "id": "catalog:function",
            "abi_profile_id": None,
            "exact_bytes_sha256": digest,
            "normalized_bytes_sha256": None,
            "unit_merkle_sha256": None,
            "cfg_sha256": _hash("cfg"),
            "imports": [],
            "strings": [],
            "constants": [],
        }
        target = {**function, "id": "target:function", "abi_profile": None}
        pairs = tuple(
            NativeLibraryCandidateBackend(native).generate_library_candidates(
                {"functions": [target]},
                {"abi_profiles": [], "functions": [function]},
            )
        )
        self.assertEqual(pairs, ())

    def test_matches_reference_implementation(self) -> None:
        random_source = random.Random(0x5EED)
        feature_pool = [_hash(f"feature:{index}") for index in range(80)]
        abi_keys = ["i686-cdecl-v1", "i686-stdcall-v1", "i686-thiscall-v1"]

        def random_record(prefix: str, index: int) -> dict[str, Any]:
            selected = random_source.sample(feature_pool, 6)
            return _record(
                f"{prefix}:{index:04d}",
                abi=random_source.choice(abi_keys),
                anchors=selected[:2],
                normalized=selected[2:4],
                structural=selected[4:],
            )

        catalog = [random_record("catalog", index) for index in range(200)]
        targets = [random_record("target", index) for index in range(30)]
        self.assertEqual(
            native.retrieve_library_candidates(catalog, targets),
            _reference_retrieval(catalog, targets),
        )

    def test_duplicate_aliases_remain_distinct_candidates(self) -> None:
        shared = _hash("shared-alias-body")
        catalog = [
            _record("catalog:alias-a", normalized=[shared]),
            _record("catalog:alias-b", normalized=[shared]),
        ]
        result = native.retrieve_library_candidates(
            catalog,
            [_record("target:one", normalized=[shared])],
        )
        self.assertEqual(
            [row["catalog_record_id"] for row in result],
            ["catalog:alias-a", "catalog:alias-b"],
        )

    def test_hash_collision_candidates_are_all_proposed(self) -> None:
        collision = _hash("deliberately-shared-retrieval-key")
        catalog = [
            _record(f"catalog:{index}", structural=[collision])
            for index in range(4)
        ]
        result = native.retrieve_library_candidates(
            catalog,
            [_record("target:collision", structural=[collision])],
        )
        self.assertEqual(len(result), 4)
        self.assertTrue(all(row["authority"] == "proposal_only" for row in result))
        self.assertEqual(
            result[0]["witnesses"],
            [
                {
                    "kind": "structural_feature_hash",
                    "feature_hash": collision,
                    "witness_id": f"structural:{collision}",
                }
            ],
        )

    def test_abi_partition_excludes_feature_matches(self) -> None:
        shared = _hash("same-bits-different-abi")
        catalog = [
            _record("catalog:cdecl", abi="i686-cdecl-v1", anchors=[shared]),
            _record("catalog:stdcall", abi="i686-stdcall-v1", anchors=[shared]),
        ]
        result = native.retrieve_library_candidates(
            catalog,
            [_record("target", abi="i686-stdcall-v1", anchors=[shared])],
        )
        self.assertEqual(
            [row["catalog_record_id"] for row in result],
            ["catalog:stdcall"],
        )

    def test_output_is_deterministic_across_input_order_and_duplicates(self) -> None:
        anchors = [_hash("anchor:2"), _hash("anchor:1"), _hash("anchor:2")]
        normalized = [_hash("normalized")]
        catalog = [
            _record("catalog:z", anchors=anchors, normalized=normalized),
            _record("catalog:a", anchors=reversed(anchors), normalized=normalized),
        ]
        targets = [
            _record(
                "target:z",
                anchors=reversed(anchors),
                normalized=normalized,
            ),
            _record("target:a", anchors=anchors, normalized=normalized),
        ]
        first = native.retrieve_library_candidates(catalog, targets)
        second = native.retrieve_library_candidates(
            list(reversed(catalog)), list(reversed(targets))
        )
        self.assertEqual(first, second)
        self.assertEqual(
            native.canonical_json_bytes(first), native.canonical_json_bytes(second)
        )

    def test_rejects_malformed_inputs(self) -> None:
        valid = _record("valid", anchors=[_hash("valid")])
        malformed_cases = [
            ("not-an-array", [valid], None),
            ([{"record_id": "missing-fields"}], [valid], None),
            ([{**valid, "unexpected": True}], [valid], None),
            ([{**valid, "fixed_anchor_hashes": ["NOT-A-HASH"]}], [valid], None),
            ([valid, valid], [valid], None),
            ([_record("empty")], [valid], None),
            ([valid], [valid], {"max_sparse_hits": True}),
            ([valid], [valid], {"unknown_limit": 1}),
        ]
        for catalog, targets, limits in malformed_cases:
            with self.subTest(catalog=catalog, limits=limits):
                with self.assertRaises(ValueError):
                    native.retrieve_library_candidates(catalog, targets, limits)

    def test_resource_bounds_fail_closed(self) -> None:
        shared = _hash("dense")
        with self.assertRaisesRegex(ValueError, "record bound"):
            native.retrieve_library_candidates(
                [
                    _record("catalog:0", anchors=[shared]),
                    _record("catalog:1", anchors=[shared]),
                ],
                [_record("target", anchors=[shared])],
                {"max_catalog_records": 1},
            )
        with self.assertRaisesRegex(ValueError, "max_features_per_record"):
            native.retrieve_library_candidates(
                [_record("catalog", anchors=[shared], normalized=[_hash("other")])],
                [_record("target", anchors=[shared])],
                {"max_features_per_record": 1},
            )
        with self.assertRaisesRegex(ValueError, "max_sparse_hits"):
            native.retrieve_library_candidates(
                [
                    _record(f"catalog:{index}", anchors=[shared])
                    for index in range(3)
                ],
                [_record("target", anchors=[shared])],
                {"max_sparse_hits": 2},
            )

    @unittest.skipUnless(
        os.environ.get("SPAGHETTI_EXTRACTOR_NATIVE_BENCHMARK") == "1",
        "set SPAGHETTI_EXTRACTOR_NATIVE_BENCHMARK=1 for the 100k-signature corpus",
    )
    def test_retrieves_from_100k_synthetic_signatures(self) -> None:
        catalog = [
            _record(
                f"catalog:{index:06d}",
                anchors=[_hash(f"benchmark:{index}")],
            )
            for index in range(100_000)
        ]
        targets = [
            _record(
                f"target:{index:06d}",
                anchors=[_hash(f"benchmark:{index}")],
            )
            for index in range(0, 100_000, 1_000)
        ]
        started = time.perf_counter()
        result = native.retrieve_library_candidates(catalog, targets)
        elapsed = time.perf_counter() - started
        self.assertEqual(len(result), 100)
        self.assertLess(elapsed, 15.0)
        print(f"native library index: 100k signatures in {elapsed:.3f}s")


if __name__ == "__main__":
    unittest.main()

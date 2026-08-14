from __future__ import annotations

from ._support import *

class LinkedLibraryRefinementTests(LinkedLibraryTestCase):
    def test_partitions_units_with_review_artifact_match_and_import_thunk(self) -> None:
        lock = self._write_runtime_catalog()
        review = bind_linked_island_review(
            {
                "format": LINKED_ISLAND_REVIEW_FORMAT,
                "original_binary_sha256": sha256_file(self.original),
                "islands": [
                    {
                        "id": "application:entry",
                        "kind": "application",
                        "authority": "operator_reviewed_exact_range",
                        "ranges": [
                            {
                                "rva_start": 0x1000 + len(_FUNCTION),
                                "rva_end": 0x1000 + len(_FUNCTION) + 1,
                            }
                        ],
                    }
                ],
            }
        )
        manifest = match_linked_islands(
            original=self.original,
            machine_ir=self.machine,
            catalog_lock=lock,
            review=review,
            out=self.root / "linked-islands.json",
        )

        self.assertEqual(manifest["status"], "classified")
        self.assertTrue(manifest["coverage"]["classified_exactly_once"])
        self.assertEqual(manifest["coverage"]["unknown_units"], 0)
        self.assertEqual(manifest["counts"]["artifact_matches"], 1)
        by_kind = {row["kind"]: row for row in manifest["islands"]}
        self.assertEqual(by_kind["application"]["unit_ids"], ["unit:1009"])
        self.assertEqual(by_kind["linked_dependency"]["unit_ids"], ["unit:1000"])
        self.assertEqual(by_kind["import_thunk"]["unit_ids"], ["unit:100a"])
        self.assertFalse(by_kind["linked_dependency"]["replacement_authorized"])
        self.assertNotIn("reviewed_unclaimed_exact_units", manifest)
        self.assertNotIn(
            "reviewed_complement_binds_ownership_only", manifest["authority"]
        )

    def test_refined_unknowns_split_at_non_call_cfg_boundaries(self) -> None:
        lock_library_catalog(indexes=[], out=self.root / "empty-lock.json")
        evidence = propose_library_match_evidence(
            original=self.original,
            machine_ir=self.machine,
            catalog_lock=self.root / "empty-lock.json",
            review=None,
            out=self.root / "empty-evidence.json",
        )
        infer_library_hypotheses(
            match_evidence=evidence,
            out=self.root / "empty-hypotheses.json",
        )

        manifest = refine_linked_islands(
            original=self.original,
            machine_ir=self.machine,
            match_evidence=self.root / "empty-evidence.json",
            hypotheses=self.root / "empty-hypotheses.json",
            review=None,
            out=self.root / "refined-islands.json",
        )

        self.assertTrue(manifest["coverage"]["classified_exactly_once"])
        self.assertEqual(manifest["counts"]["unknown_cfg_components"], 2)
        unknowns = [
            island for island in manifest["islands"] if island["kind"] == "unknown"
        ]
        self.assertEqual([island["unit_count"] for island in unknowns], [1, 1])

    def test_reviewed_complement_claims_only_still_unclaimed_exact_units(self) -> None:
        review = self._review_with_complement()
        manifest = match_linked_islands(
            original=self.original,
            machine_ir=self.machine,
            catalog_lock=None,
            review=review,
            out=self.root / "complement-islands.json",
        )

        validate_linked_island_manifest(manifest)
        self.assertEqual(manifest["status"], "classified")
        self.assertEqual(manifest["coverage"]["unknown_units"], 0)
        by_id = {row["id"]: row for row in manifest["islands"]}
        self.assertEqual(by_id["application:entry"]["unit_ids"], ["unit:1009"])
        self.assertEqual(
            by_id["import-thunk:kernel32.dll:WriteFile"]["unit_ids"],
            ["unit:100a"],
        )
        complement = by_id["compiler-linker-support:reviewed-complement"]
        self.assertEqual(complement["unit_ids"], ["unit:1000"])
        self.assertFalse(complement["replacement_authorized"])
        self.assertEqual(
            complement["match"]["preserved_claimed_island_ids"],
            ["application:entry", "import-thunk:kernel32.dll:WriteFile"],
        )
        policy = manifest["reviewed_unclaimed_exact_units"]
        self.assertTrue(policy["operator_reviewed"])
        self.assertFalse(policy["replacement_authorized"])
        self.assertEqual(
            policy["exact_bindings"]["machine_ir_sha256"],
            manifest["bindings"]["machine_ir_sha256"],
        )

    def test_refined_complement_closes_unknowns_without_semantic_authority(self) -> None:
        review = self._review_with_complement(kind="linked_dependency")
        lock_library_catalog(indexes=[], out=self.root / "empty-lock.json")
        evidence = propose_library_match_evidence(
            original=self.original,
            machine_ir=self.machine,
            catalog_lock=self.root / "empty-lock.json",
            review=review,
            out=self.root / "complement-evidence.json",
        )
        hypotheses = infer_library_hypotheses(
            match_evidence=evidence,
            out=self.root / "complement-hypotheses.json",
        )
        manifest = refine_linked_islands(
            original=self.original,
            machine_ir=self.machine,
            match_evidence=self.root / "complement-evidence.json",
            hypotheses=self.root / "complement-hypotheses.json",
            review=review,
            out=self.root / "refined-complement.json",
        )

        validate_linked_island_manifest(manifest)
        self.assertEqual(manifest["coverage"]["unknown_units"], 0)
        complement = next(
            row
            for row in manifest["islands"]
            if row["id"] == "compiler-linker-support:reviewed-complement"
        )
        self.assertEqual(complement["kind"], "linked_dependency")
        self.assertFalse(
            manifest["authority"]["artifact_recognition_authorizes_replacement"]
        )
        self.assertTrue(
            manifest["authority"]["reviewed_complement_binds_ownership_only"]
        )
        self.assertIn(hypotheses["status"], {"inferred", "incomplete"})

    def test_reviewed_complement_corruption_fails_closed(self) -> None:
        manifest = match_linked_islands(
            original=self.original,
            machine_ir=self.machine,
            catalog_lock=None,
            review=self._review_with_complement(),
            out=self.root / "bound-complement.json",
        )
        corrupted = json.loads(json.dumps(manifest))
        corrupted["reviewed_unclaimed_exact_units"]["exact_bindings"][
            "machine_ir_sha256"
        ] = "0" * 64
        core = dict(corrupted)
        core.pop("manifest_sha256")
        corrupted["manifest_sha256"] = _canonical_sha256(core)

        with self.assertRaisesRegex(LinkedLibraryError, "stale"):
            validate_linked_island_manifest(corrupted)

    def test_reviewed_complement_schema_rejects_replacement_authority(self) -> None:
        payload = {
            "format": LINKED_ISLAND_REVIEW_FORMAT,
            "original_binary_sha256": sha256_file(self.original),
            "islands": [],
            "unclaimed_exact_units": self._complement_policy(),
        }
        payload["unclaimed_exact_units"]["replacement_authorized"] = True

        with self.assertRaisesRegex(LinkedLibraryError, "may not authorize"):
            bind_linked_island_review(payload)

    def test_match_evidence_accepts_canonical_machine_ir_jsonl_path(self) -> None:
        evidence = propose_library_match_evidence(
            original=self.original,
            machine_ir=self.machine / "machine-ir.jsonl",
            catalog_lock=None,
            review=None,
            out=self.root / "jsonl-evidence.json",
        )

        self.assertEqual(evidence["status"], "proposed")
        self.assertIsNone(evidence["bindings"]["catalog_lock_sha256"])

    def test_ambiguous_library_identity_fails_closed(self) -> None:
        obj = _coff_object(_FUNCTION, symbol="_runtime")
        (self.artifacts / "one.obj").write_bytes(obj)
        (self.artifacts / "two.obj").write_bytes(obj)
        index_paths = []
        for name in ("one", "two"):
            inputs = bind_library_artifact_inputs(
                {
                    "format": LIBRARY_ARTIFACT_INPUTS_FORMAT,
                    "catalog_id": name,
                    "artifacts": [{"id": name, "path": f"{name}.obj"}],
                }
            )
            path = self.root / f"{name}-index.json"
            index_library_artifacts(
                inputs=inputs,
                artifact_root=self.artifacts,
                out=path,
            )
            index_paths.append(path)
        lock = lock_library_catalog(indexes=index_paths, out=self.root / "lock.json")
        manifest = match_linked_islands(
            original=self.original,
            machine_ir=self.machine,
            catalog_lock=self.root / "lock.json",
            review=None,
            out=self.root / "linked-islands.json",
        )

        self.assertEqual(lock["counts"]["catalogs"], 2)
        self.assertEqual(manifest["status"], "incomplete")
        self.assertEqual(manifest["counts"]["ambiguous_artifact_matches"], 1)
        self.assertGreater(manifest["coverage"]["unknown_units"], 0)
        self.assertEqual(manifest["issues"][0]["code"], "ambiguous_artifact_match")

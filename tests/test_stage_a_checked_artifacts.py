from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.errors import StageAInputError
from spaghetti_extractor.relational.build import (
    _validate_checked_artifact_source_boundaries,
)
from spaghetti_extractor.relational.checked_artifacts import (
    CHECKED_ARTIFACT_MANIFEST_FORMAT,
    CheckedArtifactIdentity,
    CheckedArtifactKind,
    CheckedArtifactManifest,
    CheckedArtifactRecord,
    checked_image_identity,
    diff_checked_artifact_manifests,
)
from spaghetti_extractor.relational.lean.generation import (
    _checked_semantic_pack_index,
)
from spaghetti_extractor.relational.lean.axiom_audit import (
    _separate_axiom_audit_declaration,
)
from spaghetti_extractor.relational.schema import SchemaError


_ZERO = "0" * 64
_ONE = "1" * 64


class StageACheckedArtifactTests(unittest.TestCase):
    @staticmethod
    def _record(identity: CheckedArtifactIdentity) -> CheckedArtifactRecord:
        return CheckedArtifactRecord(
            identity=identity,
            modules=(identity.semantic_key.replace(":", "_"),),
            exported_theorems=(),
            native_decision_theorems=(),
            acceptance_authority=False,
            metadata={},
        )

    def test_identity_is_canonical_and_tampering_fails_closed(self) -> None:
        identity = CheckedArtifactIdentity.create(
            kind=CheckedArtifactKind.REGION_SEMANTICS,
            semantic_key="region:original:00401000",
            dependency_ids=("b" * 64, "a" * 64, "b" * 64),
            relevant_input_sha256=_ZERO,
            normalized_data_sha256=_ONE,
        )
        self.assertEqual(identity.dependency_ids, ("a" * 64, "b" * 64))
        self.assertEqual(
            CheckedArtifactIdentity.parse(identity.payload()),
            identity,
        )

        tampered = identity.payload()
        tampered["semantic_key"] = "region:original:00401001"
        with self.assertRaisesRegex(SchemaError, "digest mismatch"):
            CheckedArtifactIdentity.parse(tampered)

    def test_image_identity_distinguishes_proof_sides(self) -> None:
        original = checked_image_identity(side="original", binary_sha256=_ZERO)
        candidate = checked_image_identity(side="candidate", binary_sha256=_ZERO)
        self.assertNotEqual(original.artifact_id, candidate.artifact_id)

    def test_semantic_pack_is_stable_across_region_content_changes(self) -> None:
        before = CheckedArtifactIdentity.create(
            kind=CheckedArtifactKind.REGION_SEMANTICS,
            semantic_key="pe32-region:candidate:00401000:4",
            dependency_ids=(),
            relevant_input_sha256=_ZERO,
            normalized_data_sha256=_ZERO,
        )
        after = CheckedArtifactIdentity.create(
            kind=CheckedArtifactKind.REGION_SEMANTICS,
            semantic_key=before.semantic_key,
            dependency_ids=(),
            relevant_input_sha256=_ONE,
            normalized_data_sha256=_ONE,
        )

        self.assertNotEqual(before.artifact_id, after.artifact_id)
        self.assertEqual(
            _checked_semantic_pack_index(before, pack_count=64),
            _checked_semantic_pack_index(after, pack_count=64),
        )

    def test_separate_axiom_audit_selects_exact_acceptance_theorem(self) -> None:
        ordinary = _separate_axiom_audit_declaration(
            bundle="RelationalAcceptance",
            bundle_source=(
                "theorem candidatePE32ProgramsEquivalent : True := by trivial\n"
            ),
        )
        linked = _separate_axiom_audit_declaration(
            bundle="RelationalAcceptance",
            bundle_source=(
                "theorem candidatePE32ProgramsEquivalentLinked : True := by trivial\n"
            ),
        )
        both = _separate_axiom_audit_declaration(
            bundle="RelationalAcceptance",
            bundle_source=(
                "theorem candidatePE32ProgramsEquivalent : True := by trivial\n"
                "theorem candidatePE32ProgramsEquivalentLinked : True := by trivial\n"
            ),
        )

        self.assertEqual(
            ordinary,
            "StageA.GeneratedRelational.candidatePE32ProgramsEquivalent",
        )
        self.assertEqual(
            linked,
            "StageA.GeneratedRelational.candidatePE32ProgramsEquivalentLinked",
        )
        self.assertEqual(both, linked)

    def test_manifest_rejects_missing_dependency(self) -> None:
        identity = CheckedArtifactIdentity.create(
            kind=CheckedArtifactKind.REGION_DECODE,
            semantic_key="binding:original:00401000",
            dependency_ids=("a" * 64,),
            relevant_input_sha256=_ZERO,
            normalized_data_sha256=_ONE,
        )
        payload = {
            "format": CHECKED_ARTIFACT_MANIFEST_FORMAT,
            "model": "x86-pe32-relational-v3",
            "machine_semantics_version": _ZERO,
            "authoritative": False,
            "artifacts": [{
                "acceptance_authority": False,
                "exported_theorems": [],
                "identity": identity.payload(),
                "metadata": {},
                "modules": ["RelationalProofOriginalDecodeChunk0"],
                "native_decision_theorems": [],
            }],
        }
        with self.assertRaisesRegex(SchemaError, "missing dependencies"):
            CheckedArtifactManifest.parse(payload)

    def test_manifest_diff_exposes_region_local_semantic_reuse(self) -> None:
        before_image = checked_image_identity(
            side="candidate", binary_sha256=_ZERO
        )
        after_image = checked_image_identity(
            side="candidate", binary_sha256=_ONE
        )
        changed_before = CheckedArtifactIdentity.create(
            kind=CheckedArtifactKind.REGION_SEMANTICS,
            semantic_key="pe32-region:candidate:00401000:4",
            dependency_ids=(),
            relevant_input_sha256=_ZERO,
            normalized_data_sha256=_ZERO,
        )
        changed_after = CheckedArtifactIdentity.create(
            kind=CheckedArtifactKind.REGION_SEMANTICS,
            semantic_key="pe32-region:candidate:00401000:4",
            dependency_ids=(),
            relevant_input_sha256=_ONE,
            normalized_data_sha256=_ONE,
        )
        reused = CheckedArtifactIdentity.create(
            kind=CheckedArtifactKind.REGION_SEMANTICS,
            semantic_key="pe32-region:candidate:00402000:4",
            dependency_ids=(),
            relevant_input_sha256=_ZERO,
            normalized_data_sha256=_ZERO,
        )
        binding_before = CheckedArtifactIdentity.create(
            kind=CheckedArtifactKind.REGION_DECODE,
            semantic_key="pe32-region-binding:candidate:00402000:4",
            dependency_ids=(before_image.artifact_id, reused.artifact_id),
            relevant_input_sha256=_ZERO,
            normalized_data_sha256=_ZERO,
        )
        binding_after = CheckedArtifactIdentity.create(
            kind=CheckedArtifactKind.REGION_DECODE,
            semantic_key="pe32-region-binding:candidate:00402000:4",
            dependency_ids=(after_image.artifact_id, reused.artifact_id),
            relevant_input_sha256=_ONE,
            normalized_data_sha256=_ZERO,
        )

        def manifest(*identities: CheckedArtifactIdentity) -> CheckedArtifactManifest:
            return CheckedArtifactManifest(
                model="x86-pe32-relational-v3",
                machine_semantics_version=_ZERO,
                authoritative=False,
                artifacts=tuple(self._record(identity) for identity in identities),
            )

        diff = diff_checked_artifact_manifests(
            manifest(before_image, changed_before, reused, binding_before),
            manifest(after_image, changed_after, reused, binding_after),
        )

        self.assertEqual(
            diff.reused,
            ("checked-region-semantics:pe32-region:candidate:00402000:4",),
        )
        self.assertEqual(len(diff.changed), 3)
        self.assertEqual(diff.added, ())
        self.assertEqual(diff.removed, ())

    def test_semantic_leaf_cannot_import_broad_image_or_definition_data(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "RelationalProofOriginalSemanticChunk0.lean"
            source.write_text(
                "import StageA.RelationalProofOriginal\n"
                "def checked := CheckedLocalRegionSemantics\n"
                "def replay := input.evaluate\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(StageAInputError, "imports broad artifacts"):
                _validate_checked_artifact_source_boundaries(
                    {source.stem: source}
                )

    def test_only_image_binding_may_name_full_pe_replay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            downstream = root / "RelationalProofDirectChunk0.lean"
            downstream.write_text(
                "def bad := regionBehaviorWithMachineCallContracts\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(StageAInputError, "replays raw"):
                _validate_checked_artifact_source_boundaries(
                    {downstream.stem: downstream}
                )

            binding = root / "RelationalProofOriginalDecodeChunk0.lean"
            binding.write_text(
                "def exact := regionBehaviorWithMachineCallContracts\n",
                encoding="utf-8",
            )
            _validate_checked_artifact_source_boundaries(
                {binding.stem: binding}
            )

    def test_downstream_may_restate_only_an_imported_decoded_fact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            restatement = root / "RelationalExternalCallRefinementEdge0.lean"
            restatement.write_text(
                "theorem restated :\n"
                "    regionBehaviorWithMachineCallContracts pe imports "
                "contracts span = some behavior := by\n"
                "  simpa using originalBehavior0CheckedDecoded\n",
                encoding="utf-8",
            )
            _validate_checked_artifact_source_boundaries(
                {restatement.stem: restatement}
            )

            replay = root / "RelationalSegmentRefinementChunk0.lean"
            replay.write_text(
                "theorem replayed :\n"
                "    regionBehaviorWithMachineCallContracts pe imports "
                "contracts span = some behavior := by decide\n"
                "theorem marker := originalBehavior0CheckedDecoded\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(StageAInputError, "replays raw"):
                _validate_checked_artifact_source_boundaries(
                    {replay.stem: replay}
                )


if __name__ == "__main__":
    unittest.main()

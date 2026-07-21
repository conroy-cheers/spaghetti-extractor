import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.proposal_artifact import (
    RELATIONAL_PROPOSAL_MANIFEST,
    RELATIONAL_PROPOSAL_REQUIRED_FILES,
    copy_relational_proposal,
    validate_relational_proposal,
    write_relational_proposal_manifest,
)
from spaghetti_extractor.stage_binary import StageAInputError
from spaghetti_extractor.util import sha256_file


class StageARelationalProposalArtifactTests(unittest.TestCase):
    def _tree(self, root: Path) -> tuple[str, str]:
        for relative in RELATIONAL_PROPOSAL_REQUIRED_FILES:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(
                b"original" if relative == "artifacts/original.pe"
                else b"candidate" if relative == "artifacts/candidate.pe"
                else b"{}\n"
            )
        return (
            sha256_file(root / "artifacts/original.pe"),
            sha256_file(root / "artifacts/candidate.pe"),
        )

    def test_manifest_is_exact_copyable_and_tamper_evident(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proposal = root / "proposal"
            copied = root / "copied"
            original_sha256, candidate_sha256 = self._tree(proposal)
            payload = write_relational_proposal_manifest(
                proposal,
                original_sha256=original_sha256,
                candidate_sha256=candidate_sha256,
            )
            self.assertFalse(payload["acceptance_authority"])
            manifest = validate_relational_proposal(proposal)
            copy_relational_proposal(proposal, copied)
            self.assertEqual(validate_relational_proposal(copied), manifest)

            (copied / "relational-register-relations.json").write_text(
                '{"tampered":true}\n', encoding="utf-8"
            )
            with self.assertRaisesRegex(StageAInputError, "hash mismatch"):
                validate_relational_proposal(copied)

    def test_unknown_file_and_manifest_field_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            proposal = Path(temporary)
            original_sha256, candidate_sha256 = self._tree(proposal)
            (proposal / "unexpected.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(StageAInputError, "unexpected"):
                write_relational_proposal_manifest(
                    proposal,
                    original_sha256=original_sha256,
                    candidate_sha256=candidate_sha256,
                )
            (proposal / "unexpected.json").unlink()
            write_relational_proposal_manifest(
                proposal,
                original_sha256=original_sha256,
                candidate_sha256=candidate_sha256,
            )
            manifest_path = proposal / RELATIONAL_PROPOSAL_MANIFEST
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
            payload["unchecked"] = True
            manifest_path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(StageAInputError, "fields do not match"):
                validate_relational_proposal(proposal)


if __name__ == "__main__":
    unittest.main()

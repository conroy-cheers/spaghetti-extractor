import sys
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.errors import StageAInputError
from spaghetti_extractor.relational.analysis_artifact import (
    RELATIONAL_ANALYSIS_REQUIRED_FILES,
    validate_relational_analysis,
    write_relational_analysis_manifest,
)
from spaghetti_extractor.relational.analysis_reference import (
    immutable_nix_store_file,
    materialize_relational_analysis_view,
    validate_relational_analysis_view,
)
from spaghetti_extractor.util import sha256_file


class StageARelationalAnalysisReferenceTests(unittest.TestCase):
    def _tree(self, root: Path) -> None:
        for relative in RELATIONAL_ANALYSIS_REQUIRED_FILES:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(
                b"original" if relative == "artifacts/original.pe"
                else b"candidate" if relative == "artifacts/candidate.pe"
                else b"{}\n"
            )

    def _manifest(self, root: Path) -> None:
        write_relational_analysis_manifest(
            root,
            original_sha256=sha256_file(root / "artifacts" / "original.pe"),
            candidate_sha256=sha256_file(root / "artifacts" / "candidate.pe"),
        )

    def test_mutable_symlink_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            analysis = root / "analysis"
            self._tree(analysis)
            target = root / "mutable.json"
            target.write_text("{}\n", encoding="utf-8")
            linked = analysis / "semantic-gaps.json"
            linked.unlink()
            linked.symlink_to(target)
            self._manifest(analysis)
            with self.assertRaisesRegex(
                StageAInputError, "not an immutable Nix store file"
            ):
                validate_relational_analysis_view(analysis)

    def test_hashed_nix_store_reference_can_be_materialized(self) -> None:
        store_source = immutable_nix_store_file(Path(sys.executable))
        if store_source is None:
            self.skipTest("test interpreter is not in the immutable Nix store")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            analysis = root / "analysis"
            materialized = root / "materialized"
            self._tree(analysis)
            linked = analysis / "semantic-gaps.json"
            linked.unlink()
            linked.symlink_to(store_source)
            self._manifest(analysis)

            validate_relational_analysis_view(analysis)
            with self.assertRaisesRegex(StageAInputError, "missing"):
                validate_relational_analysis(analysis)
            materialize_relational_analysis_view(analysis, materialized)
            self.assertFalse(
                (materialized / "semantic-gaps.json").is_symlink()
            )
            validate_relational_analysis(materialized)


if __name__ == "__main__":
    unittest.main()

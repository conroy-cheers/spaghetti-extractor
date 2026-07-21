import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.errors import StageAInputError
from spaghetti_extractor.relational.semantic_products_artifact import (
    INVARIANTS_FILE,
    SEMANTIC_IR_FILE,
    validate_semantic_products,
    write_semantic_products_manifest,
)


class StageASemanticProductsArtifactTests(unittest.TestCase):
    def _artifact(self, root: Path):
        root.mkdir(parents=True)
        (root / SEMANTIC_IR_FILE).write_text(
            '{"format":"semantic"}\n', encoding="utf-8"
        )
        (root / INVARIANTS_FILE).write_text(
            '{"format":"invariants"}\n', encoding="utf-8"
        )
        return write_semantic_products_manifest(
            root,
            original_sha256="a" * 64,
            candidate_sha256="b" * 64,
            proposal_closure_sha256="c" * 64,
            relation_contract_sha256="d" * 64,
            decoded_behaviors_sha256="e" * 64,
        )

    def test_manifest_binds_proposal_inputs_and_products(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "products"
            payload = self._artifact(root)
            manifest = validate_semantic_products(
                root,
                expected_proposal_closure_sha256="c" * 64,
                expected_original_sha256="a" * 64,
                expected_candidate_sha256="b" * 64,
                expected_relation_contract_sha256="d" * 64,
                expected_decoded_behaviors_sha256="e" * 64,
            )
            self.assertFalse(payload["acceptance_authority"])
            self.assertEqual(manifest.products_sha256, payload["products_sha256"])

            (root / SEMANTIC_IR_FILE).write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(StageAInputError, "hash mismatch"):
                validate_semantic_products(root)

    def test_unknown_file_and_wrong_input_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "products"
            self._artifact(root)
            (root / "unchecked.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(StageAInputError, "inventory"):
                validate_semantic_products(root)
            (root / "unchecked.json").unlink()
            with self.assertRaisesRegex(StageAInputError, "does not match"):
                validate_semantic_products(
                    root,
                    expected_decoded_behaviors_sha256="f" * 64,
                )


if __name__ == "__main__":
    unittest.main()

import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.errors import StageAInputError
from spaghetti_extractor.relational.composition_products_artifact import (
    COMPOSITION_PRODUCTS_REQUIRED_FILES,
    validate_composition_products,
    write_composition_products_manifest,
)


class StageACompositionProductsArtifactTests(unittest.TestCase):
    def _artifact(
        self,
        root: Path,
        *,
        original_isa_sha256: str | None = None,
        candidate_isa_sha256: str | None = None,
    ):
        root.mkdir(parents=True)
        for index, relative in enumerate(
            sorted(COMPOSITION_PRODUCTS_REQUIRED_FILES)
        ):
            (root / relative).write_text(
                f'{{"artifact":{index}}}\n', encoding="utf-8"
            )
        return write_composition_products_manifest(
            root,
            original_sha256="a" * 64,
            candidate_sha256="b" * 64,
            proposal_closure_sha256="c" * 64,
            register_replay_sha256="d" * 64,
            semantic_products_sha256="e" * 64,
            memory_products_sha256="f" * 64,
            original_isa_sha256=original_isa_sha256,
            candidate_isa_sha256=candidate_isa_sha256,
        )

    def test_manifest_binds_all_upstream_products(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "products"
            payload = self._artifact(root)
            manifest = validate_composition_products(
                root,
                expected_proposal_closure_sha256="c" * 64,
                expected_register_replay_sha256="d" * 64,
                expected_semantic_products_sha256="e" * 64,
                expected_memory_products_sha256="f" * 64,
                expected_original_sha256="a" * 64,
                expected_candidate_sha256="b" * 64,
            )
            self.assertFalse(payload["acceptance_authority"])
            self.assertEqual(manifest.isa_mode, "lean_extracted")
            self.assertEqual(
                manifest.products_sha256, payload["products_sha256"]
            )

    def test_product_tampering_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "products"
            self._artifact(root)
            (root / "relational-product-graph.json").write_text(
                "{}\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(StageAInputError, "hash mismatch"):
                validate_composition_products(root)

    def test_unknown_file_and_wrong_upstream_digest_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "products"
            self._artifact(root)
            (root / "unchecked.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(StageAInputError, "inventory"):
                validate_composition_products(root)
            (root / "unchecked.json").unlink()
            for field in (
                "expected_register_replay_sha256",
                "expected_semantic_products_sha256",
                "expected_memory_products_sha256",
            ):
                with self.subTest(field=field):
                    with self.assertRaisesRegex(
                        StageAInputError, "does not match"
                    ):
                        validate_composition_products(
                            root, **{field: "1" * 64}
                        )

    def test_side_isa_mode_is_explicit_and_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "products"
            self._artifact(
                root,
                original_isa_sha256="1" * 64,
                candidate_isa_sha256="2" * 64,
            )
            manifest = validate_composition_products(
                root,
                expected_original_isa_sha256="1" * 64,
                expected_candidate_isa_sha256="2" * 64,
            )
            self.assertEqual(manifest.isa_mode, "side_artifacts")
            with self.assertRaisesRegex(StageAInputError, "does not match"):
                validate_composition_products(
                    root,
                    expected_original_isa_sha256="3" * 64,
                )

    def test_one_sided_isa_binding_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "products"
            root.mkdir(parents=True)
            for relative in COMPOSITION_PRODUCTS_REQUIRED_FILES:
                (root / relative).write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(StageAInputError, "incomplete"):
                write_composition_products_manifest(
                    root,
                    original_sha256="a" * 64,
                    candidate_sha256="b" * 64,
                    proposal_closure_sha256="c" * 64,
                    register_replay_sha256="d" * 64,
                    semantic_products_sha256="e" * 64,
                    memory_products_sha256="f" * 64,
                    original_isa_sha256="1" * 64,
                    candidate_isa_sha256=None,
                )


if __name__ == "__main__":
    unittest.main()

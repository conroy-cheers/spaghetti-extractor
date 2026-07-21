import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.errors import StageAInputError
from spaghetti_extractor.relational.register_replay_artifact import (
    REGISTER_REPLAY_MANIFEST,
    REGISTER_REPLAY_RELATIONS,
    validate_register_replay,
    write_register_replay_manifest,
)


class StageARegisterReplayArtifactTests(unittest.TestCase):
    def _artifact(self, root: Path):
        root.mkdir(parents=True)
        (root / REGISTER_REPLAY_RELATIONS).write_text(
            '{"format":"test-relations"}\n', encoding="utf-8"
        )
        return write_register_replay_manifest(
            root,
            original_sha256="a" * 64,
            candidate_sha256="b" * 64,
            proposal_closure_sha256="c" * 64,
            aggregate_sha256="d" * 64,
            aggregate_file_sha256="e" * 64,
        )

    def test_manifest_binds_inputs_and_relation_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "replay"
            payload = self._artifact(root)
            manifest = validate_register_replay(
                root,
                expected_proposal_closure_sha256="c" * 64,
                expected_original_sha256="a" * 64,
                expected_candidate_sha256="b" * 64,
            )
            self.assertFalse(payload["acceptance_authority"])
            self.assertEqual(manifest.aggregate_sha256, "d" * 64)

            (root / REGISTER_REPLAY_RELATIONS).write_text(
                '{"format":"tampered"}\n', encoding="utf-8"
            )
            with self.assertRaisesRegex(StageAInputError, "hash mismatch"):
                validate_register_replay(root)

    def test_unknown_files_fields_and_wrong_proposal_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "replay"
            self._artifact(root)
            (root / "unchecked.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(StageAInputError, "inventory"):
                validate_register_replay(root)
            (root / "unchecked.json").unlink()

            manifest_path = root / REGISTER_REPLAY_MANIFEST
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
            payload["unchecked"] = True
            manifest_path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(StageAInputError, "fields do not match"):
                validate_register_replay(root)

            self._artifact(root.parent / "fresh")
            with self.assertRaisesRegex(StageAInputError, "does not match"):
                validate_register_replay(
                    root.parent / "fresh",
                    expected_proposal_closure_sha256="f" * 64,
                )


if __name__ == "__main__":
    unittest.main()

import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.workspace import workspace_prune


class WorkspacePruneTests(unittest.TestCase):
    def test_dry_run_preserves_source_and_apply_removes_only_disposable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "candidate" / "src"
            cache = root / "candidate" / "candidate-validation-cache"
            prefix = root / "fixture-wineprefix"
            source.mkdir(parents=True)
            cache.mkdir(parents=True)
            prefix.mkdir()
            (source / "candidate.c").write_text("int main(void) { return 0; }\n")
            (cache / "report.json").write_text("{}\n")
            (prefix / "state").write_text("runtime\n")

            dry_run = workspace_prune(root=root)
            self.assertEqual(dry_run["status"], "dry_run")
            self.assertEqual(dry_run["counts"]["directories"], 2)
            self.assertTrue(source.is_dir())
            self.assertTrue(cache.is_dir())

            applied = workspace_prune(root=root, apply=True)
            self.assertEqual(applied["status"], "pruned")
            self.assertTrue(source.is_dir())
            self.assertFalse(cache.exists())
            self.assertFalse(prefix.exists())

    def test_explicit_path_cannot_escape_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(ValueError, "escapes"):
                workspace_prune(root=root, include=[Path("../outside")])


if __name__ == "__main__":
    unittest.main()

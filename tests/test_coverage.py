import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from haloce_catalog import coverage
from haloce_catalog.coverage import parse_drcov_log, resolve_observed_path


class DrcovParserTests(unittest.TestCase):
    def test_parse_text_log(self):
        log = parse_drcov_log(Path("tests/fixtures/drcov_text.log"))
        self.assertEqual(len(log.modules), 2)
        self.assertEqual(log.modules[0].path, r"C:\Program Files (x86)\Microsoft Games\Halo Custom Edition\haloce.exe")
        self.assertEqual(len(log.blocks), 3)
        self.assertEqual(log.blocks[1].module_id, 0)
        self.assertEqual(log.blocks[1].start, 0x1020)
        self.assertEqual(log.blocks[1].size, 12)

    def test_parse_binary_block_table(self):
        payload = (
            b"DRCOV VERSION: 2\n"
            b"DRCOV FLAVOR: drcov\n"
            b"Module Table: version 2, count 1\n"
            b"Columns: id, containing_id, start, end, entry, offset, preferred_base, path\n"
            b" 0, 0, 0x400000, 0x410000, 0x401000, 0x0, 0x400000, test.exe\n"
            b"BB Table: 1 bbs\n"
            + (0x1234).to_bytes(4, "little")
            + (9).to_bytes(2, "little")
            + (0).to_bytes(2, "little")
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "drcov.log"
            path.write_bytes(payload)
            log = parse_drcov_log(path)
        self.assertEqual(len(log.modules), 1)
        self.assertEqual(len(log.blocks), 1)
        self.assertEqual(log.blocks[0].start, 0x1234)
        self.assertEqual(log.blocks[0].size, 9)

    def test_resolve_wine_c_path_against_install_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "drive_c" / "Program Files (x86)" / "Microsoft Games" / "Halo Custom Edition" / "haloce.exe"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"MZ")
            resolved = resolve_observed_path(
                r"C:\Program Files (x86)\Microsoft Games\Halo Custom Edition\haloce.exe",
                install_root=root,
            )
        self.assertEqual(resolved, target)

    def test_doctor_uses_resolved_true_executable(self):
        with tempfile.TemporaryDirectory() as tmp:
            true_path = Path(tmp) / "true"
            true_path.write_text("")
            true_path.chmod(0o755)

            completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
            with (
                mock.patch.object(coverage.shutil, "which", return_value=str(true_path)),
                mock.patch.object(coverage.subprocess, "run", return_value=completed) as run,
            ):
                result = coverage.doctor_drcov()

        command = run.call_args.args[0]
        self.assertEqual(command[-1], str(true_path))
        self.assertEqual(result["smoke_executable"], str(true_path))
        self.assertTrue(result["ok"])


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import unittest

import pefile

from spaghetti_extractor.testkit import fixture


TESTKIT = {"fixtures": ["pe32-minimal-import-call"]}


class MinimalPEFixtureTests(unittest.TestCase):
    def test_shared_fixture_is_pe32_and_imports_write_file(self) -> None:
        executable = fixture("pe32-minimal-import-call") / "minimal-import-call.exe"
        image = pefile.PE(str(executable), fast_load=False)

        self.assertEqual(image.FILE_HEADER.Machine, 0x14C)
        symbols = {
            imported.name.decode("ascii")
            for descriptor in image.DIRECTORY_ENTRY_IMPORT
            for imported in descriptor.imports
            if imported.name is not None
        }
        self.assertIn("WriteFile", symbols)


if __name__ == "__main__":
    unittest.main()

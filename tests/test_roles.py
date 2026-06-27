import unittest

from haloce_catalog.roles import classify_pe


class RoleTests(unittest.TestCase):
    def test_primary_runtime_binaries_are_included(self):
        self.assertEqual(classify_pe("drive_c/Program Files (x86)/Microsoft Games/Halo Custom Edition/haloce.exe").scope, "included")
        self.assertEqual(classify_pe("drive_c/Program Files (x86)/Microsoft Games/Halo Custom Edition/haloceded.exe").scope, "included")

    def test_source_available_and_installer_tools_are_excluded(self):
        self.assertEqual(classify_pe("game/ogg.dll").role, "source_available_external")
        self.assertEqual(classify_pe("game/redist/instmsiw.exe").scope, "excluded")

    def test_wine_platform_runtime_is_excluded(self):
        decision = classify_pe("drive_c/windows/syswow64/kernel32.dll")
        self.assertEqual(decision.role, "platform_runtime")
        self.assertEqual(decision.scope, "excluded")

    def test_shared_components_and_old_updaters_are_excluded(self):
        self.assertEqual(
            classify_pe("drive_c/Program Files (x86)/Common Files/Microsoft Shared/Ink/inkobj.dll").scope,
            "excluded",
        )
        self.assertEqual(
            classify_pe("drive_c/users/nixbld/AppData/Local/Temp/old haloupdate.exe").scope,
            "excluded",
        )


if __name__ == "__main__":
    unittest.main()

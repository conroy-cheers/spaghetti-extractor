import unittest

from haloce_catalog.mocks import MockClock, MockConsole, MockFileSystem, MockRegistry, MockWinsock


class MockTests(unittest.TestCase):
    def test_file_system_is_case_insensitive(self):
        fs = MockFileSystem()
        fs.mkdir(r"C:\Games")
        fs.write_bytes(r"C:\Games\Config.txt", b"sv_name test")
        self.assertTrue(fs.exists(r"c:\games\config.TXT"))
        self.assertEqual(fs.read_bytes(r"c:\games\config.txt"), b"sv_name test")
        self.assertEqual(fs.listdir(r"C:\Games"), ["config.txt"])

    def test_registry_typed_values(self):
        registry = MockRegistry()
        registry.set_value(r"HKCU\Software\Microsoft\Microsoft Games\Halo CE", "Version", "1.10")
        self.assertEqual(registry.get_value(r"hkcu\software\microsoft\microsoft games\halo ce", "version"), "1.10")
        self.assertIn("version", registry.export_json())

    def test_clock_console_and_winsock(self):
        clock = MockClock()
        clock.advance_ms(25)
        self.assertEqual(clock.get_tick_count(), 25)

        console = MockConsole()
        console.stdin.append("quit")
        self.assertEqual(console.read_line(), "quit")
        console.write_stdout("ok")
        self.assertEqual(console.stdout, ["ok"])

        winsock = MockWinsock()
        winsock.sendto(("127.0.0.1", 2302), ("127.0.0.1", 2303), b"ping")
        source, payload = winsock.recvfrom(("127.0.0.1", 2303))
        self.assertEqual(source, ("127.0.0.1", 2302))
        self.assertEqual(payload, b"ping")


if __name__ == "__main__":
    unittest.main()

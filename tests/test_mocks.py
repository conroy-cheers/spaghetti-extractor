import unittest

from haloce_catalog.mocks import (
    DisplayMode,
    MockBink,
    MockClock,
    MockConsole,
    MockDirectInput,
    MockDirectSound,
    MockFileSystem,
    MockGraphics,
    MockNetworkServices,
    MockRegistry,
    MockRuntime,
    MockThreading,
    MockWinsock,
)


class MockTests(unittest.TestCase):
    def test_file_system_is_case_insensitive(self):
        fs = MockFileSystem()
        fs.mkdir(r"C:\Games")
        fs.write_bytes(r"C:\Games\Config.txt", b"sv_name test")
        self.assertTrue(fs.exists(r"c:\games\config.TXT"))
        self.assertEqual(fs.read_bytes(r"c:\games\config.txt"), b"sv_name test")
        self.assertEqual(fs.listdir(r"C:\Games"), ["config.txt"])

    def test_file_system_handles_read_write_seek_close_and_errors(self):
        fs = MockFileSystem()
        fs.mkdir(r"C:\Games")
        handle = fs.create_file(
            r"C:\Games\config.txt",
            desired_access="readwrite",
            creation_disposition="create_always",
        )
        self.assertEqual(fs.write_file(handle, b"abcd"), 4)
        self.assertEqual(fs.get_file_size(handle), 4)
        fs.set_file_pointer(handle, -2, origin="end")
        self.assertEqual(fs.read_file(handle), b"cd")
        fs.close_handle(handle)
        with self.assertRaises(KeyError):
            fs.read_file(handle)
        self.assertEqual(fs.last_error, "ERROR_INVALID_HANDLE")

        with self.assertRaises(FileNotFoundError):
            fs.create_file(r"C:\Games\missing.txt")
        self.assertEqual(fs.last_error, "ERROR_FILE_NOT_FOUND")

        write_only = fs.create_file(
            r"C:\Games\write-only.txt",
            desired_access="write",
            creation_disposition="create_always",
        )
        with self.assertRaises(PermissionError):
            fs.read_file(write_only)
        self.assertEqual(fs.last_error, "ERROR_ACCESS_DENIED")

    def test_registry_typed_values(self):
        registry = MockRegistry()
        registry.set_value(r"HKCU\Software\Microsoft\Microsoft Games\Halo CE", "Version", "1.10")
        self.assertEqual(registry.get_value(r"hkcu\software\microsoft\microsoft games\halo ce", "version"), "1.10")
        self.assertIn("version", registry.export_json())

    def test_clock_console_and_winsock(self):
        clock = MockClock()
        clock.advance_ms(25)
        self.assertEqual(clock.get_tick_count(), 25)
        clock.sleep(5)
        self.assertEqual(clock.query_performance_counter(), 30000)
        self.assertEqual(clock.query_performance_frequency(), 1_000_000)

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

    def test_threading_thread_event_wait_and_timeout_paths(self):
        threading = MockThreading()
        thread_id = threading.create_thread("loader", start_suspended=True)
        with self.assertRaises(TimeoutError):
            threading.wait_for_thread(thread_id, timeout_ms=0)
        threading.resume_thread(thread_id)
        threading.exit_thread(thread_id, exit_code=7)
        self.assertEqual(threading.wait_for_thread(thread_id), 7)

        auto_event = threading.create_event(name="tick", initial_state=True)
        self.assertTrue(threading.wait_for_event(auto_event))
        with self.assertRaises(TimeoutError):
            threading.wait_for_event(auto_event, timeout_ms=0)

        manual_event = threading.create_event(manual_reset=True)
        threading.set_event(manual_event)
        self.assertTrue(threading.wait_for_event(manual_event))
        self.assertTrue(threading.wait_for_event(manual_event))
        threading.reset_event(manual_event)
        with self.assertRaises(TimeoutError):
            threading.wait_for_event(manual_event, timeout_ms=0)

    def test_graphics_window_gamma_and_lost_device_paths(self):
        graphics = MockGraphics()
        self.assertIn(DisplayMode(800, 600, 32, 60), graphics.enumerate_modes())
        graphics.set_display_mode(DisplayMode(800, 600, 32, 60))
        handle = graphics.create_window("Halo", 800, 600)
        graphics.set_focus(handle)
        self.assertTrue(graphics.windows[handle].focused)
        graphics.set_gamma_ramp([128] * 256)
        self.assertEqual(graphics.gamma_ramp[0], 128)
        graphics.lose_device()
        with self.assertRaisesRegex(RuntimeError, "lost"):
            graphics.present()
        graphics.reset_device()
        graphics.present()
        with self.assertRaises(ValueError):
            graphics.set_display_mode(DisplayMode(320, 200, 16, 70))

    def test_direct_input_acquire_poll_and_buffered_events(self):
        direct_input = MockDirectInput()
        direct_input.add_device("Keyboard", "keyboard")
        self.assertEqual(direct_input.enumerate_devices("keyboard"), ["Keyboard"])
        direct_input.set_state("Keyboard", "DIK_W", 1)
        with self.assertRaises(PermissionError):
            direct_input.poll("Keyboard")
        direct_input.acquire("Keyboard")
        self.assertEqual(direct_input.poll("Keyboard"), {"DIK_W": 1})
        self.assertEqual(direct_input.read_buffered("Keyboard"), [("DIK_W", 1)])
        self.assertEqual(direct_input.read_buffered("Keyboard"), [])

    def test_direct_sound_buffer_lifecycle_and_failure_paths(self):
        sound = MockDirectSound()
        sound.add_device("Primary Sound Driver")
        buffer_id = sound.create_buffer("Primary Sound Driver", b"\x00\x01")
        sound.play(buffer_id)
        sound.set_volume(buffer_id, -1000)
        self.assertEqual(sound.state(buffer_id), {"playing": True, "volume": -1000, "bytes": 2})
        sound.stop(buffer_id)
        self.assertFalse(sound.state(buffer_id)["playing"])
        with self.assertRaises(KeyError):
            sound.create_buffer("Missing Device", b"")
        with self.assertRaises(ValueError):
            sound.set_volume(buffer_id, 1)

    def test_network_services_dns_service_and_offline_paths(self):
        services = MockNetworkServices()
        services.set_dns("master.gamespy.com", "127.0.0.1")
        services.set_response("gamespy", b"query", b"servers")
        self.assertEqual(services.resolve("MASTER.GAMESPY.COM"), "127.0.0.1")
        self.assertEqual(services.request("GameSpy", b"query"), b"servers")
        with self.assertRaises(ConnectionError):
            services.request("keystone", b"missing")
        services.offline = True
        with self.assertRaises(TimeoutError):
            services.resolve("master.gamespy.com")

    def test_bink_media_open_step_close_and_failure_paths(self):
        bink = MockBink()
        bink.add_media("intro.bik", [b"frame0", b"frame1"])
        handle = bink.open("INTRO.BIK")
        self.assertEqual(bink.next_frame(handle), b"frame0")
        self.assertEqual(bink.next_frame(handle), b"frame1")
        self.assertIsNone(bink.next_frame(handle))
        bink.close(handle)
        with self.assertRaises(KeyError):
            bink.next_frame(handle)
        bink.add_media("bad.bik", [], corrupt=True)
        with self.assertRaises(ValueError):
            bink.open("bad.bik")
        with self.assertRaises(FileNotFoundError):
            bink.open("missing.bik")

    def test_runtime_heap_tls_atexit_locale_and_fpu_state(self):
        runtime = MockRuntime()
        ptr = runtime.malloc(4)
        self.assertIn(ptr, runtime.heap)
        runtime.set_tls(7, "profile", "player")
        self.assertEqual(runtime.get_tls(7, "profile"), "player")
        runtime.register_atexit("shutdown-audio")
        runtime.register_atexit("shutdown-video")
        self.assertEqual(runtime.run_atexit(), ["shutdown-video", "shutdown-audio"])
        runtime.set_locale("en_US")
        runtime.set_floating_point_mode("single-precision")
        self.assertEqual(runtime.locale, "en_US")
        self.assertEqual(runtime.floating_point_mode, "single-precision")
        runtime.free(ptr)
        with self.assertRaises(KeyError):
            runtime.free(ptr)


if __name__ == "__main__":
    unittest.main()

import json
import tempfile
import unittest
from pathlib import Path

from haloce_catalog.input_trace import (
    INPUT_EVENT,
    TRACE_FORMAT,
    event_code_name,
    list_input_devices,
    record_input_trace,
    replay_input_trace,
    summarize_input_trace,
)


class InputTraceTests(unittest.TestCase):
    def test_summarize_counts_keyboard_mouse_and_relative_motion(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "input.jsonl"
            self._write_fixture(
                path,
                [
                    {"kind": "event", "t": 0.0, "type": 1, "type_name": "EV_KEY", "code": 17, "code_name": "KEY_W", "value": 1},
                    {"kind": "event", "t": 0.1, "type": 1, "type_name": "EV_KEY", "code": 17, "code_name": "KEY_W", "value": 0},
                    {"kind": "event", "t": 0.2, "type": 2, "type_name": "EV_REL", "code": 0, "code_name": "REL_X", "value": 40},
                    {"kind": "event", "t": 0.3, "type": 1, "type_name": "EV_KEY", "code": 272, "code_name": "BTN_LEFT", "value": 1},
                ],
            )

            summary = summarize_input_trace(path)

        self.assertEqual(summary["format"], TRACE_FORMAT)
        self.assertEqual(summary["devices"], 2)
        self.assertEqual(summary["events"], 4)
        self.assertEqual(summary["keys"], {"KEY_W": 2})
        self.assertEqual(summary["buttons"], {"BTN_LEFT": 1})
        self.assertEqual(summary["relative_axes"], {"REL_X": 1})
        self.assertEqual(summary["duration_seconds"], 0.3)
        self.assertEqual(summary["role_hints"], {})

    def test_replay_dry_run_validates_supported_events_without_uinput(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "input.jsonl"
            self._write_fixture(
                path,
                [
                    {"kind": "event", "t": 0.0, "type": 1, "type_name": "EV_KEY", "code": 17, "code_name": "KEY_W", "value": 1},
                    {"kind": "event", "t": 0.1, "type": 2, "type_name": "EV_REL", "code": 1, "code_name": "REL_Y", "value": -4},
                    {"kind": "event", "t": 0.2, "type": 3, "type_name": "EV_ABS", "code": 0, "code_name": "ABS_X", "value": 10},
                ],
            )

            result = replay_input_trace(path, dry_run=True)

        self.assertEqual(result["events"], 3)
        self.assertEqual(result["supported_events"], 2)
        self.assertEqual(result["unsupported_events"], 1)
        self.assertTrue(result["dry_run"])
        self.assertEqual(result["speed"], 1.0)

    def test_record_input_trace_writes_metadata_and_relative_times(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            device_root = root / "dev" / "input"
            sysfs_root = root / "sys" / "class" / "input"
            device_root.mkdir(parents=True)
            device = device_root / "event4"
            device.write_bytes(
                b"".join(
                    [
                        INPUT_EVENT.pack(100, 1000, 1, 17, 1),
                        INPUT_EVENT.pack(100, 21000, 1, 17, 0),
                    ]
                )
            )
            caps = sysfs_root / "event4" / "device" / "capabilities"
            caps.mkdir(parents=True)
            (caps.parent / "name").write_text("fixture keyboard\n", encoding="utf-8")
            (caps / "ev").write_text("3\n", encoding="utf-8")
            (caps / "key").write_text(hex((1 << 1) | (1 << 17) | (1 << 30))[2:] + "\n", encoding="utf-8")
            out = root / "trace.jsonl"

            result = record_input_trace(
                out,
                [device],
                duration_seconds=0.01,
                test_id="client-walk-smoke",
                scenario="menu to movement",
                note="private capture",
                sysfs_root=sysfs_root,
            )
            records = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
            summary = summarize_input_trace(out)

        self.assertEqual(result["events"], 2)
        self.assertEqual(result["test_id"], "client-walk-smoke")
        self.assertEqual(records[0]["kind"], "session")
        self.assertEqual(records[0]["test_id"], "client-walk-smoke")
        self.assertEqual(records[0]["scenario"], "menu to movement")
        self.assertEqual(records[0]["note"], "private capture")
        self.assertEqual(records[0]["devices"][0]["name"], "fixture keyboard")
        self.assertEqual(records[1]["t"], 0.0)
        self.assertEqual(records[2]["t"], 0.02)
        self.assertEqual(records[-1]["kind"], "summary")
        self.assertEqual(summary["test_id"], "client-walk-smoke")
        self.assertEqual(summary["scenario"], "menu to movement")
        self.assertEqual(summary["note"], "private capture")
        self.assertEqual(summary["device_names"], ["fixture keyboard"])
        self.assertEqual(summary["recorded_summary"]["events"], 2)

    def test_code_names_cover_common_halo_controls(self):
        self.assertEqual(event_code_name(1, 17), "KEY_W")
        self.assertEqual(event_code_name(1, 57), "KEY_SPACE")
        self.assertEqual(event_code_name(1, 272), "BTN_LEFT")
        self.assertEqual(event_code_name(2, 0), "REL_X")

    def test_input_event_value_is_signed_for_mouse_deltas(self):
        _, _, event_type, code, value = INPUT_EVENT.unpack(INPUT_EVENT.pack(1, 2, 2, 1, -4))

        self.assertEqual((event_type, code, value), (2, 1, -4))

    def test_list_input_devices_reads_fake_sysfs_capabilities(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            device_root = root / "dev" / "input"
            sysfs_root = root / "sys" / "class" / "input"
            device_root.mkdir(parents=True)
            for name in ("event10", "event2"):
                (device_root / name).touch()
                caps = sysfs_root / name / "device" / "capabilities"
                caps.mkdir(parents=True)
                (caps.parent / "name").write_text(f"Device {name}\n", encoding="utf-8")
                (caps / "ev").write_text("7\n", encoding="utf-8")

            devices = list_input_devices(device_root=device_root, sysfs_root=sysfs_root)

        self.assertEqual([Path(device["path"]).name for device in devices], ["event2", "event10"])
        self.assertEqual(devices[0]["name"], "Device event2")
        self.assertEqual(devices[0]["event_types"], ["EV_SYN", "EV_KEY", "EV_REL"])

    def test_list_input_devices_marks_likely_capture_devices(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            device_root = root / "dev" / "input"
            sysfs_root = root / "sys" / "class" / "input"
            device_root.mkdir(parents=True)
            (device_root / "event0").touch()
            caps = sysfs_root / "event0" / "device" / "capabilities"
            caps.mkdir(parents=True)
            (caps.parent / "name").write_text("Fixture mouse\n", encoding="utf-8")
            (caps / "ev").write_text(hex((1 << 0) | (1 << 1) | (1 << 2))[2:] + "\n", encoding="utf-8")
            (caps / "key").write_text(hex((1 << 272) | (1 << 273))[2:] + "\n", encoding="utf-8")
            (caps / "rel").write_text(hex((1 << 0) | (1 << 1) | (1 << 8))[2:] + "\n", encoding="utf-8")

            devices = list_input_devices(device_root=device_root, sysfs_root=sysfs_root)

        self.assertEqual(devices[0]["role_hints"], ["mouse"])
        self.assertTrue(devices[0]["capture_relevant"])

    def _write_fixture(self, path: Path, events: list[dict]) -> None:
        records = [
            {
                "kind": "session",
                "format": TRACE_FORMAT,
                "created_at": "2026-06-27T00:00:00Z",
                "devices": [
                    {"id": 0, "path": "/dev/input/event0", "name": "keyboard", "event_types": ["EV_KEY"]},
                    {"id": 1, "path": "/dev/input/event1", "name": "mouse", "event_types": ["EV_KEY", "EV_REL"]},
                ],
            },
            *events,
        ]
        path.write_text("\n".join(json.dumps(record) for record in records) + "\n", encoding="utf-8")


if __name__ == "__main__":
    unittest.main()

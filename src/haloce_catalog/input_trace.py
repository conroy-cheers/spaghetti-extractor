from __future__ import annotations

import fcntl
import json
import os
import select
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .util import utc_now


TRACE_FORMAT = "wincr-input-trace-v1"
LEGACY_TRACE_FORMATS = ("haloce-input-trace-v1",)
INPUT_EVENT = struct.Struct("@llHHi")

EV_TYPES = {
    0x00: "EV_SYN",
    0x01: "EV_KEY",
    0x02: "EV_REL",
    0x03: "EV_ABS",
    0x04: "EV_MSC",
}
SYN_CODES = {0: "SYN_REPORT", 1: "SYN_CONFIG", 2: "SYN_MT_REPORT", 3: "SYN_DROPPED"}
REL_CODES = {
    0x00: "REL_X",
    0x01: "REL_Y",
    0x06: "REL_HWHEEL",
    0x08: "REL_WHEEL",
    0x0B: "REL_WHEEL_HI_RES",
    0x0C: "REL_HWHEEL_HI_RES",
}
ABS_CODES = {
    0x00: "ABS_X",
    0x01: "ABS_Y",
    0x02: "ABS_Z",
    0x03: "ABS_RX",
    0x04: "ABS_RY",
    0x05: "ABS_RZ",
    0x10: "ABS_HAT0X",
    0x11: "ABS_HAT0Y",
}
KEY_CODES = {
    1: "KEY_ESC",
    2: "KEY_1",
    3: "KEY_2",
    4: "KEY_3",
    5: "KEY_4",
    6: "KEY_5",
    7: "KEY_6",
    8: "KEY_7",
    9: "KEY_8",
    10: "KEY_9",
    11: "KEY_0",
    12: "KEY_MINUS",
    13: "KEY_EQUAL",
    14: "KEY_BACKSPACE",
    15: "KEY_TAB",
    16: "KEY_Q",
    17: "KEY_W",
    18: "KEY_E",
    19: "KEY_R",
    20: "KEY_T",
    21: "KEY_Y",
    22: "KEY_U",
    23: "KEY_I",
    24: "KEY_O",
    25: "KEY_P",
    26: "KEY_LEFTBRACE",
    27: "KEY_RIGHTBRACE",
    28: "KEY_ENTER",
    29: "KEY_LEFTCTRL",
    30: "KEY_A",
    31: "KEY_S",
    32: "KEY_D",
    33: "KEY_F",
    34: "KEY_G",
    35: "KEY_H",
    36: "KEY_J",
    37: "KEY_K",
    38: "KEY_L",
    39: "KEY_SEMICOLON",
    40: "KEY_APOSTROPHE",
    41: "KEY_GRAVE",
    42: "KEY_LEFTSHIFT",
    43: "KEY_BACKSLASH",
    44: "KEY_Z",
    45: "KEY_X",
    46: "KEY_C",
    47: "KEY_V",
    48: "KEY_B",
    49: "KEY_N",
    50: "KEY_M",
    51: "KEY_COMMA",
    52: "KEY_DOT",
    53: "KEY_SLASH",
    54: "KEY_RIGHTSHIFT",
    56: "KEY_LEFTALT",
    57: "KEY_SPACE",
    58: "KEY_CAPSLOCK",
    59: "KEY_F1",
    60: "KEY_F2",
    61: "KEY_F3",
    62: "KEY_F4",
    63: "KEY_F5",
    64: "KEY_F6",
    65: "KEY_F7",
    66: "KEY_F8",
    67: "KEY_F9",
    68: "KEY_F10",
    87: "KEY_F11",
    88: "KEY_F12",
    100: "KEY_RIGHTALT",
    102: "KEY_HOME",
    103: "KEY_UP",
    104: "KEY_PAGEUP",
    105: "KEY_LEFT",
    106: "KEY_RIGHT",
    107: "KEY_END",
    108: "KEY_DOWN",
    109: "KEY_PAGEDOWN",
    110: "KEY_INSERT",
    111: "KEY_DELETE",
    125: "KEY_LEFTMETA",
    126: "KEY_RIGHTMETA",
    272: "BTN_LEFT",
    273: "BTN_RIGHT",
    274: "BTN_MIDDLE",
    275: "BTN_SIDE",
    276: "BTN_EXTRA",
    277: "BTN_FORWARD",
    278: "BTN_BACK",
}


@dataclass(frozen=True)
class InputDevice:
    path: Path
    name: str
    event_types: list[str]
    role_hints: list[str]


def list_input_devices(*, device_root: Path = Path("/dev/input"), sysfs_root: Path = Path("/sys/class/input")) -> list[dict[str, Any]]:
    devices: list[dict[str, Any]] = []
    for path in sorted(device_root.glob("event*"), key=_event_sort_key):
        sys_name = path.name
        device_sysfs = sysfs_root / sys_name / "device"
        capabilities = _read_capabilities(device_sysfs)
        event_types = _event_type_names(capabilities.get("ev", ""))
        role_hints = _role_hints(capabilities)
        devices.append(
            {
                "path": str(path),
                "name": _read_text(device_sysfs / "name") or sys_name,
                "phys": _read_text(device_sysfs / "phys"),
                "uniq": _read_text(device_sysfs / "uniq"),
                "event_types": event_types,
                "role_hints": role_hints,
                "capture_relevant": bool(set(role_hints) & {"keyboard", "mouse"}),
                "capabilities": capabilities,
            }
        )
    return devices


def record_input_trace(
    out_path: Path,
    device_paths: Iterable[Path],
    *,
    duration_seconds: float | None = None,
    test_id: str | None = None,
    scenario: str | None = None,
    note: str | None = None,
    sysfs_root: Path = Path("/sys/class/input"),
) -> dict[str, Any]:
    paths = [Path(path) for path in device_paths]
    if not paths:
        raise ValueError("record_input_trace requires at least one --device path")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    opened: list[tuple[int, InputDevice]] = []
    try:
        for path in paths:
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
            opened.append((fd, _describe_device(path, sysfs_root=sysfs_root)))

        started_at = utc_now()
        first_kernel_time: float | None = None
        counts = {"events": 0, "devices": len(opened)}
        started = time.monotonic()
        interrupted = False
        with out_path.open("w", encoding="utf-8") as handle:
            try:
                _write_jsonl(
                    handle,
                    {
                        "kind": "session",
                        "format": TRACE_FORMAT,
                        "created_at": started_at,
                        "test_id": test_id,
                        "scenario": scenario,
                        "note": note,
                        "recorder": {
                            "tool": "wincr record-input",
                            "input_event_size": INPUT_EVENT.size,
                        },
                        "devices": [
                            {
                                "id": index,
                                "path": str(device.path),
                                "name": device.name,
                                "event_types": device.event_types,
                                "role_hints": device.role_hints,
                            }
                            for index, (_, device) in enumerate(opened)
                        ],
                    },
                )
                fd_to_device = {fd: index for index, (fd, _) in enumerate(opened)}
                while True:
                    if duration_seconds is not None and time.monotonic() - started >= duration_seconds:
                        break
                    remaining = None
                    if duration_seconds is not None:
                        remaining = max(0.0, duration_seconds - (time.monotonic() - started))
                    readable, _, _ = select.select(list(fd_to_device), [], [], remaining)
                    if not readable:
                        continue
                    for fd in readable:
                        for event in _read_available_events(fd):
                            kernel_time = event["kernel_time"]
                            if first_kernel_time is None:
                                first_kernel_time = kernel_time
                            event["t"] = round(kernel_time - first_kernel_time, 6)
                            event["device"] = fd_to_device[fd]
                            _write_jsonl(handle, event)
                            counts["events"] += 1
            except KeyboardInterrupt:
                interrupted = True
                raise
            finally:
                counts["duration_seconds"] = round(time.monotonic() - started, 3)
                _write_jsonl(
                    handle,
                    {
                        "kind": "summary",
                        "events": counts["events"],
                        "devices": counts["devices"],
                        "duration_seconds": counts["duration_seconds"],
                        "interrupted": interrupted,
                    },
                )
        counts["out"] = str(out_path)
        counts["test_id"] = test_id
        counts["scenario"] = scenario
        return counts
    finally:
        for fd, _ in opened:
            os.close(fd)


def summarize_input_trace(path: Path) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "format": None,
        "devices": 0,
        "events": 0,
        "duration_seconds": 0.0,
        "test_id": None,
        "scenario": None,
        "note": None,
        "device_names": [],
        "role_hints": {},
        "event_types": {},
        "keys": {},
        "buttons": {},
        "relative_axes": {},
        "recorded_summary": None,
    }
    for record in iter_input_trace(path):
        if record.get("kind") == "session":
            summary["format"] = record.get("format")
            devices = record.get("devices", [])
            summary["devices"] = len(devices)
            summary["test_id"] = record.get("test_id")
            summary["scenario"] = record.get("scenario")
            summary["note"] = record.get("note")
            summary["device_names"] = [device.get("name") for device in devices if device.get("name")]
            for device in devices:
                for role in device.get("role_hints", []):
                    _increment(summary["role_hints"], str(role))
        elif record.get("kind") == "event":
            summary["events"] += 1
            summary["duration_seconds"] = max(float(summary["duration_seconds"]), float(record.get("t", 0.0)))
            type_name = str(record.get("type_name") or record.get("type"))
            code_name = str(record.get("code_name") or record.get("code"))
            _increment(summary["event_types"], type_name)
            if type_name == "EV_KEY":
                target = summary["buttons"] if code_name.startswith("BTN_") else summary["keys"]
                _increment(target, code_name)
            elif type_name == "EV_REL":
                _increment(summary["relative_axes"], code_name)
        elif record.get("kind") == "summary":
            summary["recorded_summary"] = record
    return summary


def replay_input_trace(
    path: Path,
    *,
    dry_run: bool = True,
    force: bool = False,
    speed: float = 1.0,
    uinput_path: Path = Path("/dev/uinput"),
) -> dict[str, Any]:
    if speed <= 0:
        raise ValueError("speed must be greater than zero")
    events = [record for record in iter_input_trace(path) if record.get("kind") == "event"]
    supported = [
        event
        for event in events
        if int(event["type"]) in (0x00, 0x01, 0x02) and int(event["code"]) >= 0
    ]
    result = {
        "events": len(events),
        "supported_events": len(supported),
        "unsupported_events": len(events) - len(supported),
        "duration_seconds": max((float(event.get("t", 0.0)) for event in events), default=0.0),
        "dry_run": dry_run,
        "speed": speed,
        "uinput": str(uinput_path),
    }
    if dry_run:
        return result
    if not force:
        raise ValueError("replay_input_trace requires force=True unless dry_run=True")
    with UInputDevice(uinput_path, supported) as device:
        previous = 0.0
        for event in supported:
            current = float(event.get("t", 0.0))
            delay = max(0.0, (current - previous) / speed)
            if delay:
                time.sleep(delay)
            previous = current
            device.write_event(int(event["type"]), int(event["code"]), int(event["value"]))
        device.write_event(0x00, 0x00, 0)
    result["dry_run"] = False
    return result


def iter_input_trace(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            record = json.loads(line)
            if record.get("kind") == "session" and record.get("format") not in (None, TRACE_FORMAT, *LEGACY_TRACE_FORMATS):
                raise ValueError(f"unsupported input trace format on line {line_number}: {record.get('format')}")
            yield record


class UInputDevice:
    UI_DEV_CREATE = 0x5501
    UI_DEV_DESTROY = 0x5502
    UI_SET_EVBIT = 0x40045564
    UI_SET_KEYBIT = 0x40045565
    UI_SET_RELBIT = 0x40045566

    def __init__(self, path: Path, events: list[dict[str, Any]]) -> None:
        self.path = path
        self.events = events
        self.fd: int | None = None

    def __enter__(self) -> "UInputDevice":
        self.fd = os.open(self.path, os.O_WRONLY | os.O_NONBLOCK)
        event_types = {int(event["type"]) for event in self.events}
        for event_type in event_types | {0x00}:
            _ioctl_int(self.fd, self.UI_SET_EVBIT, event_type)
        for code in {int(event["code"]) for event in self.events if int(event["type"]) == 0x01}:
            _ioctl_int(self.fd, self.UI_SET_KEYBIT, code)
        for code in {int(event["code"]) for event in self.events if int(event["type"]) == 0x02}:
            _ioctl_int(self.fd, self.UI_SET_RELBIT, code)
        os.write(self.fd, _uinput_user_dev())
        fcntl.ioctl(self.fd, self.UI_DEV_CREATE)
        time.sleep(0.1)
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if self.fd is not None:
            try:
                fcntl.ioctl(self.fd, self.UI_DEV_DESTROY)
            finally:
                os.close(self.fd)
                self.fd = None

    def write_event(self, event_type: int, code: int, value: int) -> None:
        if self.fd is None:
            raise RuntimeError("uinput device is not open")
        now = time.time()
        sec = int(now)
        usec = int((now - sec) * 1_000_000)
        os.write(self.fd, INPUT_EVENT.pack(sec, usec, event_type, code, value))


def _read_available_events(fd: int) -> Iterable[dict[str, Any]]:
    while True:
        try:
            data = os.read(fd, INPUT_EVENT.size * 64)
        except BlockingIOError:
            return
        if not data:
            return
        usable = len(data) - (len(data) % INPUT_EVENT.size)
        for offset in range(0, usable, INPUT_EVENT.size):
            sec, usec, event_type, code, value = INPUT_EVENT.unpack_from(data, offset)
            kernel_time = float(sec) + float(usec) / 1_000_000.0
            yield {
                "kind": "event",
                "kernel_time": round(kernel_time, 6),
                "type": event_type,
                "type_name": EV_TYPES.get(event_type, f"EV_{event_type}"),
                "code": code,
                "code_name": event_code_name(event_type, code),
                "value": value,
            }


def event_code_name(event_type: int, code: int) -> str:
    if event_type == 0x00:
        return SYN_CODES.get(code, f"SYN_{code}")
    if event_type == 0x01:
        return KEY_CODES.get(code, f"KEY_{code}")
    if event_type == 0x02:
        return REL_CODES.get(code, f"REL_{code}")
    if event_type == 0x03:
        return ABS_CODES.get(code, f"ABS_{code}")
    return str(code)


def _describe_device(path: Path, *, sysfs_root: Path = Path("/sys/class/input")) -> InputDevice:
    sysfs = sysfs_root / path.name / "device"
    capabilities = _read_capabilities(sysfs)
    event_types = _event_type_names(capabilities.get("ev", ""))
    return InputDevice(
        path=path,
        name=_read_text(sysfs / "name") or path.name,
        event_types=event_types,
        role_hints=_role_hints(capabilities),
    )


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return None


def _read_capabilities(device_sysfs: Path) -> dict[str, str]:
    capabilities: dict[str, str] = {}
    for name in ("ev", "key", "rel", "abs"):
        value = _read_text(device_sysfs / "capabilities" / name)
        if value:
            capabilities[name] = value
    return capabilities


def _event_type_names(bits_text: str) -> list[str]:
    value = _capability_int(bits_text)
    names = []
    for bit, name in sorted(EV_TYPES.items()):
        if value & (1 << bit):
            names.append(name)
    return names


def _role_hints(capabilities: dict[str, str]) -> list[str]:
    hints: list[str] = []
    key_bits = _capability_int(capabilities.get("key", ""))
    rel_bits = _capability_int(capabilities.get("rel", ""))
    abs_bits = _capability_int(capabilities.get("abs", ""))

    has_mouse_axes = bool(rel_bits & (1 << 0x00)) and bool(rel_bits & (1 << 0x01))
    has_mouse_buttons = any(key_bits & (1 << code) for code in (272, 273, 274))
    if has_mouse_axes or has_mouse_buttons:
        hints.append("mouse")

    halo_key_codes = (1, 17, 30, 31, 32, 57)
    alpha_key_codes = range(16, 26)
    if any(key_bits & (1 << code) for code in halo_key_codes) and any(key_bits & (1 << code) for code in alpha_key_codes):
        hints.append("keyboard")

    if abs_bits and "mouse" not in hints:
        hints.append("absolute-pointer")

    return hints


def _capability_int(bits_text: str) -> int:
    value = 0
    for index, chunk in enumerate(reversed(bits_text.split())):
        try:
            value |= int(chunk, 16) << (index * 64)
        except ValueError:
            continue
    return value


def _event_sort_key(path: Path) -> tuple[str, int]:
    suffix = path.name.removeprefix("event")
    return ("event", int(suffix)) if suffix.isdigit() else (path.name, -1)


def _write_jsonl(handle: Any, record: dict[str, Any]) -> None:
    handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
    handle.flush()


def _increment(target: dict[str, int], key: str) -> None:
    target[key] = int(target.get(key, 0)) + 1


def _ioctl_int(fd: int, request: int, value: int) -> None:
    fcntl.ioctl(fd, request, struct.pack("I", value))


def _uinput_user_dev() -> bytes:
    name = b"wincr-input-replay"
    payload = bytearray(80 + 8 + 4 + 64 * 4 * 4)
    payload[: len(name)] = name
    struct.pack_into("HHHH", payload, 80, 0x03, 0x045E, 0x0001, 0x0001)
    return bytes(payload)

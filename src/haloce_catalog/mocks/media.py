from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class DisplayMode:
    width: int
    height: int
    bpp: int
    refresh_hz: int


@dataclass
class MockWindow:
    handle: int
    title: str
    width: int
    height: int
    focused: bool = False
    visible: bool = True


class MockGraphics:
    """Deterministic D3D/DDraw/GDI/windowing/gamma behavior model."""

    def __init__(self) -> None:
        self.display_modes: list[DisplayMode] = [
            DisplayMode(640, 480, 32, 60),
            DisplayMode(800, 600, 32, 60),
            DisplayMode(1024, 768, 32, 60),
        ]
        self.windows: dict[int, MockWindow] = {}
        self.current_mode = self.display_modes[0]
        self.gamma_ramp = tuple(range(256))
        self.device_lost = False
        self.operations: list[tuple[str, Any]] = []
        self._next_handle = 1

    def enumerate_modes(self) -> list[DisplayMode]:
        self.operations.append(("enumerate_modes", None))
        return list(self.display_modes)

    def set_display_mode(self, mode: DisplayMode) -> None:
        if mode not in self.display_modes:
            raise ValueError(f"unsupported display mode: {mode}")
        self.current_mode = mode
        self.operations.append(("set_display_mode", mode))

    def create_window(self, title: str, width: int, height: int) -> int:
        if width <= 0 or height <= 0:
            raise ValueError("window dimensions must be positive")
        handle = self._next_handle
        self._next_handle += 1
        self.windows[handle] = MockWindow(handle=handle, title=title, width=width, height=height)
        self.operations.append(("create_window", handle))
        return handle

    def destroy_window(self, handle: int) -> None:
        if handle not in self.windows:
            raise KeyError(handle)
        del self.windows[handle]
        self.operations.append(("destroy_window", handle))

    def set_focus(self, handle: int) -> None:
        if handle not in self.windows:
            raise KeyError(handle)
        for window in self.windows.values():
            window.focused = False
        self.windows[handle].focused = True
        self.operations.append(("set_focus", handle))

    def set_gamma_ramp(self, ramp: list[int] | tuple[int, ...]) -> None:
        if len(ramp) != 256 or any(value < 0 or value > 65535 for value in ramp):
            raise ValueError("gamma ramp must contain 256 values in 0..65535")
        self.gamma_ramp = tuple(int(value) for value in ramp)
        self.operations.append(("set_gamma_ramp", "custom"))

    def lose_device(self) -> None:
        self.device_lost = True
        self.operations.append(("lose_device", None))

    def reset_device(self) -> None:
        self.device_lost = False
        self.operations.append(("reset_device", None))

    def present(self) -> None:
        if self.device_lost:
            raise RuntimeError("graphics device is lost")
        self.operations.append(("present", None))


@dataclass
class MockInputDevice:
    name: str
    device_type: str
    acquired: bool = False
    state: dict[str, int] = field(default_factory=dict)
    events: deque[tuple[str, int]] = field(default_factory=deque)


class MockDirectInput:
    """DirectInput device enumeration, acquire, poll, and buffered events."""

    def __init__(self) -> None:
        self.devices: dict[str, MockInputDevice] = {}

    def add_device(self, name: str, device_type: str) -> None:
        self.devices[name.lower()] = MockInputDevice(name=name, device_type=device_type)

    def enumerate_devices(self, device_type: str | None = None) -> list[str]:
        names = [
            device.name
            for device in self.devices.values()
            if device_type is None or device.device_type == device_type
        ]
        return sorted(names)

    def acquire(self, name: str) -> None:
        self._device(name).acquired = True

    def unacquire(self, name: str) -> None:
        self._device(name).acquired = False

    def set_state(self, name: str, control: str, value: int) -> None:
        device = self._device(name)
        device.state[control] = value
        device.events.append((control, value))

    def poll(self, name: str) -> dict[str, int]:
        device = self._device(name)
        if not device.acquired:
            raise PermissionError(f"device is not acquired: {name}")
        return dict(device.state)

    def read_buffered(self, name: str) -> list[tuple[str, int]]:
        device = self._device(name)
        if not device.acquired:
            raise PermissionError(f"device is not acquired: {name}")
        events = list(device.events)
        device.events.clear()
        return events

    def _device(self, name: str) -> MockInputDevice:
        key = name.lower()
        if key not in self.devices:
            raise KeyError(name)
        return self.devices[key]


@dataclass
class MockSoundBuffer:
    buffer_id: int
    device: str
    data: bytes
    playing: bool = False
    volume: int = 0


class MockDirectSound:
    """DirectSound/WINMM device and buffer behavior model."""

    def __init__(self) -> None:
        self.devices: set[str] = set()
        self.buffers: dict[int, MockSoundBuffer] = {}
        self._next_buffer = 1

    def add_device(self, name: str) -> None:
        self.devices.add(name)

    def enumerate_devices(self) -> list[str]:
        return sorted(self.devices)

    def create_buffer(self, device: str, data: bytes) -> int:
        if device not in self.devices:
            raise KeyError(device)
        buffer_id = self._next_buffer
        self._next_buffer += 1
        self.buffers[buffer_id] = MockSoundBuffer(buffer_id=buffer_id, device=device, data=bytes(data))
        return buffer_id

    def play(self, buffer_id: int) -> None:
        self._buffer(buffer_id).playing = True

    def stop(self, buffer_id: int) -> None:
        self._buffer(buffer_id).playing = False

    def set_volume(self, buffer_id: int, volume: int) -> None:
        if volume < -10000 or volume > 0:
            raise ValueError("DirectSound volume is expected in -10000..0")
        self._buffer(buffer_id).volume = volume

    def state(self, buffer_id: int) -> dict[str, Any]:
        buffer = self._buffer(buffer_id)
        return {"playing": buffer.playing, "volume": buffer.volume, "bytes": len(buffer.data)}

    def _buffer(self, buffer_id: int) -> MockSoundBuffer:
        if buffer_id not in self.buffers:
            raise KeyError(buffer_id)
        return self.buffers[buffer_id]


class MockNetworkServices:
    """Winsock DNS plus GameSpy/Keystone-style request behavior."""

    def __init__(self) -> None:
        self.dns: dict[str, str] = {}
        self.responses: dict[tuple[str, bytes], bytes] = {}
        self.offline = False
        self.requests: list[tuple[str, bytes]] = []

    def set_dns(self, host: str, address: str) -> None:
        self.dns[host.lower()] = address

    def resolve(self, host: str) -> str:
        if self.offline:
            raise TimeoutError(host)
        key = host.lower()
        if key not in self.dns:
            raise LookupError(host)
        return self.dns[key]

    def set_response(self, service: str, payload: bytes, response: bytes) -> None:
        self.responses[(service.lower(), bytes(payload))] = bytes(response)

    def request(self, service: str, payload: bytes) -> bytes:
        if self.offline:
            raise TimeoutError(service)
        key = (service.lower(), bytes(payload))
        self.requests.append(key)
        if key not in self.responses:
            raise ConnectionError(service)
        return self.responses[key]


@dataclass
class MockBinkMedia:
    frames: list[bytes]
    corrupt: bool = False


class MockBink:
    """Bink open/close/frame stepping behavior model."""

    def __init__(self) -> None:
        self.media: dict[str, MockBinkMedia] = {}
        self.handles: dict[int, tuple[str, int]] = {}
        self._next_handle = 1

    def add_media(self, path: str, frames: list[bytes], *, corrupt: bool = False) -> None:
        self.media[path.lower()] = MockBinkMedia(frames=[bytes(frame) for frame in frames], corrupt=corrupt)

    def open(self, path: str) -> int:
        key = path.lower()
        if key not in self.media:
            raise FileNotFoundError(path)
        if self.media[key].corrupt:
            raise ValueError(f"corrupt Bink media: {path}")
        handle = self._next_handle
        self._next_handle += 1
        self.handles[handle] = (key, 0)
        return handle

    def next_frame(self, handle: int) -> bytes | None:
        if handle not in self.handles:
            raise KeyError(handle)
        key, index = self.handles[handle]
        frames = self.media[key].frames
        if index >= len(frames):
            return None
        self.handles[handle] = (key, index + 1)
        return frames[index]

    def close(self, handle: int) -> None:
        if handle not in self.handles:
            raise KeyError(handle)
        del self.handles[handle]


class MockRuntime:
    """CRT/TLS/heap/runtime ordering behavior model."""

    def __init__(self) -> None:
        self.heap: dict[int, bytearray] = {}
        self.tls: dict[tuple[int, str], Any] = {}
        self.atexit_handlers: list[str] = []
        self.locale = "C"
        self.floating_point_mode = "default"
        self._next_ptr = 0x1000

    def malloc(self, size: int) -> int:
        if size < 0:
            raise ValueError("allocation size must be non-negative")
        ptr = self._next_ptr
        self._next_ptr += max(size, 1)
        self.heap[ptr] = bytearray(size)
        return ptr

    def free(self, ptr: int) -> None:
        if ptr not in self.heap:
            raise KeyError(ptr)
        del self.heap[ptr]

    def set_tls(self, thread_id: int, key: str, value: Any) -> None:
        self.tls[(thread_id, key)] = value

    def get_tls(self, thread_id: int, key: str, default: Any = None) -> Any:
        return self.tls.get((thread_id, key), default)

    def register_atexit(self, name: str) -> None:
        self.atexit_handlers.append(name)

    def run_atexit(self) -> list[str]:
        order = list(reversed(self.atexit_handlers))
        self.atexit_handlers.clear()
        return order

    def set_locale(self, locale: str) -> None:
        self.locale = locale

    def set_floating_point_mode(self, mode: str) -> None:
        self.floating_point_mode = mode

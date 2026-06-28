from __future__ import annotations

import json
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import PureWindowsPath
from typing import Any


@dataclass
class MockFileHandle:
    handle: int
    path: str
    access: str
    position: int = 0


@dataclass
class MockThread:
    thread_id: int
    name: str
    state: str
    exit_code: int | None = None


@dataclass
class MockEvent:
    handle: int
    name: str | None
    manual_reset: bool
    signaled: bool


class MockFileSystem:
    """Small deterministic Win32-style filesystem mock for public oracle tests."""

    def __init__(self) -> None:
        self.files: dict[str, bytes] = {}
        self.directories: set[str] = {_norm("C:\\"), _norm("C:\\Program Files (x86)")}
        self.handles: dict[int, MockFileHandle] = {}
        self.operations: list[tuple[str, str]] = []
        self.last_error: str | None = None
        self._next_handle = 16

    def mkdir(self, path: str) -> None:
        normalized = _norm(path)
        self.directories.add(normalized)
        self.operations.append(("mkdir", normalized))
        self.last_error = None

    def write_bytes(self, path: str, data: bytes) -> None:
        normalized = _norm(path)
        parent = _norm(str(PureWindowsPath(normalized).parent))
        if parent not in self.directories:
            self.last_error = "ERROR_PATH_NOT_FOUND"
            raise FileNotFoundError(parent)
        self.files[normalized] = bytes(data)
        self.operations.append(("write", normalized))
        self.last_error = None

    def read_bytes(self, path: str) -> bytes:
        normalized = _norm(path)
        self.operations.append(("read", normalized))
        if normalized not in self.files:
            self.last_error = "ERROR_FILE_NOT_FOUND"
            raise FileNotFoundError(normalized)
        self.last_error = None
        return self.files[normalized]

    def exists(self, path: str) -> bool:
        normalized = _norm(path)
        self.operations.append(("exists", normalized))
        return normalized in self.files or normalized in self.directories

    def listdir(self, path: str) -> list[str]:
        normalized = _norm(path)
        prefix = normalized.rstrip("\\") + "\\"
        children: set[str] = set()
        for candidate in set(self.files) | self.directories:
            if not candidate.startswith(prefix):
                continue
            rest = candidate[len(prefix) :]
            if rest:
                children.add(rest.split("\\", 1)[0])
        self.operations.append(("listdir", normalized))
        return sorted(children)

    def create_file(
        self,
        path: str,
        *,
        desired_access: str = "read",
        creation_disposition: str = "open_existing",
    ) -> int:
        access = desired_access.lower()
        disposition = creation_disposition.lower()
        if access not in {"read", "write", "readwrite"}:
            raise ValueError(f"unsupported desired access: {desired_access}")
        if disposition not in {"create_always", "create_new", "open_always", "open_existing", "truncate_existing"}:
            raise ValueError(f"unsupported creation disposition: {creation_disposition}")

        normalized = _norm(path)
        parent = _norm(str(PureWindowsPath(normalized).parent))
        exists = normalized in self.files
        if not exists and disposition in {"open_existing", "truncate_existing"}:
            self.last_error = "ERROR_FILE_NOT_FOUND"
            raise FileNotFoundError(normalized)
        if exists and disposition == "create_new":
            self.last_error = "ERROR_FILE_EXISTS"
            raise FileExistsError(normalized)
        if parent not in self.directories and disposition in {"create_always", "create_new", "open_always"}:
            self.last_error = "ERROR_PATH_NOT_FOUND"
            raise FileNotFoundError(parent)
        if disposition in {"create_always", "truncate_existing"} or (not exists and disposition in {"create_new", "open_always"}):
            self.files[normalized] = b""

        handle = self._next_handle
        self._next_handle += 1
        self.handles[handle] = MockFileHandle(handle=handle, path=normalized, access=access)
        self.operations.append(("create_file", normalized))
        self.last_error = None
        return handle

    def read_file(self, handle: int, size: int | None = None) -> bytes:
        file_handle = self._handle(handle)
        if file_handle.access not in {"read", "readwrite"}:
            self.last_error = "ERROR_ACCESS_DENIED"
            raise PermissionError(file_handle.path)
        data = self.files[file_handle.path]
        end = len(data) if size is None or size < 0 else min(len(data), file_handle.position + size)
        chunk = data[file_handle.position : end]
        file_handle.position = end
        self.operations.append(("read_file", file_handle.path))
        self.last_error = None
        return chunk

    def write_file(self, handle: int, data: bytes) -> int:
        file_handle = self._handle(handle)
        if file_handle.access not in {"write", "readwrite"}:
            self.last_error = "ERROR_ACCESS_DENIED"
            raise PermissionError(file_handle.path)
        old = self.files[file_handle.path]
        start = file_handle.position
        end = start + len(data)
        self.files[file_handle.path] = old[:start] + bytes(data) + old[end:]
        file_handle.position = end
        self.operations.append(("write_file", file_handle.path))
        self.last_error = None
        return len(data)

    def set_file_pointer(self, handle: int, offset: int, *, origin: str = "begin") -> int:
        file_handle = self._handle(handle)
        origin_key = origin.lower()
        if origin_key == "begin":
            position = offset
        elif origin_key == "current":
            position = file_handle.position + offset
        elif origin_key == "end":
            position = len(self.files[file_handle.path]) + offset
        else:
            raise ValueError(f"unsupported file pointer origin: {origin}")
        if position < 0:
            self.last_error = "ERROR_NEGATIVE_SEEK"
            raise ValueError("file pointer cannot be negative")
        file_handle.position = position
        self.operations.append(("set_file_pointer", file_handle.path))
        self.last_error = None
        return position

    def get_file_size(self, handle: int) -> int:
        file_handle = self._handle(handle)
        self.operations.append(("get_file_size", file_handle.path))
        return len(self.files[file_handle.path])

    def close_handle(self, handle: int) -> None:
        file_handle = self._handle(handle)
        del self.handles[handle]
        self.operations.append(("close_handle", file_handle.path))
        self.last_error = None

    def _handle(self, handle: int) -> MockFileHandle:
        if handle not in self.handles:
            self.last_error = "ERROR_INVALID_HANDLE"
            raise KeyError(handle)
        return self.handles[handle]


@dataclass
class RegistryValue:
    kind: str
    value: Any


class MockRegistry:
    """Case-insensitive HKLM/HKCU registry model with typed values."""

    def __init__(self) -> None:
        self._keys: dict[str, dict[str, RegistryValue]] = defaultdict(dict)
        self.operations: list[tuple[str, str, str | None]] = []

    def set_value(self, key: str, name: str, value: Any, kind: str = "REG_SZ") -> None:
        key_norm = _reg(key)
        name_norm = name.lower()
        self._keys[key_norm][name_norm] = RegistryValue(kind=kind, value=value)
        self.operations.append(("set", key_norm, name))

    def get_value(self, key: str, name: str, default: Any = None) -> Any:
        key_norm = _reg(key)
        name_norm = name.lower()
        self.operations.append(("get", key_norm, name))
        if key_norm not in self._keys or name_norm not in self._keys[key_norm]:
            return default
        return self._keys[key_norm][name_norm].value

    def delete_value(self, key: str, name: str) -> None:
        key_norm = _reg(key)
        name_norm = name.lower()
        self.operations.append(("delete", key_norm, name))
        del self._keys[key_norm][name_norm]

    def export_json(self) -> str:
        data = {
            key: {name: {"kind": item.kind, "value": item.value} for name, item in sorted(values.items())}
            for key, values in sorted(self._keys.items())
        }
        return json.dumps(data, indent=2, sort_keys=True)


@dataclass
class MockClock:
    tick_ms: int = 0
    performance_counter: int = 0
    performance_frequency: int = 1_000_000

    def get_tick_count(self) -> int:
        return self.tick_ms & 0xFFFFFFFF

    def query_performance_counter(self) -> int:
        return self.performance_counter

    def query_performance_frequency(self) -> int:
        return self.performance_frequency

    def advance_ms(self, milliseconds: int) -> None:
        self.tick_ms += milliseconds
        self.performance_counter += milliseconds * (self.performance_frequency // 1000)

    def sleep(self, milliseconds: int) -> None:
        if milliseconds < 0:
            raise ValueError("sleep duration must be non-negative")
        self.advance_ms(milliseconds)


@dataclass
class MockConsole:
    stdin: deque[str] = field(default_factory=deque)
    stdout: list[str] = field(default_factory=list)
    stderr: list[str] = field(default_factory=list)

    def write_stdout(self, text: str) -> None:
        self.stdout.append(text)

    def write_stderr(self, text: str) -> None:
        self.stderr.append(text)

    def read_line(self) -> str:
        if not self.stdin:
            raise EOFError("mock console stdin exhausted")
        return self.stdin.popleft()


class MockWinsock:
    """Packet-level UDP/TCP endpoint mock keyed by host/port tuples."""

    def __init__(self) -> None:
        self.queues: dict[tuple[str, int], deque[tuple[tuple[str, int], bytes]]] = defaultdict(deque)
        self.sent: list[tuple[tuple[str, int], tuple[str, int], bytes]] = []

    def sendto(self, source: tuple[str, int], destination: tuple[str, int], payload: bytes) -> None:
        self.queues[destination].append((source, bytes(payload)))
        self.sent.append((source, destination, bytes(payload)))

    def recvfrom(self, endpoint: tuple[str, int]) -> tuple[tuple[str, int], bytes]:
        if not self.queues[endpoint]:
            raise BlockingIOError(endpoint)
        return self.queues[endpoint].popleft()


class MockThreading:
    """Deterministic CreateThread/Event/WaitForSingleObject behavior model."""

    def __init__(self) -> None:
        self.threads: dict[int, MockThread] = {}
        self.events: dict[int, MockEvent] = {}
        self.operations: list[tuple[str, int]] = []
        self._next_thread = 1
        self._next_handle = 256

    def create_thread(self, name: str, *, start_suspended: bool = False) -> int:
        thread_id = self._next_thread
        self._next_thread += 1
        state = "suspended" if start_suspended else "running"
        self.threads[thread_id] = MockThread(thread_id=thread_id, name=name, state=state)
        self.operations.append(("create_thread", thread_id))
        return thread_id

    def resume_thread(self, thread_id: int) -> None:
        thread = self._thread(thread_id)
        if thread.state != "suspended":
            raise RuntimeError(f"thread is not suspended: {thread_id}")
        thread.state = "running"
        self.operations.append(("resume_thread", thread_id))

    def exit_thread(self, thread_id: int, exit_code: int = 0) -> None:
        thread = self._thread(thread_id)
        thread.state = "exited"
        thread.exit_code = exit_code
        self.operations.append(("exit_thread", thread_id))

    def wait_for_thread(self, thread_id: int, *, timeout_ms: int | None = None) -> int:
        thread = self._thread(thread_id)
        if thread.state != "exited":
            raise TimeoutError(f"thread did not signal before timeout: {timeout_ms}")
        self.operations.append(("wait_for_thread", thread_id))
        return int(thread.exit_code or 0)

    def create_event(self, *, name: str | None = None, manual_reset: bool = False, initial_state: bool = False) -> int:
        handle = self._next_handle
        self._next_handle += 1
        self.events[handle] = MockEvent(
            handle=handle,
            name=name,
            manual_reset=manual_reset,
            signaled=initial_state,
        )
        self.operations.append(("create_event", handle))
        return handle

    def set_event(self, handle: int) -> None:
        event = self._event(handle)
        event.signaled = True
        self.operations.append(("set_event", handle))

    def reset_event(self, handle: int) -> None:
        event = self._event(handle)
        event.signaled = False
        self.operations.append(("reset_event", handle))

    def wait_for_event(self, handle: int, *, timeout_ms: int | None = None) -> bool:
        event = self._event(handle)
        if not event.signaled:
            raise TimeoutError(f"event did not signal before timeout: {timeout_ms}")
        if not event.manual_reset:
            event.signaled = False
        self.operations.append(("wait_for_event", handle))
        return True

    def _thread(self, thread_id: int) -> MockThread:
        if thread_id not in self.threads:
            raise KeyError(thread_id)
        return self.threads[thread_id]

    def _event(self, handle: int) -> MockEvent:
        if handle not in self.events:
            raise KeyError(handle)
        return self.events[handle]


def _norm(path: str) -> str:
    pure = PureWindowsPath(path)
    return str(pure).replace("/", "\\").rstrip("\\").lower()


def _reg(key: str) -> str:
    return key.replace("/", "\\").rstrip("\\").lower()

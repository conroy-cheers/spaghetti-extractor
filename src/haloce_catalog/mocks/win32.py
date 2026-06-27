from __future__ import annotations

import json
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath
from typing import Any


class MockFileSystem:
    """Small deterministic Win32-style filesystem mock for public oracle tests."""

    def __init__(self) -> None:
        self.files: dict[str, bytes] = {}
        self.directories: set[str] = {_norm("C:\\"), _norm("C:\\Program Files (x86)")}
        self.operations: list[tuple[str, str]] = []

    def mkdir(self, path: str) -> None:
        normalized = _norm(path)
        self.directories.add(normalized)
        self.operations.append(("mkdir", normalized))

    def write_bytes(self, path: str, data: bytes) -> None:
        normalized = _norm(path)
        parent = _norm(str(PureWindowsPath(normalized).parent))
        if parent not in self.directories:
            raise FileNotFoundError(parent)
        self.files[normalized] = bytes(data)
        self.operations.append(("write", normalized))

    def read_bytes(self, path: str) -> bytes:
        normalized = _norm(path)
        self.operations.append(("read", normalized))
        if normalized not in self.files:
            raise FileNotFoundError(normalized)
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

    def advance_ms(self, milliseconds: int) -> None:
        self.tick_ms += milliseconds
        self.performance_counter += milliseconds * (self.performance_frequency // 1000)


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


def _norm(path: str) -> str:
    pure = PureWindowsPath(path)
    return str(pure).replace("/", "\\").rstrip("\\").lower()


def _reg(key: str) -> str:
    return key.replace("/", "\\").rstrip("\\").lower()

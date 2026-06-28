"""Public behavior mocks used by clean-room oracle tests."""

from .media import (
    DisplayMode,
    MockBink,
    MockDirectInput,
    MockDirectSound,
    MockGraphics,
    MockNetworkServices,
    MockRuntime,
)
from .win32 import MockClock, MockConsole, MockFileSystem, MockRegistry, MockThreading, MockWinsock

__all__ = [
    "DisplayMode",
    "MockBink",
    "MockClock",
    "MockConsole",
    "MockDirectInput",
    "MockDirectSound",
    "MockFileSystem",
    "MockGraphics",
    "MockNetworkServices",
    "MockRegistry",
    "MockRuntime",
    "MockThreading",
    "MockWinsock",
]

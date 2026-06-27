"""Public behavior mocks used by clean-room oracle tests."""

from .win32 import MockClock, MockConsole, MockFileSystem, MockRegistry, MockWinsock

__all__ = [
    "MockClock",
    "MockConsole",
    "MockFileSystem",
    "MockRegistry",
    "MockWinsock",
]

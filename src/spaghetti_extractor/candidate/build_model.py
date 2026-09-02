"""Data model and constants for behavioral-C native module linking."""

from __future__ import annotations

import re

from . import native_build


_PAYLOAD_FILENAME = native_build.PAYLOAD_FILENAME
_PAYLOAD_MAP_FILENAME = native_build.PAYLOAD_MAP_FILENAME
_RUNTIME_STATE_LAYOUT_FILENAME = native_build.RUNTIME_STATE_LAYOUT_FILENAME
_RELOCATION_INVENTORY_FILENAME = native_build.PAYLOAD_RELOCATION_INVENTORY_FILENAME
_C_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_PAYLOAD_SYMBOL = re.compile(
    r"(?m)^\s*(0x[0-9a-fA-F]+)\s+(_?spx_[A-Za-z0-9_]+)\b"
)


class CandidateNativeBuildError(ValueError):
    """A behavioral-C module-link input or output failed validation."""

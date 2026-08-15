from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

import pefile


IMAGE_FILE_DLL = 0x2000
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
PE32_CONSOLE_PREFERRED_BASE_POLICY = "pe32-console-preferred-base-v1"


class LoaderDiagnosticSeverity(str, Enum):
    ERROR = "error"
    WARNING = "warning"


class LoaderDiagnosticStatus(str, Enum):
    DIAGNOSTIC_CLEAN = "diagnostic-clean"
    CONDITIONAL_LAUNCH = "conditional-launch"
    INVALID = "invalid"


@dataclass(frozen=True)
class LoaderDiagnostic:
    severity: LoaderDiagnosticSeverity
    code: str
    message: str


@dataclass(frozen=True)
class LoaderDiagnostics:
    policy: str
    status: LoaderDiagnosticStatus
    diagnostics: tuple[LoaderDiagnostic, ...]

    @property
    def hard_diagnostics(self) -> tuple[LoaderDiagnostic, ...]:
        return tuple(
            diagnostic
            for diagnostic in self.diagnostics
            if diagnostic.severity is LoaderDiagnosticSeverity.ERROR
        )

    @property
    def conditional_warnings(self) -> tuple[LoaderDiagnostic, ...]:
        return tuple(
            diagnostic
            for diagnostic in self.diagnostics
            if diagnostic.severity is LoaderDiagnosticSeverity.WARNING
        )

    def as_payload(self) -> dict[str, Any]:
        return {
            "policy": self.policy,
            "status": self.status.value,
            "diagnostics": [
                {
                    "severity": diagnostic.severity.value,
                    "code": diagnostic.code,
                    "message": diagnostic.message,
                }
                for diagnostic in self.diagnostics
            ],
        }


@dataclass(frozen=True)
class PESection:
    name: str
    rva_start: int
    rva_end: int
    raw_pointer: int
    raw_size: int
    characteristics: int
    executable: bool
    readable: bool
    writable: bool
    contains_code: bool


@dataclass(frozen=True)
class PEImport:
    dll: str
    symbol: str | None
    ordinal: int | None
    thunk_rva: int | None


@dataclass(frozen=True)
class PEExport:
    ordinal: int
    name: str | None
    rva: int
    kind: str
    forwarder: str | None


@dataclass(frozen=True)
class ParsedPEImage:
    path: Path
    sha256: str
    size: int
    machine: str
    bitness: int
    coff_characteristics: int
    is_dll: bool
    image_base: int
    entrypoint_rva: int
    exports: tuple[PEExport, ...] | None
    export_parse_error: str | None
    tls_directory_rva: int
    tls_directory_size: int
    tls_callback_rvas: tuple[int, ...] | None
    tls_callback_array_rva: int | None
    tls_callback_array_size: int | None
    tls_callback_array_immutable: bool | None
    tls_callback_parse_error: str | None
    size_of_image: int
    size_of_headers: int
    subsystem: str
    loader_diagnostics: LoaderDiagnostics
    sections: tuple[PESection, ...]
    imports: tuple[PEImport, ...]
    pe: pefile.PE


@dataclass(frozen=True)
class BlockSide:
    rva_start: int
    rva_end: int

    @property
    def size(self) -> int:
        return self.rva_end - self.rva_start


@dataclass(frozen=True)
class RawPESection:
    section: PESection


__all__ = [
    "BlockSide",
    "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE",
    "IMAGE_FILE_DLL",
    "LoaderDiagnostic",
    "LoaderDiagnosticSeverity",
    "LoaderDiagnosticStatus",
    "LoaderDiagnostics",
    "PE32_CONSOLE_PREFERRED_BASE_POLICY",
    "PEExport",
    "PEImport",
    "PESection",
    "ParsedPEImage",
    "RawPESection",
]

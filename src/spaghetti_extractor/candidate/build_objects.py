"""Linked-symbol evidence and output helpers for behavioral-C module builds."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..util import sha256_file
from . import native_build
from .build_model import CandidateNativeBuildError, _PAYLOAD_SYMBOL
from .build_values import _u32


def _payload_symbol_rvas(linker_map: Path, *, image_base: int) -> dict[str, int]:
    try:
        text = linker_map.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        raise CandidateNativeBuildError(
            f"cannot read payload linker map: {exc}"
        ) from exc
    result: dict[str, int] = {}
    for match in _PAYLOAD_SYMBOL.finditer(text):
        address = int(match.group(1), 16)
        if address < image_base:
            raise CandidateNativeBuildError(
                f"payload symbol {match.group(2)} lies below the image base"
            )
        name = match.group(2).removeprefix("_")
        rva = _u32(address - image_base, f"payload symbol {name} RVA")
        previous = result.setdefault(name, rva)
        if previous != rva:
            raise CandidateNativeBuildError(
                f"payload linker map gives ambiguous addresses for {name}"
            )
    return result


def _output_binding(path: Path, root: Path) -> dict[str, Any]:
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": sha256_file(path),
        "size": path.stat().st_size,
    }


def _compiler_runtime(compiler: Path) -> Path:
    try:
        value = native_build._tool_output(
            [str(compiler), "-print-libgcc-file-name"]
        )
    except native_build.CandidateNativeBuildError as exc:
        raise CandidateNativeBuildError(
            f"cannot locate the compiler runtime: {exc}"
        ) from exc
    path = Path(value).resolve()
    if not path.is_file():
        raise CandidateNativeBuildError(
            f"compiler runtime does not exist: {path}"
        )
    return path

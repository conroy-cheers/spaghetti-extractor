from __future__ import annotations

from .model import PESection, ParsedPEImage


def executable_section_for_rva(
    image: ParsedPEImage, rva: int,
) -> PESection | None:
    for section in image.sections:
        if section.executable and section.rva_start <= rva < section.rva_end:
            return section
    return None


def section_for_rva(image: ParsedPEImage, rva: int) -> PESection | None:
    for section in image.sections:
        if section.rva_start <= rva < section.rva_end:
            return section
    return None


def executable_section_covering_range(
    image: ParsedPEImage, rva_start: int, rva_end: int,
) -> PESection | None:
    if rva_end <= rva_start:
        return None
    for section in image.sections:
        if (
            section.executable
            and section.rva_start <= rva_start
            and rva_end <= section.rva_end
        ):
            return section
    return None


__all__ = [
    "executable_section_covering_range",
    "executable_section_for_rva",
    "section_for_rva",
]

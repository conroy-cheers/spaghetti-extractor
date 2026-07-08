from __future__ import annotations


IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000


def mapped_section_size(virtual_size: int, raw_size: int) -> int:
    """Return the PE mapped span Stage A should classify for a section."""

    virtual = int(virtual_size)
    return virtual if virtual > 0 else int(raw_size)

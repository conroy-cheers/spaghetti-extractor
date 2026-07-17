"""Fast, untrusted capability checks before relational Lean extraction."""

from __future__ import annotations

from typing import Any

import capstone

from ..stage_binary import StageAInputError, _parse_stage_a_pe


def instruction_supported(insn: Any) -> bool:
    """Mirror the reviewed PE32 decoder fragment for cheap fail-fast feedback.

    This check is diagnostic only. Lean still decodes the exact bytes and is the
    authority for proof acceptance.
    """

    encoded = bytes(insn.bytes)
    opcode = encoded[0] if encoded else -1
    modrm_group = ((encoded[1] >> 3) & 7) if len(encoded) >= 2 else -1
    word_opcode = encoded[1] if len(encoded) >= 2 and encoded[0] == 0x66 else -1
    word_modrm_group = ((encoded[2] >> 3) & 7) if len(encoded) >= 3 and encoded[0] == 0x66 else -1
    normalized_nops = {
        b"\x66\x90",
        b"\x2e\x8d\x74\x26\x00",
        b"\x2e\x8d\xb4\x26\x00\x00\x00\x00",
        b"\x8d\xb6\x00\x00\x00\x00",
        b"\x8d\xb4\x26\x00\x00\x00\x00",
    }
    return bool(
        encoded
        in {
            b"\x90", b"\xc3", b"\x89\xd8", b"\x8d\x03", b"\x89\xda",
            b"\x8d\x13", b"\x83\xc0\x00", b"\x83\xe8\x00", b"\x50",
            b"\xff\xf0", b"\x5b", b"\x8f\xc3", b"\x8d\x57\x04",
            b"\x8b\x06", b"\x8b\x46\x00", b"\x8b\x03", b"\x8b\x43\x00",
            b"\x8b\x0b", b"\x8b\x4b\x00", b"\x89\x02", b"\x89\x47\x04",
            b"\x89\x03", b"\x89\x43\x00", b"\x29\xc0", b"\x31\xc0",
            b"\x9b", b"\xa5", b"\xc9", b"\xf3\xa5",
        }
        or encoded in normalized_nops
        or (
            encoded.startswith(b"\x66")
            and (
                word_opcode in {0x2B, 0x39, 0x3B, 0x85, 0x89, 0x8B}
                or (word_opcode in {0x81, 0x83} and word_modrm_group in {0, 1, 4, 5, 6, 7})
                or (word_opcode == 0xC7 and word_modrm_group == 0)
                or (word_opcode == 0xF7 and word_modrm_group == 0)
                or word_opcode in {0x25, 0x2D, 0x3D}
                or 0xB8 <= word_opcode <= 0xBF
            )
        )
        or 0xB0 <= opcode <= 0xB7
        or opcode in {0x0A, 0x0C, 0x22, 0x24, 0x38, 0x3A, 0x3C, 0x84, 0x88, 0x8A, 0xA8}
        or (opcode in {0x80, 0xC6, 0xF6} and modrm_group in ({0, 1, 4, 5, 6, 7} if opcode == 0x80 else {0}))
        or (len(encoded) == 5 and 0xB8 <= opcode <= 0xBF)
        or (len(encoded) == 5 and opcode in {0x05, 0x0D, 0x25, 0x2D, 0x35, 0xA1, 0xA3, 0xA9, 0x3D})
        or (len(encoded) >= 3 and encoded[:2] == b"\x64\x8b")
        or (len(encoded) == 5 and opcode in {0xE8, 0xE9})
        or (len(encoded) == 6 and encoded[:2] in {b"\xff\x15", b"\xff\x25"})
        or (len(encoded) == 6 and encoded[0] == 0x0F and 0x80 <= encoded[1] <= 0x8F)
        or (len(encoded) >= 3 and encoded[0] == 0x0F and 0x40 <= encoded[1] <= 0x4F)
        or (len(encoded) >= 3 and encoded[0] == 0x0F and 0x90 <= encoded[1] <= 0x9F)
        or (len(encoded) >= 3 and encoded[:2] in {b"\x0f\xb6", b"\x0f\xb7", b"\x0f\xbe", b"\x0f\xbf"})
        or (len(encoded) >= 3 and encoded[:2] in {b"\x0f\xaf", b"\x0f\xbd"})
        or (len(encoded) >= 4 and encoded[:3] == b"\xf3\x0f\xbc")
        or (len(encoded) >= 3 and encoded[:2] in {b"\x0f\xa4", b"\x0f\xa5", b"\x0f\xac", b"\x0f\xad"})
        or (len(encoded) == 3 and encoded[:2] == b"\x83\xf8")
        or (len(encoded) == 3 and opcode == 0xC2)
        or (len(encoded) == 2 and (0x70 <= opcode <= 0x7F or opcode == 0xEB))
        or opcode in {0x01, 0x03, 0x09, 0x0B, 0x11, 0x13, 0x19, 0x1B, 0x21, 0x23, 0x29, 0x2B, 0x31, 0x33, 0x39, 0x3B, 0x85, 0x87, 0x89, 0x8B, 0x8D, 0x98, 0x99}
        or (opcode in {0x81, 0x83} and modrm_group in {0, 1, 2, 3, 4, 5, 6, 7})
        or (opcode == 0xC7 and modrm_group == 0)
        or (opcode in {0xC1, 0xD1, 0xD3} and modrm_group in {4, 5, 7})
        or opcode in {0x69, 0x6B}
        or (opcode == 0xF7 and modrm_group in {0, 2, 3, 4, 5, 6})
        or (len(encoded) >= 4 and encoded[:3] == b"\xf0\x0f\xb1")
        or (opcode == 0xFF and modrm_group in {2, 4, 6})
        or 0x50 <= opcode <= 0x5F
        or (
            len(encoded) == 2
            and (
                (opcode == 0xD9 and (0xC0 <= encoded[1] <= 0xCF or encoded[1] in {0xE0, 0xE5, 0xE8, 0xEE}))
                or (opcode == 0xDD and 0xD0 <= encoded[1] <= 0xDF)
                or (opcode == 0xD8 and (0xC0 <= encoded[1] <= 0xCF or 0xF0 <= encoded[1] <= 0xF7))
                or (opcode == 0xDC and 0xC8 <= encoded[1] <= 0xCF)
                or (opcode == 0xDE and (0xC0 <= encoded[1] <= 0xCF or 0xE0 <= encoded[1] <= 0xEF))
                or (opcode in {0xDB, 0xDF} and 0xE8 <= encoded[1] <= 0xF7)
                or encoded[:2] in {b"\xdb\xe3", b"\xdf\xe0"}
            )
        )
        or (
            len(encoded) >= 2
            and opcode in {0xD8, 0xD9, 0xDB, 0xDC, 0xDD}
            and ((encoded[1] >> 6) & 3) != 3
            and (
                (opcode in {0xD8, 0xDC} and modrm_group in {0, 1, 4, 5, 6, 7})
                or (opcode in {0xD9, 0xDB} and modrm_group in {0, 2, 3, 5, 7})
                or (opcode == 0xDD and modrm_group in {0, 2, 3})
            )
        )
    )


def side_diagnostics(
    side: str,
    path: Any,
    mapping_contract: dict[str, Any],
    *,
    issue_limit: int | None = None,
) -> list[dict[str, Any]]:
    """Return untrusted capability diagnostics for one PE32 side."""

    try:
        binary = _parse_stage_a_pe(path)
    except StageAInputError as exc:
        return [{"side": side, "category": "formal_pe_parse_failed", "blocker": str(exc)}]
    issues: list[dict[str, Any]] = []
    executable = [section for section in binary.sections if section.executable]
    if binary.bitness != 32:
        issues.append({"side": side, "category": "formal_profile_bitness", "observed": binary.bitness, "expected": 32})
    entry_sections = [
        section for section in executable
        if section.rva_start <= binary.entrypoint_rva < section.rva_end
    ]
    if len(entry_sections) != 1:
        issues.append({
            "side": side,
            "category": "formal_entrypoint_executable_section_count",
            "observed": len(entry_sections),
            "expected": 1,
        })
        return issues
    unsupported_relocations = sorted({
        int(entry.type)
        for block in getattr(binary.pe, "DIRECTORY_ENTRY_BASERELOC", []) or []
        for entry in block.entries
        if int(entry.type) not in {0, 3}
    })
    if unsupported_relocations:
        issues.append({
            "side": side,
            "category": "formal_relocation_kind_unsupported",
            "kinds": unsupported_relocations,
        })
    disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    disassembler.detail = True
    blocks = [
        item for item in mapping_contract.get("blocks", [])
        if isinstance(item, dict) and item.get("kind") == "code"
    ]
    if not blocks:
        issues.append({"side": side, "category": "formal_regions_missing"})
    for block in blocks:
        block_side = block.get(side) if isinstance(block.get(side), dict) else {}
        start = int(block_side.get("rva_start") or 0)
        stop = int(block_side.get("rva_end") or start)
        data = binary.pe.get_data(start, max(0, stop - start))
        decoded = list(disassembler.disasm(data, binary.image_base + start))
        if not decoded or sum(int(insn.size) for insn in decoded) != len(data):
            issues.append({
                "side": side,
                "category": "formal_instruction_decode_failed",
                "block": block.get("id"),
                "rva": start,
                "bytes": data[:16].hex(),
            })
            continue
        for insn in decoded:
            if instruction_supported(insn):
                continue
            issues.append({
                "side": side,
                "category": "formal_instruction_unsupported",
                "block": block.get("id"),
                "rva": int(insn.address - binary.image_base),
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "bytes": bytes(insn.bytes).hex(),
            })
            if issue_limit is not None and len(issues) >= issue_limit:
                return issues
    return issues

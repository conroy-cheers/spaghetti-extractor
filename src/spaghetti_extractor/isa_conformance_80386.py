"""Import hardware-generated 80386 vectors as PE32 conformance evidence.

SingleStepTests/80386 currently records real-mode executions.  This importer
does not pretend those executions happened in the Stage A PE32 profile.  It
admits only register/flag instructions whose real-mode and protected-32
decodes have identical explicit operands, and records every other vector as an
auditable exclusion.  Imported vectors remain veto-only evidence.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

import capstone
from capstone import x86_const

from .isa_conformance import (
    CPUProfile,
    CaseExpectation,
    ControlClass,
    DefinedOutputMasks,
    FSMask,
    FSState,
    FaultClass,
    GPR_NAMES,
    GPRState,
    ISAConformanceCorpus,
    ISAConformanceError,
    InstructionTestCase,
    MachineState,
    ObservedMemoryRegion,
    X87Mask,
    X87State,
    serialize_isa_conformance_corpus,
)


SINGLESTEP_80386_IMPORT_FORMAT = "stage-a-sst80386-import-v1"
SINGLESTEP_80386_SOURCE_SUITE = "SingleStepTests/80386"
SINGLESTEP_80386_POLICY = "real-mode-pure-register-to-pe32-v1"
PE32_IMAGE_BASE = 0x00400000
PE32_TEST_EIP = 0x00401000

_SHA1_RE = re.compile(r"[0-9a-f]{40}")
_GIT_REVISION_RE = re.compile(r"[0-9a-f]{40}")
_LEGACY_PREFIXES = {
    0xF0,
    0xF2,
    0xF3,
    0x2E,
    0x36,
    0x3E,
    0x26,
    0x64,
    0x65,
    0x66,
    0x67,
}
_ADMITTED_PREFIXES = {0x66, 0x67}
_MODELED_FLAG_BITS = {
    "o": 11,
    "d": 10,
    "i": 9,
    "s": 7,
    "z": 6,
    "a": 4,
    "p": 2,
    "c": 0,
}
# IF changes are environment/privilege-sensitive and are not admitted yet.
_PE32_CONFORMANCE_FLAG_MASK = sum(
    1 << bit for name, bit in _MODELED_FLAG_BITS.items() if name != "i"
)
_PURE_REGISTER_MNEMONICS = {
    "aaa",
    "aad",
    "aam",
    "aas",
    "adc",
    "add",
    "and",
    "bsf",
    "bsr",
    "bt",
    "btc",
    "btr",
    "bts",
    "cbw",
    "cdq",
    "clc",
    "cld",
    "cmc",
    "cmp",
    "cwd",
    "cwde",
    "daa",
    "das",
    "dec",
    "div",
    "idiv",
    "imul",
    "inc",
    "lahf",
    "mov",
    "movsx",
    "movzx",
    "mul",
    "neg",
    "nop",
    "not",
    "or",
    "rcl",
    "rcr",
    "rol",
    "ror",
    "sahf",
    "sar",
    "sbb",
    "shl",
    "shld",
    "shr",
    "shrd",
    "stc",
    "std",
    "sub",
    "test",
    "xchg",
    "xor",
}
_ALLOWED_REGISTER_NAMES = {
    "eax",
    "ax",
    "al",
    "ah",
    "ebx",
    "bx",
    "bl",
    "bh",
    "ecx",
    "cx",
    "cl",
    "ch",
    "edx",
    "dx",
    "dl",
    "dh",
    "esi",
    "si",
    "edi",
    "di",
    "ebp",
    "bp",
    "esp",
    "sp",
    "eip",
    "ip",
    "eflags",
    "flags",
}
_REJECTED_GROUPS = {
    capstone.CS_GRP_CALL,
    capstone.CS_GRP_INT,
    capstone.CS_GRP_IRET,
    capstone.CS_GRP_JUMP,
    capstone.CS_GRP_PRIVILEGE,
    capstone.CS_GRP_RET,
}
_CSV_FIELDS = (
    "op",
    "ct",
    "re",
    "g",
    "ex",
    "rm",
    "ud",
    "pf",
    "66",
    "67",
    "fc",
    "fpu",
    "pm",
    "lck",
    "rep",
    "so",
    "reg",
    "m",
    "uc",
    "fb",
    "w",
    "d",
    "sr",
    "ar",
    "nea",
    "io",
    "flds",
    "mc",
    "mnemonic",
    "dw_mnemonic",
    "w_mnemonic",
    "alt_names",
    "op1",
    "op2",
    "op3",
    "f_tested",
    "f_mod",
    "f_def",
    "f_undef",
    "f_umask",
    "f_values",
    "exceptions",
    "description",
)
_SOURCE_REGISTERS = {
    "cr0",
    "cr3",
    "eax",
    "ebx",
    "ecx",
    "edx",
    "esi",
    "edi",
    "ebp",
    "esp",
    "cs",
    "ds",
    "es",
    "fs",
    "gs",
    "ss",
    "eip",
    "eflags",
    "dr6",
    "dr7",
}


class ImportDecisionStatus(str, Enum):
    IMPORTED = "imported"
    EXCLUDED = "excluded"


class ImportReason(str, Enum):
    QUALIFIED = "qualified_mode_independent_register_form"
    REVOKED = "revoked_source_vector"
    OTHER_SHARD = "other_deterministic_shard"
    SAMPLE_LIMIT = "sample_limit"
    SOURCE_EXCEPTION = "source_exception"
    SOURCE_EIP = "source_eip_protocol_mismatch"
    SOURCE_MEMORY_EFFECT = "source_memory_effect"
    PREFIX = "unsupported_prefix"
    DECODE = "decode_or_mode_translation_failed"
    FORM = "non_register_or_environment_sensitive_form"
    METADATA = "missing_or_ambiguous_opcode_metadata"


@dataclass(frozen=True)
class ImportDecision:
    source_index: int
    source_hash: str
    source_name: str
    status: ImportDecisionStatus
    reason: ImportReason
    detail: str
    case_id: str | None = None
    source_instruction: bytes | None = None
    pe32_instruction: bytes | None = None

    def to_payload(self) -> dict[str, Any]:
        return {
            "source_index": self.source_index,
            "source_hash": self.source_hash,
            "source_name": self.source_name,
            "status": self.status.value,
            "reason": self.reason.value,
            "detail": self.detail,
            "case_id": self.case_id,
            "source_instruction": (
                None if self.source_instruction is None else self.source_instruction.hex()
            ),
            "pe32_instruction": (
                None if self.pe32_instruction is None else self.pe32_instruction.hex()
            ),
        }


@dataclass(frozen=True)
class SingleStep80386ImportResult:
    corpus: ISAConformanceCorpus
    manifest: dict[str, Any]


class _Excluded(Exception):
    def __init__(self, reason: ImportReason, detail: str):
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_object(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ISAConformanceError(f"{context} must be an object")
    return value


def _exact_fields(
    value: dict[str, Any], required: set[str], optional: set[str], context: str
) -> None:
    missing = required - set(value)
    unknown = set(value) - required - optional
    if missing or unknown:
        detail: list[str] = []
        if missing:
            detail.append(f"missing fields {sorted(missing)}")
        if unknown:
            detail.append(f"unknown fields {sorted(unknown)}")
        raise ISAConformanceError(f"{context} has " + " and ".join(detail))


def _uint(value: Any, bits: int, context: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value < 2**bits
    ):
        raise ISAConformanceError(f"{context} must be an unsigned {bits}-bit integer")
    return value


def _bytes(value: Any, context: str) -> bytes:
    if not isinstance(value, list) or not value:
        raise ISAConformanceError(f"{context} must be a non-empty byte list")
    result = bytearray()
    for index, byte in enumerate(value):
        result.append(_uint(byte, 8, f"{context}[{index}]"))
    return bytes(result)


def _ram(value: Any, context: str) -> tuple[tuple[int, int], ...]:
    if not isinstance(value, list):
        raise ISAConformanceError(f"{context} must be a list")
    result: list[tuple[int, int]] = []
    seen: set[int] = set()
    for index, row in enumerate(value):
        if not isinstance(row, list) or len(row) != 2:
            raise ISAConformanceError(f"{context}[{index}] must be [address, byte]")
        address = _uint(row[0], 32, f"{context}[{index}][0]")
        byte = _uint(row[1], 8, f"{context}[{index}][1]")
        if address in seen:
            raise ISAConformanceError(f"{context} contains duplicate address {address}")
        seen.add(address)
        result.append((address, byte))
    return tuple(result)


def _state(value: Any, context: str, *, initial: bool) -> dict[str, Any]:
    payload = _require_object(value, context)
    _exact_fields(payload, {"regs", "ram", "queue"}, {"ea"}, context)
    regs = _require_object(payload["regs"], f"{context}.regs")
    unknown = set(regs) - _SOURCE_REGISTERS
    missing = _SOURCE_REGISTERS - set(regs) if initial else set()
    if unknown or missing:
        raise ISAConformanceError(
            f"{context}.regs has missing {sorted(missing)} and unknown {sorted(unknown)}"
        )
    parsed_regs = {
        name: _uint(value, 32, f"{context}.regs.{name}")
        for name, value in regs.items()
    }
    queue = payload["queue"]
    if not isinstance(queue, list) or any(
        isinstance(item, bool) or not isinstance(item, int) or not 0 <= item <= 255
        for item in queue
    ):
        raise ISAConformanceError(f"{context}.queue must be a byte list")
    if "ea" in payload and not isinstance(payload["ea"], dict):
        raise ISAConformanceError(f"{context}.ea must be an object")
    return {
        "regs": parsed_regs,
        "ram": _ram(payload["ram"], f"{context}.ram"),
        "queue": tuple(queue),
        "ea": payload.get("ea"),
    }


def _source_rows(path: Path) -> list[dict[str, Any]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ISAConformanceError(f"cannot read converted 80386 JSON {path}: {exc}") from exc
    if not isinstance(payload, list) or not payload:
        raise ISAConformanceError("converted 80386 JSON must be a non-empty list")
    rows: list[dict[str, Any]] = []
    indices: set[int] = set()
    hashes: set[str] = set()
    for position, raw in enumerate(payload):
        context = f"80386 test[{position}]"
        row = _require_object(raw, context)
        _exact_fields(
            row,
            {"idx", "name", "bytes", "initial", "final", "cycles", "hash"},
            {"exception"},
            context,
        )
        index = _uint(row["idx"], 32, f"{context}.idx")
        if index in indices:
            raise ISAConformanceError(f"converted 80386 JSON has duplicate index {index}")
        indices.add(index)
        name = row["name"]
        if not isinstance(name, str) or not name:
            raise ISAConformanceError(f"{context}.name must be a non-empty string")
        source_hash = row["hash"]
        if not isinstance(source_hash, str) or _SHA1_RE.fullmatch(source_hash) is None:
            raise ISAConformanceError(f"{context}.hash must be lowercase SHA-1 hex")
        if source_hash in hashes:
            raise ISAConformanceError(
                f"converted 80386 JSON has duplicate hash {source_hash}"
            )
        hashes.add(source_hash)
        if not isinstance(row["cycles"], list):
            raise ISAConformanceError(f"{context}.cycles must be a list")
        exception = row.get("exception")
        if exception is not None:
            exception = _require_object(exception, f"{context}.exception")
            _exact_fields(
                exception,
                {"number", "flag_address"},
                set(),
                f"{context}.exception",
            )
            _uint(exception["number"], 8, f"{context}.exception.number")
            _uint(exception["flag_address"], 32, f"{context}.exception.flag_address")
        rows.append(
            {
                "idx": index,
                "name": name,
                "bytes": _bytes(row["bytes"], f"{context}.bytes"),
                "initial": _state(row["initial"], f"{context}.initial", initial=True),
                "final": _state(row["final"], f"{context}.final", initial=False),
                "exception": exception,
                "hash": source_hash,
            }
        )
    if [row["idx"] for row in rows] != sorted(row["idx"] for row in rows):
        raise ISAConformanceError("converted 80386 JSON rows must be index-sorted")
    return rows


def _metadata(path: Path) -> list[dict[str, str]]:
    try:
        with path.open(encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            if tuple(reader.fieldnames or ()) != _CSV_FIELDS:
                raise ISAConformanceError(
                    "80386 metadata CSV has an unexpected or reordered header"
                )
            rows = [dict(row) for row in reader]
    except OSError as exc:
        raise ISAConformanceError(f"cannot read 80386 metadata CSV {path}: {exc}") from exc
    if not rows:
        raise ISAConformanceError("80386 metadata CSV must not be empty")
    return rows


def _revocations(path: Path) -> set[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ISAConformanceError(f"cannot read 80386 revocation list {path}: {exc}") from exc
    result: set[str] = set()
    for number, line in enumerate(lines, start=1):
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        if _SHA1_RE.fullmatch(value) is None:
            raise ISAConformanceError(
                f"80386 revocation list line {number} is not lowercase SHA-1 hex"
            )
        if value in result:
            raise ISAConformanceError("80386 revocation list contains duplicates")
        result.add(value)
    return result


def _opcode_key(source_name: str) -> str:
    name = Path(source_name).name
    for suffix in (".MOO.gz.json", ".moo.gz.json", ".MOO.json", ".moo.json", ".json"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    key = name.upper()
    if re.fullmatch(r"(?:66|67)*(?:0F)?[0-9A-F]{2}(?:\.[0-9A-F]+)?", key) is None:
        raise ISAConformanceError(
            f"cannot derive an opcode key from converted test filename {source_name!r}"
        )
    while key.startswith(("66", "67")):
        key = key[2:]
    return key.split(".", 1)[0]


def _decode(data: bytes, mode: int) -> Any | None:
    decoder = capstone.Cs(capstone.CS_ARCH_X86, mode)
    decoder.detail = True
    instructions = list(decoder.disasm(data, PE32_TEST_EIP, count=1))
    return instructions[0] if instructions else None


def _prefix_inventory(data: bytes) -> tuple[int, ...]:
    result: list[int] = []
    for byte in data:
        if byte not in _LEGACY_PREFIXES:
            break
        result.append(byte)
    return tuple(result)


def _toggle_prefix(data: bytes, prefix: int) -> bytes:
    inventory = _prefix_inventory(data)
    if inventory.count(prefix) > 1:
        return b""
    if prefix in inventory:
        index = data.index(prefix)
        return data[:index] + data[index + 1 :]
    return bytes([prefix]) + data


def _operand_signature(instruction: Any) -> tuple[Any, ...] | None:
    operands: list[tuple[Any, ...]] = []
    for operand in instruction.operands:
        if operand.type == x86_const.X86_OP_REG:
            operands.append(
                ("reg", instruction.reg_name(operand.reg).lower(), int(operand.size))
            )
        elif operand.type == x86_const.X86_OP_IMM:
            bits = max(8, int(operand.size) * 8)
            operands.append(("imm", int(operand.imm) & ((1 << bits) - 1), int(operand.size)))
        else:
            return None
    return (instruction.mnemonic.lower(), tuple(operands))


def _pure_register_form(instruction: Any) -> str | None:
    mnemonic = instruction.mnemonic.lower()
    if mnemonic not in _PURE_REGISTER_MNEMONICS and not mnemonic.startswith("set"):
        return f"mnemonic {mnemonic!r} is not in the reviewed pure-register profile"
    if set(instruction.groups) & _REJECTED_GROUPS:
        return "control, interrupt, return, or privileged instruction group"
    if instruction.group(x86_const.X86_GRP_FPU):
        return "x87 instruction"
    if _operand_signature(instruction) is None:
        return "explicit memory operand"
    try:
        read, written = instruction.regs_access()
    except capstone.CsError as exc:
        return f"Capstone register access inventory failed: {exc}"
    names = {
        instruction.reg_name(register).lower() for register in (*read, *written)
    }
    unsupported = sorted(name for name in names if name not in _ALLOWED_REGISTER_NAMES)
    if unsupported:
        return f"unmodeled implicit registers {unsupported}"
    return None


def _translate_instruction(row: dict[str, Any]) -> tuple[bytes, bytes, Any]:
    source = _decode(row["bytes"], capstone.CS_MODE_16)
    if source is None or source.size <= 0:
        raise _Excluded(ImportReason.DECODE, "Capstone could not decode source instruction")
    source_bytes = row["bytes"][: source.size]
    if source.size >= len(row["bytes"]) or row["bytes"][source.size] != 0xF4:
        raise _Excluded(
            ImportReason.SOURCE_EIP,
            "source vector does not place HLT immediately after one decoded instruction",
        )
    prefixes = _prefix_inventory(source_bytes)
    if any(prefix not in _ADMITTED_PREFIXES for prefix in prefixes):
        raise _Excluded(
            ImportReason.PREFIX,
            f"prefix inventory {[hex(prefix) for prefix in prefixes]} is environment-sensitive",
        )
    if len(prefixes) != len(set(prefixes)):
        raise _Excluded(ImportReason.PREFIX, "repeated size prefixes are not admitted")
    source_form = _pure_register_form(source)
    if source_form is not None:
        raise _Excluded(ImportReason.FORM, source_form)
    source_signature = _operand_signature(source)
    assert source_signature is not None

    candidates = {source_bytes}
    for first in tuple(candidates):
        candidates.add(_toggle_prefix(first, 0x66))
        candidates.add(_toggle_prefix(first, 0x67))
        candidates.add(_toggle_prefix(_toggle_prefix(first, 0x66), 0x67))
    matches: list[tuple[bytes, Any]] = []
    for candidate in sorted(candidates, key=lambda item: (len(item), item)):
        if not candidate or len(candidate) > 15:
            continue
        decoded = _decode(candidate, capstone.CS_MODE_32)
        if decoded is None or decoded.size != len(candidate):
            continue
        if _operand_signature(decoded) != source_signature:
            continue
        form_issue = _pure_register_form(decoded)
        if form_issue is None:
            matches.append((candidate, decoded))
    if not matches:
        raise _Excluded(
            ImportReason.DECODE,
            "no protected-32 encoding has the same reviewed register operands",
        )
    pe32_bytes, pe32 = matches[0]
    return source_bytes, pe32_bytes, pe32


def _metadata_row(
    rows: list[dict[str, str]], opcode: str, mnemonic: str
) -> dict[str, str]:
    mnemonic_upper = mnemonic.upper()
    matches: list[dict[str, str]] = []
    for row in rows:
        names = {row["mnemonic"].upper()}
        names.update(
            item.strip().upper()
            for item in re.split(r"[,/]", row["alt_names"])
            if item.strip()
        )
        if row["op"].upper() == opcode and mnemonic_upper in names:
            matches.append(row)
    if len(matches) != 1:
        raise _Excluded(
            ImportReason.METADATA,
            f"opcode {opcode} mnemonic {mnemonic_upper} matched {len(matches)} metadata rows",
        )
    return matches[0]


def _undefined_flag_mask(pattern: str) -> int:
    if not pattern:
        return 0
    if len(pattern) != 8:
        raise ISAConformanceError(f"invalid 80386 flag pattern {pattern!r}")
    result = 0
    for character, name in zip(pattern.lower(), _MODELED_FLAG_BITS, strict=True):
        if character == ".":
            continue
        if character != name:
            raise ISAConformanceError(f"invalid 80386 flag pattern {pattern!r}")
        result |= 1 << _MODELED_FLAG_BITS[name]
    return result


def _canonical_eflags(value: int) -> int:
    return 0x202 | (value & _PE32_CONFORMANCE_FLAG_MASK)


def _x87_state() -> X87State:
    return X87State(
        control_word=0x037F,
        status_word=0,
        tag_word=0xFFFF,
        last_opcode=0,
        instruction_pointer=0,
        data_pointer=0,
        registers=tuple(bytes(10) for _ in range(8)),
    )


def _x87_mask() -> X87Mask:
    return X87Mask(
        control_word=0,
        status_word=0,
        tag_word=0,
        last_opcode=0,
        instruction_pointer=0,
        data_pointer=0,
        registers=tuple(bytes(10) for _ in range(8)),
    )


def _gprs(values: dict[str, int]) -> GPRState:
    return GPRState(**{name: values[name] for name in GPR_NAMES})


def _case_from_row(
    row: dict[str, Any],
    metadata_rows: list[dict[str, str]],
    opcode: str,
) -> tuple[InstructionTestCase, ImportDecision]:
    if row["exception"] is not None:
        raise _Excluded(
            ImportReason.SOURCE_EXCEPTION,
            f"hardware vector raised exception {row['exception']['number']}",
        )
    if row["initial"]["ea"] is not None or row["final"]["ea"] is not None:
        raise _Excluded(ImportReason.FORM, "source vector carries effective-address state")
    allowed_final_registers = set(GPR_NAMES) | {"eip", "eflags"}
    hidden_changes = sorted(set(row["final"]["regs"]) - allowed_final_registers)
    if hidden_changes:
        raise _Excluded(
            ImportReason.FORM,
            f"source vector changes non-PE32 register state {hidden_changes}",
        )
    if row["final"]["ram"]:
        raise _Excluded(
            ImportReason.SOURCE_MEMORY_EFFECT,
            "hardware vector reports a memory effect",
        )
    source_bytes, pe32_bytes, instruction = _translate_instruction(row)
    initial_regs = row["initial"]["regs"]
    source_linear_eip = (initial_regs["cs"] << 4) + initial_regs["eip"]
    source_ram = dict(row["initial"]["ram"])
    source_protocol = source_bytes + b"\xf4"
    observed_protocol = bytes(
        source_ram.get(source_linear_eip + offset, -1)
        for offset in range(len(source_protocol))
    ) if all(
        source_linear_eip + offset in source_ram
        for offset in range(len(source_protocol))
    ) else b""
    if observed_protocol != source_protocol:
        raise _Excluded(
            ImportReason.SOURCE_EIP,
            "initial RAM does not contain the decoded instruction and HLT at CS:EIP",
        )
    final_delta = row["final"]["regs"]
    source_final_eip = final_delta.get("eip")
    expected_source_eip = initial_regs["eip"] + len(source_bytes) + 1
    if source_final_eip != expected_source_eip:
        raise _Excluded(
            ImportReason.SOURCE_EIP,
            f"hardware final EIP {source_final_eip!r} != instruction+HLT fallthrough {expected_source_eip}",
        )
    metadata = _metadata_row(metadata_rows, opcode, instruction.mnemonic)
    undefined_mask = _undefined_flag_mask(metadata["f_undef"])
    initial_gprs = _gprs(initial_regs)
    final_regs = dict(initial_regs)
    final_regs.update(final_delta)
    final_gprs = _gprs(final_regs)
    initial_state = MachineState(
        gprs=initial_gprs,
        eip=PE32_TEST_EIP,
        eflags=_canonical_eflags(initial_regs["eflags"]),
        fs=FSState(selector=0, base=0),
        x87=_x87_state(),
    )
    final_state = MachineState(
        gprs=final_gprs,
        eip=PE32_TEST_EIP + len(pe32_bytes),
        eflags=_canonical_eflags(final_regs["eflags"]),
        fs=FSState(selector=0, base=0),
        x87=_x87_state(),
    )
    case_id = (
        f"sst80386-{opcode.lower()}-{row['idx']:05d}-{row['hash'][:12]}"
    )
    case = InstructionTestCase(
        id=case_id,
        instruction_bytes=pe32_bytes,
        profile=CPUProfile(cpu="haswell", features=()),
        image_base=PE32_IMAGE_BASE,
        initial_state=initial_state,
        memory=(),
        defined_outputs=DefinedOutputMasks(
            gprs=GPRState(**{name: 0xFFFFFFFF for name in GPR_NAMES}),
            eip=0xFFFFFFFF,
            eflags=_PE32_CONFORMANCE_FLAG_MASK & ~undefined_mask,
            fs=FSMask(selector=0, base=0),
            x87=_x87_mask(),
            memory=(),
        ),
        expected=CaseExpectation(
            final_state=final_state,
            memory=tuple[ObservedMemoryRegion, ...](),
            control=ControlClass.FALLTHROUGH,
            fault=FaultClass.NONE,
        ),
    )
    case.to_payload()
    return case, ImportDecision(
        source_index=row["idx"],
        source_hash=row["hash"],
        source_name=row["name"],
        status=ImportDecisionStatus.IMPORTED,
        reason=ImportReason.QUALIFIED,
        detail=(
            f"{source_bytes.hex()} decoded as {instruction.mnemonic} with the same "
            "register operands after protected-32 normalization"
        ),
        case_id=case_id,
        source_instruction=source_bytes,
        pe32_instruction=pe32_bytes,
    )


def import_singlestep_80386_json(
    *,
    tests_json: Path,
    metadata_csv: Path,
    revocations: Path,
    source_revision: str,
    shard_index: int = 0,
    shard_count: int = 1,
    max_cases: int | None = None,
) -> SingleStep80386ImportResult:
    """Convert a strict subset of converted hardware vectors into PE32 cases."""
    tests_json = Path(tests_json)
    metadata_csv = Path(metadata_csv)
    revocations = Path(revocations)
    if _GIT_REVISION_RE.fullmatch(source_revision) is None:
        raise ISAConformanceError("source_revision must be a lowercase 40-hex Git commit")
    if shard_count <= 0 or not 0 <= shard_index < shard_count:
        raise ISAConformanceError("shard_index must be within a positive shard_count")
    if max_cases is not None and max_cases <= 0:
        raise ISAConformanceError("max_cases must be positive when supplied")

    source_rows = _source_rows(tests_json)
    metadata_rows = _metadata(metadata_csv)
    revoked = _revocations(revocations)
    opcode = _opcode_key(tests_json.name)
    decisions: list[ImportDecision] = []
    cases: list[InstructionTestCase] = []
    for row in source_rows:
        if row["hash"] in revoked:
            decisions.append(
                ImportDecision(
                    row["idx"],
                    row["hash"],
                    row["name"],
                    ImportDecisionStatus.EXCLUDED,
                    ImportReason.REVOKED,
                    "source hash is present in the pinned revocation list",
                )
            )
            continue
        shard = int(row["hash"][:16], 16) % shard_count
        if shard != shard_index:
            decisions.append(
                ImportDecision(
                    row["idx"],
                    row["hash"],
                    row["name"],
                    ImportDecisionStatus.EXCLUDED,
                    ImportReason.OTHER_SHARD,
                    f"deterministic shard {shard} is not requested shard {shard_index}",
                )
            )
            continue
        if max_cases is not None and len(cases) >= max_cases:
            decisions.append(
                ImportDecision(
                    row["idx"],
                    row["hash"],
                    row["name"],
                    ImportDecisionStatus.EXCLUDED,
                    ImportReason.SAMPLE_LIMIT,
                    f"qualified-case limit {max_cases} has been reached",
                )
            )
            continue
        try:
            case, decision = _case_from_row(row, metadata_rows, opcode)
        except _Excluded as exc:
            decisions.append(
                ImportDecision(
                    row["idx"],
                    row["hash"],
                    row["name"],
                    ImportDecisionStatus.EXCLUDED,
                    exc.reason,
                    exc.detail,
                )
            )
        else:
            cases.append(case)
            decisions.append(decision)
    if not cases:
        reasons = Counter(decision.reason.value for decision in decisions)
        examples = "; ".join(
            f"test {decision.source_index}: {decision.detail}"
            for decision in decisions[:3]
        )
        raise ISAConformanceError(
            "80386 import produced no qualified PE32 cases: "
            + ", ".join(f"{reason}={count}" for reason, count in sorted(reasons.items()))
            + (f"; examples: {examples}" if examples else "")
        )

    source_hashes = {
        "tests_json_sha256": _sha256(tests_json),
        "metadata_csv_sha256": _sha256(metadata_csv),
        "revocations_sha256": _sha256(revocations),
    }
    corpus_seed = json.dumps(
        {
            "source_revision": source_revision,
            "source_hashes": source_hashes,
            "opcode": opcode,
            "shard_index": shard_index,
            "shard_count": shard_count,
            "max_cases": max_cases,
            "case_ids": [case.id for case in cases],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    corpus_id = "sst80386-pe32-" + hashlib.sha256(corpus_seed).hexdigest()[:20]
    corpus = ISAConformanceCorpus(id=corpus_id, cases=tuple(cases))
    corpus_payload = serialize_isa_conformance_corpus(corpus)
    corpus_sha256 = hashlib.sha256(
        json.dumps(corpus_payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    reason_counts = Counter(decision.reason.value for decision in decisions)
    manifest = {
        "format": SINGLESTEP_80386_IMPORT_FORMAT,
        "status": "complete",
        "policy": SINGLESTEP_80386_POLICY,
        "source": {
            "suite": SINGLESTEP_80386_SOURCE_SUITE,
            "revision": source_revision,
            "converted_test_file": tests_json.name,
            "opcode": opcode,
            **source_hashes,
        },
        "target_profile": {
            "architecture": "x86",
            "execution_mode": "protected-32",
            "environment": "pe32",
            "cpu": "haswell",
        },
        "selection": {
            "shard_index": shard_index,
            "shard_count": shard_count,
            "max_cases": max_cases,
        },
        "corpus": {
            "id": corpus.id,
            "sha256": corpus_sha256,
            "case_count": len(corpus.cases),
        },
        "counts": {
            "source": len(source_rows),
            "imported": len(cases),
            "excluded": len(source_rows) - len(cases),
            "by_reason": dict(sorted(reason_counts.items())),
        },
        "decisions": [decision.to_payload() for decision in decisions],
        "trust": {
            "role": "isa_conformance_evidence_only",
            "proof_authority": False,
            "closes_stage_a_proof": False,
        },
    }
    return SingleStep80386ImportResult(corpus=corpus, manifest=manifest)


__all__ = [
    "ImportDecision",
    "ImportDecisionStatus",
    "ImportReason",
    "SINGLESTEP_80386_IMPORT_FORMAT",
    "SINGLESTEP_80386_POLICY",
    "SingleStep80386ImportResult",
    "import_singlestep_80386_json",
]

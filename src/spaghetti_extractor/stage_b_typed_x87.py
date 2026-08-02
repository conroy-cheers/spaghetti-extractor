"""Stable typed x87 artifact definitions shared by proof and candidate code."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

import capstone
from capstone import x86_const

from .stage_binary import StageAInputError
from .util import sha256_bytes


TYPED_NATIVE_X87_OPERATION_FORMAT = "stage-b-typed-native-x87-operation-v1"
TYPED_NATIVE_X87_PROGRAM_FORMAT = "stage-b-typed-native-x87-program-v1"
X87_CHECKED_DECODER = "StageA.Relational.X87.decodeSingletonCommand"
X87_CHECKED_EXECUTOR = "StageA.Relational.X87.executeSingletonCommand"

X87_MEMORY_NO_SIZE_MNEMONICS = frozenset({
    "fldenv", "fnstenv", "fstenv", "frstor", "fnsave", "fsave",
})
X87_MEMORY_SIZE_KEYWORDS = {
    2: "WORD PTR",
    4: "DWORD PTR",
    8: "QWORD PTR",
    10: "TBYTE PTR",
}

_X87_GPRS = frozenset({"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"})
_X87_NO_OPERAND_MNEMONICS = frozenset({
    "f2xm1", "fabs", "fchs", "fclex", "fnclex", "fcos", "fdecstp",
    "fincstp", "finit", "fninit", "fld1", "fldl2e", "fldl2t", "fldlg2",
    "fldln2", "fldpi", "fldz", "fnop", "fpatan", "fprem", "fprem1",
    "fptan", "frndint", "fscale", "fsin", "fsincos", "fsqrt", "ftst",
    "fucompp", "fxam", "fyl2x", "fyl2xp1", "wait",
})
_X87_STACK_MNEMONICS = frozenset({
    "fadd", "faddp", "fcom", "fcomp", "fcomi", "fcomip", "fcompi", "fdiv",
    "fdivp", "fdivr", "fdivrp", "ffree", "ffreep", "fld", "fmul",
    "fmulp", "fst", "fstp", "fsub", "fsubp", "fsubr", "fsubrp",
    "fucom", "fucomp", "fucomi", "fucomip", "fucompi", "fxch",
})
_X87_AX_MNEMONICS = frozenset({"fnstsw", "fstsw"})
_X87_MEMORY_WIDTHS: dict[str, frozenset[int]] = {
    **{
        mnemonic: frozenset({4, 8})
        for mnemonic in (
            "fadd", "fcom", "fcomp", "fdiv", "fdivr", "fmul", "fst",
            "fsub", "fsubr",
        )
    },
    **{
        mnemonic: frozenset({2, 4})
        for mnemonic in (
            "fiadd", "ficom", "ficomp", "fidiv", "fidivr", "fimul",
            "fist", "fisub", "fisubr",
        )
    },
    "fild": frozenset({2, 4, 8}),
    "fistp": frozenset({2, 4, 8}),
    "fbld": frozenset({10}),
    "fbstp": frozenset({10}),
    "fldcw": frozenset({2}),
    "fnstcw": frozenset({2}),
    "fstcw": frozenset({2}),
    "fnstsw": frozenset({2}),
    "fstsw": frozenset({2}),
    "fldenv": frozenset({14, 28}),
    "fnstenv": frozenset({14, 28}),
    "fstenv": frozenset({14, 28}),
    "frstor": frozenset({94, 108}),
    "fnsave": frozenset({94, 108}),
    "fsave": frozenset({94, 108}),
    "fld": frozenset({4, 8, 10}),
    "fstp": frozenset({4, 8, 10}),
}


@dataclass(frozen=True)
class TypedX87Operand:
    kind: str
    width: int = 0
    registers: tuple[int, ...] = ()
    base: str | None = None
    index: str | None = None
    scale: int = 1
    displacement: int = 0
    image_rva: int | None = None

    def payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"kind": self.kind}
        if self.width:
            payload["width"] = self.width
        if self.registers:
            payload["stack_registers"] = list(self.registers)
        if self.kind == "memory":
            payload["address"] = {
                "base": self.base,
                "index": self.index,
                "scale": self.scale,
                "displacement": self.displacement,
                "image_rva": self.image_rva,
            }
        return payload


@dataclass(frozen=True)
class TypedX87Operation:
    mnemonic: str
    operand: TypedX87Operand
    source_size: int
    identity: str

    def semantic_payload(self) -> dict[str, Any]:
        return {
            "format": TYPED_NATIVE_X87_OPERATION_FORMAT,
            "mnemonic": self.mnemonic,
            "operand": self.operand.payload(),
        }

    def payload(self) -> dict[str, Any]:
        return {
            **self.semantic_payload(),
            "identity": self.identity,
            "source_size": self.source_size,
        }


def _operation(
    *, mnemonic: str, operand: TypedX87Operand, source_size: int
) -> TypedX87Operation:
    semantic = {
        "format": TYPED_NATIVE_X87_OPERATION_FORMAT,
        "mnemonic": mnemonic,
        "operand": operand.payload(),
    }
    return TypedX87Operation(
        mnemonic=mnemonic,
        operand=operand,
        source_size=source_size,
        identity=sha256_bytes(
            json.dumps(
                semantic, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode("ascii")
        ),
    )


def _register_operand(mnemonic: str, names: tuple[str, ...]) -> TypedX87Operand:
    if names == ("ax",):
        if mnemonic not in _X87_AX_MNEMONICS:
            raise StageAInputError(f"unsupported x87 AX form {mnemonic!r}")
        return TypedX87Operand("ax", width=2)
    registers: list[int] = []
    for name in names:
        match = re.fullmatch(r"st\(([0-7])\)", name)
        if match is None:
            raise StageAInputError(f"unsupported x87 register operand {name!r}")
        registers.append(int(match.group(1)))
    if mnemonic not in _X87_STACK_MNEMONICS or len(registers) not in {1, 2}:
        raise StageAInputError(f"unsupported x87 stack-register form {mnemonic!r}")
    return TypedX87Operand("stack", width=10, registers=tuple(registers))


def _memory_operand(
    *,
    mnemonic: str,
    width: int,
    segment: str | None,
    base: str | None,
    index: str | None,
    scale: int,
    displacement: int,
    image_base: int,
) -> TypedX87Operand:
    width = _normalized_x87_memory_width(mnemonic, width)
    if width not in _X87_MEMORY_WIDTHS.get(mnemonic, frozenset()):
        raise StageAInputError(
            f"unsupported x87 memory form {mnemonic!r} with width {width}"
        )
    if segment:
        raise StageAInputError(f"unsupported x87 segment override {segment!r}")
    if base not in _X87_GPRS | {None} or index not in _X87_GPRS | {None}:
        raise StageAInputError("typed x87 memory operand has an unsupported register")
    if scale not in {1, 2, 4, 8} or (index is None and scale != 1):
        raise StageAInputError("typed x87 memory operand has an unsupported scale")
    image_rva: int | None = None
    if image_base <= displacement <= image_base + 0xFFFFFFFF:
        image_rva = displacement - image_base
        displacement = 0
    elif base is None and index is None:
        raise StageAInputError("absolute typed x87 operand is outside its PE image")
    return TypedX87Operand(
        "memory",
        width=width,
        base=base,
        index=index,
        scale=scale,
        displacement=displacement,
        image_rva=image_rva,
    )


def extract_typed_x87_operation(
    *, encoded: bytes, instruction: Mapping[str, Any], image_base: int
) -> TypedX87Operation:
    """Validate exact source bytes once and return a byte-free x87 operation."""

    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    decoded = list(decoder.disasm(encoded, image_base, count=2))
    if len(decoded) != 1 or decoded[0].size != len(encoded):
        raise StageAInputError("x87 typed operation is not one exact IA-32 instruction")
    decoded_instruction = decoded[0]
    mnemonic = decoded_instruction.mnemonic.lower()
    guidance_mnemonic = instruction.get("mnemonic")
    guidance_operand = instruction.get("op_str")
    if guidance_mnemonic is not None and (
        not isinstance(guidance_mnemonic, str)
        or guidance_mnemonic.lower() != mnemonic
    ):
        raise StageAInputError("x87 typed mnemonic differs from the exact decoded bytes")
    if guidance_operand is not None and (
        not isinstance(guidance_operand, str)
        or guidance_operand.strip().lower()
        != decoded_instruction.op_str.strip().lower()
    ):
        raise StageAInputError("x87 typed operands differ from the exact decoded bytes")
    operands = tuple(decoded_instruction.operands)
    if not operands:
        if mnemonic not in _X87_NO_OPERAND_MNEMONICS:
            raise StageAInputError(f"unsupported operand-free x87 mnemonic {mnemonic!r}")
        operand = TypedX87Operand("none")
    elif all(item.type == x86_const.X86_OP_REG for item in operands):
        operand = _register_operand(
            mnemonic,
            tuple(decoded_instruction.reg_name(item.reg).lower() for item in operands),
        )
    elif len(operands) == 1 and operands[0].type == x86_const.X86_OP_MEM:
        raw = operands[0]
        memory = raw.mem
        operand = _memory_operand(
            mnemonic=mnemonic,
            width=int(raw.size),
            segment=(
                decoded_instruction.reg_name(memory.segment).lower()
                if memory.segment
                else None
            ),
            base=(
                decoded_instruction.reg_name(memory.base).lower()
                if memory.base
                else None
            ),
            index=(
                decoded_instruction.reg_name(memory.index).lower()
                if memory.index
                else None
            ),
            scale=int(memory.scale),
            displacement=int(memory.disp),
            image_base=image_base,
        )
    else:
        raise StageAInputError(f"unsupported typed x87 operand form for {mnemonic!r}")
    return _operation(mnemonic=mnemonic, operand=operand, source_size=len(encoded))


def typed_x87_operation_from_micro_op(
    micro_op: Mapping[str, Any], *, image_base: int
) -> TypedX87Operation:
    """Validate the byte-free machine-IR x87 projection used by Stage B."""

    if micro_op.get("format") != "stage-a-x87-micro-op-v1":
        raise StageAInputError("typed x87 micro-op has an unsupported format")
    mnemonic = micro_op.get("mnemonic")
    operands = micro_op.get("operands")
    size = micro_op.get("size")
    if not isinstance(mnemonic, str) or not mnemonic or not isinstance(operands, list):
        raise StageAInputError("typed x87 micro-op mnemonic or operands are malformed")
    if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
        raise StageAInputError("typed x87 micro-op source size is malformed")
    mnemonic = mnemonic.lower()
    if not operands:
        if mnemonic not in _X87_NO_OPERAND_MNEMONICS:
            raise StageAInputError(f"unsupported operand-free x87 mnemonic {mnemonic!r}")
        operand = TypedX87Operand("none")
    elif all(
        isinstance(item, Mapping) and item.get("kind") == "register"
        for item in operands
    ):
        operand = _register_operand(
            mnemonic, tuple(str(item.get("name") or "").lower() for item in operands)
        )
    elif (
        len(operands) == 1
        and isinstance(operands[0], Mapping)
        and operands[0].get("kind") == "memory"
    ):
        raw = operands[0]
        width_bits = raw.get("width_bits")
        scale = raw.get("scale")
        displacement = raw.get("displacement")
        if (
            isinstance(width_bits, bool)
            or not isinstance(width_bits, int)
            or width_bits % 8
        ):
            raise StageAInputError("typed x87 memory width is malformed")
        if not isinstance(scale, int) or isinstance(scale, bool):
            raise StageAInputError("typed x87 memory scale is malformed")
        if isinstance(displacement, bool) or not isinstance(displacement, int):
            raise StageAInputError("typed x87 memory displacement is malformed")
        segment = _optional_string(raw, "segment", "typed x87 memory segment")
        base = _optional_string(raw, "base", "typed x87 memory base")
        index = _optional_string(raw, "index", "typed x87 memory index")
        operand = _memory_operand(
            mnemonic=mnemonic,
            width=width_bits // 8,
            segment=segment,
            base=base,
            index=index,
            scale=scale,
            displacement=displacement,
            image_base=image_base,
        )
    else:
        raise StageAInputError(f"unsupported typed x87 operand form for {mnemonic!r}")
    return _operation(mnemonic=mnemonic, operand=operand, source_size=size)


def typed_x87_operation_from_payload(
    payload: Mapping[str, Any], *, image_base: int
) -> TypedX87Operation:
    """Validate and reconstruct one canonical byte-free x87 operation."""

    if payload.get("format") != TYPED_NATIVE_X87_OPERATION_FORMAT:
        raise StageAInputError("typed x87 operation has an unsupported format")
    mnemonic = payload.get("mnemonic")
    source_size = payload.get("source_size")
    operand_payload = payload.get("operand")
    if not isinstance(mnemonic, str) or not mnemonic or mnemonic != mnemonic.lower():
        raise StageAInputError("typed x87 operation mnemonic is malformed")
    if (
        isinstance(source_size, bool)
        or not isinstance(source_size, int)
        or source_size <= 0
    ):
        raise StageAInputError("typed x87 operation source size is malformed")
    if not isinstance(operand_payload, Mapping):
        raise StageAInputError("typed x87 operation operand is malformed")

    kind = operand_payload.get("kind")
    if kind == "none":
        operand = TypedX87Operand("none")
    elif kind == "ax":
        operand = _register_operand(mnemonic, ("ax",))
    elif kind == "stack":
        registers = operand_payload.get("stack_registers")
        if not isinstance(registers, list) or not registers:
            raise StageAInputError("typed x87 stack-register inventory is malformed")
        if any(
            isinstance(register, bool)
            or not isinstance(register, int)
            or not 0 <= register <= 7
            for register in registers
        ):
            raise StageAInputError("typed x87 stack-register index is malformed")
        operand = _register_operand(
            mnemonic, tuple(f"st({register})" for register in registers)
        )
    elif kind == "memory":
        width = operand_payload.get("width")
        address = operand_payload.get("address")
        if isinstance(width, bool) or not isinstance(width, int) or width <= 0:
            raise StageAInputError("typed x87 memory width is malformed")
        if not isinstance(address, Mapping):
            raise StageAInputError("typed x87 memory address is malformed")
        base = _optional_string(address, "base", "typed x87 memory base")
        index = _optional_string(address, "index", "typed x87 memory index")
        scale = address.get("scale")
        displacement = address.get("displacement")
        image_rva = address.get("image_rva")
        if isinstance(scale, bool) or not isinstance(scale, int):
            raise StageAInputError("typed x87 memory scale is malformed")
        if isinstance(displacement, bool) or not isinstance(displacement, int):
            raise StageAInputError("typed x87 memory displacement is malformed")
        if image_rva is not None and (
            isinstance(image_rva, bool)
            or not isinstance(image_rva, int)
            or not 0 <= image_rva <= 0xFFFFFFFF
        ):
            raise StageAInputError("typed x87 image RVA is malformed")
        if image_rva is not None:
            if displacement != 0:
                raise StageAInputError(
                    "typed x87 image-relative address has a nonzero displacement"
                )
            displacement = image_base + image_rva
        operand = _memory_operand(
            mnemonic=mnemonic,
            width=width,
            segment=None,
            base=base,
            index=index,
            scale=scale,
            displacement=displacement,
            image_base=image_base,
        )
    else:
        raise StageAInputError(f"unsupported typed x87 operand kind {kind!r}")

    operation = _operation(
        mnemonic=mnemonic, operand=operand, source_size=source_size
    )
    if dict(payload) != operation.payload():
        raise StageAInputError(
            "typed x87 operation differs from its canonical representation"
        )
    return operation


def _optional_string(
    payload: Mapping[str, Any], field: str, label: str
) -> str | None:
    value = payload.get(field)
    if value is None:
        return None
    if not isinstance(value, str):
        raise StageAInputError(f"{label} is malformed")
    return value.lower()


def _normalized_x87_memory_width(mnemonic: str, decoded_width: int) -> int:
    if mnemonic in {"frstor", "fnsave", "fsave"}:
        return {2: 94, 4: 108}.get(decoded_width, decoded_width)
    return decoded_width


__all__ = [
    "TYPED_NATIVE_X87_OPERATION_FORMAT",
    "TYPED_NATIVE_X87_PROGRAM_FORMAT",
    "TypedX87Operand",
    "TypedX87Operation",
    "X87_CHECKED_DECODER",
    "X87_CHECKED_EXECUTOR",
    "X87_MEMORY_NO_SIZE_MNEMONICS",
    "X87_MEMORY_SIZE_KEYWORDS",
    "extract_typed_x87_operation",
    "typed_x87_operation_from_micro_op",
    "typed_x87_operation_from_payload",
]

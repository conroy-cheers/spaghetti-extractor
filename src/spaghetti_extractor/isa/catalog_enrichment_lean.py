"""Lean metadata generation for exact side-ISA encodings."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .semantic_forms import (
    LEAN_SEMANTIC_FORM_CLASSIFIER_MODULES,
    lean_semantic_form_classifier_sha256,
)
from ..build_support.lean_runner import run_lean_module_graph
from ..errors import ToolkitInputError
from ..util import sha256_bytes


def _string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ToolkitInputError(
            f"{context} must be a nonempty string without surrounding whitespace"
        )
    return value

_LEAN_METADATA_SUPPORT = r"""
import SpaghettiExtractor.ISA.ISAQualification

namespace SpaghettiExtractor.ISA.Formal

open Lean

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

private def registerName : Reg -> String
  | .eax => "eax"
  | .ebx => "ebx"
  | .ecx => "ecx"
  | .edx => "edx"
  | .esi => "esi"
  | .edi => "edi"
  | .ebp => "ebp"
  | .esp => "esp"

private def optionalRegisterJson : Option Reg -> Json
  | none => Json.null
  | some reg => toJson (registerName reg)

private def addressingJson (addressing : Addressing) : Json :=
  Json.mkObj [
    ("base", optionalRegisterJson addressing.base),
    ("index", optionalRegisterJson addressing.index),
    ("scale_shift", toJson addressing.scaleShift),
    ("displacement", toJson addressing.displacement)
  ]

private def operand32Json : Operand32 -> Json
  | .register reg => Json.mkObj [
      ("kind", toJson "register"),
      ("register", toJson (registerName reg))
    ]
  | .memory addressing => Json.mkObj [
      ("kind", toJson "memory"),
      ("address", addressingJson addressing)
    ]
  | .immediate value => Json.mkObj [
      ("kind", toJson "immediate"),
      ("value", toJson value)
    ]

private def operandWidthJson : OperandWidth -> Json
  | .byte => toJson 8
  | .word => toJson 16

private def byteRegisterJson (reg : ByteRegister) : Json :=
  Json.mkObj [
    ("parent", toJson (registerName reg.parent)),
    ("high", toJson reg.high)
  ]

private def operand8Json : Operand8 -> Json
  | .register reg => Json.mkObj [
      ("kind", toJson "register"),
      ("register", byteRegisterJson reg)
    ]
  | .memory addressing => Json.mkObj [
      ("kind", toJson "memory"),
      ("address", addressingJson addressing)
    ]
  | .immediate value => Json.mkObj [
      ("kind", toJson "immediate"),
      ("value", toJson value)
    ]

private def shiftCountJson : ShiftCount -> Json
  | .immediate value => Json.mkObj [
      ("kind", toJson "immediate"),
      ("value", toJson value)
    ]
  | .cl => Json.mkObj [("kind", toJson "cl")]

private def optionalNatJson : Option Nat -> Json
  | none => Json.null
  | some value => toJson value

private def instructionMetadataJson : Instruction -> Json
  | .nop => Json.mkObj [("constructor", toJson "nop")]
  | .ret => Json.mkObj [("constructor", toJson "ret")]
  | .retPop bytes => Json.mkObj [
      ("constructor", toJson "retPop"),
      ("pop_bytes", toJson bytes)
    ]
  | .movRegImm destination value => Json.mkObj [
      ("constructor", toJson "movRegImm"),
      ("destination", toJson (registerName destination)),
      ("value", toJson value)
    ]
  | .movRegReg destination source => Json.mkObj [
      ("constructor", toJson "movRegReg"),
      ("destination", toJson (registerName destination)),
      ("source", toJson (registerName source))
    ]
  | .addZero destination => Json.mkObj [
      ("constructor", toJson "addZero"),
      ("destination", toJson (registerName destination))
    ]
  | .subZero destination => Json.mkObj [
      ("constructor", toJson "subZero"),
      ("destination", toJson (registerName destination))
    ]
  | .cmpImm source value => Json.mkObj [
      ("constructor", toJson "cmpImm"),
      ("source", toJson (registerName source)),
      ("value", toJson value)
    ]
  | .branchEqual inverted displacement => Json.mkObj [
      ("constructor", toJson "branchEqual"),
      ("inverted", toJson inverted),
      ("displacement", toJson displacement)
    ]
  | .jumpRel8 displacement => Json.mkObj [
      ("constructor", toJson "jumpRel8"),
      ("displacement", toJson displacement)
    ]
  | .jumpRel32 displacement => Json.mkObj [
      ("constructor", toJson "jumpRel32"),
      ("displacement", toJson displacement)
    ]
  | .pushReg source => Json.mkObj [
      ("constructor", toJson "pushReg"),
      ("source", toJson (registerName source))
    ]
  | .pushFlags => Json.mkObj [("constructor", toJson "pushFlags")]
  | .pushAll => Json.mkObj [("constructor", toJson "pushAll")]
  | .popReg destination => Json.mkObj [
      ("constructor", toJson "popReg"),
      ("destination", toJson (registerName destination))
    ]
  | .popAll => Json.mkObj [("constructor", toJson "popAll")]
  | .popFlags => Json.mkObj [("constructor", toJson "popFlags")]
  | .clearDirection => Json.mkObj [
      ("constructor", toJson "clearDirection")
    ]
  | .setDirection => Json.mkObj [
      ("constructor", toJson "setDirection")
    ]
  | .clearCarry => Json.mkObj [
      ("constructor", toJson "clearCarry")
    ]
  | .leave => Json.mkObj [("constructor", toJson "leave")]
  | .lea destination base offset => Json.mkObj [
      ("constructor", toJson "lea"),
      ("destination", toJson (registerName destination)),
      ("base", toJson (registerName base)),
      ("offset", toJson offset)
    ]
  | .load32 destination base offset => Json.mkObj [
      ("constructor", toJson "load32"),
      ("destination", toJson (registerName destination)),
      ("base", toJson (registerName base)),
      ("offset", toJson offset)
    ]
  | .store32 base offset source => Json.mkObj [
      ("constructor", toJson "store32"),
      ("base", toJson (registerName base)),
      ("offset", toJson offset),
      ("source", toJson (registerName source))
    ]
  | .zeroReg destination => Json.mkObj [
      ("constructor", toJson "zeroReg"),
      ("destination", toJson (registerName destination))
    ]
  | .callRel32 displacement => Json.mkObj [
      ("constructor", toJson "callRel32"),
      ("displacement", toJson displacement)
    ]
  | .callImport absoluteAddress => Json.mkObj [
      ("constructor", toJson "callImport"),
      ("absolute_address", toJson absoluteAddress)
    ]
  | .jumpImport absoluteAddress => Json.mkObj [
      ("constructor", toJson "jumpImport"),
      ("absolute_address", toJson absoluteAddress)
    ]
  | .movFromOperand destination source => Json.mkObj [
      ("constructor", toJson "movFromOperand"),
      ("destination", toJson (registerName destination)),
      ("source", operand32Json source)
    ]
  | .movToOperand destination source => Json.mkObj [
      ("constructor", toJson "movToOperand"),
      ("destination", operand32Json destination),
      ("source", toJson (registerName source))
    ]
  | .movImmediate destination value => Json.mkObj [
      ("constructor", toJson "movImmediate"),
      ("destination", operand32Json destination),
      ("value", toJson value)
    ]
  | .leaAddress destination source => Json.mkObj [
      ("constructor", toJson "leaAddress"),
      ("destination", toJson (registerName destination)),
      ("source", addressingJson source)
    ]
  | .binary operation destination source => Json.mkObj [
      ("constructor", toJson "binary"),
      ("operation", toJson (reprStr operation)),
      ("destination", operand32Json destination),
      ("source", operand32Json source)
    ]
  | .shift operation destination count => Json.mkObj [
      ("constructor", toJson "shift"),
      ("operation", toJson (reprStr operation)),
      ("destination", operand32Json destination),
      ("count", shiftCountJson count)
    ]
  | .shiftWidth width operation destination count => Json.mkObj [
      ("constructor", toJson "shiftWidth"),
      ("width_bits", operandWidthJson width),
      ("operation", toJson (reprStr operation)),
      ("destination", operand32Json destination),
      ("count", shiftCountJson count)
    ]
  | .shift8 operation destination count => Json.mkObj [
      ("constructor", toJson "shift8"),
      ("operation", toJson (reprStr operation)),
      ("destination", operand8Json destination),
      ("count", shiftCountJson count)
    ]
  | .unary operation destination => Json.mkObj [
      ("constructor", toJson "unary"),
      ("operation", toJson (reprStr operation)),
      ("destination", operand32Json destination)
    ]
  | .branchCondition condition displacement size => Json.mkObj [
      ("constructor", toJson "branchCondition"),
      ("condition", toJson (reprStr condition)),
      ("displacement", toJson displacement),
      ("size", toJson size)
    ]
  | .movZeroExtend destination source width => Json.mkObj [
      ("constructor", toJson "movZeroExtend"),
      ("destination", toJson (registerName destination)),
      ("source", operand32Json source),
      ("width_bits", toJson width)
    ]
  | .movSignExtend destination source width => Json.mkObj [
      ("constructor", toJson "movSignExtend"),
      ("destination", toJson (registerName destination)),
      ("source", operand32Json source),
      ("width_bits", toJson width)
    ]
  | .movSignExtend8 destination source => Json.mkObj [
      ("constructor", toJson "movSignExtend8"),
      ("destination", toJson (registerName destination)),
      ("source", operand8Json source)
    ]
  | .movSignExtend8ToWord destination source => Json.mkObj [
      ("constructor", toJson "movSignExtend8ToWord"),
      ("destination", toJson (registerName destination)),
      ("source", operand8Json source)
    ]
  | .movFromOperandWidth width destination source => Json.mkObj [
      ("constructor", toJson "movFromOperandWidth"),
      ("width_bits", operandWidthJson width),
      ("destination", toJson (registerName destination)),
      ("source", operand32Json source)
    ]
  | .movToOperandWidth width destination source => Json.mkObj [
      ("constructor", toJson "movToOperandWidth"),
      ("width_bits", operandWidthJson width),
      ("destination", operand32Json destination),
      ("source", toJson (registerName source))
    ]
  | .movImmediateWidth width destination value => Json.mkObj [
      ("constructor", toJson "movImmediateWidth"),
      ("width_bits", operandWidthJson width),
      ("destination", operand32Json destination),
      ("value", toJson value)
    ]
  | .binaryWidth width operation destination source => Json.mkObj [
      ("constructor", toJson "binaryWidth"),
      ("width_bits", operandWidthJson width),
      ("operation", toJson (reprStr operation)),
      ("destination", operand32Json destination),
      ("source", operand32Json source)
    ]
  | .movFromOperand8 destination source => Json.mkObj [
      ("constructor", toJson "movFromOperand8"),
      ("destination", byteRegisterJson destination),
      ("source", operand8Json source)
    ]
  | .movToOperand8 destination source => Json.mkObj [
      ("constructor", toJson "movToOperand8"),
      ("destination", operand8Json destination),
      ("source", byteRegisterJson source)
    ]
  | .movImmediate8 destination value => Json.mkObj [
      ("constructor", toJson "movImmediate8"),
      ("destination", operand8Json destination),
      ("value", toJson value)
    ]
  | .binary8 operation destination source => Json.mkObj [
      ("constructor", toJson "binary8"),
      ("operation", toJson (reprStr operation)),
      ("destination", operand8Json destination),
      ("source", operand8Json source)
    ]
  | .conditionalMove condition destination source => Json.mkObj [
      ("constructor", toJson "conditionalMove"),
      ("condition", toJson (reprStr condition)),
      ("destination", toJson (registerName destination)),
      ("source", operand32Json source)
    ]
  | .setCondition condition destination => Json.mkObj [
      ("constructor", toJson "setCondition"),
      ("condition", toJson (reprStr condition)),
      ("destination", operand8Json destination)
    ]
  | .exchange destination source => Json.mkObj [
      ("constructor", toJson "exchange"),
      ("destination", operand32Json destination),
      ("source", toJson (registerName source))
    ]
  | .convertWordToDword => Json.mkObj [
      ("constructor", toJson "convertWordToDword")
    ]
  | .convertDwordToQuad => Json.mkObj [
      ("constructor", toJson "convertDwordToQuad")
    ]
  | .binaryCarry subtract destination source => Json.mkObj [
      ("constructor", toJson "binaryCarry"),
      ("subtract", toJson subtract),
      ("destination", operand32Json destination),
      ("source", operand32Json source)
    ]
  | .multiplyFull signed source => Json.mkObj [
      ("constructor", toJson "multiplyFull"),
      ("signed", toJson signed),
      ("source", operand32Json source)
    ]
  | .multiplyLow destination source immediate => Json.mkObj [
      ("constructor", toJson "multiplyLow"),
      ("destination", toJson (registerName destination)),
      ("source", operand32Json source),
      ("immediate", optionalNatJson immediate)
    ]
  | .doubleShift left destination source count => Json.mkObj [
      ("constructor", toJson "doubleShift"),
      ("left", toJson left),
      ("destination", operand32Json destination),
      ("source", toJson (registerName source)),
      ("count", shiftCountJson count)
    ]
  | .bitScan operation destination source => Json.mkObj [
      ("constructor", toJson "bitScan"),
      ("operation", toJson (reprStr operation)),
      ("destination", toJson (registerName destination)),
      ("source", operand32Json source)
    ]
  | .bitTestRegister base index => Json.mkObj [
      ("constructor", toJson "bitTestRegister"),
      ("base", toJson (registerName base)),
      ("index", toJson (registerName index))
    ]
  | .x87LoadStack index => Json.mkObj [
      ("constructor", toJson "x87LoadStack"),
      ("index", toJson index)
    ]
  | .x87LoadConstant value => Json.mkObj [
      ("constructor", toJson "x87LoadConstant"),
      ("value", toJson value)
    ]
  | .x87Exchange index => Json.mkObj [
      ("constructor", toJson "x87Exchange"),
      ("index", toJson index)
    ]
  | .x87StoreStack index pop => Json.mkObj [
      ("constructor", toJson "x87StoreStack"),
      ("index", toJson index),
      ("pop", toJson pop)
    ]
  | .x87Unary operation => Json.mkObj [
      ("constructor", toJson "x87Unary"),
      ("operation", toJson (reprStr operation))
    ]
  | .x87BinaryStack operation destination source pop => Json.mkObj [
      ("constructor", toJson "x87BinaryStack"),
      ("operation", toJson (reprStr operation)),
      ("destination", toJson destination),
      ("source", toJson source),
      ("pop", toJson pop)
    ]
  | .x87CompareStack mode destination index pop => Json.mkObj [
      ("constructor", toJson "x87CompareStack"),
      ("mode", toJson (reprStr mode)),
      ("destination", toJson (reprStr destination)),
      ("index", toJson index),
      ("pop", toJson pop)
    ]
  | .x87CompareMemory mode format source pop => Json.mkObj [
      ("constructor", toJson "x87CompareMemory"),
      ("mode", toJson (reprStr mode)),
      ("format", toJson (reprStr format)),
      ("source", addressingJson source),
      ("pop", toJson pop)
    ]
  | .x87LoadMemory format source => Json.mkObj [
      ("constructor", toJson "x87LoadMemory"),
      ("format", toJson (reprStr format)),
      ("source", addressingJson source)
    ]
  | .x87StoreMemory format destination pop => Json.mkObj [
      ("constructor", toJson "x87StoreMemory"),
      ("format", toJson (reprStr format)),
      ("destination", addressingJson destination),
      ("pop", toJson pop)
    ]
  | .x87BinaryMemory operation format source => Json.mkObj [
      ("constructor", toJson "x87BinaryMemory"),
      ("operation", toJson (reprStr operation)),
      ("format", toJson (reprStr format)),
      ("source", addressingJson source)
    ]
  | .x87LoadControl source => Json.mkObj [
      ("constructor", toJson "x87LoadControl"),
      ("source", addressingJson source)
    ]
  | .x87StoreControl destination => Json.mkObj [
      ("constructor", toJson "x87StoreControl"),
      ("destination", addressingJson destination)
    ]
  | .x87SaveState destination => Json.mkObj [
      ("constructor", toJson "x87SaveState"),
      ("destination", addressingJson destination)
    ]
  | .x87RestoreState source => Json.mkObj [
      ("constructor", toJson "x87RestoreState"),
      ("source", addressingJson source)
    ]
  | .x87Wait => Json.mkObj [("constructor", toJson "x87Wait")]
  | .x87Initialize => Json.mkObj [
      ("constructor", toJson "x87Initialize")
    ]
  | .x87StoreStatusAx => Json.mkObj [
      ("constructor", toJson "x87StoreStatusAx")
    ]
  | .x87Examine => Json.mkObj [("constructor", toJson "x87Examine")]
  | .moveDwords repeated => Json.mkObj [
      ("constructor", toJson "moveDwords"),
      ("repeated", toJson repeated)
    ]
  | .storeDwords repeated => Json.mkObj [
      ("constructor", toJson "storeDwords"),
      ("repeated", toJson repeated)
    ]
  | .moveWords repeated => Json.mkObj [
      ("constructor", toJson "moveWords"),
      ("repeated", toJson repeated)
    ]
  | .storeWords repeated => Json.mkObj [
      ("constructor", toJson "storeWords"),
      ("repeated", toJson repeated)
    ]
  | .moveBytes repeated => Json.mkObj [
      ("constructor", toJson "moveBytes"),
      ("repeated", toJson repeated)
    ]
  | .storeBytes repeated => Json.mkObj [
      ("constructor", toJson "storeBytes"),
      ("repeated", toJson repeated)
    ]
  | .scanByteNotEqual => Json.mkObj [
      ("constructor", toJson "scanByteNotEqual")
    ]
  | .callIndirect target => Json.mkObj [
      ("constructor", toJson "callIndirect"),
      ("target", operand32Json target)
    ]
  | .jumpIndirect target => Json.mkObj [
      ("constructor", toJson "jumpIndirect"),
      ("target", operand32Json target)
    ]
  | .pushOperand source => Json.mkObj [
      ("constructor", toJson "pushOperand"),
      ("source", operand32Json source)
    ]
  | .movFs32 destination source => Json.mkObj [
      ("constructor", toJson "movFs32"),
      ("destination", toJson (registerName destination)),
      ("source", addressingJson source)
    ]
  | .movToFs32 destination source => Json.mkObj [
      ("constructor", toJson "movToFs32"),
      ("destination", addressingJson destination),
      ("source", toJson (registerName source))
    ]
  | .divideUnsigned source => Json.mkObj [
      ("constructor", toJson "divideUnsigned"),
      ("source", operand32Json source)
    ]
  | .divideSigned source => Json.mkObj [
      ("constructor", toJson "divideSigned"),
      ("source", operand32Json source)
    ]
  | .atomicCompareExchange destination source => Json.mkObj [
      ("constructor", toJson "atomicCompareExchange"),
      ("destination", addressingJson destination),
      ("source", toJson (registerName source))
    ]

private def emitDecodedMetadata (encodingId : String) (bytes : Bytes) : IO Unit :=
  IO.println <| Json.compress <| match
      decodeInstructionExactForProfile .i686 bytes with
    | none => Json.mkObj [
        ("encoding_id", toJson encodingId),
        ("status", toJson "decode_failed")
      ]
    | some decoded => Json.mkObj [
        ("encoding_id", toJson encodingId),
        ("status", toJson "decoded"),
        ("semantic_form", toJson (reprStr decoded.instruction.semanticForm)),
        ("decoded_size", toJson decoded.size),
        ("instruction", instructionMetadataJson decoded.instruction)
      ]
"""


def _lean_nat(value: int) -> str:
    return f"0x{value:x}"


def _generated_lean_module(encodings: Sequence[Mapping[str, Any]]) -> str:
    chunk_size = 256
    definitions: list[str] = [_LEAN_METADATA_SUPPORT, ""]
    chunk_count = (len(encodings) + chunk_size - 1) // chunk_size
    for chunk_index in range(chunk_count):
        definitions.append(
            f"private def emitMetadataChunk{chunk_index} : IO Unit := do"
        )
        for encoding in encodings[
            chunk_index * chunk_size : (chunk_index + 1) * chunk_size
        ]:
            encoding_id = json.dumps(
                encoding["encoding_id"], ensure_ascii=True
            )
            instruction = ", ".join(
                _lean_nat(byte) for byte in encoding["instruction_bytes"]
            )
            definitions.append(
                f"  emitDecodedMetadata {encoding_id} [{instruction}]"
            )
        definitions.append("")
    definitions.append("def _root_.main : IO Unit := do")
    for chunk_index in range(chunk_count):
        definitions.append(f"  emitMetadataChunk{chunk_index}")
    definitions.extend(["", "end SpaghettiExtractor.ISA.Formal", ""])
    return "\n".join(definitions)


def extract_lean_decoded_metadata(
    encodings: Sequence[Mapping[str, Any]],
    *,
    timeout_seconds: int = 300,
) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    """Replay exact encodings through Lean and return decoded operand metadata."""

    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int)
        or timeout_seconds <= 0
    ):
        raise ToolkitInputError("Lean metadata timeout must be a positive integer")
    expected_ids = [str(row["encoding_id"]) for row in encodings]
    if not expected_ids or expected_ids != sorted(set(expected_ids)):
        raise ToolkitInputError(
            "Lean metadata encodings must have unique canonical encoding IDs"
        )
    lean = shutil.which("lean")
    if lean is None:
        raise ToolkitInputError(
            "Lean is required to enrich exact side-ISA catalog encodings"
        )

    module_source = _generated_lean_module(encodings)
    source_root = Path(__file__).parent.parent / "lean" / "SpaghettiExtractor/ISA"
    with tempfile.TemporaryDirectory(
        prefix="isa-catalog-enrichment-"
    ) as temporary:
        lean_dir = Path(temporary)
        isa_modules = lean_dir / "SpaghettiExtractor/ISA"
        isa_modules.mkdir(parents=True)
        for module in LEAN_SEMANTIC_FORM_CLASSIFIER_MODULES:
            shutil.copyfile(
                source_root / f"{module}.lean",
                isa_modules / f"{module}.lean",
            )
        copied_classifier = lean_semantic_form_classifier_sha256(isa_modules)
        current_classifier = lean_semantic_form_classifier_sha256()
        if copied_classifier != current_classifier:
            raise ToolkitInputError(
                "Lean semantic classifier changed while preparing enrichment"
            )
        generated = isa_modules / "GeneratedISACatalogEnrichment.lean"
        generated.write_text(module_source, encoding="utf-8")
        compiled = run_lean_module_graph(
            lean_dir,
            bundle="GeneratedISACatalogEnrichment",
        )
        if compiled.get("status") != "checked":
            detail = str(compiled.get("stderr") or compiled.get("stdout"))
            raise ToolkitInputError(
                "Lean exact-encoding metadata export did not compile: " + detail
            )
        try:
            completed = subprocess.run(
                [
                    lean,
                    "--trust=0",
                    "--run",
                    "SpaghettiExtractor/ISA/GeneratedISACatalogEnrichment.lean",
                ],
                cwd=lean_dir,
                env={**os.environ, "LEAN_PATH": "."},
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise ToolkitInputError(
                "Lean exact-encoding metadata export timed out"
            ) from exc
        except subprocess.CalledProcessError as exc:
            raise ToolkitInputError(
                "Lean exact-encoding metadata export failed: "
                + (exc.stderr or exc.stdout or "unknown Lean failure")
            ) from exc

    rows: dict[str, dict[str, Any]] = {}
    for line_number, line in enumerate(completed.stdout.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ToolkitInputError(
                f"Lean metadata output line {line_number} is not JSON"
            ) from exc
        if not isinstance(raw, Mapping):
            raise ToolkitInputError(
                f"Lean metadata output line {line_number} is not an object"
            )
        encoding_id = _string(
            raw.get("encoding_id"),
            f"Lean metadata output line {line_number} encoding_id",
        )
        if encoding_id in rows:
            raise ToolkitInputError(
                f"Lean metadata output repeats encoding {encoding_id}"
            )
        rows[encoding_id] = dict(raw)
    if list(rows) != expected_ids:
        raise ToolkitInputError(
            "Lean metadata output does not cover encodings in canonical order"
        )
    version = subprocess.run(
        [lean, "--version"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout.strip()
    return rows, {
        "classifier_sha256": current_classifier,
        "metadata_exporter_sha256": sha256_bytes(module_source.encode("utf-8")),
        "lean_version": version,
    }

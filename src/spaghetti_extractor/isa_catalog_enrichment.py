"""Fail-closed enrichment for exact side-ISA catalog proposals.

The side adapter deliberately emits exact Lean semantic forms and encodings
without qualification metadata.  This module replays each encoding through
the authoritative Lean decoder, exports concrete decoded operands, and derives
only the generic effects representable by the existing corpus schema.
Unsupported forms remain explicit unresolved rows.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .isa_catalog import (
    ISA_FORM_CATALOG_ENTRY_FORMAT,
    ISA_FORM_CATALOG_FORMAT,
    ISA_PROFILE_ID,
    ISAFormCatalog,
    parse_isa_form_catalog,
)
from .isa_conformance import ISAConformanceError
from .isa_semantic_forms import (
    lean_semantic_form_classifier_sha256,
    lean_semantic_form_id,
)
from .isa_side_adapter import SIDE_ISA_EXECUTABLE_CATALOG_PROPOSAL_FORMAT
from .relational.lean.compiler import _run_lean_relational
from .relational.schema import STAGE_A_RELATIONAL_MODEL_ID
from .stage_binary import StageAInputError
from .util import sha256_bytes, sha256_file, write_json


SIDE_ISA_CATALOG_ENRICHMENT_FORMAT = (
    "stage-a-side-isa-executable-catalog-enrichment-v1"
)
SIDE_ISA_ENCODING_ENRICHMENT_FORMAT = (
    "stage-a-side-isa-executable-encoding-enrichment-v1"
)
SIDE_ISA_CATALOG_ENRICHMENT_RESULT_FORMAT = (
    "stage-a-side-isa-catalog-enrichment-result-v1"
)
_ENRICHER_VERSION = "lean-exact-encoding-catalog-enrichment-v1"
_PROPOSAL_ENCODING_FORMAT = (
    "stage-a-side-isa-executable-encoding-proposal-v1"
)
_GPRS = ("eax", "ebp", "ebx", "ecx", "edi", "edx", "esi", "esp")
_ARITHMETIC_FLAGS = 0x8D5
_LOGICAL_FLAGS = 0x8C5
_MULTIPLY_FLAGS = 0x801
_ZERO_FLAG = 0x40
_CARRY_FLAG = 0x1
_TEST_EIP = 0x00401000
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_SEGMENT_PREFIXES = frozenset({0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65})
_REP_PREFIXES = frozenset({0xF2, 0xF3})
_OTHER_UNRESOLVED_PREFIXES = {
    0x67: "address_size_override_not_representable",
}
_PREFIXES = _SEGMENT_PREFIXES | _REP_PREFIXES | frozenset({0x66, 0x67, 0xF0})


def _canonical_sha256(value: Any) -> str:
    return sha256_bytes(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    )


def _exact_fields(
    value: Any,
    expected: set[str],
    context: str,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{context} must be an object")
    missing = expected - set(value)
    unknown = set(value) - expected
    if missing or unknown:
        details: list[str] = []
        if missing:
            details.append(f"missing fields {sorted(missing)!r}")
        if unknown:
            details.append(f"unknown fields {sorted(unknown)!r}")
        raise StageAInputError(f"{context} has " + " and ".join(details))
    return value


def _string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise StageAInputError(
            f"{context} must be a nonempty string without surrounding whitespace"
        )
    return value


def _sha256(value: Any, context: str) -> str:
    digest = _string(value, context)
    if _SHA256_RE.fullmatch(digest) is None:
        raise StageAInputError(
            f"{context} must be 64 lowercase hexadecimal characters"
        )
    return digest


def _uint(value: Any, bits: int, context: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value < 2**bits
    ):
        raise StageAInputError(f"{context} must be an unsigned {bits}-bit integer")
    return value


def _objects(value: Any, context: str) -> list[Mapping[str, Any]]:
    if not isinstance(value, list):
        raise StageAInputError(f"{context} must be a list")
    result: list[Mapping[str, Any]] = []
    for index, row in enumerate(value):
        if not isinstance(row, Mapping):
            raise StageAInputError(f"{context}[{index}] must be an object")
        result.append(row)
    return result


def _strings(
    value: Any,
    context: str,
    *,
    allow_empty: bool = False,
) -> list[str]:
    if not isinstance(value, list):
        raise StageAInputError(f"{context} must be a list")
    result = [_string(row, f"{context}[{index}]") for index, row in enumerate(value)]
    if not allow_empty and not result:
        raise StageAInputError(f"{context} must not be empty")
    if result != sorted(set(result)):
        raise StageAInputError(f"{context} must be unique and canonically ordered")
    return result


def _encoding_id(form_id: str, instruction_hex: str) -> str:
    return "lean-x86-encoding-" + _canonical_sha256(
        {"form_id": form_id, "bytes": instruction_hex}
    )[:24]


def _parse_proposal(value: Any) -> dict[str, Any]:
    payload = _exact_fields(
        value,
        {
            "format",
            "status",
            "profile",
            "model",
            "classifier_sha256",
            "requirements_sha256",
            "source",
            "forms",
            "encodings",
            "missing_enrichment",
            "counts",
            "trust",
        },
        "side-ISA catalog proposal",
    )
    if payload.get("format") != SIDE_ISA_EXECUTABLE_CATALOG_PROPOSAL_FORMAT:
        raise StageAInputError("unsupported side-ISA catalog proposal format")
    if payload.get("status") != "incomplete_missing_effect_enrichment":
        raise StageAInputError("side-ISA catalog proposal status is invalid")
    if payload.get("profile") != ISA_PROFILE_ID:
        raise StageAInputError("side-ISA catalog proposal profile is invalid")
    if payload.get("model") != STAGE_A_RELATIONAL_MODEL_ID:
        raise StageAInputError("side-ISA catalog proposal model is invalid")
    classifier_sha256 = _sha256(
        payload.get("classifier_sha256"),
        "side-ISA catalog proposal classifier_sha256",
    )
    if classifier_sha256 != lean_semantic_form_classifier_sha256():
        raise StageAInputError(
            "side-ISA catalog proposal uses a stale Lean semantic classifier"
        )
    _sha256(
        payload.get("requirements_sha256"),
        "side-ISA catalog proposal requirements_sha256",
    )

    source = _exact_fields(
        payload.get("source"),
        {"adapter", "side_isa_artifacts"},
        "side-ISA catalog proposal source",
    )
    _string(source.get("adapter"), "side-ISA catalog proposal source.adapter")
    side_sources = _objects(
        source.get("side_isa_artifacts"),
        "side-ISA catalog proposal source.side_isa_artifacts",
    )
    if not 1 <= len(side_sources) <= 2:
        raise StageAInputError(
            "side-ISA catalog proposal must name one or two side artifacts"
        )
    seen_sides: list[str] = []
    for index, row in enumerate(side_sources):
        context = f"side-ISA catalog proposal side source {index}"
        row = _exact_fields(
            row,
            {"side", "binary_sha256", "artifact_sha256"},
            context,
        )
        side = _string(row.get("side"), f"{context}.side")
        if side not in {"original", "candidate"}:
            raise StageAInputError(f"{context}.side is invalid")
        seen_sides.append(side)
        _sha256(row.get("binary_sha256"), f"{context}.binary_sha256")
        _sha256(row.get("artifact_sha256"), f"{context}.artifact_sha256")
    if seen_sides != [side for side in ("original", "candidate") if side in seen_sides]:
        raise StageAInputError(
            "side-ISA catalog proposal side sources are not canonically ordered"
        )
    if len(seen_sides) != len(set(seen_sides)):
        raise StageAInputError("side-ISA catalog proposal repeats a side source")

    raw_forms = _objects(payload.get("forms"), "side-ISA catalog proposal forms")
    forms: list[dict[str, Any]] = []
    forms_by_id: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(raw_forms):
        context = f"side-ISA catalog proposal forms[{index}]"
        row = _exact_fields(
            raw,
            {
                "form_id",
                "semantic_form",
                "representative_encoding_id",
                "encoding_ids",
            },
            context,
        )
        semantic_form = _string(row.get("semantic_form"), f"{context}.semantic_form")
        form_id = _string(row.get("form_id"), f"{context}.form_id")
        expected_form_id = lean_semantic_form_id(
            semantic_form,
            classifier_sha256=classifier_sha256,
        )
        if form_id != expected_form_id:
            raise StageAInputError(f"{context}.form_id is not canonical")
        parsed = {
            "form_id": form_id,
            "semantic_form": semantic_form,
            "representative_encoding_id": _string(
                row.get("representative_encoding_id"),
                f"{context}.representative_encoding_id",
            ),
            "encoding_ids": _strings(
                row.get("encoding_ids"), f"{context}.encoding_ids"
            ),
        }
        if form_id in forms_by_id:
            raise StageAInputError("side-ISA catalog proposal repeats a form ID")
        forms.append(parsed)
        forms_by_id[form_id] = parsed
    if [row["form_id"] for row in forms] != sorted(forms_by_id):
        raise StageAInputError(
            "side-ISA catalog proposal forms are not canonically ordered"
        )
    if not forms:
        raise StageAInputError("side-ISA catalog proposal has no forms")

    raw_encodings = _objects(
        payload.get("encodings"), "side-ISA catalog proposal encodings"
    )
    encodings: list[dict[str, Any]] = []
    encodings_by_id: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(raw_encodings):
        context = f"side-ISA catalog proposal encodings[{index}]"
        row = _exact_fields(
            raw,
            {
                "format",
                "encoding_id",
                "form_id",
                "semantic_form",
                "instruction_bytes",
                "instruction_hex",
                "source_occurrence_ids",
                "representative",
                "enrichment",
            },
            context,
        )
        if row.get("format") != _PROPOSAL_ENCODING_FORMAT:
            raise StageAInputError(f"{context}.format is invalid")
        form_id = _string(row.get("form_id"), f"{context}.form_id")
        form = forms_by_id.get(form_id)
        if form is None:
            raise StageAInputError(f"{context} names an unknown form")
        semantic_form = _string(row.get("semantic_form"), f"{context}.semantic_form")
        if semantic_form != form["semantic_form"]:
            raise StageAInputError(f"{context} semantic form disagrees with its form")
        instruction_hex = _string(
            row.get("instruction_hex"), f"{context}.instruction_hex"
        )
        if (
            len(instruction_hex) % 2
            or not 1 <= len(instruction_hex) // 2 <= 15
            or re.fullmatch(r"[0-9a-f]+", instruction_hex) is None
        ):
            raise StageAInputError(f"{context}.instruction_hex is invalid")
        raw_bytes = row.get("instruction_bytes")
        if not isinstance(raw_bytes, list):
            raise StageAInputError(f"{context}.instruction_bytes must be a list")
        instruction_bytes = [
            _uint(byte, 8, f"{context}.instruction_bytes[{offset}]")
            for offset, byte in enumerate(raw_bytes)
        ]
        if bytes(instruction_bytes).hex() != instruction_hex:
            raise StageAInputError(
                f"{context} instruction bytes and hexadecimal encoding disagree"
            )
        encoding_id = _string(row.get("encoding_id"), f"{context}.encoding_id")
        if encoding_id != _encoding_id(form_id, instruction_hex):
            raise StageAInputError(f"{context}.encoding_id is not canonical")
        if encoding_id in encodings_by_id:
            raise StageAInputError("side-ISA catalog proposal repeats an encoding ID")
        source_occurrence_ids = _strings(
            row.get("source_occurrence_ids"),
            f"{context}.source_occurrence_ids",
        )
        representative = row.get("representative")
        if not isinstance(representative, bool):
            raise StageAInputError(f"{context}.representative must be a boolean")
        enrichment = _exact_fields(
            row.get("enrichment"),
            {"status", "missing_fields"},
            f"{context}.enrichment",
        )
        if enrichment.get("status") != "missing" or enrichment.get(
            "missing_fields"
        ) != ["defined_outputs", "effects", "required_features"]:
            raise StageAInputError(f"{context}.enrichment is not the v1 missing marker")
        parsed = {
            "format": _PROPOSAL_ENCODING_FORMAT,
            "encoding_id": encoding_id,
            "form_id": form_id,
            "semantic_form": semantic_form,
            "instruction_bytes": instruction_bytes,
            "instruction_hex": instruction_hex,
            "source_occurrence_ids": source_occurrence_ids,
            "representative": representative,
        }
        encodings.append(parsed)
        encodings_by_id[encoding_id] = parsed
    if [
        (row["form_id"], row["instruction_hex"]) for row in encodings
    ] != sorted(
        (row["form_id"], row["instruction_hex"]) for row in encodings
    ):
        raise StageAInputError(
            "side-ISA catalog proposal encodings are not canonically ordered"
        )
    if not encodings:
        raise StageAInputError("side-ISA catalog proposal has no encodings")

    for form in forms:
        actual_ids = sorted(
            row["encoding_id"]
            for row in encodings
            if row["form_id"] == form["form_id"]
        )
        if form["encoding_ids"] != actual_ids:
            raise StageAInputError(
                f"side-ISA catalog proposal form {form['form_id']} encoding inventory "
                "does not match the encoding rows"
            )
        representative_ids = [
            row["encoding_id"]
            for row in encodings
            if row["form_id"] == form["form_id"] and row["representative"]
        ]
        if representative_ids != [form["representative_encoding_id"]]:
            raise StageAInputError(
                f"side-ISA catalog proposal form {form['form_id']} has an invalid "
                "representative encoding"
            )

    missing = _exact_fields(
        payload.get("missing_enrichment"),
        {"status", "fields", "encoding_count", "corpus_generation_allowed"},
        "side-ISA catalog proposal missing_enrichment",
    )
    if (
        missing.get("status") != "required"
        or missing.get("fields")
        != ["defined_outputs", "effects", "required_features"]
        or missing.get("encoding_count") != len(encodings)
        or missing.get("corpus_generation_allowed") is not False
    ):
        raise StageAInputError(
            "side-ISA catalog proposal missing_enrichment summary is invalid"
        )

    counts = _exact_fields(
        payload.get("counts"),
        {"forms", "encodings", "occurrences", "representatives"},
        "side-ISA catalog proposal counts",
    )
    expected_counts = {
        "forms": len(forms),
        "encodings": len(encodings),
        "representatives": len(forms),
    }
    for field, expected in expected_counts.items():
        if counts.get(field) != expected:
            raise StageAInputError(
                f"side-ISA catalog proposal counts.{field} is inconsistent"
            )
    occurrence_count = _uint(
        counts.get("occurrences"),
        64,
        "side-ISA catalog proposal counts.occurrences",
    )
    if occurrence_count != len(
        {
            occurrence_id
            for row in encodings
            for occurrence_id in row["source_occurrence_ids"]
        }
    ):
        raise StageAInputError(
            "side-ISA catalog proposal occurrence count is inconsistent"
        )
    trust = _exact_fields(
        payload.get("trust"),
        {"role", "proof_authority", "closes_stage_a_proof"},
        "side-ISA catalog proposal trust",
    )
    if (
        trust.get("role") != "untrusted_executable_catalog_enrichment_proposal"
        or trust.get("proof_authority") is not False
        or trust.get("closes_stage_a_proof") is not False
    ):
        raise StageAInputError("side-ISA catalog proposal trust marker is invalid")

    return {
        **dict(payload),
        "forms": forms,
        "encodings": encodings,
        "classifier_sha256": classifier_sha256,
    }


_LEAN_METADATA_SUPPORT = r"""
import StageA.ISAQualification

namespace StageA.Formal

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
    definitions.extend(["", "end StageA.Formal", ""])
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
        raise StageAInputError("Lean metadata timeout must be a positive integer")
    expected_ids = [str(row["encoding_id"]) for row in encodings]
    if not expected_ids or expected_ids != sorted(set(expected_ids)):
        raise StageAInputError(
            "Lean metadata encodings must have unique canonical encoding IDs"
        )
    lean = shutil.which("lean")
    if lean is None:
        raise StageAInputError(
            "Lean is required to enrich exact side-ISA catalog encodings"
        )

    module_source = _generated_lean_module(encodings)
    source_root = Path(__file__).parent / "lean" / "StageA"
    with tempfile.TemporaryDirectory(
        prefix="isa-catalog-enrichment-"
    ) as temporary:
        lean_dir = Path(temporary)
        stage_a = lean_dir / "StageA"
        stage_a.mkdir(parents=True)
        for module in ("X87", "Formal", "ISAQualification"):
            shutil.copyfile(
                source_root / f"{module}.lean",
                stage_a / f"{module}.lean",
            )
        copied_classifier = lean_semantic_form_classifier_sha256(stage_a)
        current_classifier = lean_semantic_form_classifier_sha256()
        if copied_classifier != current_classifier:
            raise StageAInputError(
                "Lean semantic classifier changed while preparing enrichment"
            )
        generated = stage_a / "GeneratedISACatalogEnrichment.lean"
        generated.write_text(module_source, encoding="utf-8")
        compiled = _run_lean_relational(
            lean_dir,
            bundle="GeneratedISACatalogEnrichment",
        )
        if compiled.get("status") != "checked":
            detail = str(compiled.get("stderr") or compiled.get("stdout"))
            raise StageAInputError(
                "Lean exact-encoding metadata export did not compile: " + detail
            )
        try:
            completed = subprocess.run(
                [
                    lean,
                    "--trust=0",
                    "--run",
                    "StageA/GeneratedISACatalogEnrichment.lean",
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
            raise StageAInputError(
                "Lean exact-encoding metadata export timed out"
            ) from exc
        except subprocess.CalledProcessError as exc:
            raise StageAInputError(
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
            raise StageAInputError(
                f"Lean metadata output line {line_number} is not JSON"
            ) from exc
        if not isinstance(raw, Mapping):
            raise StageAInputError(
                f"Lean metadata output line {line_number} is not an object"
            )
        encoding_id = _string(
            raw.get("encoding_id"),
            f"Lean metadata output line {line_number} encoding_id",
        )
        if encoding_id in rows:
            raise StageAInputError(
                f"Lean metadata output repeats encoding {encoding_id}"
            )
        rows[encoding_id] = dict(raw)
    if list(rows) != expected_ids:
        raise StageAInputError(
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


def _signed32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value if value < 0x80000000 else value - 0x100000000


def _register(value: Any, context: str) -> str:
    register = _string(value, context)
    if register not in _GPRS:
        raise StageAInputError(f"{context} is not an IA-32 general-purpose register")
    return register


def _defined_outputs(
    eflags: int,
    *,
    gpr_masks: Mapping[str, int] | None = None,
    x87: bool = False,
) -> dict[str, Any]:
    masks = {register: 0xFFFFFFFF for register in _GPRS}
    if gpr_masks is not None:
        masks.update(gpr_masks)
    return {
        "gprs": masks,
        "eip": 0xFFFFFFFF,
        "eflags": eflags,
        "fs": {"selector": 0, "base": 0},
        "x87": {
            "control_word": 0xFFFF if x87 else 0,
            "status_word": 0xFFFF if x87 else 0,
            "tag_word": 0xFFFF if x87 else 0,
            "last_opcode": 0x7FF if x87 else 0,
            "instruction_pointer": 0xFFFFFFFF if x87 else 0,
            "data_pointer": 0xFFFFFFFF if x87 else 0,
            "registers": [
                [0xFF if x87 else 0] * 10 for _ in range(8)
            ],
        },
        "memory": [],
    }


def _register_effect(
    *,
    reads: Sequence[str | Mapping[str, Any]],
    writes: Sequence[str | Mapping[str, Any]],
    width_bits: int = 32,
) -> dict[str, Any] | None:
    def location(value: str | Mapping[str, Any]) -> dict[str, Any] | str:
        if isinstance(value, str):
            if width_bits == 8:
                return {"register": value, "lsb": 0}
            return value
        return {
            "register": _register(value.get("register"), "register location"),
            "lsb": _uint(value.get("lsb"), 5, "register location lsb"),
        }

    def canonical(
        values: Sequence[str | Mapping[str, Any]],
    ) -> list[dict[str, Any] | str]:
        locations = [location(value) for value in values]
        return sorted(
            {
                (
                    value
                    if isinstance(value, str)
                    else (str(value["register"]), int(value["lsb"]))
                )
                for value in locations
            },
            key=lambda value: (
                value if isinstance(value, tuple) else (value, 0)
            ),
        )

    def payload(
        values: Sequence[str | Mapping[str, Any]],
    ) -> list[dict[str, Any] | str]:
        return [
            (
                {"register": value[0], "lsb": value[1]}
                if isinstance(value, tuple)
                else value
            )
            for value in canonical(values)
        ]

    canonical_reads = payload(reads)
    canonical_writes = payload(writes)
    if not canonical_reads and not canonical_writes:
        return None
    return {
        "class": "register",
        "id": f"register-{width_bits:02d}-gpr",
        "width_bits": width_bits,
        "reads": canonical_reads,
        "writes": canonical_writes,
    }


def _register_effect_around_memory(
    *,
    reads: Sequence[str | Mapping[str, Any]],
    writes: Sequence[str | Mapping[str, Any]],
    effects: Sequence[Mapping[str, Any]],
    width_bits: int = 32,
) -> dict[str, Any] | None:
    def parent_register(value: str | Mapping[str, Any]) -> str:
        return (
            value
            if isinstance(value, str)
            else _register(value.get("register"), "register location")
        )

    address_registers = {
        register
        for effect in effects
        if effect.get("class") == "memory"
        for register in (
            effect["address"].get("base"),
            effect["address"].get("index"),
        )
        if register is not None
    }
    return _register_effect(
        reads=[
            register
            for register in reads
            if parent_register(register) not in address_registers
        ],
        writes=writes,
        width_bits=width_bits,
    )


def _address(value: Any, context: str) -> dict[str, Any]:
    payload = _exact_fields(
        value,
        {"base", "index", "scale_shift", "displacement"},
        context,
    )
    raw_base = payload.get("base")
    raw_index = payload.get("index")
    base = None if raw_base is None else _register(raw_base, f"{context}.base")
    index = None if raw_index is None else _register(raw_index, f"{context}.index")
    scale_shift = _uint(payload.get("scale_shift"), 3, f"{context}.scale_shift")
    if scale_shift > 3:
        raise StageAInputError(f"{context}.scale_shift exceeds IA-32 SIB width")
    if index is None and scale_shift != 0:
        raise StageAInputError(f"{context} has a scale without an index")
    return {
        "base": base,
        "index": index,
        "scale": 1 << scale_shift,
        "displacement": _signed32(
            _uint(payload.get("displacement"), 32, f"{context}.displacement")
        ),
        "segment": "flat",
    }


def _memory_effect(
    *,
    address: Mapping[str, Any],
    access: str,
    width_bits: int,
    role: str,
    condition: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "class": "memory",
        "id": f"memory-{role}-{access}-{width_bits:02d}",
        "width_bits": width_bits,
        "access": access,
        "address": dict(address),
        "condition": None if condition is None else dict(condition),
    }


def _x87_effect(*, stack_inputs: int, stack_outputs: int) -> dict[str, Any]:
    return {
        "class": "x87",
        "id": "x87-stack",
        "stack_inputs": stack_inputs,
        "stack_outputs": stack_outputs,
    }


def _x87_format_width(value: Any, context: str) -> int:
    format_name = _condition_name(value, context)
    widths = {
        "float32": 32,
        "int32": 32,
        "float64": 64,
        "float80": 80,
    }
    try:
        return widths[format_name]
    except KeyError as exc:
        raise StageAInputError(
            f"{context} is not a reviewed x87 memory format"
        ) from exc


def _x87_index(value: Any, context: str) -> int:
    index = _uint(value, 8, context)
    if index >= 8:
        raise StageAInputError(f"{context} exceeds the x87 register stack")
    return index


def _operand32(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{context} must be an object")
    kind = value.get("kind")
    if kind == "register":
        payload = _exact_fields(value, {"kind", "register"}, context)
        return {
            "kind": "register",
            "register": _register(payload.get("register"), f"{context}.register"),
        }
    if kind == "memory":
        payload = _exact_fields(value, {"kind", "address"}, context)
        return {
            "kind": "memory",
            "address": _address(payload.get("address"), f"{context}.address"),
        }
    if kind == "immediate":
        payload = _exact_fields(value, {"kind", "value"}, context)
        return {
            "kind": "immediate",
            "value": _uint(payload.get("value"), 32, f"{context}.value"),
        }
    raise StageAInputError(f"{context}.kind is unsupported")


def _width_bits(value: Any, context: str) -> int:
    width_bits = _uint(value, 8, context)
    if width_bits not in {8, 16, 32}:
        raise StageAInputError(f"{context} must be 8, 16, or 32")
    return width_bits


def _byte_register(value: Any, context: str) -> dict[str, Any]:
    payload = _exact_fields(value, {"parent", "high"}, context)
    high = payload.get("high")
    if not isinstance(high, bool):
        raise StageAInputError(f"{context}.high must be a boolean")
    return {
        "register": _register(payload.get("parent"), f"{context}.parent"),
        "high": high,
    }


def _operand8(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{context} must be an object")
    kind = value.get("kind")
    if kind == "register":
        payload = _exact_fields(value, {"kind", "register"}, context)
        return {
            "kind": "register",
            **_byte_register(payload.get("register"), f"{context}.register"),
        }
    if kind == "memory":
        payload = _exact_fields(value, {"kind", "address"}, context)
        return {
            "kind": "memory",
            "address": _address(payload.get("address"), f"{context}.address"),
        }
    if kind == "immediate":
        payload = _exact_fields(value, {"kind", "value"}, context)
        return {
            "kind": "immediate",
            "value": _uint(payload.get("value"), 8, f"{context}.value"),
        }
    raise StageAInputError(f"{context}.kind is unsupported")


def _shift_count(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{context} must be an object")
    kind = value.get("kind")
    if kind == "cl":
        _exact_fields(value, {"kind"}, context)
        return {"kind": "cl"}
    if kind == "immediate":
        payload = _exact_fields(value, {"kind", "value"}, context)
        return {
            "kind": "immediate",
            "value": _uint(payload.get("value"), 8, f"{context}.value"),
        }
    raise StageAInputError(f"{context}.kind is unsupported")


def _has_high_byte_register(*values: Mapping[str, Any]) -> bool:
    return any(
        value.get("kind") == "register" and value.get("high") is True
        for value in values
    )


def _operand_access(
    operand: Mapping[str, Any],
    *,
    read: bool,
    write: bool,
    width_bits: int,
    role: str,
) -> tuple[list[str | dict[str, Any]], list[str | dict[str, Any]], list[dict[str, Any]]]:
    reads: list[str | dict[str, Any]] = []
    writes: list[str | dict[str, Any]] = []
    memory: list[dict[str, Any]] = []
    if operand["kind"] == "register":
        register = str(operand["register"])
        location: str | dict[str, Any] = register
        if width_bits == 8:
            location = {
                "register": register,
                "lsb": 8 if operand.get("high") is True else 0,
            }
        if read:
            reads.append(location)
        if write:
            writes.append(location)
    elif operand["kind"] == "memory":
        access = "read_write" if read and write else "read" if read else "write"
        memory.append(
            _memory_effect(
                address=operand["address"],
                access=access,
                width_bits=width_bits,
                role=role,
            )
        )
    elif operand["kind"] != "immediate":
        raise StageAInputError("decoded operand kind is invalid")
    return reads, writes, memory


def _relative_target(instruction_size: int, displacement: int, bits: int) -> int:
    sign_bit = 1 << (bits - 1)
    signed = displacement if displacement < sign_bit else displacement - (1 << bits)
    return (_TEST_EIP + instruction_size + signed) & 0xFFFFFFFF


def _branch_effect(
    *,
    control: str,
    target_eip: int | None,
    target: Mapping[str, Any] | None = None,
    outcomes: Sequence[tuple[str, int, int]] = (("taken", 0, 0),),
) -> dict[str, Any]:
    rows = []
    for scenario, mask, value in sorted(outcomes):
        rows.append(
            {
                "scenario": scenario,
                "eflags_mask": mask,
                "eflags_value": value,
                "control": "fallthrough" if scenario == "not_taken" else control,
                "target": (
                    None
                    if scenario == "not_taken"
                    else (
                        dict(target)
                        if target is not None
                        else (
                            None
                            if target_eip is None
                            else {"kind": "fixed", "target_eip": target_eip}
                        )
                    )
                ),
            }
        )
    return {"class": "branch", "id": "branch-control", "outcomes": rows}


def _condition_name(value: Any, context: str) -> str:
    raw = _string(value, context)
    return raw.rsplit(".", 1)[-1]


def _binary_operation(value: Any, context: str) -> tuple[str, int]:
    operation = _condition_name(value, context)
    if operation not in {"add", "sub", "xor", "and", "or", "compare", "test"}:
        raise StageAInputError(
            f"{context} is not a reviewed binary operation"
        )
    flags = (
        _LOGICAL_FLAGS
        if operation in {"xor", "and", "or", "test"}
        else _ARITHMETIC_FLAGS
    )
    return operation, flags


def _shift_operation(value: Any, context: str) -> str:
    operation = _condition_name(value, context)
    if operation not in {"left", "right", "arithmeticRight"}:
        raise StageAInputError(f"{context} is not a reviewed shift operation")
    return operation


def _shift_eflags(width_bits: int, count: Mapping[str, Any]) -> int | None:
    if count["kind"] == "cl":
        return 0xC5 if width_bits == 32 else 0xC4
    amount = int(count["value"]) % 32
    if amount == 0:
        return None
    mask = 0xC4
    if amount <= width_bits:
        mask |= _CARRY_FLAG
    if amount == 1:
        mask |= 0x800
    return mask


def _condition_inputs(condition: str) -> tuple[tuple[int, int], tuple[int, int]]:
    cf, pf, zf, sf, of = 0x1, 0x4, 0x40, 0x80, 0x800
    table = {
        "overflow": ((of, of), (of, 0)),
        "notOverflow": ((of, 0), (of, of)),
        "equal": ((zf, zf), (zf, 0)),
        "notEqual": ((zf, 0), (zf, zf)),
        "below": ((cf, cf), (cf, 0)),
        "aboveOrEqual": ((cf, 0), (cf, cf)),
        "belowOrEqual": ((cf | zf, zf), (cf | zf, 0)),
        "above": ((cf | zf, 0), (zf, zf)),
        "sign": ((sf, sf), (sf, 0)),
        "notSign": ((sf, 0), (sf, sf)),
        "parity": ((pf, pf), (pf, 0)),
        "notParity": ((pf, 0), (pf, pf)),
        "less": ((sf | of, sf), (sf | of, 0)),
        "greaterOrEqual": ((sf | of, 0), (sf | of, sf)),
        "greater": ((zf | sf | of, 0), (zf, zf)),
        "lessOrEqual": ((zf, zf), (zf | sf | of, 0)),
    }
    try:
        return table[condition]
    except KeyError as exc:
        raise StageAInputError(
            f"decoded branch condition {condition!r} is unsupported"
        ) from exc


def _eflags_predicate(condition: str, *, taken: bool = True) -> dict[str, Any]:
    selected = _condition_inputs(condition)[0 if taken else 1]
    return {
        "kind": "eflags",
        "mask": selected[0],
        "value": selected[1],
    }


def _prefix_unresolved_reason(instruction: bytes) -> str | None:
    index = 0
    while index < len(instruction) and instruction[index] in _PREFIXES:
        prefix = instruction[index]
        if prefix in _OTHER_UNRESOLVED_PREFIXES:
            return _OTHER_UNRESOLVED_PREFIXES[prefix]
        index += 1
    return None


def _metadata_has_aliased_address_registers(value: Any) -> bool:
    if isinstance(value, Mapping):
        if set(value) == {
            "base",
            "index",
            "scale_shift",
            "displacement",
        }:
            base = value.get("base")
            return base is not None and base == value.get("index")
        return any(
            _metadata_has_aliased_address_registers(child)
            for child in value.values()
        )
    if isinstance(value, list):
        return any(_metadata_has_aliased_address_registers(child) for child in value)
    return False


def _resolved(
    *,
    effects: Sequence[dict[str, Any]],
    eflags: int,
    gpr_masks: Mapping[str, int] | None = None,
    x87: bool = False,
) -> dict[str, Any]:
    ordered = sorted(effects, key=lambda row: row["id"])
    if not ordered:
        ordered = [{"class": "noop", "id": "noop-core"}]
    return {
        "status": "resolved",
        "required_features": [],
        "effects": ordered,
        "defined_outputs": _defined_outputs(
            eflags,
            gpr_masks=gpr_masks,
            x87=x87,
        ),
    }


def _resolved_x87(
    *,
    effects: Sequence[dict[str, Any]] = (),
    stack_inputs: int,
    stack_outputs: int,
    eflags: int = _ARITHMETIC_FLAGS,
    gpr_masks: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    return _resolved(
        effects=[
            *effects,
            _x87_effect(
                stack_inputs=stack_inputs,
                stack_outputs=stack_outputs,
            ),
        ],
        eflags=eflags,
        gpr_masks=gpr_masks,
        x87=True,
    )


def _resolved_operand_accesses(
    *,
    accesses: Sequence[
        tuple[Mapping[str, Any], bool, bool, int, str]
    ],
    register_reads: Sequence[tuple[str, int]] = (),
    register_writes: Sequence[tuple[str, int]] = (),
    eflags: int,
    gpr_masks: Mapping[str, int] | None = None,
    memory_condition: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    reads_by_width: dict[int, list[str]] = {}
    writes_by_width: dict[int, list[str]] = {}
    for register, width_bits in register_reads:
        reads_by_width.setdefault(width_bits, []).append(register)
    for register, width_bits in register_writes:
        writes_by_width.setdefault(width_bits, []).append(register)
    effects: list[dict[str, Any]] = []
    for operand, read, write, width_bits, role in accesses:
        more_reads, more_writes, more_effects = _operand_access(
            operand,
            read=read,
            write=write,
            width_bits=width_bits,
            role=role,
        )
        if memory_condition is not None:
            for effect in more_effects:
                effect["condition"] = dict(memory_condition)
        reads_by_width.setdefault(width_bits, []).extend(more_reads)
        writes_by_width.setdefault(width_bits, []).extend(more_writes)
        effects.extend(more_effects)
    for width_bits in sorted(set(reads_by_width) | set(writes_by_width)):
        register = _register_effect_around_memory(
            reads=reads_by_width.get(width_bits, ()),
            writes=writes_by_width.get(width_bits, ()),
            effects=effects,
            width_bits=width_bits,
        )
        if register is not None:
            effects.append(register)
    return _resolved(effects=effects, eflags=eflags, gpr_masks=gpr_masks)


def _derive_enrichment(
    encoding: Mapping[str, Any],
    decoded: Mapping[str, Any],
) -> dict[str, Any]:
    instruction_bytes = bytes(encoding["instruction_bytes"])
    semantic_form = str(encoding["semantic_form"])
    if decoded.get("status") != "decoded":
        raise StageAInputError(
            f"Lean failed to decode proposal encoding {encoding['encoding_id']}"
        )
    decoded = _exact_fields(
        decoded,
        {
            "encoding_id",
            "status",
            "semantic_form",
            "decoded_size",
            "instruction",
        },
        f"Lean metadata for {encoding['encoding_id']}",
    )
    if decoded.get("encoding_id") != encoding["encoding_id"]:
        raise StageAInputError("Lean metadata names the wrong encoding")
    if decoded.get("semantic_form") != semantic_form:
        raise StageAInputError(
            f"Lean semantic form changed for encoding {encoding['encoding_id']}"
        )
    if decoded.get("decoded_size") != len(instruction_bytes):
        raise StageAInputError(
            f"Lean decoded size changed for encoding {encoding['encoding_id']}"
        )
    prefix_reason = _prefix_unresolved_reason(instruction_bytes)
    if prefix_reason is not None:
        return {"status": "unresolved", "reason": prefix_reason}

    instruction = decoded.get("instruction")
    if not isinstance(instruction, Mapping):
        raise StageAInputError("Lean decoded instruction metadata must be an object")
    constructor = _string(
        instruction.get("constructor"),
        f"Lean metadata for {encoding['encoding_id']} constructor",
    )
    context = f"Lean metadata for {encoding['encoding_id']} instruction"

    if constructor == "nop":
        _exact_fields(instruction, {"constructor"}, context)
        return _resolved(effects=[], eflags=_ARITHMETIC_FLAGS)
    if constructor == "movRegImm":
        row = _exact_fields(
            instruction, {"constructor", "destination", "value"}, context
        )
        destination = _register(row.get("destination"), f"{context}.destination")
        _uint(row.get("value"), 32, f"{context}.value")
        effect = _register_effect(reads=[], writes=[destination])
        return _resolved(effects=[effect] if effect else [], eflags=_ARITHMETIC_FLAGS)
    if constructor == "movRegReg":
        row = _exact_fields(
            instruction, {"constructor", "destination", "source"}, context
        )
        destination = _register(row.get("destination"), f"{context}.destination")
        source = _register(row.get("source"), f"{context}.source")
        effect = _register_effect(reads=[source], writes=[destination])
        return _resolved(effects=[effect] if effect else [], eflags=_ARITHMETIC_FLAGS)
    if constructor in {"addZero", "subZero", "cmpImm", "zeroReg"}:
        expected = (
            {"constructor", "source", "value"}
            if constructor == "cmpImm"
            else {"constructor", "destination"}
        )
        row = _exact_fields(instruction, expected, context)
        if constructor == "cmpImm":
            register = _register(row.get("source"), f"{context}.source")
            _uint(row.get("value"), 32, f"{context}.value")
            reads, writes, flags = [register], [], _ARITHMETIC_FLAGS
        elif constructor == "zeroReg":
            register = _register(row.get("destination"), f"{context}.destination")
            reads, writes, flags = [], [register], _LOGICAL_FLAGS
        else:
            register = _register(row.get("destination"), f"{context}.destination")
            reads, writes, flags = [register], [], _ARITHMETIC_FLAGS
        effect = _register_effect(reads=reads, writes=writes)
        return _resolved(effects=[effect] if effect else [], eflags=flags)
    if constructor in {"jumpRel8", "jumpRel32"}:
        row = _exact_fields(
            instruction, {"constructor", "displacement"}, context
        )
        bits = 8 if constructor == "jumpRel8" else 32
        displacement = _uint(
            row.get("displacement"), bits, f"{context}.displacement"
        )
        target = _relative_target(len(instruction_bytes), displacement, bits)
        return _resolved(
            effects=[
                _branch_effect(control="direct_branch", target_eip=target)
            ],
            eflags=_ARITHMETIC_FLAGS,
        )
    if constructor in {"branchEqual", "branchCondition"}:
        if constructor == "branchEqual":
            row = _exact_fields(
                instruction,
                {"constructor", "inverted", "displacement"},
                context,
            )
            inverted = row.get("inverted")
            if not isinstance(inverted, bool):
                raise StageAInputError(f"{context}.inverted must be a boolean")
            condition = "notEqual" if inverted else "equal"
            bits = 8
        else:
            row = _exact_fields(
                instruction,
                {"constructor", "condition", "displacement", "size"},
                context,
            )
            condition = _condition_name(row.get("condition"), f"{context}.condition")
            size = _uint(row.get("size"), 8, f"{context}.size")
            if size not in {2, 6}:
                raise StageAInputError(f"{context}.size is not a reviewed branch size")
            bits = 8 if size == 2 else 32
        displacement = _uint(
            row.get("displacement"), bits, f"{context}.displacement"
        )
        target = _relative_target(len(instruction_bytes), displacement, bits)
        taken, not_taken = _condition_inputs(condition)
        return _resolved(
            effects=[
                _branch_effect(
                    control="direct_branch",
                    target_eip=target,
                    outcomes=(
                        ("not_taken", not_taken[0], not_taken[1]),
                        ("taken", taken[0], taken[1]),
                    ),
                )
            ],
            eflags=_ARITHMETIC_FLAGS,
        )
    if constructor == "callRel32":
        row = _exact_fields(
            instruction, {"constructor", "displacement"}, context
        )
        displacement = _uint(
            row.get("displacement"), 32, f"{context}.displacement"
        )
        target = _relative_target(len(instruction_bytes), displacement, 32)
        stack = {
            "base": "esp",
            "index": None,
            "scale": 1,
            "displacement": -4,
            "segment": "flat",
        }
        register = _register_effect(reads=[], writes=["esp"])
        effects = [
            _branch_effect(control="direct_call", target_eip=target),
            _memory_effect(
                address=stack,
                access="write",
                width_bits=32,
                role="stack",
            ),
        ]
        if register is not None:
            effects.append(register)
        return _resolved(effects=effects, eflags=_ARITHMETIC_FLAGS)
    if constructor in {"ret", "retPop"}:
        expected = (
            {"constructor", "pop_bytes"}
            if constructor == "retPop"
            else {"constructor"}
        )
        row = _exact_fields(instruction, expected, context)
        if constructor == "retPop":
            _uint(row.get("pop_bytes"), 16, f"{context}.pop_bytes")
        stack = {
            "base": "esp",
            "index": None,
            "scale": 1,
            "displacement": 0,
            "segment": "flat",
        }
        register = _register_effect(reads=[], writes=["esp"])
        effects = [
            _branch_effect(control="return", target_eip=None),
            _memory_effect(
                address=stack,
                access="read",
                width_bits=32,
                role="stack",
            ),
        ]
        if register is not None:
            effects.append(register)
        return _resolved(effects=effects, eflags=_ARITHMETIC_FLAGS)
    if constructor in {"pushReg", "popReg", "pushOperand"}:
        if constructor == "pushReg":
            row = _exact_fields(instruction, {"constructor", "source"}, context)
            source = {
                "kind": "register",
                "register": _register(row.get("source"), f"{context}.source"),
            }
            destination = None
            access = "write"
            displacement = -4
        elif constructor == "popReg":
            row = _exact_fields(
                instruction, {"constructor", "destination"}, context
            )
            source = None
            destination = _register(
                row.get("destination"), f"{context}.destination"
            )
            access = "read"
            displacement = 0
        else:
            row = _exact_fields(instruction, {"constructor", "source"}, context)
            source = _operand32(row.get("source"), f"{context}.source")
            destination = None
            access = "write"
            displacement = -4
        reads = (
            [str(source["register"])]
            if source is not None and source.get("kind") == "register"
            else []
        )
        writes = ["esp"] + ([destination] if destination is not None else [])
        if "esp" in reads:
            reads.remove("esp")
        effects: list[dict[str, Any]] = [
            _memory_effect(
                address={
                    "base": "esp",
                    "index": None,
                    "scale": 1,
                    "displacement": displacement,
                    "segment": "flat",
                },
                access=access,
                width_bits=32,
                role="stack",
            )
        ]
        if source is not None and source.get("kind") == "memory":
            effects.append(
                _memory_effect(
                    address=source["address"],
                    access="read",
                    width_bits=32,
                    role="source",
                )
            )
        register = _register_effect(reads=reads, writes=writes)
        if register is not None:
            effects.append(register)
        return _resolved(effects=effects, eflags=_ARITHMETIC_FLAGS)
    if constructor == "leave":
        _exact_fields(instruction, {"constructor"}, context)
        effects = [
            _memory_effect(
                address={
                    "base": "ebp",
                    "index": None,
                    "scale": 1,
                    "displacement": 0,
                    "segment": "flat",
                },
                access="read",
                width_bits=32,
                role="stack",
            )
        ]
        register = _register_effect_around_memory(
            reads=["ebp"],
            writes=["ebp", "esp"],
            effects=effects,
        )
        if register is not None:
            effects.append(register)
        return _resolved(effects=effects, eflags=_ARITHMETIC_FLAGS)
    if constructor in {"lea", "load32", "store32"}:
        if constructor == "store32":
            row = _exact_fields(
                instruction, {"constructor", "base", "offset", "source"}, context
            )
            base = _register(row.get("base"), f"{context}.base")
            source = _register(row.get("source"), f"{context}.source")
            offset = _uint(row.get("offset"), 32, f"{context}.offset")
            effects = [
                _memory_effect(
                    address={
                        "base": base,
                        "index": None,
                        "scale": 1,
                        "displacement": _signed32(offset),
                        "segment": "flat",
                    },
                    access="write",
                    width_bits=32,
                    role="destination",
                )
            ]
            register = _register_effect_around_memory(
                reads=[source],
                writes=[],
                effects=effects,
            )
        else:
            row = _exact_fields(
                instruction,
                {"constructor", "destination", "base", "offset"},
                context,
            )
            destination = _register(
                row.get("destination"), f"{context}.destination"
            )
            base = _register(row.get("base"), f"{context}.base")
            offset = _uint(row.get("offset"), 32, f"{context}.offset")
            register = _register_effect(
                reads=[base] if constructor == "lea" else [],
                writes=[destination],
            )
            effects = []
            if constructor == "load32":
                effects.append(
                    _memory_effect(
                        address={
                            "base": base,
                            "index": None,
                            "scale": 1,
                            "displacement": _signed32(offset),
                            "segment": "flat",
                        },
                        access="read",
                        width_bits=32,
                        role="source",
                    )
                )
        if register is not None:
            effects.append(register)
        return _resolved(effects=effects, eflags=_ARITHMETIC_FLAGS)
    if constructor == "leaAddress":
        row = _exact_fields(
            instruction, {"constructor", "destination", "source"}, context
        )
        destination = _register(row.get("destination"), f"{context}.destination")
        address = _address(row.get("source"), f"{context}.source")
        reads = [
            register
            for register in (address["base"], address["index"])
            if register is not None
        ]
        register = _register_effect(reads=reads, writes=[destination])
        return _resolved(
            effects=[register] if register is not None else [],
            eflags=_ARITHMETIC_FLAGS,
        )
    if constructor in {"movFromOperand", "movToOperand", "movImmediate"}:
        if constructor == "movFromOperand":
            row = _exact_fields(
                instruction, {"constructor", "destination", "source"}, context
            )
            destination = {
                "kind": "register",
                "register": _register(
                    row.get("destination"), f"{context}.destination"
                ),
            }
            source = _operand32(row.get("source"), f"{context}.source")
        elif constructor == "movToOperand":
            row = _exact_fields(
                instruction, {"constructor", "destination", "source"}, context
            )
            destination = _operand32(
                row.get("destination"), f"{context}.destination"
            )
            source = {
                "kind": "register",
                "register": _register(row.get("source"), f"{context}.source"),
            }
        else:
            row = _exact_fields(
                instruction, {"constructor", "destination", "value"}, context
            )
            destination = _operand32(
                row.get("destination"), f"{context}.destination"
            )
            source = {
                "kind": "immediate",
                "value": _uint(row.get("value"), 32, f"{context}.value"),
            }
        reads, writes, effects = _operand_access(
            source,
            read=True,
            write=False,
            width_bits=32,
            role="source",
        )
        more_reads, more_writes, destination_effects = _operand_access(
            destination,
            read=False,
            write=True,
            width_bits=32,
            role="destination",
        )
        reads.extend(more_reads)
        writes.extend(more_writes)
        effects.extend(destination_effects)
        register = _register_effect_around_memory(
            reads=reads,
            writes=writes,
            effects=effects,
        )
        if register is not None:
            effects.append(register)
        return _resolved(effects=effects, eflags=_ARITHMETIC_FLAGS)
    if constructor in {"binary", "unary"}:
        if constructor == "binary":
            row = _exact_fields(
                instruction,
                {"constructor", "operation", "destination", "source"},
                context,
            )
            operation, flags = _binary_operation(
                row.get("operation"), f"{context}.operation"
            )
            destination = _operand32(
                row.get("destination"), f"{context}.destination"
            )
            source = _operand32(row.get("source"), f"{context}.source")
            writes_destination = operation not in {"compare", "test"}
            reads, writes, effects = _operand_access(
                destination,
                read=True,
                write=writes_destination,
                width_bits=32,
                role="destination",
            )
            more_reads, more_writes, source_effects = _operand_access(
                source,
                read=True,
                write=False,
                width_bits=32,
                role="source",
            )
            reads.extend(more_reads)
            writes.extend(more_writes)
            effects.extend(source_effects)
        else:
            row = _exact_fields(
                instruction,
                {"constructor", "operation", "destination"},
                context,
            )
            operation = _condition_name(
                row.get("operation"), f"{context}.operation"
            )
            if operation not in {"bitNot", "negate"}:
                raise StageAInputError(
                    f"{context}.operation is not a reviewed unary operation"
                )
            destination = _operand32(
                row.get("destination"), f"{context}.destination"
            )
            reads, writes, effects = _operand_access(
                destination,
                read=True,
                write=True,
                width_bits=32,
                role="destination",
            )
            flags = _ARITHMETIC_FLAGS
        register = _register_effect_around_memory(
            reads=reads,
            writes=writes,
            effects=effects,
        )
        if register is not None:
            effects.append(register)
        return _resolved(effects=effects, eflags=flags)
    if constructor in {"shift", "shiftWidth", "shift8"}:
        expected = {"constructor", "operation", "destination", "count"}
        if constructor == "shiftWidth":
            expected.add("width_bits")
        row = _exact_fields(instruction, expected, context)
        _shift_operation(row.get("operation"), f"{context}.operation")
        count = _shift_count(row.get("count"), f"{context}.count")
        if constructor == "shift":
            width_bits = 32
            destination = _operand32(
                row.get("destination"), f"{context}.destination"
            )
        elif constructor == "shiftWidth":
            width_bits = _width_bits(
                row.get("width_bits"), f"{context}.width_bits"
            )
            if width_bits not in {8, 16}:
                raise StageAInputError(
                    f"{context}.width_bits is not a partial operand width"
                )
            destination = _operand32(
                row.get("destination"), f"{context}.destination"
            )
        else:
            width_bits = 8
            destination = _operand8(
                row.get("destination"), f"{context}.destination"
            )
        if destination["kind"] == "immediate":
            raise StageAInputError(f"{context}.destination cannot be immediate")
        eflags = _shift_eflags(width_bits, count)
        if eflags is None:
            return _resolved(effects=[], eflags=0)
        return _resolved_operand_accesses(
            accesses=[
                (
                    destination,
                    True,
                    True,
                    width_bits,
                    "destination",
                )
            ],
            register_reads=(
                [("ecx", 8)] if count["kind"] == "cl" else []
            ),
            eflags=eflags,
            memory_condition=(
                {
                    "kind": "register",
                    "location": {"register": "ecx", "lsb": 0},
                    "width_bits": 8,
                    "mask": 0x1F,
                    "value": 1,
                }
                if destination["kind"] == "memory"
                and count["kind"] == "cl"
                else None
            ),
        )
    if constructor in {
        "movZeroExtend",
        "movSignExtend",
        "movSignExtend8",
        "movSignExtend8ToWord",
    }:
        expected = {"constructor", "destination", "source"}
        if constructor in {"movZeroExtend", "movSignExtend"}:
            expected.add("width_bits")
        row = _exact_fields(instruction, expected, context)
        destination_register = _register(
            row.get("destination"), f"{context}.destination"
        )
        if constructor in {"movZeroExtend", "movSignExtend"}:
            width_bits = _width_bits(
                row.get("width_bits"), f"{context}.width_bits"
            )
            if width_bits not in {8, 16}:
                raise StageAInputError(
                    f"{context}.width_bits is not an extension source width"
                )
            source = _operand32(row.get("source"), f"{context}.source")
        else:
            width_bits = 8
            source = _operand8(row.get("source"), f"{context}.source")
        destination_width = (
            16 if constructor == "movSignExtend8ToWord" else 32
        )
        destination = {
            "kind": "register",
            "register": destination_register,
        }
        return _resolved_operand_accesses(
            accesses=[
                (source, True, False, width_bits, "source"),
                (
                    destination,
                    destination_width < 32,
                    True,
                    destination_width,
                    "destination",
                ),
            ],
            eflags=_ARITHMETIC_FLAGS,
        )
    if constructor in {
        "movFromOperandWidth",
        "movToOperandWidth",
        "movImmediateWidth",
    }:
        expected = {"constructor", "width_bits", "destination"}
        if constructor == "movFromOperandWidth":
            expected.add("source")
        elif constructor == "movToOperandWidth":
            expected.add("source")
        else:
            expected.add("value")
        row = _exact_fields(instruction, expected, context)
        width_bits = _width_bits(
            row.get("width_bits"), f"{context}.width_bits"
        )
        if width_bits not in {8, 16}:
            raise StageAInputError(
                f"{context}.width_bits is not a partial operand width"
            )
        if constructor == "movFromOperandWidth":
            destination = {
                "kind": "register",
                "register": _register(
                    row.get("destination"), f"{context}.destination"
                ),
            }
            source = _operand32(row.get("source"), f"{context}.source")
        elif constructor == "movToOperandWidth":
            destination = _operand32(
                row.get("destination"), f"{context}.destination"
            )
            source = {
                "kind": "register",
                "register": _register(
                    row.get("source"), f"{context}.source"
                ),
            }
        else:
            destination = _operand32(
                row.get("destination"), f"{context}.destination"
            )
            source = {
                "kind": "immediate",
                "value": _uint(
                    row.get("value"), width_bits, f"{context}.value"
                ),
            }
        return _resolved_operand_accesses(
            accesses=[
                (source, True, False, width_bits, "source"),
                (
                    destination,
                    destination["kind"] == "register",
                    True,
                    width_bits,
                    "destination",
                ),
            ],
            eflags=_ARITHMETIC_FLAGS,
        )
    if constructor == "binaryWidth":
        row = _exact_fields(
            instruction,
            {
                "constructor",
                "width_bits",
                "operation",
                "destination",
                "source",
            },
            context,
        )
        width_bits = _width_bits(
            row.get("width_bits"), f"{context}.width_bits"
        )
        if width_bits not in {8, 16}:
            raise StageAInputError(
                f"{context}.width_bits is not a partial operand width"
            )
        operation, flags = _binary_operation(
            row.get("operation"), f"{context}.operation"
        )
        destination = _operand32(
            row.get("destination"), f"{context}.destination"
        )
        source = _operand32(row.get("source"), f"{context}.source")
        return _resolved_operand_accesses(
            accesses=[
                (
                    destination,
                    True,
                    operation not in {"compare", "test"},
                    width_bits,
                    "destination",
                ),
                (source, True, False, width_bits, "source"),
            ],
            eflags=flags,
        )
    if constructor in {
        "movFromOperand8",
        "movToOperand8",
        "movImmediate8",
        "binary8",
    }:
        if constructor == "movFromOperand8":
            row = _exact_fields(
                instruction,
                {"constructor", "destination", "source"},
                context,
            )
            destination_register = _byte_register(
                row.get("destination"), f"{context}.destination"
            )
            destination = {
                "kind": "register",
                "register": destination_register["register"],
                "high": destination_register["high"],
            }
            source = _operand8(row.get("source"), f"{context}.source")
            operation = None
            flags = _ARITHMETIC_FLAGS
        elif constructor == "movToOperand8":
            row = _exact_fields(
                instruction,
                {"constructor", "destination", "source"},
                context,
            )
            destination = _operand8(
                row.get("destination"), f"{context}.destination"
            )
            source_register = _byte_register(
                row.get("source"), f"{context}.source"
            )
            source = {
                "kind": "register",
                "register": source_register["register"],
                "high": source_register["high"],
            }
            operation = None
            flags = _ARITHMETIC_FLAGS
        elif constructor == "movImmediate8":
            row = _exact_fields(
                instruction,
                {"constructor", "destination", "value"},
                context,
            )
            destination = _operand8(
                row.get("destination"), f"{context}.destination"
            )
            source = {
                "kind": "immediate",
                "value": _uint(row.get("value"), 8, f"{context}.value"),
            }
            operation = None
            flags = _ARITHMETIC_FLAGS
        else:
            row = _exact_fields(
                instruction,
                {"constructor", "operation", "destination", "source"},
                context,
            )
            operation, flags = _binary_operation(
                row.get("operation"), f"{context}.operation"
            )
            destination = _operand8(
                row.get("destination"), f"{context}.destination"
            )
            source = _operand8(row.get("source"), f"{context}.source")
        writes_destination = (
            operation not in {"compare", "test"}
            if operation is not None
            else True
        )
        reads_destination = (
            operation is not None or destination["kind"] == "register"
        )
        return _resolved_operand_accesses(
            accesses=[
                (
                    destination,
                    reads_destination,
                    writes_destination,
                    8,
                    "destination",
                ),
                (source, True, False, 8, "source"),
            ],
            eflags=flags,
        )
    if constructor == "conditionalMove":
        row = _exact_fields(
            instruction,
            {"constructor", "condition", "destination", "source"},
            context,
        )
        condition = _condition_name(
            row.get("condition"), f"{context}.condition"
        )
        _condition_inputs(condition)
        destination = {
            "kind": "register",
            "register": _register(
                row.get("destination"), f"{context}.destination"
            ),
        }
        source = _operand32(row.get("source"), f"{context}.source")
        return _resolved_operand_accesses(
            accesses=[
                (destination, True, True, 32, "destination"),
                (source, True, False, 32, "source"),
            ],
            eflags=_ARITHMETIC_FLAGS,
            memory_condition=(
                _eflags_predicate(condition)
                if source["kind"] == "memory"
                else None
            ),
        )
    if constructor == "setCondition":
        row = _exact_fields(
            instruction,
            {"constructor", "condition", "destination"},
            context,
        )
        condition = _condition_name(
            row.get("condition"), f"{context}.condition"
        )
        _condition_inputs(condition)
        destination = _operand8(
            row.get("destination"), f"{context}.destination"
        )
        return _resolved_operand_accesses(
            accesses=[
                (
                    destination,
                    destination["kind"] == "register",
                    True,
                    8,
                    "destination",
                ),
            ],
            eflags=_ARITHMETIC_FLAGS,
        )
    if constructor == "exchange":
        row = _exact_fields(
            instruction,
            {"constructor", "destination", "source"},
            context,
        )
        destination = _operand32(
            row.get("destination"), f"{context}.destination"
        )
        source = {
            "kind": "register",
            "register": _register(row.get("source"), f"{context}.source"),
        }
        return _resolved_operand_accesses(
            accesses=[
                (destination, True, True, 32, "destination"),
                (source, True, True, 32, "source"),
            ],
            eflags=_ARITHMETIC_FLAGS,
        )
    if constructor == "convertWordToDword":
        _exact_fields(instruction, {"constructor"}, context)
        return _resolved(
            effects=[
                {
                    "class": "register",
                    "id": "register-16-gpr",
                    "width_bits": 16,
                    "reads": ["eax"],
                    "writes": [],
                },
                {
                    "class": "register",
                    "id": "register-32-gpr",
                    "width_bits": 32,
                    "reads": [],
                    "writes": ["eax"],
                },
            ],
            eflags=_ARITHMETIC_FLAGS,
        )
    if constructor == "convertDwordToQuad":
        _exact_fields(instruction, {"constructor"}, context)
        return _resolved(
            effects=[
                {
                    "class": "register",
                    "id": "register-32-gpr",
                    "width_bits": 32,
                    "reads": ["eax"],
                    "writes": ["edx"],
                }
            ],
            eflags=_ARITHMETIC_FLAGS,
        )
    if constructor == "binaryCarry":
        row = _exact_fields(
            instruction,
            {"constructor", "subtract", "destination", "source"},
            context,
        )
        if not isinstance(row.get("subtract"), bool):
            raise StageAInputError(f"{context}.subtract must be a boolean")
        destination = _operand32(
            row.get("destination"), f"{context}.destination"
        )
        source = _operand32(row.get("source"), f"{context}.source")
        return _resolved_operand_accesses(
            accesses=[
                (destination, True, True, 32, "destination"),
                (source, True, False, 32, "source"),
            ],
            eflags=_ARITHMETIC_FLAGS,
        )
    if constructor in {"multiplyFull", "multiplyLow"}:
        if constructor == "multiplyFull":
            row = _exact_fields(
                instruction,
                {"constructor", "signed", "source"},
                context,
            )
            signed = row.get("signed")
            if not isinstance(signed, bool):
                raise StageAInputError(f"{context}.signed must be a boolean")
            source = _operand32(row.get("source"), f"{context}.source")
            return _resolved_operand_accesses(
                accesses=[(source, True, False, 32, "source")],
                register_reads=[("eax", 32)],
                register_writes=[("eax", 32), ("edx", 32)],
                eflags=_MULTIPLY_FLAGS,
            )
        row = _exact_fields(
            instruction,
            {"constructor", "destination", "source", "immediate"},
            context,
        )
        destination_register = _register(
            row.get("destination"), f"{context}.destination"
        )
        source = _operand32(row.get("source"), f"{context}.source")
        immediate = row.get("immediate")
        if immediate is not None:
            _uint(immediate, 32, f"{context}.immediate")
        destination = {
            "kind": "register",
            "register": destination_register,
        }
        accesses = [(source, True, False, 32, "source")]
        if immediate is None:
            accesses.append((destination, True, False, 32, "destination"))
        accesses.append((destination, False, True, 32, "destination-output"))
        return _resolved_operand_accesses(
            accesses=accesses,
            eflags=_MULTIPLY_FLAGS,
        )
    if constructor == "doubleShift":
        row = _exact_fields(
            instruction,
            {"constructor", "left", "destination", "source", "count"},
            context,
        )
        if not isinstance(row.get("left"), bool):
            raise StageAInputError(f"{context}.left must be a boolean")
        destination = _operand32(
            row.get("destination"), f"{context}.destination"
        )
        if destination["kind"] == "immediate":
            raise StageAInputError(f"{context}.destination cannot be immediate")
        source = _register(row.get("source"), f"{context}.source")
        count = _shift_count(row.get("count"), f"{context}.count")
        eflags = _shift_eflags(32, count)
        if eflags is None:
            return _resolved(effects=[], eflags=0)
        register_reads = [(source, 32)]
        if count["kind"] == "cl":
            register_reads.append(("ecx", 8))
        return _resolved_operand_accesses(
            accesses=[(destination, True, True, 32, "destination")],
            register_reads=register_reads,
            eflags=eflags,
            memory_condition=(
                {
                    "kind": "register",
                    "location": {"register": "ecx", "lsb": 0},
                    "width_bits": 8,
                    "mask": 0x1F,
                    "value": 1,
                }
                if destination["kind"] == "memory"
                and count["kind"] == "cl"
                else None
            ),
        )
    if constructor == "bitScan":
        row = _exact_fields(
            instruction,
            {"constructor", "operation", "destination", "source"},
            context,
        )
        operation = _string(
            row.get("operation"), f"{context}.operation"
        )
        if not (
            operation.endswith(".forward")
            or operation.endswith(".reverse")
            or ".trailingZeroCount" in operation
        ):
            raise StageAInputError(
                f"{context}.operation is not a reviewed bit-scan operation"
            )
        if ".trailingZeroCount" in operation:
            return {
                "status": "unresolved",
                "reason": "profile_feature_not_representable",
            }
        destination = _register(
            row.get("destination"), f"{context}.destination"
        )
        source = _operand32(row.get("source"), f"{context}.source")
        return _resolved_operand_accesses(
            accesses=[(source, True, False, 32, "source")],
            register_writes=[(destination, 32)],
            eflags=_ZERO_FLAG,
            gpr_masks={destination: 0},
        )
    if constructor == "bitTestRegister":
        row = _exact_fields(
            instruction,
            {"constructor", "base", "index"},
            context,
        )
        base = _register(row.get("base"), f"{context}.base")
        index = _register(row.get("index"), f"{context}.index")
        effect = _register_effect(reads=[base, index], writes=[])
        return _resolved(
            effects=[effect] if effect is not None else [],
            eflags=_CARRY_FLAG,
        )
    if constructor == "x87LoadStack":
        row = _exact_fields(instruction, {"constructor", "index"}, context)
        index = _x87_index(row.get("index"), f"{context}.index")
        inputs = index + 1
        return _resolved_x87(
            stack_inputs=inputs,
            stack_outputs=min(inputs + 1, 8),
        )
    if constructor == "x87LoadConstant":
        row = _exact_fields(instruction, {"constructor", "value"}, context)
        _uint(row.get("value"), 80, f"{context}.value")
        return _resolved_x87(stack_inputs=0, stack_outputs=1)
    if constructor == "x87Exchange":
        row = _exact_fields(instruction, {"constructor", "index"}, context)
        inputs = _x87_index(row.get("index"), f"{context}.index") + 1
        return _resolved_x87(
            stack_inputs=inputs,
            stack_outputs=inputs,
        )
    if constructor == "x87StoreStack":
        row = _exact_fields(
            instruction,
            {"constructor", "index", "pop"},
            context,
        )
        inputs = _x87_index(row.get("index"), f"{context}.index") + 1
        pop = row.get("pop")
        if not isinstance(pop, bool):
            raise StageAInputError(f"{context}.pop must be a boolean")
        return _resolved_x87(
            stack_inputs=inputs,
            stack_outputs=max(0, inputs - int(pop)),
        )
    if constructor == "x87Unary":
        row = _exact_fields(
            instruction,
            {"constructor", "operation"},
            context,
        )
        operation = _condition_name(
            row.get("operation"), f"{context}.operation"
        )
        if operation != "negate":
            raise StageAInputError(
                f"{context}.operation is not a reviewed x87 unary operation"
            )
        return _resolved_x87(stack_inputs=1, stack_outputs=1)
    if constructor == "x87BinaryStack":
        row = _exact_fields(
            instruction,
            {"constructor", "operation", "destination", "source", "pop"},
            context,
        )
        operation = _condition_name(
            row.get("operation"), f"{context}.operation"
        )
        if operation not in {
            "add",
            "multiply",
            "subtract",
            "reverseSubtract",
            "divide",
            "reverseDivide",
        }:
            raise StageAInputError(
                f"{context}.operation is not a reviewed x87 binary operation"
            )
        destination = _x87_index(
            row.get("destination"), f"{context}.destination"
        )
        source = _x87_index(row.get("source"), f"{context}.source")
        pop = row.get("pop")
        if not isinstance(pop, bool):
            raise StageAInputError(f"{context}.pop must be a boolean")
        inputs = max(destination, source) + 1
        return _resolved_x87(
            stack_inputs=inputs,
            stack_outputs=max(0, inputs - int(pop)),
        )
    if constructor == "x87CompareStack":
        row = _exact_fields(
            instruction,
            {"constructor", "mode", "destination", "index", "pop"},
            context,
        )
        mode = _condition_name(row.get("mode"), f"{context}.mode")
        destination = _condition_name(
            row.get("destination"), f"{context}.destination"
        )
        if mode not in {"ordered", "unordered"}:
            raise StageAInputError(
                f"{context}.mode is not a reviewed x87 compare mode"
            )
        if destination not in {"status", "eflags"}:
            raise StageAInputError(
                f"{context}.destination is not a reviewed x87 compare destination"
            )
        inputs = _x87_index(row.get("index"), f"{context}.index") + 1
        pop = row.get("pop")
        if not isinstance(pop, bool):
            raise StageAInputError(f"{context}.pop must be a boolean")
        return _resolved_x87(
            stack_inputs=inputs,
            stack_outputs=max(0, inputs - int(pop)),
            eflags=0x8C5 if destination == "eflags" else _ARITHMETIC_FLAGS,
        )
    if constructor in {
        "x87LoadMemory",
        "x87StoreMemory",
        "x87BinaryMemory",
    }:
        if constructor == "x87StoreMemory":
            row = _exact_fields(
                instruction,
                {"constructor", "format", "destination", "pop"},
                context,
            )
            address = _address(
                row.get("destination"), f"{context}.destination"
            )
            access = "write"
            role = "destination"
            pop = row.get("pop")
            if not isinstance(pop, bool):
                raise StageAInputError(f"{context}.pop must be a boolean")
            stack_inputs = 1
            stack_outputs = 0 if pop else 1
        else:
            row = _exact_fields(
                instruction,
                {"constructor", "format", "source"}
                | (
                    {"operation"}
                    if constructor == "x87BinaryMemory"
                    else set()
                ),
                context,
            )
            address = _address(row.get("source"), f"{context}.source")
            access = "read"
            role = "source"
            if constructor == "x87BinaryMemory":
                operation = _condition_name(
                    row.get("operation"), f"{context}.operation"
                )
                if operation not in {
                    "add",
                    "multiply",
                    "subtract",
                    "reverseSubtract",
                    "divide",
                    "reverseDivide",
                }:
                    raise StageAInputError(
                        f"{context}.operation is not a reviewed x87 binary operation"
                    )
                stack_inputs = stack_outputs = 1
            else:
                stack_inputs, stack_outputs = 0, 1
        width_bits = _x87_format_width(
            row.get("format"), f"{context}.format"
        )
        return _resolved_x87(
            effects=[
                _memory_effect(
                    address=address,
                    access=access,
                    width_bits=width_bits,
                    role=role,
                )
            ],
            stack_inputs=stack_inputs,
            stack_outputs=stack_outputs,
        )
    if constructor in {"x87LoadControl", "x87StoreControl"}:
        field = "source" if constructor == "x87LoadControl" else "destination"
        row = _exact_fields(instruction, {"constructor", field}, context)
        return _resolved_x87(
            effects=[
                _memory_effect(
                    address=_address(row.get(field), f"{context}.{field}"),
                    access=(
                        "read"
                        if constructor == "x87LoadControl"
                        else "write"
                    ),
                    width_bits=16,
                    role=field,
                )
            ],
            stack_inputs=0,
            stack_outputs=0,
        )
    if constructor in {"x87SaveState", "x87RestoreState"}:
        field = "destination" if constructor == "x87SaveState" else "source"
        row = _exact_fields(instruction, {"constructor", field}, context)
        operand_size_16 = 0x66 in instruction_bytes[:-1]
        return _resolved_x87(
            effects=[
                _memory_effect(
                    address=_address(row.get(field), f"{context}.{field}"),
                    access=(
                        "write"
                        if constructor == "x87SaveState"
                        else "read"
                    ),
                    width_bits=752 if operand_size_16 else 864,
                    role=field,
                )
            ],
            stack_inputs=8 if constructor == "x87SaveState" else 0,
            stack_outputs=0 if constructor == "x87SaveState" else 8,
        )
    if constructor in {"x87Wait", "x87Initialize"}:
        _exact_fields(instruction, {"constructor"}, context)
        return _resolved_x87(
            stack_inputs=0,
            stack_outputs=0,
        )
    if constructor == "x87StoreStatusAx":
        _exact_fields(instruction, {"constructor"}, context)
        register = _register_effect(
            reads=[],
            writes=["eax"],
            width_bits=16,
        )
        return _resolved_x87(
            effects=[register] if register is not None else [],
            stack_inputs=0,
            stack_outputs=0,
        )
    if constructor == "x87Examine":
        _exact_fields(instruction, {"constructor"}, context)
        return _resolved_x87(stack_inputs=1, stack_outputs=1)
    if constructor in {"moveDwords", "storeDwords"}:
        row = _exact_fields(
            instruction, {"constructor", "repeated"}, context
        )
        repeated = row.get("repeated")
        if not isinstance(repeated, bool):
            raise StageAInputError(f"{context}.repeated must be a boolean")
        condition = (
            {
                "kind": "register",
                "location": {"register": "ecx", "lsb": 0},
                "width_bits": 32,
                "mask": 0xFFFFFFFF,
                "value": 1,
            }
            if repeated
            else None
        )
        effects: list[dict[str, Any]] = [
            _memory_effect(
                address={
                    "base": "edi",
                    "index": None,
                    "scale": 1,
                    "displacement": 0,
                    "segment": "flat",
                },
                access="write",
                width_bits=32,
                role="destination",
                condition=condition,
            ),
            {
                "class": "state",
                "id": "state-eflags",
                "state": "eflags",
                "access": "read",
            },
        ]
        reads = ["edi", "eax"] if constructor == "storeDwords" else ["esi", "edi"]
        writes = ["edi"]
        if constructor == "moveDwords":
            effects.append(
                _memory_effect(
                    address={
                        "base": "esi",
                        "index": None,
                        "scale": 1,
                        "displacement": 0,
                        "segment": "flat",
                    },
                    access="read",
                    width_bits=32,
                    role="source",
                    condition=condition,
                )
            )
            writes.append("esi")
        if repeated:
            reads.append("ecx")
            writes.append("ecx")
        register = _register_effect_around_memory(
            reads=reads,
            writes=writes,
            effects=effects,
        )
        if register is not None:
            effects.append(register)
        return _resolved(effects=effects, eflags=0)
    if constructor == "movFs32":
        row = _exact_fields(
            instruction, {"constructor", "destination", "source"}, context
        )
        destination = _register(
            row.get("destination"), f"{context}.destination"
        )
        source = _address(row.get("source"), f"{context}.source")
        source["segment"] = "fs"
        effects = [
            _memory_effect(
                address=source,
                access="read",
                width_bits=32,
                role="source",
            ),
            {
                "class": "state",
                "id": "state-fs",
                "state": "fs",
                "access": "read",
            },
        ]
        register = _register_effect_around_memory(
            reads=[],
            writes=[destination],
            effects=effects,
        )
        if register is not None:
            effects.append(register)
        return _resolved(effects=effects, eflags=_ARITHMETIC_FLAGS)
    if constructor == "atomicCompareExchange":
        row = _exact_fields(
            instruction, {"constructor", "destination", "source"}, context
        )
        destination = _address(
            row.get("destination"), f"{context}.destination"
        )
        source = _register(row.get("source"), f"{context}.source")
        effects = [
            _memory_effect(
                address=destination,
                access="read_write",
                width_bits=32,
                role="destination",
            )
        ]
        register = _register_effect_around_memory(
            reads=["eax", source],
            writes=["eax"],
            effects=effects,
        )
        if register is not None:
            effects.append(register)
        return _resolved(effects=effects, eflags=_ARITHMETIC_FLAGS)
    if constructor in {"callImport", "jumpImport"}:
        row = _exact_fields(
            instruction,
            {"constructor", "absolute_address"},
            context,
        )
        absolute_address = _uint(
            row.get("absolute_address"),
            32,
            f"{context}.absolute_address",
        )
        effects: list[dict[str, Any]] = [
            _branch_effect(
                control=(
                    "indirect_call"
                    if constructor == "callImport"
                    else "indirect_branch"
                ),
                target_eip=None,
                target={
                    "kind": "memory",
                    "address": {
                        "base": None,
                        "index": None,
                        "scale": 1,
                        "displacement": _signed32(absolute_address),
                        "segment": "flat",
                    },
                },
            )
        ]
        if constructor == "callImport":
            effects.append(
                _memory_effect(
                    address={
                        "base": "esp",
                        "index": None,
                        "scale": 1,
                        "displacement": -4,
                        "segment": "flat",
                    },
                    access="write",
                    width_bits=32,
                    role="stack",
                )
            )
            register = _register_effect(reads=[], writes=["esp"])
            if register is not None:
                effects.append(register)
        return _resolved(effects=effects, eflags=_ARITHMETIC_FLAGS)
    if constructor in {"divideUnsigned", "divideSigned"}:
        row = _exact_fields(instruction, {"constructor", "source"}, context)
        source = _operand32(row.get("source"), f"{context}.source")
        divisor_register = (
            str(source["register"])
            if source["kind"] == "register"
            else None
        )
        if divisor_register in {"eax", "edx"}:
            return {
                "status": "unresolved",
                "reason": "divide_operand_aliases_implicit_dividend",
            }
        divisor: dict[str, Any]
        if source["kind"] == "register":
            divisor = {
                "kind": "register",
                "location": {"register": divisor_register, "lsb": 0},
            }
        elif source["kind"] == "memory":
            divisor = {
                "kind": "memory",
                "address": source["address"],
            }
        else:
            raise StageAInputError(f"{context}.source cannot be immediate")
        return _resolved(
            effects=[
                {
                    "class": "divide",
                    "id": "divide-core",
                    "width_bits": 32,
                    "signed": constructor == "divideSigned",
                    "dividend_high": {"register": "edx", "lsb": 0},
                    "dividend_low": {"register": "eax", "lsb": 0},
                    "divisor": divisor,
                }
            ],
            eflags=0,
        )
    if constructor in {"callIndirect", "jumpIndirect"}:
        row = _exact_fields(
            instruction, {"constructor", "target"}, context
        )
        target_operand = _operand32(row.get("target"), f"{context}.target")
        if target_operand["kind"] == "register":
            target = {
                "kind": "register",
                "location": {
                    "register": target_operand["register"],
                    "lsb": 0,
                },
            }
        elif target_operand["kind"] == "memory":
            target = {
                "kind": "memory",
                "address": target_operand["address"],
            }
        else:
            raise StageAInputError(f"{context}.target cannot be immediate")
        effects = [
            _branch_effect(
                control=(
                    "indirect_call"
                    if constructor == "callIndirect"
                    else "indirect_branch"
                ),
                target_eip=None,
                target=target,
            )
        ]
        if constructor == "callIndirect":
            effects.append(
                _memory_effect(
                    address={
                        "base": "esp",
                        "index": None,
                        "scale": 1,
                        "displacement": -4,
                        "segment": "flat",
                    },
                    access="write",
                    width_bits=32,
                    role="stack",
                )
            )
            register = _register_effect(reads=[], writes=["esp"])
            if register is not None:
                effects.append(register)
        return _resolved(effects=effects, eflags=_ARITHMETIC_FLAGS)
    if constructor in {"pushFlags", "popFlags", "clearDirection"}:
        _exact_fields(instruction, {"constructor"}, context)
        effects: list[dict[str, Any]] = [
            {
                "class": "state",
                "id": "state-eflags",
                "state": "eflags",
                "access": (
                    "read"
                    if constructor == "pushFlags"
                    else "write"
                ),
            }
        ]
        if constructor != "clearDirection":
            effects.append(
                _memory_effect(
                    address={
                        "base": "esp",
                        "index": None,
                        "scale": 1,
                        "displacement": (
                            -4 if constructor == "pushFlags" else 0
                        ),
                        "segment": "flat",
                    },
                    access=(
                        "write" if constructor == "pushFlags" else "read"
                    ),
                    width_bits=32,
                    role="stack",
                )
            )
            register = _register_effect(reads=[], writes=["esp"])
            if register is not None:
                effects.append(register)
        return _resolved(
            effects=effects,
            eflags=(
                0
                if constructor == "pushFlags"
                else 0x400 if constructor == "clearDirection" else 0x003F7FD7
            ),
        )
    if constructor in {"pushAll", "popAll"}:
        _exact_fields(instruction, {"constructor"}, context)
        effects = [
            _memory_effect(
                address={
                    "base": "esp",
                    "index": None,
                    "scale": 1,
                    "displacement": -32 if constructor == "pushAll" else 0,
                    "segment": "flat",
                },
                access="write" if constructor == "pushAll" else "read",
                width_bits=256,
                role="stack",
            )
        ]
        register = _register_effect_around_memory(
            reads=list(_GPRS) if constructor == "pushAll" else [],
            writes=(
                ["esp"]
                if constructor == "pushAll"
                else list(_GPRS)
            ),
            effects=effects,
        )
        if register is not None:
            effects.append(register)
        return _resolved(effects=effects, eflags=_ARITHMETIC_FLAGS)
    if constructor == "unsupported":
        _exact_fields(instruction, {"constructor", "repr"}, context)
        _string(instruction.get("repr"), f"{context}.repr")
        return {
            "status": "unresolved",
            "reason": "instruction_family_not_soundly_derivable",
        }
    raise StageAInputError(
        f"{context}.constructor was not emitted by the reviewed Lean exporter"
    )


def _qualified_representatives(
    encodings: Sequence[Mapping[str, Any]],
) -> list[Mapping[str, Any]]:
    rows_by_form: dict[str, list[Mapping[str, Any]]] = {}
    for row in encodings:
        rows_by_form.setdefault(str(row["form_id"]), []).append(row)
    representatives: list[Mapping[str, Any]] = []
    for form_id in sorted(rows_by_form):
        rows = rows_by_form[form_id]
        if any(row["enrichment"]["status"] != "resolved" for row in rows):
            continue
        representative = [row for row in rows if row["representative"]]
        if len(representative) != 1:
            raise StageAInputError(
                f"side-ISA enrichment form {form_id} does not have one representative"
            )
        representatives.append(representative[0])
    return representatives


def enrich_side_isa_catalog(
    proposal: Any,
    decoded_metadata: Mapping[str, Mapping[str, Any]],
    *,
    lean_binding: Mapping[str, str],
) -> dict[str, Any]:
    """Build one deterministic enrichment artifact from validated Lean rows."""

    parsed = _parse_proposal(proposal)
    expected_ids = [row["encoding_id"] for row in parsed["encodings"]]
    if list(decoded_metadata) != expected_ids:
        raise StageAInputError(
            "decoded metadata must cover proposal encodings in canonical order"
        )
    binding = _exact_fields(
        lean_binding,
        {"classifier_sha256", "metadata_exporter_sha256", "lean_version"},
        "Lean metadata binding",
    )
    if binding.get("classifier_sha256") != parsed["classifier_sha256"]:
        raise StageAInputError(
            "Lean metadata binding classifier does not match proposal"
        )
    _sha256(
        binding.get("metadata_exporter_sha256"),
        "Lean metadata binding metadata_exporter_sha256",
    )
    _string(binding.get("lean_version"), "Lean metadata binding lean_version")

    enriched_rows: list[dict[str, Any]] = []
    reason_counts: Counter[str] = Counter()
    for encoding in parsed["encodings"]:
        enrichment = _derive_enrichment(
            encoding,
            decoded_metadata[encoding["encoding_id"]],
        )
        if enrichment["status"] == "unresolved":
            reason_counts[str(enrichment["reason"])] += 1
        enriched_rows.append(
            {
                "format": SIDE_ISA_ENCODING_ENRICHMENT_FORMAT,
                "encoding_id": encoding["encoding_id"],
                "form_id": encoding["form_id"],
                "semantic_form": encoding["semantic_form"],
                "instruction_bytes": list(encoding["instruction_bytes"]),
                "instruction_hex": encoding["instruction_hex"],
                "source_occurrence_ids": list(encoding["source_occurrence_ids"]),
                "representative": encoding["representative"],
                "enrichment": enrichment,
            }
        )
    resolved = sum(
        row["enrichment"]["status"] == "resolved" for row in enriched_rows
    )
    unresolved = len(enriched_rows) - resolved
    qualified_representatives = _qualified_representatives(enriched_rows)
    qualified_forms = len(qualified_representatives)
    proposal_sha256 = _canonical_sha256(proposal)
    result = {
        "format": SIDE_ISA_CATALOG_ENRICHMENT_FORMAT,
        "status": "complete" if unresolved == 0 else "incomplete_unresolved_encodings",
        "profile": parsed["profile"],
        "model": parsed["model"],
        "classifier_sha256": parsed["classifier_sha256"],
        "proposal_sha256": proposal_sha256,
        "source": {
            "enricher": _ENRICHER_VERSION,
            "lean_version": binding["lean_version"],
            "metadata_exporter_sha256": binding["metadata_exporter_sha256"],
        },
        "forms": [dict(row) for row in parsed["forms"]],
        "encodings": enriched_rows,
        "counts": {
            "forms": len(parsed["forms"]),
            "encodings": len(enriched_rows),
            "resolved": resolved,
            "unresolved": unresolved,
            "qualified_forms": qualified_forms,
            "unresolved_forms": len(parsed["forms"]) - qualified_forms,
            "corpus_entries": qualified_forms,
        },
        "unresolved_reasons": {
            reason: reason_counts[reason] for reason in sorted(reason_counts)
        },
        "trust": {
            "role": "untrusted_lean_derived_isa_catalog_enrichment",
            "proof_authority": False,
            "closes_stage_a_proof": False,
            "corpus_generation_rule": (
                "one_representative_per_fully_resolved_form"
            ),
        },
    }
    # Ensure every resolved row is consumable by the existing typed catalog.
    if qualified_forms:
        resolved_isa_catalog(result)
    return result


def enrich_side_isa_catalog_with_lean(
    proposal: Any,
    *,
    timeout_seconds: int = 300,
) -> dict[str, Any]:
    parsed = _parse_proposal(proposal)
    metadata, binding = extract_lean_decoded_metadata(
        sorted(parsed["encodings"], key=lambda row: row["encoding_id"]),
        timeout_seconds=timeout_seconds,
    )
    # The proposal is ordered by form/bytes; the Lean exporter requires stable
    # encoding-ID order so output is independent of proposal form grouping.
    metadata_by_proposal_order = {
        row["encoding_id"]: metadata[row["encoding_id"]]
        for row in parsed["encodings"]
    }
    return enrich_side_isa_catalog(
        proposal,
        metadata_by_proposal_order,
        lean_binding=binding,
    )


def _parse_enrichment(value: Any) -> Mapping[str, Any]:
    payload = _exact_fields(
        value,
        {
            "format",
            "status",
            "profile",
            "model",
            "classifier_sha256",
            "proposal_sha256",
            "source",
            "forms",
            "encodings",
            "counts",
            "unresolved_reasons",
            "trust",
        },
        "side-ISA catalog enrichment",
    )
    if payload.get("format") != SIDE_ISA_CATALOG_ENRICHMENT_FORMAT:
        raise StageAInputError("unsupported side-ISA catalog enrichment format")
    if payload.get("status") not in {
        "complete",
        "incomplete_unresolved_encodings",
    }:
        raise StageAInputError("side-ISA catalog enrichment status is invalid")
    if payload.get("profile") != ISA_PROFILE_ID:
        raise StageAInputError("side-ISA catalog enrichment profile is invalid")
    if payload.get("model") != STAGE_A_RELATIONAL_MODEL_ID:
        raise StageAInputError("side-ISA catalog enrichment model is invalid")
    classifier_sha256 = _sha256(
        payload.get("classifier_sha256"),
        "side-ISA catalog enrichment classifier_sha256",
    )
    if classifier_sha256 != lean_semantic_form_classifier_sha256():
        raise StageAInputError(
            "side-ISA catalog enrichment uses a stale Lean semantic classifier"
        )
    _sha256(
        payload.get("proposal_sha256"),
        "side-ISA catalog enrichment proposal_sha256",
    )
    source = _exact_fields(
        payload.get("source"),
        {"enricher", "lean_version", "metadata_exporter_sha256"},
        "side-ISA catalog enrichment source",
    )
    if source.get("enricher") != _ENRICHER_VERSION:
        raise StageAInputError("side-ISA catalog enrichment enricher is invalid")
    _string(source.get("lean_version"), "side-ISA catalog enrichment lean_version")
    _sha256(
        source.get("metadata_exporter_sha256"),
        "side-ISA catalog enrichment metadata_exporter_sha256",
    )
    forms = _objects(payload.get("forms"), "side-ISA catalog enrichment forms")
    form_ids: list[str] = []
    forms_by_id: dict[str, Mapping[str, Any]] = {}
    for index, row in enumerate(forms):
        row = _exact_fields(
            row,
            {
                "form_id",
                "semantic_form",
                "representative_encoding_id",
                "encoding_ids",
            },
            f"side-ISA catalog enrichment forms[{index}]",
        )
        context = f"side-ISA catalog enrichment forms[{index}]"
        form_id = _string(
            row.get("form_id"),
            f"{context}.form_id",
        )
        semantic_form = _string(
            row.get("semantic_form"),
            f"{context}.semantic_form",
        )
        if form_id != lean_semantic_form_id(
            semantic_form,
            classifier_sha256=classifier_sha256,
        ):
            raise StageAInputError(f"{context}.form_id is not canonical")
        _string(
            row.get("representative_encoding_id"),
            f"{context}.representative_encoding_id",
        )
        _strings(
            row.get("encoding_ids"),
            f"{context}.encoding_ids",
        )
        form_ids.append(form_id)
        forms_by_id[form_id] = row
    if form_ids != sorted(set(form_ids)):
        raise StageAInputError(
            "side-ISA catalog enrichment forms are not canonically ordered"
        )
    encodings = _objects(
        payload.get("encodings"), "side-ISA catalog enrichment encodings"
    )
    encoding_ids: list[str] = []
    resolved_entries: list[dict[str, Any]] = []
    actual_reasons: Counter[str] = Counter()
    for index, row in enumerate(encodings):
        context = f"side-ISA catalog enrichment encodings[{index}]"
        row = _exact_fields(
            row,
            {
                "format",
                "encoding_id",
                "form_id",
                "semantic_form",
                "instruction_bytes",
                "instruction_hex",
                "source_occurrence_ids",
                "representative",
                "enrichment",
            },
            context,
        )
        if row.get("format") != SIDE_ISA_ENCODING_ENRICHMENT_FORMAT:
            raise StageAInputError(f"{context}.format is invalid")
        encoding_id = _string(row.get("encoding_id"), f"{context}.encoding_id")
        encoding_ids.append(encoding_id)
        form_id = _string(row.get("form_id"), f"{context}.form_id")
        semantic_form = _string(
            row.get("semantic_form"), f"{context}.semantic_form"
        )
        if form_id not in forms_by_id:
            raise StageAInputError(f"{context} names an unknown form")
        raw_bytes = row.get("instruction_bytes")
        if not isinstance(raw_bytes, list):
            raise StageAInputError(f"{context}.instruction_bytes must be a list")
        instruction_bytes = [
            _uint(byte, 8, f"{context}.instruction_bytes[{offset}]")
            for offset, byte in enumerate(raw_bytes)
        ]
        if not 1 <= len(instruction_bytes) <= 15:
            raise StageAInputError(
                f"{context}.instruction_bytes must contain 1 to 15 bytes"
            )
        instruction_hex = _string(
            row.get("instruction_hex"), f"{context}.instruction_hex"
        )
        if bytes(instruction_bytes).hex() != instruction_hex:
            raise StageAInputError(
                f"{context} instruction bytes and hexadecimal encoding disagree"
            )
        if encoding_id != _encoding_id(form_id, instruction_hex):
            raise StageAInputError(f"{context}.encoding_id is not canonical")
        _strings(row.get("source_occurrence_ids"), f"{context}.source_occurrence_ids")
        if not isinstance(row.get("representative"), bool):
            raise StageAInputError(f"{context}.representative must be a boolean")
        enrichment = row.get("enrichment")
        if not isinstance(enrichment, Mapping):
            raise StageAInputError(f"{context}.enrichment must be an object")
        status = enrichment.get("status")
        if status == "resolved":
            enrichment = _exact_fields(
                enrichment,
                {
                    "status",
                    "required_features",
                    "effects",
                    "defined_outputs",
                },
                f"{context}.enrichment",
            )
            resolved_entries.append(
                {
                    "format": ISA_FORM_CATALOG_ENTRY_FORMAT,
                    "form_id": encoding_id,
                    "encoding_id": encoding_id,
                    "instruction_bytes": instruction_bytes,
                    "required_features": enrichment["required_features"],
                    "effects": enrichment["effects"],
                    "defined_outputs": enrichment["defined_outputs"],
                }
            )
        elif status == "unresolved":
            enrichment = _exact_fields(
                enrichment,
                {"status", "reason"},
                f"{context}.enrichment",
            )
            reason = _string(
                enrichment.get("reason"), f"{context}.enrichment.reason"
            )
            actual_reasons[reason] += 1
        else:
            raise StageAInputError(f"{context}.enrichment.status is invalid")
        if semantic_form != forms_by_id[form_id]["semantic_form"]:
            raise StageAInputError(f"{context} semantic form disagrees with its form")
    if [
        (row["form_id"], row["instruction_hex"]) for row in encodings
    ] != sorted(
        (row["form_id"], row["instruction_hex"]) for row in encodings
    ) or len(encoding_ids) != len(set(encoding_ids)):
        raise StageAInputError(
            "side-ISA catalog enrichment encodings are not canonically ordered"
        )
    for form_id, form in forms_by_id.items():
        actual_ids = sorted(
            row["encoding_id"] for row in encodings if row["form_id"] == form_id
        )
        if list(form["encoding_ids"]) != actual_ids:
            raise StageAInputError(
                f"side-ISA catalog enrichment form {form_id} encoding inventory "
                "does not match the encoding rows"
            )
        representatives = [
            row["encoding_id"]
            for row in encodings
            if row["form_id"] == form_id and row["representative"]
        ]
        if representatives != [form["representative_encoding_id"]]:
            raise StageAInputError(
                f"side-ISA catalog enrichment form {form_id} has an invalid "
                "representative encoding"
            )
    reasons = payload.get("unresolved_reasons")
    if not isinstance(reasons, Mapping) or dict(reasons) != {
        reason: actual_reasons[reason] for reason in sorted(actual_reasons)
    }:
        raise StageAInputError(
            "side-ISA catalog enrichment unresolved reason summary is inconsistent"
        )
    counts = _exact_fields(
        payload.get("counts"),
        {
            "forms",
            "encodings",
            "resolved",
            "unresolved",
            "qualified_forms",
            "unresolved_forms",
            "corpus_entries",
        },
        "side-ISA catalog enrichment counts",
    )
    qualified_representatives = _qualified_representatives(encodings)
    qualified_forms = len(qualified_representatives)
    expected_counts = {
        "forms": len(forms),
        "encodings": len(encodings),
        "resolved": len(resolved_entries),
        "unresolved": len(encodings) - len(resolved_entries),
        "qualified_forms": qualified_forms,
        "unresolved_forms": len(forms) - qualified_forms,
        "corpus_entries": qualified_forms,
    }
    if dict(counts) != expected_counts:
        raise StageAInputError(
            "side-ISA catalog enrichment counts are inconsistent"
        )
    expected_status = (
        "complete"
        if expected_counts["unresolved"] == 0
        else "incomplete_unresolved_encodings"
    )
    if payload.get("status") != expected_status:
        raise StageAInputError(
            "side-ISA catalog enrichment aggregate status is inconsistent"
        )
    trust = _exact_fields(
        payload.get("trust"),
        {
            "role",
            "proof_authority",
            "closes_stage_a_proof",
            "corpus_generation_rule",
        },
        "side-ISA catalog enrichment trust",
    )
    if (
        trust.get("role") != "untrusted_lean_derived_isa_catalog_enrichment"
        or trust.get("proof_authority") is not False
        or trust.get("closes_stage_a_proof") is not False
        or trust.get("corpus_generation_rule")
        != "one_representative_per_fully_resolved_form"
    ):
        raise StageAInputError("side-ISA catalog enrichment trust marker is invalid")
    return payload


def resolved_isa_catalog(value: Any) -> ISAFormCatalog:
    """Project one representative from each fully resolved semantic form."""

    payload = _parse_enrichment(value)
    entries: list[dict[str, Any]] = []
    for row in sorted(
        _qualified_representatives(payload["encodings"]),
        key=lambda item: item["encoding_id"],
    ):
        enrichment = row["enrichment"]
        entries.append(
            {
                "format": ISA_FORM_CATALOG_ENTRY_FORMAT,
                # Existing catalogs require unique form IDs. Encoding IDs are
                # already canonical exact-(Lean-form, bytes) identities.
                "form_id": row["encoding_id"],
                "encoding_id": row["encoding_id"],
                "instruction_bytes": list(row["instruction_bytes"]),
                "required_features": list(enrichment["required_features"]),
                "effects": list(enrichment["effects"]),
                "defined_outputs": dict(enrichment["defined_outputs"]),
            }
        )
    if not entries:
        raise StageAInputError(
            "side-ISA catalog enrichment has no qualified representative "
            "corpus entries"
        )
    catalog_payload = {
        "format": ISA_FORM_CATALOG_FORMAT,
        "profile": ISA_PROFILE_ID,
        "source": {
            "extractor": _ENRICHER_VERSION,
            "version": "1",
            "input_sha256": payload["proposal_sha256"],
        },
        "entries": entries,
    }
    try:
        return parse_isa_form_catalog(catalog_payload)
    except ISAConformanceError as exc:
        raise StageAInputError(
            f"resolved side-ISA enrichment is not corpus-compatible: {exc}"
        ) from exc


def write_enriched_side_isa_catalog(
    *,
    proposal: Path,
    out: Path,
    timeout_seconds: int = 300,
) -> dict[str, Any]:
    try:
        payload = json.loads(Path(proposal).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageAInputError(
            f"cannot read side-ISA catalog proposal {proposal}: {exc}"
        ) from exc
    enriched = enrich_side_isa_catalog_with_lean(
        payload,
        timeout_seconds=timeout_seconds,
    )
    write_json(Path(out), enriched)
    return {
        "format": SIDE_ISA_CATALOG_ENRICHMENT_RESULT_FORMAT,
        "status": "generated",
        "enrichment_status": enriched["status"],
        "out": str(out),
        "sha256": sha256_file(Path(out)),
        "counts": enriched["counts"],
        "unresolved_reasons": enriched["unresolved_reasons"],
        "proof_authority": False,
        "closes_stage_a_proof": False,
    }


__all__ = [
    "SIDE_ISA_CATALOG_ENRICHMENT_FORMAT",
    "SIDE_ISA_CATALOG_ENRICHMENT_RESULT_FORMAT",
    "SIDE_ISA_ENCODING_ENRICHMENT_FORMAT",
    "enrich_side_isa_catalog",
    "enrich_side_isa_catalog_with_lean",
    "extract_lean_decoded_metadata",
    "resolved_isa_catalog",
    "write_enriched_side_isa_catalog",
]

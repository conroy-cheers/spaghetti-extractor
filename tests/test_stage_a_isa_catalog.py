from __future__ import annotations

import copy
from unittest import mock
import unittest

from spaghetti_extractor.isa_catalog import (
    DispositionReason,
    EffectClass,
    ISAFormCatalog,
    ProfileDisposition,
    XEDInstructionCatalog,
    isa_form_catalog_sha256,
    parse_isa_catalog,
    parse_isa_form_catalog,
    parse_xed_instruction_catalog,
    serialize_isa_form_catalog,
    serialize_xed_instruction_catalog,
)
from spaghetti_extractor.isa_conformance import ISAConformanceError


GPRS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")


def _x87_masks() -> dict:
    return {
        "control_word": 0xFFFF,
        "status_word": 0xFFFF,
        "tag_word": 0xFFFF,
        "last_opcode": 0x7FF,
        "instruction_pointer": 0xFFFFFFFF,
        "data_pointer": 0xFFFFFFFF,
        "registers": [[0xFF] * 10 for _ in range(8)],
    }


def defined_outputs() -> dict:
    return {
        "gprs": {register: 0xFFFFFFFF for register in GPRS},
        "eip": 0xFFFFFFFF,
        "eflags": 0x8D5,
        "fs": {"selector": 0xFFFF, "base": 0xFFFFFFFF},
        "x87": _x87_masks(),
        "memory": [],
    }


def entry(
    form_id: str,
    effect: dict,
    *,
    instruction: list[int] | None = None,
    features: list[str] | None = None,
) -> dict:
    return {
        "format": "pe32-i686-form-v1",
        "form_id": form_id,
        "encoding_id": "encoding-" + form_id,
        "instruction_bytes": instruction or [0x90],
        "required_features": features or [],
        "effects": [effect],
        "defined_outputs": defined_outputs(),
    }


def catalog_payload() -> dict:
    return {
        "format": "stage-a-isa-form-catalog-v1",
        "profile": "pe32-i686-v1",
        "source": {
            "extractor": "fixture-metadata",
            "version": "1",
            "input_sha256": "a" * 64,
        },
        "entries": [
            entry(
                "form-register",
                {
                    "class": "register",
                    "id": "effect-register",
                    "width_bits": 32,
                    "reads": ["eax"],
                    "writes": ["eax"],
                },
            )
        ],
    }


def xed_operand(**changes) -> dict:
    result = {
        "name": "REG0",
        "visibility": "EXPLICIT",
        "action": "RW",
        "width": "D",
        "xtype": "INT",
        "type": "NT_LOOKUP_FN",
        "nonterminal": "GPRV_R",
        "register": "",
        "immediate": None,
    }
    result.update(changes)
    return result


def xed_template(table_index: int, **changes) -> dict:
    result = {
        "table_index": table_index,
        "iform": "OPAQUE_FORM_A",
        "iclass": "OPAQUE_CLASS_A",
        "category": "BINARY",
        "extension": "BASE",
        "isa_set": "I86",
        "cpl": 3,
        "exception": "INVALID",
        "flag_info_index": 1,
        "flag_complex": False,
        "attributes": [],
        "operands": [xed_operand()],
    }
    result.update(changes)
    return result


def xed_payload(*templates: dict) -> dict:
    return {
        "format": "spaghetti-extractor-xed-inst-catalog-v1",
        "generator": {"name": "xed-isa-catalog", "xed_version": "2025.06.08"},
        "profile": {
            "id": "pe32-i686-v1",
            "chip": "PENTIUMPRO",
            "machine_mode": "LEGACY_32",
            "stack_address_width": 32,
            "privilege": "ring3",
        },
        "templates": list(templates or (xed_template(4),)),
    }


class StageAISAFormCatalogTests(unittest.TestCase):
    def test_enriched_catalog_round_trips_with_deterministic_hash(self):
        payload = catalog_payload()
        parsed = parse_isa_form_catalog(payload)

        self.assertIsInstance(parsed, ISAFormCatalog)
        self.assertEqual(serialize_isa_form_catalog(parsed), payload)
        self.assertEqual(parsed.to_payload(), payload)
        self.assertEqual(
            isa_form_catalog_sha256(parsed),
            isa_form_catalog_sha256(parse_isa_form_catalog(copy.deepcopy(payload))),
        )
        reordered = {
            "entries": payload["entries"],
            "source": payload["source"],
            "profile": payload["profile"],
            "format": payload["format"],
        }
        self.assertEqual(
            isa_form_catalog_sha256(parsed),
            isa_form_catalog_sha256(parse_isa_form_catalog(reordered)),
        )

    def test_effect_union_is_strict_and_unknown_classes_fail_closed(self):
        valid_effects = {
            "register": {
                "class": "register",
                "id": "e",
                "width_bits": 32,
                "reads": ["eax"],
                "writes": [],
            },
            "memory": {
                "class": "memory",
                "id": "e",
                "width_bits": 16,
                "access": "read_write",
                "address": {
                    "base": "ebx",
                    "index": "ecx",
                    "scale": 2,
                    "displacement": -4,
                    "segment": "flat",
                },
            },
            "branch": {
                "class": "branch",
                "id": "e",
                "outcomes": [
                    {
                        "scenario": "not_taken",
                        "eflags_mask": 0x40,
                        "eflags_value": 0,
                        "control": "fallthrough",
                        "target_eip": None,
                    },
                    {
                        "scenario": "taken",
                        "eflags_mask": 0x40,
                        "eflags_value": 0x40,
                        "control": "direct_branch",
                        "target_eip": 0x401100,
                    },
                ],
            },
            "divide": {
                "class": "divide",
                "id": "e",
                "width_bits": 32,
                "signed": False,
                "dividend_high": "edx",
                "dividend_low": "eax",
                "divisor": "ecx",
            },
            "x87": {
                "class": "x87",
                "id": "e",
                "stack_inputs": 2,
                "stack_outputs": 1,
            },
        }
        for effect_class, effect in valid_effects.items():
            with self.subTest(effect_class=effect_class):
                payload = catalog_payload()
                payload["entries"][0] = entry("form-register", effect)
                parsed = parse_isa_form_catalog(payload)
                self.assertEqual(
                    parsed.entries[0].effects[0].effect_class,
                    EffectClass(effect_class),
                )

        unsupported = catalog_payload()
        unsupported["entries"][0]["effects"][0]["class"] = "system_magic"
        with self.assertRaisesRegex(ISAConformanceError, "class is unsupported"):
            parse_isa_form_catalog(unsupported)

    def test_malformed_catalog_fields_order_and_ranges_are_rejected(self):
        unknown = catalog_payload()
        unknown["surprise"] = True
        unordered = catalog_payload()
        unordered["entries"] = [
            entry(
                "form-z",
                {
                    "class": "register",
                    "id": "e",
                    "width_bits": 32,
                    "reads": ["eax"],
                    "writes": [],
                },
            ),
            entry(
                "form-a",
                {
                    "class": "register",
                    "id": "e",
                    "width_bits": 32,
                    "reads": ["eax"],
                    "writes": [],
                },
            ),
        ]
        bad_width = catalog_payload()
        bad_width["entries"][0]["effects"][0]["width_bits"] = 64
        memory_masks = catalog_payload()
        memory_masks["entries"][0]["defined_outputs"]["memory"] = [
            {"address": 0x600000, "mask": [0xFF]}
        ]

        for malformed in (unknown, unordered, bad_width, memory_masks):
            with self.subTest(malformed=malformed):
                with self.assertRaises(ISAConformanceError):
                    parse_isa_form_catalog(malformed)


class StageAXEDInstructionCatalogTests(unittest.TestCase):
    def test_real_emitter_shape_is_accepted_and_semantic_ids_ignore_table_index(self):
        first = xed_template(4)
        alias = xed_template(91)
        parsed = parse_xed_instruction_catalog(xed_payload(first, alias))

        self.assertIsInstance(parsed, XEDInstructionCatalog)
        self.assertEqual(len(parsed.templates), 1)
        self.assertEqual(parsed.templates[0].table_indices, (4, 91))
        self.assertEqual(
            parsed.templates[0].form_id,
            parse_xed_instruction_catalog(xed_payload(xed_template(900))).templates[
                0
            ].form_id,
        )
        self.assertEqual(
            serialize_xed_instruction_catalog(parsed), xed_payload(first, alias)
        )
        self.assertIsInstance(parse_isa_catalog(xed_payload(first)), XEDInstructionCatalog)

    def test_same_hash_with_conflicting_semantics_is_rejected(self):
        payload = xed_payload(
            xed_template(1),
            xed_template(2, category="LOGICAL"),
        )
        with mock.patch(
            "spaghetti_extractor.isa_catalog.xed_template_form_id_from_fields",
            return_value="xed-" + "0" * 64,
        ):
            with self.assertRaisesRegex(
                ISAConformanceError, "conflicting fields"
            ):
                parse_xed_instruction_catalog(payload)

    def test_profile_disposition_is_generic_and_excluded_forms_remain_visible(self):
        rows = [
            xed_template(1),
            xed_template(2, iform="B", iclass="B", category="SYSCALL"),
            xed_template(3, iform="C", iclass="C", category="SYSTEM"),
            xed_template(
                4,
                iform="D",
                iclass="D",
                attributes=["PRIVILEGED"],
            ),
            xed_template(
                5,
                iform="E",
                iclass="E",
                operands=[xed_operand(register="CR0", nonterminal="")],
            ),
            xed_template(
                6,
                iform="F",
                iclass="F",
                category="X87_ALU",
                operands=[xed_operand(xtype="X87")],
            ),
            xed_template(
                7,
                iform="G",
                iclass="G",
                flag_complex=True,
            ),
            xed_template(
                8,
                iform="H",
                iclass="H",
                category="IOSTRINGOP",
            ),
            xed_template(
                9,
                iform="I",
                iclass="I",
                category="FLAGOP",
            ),
        ]
        parsed = parse_xed_instruction_catalog(xed_payload(*rows))
        by_index = {row.table_index: row for row in parsed.templates}

        self.assertEqual(by_index[1].disposition, ProfileDisposition.CORE)
        self.assertEqual(
            by_index[2].disposition, ProfileDisposition.EXTERNAL_PLATFORM
        )
        self.assertEqual(
            by_index[3].disposition, ProfileDisposition.EXCLUDED_UNSUPPORTED
        )
        self.assertEqual(
            by_index[4].disposition_reasons,
            (DispositionReason.PRIVILEGED_ATTRIBUTE,),
        )
        self.assertEqual(
            by_index[5].disposition_reasons,
            (DispositionReason.PRIVILEGED_OPERAND_CLASS,),
        )
        self.assertEqual(
            by_index[6].disposition, ProfileDisposition.SEPARATELY_QUALIFIED
        )
        self.assertEqual(
            by_index[7].disposition_reasons,
            (DispositionReason.COMPLEX_FLAG_STATE,),
        )
        self.assertEqual(
            by_index[8].disposition, ProfileDisposition.EXCLUDED_UNSUPPORTED
        )
        self.assertEqual(
            by_index[9].disposition, ProfileDisposition.SEPARATELY_QUALIFIED
        )
        self.assertEqual(
            by_index[9].disposition_reasons,
            (DispositionReason.AMBIGUOUS_SPECIAL_STATE_CATEGORY,),
        )
        self.assertEqual(len(parsed.templates), len(rows))

    def test_raw_xed_schema_and_profile_fail_closed(self):
        unknown = xed_payload(xed_template(1))
        unknown["templates"][0]["surprise"] = True
        duplicate_index = xed_payload(xed_template(1), xed_template(1, iform="B"))
        wrong_profile = xed_payload(xed_template(1))
        wrong_profile["profile"]["chip"] = "HASWELL"

        for malformed in (unknown, duplicate_index, wrong_profile):
            with self.subTest(malformed=malformed):
                with self.assertRaises(ISAConformanceError):
                    parse_xed_instruction_catalog(malformed)


if __name__ == "__main__":
    unittest.main()

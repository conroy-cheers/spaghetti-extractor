from __future__ import annotations

from ._support import *

class StaticPE32JumpTableTests(unittest.TestCase):
    def test_recovers_guarded_36_entry_inventory_deterministically(self) -> None:
        target_rvas = [0x1100 + (index % 6) * 0x10 for index in range(36)]
        kwargs = {
            "target_expression": _table_expression(),
            "predecessor_evidence": [_guarded_predecessor(36)],
            "image_base": IMAGE_BASE,
            "sections": _sections(),
            "read_rva": _reader(_table_bytes(target_rvas)),
            "valid_target_rvas": set(target_rvas),
        }

        first = recover_static_pe32_jump_table_inventory(**kwargs)
        second = recover_static_pe32_jump_table_inventory(**kwargs)

        self.assertEqual(first, second)
        self.assertEqual(
            json.dumps(first, sort_keys=True, separators=(",", ":")),
            json.dumps(second, sort_keys=True, separators=(",", ":")),
        )
        self.assertEqual(first["status"], "recovered")
        self.assertEqual(first["closure"], "checked_finite_target_inventory")
        self.assertEqual(first["index"]["upper_exclusive"], 36)
        self.assertEqual(
            first["index"]["bound_evidence"],
            [
                {
                    "source_unit_id": "guard",
                    "upper_exclusive": 36,
                    "sources": ["guard", "instructions"],
                }
            ],
        )
        self.assertEqual(first["table"]["entry_count"], 36)
        self.assertEqual(len(first["entries"]), 36)
        self.assertEqual(first["target_rvas"], sorted(set(target_rvas)))

    def test_recovers_machine_ir_add32_mul32_and_masked_byte_index(self) -> None:
        target_rvas = [0x1100 + (index % 3) * 0x10 for index in range(36)]
        index = {
            "op": "and32",
            "args": [
                {"op": "const", "value": 255, "width": 32},
                {"op": "reg", "name": "eax", "width": 32},
            ],
        }
        expression = {
            "op": "load",
            "width": 4,
            "address": {
                "op": "add32",
                "args": [
                    {"op": "const", "value": IMAGE_BASE + TABLE_RVA, "width": 32},
                    {
                        "op": "mul32",
                        "args": [index, {"op": "const", "value": 4, "width": 32}],
                    },
                ],
            },
        }
        predecessor = {
            "source_unit_id": "guard",
            "edge_kind": "fallthrough",
            "instructions": [
                {
                    "mnemonic": "cmp",
                    "operands": [
                        {"kind": "register", "name": "al", "width_bits": 8},
                        {"kind": "immediate", "value": 35, "width_bits": 8},
                    ],
                },
                {"mnemonic": "ja", "operands": []},
            ],
        }

        result = recover_static_pe32_jump_table_inventory(
            target_expression=expression,
            predecessor_evidence=[predecessor],
            image_base=IMAGE_BASE,
            sections=_sections(),
            read_rva=_reader(_table_bytes(target_rvas)),
            valid_target_rvas=set(target_rvas),
        )

        self.assertEqual(result["status"], "recovered")
        self.assertEqual(result["index"]["upper_exclusive"], 36)
        self.assertEqual(result["table"]["expression_form"], "multiply_4")
        self.assertEqual(
            result["entries"][0]["bytes_le"],
            list((IMAGE_BASE + target_rvas[0]).to_bytes(4, "little")),
        )

    def test_guard_binds_exact_predecessor_register_output(self) -> None:
        target_rvas = [0x1100, 0x1110]
        selector = {"op": "reg", "name": "eax", "width": 32}
        predecessor_value = {
            "op": "load",
            "width": 1,
            "address": {
                "op": "add32",
                "args": [
                    {"op": "reg", "name": "esp", "width": 32},
                    {"op": "const", "value": 28, "width": 32},
                ],
            },
        }
        expression = {
            "op": "load",
            "width": 4,
            "address": {
                "op": "add32",
                "args": [
                    {"op": "const", "value": IMAGE_BASE + TABLE_RVA, "width": 32},
                    {
                        "op": "mul32",
                        "args": [selector, {"op": "const", "value": 4, "width": 32}],
                    },
                ],
            },
        }
        predecessor = {
            "source_unit_id": "guard",
            "edge_kind": "fallthrough",
            "guard": {
                "op": "not",
                "args": [{
                    "op": "and_bool",
                    "args": [
                        {
                            "op": "not",
                            "args": [{
                                "op": "eq",
                                "args": [
                                    {
                                        "op": "and32",
                                        "args": [
                                            {"op": "const", "value": 0xFF, "width": 32},
                                            {
                                                "op": "sub32",
                                                "args": [
                                                    {
                                                        "op": "and32",
                                                        "args": [
                                                            {"op": "const", "value": 0xFF, "width": 32},
                                                            predecessor_value,
                                                        ],
                                                    },
                                                    {"op": "const", "value": 1, "width": 32},
                                                ],
                                            },
                                        ],
                                    },
                                    {"op": "const", "value": 0, "width": 32},
                                ],
                            }],
                        },
                        {
                            "op": "not",
                            "args": [{
                                "op": "ult32",
                                "args": [
                                    {
                                        "op": "and32",
                                        "args": [
                                            {"op": "const", "value": 0xFF, "width": 32},
                                            predecessor_value,
                                        ],
                                    },
                                    {"op": "const", "value": 1, "width": 32},
                                ],
                            }],
                        },
                    ],
                }],
            },
            "register_outputs": [
                {"register": "eax", "value": predecessor_value}
            ],
            "instructions": [],
        }

        result = recover_static_pe32_jump_table_inventory(
            target_expression=expression,
            predecessor_evidence=[predecessor],
            image_base=IMAGE_BASE,
            sections=_sections(),
            read_rva=_reader(_table_bytes(target_rvas)),
            valid_target_rvas=set(target_rvas),
        )

        self.assertEqual(result["status"], "recovered")
        self.assertEqual(result["index"]["values"], [0, 1])
        self.assertEqual(result["target_rvas"], target_rvas)

    def test_recovers_immutable_byte_remapped_index(self) -> None:
        target_rvas = [0x1100, 0x1110, 0x1120]
        remap_rva = TABLE_RVA + len(target_rvas) * 4
        remap_values = bytes([2, 0, 1, 2, 1])
        image = _table_bytes(target_rvas) + remap_values
        index = {
            "op": "or32",
            "args": [
                {
                    "op": "and32",
                    "args": [
                        {"op": "const", "value": 0, "width": 32},
                        {"op": "const", "value": 0xFFFFFF00, "width": 32},
                    ],
                },
                {
                    "op": "and32",
                    "args": [
                        {
                            "op": "and32",
                            "args": [
                                {"op": "const", "value": 255, "width": 32},
                                {
                                    "op": "load",
                                    "width": 1,
                                    "address": {
                                        "op": "add32",
                                        "args": [
                                            {
                                                "op": "const",
                                                "value": IMAGE_BASE + remap_rva,
                                                "width": 32,
                                            },
                                            {"op": "reg", "name": "ecx", "width": 32},
                                        ],
                                    },
                                },
                            ],
                        },
                        {"op": "const", "value": 255, "width": 32},
                    ],
                },
            ],
        }
        expression = {
            "op": "load",
            "width": 4,
            "address": {
                "op": "add32",
                "args": [
                    {"op": "const", "value": IMAGE_BASE + TABLE_RVA, "width": 32},
                    {
                        "op": "mul32",
                        "args": [index, {"op": "const", "value": 4, "width": 32}],
                    },
                ],
            },
        }
        predecessor = {
            "source_unit_id": "guard",
            "edge_kind": "fallthrough",
            "instructions": [
                {
                    "mnemonic": "cmp",
                    "operands": [
                        {"kind": "register", "name": "ecx", "width_bits": 32},
                        {"kind": "immediate", "value": 4, "width_bits": 32},
                    ],
                },
                {"mnemonic": "ja", "operands": []},
            ],
        }

        result = recover_static_pe32_jump_table_inventory(
            target_expression=expression,
            predecessor_evidence=[predecessor],
            image_base=IMAGE_BASE,
            sections=_sections(),
            read_rva=_reader(image),
            valid_target_rvas=set(target_rvas),
        )

        self.assertEqual(result["status"], "recovered")
        self.assertEqual(result["index"]["upper_exclusive"], 3)
        self.assertEqual(result["index"]["remap"]["source_upper_exclusive"], 5)
        self.assertEqual(result["index"]["remap"]["possible_values"], [0, 1, 2])
        self.assertEqual(result["index"]["remap"]["bytes_le"], list(remap_values))
        self.assertEqual(
            result["index"]["remap"]["bytes_sha256"],
            sha256(remap_values).hexdigest(),
        )
        self.assertEqual(result["table"]["entry_count"], 3)

        writable = recover_static_pe32_jump_table_inventory(
            target_expression=expression,
            predecessor_evidence=[predecessor],
            image_base=IMAGE_BASE,
            sections=_sections(writable_table=True),
            read_rva=_reader(image),
            valid_target_rvas=set(target_rvas),
        )
        self.assertEqual(writable["status"], "incomplete")
        self.assertEqual(writable["failure"]["code"], "writable_index_remap")

    def test_recovers_wrapped_sparse_finite_index_domain(self) -> None:
        target_rvas = [0x1100, 0x1110, 0x1120, 0x1130]
        index = {"op": "reg", "name": "ecx", "width": 32}
        table_address = IMAGE_BASE + TABLE_RVA + 16
        expression = {
            "op": "load",
            "width": 4,
            "address": {
                "op": "add32",
                "args": [
                    {"op": "const", "value": table_address, "width": 32},
                    {
                        "op": "mul32",
                        "args": [index, {"op": "const", "value": 4, "width": 32}],
                    },
                ],
            },
        }
        values = [0xFFFFFFFC, 0xFFFFFFFD, 0xFFFFFFFE, 0xFFFFFFFF]
        domain = {
            "format": "spaghetti-extractor-finite-u32-expression-domain-v1",
            "status": "complete",
            "source_unit_id": "dispatch",
            "expression_sha256": sha256(
                json.dumps(index, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            "values": values,
        }

        result = recover_static_pe32_jump_table_inventory(
            target_expression=expression,
            predecessor_evidence=[],
            image_base=IMAGE_BASE,
            sections=_sections(),
            read_rva=_reader(_table_bytes(target_rvas)),
            finite_index_domain=domain,
            valid_target_rvas=target_rvas,
        )

        self.assertEqual(result["status"], "recovered")
        self.assertEqual(result["index"]["values"], values)
        self.assertIsNone(result["index"]["upper_exclusive"])
        self.assertEqual(result["table"]["rva_start"], TABLE_RVA)
        self.assertEqual(result["table"]["rva_end"], TABLE_RVA + 16)
        self.assertTrue(result["table"]["contiguous"])
        self.assertEqual(
            result["table"]["bytes_sha256"],
            sha256(_table_bytes(target_rvas)).hexdigest(),
        )
        self.assertEqual(result["target_rvas"], target_rvas)

        malformed = recover_static_pe32_jump_table_inventory(
            target_expression=expression,
            predecessor_evidence=[],
            image_base=IMAGE_BASE,
            sections=_sections(),
            read_rva=_reader(_table_bytes(target_rvas)),
            finite_index_domain={**domain, "expression_sha256": "0" * 64},
        )
        self.assertEqual(
            malformed["failure"]["code"],
            "invalid_finite_index_domain",
        )

    def test_unresolved_or_ambiguous_bounds_do_not_read_a_table(self) -> None:
        reads = []

        def reader(rva: int, size: int) -> bytes:
            reads.append((rva, size))
            return b""

        missing = recover_static_pe32_jump_table_inventory(
            target_expression=_table_expression(),
            predecessor_evidence=[],
            image_base=IMAGE_BASE,
            sections=_sections(),
            read_rva=reader,
        )
        ambiguous = recover_static_pe32_jump_table_inventory(
            target_expression=_table_expression(),
            predecessor_evidence=[
                _guarded_predecessor(36),
                {**_guarded_predecessor(35), "source_unit_id": "other-guard"},
            ],
            image_base=IMAGE_BASE,
            sections=_sections(),
            read_rva=reader,
        )

        self.assertEqual(missing["status"], "incomplete")
        self.assertEqual(missing["failure"]["code"], "missing_predecessor_evidence")
        self.assertEqual(ambiguous["failure"]["code"], "ambiguous_index_bound")
        self.assertEqual(missing["target_rvas"], [])
        self.assertEqual(ambiguous["target_rvas"], [])
        self.assertEqual(reads, [])

    def test_writable_table_and_invalid_target_fail_closed(self) -> None:
        targets = [0x1100, 0x1110]
        writable = recover_static_pe32_jump_table_inventory(
            target_expression=_table_expression(),
            predecessor_evidence=[_guarded_predecessor(2)],
            image_base=IMAGE_BASE,
            sections=_sections(writable_table=True),
            read_rva=_reader(_table_bytes(targets)),
            valid_target_rvas=targets,
        )
        invalid_target = recover_static_pe32_jump_table_inventory(
            target_expression=_table_expression(),
            predecessor_evidence=[_guarded_predecessor(2)],
            image_base=IMAGE_BASE,
            sections=_sections(),
            read_rva=_reader(
                _table_bytes([targets[0]]) + (IMAGE_BASE + TABLE_RVA).to_bytes(4, "little")
            ),
            valid_target_rvas=targets,
        )

        self.assertEqual(writable["failure"]["code"], "writable_table")
        self.assertEqual(writable["entries"], [])
        self.assertEqual(invalid_target["failure"]["code"], "invalid_table_target")
        self.assertEqual(invalid_target["entries"], [])

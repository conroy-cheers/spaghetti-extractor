from __future__ import annotations

import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.stage_b_engine_layout import (
    EngineField,
    EngineFieldKind,
    EngineFlag,
    EngineLayoutCField,
    EngineLayoutCSpec,
    EngineLayoutFeature,
    EngineLayoutFormatError,
    EngineRegister,
    STAGE_B_ENGINE_LAYOUT_HEADER_WORDS,
    STAGE_B_ENGINE_LAYOUT_MAGIC,
    STAGE_B_ENGINE_LAYOUT_RECORD_WORDS,
    STAGE_B_ENGINE_LAYOUT_VERSION,
    canonical_stage_b_machine_state_spec,
    parse_stage_b_engine_layout_payload,
    render_stage_b_engine_layout_c,
)


def _fields(
    features: EngineLayoutFeature, x87_slot_count: int = 8
) -> list[EngineField]:
    fields = [EngineField.register(register) for register in EngineRegister]
    if features & EngineLayoutFeature.SPLIT_FLAGS:
        fields.extend(EngineField.flag(flag) for flag in EngineFlag)
    if features & EngineLayoutFeature.PACKED_EFLAGS:
        fields.append(EngineField(EngineFieldKind.EFLAGS))
    fields.extend(EngineField.x87_stack(index) for index in range(x87_slot_count))
    fields.extend(EngineField.x87_empty(index) for index in range(x87_slot_count))
    fields.extend(EngineField.x87_tag(index) for index in range(x87_slot_count))
    fields.extend(
        (
            EngineField(EngineFieldKind.X87_CONTROL),
            EngineField(EngineFieldKind.X87_STATUS),
            EngineField(EngineFieldKind.X87_PENDING_EXCEPTION),
            EngineField(EngineFieldKind.X87_LAST_OPCODE),
            EngineField(EngineFieldKind.X87_INSTRUCTION_POINTER),
            EngineField(EngineFieldKind.X87_CODE_SELECTOR),
            EngineField(EngineFieldKind.X87_DATA_POINTER),
            EngineField(EngineFieldKind.X87_DATA_SELECTOR),
        )
    )
    if features & EngineLayoutFeature.FS_BASE:
        fields.append(EngineField(EngineFieldKind.FS_BASE))
    if features & EngineLayoutFeature.ORIGINAL_RVA:
        fields.append(EngineField(EngineFieldKind.ORIGINAL_RVA))
    return fields


def _payload(
    *,
    features: EngineLayoutFeature = EngineLayoutFeature.SPLIT_FLAGS,
    x87_slot_count: int = 8,
    fields: list[EngineField] | None = None,
) -> bytes:
    fields = list(fields if fields is not None else _fields(features, x87_slot_count))
    records: list[int] = []
    offset = 0
    for field in fields:
        if field.kind == EngineFieldKind.X87_STACK:
            size = 10
        elif field.kind in {
            EngineFieldKind.X87_TAG,
            EngineFieldKind.X87_PENDING_EXCEPTION,
        }:
            size = 1
        elif field.kind in {
            EngineFieldKind.X87_CONTROL,
            EngineFieldKind.X87_STATUS,
            EngineFieldKind.X87_LAST_OPCODE,
            EngineFieldKind.X87_CODE_SELECTOR,
            EngineFieldKind.X87_DATA_SELECTOR,
        }:
            size = 2
        else:
            size = 4
        records.extend((int(field.kind), field.index, offset, size))
        offset += size
    total_words = STAGE_B_ENGINE_LAYOUT_HEADER_WORDS + len(records)
    words = [
        STAGE_B_ENGINE_LAYOUT_MAGIC,
        STAGE_B_ENGINE_LAYOUT_VERSION,
        total_words,
        STAGE_B_ENGINE_LAYOUT_HEADER_WORDS,
        STAGE_B_ENGINE_LAYOUT_RECORD_WORDS,
        len(fields),
        offset,
        x87_slot_count,
        int(features),
        0,
        *records,
    ]
    return struct.pack(f"<{len(words)}I", *words)


def _mutate(payload: bytes, index: int, value: int) -> bytes:
    words = list(struct.unpack(f"<{len(payload) // 4}I", payload))
    words[index] = value
    return struct.pack(f"<{len(words)}I", *words)


class StageBEngineLayoutTests(unittest.TestCase):
    def test_render_is_deterministic_and_uses_compiler_layout_operators(self) -> None:
        spec = canonical_stage_b_machine_state_spec(
            include_fs_base=True,
            include_original_rva=True,
            member_overrides={
                EngineField(EngineFieldKind.FS_BASE): "segments.fs_base",
            },
        )
        reversed_spec = EngineLayoutCSpec(
            fields=tuple(reversed(spec.fields)),
            x87_slot_count=spec.x87_slot_count,
        )

        source = render_stage_b_engine_layout_c(spec)

        self.assertEqual(
            spec.features,
            EngineLayoutFeature.SPLIT_FLAGS
            | EngineLayoutFeature.PACKED_EFLAGS
            | EngineLayoutFeature.FS_BASE
            | EngineLayoutFeature.ORIGINAL_RVA,
        )
        self.assertEqual(source, render_stage_b_engine_layout_c(spec))
        self.assertIn("const uint32_t stage_b_engine_layout_table", source)
        self.assertIn('.rdata$SBEL', source)
        self.assertIn("offsetof(stage_b_machine_state, eax)", source)
        self.assertIn(
            "sizeof(((stage_b_machine_state *)0)->x87_stack[7].value_bytes)",
            source,
        )
        self.assertIn(
            "sizeof(((stage_b_machine_state *)0)->x87_stack[7].tag)",
            source,
        )
        self.assertIn(
            "sizeof(((stage_b_machine_state *)0)->x87_instruction_pointer)",
            source,
        )
        self.assertIn("offsetof(stage_b_machine_state, segments.fs_base)", source)
        self.assertIn("offsetof(stage_b_machine_state, original_rva)", source)
        self.assertIn("no proof or acceptance authority", source)
        self.assertEqual(
            render_stage_b_engine_layout_c(reversed_spec),
            source,
        )

    def test_schema_rejects_missing_duplicate_and_injected_members(self) -> None:
        spec = canonical_stage_b_machine_state_spec()
        missing_status = tuple(
            entry
            for entry in spec.fields
            if entry.field.kind != EngineFieldKind.X87_STATUS
        )
        with self.assertRaisesRegex(ValueError, "missing x87_status"):
            EngineLayoutCSpec(fields=missing_status)

        eax = EngineField.register(EngineRegister.EAX)
        with self.assertRaisesRegex(ValueError, "duplicate member"):
            canonical_stage_b_machine_state_spec(
                member_overrides={eax: "ebx"}
            )
        with self.assertRaisesRegex(ValueError, "invalid C member"):
            EngineLayoutCField(eax, "eax); injected()")

    def test_parser_returns_canonical_typed_layout(self) -> None:
        features = (
            EngineLayoutFeature.PACKED_EFLAGS
            | EngineLayoutFeature.FS_BASE
            | EngineLayoutFeature.ORIGINAL_RVA
        )
        layout = parse_stage_b_engine_layout_payload(
            _payload(features=features),
            expected_features=features,
            expected_x87_slot_count=8,
        )

        self.assertEqual(layout.version, STAGE_B_ENGINE_LAYOUT_VERSION)
        self.assertEqual(layout.features, features)
        self.assertEqual(layout.x87_slot_count, 8)
        self.assertEqual(
            layout.field_layout(EngineField.register(EngineRegister.EAX)).size,
            4,
        )
        self.assertEqual(
            layout.field_layout(EngineField.x87_stack(7)).size,
            10,
        )
        self.assertEqual(layout.field_layout(EngineField.x87_tag(7)).size, 1)
        self.assertEqual(
            layout.field_layout(
                EngineField(EngineFieldKind.X87_INSTRUCTION_POINTER)
            ).size,
            4,
        )
        self.assertEqual(
            set(layout.fields_by_identity),
            set(_fields(features)),
        )

    def test_parser_fails_closed_on_missing_or_unexpected_fields(self) -> None:
        features = EngineLayoutFeature.SPLIT_FLAGS
        fields = _fields(features)
        without_status = [
            field for field in fields if field.kind != EngineFieldKind.X87_STATUS
        ]
        with self.assertRaisesRegex(EngineLayoutFormatError, "missing x87_status"):
            parse_stage_b_engine_layout_payload(
                _payload(features=features, fields=without_status)
            )

        fs_base = EngineField(EngineFieldKind.FS_BASE)
        with self.assertRaisesRegex(EngineLayoutFormatError, "caller-required.*fs_base"):
            parse_stage_b_engine_layout_payload(
                _payload(features=features), required_fields=(fs_base,)
            )

        packed_with_split_flag = _fields(EngineLayoutFeature.PACKED_EFLAGS)
        packed_with_split_flag.insert(9, EngineField.flag(EngineFlag.CF))
        with self.assertRaisesRegex(EngineLayoutFormatError, "unexpected flag:cf"):
            parse_stage_b_engine_layout_payload(
                _payload(
                    features=EngineLayoutFeature.PACKED_EFLAGS,
                    fields=packed_with_split_flag,
                )
            )

    def test_parser_rejects_header_identity_bounds_overlap_and_order_errors(self) -> None:
        payload = _payload()
        first = STAGE_B_ENGINE_LAYOUT_HEADER_WORDS
        second = first + STAGE_B_ENGINE_LAYOUT_RECORD_WORDS
        state_size = struct.unpack_from("<I", payload, 6 * 4)[0]
        cases = {
            "magic": (_mutate(payload, 0, 0), "magic"),
            "version": (_mutate(payload, 1, 99), "version"),
            "reserved": (_mutate(payload, 9, 1), "reserved"),
            "unknown feature": (_mutate(payload, 8, 1 << 31), "unknown feature"),
            "duplicate": (
                _mutate(
                    _mutate(payload, second, int(EngineFieldKind.REGISTER)),
                    second + 1,
                    int(EngineRegister.EAX),
                ),
                "duplicate field",
            ),
            "zero size": (_mutate(payload, first + 3, 0), "zero size"),
            "wrong semantic width": (
                _mutate(payload, first + 3, 2),
                "has size 2, expected 4",
            ),
            "out of bounds": (
                _mutate(payload, first + 2, state_size),
                "outside the state bounds",
            ),
            "overlap": (
                _mutate(payload, second + 2, 1),
                "fields overlap",
            ),
        }
        for name, (malformed, message) in cases.items():
            with self.subTest(name=name):
                with self.assertRaisesRegex(EngineLayoutFormatError, message):
                    parse_stage_b_engine_layout_payload(malformed)

        words = list(struct.unpack(f"<{len(payload) // 4}I", payload))
        first_record = words[first : first + STAGE_B_ENGINE_LAYOUT_RECORD_WORDS]
        second_record = words[second : second + STAGE_B_ENGINE_LAYOUT_RECORD_WORDS]
        words[first : first + STAGE_B_ENGINE_LAYOUT_RECORD_WORDS] = second_record
        words[second : second + STAGE_B_ENGINE_LAYOUT_RECORD_WORDS] = first_record
        reordered = struct.pack(f"<{len(words)}I", *words)
        with self.assertRaisesRegex(EngineLayoutFormatError, "not canonical"):
            parse_stage_b_engine_layout_payload(reordered)

        with self.assertRaisesRegex(EngineLayoutFormatError, "declared size"):
            parse_stage_b_engine_layout_payload(payload[:-4])

    def test_compiler_materializes_target_abi_offsets_and_sizes(self) -> None:
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("cc is unavailable")
        features = (
            EngineLayoutFeature.PACKED_EFLAGS
            | EngineLayoutFeature.FS_BASE
            | EngineLayoutFeature.ORIGINAL_RVA
        )
        spec = canonical_stage_b_machine_state_spec(
            flag_storage="packed",
            include_fs_base=True,
            include_original_rva=True,
        )
        checks = "\n".join(
            f"  CHECK_FIELD({index}U, {entry.member});"
            for index, entry in enumerate(spec.fields)
        )
        expected_words = (
            STAGE_B_ENGINE_LAYOUT_HEADER_WORDS
            + STAGE_B_ENGINE_LAYOUT_RECORD_WORDS * len(spec.fields)
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "state-machine-runtime.h").write_text(
                """#ifndef STATE_MACHINE_RUNTIME_H
#define STATE_MACHINE_RUNTIME_H
#include <stdint.h>

typedef struct stage_b_x87_value {
  uint8_t value_bytes[10];
  uint32_t empty;
  uint8_t tag;
} stage_b_x87_value;

typedef struct stage_b_machine_state {
  uint8_t target_abi_prefix;
  uint32_t eax, ebx, ecx, edx, esi, edi, ebp, esp;
  uint32_t eflags;
  stage_b_x87_value x87_stack[8];
  uint16_t x87_control;
  uint16_t x87_status;
  uint8_t x87_pending_exception;
  uint16_t x87_last_opcode;
  uint32_t x87_instruction_pointer;
  uint16_t x87_code_selector;
  uint32_t x87_data_pointer;
  uint16_t x87_data_selector;
  uint32_t fs_base;
  uint32_t original_rva;
} stage_b_machine_state;

#endif
""",
                encoding="utf-8",
            )
            (root / "layout.c").write_text(
                render_stage_b_engine_layout_c(spec), encoding="utf-8"
            )
            (root / "harness.c").write_text(
                f"""#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "state-machine-runtime.h"

extern const uint32_t stage_b_engine_layout_table[];
extern const uint32_t stage_b_engine_layout_table_word_count;

#define CHECK_FIELD(index_, member_) do {{ \\
  size_t base_ = {STAGE_B_ENGINE_LAYOUT_HEADER_WORDS}U \\
      + (size_t)(index_) * {STAGE_B_ENGINE_LAYOUT_RECORD_WORDS}U; \\
  if (stage_b_engine_layout_table[base_ + 2U] \\
      != (uint32_t)offsetof(stage_b_machine_state, member_)) return 20; \\
  if (stage_b_engine_layout_table[base_ + 3U] \\
      != (uint32_t)sizeof(((stage_b_machine_state *)0)->member_)) return 21; \\
}} while (0)

int main(void) {{
  if (stage_b_engine_layout_table_word_count != {expected_words}U) return 1;
  if (stage_b_engine_layout_table[6] != sizeof(stage_b_machine_state)) return 2;
{checks}
  if (fwrite(stage_b_engine_layout_table, sizeof(uint32_t),
      stage_b_engine_layout_table_word_count, stdout)
      != stage_b_engine_layout_table_word_count) return 3;
  return 0;
}}
""",
                encoding="utf-8",
            )
            subprocess.run(
                [
                    compiler,
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "layout.c",
                    "harness.c",
                    "-o",
                    "layout-harness",
                ],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            )
            result = subprocess.run(
                [str(root / "layout-harness")],
                cwd=root,
                check=True,
                capture_output=True,
            )

        layout = parse_stage_b_engine_layout_payload(
            result.stdout,
            expected_features=features,
            expected_x87_slot_count=8,
        )
        self.assertEqual(
            layout.field_layout(EngineField(EngineFieldKind.EFLAGS)).size,
            4,
        )
        self.assertEqual(
            layout.field_layout(EngineField(EngineFieldKind.X87_CONTROL)).size,
            2,
        )
        self.assertEqual(
            layout.field_layout(
                EngineField(EngineFieldKind.X87_PENDING_EXCEPTION)
            ).size,
            1,
        )
        self.assertEqual(
            layout.field_layout(EngineField(EngineFieldKind.X87_LAST_OPCODE)).size,
            2,
        )
        slots = [
            layout.field_layout(EngineField.x87_stack(index))
            for index in range(8)
        ]
        # Persistent x87 values have an exact ten-byte representation. The
        # containing slot stride still follows the target ABI because each slot
        # also carries its separately inventoried occupancy field.
        self.assertEqual(len({slot.size for slot in slots}), 1)
        self.assertEqual(slots[0].size, 10)
        self.assertTrue(
            all(
                right.offset >= left.stop
                for left, right in zip(slots, slots[1:])
            )
        )


if __name__ == "__main__":
    unittest.main()

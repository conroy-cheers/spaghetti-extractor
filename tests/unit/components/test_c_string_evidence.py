"""NUL-terminated component-view evidence tests."""

from __future__ import annotations

import unittest

from spaghetti_extractor.components.logical_abi import (
    LOGICAL_OBJECT_C_V1,
    NUL_TERMINATED_BYTES_V1,
    logical_c_type,
    logical_type_kind,
)
from tests.unit.components import test_evidence_v3 as _fixture


TESTKIT = {"capabilities": ("compiler",)}


class ComponentCStringEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = _fixture.ComponentEvidenceTests(methodName="runTest")
        self.fixture.setUp()

    def tearDown(self) -> None:
        self.fixture.tearDown()

    def test_logical_type_is_a_borrowed_c_string_view(self) -> None:
        self.assertEqual(
            logical_type_kind(
                NUL_TERMINATED_BYTES_V1, source_abi=LOGICAL_OBJECT_C_V1
            ),
            "nul_terminated_bytes",
        )
        self.assertEqual(
            logical_c_type(
                NUL_TERMINATED_BYTES_V1, source_abi=LOGICAL_OBJECT_C_V1
            ),
            "const spx_c_string_v1 *",
        )

    def test_view_and_pointer_offset_result_are_checked_together(self) -> None:
        self.fixture._write_c_string_machine()
        self.fixture._write_c_string_contract()
        package = self.fixture._object_source(
            """
uint32_t identity(const spx_c_string_v1 *value) {
  uint8_t byte = 0U;
  if (value->read_u8(value->context, 0U, &byte) != 0U) return 0U;
  return byte == 0U ? 0U : 1U;
}
"""
        )
        adapter = self.fixture._adapter(package)
        evidence = self.fixture._evidence(
            package,
            adapter,
            _verification([[65, 0], [255, 0]]),
            "c-string-offset-evidence.json",
        )
        self.assertEqual(evidence["status"], "satisfied", evidence["issues"])
        self.assertEqual(evidence["coverage"]["cases"], 2)

    def test_domain_without_terminator_fails_closed(self) -> None:
        self.fixture._write_c_string_machine()
        self.fixture._write_c_string_contract()
        package = self.fixture._object_source(
            """
uint32_t identity(const spx_c_string_v1 *value) {
  (void)value;
  __builtin_trap();
}
"""
        )
        adapter = self.fixture._adapter(package)
        evidence = self.fixture._evidence(
            package,
            adapter,
            _verification([[65]]),
            "c-string-missing-terminator.json",
        )
        self.assertEqual(evidence["status"], "incomplete")
        self.assertTrue(evidence["issues"], evidence)
        self.assertIn(
            "component_evidence_semantics_unsupported",
            [row["code"] for row in evidence["issues"]],
            evidence["issues"],
        )
        issue = _fixture._issue(
            evidence, "component_evidence_semantics_unsupported"
        )
        self.assertIn("no NUL terminator", issue["detail"])


def _verification(buffers: list[list[int]]) -> dict[str, object]:
    return {
        "producer": "exhaustive-finite-domain-v1",
        "parameter_domains": [
            {
                "parameter_id": "value",
                "kind": "nul-terminated-byte-buffer-set",
                "values": buffers,
            }
        ],
    }


if __name__ == "__main__":
    unittest.main()

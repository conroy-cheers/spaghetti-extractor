from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.isa.kernel_qualification import (
    serialize_kernel_qualification,
)
from spaghetti_extractor.isa.qualification_certificate import (
    ISAKernelQualificationCertificateError,
    build_isa_kernel_qualification_certificate_v1,
    parse_isa_kernel_qualification_certificate_v1,
)
from spaghetti_extractor.util import sha256_file, write_json
from tests.unit.isa.kernel_qualification._support import (
    _consensus,
    _form,
    _qualification,
)


class ISAKernelQualificationCertificateTests(unittest.TestCase):
    def _certificate(self, root: Path) -> dict:
        qualification = _qualification((_form((_consensus(),)),))
        payload = serialize_kernel_qualification(qualification)
        full = root / "qualification.json"
        write_json(full, payload)
        return build_isa_kernel_qualification_certificate_v1(
            qualification=qualification,
            qualification_payload=payload,
            qualification_content_sha256=sha256_file(full),
        )

    def test_projection_is_compact_total_and_non_authorizing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            certificate = self._certificate(Path(temporary))
            parsed = parse_isa_kernel_qualification_certificate_v1(
                certificate
            )
            self.assertFalse(parsed["authority"])
            self.assertTrue(parsed["target_independent"])
            self.assertEqual(parsed["counts"], {
                "forms": 1,
                "qualified": 1,
                "incomplete": 0,
                "disputed": 0,
                "vetoed": 0,
            })
            self.assertEqual(parsed["forms"][0]["structural_status"], "complete")
            self.assertEqual(parsed["forms"][0]["oracle_status"], "qualified")

    def test_status_corruption_fails_after_outer_rehash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            certificate = self._certificate(Path(temporary))
            corrupted = copy.deepcopy(certificate)
            corrupted["forms"][0]["oracle_status"] = "incomplete"
            corrupted["certificate_sha256"] = canonical_sha256_v3({
                key: value for key, value in corrupted.items()
                if key != "certificate_sha256"
            })
            with self.assertRaisesRegex(
                ISAKernelQualificationCertificateError, "counts are stale"
            ):
                parse_isa_kernel_qualification_certificate_v1(corrupted)

if __name__ == "__main__":
    unittest.main()

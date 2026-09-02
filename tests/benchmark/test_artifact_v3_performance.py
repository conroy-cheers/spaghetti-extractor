from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import (
    ArtifactBindingV3,
    ArtifactRecordV3,
    ArtifactSetWriterV3,
)
from spaghetti_extractor.artifacts.io import ArtifactSetReaderV3


RECORD_COUNT = 12_000
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_SECONDS = 30.0


class ArtifactV3PerformanceTests(unittest.TestCase):
    def test_streaming_pack_round_trip_stays_bounded(self) -> None:
        binding = ArtifactBindingV3("fixture", "benchmark", "records", "a" * 64)
        started = time.monotonic()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "artifact"
            manifest = ArtifactSetWriterV3(
                artifact_kind="benchmark-records-v3",
                bindings=(binding,),
            ).write(
                output,
                (
                    ArtifactRecordV3.create(
                        f"unit:{index:08x}",
                        {
                            "unit": index,
                            "effects": [
                                {"kind": "register", "name": "eax", "value": index},
                                {"kind": "memory", "address": 0x401000 + index * 4},
                            ],
                            "status": "complete",
                        },
                    )
                    for index in range(RECORD_COUNT)
                ),
            )
            reader = ArtifactSetReaderV3(output)
            self.assertEqual(sum(1 for _ in reader.iter_records()), RECORD_COUNT)
            total_bytes = sum(pack.size_bytes for pack in manifest.packs)
            self.assertLessEqual(total_bytes, MAX_ARTIFACT_BYTES)
            self.assertLessEqual(max(pack.decoded_size_bytes for pack in manifest.packs), 8 * 1024 * 1024)

        elapsed = time.monotonic() - started
        self.assertLess(elapsed, MAX_SECONDS)


if __name__ == "__main__":
    unittest.main()

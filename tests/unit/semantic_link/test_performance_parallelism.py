from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import unittest
from unittest.mock import patch

from spaghetti_extractor.semantic_link.benchmark import (
    _isolated_semantic_link_samples,
    check_semantic_link_performance,
)


def _semantic_sample(_arguments: argparse.Namespace) -> dict[str, int]:
    process = os.getpid()
    return {
        "optional_precision_cpu_milliseconds": process,
        "optional_precision_wall_milliseconds": process,
        "link_cpu_milliseconds": process,
        "link_wall_milliseconds": process,
        "peak_rss_kib": process,
    }


class PerformanceParallelismTests(unittest.TestCase):
    def test_semantic_link_receipt_has_cpu_budget_and_rss_telemetry(self) -> None:
        samples = [
            {
                "optional_precision_cpu_milliseconds": 10,
                "optional_precision_wall_milliseconds": 11,
                "link_cpu_milliseconds": 3,
                "link_wall_milliseconds": 4,
                "peak_rss_kib": 2_000_000,
            }
        ]
        output = io.StringIO()
        arguments = argparse.Namespace(
            maximum_cpu_milliseconds=100,
            maximum_prepared_link_milliseconds=20,
            observations=None,
        )

        with patch(
            "spaghetti_extractor.semantic_link.benchmark."
            "_isolated_semantic_link_samples",
            return_value=samples,
        ), contextlib.redirect_stdout(output):
            check_semantic_link_performance(arguments)

        receipt = json.loads(output.getvalue())
        self.assertEqual(receipt["peak_rss_kib"], 2_000_000)
        self.assertEqual(
            receipt["budgets"], {
                "maximum_cpu_milliseconds": 100,
                "maximum_prepared_link_milliseconds": 20,
            }
        )
        self.assertEqual(
            receipt["worst_link_cpu_milliseconds"], 3
        )
        self.assertEqual(
            receipt["worst_link_wall_milliseconds"], 4
        )
        self.assertEqual(
            receipt["worst_optional_precision_cpu_milliseconds"], 10
        )
        self.assertNotIn("maximum_peak_rss_kib", receipt["budgets"])

    def test_semantic_link_samples_use_isolated_workers(self) -> None:
        with patch(
            "spaghetti_extractor.semantic_link.benchmark._semantic_link_sample",
            _semantic_sample,
        ):
            samples = _isolated_semantic_link_samples(
                argparse.Namespace(), count=3
            )

        self.assertEqual(len(samples), 3)
        self.assertEqual(
            len(
                {
                    sample["optional_precision_cpu_milliseconds"]
                    for sample in samples
                }
            ),
            3,
        )

if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Emit typed access/fault qualification sources for the GNU proof lane."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from spaghetti_extractor.relational.access_domain_receipts import (
    _load_state_machine_rows,
    generate_typed_access_fault_qualification,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-isa", required=True)
    parser.add_argument("--state-machine", required=True)
    parser.add_argument("--reachability-plan", required=True)
    parser.add_argument("--kernel-data-inventory", required=True)
    parser.add_argument("--certificate-pack-size", type=int, default=8)
    parser.add_argument("--out", required=True)
    arguments = parser.parse_args()
    original_isa = json.loads(
        Path(arguments.original_isa).read_text(encoding="utf-8")
    )
    reachability_plan = json.loads(
        Path(arguments.reachability_plan).read_text(encoding="utf-8")
    )
    kernel_data_inventory = json.loads(
        Path(arguments.kernel_data_inventory).read_text(encoding="utf-8")
    )
    generate_typed_access_fault_qualification(
        original_isa=original_isa,
        state_machine_rows=_load_state_machine_rows(
            Path(arguments.state_machine)
        ),
        reachability_plan=reachability_plan,
        kernel_data_inventory=kernel_data_inventory,
        out=Path(arguments.out),
        certificate_pack_size=arguments.certificate_pack_size,
    )


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Profile the pure v2 static-authority replay from a CA phase manifest."""

from __future__ import annotations

import argparse
import cProfile
import hashlib
import io
import json
import pathlib
import pstats
from collections.abc import Mapping
from typing import Any

from spaghetti_extractor.external_profile_authority_v2 import (
    parse_external_profile_authority_v2,
)
from spaghetti_extractor.external_site_proposals_v2 import (
    parse_external_site_proposals_v2,
)
from spaghetti_extractor.static_hybrid_authority_v2 import (
    build_static_hybrid_authority_v2,
)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "phase_manifest",
        type=pathlib.Path,
        help="phase-manifest.json from a static-authority-v2 derivation",
    )
    parser.add_argument("--limit", type=int, default=40)
    return parser.parse_args()


def _load(path: pathlib.Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _input_paths(manifest: Mapping[str, Any]) -> dict[str, pathlib.Path]:
    if manifest.get("phase") != "static-authority-v2":
        raise ValueError("manifest is not for static-authority-v2")
    rows = manifest.get("inputs")
    if not isinstance(rows, list):
        raise ValueError("manifest input inventory is malformed")
    result = {
        str(row["name"]): pathlib.Path(str(row["store_path"]))
        for row in rows
        if isinstance(row, Mapping)
    }
    required = {
        "behavioral_roots",
        "checked_external_sites",
        "entry_root_closure",
        "exact_unit_prep",
        "exception_certificates",
        "external_profile_authority",
        "interprocedural_v2",
        "isa_requirements",
        "isa_selection_authority",
        "machine_ir",
        "machine_ir_manifest",
        "original_pe",
    }
    missing = sorted(required - result.keys())
    if missing:
        raise ValueError(f"manifest is missing inputs: {', '.join(missing)}")
    return result


def _replay(inputs: Mapping[str, pathlib.Path]) -> dict[str, Any]:
    rows = [
        json.loads(line)
        for line in inputs["machine_ir"].read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    pe_sha256 = hashlib.sha256(inputs["original_pe"].read_bytes()).hexdigest()
    machine_ir_sha256 = hashlib.sha256(
        inputs["machine_ir"].read_bytes()
    ).hexdigest()
    externals = parse_external_site_proposals_v2(
        _load(inputs["checked_external_sites"]),
        pe_sha256=pe_sha256,
        machine_ir_sha256=machine_ir_sha256,
    )
    profile_authority = parse_external_profile_authority_v2(
        _load(inputs["external_profile_authority"])["authority"]
    )
    exceptions = _load(inputs["exception_certificates"])
    isa = _load(inputs["isa_selection_authority"])
    return build_static_hybrid_authority_v2(
        machine_ir_rows=rows,
        machine_ir_manifest=_load(inputs["machine_ir_manifest"]),
        exact_unit_preparation=_load(inputs["exact_unit_prep"]),
        pe_sha256=pe_sha256,
        behavioral_roots=_load(inputs["behavioral_roots"]),
        entry_state_analysis=_load(inputs["entry_root_closure"]),
        interprocedural_result=_load(inputs["interprocedural_v2"]),
        checked_external_sites=externals,
        external_profile_authority=profile_authority,
        checked_exception_reports=exceptions.get("reports", []),
        checked_exception_records=exceptions.get("authority_records", []),
        isa_selection_authority=isa.get(
            "selection_certificate", isa.get("authority")
        ),
        isa_requirements=_load(inputs["isa_requirements"]),
    )


def main() -> int:
    args = _parse_args()
    manifest = _load(args.phase_manifest)
    if not isinstance(manifest, Mapping):
        raise ValueError("phase manifest must be an object")
    inputs = _input_paths(manifest)
    profiler = cProfile.Profile()
    report = profiler.runcall(_replay, inputs)
    stream = io.StringIO()
    pstats.Stats(profiler, stream=stream).strip_dirs().sort_stats(
        "cumulative"
    ).print_stats(args.limit)
    print(stream.getvalue(), end="")
    print(
        json.dumps(
            {
                "status": report.get("status"),
                "blockers": report.get("diagnostics", {}).get("counts", {}).get(
                    "blockers"
                ),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

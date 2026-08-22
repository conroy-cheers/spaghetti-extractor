"""Expert validation leaf for shared target boundary schemas."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..boundary import BoundarySchemaV1, TargetDataLayoutV1, render_boundary_header
from ..calls.dialects.ia32 import IA32DialectCheckerV1
from .common import Handler


def _check(args: argparse.Namespace) -> dict[str, object]:
    spec = json.loads(args.spec.read_text(encoding="utf-8"))
    if not isinstance(spec, dict) or set(spec) != {
        "format", "schema_id", "types", "signatures", "layout", "frames",
        "source_names",
    }:
        raise ValueError("boundary check spec has unexpected fields")
    if spec["format"] != "spaghetti-extractor-boundary-check-spec-v1":
        raise ValueError("unsupported boundary check spec format")
    schema = BoundarySchemaV1.create(
        schema_id=spec["schema_id"], types=spec["types"], signatures=spec["signatures"]
    )
    layout_row = spec["layout"]
    if not isinstance(layout_row, dict) or set(layout_row) != {
        "target", "abi_dialect", "byte_order", "pointer_width_bits", "packing",
        "layouts",
    }:
        raise ValueError("boundary target layout has unexpected fields")
    layout = TargetDataLayoutV1.create(
        target=layout_row["target"], abi_dialect=layout_row["abi_dialect"],
        byte_order=layout_row["byte_order"],
        pointer_width_bits=layout_row["pointer_width_bits"],
        packing=layout_row["packing"], schema=schema,
        layouts=layout_row["layouts"],
    )
    checker = IA32DialectCheckerV1(layout.abi_dialect)
    frames = []
    if not isinstance(spec["frames"], list):
        raise ValueError("boundary frames must be an array")
    for index, frame_row in enumerate(spec["frames"]):
        if not isinstance(frame_row, dict) or set(frame_row) != {
            "id", "subject", "signature_id", "transfer_kind"
        }:
            raise ValueError(f"boundary frame {index} has unexpected fields")
        frames.append((frame_row["id"], checker.lower_boundary(
            subject=frame_row["subject"], schema=schema, layout=layout,
            signature_id=frame_row["signature_id"],
            transfer_kind=frame_row["transfer_kind"],
        )))
    names = spec["source_names"]
    if not isinstance(names, dict) or set(names) != {"types", "signatures"}:
        raise ValueError("boundary source names have unexpected fields")
    if not isinstance(names["types"], dict) or not isinstance(names["signatures"], dict):
        raise ValueError("boundary source names must be mappings")
    output = args.out.resolve()
    output.mkdir(parents=True, exist_ok=True)
    _write(output / "boundary-schema.json", schema.to_payload())
    _write(output / "target-data-layout.json", layout.to_payload())
    for frame_id, frame in frames:
        _write(output / f"physical-call-frame-{frame_id}.json", frame.to_payload())
    (output / "boundary.h").write_text(
        render_boundary_header(
            schema,
            type_names={str(key): str(value) for key, value in names["types"].items()},
            signature_names={str(key): str(value) for key, value in names["signatures"].items()},
        ),
        encoding="utf-8",
    )
    result = {
        "format": "spaghetti-extractor-boundary-check-result-v1",
        "status": "complete",
        "schema_id": schema.schema_id,
        "schema_sha256": schema.schema_sha256,
        "layout_sha256": layout.layout_sha256,
        "frames": [frame.frame_id for _frame_id, frame in frames],
    }
    _write(output / "boundary-status.json", result)
    return result


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def configure_command(name: str, parser: argparse.ArgumentParser) -> Handler:
    if name != "boundary-check":
        raise ValueError(f"unsupported boundary command: {name}")
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    return _check


__all__ = ["configure_command"]

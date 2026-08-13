"""Narrow command boundary for one concrete ISA conformance backend."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .isa_conformance import (
    parse_isa_conformance_corpus,
    serialize_isa_conformance_report,
)
from .isa_conformance_bochs import run_bochs_corpus
from .isa_conformance_lean import run_lean_isa_conformance_with_definedness
from .isa_conformance_shards import lean_semantic_forms_payload
from .isa_conformance_unicorn import run_unicorn_corpus
from .stage_binary import StageAInputError


def run_isa_conformance_worker(
    *,
    corpus_path: Path,
    backend: str,
    out: Path,
    bochs_runner: Path | None = None,
    lean_kernel_cache: Path | None = None,
    lean_timeout_seconds: int = 1800,
    forms_out: Path | None = None,
) -> dict[str, Any]:
    """Execute one backend and emit a canonical report plus thin result."""

    if backend not in {"lean", "unicorn", "bochs"}:
        raise StageAInputError(f"unsupported ISA conformance backend {backend!r}")
    corpus = parse_isa_conformance_corpus(
        json.loads(Path(corpus_path).read_text(encoding="utf-8"))
    )
    if backend == "lean":
        report, forms, definedness = run_lean_isa_conformance_with_definedness(
            corpus,
            timeout_seconds=lean_timeout_seconds,
            kernel_cache=lean_kernel_cache,
        )
        if forms_out is not None:
            Path(forms_out).parent.mkdir(parents=True, exist_ok=True)
            Path(forms_out).write_text(
                json.dumps(
                    lean_semantic_forms_payload(
                        corpus,
                        forms,
                        x87_definedness_by_id={
                            case_id: {
                                "control_word": row.control_word,
                                "status_word": row.status_word,
                                "tag_word": row.tag_word,
                                "last_opcode": row.last_opcode,
                                "instruction_pointer": row.instruction_pointer,
                                "data_pointer": row.data_pointer,
                                "registers": [
                                    register.hex() for register in row.registers
                                ],
                            }
                            for case_id, row in definedness.items()
                        },
                    ),
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
    elif backend == "unicorn":
        report = run_unicorn_corpus(corpus)
    else:
        if bochs_runner is None:
            raise StageAInputError("Bochs conformance requires a runner")
        report = run_bochs_corpus(corpus, runner=Path(bochs_runner))
    payload = serialize_isa_conformance_report(report, corpus=corpus)
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return {
        "format": "stage-a-isa-conformance-check-v1",
        "status": "checked",
        "backend": payload["backend"],
        "qualification": payload["qualification"],
        "counts": payload["counts"],
        "out": str(out),
        "proof_authority": False,
        "closes_stage_a_proof": False,
    }


__all__ = ["run_isa_conformance_worker"]

"""Non-authorizing, incremental timing records for a compiled proof model."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path
from typing import Callable, Mapping, Sequence


class ProofQueryTimings:
    def __init__(self, model: Path, subject: Mapping[str, str], *, query_evidence=None) -> None:
        self.query_evidence = query_evidence
        self.model = model.resolve()
        self.subject = dict(subject)
        self.path = model.parent / "query-timings.jsonl"
        self.started = time.perf_counter()
        self.lock = threading.Lock()
        self.model_sha256: str | None = None

    def record_compile_inputs(self, command: Sequence[str], *, proof_root: Path, compiler_workspace=None) -> None:
        """Preserve path-sensitive include lookup for diagnostic reconstruction.

        Equal C bytes in separate regions may include different local headers.
        A hash-only join cannot reconstruct the actual compilation. This record
        preserves ordered arguments and retained file paths; it is not a proof
        receipt or a claim that external dependencies have been archived.
        """
        root = proof_root.resolve()

        def relative(path: Path) -> str:
            return "$PROOF_ROOT/" + path.resolve().relative_to(root).as_posix()

        def argument_path(argument: str) -> str:
            path = Path(argument)
            if path.is_absolute() and path.is_relative_to(root):
                return "$PROOF_ROOT" if path == root else relative(path)
            return argument

        files = set(root.rglob("*.h"))
        for argument in command:
            path = Path(argument)
            if path.suffix == ".c" and path.is_file() and path.resolve().is_relative_to(root):
                files.add(path)
        record = {
            **({"compiler_workspace": str(compiler_workspace), "compiler_workspace_host": "$PROOF_ROOT"}
               if compiler_workspace is not None else {}),
            **self.subject, "authorizing": False,
            "scope": "retained compilation paths; external dependencies remain external",
            "command": [argument_path(str(item)) for item in command],
            "files": [
                {"path": relative(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                for path in sorted(files)
            ],
        }
        (self.model.parent / "compile-inputs.json").write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    def run(self, kind: str, function: Callable, *, command: Sequence[str], **arguments):
        started = time.perf_counter()
        result = None
        completed = False
        try:
            if self.query_evidence is not None and kind != "compile":
                arguments["query_evidence"] = self.query_evidence
            result = function(command=command, **arguments)
            completed = True
            return result
        finally:
            elapsed = time.perf_counter() - started
            status = (str(result.get("status", "incomplete")) if isinstance(result, Mapping)
                      else "satisfied" if completed and result is None else "error")
            with self.lock:
                if self.model_sha256 is None and self.model.is_file():
                    self.model_sha256 = hashlib.sha256(self.model.read_bytes()).hexdigest()
            row = {
                **self.subject, "authorizing": False, "kind": kind,
                "started_after_seconds": started - self.started,
                "elapsed_seconds": elapsed, "status": status,
                "code": result.get("code") if isinstance(result, Mapping) else None,
                "detail": result.get("detail") if isinstance(result, Mapping) else None,
                "command": [str(item).replace(str(self.model.parent), "$OBLIGATION_ROOT") for item in command],
                "goto_model_sha256": self.model_sha256,
                "output_sha256": result.get("output_sha256") if isinstance(result, Mapping) else None,
            }
            # Record each completed query, including timeouts, before the whole
            # obligation finishes. Concurrent solver workers must not interleave
            # partial JSON records. No timing enters an authority receipt.
            with self.lock:
                with self.path.open("a", encoding="utf-8") as output:
                    output.write(json.dumps(row, sort_keys=True) + "\n")


def timed_query(timings: ProofQueryTimings | None, kind: str, function: Callable,
                *, command: Sequence[str], **arguments):
    if timings is None:
        return function(command=command, **arguments)
    return timings.run(kind, function, command=command, **arguments)

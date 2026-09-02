"""Canonical IA-32 exception-record projection paths.

Transfer semantics, reference kernels, and native ingress use this one small
vocabulary. A nested path names the record reached by following the primary
``ExceptionRecord`` pointer exactly ``depth`` times. Runtime realization
requires an exact chain of that depth and never truncates a longer host chain.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


MAX_EXCEPTION_RECORD_CHAIN_V1 = 4

PRIMARY_EXCEPTION_RECORD_FIELDS_V1 = frozenset({
    "exceptioncode",
    "exceptionflags",
    "exceptionrecord",
    "exceptionaddress",
    "numberparameters",
    *(f"exceptioninformation[{index}]" for index in range(15)),
})

_NESTED_EXCEPTION_RECORD_PATH_V1 = re.compile(
    r"exceptionrecord\[([1-9][0-9]*)\]\.([a-z][a-z0-9]*(?:\[[0-9]+\])?)"
)


@dataclass(frozen=True, order=True, slots=True)
class ExceptionRecordProjectionPathV1:
    depth: int
    field: str


def parse_exception_record_projection_path_v1(
    value: str,
) -> ExceptionRecordProjectionPathV1 | None:
    """Parse one canonical primary or nested record field."""

    lowered = value.lower()
    if lowered in PRIMARY_EXCEPTION_RECORD_FIELDS_V1:
        return ExceptionRecordProjectionPathV1(0, lowered)
    match = _NESTED_EXCEPTION_RECORD_PATH_V1.fullmatch(lowered)
    if match is None:
        return None
    field = match.group(2)
    if field not in PRIMARY_EXCEPTION_RECORD_FIELDS_V1:
        return None
    return ExceptionRecordProjectionPathV1(int(match.group(1)), field)


def exception_record_projection_paths_v1(
    values: set[str] | frozenset[str],
) -> tuple[
    tuple[ExceptionRecordProjectionPathV1, ...],
    tuple[str, ...],
    tuple[str, ...],
]:
    """Return canonical paths, malformed names, and out-of-bound names."""

    paths: list[ExceptionRecordProjectionPathV1] = []
    malformed: list[str] = []
    out_of_bounds: list[str] = []
    for value in sorted(values):
        path = parse_exception_record_projection_path_v1(value)
        if path is None:
            malformed.append(value)
        elif path.depth >= MAX_EXCEPTION_RECORD_CHAIN_V1:
            out_of_bounds.append(value)
        else:
            paths.append(path)
    return tuple(paths), tuple(malformed), tuple(out_of_bounds)


__all__ = [
    "ExceptionRecordProjectionPathV1",
    "MAX_EXCEPTION_RECORD_CHAIN_V1",
    "PRIMARY_EXCEPTION_RECORD_FIELDS_V1",
    "exception_record_projection_paths_v1",
    "parse_exception_record_projection_path_v1",
]

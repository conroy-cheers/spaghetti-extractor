"""Checked immutable data recovered from executable PE32 sections.

The Stage A load-image contract deliberately omits executable-section bodies so
that a generated candidate cannot accidentally contain or execute reference
code.  Some compilers place jump tables and their index maps in ``.text``.
This artifact carries only ranges that static control recovery identified as
immutable data and binds them to both the original image and sanitized machine
IR.  It has no acceptance authority; candidate execution must still reject the
ranges as code targets.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

import capstone
from capstone.x86 import X86_OP_REG

from .stage_binary import StageABinary, StageAInputError
from .util import sha256_bytes


RECOVERED_EXECUTABLE_DATA_FORMAT = "stage-a-recovered-executable-data-v1"
RECOVERED_EXECUTABLE_DATA_FILENAME = "recovered-executable-data.json"
_MAX_ALIGNMENT_PADDING_BYTES = 15


class RecoveredExecutableDataError(StageAInputError):
    """Recovered executable-section data is malformed or insufficiently bound."""


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _u32(value: Any, label: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value < 2**32
    ):
        raise RecoveredExecutableDataError(f"{label} must be an unsigned 32-bit integer")
    return value


def _sha256(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise RecoveredExecutableDataError(
            f"{label} must be a lowercase SHA-256 digest"
        )
    return value


def _strings(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise RecoveredExecutableDataError(f"{label} must be a string list")
    result = tuple(value)
    if result != tuple(sorted(set(result))):
        raise RecoveredExecutableDataError(f"{label} must be sorted and unique")
    return result


@dataclass(frozen=True)
class RecoveredExecutableDataRange:
    identity: str
    rva_start: int
    rva_end: int
    section_index: int
    section_name: str
    data: bytes
    bytes_sha256: str
    kinds: tuple[str, ...]
    recovery_ids: tuple[str, ...]

    @property
    def size(self) -> int:
        return self.rva_end - self.rva_start

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.identity,
            "rva_start": self.rva_start,
            "rva_end": self.rva_end,
            "size": self.size,
            "section_index": self.section_index,
            "section_name": self.section_name,
            "bytes_hex": self.data.hex(),
            "bytes_sha256": self.bytes_sha256,
            "kinds": list(self.kinds),
            "recovery_ids": list(self.recovery_ids),
        }

    @classmethod
    def parse(
        cls, value: Mapping[str, Any], *, label: str
    ) -> "RecoveredExecutableDataRange":
        expected = {
            "id",
            "rva_start",
            "rva_end",
            "size",
            "section_index",
            "section_name",
            "bytes_hex",
            "bytes_sha256",
            "kinds",
            "recovery_ids",
        }
        if set(value) != expected:
            raise RecoveredExecutableDataError(f"{label} has noncanonical fields")
        start = _u32(value["rva_start"], f"{label}.rva_start")
        end = _u32(value["rva_end"], f"{label}.rva_end")
        if end <= start or value["size"] != end - start:
            raise RecoveredExecutableDataError(f"{label} has an invalid span")
        raw = value["bytes_hex"]
        if not isinstance(raw, str) or len(raw) != 2 * (end - start):
            raise RecoveredExecutableDataError(f"{label}.bytes_hex has the wrong size")
        try:
            data = bytes.fromhex(raw)
        except ValueError as exc:
            raise RecoveredExecutableDataError(
                f"{label}.bytes_hex must be hexadecimal"
            ) from exc
        if data.hex() != raw:
            raise RecoveredExecutableDataError(
                f"{label}.bytes_hex must be lowercase canonical hexadecimal"
            )
        digest = _sha256(value["bytes_sha256"], f"{label}.bytes_sha256")
        if sha256_bytes(data) != digest:
            raise RecoveredExecutableDataError(f"{label} byte hash mismatch")
        identity = value["id"]
        section_name = value["section_name"]
        if not isinstance(identity, str) or not identity:
            raise RecoveredExecutableDataError(f"{label}.id must be nonempty")
        if not isinstance(section_name, str) or not section_name:
            raise RecoveredExecutableDataError(
                f"{label}.section_name must be nonempty"
            )
        result = cls(
            identity=identity,
            rva_start=start,
            rva_end=end,
            section_index=_u32(value["section_index"], f"{label}.section_index"),
            section_name=section_name,
            data=data,
            bytes_sha256=digest,
            kinds=_strings(value["kinds"], f"{label}.kinds"),
            recovery_ids=_strings(value["recovery_ids"], f"{label}.recovery_ids"),
        )
        expected_identity = "recovered-executable-data:" + sha256_bytes(
            _canonical_bytes({
                "rva_start": result.rva_start,
                "rva_end": result.rva_end,
                "section_index": result.section_index,
                "bytes_sha256": result.bytes_sha256,
                "kinds": list(result.kinds),
                "recovery_ids": list(result.recovery_ids),
            })
        )[:20]
        if identity != expected_identity:
            raise RecoveredExecutableDataError(f"{label} identity mismatch")
        return result


@dataclass(frozen=True)
class RecoveredExecutableDataContract:
    original_pe_sha256: str
    image_base: int
    machine_ir_sha256: str
    control_sha256: str
    ranges: tuple[RecoveredExecutableDataRange, ...]

    def to_payload(self) -> dict[str, Any]:
        core: dict[str, Any] = {
            "format": RECOVERED_EXECUTABLE_DATA_FORMAT,
            "status": "checked",
            "authority": (
                "candidate-generation data only; no original execution and no "
                "acceptance authority"
            ),
            "original": {
                "pe_sha256": self.original_pe_sha256,
                "image_base": self.image_base,
            },
            "machine_ir": {
                "sha256": self.machine_ir_sha256,
                "control_sha256": self.control_sha256,
            },
            "ranges": [item.to_payload() for item in self.ranges],
            "counts": {
                "ranges": len(self.ranges),
                "bytes": sum(item.size for item in self.ranges),
            },
            "constraints": {
                "original_binary_executed": False,
                "executable_code_bytes_exported": False,
                "ranges_are_readable_immutable_initialized_data": True,
                "ranges_do_not_overlap_rooted_reachable_transfers": True,
                "indirect_dispatch_into_ranges_must_fail_closed": True,
            },
        }
        return {
            **core,
            "hashes": {
                "algorithm": "sha256",
                "contract_sha256": sha256_bytes(_canonical_bytes(core)),
            },
        }

    @classmethod
    def parse(cls, value: Mapping[str, Any]) -> "RecoveredExecutableDataContract":
        expected = {
            "format",
            "status",
            "authority",
            "original",
            "machine_ir",
            "ranges",
            "counts",
            "constraints",
            "hashes",
        }
        if set(value) != expected:
            raise RecoveredExecutableDataError(
                "recovered executable-data contract has noncanonical fields"
            )
        if (
            value["format"] != RECOVERED_EXECUTABLE_DATA_FORMAT
            or value["status"] != "checked"
        ):
            raise RecoveredExecutableDataError(
                "unsupported recovered executable-data contract"
            )
        original = value["original"]
        machine_ir = value["machine_ir"]
        raw_ranges = value["ranges"]
        counts = value["counts"]
        constraints = value["constraints"]
        hashes = value["hashes"]
        if not all(
            isinstance(item, Mapping)
            for item in (original, machine_ir, counts, constraints, hashes)
        ) or not isinstance(raw_ranges, list):
            raise RecoveredExecutableDataError(
                "recovered executable-data contract has malformed objects"
            )
        required_constraints = {
            "original_binary_executed": False,
            "executable_code_bytes_exported": False,
            "ranges_are_readable_immutable_initialized_data": True,
            "ranges_do_not_overlap_rooted_reachable_transfers": True,
            "indirect_dispatch_into_ranges_must_fail_closed": True,
        }
        if dict(constraints) != required_constraints:
            raise RecoveredExecutableDataError(
                "recovered executable-data constraints are not fail-closed"
            )
        ranges = tuple(
            RecoveredExecutableDataRange.parse(
                item, label=f"recovered executable-data range {index}"
            )
            for index, item in enumerate(raw_ranges)
            if isinstance(item, Mapping)
        )
        if len(ranges) != len(raw_ranges):
            raise RecoveredExecutableDataError(
                "recovered executable-data range is not an object"
            )
        if ranges != tuple(sorted(ranges, key=lambda item: item.rva_start)):
            raise RecoveredExecutableDataError(
                "recovered executable-data ranges are not sorted"
            )
        for previous, current in zip(ranges, ranges[1:]):
            if current.rva_start < previous.rva_end:
                raise RecoveredExecutableDataError(
                    "recovered executable-data ranges overlap"
                )
        if dict(counts) != {
            "ranges": len(ranges),
            "bytes": sum(item.size for item in ranges),
        }:
            raise RecoveredExecutableDataError(
                "recovered executable-data counts are inconsistent"
            )
        core = {key: value[key] for key in value if key != "hashes"}
        if (
            hashes.get("algorithm") != "sha256"
            or _sha256(
                hashes.get("contract_sha256"),
                "recovered executable-data contract SHA-256",
            )
            != sha256_bytes(_canonical_bytes(core))
        ):
            raise RecoveredExecutableDataError(
                "recovered executable-data contract hash mismatch"
            )
        return cls(
            original_pe_sha256=_sha256(
                original.get("pe_sha256"), "recovered executable-data PE SHA-256"
            ),
            image_base=_u32(original.get("image_base"), "recovered executable-data image base"),
            machine_ir_sha256=_sha256(
                machine_ir.get("sha256"), "recovered executable-data machine-IR SHA-256"
            ),
            control_sha256=_sha256(
                machine_ir.get("control_sha256"),
                "recovered executable-data control SHA-256",
            ),
            ranges=ranges,
        )


def build_recovered_executable_data_contract(
    *,
    binary: StageABinary,
    control: Mapping[str, Any],
    source_map: Sequence[Mapping[str, Any]],
    machine_ir_sha256: str,
) -> RecoveredExecutableDataContract:
    """Extract exact, immutable executable-section data from checked recoveries."""

    reachable = control.get("reachability")
    reachable_ids = set(
        reachable.get("reachable_units", [])
        if isinstance(reachable, Mapping)
        else []
    )
    reachable_spans = [
        (
            _u32(row.get("rva_start"), "reachable unit start"),
            _u32(row.get("rva_end"), "reachable unit end"),
            str(row.get("unit_id")),
        )
        for row in source_map
        if row.get("unit_id") in reachable_ids
    ]
    code_targets: set[int] = set()
    for row in control.get("roots", []):
        if isinstance(row, Mapping) and isinstance(row.get("rva"), int):
            code_targets.add(int(row["rva"]))
    for row in control.get("direct_targets", []):
        if (
            isinstance(row, Mapping)
            and row.get("source_unit_id") in reachable_ids
            and isinstance(row.get("target_rva"), int)
        ):
            code_targets.add(int(row["target_rva"]))
    for row in control.get("recovered_indirect_targets", []):
        if not isinstance(row, Mapping) or row.get("source_unit_id") not in reachable_ids:
            continue
        for target in row.get("target_rvas", []):
            if isinstance(target, int) and not isinstance(target, bool):
                code_targets.add(target)
    classification = control.get("executable_classification")
    classified_ranges = (
        classification.get("immutable_data_ranges", [])
        if isinstance(classification, Mapping)
        else []
    )
    ranges = _merge_recovered_ranges(
        _ranges_from_classification(binary, classified_ranges)
        if isinstance(classified_ranges, list)
        else (),
        recover_executable_data_ranges(
            binary=binary,
            recoveries=control.get("recovered_indirect_targets", []),
            require_complete_unit_binding=True,
            allowed_source_unit_ids=reachable_ids,
            known_code_unit_rvas={start for start, _, _ in reachable_spans},
        ),
    )

    for item in ranges:
        overlapping_reachable = [
            identity
            for span_start, span_end, identity in reachable_spans
            if item.rva_start < span_end and span_start < item.rva_end
        ]
        if overlapping_reachable:
            raise RecoveredExecutableDataError(
                "recovered executable data overlaps rooted reachable transfer "
                f"{overlapping_reachable[0]}"
            )
        overlapping_target = next(
            (
                target
                for target in sorted(code_targets)
                if item.rva_start <= target < item.rva_end
            ),
            None,
        )
        if overlapping_target is not None:
            raise RecoveredExecutableDataError(
                "recovered executable data contains code target RVA "
                f"0x{overlapping_target:x}"
            )
    return RecoveredExecutableDataContract(
        original_pe_sha256=binary.sha256,
        image_base=binary.image_base,
        machine_ir_sha256=_sha256(machine_ir_sha256, "machine-IR SHA-256"),
        control_sha256=sha256_bytes(_canonical_bytes(control)),
        ranges=ranges,
    )


def recover_executable_data_ranges(
    *,
    binary: StageABinary,
    recoveries: Sequence[Mapping[str, Any]],
    require_complete_unit_binding: bool = False,
    allowed_source_unit_ids: set[str] | None = None,
    known_code_unit_rvas: set[int] | None = None,
) -> tuple[RecoveredExecutableDataRange, ...]:
    """Check exact immutable ranges proposed by static control recovery.

    This deliberately has no reachability policy.  It is usable before rooted
    control closure: callers decide which recovery sources are eligible and
    must separately reject behavioral roots or control targets into the
    returned ranges.
    """

    candidates: dict[tuple[int, int, str], dict[str, Any]] = {}
    for recovery in recoveries:
        if not isinstance(recovery, Mapping):
            continue
        source_unit_id = recovery.get("source_unit_id")
        if (
            allowed_source_unit_ids is not None
            and source_unit_id not in allowed_source_unit_ids
        ):
            continue
        if (
            recovery.get("status") != "recovered"
            or recovery.get("closure") != "checked_finite_target_inventory"
        ):
            continue
        if require_complete_unit_binding and (
            not isinstance(recovery.get("unit_binding"), Mapping)
            or recovery["unit_binding"].get("status") != "complete"
        ):
            continue
        recovery_id = recovery.get("id")
        if not isinstance(recovery_id, str) or not recovery_id:
            raise RecoveredExecutableDataError(
                "recovered indirect target has no stable identity"
            )
        descriptors: list[tuple[str, Mapping[str, Any]]] = []
        table = recovery.get("table")
        if isinstance(table, Mapping):
            descriptors.append(("finite_target_table", table))
        index = recovery.get("index")
        remap = index.get("remap") if isinstance(index, Mapping) else None
        if isinstance(remap, Mapping):
            descriptors.append(("finite_index_remap", remap))
        for kind, descriptor in descriptors:
            start = _u32(descriptor.get("rva_start"), f"{kind} start")
            end = _u32(descriptor.get("rva_end"), f"{kind} end")
            if end <= start:
                raise RecoveredExecutableDataError(f"{kind} has an empty range")
            section_matches = [
                (section_index, section)
                for section_index, section in enumerate(binary.sections)
                if section.rva_start <= start and end <= section.rva_end
            ]
            if len(section_matches) != 1:
                raise RecoveredExecutableDataError(
                    f"{kind} range is not bounded by exactly one PE section"
                )
            section_index, section = section_matches[0]
            if not section.executable:
                # Non-executable initialized sections already cross the ordinary
                # load-image contract and need no duplicate artifact.
                continue
            initialized_end = min(
                section.rva_end, section.rva_start + section.raw_size
            )
            if (
                not section.readable
                or section.writable
                or end > initialized_end
            ):
                raise RecoveredExecutableDataError(
                    f"{kind} must be readable immutable initialized PE data"
                )
            data = bytes(binary.pe.get_data(start, end - start))
            if len(data) != end - start:
                raise RecoveredExecutableDataError(f"{kind} bytes are truncated")
            digest = sha256_bytes(data)
            if _sha256(descriptor.get("bytes_sha256"), f"{kind} byte hash") != digest:
                raise RecoveredExecutableDataError(
                    f"{kind} bytes disagree with recovered control evidence"
                )
            key = (start, end, digest)
            aggregate = candidates.setdefault(
                key,
                {
                    "section_index": section_index,
                    "section_name": section.name,
                    "data": data,
                    "kinds": set(),
                    "recovery_ids": set(),
                },
            )
            if (
                aggregate["section_index"] != section_index
                or aggregate["section_name"] != section.name
                or aggregate["data"] != data
            ):
                raise RecoveredExecutableDataError(
                    "duplicate recovered executable-data range disagrees"
                )
            aggregate["kinds"].add(kind)
            aggregate["recovery_ids"].add(recovery_id)

    ranges: list[RecoveredExecutableDataRange] = []
    for (start, end, digest), aggregate in sorted(candidates.items()):
        kinds = tuple(sorted(aggregate["kinds"]))
        recovery_ids = tuple(sorted(aggregate["recovery_ids"]))
        identity_core = {
            "rva_start": start,
            "rva_end": end,
            "section_index": aggregate["section_index"],
            "bytes_sha256": digest,
            "kinds": list(kinds),
            "recovery_ids": list(recovery_ids),
        }
        ranges.append(
            RecoveredExecutableDataRange(
                identity="recovered-executable-data:"
                + sha256_bytes(_canonical_bytes(identity_core))[:20],
                rva_start=start,
                rva_end=end,
                section_index=aggregate["section_index"],
                section_name=aggregate["section_name"],
                data=aggregate["data"],
                bytes_sha256=digest,
                kinds=kinds,
                recovery_ids=recovery_ids,
            )
        )
    protected_code_rvas = set(known_code_unit_rvas or ())
    for recovery in recoveries:
        if not isinstance(recovery, Mapping):
            continue
        protected_code_rvas.update(
            target
            for target in recovery.get("target_rvas", [])
            if isinstance(target, int) and not isinstance(target, bool)
        )
    ranges.extend(
        _recover_adjacent_alignment_padding(
            binary=binary,
            data_ranges=ranges,
            protected_code_rvas=protected_code_rvas,
        )
    )
    ranges.extend(
        _recover_adjacent_static_code_pointer_slots(
            binary=binary,
            data_ranges=ranges,
            known_code_unit_rvas=known_code_unit_rvas,
        )
    )
    ranges.sort(key=lambda item: item.rva_start)
    for previous, current in zip(ranges, ranges[1:]):
        if current.rva_start < previous.rva_end:
            raise RecoveredExecutableDataError(
                "distinct recovered executable-data ranges overlap"
            )
    return tuple(ranges)


def _recover_adjacent_static_code_pointer_slots(
    *,
    binary: StageABinary,
    data_ranges: Sequence[RecoveredExecutableDataRange],
    known_code_unit_rvas: set[int] | None,
) -> tuple[RecoveredExecutableDataRange, ...]:
    """Recover one exact code-pointer slot inside a checked data structure.

    The slot must be the complete four-byte gap between two immutable ranges
    produced by the same recovery and point to an exact known machine-unit
    start.  This covers default dispatch targets stored beside a table without
    turning general pointer-looking bytes into data authority.
    """

    if not known_code_unit_rvas:
        return ()
    ordered = sorted(data_ranges, key=lambda item: item.rva_start)
    result: list[RecoveredExecutableDataRange] = []
    for left, right in zip(ordered, ordered[1:]):
        start = left.rva_end
        end = right.rva_start
        shared_recoveries = set(left.recovery_ids) & set(right.recovery_ids)
        if (
            end - start != 4
            or left.section_index != right.section_index
            or not shared_recoveries
        ):
            continue
        section = binary.sections[left.section_index]
        initialized_end = min(
            section.rva_end, section.rva_start + section.raw_size
        )
        if (
            not section.executable
            or not section.readable
            or section.writable
            or end > initialized_end
        ):
            continue
        data = bytes(binary.pe.get_data(start, 4))
        if len(data) != 4:
            continue
        target_va = int.from_bytes(data, "little")
        target_rva = target_va - binary.image_base
        target_sections = [
            candidate
            for candidate in binary.sections
            if candidate.executable
            and candidate.rva_start <= target_rva < candidate.rva_end
        ]
        if target_rva not in known_code_unit_rvas or len(target_sections) != 1:
            continue
        digest = sha256_bytes(data)
        kinds = ("static_code_pointer_slot",)
        recovery_ids = tuple(sorted(shared_recoveries))
        identity_core = {
            "rva_start": start,
            "rva_end": end,
            "section_index": left.section_index,
            "bytes_sha256": digest,
            "kinds": list(kinds),
            "recovery_ids": list(recovery_ids),
        }
        result.append(
            RecoveredExecutableDataRange(
                identity="recovered-executable-data:"
                + sha256_bytes(_canonical_bytes(identity_core))[:20],
                rva_start=start,
                rva_end=end,
                section_index=left.section_index,
                section_name=section.name,
                data=data,
                bytes_sha256=digest,
                kinds=kinds,
                recovery_ids=recovery_ids,
            )
        )
    return tuple(result)


def _recover_adjacent_alignment_padding(
    *,
    binary: StageABinary,
    data_ranges: Sequence[RecoveredExecutableDataRange],
    protected_code_rvas: set[int],
) -> tuple[RecoveredExecutableDataRange, ...]:
    """Recover bounded semantic no-ops adjoining checked immutable data.

    Compilers commonly align a jump table or the code following it with NOPs.
    Adjacency to a separately checked immutable range provides the structural
    anchor; exact IA-32 decoding provides the content check.  The caller still
    rejects roots and control targets into the resulting range, so a no-op at
    a genuine entry point cannot silently become padding.

    Only one conventional 16-byte alignment gap is considered.  Longer runs,
    non-identity instructions, and bytes between data ranges that do not
    decode wholly as no-ops remain unclassified.
    """

    if not data_ranges:
        return ()

    ordered = sorted(data_ranges, key=lambda item: item.rva_start)
    proposals: list[tuple[int, int, set[str]]] = []
    for index, item in enumerate(ordered):
        section = binary.sections[item.section_index]
        initialized_end = min(
            section.rva_end, section.rva_start + section.raw_size
        )
        previous_end = section.rva_start
        if index > 0 and ordered[index - 1].section_index == item.section_index:
            previous_end = ordered[index - 1].rva_end
        next_start = initialized_end
        if (
            index + 1 < len(ordered)
            and ordered[index + 1].section_index == item.section_index
        ):
            next_start = ordered[index + 1].rva_start

        left_start = _bounded_noop_suffix_start(
            binary=binary,
            start=previous_end,
            end=item.rva_start,
        )
        if left_start is not None:
            if not any(
                left_start <= target < item.rva_start
                for target in protected_code_rvas
            ):
                proposals.append(
                    (left_start, item.rva_start, set(item.recovery_ids))
                )

        right_end = _bounded_noop_prefix_end(
            binary=binary,
            start=item.rva_end,
            end=next_start,
        )
        if right_end is not None:
            if not any(
                item.rva_end <= target < right_end
                for target in protected_code_rvas
            ):
                proposals.append((item.rva_end, right_end, set(item.recovery_ids)))

    normalized: list[tuple[int, int, set[str]]] = []
    for start, end, recovery_ids in sorted(proposals):
        if not normalized or start >= normalized[-1][1]:
            normalized.append((start, end, set(recovery_ids)))
            continue
        previous_start, previous_end, previous_ids = normalized.pop()
        merged_start = min(previous_start, start)
        merged_end = max(previous_end, end)
        if (
            merged_end - merged_start <= _MAX_ALIGNMENT_PADDING_BYTES
            and _is_exact_semantic_noop_span(
                binary=binary, start=merged_start, end=merged_end
            )
        ):
            normalized.append(
                (
                    merged_start,
                    merged_end,
                    previous_ids | recovery_ids,
                )
            )
        # Overlapping proposals wider than one alignment gap are ambiguous;
        # neither proposal is retained.

    result: list[RecoveredExecutableDataRange] = []
    for start, end, recovery_ids in normalized:
        section_matches = [
            (section_index, section)
            for section_index, section in enumerate(binary.sections)
            if section.rva_start <= start and end <= section.rva_end
        ]
        if len(section_matches) != 1:
            continue
        section_index, section = section_matches[0]
        initialized_end = min(
            section.rva_end, section.rva_start + section.raw_size
        )
        if (
            not section.executable
            or not section.readable
            or section.writable
            or end > initialized_end
        ):
            continue
        data = bytes(binary.pe.get_data(start, end - start))
        if len(data) != end - start:
            continue
        digest = sha256_bytes(data)
        kinds = ("alignment_padding",)
        bound_recovery_ids = tuple(sorted(recovery_ids))
        identity_core = {
            "rva_start": start,
            "rva_end": end,
            "section_index": section_index,
            "bytes_sha256": digest,
            "kinds": list(kinds),
            "recovery_ids": list(bound_recovery_ids),
        }
        result.append(
            RecoveredExecutableDataRange(
                identity="recovered-executable-data:"
                + sha256_bytes(_canonical_bytes(identity_core))[:20],
                rva_start=start,
                rva_end=end,
                section_index=section_index,
                section_name=section.name,
                data=data,
                bytes_sha256=digest,
                kinds=kinds,
                recovery_ids=bound_recovery_ids,
            )
        )
    return tuple(result)


def _bounded_noop_suffix_start(
    *, binary: StageABinary, start: int, end: int
) -> int | None:
    scan_start = max(start, end - 2 * _MAX_ALIGNMENT_PADDING_BYTES)
    for candidate in range(scan_start, end):
        if _is_exact_semantic_noop_span(binary=binary, start=candidate, end=end):
            return (
                candidate
                if end - candidate <= _MAX_ALIGNMENT_PADDING_BYTES
                else None
            )
    return None


def _bounded_noop_prefix_end(
    *, binary: StageABinary, start: int, end: int
) -> int | None:
    scan_end = min(end, start + 2 * _MAX_ALIGNMENT_PADDING_BYTES)
    data = bytes(binary.pe.get_data(start, scan_end - start))
    if not data:
        return None
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    cursor = start
    try:
        for instruction in decoder.disasm(data, binary.image_base + start):
            if instruction.address != binary.image_base + cursor:
                break
            if not _is_semantic_noop(instruction):
                break
            cursor += instruction.size
    except capstone.CsError:
        return None
    size = cursor - start
    return cursor if 0 < size <= _MAX_ALIGNMENT_PADDING_BYTES else None


def _is_exact_semantic_noop_span(
    *, binary: StageABinary, start: int, end: int
) -> bool:
    if end <= start:
        return False
    data = bytes(binary.pe.get_data(start, end - start))
    if len(data) != end - start:
        return False
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    try:
        instructions = list(decoder.disasm(data, binary.image_base + start))
    except capstone.CsError:
        return False
    if (
        not instructions
        or sum(instruction.size for instruction in instructions) != len(data)
    ):
        return False
    return all(_is_semantic_noop(instruction) for instruction in instructions)


def _is_semantic_noop(instruction: capstone.CsInsn) -> bool:
    if instruction.id == capstone.x86_const.X86_INS_NOP:
        return True
    if instruction.id != capstone.x86_const.X86_INS_MOV:
        return False
    if any(
        prefix
        not in {
            0,
            0x26,
            0x2E,
            0x36,
            0x3E,
            0x64,
            0x65,
            0x66,
            0x67,
        }
        for prefix in instruction.prefix
    ):
        return False
    operands = instruction.operands
    return (
        len(operands) == 2
        and operands[0].type == X86_OP_REG
        and operands[1].type == X86_OP_REG
        and operands[0].reg == operands[1].reg
        and operands[0].size == operands[1].size
    )


def _ranges_from_classification(
    binary: StageABinary,
    rows: Sequence[Mapping[str, Any]],
) -> tuple[RecoveredExecutableDataRange, ...]:
    ranges: list[RecoveredExecutableDataRange] = []
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            raise RecoveredExecutableDataError(
                "classified executable-data range is not an object"
            )
        expected = {
            "id",
            "rva_start",
            "rva_end",
            "size",
            "section_index",
            "section_name",
            "bytes_sha256",
            "kinds",
            "recovery_ids",
        }
        if set(row) != expected:
            raise RecoveredExecutableDataError(
                "classified executable-data range has noncanonical fields"
            )
        start = _u32(row.get("rva_start"), f"classified range {index} start")
        end = _u32(row.get("rva_end"), f"classified range {index} end")
        if end <= start or row.get("size") != end - start:
            raise RecoveredExecutableDataError(
                f"classified range {index} has an invalid span"
            )
        data = bytes(binary.pe.get_data(start, end - start))
        digest = _sha256(
            row.get("bytes_sha256"), f"classified range {index} byte hash"
        )
        if len(data) != end - start or sha256_bytes(data) != digest:
            raise RecoveredExecutableDataError(
                f"classified range {index} no longer matches the original PE"
            )
        ranges.append(
            RecoveredExecutableDataRange(
                identity=str(row.get("id")),
                rva_start=start,
                rva_end=end,
                section_index=_u32(
                    row.get("section_index"),
                    f"classified range {index} section index",
                ),
                section_name=str(row.get("section_name")),
                data=data,
                bytes_sha256=digest,
                kinds=_strings(row.get("kinds"), f"classified range {index} kinds"),
                recovery_ids=_strings(
                    row.get("recovery_ids"),
                    f"classified range {index} recovery IDs",
                ),
            )
        )
    for item in ranges:
        # Reuse the canonical parser to check identity and field invariants.
        RecoveredExecutableDataRange.parse(
            item.to_payload(), label=f"classified range {item.identity}"
        )
    if ranges != sorted(ranges, key=lambda item: item.rva_start):
        raise RecoveredExecutableDataError(
            "classified executable-data ranges are not sorted"
        )
    for previous, current in zip(ranges, ranges[1:]):
        if current.rva_start < previous.rva_end:
            raise RecoveredExecutableDataError(
                "classified executable-data ranges overlap"
            )
    return tuple(ranges)


def _merge_recovered_ranges(
    *inventories: Sequence[RecoveredExecutableDataRange],
) -> tuple[RecoveredExecutableDataRange, ...]:
    aggregates: dict[tuple[int, int], dict[str, Any]] = {}
    for item in (item for inventory in inventories for item in inventory):
        key = (item.rva_start, item.rva_end)
        aggregate = aggregates.setdefault(
            key,
            {
                "section_index": item.section_index,
                "section_name": item.section_name,
                "data": item.data,
                "bytes_sha256": item.bytes_sha256,
                "kinds": set(),
                "recovery_ids": set(),
            },
        )
        if any(
            aggregate[field] != getattr(item, field)
            for field in (
                "section_index",
                "section_name",
                "data",
                "bytes_sha256",
            )
        ):
            raise RecoveredExecutableDataError(
                "duplicate recovered executable-data range disagrees"
            )
        aggregate["kinds"].update(item.kinds)
        aggregate["recovery_ids"].update(item.recovery_ids)

    result: list[RecoveredExecutableDataRange] = []
    for (start, end), aggregate in sorted(aggregates.items()):
        kinds = tuple(sorted(aggregate["kinds"]))
        recovery_ids = tuple(sorted(aggregate["recovery_ids"]))
        identity_core = {
            "rva_start": start,
            "rva_end": end,
            "section_index": aggregate["section_index"],
            "bytes_sha256": aggregate["bytes_sha256"],
            "kinds": list(kinds),
            "recovery_ids": list(recovery_ids),
        }
        result.append(
            RecoveredExecutableDataRange(
                identity="recovered-executable-data:"
                + sha256_bytes(_canonical_bytes(identity_core))[:20],
                rva_start=start,
                rva_end=end,
                section_index=aggregate["section_index"],
                section_name=aggregate["section_name"],
                data=aggregate["data"],
                bytes_sha256=aggregate["bytes_sha256"],
                kinds=kinds,
                recovery_ids=recovery_ids,
            )
        )
    for previous, current in zip(result, result[1:]):
        if current.rva_start < previous.rva_end:
            raise RecoveredExecutableDataError(
                "distinct recovered executable-data ranges overlap"
            )
    return tuple(result)


def load_recovered_executable_data_contract(
    path: Path | str,
) -> RecoveredExecutableDataContract:
    source = Path(path)
    try:
        value = json.loads(source.read_text(encoding="ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RecoveredExecutableDataError(
            f"cannot read recovered executable-data contract: {exc}"
        ) from exc
    if not isinstance(value, Mapping):
        raise RecoveredExecutableDataError(
            "recovered executable-data contract must be an object"
        )
    return RecoveredExecutableDataContract.parse(value)


__all__ = [
    "RECOVERED_EXECUTABLE_DATA_FILENAME",
    "RECOVERED_EXECUTABLE_DATA_FORMAT",
    "RecoveredExecutableDataContract",
    "RecoveredExecutableDataError",
    "RecoveredExecutableDataRange",
    "build_recovered_executable_data_contract",
    "load_recovered_executable_data_contract",
    "recover_executable_data_ranges",
]

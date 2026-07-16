from __future__ import annotations

from pathlib import Path
from typing import Any

from ...stage_binary import StageABinary, StageAInputError
from ..contract import _raw_base_relocations


def _lean_code_aliases(target: dict[str, Any], side: str) -> str:
    aliases = target.get(f"{side}_aliases", [])
    indices = target.get(f"{side}_alias_padding_indices", [])
    if len(aliases) != len(indices):
        raise StageAInputError(
            f"{side} alias padding certificate length does not match target {target.get('id')}"
        )
    rows = ", ".join(
        f"{{ rva := {alias}, paddingIndex := {padding_index} }}"
        for alias, padding_index in zip(aliases, indices, strict=True)
    )
    return f"[{rows}]"

def _lean_register_pair(pair: dict[str, str]) -> str:
    return f"{{ original := .{pair['original']}, candidate := .{pair['candidate']} }}"

def _lean_relation_constructor(relation: str | None) -> str:
    source_relation = relation
    relation = {
        "exact": "exact",
        "code_pointer": "codePointer",
        "data_pointer": "dataPointer",
        "related_word": "relatedWord",
    }.get(relation)
    if relation is None:
        raise StageAInputError(
            f"unsupported register relation kind {source_relation!r}"
        )
    return relation

def _lean_register_relation_pair(pair: dict[str, Any]) -> str:
    relation_name = pair.get("relation")
    if relation_name == "fixed_code_pointer":
        target_id = pair.get("target_id")
        if (
            not isinstance(target_id, int)
            or isinstance(target_id, bool)
            or target_id < 0
        ):
            raise StageAInputError(
                "fixed_code_pointer register relation requires a nonnegative target_id"
            )
        relation = f"fixedCodePointer {target_id}"
    else:
        if "target_id" in pair:
            raise StageAInputError(
                f"register relation {relation_name!r} does not accept target_id"
            )
        relation = _lean_relation_constructor(relation_name)
    return (
        f"{{ original := .{pair['original']}, candidate := .{pair['candidate']}, "
        f"relation := .{relation} }}"
    )

def _required_input_pairs(regions: list[dict[str, Any]]) -> list[dict[str, str]]:
    return _required_input_pairs_from([], regions)

def _required_input_pairs_from(
    initial: list[dict[str, str]],
    regions: list[dict[str, Any]],
) -> list[dict[str, str]]:
    required = list(initial)
    seen = {(pair["original"], pair["candidate"]) for pair in required}
    for region in regions:
        for pair in region["inputs"]:
            key = (pair["original"], pair["candidate"])
            if key not in seen:
                seen.add(key)
                # Match Lean's insertRegisterPair, which prepends each first occurrence.
                required.insert(0, pair)
    return required

def _lean_span(span: dict[str, Any]) -> str:
    return f"{{ start := {span['rva_start']}, size := {span['size']} }}"

def _side_padding(contract: dict[str, Any], side: str) -> list[dict[str, Any]]:
    return [
        span for span in contract["padding"]
        if span["side"] in {side, "both"}
    ]

def _side_coverage_spans(contract: dict[str, Any], side: str) -> list[dict[str, Any]]:
    return [region[side] for region in contract["regions"]] + _side_padding(contract, side)

def _sorted_span_certificate(spans: list[dict[str, Any]]) -> dict[str, Any]:
    ordered = sorted(
        enumerate(spans),
        key=lambda item: (item[1]["rva_start"], item[1]["size"], item[0]),
    )
    source_to_sorted = [0] * len(spans)
    for ordinal, (source_index, _) in enumerate(ordered):
        source_to_sorted[source_index] = ordinal
    return {
        "sorted": [span for _, span in ordered],
        "sorted_source_indices": [source_index for source_index, _ in ordered],
        "source_to_sorted": source_to_sorted,
        "source": spans,
    }

def _lean_sorted_span_certificate(spans: list[dict[str, Any]]) -> str:
    certificate = _sorted_span_certificate(spans)
    sorted_spans = ", ".join(_lean_span(span) for span in certificate["sorted"])
    sorted_indices = ", ".join(str(index) for index in certificate["sorted_source_indices"])
    return (
        f"{{ sorted := [{sorted_spans}], "
        f"sourceIndex := {_lean_index_tree([_lean_span(span) for span in certificate['source']])}, "
        f"sortedSourceIndices := [{sorted_indices}], "
        f"sourceToSorted := {_lean_index_tree([str(index) for index in certificate['source_to_sorted']])} }}"
    )

def _lean_padding_alias_certificate(spans: list[dict[str, Any]]) -> str:
    certificate = _sorted_span_certificate(spans)
    run_stops = [0] * len(spans)
    next_start: int | None = None
    next_run_stop: int | None = None
    for source_index, span in reversed(
        list(zip(certificate["sorted_source_indices"], certificate["sorted"], strict=True))
    ):
        stop = span["rva_start"] + span["size"]
        run_stop = next_run_stop if next_start == stop else stop
        run_stops[source_index] = run_stop
        next_start = span["rva_start"]
        next_run_stop = run_stop
    return (
        f"{{ sorted := {_lean_sorted_span_certificate(spans)}, "
        f"runStops := {_lean_index_tree([str(stop) for stop in run_stops])} }}"
    )

def _lean_index_tree(items: list[str]) -> str:
    if not items:
        return ".empty"
    if len(items) == 1:
        return f".leaf ({items[0]})"
    midpoint = len(items) // 2
    return (
        f".node {midpoint} ({_lean_index_tree(items[:midpoint])}) "
        f"({_lean_index_tree(items[midpoint:])})"
    )

def _lean_index_tree_join(items: list[tuple[str, int]]) -> str:
    if not items:
        return ".empty"
    if len(items) == 1:
        return items[0][0]
    midpoint = len(items) // 2
    left = items[:midpoint]
    right = items[midpoint:]
    return (
        f".node {sum(size for _, size in left)} "
        f"({_lean_index_tree_join(left)}) ({_lean_index_tree_join(right)})"
    )

def _lean_right_append(names: list[str]) -> str:
    if not names:
        return "[]"
    if len(names) == 1:
        return names[0]
    return f"{names[0]} ++ ({_lean_right_append(names[1:])})"

def _lean_all_append_proof(
    predicate: str,
    chunks: list[str],
    facts: list[str],
) -> str:
    if len(chunks) != len(facts) or not chunks:
        raise ValueError("chunk and fact lists must be non-empty and equal length")
    if len(chunks) == 1:
        return facts[0]
    return (
        f"listAllAppendTrue ({predicate}) {chunks[0]} "
        f"({_lean_right_append(chunks[1:])}) {facts[0]} "
        f"({_lean_all_append_proof(predicate, chunks[1:], facts[1:])})"
    )

def _lean_direct_append_proof(chunks: list[str], facts: list[str]) -> str:
    if len(chunks) != len(facts) or not chunks:
        raise ValueError("chunk and fact lists must be non-empty and equal length")
    if len(chunks) == 1:
        return facts[0]
    return (
        "allDirectRegionGoals_append originalPe candidatePe originalImports candidateImports machineImportCallContracts "
        f"{chunks[0]} ({_lean_right_append(chunks[1:])}) {facts[0]} "
        f"({_lean_direct_append_proof(chunks[1:], facts[1:])})"
    )

def _lean_bool(value: bool) -> str:
    return "true" if value else "false"

def _lean_bytes(data: bytes) -> str:
    rows = [", ".join(str(byte) for byte in data[offset : offset + 32]) for offset in range(0, len(data), 32)]
    return "[\n  " + ",\n  ".join(rows) + "\n]"

def _lean_byte_tree_definitions(name: str, data: bytes, *, chunk_size: int = 1024) -> str:
    chunks = [data[offset : offset + chunk_size] for offset in range(0, len(data), chunk_size)]
    definitions = [
        f"def {name}Chunk{index} : Bytes := {_lean_bytes(chunk)}"
        for index, chunk in enumerate(chunks)
    ]
    trees = [
        (len(chunk), f"(.leaf {name}Chunk{index})")
        for index, chunk in enumerate(chunks)
    ]
    if not trees:
        definitions.append(f"def {name} : ByteTree := .empty")
        return "\n\n".join(definitions)
    while len(trees) > 1:
        merged: list[tuple[int, str]] = []
        for index in range(0, len(trees), 2):
            if index + 1 == len(trees):
                merged.append(trees[index])
                continue
            left_size, left = trees[index]
            right_size, right = trees[index + 1]
            merged.append((
                left_size + right_size,
                f"(.node {left_size + right_size} {left_size} {left} {right})",
            ))
        trees = merged
    definitions.append(f"def {name} : ByteTree := {trees[0][1]}")
    return "\n\n".join(definitions)

def _lean_import_certificate(binary: StageABinary) -> str:
    def bytes_literal(value: bytes) -> str:
        return "[" + ", ".join(str(byte) for byte in value) + "]"

    descriptors: list[str] = []
    import_directory_rva = int(binary.pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress)
    for descriptor_index, entry in enumerate(getattr(binary.pe, "DIRECTORY_ENTRY_IMPORT", []) or []):
        dll = bytes(entry.dll) if isinstance(entry.dll, bytes) else str(entry.dll).encode()
        original_first_thunk = int(entry.struct.OriginalFirstThunk)
        first_thunk = int(entry.struct.FirstThunk)
        lookup_rva = original_first_thunk or first_thunk
        thunks: list[str] = []
        for thunk_index, imported in enumerate(entry.imports):
            if imported.name is not None:
                raw_name = bytes(imported.name) if isinstance(imported.name, bytes) else str(imported.name).encode()
                name = f"(.symbol {bytes_literal(raw_name)})"
                name_rva = int(imported.hint_name_table_rva)
            else:
                name = f"(.ordinal {int(imported.ordinal)})"
                name_rva = 0
            iat_rva = int(imported.address - binary.image_base)
            imported_literal = f"{{ dll := {bytes_literal(dll)}, name := {name}, iatRva := {iat_rva} }}"
            thunks.append(
                "{ lookupRva := " + str(lookup_rva + thunk_index * 4)
                + ", iatRva := " + str(iat_rva)
                + ", nameRva := " + str(name_rva)
                + ", imported := " + imported_literal + " }"
            )
        descriptors.append(
            "{ descriptorRva := " + str(import_directory_rva + descriptor_index * 20)
            + ", lookupRva := " + str(lookup_rva)
            + ", firstThunk := " + str(first_thunk)
            + ", nameRva := " + str(int(entry.struct.Name))
            + ", dll := " + bytes_literal(dll)
            + ", thunks := [" + ", ".join(thunks) + "] }"
        )
    return "{ descriptors := [" + ", ".join(descriptors) + "] }"

def _lean_relocations(binary: StageABinary) -> str:
    relocations = [
        f"{{ rva := {relocation['rva']}, kind := 3 }}"
        for relocation in _raw_base_relocations(binary)
        if relocation["type"] == 3
    ]
    return "[" + ", ".join(relocations) + "]"

def _lean_pe(binary: StageABinary, byte_tree_name: str) -> str:
    pe = binary.pe
    imports = pe.OPTIONAL_HEADER.DATA_DIRECTORY[1]
    relocations = pe.OPTIONAL_HEADER.DATA_DIRECTORY[5]
    sections = ", ".join(
        "{ virtualSize := " + str(int(section.Misc_VirtualSize))
        + ", virtualAddress := " + str(int(section.VirtualAddress))
        + ", rawSize := " + str(int(section.SizeOfRawData))
        + ", rawPointer := " + str(int(section.PointerToRawData))
        + ", characteristics := " + str(int(section.Characteristics)) + " }"
        for section in pe.sections
    )
    return (
        "{ bytes := " + byte_tree_name
        + ", peOffset := " + str(int(pe.DOS_HEADER.e_lfanew))
        + ", entrypointRva := " + str(binary.entrypoint_rva)
        + ", imageBase := " + str(binary.image_base)
        + ", sectionAlignment := " + str(int(pe.OPTIONAL_HEADER.SectionAlignment))
        + ", fileAlignment := " + str(int(pe.OPTIONAL_HEADER.FileAlignment))
        + ", sizeOfImage := " + str(binary.size_of_image)
        + ", sizeOfHeaders := " + str(binary.size_of_headers)
        + ", importDirectoryRva := " + str(int(imports.VirtualAddress))
        + ", importDirectorySize := " + str(int(imports.Size))
        + ", tlsDirectoryRva := " + str(binary.tls_directory_rva)
        + ", tlsDirectorySize := " + str(binary.tls_directory_size)
        + ", relocationDirectoryRva := " + str(int(relocations.VirtualAddress))
        + ", relocationDirectorySize := " + str(int(relocations.Size))
        + ", sections := [" + sections + "] }"
    )

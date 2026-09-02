"""Independent veto-only replay for ``linked-semantic-module-v2``.

Replay checks that the published may universe contains the root-and-relocation
closure declared by its packaged semantic object. It deliberately performs no
value/provenance fixed point and never grants execution authority.
"""

from __future__ import annotations

from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..util import sha256_file, write_json
from .formats import LINKED_SEMANTIC_MODULE_REPLAY_FORMAT
from .may_link import MAY_LINK_ALGORITHM_V1
from .module_v2_codec import LinkedSemanticModuleV2


class LinkedSemanticModuleReplayError(ValueError):
    """The linked module disagrees with its independently replayed graph."""


def _fail(message: str) -> None:
    raise LinkedSemanticModuleReplayError(message)


def _mapping(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(f"{context} must be an object")
    return value


def _verify_linked_semantic_module_v2(
    *, linked_semantic_module: Path,
) -> LinkedSemanticModuleV2:
    linked = LinkedSemanticModuleV2.load(linked_semantic_module)
    semantic = linked.semantic_object
    if semantic is None or semantic.package_root is None:
        _fail("linked-module V2 replay requires a packaged semantic object")
    payload = linked.payload
    if payload["link_provenance"].get("algorithm") != MAY_LINK_ALGORITHM_V1:
        _fail("linked-module V2 uses an unsupported may-link algorithm")

    active = {
        str(row["symbol_id"]): row for row in payload["active_symbols"]
    }
    semantic_symbols = {
        str(row["symbol_id"]): row for row in semantic.payload["symbols"]
    }
    transfer_by_rva = {
        int(semantic_symbols[str(definition["symbol_id"])]["original_rva"]):
        str(definition["symbol_id"])
        for definition in semantic.payload["definitions"]
        if definition.get("definition_kind") == "transfer_v2"
    }
    outgoing: dict[str, set[str]] = defaultdict(set)
    for raw in semantic.payload["relocations"]:
        relocation = _mapping(raw, "semantic relocation")
        source = relocation.get("source_symbol")
        target = relocation.get("target_symbol")
        if not isinstance(target, str):
            rva = relocation.get("target_rva")
            target = (
                transfer_by_rva.get(rva)
                if isinstance(rva, int) and not isinstance(rva, bool)
                else None
            )
        if isinstance(source, str) and isinstance(target, str):
            outgoing[source].add(target)
    effect_index = _mapping(
        semantic.payload.get("effect_index"), "semantic effect index"
    )
    for raw in effect_index["runtime_primitive_dependencies"]:
        dependency = _mapping(raw, "runtime-primitive dependency")
        target = dependency.get("target_symbol")
        sources = dependency.get("source_symbols")
        if not isinstance(target, str) or not isinstance(sources, list):
            _fail("runtime-primitive dependency is malformed")
        for source in sources:
            if not isinstance(source, str):
                _fail("runtime-primitive dependency source is malformed")
            outgoing[source].add(target)

    expected: set[str] = set()
    pending: deque[str] = deque()
    for raw in semantic.payload["roots"]:
        root = _mapping(raw, "semantic root")
        if root.get("kind") in {"data_export", "forwarder"}:
            continue
        target = root.get("target_symbol")
        if not isinstance(target, str):
            # The canonical module remains incomplete for this root. Its
            # absence cannot justify inventing an executable graph node.
            continue
        if target not in expected:
            expected.add(target)
            pending.append(target)
    while pending:
        source = pending.popleft()
        for target in outgoing.get(source, ()):
            if target not in expected:
                expected.add(target)
                pending.append(target)
    missing = sorted(expected - set(active))
    if missing:
        _fail("linked-module V2 omitted root-reachable semantic symbols")

    if payload["may_reach"]["widened_by_dynamic_dispatch"]:
        expected_transfers = set(transfer_by_rva.values())
        if not expected_transfers <= set(active):
            _fail("linked-module V2 dynamic domain omits transfer entries")

    active_relocations = {
        str(row["relocation_id"]): row
        for row in payload["active_relocations"]
    }
    for raw in semantic.payload["relocations"]:
        relocation = _mapping(raw, "semantic relocation")
        source = relocation.get("source_symbol")
        target = relocation.get("target_symbol")
        if not isinstance(target, str):
            rva = relocation.get("target_rva")
            target = (
                transfer_by_rva.get(rva)
                if isinstance(rva, int) and not isinstance(rva, bool)
                else None
            )
        if (
            isinstance(source, str) and source in expected
            and isinstance(target, str) and target in expected
            and relocation.get("kind") in {"direct_control", "internal_call"}
            and str(relocation["relocation_id"]) not in active_relocations
        ):
            _fail("linked-module V2 omitted a root-reachable direct edge")
    return linked


def verify_linked_semantic_module_v2(
    *, linked_semantic_module: Path,
) -> LinkedSemanticModuleV2:
    return _verify_linked_semantic_module_v2(
        linked_semantic_module=linked_semantic_module,
    )


def write_linked_semantic_module_replay_receipt_v2(
    *, linked_semantic_module: Path, out: Path,
) -> dict[str, Any]:
    """Independently replay one link and emit a veto-only bound receipt."""

    linked = _verify_linked_semantic_module_v2(
        linked_semantic_module=linked_semantic_module,
    )
    core = {
        "format": LINKED_SEMANTIC_MODULE_REPLAY_FORMAT,
        "status": "complete",
        "authority": "none",
        "linked_semantic_module_sha256": linked.identity,
        "semantic_object_file_sha256": sha256_file(
            linked.require_member("semantic_object")
        ),
        "link_algorithm": MAY_LINK_ALGORITHM_V1,
    }
    receipt = {**core, "replay_sha256": canonical_sha256_v3(core)}
    write_json(out, receipt)
    return receipt


__all__ = [
    "LinkedSemanticModuleReplayError", "verify_linked_semantic_module_v2",
    "write_linked_semantic_module_replay_receipt_v2",
]

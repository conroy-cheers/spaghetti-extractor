#!/usr/bin/env python3
"""Assemble generated Lean sources without importing proof-generation code.

This command is intentionally stdlib-only. Proof-source aggregation and pack
scheduling are cache policy, so changing them must not invalidate static
extraction or semantic source generation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import Any, Mapping


DIRECT_CALL_NODE_FAMILY = re.compile(
    r"^GeneratedRelationalInternalDirectCallSummaryNode([0-9a-f]{64}).*$"
)
# A direct-call family is one semantic certificate unit. Keeping the complete
# family in one derivation avoids a large dynamic CA graph while Lean still
# compiles its modules sequentially in checked topological order. Exceptionally
# large generated families retain deterministic level-based sharding.
DIRECT_CALL_BUILD_PACK_MAX_MODULES = 128
DIRECT_CALL_BUILD_PACK_SPLIT_THRESHOLD = 128
# Keep ordinary packs small enough that independent modules exploit the remote
# builder's job budget. High-memory modules remain isolated below, so this
# concurrency does not multiply their declared 8-12 GiB working sets.
COARSE_BUILD_PACK_MAX_MODULES = 32
COARSE_BUILD_PACK_BUCKETS = 8
# Build packs compile their modules sequentially, but Nix cannot publish or
# reuse any result until the entire pack finishes.  Bound cumulative declared
# work as well as module count so medium semantic certificates reach the store
# frequently enough for useful incremental caching.
COARSE_BUILD_PACK_MAX_ESTIMATED_MEMORY_MB = 16 * 1024
# This worker is intentionally stdlib-only and cannot import the package
# constant without widening its Nix invalidation boundary.
RELATIONAL_PHASE_FORMAT = "stage-a-relational-phase-v1"


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def direct_call_family_levels(
    family_id: str,
    modules: list[str],
    imports: Mapping[str, set[str]],
) -> dict[str, int]:
    members = set(modules)
    levels: dict[str, int] = {}
    active: set[str] = set()

    def visit(module: str) -> int:
        if module in levels:
            return levels[module]
        if module in active:
            raise ValueError(
                f"Lean build pack direct-call-{family_id} contains an "
                f"import cycle at {module}"
            )
        active.add(module)
        level = 1 + max(
            (visit(dependency) for dependency in imports[module] & members),
            default=-1,
        )
        active.remove(module)
        levels[module] = level
        return level

    for module in sorted(modules):
        visit(module)
    return levels


def proof_build_pack_ids(
    modules: list[str],
    imports: Mapping[str, set[str]],
) -> dict[str, str]:
    result: dict[str, str] = {}
    direct_call_families: dict[str, list[str]] = {}
    for module in modules:
        family = DIRECT_CALL_NODE_FAMILY.match(module)
        if family is not None:
            direct_call_families.setdefault(family.group(1), []).append(module)
            continue
        result[module] = module
    for family_id, family_modules in sorted(direct_call_families.items()):
        base_pack_id = f"direct-call-{family_id}"
        if len(family_modules) <= DIRECT_CALL_BUILD_PACK_SPLIT_THRESHOLD:
            for module in family_modules:
                result[module] = base_pack_id
            continue
        levels = direct_call_family_levels(
            family_id,
            family_modules,
            imports,
        )
        modules_by_level: dict[int, list[str]] = {}
        for module, level in levels.items():
            modules_by_level.setdefault(level, []).append(module)
        for level, level_modules in sorted(modules_by_level.items()):
            for offset in range(
                0,
                len(level_modules),
                DIRECT_CALL_BUILD_PACK_MAX_MODULES,
            ):
                pack_id = (
                    f"{base_pack_id}-layer-{level:02d}-part-"
                    f"{offset // DIRECT_CALL_BUILD_PACK_MAX_MODULES:04d}"
                )
                for module in sorted(level_modules)[
                    offset:offset + DIRECT_CALL_BUILD_PACK_MAX_MODULES
                ]:
                    result[module] = pack_id
    return result


def topological_build_pack(
    pack_id: str,
    modules: list[str],
    imports: Mapping[str, set[str]],
) -> list[str]:
    """Order one stable pack so its internal imports compile first."""

    members = set(modules)
    ordered: list[str] = []
    complete: set[str] = set()
    active: set[str] = set()

    def visit(module: str) -> None:
        if module in complete:
            return
        if module in active:
            raise ValueError(
                f"Lean build pack {pack_id} contains an import cycle at "
                f"{module}"
            )
        active.add(module)
        for dependency in sorted(imports[module] & members):
            visit(dependency)
        active.remove(module)
        complete.add(module)
        ordered.append(module)

    for module in sorted(modules):
        visit(module)
    return ordered


def coarse_build_pack_ids(
    modules: list[str],
    imports: Mapping[str, set[str]],
    base_pack_ids: Mapping[str, str],
    resources: Mapping[str, Mapping[str, object]],
) -> dict[str, str]:
    """Group independent base packs without changing checked import order."""

    base_packs: dict[str, list[str]] = {}
    for module in modules:
        base_packs.setdefault(base_pack_ids[module], []).append(module)
    dependencies = {
        pack_id: {
            base_pack_ids[dependency]
            for module in pack_modules
            for dependency in imports[module]
            if base_pack_ids[dependency] != pack_id
        }
        for pack_id, pack_modules in base_packs.items()
    }
    estimated_work = {
        pack_id: sum(
            int(resources[module]["estimated_memory_mb"])
            for module in pack_modules
        )
        for pack_id, pack_modules in base_packs.items()
    }
    levels: dict[str, int] = {}
    active: set[str] = set()

    def visit(pack_id: str) -> int:
        if pack_id in levels:
            return levels[pack_id]
        if pack_id in active:
            raise ValueError(
                f"Lean base build-pack graph contains a cycle at {pack_id}"
            )
        active.add(pack_id)
        level = 1 + max(
            (visit(dependency) for dependency in dependencies[pack_id]),
            default=-1,
        )
        active.remove(pack_id)
        levels[pack_id] = level
        return level

    for pack_id in sorted(base_packs):
        visit(pack_id)

    groups: dict[tuple[int, int], list[str]] = {}
    isolated: list[str] = []
    for pack_id, pack_modules in sorted(base_packs.items()):
        resource_classes = {
            str(resources[module]["resource_class"])
            for module in pack_modules
        }
        if resource_classes & {"large-memory", "high-memory"}:
            isolated.append(pack_id)
            continue
        bucket = (
            int(hashlib.sha256(pack_id.encode("ascii")).hexdigest()[:8], 16)
            % COARSE_BUILD_PACK_BUCKETS
        )
        groups.setdefault((levels[pack_id], bucket), []).append(pack_id)

    result: dict[str, str] = {}
    for pack_id in isolated:
        digest = hashlib.sha256(pack_id.encode("ascii")).hexdigest()[:16]
        coarse_id = f"coarse-isolated-{levels[pack_id]:02d}-{digest}"
        for module in base_packs[pack_id]:
            result[module] = coarse_id
    for (level, bucket), pack_ids in sorted(groups.items()):
        part: list[str] = []
        part_modules = 0
        part_estimated_work = 0

        def emit() -> None:
            nonlocal part, part_modules, part_estimated_work
            if not part:
                return
            digest = hashlib.sha256(
                "\n".join(part).encode("ascii")
            ).hexdigest()[:16]
            coarse_id = (
                f"coarse-level-{level:02d}-bucket-{bucket:02d}-{digest}"
            )
            for member in part:
                for module in base_packs[member]:
                    result[module] = coarse_id
            part = []
            part_modules = 0
            part_estimated_work = 0

        for pack_id in sorted(pack_ids):
            module_count = len(base_packs[pack_id])
            pack_estimated_work = estimated_work[pack_id]
            if (
                part
                and (
                    part_modules + module_count
                    > COARSE_BUILD_PACK_MAX_MODULES
                    or part_estimated_work + pack_estimated_work
                    > COARSE_BUILD_PACK_MAX_ESTIMATED_MEMORY_MB
                )
            ):
                emit()
            part.append(pack_id)
            part_modules += module_count
            part_estimated_work += pack_estimated_work
        emit()
    if set(result) != set(modules):
        raise ValueError("coarse Lean build-pack assignment is incomplete")
    return result


def default_resource(module: str) -> dict[str, object]:
    if module.startswith("GeneratedInterpreterX87Schedule"):
        return {"resource_class": "medium", "estimated_memory_mb": 4096}
    if module.startswith("GeneratedGnuHelloOriginalBytePack"):
        return {"resource_class": "medium", "estimated_memory_mb": 4096}
    if module in {
        "GeneratedGnuHelloOriginalPE",
        "GeneratedSemanticInterpreterProgram",
        "GeneratedRelationalInterpreterKernelBlockContext",
    }:
        return {"resource_class": "high-memory", "estimated_memory_mb": 8192}
    if module in {
        "GeneratedRelationalInterpreterMixedOriginalBase",
        "GeneratedRelationalInterpreterMixedOriginal",
    }:
        return {"resource_class": "high-memory", "estimated_memory_mb": 76800}
    if module == "GeneratedRelationalInterpreterOriginalCarrierBinding":
        return {"resource_class": "high-memory", "estimated_memory_mb": 16384}
    if (
        module.startswith("GeneratedInterpreterNormalization")
        or module.startswith("GeneratedInterpreterKernelData")
        or module.startswith("GeneratedInterpreterX87CandidateReplay")
        or module.startswith("GeneratedRelationalInterpreterKernelBlockShard")
    ):
        return {"resource_class": "medium", "estimated_memory_mb": 2048}
    return {"resource_class": "light", "estimated_memory_mb": 768}


def emit_precomputed_module_graph(
    out: Path,
    stage_a: Path,
    modules: list[str],
    module_imports: Mapping[str, set[str]],
    resources: Mapping[str, Mapping[str, object]],
    module_build_packs: Mapping[str, str],
    build_packs: Mapping[str, list[str]],
    targets: set[str],
) -> None:
    source_pack_data = out / "source-pack-data"
    module_metadata: dict[str, dict[str, object]] = {}
    for pack_id, pack_modules in sorted(build_packs.items()):
        if re.fullmatch(r"[A-Za-z0-9_.+-]+", pack_id) is None:
            raise ValueError(f"unsafe Lean build-pack id {pack_id!r}")
        pack_sources: dict[str, str] = {}
        for module in pack_modules:
            source = stage_a / f"{module}.lean"
            source_text = source.read_text(encoding="utf-8")
            pack_sources[module] = source_text
            module_metadata[module] = {
                "source": f"StageA/{module}.lean",
                "source_pack": pack_id,
                "source_sha256": hashlib.sha256(
                    source_text.encode("utf-8")
                ).hexdigest(),
                "imports": sorted(module_imports[module]),
            }
        source_pack_data.mkdir(parents=True, exist_ok=True)
        (source_pack_data / f"{pack_id}.json").write_text(
            json.dumps(
                {
                    "format": "stage-a-lean-source-pack-v1",
                    "id": pack_id,
                    "modules": pack_sources,
                },
                sort_keys=True,
                separators=(",", ":"),
            ) + "\n",
            encoding="utf-8",
        )

    dependencies = {
        pack_id: sorted({
            module_build_packs[dependency]
            for module in pack_modules
            for dependency in module_imports[module]
            if module_build_packs[dependency] != pack_id
        })
        for pack_id, pack_modules in build_packs.items()
    }
    semantic_ids: dict[str, str] = {}
    active: set[str] = set()

    def semantic_id(pack_id: str) -> str:
        if pack_id in semantic_ids:
            return semantic_ids[pack_id]
        if pack_id in active:
            raise ValueError(
                f"Lean build-pack graph contains a cycle at {pack_id}"
            )
        active.add(pack_id)
        pack_modules = build_packs[pack_id]
        source_sha256 = hashlib.sha256(
            ":".join(
                str(module_metadata[module]["source_sha256"])
                for module in pack_modules
            ).encode("ascii")
        ).hexdigest()
        payload = {
            "format": "stage-a-lean-semantic-node-id-v1",
            "recipe_version": "stage-a-lean-semantic-recipe-v1",
            "modules": pack_modules,
            "source_sha256": source_sha256,
            "dependencies": [
                {
                    "node": dependency,
                    "semantic_id": semantic_id(dependency),
                }
                for dependency in dependencies[pack_id]
            ],
        }
        active.remove(pack_id)
        result = hashlib.sha256(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
        ).hexdigest()
        semantic_ids[pack_id] = result
        return result

    resource_rank = {
        "light": 0,
        "medium": 1,
        "large-memory": 2,
        "high-memory": 3,
    }
    nodes = []
    for pack_id, pack_modules in sorted(build_packs.items()):
        resource_class = max(
            (
                str(resources[module]["resource_class"])
                for module in pack_modules
            ),
            key=resource_rank.__getitem__,
        )
        source_sha256 = hashlib.sha256(
            ":".join(
                str(module_metadata[module]["source_sha256"])
                for module in pack_modules
            ).encode("ascii")
        ).hexdigest()
        nodes.append({
            "id": pack_id,
            "modules": pack_modules,
            "dependencies": dependencies[pack_id],
            "resource_class": resource_class,
            "estimated_memory_mb": max(
                int(resources[module]["estimated_memory_mb"])
                for module in pack_modules
            ),
            "source_sha256": source_sha256,
            "semantic_id": semantic_id(pack_id),
            "dependency_semantic_ids": [
                semantic_id(dependency)
                for dependency in dependencies[pack_id]
            ],
            "semantic_recipe_version": "stage-a-lean-semantic-recipe-v1",
        })

    target_modules = sorted(targets)
    final_module = target_modules[0] if target_modules else modules[-1]
    graph = {
        "format": "stage-a-lean-module-graph-v1",
        "lean": {"trust": 0},
        "modules": module_metadata,
        "nodes": nodes,
        "final_node": module_build_packs[final_module],
        "root_module": final_module,
        "expected_final_theorem": "",
        "approved_axioms": [],
        "acceptance": {
            "status": "not-ready",
            "node_steps": [],
        },
    }
    write_json(out / "module-graph.json", graph)


def aggregate(args: argparse.Namespace) -> None:
    out = Path(args.out)
    stage_a = out / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    sources = [Path(path) for path in args.source]
    declared_resources: dict[str, dict[str, object]] = {}
    for source_root in sources:
        for source in sorted(source_root.rglob("*.lean")):
            destination = stage_a / source.name
            if destination.exists():
                if destination.read_bytes() != source.read_bytes():
                    raise ValueError(f"conflicting Lean module {source.stem}")
                continue
            shutil.copyfile(source, destination)
        resource_manifest = source_root / "module-resources.json"
        if resource_manifest.is_file():
            payload = json.loads(resource_manifest.read_text(encoding="utf-8"))
            if not isinstance(payload, Mapping):
                raise ValueError(
                    "module resource manifest is not an object: "
                    f"{resource_manifest}"
                )
            for module, resource in payload.items():
                if not isinstance(module, str) or not isinstance(resource, Mapping):
                    raise ValueError(
                        f"malformed module resource entry in {resource_manifest}"
                    )
                normalized = dict(resource)
                prior = declared_resources.get(module)
                if prior is not None and prior != normalized:
                    raise ValueError(
                        f"conflicting resource metadata for Lean module {module}"
                    )
                declared_resources[module] = normalized

    modules = sorted(path.stem for path in stage_a.glob("*.lean"))
    module_set = set(modules)
    targets: set[str] = set()
    if not args.explicit_targets_only:
        for source_root in sources:
            manifest = source_root / "phase-manifest.json"
            if not manifest.is_file():
                continue
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            targets.update(payload.get("targets", []))
    targets.update(args.target)
    missing_targets = sorted(targets - module_set)
    if missing_targets:
        raise ValueError(f"generated proof targets are absent: {missing_targets}")

    if args.target_closure_only:
        if not targets:
            raise ValueError(
                "target-closure-only aggregation requires at least one target"
            )
        closure: set[str] = set()
        pending = list(targets)
        while pending:
            module = pending.pop()
            if module in closure:
                continue
            closure.add(module)
            source = stage_a / f"{module}.lean"
            imports = re.findall(
                r"^import StageA\.([A-Za-z0-9_]+)$",
                source.read_text(encoding="utf-8"),
                re.MULTILINE,
            )
            missing_imports = sorted(set(imports) - module_set)
            if missing_imports:
                raise ValueError(
                    f"generated proof target closure for {module} has "
                    f"missing imports {missing_imports}"
                )
            pending.extend(imports)
        for module in module_set - closure:
            (stage_a / f"{module}.lean").unlink()
        modules = sorted(closure)

    resources = {
        module: declared_resources.get(module, default_resource(module))
        for module in modules
    }
    module_imports = {
        module: set(
            re.findall(
                r"^import StageA\.([A-Za-z0-9_]+)$",
                (stage_a / f"{module}.lean").read_text(encoding="utf-8"),
                re.MULTILINE,
            )
        )
        for module in modules
    }
    module_build_packs = proof_build_pack_ids(modules, module_imports)
    if args.coarse_build_packs:
        module_build_packs = coarse_build_pack_ids(
            modules,
            module_imports,
            module_build_packs,
            resources,
        )
    build_packs: dict[str, list[str]] = {}
    for module, pack_id in module_build_packs.items():
        build_packs.setdefault(pack_id, []).append(module)
    build_packs = {
        pack_id: topological_build_pack(
            pack_id,
            pack_modules,
            module_imports,
        )
        for pack_id, pack_modules in build_packs.items()
    }

    write_json(out / "standalone-modules.json", modules)
    write_json(out / "proof-targets.json", sorted(targets))
    write_json(out / "module-resources.json", resources)
    build_pack_manifest = {
        "format": "stage-a-lean-build-packs-v1",
        "modules": module_build_packs,
        "packs": {
            pack_id: pack_modules
            for pack_id, pack_modules in sorted(build_packs.items())
        },
    }
    write_json(out / "module-build-packs.json", build_pack_manifest)
    if args.emit_module_graph:
        emit_precomputed_module_graph(
            out,
            stage_a,
            modules,
            module_imports,
            resources,
            module_build_packs,
            build_packs,
            targets,
        )
    write_json(
        out / "phase-manifest.json",
        {
            "format": RELATIONAL_PHASE_FORMAT,
            "phase": "proof-source-aggregate",
            "executes_original_binary": False,
            "executes_candidate_binary": False,
            "inputs": {},
            "status": "source-ready",
            "modules": modules,
            "targets": sorted(targets),
            "target_closure_only": args.target_closure_only,
            "explicit_targets_only": args.explicit_targets_only,
            "coarse_build_packs": args.coarse_build_packs,
            "precomputed_module_graph": args.emit_module_graph,
            "public_outputs": {
                "module_build_packs": "module-build-packs.json",
                **(
                    {
                        "module_graph": "module-graph.json",
                        "source_pack_data": "source-pack-data",
                    }
                    if args.emit_module_graph
                    else {}
                ),
            },
            "counts": {
                "build_packs": len(build_packs),
                "modules": len(modules),
                "targets": len(targets),
            },
        },
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", action="append", required=True)
    parser.add_argument("--target", action="append", default=[])
    parser.add_argument("--target-closure-only", action="store_true")
    parser.add_argument("--explicit-targets-only", action="store_true")
    parser.add_argument("--coarse-build-packs", action="store_true")
    parser.add_argument("--emit-module-graph", action="store_true")
    parser.add_argument("--out", required=True)
    aggregate(parser.parse_args())


if __name__ == "__main__":
    main()

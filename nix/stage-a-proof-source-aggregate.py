#!/usr/bin/env python3
"""Assemble generated Lean sources without importing proof-generation code.

This command is intentionally stdlib-only. Proof-source aggregation and pack
scheduling are cache policy, so changing them must not invalidate static
extraction or semantic source generation.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
from pathlib import Path
from typing import Any, Mapping


DIRECT_CALL_NODE_FAMILY = re.compile(
    r"^GeneratedRelationalInternalDirectCallSummaryNode([0-9a-f]{64}).*$"
)
DIRECT_CALL_BUILD_PACK_MAX_MODULES = 4
DIRECT_CALL_BUILD_PACK_SPLIT_THRESHOLD = 8
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
            "public_outputs": {
                "module_build_packs": "module-build-packs.json",
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
    parser.add_argument("--out", required=True)
    aggregate(parser.parse_args())


if __name__ == "__main__":
    main()

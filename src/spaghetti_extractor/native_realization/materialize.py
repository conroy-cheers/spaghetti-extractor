"""Internal native ingress/runtime materialization for one realization.

This module is an implementation detail of native realization, not a public
artifact or semantic authority.  It renders the runtime from the linked
semantic module, compiles independent sources concurrently, and returns exact
object evidence to the linker in the same phase.
"""

from __future__ import annotations

import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..candidate.formats import (
    BEHAVIORAL_C_PACKAGE_FORMAT,
    SHARED_MODULE_RUNTIME_PACKAGE_FORMAT,
)
from ..candidate.native_build import (
    _common_compile_flags,
    _deterministic_environment,
    _run,
)
from ..candidate.runtime import (
    write_shared_module_runtime_package_from_linked_module,
)
from ..util import sha256_file, write_json


_SOURCES = (
    "module-runtime.c",
    "native-ingress-bridges.S",
    "shared-module-runtime.c",
    "module-ingress-bridges.S",
    "behavioral-dispatch.c",
    "behavioral-support.c",
    "spx-atomics.c",
    "spx-capability-backend.c",
    "module-runtime-layout.c",
    "native-ingress-runtime.c",
    "shared-module-runtime-bindings.c",
)
_REQUIRED_SYMBOLS = {
    "module-runtime.c": ("spx_dispatch_external_call",),
    "native-ingress-bridges.S": (
        "spx_native_exception_recovery",
        "spx_native_raise_exception_gateway",
    ),
    "shared-module-runtime.c": (
        "spx_native_runtime_instance",
        "spx_native_runtime_run_at_rva",
        "spx_runtime_atomic_compare_exchange",
        "spx_runtime_atomic_exchange",
    ),
    "module-ingress-bridges.S": ("spx_native_bridge",),
    "behavioral-dispatch.c": ("spx_behavioral_run",),
    "behavioral-support.c": ("spx_read",),
    "spx-atomics.c": ("spx_atomic_compare_exchange",),
    "spx-capability-backend.c": ("spx_capability_bind",),
    "module-runtime-layout.c": ("spx_runtime_state_layout_table",),
    "native-ingress-runtime.c": ("spx_native_ingress_prepare",),
    "shared-module-runtime-bindings.c": ("spx_module_runtime_plan_sha256",),
}


class NativeMaterializationError(ValueError):
    """Native realization support could not be rendered or compiled."""

    def __init__(
        self, message: str, *,
        planning_blockers: Sequence[Mapping[str, Any]] | None = None,
    ) -> None:
        super().__init__(message)
        self.planning_blockers = (
            tuple(dict(row) for row in planning_blockers)
            if planning_blockers is not None
            else None
        )


def _required_symbols_for_source(
    source_path: str, ingress_plan: Mapping[str, Any],
) -> tuple[str, ...]:
    required = set(_REQUIRED_SYMBOLS[source_path])
    if source_path != "native-ingress-bridges.S":
        return tuple(sorted(required))
    raw_protocols = ingress_plan.get("seh_protocols")
    if not isinstance(raw_protocols, list) or any(
        not isinstance(row, Mapping) for row in raw_protocols
    ):
        raise NativeMaterializationError(
            "native ingress SEH protocol inventory is malformed"
        )
    for row in raw_protocols:
        symbol = row.get("gateway_handler_symbol")
        if not isinstance(symbol, str) or not symbol:
            raise NativeMaterializationError(
                "native ingress SEH protocol omits its gateway symbol"
            )
        required.add(symbol)
    return tuple(sorted(required))


def _object(value: object, context: str) -> dict[str, Any]:
    import json

    try:
        payload = json.loads(Path(value).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise NativeMaterializationError(f"cannot read {context}: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise NativeMaterializationError(f"{context} must be a JSON object")
    return dict(payload)


def _source_inventory(
    root: Path, manifest: Mapping[str, Any], context: str,
) -> dict[str, Mapping[str, Any]]:
    rows = manifest.get("sources")
    if not isinstance(rows, list):
        raise NativeMaterializationError(f"{context} has no source inventory")
    result: dict[str, Mapping[str, Any]] = {}
    for raw in rows:
        if not isinstance(raw, Mapping):
            raise NativeMaterializationError(f"{context} source row is malformed")
        relative = raw.get("path")
        digest = raw.get("sha256")
        if (
            not isinstance(relative, str)
            or not isinstance(digest, str)
            or relative in result
            or not (root / relative).is_file()
            or sha256_file(root / relative) != digest
        ):
            raise NativeMaterializationError(f"{context} source binding is stale")
        result[relative] = raw
    return result


def _compile_flags(
    source_sha256: str, behavioral_root: Path, runtime_root: Path,
) -> list[str]:
    flags = [
        flag for flag in _common_compile_flags(source_sha256) if flag != "-Os"
    ]
    flags.extend(("-O0", "-fno-inline", "-fno-omit-frame-pointer"))
    for label, root in (("behavioral", behavioral_root), ("runtime", runtime_root)):
        for prefix in ("file", "debug", "macro"):
            flags.append(f"-f{prefix}-prefix-map={root}=/candidate/{label}")
    return flags


def _defined_global_symbols(nm: Path, object_path: Path) -> frozenset[str]:
    try:
        output = subprocess.run(
            [str(nm), "-g", "--defined-only", str(object_path)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise NativeMaterializationError(
            f"cannot inspect native realization object {object_path.name}: {exc}"
        ) from exc
    return frozenset(
        line.rsplit(maxsplit=1)[-1].removeprefix("_")
        for line in output.splitlines()
        if line.split()
    )


def materialize_native_realization_support_v1(
    *,
    linked_semantic_module: Path,
    behavioral_c_package: Path,
    compiler: Path,
    nm: Path,
    out: Path,
    pinned_layout_authorities: Sequence[Mapping[str, Any]] = (),
    recovered_executable_data: Path | None = None,
) -> dict[str, Path]:
    """Render and compile all realization-owned support in one working set."""

    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    runtime = write_shared_module_runtime_package_from_linked_module(
        linked_semantic_module=Path(linked_semantic_module),
        behavioral_c_package=Path(behavioral_c_package),
        pinned_layout_authorities=tuple(pinned_layout_authorities),
        recovered_executable_data=recovered_executable_data,
        out=output,
    )
    if runtime.get("status") != "ready":
        blockers = runtime.get("blockers")
        if not isinstance(blockers, list) or any(
            not isinstance(row, Mapping) for row in blockers
        ):
            raise NativeMaterializationError(
                "incomplete native realization runtime has a malformed "
                "blocker inventory"
            )
        raise NativeMaterializationError(
            "native realization runtime is incomplete: "
            + repr(blockers),
            planning_blockers=blockers,
        )

    runtime_manifest_path = output / "shared-module-runtime-package.json"
    runtime_manifest = _object(runtime_manifest_path, "shared runtime package")
    if runtime_manifest.get("format") != SHARED_MODULE_RUNTIME_PACKAGE_FORMAT:
        raise NativeMaterializationError("shared runtime package is unsupported")
    runtime_sources = _source_inventory(
        output, runtime_manifest, "shared runtime package"
    )
    ingress_plan = _object(
        output / "native-ingress-plan.json", "native ingress plan"
    )
    behavioral_root = Path(behavioral_c_package)
    behavioral_manifest_path = behavioral_root / "behavioral-c-package.json"
    behavioral_manifest = _object(
        behavioral_manifest_path, "Behavioral-C package"
    )
    if (
        behavioral_manifest.get("format") != BEHAVIORAL_C_PACKAGE_FORMAT
        or behavioral_manifest.get("status") != "ready"
    ):
        raise NativeMaterializationError("Behavioral-C package is incomplete")
    behavioral_sources = _source_inventory(
        behavioral_root, behavioral_manifest, "Behavioral-C package"
    )
    runtime_plan = _object(
        output / "module-runtime-plan.json", "module runtime plan"
    )
    implementation_receipt = runtime_plan.get(
        "implementation_dispatch_receipt"
    )
    if not isinstance(implementation_receipt, Mapping):
        raise NativeMaterializationError(
            "module runtime plan omits implementation dispatch authority"
        )
    generated_runtime_sources: list[str] = []
    compiler_path = Path(compiler)
    nm_path = Path(nm)
    if not compiler_path.is_file() or not nm_path.is_file():
        raise NativeMaterializationError("PE32 realization toolchain is unavailable")

    objects_root = output / "native-realization-objects"
    objects_root.mkdir()
    environment = _deterministic_environment()

    def compile_one(item: tuple[int, str]) -> dict[str, Any]:
        index, source_path = item
        if source_path in runtime_sources:
            declared = runtime_sources[source_path]
            source_root = output
            source_owner = (
                "behavioral_c"
                if source_path == "behavioral-dispatch.c"
                else "shared_module_runtime"
            )
        else:
            declared = behavioral_sources.get(source_path)
            source_root = behavioral_root
            source_owner = "behavioral_c"
        if declared is None:
            raise NativeMaterializationError(
                f"native realization source is undeclared: {source_path}"
            )
        source = source_root / source_path
        if not source.is_file() or sha256_file(source) != declared["sha256"]:
            raise NativeMaterializationError(
                f"native realization source binding is stale: {source_path}"
            )
        destination = objects_root / f"{index:03d}.o"
        language = "assembler-with-cpp" if source.suffix.lower() == ".s" else "c"
        flags = _compile_flags(
            str(declared["sha256"]), behavioral_root, output
        )
        _run(
            [
                str(compiler_path), "-x", language, "-c", str(source),
                "-o", str(destination), "-I", str(behavioral_root),
                "-I", str(output), *flags,
            ],
            phase=f"compile native realization support {source_path}",
            env=environment,
        )
        defined = _defined_global_symbols(nm_path, destination)
        missing = sorted(
            set(_required_symbols_for_source(source_path, ingress_plan))
            - set(defined)
        )
        if missing:
            raise NativeMaterializationError(
                f"native realization object {source_path} omits {missing}"
            )
        return {
            "path": destination.relative_to(output).as_posix(),
            "object_sha256": sha256_file(destination),
            "source": source_path,
            "source_owner": source_owner,
            "source_role": declared["role"],
            "source_sha256": declared["sha256"],
            "language": language,
            "compile_flags": [
                flag.replace(str(behavioral_root), "<behavioral-c-package>")
                .replace(str(output), "<native-realization>")
                for flag in flags
            ],
        }

    sources = (*_SOURCES, *generated_runtime_sources)
    with ThreadPoolExecutor(max_workers=len(sources)) as executor:
        object_rows = list(executor.map(compile_one, enumerate(sources)))

    manifest_core = {
        "materialization": "native-realization-internal-v1",
        "objects": object_rows,
        "compiler_sha256": sha256_file(compiler_path),
        "source_runtime_package_sha256": sha256_file(runtime_manifest_path),
    }
    manifest_path = output / "native-realization-object-manifest.json"
    write_json(manifest_path, {
        **manifest_core,
        "receipt_sha256": canonical_sha256_v3(manifest_core),
    })
    return {
        "native_ingress_plan": output / "native-ingress-plan.json",
        "object_manifest": manifest_path,
    }


__all__ = [
    "NativeMaterializationError",
    "materialize_native_realization_support_v1",
]

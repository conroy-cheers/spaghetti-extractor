"""Compile portable components for development and PE32 activation."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..util import sha256_file, write_json
from .compiler import ComponentCompileError, compile_component
from .inductive_source import InductiveSourcePlanV1
from .interface_ir import PortableComponentInterfaceV2
from .source import component_operation_symbols, load_component_source_package


COMPONENT_COMPILE_RECEIPT_V1 = (
    "spaghetti-extractor-component-compile-receipt-v1"
)
_MUTABLE_SYMBOL_TYPES = frozenset("BbCcDdGgSs")


class ComponentCompileReceiptError(RuntimeError):
    """A portable component cannot satisfy the activation compile policy."""


def build_component_compile_receipt(
    *,
    interface: Path | str | Mapping[str, object],
    source_package: Path | str,
    host_compiler: Path | str,
    pe32_compiler: Path | str,
    out_dir: Path | str,
    inductive_source_plans: Sequence[
        Path | str | Mapping[str, object] | InductiveSourcePlanV1
    ] = (),
) -> dict[str, object]:
    """Compile exact source for host tests and PE32 with no mutable globals."""

    payload = _load_interface(interface)
    portable = PortableComponentInterfaceV2.parse(payload)
    source_root = Path(source_package)
    source = load_component_source_package(source_root)
    symbols = component_operation_symbols(source)
    portable.validate_operation_symbols(symbols)
    induction = tuple(
        item
        if isinstance(item, InductiveSourcePlanV1)
        else InductiveSourcePlanV1.parse(_load_json(item))
        for item in inductive_source_plans
    )
    output = Path(out_dir)
    output.mkdir(parents=True, exist_ok=True)
    host_library = output / "component.so"
    pe32_object = output / "component-pe32.o"
    compile_component(
        package=source_root,
        source=source,
        compiler=Path(host_compiler),
        output=host_library,
        interface=portable,
        operation_symbols=symbols,
        inductive_source_plans=induction,
        mode="host-shared",
    )
    compile_component(
        package=source_root,
        source=source,
        compiler=Path(pe32_compiler),
        output=pe32_object,
        interface=portable,
        operation_symbols=symbols,
        inductive_source_plans=induction,
        mode="pe32-object",
        mutable_global_audit=lambda path: _audit_mutable_globals(
            Path(pe32_compiler), path
        ),
    )
    core: dict[str, object] = {
        "format": COMPONENT_COMPILE_RECEIPT_V1,
        "status": "checked",
        "component_id": source["lift_unit_id"],
        "interface_id": portable.identity,
        "bindings": {
            "interface_sha256": portable.sha256,
            "implementation_sha256": source["implementation_sha256"],
            "inductive_source_plan_sha256s": [
                item.plan_sha256 for item in induction
            ],
        },
        "operation_symbols": symbols,
        "toolchains": {
            "host_compiler": str(Path(host_compiler)),
            "pe32_compiler": str(Path(pe32_compiler)),
        },
        "artifacts": {
            "host_shared": {
                "path": host_library.name,
                "sha256": sha256_file(host_library),
            },
            "pe32_object": {
                "path": pe32_object.name,
                "sha256": sha256_file(pe32_object),
            },
        },
        "policy": {
            "portable_interface_v2": True,
            "host_and_pe32_abi_checked": True,
            "framework_managed_state": True,
            "component_mutable_globals_forbidden": True,
            "inductive_public_wrappers_framework_generated": True,
        },
    }
    result = {**core, "receipt_sha256": canonical_sha256_v3(core)}
    write_json(output / "compile-receipt.json", result)
    return result


def _load_json(value: Path | str | Mapping[str, object]) -> dict[str, object]:
    if isinstance(value, Mapping):
        return json.loads(json.dumps(value))
    try:
        payload = json.loads(Path(value).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ComponentCompileReceiptError(
            f"cannot read inductive source plan: {exc}"
        ) from exc
    if not isinstance(payload, Mapping):
        raise ComponentCompileReceiptError(
            "inductive source plan must be an object"
        )
    return dict(payload)


def _audit_mutable_globals(compiler: Path, object_path: Path) -> None:
    prefix = compiler.name.removesuffix("gcc")
    nm = compiler.parent / f"{prefix}nm"
    if not nm.is_file():
        raise ComponentCompileError(f"PE32 symbol auditor is missing: {nm}")
    completed = subprocess.run(
        [str(nm), "-a", "--format=posix", str(object_path)],
        check=False,
        text=True,
        capture_output=True,
    )
    if completed.returncode != 0:
        raise ComponentCompileError(
            f"PE32 symbol audit failed: {completed.stderr.strip()}"
        )
    mutable: list[str] = []
    for line in completed.stdout.splitlines():
        fields = line.split()
        if (
            len(fields) >= 2
            and fields[1] in _MUTABLE_SYMBOL_TYPES
            and not fields[0].startswith(".")
        ):
            mutable.append(fields[0])
    if mutable:
        raise ComponentCompileError(
            "portable component defines mutable globals outside managed context: "
            f"{sorted(set(mutable))!r}"
        )


def _load_interface(
    value: Path | str | Mapping[str, object],
) -> dict[str, object]:
    if isinstance(value, Mapping):
        return json.loads(json.dumps(value))
    try:
        payload = json.loads(Path(value).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ComponentCompileReceiptError(
            f"cannot read portable component interface: {exc}"
        ) from exc
    if not isinstance(payload, Mapping):
        raise ComponentCompileReceiptError(
            "portable component interface must be an object"
        )
    return dict(payload)


__all__ = [
    "COMPONENT_COMPILE_RECEIPT_V1",
    "ComponentCompileReceiptError",
    "build_component_compile_receipt",
]

"""Deterministic compilation of content-bound portable components."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Callable, Literal, Mapping, Sequence

from .inductive_source import (
    InductiveSourceError,
    InductiveSourcePlanV1,
    validate_inductive_source_plans,
)
from .interface_ir import (
    ComponentInterfaceIRError,
    PortableComponentInterfaceV2,
)


ComponentCompileMode = Literal["host-shared", "pe32-object"]
MutableGlobalAudit = Callable[[Path], None]


class ComponentCompileError(RuntimeError):
    """Portable component source cannot be compiled by the declared toolchain."""


def compile_component_library(
    *,
    package: Path,
    source: Mapping[str, object],
    compiler: Path,
    output: Path,
    forced_header: Path | None = None,
    interface: PortableComponentInterfaceV2 | None = None,
    operation_symbols: Mapping[str, object] | None = None,
    inductive_source_plans: Sequence[InductiveSourcePlanV1] = (),
    mode: ComponentCompileMode = "host-shared",
    mutable_global_audit: MutableGlobalAudit | None = None,
) -> None:
    """Compile V1 or V2 source, including the V2 symbol-conformance TU.

    ``mutable_global_audit`` is intentionally policy-free here. Activation can
    inject its target-aware object audit without coupling development builds to
    one object format or symbol tool.
    """

    source_root = package / "sources"
    translation_units = _translation_units(source_root, source)
    if interface is None:
        if mode != "host-shared":
            raise ComponentCompileError(
                "PE32 object mode requires a portable component interface V2"
            )
        if forced_header is None:
            raise ComponentCompileError("component compilation requires a header")
        _compile_host_shared(
            compiler=compiler,
            output=output,
            source_root=source_root,
            header=forced_header,
            translation_units=translation_units,
            generated_translation_units=(),
        )
    else:
        if operation_symbols is None:
            raise ComponentCompileError(
                "portable component V2 compilation requires operation symbols"
            )
        try:
            symbols = interface.validate_operation_symbols(operation_symbols)
            induction = validate_inductive_source_plans(
                inductive_source_plans, interface, operation_symbols
            )
        except (ComponentInterfaceIRError, InductiveSourceError) as exc:
            raise ComponentCompileError(str(exc)) from exc
        generated_root = output.parent
        generated_root.mkdir(parents=True, exist_ok=True)
        public_header = generated_root / "portable-component.h"
        implementation_header = generated_root / "portable-component-implementation.h"
        conformance_tu = generated_root / "component-conformance.c"
        public_header.write_text(interface.render_public_header(), encoding="ascii")
        implementation_header.write_text(
            interface.render_implementation_header(
                symbols, public_header=public_header.name
            ),
            encoding="ascii",
        )
        conformance_tu.write_text(
            interface.render_conformance_translation_unit(
                symbols, implementation_header=implementation_header.name
            ),
            encoding="ascii",
        )
        generated_translation_units: list[Path] = [conformance_tu]
        forced_interface_header = implementation_header
        if induction:
            aggregate_header = generated_root / "portable-component-inductive.h"
            aggregate_lines = [f'#include "{implementation_header.name}"']
            for index, plan in enumerate(induction):
                plan_header = generated_root / f"inductive-operation-{index:04d}.h"
                wrapper_tu = generated_root / f"inductive-operation-{index:04d}.c"
                plan_header.write_text(
                    plan.render_header(
                        interface,
                        symbols,
                        implementation_header=implementation_header.name,
                    ),
                    encoding="ascii",
                )
                wrapper_tu.write_text(
                    plan.render_wrapper(
                        interface,
                        symbols,
                        header=plan_header.name,
                    ),
                    encoding="ascii",
                )
                aggregate_lines.append(f'#include "{plan_header.name}"')
                generated_translation_units.append(wrapper_tu)
            aggregate_lines.append("")
            aggregate_header.write_text("\n".join(aggregate_lines), encoding="ascii")
            forced_interface_header = aggregate_header
        if mode == "host-shared":
            _compile_host_shared(
                compiler=compiler,
                output=output,
                source_root=source_root,
                header=forced_interface_header,
                translation_units=translation_units,
                generated_translation_units=generated_translation_units,
            )
        elif mode == "pe32-object":
            _compile_relocatable_object(
                compiler=compiler,
                output=output,
                source_root=source_root,
                header=forced_interface_header,
                translation_units=translation_units,
                generated_translation_units=generated_translation_units,
            )
            missing = _missing_bound_symbols(
                compiler=compiler,
                output=output,
                symbols=set(symbols.values()),
            )
            if missing:
                raise ComponentCompileError(
                    f"portable component is missing configured symbols: {sorted(missing)!r}"
                )
        else:
            raise ComponentCompileError(f"unsupported component compile mode {mode!r}")

    if mutable_global_audit is not None:
        try:
            mutable_global_audit(output)
        except ComponentCompileError:
            raise
        except Exception as exc:
            raise ComponentCompileError(
                f"portable component mutable-global audit failed: {exc}"
            ) from exc


def compile_component(
    *,
    package: Path,
    source: Mapping[str, object],
    compiler: Path,
    output: Path,
    interface: PortableComponentInterfaceV2,
    operation_symbols: Mapping[str, object],
    inductive_source_plans: Sequence[InductiveSourcePlanV1] = (),
    mode: ComponentCompileMode = "host-shared",
    mutable_global_audit: MutableGlobalAudit | None = None,
) -> None:
    """Compile a portable V2 component for development or PE32 activation."""

    compile_component_library(
        package=package,
        source=source,
        compiler=compiler,
        output=output,
        interface=interface,
        operation_symbols=operation_symbols,
        inductive_source_plans=inductive_source_plans,
        mode=mode,
        mutable_global_audit=mutable_global_audit,
    )


def _translation_units(
    source_root: Path, source: Mapping[str, object]
) -> list[Path]:
    files = source.get("files")
    if not isinstance(files, list):
        raise ComponentCompileError("source package file inventory is malformed")
    translation_units = [
        source_root / str(row["path"])
        for row in files
        if isinstance(row, Mapping) and str(row.get("path", "")).endswith(".c")
    ]
    if not translation_units:
        raise ComponentCompileError("source package has no C translation unit")
    return translation_units


def _base_compile_command(
    *, compiler: Path, source_root: Path, header: Path
) -> list[str]:
    return [
        str(compiler),
        "-O1",
        "-fno-inline",
        "-std=c11",
        "-Wall",
        "-Werror",
        "-I",
        str(source_root),
        "-I",
        str(header.parent),
        "-include",
        str(header),
    ]


def _compile_host_shared(
    *,
    compiler: Path,
    output: Path,
    source_root: Path,
    header: Path,
    translation_units: list[Path],
    generated_translation_units: Sequence[Path],
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    command = [
        *_base_compile_command(
            compiler=compiler, source_root=source_root, header=header
        ),
        "-shared",
        "-fPIC",
        "-Wl,--no-undefined",
        "-o",
        str(output),
        *(str(path) for path in translation_units),
    ]
    command.extend(str(path) for path in generated_translation_units)
    _run_compiler(command)


def _compile_relocatable_object(
    *,
    compiler: Path,
    output: Path,
    source_root: Path,
    header: Path,
    translation_units: list[Path],
    generated_translation_units: Sequence[Path],
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="component-objects-", dir=output.parent
    ) as temporary:
        object_root = Path(temporary)
        objects: list[Path] = []
        for index, translation_unit in enumerate(
            [*translation_units, *generated_translation_units]
        ):
            object_path = object_root / f"unit-{index}.o"
            _run_compiler(
                [
                    *_base_compile_command(
                        compiler=compiler,
                        source_root=source_root,
                        header=header,
                    ),
                    "-c",
                    "-o",
                    str(object_path),
                    str(translation_unit),
                ]
            )
            objects.append(object_path)
        _run_compiler(
            [
                str(compiler),
                "-r",
                "-o",
                str(output),
                *(str(path) for path in objects),
            ]
        )


def _missing_bound_symbols(
    *, compiler: Path, output: Path, symbols: set[str]
) -> set[str]:
    inspector = _find_nm(compiler)
    if inspector is None:
        raise ComponentCompileError(
            "cannot inspect configured symbols in PE32 object: nm is unavailable"
        )
    completed = subprocess.run(
        [str(inspector), "-u", str(output)],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise ComponentCompileError(
            f"portable component symbol inspection failed: {detail[:4000]}"
        )
    undefined = {
        line.split()[-1]
        for line in completed.stdout.splitlines()
        if line.split()
    }
    return {
        symbol
        for symbol in symbols
        if symbol in undefined
        or f"_{symbol}" in undefined
        or any(item.startswith(f"_{symbol}@") for item in undefined)
    }


def _find_nm(compiler: Path) -> Path | None:
    name = compiler.name
    candidates: list[str] = []
    for suffix in ("gcc", "cc", "clang"):
        if name.endswith(suffix):
            candidates.append(f"{name[:-len(suffix)]}nm")
    candidates.append("nm")
    for candidate in candidates:
        sibling = compiler.with_name(candidate)
        if sibling.is_file():
            return sibling
        resolved = shutil.which(candidate)
        if resolved is not None:
            return Path(resolved)
    return None


def _run_compiler(command: list[str]) -> None:
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise ComponentCompileError(
            f"portable component compiler failed: {detail[:4000]}"
        )


__all__ = [
    "ComponentCompileError",
    "ComponentCompileMode",
    "MutableGlobalAudit",
    "compile_component",
    "compile_component_library",
]

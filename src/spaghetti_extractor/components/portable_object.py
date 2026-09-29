"""Compile one checked portable-C source package into host and PE32 objects.

This is a mechanical realization helper.  It consumes the retained V5
interface plus a format-free normalized machine overlay and emits no component
authority record.  Qualification and provider selection remain separate.
"""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..boundary._canonical import BoundaryModelError
from ..util import sha256_file, write_json
from .atomics import spx_atomics_header
from .component_c_v5 import render_component_c_headers_v5
from .interface_package_v5 import CompiledComponentInterfaceV5
from .machine_overlay_v5 import ComponentMachineOverlayV1


def compile_portable_component_objects(
    root: Path,
    source: Mapping[str, object],
    *,
    bundle: CompiledComponentInterfaceV5,
    operation_symbols: Mapping[str, str],
    induction_source_plan: Path | None,
    machine_overlay: ComponentMachineOverlayV1 | None,
    machine_overlay_error: str | None,
    runtime_header: str,
    host_compiler: Path,
    pe32_compiler: Path,
    output: Path | None,
    summary_dependencies=(),
    inspect_storage: bool = False,
    compiler_view_output: Path | None = None,
) -> tuple[list[Mapping[str, object]], str, str | None]:
    """Compile and content-bind every authored and generated translation unit."""

    source_root = root / "sources"
    files = [
        source_root / str(item["path"])
        for item in source.get("files", [])
        if str(item.get("path", "")).endswith(".c")
    ]
    if not files:
        return (
            [{"code": "component_source_translation_unit_missing"}],
            "incomplete",
            None,
        )
    checks: list[Mapping[str, object]] = []
    objects: list[Mapping[str, object]] = []
    status = "checked"
    with tempfile.TemporaryDirectory() as temporary:
        temporary_root = Path(temporary)
        generated_root = temporary_root / "generated"
        generated_root.mkdir()
        (generated_root / "state-machine-runtime.h").write_text(
            runtime_header, encoding="ascii"
        )
        induction_source = None
        if induction_source_plan is not None:
            loaded = json.loads(induction_source_plan.read_text(encoding="utf-8"))
            if not isinstance(loaded, Mapping):
                raise BoundaryModelError(
                    "component induction source plan must be an object"
                )
            induction_source = loaded
        generated = render_component_c_headers_v5(
            bundle, operation_symbols, induction_source
        )
        if summary_dependencies:
            # Declarations are compilation inputs, not proof authority. The
            # enclosing checker validates supplier evidence separately.
            from .bisimulation_source_dependencies import dependency_headers
            generated = dependency_headers(generated, summary_dependencies)
        if machine_overlay is not None:
            generated["component-machine-overlay.c"] = machine_overlay.source
        else:
            checks.append(
                {
                    "code": "component_machine_overlay_incomplete",
                    "status": "incomplete",
                    "diagnostic": machine_overlay_error,
                }
            )
            status = "incomplete"
        for name, content in generated.items():
            (generated_root / name).write_text(content, encoding="ascii")
        if any("spx_atomic_object" in content for content in generated.values()):
            (generated_root / "spx-atomics.h").write_text(
                spx_atomics_header(), encoding="ascii"
            )
        include_paths = sorted(
            {
                generated_root,
                source_root,
                *(path.parent for path in source_root.rglob("*.h")),
            }
        )
        for compiler_kind, compiler in (
            ("host", host_compiler),
            ("pe32", pe32_compiler),
        ):
            compile_files = [*files, *sorted(generated_root.glob("*.c"))]
            for index, source_path in enumerate(compile_files):
                object_path = temporary_root / f"{compiler_kind}-{index}.o"
                command = [
                    str(compiler),
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    *(
                        argument
                        for include in include_paths
                        for argument in ("-I", str(include))
                    ),
                    "-c",
                    str(source_path),
                    "-o",
                    str(object_path),
                ]
                completed = subprocess.run(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
                check = {
                    "code": (
                        "component_translation_unit_compiled"
                        if completed.returncode == 0
                        else "component_translation_unit_compile_failed"
                    ),
                    "compiler": compiler_kind,
                    "source": (
                        source_path.relative_to(source_root).as_posix()
                        if source_path.is_relative_to(source_root)
                        else source_path.name
                    ),
                    "status": (
                        "checked" if completed.returncode == 0 else "violated"
                    ),
                    "diagnostic_sha256": canonical_sha256_v3(
                        {"stdout": completed.stdout, "stderr": completed.stderr}
                    ),
                    "diagnostic": (completed.stderr or completed.stdout)[-4000:],
                    "object_sha256": (
                        sha256_file(object_path)
                        if completed.returncode == 0
                        else None
                    ),
                }
                checks.append(check)
                if inspect_storage and completed.returncode == 0 and source_path in files:
                    from .source_dialect import inspect_object_storage
                    check['storage'] = inspect_object_storage(compiler, object_path)
                if compiler_view_output is not None and source_path in files:
                    from .source_compiler_view import write_compiler_view
                    view = compiler_view_output/f'{compiler_kind}-{index}'
                    feedback = write_compiler_view(command, cwd=source_root, output=view)
                    check['compiler_view'] = dict(status=feedback['status'], path=view.name+'/view.json')
                if completed.returncode != 0:
                    status = "violated"
                elif output is not None:
                    relative = Path("objects") / compiler_kind / f"{index:04d}.o"
                    destination = output / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(object_path, destination)
                    objects.append(
                        {
                            "compiler": compiler_kind,
                            "compiler_sha256": sha256_file(Path(compiler)),
                            "source": check["source"],
                            "path": relative.as_posix(),
                            "sha256": sha256_file(destination),
                        }
                    )
        artifact_sha256 = None
        if status == "checked" and output is not None:
            generated_rows = []
            for name in sorted(generated):
                destination = output / "generated" / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(generated[name], encoding="ascii")
                generated_rows.append(
                    {"path": f"generated/{name}", "sha256": sha256_file(destination)}
                )
            core = {
                "component_id": bundle.interface.identity,
                "interface_sha256": bundle.interface.interface_sha256,
                "source_package_sha256": str(source["implementation_sha256"]),
                "objects": sorted(objects, key=lambda item: str(item["path"])),
                "generated": generated_rows,
                "machine_overlays": (
                    [] if machine_overlay is None else list(machine_overlay.entries)
                ),
                "policy": {
                    "host_objects_deployable": False,
                    "pe32_objects_deployable": True,
                    "operation_and_dispatch_symbols_only": True,
                },
            }
            artifact_sha256 = canonical_sha256_v3(core)
            write_json(
                output / "object-manifest.json",
                {**core, "artifact_sha256": artifact_sha256},
            )
    return checks, status, artifact_sha256


__all__ = ["compile_portable_component_objects"]

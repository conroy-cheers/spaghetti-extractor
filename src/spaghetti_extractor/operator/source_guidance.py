"""Authoring assistance, separate from source-profile and proof authority."""

from __future__ import annotations

import json
from pathlib import Path
import shutil

from ..components.source_profile import PROFILE_ID
from ..components.source_dialect import PRACTICAL_PROFILE_ID


_REMEDIATIONS = {
    "inline_assembly": "Keep instruction-specific behavior in the original-side adapter; call a declared service from component C.",
    "volatile_storage": "Express observable reads/writes through the generated state/view or service interface; removing volatile alone does not preserve behavior.",
    "atomic_storage": "Use a declared atomic/service boundary with an implemented adapter; replacing the operation with an ordinary load/store changes its meaning.",
    "nonlocal_control": "Represent the supported outcome through the boundary and its adapter; nonlocal jumps are outside this C profile.",
    "thread_creation": "Use a declared runtime service with an explicit interaction contract; this profile does not implement thread creation.",
    "unrestricted_allocation": "Declare allocation/release services and use their generated API once executable adapters exist; keep ownership and lifetime expectations in the boundary.",
    "cbmc_intrinsic": "Keep checker intrinsics in generated proof code; write component behavior using ordinary C and declared services.",
    "conditional_compilation": "Select implementation variants in the build configuration; only conventional outer header guards are exempt from the conditional-compilation restriction.",
    "thread_local_storage": "Pass the relevant per-thread state explicitly through the component boundary.",
    "hidden_storage": "Move persistent state into the declared component context; use local variables for temporary state.",
    "hidden_static_storage": "Move persistent state into the declared component context; block-scope static storage is outside this profile.",
    "macro_definition": "Use an ordinary helper function or a supported constant definition instead of an executable macro.",
}


def source_issue_guidance(code: str) -> str:
    """Explain supported alternatives without changing the checked profile."""
    return _REMEDIATIONS.get(code.removeprefix("restricted_c_"),
                             "Review the selected C profile and generated boundary header.")


def write_authoring_guidance(output: Path, *, sources=('src/component.c',),
        include_directories=('include',), compiler: str | None = None,
        header='include/component.h', check_command: str | None = None,
        source_include_directories: dict | None = None, adapter_sources=(),
        workspace: Path | None = None, check_label: str = 'Public check',
        boundary_guide: str = 'generated/workspace.md', source_check_command: str | None = None) -> None:
    """Add editable development aids outside the immutable package inventory."""
    root = (workspace or output).resolve()
    compiler = compiler or shutil.which("cc") or "cc"
    commands=[{"directory":str(root),"file":str(root/source),
               "arguments":[compiler,"-std=c11","-Wall","-Wextra",
                            *[arg for directory in (source_include_directories or {}).get(source,include_directories)
                              for arg in ('-I',str(root/directory))],
                            "-fsyntax-only",str(root/source)]} for source in [*sources,*adapter_sources]]
    (output / "compile_commands.json").write_text(json.dumps(commands,indent=2)+"\n",encoding="utf-8")
    lines = [
        "# Component C authoring", "", f"Practical dialect: `{PRACTICAL_PROFILE_ID}`; formal eligibility: `{PROFILE_ID}`.", "",
        "Ordinary C macros, conditionals and generated code are compiled normally. Practical checks inspect every authored object; "
        "writable persistent state belongs in the declared component context. Formal profile restrictions "
        "are reported separately and still apply to proof requests.", "",
        "Edit "+", ".join(f"`{source}`" for source in sources)+f"; `{header}` provides the generated API.",
        "Replace the generated `#error` with your implementation. Ordinary control",
        "flow, helper functions, local structs and arrays are supported subject to",
        "the C profile and the declared boundary. Generated headers are tool-owned;",
        "their implementation details are not a template for authored code.", "",
        *(["Comparison adapters: "+", ".join(f"`{source}`" for source in adapter_sources)+".",
           "Their editor commands use the same per-component compiler and include paths.",
           "Adapters implement native entry, transport and observations; they are separate",
           f"from the portable component C profile. Inspect `{boundary_guide}` for their roles.", ""]
          if adapter_sources else []),
        "`compile_commands.json` supplies editor diagnostics and a syntax-check",
        "command using the selected package compiler, or `cc` from the creation",
        "environment. Regenerate the draft if its paths or toolchain change.",
        (f"{check_label}: `{check_command}`." if check_command else
         "Run `component check --source` for canonical host/PE32 compilation and profile feedback."), "",
        *([f"Source/profile check: `{source_check_command}`.",
           "This checks current authored C and regenerated declarations with the lifting shell's host and PE32 compilers.",
           "It needs no target registration, comparison driver or original execution. Adapter syntax remains the separate command above.",
           "Repeat after edits; add `--output NEW_DIRECTORY` to retain source inputs and diagnostics. Without it, feedback is temporary.", ""]
          if source_check_command else []),
        "Syntax success is not dialect conformance, behavioral comparison or proof.",
        "A supported C program may need a formal rule that is not implemented.",
        "Binary32/64 values have generated float/double interfaces and native ABI",
        "checks. This does not supply a floating arithmetic or resource proof.",
        "Optional local shared-memory/service checks use an explicit existing",
        "relation and model capacities; their conditional results are separate",
        "from the concrete comparison and do not prove original equivalence.",
        "Executable local comparisons also require concrete boundary adapters.",
        "These editor files confer no qualification or execution authority.", "",
        "Use `--compiler-view` with an authoring source check (`--output` required) or a comparison check "
        "to retain active C, macro definitions, line markers and consumed inputs for that compiler configuration. "
        "These are diagnostic views; edit and export the original C, not preprocessed platform headers.", "",
        "Runtime services, memory transport, effects and lifetime still need explicit boundary adapters and observations. "
        "Compilation and storage inspection do not prove those premises.", "",
        "## Optional formal profile: restricted constructs and alternatives", "",
        "The restrictions below govern formal eligibility. They do not block practical compilation or comparison "
        "merely because they appear in raw C. Unavailable proof rules remain separate from behavioral evidence.", "",
    ]
    lines.extend(f"- {name.replace('_', ' ')}: {text}" for name, text in _REMEDIATIONS.items())
    (output / "AUTHORING.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

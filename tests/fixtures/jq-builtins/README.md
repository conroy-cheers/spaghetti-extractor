# jq builtin library

This source-assisted module supplies the eleven existing binary value operators
and builtin registration. Its ordinary C contains arithmetic, comparison,
conversion, formatting, regex, path, input, debug/halt and calendar handlers,
the persistent C callback table, and bytecoded/jq-coded builtin definitions.
Read [BOUNDARY.md](BOUNDARY.md) for ownership and runtime assumptions.

`builtins.c` derives from jq under [COPYING](COPYING). Private handlers stay in
the module. `builtin-profile.h` preserves the pinned Windows build's available
math functions; the six missing functions keep their original error behavior.
Calendar conversion explicitly preserves its 32-bit CRT range on wider hosts.
Compiler/VM graphs, values, allocation, Oniguruma and libc remain C dependencies.

In the lifting shell, using the installed toolkit and retained native inputs:

```sh
python tests/fixtures/jq-builtins/prepare.py PROJECT WORK TOOLKIT
python tests/fixtures/jq-builtins/compare.py WORK/authoring RETAINED_INPUTS WORK/comparison
spaghetti-headless-wayland spaghetti-extractor component check jq builtin-library \
  --comparison-package WORK/comparison --output WORK/checked
```

The native import adapter binds private services by reviewed RVA and derives the
Oniguruma import library from the retained DLL exports, including data symbols.
It does not rebuild either library or the pilot. The comparison traps the old
public entries and intervening private builtin handlers. The consumer compiles
and executes programs in two jq states, checks bytecode structure, values,
callbacks, input aliases and allocation lifetime. A syntax error rejected before
builtin binding has no module entry; successfully compiled cases require one.

Use the same action for initial integration and later edits:

```sh
lifting_repo="$PWD"
spaghetti-extractor candidate apply jq --project PROJECT \
  --comparison WORK/checked --component builtin-library \
  --accept-boundary-change builtin-library \
  --assembly-command "python $lifting_repo/tests/fixtures/jq-portable/refresh.py {project} --bindings $lifting_repo/tests/fixtures/jq-builtins/portable-bindings.json" \
  --check-command 'make -j2 jq live-values'
```

Add normal-program workload checks before publishing. Exported implementation
headers and the adapter travel with the project. The portable recipe retires all
twelve old public bodies. Their unreferenced private callback table and handlers
must also disappear from the compiled `builtin.o`; inspect that archive member
alongside the declared-entry checks. Dead source text is not executable fallback.

The retained continuation lives under `build/jq-builtin-lifting-2026-09-27/`.
Native comparison is finite behavioral evidence; formal eligibility and complete
jq lifting remain separate.

# Practical C modules and portable assembly

Components can contain ordinary private C helpers, immutable static data and
several public operations. Their existing interfaces, source packages and
comparison receipts remain shared inputs to compilation, execution, assembly
and optional proof. This adds no new proof format or qualification authority.

## Practical dialect and formal eligibility

`portable-component-c11-practical-v2` admits ordinary compiler-accepted C and
inspects every authored object for persistent storage. The
[compiler-backed workflow](compiler-backed-practical-c.md) supplies active-source
views, jq frontend refactoring and defect replay. The earlier v1 milestone below
introduced immutable persistent storage after
inspection of the selected compiler's object sections. Both file-scope tables and
block-scope static constants keep C's normal storage duration. The compiler
handles typedefs, arrays, pointer qualifiers and relocations; the checker does not
guess constness from declaration spelling. Allocated read-only sections and
ordinary ELF relocation-read-only sections are accepted. Writable storage and
common symbols require explicit component context or a subsequent
[state-owner declaration](stateful-component-workflow.md); missing inspection tools or
unsupported object formats remain diagnostics. Use the lifting shell's matching
compiler/binutils for host and PE32.

Raw macro/conditional and other formal syntax restrictions no longer gate practical
comparison. Runtime dependencies, state transport and observations still have to
work; allocation, volatile/atomic access and nonlocal control do not acquire checked
semantics simply because the compiler accepts them. Portability is assessed per
target configuration and through program execution.

The unchanged `portable-component-c11-cbmc-v1` profile controls formal checks.
Source feedback and comparison results report practical admission and formal
eligibility separately. A supported executable component can match its original
while a requested proof remains unavailable. Existing formal failures retain
their meaning and existing strong readers retain their original rules.

Object inspection is evidence about compiled storage, not a proof of effects:
an immutable table can refer to mutable objects or external services. The boundary
still needs their dependencies and lifetime assumptions, and comparisons need
relevant observations. Returned pointers are compared through contents, alias
relationships and lifetime behavior rather than assuming equal numeric addresses
on different architectures. No implicit deep immutability is inferred.

## Explicit portable assembly bindings

Use [`candidate apply`](component-assembly-updates.md) to coordinate a compared
source change with these program bindings and optional integration checks. The
shared reconciliation handles entry changes, provider moves and reversible body
retirement; failed preparation leaves the working project unchanged. The same
declarations serve initial assembly and subsequent edits.

`candidate.source_assembly` supplies shared validation, file retention and entry
inventory checks for ordinary C adapters. The jq and Hello source recipes consume
these facilities. Application adapters are independent of comparison-harness
adapters; the same component can use different native and portable backends.

For jq, the existing `--bindings FILE` accepts an `assembly` declaration:

```json
{
  "json-parser": {
    "assembly": {
      "entries": {
        "jv_parser_new": ["create"],
        "jv_parser_free": ["destroy"]
      },
      "sources": {"entry.c": "parser-entry.c"},
      "headers": {},
      "replacements": [
        {"file": "src/jv_parse.c", "symbol": "jv_parser_new"},
        {"file": "src/jv_parse.c", "symbol": "jv_parser_free"}
      ],
      "lifetime": "Parser handles own state from create through destroy; input buffers remain borrowed until consumed."
    }
  }
}
```

This abbreviated example shows the declaration shape; replacing the full parser
requires its other entries too. An entry can invoke several component operations,
and several native aliases can use one operation. Initialization, state transport,
service wiring and cleanup live in the supplied C. `lifetime` documents that
review; it does not implement or verify it. Proof regions, components and the set
of definitions replaced together retain their distinct purposes.

Relative adapter paths resolve beside the binding file. Preparation copies them
under `bindings/COMPONENT/`, builds every source translation unit and retains
project-relative paths. Refresh uses the same implementation, preserves unchanged
files and mtimes, and retains the existing conflict/proposal/backup behavior.
Adapter contents participate in invalidation even when their paths are unchanged.
Existing replacement sets require explicit assembly review before changing.
The compiler/linker check executable types; the build requires every declared
entry exactly once and verifies removal of the selected old definitions.

The existing generated single-entry bridge remains supported. An explicit
`service_bridge` can select a portable service mapping independently of retained
comparison examples. With operator-written grouped entries, optional generated
service helpers are written to `services.generated.h` beside the adapters.
Without that selection, the adapter owns service wiring directly, as Hello's
existing grouped conversion adapter does.

## 2026-09-25 operator trial

Retained evidence is in `build/component-module-workflow-2026-09-25/`:

- The previously rejected jq opcode component passes host/PE32 compilation and
  46 native comparisons, observing descriptor contents, stable returned pointers
  through intervening calls and the shared invalid-opcode sentinel.
- The six-operation JSON parser installs through the shared assembly declaration,
  replacing all nine public parser definitions. Normal jq execution matches the
  original in 62 CLI cases plus 32 live-value scenarios on x86-64 and AArch64.
- A local C edit makes the BOM table `static const`. Its 12 native parser cases
  match. Public partial export and recipe refresh retain all 22 neighboring host
  components. The subsequent host build recompiles one parser object in 0.315s;
  the original/source CLI comparisons still match. The first comparison after
  the engine/environment change revalidated all four fixture translation units;
  this is not reported as free native-evidence reuse.
- Hello's existing grouped reset/decode adapter uses the same declaration and
  retention functions. Adapter bytes remain unchanged, and the resulting normal
  executable matches the retained build in three focused workloads.
- Editing a retained adapter invalidates program validation and rebuilds just
  that adapter object (0.164s in the focused trial). A subsequent unchanged refresh
  is a no-op. Both architecture builds have every declared parser entry exactly
  once, including native aliases that need not be called by a particular workload.

The rebuilt installed toolkit accepts the opcode workspace on host and PE32.
Focused dialect, comparison, source-export and assembly tests pass, as do the
repository metadata, format registry, production Python lint, module closure,
build infrastructure, boundary workbench and target SDK Nix checks.

These are source-assisted partial jq results, not full jq recovery or universal
equivalence. Compiler/VM/value/platform dependencies remain. Wine executions use
headless Wayland. Formal qualification remains separate.

Validation limitation: two existing optional local-proof tests report `disproved`
where they expect `proved` or `incomplete` in the retained development shell.
Bypassing the new practical admission path reproduces the unexpected disproof
with the unchanged strict profile. Their concrete comparisons still match; the
new test for immutable-storage formal ineligibility also passes. This delivery
does not claim those optional-proof regressions are resolved. Exact diagnostics
and the isolated strict-profile check are retained beside the workflow evidence.

# Compiler-backed practical C and progressive refactoring

The 2026-09-26 workflow makes ordinary compiled C the entry point for practical
lifting. Operators can compare a mechanically recovered or generated first
implementation, then improve it within a stable component boundary. Formal source
eligibility and strong qualification retain their existing rules.

## Implemented admission and evidence

`portable-component-c11-practical-v2` uses the selected C compiler for syntax.
The raw `portable-component-c11-cbmc-v1` profile is retained as separate formal
feedback; its macro, conditional, allocation and other lexical diagnostics do
not determine practical admission. An inactive allocation declaration is no longer
treated as an active call. This policy change versions the practical profile and
invalidates affected execution reuse through the existing engine binding.

Every successfully compiled authored translation unit receives object-storage
inspection, including unchanged cached objects and state introduced by included
headers or macros. Immutable static storage keeps normal C lifetime. Writable
persistent storage requires an explicit component context or the subsequent
[state-owner declaration workflow](stateful-component-workflow.md); diagnostics
name object symbols where available. Declared state retains ordinary C/runtime
lifetime, without a managed global/TLS emulation model. Missing storage inspection
remains incomplete.

The compiler and linker still have to accept the selected configuration. Original
entry adapters, runtime dependencies, memory transport and meaningful observations
are still needed to execute a comparison. A compiler-accepted extension can be
usable in that configuration without being portable. Direct allocation, volatile
access, atomics, callbacks and nonlocal control need appropriate runtime behavior
and boundary observations; syntax acceptance does not implement them or establish
their effects. Read-only pointer storage is not deep immutability.

Existing source checks, concrete comparisons and experimental packaging consume
the practical result. Strong proof/provider readers retain their strict profile.
An optional proof result remains separately visible, with its exact source
bindings. A matching finite comparison is neither universal equivalence nor
activation authority. Existing experimental policy requirements remain in force.

## Inspect the active implementation

The public source check supports an optional compiler view:

```sh
spaghetti-extractor component check TARGET COMPONENT --source \
  --authoring-workspace WORKSPACE --compiler-view --output SOURCE_CHECK
```

It retains `compiler-views/host-N/` and `compiler-views/pe32-N/`. A concrete check
also accepts `--compiler-view`, writing `build/compiler-views/N/` in its result.
Each directory contains active C with macro definitions and line markers, compiler
diagnostics, a dependency file and `view.json`. The record binds the preprocessing
command, selected compiler, environment digest, consumed input hashes and outputs.
Environment values are not recorded. Views are available for failed compilation
as well, when preprocessing itself succeeds.

Views are diagnostic preprocessing invocations for the selected configuration.
They do not become executable/proof inputs or assert that every effect is known.
An unavailable optional view does not change behavioral comparison eligibility.
Author and export the original C; rebuilding on another architecture selects that
architecture's headers and conditionals. Do not export a flattened host `.i` file.
Existing source `#line` directives retain their original locations, which can name
generator inputs that were not recovered with a binary.

Normal checks do not preprocess an additional time. The existing translation-unit
cache continues to bind compiler options, environment, consumed headers and include
search decisions. Unsupported dependency-discovery constructs cause recompilation
with a reason, rather than a new syntax prohibition. Diagnostic views are retained
inside the existing result, not a new authority/artifact family.

## Operator loop

1. Define the boundary and its inputs, shared objects, services, outcomes and
   lifetime assumptions. Ordinary C adapters supply executable transport.
2. Bring in the first C implementation, including generated mechanisms when useful.
   Check both compilers and inspect active code if diagnostics need explanation.
3. Establish original-versus-replacement comparisons through relevant consumers.
   Compare state, diagnostic/interaction outcomes and cleanup as well as values.
4. Refactor a meaningful operation into readable C, preserving the boundary.
   Replay discrepancies against retained original inputs; earlier C is supporting
   regression evidence, not a replacement for the machine reference.
5. Export just the edited component, refresh its reviewed assembly and exercise
   the affected program workloads on the selected architectures.

Private helpers are not automatically new components. Proof regions, components
and replacement groups remain distinct. A signature match does not establish
ownership, effect or representation compatibility; changes to those premises use
the existing explicit boundary/refinement workflow. Unaffected local evidence and
objects can remain reusable while affected integration workloads run again.

## jq frontend trial

Retained inputs, recipes, outputs and costs are under
`build/practical-c-workflow-2026-09-26/`. The installed toolkit is retained there as
`toolkit`; the lifting environment is
`build/component-shell-invalidation-2026-09-24/environment`.

The previously rejected 4,188-line Bison parser now passes practical host/PE32
source checking. Compiler inspection exposed a generated location default in
writable PE32 storage. Making that never-mutated default const, and the analogous
conditional semantic-value default const, retains initialization/lifetime without
bulk macro normalization. Formal source eligibility remains incomplete.

The parser boundary borrows source locations, returns an owned compiler block and
an error count, and distinguishes program/library parsing. The lexer, IR builders,
values, diagnostics and allocator remain runtime dependencies. The native adapter
uses 58 explicitly image-bound internal runtime bindings; this preparation effort
is separate from the subsequent local C edit. The scoped diagnostic varargs adapter
formats a message before forwarding it, so allocation-failure behavior is not
claimed by this experiment.

The first generated implementation matches 23 native consumer cases. Refactoring
the duplicated module/import metadata actions into ordinary C helpers, together
with six relevant cases, matches 29. Cases cover two contexts, restarts, closures,
backtracking, callbacks, malformed input, metadata diagnostics, interpreter results
and observed allocation lifetime. The source side redirects program/library entries
and traps the original `jq_parse`, `jq_parse_library` and `yyparse` bodies.

A deliberate object-versus-array metadata defect produces a retained mismatch and
replays from the reported public command. Repair restores all 29 matches. The edit
and repair each compile one helper object and reuse five neighboring objects.
The first transition from a local Python development invocation to the installed
toolkit recompiled the fixture; that environment transition is not claimed as
evidence reuse. Wine comparisons always use a headless Wayland desktop.

`refactor-frontend.py` and the retained workspace demonstrate adding private helper
C through `component start --comparison-result --source-file --private-header`.
No frontend-specific checker, compiler or artifact rules were added. The native
adapter remains operator-authored C, with the original DLL identity
`50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d`.

The public partial export and shared assembly add this frontend to the existing
standalone source projects. Both x86-64 and AArch64 under QEMU match the original
in 81 normal CLI cases and 32 live-value cases. Each records 158 calls into the
replacement language parser. The linked programs contain no old `yyparse` body.
All 25 previous component records and their files remain byte-identical: 267 host
and 264 AArch64 component files. Each incremental build changes six objects;
host build time is 0.565 seconds and AArch64 build time is 7.276 seconds.

Costs are recorded separately in the existing receipts. The initial native
comparison spends about 0.64 seconds compiling, 0.064 linking, 0.053 producing the
optional views and 6.96 executing. The private-helper edit compiles in 0.032 seconds
and reuses the other five objects. Model/solver work is zero. Wine startup is a
separate, variable cost (7.62 seconds initially, up to 54.26 in a concurrent run).
The preparation API takes about 0.02 seconds in comparison execution; this is not
operator preparation time. First preparation still requires reviewing runtime
layouts, 58 internal native bindings, two entry adapters and observations. Manual
analysis/editing time was not separately timed; prepared recipe timings must not
be presented as the effort of establishing an unfamiliar boundary.

Focused admission/comparison/source/export tests and eight Nix repository gates
pass. These cover metadata freshness, format registry, production Python lint,
module closure, build infrastructure, boundary workbench, retired architecture
and native-kernel dependency boundaries. Existing optional-proof limitations
recorded in the previous module milestone were not part of this practical change.

## Transfer and remaining limits

The installed workflow also accepts a macro-configured DX-Ball graphics-bind
implementation through its 37-case, four-component consumer network, with twelve
existing service contracts and shared mutable sprite state. The bind unit's formal
profile is incomplete; practical comparison matches. This is retained-C consumer
evidence, not a new independent native proof of the bind operation.

This work remains a source-assisted partial jq lift. It does not recover arbitrary
grammars from binaries, make generated tables idiomatic by declaration, infer all
runtime effects, or finish the compiler/linker/value/platform backend migration.
Writable persistent state, concurrent behavior and unsupported executable transport
can still require substantial boundary/adaptation work. Strong qualification is a
separate objective, not a prerequisite for the practical editing loop above.

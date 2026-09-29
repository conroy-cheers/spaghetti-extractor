# Fresh-input connected lifting handoff

This recipe prepares the existing eight-component Hello network from the pinned
original executable, retained transfer plan and repository declarations/C. It
does not require an old comparison package, a completed workflow or a solver run.
The public walkthrough checks the five local neighbors, then runs the existing
conversion/quoting/native edit, discrepancy replay, repair, reuse and experimental
assembly sequence. [DX-Ball](../dxball-graphics-network/README.md) uses the same
development shell and authoring facilities with a structurally different state
and service boundary.

These are component-network experiments. Hello's routine image still omits
original process startup/TLS. The separate
[normal-entry workflow](../hello-program/README.md) now runs the selected C through
original startup and TLS. Add `--program-observer` when preparing this network
to enable its documented program recipe.
Passing this recipe does not qualify a whole portable Hello or native DirectDraw.
The subsequent [new string boundary](../hello-string-conversion/README.md) records
H1's previously unprepared component trial: manual analysis/declarations/adapters,
local C edits, discrepancy replay, neighbor reuse and normal-program execution.
That trial's first-time effort is distinct from reproducing this prepared network.

## Inputs and one-time provisioning

Use already retained inputs when available. The public target artifacts can
otherwise be retained once with:

```sh
nix build --out-link build/hello-original-input \
  ./targets#legacyPackages.x86_64-linux.targets.gnu-hello.input.original
nix build --out-link build/hello-plan-input \
  ./targets#legacyPackages.x86_64-linux.targets.gnu-hello.target.hello-executable-transfer-plan
nix build --out-link build/dxball-original-input \
  ./targets#legacyPackages.x86_64-linux.targets.dxball.input.original
```

These commands may fetch/build missing inputs; they are not part of the edit
loop. The DX-Ball extraction recipe runs its installer under headless Wayland.
The Hello preparation checks executable SHA-256
`71b228f2babc9d3b4095ecf355db676c8ed8b45a7c8a7d350f47e962b4bf554c`
and plan SHA-256
`7be11fac9ce1488cc893f7ac30ba9fde00e23a2fa92cf8f2e2c882965b77be11`.
A different binary/plan needs boundary review; changing a label is insufficient.

From the repository root, enter `nix develop .#lifting`. The shell supplies Python, host and
PE32 compilers, Wine, the Wayland wrapper, and the cross-compiler's thread runtime.
`components.comparison_environment.native_environment()` obtains the GCC runtime from the selected
compiler and the thread DLL from `SPAGHETTI_PE32_MCFGTHREAD_DLL`. The development
shell supplies the corresponding link search path while preserving existing
target-specific linker flags. Missing runtime inputs reject before preparation
creates its output directory. Actual tool and DLL bytes are bound in each
comparison package; discovery is not assurance evidence.
The helper and entry/import interception headers are installed with the toolkit;
new operator recipes do not need to import its test fixtures.

The full default development shell retains proof/toolkit-development tools. Its
larger Nix build environment triggered a Wine/Linux-loader crash in the retained
jq long-argument cases before the target started. The lifting shell limits build
inputs instead of changing target code or silently filtering runtime variables.

## Prepare and exercise Hello

Inside that development shell:

```sh
python tests/fixtures/hello-handoff/prepare.py \
  build/hello-original-input/bin/hello.exe \
  build/hello-plan-input/executable-transfer-plan.json build/hello-handoff-packages
spaghetti-headless-wayland python tests/fixtures/hello-handoff/walkthrough.py \
  build/hello-handoff-packages build/hello-handoff-run
```

Keep the complete Wine workflow in one desktop so unchanged checks use the same
execution environment. Every Wine application, boot and server runs inside it.
The component recipes remain independently callable; omitting their formerly
required environment-package argument selects these fresh tools. Supplying an
explicit retained package still works.

`prepare.py` records the manual complete-operation ranges for quoting, release
and growth, including the cold quoting fragment. It uses the existing exact-C
slice API and excludes lower supplier bodies from those local oracles. The
cleanup, reallocation and checked-allocation recipes review their own ranges
against the existing partition. Conversion and the full quoting engine use the
native original routines. This regenerates boundaries, interfaces, headers,
service bridges and dependency selection; it does not infer or prove the manual
partition. The authored C is source-assisted GNU code with its existing licenses.

The prepared tree contains `base`, `cleanup`, `reallocate`, `checked`, `conversion`,
`engine`, `original-runtime-engine` and `native`. A new operator can inspect and
adapt the manual declarations and ordinary C in the linked component recipes;
routine changes do not require editing generated hashes, solver models or Nix.
The workbench retains exact inputs and explicit assumptions. Shared aliases,
allocation/lifetime effects, native and controlled locales and actual abort
observations keep their documented scopes.

The walkthrough's public `component start/check` and `candidate build/test`
commands are recorded in `commands.json` and `connected/commands.json`. It exercises
a compatible conversion edit at three levels, incorrect characters through actual
callers, a state-only defect, replay after repair and zero-work unaffected reuse.
`preparation.json` and comparison receipts separate setup, compilation, execution,
linking and evidence costs; formal checks are not requested.

## Repeat the workflow on DX-Ball

The initializer's 65 reviewed blocks are already recorded in
`targets/dxball/intent/bindings-v5/directdraw-init.json`. The existing extractor,
normalizer and C renderer recover those blocks and the three helper operations
directly from the pinned original; no saved initializer C is necessary:

```sh
python tests/fixtures/dxball-graphics-network/walkthrough.py \
  build/dxball-original-input/DXBall.exe build/dxball-handoff-run
```

The four components retain their shared sprite/resource state, synchronous
callbacks and controlled platform services. The sequence defines packages afresh,
edits reset and initialization, detects memory and service-order differences,
replays after repair, reuses unaffected neighbors and assembles the selected
network. The regenerated original C and its boundary/semantic inputs are retained.
It remains a machine-derived-C oracle, not native DirectDraw or whole-game execution.

## Accepted run and remaining operator test

`build/operator-handoff-2026-09-22/hello-packages-v2/` prepares in 12.261s.
`hello-workflow-v2/` passes 33 public commands and 30 comparisons in 363.147s,
including the eight-unit / 63-case experimental assembly. The local compatible
edit takes 14.889s, with 0.032s compiling the changed C; unchanged engine reuse
takes 4.304s with zero compiler/link/execution/model/solver work.

The same shell's `dxball-workflow-v2/` passes 22 commands and 17 comparisons in
34.230s, including its four-unit / 37-case assembly. Fresh original recovery and
package preparation take 0.504s. All 37 recovered-original observations match the
prior retained oracle. The connected jq regression passes all 42 cases; integrated
Nix validation passes 13 tests and six repository/SDK gates. The checkpoint audit
revalidates all 48 comparison receipts and both experimental assemblies. No pilot
rebuild or formal check is part of these measurements.

These are automated reproduction and edit timings. They do not measure how long
an operator takes to establish a new boundary. H1 remains open until a previously
unprepared component is defined through the documented facilities, with analysis,
declarations, C adapter work and documentation gaps recorded separately. Its
workspace must expose inputs, shared objects, services, outcomes, examples and
assumptions, reusing shared layout/lifecycle definitions. Requiring changes to
checker, artifact or compiler internals counts as a tooling gap. An agent-run trial
must be identified as such; this recipe does not constitute a human usability test.

The separate normal-entry Hello workflow is now delivered for its documented
workloads. The subsequent practical whole-program path requires standalone source, reusable
platform backends and another architecture. Strong qualification retains its
separate standards; the successful experimental runs do not provide it.

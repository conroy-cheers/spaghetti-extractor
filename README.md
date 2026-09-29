# Spaghetti Extractor

Spaghetti Extractor helps operators reconstruct 32-bit Windows PE programs as
idiomatic C, one manually defined component at a time. Establish an executable
boundary, write C within the supported dialect, compare behavior, diagnose
differences, and integrate the replacement. Shared interfaces and C adapters
carry the knowledge needed for local work.

The delivered application may remain a Windows binary and use Windows runtimes,
including Win32, DirectDraw, DirectSound and WinMM. Wine is the preferred execution
environment for validation. Porting the lifted application to a non-Windows runtime
is outside project scope. Existing Portable-C artifact names and cross-architecture
experiments do not impose that requirement.

The practical workbench compares original and replacement behavior, including
declared memory and service observations. It supports retained cases, discrepancy
replay, unaffected-work reuse and source-library export. Original execution is
explicit: native comparisons run the pinned x86 instructions; recovered-C
comparisons use a retained machine-derived oracle. Wine always runs in a headless
Wayland desktop. Formal checks are available separately.

## Start with a component

Follow the [component workflow](docs/component-workflow.md) for a complete manual
editing, diagnosis, integration and export sequence. It includes a reproducible
DX-Ball example and explains how to establish a new boundary through the existing
Python authoring API. For an already prepared package:

```sh
nix develop .#lifting
spaghetti-extractor component start TARGET COMPONENT --comparison-package PACKAGE --output build/draft
spaghetti-extractor component status TARGET COMPONENT --comparison-package build/draft
spaghetti-extractor component check TARGET COMPONENT --comparison-package build/draft --output build/check
spaghetti-extractor component status TARGET COMPONENT --comparison-result build/check
```

For a package that executes Wine, run its checks inside
`spaghetti-headless-wayland`, as explained in the guide. Preparation and boundary
review happen once; ordinary implementation edits use the retained workspace.
They do not require rebuilding an extraction or qualification pilot.

The delivered examples cover bounded Hello, jq and DX-Ball workflows. Standalone
Hello and a partial jq source project execute on x86-64 and AArch64 under their
documented runtime assumptions. The [DX-Ball Windows source project](docs/dxball-windows-lift-delivery.md)
builds independently and exercises all five scenes, with explicit fidelity limits.
General Win32 recovery and a complete jq lift remain unfinished. A matching
comparison establishes sampled behavior in its declared scope; assumptions and
proved properties are reported separately.

## Static qualification and target analysis

The stronger pipeline retains its own acceptance and activation requirements.
Concrete comparisons do not supply missing proofs or qualify a provider. Static
analysis/refinement does not execute the original binary; experimental native
comparisons use the separate workflow above.

1. Inventory the original PE, executable bytes, imports, relocations, roots,
   code regions, and required ISA forms.
2. Emit an original-only static-program contract and canonical machine IR.
3. Recognize libraries and external interfaces, then emit checked structural
   facts for units, targets, external sites, callbacks, roots, exceptions, and
   fallback capabilities.
4. Package the exact transfer universe as `semantic-object-v1`, then link its
   complete reachable closure once as `linked-semantic-module-v2`.
5. Generate the executable machine-oriented baseline and propose components.
6. Replace components with portable C through machine-free interface V5,
   framework-managed state, exact machine bindings, contextual bisimulation,
   service graphs, and provider qualification.
7. Require a total implementation selection, one strong linked dispatch
   registry, and payload/link-map-bound activation authority for every enabled
   Portable-C definition.
8. Optionally run candidate-only behavior tests under headless Wine after static
   acceptance. A failure vetoes confidence but a pass never authorizes a lift.

Generated analyses are proposals unless a checker explicitly qualifies them.
Unsupported instructions, ambiguous targets, stale hashes, missing interfaces,
and uncovered executable bytes remain `incomplete`; observed contradictions are
`violated`.

### Qualification commands

```console
nix develop
spaghetti-extractor --help
spaghetti-extractor project status gnu-hello
spaghetti-extractor project analyze gnu-hello
spaghetti-extractor component list gnu-hello
spaghetti-extractor component status gnu-hello ascii-to-lower --development
spaghetti-extractor component status gnu-hello ascii-to-lower
spaghetti-extractor component build gnu-hello ascii-to-lower
spaghetti-extractor component start dxball startup-1000 --output build/startup-1000
spaghetti-extractor component check gnu-hello ascii-to-lower
spaghetti-extractor library status gnu-hello
spaghetti-extractor library inspect gnu-hello --family mingw-w64
spaghetti-extractor candidate list gnu-hello
spaghetti-extractor candidate status gnu-hello
spaghetti-extractor project check gnu-hello
```

A newly registered target does not need component intent up front. Its
transfer-v2, semantic object, and linked-module status can run first;
`component list <target>` then displays
the compact selector index from a bounded v2 proposal package. Rich proposal
diagnostics are stored in stable hash buckets. A checked preparation resolves
reviewed selectors once, then re-interns only each selected proposal's exact
resolution fields as the downstream component input; diagnostic and unrelated
discovery changes therefore do not invalidate component resolution. The
producer still validates every complete record before publishing the package.
Qualified component builds and configured candidate commands require reviewed
intent and a default configuration. The [local component workflow](docs/component-workflow.md)
also works directly from retained comparison packages. `candidate policy` prepares
a readable experimental policy and build command from those comparisons without
manual hashes; experimental execution and standalone source export retain their
separate scopes.

Linked-library discovery is ABI-first and independently cached. Immutable
catalog packs contribute per-function byte, structural, call, and ABI evidence;
the target-wide constellation solver uses those function matches to identify a
release and exact ownership island. An operator may adopt a reusable behavior
pack, but adoption intent is non-authorizing. The checked-island phase rechecks
identity, canonical crossings, and implementation bindings; candidate generation
then materializes an ordinary component whose exact unit inventory is rebound by
the component machine-binding checker. Compile, semantic refinement, services,
and exclusive ownership must still close before portable source replaces machine
IR. Unselected application code remains owned by the machine-IR fallback.

Public realizations use an explicit portable builder policy. They prefer a
CLI-selected inventory, then `SPAGHETTI_EXTRACTOR_BUILDERS_FILE`, the nearest
ignored `nix/builders.local`, and the XDG configuration file
`$XDG_CONFIG_HOME/spaghetti-extractor/builders`. Use `--local` to disable
remote builders for one command. When no inventory is found, the command
explicitly selects local execution instead of inheriting host-global builders.

Individual pipeline leaves are available only in the explicit expert namespace:

```console
spaghetti-extractor expert static-inventory-binary \
  --binary original.exe --out build/inventory.json
spaghetti-extractor expert isa-inventory \
  --binary original.exe --inventory build/inventory.json \
  --out build/isa.json
spaghetti-extractor expert static-program-export \
  --original original.exe --inventory build/inventory.json \
  --out build/static-export
```

The release gates are Nix-native and content-addressed:

```console
nix run .#test -- smoke
nix run .#test -- affected
nix run .#test -- full
nix run .#test -- benchmark
nix run ./targets#test -- dxball
nix flake check
nix flake check ./targets
nix build .#roundtrip-qualification --no-link
nix build .#isa-kernel --no-link
```

`nix run .#test` is the supported generic-toolkit test path. It creates a
filtered source snapshot, plans import/resource impact, and realizes stable CA
shards. Unchanged shards substitute without executing a builder. Heavy tests
consume shared compiler, Lean, Bochs, Nix, PE32, and headless-Wine fixtures.
Validation targets are independent consumers and run through
`nix run ./targets#test -- <id>`.

Developer operations use the same conventions:

```console
nix run .#dev -- doctor
nix run .#dev -- fixtures
nix run .#dev -- refresh --check
nix run .#dev -- scaffold test control branch_targets
nix run .#dev -- scaffold phase map-sccs pointer_provenance
nix run .#dev -- scaffold target sample-app
nix run .#dev -- explain-rebuild --before before.json --after after.json
```

`refresh` transactionally regenerates both checked repository manifests;
`refresh --check` verifies them without writing. Scaffolding creates
convention-wired files, refreshes both manifests, and rolls the new files back
if metadata generation fails. Add `--dry-run` to inspect the generated files
without changing the worktree.

Portable-source iteration is also Nix-native. GNU Hello exposes the canonical
component and target-gate workflow:

```console
spaghetti-extractor component list gnu-hello
spaghetti-extractor component status gnu-hello ascii-to-lower
spaghetti-extractor component build gnu-hello ascii-to-lower
spaghetti-extractor component start dxball startup-1000 --output build/startup-1000
spaghetti-extractor component check gnu-hello ascii-to-lower
spaghetti-extractor project check gnu-hello
spaghetti-extractor project check gnu-hello --acceptance
spaghetti-extractor candidate list gnu-hello
spaghetti-extractor candidate status gnu-hello --configuration operator-one-leaf
spaghetti-extractor candidate build gnu-hello --configuration operator-one-leaf
spaghetti-extractor candidate test jq
```

For compared C, `candidate export TARGET --comparison build/check --output
build/source` produces existing component source packages and a conventional
Makefile. Repeat `--comparison` to select connected units. The result is a source
library with its interfaces, assumptions and required services; application entry
and platform bindings remain explicit integration work. See the
[Hello source handoff](tests/fixtures/hello-source/README.md).
The [standalone Hello follow-up](tests/fixtures/hello-standalone/README.md) adds
ordinary application C and runtime backends, compares normal program behavior,
and executes the declared Windows-1252 configuration on x86-64 and AArch64 under
QEMU. Its optional portable UTF-8 entry accepts normal shell arguments while
preserving the target's best-fit narrow arguments and redirected output bytes.
An explicit diagnostic build also compares controlled allocation failure through
real program diagnostics and exit, with retained defect replay and repair.
After local component edits, `candidate export --update` refreshes the assembled
library while preserving application/backend work and retaining the prior library.
Changed boundaries or conflicting local edits require explicit review.
Its finite practical evidence is separate from strong qualification.
The [portable jq subsystem](tests/fixtures/jq-portable/README.md) carries twelve
existing array/path/string components through normal jq execution on both
architectures with an explicit unlifted source backend. Compatible source updates
retain unchanged component objects; affected program comparisons still rerun.
This is source-assisted partial lifting, not complete jq recovery.
Its source assembly can also consume the public exported library directly,
without the original comparison workspace or native runtime tools. Recorded
binding references support explicit backend integration through the existing
C generator; they do not validate new backend behavior.

Component drafts now include a [boundary workspace](docs/components.md#practical-originalsource-execution)
with inputs, shared types, services, outcomes, assumptions and examples.
`component status TARGET COMPONENT --comparison-package DIR` refreshes that local
view without running a provider build. The [string-length trial](tests/fixtures/jq-string-length/README.md)
uses existing shared string services for a new boundary, then carries the compared
C into the portable jq project. These guides describe the boundary; they do not
establish its correctness.

Building one component unit produces its non-authorizing V6 work package.
For an unconfigured region, `component list TARGET --near 0xRVA` lists the
bounded alternatives generated for the containing instruction. Add `--json` for
machine-readable choices. Use `boundary inspect TARGET component-seed:0xRVA
--proposal ID` to review one, then `boundary propose TARGET component-seed:0xRVA
--proposal ID --output DIR` to preserve that exact choice in an editable draft.
These proposals still require interface refinement and qualification.
After adding edited canonical `interface.json` and `binding.json` to the draft,
`boundary adopt TARGET component-seed:0xRVA --input DIR --output INPUTS` validates
them against the current selected boundary and writes the existing indexed
component inputs. Schema/intent self-digests may be omitted; the command derives
them and canonical value-binding order. It preserves binding blockers and uses
only draft activation. The output must be a new or empty directory; existing
target inputs are not merged or overwritten. Interface authoring and SDK
registration remain explicit steps before `component start`.

`component start UNIT --output DIR` verifies that package and copies it into a
writable worktree. `component start UNIT --apply` additionally requires a local
target checkout: it adds the generated skeleton to the target source tree and
re-hashes the existing canonical lifting intent as one locked, rollback-safe
transition. It never creates a parallel component-adoption intent.
Use `component check TARGET UNIT --source` while editing: it compiles the exact
source package and interface with the host and PE32 compilers and runs the
existing C-profile checks, even when machine bindings are incomplete. Errors
retain source filenames and compiler locations; `--json` returns structured
status and details. Success covers source compilation/profile only and grants
no qualification or activation authority. This phase depends only on the
selected source, interface and compiler inputs, so it does not require original
analysis or unrelated provider proofs. Run the default check for qualification.
An incomplete `component check` displays up to three failed proof obligations
when matching retained diagnostics are available, with recorded source/proof
locations and relevant next steps. These locations refer to the built artifact
snapshot. The command still fails until the provider qualification is complete.
Candidate status separately reports exact selection and the selected provider
mix, so exact completion cannot be mistaken for portable-C coverage;
candidate configurations exclusively own whole-program selection and
realization. Whole-candidate realization is gated by a complete linked semantic
module and total implementation selection, not by a status projection or test
result. Release acceptance additionally requires that every selected
Portable-C definition has its contextual-bisimulation
lineage and exact strong-dispatch link receipt; generated definitions retain
their exact provider authority. Declared candidate tests run only the generated candidate through an
isolated headless X session after static acceptance, and remain optional veto
diagnostics.
`project status` remains diagnostic. `component status` and `candidate status`
locally project one exact indexed domain artifact; none of the status commands
opens a gate. Add `--family`, `--code`, or `--all` together with `--details`
to fetch source-native blocker rows on demand.

## Public Surfaces

- `spaghetti-extractor`: project, component, boundary, library, and candidate
  operator workflows, plus explicit `expert` access to individual pipeline
  leaves.
- `nix run .#test`: cached smoke, affected, full, and benchmark toolkit gates.
- `nix run ./targets#test`: validation for one explicitly registered consumer.
- `nix run .#dev`: scaffolding, fixture discovery, environment diagnosis, and
  rebuild explanations.
- `flake.lib.mkTargetSdk`: the stable configured Nix interface for analysis,
  authority, candidate, lifting, validation, and target-bundle construction.
- [Composable component lifting](docs/components.md): exact leaf/group
  boundaries, portable interface V5, deterministic local checks, activation
  authority, fallback ownership, and incremental Nix artifacts.
- `targets/`: a separate in-tree consumer flake containing authored validation
  intent and source, never generic Python implementation code.

See [REPOSITORY_MAP.md](REPOSITORY_MAP.md) for every subsystem and dependency,
and [docs/architecture.md](docs/architecture.md) for the assurance model.

## Scope

The current machine profile is IA-32 PE32. Capstone and `pefile` provide
untrusted extraction proposals; the compact Lean model, Unicorn, Bochs, and
hardware-derived corpora qualify supported ISA behavior. Z3 assists bounded
symbolic analysis, and CBMC checks independently sharded contextual component
obligations. Ghidra remains an
optional proposal source.

The intended output is initially conservative C, not beautiful C. Components
can then be coarsened and rewritten into idiomatic, portable source without
requiring the entire program to retain x86 register state.

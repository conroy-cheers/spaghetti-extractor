# Performance And Invalidation

Performance is a correctness property of the interactive reconstruction
workflow. A phase that reads an undeclared global artifact may produce the
right answer, but it makes unrelated candidate edits expensive and is not an
accepted v3 phase design.

## Supported Workflow

Use only the Nix-first entrypoints:

```console
nix run .#test -- smoke
nix run .#test -- affected
nix run .#test -- full
nix run .#test -- benchmark
nix run ./targets#test -- <target-id>
nix run .#dev -- doctor
nix run .#dev -- fixtures
nix run .#dev -- refresh --check
nix run .#dev -- scaffold test <subsystem> <name>
nix run .#dev -- explain-rebuild --before before.json --after after.json
```

The scaffolder creates files by default, refuses overwrites and repository
escapes, and emits the affected Nix command. `--dry-run` renders the proposed
files. A real scaffold transaction refreshes both the Python import index and
the stable test manifest, and rolls its new files back if either metadata build
fails. `refresh` is the only supported writer for those checked manifests.
Test-only manifests and planners are excluded from the distributable toolkit
source, so changing test topology cannot rebuild the installed CLI package.
Direct Lean, compiler, emulator, Nix, or Wine execution from tests is a
policy error; tests consume a shared fixture. Wine fixtures are headless.

The test runner caches only the expensive evaluation from a filtered source
snapshot to the selected derivation paths. The receipt binds the full admitted
source hash, exact Nix expression, Nix executable and version, host system, and
derivation paths, and carries an integrity checksum. A hit still asks Nix to
realize the derivations, so Nix remains the sole build and substitution
authority. A concurrent source change prevents receipt publication. Inspect
receipt location, count, and size with `nix run .#dev -- doctor`.

Target component graphs contain controlled IFD boundaries because reviewed
selectors are resolved against content produced by static analysis. A cold
target-flake evaluation may therefore realize those CA preparation derivations
even when invoked with `--no-build`; the option suppresses requested check
realization, not evaluator dependencies. After preparation, `--no-build` is a
pure warm graph check and all content-derived paths substitute normally.

Library recognition has an orthogonal content-addressed chain:

```text
immutable artifact pack -> catalog signature shards
target machine IR -> target signature packs
catalog index + target signatures -> sparse constellation hypotheses
adoption intent + canonical boundaries -> checked whole-island receipt
checked island + reusable behavior pack -> generated ordinary component
generated component + runtime ownership -> candidate component package
```

Generated and authored components then converge on the same CA subgraph:

```text
interface + normalized semantics -> universal contract
exact machine projection          -> universal machine binding
source/IR/library authority       -> selected implementation
contracts + service graph         -> dependency SCC graph
dependency graph + activation     -> hybrid and portable release gates
```

Contract and implementation identities are deliberately separate. Editing
portable source cannot invalidate a consumer whose required interface did not
change. Editing an interface invalidates only its binding, implementation,
dependent contract edges, and release descendants. The total activation-plan
hash is included only at the release-gate layer, where fallback ownership is a
whole-configuration property.

Catalog lookup is inverted by ABI partition, fixed anchors, normalized hashes,
and structural features. It scales with target features plus sparse hits, not
catalog functions multiplied by executable-section bytes. Adding a pack does
not rebuild target signatures; changing an adoption does not rerun extraction or
matching. Native retrieval emits proposals only, and checked Python authority
revalidates selected witnesses from canonical pack records.

The Nix implementation uses separate phase-specific Python closures for catalog
ingestion, target signatures, catalog search, constellation solving,
checked-island authority, and generated-component construction. A catalog
change therefore does not invalidate target signatures; a target-unit change
does not rebuild the catalog; and an adoption change rebuilds only its authority
receipt, generated component, and downstream candidate ownership closure. On
the GNU Hello benchmark, a recognition-only
rebuild with machine IR available measured 27.394 seconds. A cold end-to-end
realization after source-closure changes, including the original MinGW build,
PE inventory, rooted state machine, and machine IR, measured 115.195 seconds;
the immediately repeated library-status realization measured 0.051 seconds.
The warm result is the important interactive invariant. Clean prerequisite and
scheduling cost remains a separate optimization target.

## Semantic-object scheduling

The active cache topology has three coarse semantic units: one semantic object
compiled from checked machine IR, one linked semantic module closed against a
qualified platform, and independently reusable selected provider packages.
Native realization consumes those exact identities. Nix is the persistent
content cache; within each phase, Python/Rust may retain the entire decoded
module, dense indexes, solver contexts, and prepared outputs and may use every
available core.

The production link is a conservative semantic-object graph link, not a
whole-program abstract interpretation. Its sole scheduled input is the
content-bound semantic-object package; the original PE and duplicate
behavioral-roots artifact are already represented by that package and are not
link inputs. The linker closes roots over declared relocations and runtime
dependencies, inventories exact transfer-v2 indirect/callback sites, and emits
typed finite-domain obligations. The context-sensitive Python/Rust
must-provenance fixed point is a separate veto-only performance and precision
check. Its step bound and result never enter `linked-semantic-module-v2`
identity or completeness.

On the current real artifacts, canonical Hello linking takes 3.7 seconds and
real libjq linking takes 20.6 seconds for 36,005 transfers and 51,809
relocations. The former production path did not finish libjq within fifteen
minutes because it ran the optional native fixed point before linking. This is
an algorithm and boundary correction, not a cache: only the canonical module
and independently required receipts persist through Nix.

The same rule applies one phase upstream. Profiling the exact 36,005-unit,
531-MiB libjq prepared-machine-IR input found that final machine-IR export spent
326.3 of 419.7 seconds comparing every unit start with every reachable
instruction. The classifier now uses a deterministic interval sweep, coverage
merges its code ranges once, and the zero-materialization path preserves
immutable nested unit records instead of cloning the complete expression
forest. Total wall time is 64.9 seconds (6.5x faster): overlap classification
is 0.77 seconds, coverage is 0.07 seconds, and cutpoint materialization is 7.7
seconds. `machine-ir.jsonl`, its manifest, and recovered executable data remain
byte-for-byte identical to the pre-change artifacts. This optimization adds no
format, cache, native dependency, or semantic implementation.

Preparation and final export now also import their owning Python modules
directly. The former shared `reconstruction.ir` facade pulled final
classification into the preparation source closure, so an exporter-only edit
rescheduled the 531-MiB prepared package. The closure cut caused one intentional
content-addressed re-interning; both phases converged on their existing output
paths. The complete one-time libjq realization took 2 minutes 54 seconds, while
the immediate unchanged realization took 0.065 seconds. Nix may still list
floating content-addressed derivations before resolving their known outputs;
that display is not evidence that their builders ran.

The retired artifact-v3 Nix scheduler split units, SCCs, source preparation,
reinterning, and reductions into an additional public derivation graph. No
target consumed that graph after the semantic-module pivot, so its Nix
constructors and developer-only fixtures were removed rather than wrapped in
another cache. The Python artifact-set codec remains an implementation detail
for active typed packages. Incremental acceptance is now checked by mutating a
semantic object, platform, provider selection, and observation independently
and asserting that only their true descendants rebuild.

## Native Acceleration Boundary

The supported Python package includes a Nix-built PyO3 extension for measured
CPU-bound artifact kernels. Native calls are deliberately coarse grained: the
canonical reader validates and converts one complete bounded NDJSON pack in a
single call. Python retains typed schemas, dependency tracking, completeness,
diagnostics, and verdict production, so a native result cannot turn missing or
contradictory evidence into acceptance.

Every native operation has a Python reference implementation and differential
tests for valid, malformed, noncanonical, oversized, and Unicode inputs.
Authority derivations require the pinned native API and fail closed when it is
missing. Developer use may fall back to the reference implementation for
diagnosis. Further modules, such as graph fixed-point kernels, are justified
only when profiling shows that kernel remains dominant after choosing the right
algorithm and data representation. Fine-grained per-record or per-edge PyO3
calls are prohibited because they move overhead across the FFI boundary rather
than removing it.

## Budgets

The release gates are:

| Gate | Limit |
|---|---:|
| Smoke, cold | below 10 seconds |
| Smoke, warm | below 2 seconds |
| Warm generic `nix flake check` | below 10 seconds, zero builders |
| Clean generic suite | below 4 minutes with configured builders |
| Warm Lean/Unicorn differential pair | below 10 seconds |
| Common source edit | dependent shards below 60 seconds |
| One target unit edit | one transition pack plus graph descendants |
| DX-Ball transition artifact | at most 64 MiB |
| Unchanged DX-Ball authority | no slower than 1.3 seconds, zero builders |
| Clean DX-Ball static analysis | below 5 minutes |
| Any governed shard/pack peak RSS | recorded, not gated |

Oracle processes may use a separately declared budget, but they must remain
shared fixtures and cannot be hidden inside an ordinary proof shard. Every test
shard reports elapsed seconds, peak RSS, resource class, and budget compliance.
Peak RSS is diagnostic rather than a release veto. Hot phases should retain
content-bound decoded data, dense indexes, reverse indexes, and wider shared
working sets whenever that lowers CPU or wall time. The ordinary test harness
records each shard's peak RSS but applies no project memory ceiling; OOM and
sustained swap thrashing remain operational failures owned by the host/Nix
resource boundary. Canonical and test phases default to that boundary; the
repository carries no project-level RSS ceiling or configurable memory tier.

The semantic-link migration confirms where the remaining cost lives. The real
GNU Hello link peaks below 1 GiB in the recorded baseline, while a combined
Hello, jq, and DX-Ball regression evaluation schedules 706 transitional
derivations. The governing optimization is therefore removal of legacy
authority-DAG fan-out and repeated semantic phases, not serialization tricks
or tighter memory. The completed cut must compile each semantic object once,
run one conservative may-link, and expose cheap views from that result; it must
not add another status cache or independently scheduled evidence projection.
Even a change confined to the linked-object view/generation projection causes
534 scheduled derivations for Hello and 256 for the jq/DX-Ball pair in the
current migration graph. Those figures are explicit retirement targets for the
authority DAG, component re-instantiation, and repeated Python closure parity
paths; increasing memory budgets cannot improve them.

The DX-Ball callback-pointee cut removes another false platform dependency.
Qualified-platform qualification previously imported and content-bound the
entire reference-provenance facade merely to obtain its total-operation
coverage declaration.  Callback registry, object-reference, or fixed-point
implementation edits therefore rescheduled the target-independent platform
release and its visible 32-shard graph.  The coverage declaration now lives in
the small `transfer/provenance_coverage.py` module.  Qualified-platform and
Behavioral-C coverage checks import only that declaration; linked-semantic-
module construction consumes only the conservative semantic-object graph. The
separate performance veto still executes the full Python/Rust provenance
kernel. An architecture assertion rejects any other provenance
module in the qualified-platform source closure.  This is a dependency-edge
removal, not a cache or second semantic implementation, and it leaves RAM
available to the resident fixed point rather than rebuilding unrelated ISA
qualification.

The first closure-authority clean cut removed the independently scheduled
target parity fixed point and made the Hello-derived registration fixture use
the linked-module closure directly. With the semantic-object role change in the
same source cut, a dry-run of the changed-tree Hello aggregate schedules 531
derivations instead of 534. The three-derivation reduction is intentionally not
presented as the main speedup: it proves the duplicate closure edge is gone,
while showing that legacy authority construction and component/status fan-out
still dominate evaluation. The next performance work removes those producer
edges rather than adding a cache around them.

The linked semantic module now also acts as the package boundary it denotes.
It republishes the semantic object's exact store members as symlinks, validates
them once per consumer process, and retains their resolved paths in the loaded
module object. Native realization therefore receives one linked package instead
of separately wiring the original interface, transfer plan, object authority,
resolved environment, and qualified-platform digest. Closure-only legacy
consumers deliberately retain a tiny content-addressed copy projection: the
invalidation test shows it remains reusable when unrelated linked-module bytes
change. Native consumers bypass it and use the package. This reduces repeated
validation without a cache service, second IR, eviction policy, or
memory-saving reconstruction, while preserving the one cache boundary that
currently prevents broad transitional invalidation.
The legacy synthetic DLL may explicitly supply its pre-migration closure until
its handled/unwind exception protocols move into the resolved environment; the
normal realization path uses the module-owned closure. Normal callback
transport no longer schedules the authority-v3 callback graph: the existing
runtime profile and transfer-v2 registration occurrence produce the checked
frame binding directly, while the linked module owns target reachability and
escape lifetime. The real-Hello semantic-object cold graph dropped from 219 to
88 missing derivations after the exception and callback side edges were cut.

SDK native-realization construction is lazy and remains off the status path:
enumerating all nine Hello configuration realizations takes about 0.2 seconds.
Forcing the default realization after a source change still required 3 minutes
7 seconds of Nix evaluation, exposed a nominal 421-derivation closure, and then
failed correctly because Hello's native-ingress plan is incomplete. This
separates the two performance regimes clearly. The module/provider/realizer
cache boundary is cheap to address, while the inputs still inherit legacy
authority-v3 and per-component fan-out. The remedy is to retire those producers
as semantic-link facts migrate, not to raise memory ceilings again or introduce
a project cache around the 421-node graph.

The repeated Python implementation closures are now derivation-free. Before
the cut, the same Hello realization graph contained 126 scheduled
`python-closure` derivations: each reparsed a checked import graph, copied a
small exact source tree, and emitted a receipt before the semantic phase could
start. The generated module index now carries each module's source SHA-256.
Nix retains exact role/source-class closure and stale-index rejection during
evaluation, materializes only the selected module/resource files with
`fileset.toSource`, and emits the closure manifest with `builtins.toFile`.
The repository metadata gate remains the single whole-repository AST/resource
freshness check. This deliberately spends evaluator memory on the checked
index and filtered filesets to remove build scheduling and process startup; it
does not replace precise invalidation with one broad Python source dependency.
A closure-representation change causes a one-time re-interning of dependent
content-addressed phase receipts, so cold migration timing is recorded
separately from steady-state graph and warm timing.

A controlled DX-Ball probe on 2026-09-02 confirmed that this boundary still
works after the V8 runtime work. A comment-only edit to
`candidate/runtime.py`, with the checked module index refreshed, changed the
qualified-runtime and downstream aggregate derivations but preserved the exact
transfer-plan, semantic-object, Behavioral-C, and linked-semantic-module
derivation identities. Reverting the comment restored the original downstream
identities. The Python-closure architecture check now asserts both halves of
that dependency cut: semantic linking excludes runtime-provider modules, while
runtime qualification contains its runtime implementation. The earlier broad
388.81-second rebuild included edits to shared external-contract code and was
not evidence for another cache or closure design.

The exact recursive GNU Hello default native-realization graph falls from
1,882 derivations, including 126 Python-closure derivations, to 1,756
derivations with zero Python-closure derivations. Fifty repeated exact-closure
evaluations take 0.345 seconds after rooting filtered traversal at `src/`
rather than the repository root. The initial whole-repository prototype was
rejected because it traversed unrelated target/private/native trees and made
evaluation slower despite reducing scheduled builds.
With the same missing downstream realization products, `nix build --dry-run`
now reports 294 scheduled derivations rather than 420. A direct warm evaluation
of the real Hello default native-realization derivation takes 37.786 seconds,
effectively preserving the prior 36.9-second evaluation cost while eliminating
30 percent of the scheduled jobs. Evaluation remains the next measured target;
this cut removes process scheduling rather than claiming to solve the legacy
authority/component expression fan-out.

The subsequent target deployment-tail clean cut makes native realization the
only ordinary candidate build, acceptance, and Wine-test authority. Twelve
standalone Nix wrappers for static candidate construction, structural/release
receipts, native build/link receipts, loader composition receipts, and module
deployment were removed. After the broad source/package moves that accompanied
the cut, one cold Hello status materialization scheduled 161 derivations and a
default candidate dry-run scheduled 166; those numbers include migration-wide
invalidation and are not steady-state cache results. Direct status evaluation
took 1.33 seconds before materialization, while the unchanged public status
path took 0.113 seconds afterward. The result supports retaining decoded
semantic modules, indexes, solver state, compiler processes, and object
manifests aggressively in RAM. The optimization target is cold invalidation
breadth and useful parallelism, not peak RSS or memory-saving reconstruction.

Transfer compilation and target ISA requirement extraction have also moved
ahead of the legacy authority reducer. They are now canonical semantic inputs,
and authority can only consume the exact ISA occurrence inventory for parity
projection. Hello retains the same 1,756-node total while authority-named nodes
fall from 14 to 12; the replacement ISA payload preserves all 323 forms,
21,109 occurrences, and the exact requirements identity. This intentionally
does not duplicate or cache the target extraction: semantic-object construction
and temporary authority parity share one content-addressed input.

The target-independent Lean proof tree is imported through its own exact
`fileset.toSource` identity. A plain nested flake path carried the enclosing
dirty source context, so an unrelated Behavioral-C or runtime edit could
reschedule the semantic kernel and make the 32-shard qualified-platform graph
look invalidated until content-addressed outputs converged. A controlled
candidate-source mutation now leaves both derivation paths unchanged:
`/nix/store/h06gwjnxpk0ky0gyn0vb10g5gr45k32n-spaghetti-extractor-isa-semantic-kernel.drv`
and
`/nix/store/hcf45smqgv6c86znz3rd8apqqb65p2zn-spaghetti-extractor-qualified-platform-v1-release.drv`.
The one-time source-identity transition realized the two small kernel bindings
and converged on the existing downstream content in 29.300 seconds; the
immediate qualified-platform realization took 0.063 seconds. No corpus,
qualification, shard, or authority format changed. This is the preferred
performance pattern: make immutable inputs independently addressable, then let
Nix reuse them; do not add a mutable proof cache or constrain the resident
working set.

Native realization now consumes only precompiled content-addressed provider
objects. Generated Behavioral C, portable C, and reviewed intrinsic
runtime/ingress code are compiled at their owning provider boundaries; the
realizer validates the selected object digests, deduplicates their exact union,
and links without reading source packages or compiling a fallback. The old
candidate source-closure/compilation subsystem has been deleted. This moves
reuse to the most fundamental safe boundary: identical qualified object bytes
are compiled once and reused by every compatible configuration, while a
realization invalidates only when its linked semantics, selection, exact
selected/intrinsic objects, load image, or composition inputs change. The
synthetic native manifest contains no `compiled_in_candidate_derivation` rows,
and the full PE32/Wine, SDK, and real-Hello vertical passes. Available RAM may
be used to keep all provider manifests, decoded module members, symbol maps,
and link-planning indexes resident; no memory-saving source reconstruction or
object eviction is warranted.

The SDK also has only one intrinsic-provider package and one implementation
selection per component configuration. The former status-only `unavailable`
provider and preliminary selection duplicated every provider identity before
the real materialization. The sole package now emits compiled evidence when
its linked module closes and honest incomplete evidence when internal runtime
lowering is blocked; status and realization consume the same selection. This
deletes two configuration-indexed derivations without adding a cache or making
status authorize execution. A warm combined synthetic-native plus GNU Hello
request evaluates in 0.096 seconds on the validation host.

The remaining component proof-kernel compatibility adapter now projects only
the exact component-rooted execution closure. It previously walked and
translated every transfer in the target for every semantic-refinement process,
even though the proof kernel could consume only the selected component units.
The same transfer-v2 input and checked closure now reduce the per-process
working rows from 7,937 to 104 for GNU Hello, 4,614 to 23 for jq, and 9,008 to
94 for DX-Ball. This is deliberately an in-process working-set reduction: it
adds no persistent cache, public artifact, scheduler node, or semantic
authority. RAM remains available for the complete selected closure, prepared
indexes, CBMC inputs, and solver state. The target regressions pass unchanged;
the longer-term clean cut is direct transfer-v2 execution in component
refinement followed by deletion of the compatibility projection itself.

That clean cut is complete. V5 component refinement now keeps the selected
canonical rows resident and executes their `transfer_v2` bodies directly. It
does not write, hash, parse, or validate a second proof-unit JSONL and manifest
for every component process. Narrow call-event and atomic-authority boundary
views are computed in memory only for selected rows. The retired projection
module and its format literals are absent-gated, so the speedup cannot turn
into another persistent cache or semantic pipeline. The real Hello, jq, and
DX-Ball aggregates pass after this cut. The first Hello validation also moved
inductive SCC edge extraction onto canonical transfer terminators, closing a
hidden consumer of the projected control fields instead of retaining a second
control model.

Component refinement no longer schedules a second execution-closure
derivation either. Each component contract already content-binds its exact
transfer identities, entry and exit units, service crossings, and machine
projection; transfer-v2 already owns the finite-control route inventory.
Refinement therefore selects those rows directly, validates that local control
cannot escape the selection, and includes provider-contract rows only for an
explicit induction proof. The module-wide linked closure remains the single
root-provenance authority used by semantic linking and deployment. This clean
cut removes one aggregate derivation, its JSON serialization and validation,
and four workflow inputs without introducing a replacement cache. High-RAM
hosts may retain transfer indexes and solver state freely; resident-set size is
telemetry rather than an acceptance limit.

The V5 component unit inventory is now a sidecar of the contract/binding
phase, not a separate phase. Both artifacts require the same binding intent,
structural-unit hash, transfer bindings, and selected transfer-unit geometry;
the old graph nevertheless launched one Python process to parse all of
transfer-v2 for the inventory and a second process to parse it again for the
contract. One shared parse now emits all three checked files while retaining
their independent content hashes. This removes 12 derivations and full-plan
parses from GNU Hello, 21 from jq, and 6 from DX-Ball without merging component
cache boundaries or changing any public artifact. Their target regression
graphs fall from 202 to 190, 189 to 168, and 132 to 126 scheduled derivations,
respectively, on the clean-cut validation build.

All downstream component phases now consume the canonical machine-free V5
interface package instead of rereading the operator's raw interface JSON.
Contracts, refinement, implementations, work packages, induction providers,
and dependency graphs therefore key on the compiled canonical boundary; an
equivalent presentation-only edit converges at that existing content-addressed
boundary rather than fanning out through every component phase. No interface
adapter or new artifact was introduced.

Work-package generation also no longer loads the target-wide transfer plan to
recover two integers per selected unit. It checks the contract phase's exact
unit-inventory digest and uses that inventory's `rva_start`/`rva_end`, removing
12 full-plan parses for Hello, 21 for jq, and 6 for DX-Ball. Portable dependency
graphs likewise omit transfer-v2, Behavioral-C manifests, coverage, and
structural-unit inputs: those are used only when hybrid mode constructs the
generated-C remainder. The portable and hybrid graphs remain separate because
that separation prevents generated-C churn from invalidating portable-only
qualification.

Portable component and adopted-library qualification now take the linked
semantic module as their sole target-semantic input. Transfer-v2, the resolved
environment, and machine-object authority are loaded from its validated package
members instead of being scheduled beside the module and then pairwise hashed
back against it. This removes three broad dependency edges per implementation,
eliminates a cross-pairing state, and makes module packaging the actual cache
boundary. Portable compilation also no longer takes the target-wide
Behavioral-C package merely to find `state-machine-runtime.h`. The exact shared
runtime ABI now belongs to the neutral transfer domain and is rendered directly
into each component's temporary compile tree. Consequently a fallback-C layout
or unit edit cannot invalidate every portable component; only a genuine shared
ABI source change can.

V5 semantic refinement follows the same package boundary. It receives one
linked semantic module and loads transfer-v2 plus the resolved environment from
validated members; the component workflow no longer accepts a resolved-
environment argument at all. Component contracts remain independently cached
machine selections upstream, while CBMC refinement cannot represent a stale
transfer/environment/module cross-pair. This deletes two authority inputs and
one workflow API without changing proof obligations or adding a projection.

Adopted library islands now use the identical semantic-module member path for
transfer-v2 and the resolved environment. Their orchestrator has also dropped
its dead Behavioral-C and resolved-environment parameters. Structural-unit
geometry remains explicit only in V5 component generation, where it is an
independent structural binding not currently packaged by the semantic module.
This keeps recognition non-authorizing and removes inputs rather than hiding
them behind a new library facade.

The following V5 library-authority phase now loads transfer-v2 from that same
module as well. `linked-libraries.nix` therefore has no transfer, environment,
or Behavioral-C argument; its target-semantic API is one linked module plus the
independent structural-unit artifact. This is the narrowest honest boundary
until structural geometry is either proven redundant with transfer-v2 or made
an explicit semantic-object member.

Native ingress and shared runtime have now removed their final packaged
execution-closure read. The linked module carries conservative active symbols,
edges, effects, holes, and typed obligations and exposes a transient in-memory
view over those resident tables. Optional fixed-point status and identity are
absent from the module. No extra file, cache, parser, or production fixed-point
run was introduced. This spends the available RAM on the already decoded
linked module and removes one parse plus a stale cross-pairing seam per
realization.

The real-Hello semantic-link benchmark and independent replay remain strict
isolated release vetoes, but are no longer embedded in the broad target
regression link farm. Independent replay recomputes root/relocation inclusion
without invoking the fixed point. The performance check rebuilds and compares
complete canonical linked-module bytes, then runs optional precision under its
separate CPU budget. Neither path publishes another semantic artifact, and
ordinary iteration never waits for optional precision.
The compatibility execution-closure projection is now retired entirely.

The standalone Nix execution-closure phase and its focused public artifact gate
are retired as well. The transfer-domain codec remains an internal transient
used by the linker and veto-only replay, but it is no longer independently
scheduled or exposed as a cache product. On the clean-cut real-Hello graph,
optional precision retained its 30-second CPU veto at the earlier 25.107-second
worst CPU, 25.367-second worst wall, and 843,296 KiB peak RSS. Those observations
are diagnostic only. Canonical replay binds module and semantic-object
identities without accepting or publishing an execution-closure file.

Intrinsic-provider materialization has now been removed from the scheduled
graph. The intrinsic phase emits only semantic qualifications and total
choices; it has no compiler, Behavioral-C package, component-object package,
runtime source, ingress plan, or object-manifest input/output. Native
realization opens the selected generated-C provider's exact content-bound
Behavioral-C package reference and the selected portable-C provider's checked
dispatch manifests,
then retains the complete linked semantic module and generated runtime in one
process while compiling the eleven independent support sources concurrently.
This removes one configuration-indexed build phase and every cross-package
pairing edge without adding a cache, daemon, or authority surface. Peak RSS is
telemetry only; the process is intentionally allowed to keep all decoded and
rendered data resident when that reduces parsing and scheduling latency.

The completed migration has the following measured results on the validation
host. Times are wall-clock unless the row names aggregate shard execution.

| Gate | Measured result |
|---|---:|
| Smoke, cold / warm | 5.62 s / 0.17 s |
| Warm generic `nix flake check` | 2.06 s, zero builders |
| Wide post-migration generic release build | 59.25 s with configured builders |
| Warm Lean/Unicorn benchmark | 4.72 aggregate shard seconds; 0.53 s warm realization |
| Common source edit (`semantic_index.py`) | 7.06 s for 24 dependent shards plus smoke |
| Test-only edit | one changed stable shard plus cached smoke, 19.02 s including evaluation |
| DX-Ball transition members | 32,541,657 bytes for 9,041 records |
| DX-Ball final authority, clean / warm | 174.39 s / 0.09 s |
| Generic full-suite peak shard RSS | 163,416 KiB |

The first native artifact migration reduced the GNU Hello parametric proposal
phase from 85.25 seconds to 7.06 seconds and the checked-summary producer from
79.5 seconds to 7.26 seconds. The proposal retained its exact 7,934 records and
artifact identity. The summary output likewise retained its artifact identity;
an independent storage replay takes 0.86 seconds. These are phase-level results,
not a claim that every target-analysis phase is now native or equally fast.

Machine-consumed JSON is emitted in canonical compact form. On the GNU Hello
analysis artifacts this reduced the exact static-program contract from 70.2 MiB to
30.5 MiB, ABI callsites from 57.1 MiB to 25.5 MiB, the machine-IR manifest from
32.1 MiB to 18.0 MiB, and the reconstruction plan from 59.0 MiB to 30.8 MiB.
The v2 component-proposal package is 59 MiB instead of the former 143.5 MiB
monolith: its selector index is 8,153,250 bytes and its 64 bounded rich-record
packs total 33,871,985 compressed bytes, with a 666,639-byte largest pack.
Semantic proposal metadata lives in the selector index; the package manifest
is only a transport inventory. The producer validates all records once in pack
order,
while component resolution validates only the index and selected record.
Exact ISA request planning for 21,040 unique instruction locations takes about
0.33 seconds after replacing pairwise overlap discovery with one canonical sort
and adjacent-interval check. Rebuilding the real GNU Hello proposal package
from warm upstream analysis inputs took 97.7 seconds after the package
migration. The first `component status` after that package identity changed
took 37.1 seconds; an unchanged warm invocation took 1.17 seconds. Component
resolution now consumes a controlled-IFD selected-proposal input: changing an
unselected or diagnostic-only discovery field reruns only the preparation,
while preserving the selected input and every downstream derivation identity.
A changed selected membership or identity invalidates resolution and its
actual descendants. On GNU Hello the resulting selected input is 16,421 bytes,
down from the 59 MiB complete proposal package. The first status invocation
after introducing the boundary rebuilt its closure in 51.36 seconds; the
immediate unchanged invocation took 0.295 seconds. The corresponding selected
inputs are 21,860 bytes for jq and 3,172 bytes for DX-Ball.

Component status has a second authority boundary. Pure component development
and activation leaves do not depend on canonical external sites, ISA
qualification, implementation capability coverage, or final authority. Only a
component whose authored binding declares an `external_site` service consumes
the pre-ISA canonical external-site graph. Whole-target ISA qualification and
release authority are evaluated only by candidate release products.

Framework-owned planning for the 9,041-unit DX-Ball structural universe takes
about 1.70 seconds and 73 MiB RSS. The controlled Nix mutation fixture verifies
that changing one unit changes one transition pack, two dependent SCC and
composition packs in its fixture graph, and no independent pack. The full
generic suite now runs 1,889 tests, up from the 1,664-case pre-migration
inventory; 364 generated corruption cases exercise authority-family failures.

GNU Hello, jq, and DX-Ball retain exact structural universes of 7,882, 4,516,
and 9,041 units respectively. Their stronger formal-analysis aggregates remain
truthfully `incomplete`: Hello and jq stop at callback frontier
`original-cutpoint-00001040-0000104d`, while DX-Ball stops at
`original-cutpoint-000010cb-000010d0`. The migration did not hide or relabel
those blockers.

## Semantic-V2 invalidation checkpoint (2026-08-31)

The first complete faithful GNU Hello deployment confirms that runtime memory
is not the limiting resource. Native realization used roughly 1.2 GiB peak RSS
and about one minute of CPU while retaining the decoded semantic module and
large generated tables; the resulting candidate executed correctly. This is
acceptable under the speed-first policy.

The remaining problem is dependency fan-out. A change confined to canonical
runtime/realization Python scheduled a nominal 96-derivation Hello realization
closure. Adding independent semantic-object replay support for the already
admitted dynamic-export catalog made a focused real-scale replay report 88
derivations and the full Hello aggregate 205. The aggregate passed, but these
counts are too high for an interactive semantic or receipt edit. The configured
remote builder was unavailable during this measurement, so local wall time is
not a stable release number; the derivation inventory itself is the useful
evidence.

The remedy remains architectural and cache-free: phase source closures must
bind only the owning semantic codec and its true implementation dependencies;
target-independent ISA qualification and unrelated component refinements must
not descend from a receipt parser, runtime renderer, or replay checker edit.
The content-addressed semantic module, selected provider packages, and native
realization remain the reuse boundaries. Do not add an eviction cache, daemon,
serialized compact mirror, or second semantic pipeline to mask these false
edges.

Direct V6 component qualification now has the intended local invalidation
boundary. An independently content-addressed component projection emits the
existing `semantic-slice-v2`; ordinary machine-overlay qualification consumes
that slice and no V6 presentation work package or complete linked-module
artifact. Callback publication and `encapsulated_owned` total-ownership
admission retain the linked-module input because those are genuinely
module-wide facts. This is dependency removal, not a mutable cache or a second
semantic pipeline.

The V7 module-runtime plan applies the same rule to external callthroughs.
It retains the planner's expanded relation in RAM but serializes a single
target-contract catalog, deduplicated checked domains, and physical-site
references. DX-Ball preserves all 25,064 site-target pairs while shrinking the
plan from 115,277,024 bytes to 10,851,144 bytes (90.6 percent). A controlled
target-only Nix edit retained the exact derivation identities of the transfer
plan, qualified platform, semantic object, linked module, generated provider,
and runtime provider; only target lint/regression leaves changed. The floating
content-addressed dry-run continued to print the whole 123-node graph, but an
unchanged realization took 0.09 seconds and ran no builder. Treat that listing
as graph visibility, not invalidation evidence; compare derivation identities
and executed builders instead.

The controlled codec tests show that both an analysis-only module change and
an unrelated added definition preserve the exact slice payload and identity.
Changing a selected definition invalidates it. Nix derivation inspection on
real Hello shows no work-package or linked-module input for `ascii-to-lower`,
while `startup-callback-registration` includes the linked module in addition
to its local slice. A forced prepared-input rebuild took 5.94 seconds for the
small `ascii-to-lower` provider and 13.51 seconds for the medium
`program-name-selection` provider. Both are comfortably within the 60-second
and five-minute gates. The full Hello aggregate and Wine cases pass with these
boundaries.

The semantic-link performance receipt now measures the two intentionally
different boundaries in the same isolated run. On real GNU Hello, three full
optional fixed-point-plus-link samples used 23.97--24.09 seconds CPU, below the
30-second diagnostic budget. Once the construction-local link facts were
prepared, the canonical V2 projection used 907--922 milliseconds CPU and
908--924 milliseconds wall time, below the five-second operator-path budget.
The receipt enforces both CPU and wall time for the prepared projection; peak
RSS remains telemetry and was about 998 MiB.

## Guardrails

- Every artifact and schedule has bounded parsing, canonical ordering, exact
  dependency identities, and corruption tests.
- `incomplete` means required evidence is absent; `violated` identifies a
  contradictory location. Neither can authorize candidate generation.
- Target names and policy stay in the independent `targets/` consumer flake;
  generic evaluation and cache fingerprints exclude that corpus entirely.
- Test-only changes retain stable shard assignment. New tests use convention
  directories, so no central shard list needs editing.
- Diagnostic formatting cannot be an authority dependency.
- CA derivations improve substitution, but never compensate for a monolithic
  semantic dependency. Invalidation is tested by comparing derivation paths
  under controlled unit, edge, phase, checker, and test mutations.

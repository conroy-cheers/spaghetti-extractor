# Stage A Architecture

## Authority

Stage A has one acceptance claim: Lean checks
`StageA.GeneratedRelational.candidatePE32ProgramsEquivalent` for the exact
original and candidate PE bytes under the declared launch and external-world
profile. Only a `stage-a-relational-nix-build-v1` report with `verdict: pass`,
`claim_scope.acceptance_eligible: true`, a trust-zero final theorem audit, and
all mandatory checks true may authorize a faithful reimplementation. The
current command surface accepts no host-local or legacy proof report.

Historical v2 validation and regional-refinement reports are not accepted by
the current command surface. Image, region, segment, solver, and
composition-progress certificates are intermediate evidence. Contract export
and candidate-only feedback commands are not acceptance gates.

## Python Phases

Implementation and the stable API live in `spaghetti_extractor.relational`:

- `api.py` exposes the Nix-backed preparation, proof, build, and report-checking API.
- `schema.py` parses immutable, runtime-validated artifact boundaries.
- `ir.py` validates proof, graph, acceptance, and progress records.
- `phases.py` makes decoded, state-analysis, and composition phase order
  explicit with immutable runtime-validated records.
- `contract.py` validates PE mappings, ranges, padding, imports, and machine
  call contracts.
- `extraction.py` performs exact-byte semantic extraction and emits semantic
  and memory IR. Its caches are untrusted and content-addressed.
- `analyses/` proposes control, register, stack, memory, invariant, external,
  and segment evidence. A proposal cannot close an obligation.
- `proposal_cli.py` terminates static discovery at a strict, hashed proposal
  closure. Its package does not contain aggregate replay or final assembly.
- `composition_products.py` consumes the independently checked register,
  semantic, memory, and ISA products and emits segment, product-graph, ISA,
  and final proof-IR composition products.
- `assembly.py` validates those phase products and merges them into the legacy
  analysis view. It cannot silently rerun proposal discovery or composition.
- `lean/` emits definitions, local segment certificates, product composition,
  and the final acceptance module.
- `api.py` is the stable Nix-only orchestration API.
- `nix_pipeline.py` realizes the analysis and proof derivation DAGs.
- `build.py` validates prepared source graphs and drives the Nix derivation
  DAG.
- `lean/compiler.py` is the low-level Lean process adapter used inside Nix
  workers and by semantic kernel fixtures; it has no acceptance authority.
- `worker_diagnostics.py` emits fail-closed phase diagnostics that cannot be
  mistaken for proof verdicts.
- `pipeline.py` orchestrates the phases without owning their data models.

JSON is accepted and emitted only at explicit phase boundaries. New internal
interfaces should use frozen dataclasses or equally strict typed structures;
mutable `dict[str, Any]` remains compatibility debt and must not spread into
new phases.

The relational tests mirror these boundaries in `contract`, `state`, `lean`,
`acceptance`, and `pipeline` suites. Shared PE constructors live in
`tests/stage_a_relational_support.py`; no monolithic relational test class is
authoritative.

## Lean Modules

The reviewed kernel is split by semantic ownership:

- `Formal.lean`, `RelationalDecode.lean`, and `RelationalMachine.lean` define
  the PE32/x86 machine foundation.
- `Relational.lean` defines values, memory families, state relations, and
  region semantics.
- `RelationalInvariant.lean` defines invariant and weakest-precondition
  machinery.
- `RelationalExecution.lean` defines the relational execution/trace layer.
- `RelationalImage.lean` defines structural coverage and the intermediate
  image certificate.
- `RelationalSegment.lean`, `RelationalComposition.lean`, and
  `RelationalEnvironment.lean` define local refinement, rooted product-graph
  composition, and exact lockstep external refinement.
- `RelationalCertificates.lean` contains the whole-program certificate and
  final soundness theorem.

The console acceptance profile binds its selected launch node to a checked
`.entrypoint` root in `StaticProofContext`. A top-level return observes the
concrete EAX result as well as the relational world, and the terminal
invariant must require exact EAX identity. Returning programs therefore cannot
pass while disagreeing on their process result. External-call continuations
may recover exact or related-word result registers only from the uniquely
resolved `MachineImportCallContract`; ESP remains governed separately by the
checked stack delta and runtime-frame relation.

Generated modules contain data and compact certificates, not duplicated proof
rules. Nix derivations follow direct Lean imports so proof-only changes
invalidate only affected descendants.

## Trust And Failure

PE parsing proposals, Capstone, symbols, linker maps, Ghidra, Python analyses,
Z3 status, caches, source mappings, and human/LLM annotations are untrusted.
Lean re-parses exact bytes, checks supported instruction semantics, validates
mapping witnesses, replays supported solver evidence, checks complete rooted
product behavior, composes segment refinements, and audits the final theorem at
trust level zero.

Unsupported instructions, unresolved indirect targets, missing product edges,
unproved invariants, unknown callbacks/effects, pointer-disjunction overflow,
and absent external contracts yield `incomplete`. There are no acceptance
waivers. Runtime tests run only after Stage A passes; a public behavior failure
after a Stage A pass is a prover/toolchain defect investigation.

## Artifact Lifecycle

Prepared proof inputs are source-only and content-addressed. Nix store paths
are the authoritative analysis and compiled-Lean cache for supported builds.
Host-local caches may accelerate derivation-worker tests but are never a
first-class proof build or proof input. `build/` contains disposable or
explicitly exported work products and must never be an implicit proof input.
Large generated Ghidra/skeleton data is reused by content hash and regenerated
only when its own inputs change.

The user-facing `stage-a-prepare-relational`, `stage-a-build-relational`,
`stage-a-prove`, and `stage-a-check-proof` commands all coordinate or audit Nix
artifacts. `stage-a-check-proof` never recompiles Lean. Analysis, extraction,
semantic replay, and Lean compilation executables are phase-scoped derivation
workers. Fixture and CI derivations must import the phase graph directly and
must not invoke a public coordinator from inside a Nix sandbox.

Nix executables are phase-scoped. `spaghetti-extractor-mapping` owns static
maps and relation contracts, `spaghetti-extractor-side` owns side-local
extraction, `spaghetti-extractor-normalize` owns pair normalization,
`spaghetti-extractor-region-facts` owns immutable region-local proposals,
`spaghetti-extractor-proposal` owns global proposal discovery,
`spaghetti-extractor-register-dataflow-problem` owns transfer-problem
compilation, `spaghetti-extractor-register-replay` owns aggregate validation,
`spaghetti-extractor-semantic-products` owns semantic IR and invariants,
`spaghetti-extractor-memory-products` owns memory contracts and external call
sites, `spaghetti-extractor-composition-products` owns segments, the product
graph, ISA requirements, and final proof IR,
`spaghetti-extractor-analysis` owns only validated assembly, and
`spaghetti-extractor-preparation` owns generated Lean sources and the module
graph. Fixture derivations must use the narrowest executable. The general CLI
is a user-facing facade, not an acceptable build dependency for an isolated
phase. Source-boundary checks enforce the dependency direction so an analysis
or proof-generator edit cannot invalidate mapping, extraction, or
normalization merely because those commands once shared a Python package.

Static behavior extraction is side-local and precedes relation synthesis. Each
binary emits a strict executable inventory, raw behavior artifact, and ISA
artifact without consuming the other binary or a relation contract. Raw
behavior artifacts bind their untrusted terms to the complete analysis-kernel
source inventory, extraction-driver source, and Lean toolchain identity. A
passing inventory is required before base or pair-supplement extraction can be
requested.

Pair analysis consumes those immutable side artifacts. Pair-specific spans are
added as explicit supplements, never hidden inside extraction, and contracted
behavior normalization runs as an exact-cover set of bounded packs. Pack
aggregation rejects missing, duplicate, overlapping, or unexpected region
outputs while preserving the contract's global region identifiers. Final Lean
modules still reconstruct these proposals from the exact PE bytes; neither a
side artifact nor a normalization pack is acceptance evidence by itself.

Contracted behavior normalization is itself an immutable pair artifact and a
separate Nix derivation. It binds the exact PE, normalized contract, side
extraction, analysis-kernel, source-generator, and Lean-toolchain identities.
Downstream register, stack, memory, graph, diagnostic, or proof-generation
changes consume this artifact and must not rerun normalization. Missing or
mismatched identities fail closed; there is no implicit normalization fallback
in the cached GNU hello analysis path.

Region-local facts form the next immutable boundary. Bounds, initial static
code-pointer slots, finite indirect-target proposals, import-register seeds,
address-separation claims, and machine-level import-call analysis are produced
from normalized behavior without importing the global register or callsite
fixed-point implementation. The region-facts artifact binds its exact PE,
contract, normalized-behavior, and reduced analysis-source identities. Changes
to global dataflow, diagnostics, graph construction, or proof generation must
therefore consume the existing artifact instead of replaying region-local
analysis.

Register analysis now uses bottom-rooted monotone propagation. Declared launch
roots begin exact, protocol callback entries begin related, and disconnected
source SCCs begin conservatively related so every mapped region is analyzed
without inventing exact state. The artifact distinguishes this complete
analysis inventory from the register graph's declared-root closure; neither is
the authoritative behavioral reachability computed by the product graph.
Iteration exhaustion or any unanalyzed region makes `dataflow_complete` false
and the proposal fails closed.

The remaining global state analysis is transitional. Register, callsite,
stack, static-memory, dynamic-range, and indirect-control feedback still share
one discovery derivation. During migration it emits both the former observed
transfer table and `relational-register-transfer-programs.json`. The latter is
a strict, ordered local transfer IR over the register lattice. It represents
constant relations, input copies, fixed-expression evaluation, exact-input
conditions, and conservative terminal relations. Unknown rules, malformed
relations, missing context, and context identity mismatches fail closed.

Transfer workers consume no observed input/output rows. They receive per-region
programs plus one content-addressed evaluation context containing only paired
constant targets and immutable PE memory ranges, with IAT ranges excluded. The
pure worker source closure therefore does not parse PE files or import the
global analyzer. The context implementation has been exhaustively compared
against the prior immutable-word reader over both GNU hello images: all 237,888
valid word positions agreed. Program-mode SCC replay covers all 7,430 regions
and produces byte-identical register relations to the monolithic analyzer.

The observed table remains only as a differential migration oracle. The
analyzer emits a strict
`relational-register-dataflow-problem-seed.json`, containing the exact binary
identities, contract/behavior content hashes, and proposal inputs. A separate
problem-compiler derivation produces the canonical
`relational-register-dataflow-problem.json` from the exact PE files, referenced
contract and decoded-behavior artifacts, and seed. Large semantic inventories
are referenced rather than embedded in the seed, and the compiled problem is
not copied into the broad analysis artifact. The planner consumes this one
immutable problem instead of independently supplied graph, program, and hash
arguments. The broad analyzer's source closure deliberately excludes the
problem compiler and planner.

Pack aggregation is consumed through a separate linear checker. It recomputes
every region input from seeds and predecessor summaries and checks each output
against the local transfer program, without rerunning the iterative SCC solver.
Malformed, stale, noncanonical, incomplete, or non-monotone solutions fail
closed. The aggregate remains an untrusted proposal: Lean still checks the
resulting state claims and final composition theorem.

Checked aggregate consumption terminates in
`stage-a-relational-register-replay-v1`. Its two-file artifact binds both PE
identities, the proposal closure, aggregate semantic digest, aggregate file
hash, and reconstructed register-relation bytes. Final assembly validates
those bindings and requires the replayed relations to equal proposal discovery
byte-for-byte. The replay package contains neither proposal orchestration nor
final composition, while the assembly package contains the replay schema but
not the aggregate checker or SCC implementation.

Semantic IR plus invariant synthesis form an independent proposal-bound branch.
They consume no register solution and run in parallel with transfer compilation
and SCC solving. Memory contracts plus external-call sites form a second branch
bound to both proposal and register replay. Both artifacts use exact file
inventories and bind their source closure identities and input-file hashes.
Composition contains their validators but not their producers. Assembly
contains only the proposal, replay, semantic, memory, composition, and final
analysis validators. Edits in any downstream family therefore cannot
invalidate proposal discovery or register propagation.

Global discovery now terminates in
`stage-a-relational-proposal-closure-v1`. The manifest lists an exact file
inventory, hashes every member, binds both PE identities, and rejects missing,
unknown, noncanonical, or modified files. The closure contains the final
register seed and the surrounding fixed-register-call, callsite, stack,
static-word, and dynamic/static-pointer proposals, but contains neither Lean
outputs nor final product-graph assembly. Register replay validates the closure,
consumes the separately checked register solution, and requires the
reconstructed contract and register relations to match discovery byte-for-byte.
Composition consumes those independently validated artifacts and emits a
strict six-file `stage-a-relational-composition-products-v1` artifact. Final
assembly then combines the validated phase products without running analysis.

The physical source graph matches the artifact graph. Proposal discovery is in
a source closure that omits assembly, composition, aggregate replay, SCC
workers, and solution validation. Composition has its own source closure and
does not contain proposal, replay, semantic, or memory producers. Assembly has
a dedicated CLI and contains validators but no analysis producer or Lean
generator. The transfer-problem compiler has another reduced source closure.
Boundary checks exercise each packaged entrypoint and assert those exclusions.
Consequently, editing assembly schedules only the assembly executable, final
analysis, and its checks; editing composition starts at composition; editing
the solution checker starts at aggregate replay; editing transfer compilation
starts at the problem; only proposal semantics can invalidate discovery.

The register analyzer emits
`relational-register-program-dataflow-graph.json` as the incremental manifest
for that boundary. Its semantic hashes derive from transfer programs, not the
legacy observation inventory. The program collection carries its strict seed
and propagation-edge inventory, so the planner does not read the observed
transfer table. The graph contains a deterministic SCC condensation DAG and
coarser packs for Nix execution. SCC identities depend on stable region
identities rather than inventory positions. Pack identities depend on SCC
membership, while pack semantics hashes include local transfer and boundary
hashes. Therefore a local semantic edit preserves the node identity and
invalidates its result plus its true descendants; reordering the input
inventory invalidates nothing. Large SCCs are isolated and resource classes are
assigned from total pack region counts so the remote scheduler can limit memory
pressure. This manifest is an untrusted scheduling proposal and has no
acceptance authority.

The intended build DAG is directional:

1. Each PE independently produces inventory, decode, ISA, and raw-semantics
   artifacts.
2. Mapping consumes the two static inventories, while pair normalization
   consumes the map and the two side artifacts.
3. Region-local facts consume normalized behavior but not global fixed-point
   code.
4. The register problem compiler consumes the immutable proposal closure and
   its compact seed. SCC
   packs consume only their projected local programs, the shared immutable
   evaluation context, and predecessor summaries. They contain no observed
   transfer rows. An exact-cover aggregation step rejects missing, duplicate,
   or stale outputs, and the linear consumer validates the solution before
   state claims are emitted. The pre-migration global result is compared region
   by region until seed generation is extracted from broad analysis and the
   monolithic solver path is retired.
5. Segment proofs consume only the relevant state summaries and exact decoded
   paths. Product composition depends on the segment certificates it reaches.
6. The final acceptance derivation is small and depends on all required roots,
   frontiers, environment refinements, and the final Lean theorem.

Nix inputs for a semantic pack must be projected into content-addressed
per-pack files.
Passing the monolithic normalized-behavior or analysis JSON path to every pack
would make every parent store-path change invalidate every child, defeating
the graph even when the pack hashes are stable. The same rule applies to Lean:
generated modules are individual `builtins.path` inputs, and kernel modules are
separate from generated facts. A broad source tree, complete report directory,
or user-facing CLI package is never an input to a narrow phase derivation.

Semantic graph identity and Nix scheduling policy are separate. The proposal
retains the stable SCC graph and transfer identities; the planner derives a
solver schedule from that immutable graph. Changing pack size or scheduling
heuristics therefore invalidates planning and workers, not PE extraction or
proposal discovery. The current lineage-aware scheduler extends a predecessor
pack only when all incoming components are already in that pack. Other work is
grouped by deterministic same-depth hash buckets. This preserves useful branch
parallelism, cannot introduce a quotient-graph cycle, and bounds ordinary
workers to 128 regions. Indivisible SCCs may exceed that budget.

On GNU hello, this converts 7,430 regions and 6,271 SCCs into 237 packs. The
pack graph has a 41-pack critical path, maximum width fourteen, and one
indivisible 554-region SCC. A more aggressive contiguous schedule produced
only 127 packs but had a 104-pack critical path and width three, so total node
count alone is not used as the performance objective.

Fine-grained graph mode reads generated manifests at explicit IFD evaluation
boundaries to construct the derivation DAG. Focused node builds do not import the final
prepared-proof manifest, because it is not an input to node semantics; the
whole-program audit still checks and copies that manifest. The Nix-only
coordinator realizes each manifest-producing boundary before evaluating its
dependent graph. Each pack file and the shared transfer context pass through
independent, cheap content-addressed projection derivations. Once realized,
unchanged projected bytes recover their prior store paths, so changing one pack
does not change every worker merely because its parent plan directory acquired
a new store path.

Floating CA outputs require one additional evaluation boundary. Nix cannot
purely IFD-read the unresolved output placeholder of a content-addressed
preparation derivation, even though that output will become a concrete store
path after realization. `stage-a-build-relational --prepared-nix-ref` therefore
realizes preparation first and evaluates the Lean graph second. Both phases are
ordinary cached Nix builds and may use the same remote builders; only their
coordination runs outside the sandbox. This avoids disabling CA early cutoff or
silently compiling Lean locally merely to recover a one-command interface.

The cold 237-pack GNU solve ran on `acacia` in 221.1 seconds and produced a
complete 7,430-region aggregate with no missing observations. A fully cached
replay took 0.8 seconds. Requalifying all producers after narrowing the shared
context input took 73.9 seconds and resolved to the existing semantic and
aggregate paths. Project-specific binary-cache realization lookups can dominate
a cold development run when an endpoint is unavailable; the measured cold
qualification therefore used `--option substituters ''`, while release builds
may use the configured caches.

Final Nix assembly now emits an immutable reference view instead of copying the
legacy 936 MiB tree. Every referenced file must resolve to a regular file under
`/nix/store`, and its bytes are checked against the unchanged analysis
manifest. Mutable, relative, missing, or non-store symlinks fail closed. The
GNU hello output is 156 KiB physically, retains a 1.14 GB Nix closure through
34 explicit references, and an assembly-only remote rebuild plus exact
7,430-region comparison takes about 10.2 seconds. Local non-Nix assembly still
uses regular files. `materialize_relational_analysis_view` provides the
explicit portable-export boundary and proof preparation currently uses it for
compatibility. A later preparation refinement can consume the validated view
directly and avoid that final materialization as well.

Floating content-addressed Nix derivations implement early cutoff for the
fine-grained register-dataflow DAG. Each pack is one multi-output CA derivation:

- `out` contains only status and canonical output relations consumed by
  descendants;
- `solution` contains the full canonical region solution consumed by final
  aggregation;
- `audit` contains command transcripts and diagnostics and retains explicit
  links to the semantic outputs for inspection.

The outputs are addressed independently. Audit or producer changes may alter
`audit` while `out` and `solution` resolve to their existing semantic paths, at
which point Nix prunes all potential descendants and the final aggregate. The
aggregate consumes every `solution` output and checks predecessor bindings
against the semantic digests. Its own `out` contains only canonical aggregate
JSON and has no Nix references; its separate `audit` output retains the plan,
summaries, solutions, and command transcript. These summaries and solutions
remain untrusted proposal data and cannot authorize Stage A acceptance without
Lean replay.

`nix/stage-a-ca-derivation-smoke.nix` exercises the same early-cutoff contract
independently of the production graph. The local coordinator, `acacia`, and
`banksia` now run the Nix 2.35 build-trace protocol and advertise
`ca-derivations`. The executor checks every participating store before
evaluation and rejects a mixed 2.34/2.35 deployment. Content-addressed
derivations are the qualified default.

The checked-in remote inventory gives each 32-thread, roughly 96 GiB builder 10
two-core jobs. Required-system features retain resource classifications for
ordinary, large-memory, and exceptional proof nodes, while the global job cap
provides the actual memory-safety boundary because Nix does not apply weighted
memory quotas. `--max-jobs 0` prohibits local derivation builds; only
evaluation, scheduling, and result validation run on the coordinator.

Lean nodes expose a compact semantic output and a separate audit output. A
semantic output contains only that node's `.olean` files, checked interface, and
direct dependency references. Transitive dependencies are followed into an
ephemeral module overlay at build time. The final audit and focused target
views retain store references rather than copying a closure or constructing a
root archive.

Each generated node has a canonical semantic ID over its source, recipe
version, and direct dependency semantic IDs. Stable hash buckets prevent
unrelated pack renumbering. Resource measurement is always part of the
canonical recipe, so profiling and normal proof requests use identical
derivation paths. A controlled candidate-semantics mutation on the generated
whole-program fixture changed exactly 18 of 208 node identities, reused the
other 190, rebuilt its focused closure in 5.9 seconds, and restored the final
theorem in 36.6 seconds. A fully warm theorem replay took 1.05 seconds.

Dynamic graph evaluation is cached separately from proof outputs. The first
evaluation records the resulting `.drv^out` installables under the exact graph,
relevant manifest, evaluator, lock-file, platform, and target-set digest.
Focused cache identities omit the final prepared-proof manifest; final-audit
identities retain it. Later focused or final requests realize those derivations
directly instead of reconstructing thousands of Nix attribute nodes. This cache
is only a scheduling hint: returned module results must still match the graph's
source and semantic IDs, and a stale realization falls back to authoritative
graph evaluation.

Semantic outputs are also indexed individually by semantic ID. When the exact
graph digest changes, the coordinator computes the invalidated target closure,
instantiates only those nodes, and passes unchanged direct parents to Nix as
checked store-path boundaries. The Nix evaluator rechecks each boundary
interface against the current graph, and Lean dependency assembly rechecks its
module hashes. This preserves fail-closed provenance while avoiding a complete
dynamic-expression reconstruction after every candidate-region edit.

The production GNU hello preflight also exercises the CA projection boundary.
The one-time migration realization of its 275-pack dataflow graph took 343.7
seconds across `acacia` and `banksia`. An unchanged rerun resolved the same
derivation and output paths in 0.194 seconds with no build actions. The
prepared-proof frontier remains incomplete and unchanged; cache reuse does not
alter the acceptance inventory.

On the 5,991-node GNU graph, a cold evaluator-key focused request instantiated
only its 165-node semantic closure and completed in 13.2 seconds with no Lean
work. After changing only the launch certificate's resource recipe, the next
request instantiated one changed node with four checked semantic boundaries;
the 63.5-second total was dominated by the required 46.6-second Lean compile at
6.75 GiB RSS. Its unchanged replay completed in 4.3 seconds with zero Nix
evaluation or proof work.

The same path has been realized for the full jq alignment pair. Its prepared
proof contains 3,235 semantic-identity-bearing Lean graph nodes. The current
rooted composition frontier has 407 reachable nodes, 458 feasible edges, and
242 refined segments, with no unsupported instructions and fourteen explicit
acceptance blocker categories. An unchanged prepared-proof replay emits no Nix
build events. These counts are proof-progress diagnostics; the jq acceptance
status remains `incomplete`.

The relational Lean graph also has a checked-artifact v2 path. Ordinary regions
are split into:

- deterministic 32 KiB exact-image packs, assembled into one checked image
  attestation per side;
- a stable hash-bucketed semantic pack containing only local bytes, compact
  imports, machine-call contracts, the proposed behavior, and one Lean replay;
- a small exact-image binding that proves those local bytes and image base are
  the selected PE span and exports the existing decoded-behavior theorem;
- downstream relational proofs that consume the exported theorem and never
  invoke raw region decoding or symbolic execution.

Every exact-image binding exports its decoded-behavior theorem against the
single canonical `machineImportCallContracts` inventory. Semantic packs and
the legacy x87 replay may use private pack-local aliases internally, but
acceptance and composition do not know those names. This prevents proof
consumers from acquiring a second machine-call-contract authority.

Import-table and relocation-table attestations are independent siblings of the
checked image attestation. Exact region bindings depend on the image
attestation, but not on those table attestations. Full acceptance still depends
on all three. This removes expensive whole-table validation from ordinary
candidate-region iteration without weakening the final gate.

The bucket is selected from the stable semantic key, not behavior contents or
region order. A controlled candidate mutation changed exactly one semantic
pack; two unrelated candidate packs and every original pack retained identical
Nix paths. Building an unchanged pack took 6.52 seconds cold and 0.49 seconds
after the mutation. A representative exact-image binding itself took 1.84
seconds and peaked at 1.12 GiB, so ordinary bindings use the medium parallel
lane. Legacy x87 regions still use full-image replay and remain high-memory
until they migrate to context-independent local semantic summaries.

On the full GNU hello pair, the previous monolithic candidate PE authority made
one cold exact binding take 441.3 seconds and drove the PE attestation to about
12 GiB RSS. Image packing alone reduced that cold path to 295.9 seconds. After
separating image metadata from imports and relocations, the same 81-node,
171-module exact-binding closure checked remotely in 57.5 seconds. A fully warm
replay performs no Lean work and reports 9.48 seconds in the executor. The
separate candidate import and relocation attestations took 140.3 seconds cold
when built together; they are cached independently and no longer sit on every
region-binding path.

The same graph shape scales to jq. Its current prepared proof contains 8 exact
image chunks, 128 semantic-pack derivations, 128 exact-binding derivations,
8,794 checked semantic artifacts, and 8,512 exact decode bindings. Of the
semantic artifacts, 282 x87 regions still use legacy full-image replay. A
representative 12-region candidate binding has a 32-node, 54-module, 6.1 MB
focused closure: it checked cold in 61.6 seconds and replayed fully warm in
3.41 seconds. The truthful jq composition inventory currently has 4,402
potential nodes, 407 rooted nodes, 458 rooted feasible edges, 242 refined
segments, and no unsupported instructions.

Final-theorem axiom auditing is now a lazy, separate source module as well as a
separate Nix node. Static extraction reuses the Lean compiler but does not
contain that audit policy. A controlled edit to only `axiom_audit.py` kept the
jq region-facts derivation at the identical store path while changing the
prepared-proof derivation. After the one-time source-ownership migration, jq
requalification rebuilt only semantic, register, memory, composition, and
preparation descendants in 59.0 seconds; extraction, normalization, region
facts, proposal discovery, and the fine-grained dataflow solve were reused.
The immediate prepared-proof replay took 0.10 seconds. With those dependencies
warm, the changed representative exact binding checked in 12.9 seconds and
then replayed in 3.42 seconds with `nix_work_reused = true`.
After the boundary was established, a change confined to segment generation
rebuilt exactly the preparation package and jq prepared-proof derivation in
34.3 seconds. The unchanged representative exact-binding artifact retained its
Nix identity and replayed in 3.38 seconds.

Introducing the three-output pack contract required one graph-wide production
qualification because every pack recipe changed. Rebuilding 237 packs plus the
aggregate on `acacia` took 26 minutes 48 seconds. Every semantic output resolved
to its prior content address: the aggregate retained digest
`eaca819d50e6da1ed04cbb2f7357419853192b5fe9d8c690e03159045a2731d8`,
contains 7,430 region solutions, and has zero Nix references. A subsequent
register-graph build took 1.39 seconds and downstream composition took 1.43
seconds without executing their prospective derivations. The cold time is the
cost of globally changing a producer recipe, not the expected cost of changing
one candidate slice; ordinary semantic changes invalidate only affected packs
and their descendants.

Invariant synthesis no longer owns the shared decoded-exit normalizer.
`analyses/semantic_control.py` contains that stable helper, while region facts,
proposal discovery, register-problem compilation, and register replay omit
`analyses/invariants.py` from their source closures. The source-boundary check
asserts those exclusions and exercises each packaged entrypoint. Qualifying
this source-inventory change on GNU hello took 298.7 seconds: region facts and
proposal discovery ran once, Nix listed the 237 potential pack derivations but
built none of them, and the aggregate resolved to the existing store path and
semantic digest above. The immediately repeated remote-only register plus
composition build took 0.171 seconds and reused the existing composition
output. Future invariant-synthesis edits therefore begin at semantic products
and composition instead of restarting extraction and register propagation.

The relational test graph still has coarser invalidation boundaries than the
production analysis graph. Each per-method test derivation currently embeds
its complete source test module, so editing one method invalidates every shard
from that module. Every shard also consumes the monolithic Python package, so a
change confined to one analysis phase invalidates unrelated decoder, emulator,
and acceptance tests. The next test-graph optimization is a content-addressed
per-method source-extraction layer followed by phase-specific Python package
closures. That work affects iteration cost only; it must not remove any test
from the aggregate release gate.

Diagnostics must resolve the current flake derivation before requesting a
companion output. A reverse `nix-store -q --deriver` lookup from an unchanged CA
semantic output may name an older producer whose `audit` output predates the
current output schema. The current aggregate audit contains all 237 summaries
and 237 full solutions, while the semantic aggregate remains reference-free.

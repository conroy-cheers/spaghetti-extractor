# Stage A Relational v3 Profile

Parallel Stage A ownership, schema stability, and integration rules are defined
in [stage-a-parallel-development.md](stage-a-parallel-development.md). Every
prepared proof records these boundaries in `stage-a-interface-manifest.json`.

## Purpose

The normative command authority and trust boundary are defined in
[stage-a-architecture.md](stage-a-architecture.md). This document records the
implemented v3 profile and measured progress; where older wording conflicts,
the architecture document controls.

`x86-pe32-relational-v3` is the authoritative proof profile for equivalent
PE32/i386 programs whose code layout and instruction selection may differ.
Historical v2 evidence is not accepted. A v3 report embeds the exact original and
candidate bytes, re-parses them in Lean, decodes every classified executable
region with the reviewed x86 semantics, and proves the declared relations.

Python, pefile, Capstone, block-map generation, decoded-semantics caches, and
SAT proof production are untrusted producers. The checked boundary is the Lean
kernel, `Formal.lean`, `Relational.lean`, and either a replayed LRAT certificate
or kernel-checked bitvector normalization for each region.

The forward plan for completing internal whole-program equivalence, replacing
detailed external semantics with an exact lockstep shared-oracle boundary, and
then validating the architecture on a representative 3D application and a game
is documented in
[stage-a-internal-equivalence-and-3d-roadmap.md](stage-a-internal-equivalence-and-3d-roadmap.md).

## Workflow

Project an existing complete block map into an editable relation contract:

```sh
spaghetti-extractor stage-a-generate-relation-contract \
  --original original.exe \
  --candidate candidate.exe \
  --mapping block-map.json \
  --out relation-contract.json
```

Prove and independently replay it:

```sh
spaghetti-extractor stage-a-prove \
  --original original.exe \
  --candidate candidate.exe \
  --relation-contract relation-contract.json \
  --out report/

spaghetti-extractor stage-a-check-proof --report report/
```

The authoritative commands are `stage-a-prove` and `stage-a-check-proof`.

For large proofs, separate deterministic extraction from Lean compilation:

```sh
spaghetti-extractor stage-a-prepare-relational \
  --original original.exe \
  --candidate candidate.exe \
  --relation-contract relation-contract.json \
  --out prepared-proof/

spaghetti-extractor stage-a-build-relational \
  --prepared prepared-proof/ \
  --executor nix \
  --builders-file nix/stage-a-builders \
  --out report/
```

Preparation emits source only: exact PE artifacts, normalized proof IR,
generated Lean modules, their direct import graph, source hashes, estimated
resource classes, the expected final theorem, and the approved axiom set. It
rejects unsupported semantics before creating the graph and removes all
`.olean` files so an unrecorded local build cannot enter the prepared input.

The Nix executor validates the complete graph before evaluation. Independent
definition, local-proof, decode, direct-composition, structural, and closure
nodes become separate derivations using the Lean version pinned by
`flake.lock`. Builder selection is external: normal Nix configuration is used
unless `--builders-file` supplies a machines file. Supplying that option also
sets `--max-jobs 0` and `--cores 2`, so every derivation, including dependency
packing and the final audit, is remote-only. A single-module derivation uses one
`lean -j 2` process. A pack of independent generated modules uses its two
allocated cores for two concurrent `lean -j 1` processes; the graph generator
checks that packed modules have no internal import edges. This prevents a
16-module pack from serializing otherwise independent elaboration without
oversubscribing the host. Nix expression evaluation, scheduling, and store
transfer remain local. The evaluator does not name or special-case any host or
target binary.

The final derivation imports the generated bundle and runs Lean with
`--trust=0`, which type-checks imported modules rather than trusting remote
`.olean` files. It also rejects final-theorem dependencies outside the approved
axiom set. Non-root node outputs are merged by a remote-eligible derivation into
a deterministic zstd dependency pack before the root bundle and audit run.
This avoids transferring thousands of individual files to the final builder
and prevents the audit result from retaining the complete intermediate store
closure.

The repository builders file currently allows 16 derivations on each of two
32-thread, roughly 96 GiB hosts. A live jq graph build showed no local Lean
processes and concurrent compilation on both hosts. Sixteen two-thread Lean
jobs can occupy all 32 hardware threads. The latest focused external-call
rebuild reached 16 `.lean-wrapped` processes on both hosts. Static-code-map
leaves used about 1.2-4.5 GiB RSS, and the busier host retained about 46 GiB
available memory. The original and candidate proof-base modules used about
5.3-5.7 GiB RSS in that run, while graph width made only one such module ready
per host. The current profile is therefore safe for this jq graph, although a
future graph that exposes sixteen 6+ GiB nodes at once will need stricter
resource-class scheduling. The
first dependency waves may contain only the original proof, candidate proof,
and global mapping context; low process counts there reflect graph width, not
unused scheduler slots. Nodes now declare only their direct graph parents and
inherit deduplicated indexes of transitive `.olean` and node-result paths.
Previously every node listed its full transitive closure as direct Nix inputs;
late jq nodes spent minutes issuing serial remote store-validity queries for
hundreds of already-cached paths before Lean could start. The indexed form
preserves the complete dependency and provenance inventory while making remote
setup scale with direct fan-in. Ordinary bounded graph shards used roughly
3-4.4 GiB RSS each.

Lean nodes raise the inherited 8 MiB soft native-stack limit to the hosts'
existing unlimited hard limit. Stack pages remain demand-allocated; this avoids
aborting aggregate elaboration because of the shell default without reserving
memory for every worker. The 16-job limit remains the practical memory guard.

After changing the evaluator to `lean -j 2`, a cold focused jq graph-chunk
build compiled a 413-node closure in 597.07 seconds. Broad waves sustained
13-16 concurrent Lean processes per host without OOM. The identical warm build
substituted the checked node in 0.58 seconds. The cold time is a one-time cache
invalidation for the evaluator change, not the expected slice-iteration cost.
A later 48-target medium-proof request built a 100-node, 1,540-module focused
closure in one scheduler invocation in 68.02 seconds. Both hosts reached their
full 16-process limits. Available memory remained above about 83 GiB on acacia
and 70 GiB on banksia during sampling, confirming that a broad ready queue is
distributed across all 32 configured derivation slots.

The default decode/direct partition now targets 64 chunks. Region inventories
are emitted as one module per chunk, with the all-region module retained only
as a thin final-closure aggregate. A focused jq segment that previously pulled
2,979 modules, 45.9 MiB of source, and 204 Nix nodes now pulls 276 modules,
7.1 MiB, and 36 nodes; its cached-kernel remote check fell from 239.01 seconds
to 20.12 seconds. Cross-chunk continuation invariants are declared as explicit
imports, so this reduction does not hide target dependencies. Broad validation
still exposes enough independent proof packs to fill 16 slots on each host.
The Nix-wrapped Lean process is named `.lean-wrapped`; `ps -C lean` therefore
reports zero even during an active wave. Use `ps -C .lean-wrapped` when
sampling remote CPU and RSS.

Changing the generic builder recipe to apply the stack policy invalidated 436
derivations in the focused external-call closure. That one-time rebuild took
667.497 seconds and spent a material fraction of its tail copying the static
context closure between builders. With those dependencies warm, rebuilding the
corrected aggregate external-call certificate took 12.217 seconds in Nix and
13.158 seconds end to end; an identical cached replay took 0.564 seconds in Nix
and 1.512 seconds end to end. Reducing cross-builder transitive `.olean`
transfer is the remaining remote-execution bottleneck for cold focused
closures.

The non-Nix compatibility runner now compiles PE attestations and
`RelationalProofBase` before generated shards that import them, and defers
static-context consumers until `RelationalStaticContext` exists. This ordering
matches the generated import DAG; it prevents a local smoke or unit test from
reporting a missing `.olean` merely because a dependent shard was submitted in
an earlier scheduling phase.

The former `RelationalProofClosureData` module combined 1.37 MB of unrelated
generated literals and checks. It exceeded 18 GiB RSS and 10 minutes without
finishing. It is now a 895-byte compatibility module over separately compiled
coverage, padding, required-input, region-inventory, region-index, and
static-usage certificates. Region indexes are composed from 32 checked chunks.
Static-context scans use 16-region leaves packed four per Nix derivation; this
kept observed leaf RSS around 1.5-3 GiB while sustaining 13 concurrent remote
Lean processes. On the jq graph, the packed static-usage certificate took
203.44 seconds cold and 1.62 seconds warm, while the complete assembled closure
took 25.21 seconds after its dependencies were cached. The first complete graph
after this refactor finished in 428.33 seconds; a fully warm rebuild, including
the trust-zero audit and provenance collection, took 6.60 seconds. The final
dependency pack contains 2,137 node outputs and is 1.45 GB, so compact
reflective certificates remain important for reducing release-build transfer
and storage costs.

`nix-provenance.json` records every node's source identity and the SHA-256 and
size of every `.olean`, dependency-pack metadata, the evaluator and lock
hashes, and Nix path metadata for the zero-reference final audit output. A
cached node is reused only when its generated source, dependencies, pinned
toolchain, and evaluator are unchanged.

The build command still fails closed on the proof inventory. A checked Lean
bundle does not produce `pass` while CFG invariants, memory relations, or any
other non-local obligation remains incomplete.

## Contract

The contract explicitly names observations and environmental assumptions:

```json
{
  "format": "stage-a-relation-contract-v1",
  "environment": {"id": "adversarial-pe32-external-v1"},
  "observations": ["external_call", "external_jump", "return", "fault"],
  "memory_relation": {"mode": "identity"},
  "code_targets": [
    {"id": 0, "original_rva": 4096, "candidate_rva": 4128}
  ],
  "regions": [
    {
      "id": "entry",
      "root": true,
      "original": {"rva": 4096, "size": 7},
      "candidate": {"rva": 4128, "size": 8},
      "inputs": [{"original": "eax", "candidate": "eax"}],
      "outputs": [{"original": "eax", "candidate": "eax"}]
    }
  ],
  "padding": []
}
```

The checker rejects coverage gaps, overlaps, ambiguous register relations,
roots that do not pair the PE entrypoints, unresolved logical targets, invalid
padding, hidden environment assumptions, and unsupported memory translations
before proof production.

The exact-byte theorem checks:

- both inputs parse as PE32/i386 with valid import and relocation tables;
- every executable byte is a decoded region or verified padding;
- the paired entrypoint is a checked root and every logical target resolves;
- every recorded symbolic behavior is decoded from the embedded PE bytes;
- related arbitrary registers and memory produce related output registers,
  equal ordered memory-write traces, equal normalized control outcomes, and
  equal external API identities and arguments;
- output relations compose with region input relations in the current
  conservative profile.

Preparation also emits `relational-memory-contracts.json`. It inventories
ordinary and x87 memory observations from the normalized decoded behaviors,
pairs reads by semantic path, records direct successor requirements, and
classifies unsupported pullback fragments. Python's classification is only a
proposal. Generated Lean modules reconstruct each target behavior's complete
ordinary-read or x87-load inventory and prove predecessor pullbacks from the
exact behavior definitions. X87 load pullbacks cover the control word and each
byte in the format-specific load range. These certificates do not by
themselves prove paired values related or close whole-program memory
transitions.

For sources without mapped-data objects, Stage A separately proposes paired
pullbacks whose complete expression depends only on exact register inputs,
equal ordinary memory, undefined values, and FS base. Lean checks the pulled
expression, including local `write32` overlays, proves the successor read
values equal, and lifts complete read inventories to
`MemoryObservationTransitionClosed`. Empty live-read inventories close
trivially. Mapped-memory, flag/x87-dependent, and non-exact address cases stay
incomplete. This test is against `globalValueTargets`, not a source region's
local value list; every memory-transition theorem receives the same explicit
global mapping context as whole-program execution.

Preparation emits `relational-register-relations.json` as a separate,
point-sensitive register dataflow contract. Register values are classified as
`exact`, `code_pointer`, `data_pointer`, or `related_word`; the relation is
attached to each region input and output rather than globally to an
architectural register. The fixed-point analysis is untrusted proposal logic.
Generated Lean modules reconstruct and check:

- exact memory-free output expressions from exact input relations;
- exact ordinary-memory output expressions when addresses use exact inputs and
  the complete proof has no mapped-data relation;
- identity transfers for scalar and pointer relations;
- paired constant relations, including checked code/data mappings;
- complete local register transfers when every output has a checked claim;
- direct CFG membership and per-register exact-output edge claims.

External-call continuations and predecessorless non-entry regions are explicit
barriers. Unsupported arithmetic, mapped-memory values, and mixed pointer joins
remain `related_word` with incomplete obligations. A checked partial register
certificate does not close whole-program composition: Stage A still requires a
checked transfer for every live destination relation under one explicit mapping
context. Preparation emits `RelationalGlobalMappingContext.lean`, and every
generated register-transfer, memory-transition, and direct-edge theorem
receives its `globalCodeTargets` and `globalValueTargets`. The whole-program execution
relation receives those same lists explicitly; per-region target/value lists
remain decoder and local-proof inputs only. In particular, an exact memory read
cannot be promoted to a composable register transfer merely because one
region's local value list is empty.

Relation-contract generation preserves linker-map `function_id`, block index,
cut index, and checked function-entry evidence instead of collapsing every root
to the PE loader entry. The register fixed point uses that metadata only to
propose context-insensitive return-to-continuation edges. Every proposal emits a
`call_return_stack_composition` obligation and remains incomplete until Lean
checks the decoded call and return, the abstract call stack, mapped return-address
resolution, and successor state relation. Function names are never accepted as
proof of a return edge by themselves.

Physical code addresses are normalized through `code_targets`. Imported calls
are compared by DLL and symbol or ordinal, not IAT RVA. External results are
adversarial and cannot be specialized from observations of the original. The
generated `win32-cdecl-stdcall-registers-v1` policy preserves the relation on
EBX, ESI, EDI, EBP, and ESP and degrades EAX, ECX, and EDX to `related_word`.
Lean checks each external continuation and policy edge. This does not assume an
API result: whole-program composition must still quantify original and
candidate environments satisfying `RelationalEnvironmentsRegisterCompatible`.
The original binary is consumed statically only.

`PairedMemoryUpdateFrame` binds exact original and candidate write lists to
preservation transformers for every authoritative memory family.
`RelationalMemoryFamiliesHold.afterPairedMemoryUpdate` applies such a frame
once, instead of making each segment reconstruct the aggregate relation. The
first constructor is a checked singleton stack-word write: its footprint and
disjointness witnesses preserve ordinary related memory, stack windows, IAT
slots, immutable image bytes, dynamic ranges, and pointer slots together.
`PairedStackWordUpdate` lifts the same evidence to an ordered finite list;
`afterPairedStackWordUpdates` folds each write through all seven memory
families before `StateRel.afterPairedMemoryFamiliesUpdate` reconstructs the
authoritative successor relation. Every list item has a checked aligned window
offset, range bound, exact symbolic write, and related value. Duplicate or
overlapping writes retain decoded order rather than being collapsed.
`pairedStackWordWriteReadsBack` separately proves the exact new call-frame
word. No-write segments use `StateRel.afterNoWriteEvaluation`. This keeps flat
concrete memory authoritative while making calls, spills, prologues, output
parameters, and future heap updates share one proof interface.

## Evidence And Replay

The report contains the bundled PEs, normalized contract, relational proof IR,
trusted-base declaration, diagnostics, LRAT or normalization evidence, copied
Lean semantics, generated bundle, `semantic-gaps.json`, and verdict. A fast
Capstone preflight reports unsupported instruction forms and malformed
cutpoints before generating a large Lean bundle; it can only block a proof and
is never proof authority. `stage-a-check-proof` verifies
all hashes, regenerates decoded behavior from the bundled PEs without the
iteration cache, regenerates the bundle byte-for-byte, and checks replay.

Prepared proofs also emit `composition-progress.json`. It projects only hashed
proof inputs and has no acceptance authority. Its primary counts are checked
rooted nodes, conservative potential nodes, rooted feasible edges, refined
rooted segments, decoded-control and segment frontiers, unresolved indirect
targets, unsupported instructions, external-environment frontiers, and stack
invariant frontiers. Non-zero stack-delta SCCs and recursive call-window cycles
are reported separately as relational-call-frame work; they are never widened
into a finite flat stack window. Exact node and edge IDs accompany each count.
This makes composition progress the
iteration metric while keeping local proof totals explicitly secondary.
Whole-program acceptance blockers use the same iteration discipline: repeated
node-profile failures are grouped by stable reason code with an exact total,
ten deterministic examples, and an omitted-example count. Compaction changes
diagnostics only; one or thousands of instances still make acceptance
`incomplete`.

Set `SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_CACHE` to select the untrusted decoded-semantics
cache, or to `off` to disable it. Keys include the PE hash, span, and Lean
decoder module hash. Decoder and normalization semantics now live in the
separately compiled `StageA.RelationalDecode` module; proof tactics and
composition theorems cannot affect that module's hash. Generated decode
equalities reconnect every cached term to the exact bytes, so a bad cache entry
can only make checking fail. The old extraction marker is retained only to
migrate existing untrusted cache entries.

Prepared proofs also emit a checked `StaticProofContext`. Its code and data maps
are indexed by deterministic target IDs. Sorted original and candidate address
inventories prove that every canonical address and alias occurs exactly once;
data ranges are likewise indexed, ordered, and bounded. Overlap is accepted
only when every overlapping entry induces the same original-to-candidate
translation. Lean
re-parses both PEs, imports, and relocation tables, checks roots against the PE
entry profile, rejects unsupported observation-profile features, validates
mapped data contents, and proves that every region-local target is the exact
entry from the canonical map. The generated
`candidateRelationalImageCertificate` includes these facts, but remains
explicitly ineligible for whole-program acceptance.

`StateRel context world invariant` is now the sole exported state-relation
interface for composition. Exact regional inputs and the older composable-state
API remain legacy local-proof interfaces; exact equality is represented by
`.exact` register atoms rather than a second whole-program relation.
Whole-program `StateRel` uses `StateRelCoreWithImportMask`: ordinary mapped
memory is related at every candidate byte except candidate IAT bytes and bytes
whose normalized address is an original IAT byte. Those excluded dwords remain
constrained by `ImportAddressPair.memoryHolds`, so differing runtime function
addresses do not make the relation contradictory and no IAT byte becomes
unconstrained. Generated register transfers use a Lean checker that accepts
identity, constant, and exact memory-free expression claims; exact-memory
claims cannot be reused across the mask. `StateRel` also carries checked
immutable-image word relations for both concrete memories. These permit local
proofs to recover a word from exact PE bytes only when the containing section
is non-writable. No-write segment transitions preserve all three relations.
The eventual launch theorem must establish these relations from the bounded
preferred-base PE launch profile; until then they remain an explicit
`StateRel` premise and do not create an acceptance theorem.
`StateRel` now accepts checked paired dynamic ranges as well as static image and
stack mappings. A dynamic range must be nonempty and non-wrapping, disjoint from
both PE images, pairwise disjoint on each side, and disjoint from every stack
range. Its typed four-byte cells must be in bounds, unique, and non-overlapping.
Each cell is related as a general related word, code pointer, data pointer, or
nullable pointer to another range with the same checked shape over the
authoritative flat memories. `DynamicRegisterRangeRelation` then ties
a register-plus-offset on each side to one such range and requires the named
typed cells. Ambiguous, overlapping, wrapping, untyped, or absent ranges remain
incomplete. Opaque resources and world updates across allocating/external
transitions remain fail-closed. Existing regional image proofs still use local
map subsets, so they are not yet segment refinements under the global
`StateRel`; this is an explicit migration blocker, not an inferred whole-program
fact.

`StaticProofContext` also carries checked paired dynamic-pointer slots for
mutable PE globals that hold runtime allocation bases. Each slot is one
nonzero, non-wrapping four-byte word wholly inside a writable, non-executable
mapped section on both sides, outside every parsed IAT cell, and disjoint from
all other slots. Its required dynamic-word shape is nonempty, unique, and
non-overlapping. `StateRel` excludes those bytes from ordinary identity memory
and separately requires the two concrete words to be zero/zero or the bases of
one paired dynamic range with the declared shape. This is a global invariant:
launch, external-world updates, and writes must establish or preserve it. Lean
checks null-guard agreement, zero/zero register output, and non-null
slot-to-register range seeding; no local source invariant may assume an
arbitrary writable word contains a related allocation.

`RelationalSegmentRefinement` is the new composition boundary. A segment edge
names its source cutpoint, guarded exit, exact original/candidate PE spans,
canonical local code/data target IDs, and target invariant. Lean resolves those
IDs through the checked indexed static maps; an unresolved ID makes the segment
claim false. Regional normalization uses only this checked local projection,
while input and successor states remain related by the global `StateRel`. Its
theorem requires exact decode from the PEs and proves,
for every source `StateRel`, matching internal/external/return/fault exits,
related machine-level outcomes, and a target `StateRel` for internal exits.
Indirect exits remain outside product-graph completeness until reduced to a
checked finite target set.
The first such reduction profile handles an indirect call through one relocated
function-pointer word in immutable image data. Lean checks the exact original
and candidate PE words, canonical code target, mapped data offset, relocation
offset, normalized call outcomes, continuation target, and every byte-level
non-aliasing witness for preceding register-plus-offset writes. It then proves
that every source `StateRel` evaluates both indirect targets to their mapped
code addresses. Writable tables, ambiguous code targets, conflicting data
mappings, unsupported address expressions, and missing separation witnesses
remain incomplete.
The dynamic-range reduction profile separately recognizes a paired indirect
call through `read32(register + offset)`. Lean checks that both normalized
outcomes use the declared registers, offset, and continuation; that the source
invariant contains the exact dynamic register-range relation; and that the
range classifies the loaded word as a code pointer. From `StateRel`,
`DynamicRangeIndirectCallTargetsClosed` proves that the two concrete loads are
related code pointers. This local certificate does not invent a graph edge: a
world producer/update proof and finite runtime target inventory are still
required before decoded-control completeness can close.
The edge theorem proves original/candidate guard agreement; it does not assume
that both guards hold. The generator emits checked segment refinements for
composable no-write direct segments with checked local target projection,
non-memory register-relation transfer, state-only x87 transfer, and empty-or-DF
flag invariants. The older exact-map wrapper was removed because it required
the pre-IAT full-memory relation and duplicated this interface. Shape certificates
must provide successful evaluations on both sides; failed evaluation cannot
close a segment vacuously. Unsupported edges remain incomplete rather than
being relabeled from weaker regional certificates.

No-write segments preserve dynamic register-range witnesses by identity. They
may also traverse a checked `nullableDynamicPointer` cell: Lean verifies the
exact paired `read32(base + offset)` expressions, source and successor range
shapes, zero base offsets, and paired nonzero branch guards. The loaded range
bases become both the successor dynamic-range witness and an ordinary
`related_word` register atom. A missing or ambiguous source range, stronger
successor shape, nonzero offset, or mismatched guard remains incomplete. The
proof IR reports stable blocker codes and exact source, output-register, and
word-offset fields, but only when one side already has dynamic-range
provenance; an arbitrary null-tested stack or memory load is not misreported as
a linked-range traversal.

On the full jq pair, the no-write wrappers now propose 516 of 4,933 segment
refinements; the other 4,417 remain explicit incomplete obligations. The
expanded profile includes exact or `related_word` zero-test branches with any
checked number of leading Boolean negations. Lean separately checks guard
agreement and that a selected edge implies the decoded branch condition's
truth value; Python not-parity normalization is not trusted.
All 32 segment chunks compose through the dedicated
`RelationalSegmentRefinementCertificate` Nix node. The expanded 449-edge jq
aggregate checked remotely in 482.648 seconds over a focused 935-node closure;
a focused changed chunk checked in 38.691 seconds. Replacing the authoritative
memory relation invalidated that full closure; all 449 edges checked again in
2,999.756 seconds. That cold run used the former transitive-input executor and
exposed its remote setup bottleneck. The aggregate certificate is not a
whole-program theorem: product-edge coverage, calls, writes, external events,
dynamic worlds, and SCC composition remain open.

The next layer emits `relational-product-graph.json` and a checked
`RelationalProductGraph`. Nodes are indexed cutpoints tied to canonical code
target IDs; edges are indexed source/target pairs and retain the decoded
symbolic guard; each node carries a sorted outgoing-edge inventory; roots
resolve to the `StaticProofContext` roots; and proved edge IDs form a separate
sorted evidence inventory. Lean checks all of these facts. Proved edge IDs are
connected to their segment theorems by a
`PartialProductEdgeRefinementCertificate`; a Python status list alone is not
evidence. A `CompleteProductEdgeRefinementCertificate` is generated only when
every declared edge has a `RelationalSegmentRefinement`.

The first behavioral-coverage profile additionally emits a
`PartialProductNodeCoverageCertificate`. It includes a node only when that node
has exactly one declared successor, its decoded guard is unconditional, and
the successor edge has a checked segment refinement whose original and
candidate guards are also unconditional. The direct-loop fixture constructs
both partial certificates and the complete edge certificate. Deleting its
reachable outgoing edge or changing its graph guard is rejected by Lean.

For jq, the checked graph now has 4,149 nodes, 4,933 edges, one root, 449 proved
edge IDs, and 4,484 incomplete edge refinements. The original 195 proved edges
are the sole unconditional successor of their source node, so Lean also checks
195 partial node-coverage witnesses; guarded node coverage remains a separate
composition obligation. Evidence
completeness is checked as `false`. Graph and product-proof checks use 16-entry
Nix derivations: 64-entry graph chunks were rejected after reaching 10-14 GiB
RSS, while the bounded graph chunks observed roughly 3-4.4 GiB.

Exact-decode-backed control certificates currently close 4,078 of those 4,149
nodes and leave 71 explicit incomplete nodes. The immutable-table certificate
closes jq region 2709 and adds its call edge to region 393. The declared root
closure previously reached region 401 through the syntactically false side of
a constant branch. Product edges now carry an untrusted infeasibility proposal;
Lean recomputes it from the exact normalized guards and proves that a marked
edge cannot execute. Checked root closure consequently reaches 75 nodes and
initially exposed region 3144. Stage A now extracts paired import seeds from
original/candidate IAT slots and register expressions. Lean canonicalizes DLL
bytes with ASCII lowercase before comparing import identities, matching the
case-insensitive Windows DLL-name contract without changing symbol names.

The generic import-register proposal finds seven checked IAT seeds, 24 inductive
register relations, and six indirect import calls in jq. In the reachable
cluster, region 3143 loads `kernel32!TlsGetValue` into `EBP` and
`kernel32!GetLastError` into `EDI`; the proposal carries both nonvolatile
registers through the 3144-3149 loop. `StateRel` now has explicit paired runtime
import addresses, checked IAT memory slots, per-register import identities, and
a fail-closed completeness condition requiring every parsed IAT cell to have a
world binding. Import-pointer atoms replace the redundant ordinary
`related_word` atom for the same register pair.
Indirect execution can resolve a target through a machine-level import-call
contract only when that contract supplies both the normalized import and the
argument words; it never invents an empty argument list.

The world-aware environment layer separates local call setup from the abstract
platform transition. `ExternalCallSiteContract` names the source cutpoint,
continuation, machine contract, post-setup boundary invariant, and successor
invariant. `ExternalEnvironmentRefinesAt` requires paired environments to agree
on the successor world, satisfy the declared stack cleanup, preserved-register,
memory, and world effects on each side, and re-establish the continuation
`StateRel`. `RelationalWorld` now models paired TLS slots whose values resolve
through exact, static-data, dynamic-range, or opaque-resource witnesses. A
`.tlsState` machine-call effect may update only that checked TLS component;
unsupported or ambiguous TLS values still fail closed. Opaque-resource worlds
are accepted only when IDs and concrete values are injective on both sides and
nonzero. Stage A emits
`relational-external-call-sites.json` for actionable gaps and a Lean-checked
`RelationalExternalCallSites` inventory. Candidate generation is now
fail-closed on paired unconditional guards, exact import identity, explicit
machine contracts, related arguments, x87/flag setup, one unambiguous claim per
boundary register, and affine stack-window transfer. It also externalizes a
register-held indirect call only when exact decode ends in the synthetic return
address push and one checked import-register relation uniquely identifies the
target and continuation. On the current jq pair, five edges satisfied these
profiles in the initial three-contract replay. An affine register-argument
witness then closed edge 4844 without treating a nonzero offset from a generic
`related_word` as sound. Machine-call contracts may now select
`pe32-cdecl-v1` or `pe32-stdcall-v1` plus an explicit `argument_words` count;
normalization derives stack argument offsets, cleanup, and the standard x86
volatile/nonvolatile register partition. Memory and relational-world effects
remain mandatory explicit fields. ABI templates therefore remove repetitive
contract syntax but cannot authorize an external write or resource update.

The external protocol also names runtime control-frame preservation explicitly.
For every admitted live `RelationalRuntimeCallFrame`, the paired environment
must preserve the frame's concrete return-address words across the matching API
result. This is a hypothesis of `ExternalEnvironmentRefinesAt`, not a fact
inferred from matching import names. Before invoking that hypothesis, Lean
checks `ReturnSlotMemoryTransferClaim` certificates proving that the binary's
own call-setup writes are disjoint from each live four-byte return slot. It then
checks affine register witnesses for the pre-call, call-boundary, and ABI-result
locations and carries the same frame objects and continuations into the
successor product node. A missing write witness, unsupported clobber, ambiguous
control state, or unpreserved frame remains `incomplete`.

Direct import thunks use the same rule after an additional checked boundary
normalization. `ExternalJumpReturnSlotTransferClaim` proves the thunk's decoded
register transformation, proves its writes disjoint from every outer return
slot, accounts for the synthetic import return-slot pop, and then applies the
machine contract's stack-result and preserved-register rules. The checked list
theorem carries any number of outer runtime frames through the matching
external event. Ordinary internal calls and jumps use
`ReturnSlotFrameTransferClaim`: every live frame needs an affine register
witness and a complete write-disjointness inventory. This applies to loops as
well as call setup, so runtime-frame preservation is no longer restricted to
top-level control states.

The relational world now has an explicit `dynamicRangeRelease` effect for
deallocation contracts. A non-null argument must identify exactly one existing
paired dynamic range on the appropriate original or candidate side, and the
successor world removes that same range while preserving stack ranges, opaque
resources, import addresses, and TLS state. A null argument is an exact world
no-op. The environment must still return one equal successor world for the
paired events and re-establish the continuation `StateRel`; matching the name
`free` alone proves nothing.

Machine-call memory effects now fail closed on explicit argument-relative
footprints. Each footprint identifies a read or write range by base-argument
index, byte offset, and either a fixed byte count or an argument-derived byte
count with a checked scale. Python normalization rejects malformed indexes,
zero or wrapping sizes, duplicate footprints, legacy unconstrained effects,
and effect/footprint mismatches. Lean independently checks the same shape and
recomputes each concrete range from the recovered argument words. Nonzero
ranges require a non-null base and may not wrap the PE32 address space unless
the footprint explicitly declares a nullable pointer. Lean interprets a null
value for such a footprint as an empty range and proves that it authorizes no
memory changes; non-null values retain the ordinary size and non-wrapping
checks. Nullability is part of the reviewed machine contract and cannot be
inferred from a call-site value.
`.none` and `.readOnly` preserve the complete concrete memory; an
`.argumentRanges` transition may change only bytes covered by a declared write
footprint. The former `.opaqueStatic` and `.relationalMemory` cases, which
allowed arbitrary memory changes, are no longer representable.

This closes the arbitrary external-write hole, but it does not yet discharge
the paired external-environment theorem. Read footprints are emitted as
machine-level evidence; the future environment checker must still prove that
both environments inspect related bytes and produce related contents inside
the permitted write ranges. `ExternalEnvironmentRefinesAt` remains an explicit
assumption until that checker and the whole-program composition theorem are in
place.

An expanded jq replay with eleven additional explicitly effect-annotated
Win32/MSVCRT contracts produces 17 Lean candidates and 31 incomplete edges. The
remaining first blockers are 25 missing machine contracts, two missing
non-memory register-output claims, one nonzero affine `related_word` argument,
one missing dynamic-range argument relation, one unsupported argument
expression, and one differing argument expression. Every gap now includes the
original and candidate import identities directly; missing-contract next
actions name the exact `dll!symbol`, point to the ABI templates, and still
require explicit memory/world effects.

Replaying the same binary pair with checked caller-buffer footprints and five
additional generic Win32 contracts produced 29 candidate edges and 19 explicit
gaps. Critical-section APIs use fixed 24-byte PE32 object ranges,
`GetConsoleMode` uses its four-byte output word, and `VirtualQuery` uses an
argument-sized output range. At that checkpoint, `WriteFile`,
`VirtualProtect`, and the character-conversion APIs remained incomplete rather
than silently approximating nullable buffers, sentinel lengths, or
page-protection state.

All 29 edge theorems and their aggregate certificate check through the remote
Nix graph. The proof-core change invalidated a 577-node, 1,582-module focused
closure and took 890.276 seconds in Nix (14 minutes 51 seconds end to end).
Sampling observed up to 15 simultaneous Lean processes on `acacia` and 39 on
`banksia`; packed derivations can run two single-threaded modules within each of
the 16 two-core Nix slots. Both hosts remained well below their 96 GiB memory
limit, so this run was constrained by the dependency graph and compilation,
not memory or the configured job ceiling.

Adding explicit nullable footprints plus a generic affine stack-word witness
admits `WriteFile` without changing the environment assumption. Its five
arguments are justified by two checked register relations and three 32-bit
reads inside the source region's 64-byte paired stack window. The bytewise
decoder form at nonzero offsets is reconstructed in Lean from the exact
`esp+n` addresses and proved equal to `Memory.read32`; Python accepts only that
same deterministic four-byte pattern. The jq replay now produces 33 Lean
candidates and 15 explicit gaps.

The new edge 3251 checked remotely in 544.784 seconds over a cold 494-node,
1,349-module focused closure. Building all 33 edge theorems and their aggregate
certificate then took 253.769 seconds over 588 nodes and 1,638 modules. The
identical warm aggregate replay took 0.756 seconds in Nix and 1.895 seconds end
to end. During the cold static-code-map wave `acacia` reached 16 active
two-core Lean jobs and `banksia` reached 15, while retaining 49 GiB and 57 GiB
available memory respectively. Narrow decode waves exposed only about 18 ready
modules, and the final result-collection tail exposed no Lean work. Low process
counts in those phases therefore come from graph width and store/result
handling, not the 16-job machine declarations.

The 15 remaining external-call gaps are classified, not hidden: seven sites
lack a unique machine contract (`VirtualProtect`, character conversion,
`_setmode`, and `GetProcAddress`); five fail register or stack-window boundary
transfer; two require a checked nonzero affine pointer/range witness; and one
`SetUnhandledExceptionFilter` site has differing argument expressions. The
generic next capabilities are sentinel-sized string footprints, a checked
page-protection world transition, recoverable imported function-pointer
results, and stronger boundary transfer. None weakens the already generated
local edge certificates, and every reachable gap remains a hard blocker for
whole-program acceptance.

Focused target results are now detached from their transitive build closure
before returning to the coordinator. The direct aggregate output retained 576
store references and a 648.8 MiB closure solely through inherited OLean indexes;
the detached output retains the target source, OLean, hashes, and module result
with zero store references and a 48.8 KiB closure. After the one-time detached
wrapper build, a fully warm replay took 0.705 seconds in Nix and 2.525 seconds
end to end. Full acceptance audits still retain and audit the complete proof
closure.

Each accepted site gets its own generated theorem checking exact decode,
normalized external outcome and arguments, local target resolution,
register/stack/x87/DF boundary transfer, `ExternalCallTransitionClosed`, and
`RelationalExternalProductEdgeRefinement`. All 17 expanded edge modules and
their aggregate certificate check remotely. Changing the generic Nix pack
recipe invalidated the 534-node, 1,314-module focused closure; that one-time
cold rebuild took 813.544 seconds while exercising all 16 two-thread slots on
both hosts. The identical warm aggregate replay took 0.675 seconds in Nix and
1.645 seconds end to end. This remains intermediate evidence: the old internal-only
product certificate does not yet include external edges, so whole-program
composition remains incomplete rather than treating the aggregate as a pass.

The register-held import class is now closed locally without weakening decode:
the generated theorem retains the indirect-target witness, proves the exact
call-push externalization, recovers stack arguments, resolves the reviewed
machine contract, and checks the successor-world effect. `TlsGetValue` obtains
argument zero from a dynamic range only because the source invariant explicitly
requires a `relatedWord` at that offset; otherwise the site is incomplete with
the required offset in its diagnostic. The next broad external-call work is to
add checked sentinel-sized footprints and a page-protection world effect, then
use read and write footprints in a constructive paired-environment refinement
theorem. The newly exposed call-shape and boundary-transfer gaps remain
independent fail-closed obligations.

Lean locally checks each register-held call target against its `StateRel`
import relation, so jq regions 3144 and 3145 gain external-call continuation
edges. This raises the checked root closure to 80 nodes and moves the sole
decoded-control frontier to region 3148. Both register-held TLS environment
edges now have local product-refinement theorems, but incoming establishment of
the strengthened region-3144 dynamic-word invariant and whole-product
composition remain separate hard obligations. The seven IAT load facts and seed-to-successor transfers for regions
1684 and 3143 are Lean-checked. Generic preservation witnesses plus zero-test
branch proofs also cover both exits around regions 3146 and 3147. External
nonvolatile-register preservation, argument recovery, environment effects,
successor-world refinement, and the remaining SCC incoming edges stay as hard
obligations. Each import-register obligation lists its exact covered and
uncovered incoming edges. Thus
submitted graph reachability is not used as whole-program coverage. Region
3148 is a different generic class, an indirect call through `[EBX+4]` in a
runtime callback record. With an explicit paired range and a typed code-pointer
cell at offset 4, Stage A emits and remotely checks the local
`DynamicRangeIndirectCallTargetsClosed` theorem. The proof IR reports the site
as a Lean replay candidate rather than a generic omitted indirect exit. It
remains the sole root-reachable decoded-control frontier because the current
contract does not yet establish the callback record at its producer, preserve
that world mapping to region 3148, or reduce the loaded pointer to a finite
checked product target set.

The next jq callback-loop increment checks dynamic-range preservation on the
internal edges and a nullable next-record pointer at offset 8. Edge 3580 from
region 3149 back to region 3144 now has a generated
`RelationalSegmentRefinement`: Lean derives guard agreement, the new dynamic
range, the ordinary related-word output, stack/import preservation, and the
successor `StateRel` from the same source theorem. The first cold replay of
segment chunk 23 checked remotely in 1,404.341 seconds over 606 nodes, 3,426
modules, and 48,395,520 source bytes. Segment and register chunks were importing
the full global static-context validity proof despite using only the
`staticProofContext` definition and local `resolveIds` checks. Switching those
chunks to `RelationalStaticContextBase` retained the independent final static
validity certificate, reduced the focused closure to 206 nodes and 3,026
modules, and checked the same target in 89.867 seconds. At that point, the
callback-cluster blockers were the mutable-static list-head to dynamic-world seed,
external environment/world refinement across the TLS calls, a finite checked
callback target inventory, and the null/fallthrough exit. None is waived by the
local traversal theorem.

The checked static-slot profile closes that list-head gap. The jq global at
`0x41005c` lies in writable `.bss` on both sides and outside `.idata`. Edge 3573
proves its null load as a zero/zero related-word output, edge 3574 proves its
non-null load seeds the callback-record dynamic range, and edge 3575 preserves
the range while loading the two import registers. A cold remote replay of
segment chunk 23 checked all three certificates in 298.01 seconds over the same
206-node focused closure and emitted an OLean with SHA-256
`1a6c54527b0d04fc6844388f22838bcecf4ee454b8500d6210475de5b3dcd198`.
This cold run invalidated the shared machine/state modules; later contract-only
iterations can substitute those dependencies. The callback cluster still needs
external environment/world refinement across the TLS calls and a finite
checked callback target inventory.

Memory-contract diagnostics classify every primitive read as an exact IAT
cell, statically outside the IAT, dynamically requiring a non-IAT proof, or a
partial overlap. They also recognize dwords assembled from byte loads. jq
region 2416 contains such an assembled IAT value after an intervening stack
write. Stage A now emits the sixteen byte-pair separation atoms needed to show
that the dword write at `ESP+1152` cannot overlap the four-byte
`msvcrt!_errno` IAT cell. `ImportRegisterSeedClaim` checks the normalized byte
assembly, every intervening register-relative write, the parsed import identity,
and the `ImportAddressPair` memory binding in Lean. Region 2416's local seed is
therefore a checked replay candidate; whole-program acceptance still requires
the stack-range/root/edge invariant proof that establishes those separation
atoms. The proposal consequently identifies region 2417 as the corresponding
register-indirect `msvcrt!_errno` call with continuation region 2418, but that
edge remains outside acceptance until the same invariant chain is composed.

Import-seed proof modules no longer import the whole product graph and static
code map. They depend on the relational kernel, exact original/candidate PE and
import attestations, and only the decode chunk owning their source region. Seeds
are packed by decode ownership rather than by an unrelated fixed count. On jq,
the focused region-2416 closure fell from 461 nodes, 989 modules, 15.4 MB of
Lean source, and 1,073.15 seconds for the first cold replay to 18 nodes, 123
modules, 2.98 MB, and 10.33 seconds after the relevant kernel/decode cache was
populated. The optimized target produced a 67,952-byte `.olean` with SHA-256
`29143b77480b6a605e40904bfef0b6cdab0a75ed1341ba3462c8da67ceb74851`.

The focused region-2709 Nix node checked remotely from a cold kernel closure in
807.8 seconds. After the kernel closure was populated, the final stable-edge
graph checked that node in 39.2 seconds and then substituted it from cache in
0.6 seconds (1.6 seconds including command startup).

Newly certified indirect edges are appended after the existing direct and
call-return inventory. This preserves every existing edge ID, so adding one
indirect target changes the tail graph chunk and its source node rather than
renumbering all later edges. The semantic certificate still resolves the
source's exact outgoing edge list through Lean; stable numbering is only a
cache property, not a trusted mapping assumption.

Adding guard data caused a one-time cold rebuild of the graph closure and the
new 13 edge-refinement plus 13 node-coverage chunks; the focused aggregate
node completed remotely in 1,025.48 seconds. An identical cached aggregate
check took 61.27 seconds, dominated by staging and evaluating its 6,656-module,
130.7 MB dependency closure. Normal slice iteration targets one bounded
node-coverage chunk instead and took 2.40 seconds warm. Structural validity,
195 partial witnesses, and soundly closed root reachability still do not prove
that all reachable decoded behavior is exhausted by declared guards; guarded
multi-successor coverage and SCC composition remain separate fail-closed
obligations.

Prepared Nix reports additionally contain:

```text
prepared-proof/
  prepared-proof.json
  module-graph.json
  relation-contract.json
  relational-proof-ir.json
  relational-semantic-ir.json
  relational-memory-contracts.json
  relational-register-relations.json
  relational-product-graph.json
  relational-invariants.json
  artifacts/{original,candidate}.pe
  lean/StageA/*.lean

report/
  verdict.json
  relational-proof-ir.json
  relational-semantic-ir.json
  relational-memory-contracts.json
  relational-register-relations.json
  relational-invariants.json
  lean-audit.json
  dependency-pack.json
  nix-provenance.json
  lean.stdout
  lean.stderr
```

Failed Nix builds persist complete `nix.stdout`, `nix.stderr`, and an
`incomplete` verdict in the requested output directory instead of returning
only truncated downstream dependency failures.

### Paired stack ranges and stack-memory reads

`RelationalWorld` now carries checked paired stack ranges in addition to static
image mappings. `StateRel` requires each range to be nonempty, non-wrapping,
disjoint from its corresponding PE image, and byte-equal at paired offsets in
the two concrete flat memories. Ordinary memory comparison masks those stack
bytes only after this separate relation is present; stack memory is not treated
as an unchecked waiver.

`StackWindowPair` records the range ID, original/candidate register pair, and
the required byte extents below and above that pair. Lean checks byte and dword
reads through a window, image/IAT separation atoms implied by a window, and
identity or constant add/sub stack-window transfer. Add/sub transfer checks
both decoded register expressions, no-wrap or no-underflow, range bounds, and
preservation of the paired base-relative offset. Source windows may be stronger
than target windows.

Static proposal generation seeds ESP windows from paired memory reads, writes,
and explicit image-separation obligations, then propagates them backward over
checked product edges. It distinguishes direct read/write seeds, separation
seeds, backward propagation, missing incoming edges, environment barriers, and
unsupported or mismatched deltas. EBP-relative accesses are not automatically
classified as stack accesses until checked ESP-to-EBP provenance exists.
Before propagation, Stage A computes reachable weighted SCCs for each register
pair. A zero-net affine cycle converges normally. A non-zero-net cycle cannot
have a finite flat-window invariant, so synthesis emits
`nonzero_stack_delta_cycle_requires_relational_frame` and stops at that SCC.
This is a structural fail-closed result, not a time or iteration bound.

Paired stack-read guards are accepted only when the original and candidate
guard trees match structurally and every `read32` leaf has one unique covering
window. A separate checked output claim currently handles the common
`read32(stack + offset) - immediate` register result. Stack-covered register
pairs are removed from the generic `related_word` inventory on internal edges,
so the authoritative stack-window relation proves them once instead of being
duplicated by an incompatible static-pointer relation.

Stack writes use one generic paired-memory frame rule rather than separate
preservation arguments for ordinary memory, stack memory, imports, immutable
image memory, dynamic ranges, and static pointer slots. A checked footprint and
image-disjoint paired location preserve all seven memory families. The rule
accepts an ordered finite list, so spills, argument setup, and out-parameter
initialization reuse the same induction instead of generating one theorem per
write count. Every stored value carries an explicit proof witness: either an
expression whose inputs are exact, or the same `RegisterArgumentClaim` used at
machine call boundaries. A bare `related_word` register may therefore be
stored at paired addresses, while arithmetic over such a relocated value fails
closed unless a stronger relation theorem is supplied.

Segment-certificate proposal objects are also the diagnostic contract. The
same immutable object supplies the Lean emitter and is serialized under each
proved segment obligation in `relational-proof-ir.json`, including cutpoints,
guards, stack windows, transfer claims, ordered effects, and value witnesses.
The profile name is only a summary; there is no second hand-maintained JSON
model that can silently drift from the formal claim.

On the full jq alignment pair, this generated 3,608 region windows. Constant
affine propagation reduced the unsupported/dynamic stack-transition frontier
from 370 to 171; the newly reached earlier cutpoints expose 1,341 missing
incoming-edge/root obligations. Stack-read guard and output claims increased
the generated segment-refinement inventory from 449 to 507, closing both
outgoing edges of `umain-0359` (2415). Lowering stack-owned register pairs and
using affine transfer increased it again to 513. These counts are proposal and
certificate inventory metrics; final acceptance still depends on successful
Lean replay and whole-program composition.

The jq affine-transfer fixture was replayed through the distributed Nix graph.
Its first focused build populated 403 newly separated static-context
derivations and checked segment chunk 1 in 595.5 seconds. Once those paths were
cached, a proof-only correction rebuilt only segment chunk 18 and checked it in
43.1 seconds. The builders reached 16 concurrent two-thread Lean processes on
acacia and 15 on banksia during the wide phase; the narrow focused rebuild used
one process because only one invalidated graph node was ready.

### Relational call-stack reconstruction

Direct calls and returns are now reconstructed from decoded machine behavior
without using function names or linker ownership as trusted facts.
`DirectCallPushClaim` checks the mapped callee and continuation IDs, the final
ESP expressions, and the final stack writes containing the exact continuation
addresses. Continuations may use a canonical code target or a Lean-checked
padding alias independently on either side. `ReturnPopClaim` checks a direct
ESP-relative return-address read and an ESP advance of exactly `4 + imm16`.
`RelationalRuntimeCallFrame` records the paired concrete stack slots and mapped
return addresses. Given a frame-memory fact and a propagated return-slot
invariant, Lean proves that both return outcomes dispatch to the frame's paired
addresses. Function ownership is therefore not needed for the trusted return
rule; the remaining obligation is product-graph propagation of the top-frame
slot.

Affine stack evidence is explicit rather than inferred inside Lean from an
untrusted offset value. `RegisterOffsetWitness` reconstructs the exact nested
`ESP`, constant-add, and constant-subtract expression. Lean checks the
reconstruction and proves its evaluation by induction over the witness.
`ReturnSlotTransferClaim` composes a finite pair of original/candidate frame
offsets across an ordinary edge. Joins preserve at most eight alternatives;
exceeding that budget is an `incomplete` frontier rather than a widening.
`ReturnPopFrameClaim` then connects a checked return read to the active runtime
frame.

On the jq alignment pair, all 634 statically decoded direct calls have checked
push claims and all 143 return regions have checked pop claims. The non-direct
case, `_set_invalid_parameter_handler-0000`, writes a dword to a fixed writable
PE-image address before reading the return slot. Stage A reconstructs the exact
`read32AfterWrites` expression and emits all 16 byte-pair separation witnesses
between the four-byte stack slot and the four-byte image write. Lean checks that
the write addresses are constant, that every separation is covered by the
region invariant, and that the invariant follows from a paired stack range
disjoint from both PE images. It then proves that applying the writes preserves
the runtime frame's return-address word. Dynamic writes, out-of-image writes,
wrapping addresses, incomplete separation inventories, and malformed assembled
reads remain incomplete.

The jq replay raised exact active-frame closure from 41 to 42 return regions.
Preparation from cached PE extraction took 29.6 seconds. The new region-1713
stack-separation node checked remotely in 3.9 seconds; its 604-module focused
register-relation closure checked in 71.2 seconds cold. Adding the concrete
universally quantified runtime-frame theorem rebuilt the same target in 21.2
seconds with dependencies cached. The generated theorem states that every
source `StateRel`, frame-offset witness, and frame-memory fact yields the paired
original/candidate return outcomes, rather than merely recording a recognized
syntax profile.

The first full jq return-slot propagation seeds all 634 direct callees, emits
935 ordinary affine transfer certificates, and reaches 928 regions without a
finite-join overflow. It proves one exact active-frame offset at 42 of the 143
return regions. A provenance-independent pushdown proposal computes return
sets from decoded edges rather than function names. Its strict closed-exit
check currently accepts 33 call targets; 13 call summaries emit 16 Lean-checked
certificates. The other 101 returns have no complete checked path from a call
seed, principally because an external or unresolved indirect transition cuts
the static summary. These are reported as contract frontiers, not accepted
edges.

`ReturnSlotCallSummaryClaim` checks the call-site stack expression, return-slot
and return-output expressions, callee pop size, and the caller-frame offset
restored at the continuation. Lean proves that the checked summary preserves
the enclosing runtime frame. This allows nested calls to be composed without
using recovered function ownership as proof evidence.

`stage-a-build-relational --target-node ...` may now be repeated. The command
constructs one focused source closure and asks one Nix scheduler invocation to
build the complete node set. This avoids evaluator, SSH, and daemon contention
from running one coordinator per independent module. An eleven-node warm jq
node set completed in 31.5 seconds and emitted per-node OLean hashes in
`node-set-build.json`.

Four sequential eight-target requests replayed the current 32 jq register
chunks in 14.9, 15.0, 25.2, and 16.4 seconds. An earlier single 32-target
register request left idle daemon sessions after Lean had stopped and was
cancelled rather than treated as a proof result. This is not a general target
count limit: a later 48-target medium local-proof request completed successfully
in 68.02 seconds and saturated both builders. Batch sizing should therefore be
driven by the target closure's fan-in, output volume, and memory class rather
than an arbitrary eight-node ceiling.

The jq dynamic-callback preparation reused the extraction cache and completed
in 28.3 seconds. Its focused local theorem had an 18-node, 123-module, 3.2 MB
closure and checked remotely in 103.0 seconds cold. The aggregate certificate
initially imported `RelationalProductGraphContext` despite not using the graph;
that accidental dependency began pulling thousands of static-context nodes and
was cancelled. Removing it reduced the aggregate to 19 nodes and 124 modules;
the warm remote replay then completed in 5.1 seconds. Certificate families must
not import global contexts merely to obtain common definitions, because those
imports directly determine Nix scheduling width and invalidation cost.

Focused single-node materialization now restores write permission on the copied
Nix result directory before adding `node-build.json`; Nix store modes had made
an otherwise successful cached build fail while recording local provenance.

### Reachable local-refinement certificate

`RelationalProductLocalEvidence` now separates the reachable composition
frontier from global proposal counts. Its partial certificate requires every
listed node to be marked reachable, every listed edge to be both reachable and
feasible, every node to have decoded-control completeness, and every edge to
have either an internal segment refinement or an external-call refinement.
Strictly increasing ID inventories and all local claims are checked in Lean.
The full `ReachableProductLocalCertificate` is emitted only when the listed
nodes and edges equal the complete reachable inventories. It remains
fail-closed and is an intermediate certificate, not the whole-program
acceptance theorem.

The jq alignment pair currently has 80 nodes and 95 feasible edges in the
checked root closure of the incomplete submitted graph. These counts are an
under-approximation and must not be interpreted as behavioral reachability or
coverage progress. Seventy-nine checked-closure nodes have decoded-control
completeness, while 17 checked-closure edges have local refinements: ten
internal and seven external. The immediate truthful frontier is therefore one
decoded-control node and 78 local edge refinements. Across the whole graph, the
proposal inventory contains 492 internal and 33 external local refinements.

Conservative potential reachability expands unresolved indirect control to
every canonical code-map target. On the same jq pair it reaches all 4,149 nodes
and 4,932 existing feasible edges, and reports 70 control cuts representing a
pessimistic 290,430 as-yet-unrepresented transitions. The first cut is an
internal callback loaded from a paired dynamic range in
`___mingwthr_run_key_dtors.part.0`. Acceptance cannot classify code outside the
small checked closure as unreachable until these cuts are replaced by
Lean-checked finite target inventories and composed product edges. Neither set
of counts constitutes a Stage A pass, and runtime testing remains gated.

The first dynamic callback now has an explicit fail-closed fanout. Stage A
appends one guarded call edge for every canonical code-map target while keeping
the preceding 4,933 edge IDs stable. Each guard checks the loaded callback word
against the target's primary address and all checked aliases on the
corresponding PE side. Lean derives a concrete member of the finite code-map
inventory from `StateRel`'s `codePointerRelated` witness, checks every generated
edge's source, destination, kind, and guards, and rejects missing, duplicate,
or extra outgoing entries.

This deliberately broad but sound fanout expands the checked jq root closure
to all 4,149 nodes and 9,081 feasible edges. It closes the first cut but exposes
the real next frontier: 69 reachable nodes still lack decoded-control
inventories, 8,556 reachable feasible edges lack local refinements, and the
remaining indirect cuts conservatively represent 286,281 unsubmitted
transitions. Reaching every node does not mean every node or edge is proved; it
means the previous 80-node figure is no longer hiding work behind the first
unresolved callback.

A single `by decide` over the 4,149-edge fanout used about 12.8 GiB in one Lean
process and was still running after twelve minutes. The exact inventory is now
split into 130 independently cached 32-target range certificates plus a small
coverage join. The generated module graph marks these checks high-memory based
on measured reduction cost rather than their small source files, and Nix can
schedule the independent ranges across both remote builders. A cache-compatible
run that completed the remaining range shards, join, and node-3148 control
theorem checked in 620.6 seconds; its immediate warm replay checked in 0.587
seconds. Wide-join dependency materialization remains a clear cold-build
optimization target.

Generating this certificate exposed an unsound proposal rule in paired stack
guards. A guard such as a checked stack read compared with an ordinary input
register had been accepted after checking only the stack read. The generator
now requires every other input-register leaf to have one unique exact source
relation. Related-word inputs fail closed. This removed 24 false internal jq
proposals before Lean composition; the reachable 17-edge inventory was
unchanged.

The first certificate implementation imported all selected decoded and edge
proofs into one module. Its focused jq closure was reduced from 2,021 graph
nodes to about 700 by selecting exact proof chunks, but Lean still used about
33 GiB in one serial process. The certificate is now a DAG: one lightweight ID
inventory, ten reachable-node shards, three reachable-edge shards, two joins,
and a small final certificate. Reachability/feasibility validity is proved in
the same shards as the semantic claims; no prerequisite performs a monolithic
reduction over all 4,149 nodes and 4,933 edges.

With 16 two-core derivation slots configured on each 32-thread, 96 GiB remote
builder, the corrected focused jq build checked cold in 125.9 seconds. Remote
Nix logs attribute ten modules to acacia and seven to banksia, confirming that
both hosts participated. An immediate warm replay completed in 0.843 seconds.
The previous global-validity module alone had already run for more than three
minutes at roughly 8.6 GiB before any shard became runnable. The builders use
their Tailscale FQDNs so the dedicated non-interactive Stage A key is selected
without an unrelated interactive SSH identity taking precedence.

`stage-a-build-relational --target-node <node-id>` builds one graph node and
its dependency closure for focused iteration. The command stages only sources
in that closure. The Nix evaluator imports every `.lean` source as an
independent store path, so editing a composition theorem does not change the
derivations for unchanged original/candidate PE attestations. Full builds still
select the final audit node and retain complete node/NAR provenance.

### First whole-program acceptance theorem

`WholeProgramCertificate` is now the only acceptance-capable certificate. It
binds the exact static context, canonical product graph, region inventory,
inductive invariant table, checked reachability closure, decoded-control
completeness, local edge refinements, concrete execution-edge refinements,
paired external environments, and launch relation. Lean's
`pe32ProgramsEquivalent` theorem composes those fields into a relation over the
two decoded world executions and proves related observations and successor
states for every reachable step. The older relational-image certificate remains
intermediate evidence and cannot select an acceptance theorem.

The generated acceptance profiles remain deliberately narrow. In addition to
`direct-no-write-jump-v1`, guarded direct branches close through exhaustive
paired guards, and `finite-call-return-v1` closes direct calls and returns with
an authoritative `RelationalRuntimeCallFrame`, exact return-slot readback,
mapped continuation resolution, and finite checked control states. A generic
eight-byte fixture containing a direct call, return, continuation jump, and
loop closes `candidatePE32ProgramsEquivalent` over three rooted nodes and two
refined feasible edges. External events, writes outside the checked framed
update profiles, multiple roots, and unresolved control still produce specific
`whole-program-acceptance.json` blockers.

An exact two-byte PE32 self-loop (`eb fe`) closes this profile end to end. The
generated `candidatePE32ProgramsEquivalent` theorem checks at Lean trust zero,
depends only on the approved `propext`, `Classical.choice`, and `Quot.sound`
axioms, and makes the distributed Nix build return `pass`. The cold 73-module,
73-derivation build completed in 104.2 seconds with local derivation builds
disabled. This establishes that the acceptance path is connected; it does not
establish realistic PE breadth.

## Current Boundaries

This v3 implementation has closed whole-program theorems for direct loops,
guarded branches, and a finite direct call/return loop, but not yet a broad
practical PE equivalence theorem. Its
intermediate proofs support arbitrary register relations, identity-address
arbitrary memory, loads, ordered stores, direct logical targets, returns, and
imported calls exposed by the existing decoder. Whole-program acceptance still
deliberately reports `incomplete` for:

- translated or object-mapped data layouts;
- indirect internal targets outside the checked immutable relocated-word call
  profile, including mutable tables and unresolved finite target sets;
- clusters containing internal control-flow joins;
- internal-call return-address normalization across moved code;
- unsupported x86, x87, SIMD, exception, callback, or self-modifying-code
  semantics, and TLS behavior outside the checked paired-slot model;
- any reachable external event, general memory-writing segment, bounded
  indirect target, or call/return shape outside the finite checked runtime-frame
  profile that is not yet connected to the generated world-step proof.

The jq-sized canonical map is now checked as 16-entry indexed range
certificates. Bounded-fanout Lean trees compose code-entry, original-address,
candidate-address, and exact alias-count certificates without a monolithic
reduction. Data-map validation separately permits overlapping relocation uses
only when they induce the same address translation; conflicting overlaps and
non-permutation order inventories are rejected. On the full jq pair, the
focused `RelationalStaticContext` build checks 4,149 code targets, 4,600
original addresses, and 4,743 candidate addresses. The first corrected remote
build took 448.9 seconds; a warm Nix-cache rebuild took 4.3 seconds. The former
77+ GiB monolithic map blocker is therefore closed rather than waived.

These are implementation milestones, not waivers. The theorem formerly named
`candidateRelationalCertificate` remains
`candidateRelationalImageCertificate` and is not acceptance eligible. `pass`
requires the generated `candidatePE32ProgramsEquivalent` theorem. The full jq
pair remains incomplete until that theorem covers its complete rooted product
graph; the small loop, branch, and call/return fixtures only validate their
current composition profiles.

Projecting the latest cached jq graph through `composition-progress.json`
distinguishes 371 nodes reached by decoded rooted traversal from the 4,149-node
conservative potential inventory. The rooted slice currently has 421 feasible
edges, 54 locally refined segments, 367 segment frontiers, 72 stack-invariant
frontiers, and no relational-call-frame frontier. Seventy unresolved indirect
controls contribute 290,430 conservative potential targets. Twelve rooted
external edges include nine refinement candidates and three contract gaps;
direct import-thunk analysis emits four checked `free` sites and four checked
`strlen` sites plus two checked `_amsg_exit` sites, while 41 other thunk
contracts remain absent. These are
composition-frontier counts, not a completion percentage and not evidence of
final equivalence.

The first jq reprepare with the `free` contract took 97 seconds and a warm
reprepare took 28.6 seconds without rebuilding either PE or any Stage B
artifact. Focused remote Nix compilation of
the jq caller-1041 `free` site checked a 94-derivation, 958-module, 16.2 MB Lean
closure in 148.7 seconds and emitted a reproducible OLean hash. Rooted control
then reached an earlier `_amsg_exit` thunk first.

The generic machine-call contract now distinguishes returning and terminating
interactions. A terminating interaction emits the same checked external event
on both sides and enters a distinct terminal world-execution state without
querying an environment result. Contract validation and Lean both reject a
terminating declaration with a successor stack delta, memory footprint, memory
effect, or world update. The whole-program fixture checks a nested internal
caller, direct import thunk, related stack argument, exact external observation,
and terminal/terminal execution relation through `candidatePE32ProgramsEquivalent`.

Applying that contract to jq emits two checked `_amsg_exit` thunk sites. A
remote-only Nix replay of the machine-contract table and both site modules took
155.5 seconds and produced checked OLean artifacts. The rooted counts remain 371
nodes, 421 feasible edges, 54 refined segments, and 367 segment frontiers, while
the stack-invariant frontier falls from 74 to 72 and absent thunk contracts fall
from 43 to 41. Rooted traversal now stops at `msvcrt!exit` in node 69, which is
also non-returning and remains undeclared. The jq proof is therefore still
truthfully incomplete; this increment closes a generic terminal-interaction
class rather than asserting whole-program acceptance.

The relational world now also carries an ordered inventory of registered
callback pairs. Each registration names one canonical code-map target and the
exact original/candidate entry addresses; Lean checks primary and alias
addresses against the embedded PE mapping. The machine-call world effect
preserves dynamic ranges, stack ranges, opaque resources, import addresses, and
TLS while prepending exactly one valid callback. Contract shape validation
rejects a missing or out-of-range callback argument.

Direct import-thunk recovery now follows a finite chain of paired unconditional
internal tail jumps from a checked call edge. The proposal records every wrapper
region and local edge; ambiguity produces `incomplete`. Whole-program acceptance
still independently derives the decoded call/jump runtime frames and consumes a
Lean-checked external-jump refinement, so the recovery path is not trusted.
A generic fixture checks nested calls, a mapped callback argument carried in the
outer return slot, an internal tail wrapper, `atexit` registration, return-slot
normalization, and continuation through `candidatePE32ProgramsEquivalent`.

On jq this finds both actual `atexit` sites: callers 373 and 4071 call wrapper
1726, which tail-jumps over checked edge 2017 to import thunk 66. Remote Nix
replay checked site modules 4935 and 4945 and emitted reproducible OLean hashes.
The prepare reused exact PE semantics and took 14 seconds; the focused remote
build took 295.4 seconds, mostly due to remote contention and transferring the
large prepared source closure. Rooted composition counts do not advance because
the current rooted frontier reaches `msvcrt!exit` first. The reusable CRT
profile now declares it as a stateful protocol boundary, not as a terminal
interaction. The acceptance planner reports the missing paired action proof
explicitly; declaration alone cannot bypass the required well-bracketed
callback frames.

The first callback-invocation kernel is now split into
`RelationalCallbacks.lean`. It defines a mixed runtime stack with typed internal
and external continuations. An external callback frame must resolve all of the
following in Lean: a canonical registered callback pair, a mapped PE
continuation for the suspended call, a same-offset slot in one paired stack
range, and a non-null paired opaque-resource token for the external return
address. Concrete memory and ESP predicates connect those witnesses to callback
entry and return states. A checked adapter embeds every existing internal-only
runtime stack into the mixed relation, avoiding a second proof regime.

The decoded execution model also has explicit `awaitingExternal` and
`callbackRunning` states and a stateful protocol action type with `returned`,
`callback`, and `terminated` outcomes. Callback return advances the suspended
protocol phase only after the decoded return target equals the side-specific
opaque return token. `WorldExecutionsRelated` now represents both states. A
paired suspension carries the exact canonical call-site contract selected from
the program and must resolve to a `.protocol` machine contract, preserve its
phase invariant, and retain every outer callback return frame. A running
callback must additionally resolve its entry target to a reachable product
node and checked invariant while preserving its internal calls and all
concrete external return slots.

This remains intentionally unavailable to acceptance. The currently accepted
`ExternalEnvironmentRefinesAt` rejects `.protocol`, and Lean derives a
contradiction from any submitted related protocol state under that refinement.
The next increment must replace that contradiction with checked paired
protocol-action and callback-node step refinements before any profile may
select the disposition.

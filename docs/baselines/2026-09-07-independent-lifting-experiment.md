# Independent lifting experiment: Metapad text cleanup

This is the historical starting experiment. The current result is recorded in the
[2026-09-14 milestone audit](2026-09-14-independent-component-milestone.md); statuses
and blockers below describe the earlier checkpoints.

Status: in progress, updated 2026-09-08. This is a non-authorizing experiment under
[the independent lifting plan](../independent-portable-lifting-plan.md).
The [contextual-bisimulation contract](../portable-c-contextual-bisimulation.md)
remains authoritative. No application provider is qualified by this baseline.

Current borrowed-prefix checkpoint: the adapter now uses a current registered
terminated prefix within an already-realized borrowed reference, with a final
read through the actual runtime. It retains the containing object and visible
capacity. The fallback remains a checked zero at the view's own final byte.
Tests cover interior aliases, missing registration, stale terminators, narrow
visibility, unavailable readers and existing reference/lifetime rejection.
Both contextual readers require the implementation closure. All 56 targeted
Nix tests pass with zero skips and repository gates in 29.480s.

`cleanup-entry-allocation-v4/` compiles the same full source and allocation-cut
proposal with the new proof adapter. Costs are 1.695/0.026/0.252s for preparation/
model/compiler. The model has 167 functions/10,625 instructions, including proof
and native-adapter support, and four original transfers. The 49-cut-assertion
group and five string-admission/scratch assertions initially exceed 120s during
SSA conversion. The complete cut group with a 300s limit finds a new failure in
177.013s: `spx-bisimulation-allocation-cut-admission:allocated`.

In that trace, scratch has live identity and extent 110 at address 8387474,
ending at 8387584, exactly the entry private-window lower bound. ESP falls from
8388608 to 8388580 before the cut; its recomputed lower bound is 8387556. The
last 28 allocation bytes therefore become private under resumed admission.
The trace's public-memory comparison succeeds before history admission fails;
this is a concrete witness, not a theorem for every state. `frame-finding.json`
binds the arithmetic to the full trace. The separate five string-admission/scratch-descriptor assertions and three
unwind assertions pass on this same model in 146.031s. This proves the selected
constructor transport fix under the retained image-input premises; the complete
cut proof still fails at allocation-history admission. Consistent private/public memory scope
across cuts is the next transport requirement; pointer capture or erased checks
cannot supply it. Separately, `allocation-boundary-required-target-relation.json`
authors the consumed EBX/current-IAT relation and retains its parser rejection.
Automatic boundary recommendation work remains deferred. No pilot or link runs.

Previous hand-defined split checkpoint: `public-cleanup-allocation-split-v5/`
adds an allocation cut at `0x55d7`, with scratch in EAX; the existing loop cut
captures scratch in EBX. All 35 original units and the ordinary C operation
remain. Canonical planning produces three obligations in 0.009s after 2.276s
preparation. Public source compilation/profile checking passes in 3.573s.
These checks do not qualify the proposal or its semantic binding.

The preceding 14-transfer constructor-to-loop attempt used the unchanged full
source, took 1.690/0.111/0.292s for preparation/model/compiler, and exceeded its
120s selected-query limit during SSA conversion (120.488s elapsed). The split's
four-transfer constructor takes 1.696/0.027/0.253s, with the full marked source
unchanged within the proposal. Selected invariant, access, frame and initialized
counter assertions plus unwinding pass in 54.014s. Expanding selection to all
49 allocation-cut/access assertions finds a scratch-capture counterexample in
59.909s. This is a failed transport check, not a completed local proof.

The retained trace has a 255-byte admitted terminated span, an original length
response of 64 and a live 65-byte allocation. The generated source parameter
view instead uses the input object's remaining capacity. Its length adapter
checks that capacity's final byte, which is 255 in the counterexample, sets a
service failure and returns zero. The following source allocation consequently
returns a null view. This identifies a mismatch between a terminated span and
object capacity, not evidence that pointer reconstruction preserves contents.
A checked span and its native/proof transport are required; asserting a zero in
otherwise unused capacity would merely narrow away the counterexample.

Separate live/null witnesses pass in 74.036/71.701s; their reachability does not
repair failed assertions. The resumed allocation region additionally needs the
loaded `EBX` service target related to the current import slot. Its source
`length` local is dead at the cut. Complete typed-service and language-safety
checks, successor transport, actual caller lifetime, copy-service selection and
public qualification remain open. All inputs, models, commands, traces and
phase costs are indexed by `real-network/checkpoint-allocation-split.json`.
No pilot or native link runs for this checkpoint.

Current content-boundary checkpoint: the existing `byte_read` expression now
observes canonical source-local views with checked access and incoming/current
memory selection. Two new solver tests retain a current zero at a cut, reject a
paired change to that byte at the successor, and reject an invalid read before
assuming the invariant. Existing reader tests additionally reject missing byte
access evidence. All 44 selected Nix tests pass, zero skips, plus repository
gates in 33.055s (`real-network/local-byte-invariant-nix-result.json`).

The nine real loop transfers are retained in
`real-network/cleanup-loop-content-invariant-v11/`. The invariant states
`output <= input`, `output + removed == input`, `input < scratch.extent`, positive
scratch extent no greater than the text view, and a zero byte in both views at
`scratch.extent - 1`. The regional source uses a canonical local image view for
text alongside its canonical scratch view. Incoming premises explicitly include
these facts, one live allocation of extent 1..256, a 500-byte image input, and the
previous fixed entry frame/other-register initialization. This does not establish
the real callers' heap or allocation premises. Preparation/model/compiler cost
is 1.565/0.038/0.164s. The selected invariant and access assertions plus three
unwind assertions pass in 82.148s. All three branch witnesses pass in 115.082s.
Other equivalence and language-safety partitions have not been rerun on this
model; these checks are not full regional qualification.

The current cut header regenerates byte-identically after subsequent reader-only
changes; `current-generation-recheck.json` records both source identities without
relabeling the original compilation. The full cleanup proposal now carries the
content predicate with a distinct null-allocation branch, preserving its C and
source compilation inputs (`real-network/public-cleanup-content-boundary-v4/`).
Its proposed plan takes 2.340s preparation and 0.008s assembly, with no compiler,
solver, pilot or link work. It remains a diagnostic plan, not a qualified semantic
contract. Establishing this boundary from the allocating prefix, the full source
proof, selected copy semantics and caller composition remain required.

Previous finite-source-loop checkpoint: the canonical intent accepts an explicit
`source_unwind_limit`; the engine and both readers bind it to checked unwinding
with self-loop-to-assumption rewriting disabled. Five new tests include a full
paired finite-loop proof, insufficient-bound rejection, divergence rejection and
receipt mutations. The final Nix selection passes 46 tests with zero skips plus
smoke/lint/freshness/retired-architecture gates in 28.298s.

The unchanged full cleanup C now has a hand-authored limit of 3. The diagnostic
plan retains all 35 original transfers, three lexical loops and one main-loop
sync; it does not invent cuts for the two finite copy loops. Its semantic input
identity binds the proposed boundary and retained transfer digest, not a
qualified semantic-contract receipt. Preparation/model times are 2.288/0.008s.
The public source check reuses the pinned SDK/source product and passes in
2.152s. It does not exercise the new proof policy. No pilot, solver or link runs
for this proposal. Its first preparation attempt incorrectly supplied a bare
machine projection where the planner requires executable units; the corrected
driver loads all selected units through the canonical transfer-universe loader.
Both attempts are retained. Evidence is in `real-network/public-cleanup-source-loops-v3/`
and `real-network/source-loop-nix-result.json`.

The full component's bounded-loop execution, caller heap/lifetime premises,
selected copy service and inductive successor relation remain unproved. These
are the next real-consumer obligations; the old scanner rejection is resolved.

Previous checkpoint: the version 10 model supplies the normal generated
typed-call focus entry and uses checked same-entry unwinding reuse. All 114
semantic assertions and five safety partitions pass in 697.674s. Preparation,
model generation and compilation take 1.616/0.039/0.168s; pilot and link costs
are zero. Three branch witnesses pass in 55.344s after 0.164s compilation.
Writing zero instead of the input byte violates the world-memory assertion in
35.341s after 0.167s compilation, retaining independent unwinding checks for the
mutated model. All 143 selected Nix tests pass with zero skips, plus smoke and
repository checks. Evidence is indexed in
`real-network/checkpoint-entry-unwinding-reuse.json`.

This is a conditional nine-transfer region, not full loop induction or component
qualification. The harness admits one live scratch allocation of extent 1..256,
an output index below that extent, image-backed text of 500 bytes and input index
at most 497. It fixes ESP to `0x800000`, EBP to ESP+24, and zeroes other initial
registers before overriding the named state. Current scratch bytes and the
removed counter are arbitrary. The boundary invariant is `true`; these harness
premises have not been established by all actual callers or preserved as a
complete successor invariant. The full ordinary-C source still needs checked
progress for its two internal bounded copy loops. All 589 implementation hashes,
16 model-file hashes, twelve trial inputs and original cleanup C match their
retained manifests at this checkpoint. No background proof job remains.

Earlier production-partition checkpoint: the corrected version 9 model exhausts
the old checker's 256 addressed C objects. The current shared command policy
uses 10 object bits and dereference caching; the Python and JQ readers bind both
options. The new 300-object fixture reproduces the old exhaustion and passes
under the new policy. Final Nix validation passes 133 affected/repository tests
with zero skips plus smoke/lint/freshness/retired-architecture checks. The first
Nix run exposed an omitted compiler fixture dependency; the final declaration
includes it. Exact products are in `real-network/property-policy-final-nix-result.json`.

All real-region safety partitions now pass, including a 74.808s isolated pointer
check at the larger-region 120s limit. The complete engine run passes 17
equivalence assertions before an explicit interruption after its current batch:
those assertions consume 1,037.181 summed query seconds. At that checkpoint no
regional proof was complete. Grouping the 112 assertions sharing `main` times out at
120s; two typed-call assertions have a distinct focused entry. A diagnostic that
reuses the already satisfied same-entry unwind partition checks call-count
equality in 8.714s. Production then still rechecked unwinding per assertion; changing
that rule requires checked same-entry prerequisites and separate focused-entry
handling. Evidence is under `real-network/cleanup-loop-local-view-v9/`.
The production coverage command reaches copy, removal and tail witnesses in
56.281s on a separately compiled coverage model. Its initial driver failed before
query execution because it supplied an unsupported output argument; the resumed
driver reuses that compiled model with the normal query-evidence recorder.
The original compilation timing was not retained and is reported as unknown.
Compiled-function inspection also confirms the manual model lacks
`main_focus_typed_call_0`; its two focused obligations remain unsupported until
normal model generation supplies the correct entry. All twelve trial inputs and
the original cleanup C remain unchanged.

Latest real local-view correction: the version 6/7 diagnostic runner omitted
`spx_proof_exact_input_read` and `spx_proof_exact_output_read`. CBMC explicitly
removed those bodyless calls. Production supplied both; the retained runner now
imports their unchanged implementation through the shared
`memory_projection_readers()` helper. Seven focused tests now include an actual
stack capture across a native-view cut with distinct incoming and successor
bytes. Final Nix validation passes 114 affected/repository-boundary tests, zero
skips, plus smoke/lint/freshness/retired-architecture gates in 34.146s.

Corrected version 8 uses production unwind limits, reachability/formula slicing,
and CBMC dereference caching. Its separately selected descriptor-entry and
outgoing-capture queries pass in 45.934s and 58.873s using the same compiled
model. Complete properties remain incomplete at 60s. Version 9 also uses the
production temporary compactor and remains incomplete at 60s. These checks keep
the same nine transfers and conditional input premises, and do not establish
the successor invariant, all safety checks, actual callers or the full network.
Commands, implementation identities and separate costs are retained under
`real-network/cleanup-loop-local-view-v8/` and `cleanup-loop-local-view-v9/`.

Latest source-local boundary checkpoint: canonical service views now have an
explicit `native_view` cut capture, bound to the real native accessor codec and
the checked image/allocation authority. Current memory remains in the paired
world; descriptor reconstruction does not replay allocation initialization.
The descriptor is checked after every capture restore, including aliased scalar
writes. Six focused tests cover actual resume/read/alias-write behavior,
descriptor and runtime mutations, retired lifetime, outgoing capture rejection,
schema and both receipt policies, and an alias corrupting the restored descriptor.
The final Nix selection passes 113 affected/repository-boundary tests with zero
skips, plus smoke, lint, freshness and retired-architecture gates, in 32.602s.
Exact products and per-shard logs are retained in
`real-network/local-view-cut-final-nix-result.json`. All twelve original trial
inputs remain unchanged.

The complete ordinary-C cleanup with explicit main-loop markers passes public
`component check metapad text-cleanup --source` against
`real-network/public-cleanup-local-view-v2/`. Compiler local inventory identifies
the aggregate scratch capture in 0.080s. The full proof-marker scanner still
rejects two unannotated bounded copy loops, so this is source readiness only.
The separate nine-transfer real-loop model uses the new codec but remains
incomplete: 90s for all properties and 60s each for focused descriptor queries,
including retries using production reachability/formula slicing. Output stops
during SSA conversion. Retained commands, hashes and costs are under
`real-network/cleanup-loop-local-view-v6/`; these models predate the final
post-restoration alias assertion ordering fix. They do not establish the full
loop or supersede the earlier conditional evidence below. No pilot or link runs.

Latest allocation-boundary checkpoint: a canonical sync declaration names
`cleanup.scratch` and a maximum history of one instance, including retired
generations. The existing engine now uses checked allocating-service classes and
one metadata predicate for predecessor admission and resumed construction. Both
receipt readers bind the transport policy and input bound and require the resumed
constructor assertion. Parameter/reference decoding retains its separate checks;
an arbitrary source-local descriptor or logical-origin registry is not transported
by this declaration.

The retained nine-transfer loop uses this declaration and passes 5,313 properties,
three branch witnesses and a negative current-byte/zero-initialization check. Its
model contains 133 functions and 32,588 instructions, with the original prefix
body absent and zero service calls checked. Source and original-input hashes are
verified. Evidence is under `real-network/cleanup-loop-allocation-history-v5/`.
The actual five-transfer allocating predecessor's named admission query remains
incomplete at 60 seconds (`cleanup-allocation-history-cut-v3/`); no larger retry
was made. Neither result establishes the full local-view relation, successor
invariant, actual callers or public network workflow. All 95 affected and
repository-boundary tests pass in Nix with zero skips, plus smoke/lint/freshness.
The first Nix attempt rejected a missing profile resource in the new test fixture;
the final run includes that explicit resource. No pilot rebuild or link ran.

Latest correction: the real predecessor establishes EBP=ESP+24 under the
explicit normal-return ABI and memory-frame premises described in the
real-predecessor checkpoint below. Earlier fixed snapshots using +28 are
conditional diagnostics, not real-entry evidence. The separate synthetic +28
engine regression retains its original meaning.

Latest source-workflow checkpoint: checked source dependencies now compose
acyclic memory contracts without their implementation bodies. The public Nix
source product consumes explicit dependency and prior-evidence packages. A
retained supplier growth rebinds current evidence while reusing both caller
queries; a supporting three-level regression reuses both consuming levels. An
incompatible consumed extent forces new queries and fails the call boundary.
The real Metapad core's unchanged local source theorem is also reused through
the public command, eliminating its 34.074s of solver work while retaining
compilation and evidence validation. The first 30-second timeout remains
incomplete; the accepted source run uses a 120-second process limit.

This is source-theorem composition and reuse, not the real-network exit. The
actual predecessor/caller, transitive machine frame, allocation lifetime and
service obligations remain below. No normalization core proof region has been
promoted into a synthetic production API. Evidence lives under
`build/independent-lifting/composition-network/`; the performance document records
separate phase costs. Targeted Nix validation passes 89 tests, followed by the
affected public-product and smoke gates after adding timing/timeout controls.

## Real operation and caller contexts

Select Metapad 3.6's routine beginning at RVA `0x55b7`. Its instructions scan a
NUL-terminated byte string and remove the first CR of CR-CR-LF triples into
scratch storage. It counts removals, conditionally copies the result into the
caller's text buffer, releases scratch storage, and takes conditional UI paths.
This description is an interpretation of the retained instructions; the ordinary
C implementation and its full contract still need qualification.

The current canonical machine IR independently confirms two direct call sites:

| Call site | Concrete context |
|---|---|
| `0x5c2f` | Loads the text pointer from caller `[EBP-0x14]`; subtracts the returned removal count from `[EBP-0xc]` at `0x5c3a`; later calls the existing newline normalizer at `0x5c49`. |
| `0xb19c` | Uses the buffer produced through a separate call to `0x5817` at `0xb131`; a preceding loop can replace NUL bytes with spaces; after conditional cleanup, passes the buffer to the message call beginning at `0xb1a1`. |

These are different consumers of the shared text and result. The direct
inventory is not a complete caller set: it retains 629 unresolved indirect-call
sites in the supplied machine IR. Neither reachability nor ownership is inferred.
The earlier `0x5731` newline slice has only one confirmed direct caller to its
enclosing function and is not the primary decomposition experiment.

## Exact inputs and retention

The retained binary is `build/metapad-trial/metapad.exe`, 194,560 bytes, SHA-256
`685989bad8d8119eddbb49e36006d8ac9155c45d69dee060807368241c8e58ce`.
It was inspected statically and was not executed.

At the start of this experiment the historical Nix machine-IR, transfer-plan,
and SDK store paths were absent. The trial's declared SDK pin still names
`/nix/store/mrgh4g1188scyhqzhz2cdn0bgm7vahii-source`; its absence is an explicit
reproduction blocker, not permission to call a different SDK the same version.
The external trial's files and declared pin are preserved.

Rebuilding **only canonical extraction** with the current engine restored the
same machine-IR identity as the earlier retained report:

- Root: `build/independent-lifting/preparation/machine-ir` (a Nix output root).
- File: `machine-ir.jsonl`.
- SHA-256: `d131672a2ba80f8163f8dfab0ad9945deafe309ec6d15c4829a10bb30a006ba8`.
- Store output: `/nix/store/d3985cln0b5q8zvv380a9143w5wsdxn4-spaghetti-extractor-metapad-machine-ir-v3`.

The extraction command, log and timing are retained in
`build/independent-lifting/preparation/`. `callers.json` retains exact canonical
call inputs, hashes, line locations and JSON pointers. `operation-transfers.json`
is a diagnostic projection through the existing machine-IR adapter, not a new
IR or evidence authority. It contains the 35 existing transfers in this routine.
The original extraction inputs and manifest stay in the rooted package.

Repeat caller navigation without evaluating a target:

```console
nix run --builders '' . -- expert semantic-diagnose --view callers \
  --machine-ir build/independent-lifting/preparation/machine-ir/machine-ir.jsonl \
  --entry-unit semantic-transfer:original-cutpoint-000055b7-000055be
```

The isolated experiment now uses SDK source
`/nix/store/s0xqi5fqjyx57lnbbnc0imyqc5hwpd42-source`, retained by
`build/independent-lifting/preparation/sdk`. Its copied trial is under
`build/independent-lifting/trial/`; only the extractor node changed in its lock.
All 12 original trial input files remain byte-identical. `sdk-result.json`
records this checkpoint and hashes. It is a frozen development input, not a
qualified SDK or a restoration of the unavailable historical source.

## Boundaries and proposed contract

The current hand-defined service preparation binds the actual `GlobalAlloc`
CALL at `0x55d1` and `GlobalFree` CALL at `0x5633` through the production service
and lifetime rules. It extends the unchanged image authority with the local
`cleanup.scratch` allocation class; native selectors and complete producer/caller
coverage are still separate obligations. Preparation scans the retained 35
transfers and takes 1.786s, with no compiler, solver or pilot work. Inputs and
checked site projections are under `real-network/cleanup-lifetime-inputs-v1/`.

The two actual machine regions paired with ordinary C service calls pass 6,920
assertion/safety properties, including nullable allocation results, current zeroed
bytes, full identity correspondence, both release outcomes and retained history.
This is a conditional regional check: the intervening cleanup loop is omitted,
and the release argument is explicitly transported from the allocated result.
The run assumes `length != UINT32_MAX`, so `length + 1` is nonzero. The preceding
string-length contract must establish this fact before the regions compose.
The unrestricted first run retains a counterexample at `length == UINT32_MAX`:
a nonnull zero-sized allocation cannot satisfy the proposed one-byte result
projection. Neither this follow-up nor nullable-result checks establish general
zero-sized allocation transport or the original cleanup's faulting accesses.
Evidence is under `real-network/cleanup-lifetime-pair-v1/` and `-v2/`; v2 takes
1.662s preparation, 0.002s generation, 0.270s compilation and 120.519s checking.

Remaining service boundaries must preserve their actual outcomes. In particular,
the selected `lstrlenA` entry is still ABI-only, `lstrcpyA` is unresolved, and
the UI entries select native callthrough. A declared NUL view does not establish
the first-NUL result or a UI memory frame. The eventual copy contract must also
represent failure without promising termination of the destination, and must
check nonoverlap and destination capacity. These requirements follow the
[documented lstrcpyA contract](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lstrcpya);
that documentation is a specification input, not proof evidence.

| Boundary | Current state | Proposed experiment |
|---|---|---|
| Proof regions | No installed proof intent for `0x55b7`. | Separate setup, the scan loop, and copy/release continuation using proof barriers inside ordinary C. |
| Component | The installed trial selects the separate newline-normalization component. | Start with the enclosing cleanup operation; do not expose setup/scan/finish as production functions merely to cut a proof. |
| Replacement group | No qualified replacement for the selected operation. | Preserve the concrete representation first. Group compatibility and representation changes are later checked experiments. |

The service-free scan core consists of the **existing** units in
`[0x55dd,0x5623)` and `[0x5675,0x56b5)`: 20 transfers with one outgoing
continuation at `0x5623`. The second interval is essential; address order is not
control-flow order. A candidate loop cut at `0x5606` intercepts the backedges
through `0x5601` and `0x5605`. This is a decomposition proposal, not a checked
split or coverage/progress receipt.

The initial concrete relation must include the incoming string length in EAX,
text pointer in EDI, index in ESI, scratch pointer in `[EBP-0xc]`, removal count
at `[EBP-8]`, and the guest frame bytes used at `[EBP-1]` and `[EBP-2]`. The
loop additionally transports the destination index in ECX and current byte in
AL. Exact live-in/out requirements must be derived by the existing binding and
proof-plan builders; this list is an investigation starting point.

The intended memory contract borrows the readable input string, its writable
caller-visible storage, and the scratch allocation. It preserves aliases,
permissions, bounds, live identities, generations and current bytes. The scan's
write frame contains only the written scratch prefix and declared frame locals;
the later copy-back changes the caller's text. Scratch zero initialization is
relevant to termination of the produced string. It must not replace current
contents when resuming across a cut.

Initial blockers (historical snapshot; current evidence is recorded above and in
[current-goal](../current-goal.md)):

1. The fixed readable-view local checker is implemented, but its results are
   not yet admitted connected summary certificates. Mutable-buffer summaries
   remain unimplemented. The pure scalar certificate establishes neither.
2. Allocation failure, `length + 1` overflow, string bounds and allocator-return
   ownership require explicit outcomes. The instructions do not visibly test
   the allocation result before its use; do not assume failure away globally.
3. Current allocation contents and frame ownership must survive the scan cut.
   Reconstructing pointers or resetting allocation records does not prove this.
4. Copy/release, caller count updates and intervening UI interactions need
   checked service and lifecycle composition, including unsupported callbacks.
5. Split/merge coverage and progress, stable consumer contract identity, and
   exact supplier qualification are not yet an implemented edit/reuse workflow.
6. The old trial SDK bytes are unavailable. Historical trial reproduction is
   blocked; the isolated checkpoint below has its own explicit SDK identity.

## Initial support matrix after live inspection

“Conditional” means a composition mechanism was exercised under its premises;
it does not mean a supplier has proved those premises.

| Capability | Represented | Locally checked | Composed without body execution | Real consumer qualified |
|---|---|---|---|---|
| Pure scalar result, empty frame | Yes | Existing source certificates | Yes | Limited existing scalar scope; pilots still need final-policy gates |
| Readable views and aliases | Yes | Input correspondence and runtime realization | Conditional experiment added | No |
| Read-only source frame and readable-input dependence | Shape recognition only | No memory source certificate | No qualified supplier selection | No |
| Mutable byte buffers | Yes | Existing allocation/write/read/release fixture | No | No for this operation |
| Allocation current contents across cuts | Partial infrastructure | Incomplete | No | No |
| Shared object invariants, service outcomes, representation groups | Existing interfaces/relations | Scope-dependent; required rules incomplete | No general rule | No for this experiment |
| Split/merge and contract edit reuse | Existing barriers/work packages | Automatic proposals and compatibility unfinished | Not demonstrated | No |

## Measured baseline

Canonical extraction took **82.280 seconds**, one sample, including Nix
preparation and realization. No provider, pilot or native link was built. The
public caller diagnostic took **4.168 seconds** using the retained machine IR
and the provisioned Python command dispatcher. This is preparation/navigation,
not a proof timing.

Recompiling the retained canonical transfer plan took **13.359 seconds** and
strict replay took **2.349 seconds**. It restored the historical plan file hash
`1d1eb428e0fd4a37fc41090ca8904cf83597ce561d3de2be773cf5618c798781`.
The full plan remains incomplete; the selected 20-transfer core is lowerable
and has no calls. Emitting its exact C took **0.018 seconds**, and compiling its
host objects took **0.102 seconds**. The empty diagnostic proof intent used for
this measurement is not a checked cut/coverage plan. Real-core solver and link
costs are explicitly **not run**, pending the interface, lifetime and cut
relations. Commands and results are in `preparation/exact-core-result.json`.

The new conditional read-only fixture uses the existing paired proof world,
reference transport and range observer. It exercises overlapping views into
private caller memory and different caller contexts. Three fresh compilations
on an AMD Ryzen 7 9700X, Linux 7.1.10, CBMC 6.9.0/CaDiCaL, ran sequentially
alongside the previously started repository validation:

| Phase | Median seconds | Maximum of three |
|---|---:|---:|
| C proof-model generation | 0.000597 | 0.000746 |
| GOTO source compilation | 0.069725 | 0.070881 |
| Solver | 0.257921 | 0.269141 |
| Native linking | Not run | No qualified supplier yet |

Each parent model contains 2,110 GOTO instructions and no hidden callee body.
These are small composition-fixture measurements, not timing or qualification
claims for the Metapad operation. A constant parent across repeated compilations
is not yet the required experiment with locally qualified growing children.
Preparation, child qualification and native linking remain separately visible.

The solver rejects different readable bytes with identical reference metadata,
changed descriptor-pointer aliases, a missing nonnullable view and an unproved
result fact. Descriptor-pointer aliasing and overlap between their underlying
ranges are checked separately. The experimental renderer has no provider
selector path. The Python strategy validator rejects it explicitly; both full
readers accept the retained positive allocation fixture and reject an attempted
experimental dependency added to it. All 29 focused composition/summary tests
pass in 9.467 seconds with zero skips.

Evidence and generated C/GOTO models are under
`build/independent-lifting/readonly-composition/`. The tracked reproduction
helper is in `tests/unit/components/test_bisimulation_readonly_summary.py`.
No additional proof cache, state database or authorizing artifact format was
introduced.

## Source-frame feasibility and validation

A retained local experiment uses CBMC's dynamic frame checking with the existing
view accessors. Under an explicit `count <= 4` domain and prepared fresh
descriptor storage, the comparison's empty frame passes in 0.674 seconds of
solver time. The checker rejects writes to caller state, writes that restore the
old value, and reads outside the declared domain. This is a feasibility probe:
it does not establish readable-input dependence, the complete alias/transport
domain, or a supplier certificate. Its initialized transport fields must not be
mistaken for universal admissible caller state.

The probe also exposed CBMC's default empty-self-loop simplification. The
bounded source-contract check needs `--no-self-loops-to-assumptions` alongside
unwinding assertions to reject `while (1) {}`. The normal integrated contextual
builder already rejects the same mutation as an unannotated source cycle and
emits no receipt. Its authority policy was not changed by this experiment.
Evidence and remaining certificate requirements are under
`build/independent-lifting/readonly-local-contract/` and `progress-audit/`.

Affected repository validation passes in **1,357.45 seconds** with unchanged
recorded inputs. All 41 newly realized shards pass **365 tests, zero skips**;
cached selected shards are additional and are not recounted in that number.
The previous combined run's sole failure was the missing repository-map entry
for the new plan; that entry is corrected. No full pilot or native activation
claim follows from this generic validation.

## Acceptance sequence

### Source-bound readable-view checkpoint

The checker in `components/bisimulation_readonly_contracts.py` now consumes the
existing content-bound source package and fixed view extents. It retains typed
authored GOTO inventories, rejects private transport inspection and nonlocal
storage reads, and checks the source's empty write frame and readable-input
dependence. It uses arbitrary scalar values, related arbitrary logical reference
metadata, independent private contexts, consistent descriptor aliases and a
shared byte map that admits overlapping ranges. Loop bounds are solver limits;
no scalar precondition is inferred from them. Canonical view helpers retain
out-of-range read outcomes.

Fifty-one focused tests pass in 16.892 seconds, with zero skips. Negative cases
cover hidden or restored writes,
private-state and nondeterministic results, pointer/transport inspection,
nontermination, recursion, source assumptions, changed readable bytes, false
descriptor-disjointness claims, and inconsistent caller width/fixed extent.
Compiler dependency inventories reject included headers outside the bound source
package and generated headers before compilation; ambient standard includes are
disabled for this local model.

Retained local checks of three comparison sources have these separated costs:

| Source GOTO instructions, including compiler entry support | Preparation (s) | Compiler (s) | Model work (s) | Solver (s) |
|---:|---:|---:|---:|---:|
| 185 | 0.001404 | 0.138084 | 0.219303 | 0.970491 |
| 215 | 0.000991 | 0.144081 | 0.224539 | 1.327704 |
| 279 | 0.000879 | 0.147775 | 0.227425 | 2.739750 |

All three local checks pass. The larger sources repeat checked reads before the
same comparison; their authored function bodies contain 50, 80 and 144
instructions respectively. Measurements are outside deterministic certificates
and were collected while the focused tests also ran. Exact
inputs and full generated models are retained under
`build/independent-lifting/readonly-source-domain/final/`; recorded inputs stayed
unchanged during the run. A separate fixed-extent conditional parent also
passes with 2,112 GOTO instructions and no callee body. These local children use four-byte extents and that
parent fixture uses two-byte extents, so their successes are explicitly **not**
composed or reported as qualified neighboring-proof reuse. No link was run.

The next qualification work must validate certificates through both readers,
establish the same entry transport domain in the parent and local checker,
and supply exact/source child proofs before enabling provider selection.
Mutable memory, checked cuts and actual neighboring-proof reuse remain open.

The checker is now reachable through the existing public source-check workflow:

```console
spaghetti-extractor component check TARGET UNIT --source --local-contracts --local
```

The separate `sourceContractCheck` product adds the solver only when requested.
Its normal host and PE32 compilation, C profile, and local proofs pass for the
bounded comparison fixture. Public `--source --local-contracts` accepts that
Nix-built fixture product; default `component check` still rejects its absent
provider qualification. The public fixture only exposes a retained product and
does not register or qualify a real target. A restored view write appears as a
local-contract blocker. Eight operator tests pass in 2.308 seconds.

The first Nix realization exposed stale GOTO hashes caused by output-path
rewriting. The repaired phase stages its compiler workspace outside `$out` and
retains relative source paths. All six C/GOTO model hash comparisons now match
after realization, and a Nix repeat build of the resolved derivation passes.
The failed artifact remains rooted separately; the binding audit and both
realizations are under `readonly-source-domain/nix-source-check/`.

A separate synthetic byte-reading fixture passes the normal exact/source
checker, including its actual cut and reference transport, in 44.289 seconds.
The same source and interface pass the local checker. This is an acyclic
byte-read experiment, not qualification of the Metapad loop or a linked target.
Its evidence is under `readonly-source-domain/exact-byte/`. Both full readers
continue to reject attaching the experimental local certificate as a connected
summary, including an attempt to label it as the old scalar strategy.

The initial affected run for this batch was cancelled after 304.53 seconds
because generated metadata was incorrectly included in its change selectors,
expanding it to the full suite. The corrected-scope run finished after 1,170.72
seconds with one architecture failure: the new modules then had no production
consumer. That failure prompted the operator integration above. It ran against
an earlier snapshot while the repair advanced; it is not a current passing
repository result. The final operator/staging run subsequently passed in
1,298.80 seconds with unchanged recorded inputs. Its 82 newly realized shards
contain 658 tests and zero skips; cached selected shards are additional. The
61 focused checks passed in 20.869 seconds. These results precede the later
transport and retained-certificate changes below.

The following batch replaces the conditional fixture's null accessors with
actual canonical transports. The fixed two-byte views can overlap and retain
separate descriptor aliases. The parent checks the actual callback identities,
shared context, runtime/world, issued reference generation, permissions and
physical span. Trusted inspectors also work across separate C translation units.
Null/substituted accessors, an unrelated context, bad address/extent/permissions,
stale generation and substituted runtime readers/realizers reject without
executing an untrusted callback. Automatic trusted-inspector assembly for a real
qualified consumer remains unfinished.

Successful local source checks now revalidate their retained evidence. The
validator reconstructs model C from the exact bound interface and compares
source/profile/include closure, generated/support headers, typed opacity,
complete commands and compiler inventories, tools, solver outputs and GOTO
bytes. Rehashed missing premises, altered retained bytes, weakened model C and
failing solver output reject. Relocated unchanged artifacts pass without a new
solver run. Deployment readers still reject the experimental summary strategy.

A small content-addressed Nix audit also reproduced the older scalar summary
path's output-rewrite problem. Its provider phase now stages summary compilation
outside the output path. All three retained scalar GOTO hashes (frame,
context-independence, and postcondition) match after realization; the resolved
repeat build passes. The before, prototype and production audits are retained
under `scalar-binding-audit/`, `scalar-binding-fixed/` and
`scalar-binding-production/` within `readonly-source-domain/`. The production
output is `/nix/store/h96lmbf220q2f625wnjfx2ysqxh5rhzd-independent-lifting-scalar-binding-production`.
This is a small summary-phase audit, not a rebuilt pilot or activation receipt.

The same-domain growth experiment uses a two-byte fixed local contract and a
conditional parent with canonical transport checks. Adding 64 authored scalar
statements increases the child inventory from 185 to 249 instructions. Parent C
is byte-identical and both parent inventories contain 2,312 instructions, with
no child implementation. Local end-to-end checks take 0.928 and 0.939 seconds
in this one warm sample; separate phase timings are retained. This is not an
exact/source supplier qualification, a real caller, or neighboring-proof reuse.
Evidence is under `readonly-source-domain/transport-batch/`.

### Auxiliary qualification evidence and callee entry domain

The readable local checker now supports certificate-only validation for receipt
readers and retained-byte validation for supplier binding. The latter remains
mandatory at connected supplier loading. A satisfied local result can accompany
an ordinary exact/source qualification; connected calls still use replay.

The retained exact-byte proof was accepted by both full readers before and after
attaching a fresh local certificate for its same source and four-byte interface.
Both readers rejected rehashed stale source, profile, proof-interface and failed
solver cases. This probe took 1.370 seconds, including the local proof, without
rebuilding the exact/source pilot. Exact inputs and results are retained at
`readonly-source-domain/transport-batch/qualified-reader-probe/`. This demonstrates
reader integration on a synthetic byte-reader theorem, not a qualified connected
caller or activation. The experiment is now represented directly in
`test_bisimulation_normal_exits.py` and exercised by the readable receipt tests;
future runs need no dynamic test-source rewriting.
The versioned integration test passes its fresh exact/source and local proofs,
and both full readers pass its positive and four binding/solver rejection cases.
The three readable receipt tests pass in 44.462 seconds with no skips; their
smaller structural test also rejects sixteen weakened certificate variants.
The accompanying 86 focused tests pass in 52.497 seconds with zero skips,
covering source certificates, transport, view admission, scalar summaries and
proof code generation. The batch's affected-validation command, exact inputs,
terminal status and logs are retained separately under
`readonly-source-domain/certificate-batch/`.
That frozen affected run terminates with one repository module-size failure in
1,413.878 seconds: 52 newly realized shards contain 487 tests and zero skips;
51 shards pass, including the solver regressions. All recorded inputs and all
12 original trial inputs remain unchanged during the run. The certificate
selection and staging logic is subsequently moved into the existing contract
modules, bringing both orchestration modules below the 1,600-line limit.
The repaired tree passes all 33 repository-boundary tests in 6.502 seconds and
26 focused contract/reader tests in 55.938 seconds, with zero skips. These also
cover the jq auxiliary-policy dispatch repair: unknown policies, extra fields,
missing certificates and null certificates are rejected. The narrow Nix
follow-up is recorded separately in `certificate-batch/followup/`; the original
failed batch is retained as failed evidence.

The entry-domain audit found a concrete missing implication: with an image
ending at `0x410000`, caller ESP `0x410400` admits its private stack window,
while callee ESP `0x4103fc` after a four-byte adjustment does not. CBMC rejects
the claim that the latter is admitted. A companion symbolic check proves the
factored predicate preserves the previous stack-domain meaning and is shared
with view admission. The test takes 0.104 seconds for its three solver queries.
This does not establish a whole-pipeline exploit; it establishes that caller
domain admission alone cannot discharge the callee premise. Full reference
extent, private/public frame transport and exact/source entry assumptions must
be checked before body-free readable strategy admission.

This batch passes 70 focused checks in 33.039 seconds with zero skips. The real
Nix source-contract product passes retained-artifact validation after realization
and a repeat build. Its affected validation passes in 1,363.86 seconds with
unchanged recorded inputs: 662 tests, zero skips across 82 newly realized shards,
plus cached selected shards. This result precedes a narrow follow-up that admits
read borrowing from an object with read/write backing permissions. The prepared
regression first failed under the exact-permission check (0.232 seconds) and
passed with the read-bit requirement (0.507 seconds). Missing read permission
remains a checked rejection; the live reference and transport rules remain in
force. That correction passes all 12 focused tests in 13.554 seconds and the
selected regression dependents plus metadata/smoke gates in 96.025 seconds
with unchanged recorded inputs (74 tests, zero skips across 7 newly
realized shards). This is a targeted follow-up, separate from the broader frozen
affected-source run.

First qualify bounded readable-memory source contracts, including the empty
write frame, dependence on all readable bytes, C definedness, and progress.
Exercise mismatched bytes, hidden writes, wrong results and false preconditions
through both readers. Qualify changed child implementations with the same
contract and measure parent body absence and invariant model size.

Then admit the scan's mutable buffer frame and post-memory relation. Establish
allocation/current-memory transport before splitting it. Edit one implementation
and record exactly which neighboring proofs were reused; refine one contract
fact and identify its actual consumers. Merge cuts for a valid rewrite that
cannot preserve the earlier intermediate relation. Preserve all exits and
progress throughout.

Extend through the two real caller contexts, then shared jq objects and the
required jq/DX-Ball interactions. Repeat on an unrelated target and close the
retained pilot, native-link, repository-validation, export and alternate-backend
milestones. More components alone do not satisfy any of these exits.


The next fixture adds an actual machine return and a supplementary original
physical-memory frame query to the existing paired GOTO. A byte-reading callee
satisfies both segment frames. A variant that writes one private stack byte
still satisfies ordinary exact/source equivalence but fails the segment frame;
it cannot supply an operation-wide empty frame. Both full readers retain this
distinction. Supplier loading requires exact retained positive GOTO/transcript
bindings for every segment and rejects fabricated success metadata against the
actual failed transcript. Four focused tests pass in 93.541 seconds, with zero
skips; all 33 repository-boundary tests pass in 6.319 seconds.

A small Nix realization of this real-return fixture passes retained frame-byte
validation after copying its staged artifacts into the output. The first audit
attempt fails because the fixture supplies a relative source path to cut
compilation; resolving the fixture root repairs that audit without changing the
engine. Both logs remain under `build/independent-lifting/exact-frame/`.
The realized output is
`/nix/store/3admkk23dhqffqa9c5bpr8z97cbfy1ip-independent-lifting-exact-frame-binding`.
Across its two obligations, compilation takes 0.268 seconds; the supplementary
frame solver queries take 0.740 seconds with no additional compilation. These
are summed query costs, not end-to-end wall time. Repeat-build determinism is
not tested by this audit. The frame fact establishes no callee entry, allocation
history, lifetime, qualified connected caller, or activation; readable calls
still use replay. The real Metapad loop and all later workflow exits remain open.


The subsequent entry-domain experiment proves all paired, safety, unwind and
physical-frame properties over a wider stack domain. It preserves the ordinary
entry; a separate query enables the stronger theorem in the same compiled GOTO.
A symbolic regression proves ordinary-domain inclusion, unchanged private
partitioning for its witnesses, and stack-domain admission after a four-byte
CALL when the private-high bounds match. This is not a complete reference or
lifetime composition rule.

The new CALL/RET fixture uses a separately checked reader and shared transfer
construction with explicit evaluation actions. Its positive conditional replay
proof passes. A reader variant returns one more than the input byte only at ESP
`image_end + 1020`; ordinary qualification and its empty frame pass because the
old domain excludes that ESP. The wider paired theorem rejects the result
mismatch. Concrete transfer diagnostics produce 17 and 18 at that same input.
Existing conditional replay still passes the caller of this variant, identifying
a missing actual-entry premise check. This counterexample uses synthetic engine
inputs; no end-to-end supplier qualification or native activation is claimed.

The integrated wider-domain checker and both readers pass their positive and
negative cases. The first combined local run records 11 tests in 259.117 seconds
with one failed fixture assertion: it incorrectly treated the engine's internal
activation flag as a standalone native decision. The fixture now writes an
explicitly non-authorizing observation; it creates neither a supplier
qualification nor a native receipt. The corrected selected Nix run passes in
272.030 seconds with unchanged recorded inputs and all 12 original trial inputs:
55 tests and zero skips across five newly realized shards, plus metadata/smoke
gates. All 33 local repository-boundary tests also pass in 6.985 seconds.

A small Nix realization passes retained-byte validation for every original
physical-frame and wider-entry certificate. Its output is
`/nix/store/fisc8yai7k4icxbks19xlgvs516cmv9h-independent-lifting-readable-entry-binding`.
The two obligations use 0.268 seconds of compilation; their added wider-domain
queries use 9.096 seconds without further compilation. These are summed query
costs, not wall time. Repeat-build determinism is not established. Commands,
exact inputs, failed and passing logs, solver probes and artifact audits are
retained under `build/independent-lifting/readable-entry-domain/`.

Caller-side enforcement remains the immediate frontier, including existing
replay. Readable body-free strategy admission, actual body absence and growth
independence, mutable buffers and the real Metapad loop remain unfinished. The
full decomposition/editing/reuse, shared-object, interaction, representation,
unrelated-target and retained pilot/native/repository/export/portability exits
remain required.


### Actual caller stack-entry checks

The caller now consumes `checked-readable-callee-stack-entry-v1`, derived from
the separately checked leaf proof system and binding intent. The wider domain
requires every covered segment's retained positive theorem. The actual original
CALL asserts the applicable stack and image-base premise after pushing its return
address; the component/operation guard is mandatory in both receipt readers.
The positive reader caller passes. The previously accepted domain-trap caller
now fails at `spx-bisimulation-connected-callee-stack-entry:counter:run`.
Rehashed domain, supplier/binding, missing-contract and missing-guard mutations
are rejected. These are conditional engine fixtures, with synthetic qualification
identity and no provider or native activation receipt.

The retained probes reused their separately checked child inputs. The positive
caller compiled in 0.186s, inventoried properties/loops in 0.755s, and used 70.886s
of summed solver-query time over a 38.513s observed obligation wall interval.
The negative caller compiled in 0.180s, inventoried in 0.740s, and used 45.490s
of summed solver-query time over 25.433s of observed obligation wall time.
Queries run concurrently, so their sum is not wall time. No pilot preparation
or native link was rerun; these costs are unmeasured here, not zero-cost claims.
Exact inputs and query timing records remain under
`build/independent-lifting/call-entry/`.

The initial selected Nix integration run passes in **344.523s**, with unchanged
recorded inputs and all 12 original trial files: **134 tests, zero skips in 10
newly realized shards**, plus selected cached checks and metadata/smoke gates.
The selection covers connected/refinement/code-generation, physical frames,
readable entry, shared-view admission, and repository boundaries. A separate
local boundary run passes all 33 tests in 6.371s.

A subsequent input-validation tightening requires actual dispatch to match the
supplier operation model's exact entry and overlay symbol. Its two focused
regressions pass, and its emitted guards match both retained compiled caller
models byte for byte. Final dispatch-only Nix/metadata validation passes in
**83.664s**, with unchanged recorded inputs and all 12
original trial files: **35 tests, zero skips across 2 newly realized shards**,
plus selected cached checks and metadata/smoke gates.
This remains selected regression evidence, not full affected-source, pilot,
export or portability validation. Complete reference/ambient-state premises,
readable body absence, mutable composition and real neighboring-proof reuse
remain open.


### Real caller transport and machine frames at cuts

Connected readable replay now compiles canonical inspectors alongside each
unchanged raw supplier overlay, records included C separately from compiled
translation units, and requires the named transport guards in both readers.
The positive real caller passes. Substituting another memory reader while
retaining the same world context fails at
`spx-bisimulation-connected-summary-readable-runtime`. Removing its policy,
guards or raw overlay input is rejected by both receipt readers.

The wider-entry model now has fixed compiled machine-state guards for return
and proof cuts. A final ECX clobber preserves ordinary equivalence and the
physical frame but fails the stronger exit guard. Crucially, the initial
exit-only implementation incorrectly accepted an ECX change **before** a cut:
the resumed proof started both sides from a fresh shared state. The retained
`before-cut-old` experiment demonstrates that failure. The corrected cut hook
runs before the proof marker stops execution, conservatively requiring original
architectural state preservation at the cut. `before-cut-fixed` rejects segment
0 at `spx-bisimulation-readable-cut-machine-state`, even though its final segment
passes. The current consumer cannot derive the whole-operation machine frame
from the older evidence. These remain auxiliary, conditional engine facts,
with no supplier/native activation receipt and no new production APIs.

The initial transport/exit-only Nix selection passed **185 tests, zero skips
in 17 newly realized shards, 453.533s**, with recorded/trial inputs
unchanged. That test selection did not establish the cut frame and was followed
by the new counterexample and correction. Final selected Nix validation passes
**138 tests, zero skips in 10 newly realized shards, 455.245s**, plus
selected cached checks and metadata/smoke gates, again with unchanged recorded
inputs and all 12 original trial files. Local final boundary/code-generation
checks pass **48 tests in 6.500s**.

A fresh retained Nix reader at `/nix/store/4jyy9nkzm5ri9bn4l3ddpy6w3s9dpx2q-independent-lifting-readable-transport-frame-binding` passes both full receipt
readers and actual retained-model/solver-byte validation for all three facts:
empty physical frame, wider entry, and the conservative machine frame across
cuts and exits. Repeat-build determinism was not tested. Diagnostics, exact
input hashes and the checkpoint remain under
`build/independent-lifting/caller-transport/`.

Readable calls still execute supplier bodies in real caller proofs. Actual
input-world compatibility, body absence/growth independence, mutable-memory
composition, checked split/merge and real neighboring-proof reuse remain open,
as do the real Metapad workflow and every retained pilot/native/repository/export/
portability exit. No pilot rebuild was needed for this batch.


## Checked image-readable body omission and callee growth

The next checkpoint admits `image-readable-body-free-v1` for fixed image origins,
compatible image authority/layout, no allocation history, and no finite-control
initial-byte overrides. It consumes the checked source contract and the paired
physical, wider-entry and cut/exit machine-state facts. Actual CALL guards prove
stack and full native origin admission; canonical transport and empty-allocation
guards apply to both worlds. The shared frame predicate checks the fixed
compiled assertion identity, source function and description in every segment.
Other worlds remain on replay.

The retained small supplier is the previous Nix reader above. The parent GOTO
has neither `spx_sub_00001000` nor an authored `spx_proof_connected_impl_*` body;
`authored_run` is the generated summary wrapper. Its retained GOTO hash matches
the proof receipt. Growing the separately qualified authored callee with 32
pairs of cancelling byte operations changes its GOTO from **197 to 261
instructions**. The parent retains exactly the same C proof inputs and model
hash, **149 body-bearing functions and 4,869 instructions**. Current supplier
receipt identity changes. Both full readers accept the ordinary and grown
conditional proofs.

The grown supplier qualifies in **59.198s**; checking the same parent with it
takes **56.360s**. Parent compilation takes **0.158s**, with inventory and solver
costs retained separately in `phase-costs.json`. Query time sums are not wall
time because solver queries run concurrently. Preparation reuses the retained
leaf and small exact fixtures; no pilot preparation or native link was run.
The original and grown parent GOTO hashes differ with temporary compiler paths.
A separate compile-only probe stages both parent inputs at the same physical
path and produces byte-identical GOTO files (0.192s and 0.181s). It runs no solver.
No neighboring solver result was reused: deterministic compile staging and a
complete compile-input/evidence boundary remain necessary before claiming that.

An invalid actual callee view fails at
`spx-bisimulation-connected-readable-entry:counter:run`. A source caller that
changes the readable byte fails the exit world-memory comparison. Both readers
accept these honest negative receipts and reject rehashed missing/changed
contracts and guards. Unsupported finite-control or allocation inputs, mismatched image layouts, and
missing machine-frame premises prevent body-free admission. The retained evidence and costs are under
`build/independent-lifting/image-readable-composition/`.

Local repository boundaries pass **33 tests in 6.820s**. Selected Nix validation
passes **203 tests, zero skips across 18 newly realized shards in 618.453s**,
plus selected cached checks and metadata/smoke gates. Recorded inputs and all
12 original trial files remain unchanged. This includes the actual GOTO growth
regression. No full affected-source or pilot/native/export/portability exit is
claimed. Mutable buffers, practical cut proposals, actual
neighboring proof reuse, the real two-caller Metapad workflow and the remaining
shared-object/interaction priorities are still implementation work.


## Explicit reuse of checked parent queries

The stable-workspace experiment now reuses actual neighboring solver evidence.
The first caller proof takes **58.526s**. After selecting the separately checked
grown reader, the caller takes **1.292s**, with **97 reused CBMC queries and zero
fresh queries**. This includes inventory, property/safety and nonvacuity queries;
version identification still runs. The experiment guards the process runner and
fails if a new CBMC query is attempted. Current supplier checks, C generation,
compilation, metadata validation and current output parsing remain active. Both
full proof readers pass. Parent GOTO SHA-256 is identical before and after:
`ff3a137393a62802cf9cc19fa20b7bc2a1865746a7e46d9aca5623a97529c150`.

The prior proof receipt is
`3b906f89d5cc31977a384fd2fe03f9ea056ecabd02783523b59b60203182dc7e`.
Its complete local proof is validated, and only outputs bound by the matching
obligation can be reused. The query key binds actual compiled bytes, tool paths
and hashes, complete arguments and working directory. Corrupt, missing or
symlinked bytes and altered bindings fail closed. A header-only predicate edit
leaves the C source identical but changes GOTO bytes, misses the cache and yields
a fresh counterexample. The current parser also rejects malformed retained
output even when its byte hashes agree.

The existing Nix provider gains explicit `previousQueryEvidence` as a declared
input and a fresh fixed proof workspace outside `$out`. This is not automatic
previous-evidence selection or a separately cached Nix solver phase. No pilot or
native link is established by the conditional fixture. Retained proofs, query
bytes, guarded-run logs and counters are under
`build/independent-lifting/query-reuse/`. Local backend, reuse and repository
boundary checks pass **44 tests in 6.951s**. Selected Nix validation passes
**145 tests, zero skips across 12 newly realized shards in 565.399s**, plus
selected cached and metadata/smoke checks. Recorded inputs and all 12 trial
files are unchanged.
Mutable contracts, checked cut proposals/refinement, actual Metapad lifting and
all retained shared-object/interaction and target validation exits remain open.


A final strictness check compares canonical query bindings so JSON `false` cannot
be replaced by numeric `0`. Its five local tests pass in 0.417s; the scoped Nix
check passes in 67.681s with unchanged recorded and trial inputs. The final guarded
caller again reuses all 97 queries with zero fresh queries in **1.090s**, passes
both full readers, and produces exactly the same conditional shard evidence as
the original caller. Current supplier receipt identity still changes. See
`canonical-reuse.json` and `canonical-gate/` for the final retained checkpoint.


## Mutable source-local checkpoint

The shared source checker now admits fixed readable and read/write views under
an explicitly separate local policy. It checks paired current input bytes,
compatible descriptor aliases and arbitrary physical overlaps, write-frame
protection for context/descriptor/transport storage, scalar outcomes, every
final byte and bounded progress. Read-only aliases observe writes through the
shared physical map. The existing readable/scalar supplier paths continue to
reject this new local policy; it does not authorize mutable body omission.

The retained candidate in `build/independent-lifting/mutable-source/metapad/`
is ordinary C derived from the 20-transfer normalization core. Its proposal
binds the retained transfer inventory, disassembly and exact slice. The loop
skips the first CR in CRCRLF and preserves the unwritten scratch tail; no
allocation-time NUL is reconstructed. Checked-access failure and unsupported
signed-length cases are explicit source outcomes whose original correspondence
remains unproved. The candidate has no machine binding, cut proof, caller
qualification, copyback/free/UI composition or native selection.

The initial local source run passes at unwind 10 in **38.010s**, including
0.002s preparation, 0.133s compilation, 0.318s model/evidence work and 37.519s
solver time. The first Nix attempt at default unwind 16 reaches CBMC's 256-object
limit in the paired model. Twelve object bits time out in both checks; nine
bits discharge the frame but the paired check still times out at 30s. All
attempts and non-authorizing diagnostics are retained. Separate fixed harness
storage avoids modeling irrelevant malloc behavior while preserving the frame.
The resulting retained check at explicit unwind 10 passes in **34.130s**; the
exact phase timings are in `metapad/timings-fixed-storage10.json`. Linking is
not performed and has no measured duration. The local Nix phase now accepts an
explicit unwind option without disabling any unwinding assertion. This does
not establish scalable loop composition or an automatic resource-budget UI.

The failure suite checks divergent post-memory with equal scalar results,
missing input-byte correspondence, stale overlapping bytes, restored protected
writes, wrong callback contexts, out-of-range/read-only access outcomes,
unrestricted scalar inputs, descriptor aliases, and nonprogress. Readable
certificate validation against retained model bytes continues to pass.
Full affected-source, pilot/native, export and portability validation remain
required. Final selected and public-product results follow after completion.

The final Nix source product is
`/nix/store/wq3jk0h9jwr9kyjs0cgww05825bcg9pm-independent-lifting-mutable-local-normalization-core-component-source-contract-check`.
Host and PE32 source compilation and all three local obligations pass. Its
retained bytes validate after realization, and its source-local receipt is
`49f43abccdd83421d4b2c9025f1af7d7ec722ed262ac386cf06575ee6c1755e6`.
The public `component check fixture normalization-core --source --local-contracts`
experiment returns success with zero authority held; ordinary qualification
returns exit 2 for the absent provider product. Both existing readable-policy
readers reject the mutable local certificate. Public command logs and separate
byte/policy audits are retained under `mutable-source/`. This is a source-local
candidate over retained real instructions, not a qualified Metapad component.

Final selected Nix validation passes **170 tests, zero skips in 15 newly realized
shards (174.434s)**, plus selected cached and metadata/smoke checks. The recorded
validation inputs and all 12 original trial files remain unchanged. A repeat
Nix build reuses the exact final source-product output without another build.
The preliminary local batch had one missing test import; the corrected timeout
and resource diagnostics tests pass, and the complete class is included in the
passing Nix selection. `mutable-source/gate/` retains commands, exact input
hashes, terminal results and shard logs. Only this baseline and current-goal
status text were updated after that gate. The full user goal remains active:
mutable original/source composition, checked state transport and split/merge,
shared-object/interaction work, unrelated-target reuse and all retained full
validation/activation exits are still required.


## Original mutable-frame checkpoint

The mutable local certificate now attaches to an actual original/source engine
proof through both readers. The provider's existing optional memory-contract
path selects the supported checker and retains exact bytes. Supplier loading
checks those bytes and bindings while keeping connected replay. The first
synthetic byte-store fixture passes in **45.126s** before the new frame probe.

A separate `exact_mutable_memory_frame` certificate then checks original writes
against the **current segment's** fixed writable-view union. It does not enlarge
a grant to the reference origin or ignore private stores. The positive pair
passes in **49.784s**. A restored write at `buffer + 4` (outside its four-byte
view but within the image world) passes ordinary equivalence and fails the
mutable frame; this probe takes **52.243s**. A private-stack store likewise
passes ordinary equivalence and fails the frame. The dedicated class checks
all three cases, both readers, stale/weak evidence, and retained source/GOTO/
solver bytes: **4 tests pass in 152.942s**. A follow-up also checks bytewise
adjacent grants, gaps, and address overflow. Focused source/evidence/reuse and
repository-boundary checks pass **51 tests in 15.902s**.

The first diagnostic copier omitted the new GOTO filename. Retained-byte
validation rejected that missing artifact; the copier now preserves it. The
fresh Nix fixture is rooted at
`/nix/store/vfqijg5rkpypk6cpvlr6ac95gi7lhwfa-independent-lifting-mutable-segment-frame-binding`.
Its proof receipt is
`71fd8cbe85c04c8a08319cc9ef622bf75bd4a29b78903002b1f2991d986e487c`.
Both full readers and retained source/frame bytes validate after realization.
The fixture's constructed transfers and placeholder input identities do not
qualify an actual provider or native artifact. Metapad remains source-local.

Evidence is under `build/independent-lifting/mutable-composition/`. Mutable
callee-entry, stable footprint/cut and post-memory composition remain required;
per-segment frames cannot be silently promoted to an operation theorem. No
mutable body omission, full pilot/native gate, export, portability, or unrelated
target workflow exit is claimed.

The selected Nix batch finished in **1,412.000s**. **287 tests passed across 32
newly realized shards, zero skips**; the remaining four-test normal-exit shard
failed because common-continuation comparison retained references to removed
Python variables after a helper refactor. The correction uses the actual exact
output and source state. Its existing full-engine Nix tests now all pass:
**4 tests in 13.381s**, including observed-state differences and exhausted
continuation bounds. The initial failed batch is retained as failed; these
results describe two source snapshots, not one all-green batch.

The focused correction plus a fresh retained mutable fixture took **54.721s**.
The latest fixture is
`/nix/store/cwg9acylc4k2hnzy9r9i31mm1173i4v8-independent-lifting-mutable-segment-frame-binding`,
with receipt
`9bb67f8d229ac759b44eb26da8f75705a0f3c17adb681d1c391305c22b8f7f3a`.
Both full readers and retained source/frame/GOTO bytes validate after realization.
`mutable-composition/gate/` and `gate-fix/` retain their separate input hashes,
commands, terminal results and logs. Each run kept its recorded inputs and all
12 original trial files unchanged. Only checkpoint status documentation changed
after the focused follow-up.

Regression costs differ substantially from the roughly fifty-second leaf proof:
the existing service-result-view shard took **1,052.526s**, readable entry
**519.927s**, the five mutable-frame tests **166.301s**, and empty-frame tests
**134.843s**. These are single samples with two Nix workloads allowed; the
individual shard times overlap and must not be summed as wall-clock latency.
No full pilot rebuild was used for this checkpoint. The final affected-source,
pilot/native and later workflow gates remain required.

The final Nix smoke selection passes, including repository metadata freshness,
production Python lint and retired-architecture boundaries. `git diff --check`
also passes. This smoke result does not replace the remaining full gates.

## Mutable footprints across cuts

The new `exact_mutable_cut_frame` query checks that each outgoing cut preserves
its segment's fixed writable-view addresses and requested/visible extents. It
projects pointers from **current** original memory. The existing write-frame
query remains separate. After ordinary supplier validation, the loader exports
physical operation confinement only when every segment's write and cut facts
pass and their retained bytes validate. This is a confinement theorem, not a
mutable body-free summary or heap-lifetime theorem.

A retained two-view operation supplies the specific counterexample: one writable
view holds a pointer word; another is its pointee. Their physical ranges may
overlap. A stable word store preserves the pointer, then the operation reads and
writes the pointee after a cut. A moved word store updates the actual pointer
and corresponding concrete source descriptor. Neither first transfer changes
architectural registers. Both operations pass ordinary original/source proof
and each segment's write frame, but the moved operation fails cut transport.
A false successor pointer invariant fails its predecessor's actual invariant
query and cannot authorize activation.

The final manual cases are `mutable-cut/stable-fixed` and `shift-fixed`, taking
**149.826s** and **153.662s**, respectively, run concurrently with the existing
30-second per-query limit. Earlier copied/reassigned source descriptors caused
expensive pointer havoc and exceeded both 30- and 90-second experiments. Keeping
the C view pointer fixed resolved those timeouts without relaxing safety or
progress. The moved negative case updates concrete adapter metadata in place;
it is not an opaque source-local certificate. The stable case uses ordinary
view callbacks. An attempted early address-assumption optimization was removed.

Two remaining limitations were exposed rather than hidden. A constant
function-entry view projection cannot generally reconstruct a changed resumed
view; the slot/pointee fixture instead uses current shared pointer bytes. Four
source byte writes can exhaust a history sized from one original word write.
The public diagnostic now identifies known history exhaustion as
`proof_model_capacity_exhausted`, retaining the exact property and evidence.
All nine diagnostic tests pass locally in 0.752s. Capacity derivation itself
remains open; the current fixture uses a word callback on each side.

The first Nix run of the final semantic cases took **388.014s**, including
**385.152s** for five tests. Four tests passed; the false-invariant test had an
incorrect expectation that structural validation must reject honest failed
evidence. Both structural readers correctly accept that diagnostic artifact;
the corrected test checks rejection by `spx_strong_contextual_proof` separately.
This failed run, its exact inputs and logs are retained under
`mutable-cut/structural-reader-expectation-failure/`.

That measured invalidation motivated separating the experiment's retained proof
generation from its reader tests through existing Nix dependencies and the test
manifest's source closure. The first split attempt took **392.154s** and exposed
an experiment packaging error: compiling beneath the content-addressed output
path let Nix rewrite embedded paths in the GOTO. The retained-byte checks
correctly rejected the changed model. The failing output and its hash audit are
rooted under `mutable-cut/output-path-relocation-failure/`. The producer now
uses the existing fixed-workspace pattern, compiling outside `$out` before
copying its evidence. No reader normalizes hashes or accepts rewritten models.
This split is an experimental validation dependency, not a new public format or
automatic production proof-cache feature.

The corrected retained proof producer is rooted at
`/nix/store/9awirfalzjykpdr787gqbhsbw5b9lii2-independent-lifting-mutable-cut-proofs`.
Its stable, moved and false-invariant cases take **137.778s**, **142.117s** and
**102.983s**, respectively, sequentially at a 30-second per-query limit. A
reader-fixture directory-permission error followed successful byte validation;
that separate failed test run is retained. After fixing the writable test copy
and strengthening the test to require the actual failed invariant query, the
five-test reader suite passes in a **4.378s Nix run with no new solver workload**.
The retained proof producer output is identical before and after that test edit.
This demonstrates experiment-level invalidation isolation, not a mutable
neighboring-component proof reuse or automatic public cache feature.

The final reader result is rooted at
`/nix/store/idyqcw15fbxfn7i26nrrlsb3dl788xmf-independent-lifting-mutable-cut-transport`.
Both structural readers and every positive auxiliary fact's retained bytes
validate after realization. The stable operation exports confinement; the moved
and failed operations export none. The strong local predicate rejects the false
invariant. Its diagnostic artifact remains structurally valid. The three
ordinary proof receipts, per-query/compile timing sums and artifact audits are
recorded in `mutable-cut/nix-audit.json`; concurrent query elapsed times are not
reported as solver wall time. `reader-reuse.json` records the exact input change
and identical producer output. These constructed engine fixtures still do not
qualify Metapad, a provider object, or a native artifact.

The final focused regression batch passes **84 tests, zero skips across eight
Nix shards in 197.009s**. It covers mutable frames, canonical view context,
reference transport, cut state, normal exits, proof diagnostics, refinement
generation and repository boundaries. The recorded inputs and all 12 original
trial files remain unchanged. Public Nix smoke also passes, including metadata
freshness, production Python lint and retired architecture; `git diff --check`
passes. Commands, terminal results and per-shard reports are retained in
`mutable-cut/gate/`. These selected checks and the five new cut-transport tests
do not replace full affected-source, pilot/native, export or portability gates.


## Mutable actual-caller entry and canonical transport

The next implemented premise is a wider mutable callee entry, bound to a real
CALL/RET engine fixture. `mutable_entry_contract` runs the complete paired
model over the wider domain only after both ordinary physical facts pass.
Every segment must pass before the supplier exports wider admission. The
actual caller checks the post-CALL machine state. A leaf that differs outside
its ordinary domain still qualifies there, but its failed wider theorem cannot
admit the trapping caller.

Entry admission alone exposed a soundness failure in the existing mutable
replay path: a substituted world reader was accepted in **39.489s**. This
precursor is preserved under `mutable-entry/entry-only/caller-forged/`; it is
not current positive evidence. The corrected path requires canonical world
read/write and reference callbacks, plus trusted view inspectors checking
callbacks, context, physical span, extent and permissions. The current Python
and jq readers reject that old receipt for its absent mutable transport policy.
Substituted reader and writer callbacks now fail the actual
`spx-bisimulation-connected-summary-mutable-runtime` query. A stable C signature
or reconstructed pointer alone supplies none of these premises.

The first transport attempt had a generated helper-symbol collision caused by
a Python loop variable shadowing its requested function name. The two failed
compile probes are retained under
`mutable-entry/transport-symbol-compile-failure/`. The corrected mutable helper
names are component-specific. This does not itself demonstrate multi-supplier
composition. The prior readable transport renderers remain byte-identical in
the checked single-inspector comparison; fresh readable qualification and
caller composition also pass below.

The retained Nix experiment compiles outside its content-addressed output and
separates proof generation from reader tests using existing dependencies. Its
producer is
`/nix/store/91libzw1vjmnr1rrzz9n3dglp1j9piij-independent-lifting-mutable-entry-proofs`.
The reader output is
`/nix/store/3bw9q0y6g5359br382kf72mp6g2357bc-independent-lifting-mutable-entry-transport`.
Generation and reader realization take **371.747s** with unchanged recorded
inputs. All **eight tests pass in 7.175s, zero skips** against the retained
cases. This run generated the proofs; it is not a new zero-solver reuse claim.

| Retained case | Ordinary result | Elapsed seconds | Additional result |
|---|---|---:|---|
| Mutable leaf | satisfied | 61.532 | Both wider segments pass |
| Mutable domain trap | satisfied | 60.652 | Final wider segment fails |
| Readable leaf | satisfied | 62.705 | Readable entry and machine frames pass |
| Mutable caller | satisfied | 59.931 | Checked wider entry; replay retained |
| Trapping caller | violated | 38.782 | Actual callee entry rejects |
| Substituted reader | violated | 7.847 | Canonical mutable runtime rejects |
| Substituted writer | violated | 7.936 | Canonical mutable runtime rejects |
| Readable caller | satisfied | 59.428 | Image-readable body-free strategy retained |

After realization, both full structural readers validate all eight honest
artifacts. The strong local predicate accepts exactly the satisfied ordinary
proofs. All 11 positive mutable frame/entry facts and all three source-local
certificates pass retained-byte validation; the readable leaf also exports its
checked empty-frame, entry and machine-state facts. The mutation suite rejects
rehashed domain/policy/tool/model/property substitutions, absent transport
premises and missing raw wider solver output. `mutable-entry/nix-audit.json`
records receipts and per-category timing sums. Summed concurrent query durations
are not solver wall time; preparation/model/link costs are not independently
measured by these small fixtures.

These are conditional original/source engine fixtures, not provider or native
qualification. Mutable bodies still execute in parent models. Paired post-memory
abstraction, checked machine-state transport, actual Metapad loop/callers,
public split/merge/refinement, shared objects/interactions, representation groups,
unrelated-target reuse and the retained full integration gates remain open.


The reader experiment was then strengthened with five existing readable
rejection/reuse-validation tests. The first reader-only run exposed a copied
root-directory permission error (**10.430s**), retained separately. After fixing
the fixture root, all **13 tests pass in 13.966s**, with a **16.543s Nix run**.
The producer output and all eight proof receipts are identical; only the reader
derivation builds, with **zero new solver workloads**. The final reader output is
`/nix/store/yn15qd0f1xcsw6j8y4gazm8f30vpql4y-independent-lifting-mutable-entry-transport`.
`mutable-entry/reader-reuse.json` records this comparison. The strengthened
readable tests reject missing frames, weakened domains, missing caller transport
premises and invalid previous-proof receipts using the newly qualified readable
cases. They do not stand in for fresh negative solver cases outside that scope.

The first nine-shard regression batch took **229.956s** and failed one stale
mutable-frame test expectation. Removing a write-frame fact while retaining the
new wider-entry theorem leaves a dangling dependency, so both readers correctly
reject. The updated test requires that rejection, then removes the dependent
entry claim and checks that ordinary qualification remains valid without an
exported whole-operation frame. It passes against the retained positive case in
**0.375s** before the affected Nix shard is rerun. No semantic reader or proof
obligation is weakened to make the test pass. The original failed batch and its
unchanged input/trial-file audit remain under
`mutable-entry/gate/initial-frame-expectation-failure/`.


The corrected focused Nix batch passes **88 tests, zero skips across nine
shards in 193.130s**, reusing the unaffected shard outputs. Its recorded inputs
and all 12 original trial files are unchanged. The final report and per-shard
logs are under `mutable-entry/gate/`. Public Nix smoke passes metadata freshness,
production Python lint and retired-architecture checks; `git diff --check`
passes. The initial failed batch remains a separate result. These targeted
checks and retained fixtures do not establish full affected-source validation,
pilot/native qualification, whole-application coverage, export or portability.

## Mutable machine frames and replay correctness

The mutable paired engine now checks separate cut and exit architectural-state
facts after the wider entry theorem passes. The initial cut policy requires
identity; the exit policy compares against the source adapter. A failure of
either stronger fact leaves ordinary qualification and wider entry intact.
The stable supplier passes both facts in both segments. An ECX update before
the cut fails its cut query; an ECX update before return fails its exit query.
The domain-trapping segment emits neither fact after its wider entry fails.
This is a restricted frame theorem, not general clobber or liveness reasoning.

Testing a real CALL/RET fixture exposed a replay soundness bug: the original
callee sets ECX to 77, and the original caller returns ECX. The authored caller
saves the input byte 17, invokes the authored callee and returns 17. The old
replay accepted this mismatching caller in **56.888s**. A concrete transfer
evaluation preserves the 77-versus-17 witness; it is a veto, not proof authority.
The generated caller now checks a named callee-machine-state assertion at the
actual CALL, backed by the supplier's separate facts. Its manual query fails
in **11.917s**. Both current receipt readers reject the old accepted receipt
`73555806053dc65572412c8ca0addfa02de3917b9ca2dc07af380d25570ff597`.

Replay also cannot omit the entire entry contract, its canonical transport
policy and all related guards. Both readers reject that resealed mutation.
Removing source-contract inputs from preparation raises a checked-premise
error before any proof obligation executes. Scalar body-free composition is a
separate strategy; this experiment does not establish a general scalar
machine-state theorem. Mutable summaries continue to execute their bodies.

The first machine-frame run exposed an omitted GOTO retention name. Recovery
copied an already-retained model only after matching its exact bound hash;
solver bytes and receipts were not changed. Fresh Nix generation retains the
new GOTO files directly. The four resulting supplier cases are reused from
`/nix/store/2vwqnn00njfh6pdlrddqin7m341cli6k-independent-lifting-mutable-machine-proofs`.
The old caller from that first run lacks the new replay guards and is stale.

The guarded caller producer regenerates only five affected callers, reusing
those suppliers and the preceding readable cases. Its producer and 21-test
reader run takes **125.363s**, with unchanged recorded inputs. The final output
is `/nix/store/33pnzbgjiqqj7rwfsa56r4wf7simwi4g-independent-lifting-checked-machine-replay`.
The ordinary caller passes in 57.585s; trapping-entry, forged-reader,
forged-writer and register-clobber callers fail in 11.665s, 7.434s, 7.556s and
12.290s respectively. Supplier generation is excluded from those caller times.

Adding the two whole-contract omission tests reuses every supplier and caller
artifact. The final reader passes **23 tests** through Nix in **27.865s**, with
zero new solver workloads and unchanged recorded inputs. Its output is
`/nix/store/jdm5ycshnysk4lakvdiv2a6y6qxgfcsm-independent-lifting-replay-contract-omission`.
Both readers and all **12 positive machine-frame facts** pass retained-byte
validation after realization. Evidence, exact commands, input hashes and
separate failure logs are under `build/independent-lifting/mutable-machine/`;
`replay-guard/` and `omission-reader/` preserve the two dependency experiments.
Per-query timing sums can include concurrent work and are not solver wall time.
These fixtures do not separately measure preparation/model/link costs.

Selected Nix regressions pass **92 tests, zero skips across nine shards in
44.662s**, with unchanged recorded inputs and all 12 original trial files.
Public Nix smoke and the diff check pass. Public diagnostics identify the new
failure as `proof_callee_machine_state_unproved`. This selected validation is
not full affected-source or pilot/native qualification. Paired mutable
post-memory abstraction, general machine-state relations, the real Metapad loop
and two callers, public split/merge/refinement, shared objects/interactions,
representation changes, unrelated-target reuse and all retained full
integration exits remain required.

## Conditional mutable post-memory lowering

The connected wrapper now has a conditional mutable rendering mode. It captures
input memory before writing arbitrary final bytes through the existing sparse
world, then replays exactly those write events on the other side. Overlapping
writable views and read-only aliases share physical byte contents; descriptor
aliasing is checked independently. The frame is checked at an arbitrary address
outside the writable union, and post-memory equality at an independent arbitrary
address. Caller contexts remain distinct. An arbitrary paired result supplies
no unproved relationship to the final bytes.

Nine retained probes comprise three positive cases (mixed read/write overlap,
overlapping writers, identical descriptors) and six negative cases (different
input bytes, changed descriptor aliases, unproved byte or return facts,
substituted writer callback and substituted runtime writer). All produce their
expected actual solver verdict. GOTO inventories show no callee bodies. Input
files, compiled models, inventories, exact commands and raw solver bytes are
retained and hash-checked under
`build/independent-lifting/mutable-post-memory/retained/`.

The mixed-access case initially failed the transport premise. A read-only
borrow must retain the issued reference's writable backing permissions, while
its callbacks and transport grant restrict access to reads. The existing
mutable transport wrongly required backing permissions to equal the grant.
It now requires the backing to include the grant; the realizer and trusted
inspector still check reference identity/lifetime, span, canonical callbacks
and exact transport permissions. The failed probe under `read-alias/` and the
earlier reserved-inspector-name failure remain separate diagnostics.

The nine probes total **0.006s generation, 0.634s compilation and 6.761s solver
time**. Their positive GOTO models contain **2,539–2,646 instructions**. Write
event capacity is one fixture initialization plus the sum of writable extents,
including duplicate coverage: three or five events in these cases. The
renderer emits C loops, not Python-expanded stores; changing an extent from 2
to 4096 retains one write site and adds fewer than 50 source characters. This
does not establish large-buffer solver performance or production model growth
independence. Production capacity and unwind derivation remain unimplemented.

Both readers reject a retained caller receipt changed to
`mutable-body-free-experiment-v1`. A fresh production caller proof with the
updated transport passes in **61.014s**, reusing the existing checked supplier,
and both readers pass; it still selects `connected-replay-v1`. The conditional
renderer cannot qualify a provider or authorize body omission. Its checked
composition premises still need to be connected to current supplier evidence
and an actual caller/callee-edit experiment.

Selected Nix validation passes **95 tests, zero skips across seven shards in
53.808s**, with unchanged recorded inputs and all 12 original trial files.
This includes the new conditional composition tests, readable summaries,
mutable source models, connected memory/transport regressions, code generation
and repository boundaries. The report is under `mutable-post-memory/gate/`.
These probes and selected regressions do not establish the real Metapad loop
and two callers, public split/merge/refinement, shared-object/lifecycle
composition, representation changes, unrelated-target reuse or the retained
full pilot/native/repository/export/portability exits.

## Qualified fixed-image mutable summaries and callee edits

The production engine now selects `image-mutable-body-free-v1` when all checked
supplier premises hold. Both authority readers recognize the same restricted
rule. Source-local mutable contracts, wider entry, original write/cut frames,
cut/exit machine frames and actual-call transport remain mandatory. The world
has fixed image-backed views and no allocation history. Writable extents from
validated contracts determine wrapper loop bounds and event capacity; neither
is taken from callee instruction counts. The experimental renderer strategy
remains inadmissible.

Retained evidence is under `build/independent-lifting/mutable-qualified/`.
The positive parent includes only caller transfers `0x2000` and `0x2001` from
the original program and contains no authored callee implementation. Its
167 functions / 5,476 instructions include the generated summary wrapper.
Increasing the callee's authored function from 208 to 272 instructions leaves
the parent's compilation inputs, raw GOTO and query shards identical. The
growth edit adds 32 cancelling XOR pairs; it tests body-size independence,
not idiomatic source improvement. The supplier receipt changes and is
requalified before composition.

| Run | Result | Seconds | Scope |
|---|---|---:|---|
| Initial mutable caller | satisfied | 96.344 | Full current caller queries |
| Changed supplier | satisfied | 74.571 | Separate source/original qualification |
| Caller after supplier edit | satisfied | 1.155 | 105 reused queries, zero fresh queries |
| Trapping caller | violated | 12.138 | Actual entry premise |
| Substituted reader | violated | 13.986 | Canonical read transport |
| Substituted writer | violated | 13.814 | Canonical write transport |
| Caller observing ECX clobber | violated | 12.058 | Machine-state premise; replay retained |

Reuse runs in the same fresh, fixed workspace as the donor compilation, with
fresh solver queries forbidden. No GOTO/debug paths or proof hashes are
normalized. Current source generation, compilation and supplier validation
still run. `growth-audit.json` records actual GOTO inventories, byte equality,
supplier identities and timings. `nix-audit.json` independently checks both
readers and 16 positive retained machine facts.

A separate fresh Nix proof producer and reader pass **27 tests, zero skips in
259.196s**. Its initial caller takes 95.726s, changed supplier 76.471s and reused
caller 1.200s, again with 105 reused queries and zero fresh queries. Outputs:

- Proofs: `/nix/store/g00fk5hg7kcd4s03k555z9wp4ybbyisd-independent-lifting-qualified-mutable-proofs`.
- Reader: `/nix/store/3x2s7q0s5d5zdbl9mqmkn5ynf09qb75z-independent-lifting-qualified-mutable-composition`.

Selected regression validation passes **129 tests, zero skips across twelve
shards in 76.745s**. Recorded inputs and all twelve original trial files remain
unchanged. These include source models, transport, connected composition,
continuations, provider selection, public diagnostics and repository boundaries.
The new selection is covered by the separate Nix composition experiment.

Preparation mistakes are retained separately: a relative supplier fixture root
failed include resolution and was rerun with an absolute root; a reader test
looked for paths in hash-only proof inputs and was corrected to inspect the
compilation file inventory. The first inventory audit expected a non-retained
ordinary supplier `model.goto`; the corrected audit uses its already-retained
identically bound mutable-frame GOTO. None of these failures was hidden by
regenerating or modifying solver evidence.

This establishes local mutable body omission and explicit neighboring-query
reuse. General machine clobbers, transitive suppliers, live allocations, shared
objects/interactions, the real loop and two callers, public split/merge and
contract refinement, automatic reuse selection, representation changes and
all retained full integration exits remain required. Component-count scaling
and large-buffer solver costs have not been measured by this experiment.

The following real-boundary diagnostic uses the retained executable transfer
plan and existing concrete evaluator, with no pilot rebuild or new interpreter.
Seven inputs exercise the original 20-transfer core through its proposed
`0x5606` cut and exit at `0x5623`. The retained trace observes EAX, ECX, EDX and
ESI changing between cut visits, and stack writes at EBP offsets -8, -2 and -1.
This supplies concrete counterexamples to applying the current identity-cut
and buffer-only physical-frame premises directly to that loop. Scratch tails
start at arbitrary diagnostic bytes (0xA5) and remain untouched; they are not
reinitialized at cuts. The sampled cut relation `output + removed == input`
holds, but is only a proposed invariant until its universal obligations pass.
Preparation takes 1.879s; compiler, solver and linking are not invoked.
`real-boundary-audit.json` binds the exact plan and script and retains states,
writes and paths. These seven executions are neither a loop proof nor incoming
caller coverage.

Public machine-premise failure diagnostics now navigate the recorded supplier
dependency and identify its failed or missing wider-entry/cut/exit fact, named
operation/segment and proof receipt. The actual retained ECX counterexample
reports `counter / run / sync:cut: exit machine frame violated`. The command's
qualification result remains incomplete. Ordinary equivalence and stronger
composition premises remain separate; stale or foreign diagnostics cannot
provide this navigation. This is initial dependency navigation, not full
contract refinement or automatic invalidation.

The diagnostic follow-up passes all 11 operator tests through the public command
fixtures and the focused Nix shard in 2.939s, with no solver workloads and no
changed recorded/trial inputs. The real retained clobber caller also produces
the expected supplier navigation directly. After refreshing generated metadata,
the public Nix smoke command passes, including metadata freshness, production
Python lint and retired-architecture checks. `git diff --check` passes. These
follow-up checks supplement the earlier composition/regression source snapshot;
they do not replace the full retained integration exits.

## Checked register clobbers at cuts and calls

The existing bisimulation intent now accepts an optional canonical
`machine_clobbers` list. Supplementary wider-domain cut and exit queries check
the remaining architectural frame. Mapped full-width register results may
change at internal cuts but remain related to source results at exits; they
cannot also be declared clobbers. ESP, FS and x87 storage are excluded from the
initial declaration vocabulary. Ordinary memory, reference, control and
continuation obligations remain unchanged.

Both authority readers bind the declared fields and result registers to
operation/segment metadata, proof-plan identity and exact guard/entry symbols.
Those names also bind actual solver property IDs and retained raw bytes.
Supplier consumption checks the result registers against its machine binding.
Only a complete positive cut/exit set can supply the alternative machine frame.
The source signature alone supplies no frame or compatibility theorem.

At a summarized call, declared clobbers become arbitrary values on the original
side after its checked adapter. The source-side caller does not receive matching
arbitrary registers. Thus the parent must tolerate the clobbers, rather than
silently assuming preserved machine state. This works through the existing
replay and qualified image-mutable strategy; it introduces no provider format
or production API.

Manual retained cases under `build/independent-lifting/machine-clobbers/`:

| Case | Ordinary result | Stronger result | Seconds |
|---|---|---|---:|
| Supplier changes ECX, declares ECX | satisfied | All clobber frames satisfied; old identity exit frame violated | 94.415 |
| Same supplier declares EDX | satisfied | Declared exit frame violated | 88.697 |
| Caller ignores ECX | satisfied | Image-mutable strategy omits both callee bodies | 101.107 |
| Caller observes ECX but C returns a saved byte | violated | Actual result-equivalence query fails | 35.103 |

All six initial reader tests pass in 3.367s using retained proofs, including
missing facts, changed masks/results, missing call guards and substituted raw
bytes. Planning/code-generation tests pass 28 tests. The initial diagnostic
copy filter omitted the two new auxiliary GOTO filenames; it is corrected.
The first manual fixture recovered those names only by copying an existing
model whose bytes match each bound GOTO hash. That recovery is recorded in
`supplier-retention-recovery.json`; no solver output was changed.

Fresh Nix generation additionally checks declared and undeclared ECX changes
at internal cuts and directly retains the new GOTO artifacts. The remaining
real-loop work includes private-frame write confinement, current scratch
allocation contents and lifetime, and a boundary that transports actual live
values without inventing production APIs. Transitive suppliers, public
split/merge/refinement, shared objects/services, representation changes and
all retained integration exits remain open.

The fresh Nix producer and reader pass **seven tests in 497.275s**, with zero
skips and unchanged recorded inputs. The declared cut-clobber supplier passes
its new frames while its old identity cut frame fails; the supplier that names
EDX instead fails the new cut frame. Both retain satisfied ordinary equivalence.
The parent that observes ECX fails its actual result query, including when its
callee body is omitted. All **fourteen positive clobber facts** validate against
retained GOTO and solver bytes after realization. Outputs:

- Proofs: `/nix/store/sn9bizakscmj8fx87yfl3x5msv86vw57-independent-lifting-machine-clobber-proofs`.
- Reader: `/nix/store/70r6vg5fzg6ki4rxbkr9xix5vigkfy5a-independent-lifting-machine-clobber-readers`.

Selected regressions pass **144 tests, zero skips across thirteen shards in
74.088s**, with unchanged recorded inputs and all twelve original trial files.
The public Nix smoke command, metadata freshness, Python lint and retired
architecture checks pass, as does `git diff --check`. This is a completed
register-clobber composition checkpoint, not completion of the real loop,
the two-caller workflow or the retained full integration exits.

## Omitted setup arguments at source cuts

The next checkpoint removes an inspected source-shaping obstacle in the retained
normalization core: `length` is used during setup while EAX is reused for byte
reads. A loop cut need not preserve an old argument that the suffix does not
need. The production signature and generated original semantics are unchanged.

Compiler-resolved integer parameters of 8/16/32 bits may be omitted at a cut
when their machine decoder is a register or stack slot. The source storage
inventory now includes those argument objects in havoc even when unmodified.
Aliases still address that actual storage. The ordinary resumed proof runs for
arbitrary forgotten values; no liveness fact or original argument correlation
is assumed. Non-scalar omissions and ambiguous/shadowed storage remain rejected.
Existing parameter and storage inventory roles bind the generated proof header.

Retained small solver cases under `build/independent-lifting/omitted-scalars/`
show the setup-only omission passing, and direct, aliased and mutated uses of a
forgotten argument failing `spx-bisimulation-exit-observable:run:result:result`
in `sync:loop`. Entry proofs pass for the direct and aliased negative cases.
Ten compiler-inventory tests cover existing storage rules, immutable omitted
arguments, aliases, pointer rejection and shadowing. A scan marker added to a
copy of the retained Metapad source produces the expected inventory including
`length` in 0.074s. That diagnostic uses illustrative capture projections only;
it is neither a machine boundary proposal nor a real-loop equivalence proof.
Its original source and header hashes are recorded in `real-source-inventory.json`.

Selected Nix validation passes **95 tests across eight shards, zero skips, in
106.431s**, with unchanged recorded inputs and all twelve original trial files.
The selected cases include source-cut integration, compiler storage inventory,
code generation, receipts, normal exits, exposed stack and operator diagnostics.
Public smoke, metadata freshness, Python lint and diff checks pass. No pilot
rebuild was needed for this rule. Private-frame write containment, allocation
current-memory transport, real-loop coverage/progress, transitive summaries and
the two actual callers remain open alongside the full retained goal.

## Symbolic real-loop footprint and current-state experiment

The retained Metapad core now has a conditional symbolic boundary experiment
under `build/independent-lifting/real-stack-frame/`. The driver uses the existing
transfer-plan loader and Behavioral-C slice producer, including a real forced
barrier at RVA `0x5606`, and the existing sparse memory and physical write-frame
fragments. It does not modify the retained extraction or introduce a production
`step` API. The region, containing part of an enclosing operation, remains
distinct from a component or replacement group.

The exact twenty transfers and original PE/IR identities are unchanged. The
new slice digest is `767d947564dd1f963ec744c7e40af874bd14ecc83c3c690a4a1a1ac9e901e92f`.
The experiment's admitted domain is explicit and conditional:

- Two disjoint eight-byte buffers at `0x420000` and `0x430000`, with arbitrary
  current bytes and a zero byte at text offset seven.
- EBP `0x440000`, ESP `EBP-28`, EDI pointing to text, and EBX to scratch.
- Input index below eight, output index no larger than input, and the current
  removal count at `[EBP-8]` equal to input minus output.
- Other machine fields and private bytes are arbitrary. Allocation identity,
  generation, permissions, actual callers and incoming coverage are not proved
  by these fixed-address premises.

One original step from the scan cut checks its actual read footprint and allows
writes only to scratch, `[EBP-8, EBP-4)` and `[EBP-2, EBP)`. At a backedge, input
advances by one, remains in bounds, and output plus the current removal count
still equals input. ESP/EBP stay fixed; every outcome reaches the cut or the
declared exit `0x5623`. Unwritten scratch-tail bytes keep their arbitrary current
contents. The complete query passes **1,972 properties**. Separate cover queries
witness the backedge, exit and removal path, avoiding a vacuous result.

Three intended negative checks fail at their specific predicates: omitting the
lookahead byte at EBP-1 violates the write footprint; leaving the source's
initially equal private bytes unchanged violates residual private-memory
agreement; resetting a current scratch word violates untouched-tail agreement.
An earlier reset diagnostic used the source-frame initializer and was rejected
by that initializer's existing guard; `reset-current-scratch-write` is the
separate negative that actually reaches the tail predicate.

| Work | Seconds | Scope |
|---|---:|---|
| Load retained transfers and generate barrier slice | 1.662 | No pilot rebuild |
| Generate complete boundary model | 0.00018 | Existing memory/frame fragments |
| Compile complete boundary model | 0.454 | Fresh GOTO model |
| Complete boundary query | 3.036 | Conditional original semantics |
| Missing-byte negative | 3.035 | Actual write-frame violation |
| Residual private-memory negative | 3.473 | Initially equal bytes become distinguishable |
| Three path witnesses | 3.658 | Explicit reachable cover points |
| Current-scratch reset negative | 3.409 | Actual tail-memory violation |
| Compile full bounded core/source comparison | 0.564 | Retained authored normalization body |
| Full bounded core/source comparison | 120.080 | Timeout; incomplete |

These are single-run observations, not latency percentiles or scalability
claims. Solver queries were run one at a time. The full comparison retains its
incomplete result and original scope; the small boundary result does not stand
in for it. Linking was not run. The immediate integration target is checked
private-write footprints and corresponding caller poststate transport, followed
by current allocation state and the two actual callers. No native/provider
authority or complete original/source loop qualification is supplied here.

A fresh Nix derivation reruns the five retained boundary models: the positive
query, three specific negatives and the three-path witness query. All reproduce
their expected outcomes, with raw output hashes and GOTO identities checked.
The output is
`/nix/store/pmxj6gyxivw110sdbbad6hdz5kmxxmli-independent-lifting-real-loop-boundary-checks`.
This reruns the solver on retained models; it is not a fresh provider build.
`checkpoint.json` verifies those bytes, unchanged preceding implementation
inputs and all twelve original trial files. Host observations used a Ryzen 7
9700X, sixteen logical CPUs and 96,405,640 KiB system RAM; peak query memory was
not collected. The repository diff check passes. No semantic engine change or
new activation rule was made by this experiment.

## Checked residual private-stack footprints

The private-frame integration is retained under
`build/independent-lifting/private-stack-contract/`. It extends the existing
bisimulation intent with ordered, disjoint `private_stack_writes` offset/size
ranges relative to operation-entry ESP, initially bounded by `[-1024,4096)`.
The physical write query checks each byte against the logical writable union
or private ranges; private bytes must be private in both worlds. A second query
checks the ESP anchor at outgoing cuts. The wider-entry theorem requires both
facts and the existing writable-view cut frame, with minimum ESP and image
exclusion accounting for negative offsets. The old writable-only frame keeps
its original meaning. All ranges, domains, guards and queries remain bound to
the exact supplier proof and raw model/output bytes.

A consumed frame saves actual callee-entry ESP, runs the checked adapter and
writes arbitrary bytes only into the permitted original-side ranges. Source
private bytes are not changed in tandem. Existing history capacities account
for these writes, and callers check write faults as well as the existing input,
view, alias, outcome and canonical transport premises. Body-free admission still
requires the full checked fixed-image mutable contract. This is not a general
heap/lifetime theorem or a transitive entry rule.

| Fresh Nix case | Ordinary result | Composition observation | Seconds |
|---|---|---|---:|
| Original writes ESP-8, declares ESP-8 | satisfied | Both private frames and wider entry pass for every segment | 83.451 |
| Original writes ESP-8, declares ESP-4 | satisfied | Stronger write frame fails in the writing segment | 75.909 |
| Caller ignores the residual byte | satisfied | Both callee bodies omitted | 114.633 |
| Caller initializes the slot to zero and observes it after the call | violated | Actual result equivalence fails against C returning zero | 48.093 |

The fresh producer and reader build passes **six tests in 332.862s**, zero skips,
with unchanged recorded inputs. Both Python and JQ readers validate the cases
and reject missing facts, weaker domains, changed footprints and missing call
guards. All seven positive private-frame facts pass retained GOTO and solver-byte
validation. The parent model contains 167 functions, neither callee body, and
only the two caller transfer units. Outputs are:

- Proofs: `/nix/store/g83j7cqx214yd8adlin035q8mcqr37a9-independent-lifting-private-stack-proofs`
- Readers: `/nix/store/z6556ra4hrjm940q9dj7zrvcmmbh7h0w-independent-lifting-private-stack-readers`

Earlier local runs took 79.339s and 70.873s for the two suppliers, 110.309s for
the ignoring caller and 48.180s for the final observing caller. The first
observing attempt lacked the caller's initializing store; it is retained under
`observed-uncorrelated-caller` and is not the final regression. No result or raw
solver output was overwritten to turn that attempt into the stronger test.

The retained real Metapad step now uses the production rule too. Scratch is its
sole logical writable view. With EBP=ESP+28 as an explicit entry premise, the
private ranges are ESP+20..24 and ESP+26..28. Under the same eight-byte fixed
buffers, termination byte, current counter and input/output premises as the
preceding diagnostic, the complete model passes **1,978 properties**. Omitting
ESP+27 fails `spx-bisimulation-private-write-frame:p20n4_p26n1`; deliberately
shifting ESP by four after the real step fails
`spx-bisimulation-private-cut-frame:p20n4_p26n2`. The negative shift is a diagnostic
mutation, not a claim about the original operation's behavior.

Preparation takes 1.751s, complete-model generation 0.00022s, compilation 0.552s
and the complete query 3.573s. The two negative queries take 3.580s and 3.462s.
These were single observations concurrent with Nix validation, not controlled
benchmarks. Linking was not run. These original-only facts do not qualify the
paired normalization source or discharge the real predecessor/entry, allocation
lifetime or two-caller obligations. The previous 120-second complete paired
comparison remains incomplete with its scope unchanged.

Selected regressions pass **71 tests across seven Nix shards**, zero skips, in
42.805s; recorded inputs and all twelve original trial inputs are unchanged.
Public smoke passes, including metadata freshness and production Python lint.
The operator now explains private write/anchor failures and navigates declared
private/clobber premises instead of reporting irrelevant missing identity frames.
These are selected validation exits; full pilot/native/repository/export/portability
validation remains required, along with the public edit/refine workflow, transitive
summaries, shared objects/interactions, representation changes and unrelated-target
reuse. The full independent-lifting goal remains active.

## Paired real entry and scan regions

`build/independent-lifting/paired-real-cuts/` now retains an original/source
comparison at the real `0x5606` barrier. It uses the same twenty exact transfers,
ordinary normalization source, compiler-resolved local havoc, production proof
header, sparse worlds and private-frame guards. Removing only the proof include
and `SPX_PROOF_BEGIN`/`SPX_PROOF_SYNC` lines restores the original source bytes.
The production signature remains unchanged. No contextual/provider receipt is
generated by these diagnostic wrappers.

The initial positive entry and scan checks did not close the same relation:
entry permits its first NUL at any `length<8`, while scan assumed `text[7]==0`.
The retained `closed-relation` intent instead carries the existence of a NUL
within the readable suffix beginning at `input`, along with `input<8`,
`output<=input` and `removed=input-output`. The predecessor checks that invariant
at its outgoing cut. The resumed case admits the same suffix relation without
requiring the last byte to be zero. This corrects the cut relation without
narrowing the original entry's text domain.

| Retained query | Result | Solver seconds |
|---|---|---:|
| Closed entry, ten object bits | incomplete: addressed-object capacity | 32.955 |
| Closed scan, ten object bits | incomplete: addressed-object capacity | 35.288 |
| Identical entry GOTO, twelve object bits | 5,814 properties satisfied | 46.771 |
| Identical scan GOTO, twelve object bits | 5,814 properties satisfied | 57.608 |
| Closed scan with current live scratch and backedge progress | 6,032 properties satisfied | 94.783 |
| Reset current scratch byte after incoming relation | violated: public memory | 75.587 |
| Release scratch during the region | violated: public memory | 38.032 |
| Wrong source removal count under the closed live relation | violated: scan invariant | 89.110 |

The twelve-bit rerun changes only addressed-object capacity. The property checks
retain the 120-second timeout, unwind 12, unwinding assertions and all safety
flags. They are unsliced diagnostics and do not change or establish failure of
the production partitioned query policy. The earlier complete-core timeout is
still incomplete. Compiler inventory takes 0.075s; entry model generation takes
0.00076s and compilation 0.587s. Link/native and pilot rebuild costs are absent
because those actions were not run. Timing samples are individual observations.

The live allocation case establishes a conditional current-state snapshot with
arbitrary current bytes. It does not replay `GlobalAlloc` initialization or
prove the real allocation's birth, ownership, history or caller coverage. A
release before the incoming relation can leave conditional properties vacuously
satisfied: the separate expired-view witness fails to reach that relation.
The final closed-relation witnesses cover lengths 0, 1, 2 and at least 3, plus
the resumed input relation with and without the live snapshot. Witness queries
are existential and do not establish all incoming entries or replace progress
proofs. Releasing during the admitted region is a distinct negative test and
fails actual public-memory equality.

Fixed disjoint eight-byte text/scratch buffers, the stack snapshot and
EBP=ESP+28 remain explicit premises. Existing derived relations already support
`exact_stack_address`; use that mechanism to carry the frame relation in the
production cut contract. Its predecessor must prove the relation, and the
full prologue's changing ESP cannot be justified by the stable-ESP private rule
alone. The production contextual path, exact entry/lifetime transport and both
actual callers remain next integration work. All public decomposition,
transitive/shared-state and retained full integration obligations remain open.

The pinned Nix recheck reproduces all ten expected results in **457.629s** at
`/nix/store/9m0v574wlrzcn7gc6ww8wydygrc552c2-independent-lifting-real-paired-cut-checks`.
It rechecks retained GOTO models with the existing backend, including the
intentional counterexamples and missing expired-view witness; it does not
regenerate or qualify a contextual package. `checkpoint.py` checks all fourteen
manual records against retained source/model/solver bytes, the Nix raw-output
hashes, exact marker erasure and all twelve original trial inputs. Recorded
semantic source is unchanged since private-stack validation, and the diff check
passes. `frame-anchor-proposal/` contains a parsed/rendered existing-format
derived-relation proposal, explicitly unproved. The full goal remains active.

## Incoming machine-frame relations before original execution

The production two-region fixture in `incoming-frame-domain/` isolates the next
real-loop requirement. Its predecessor establishes EBP=ESP+28; the successor
writes through EBP-8 into the declared ESP+20 private byte, alongside its logical
buffer write. The baseline ordinary proof is satisfied in 86.397s, but the
resumed private-write frame is violated because it executes before the later
source-header assumption constrains EBP.

The engine now also admits existing derived relations with register projections
and `exact_stack_address` expressions before original execution. No relation is
inferred or added to the contract. Source-header input assumptions, predecessor
assertions and nonvacuity remain checked. The entry harness and both proof headers
are unchanged; the resumed harness gains the same assumption in its property and
relation-only functions. This does not translate memory-bearing or source-dependent
relations into early assumptions.

The corrected local run takes 100.100s and satisfies the private frames. Fresh
Nix generation reproduces three cases: valid relation (100.625s), false relation
(53.568s, predecessor derived assertion fails), and missing relation (78.152s,
ordinary exit public memory fails). The writable-view-only frame still rejects
the private store. Four reader tests pass, including both authority readers and
positive-frame model/output tampering. An initial test incorrectly expected an
auxiliary receipt after ordinary equivalence failed; its correction reuses the
same three proof artifacts without fresh solver work. All semantic and fixture
generation inputs match the retained Nix snapshot.

The public diagnostic now identifies a failed derived relation as a predecessor
obligation. This is an engine prerequisite for the real Metapad cut, not production
qualification of its whole operation, live allocation or actual callers. Shared
object/service composition, public decomposition/refinement, neighboring reuse,
representation compatibility, unrelated-target workflow and all retained full
integration exits remain required. The full goal remains active.

Final incoming-frame validation passes **51 selected regressions in four Nix
shards**, zero skips, in 3.270s, plus public smoke, metadata freshness, production
Python lint and the diff check. All four positive private-frame facts validate
against retained model/output bytes; all twelve original trial inputs remain
unchanged. Proofs are retained at
`/nix/store/v3mrvw7zqv9amx87n4xfjqhj5lg94xcs-independent-lifting-incoming-stack-proofs`
and the four passing reader tests at
`/nix/store/bdfi5k0hghwj35c26g93z8vvryb5fnn8-independent-lifting-incoming-stack-readers`.

## Real predecessor and corrected frame checkpoint

The next investigation executes the five original transfers from `0x55b7` to
`0x55dd`, using the existing exact-C slice emitter and dispatch implementation.
The emitted slice identity is
`b2eee31f14489e274ca856e77758544545cddb12e1198c2a80cc489a549f6d0d`.
The binary, canonical transfer plan and original authored `normalize.c` remain
unchanged. Inputs, scripts, models and raw outputs are retained under
`build/independent-lifting/real-predecessor/`.

Inspection of the PE imports confirms `0x40e158` is the `lstrlenA` slot and
`0x40e128` is `GlobalAlloc`. The actual transfers retain the two calls through
EBX as indirect calls. Their loader binding and continued validity remain
explicit premises, not resolved incoming/call coverage. The current kernel32
profile describes `lstrlenA` as ABI-only: it does not supply a string-content
or memory-frame theorem. The diagnostic separately assumes normal returns and
preserved stack/import memory, havocs the volatile registers and flags, and
allows arbitrary results, including a null allocation result. It does not
implement the returned allocation's contents, lifetime or string semantics.

For entry ESP=S, the prologue sets EBP=S-4. Its `push edi` at `0x55c7` supplies
the string argument; it is not an additional saved register. The first and
second `lstrlenA` calls each remove four argument bytes, and `GlobalAlloc`
removes eight. At `0x55dd`, ESP=S-28, so **EBP=ESP+24**. The removal-count slot
is ESP+[16,20), and the two lookahead bytes are ESP+[22,24). The old real-core
proposal's +28 relation is therefore superseded. Historical +28 fixed-snapshot
results and the independent generic +28 regression retain their conditional
and fixture-specific meanings respectively.

| Retained query | Result | Solver wall time |
|---|---|---:|
| Actual predecessor with old +28 assertion | Violated: `real-predecessor-frame-offset:28` | 39.241s |
| Null and nonnull allocation outcomes | Both witnessed | 38.877s |
| Correct +24 predecessor, production partition execution | Satisfied: 54 authored assertions and safety partitions | 140.945s |
| Paired ordinary-C entry with +24 frame | Satisfied: 5,815 properties | 46.300s |
| Paired ordinary-C resumed scan with +24 frame | Satisfied: 5,815 properties | 57.236s |

The predecessor checks the actual call order, call arguments, removal-count
initialization, scratch-result slot, text/counter registers, continuation and
frame relation. Its nine original stores determine the diagnostic write-history
capacity; overflow and unwind checks remain enabled. Source/model preparation
and compilation are recorded separately from solver execution. The bounded
predecessor generation took 0.000190s and compilation 0.301s before the
partition-entry adapter; the adapter compilation has its own `compile.json`.
No pilot preparation or native linking was repeated for these checks.

The first positive harness incorrectly left a cover helper reachable in property
mode and failed for its missing body. Subsequent whole-model positive queries
timed out at 90 seconds, including the smaller history model and a sliced query.
These remain incomplete. Production partition execution initially failed because
the standalone diagnostic lacked the typed-boundary entry expected by the
production property router. The corrected diagnostic adds an entry alias that
calls the unchanged complete `check()` function, with no added assumptions or
omitted behavior. It uses the existing production partitioner and CaDiCaL with
90 seconds per query, not a 90-second total-operation limit. The failed models,
the weak-attribute compilation failure and setup/launch errors are preserved.

The paired regions retain the suffix-NUL invariant, current arbitrary text and
scratch bytes, and ordinary source with proof markers only. Their fixed ESP is
now `0x43ffe8`, with EBP `0x440000`. This is a corrected conditional snapshot;
the predecessor result does not establish the string-length, scratch-object or
fixed-storage premises of these separate paired models. Actual allocation
identity, generation, contents, extent and permissions still need transport.
The five successful/expected-negative cases above are the pinned Nix recheck
set; its output and byte audit are recorded separately in `checkpoint.json`.

The accepted pinned recheck is
`/nix/store/23ynvcg1vwsz54lv1d859j01xmiz1zzc-independent-lifting-real-predecessor-checks`.
It reproduces all five expected outcomes in **320.339s**. The audit validates
the query bindings and retained output bytes, including 63 distinct manual
partition output hashes, all five packaged cases, marker-erased ordinary source
and twelve unchanged original trial inputs. Recorded production, test and
generated inputs are unchanged from the preceding validation. The first Nix
package produced expected query outcomes in 324.147s but failed the byte audit
after `$out` path rewriting changed transcripts. It remains preserved as
`nix-checks-output-rewrite`; the accepted runner uses a separate build workspace.
The audit's initial handling of CBMC's lowercase `failed` status was corrected
to use the existing backend normalizer without rerunning any queries. Neither
packaging nor reader corrections change a semantic proof rule.

The next acceptance milestone remains the real dependency network and public
editing workflow, not another standalone diagnostic. The retained mutable caller
has a satisfied paired proof but no checked source summary. Source dependency
composition and transitive entry/frame composition must land together before it
can become a body-independent supplier to a further caller. Both consuming
levels must omit callee bodies and reuse their queries after a separately
qualified leaf edit. The real operation, both callers and its service/lifecycle
dependencies remain the consumers for this capability, with all retained
pilot/native/repository/export/portability obligations still open.
## Real network integration checkpoint

The transitive image-memory support is now checked through three machine levels
and both receipt readers. A retained leaf implementation change reuses 122 middle
and 179 outer machine queries plus two source queries, with unchanged consumer
models, current supplier rebinding and no fresh solver invocation (5.393s total).
Fresh Nix tests pass; a separate current-reader Nix check validates the edited
retained evidence. These remain conditional regression proofs. See
`build/independent-lifting/transitive-machine/` for accepted and rejected runs.

Integration has moved to the complete original cleanup at `0x55b7`, its real
resource-text helper at `0x1284`, and the retained actual caller sites `0x5c2f`
and `0xb19c`. The two operations now have canonical V5 interfaces and ordinary C
source packages. Exact-C emission retains all 35 cleanup transfers and the four
helper transfers; no internal setup/scan/finish API was introduced. The helper
body is still present in this initial original-side slice.

The helper uses image buffer `0x413d20` (500 bytes), reads the module value at
`0x410150`, invokes `user32.dll!LoadStringA` through IAT `0x40e220`, and returns
the buffer without checking the service result. Its proposed return therefore
uses a fixed shared view, with termination left for consumers to establish.
Repeated calls must preserve object identity and account for overwrites of the
same storage. This real shared-object requirement is now explicit in the
candidate interface; it is not implemented summary authority.

Both candidates pass host/PE32 compilation and the C profile through public
`component check --source`. Both `--source --local-contracts` attempts reject
the state/service scope without solver work; ordinary qualification is refused.
The cleanup's provisional failure return is not a proved counterpart of an
original memory fault. Actual incoming coverage, text lengths, allocation
outcomes, live scratch contents, copy-back, release and UI callbacks remain open.
All six commands, source/interface byte bindings, immutable products and phase
measurements are retained in `build/independent-lifting/real-network/`. Its audit
checks all twelve original trial inputs unchanged. This checkpoint does not
satisfy the public real-network edit/refine/reuse milestone or any retained
pilot/native/repository-wide/export/portability exit.

## Shared incoming-buffer producer

Inspection of the retained PE and transfer plan identifies the same routine at
RVA `0x5817` as the buffer producer in both actual caller contexts. Calls at
`0x5c09` and `0xb131` precede the cleanup calls at `0x5c2f` and `0xb19c`.
The first caller loads its buffer from `[EBP-20]`; the second retains it in EDI
after loading its output cell. These are two bindings to one producer contract,
not evidence that either incoming heap lifetime has been proved.

The producer spans 74 retained transfers. It allocates and zeroes file storage,
performs bounded reads and encoding checks, and can allocate converted storage,
release the old buffer and replace the output pointer. A useful shared contract
must carry the current allocation identity, contents, extent and termination
through the output cell, with checked error outcomes and caller path premises.
Reconstructing EDI or the stack-cell pointer cannot supply those facts. Factor
that producer contract for both consumers instead of embedding its whole body
and allocation history in each cleanup proof. This is a hand-defined boundary
candidate; no checked summary or additional caller-coverage claim is issued.

Exact call events, import identities, PE/transfer hashes and disassembly are
retained under `build/independent-lifting/real-network/input-producer-inspection-v1/`.

## Complete cleanup boundary proposal

The September 8 retained proposal covers the complete original cleanup
operation, all 35 transfers and seven services at eight call sites. Five view
parameters describe text, notification suppression, both window cells and the
caption. The existing result binding maps the candidate's `UINT32_MAX` failure
value explicitly. Canonical parse/serialization succeeds; binding status stays
incomplete. The incoming `cleanup.input` authority is deliberately absent:
neither caller's allocation lifetime has been established.

The public source check succeeds:

```sh
python -m spaghetti_extractor component check metapad text-cleanup --source \
  --target-flake path:/home/conroy/src/spaghetti-extractor/build/independent-lifting/real-network/public-cleanup-boundary-v1
```

It realizes
`/nix/store/yh4b8v09k7mdqp7agcg69q05cq91aza3-independent-lifting-metapad-full-cleanup-boundary-text-cleanup-component-source-check`,
using the retained v7 SDK. It checks ordinary C compilation for host and PE32
and the source profile; the machine binding is not an input. Builder preparation
takes 0.002s and compilation 0.069s, with no qualification, solver, link or pilot
phase. Proposal preparation/admission takes 1.651s separately.

Actual service selection accepts allocate, release, length, message, focus and
resource-text. Copy rejects with `component external service resolved contract
is absent`, which also stops complete overlay generation. A separate 1.657s
probe generates native/proof fragments for the five selected external services;
these fragments were not compiled or proved by this probe. Resource-text still
requires admission of the exact qualified supplier. UI native-callthrough
selection is not portable interaction composition.

The next internal boundary is the loop at RVA `0x5606`: input/output indices,
removed count and the local scratch view remain live. Current view capture
recognizes parameter views; it does not establish transport of this locally
allocated descriptor, current contents, aliases and generation. Validate an
allocation/write/cut/alias-read/release case before authoring the full loop's
cuts. Keep proof regions inside ordinary C rather than forcing production APIs.

There is also an explicit memory-admission gap. Proof baseline accesses outside
known allocations are permitted, while native runtime access checks admit
specific ranges. A fixture's null-write fault cannot become an unconditional
production premise. Full cleanup qualification therefore still requires native
memory correspondence, incoming lifetime, selected copy semantics, checked loop
cuts and UI composition; both real callers and incoming coverage remain open.

Evidence and exact hashes are retained under
`build/independent-lifting/real-network/public-cleanup-boundary-v1/`, including
`boundary-readiness.json`, `material/binding.json` and
`service-lowering/result.json`. Preparation, source realization and build logs
are the adjacent `full-cleanup-boundary-v1-*` files. All twelve original trial
inputs retain their recorded hashes. No new qualification is claimed.

### Allocation history at the proposed cut

Live inspection establishes a second obligation beneath local-view decoding:
`spx_proof_reset_worlds` resets allocation counts at every resumed region.
Public-memory equality compares the two reached allocation histories, but equal
nonempty histories do not establish an empty resumed input. The production cut
macro now requires `spx-bisimulation-allocation-cut-admission:<sync>`; both
contextual readers require that assertion independently. Until checked incoming
lifetime transport exists, either a live allocation or a released generation
prevents this cut. Null allocation, which creates no instance, remains admitted.

The regression uses the actual sparse proof world and generated cut macro.
Equal live and equal retired histories fail this new premise, while erasing its
assertion admits both. Tests also cover empty/null histories and omitted
evidence in the Python/JQ inventories. This is a soundness restriction that
exposes required transport, not completed B4/B6 expressiveness.

The actual cleanup's five consecutive length/allocation/length transfers now
reach the same generated cut at RVA `0x55dd`. The retained conditional
image-backed text input, selected string/allocation contracts and typed
adapters remain in place. The focused query finds
`spx-bisimulation-allocation-cut-admission:allocated` violated. It does not
establish the real callers' input heap or freshly qualify every prefix property.
The compiled model and query are retained in `real-network/cleanup-allocation-cut-v2/`;
all recorded Python implementation hashes match the current source. Preparation
takes 1.545s, model assembly 0.001s, compilation 0.313s and assertion inventory
plus solver 31.061s. No pilot or native link runs.

Public Nix checks pass all 70 targeted/repository-boundary tests with zero skips,
plus smoke, lint, metadata freshness and retired-architecture gates. See
`real-network/allocation-cut-nix-result.json`. The next capability must transport
current memory and lifetime history into resumed regions before restoring a
local view; replaying allocation-time initialization or changing a scalar
decoder cannot satisfy that requirement.

### Current allocation inputs and the real loop region

The sparse proof world now distinguishes imported allocation storage from fresh
births. `spx_proof_restore_allocation_input` restores ordered metadata, rebases
write/shadow offsets and reads incoming live bytes from current input memory.
Subsequent allocations use fresh initialization. It rejects malformed epochs,
duplicate native generations, overlapping live storage, capacity failures and
insertion after region effects. Native rows retain the allocating-call path's
representable one-past requirement. The constructor alone grants no authority
and does not establish an incoming memory or logical-origin relation.

Four constructor tests exercise current bytes, aliases, release, address reuse,
retired generations, malformed/late input and native endpoint rejection. Erasing
the imported-memory rule reproduces incorrect birth-time zeroing. The final
public Nix check passes 70 targeted/repository-boundary tests with no skips,
plus smoke, lint, metadata freshness and retired-architecture checks. Its product
inventory is `real-network/allocation-input-final-nix-result.json`.

The first combined real-prefix experiment remains incomplete. It selects 13
original transfers through `0x5606`, executes the candidate's short-input prefix,
and assumes a two-byte current-memory relation before restoring the captured
metadata. Full queries time out at 60s and 180s; a focused alias query times out
at 60s. The post-resume cover is reachable in 37.470s. The early combined models
also retain an unseparated coverage marker; they cannot be reported as complete
property proofs. Raw results remain under `real-network/cleanup-allocation-input-*`.

The independent loop-region experiment selects nine original transfers:
`0x5601`, `0x5605`, `0x5606`, `0x5679`, `0x5684`, `0x5693`, `0x569b`,
`0x56a4`, `0x56ad`. The real forced label at `0x5606` stops the backedge, while
zero-byte branches exit to `0x560d`. The ordinary source is the actual candidate's
loop body executed once, with explicit failures for invalid view accesses.
The region neither runs the allocating/length prefix nor includes its original
function. Its allocator family, authority selector and birth-spec constants are
checked against the selected contract's canonical transition recipe.

The conditional input is one live scratch allocation with arbitrary native
generation and admissible address, extent 1..256, output index below extent,
an image-backed 500-byte text view and input index 0..497. Removed count and
current memory bytes are arbitrary. The original frame binds EBP to ESP+24.
These are region premises, not established facts about either real caller.
In particular, the outgoing state has not yet been shown to establish every
successor entry relation; this is not an inductive proof of the complete loop.

Version 1 finds an input range ending at `2^32`: base 4,294,967,233 and extent
63. The native resolver rejects it, exposing the constructor's missing native
endpoint check. Version 2 checks the corrected domain but fails its unseparated
coverage marker. Versions 3/4 separate coverage from property compilation.
Version 4 passes all 4,906 properties, including restored-view access to
arbitrary current bytes, control, indices, removed count and public
memory/lifetime correspondence. Tail, copy and CR-CR-LF removal paths each have
a reachable witness. Replaying birth zeroing fails the current-input-byte check.

Preparation/model/compiler/solver costs are 1.537/0.001/0.196/39.006s. Coverage
takes 10.432s and the zeroing mutant 5.785s, with separate compilation costs
retained in the evidence. The compiled model has 128 functions and 32,276
instructions. Evidence is `real-network/cleanup-loop-allocation-input-v4/`,
especially `result.json`, `allocation-input-recipe.json` and
`additional-evidence.json`. No pilot rebuild, link or provider qualification
runs. The next step is to connect these current-state rules to canonical cut
declarations, local-view restoration and actual predecessor obligations; the
existing allocation-cut admission guard remains active until that is checked.

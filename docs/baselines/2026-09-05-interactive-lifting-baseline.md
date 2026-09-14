# Interactive lifting: frozen starting point and unfamiliar application

This is diagnostic baseline evidence for stage 0 of the
[interactive lifting roadmap](../interactive-portable-lifting-roadmap.md).
It does not qualify a provider or authorize a candidate.

## Source snapshot

The implementation baseline has HEAD `2df8e33` plus the existing dirty tree.
Its 1,110 present tracked/unignored files, including the previously untracked
connected-summary module, were copied before implementation changes to:

`build/roadmap-baseline/faef9dc136d891ef/source/`

The manifest identity is
`faef9dc136d891ef7f6a8dca806d2d9b6c1bb1fda1491326830a5a75c2fd2ef9`.
The adjacent `source-manifest.json` records file hashes/modes, capture time,
HEAD, hardware and Nix version. `status.txt`, `worktree.patch`, and `index.patch`
preserve the original change inventory. This snapshot includes unrelated work
for accurate baseline reproduction; it does not assign ownership of that work
to this migration or stage it for commit.

`pilot-command.json` records a single local, keep-going build of the Hello
program-name-selection, jq output-value-pipeline, and DX-Ball directdraw-init
providers from that immutable source copy. The process writes `pilot-build.log`,
`pilot-build.json`, and, on termination, `pilot-build-summary.json`. Provider
derivation realization is not proof satisfaction; inspect the resulting
qualification and contextual receipts separately. This build completed in
1,101.49 seconds with exit code zero. Its actual proof outcomes are:

| Frozen-baseline provider | Qualification | Contextual evidence |
|---|---|---|
| jq output-value-pipeline | Complete | Satisfied; no blockers |
| Hello program-name-selection | Incomplete | One 300-second authored-assertion timeout, `spx_bisimulation_check_0000.assertion.6` |
| DX-Ball directdraw-init | Incomplete | Five 300-second language-safety timeouts: bounds, pointer, signed overflow, undefined shift, and unwinding |

Exact provider outputs under `/nix/store/` are:

- `y5qsvi9ch7c0lx9nqhmlfhnk1v8zdz66-spaghetti-extractor-jq-jq-output-value-pipeline-portable-c-work-package-provider-v2`
- `dl7z0ixvnx4chfl8d30q56vh1l75chya-spaghetti-extractor-gnu-hello-program-name-selection-portable-c-work-package-provider-v2`
- `ginl05blqi399l5qdy817zgnn6drc6fn-spaghetti-extractor-dxball-directdraw-init-portable-c-work-package-provider-v2`

`observed-provider-status.json` records reopened qualification/result statuses.
These outputs predate the connected-memory repair and cannot validate that
repair's full pilot behavior. Strong candidate selection/link evidence remains
to be rebuilt. Stage 0 and the original migration remain incomplete.

## Frozen unfamiliar application

Use the regular **Metapad 3.6** release, not its Light Edition. The upstream
[download page](https://liquidninja.com/metapad/download.html) links the release
archive, and its [source page](https://liquidninja.com/metapad/sourcecode.html)
links the author's GPL source repository. Source is optional diagnostic context;
it is not the reconstruction input or proof authority.

- Archive: `https://liquidninja.com/metapad/downloads/metapad36.zip`
- Archive SHA-256:
  `b350e854eab7ecd2d6f0510eb4bd03ea3a2eb1ff854c226247a4acda1bf36b51`
- Executable: `metapad.exe`, 194,560 bytes.
- Executable SHA-256:
  `685989bad8d8119eddbb49e36006d8ac9155c45d69dee060807368241c8e58ce`
- Distribution assets: `metapad.exe` and `metapad.txt`; preserve the latter.
- Static PE inspection: machine `0x14c`, PE32 magic `0x10b`, GUI subsystem,
  image base `0x400000`, entry RVA `0x1212`, executable `.text` virtual size
  49,618 bytes. The archive and original executable were not executed.

The independent public-SDK consumer is at
`/home/conroy/src/spaghetti-extractor-trials/metapad/`. It pins the baseline
extractor snapshot, verifies the primary PE hash through the SDK, and exposes
original, identity and inventory packages plus standard operator artifacts.
Its target is analysis-only: no authored component/configuration or candidate
execution authority is invented to make the first import succeed. Its selected
existing environment profiles are inputs to checking, not evidence that every
import is supported. Generated diagnostic inventory is retained under
`build/metapad-trial/` in the extractor checkout.

## Scenarios fixed before toolkit adaptation

1. Launch an empty editor; create and edit text, observe dirty state, cancel
   close, save, and then close cleanly.
2. Open separate LF and CRLF text files, edit, save to a new path, reopen, and
   verify exact output bytes under the selected encoding/newline mode.
3. Find/replace through the modeless dialog, including no match, replacement
   growth/shrinkage, cancellation, and continued editing after dialog dismissal.
4. Exercise missing-file, unwritable-destination, and allocation-failure paths
   through qualified service/environment fixtures without losing live content.
5. Exercise callback and resource cleanup through repeated open/edit/close and
   modal dialogs; detect expired ownership or callback-after-destruction.
6. Exercise the printing/abort path once its callbacks and thread behavior have
   been recovered and qualified. Preserve the related reachability obligation
   even before that scenario can execute.

Freeze normal application operation without third-party language plugins as the
initial external environment. Every requested unresolved dynamic module or
plugin remains a visible blocker; absence of a scenario does not remove a
may-reachable definition from the semantic closure. Candidate-only tests and
their expected observations must be authored and gated before any execution.
Allocation-failure observations are fixture cases, not changes to the original
program's input contract.

## Static capability inventory and next evidence

The PE imports nine DLLs. CRT byte/string operations, GlobalAlloc/GlobalLock/
GlobalUnlock/GlobalFree, file open/read/write/close, window messages, subclassing,
dialogs, GDI printing, clipboard, registry settings, and dynamic library loading
are present. `CreateThread` is also imported. These are observed import facts;
call-site reachability, inferred prototypes and semantic coverage remain to be
checked. In particular, no single-threaded assumption is justified by choosing
a small editor.

The independent SDK consumer successfully built its input-identity receipt and
static inventory. The public `project status` command then completed in 182.94
seconds from the cold starting state and reported **incomplete**, with 1,156
blocker rows. Its linked-module file hash is
`22f53397438ac419b315b307c751f1c2a605d21d7e3aad57280ad8ee90c480b4`.
Five subsequent identical command invocations produced identical output hashes,
with median 1.246 seconds and maximum 1.332 seconds. This includes `nix run`
startup and warm evaluation, and exceeds the roadmap's one-second status target;
it is not a claim that interactive latency is complete.

The blocker groups are 566 unchecked import-code contracts, 132 missing import
protocols, 137 unresolved environment rows, 268 symbols without providers, 32
incomplete platform selections, 20 unresolved relocation rows, and one upstream
transfer-plan incompleteness. These are dependent diagnostic rows, not 1,156
independent missing features. Rank original causes through their bound source
artifacts before making repairs. Exact JSON and timings are in
`build/metapad-trial/operator-{status,summary,warm-summary}.json`.

The toolkit already has relevant ownership, call, callback, runtime and native
ingress machinery. No capability in this application is declared qualified on
that basis alone. Next classify primary reachable blockers from the public SDK
inventory and operator baseline, and bind the scenarios to exact sites.
Keep the application fixed if it exposes missing generic capabilities.

### Primary-cause inspection

Reopening the public SDK's `candidate.linked-semantic-module` product reproduced
the linked-file hash above. Its directory is
`/nix/store/fq034qrwdn3jq6mj0g7vwhi8y3anxhxl-spaghetti-extractor-metapad-linked-semantic-module-v2`.
The following is an implementation priority, not a qualification claim:

1. Resolve the exact transfer blocker at RVA `0xa372`–`0xa379`; the platform
   diagnostic identifies `repe cmpsd` at `0xa377`. Inspect and qualify the actual
   instruction form. The platform selection separately contains nine unsupported
   Lean-form diagnostics and 32 unavailable-form issues, including an x87 `fdiv`
   diagnostic at `0x333f`. These counts overlap by dependency and do not establish
   that fixing one transfer completes ISA coverage.
2. Establish the mutable edit-buffer and callback boundary before portable
   rewriting. `GlobalAlloc`, `GlobalLock`, `GlobalUnlock`, and `GlobalFree` have
   selected import contracts, but that alone does not demonstrate the editor's
   ownership/lifetime protocol. `SetWindowLongA` (IAT RVA `0xe1c0`), `SendMessageA`
   (`0xe1ec`), and `CallWindowProcA` (`0xe2a0`) lack contracts. They are concrete
   starting points for subclassing and reentrant edit notifications.
3. Bind open/save acceptance to `GetOpenFileNameA` (`0xe050`) and
   `GetSaveFileNameA` (`0xe048`), which lack contracts. `ReadFile` and `WriteFile`
   already have import contracts; their presence does not discharge the dialogs,
   cancellation behavior, or the complete file/ownership protocol.
4. Classify `CreateThread` (`0xe0f4`, missing contract) and printing callbacks
   explicitly. Do not assume a single-threaded program or prune reachable
   behavior to fit the first scenario set.

The environment's 137 blockers comprise 136 unresolved import contracts
(user32 70, kernel32 24, gdi32 17, comdlg32 9, advapi32 6, comctl32 4, msvcrt 3,
shell32 3) and one static-authority incompleteness. Other imports and relocation
closure remain required beyond the priorities above. Machine-readable rows,
exact source-file hashes, and scenario import locations are preserved in
`build/metapad-trial/primary-blockers.json`. These IAT locations bind the initial
scenario investigation; callback targets and individual call-site coverage still
need to be resolved before scenario qualification.

## First connected-summary adversarial check

A CBMC test using the actual generated shared world and connected replay hooks
made one exact and one source write to address 4096 with different byte values
(17 versus 23), retaining equal write and call counts. Before the repair, all
613 discovered properties passed and replay accepted the boundary. This is a
reproduced gap in the replay helper's admission checks, not evidence that a
particular deployed application was miscompiled. The new regression requires a
dedicated input-memory equality failure before any result/effect replay.

The repair captures a fresh arbitrary memory byte before exact callee effects,
checks corresponding source input memory before replay, and includes private
storage exposed through logical references/views. Reference metadata includes
origin, generation, bounds, and permissions. Ordinary write histories may differ
in order and count when their effective bytes agree. The callee still executes
inside the parent model; this is not the planned body-free relational summary.

After splitting connected replay, solver execution, evidence validation, and
memory rendering into their existing responsibilities, 85 focused tests passed.
The eight connected-call solver fixtures cover differing input bytes, pre-effect
snapshot timing, reordered and overwritten writes, partial overlap, exposed and
unexposed private memory, and stale reference generations. Two captured world
renderer outputs remained byte-identical across the split. The supported
`nix run .#test -- affected` invocation passed again after final import cleanup
(119.30 seconds), including its smoke and selected repository/native/proof
checks. Exact changed-file arguments, logs, and timing are in
`build/connected-summary-audit/affected-{command,summary}.json` and `affected.log`.
Generated module/test registries were refreshed and `git diff --check` passed.

This is targeted migration validation. The three pilot receipts above belong to
the frozen pre-repair baseline; post-repair pilot qualification, fresh selected
objects and link/activation receipts, and the complete repository/target/port
roadmap gates remain outstanding.

## Authored acyclic regions and boundary composition

The planner now admits authored acyclic synchronization points through the same
forced-label and relation mechanism used for cyclic cutpoints. Removing all
cutpoint units must still break every exact cycle. The production qualification
gate requires the updated proof-plan policy; its previous cyclic-only policy is
not accepted by that gate.

A real CBMC fixture reproduced synchronization terminating a shard with equal
captures but unequal public bytes. The boundary now asserts equality at a fresh
arbitrary public address before termination. Another boundary assertion requires
all connected calls to be paired. Both checks are independently inventoried, and
the aggregate reader derives their required presence from the selected units and
outgoing cutpoint edges, rejecting even a newly hashed inventory that omits them.
Ordinary write histories can still differ when their effective bytes agree.

The integration fixture now uses `write_component_exact_c_slice_v1`, including
generated Behavioral-C, source maps, and forced labels. Its acyclic branch graph
proves with two regions selecting two and three exact units respectively. Actual
solver mutations reject an incorrect live capture, an incorrect suffix result,
and a branch that misses its required source barrier. A separate graph test
rejects an acyclic cut offered in place of a missing cyclic cut.

The affected suite passed in 126.25 seconds, including its smoke and selected
repository/native/solver checks. Arguments and logs are in
`build/acyclic-cutpoints/{command,summary}.json` and `affected.log`.
Fresh pilot rebuilds completed separately in 1,006.99 seconds. Reopened receipts
show jq still complete, Hello violated at
`spx-bisimulation-connected-summary-input:0`, and DX-Ball incomplete with the same
five 300-second language-safety timeouts. Hello's counterexample is from
`gnu_hello_memory_regions_equal.assertion.5`; it requires diagnosis of the
connected input relation and is not by itself a claim about an application bug.
The result directories are:

- Hello: `/nix/store/yy7wfy3q3gkzqvh195p8y6ac7d37nnkd-spaghetti-extractor-gnu-hello-program-name-selection-portable-c-work-package-provider-v2`
- jq: `/nix/store/kl25mvcp6jjslbcr9npazpky4s6hxfjy-spaghetti-extractor-jq-jq-output-value-pipeline-portable-c-work-package-provider-v2`
- DX-Ball: `/nix/store/df916l27f39xwm318icnzarn5d7kqj3g-spaghetti-extractor-dxball-directdraw-init-portable-c-work-package-provider-v2`

Commands, logs, file hashes, and compact failed-query inventories are under
`build/acyclic-cutpoints/`. Successful provider derivation realization does not
make an incomplete qualification authoritative. Fresh link/activation receipts
were not built in this run.
Automatic proposals, measured region budgets, typed resource/state captures for
the real DX-Ball cuts, and body-free summaries remain unfinished.

### Pinned contract-lowering experiment

The Nix development environment provides CBMC 6.9.0. A separate diagnostic
experiment exercised its documented function-contract enforcement and call
replacement commands on a scalar mutation through one valid pointer. Enforcement
proved the callee's postcondition and frame; replacement proved the caller's
result, aliased read, and unchanged unrelated local. Mutated postconditions,
out-of-frame writes, and missing caller preconditions each produced a solver
failure. The experiment follows the primary
[function-contract documentation](https://diffblue.github.io/cbmc/contracts-functions.html).

After replacement and `--drop-unused-functions`, the reachable parent graph has
no callee body. Expanding that body by 256 additional statements left 54 GOTO
instructions and an identical code hash after removing location comments.
Commands, source, property output, reachable call graphs, and the size comparison
are in `build/summary-contract-probe/`. This establishes availability of a useful
lowering facility in the pinned toolchain. It does not establish relational
coupling, complete effect/outcome coverage, receipt dependency composition, or a
production summary path; those remain stage-1 implementation obligations.

## Source member capture bindings

The sync-intent parser and source marker scanner now support optional structured
`source_bindings`. A capture can name a root object and a sequence of direct or
pointer member accesses. The marker must supply the same path; arbitrary C,
side effects, unknown captures, and duplicate syntactic paths are rejected.
Unbound captures retain their original spelling and serialization.

Twenty-five focused tests passed after the change. Generated Behavioral-C
integration fixtures prove resumption with a local struct member and with a
pointer member. A null base produces a real solver failure; the binding does not
assert pointer validity or non-aliasing. The supported affected suite also passed
in 122.94 seconds, including its selected repository/native/solver checks.
Arguments, logs, and timing are recorded under `build/source-member-captures/`.
Generated module metadata was refreshed and `git diff --check` passed.

Tracing `machine_overlay_v5.py` confirmed that it calls the source operation
before `_state_export_lines` publishes `context->state` back to machine storage.
Consequently DX-Ball's future internal cuts need an explicitly checked relation
between those lifted fields and their machine storage, in addition to the public
memory frame check. Merely adding member bindings or ignoring differing bytes
would not establish that relation. The running pilot rebuild was launched before
this optional binding extension; its exact receipts remain bound to that earlier
source realization.

### Replayed Hello counterexample

The saved proof diagnostics were recompiled from the exact C inputs named by
their receipt hashes, using the original exact-slice headers. Replaying only
`gnu_hello_memory_regions_equal.assertion.5` reproduced
`spx-bisimulation-connected-summary-input:0` in 32.41 seconds. The left exact
argument has object/address 4149283, offset zero, and enclosing extent seven;
the source argument has object/address 2003201, offset 2146082, and enclosing
extent 3194880. Both have domain/generation one and read permission. The effective
address agrees, but their reference representations differ. The right argument
similarly retains a larger enclosing source extent.

This supplies concrete input for the checked view/origin relation required by
modular summaries. It does not prove that ignoring origins or bounds is sound,
nor that the later memory/result goals pass. Commands, original source-input
selection, raw CBMC output, trace, and compact metadata are preserved under
`build/acyclic-cutpoints/hello-input-replay/`.

### Checked connected-view adaptation

The generated logical-operation adapter now checks the requested byte range
against both the supplied view and its origin, validates the reference through
runtime realization, resolves the callee view, and rebuilds both byte and span
access contexts at the checked address. The strict connected summary comparator
remains unchanged. The proof runtime records issued origin metadata and rejects
forged bounds and capabilities; its finite registry capacity is an assertion.
It also checks domain, generation, offset, one-past policy, permissions, address
overflow, and canonical null representation. NUL-origin extents are now shared
between the paired worlds rather than registered only in the source world.

Actual CBMC tests cover subviews reading the correct byte, callback overread
rejection, expired and forged origins, permission failures, insufficient view and
origin bounds, invalid/null references, and shared origin extents. Twenty-five
focused world and region tests passed in 21.34 seconds. A separate diagnostic
replay of the historical Hello connected-input property passed in 86.57 seconds;
its commands, altered diagnostic C, and solver output are saved under
`build/connected-view-normalization/`. This replay is explicitly non-authorizing.
Supported affected validation passed in 102.01 seconds. Its broader overlay
coverage also exposed a stale absolute-address test expectation, now corrected
to require the existing runtime-image-base-relative state-slot accesses. Fresh
Hello/jq providers were launched next; their results must be reopened before
changing target qualification status.

The final receipt audit also made issued-origin realization and shared NUL-origin
metadata mandatory in both the Python and Nix authority readers. The already
running provider build includes the proof-model changes but predates these two
policy fields, so its output must be refreshed under the final receipt policy
before it can authorize current selection. Policy-focused affected validation is
recorded separately in `policy-{command,summary}.json` and `policy.log`.

That policy-focused affected run passed in 124.66 seconds. The pre-policy-field
provider rebuild completed in 826.31 seconds and both qualification files were
reopened. Hello's connected input property passes, but
`spx-bisimulation-exit-observable:select:state:program_name` times out at 300
seconds. jq also has a 300-second timeout at
`spx-bisimulation-typed-call-fields:1`; its preceding baseline had passed. Both
new provider qualifications are incomplete, with no reported counterexample.
Exact paths, result file hashes, and failing query identities are recorded in
`observed-provider-status.json`. No dispatch/link activation was rebuilt.

The next adjustment keeps issued-origin records in separate per-world structures
instead of adding fields to the existing public-memory/event structure. It keeps
the checks while preserving the latter structure's layout for unrelated models.
Twenty-one focused CBMC/world tests passed in 2.87 seconds after this adjustment;
a speedup is a hypothesis until the updated providers are measured.

A non-authorizing mutation check using the real Hello receipt confirms that both
Python and Nix accept the policy control and reject the old policy or either
missing origin-policy field, even with the proof receipt hash recomputed. The
script and compact results are `check-receipt-policy.py` and
`receipt-policy-check.json`. The final-policy rebuild and affected run, including
the isolated origin structures, are recorded under `final-policy/`; inspect their
completion records and reopen the new qualification files before reporting a
recovery of either pilot.

The final-policy affected run passed in 141.98 seconds. The corresponding
Hello/jq provider build completed in 770.54 seconds. Reopened receipts under
`final-policy/observed-provider-status.json` show Hello incomplete on two
300-second exit value/observable queries and jq incomplete on its position-one
typed-call-fields query. The build itself passed because incomplete qualification
is a valid fail-closed artifact. No activation recovery was established.

## Scalar summaries and exit-memory audit

The production provider checker now emits supplementary, non-authorizing source
certificates for scalar operations with no state, services, or effects. Actual
CBMC contract instrumentation checks an empty write frame; a separate paired
source harness checks context independence for equal scalar arguments. Reachable
undefined functions, loops (including an empty infinite loop), and recursive calls
reject the initial strategy. Input and tool hashes, headers, models, instrumentation,
and required checker options are bound and validated. The connected provider path
consumes these only alongside a qualified exact/source child and matching actual
source/profile/interface bindings. It omits the scalar callee body and couples an
arbitrary result after the existing argument and memory checks.

The real `ascii-to-lower` child produced satisfied contextual and supplementary
certificates in 28.97 seconds, recorded in `build/scalar-summary-contracts/`.
That receipt predates the subsequent exit-memory requirement and is historical.
Nine focused tests pass, checking real GOTO-body absence, unequal scalar argument
rejection, source-byte binding, and required certificate mutations. This does not
complete the real-parent, callee-size, or stateful-composition scaling exits.

An adversarial exact transfer writing an undeclared public byte was previously
accepted when declared exit values matched. Operation exits now inventory and
prove effective public-memory equality; the fixture rejects the write, and a
rehashed receipt cannot omit the exit-memory inventory. Python and Nix require
the new policy field. Twenty-three focused tests passed in 20.24 seconds, and
affected validation passed in 136.42 seconds (`body-free/affected-summary.json`).
Earlier pilot receipts lack this new requirement and are not current authority.

The first real `ascii-string-compare` parent build failed in 99.51 seconds before
the solver because cost calculation reintroduced the backedge to the starting
cutpoint. Region slicing already stopped at that barrier. The calculator now
uses the same barrier set, with tests distinguishing a valid cut backedge from
an uncut cycle. The subsequent build and compact results are recorded under
`build/scalar-summary-contracts/cost-barrier-fix/`. It finished in 107.07 seconds,
with both shards rejecting a missing connected runtime context. Service-free
adapters previously left their service context null. They now initialize that
context, including the empty service struct's reserved field; host and PE32
compilation check the same generated adapter.

The parent input audit also found the exact scalar callee retained in the
generated direct-call closure despite omission of its Portable-C body. Qualified
scalar summary entries now stop expansion at the checked adapter. The original
closure and call inventory are still authenticated, and ordinary unsummarized
callees remain present. Tests distinguish both cases.

The resulting real parent build finished in 256.01 seconds, recorded under
`build/scalar-summary-contracts/omitted-exact-body/` in `pilot-retry-summary.json`
and `observed-provider-status.json`. The output is
`/nix/store/9inp94ld12w1lc2q289k3nff3qs77bdq-spaghetti-extractor-gnu-hello-ascii-string-compare-portable-c-work-package-provider-v2`.
Qualification is incomplete: both shards report `spx-bisimulation-invariant:scan`.
The trace gives zero input bytes nonzero abstract results (128 at entry, 161 at
the sync), allowing the loop to continue beyond the terminator. This is evidence
that the arbitrary-result summary needs a checked postrelation, not permission
to assume a callee-specific fact. The selected scalar strategy and satisfied
child certificate are present in the parent receipt.

`inspect-parent.py` recompiles the receipt-bound diagnostic C inputs and records
the GOTO function inventory. Both parent models omit `spx_sub_0000933d` and the
hidden source implementation. Their total instruction counts are 7,283 and
6,467, versus 7,917 and 7,101 before the adapter and closure repairs; the previous
exact child body alone contained 630 instructions. These reconstructed diagnostic
models are non-authorizing. A fixed-interface callee-size experiment and passing
real parent qualification are still required. In particular, audit capacity
derivation against body growth as well as compiled-function absence.

Affected validation passes in 150.25 seconds (`affected-retry-summary.json`).
The first invocation in that directory rejected stale generated module metadata;
the documented passing retry followed a metadata refresh. No new native or link
activation is claimed.

## Checked scalar postrelations

The scalar certificate now admits proved predicates in the existing Relation IR.
The initial candidate generator proposes zero preservation without inspecting
component names. A generated harness checks it against the same compiled source
after the required frame/context-independence/control proofs. Failed candidates
are recorded as diagnostics and omitted from the admitted fact inventory. The
reader reconstructs the predicate harness from its typed signature and expression,
checks its source hash, and verifies compilation inputs and checker options.
The paired wrapper applies only admitted predicates to its arbitrary result.

Twelve focused tests pass in 5.52 seconds. They include omission of a false
candidate, rejection of rehashed predicate/source/checker mutations, and a paired
CBMC proof that requires the fact. The reproducible non-authorizing size experiment
is `build/scalar-summary-contracts/checked-postrelations/size-experiment.py`, with
results beside it in `size-experiment.json`. Adding 256 statements grows the child
from 4 to 260 instructions; both paired parent models contain 1,158 instructions
and satisfy their checks. Connected slot capacity now counts caller-owned sites
instead of all callee-closure calls. The real parent scaling and qualification
exits remain distinct from this experiment.

Initial affected validation passed in 153.11 seconds. After certificate-reader
hardening, it passed in 148.32 seconds (`final-policy/affected-summary.json`). A
subsequent Nix policy change also requires the predicate signature and command
fields. The real postcondition-enabled parent build remains live; its terminal
summary and receipt must be reopened. The build started before reader hardening,
so a final-policy build is also required for current authority.

The current-policy affected run, including the final Nix predicate-field checks,
passes in 128.56 seconds (`final-policy/current-validation/affected-summary.json`).
Both the initial postrelation-enabled caller build and the final-policy caller
build are confirmed live; the latter records its command, log, and eventual
terminal summary under `final-policy/`. Neither has supplied a terminal
qualification at this checkpoint.

## Real scalar caller qualification and model retention

Both postrelation-enabled builds subsequently completed. The first took
1,308.27 seconds and produced complete qualification with satisfied entry and
sync shards at
`/nix/store/h7bnmkh6z4451w75p5lmy2g96kgq55im-spaghetti-extractor-gnu-hello-ascii-string-compare-portable-c-work-package-provider-v2`.
The hardened-policy rebuild took 1,415.89 seconds and also completed qualification:
`/nix/store/7s27ggdaspjzs7k10iv83ps2rakp6a8v-spaghetti-extractor-gnu-hello-ascii-string-compare-portable-c-work-package-provider-v2`.
Its contextual result file SHA-256 is
`bb35a5609ad84d6e5c356be525bfc0e6d336f6854314f97682068dacb8f2b6c6`.
The two shards satisfy 85 and 86 assertion properties respectively, plus their
required language-safety and nonvacuity checks. The connected scalar certificate
contains the proved `zero-preserving` predicate. Terminal summaries and compact
receipt observations are saved in the initial directory and `final-policy/`.

Both current Python and Nix strong readers accept the latter receipt and reject
rehashed removal of the fact signature or either command record, and an
unsatisfied fact. `final-policy/check-readers.py` and its adjacent JSON record
this non-authorizing mutation check. No linked/native candidate activation was
rebuilt. The build times are not isolated latency benchmarks; other solver and
validation work overlapped them. They nevertheless show that interactive latency
is unfinished.

The live queries included capacity assertions for impossible scalar replay
effects. The scalar strategy now omits those generated write/call/atomic branches,
retaining argument, input-memory, prefix and invocation pairing checks. Twenty-two
focused tests pass in 7.48 seconds; affected validation passes in 150.55 seconds.
The paired growth experiment under `build/scalar-summary-contracts/effect-free-replay/`
keeps the callee at 4/260 instructions and the parent at 1,122 in both cases,
down from 1,158. The real specialization build remains live there.

Successful proof artifacts previously omitted diagnostic C inputs, preventing
direct inspection of their compiled models. The checker now retains the
receipt-bound inputs for success and failure whenever the destination is
requested, still excluding large GOTO binaries. Fourteen integration tests pass
in 26.09 seconds and verify the retained hashes; affected validation passes in
135.94 seconds. The real build under `build/scalar-summary-contracts/retained-models/`
is live and must finish before inspecting its successful GOTO reconstruction.
Neither the earlier failed-model inventory nor the small paired fixture alone
completes the roadmap's successful-model inspection requirement.

The specialization build completed in 1,237.76 seconds with complete qualification
at `/nix/store/gik4xx7d3nrxvp7a65b47qmmwqqlp6kc-spaghetti-extractor-gnu-hello-ascii-string-compare-portable-c-work-package-provider-v2`.
Its shards satisfy 81/82 assertion properties, removing the four impossible
effect-capacity queries from each shard without losing the remaining checks.
The retained-model build completed in 1,097.36 seconds, also fully qualified:
`/nix/store/b48g1qfmrfb9hvvsnhami0bb3h177aj0-spaghetti-extractor-gnu-hello-ascii-string-compare-portable-c-work-package-provider-v2`.
Its contextual result file SHA-256 is
`06577ee902edc3eae8a3518f8131f78fb265d76d38b4919bf77fed5872f9bb7a`.
Current Python and Nix readers accept it and reject the same rehashed negative
mutations (`retained-models/check-readers.py` and adjacent JSON).

The initial inspection scripts reconstructed compilation units by hash across
all proof regions. A subsequent property replay exposed an invalid reconstruction:
identical source wrappers in the two regions include different local
`component-bisimulation.h` files. Matching the C hashes without preserving their
parent directories is insufficient. The earlier `qualified-model-inventory/` and
`retained-models/goto-inventory/` reconstructions are superseded as evidence of
the complete compiled model; the original qualified build receipts are unchanged.
The invalid entry replay is retained under `build/proof-query-timings/entry/`.

The corrected `inspect-parent.py` selects only the current region's compilation
units and header plus common connected/overlay inputs. It checks every selected
proof-input hash, the root and connected interface headers, and pinned tool
hashes. Reconstruction under `retained-models/corrected-goto-inventory/` still
contains 7,236/6,420 instructions and omits both the exact `spx_sub_0000933d` body
and the hidden source implementation. This is non-authorizing inspection;
a property replay of the corrected entry is recorded separately under
`build/proof-query-timings/entry-corrected/`.
The scalar milestone does not complete general memory/state/effect composition,
interactive latency, remaining pilot proofs, or linked/native activation.

Per-query diagnostics now append `query-timings.jsonl` records as compilation,
property discovery, safety queries, authored assertions, and nonvacuity queries
finish. Records include elapsed time, status, model and output hashes, and the
actual command. They remain outside authority receipts and preserve incomplete
results and exceptions. Each region also retains `compile-inputs.json` with
ordered compile arguments and path-qualified retained C/header hashes. This
preserves local include lookup; dependencies outside the diagnostic directory
remain external. Concurrent workers produce complete independent timing rows.
Twenty-four focused tests pass in 23.71 seconds. After the final path-normalization
adjustment, affected validation passes in 136.41 seconds, including selected
component tests and repository metadata, architecture, and lint gates. Commands,
logs, and the result are under `build/proof-query-timings/final-policy/`.

The corrected entry replay completes all 90 queries successfully in 616.26
seconds: four inventories, five nonempty safety partitions, and 81 assertion
queries. This excludes compilation, nonvacuity, the second region, and target
qualification. The slowest queries are connected-summary source readiness
(107.82 seconds), exit value (88.62), connected argument agreement (82.07), and
connected input-memory agreement (78.24). These runs overlapped validation and
a bounded joint-query experiment; they are not isolated comparative benchmarks.
The timing remains far beyond the planned 120-second larger-region budget.
The replay validates the corrected reconstruction's entry checks and identifies
costs; it does not authorize a fresh provider or native candidate.

The bounded joint-entry experiment under `build/proof-query-timings/joint-entry/`
checks all assertions from the paired entry in one query with the same model,
solver, unwinding limit, and slicing options. It times out at 300.06 seconds
and remains incomplete. No production query strategy or receipt policy was
changed. This measurement overlaps the partitioned replay and is not an isolated
speed comparison; it supplies no evidence for adopting a whole-entry query.
The next performance work must address the measured call-boundary and exit
obligations through checked region/summary structure rather than accepting an
incomplete result or restricting the input domain.

A later scalar-frame regression demonstrated that the summary wrapper copied the
exact context's reserved field into the source context despite the empty-frame
contract. The corrected wrapper keeps only the protocol-state capture and leaves
both context objects unchanged. Twenty-one scalar/connected tests pass in 6.02
seconds. The context-only real build completed in 1,044.15 seconds at
`/nix/store/wb6hxlsigpsf3spnnq2kkglgjl4145h0-spaghetti-extractor-gnu-hello-ascii-string-compare-portable-c-work-package-provider-v2`.
It predates the following cut-state correction and is superseded for authority.

The audit in `build/cut-state-completeness/audit.py` then constructed a local
initialized to zero, set to one before an authored cut, omitted from captures,
and added to the final result. The old checker incorrectly returned satisfied:
its resumed source re-ran the zero initializer. Compiler-derived local havoc now
makes the omitted value arbitrary at resume before restoring declared captures,
and the same audit returns a counterexample. Scalar and array regressions reject
the omission; a value overwritten before use still passes. Existing direct- and
pointer-member capture fixtures continue to pass.

The compiler inventory records lexical scope, declarations, assignments, and
address exposure. It retains only immediately initialized closed constants or
unchanged direct aliases of local storage; memory/input-dependent initializers
are overapproximated. BEGIN must be in the function's outer block, and its prefix
must not write outside automatic local storage, invoke effects, or bypass BEGIN.
Ambiguous shadowed mutable storage is rejected explicitly. These restrictions
remain supported-profile limits, not a claim of arbitrary source coverage.
The emitted inventory is a required bound proof input for cutpoint segments.
Both readers require the new policy and inventory, so merely setting a flag on
an old receipt cannot upgrade it. Historical pilot receipts in this document
must be rebuilt before they can serve as current authority.

Final affected validation for the local-state correction passes in 142.21
seconds (`build/cut-state-completeness/affected-command.json`, adjacent log and
result). Twenty-three focused inventory/integration/receipt tests passed during
development; the final affected selection includes the completed changes.
The Python and Nix readers both reject the historical context-only receipt and
a rehashed copy with the new policy flag but no inventory. Reproduction is in
`build/cut-state-completeness/check-old-readers.py` and its JSON output. The fresh
real scalar-caller build under `build/cut-state-completeness/pilot/` finished in
1,019.27 seconds with complete provider qualification and both regions satisfied:
`/nix/store/n9ap1giizdy70wbq62g6vf5aa3gjf82s-spaghetti-extractor-gnu-hello-ascii-string-compare-portable-c-work-package-provider-v2`.
Its bound compiler inventory identifies six mutable locals at `scan`; the
retained proof header applies their havoc before restoring captures. This is the
first scalar-caller result including both the cut-local correction and separate
caller-context preservation. The full roadmap, remaining pilots, native
activation, operator workflow, and portability exits remain incomplete.

The current scalar receipt passes both Python and Nix readers; each rejects
a rehashed mutation missing either the mandatory policy or local inventory.
`build/cut-state-completeness/check-current-readers.py` and its JSON record the
checks, including the retained inventory hash. A separate build of the remaining
Hello program-name, jq pipeline, and DX-Ball initialization pilots is running in
`build/cut-state-completeness/remaining-pilots/`; no outcome is yet claimed.

Public `component check` now includes a bounded explanation of failed proof
obligations, with a recorded source/proof location when available and a relevant
next step. The sidecar must match its recomputed receipt, selected component,
and qualification dependency. Missing or malformed diagnostics cannot turn an
incomplete qualification into success. Thirty-nine CLI/operator tests pass in
2.71 seconds, including public failure status, tampered identities, malformed
sidecars, bounded output, and recorded source locations. The historical Hello
and jq display check is retained in
`build/operator-proof-diagnostics/historical-pilot-display.json`; it exercises
diagnostics only and does not upgrade those historical proofs.

Affected validation for the operator diagnostics passes in 101.25 seconds,
including the selected tests and repository lint, metadata, and architecture
checks. Its exact command, log, and result are retained in
`build/operator-proof-diagnostics/`. This covers the diagnostic display increment;
automatic proposals, workspace source mapping, and measured interactive proof
latency remain open.


## Distinct capture sets and mutable parameter storage

A three-region acyclic fixture now captures `n` at its first cut and `final` at
its second. Valid composition passes; using the earlier uncaptured `n` after the
second cut or corrupting its incoming `final` relation rejects. These three solver
tests pass in 14.24 seconds. An assertion-inventory issue appeared when resuming
skipped a lexically earlier unexpected marker. Its alignment check now lives in
a shared helper called with the real predicate at marker visits and with true
from the harness, so one checked assertion remains discoverable in every region.
It supplies no assumption that a reached marker is aligned.

The follow-up storage audit found that ordinary interface parameters already
require reconstruction at each cut, but the generated context pointer was an
uncaptured automatic parameter. A source context pointer redirected to a local
context with reserved value one before the cut was reset to the original context
at resume. The checker falsely satisfied a source that returns two for input two
while the exact operation returns one. The recorded result is
`build/cut-parameter-state/context-before.json`; the reproducer and corrected
result are `build/cut-parameter-state/audit.py`, `reassigned-context.c`, and
`context-after.json` there.

The compiler inventory now includes every assigned or address-exposed automatic
parameter. Unchanged parameter addresses may remain as fixed aliases; their
mutable values are not retained. Readers require the replacement
`source_cut_storage_overapproximated` policy and `source_cut_storage_inventory`
role, binding the expanded inventory. All earlier pilot receipts above are
superseded for authority, including the 1,019.27-second scalar caller. The
remaining-pilot build already in flight uses the previous policy and supplies
only diagnostic evidence. A new current-policy qualification remains required.

The corrected pointer audit rejects on a source-language safety obligation: its
unconstrained pointer can be null because the relation omits its target. This is
an abstract-model counterexample, not a claim that the original source actually
dereferences null. Both Python and Nix readers reject the historical scalar
receipt and a policy-only upgrade with the old inventory role; see
`build/cut-parameter-state/check-old-readers.py` and its JSON.

The preceding remaining-pilot build finished in 864.45 seconds. Hello timed out
on exit value and the `program_name` observable, jq on typed-call fields at
position one, and DX-Ball on bounds, pointer, signed overflow, undefined shift,
and unwinding partitions. Reopened statuses and query details are in
`build/cut-state-completeness/remaining-pilots/observed-provider-status.json` and
`proof-diagnostics-summary.json`. All three qualifications are incomplete and
predate the mutable-parameter correction. The scalar caller is now rebuilding
under the replacement policy in `build/cut-parameter-state/pilot/`; no new
qualification is yet claimed.


The storage-only affected validation passes in 117.43 seconds. Its initial
failures were a guard-location test expectation and a documentation reference
to an ignored build artifact; corrected results are in
`build/cut-parameter-state/affected-result.json`. This predates the following
additional argument-binding check.

`build/cut-parameter-binding/audit.py` then reproduced a separate false acceptance:
a cut related logical parameter `count` to a constant local `shadow`, while the
original C parameter still affected the result. The exact entry cleared the
parameter register before the cut. Reconstruction reset the source argument
from that register, so the suffix proved a different source state. The saved
`before.json` is satisfied despite that mismatch; `source.c` and the audit retain
the case. The corrected `after.json` rejects the local substitution before proof.

Compiler argument ordering now binds interface parameters to actual source
argument identities, and lexical scope prevents a same-named local from standing
in for one. Renamed arguments are supported through the existing source bindings.
Every parameter requires an explicit capture; unsupported record reconstruction
cannot enter through the old implicit fallback. Both readers require a separate
`source_parameter_binding_inventory` proof input and
`source_cut_parameter_bindings_checked` policy. The storage-only scalar build
already in flight predates this check and is diagnostic until a final rebuild.
The historical scalar receipt and upgrades changing one or both policy flags
are rejected by both readers; the updated checks are retained under
`build/cut-parameter-state/`.

The storage-only scalar build finished in 1,096.57 seconds with a complete
qualification at
`/nix/store/mw8xd3d2dk4s2xfd8f9h4myl8sr8j1rh-spaghetti-extractor-gnu-hello-ascii-string-compare-portable-c-work-package-provider-v2`.
It predates the argument-binding policy and is superseded. The final rebuild
under both corrections is running in `build/cut-parameter-binding/pilot/`.
Argument-binding affected validation passes in 174.84 seconds before the final
explicit-argument requirement; the final selection is rerunning.


Final argument-binding affected validation passes in 155.22 seconds, including
the explicit-argument requirement (`build/cut-parameter-binding/`). The following
codec correction extends that checkpoint.

The codec audit in `build/cut-capture-codecs/` first found a constant parameter
encoding falsely passing even with the correct C argument bound. Parameters now
require the canonical scalar, byte-address, or resource-identity encoding that
the existing reconstruction actually supports. Noncanonical parameter codecs
reject before proof. A second fixture encodes a live source local as zero and
decodes it as zero; its forward relation holds while reconstruction loses the
actual value. With just the new round-trip checks removed to emulate the prior
rule, the incorrect doubled-result source satisfies both regions. The current
checker rejects at `spx-bisimulation-capture-roundtrip:loop:n` on the incoming
transition. This is a controlled emulation, not a saved historical qualification.

Both readers independently require round-trip assertion inventory entries for
machine-coded source values at next cuts; Nix also checks canonical parameter
encodings directly. Four focused integration/receipt tests pass in 2.41 seconds.
The separate Nix predicate test accepts its valid fixture and rejects omission
or constant-parameter mutations; it is diagnostic, not full qualification.
The audit scripts, exact results, and compact summaries are retained in
`build/cut-capture-codecs/`. The binding-policy scalar build already in flight
predates these assertions and cannot provide current authority.


Codec affected validation passes in 177.00 seconds, with metadata freshness and
whitespace checks also passing. Exact selection, logs, and result are under
`build/cut-capture-codecs/`. The argument-binding scalar build finished in
1,125.82 seconds with a complete qualification at
`/nix/store/0953cnildkaf0wv9gak7a43bb4hr5h60-spaghetti-extractor-gnu-hello-ascii-string-compare-portable-c-work-package-provider-v2`.
Both current readers reject that full receipt because its required inventory
lacks the decoder round-trip checks; the result is in
`build/cut-capture-codecs/check-old-full-receipt.json`. The final scalar build
under all corrections is running in `build/cut-capture-codecs/pilot/`, with no
new qualified or native/linked outcome claimed yet. The full roadmap remains
incomplete.


## Current codec-policy qualification and product checkpoint

The scalar build under all storage, parameter-binding and capture-codec
corrections finished in 1,084.57 seconds. Its provider is
`/nix/store/ccj9qz01fixa8dvl5s41jxpdd7aig4r1-spaghetti-extractor-gnu-hello-ascii-string-compare-portable-c-work-package-provider-v2`.
Qualification is complete, both entry and scan regions are satisfied, and both
current Python and Nix receipt readers accept the full proof. The command,
terminal build result and reader report are retained under
`build/cut-capture-codecs/pilot/`. This supersedes the pending build status above;
it does not establish fresh native/link activation or complete other pilots.

A hash-checked reconstruction of the historical jq model, retaining recorded
region-specific compile paths and pinned checker binaries, spent 8.09 seconds
in symbolic execution and timed out after 90 seconds in a diagnostic replay of
the second call-field assertion. This is evidence about solver cost, not new
qualification. Inputs, commands and results are under
`build/jq-proof-cost-profile/`; individual argument probes are also diagnostic.

The roadmap now carries a product checkpoint distinguishing proof progress from
unfinished assisted editing, standalone export, alternate-backend execution,
unfamiliar-application acceptance and independent reuse. No percentage of general
Win32 application coverage can be inferred from these pilot results.


## First unfamiliar-application boundary workflow

The public Metapad `component list` completed with 13,668 proposal rows. At RVA
0x5731, the old enclosing-span selector considered 207 candidates and selected
`component-proposal:1a13b67c26a6dfe13763`, a noncontiguous 126-unit region that did
not contain the requested unit. The production selector now uses the containing
graph unit, its bounded seed index, and its own ranking. Selected rich records
must contain that unit; modified graph/seed sidecars reject.

`component list TARGET --near RVA` exposes the resulting alternatives, including
JSON output. `boundary inspect` and `boundary propose` accept `--proposal ID` to
carry an explicit choice into the existing non-authorizing editable package.
The Metapad seed offers four choices. The selected nine-unit region
`component-proposal:71d147d4e0d726d92075` spans 0x5731 through 0x5762 and has no
discovery blockers. Static instructions show lone-CR conversion plus a stack
count update; discovery does not establish its typed memory or continuation
relations.

The actual public choices, inspection and draft-export commands pass in 1.30,
1.86 and 1.63 seconds respectively, each measured once with existing analysis
cached. These are navigation measurements, not proof or full import latency.
Commands, outputs and the old/new selection comparison are retained under
`build/metapad-trial/navigation/`. A persistent draft is at
`/home/conroy/src/spaghetti-extractor-trials/metapad/work/newline-normalization/`,
including a manually prepared instruction review and the unresolved interface,
alias, stack-origin and continuation requirements. It remains an explicit C
skeleton, not a qualified provider. The frozen input and scenarios are unchanged.

Affected validation passes in 113.59 seconds; exact selection, log and result
are under `build/metapad-trial/navigation/`. Tests cover actual-unit selection,
enclosing-span holes, wrong indexed membership, seed-specific ranking, stale
graphs, public explicit choice, and preservation of that choice in the exported
draft. The full roadmap and its pilot/native/port/repository exits remain open.

The jq field diagnostics are also terminal. Four returned-record word checks
each timed out at 45 seconds; the stream and constant-option checks passed in
28.74 and 27.58 seconds. These instrumented historical-model results identify
record-word propagation as the next cost investigation, not new qualification.

## First registered unfamiliar-application source edit

The previous skeleton checkpoint is superseded by a registered Metapad
`newline-normalization` component with authored source. Public `boundary adopt`
accepts reviewed canonical interface/binding inputs for the selected seed,
validates current proposal membership and identities, derives canonical digests,
and atomically exports the existing five-file intent layout. It preserves
blockers and draft activation. Canonical input authoring and external SDK
registration are still manual; this is not the completed assisted editor.

The first properly configured public source-start attempt exposed an unrelated
whole-application Behavioral-C coverage gate. The SDK now uses a review-only
invocation of the same canonical generator for component work packages. Its
Metapad artifact remains incomplete: 5,521 of 5,522 required units are lowered.
The normal generated-provider path retains complete coverage and compilation
requirements, and rejects this review artifact before invoking its compiler.
No incomplete artifact gained execution authority.

Public `component start --apply` then succeeded in 21.08 seconds. Authored C now
uses a typed writable text view and explicit count state to express the selected
lone-CR normalization region. Source checks pass against both installed and
work-package headers. The latter previously exposed a different signature;
the work-package renderer now shares the production component header renderer.
These checks establish syntax and interface conformance only.

Public development status reports incomplete with five blockers: text extent
and aliasing, frame-relative state projection, machine effects, continuation
registers, and contextual proof intent. Public `component check` exits 2 because
no provider qualification product exists. It does not yet offer an integrated
source-check/repair loop for this blocked component. No equivalence, native
activation, full-application scenario or platform port is claimed.

Commands and results are under `build/metapad-trial/component-review/`. The
public source-start measurement uses immutable toolkit snapshot
`/nix/store/8qdh0nd5s0crap63bdk3x2hg4wphdxrs-source`; the subsequent header fix is
checked in the current workspace and is not part of that snapshot. The frozen
original and scenarios are unchanged. Affected validation of review adoption
and review-stage wiring passed in 123.67 seconds, before the subsequent header
fix and regression-test additions. The full current-tree repository gates and
all roadmap exits remain open.

Checkpoint validation including the header fix and incomplete-review regression
now passes in 124.68 seconds; command, log and result use the
`checkpoint-affected` prefix in that evidence directory. Seven focused review,
header-compilation and incomplete-provider rejection tests also pass. Metadata
refresh reports current and whitespace validation passes. These targeted checks
do not replace the outstanding full repository or pilot/native gates.

## Public source feedback on the frozen trial

Public `component check --source` now builds a component-local source check from
the canonical source and interface packages. It uses the existing portable
object compiler helper with no object export or machine overlay, and the
existing source-profile checker. Its status and detailed compiler failures use
the existing non-authorizing operator formats. The default check continues to
require provider qualification. No proof, semantic or activation format changed.

The external Metapad toolkit is pinned to
`/nix/store/mmhb33i5c033xkyh1ag45rpdm8fm2xcx-source`, including the work-package
header correction and source-check workflow. The public trial reports:

| Command state | Exit | Seconds |
|---|---|---|
| First source check | 0 | 6.21 |
| Unchanged source check | 0 | 0.92 |
| Newly inserted compile error | 2 | 5.91 |
| Restored source | 0 | 0.95 |
| Default qualification check | 2 | 0.23 |

These are individual observations with existing analysis and toolchains cached;
they are not distributions or proof timings. The error case reports both host
and PE32 compiler failures at `components/newline-normalization.c:34:2`.
Source bytes were restored exactly. The new-error time exceeds the planned
five-second source-feedback budget. Forty focused CLI/operator regressions pass
in 2.97 seconds, including stale input/details rejection, compile-error repair,
profile failure despite successful compilation, and source success leaving the
default qualification blocked.

Commands, complete outputs, timing results, source backup/restoration hash and
snapshot identity are under `build/metapad-trial/source-feedback/`. The successful
source product is
`/nix/store/1axa6m0k9avmqy3hbhrkdnyyw5162bp4-spaghetti-extractor-metapad-newline-normalization-component-source-check`.
It grants zero authority. The five previously recorded Metapad proof blockers,
behavioral repair demonstration, required pilots, native activation, export,
platform port and independent reuse remain unfinished.

Affected validation initially caught a missing repository-map entry for the new
Nix constructor. After documenting it, the complete affected selection passes
in 76.35 seconds; the first failed result is retained with the `before-map`
prefix. Whitespace checks also pass. The retained recursive derivation graph
contains only the selected source, interface and source-check target phases,
plus toolkit-native/compiler infrastructure. It has no target extraction,
Behavioral-C or provider-proof dependency. Its 1,424 transitive derivations are
declared dependencies, not executed-build counts.

The next machine-side blocker is reproduced directly from the registered
Metapad interface and binding: the production state importer rejects its
`line_count` projection with `component scalar state requires an exact static
slot`. The binding schema admits memory addressed through EBP minus four, but
the scalar state importer/exporter currently handles static image slots.
Supporting that frame-relative word requires checked address/state preservation
and alias relations, not substituting an arbitrary static slot or deleting the
blocker. The non-authorizing reproduction is retained in the same evidence
directory.

## Frame-relative state adapter and remaining proof limitation

The static-slot-only renderer checkpoint above is superseded for scalar memory
state. The common address rule now validates 8/16/32-bit read-write state at a
32-bit register plus an optional signed displacement. It checks observation
phases, width and matching entry/exit address expressions. The production
adapter captures the imported address and rejects a changed address before
export. It retains memory-fault handling and existing write-restoration behavior.
The proof checks address preservation during cut reconstruction, shared input
bytes, and equal addresses and byte snapshots at exit. No alias-disjointness
assumption is introduced.

The actual Metapad interface, binding and nine selected canonical transfers now
render an adapter. Its authored source, conformance unit and machine adapter all
compile with both host and PE32 compilers. The transfer plan as a whole remains
incomplete; this was a non-authorizing selected-unit compilation, with all five
binding blockers preserved. The external target SDK remains pinned to the prior
source-feedback snapshot; the adapter diagnostic uses the current workspace.

Thirty-two focused tests pass in 0.51 seconds. CBMC checks the generated adapter
for arbitrary frame addresses, read/write faults and address changes. A deliberate
aliasing mismatch fails. Cut reconstruction rejects changed addresses and altered
memory, and exit relations reject equal values stored at different frame
addresses. Wrapped-address snapshot checks preserve mismatched-byte detection.

A full contextual-checker fixture exposed a spurious exit-read failure at
EBP=2: both executions fault on the four-byte access, but the old comparison
reissued that faulting read. Total byte snapshots now handle that case. The
next full run remains violated at `spx-bisimulation-private-write-containment`:
the arbitrary frame word can straddle the proof model's private/public boundary.
This is the next model limitation to resolve. The input domain was not narrowed
to avoid it, and no complete frame-state or Metapad qualification is claimed.
Inputs, generated adapter, compiler checks, full failed checker reports and
retained proof inputs are under `build/metapad-trial/frame-state/`.

The complete affected selection passes in 183.46 seconds, with command, terminal
result and log retained in that directory. Generated metadata is current and
whitespace validation passes. These checks validate the implementation change;
they do not discharge the recorded full-checker containment failure or the
remaining pilot/native/port/repository completion requirements.


## Crossing-memory stores and complete frame-state fixture

The preceding private-write-containment limitation is resolved. A store touching
both partitions is logged once in each affected history; byte reads select the
history for that byte. Classification includes interior bytes, and partial
aliases invalidate exact stack-word caches. Connected replay uses the same
writer. Both histories use the full structural write bound, with capacity and
public-memory equality still checked.

The complete contextual frame-state fixture now reports satisfied with no
issues, including arbitrary EBP and fault outcomes. Its diagnostic inputs and
report are retained under `build/metapad-trial/frame-state/proof-fixture-v4/`.
The v3 diagnostic stopped at a relative input-path compile error and supplied no
proof evidence. A durable integration test also changes the source increment
from one to two and requires rejection at the state observable. Separate solver
tests compare three arbitrary overlapping writes against last-written-byte
semantics, exercise private islands inside words, check cache invalidation and
faults, and detect an intentionally stale cache. Connected replay has a crossing
write regression.

This discharges the synthetic frame-state model limitation, not Metapad's region
qualification. Its text extent/alias relation, contextual intent, continuation
register relation, effect projection and frame-state integration remain explicit
binding blockers. The external SDK is still pinned to the source-feedback
snapshot. Required pilots, fresh native activation, standalone export, platform
port, independent trial and full repository validation remain open.

Affected validation passes in 121.81 seconds. Its command, terminal result and
log use the `crossing-affected` prefix under `build/metapad-trial/frame-state/`.
The first run failed only at an obsolete raw-write-copy code-generation
expectation; that run remains under the `before-expectation` prefix. The updated
check requires replay through the common writer. Registry refresh and whitespace
validation pass. These are affected checks, not the outstanding full current-tree
pilot, native, port or repository completion gates.


## Metapad count/text alias review

The actual nine-unit region and installed authored source reproduce a count/text
alias mismatch under the current binding's admitted inputs. With ESI at
`0x10000`, EBP at `0x10004`, EBX zero and bytes CR/NUL/zero/zero, the binary changes
CR to LF and then reads the count word. The source adapter imports that word
before the text loop and restores its old CR value at export. The retained CBMC
counterexample is `count-text-alias`. This does not establish that the original
application reaches the witness; caller-frame and alias obligations were already
explicitly unqualified.

A revised draft represents the count word as a borrowed four-byte view and reads
it after normalization. It passes the same witness. A further bounded diagnostic
covers arbitrary bytes with a terminator within the first four bytes, arbitrary
32-bit count delta, and a four-byte count word starting at offsets zero through
four in the same eight-byte object. All eight output bytes, outcome kind and EAX
agree. Neither diagnostic proves unbounded behavior, continuation flags/registers,
caller obligations, arbitrary memory faults or whole-region qualification.

Production view-base rendering now shares the scalar-state register-address
rule with proof projection rendering. Tests cover modular positive/negative
arithmetic, phase mismatch, narrow registers, nested offsets and oversized
displacements. The revised source, conformance unit and complete machine adapter
compile with both host and PE32 compilers. Evidence, exact selected generated C,
source/binding hashes, commands and counterexamples are retained under
`build/metapad-trial/alias-review/`.

The first public adoption attempt rejected an already configured seed. Reviewed
seed revisions now use the same public export path while checking the configured
component identity; stale proposals and nonempty destinations remain rejected.
This exports canonical draft inputs and does not grant qualification or replace
installed source automatically.

The canonical reviewed revision is now installed in the external target. Its
public configured-seed adoption succeeded in 8.61 seconds. The first revised
view draft mixed fields from two projection forms and was rejected; the final
`view` projection passes strict adoption and the repeated bounded diagnostic
under `canonical-bounded/`. Its generated adapter and authored C are byte-identical
to the compiler-checked files. Installation preserves the component's source
catalog and draft selection; previous interface, binding, indexes and source
are backed up with before/after hashes in the evidence directory.

The external SDK now pins toolkit snapshot
`/nix/store/pv1d9pzc7hmmb1pz5aivwsnagc4yd7vd-source`. Public source checking passes
in 14.80 seconds for the first revised check and 1.09 seconds unchanged. These
single observations ran alongside affected validation and are not normalized
edit-latency distributions. The normal qualification check exits 2 in 0.21 seconds
because no provider qualification product exists. An earlier attempt stopped
at an unsupported JSON option and is retained separately as an argument error.

The binding retains five blockers: text extent/alias relation, contextual proof
intent, continuation registers, machine effects and the unqualified frame-relative
count view. No disjointness assumption was added to suppress the witness.
The diagnostic checks remain outside the public behavioral proof/repair workflow;
unbounded qualification and candidate selection have not been demonstrated.

The complete affected selection passes in 195.10 seconds; its exact command,
terminal result and log are retained in the same evidence directory. Twenty-one
focused component tests and six public-review tests also pass. Generated metadata
and whitespace checks pass. The full current-tree pilot/native/port/repository
completion gates remain outstanding.

## Normal-exit result checking

Investigation of the Metapad continuation exposed a general checker defect:
declared logical register results were compared only on `SPX_RETURN`. A retained
full-engine fixture writes EAX 7 on the exact side and returns 8 from authored C
before a machine fallthrough. The previous checker incorrectly reports
`satisfied`. Logical result equality is now checked on fallthrough, jump, branch,
return and indirect jump. Fault and nonlocal outcomes retain their separate
outcome relation. This does not establish preservation of undeclared continuation
registers or discharge Metapad's caller-context obligations.

The full-engine regression checks correct and incorrect results for fallthrough
and direct jump. Each run builds and validates a contextual receipt over the
production exact slice and machine overlay. Correct values satisfy the proof;
incorrect values fail `spx-bisimulation-exit-observable:run:result:value`.
Retained inputs, results and reader checks are under
`build/metapad-trial/normal-exits/`. These are synthetic fixtures, not application
qualification or evidence for every continuation outcome.

Both Python and Nix require `normal_exit_results_checked` and
`exact_stack_cache_partial_overlaps_invalidate`. The latter replaces a stale
claim that partial writes were excluded by an assertion. Checker options now
also describe partial-overlap invalidation. Reader checks reject absent and
false values for either field, including mutations with recomputed receipt
digests. A violated proof remains a valid diagnostic receipt in Python but
fails the Nix consumer's satisfied/activation checks. The saved scalar ASCII
pilot receipt is rejected under the new policy and requires rebuilding.

The affected selection passes in 170.11 seconds, including the full-engine
normal-exit regression. Its command, terminal result and log are retained in
the normal-exit evidence directory. Metadata refresh and whitespace checks pass.
This does not close the full current-tree pilot/native/port/repository gates.

## Metapad failed-view-read outcome

A separate diagnostic uses the same nine generated units and installed authored
source as the canonical alias check, with a concrete failure on the initial text
read. Reference resolution succeeds, but the runtime read reports a fault. The
exact region takes its memory-fault exit; the source callback returns a failed
access status and the authored operation returns zero. Its adapter then produces
`SPX_FALLTHROUGH`, failing `outcome-kind`. The callback's local fault does not
update the operation adapter's memory-fault flag.

The retained inputs and trace are under `build/metapad-trial/view-fault/`.
The authored-source digest remains
`21dda686aca717f815de89af7a5174b1412b8e17a5d9b559db5de72c5838ba2d`.
This is a static diagnostic, not original-application execution or a claim that
the witness is reachable under a qualified caller/environment contract. The
earlier bounded alias diagnostic covered successful accesses. The failed-access
outcome requires an explicit contract and checked implementation; no assumption
excluding it or blanket conversion of recoverable view errors has been added.

Following the diagnostic into the production proof world establishes a narrower
boundary: both exact and source reads return arbitrary bytes successfully for
every width from one through four that does not wrap the address space. They do
not model an independently unreadable page at the injected address. Consequently
this injected-read-failure witness is outside that proof world's domain. It is
evidence of missing failed-access coverage for the broader portability goal,
not a counterexample within a previously qualified Metapad contract. Origin and
permission checks alone do not discharge the separate obligation to connect
this memory model to a concrete platform's admitted accesses.

## Public feedback before qualification exists

The current CLI now loads the available canonical binding intent when
`component check` has no qualification product. On the external Metapad target
it reports all five declared blockers, the exact binding artifact path and a
development-status command preserving the external target flake and `--local`.
Both checks exit 2, in 0.49 and 0.46 seconds respectively. These single warm
observations were recorded while the updated-policy ASCII pilot build ran;
they measure prerequisite feedback, not solver or source-edit latency.

The external SDK pin and installed source remain unchanged. The current CLI
source identity, commands and outputs are under
`build/metapad-trial/contract-feedback/`. Stale or foreign binding payloads are
rejected before their declared blockers are displayed. An absent binding or
empty blocker list still cannot grant qualification. This improves the public
prerequisite feedback but leaves the behavioral diagnose/repair/qualify cycle
and all five local binding obligations open.

The emitted development-status command was executed verbatim. It reports the
same five blockers with `status=incomplete` and `authority=not-applicable`,
returning 0 for successful status retrieval. The first retrieval took 20.13
seconds and the repeated retrieval 1.23 seconds. The latter remains above the
planned one-second warm status target; neither is a qualification success.
The complete affected selection passes in 123.24 seconds, including the public
diagnostic regression and its external-flake command check.

## Scoped Metapad loop-plan preparation

The component semantic loader previously demanded a globally complete transfer
plan even when every selected unit was compiled. It now admits unrelated missing
units only when each omission has a semantic-qualification or semantic-lowering
blocker bound to its inventory entry. A selected unit, overlapping source range,
compiled-unit blocker, unknown scope or identity-validation failure rejects the
selection. Unexplained omissions also reject it. The complete original transfer
payload and hash remain bound to the region; no incomplete plan is promoted.
Whole-plan consumers using complete admission still reject the same input.

This admits the nine Metapad units without ignoring the unqualified unit at
`0xa372`. The resulting kernel semantic contract is satisfied while its normalized
binding and global transfer plan remain incomplete. A draft inserts one source
sync at the loop-body entry corresponding to `0x5737`, capturing the parameters,
EAX-backed index and current character. Its proposed invariant relates the
character to the current text byte, excludes zero, and bounds the lookahead.
The canonical plan has nine exact units, 14 edges, two obligations and no
materialized paths. Source-profile checking passes. The first source marker used
a different capture order and was rejected; the retained draft uses the binding
order. The invariant, caller domain and continuation have not been proved.

Editable inputs are retained in the external trial's
`work/newline-normalization-proof/`; exact evidence is under
`build/metapad-trial/loop-plan/`. The installed source, binding and SDK pin are
unchanged, and all five installed blockers remain open. No provider or runtime
authority is granted by this preparation.

## Metapad direct loop proof

The two-obligation success below is historical and superseded by the
[value-contract correction](#logical-view-contract-correction). It was not a
proof over the declared fixed count-view domain.

The first direct run rejected the proposed logical-carry capture because the
existing source header renderer requires a machine projection for that form.
The draft now uses the supported logical definition `current = text[index]`.
The next run exposed missing inverse reconstruction of a register-relative
view base. The canonical machine-storage helper now restores the source base
register by subtracting the signed displacement modulo 32 bits. Focused CBMC
checks cover the full signed displacement boundary, arbitrary original bases,
unrelated-register preservation and malformed projection rejection.

With reconstruction working, entry proved, but scan stopped on a safety-inventory
mismatch. Full standard instrumentation renumbers automatic function-pointer
guards, and cutpoint reachability removes the initial callback. The v9 query
strategy now selects static safety IDs under consistent instrumentation, while
the unsliced unwind query retains its own intrinsic baseline. Baseline IDs can
never excuse missing or extra static checks. A real callback-after-cut regression
passes and rejects invalid-pointer, array-bounds and insufficient-unwind cases.
Earlier v8 receipts are invalid under this command strategy.

The fourth retained direct attempt satisfies both obligations with a ten-second
limit per query: entry has 60 authored properties and 65 queries; scan has 61
and 66. Source profile, canonical plan and strict model/shard evidence validation
pass. The Nix safety-selection predicate accepts both inventories and rejects
missing selected properties and extra baseline IDs in a static query. Evidence
is under `build/metapad-trial/loop-plan/proof-attempt-4/` and
`build/metapad-trial/safety-selection/`; the prior editable draft is preserved
before updating `work/newline-normalization-proof/` in the external trial.

This is direct checker evidence for the proposed model, not a provider
qualification. No proof-world/object-authority receipt was invented to promote
the result. The installed source, binding and SDK pin remain unchanged and the
five installed blockers remain open. Caller/view-domain admission, exposed stack
ownership, continuation registers and public qualification integration still
need proof. The existing memory model excludes the injected failed-read case
described above; this successful run does not expand that domain.

## Public proof-intent review

`boundary adopt` previously exported the reviewed interface and binding while
ignoring an optional proof intent. It now accepts editable `bisimulation.json`,
refreshes only its derived digest and exports the canonical intent and lifting
reference in the existing atomic output-directory transaction. It rejects
foreign components/operations, cuts outside the selected region, unsupported
formats, extra fields and nonregular input files. Blockers and draft activation
are preserved even for a structurally valid false invariant; review is not proof.

The public command exported Metapad's actual successful diagnostic draft to
`work/newline-normalization-proof/adopted-intent/` in 12.298 seconds. The exported
intent digest matches the proved draft, and the binding remains incomplete with
all five blockers. Hash checks confirm the installed target, source and SDK pin
were unchanged. Command, timing and validation evidence are retained under
`build/metapad-trial/proof-review/`. The interface, binding and inspection used
for review are in the draft's `inputs/` directory. Installing the reviewed inputs
and qualifying the admitted caller/view and continuation contracts remain open.

## Logical view-contract correction

Tracing the caller domain exposed a projection defect: the text and four-byte
count share the physical `text_bytes` pointer type, and the logical projection
used the first occurrence's NUL extent for both. The previous proof therefore
restricted the count view incorrectly and registered it as a second NUL view.
Logical type uses now retain their own extent, access, interpretation, nullability
and representation, with deterministic identities independent of parameter order.
Ambiguous nested uses reject instead of inheriting an arbitrary sibling contract;
nullable views without a supported logical representation reject explicitly.
The new view-contract policy is required by both Python and Nix receipt readers.

The fifth direct Metapad run exposed two exit-control counterexamples. At entry,
a one-byte NUL view aliasing the four-byte count caused the proof resolver to
shorten the count extent. The resolver now preserves at least the requested
range in the existing arbitrary-public-memory model. Its solver regression checks
both the larger fixed view and the shorter NUL view at the same base.

The sixth run restores entry success (60 authored properties, 65 queries), while
scan remains violated. Its witness reconstructs the count address as
`0xfffffffd`, so the four-byte range wraps and the source wrapper faults before
reaching the cut. The earlier scan witness placed that view inside the proof's
private stack window. The sync currently carries non-nullness but not the full
fixed-view admission contract. Those conditions must be checked at the outgoing
cut before being assumed at resumption; do not hide the failure with an unchecked
precondition or disjointness assumption. Exposed stack ownership and caller
admission remain separate qualification work.

The earlier successful draft and public review export remain historical,
non-authorizing inputs. Current evidence is in
`build/metapad-trial/loop-plan/proof-attempt-6/` and
`build/metapad-trial/value-contracts/`. The installed target and its five blockers
remain unchanged. Focused tests verify distinct fixed/NUL extents, access and
reference nullability, nullable-view rejection, and rejection of missing/false
view-contract policy even after receipt digests are refreshed.

## Recorded ASCII pilot rebuild

The rebuild following normal-exit result checking completed in 1,245.05 seconds.
The scan sync shard is satisfied, but the entry shard remains incomplete because
`spx-bisimulation-exit-value:compare:spx_bisimulation_check_0000` exceeded 300
seconds. Both provider proof facets remain incomplete and activation is false.
Python accepts the bound diagnostic receipt; the Nix proof-system checks pass,
but its satisfied/activation acceptance predicate rejects the result.

The provider is
`/nix/store/06qan8jip5gz095qd0ird8s7g1irmg0y-spaghetti-extractor-gnu-hello-ascii-string-compare-portable-c-work-package-provider-v2`.
Commands, inspection and reader results are under
`build/metapad-trial/normal-exits/pilot/`. This supersedes the historical scalar
qualification as the latest pilot observation. It predates the v9 safety-selection
strategy and is not current authority. It does not establish a regression within an
unchanged model: both memory behavior and checked result coverage changed.
Further pilot runs are batched at integration checkpoints; focused mechanism
regressions and affected checks support the intervening work.


## Checked view admission at cuts (2026-09-06)

The eighth direct Metapad run satisfies both obligations: entry has 61 authored
properties in 66 queries, and scan has 62 in 67. A machine-coded parameter view
is checked at each outgoing cut for a nonzero address, a non-wrapping requested
extent and no overlap with either modeled private window. The resumed-input
assumption uses the identical predicate. Null, wrapping, private and partially
private ranges fail the focused solver regression even when captured addresses
agree; the highest valid four-byte range succeeds.

The seventh run checked the assertion but omitted it from the required manifest:
its producer tested a parsed projection as if it were a raw mapping. The strict
reader rejected that receipt. The producer now shares the header's classifier,
and a regression checks the manifest using the parsed canonical intent.
Both readers accept attempt eight and reject removal of its admission assertion
after refreshing the inventory digest. The Python reader also rejects attempt
six's predecessor evidence without the new assertion.

Evidence is under `build/metapad-trial/loop-plan/proof-attempt-8/` and
`build/metapad-trial/cut-view-domain/`. This is a direct diagnostic proof, not a
qualified provider or linked object. It transports the existing domain rather
than establishing real caller ownership or exposing private stack storage.
The installed target's five blockers, source, binding and SDK pin remain
unchanged. The public proof/repair cycle and caller qualification are still open.
Focused validation passes 23 tests in 0.600 seconds; full pilots remain deferred
to the integration checkpoint.


### Resumed stack anchor correction

The first affected validation passed in 182.77 seconds. A subsequent focused
solver case found that the outgoing check used the preceding private window,
while the next shard rebuilds that window around its captured ESP. Address 10000
was admitted before ESP moved to 9000, which makes that view private on resume.
The regression reproduced the mistaken success before the correction.

The shared predicate now derives the resumed window from the captured outgoing
ESP and checks its bounds as well as the view range. The regression checks
admission and rejection after stack movement in both directions, and rejects
invalid stack anchors. Both readers require the new resumed-view assertion;
attempt eight's check of the old window is insufficient and is rejected.

The ninth direct run satisfies both obligations with the same 61/62 authored
property and 66/67 query counts. Both readers accept it and reject omission of
the revised assertion after refreshing its digest. Evidence is under
`build/metapad-trial/loop-plan/proof-attempt-9/` and
`build/metapad-trial/cut-view-domain/`. The focused group passes 23 tests in
0.808 seconds; the additional reader regression rejects both an absent assertion
and its obsolete predecessor. Caller ownership and full resumption-domain
qualification remain open; this result establishes the checked view predicate
under the modeled domain, not a qualified real caller. No full pilot was rebuilt.


Final affected validation for the resumed-window correction passes in 170.33
seconds, including the changed solver and receipt regressions and repository
metadata/architecture checks. No full pilot was rebuilt.

### Concrete caller frame at the selected entry

A diagnostic traversal of the frozen canonical transfer plan starts at RVA
0x56b5 with text bytes CR, X, NUL, an initialized stack, and the original global
at 0x410f6c set to one. It reaches the selected entry at 0x5731 without taking an
external call. The production transfer evaluator reports the count cell EBP−4
at ESP+8. Its complete four-byte range is inside the current proof's private
window, so that concrete path does not satisfy the current view domain.

The case, exact unit trace, input hashes and resulting frame are retained under
`build/metapad-trial/caller-frame/`. This is a diagnostic traversal of canonical
transfers; the original PE was not executed and the whole transfer plan remains
incomplete at its unrelated blocked unit. It neither proves all caller paths nor
supplies ownership authority. It establishes a concrete reason to implement
checked exposed stack storage and shared byte observations before treating the
inner-region proof as applicable to its real caller.


## Shared stack-span proof primitives (2026-09-06)

The proof-world renderer now has an opt-in, bounded set of shared spans inside
its stack window. Registration occurs before either paired execution has writes,
source-frame initialization, calls or atomics; malformed ranges and capacity
exhaustion fail checked assertions. Spans change visibility, not byte contents or
permissions. The shared union is independent of registration order, handles
partial overlap and crossing writes, and cannot expose fixed private objects.
World reset clears the registrations.

An explicit range-equality primitive compares the current effective bytes even
while the range remains private. Its negative case demonstrates that a difference
ignored by the ordinary public-memory comparison is rejected when that range is
proposed for sharing. The comparison validates the full extent without wrapping
and quantifies over the address, rather than enumerating every byte.

Nine focused tests pass in 1.942 seconds, including the observed caller's ESP+8
cell, paired aliases and mixed stores, omitted writes, source-frame clobbers,
unordered span unions, gaps, protected private objects, late registration,
capacity, reset, and extent boundaries. An earlier combined world/reference group
passed 22 tests in 19.856 seconds before the additional range-comparison cases.
Evidence is retained under `build/metapad-trial/exposed-stack/`.

The ordinary harness continues to use zero exposed spans. These primitives do
not authorize the Metapad caller or widen its current admitted domain. The next
integration must derive spans from canonical boundary contracts, establish byte
relations before those spans become shared at a cut, and bind those obligations
in receipt evidence. Caller ownership and the installed five blockers remain
open. No full pilot rebuild is needed for this primitive batch.


Affected validation for the shared-span primitives passed in 182.24 seconds,
including solver fixtures and repository metadata/architecture checks. The
normal proof harness and installed trial inputs remain unchanged by this batch.

Integration must retain the canonical adapter's extent rules: a fixed view uses
its declared extent, a bounded byte view uses its related extent parameter, and
a NUL view uses the resolved origin remainder. Exposing a requested minimum alone
is insufficient for the latter. At a cut, the next view's complete admitted range
must have a checked byte relation before reconstruction. The existing store
capacities already bound both histories by the full local write inventory, so
possible stack/public aliases must retain that bound during integration.


## Captured view bytes in the normal cutpoint path (2026-09-06)

The production proof header now asserts byte-range equality for every
machine-coded view and byte-view parameter capture. It uses the captured machine
address and the source view's visible extent, comparing effective bytes even
when they are currently private. Both readers derive this per-view requirement
from the planned captures. A shared classifier handles parsed projections in the
producer and manifest builder, avoiding the earlier parsed-object/mapping error.

A solver regression gives both captured views the same address but different
private contents. The ordinary public comparison succeeds because it omits those
bytes; the new capture-memory assertion rejects the difference. Fixed and byte
view captures both appear in the semantic-goal inventory. Public component-check
regressions retain the failing view and bound source location, and provide a hint
to inspect preceding writes and aliases; admission failures instead point to the
view's extent and ownership.

The tenth direct Metapad run satisfies entry with 63 authored properties in 68
queries and scan with 64 in 69. Both readers accept it and reject removal of each
individual captured-view memory assertion after refreshing its inventory digest.
They also reject attempt nine, which lacks the new assertions. Evidence is under
`build/metapad-trial/loop-plan/proof-attempt-10/` and
`build/metapad-trial/cut-view-memory/`. The focused cut/reader/operator group passed
14 tests in 0.748 seconds before the additional missing-memory reader case.

This consumes the range-comparison primitive in the normal proof path. It does
not yet register shared spans there or establish complete view-state transport:
extents, metadata and access methods must reconstruct correctly before the stack
admission domain can be widened. The concrete ESP+8 caller path remains outside
that domain, and the installed target's five blockers and qualification status
remain unchanged. No full pilot was rebuilt.


Affected validation for the captured-view byte checks and operator diagnostics
passed in 182.63 seconds. No full pilot was rebuilt.

A separate draft mutation clears the text view's `read_u8` callback after one
iteration, by casting the borrowed view pointer back to its mutable underlying
struct type. Its source profile passes. Entry remains satisfied, but scan is
incomplete after a 10-second timeout on its exit-world-memory assertion. This
is inconclusive evidence, not a successful proof of the mutation and not an
explicit access-method rejection. The retained case is under
`build/metapad-trial/loop-plan/proof-view-callback-mutation/`.
The installed source and target remain untouched.

The next transport work must check view access methods and metadata, rather than
infer their preservation from equal captured addresses or visible bytes. A
canonical entry-view snapshot can supply the access-method comparison at each
outgoing cut; generated snapshots must be excluded from source-local havoc and
bound into the proof header. This must accompany, not replace, full extent and
context reconstruction before shared stack-span admission is enabled.


## Checked access-method transport (2026-09-06)

BEGIN now snapshots each captured view's canonical entry realization in generated
storage. Outgoing cuts assert equality of the byte and span read/write method
pointers, and the resumed relation assumes that same tuple. The generated
snapshots use the actual bound C argument, including a renamed parameter, and
are not part of source-local havoc. Both readers require each view's method
assertion. Method checks receive early query priority alongside exit control so
a precise failure can be reported before expensive aggregate memory queries.

The unchanged eleventh direct Metapad run satisfies entry with 65 authored
properties in 70 queries and scan with 66 in 71. Both readers accept it and reject
removal of either individual method assertion after refreshing its inventory
digest. They reject attempt ten, which lacks those assertions.

The retained callback-clearing mutation now violates
`spx-bisimulation-capture-methods:scan:text`. Its failing query takes 0.5805 seconds,
starting 3.7471 seconds into the scan obligation's retained timing sequence.
These are query/obligation observations, not a whole operator-cycle measurement.
The strict reader accepts its bound diagnostic evidence while the proof remains
violated. The earlier 10-second memory-query timeout is superseded as the current
observation for this mutation.

The focused cut/storage/reader/operator group passes 21 tests in 1.467 seconds.
An additional renamed-view regression passes and still identifies the logical
capture when its actual C argument has another name. Evidence is under
`build/metapad-trial/view-methods/`,
`build/metapad-trial/loop-plan/proof-attempt-11/` and
`build/metapad-trial/loop-plan/proof-view-callback-mutation-checked/`.

Method identity is only one part of view-state transport. Extent, reference
metadata, opaque context contents and caller ownership still need their checked
relations before the normal harness may register shared stack spans. The current
harness continues to register none, and the installed trial's source, binding,
five blockers and SDK pin remain unchanged. No full pilot was rebuilt.


Affected validation for the access-method batch completed successfully in 185.19
seconds; its terminal result is under
`build/metapad-trial/view-methods/affected/`.

## Checked reference-metadata transport (2026-09-06)

A direct Metapad mutation changed the count view's reference permissions from
read/write to read-only after advancing the loop. The previous checker reported
both shards satisfied: reconstruction restored the original permissions at the
next cut. This is retained under
`build/metapad-trial/loop-plan/proof-view-permission-mutation/` and is not authority.

Outgoing cuts now compare each captured view's reference domain, generation,
offset and permissions plus element width against its entry snapshot. The proof
resolver reconstructs these fields canonically. Resumption assumes this same
checked relation; address transport still has its machine codec. Both evidence
readers require `spx-bisimulation-capture-metadata` for regular and byte views.
The production checker now rejects the mutation at `scan:line_count`; the failing
query took 1.421 seconds, starting 4.425 seconds into that scan obligation.
Evidence is under
`build/metapad-trial/loop-plan/proof-view-permission-mutation-checked/`.

The unchanged draft's attempts twelve and thirteen pass entry but time out in
scan's aggregate memory comparison with a 10-second per-query limit. Attempt
thirteen ran without another direct proof job. A retained single-query replay
passes in 12.173 seconds with a 30-second limit; the older attempt-eleven query
passes in 8.620 seconds. This isolates a query-cost increase and does not convert
either incomplete receipt into satisfaction. Replay commands, retained models
and outputs are under `build/metapad-trial/view-metadata/query-probe/`.

Extent transport, opaque access-context contents and caller ownership remain
unfinished. The normal harness still exposes no shared stack spans, and the
installed Metapad inputs and five blockers remain unchanged. No full pilot was
rebuilt for this batch.

Attempt fourteen then passes both unchanged direct obligations at a 30-second
per-query budget: entry has 67 authored properties in 72 queries, scan 68 in 73.
Both readers accept its bound evidence and reject each omitted metadata assertion
individually even after the required-inventory digest is refreshed. Both reject
the preceding attempt-eleven evidence without metadata checks. The Python reader
also accepts the permission mutation's bound diagnostic result while the proof
remains violated. Evidence is under
`build/metapad-trial/loop-plan/proof-attempt-14/` and
`build/metapad-trial/view-metadata/`. Production query limits remain unchanged.

Focused cut/view, storage, receipt and operator validation passes 21 tests in
2.857 seconds, including each metadata field, C-parameter renaming, temporary
permission changes restored before the cut, and independently omitted required
view checks. The receipt-reader and focused logs are retained under
`build/metapad-trial/view-metadata/`.

Affected validation for this batch passes in 183.50 seconds, including selected
solver, compiler, native and pure tests plus metadata, production lint and
architecture gates. Command, log and terminal result are under
`build/metapad-trial/view-metadata/affected/`. Installed source, interface and
binding hashes were rechecked unchanged. Full pilot qualification, selected
link/native activation and final repository/port gates remain outstanding.


## Checked callback-context reconstruction (2026-09-06)

The view-context declaration is now shared between the native overlay and proof
header. Protected BEGIN snapshots retain context and runtime state. Outgoing
cuts require the canonical byte/span context alias, context identity, runtime
identity and every runtime member. Context permissions must remain canonical;
context address and extent must match the reached projection and visible view.
The complete 64-bit reference object must equal the projected machine address,
so its high bits cannot disappear through the older 32-bit address codec.
Resumption assumes the same checked relation. Both readers require
`spx-bisimulation-capture-context` for regular and byte views.

The ABI coverage test caught an initially missing `execute_typed_x87_operation`
member; the final snapshot includes it and every other runtime member. Focused
checks cover changed context contents behind a stable pointer, changed identity
or runtime, dispatch mutations, restored permissions, consistent address/extent
transport, renamed C parameters and high address bits. The focused group passes
23 tests in 12.648 seconds, with logs under `build/metapad-trial/view-context/`.

The earlier null-context mutation is inconclusive: its unsliced unwind check
reports an unexpected safety-property inventory, including a recursion property.
It is retained under
`build/metapad-trial/loop-plan/proof-view-context-mutation/` and is not evidence of
false success. A separate mutation changes permissions inside the actual context
without replacing its pointer. The checked direct run rejects it at
`scan:line_count`; its failing query takes 1.128 seconds, starting 5.543 seconds
into the scan obligation. Evidence is under
`build/metapad-trial/loop-plan/proof-view-context-permissions/`.

The unchanged fifteenth direct attempt passes both obligations. It precedes the
final full-width address conjunct; final direct evidence is recorded below.
Canonical visible/reference extent reconstruction, pointed-to world state and
caller ownership remain separate obligations. The normal harness still exposes
no shared stack spans. No full pilot was rebuilt for this batch.

Final attempt sixteen satisfies entry with 69 authored properties in 74 queries
and scan with 70 in 75, using the prior measured 30-second per-query budget.
Both readers accept this diagnostic evidence and reject removal of each context
assertion individually, including when the required-inventory digest is refreshed.
They reject attempt fourteen, which lacks context checks. The final context
mutation is rejected at `scan:line_count`; its failing query takes 1.142 seconds,
starting 5.830 seconds into the scan obligation. Its bound diagnostic evidence
passes the Python reader while proof status remains violated.

Final evidence is under `build/metapad-trial/loop-plan/proof-attempt-16/`,
`build/metapad-trial/loop-plan/proof-view-context-permissions-final/` and
`build/metapad-trial/view-context/`. The generated native overlay source hash
matches attempt fourteen byte for byte; declaration sharing does not change
native callback behavior. Production query limits and installed trial inputs
remain unchanged. The full pilot, link/native, port and repository completion
gates remain outstanding.

Affected validation for the final context batch passes in 191.60 seconds,
including selected solver/compiler/native/pure tests, production lint and
metadata/architecture checks. Commands, log and terminal result are under
`build/metapad-trial/view-context/affected/`. Installed source/interface/binding
hashes were independently rechecked unchanged.

The next extent relation must reproduce the current decoder's admission. In
particular, NUL registration chooses a nonzero extent at least as large as its
requested minimum, requires a non-wrapping admitted range and a zero final byte;
it does not require that byte to be the first zero. Reference resolution keeps
the maximum of the requested extent and every matching registered NUL extent.
Outgoing admission must establish that same relation, including aliases, before
reconstructing the next view or admitting the caller's shared stack cell.


## Canonical extent and reference-range transport (2026-09-06)

Outgoing cuts now check the requested, resolved-reference and source-visible
extents used by the canonical overlay. NUL parameters are derived from compiled
interface types. Reference resolution takes the maximum of the requested extent
and registered NUL extents at the same address; fixed and count-bounded views
retain their declared visible extent. The outgoing NUL predicate uses the same
logical origin oracle as registration and proves nonzero/minimum extent,
non-wrapping admission against the captured outgoing ESP, and the zero final
byte in both worlds. Interior zero bytes remain admitted. Resumption assumes
this checked relation. Both readers require `spx-bisimulation-capture-extent`.

The memory comparison now covers each captured reference's full extent, including
bytes beyond its visible prefix. The separate required assertion name
`spx-bisimulation-capture-reference-memory` invalidates older visible-only
receipts, including attempt seventeen. A solver regression keeps the visible
prefix equal while differing private bytes beyond it; the new check rejects
that reached state. Other fixtures cover fixed/long/short NUL aliases, bounded
and empty visible views, minimum NUL extents, high-address non-wrapping limits,
changed terminators in either world and rebased private windows.

Final attempt eighteen satisfies entry with 71 authored properties in 76 queries
and scan with 72 in 77, under the existing 30-second per-query diagnostic budget.
Its longest query takes 14.204 seconds. A mutation shrinks the fixed count view
and its callback context to two bytes while leaving the declared reference at
four. The production checker rejects it at `scan:line_count`; its failing query
takes 1.331 seconds, starting 8.187 seconds into the scan obligation. Final
artifacts are under `build/metapad-trial/loop-plan/proof-attempt-18/` and
`build/metapad-trial/loop-plan/proof-view-visible-extent-mutation-final/`.

Both readers accept the bound direct evidence and reject removal of each extent
or full-reference memory assertion after the required-inventory digest is
refreshed. They reject attempt seventeen, which checked only visible bytes. The
mutation's bound diagnostic evidence is accepted while its proof remains
violated. Focused validation passes 25 tests in 14.323 seconds. Reader, focused
and validation evidence is under `build/metapad-trial/view-extent/`.

This closes extent transport under the current origin policy, not caller
ownership, allocation/lifetime composition or the pointed-to world-state
relation. The normal harness still exposes no shared stack spans, and the
installed trial remains unqualified. Production query limits remain unchanged;
no full pilot was rebuilt for this batch.

Affected validation for the final extent/reference-range batch passes in 194.17
seconds, including selected solver/compiler/native/pure tests and metadata,
lint and architecture checks. Its command, log and terminal result are under
`build/metapad-trial/view-extent/affected/`. Installed source/interface/binding
hashes were independently checked unchanged. Shared stack-span admission and
caller/platform qualification remain the next integration work; the current
diagnostic proof still excludes the concrete caller's count cell.


## Canonical shared-view inputs and frame preservation (2026-09-06)

The ordinary harness now derives frozen borrowed spans from canonical parameter
projections before either world performs effects. Extents include the full
resolved reference range and matching NUL aliases. Shared input admission permits
a declared view inside the stack window, rejects nonempty overlap with fixed
private objects, and retains non-null/non-wrapping and image/stack separation
checks. Nullable parameter views fail with an explicit unsupported diagnostic.

Source-frame reconstruction records a sticky preservation predicate for every
borrowed byte it initializes. Property and nonvacuity harnesses check that
predicate before executing the source overlay and assuming its resumed relation.
A temporary clobber followed by restoration still fails. Both receipt readers
require `shared-view-inputs` and `source-frame-preservation` per proof function;
the contextual policy additionally requires `canonical_borrowed_view_spans`.
The projection expression renderer is shared by harness and extent construction.

Attempt nineteen correctly returned incomplete: property and nonvacuity roots
had duplicate assertion descriptions. A replay of its bound compile inputs
confirmed exactly two copies of each new required assertion. Distinct root names
fix this without relaxing the inventory. Attempt twenty satisfies both normal
Metapad shards: entry 78 authored properties/83 queries, scan 79/84. Retained shard
timing sequences span 24.56 and 74.51 seconds respectively; the longest query is
23.97 seconds. These are diagnostic runs at the existing 30-second query limit,
not full provider or native realization builds.

A separate replay constrains the scan cut to ESP=1048560, EBP=ESP+12 and the
four-byte count cell at ESP+8, with a three-byte CR/X/NUL text view. The unchanged
exit public-memory property and relation witness satisfy in 1.89 seconds combined.
Removing only the source count store retains a reachable relation witness and
violates `spx-bisimulation-exit-world-memory:normalize:spx_bisimulation_check_0001`
in a 1.64-second combined replay. The original paired proof remains unmodified.
This establishes admitted shared storage and observable missing writes at that
cut layout; it does not establish the caller's ownership/lifetime contract.

Focused validation passes 35 tests in 12.889 seconds, covering interval aliases,
fixed-private exclusions, source-frame clobbers, missing receipt checks and
operator diagnostics. Python and jq readers accept attempt twenty, reject each
new assertion removed after inventory-digest refresh, and reject attempt eighteen.
Python receipt tests and the jq reader also reject missing/false policy fields.
Evidence and retained replay copies are under
`build/metapad-trial/shared-view-inputs/`; normal direct results are under
`build/metapad-trial/loop-plan/proof-attempt-20/`.

The external installed source, interface and binding are unchanged. All five
binding blockers and public caller/provider qualification remain open. No full
pilot was rebuilt for this batch; the integration checkpoint remains after the
Metapad proof-plan/public workflow integration.

Affected validation for the completed shared-input batch passes in 189.50 seconds,
including its selected solver/compiler/native/pure tests, metadata freshness,
production lint and architecture checks. The additional generated-harness and
repository/semantic-boundary group passes 52 tests in 6.605 seconds. Generated
module metadata is refreshed and `git diff --check` passes. The machine-overlay
digest matches attempt eighteen, and installed input hashes are reverified in
`build/metapad-trial/shared-view-inputs/installed-inputs.json`.


## Public Metapad proof-input integration (2026-09-06)

The normal public review initially rejected Metapad's write-fact mapping:
`text_written` occurs at two distinct instructions, but effect rows were keyed
only by logical effect ID. The generic operation-binding parser now retains
multiple references for one logical effect, ordered and unique by
`(effect_id, unit_id, family, index)`. A repeated fact identity is rejected even
if its supplied digest differs. Existing zero/single-reference rows remain
supported. Focused binding and public-review tests pass 14 tests in 0.035 seconds.
This change does not itself qualify the supplied facts or source behavior.

The reviewed draft maps the two byte stores at RVAs 0x574a and 0x575b to
`text_written`, and the four-byte store at 0x575f to `line_count_updated`.
Their references bind the canonical machine-IR memory-event indices and fact
hashes; the retained review includes the full referenced facts. Public
`boundary adopt` accepts these inputs and exports the reviewed proof intent.
The external target now installs the source sync marker, proof-intent reference,
interface/binding indexes and write-fact mapping, with rollback backups retained
under `build/metapad-trial/public-proof-integration/installed-before/`.
Its source selection and configuration retain draft activation. The SDK pin is
`/nix/store/xwf023i0p5n1qvlf6j28vh81hdwfq1cv-source`; only the extractor input
changes in the external lock file.

The two resolved missing-input blockers are removed. The remaining three are
kept with actionable detail: qualify the mutable NUL text origin and lifetime,
bind or prove dead continuation registers/flags before RVA 0x5762, and qualify
the four writable count bytes at EBP-4 with the caller-frame lifetime. Shared
proof spans and an inhabited diagnostic state do not grant runtime object
ownership. Previous attempt-twenty evidence remains diagnostic; these installed
bindings still require public provider qualification.

Public `component check --source --json` passes in 7.603 seconds and an unchanged
repeat in 1.580 seconds. Default `component check` exits incomplete in 0.982
seconds, naming the three blockers. `component status --development --json`
reports exactly three blockers and no held authority, but takes 80.192 seconds
cold. That development-status cost remains a performance gap, separate from the
fast source-check and prerequisite-feedback paths.

Adding guidance text to the binding alone preserves the exact source-check
receipt, returned in 2.364 seconds. The subsequent default check remains
incomplete in 1.327 seconds and displays each concrete next step. These are
single observations, not percentile measurements. Public command arguments,
stdout/stderr, SDK/installation hashes and the canonical effect review are
retained under `build/metapad-trial/public-proof-integration/`. No full pilot,
provider proof, candidate execution or native qualification was run in this batch.

Affected validation for the effect-reference/public-review integration passes in
204.67 seconds. The separate repository and semantic-boundary group passes 37
tests in 6.184 seconds. Generated module/test metadata is refreshed and
`git diff --check` passes. Final installed-file hashes, the extractor-only lock
change, three detailed blockers and exact source-check receipt reuse are verified
in `build/metapad-trial/public-proof-integration/final-installed-state.json`.

## Metapad continuation dependencies without a pilot rebuild (2026-09-06)

The normalization region changes EAX, CL and five arithmetic flags; it does not
write EDX. The continuation at RVA 0x5762 overwrites CF/ZF/SF/OF/PF before using
them. ECX survives to two imports: a call through EDI at 0x578b after loading
`kernel32.dll!lstrlenA` from IAT RVA 0xe158, and the call at 0x580a through IAT
RVA 0xe294 for `user32.dll!SetWindowTextA`. Import declarations identify these
frontiers but do not discharge their semantic contracts.

`machine_ir/entry_dependencies.py` adds a non-authorizing entry-state query to
the existing definedness dependency engine. It accepts real entry unit IDs and
whole-register/flag locations, binds the canonical transfer input digest and
retains the existing observation, call, control and budget obligations. It
neither generates synthetic input transfers nor creates new proof authority.
Even a complete dependency graph requires local semantic soundness and every
recorded call obligation. Missing or ambiguous roots and invalid location/budget
queries fail; incomplete transfers and traversal budgets remain incomplete.
Nine focused tests pass, including multiple roots, observed memory dependencies,
overwritten flags and retained call-frame obligations.

The real Metapad entry query takes 4.741 seconds including machine-IR loading and
adaptation. Each arithmetic flag produces a one-node graph with no additional
call obligation. ECX produces four nodes and two `call_frame_noninterference`
obligations at transfers 0x5786–0x578d and 0x5804–0x5810. The earlier synthetic
probe is retained as history; the current query uses only canonical rows and the
real root 0x5762. Evidence is under `build/metapad-trial/continuation/entry-query/`.

A paired exact-C diagnostic executes the actual first continuation unit with
equal incoming states except for arbitrary CF/ZF/SF/OF/PF. It compares control,
all 25 scalar machine-state fields, the full x87 stack and effective bytes across
the entire 32-bit memory space, including the private stack. The diagnostic
requires the exact body to execute and a reachable branch witness; it passes in
1.472 seconds. An additional ECX difference preserves the witness and fails
`complete scalar continuation state agrees` in 1.209 seconds. Each query has the
existing 30-second diagnostic budget; production defaults are unchanged.
`flags-proof-3/` retains harness/model/slice hashes and results. Earlier attempts
failed fixture compilation or omitted the exact-body fallback hook and remain
historical fixture failures, not evidence of a machine semantic mismatch.

The installed continuation blocker now names both calls and requires their
noninterference contracts plus the complete continuation relation in provider
proof. All three blockers remain. Caller-saved convention, dependency closure
and this local exact-C diagnostic alone grant no qualification. Guidance backups
and resulting binding/index hashes are retained in the same continuation evidence
directory. No full pilot/provider build or original-PE execution is needed for
this investigation.

The first repository/affected validation rejected the new helper because it had
no production consumer. The existing public `expert semantic-diagnose` command
now supports `--view entry-dependencies` over a retained `--machine-ir` file,
with repeated entry units, register/flag locations and a bounded state budget.
It binds the file hash as well as the adapted transfer digest, returns incomplete
analysis separately from invalid input, and never grants authority. Public CLI
coverage exercises successful analysis, a missing CFG successor, absent roots,
invalid budgets and malformed input. The repository consumer check then passes.

The combined public Metapad query completes in 4.076 seconds, retaining exactly
four nodes and the two call-frame obligations. Public component checking returns
the updated three blockers and both call names in 0.992 seconds. These commands
do not build a provider or execute the original binary. Command arguments,
JSON results and stderr are retained as `public-entry*` and `public*` under
`build/metapad-trial/continuation/`. See
[`performance-and-invalidation.md`](../performance-and-invalidation.md) for the
reusable command syntax and exit-status semantics.

Final affected validation for the shared engine entry state, diagnostic query
and public command passes in 162.563 seconds. The final CLI test passes and the
37 repository/semantic-boundary checks pass after adding the real consumer.
Generated module/test metadata is refreshed and `git diff --check` passes.
The final installed-state comparison confirms that only binding guidance and
its index changed; source, operations, proof intent, SDK pin and all three
blocker codes are preserved. No provider qualification is claimed.

## Provider continuation-state enforcement (2026-09-06)

The retained Metapad transfer plan confirms the two call prerequisites are
unfinished. The lstrlenA call remains indirect, with no declared argument nodes
or stack inputs; its target is identified by the preceding IAT load. The
SetWindowTextA call has no declared argument nodes and only one four-byte stack
snapshot. These facts cannot be promoted into complete ABI/noninterference
contracts. The installed profiles do not declare either service explicitly.

Review of the provider checker then exposed a separate proof gap: a tiny
fallthrough region with EAX=7 and an unbound ECX=7 write passed against a source
returning 7 while preserving incoming ECX. That pre-fix diagnostic passed in
1.163 seconds. The harness compared declared results and public effects but did
not require architectural state agreement at the intrafunction continuation.

The normal cutpoint harness now requires the equality case of the continuation
relation for fallthrough, direct jump, branch and indirect jump. All canonical
scalar machine-state fields except diagnostic instruction provenance are
compared; control kind and target already have separate checks. Universal x87
slot/byte indices compare all payload, occupancy and tag values without padding
or extra loops. Unsupported ABI storage fails generation. Return and exceptional
boundary contracts retain their separate observations. No declared-register mask
or unproved deadness claim can waive the new check.

The normal proof path retains matching fallthrough/jump behavior and rejects
both incorrect logical results and the previously accepted ECX difference.
The retained fresh equal case passes in 1.341 seconds; the ECX mutation fails
`spx-bisimulation-exit-continuation-state:run:spx_bisimulation_check_0000` in
0.894 seconds. Both Python and the complete strong jq predicate accept the
fresh positive proof and reject the old ECX proof, missing/false new policy and
a rehashed inventory with the new assertion removed. Operator diagnostics direct
the author to bind the missing output or prove a checked context relation.
Four focused proof/receipt tests and 25 receipt/operator/codegen tests pass.

The new required policy is `intra_function_continuation_state_checked`.
Historical direct Metapad and pilot receipts lack it and are not current
authority. Metapad's three blockers remain; checked context relations capable of
admitting dead flags/registers and complete call contracts are still required.
Evidence is retained under `build/metapad-trial/continuation-state/`. This batch
does not rebuild a full pilot, execute the original PE or claim provider/native
qualification.

Affected validation passes in 184.985 seconds, including the applicable
repository/metadata and solver checks. The external trial now pins SDK snapshot
`/nix/store/mrgh4g1188scyhqzhz2cdn0bgm7vahii-source`, which includes the repaired
checker and public entry-dependency query. The staged lock update changes only
the extractor input and retains rollback copies of both flake files. Public
source checking passes in 7.098 seconds; default qualification prerequisite
checking returns the same three blockers in 0.982 seconds. The target remains a
draft with unchanged source and component proof/binding inputs. SDK/public
command evidence is retained alongside the proof diagnostics.

## Conditional shared continuation prefixes (2026-09-06)

The proof engine now executes a declared common exact continuation after the
replacement body, using existing `continuation_unit_ids` separately from owned
`unit_ids`. The declared context inventory is limited to 256 qualified units;
every unit is a forced exact-C step boundary. Both executions must leave the
context within its unit-count step bound. Body result/effect checks precede the
prefix, and prefix checks retain control, result, implementation coverage,
public memory, call/atomic effects and complete final architectural state,
including exceptional outcomes. Context calls are rejected pending checked
call contracts.

Focused proofs accept an incoming register difference overwritten by the
prefix, reject a store exposing it, and reject a prefix that does not exit its
bound. Python and jq proof readers accept the conditional local proof and reject
missing context metadata, a changed bound, a removed required assertion and
forged activation. Such proofs remain `activation_authorized: false`, and
direct provider refinement facets remain incomplete: dispatch/link selection
must still enforce the premise that the declared continuation executes its
exact behavior. Independently replacing that context would invalidate the
premise. Public draft review and diagnostics expose this boundary.

The current generated continuation code was also run against Metapad's retained
first continuation unit at 0x5762. Arbitrary incoming arithmetic flag differences
pass in 2.231 seconds, including a full memory comparison covering private stack
bytes and a reachable branch witness. Adding an ECX difference fails final state
agreement in 1.792 seconds. These are local diagnostics with a 30-second budget
per query, not a fresh provider qualification. An earlier standalone harness
omitted the normal call/atomic comparison wrappers; its failed attempt remains
recorded as a harness construction error. The corrected diagnostic uses the
normal wrappers.

Focused context, reader, review and operator checks pass. Final affected
validation passes in 210.521 seconds, and generated metadata is refreshed.
Evidence is under `build/metapad-trial/common-continuation/`, including reader
mutations, `metapad-prefix-2/`, affected validation and the final installed-file
hash comparison. The external trial source, binding, proof intent and SDK pin
are unchanged. Its three qualification blockers remain. This batch performs no
full pilot/provider build or original-PE execution.

## Exact context requirements in provider selection (2026-09-06)

The qualification codec now admits an optional `exact_context` semantic slice
for Portable-C providers. It describes unowned transfer definitions and their
dependency contracts; it cannot add ownership or service obligations. The direct
provider derives this slice from its proof-plan continuation units and the linked
module, whose transfer-plan identity is already checked against proof inputs.
Missing linked context is rejected before solving.

The existing implementation-selection builder re-admits the context against the
current semantic module and checks the final choices. Each required definition
must select a complete generated Behavioral-C provider with matching semantics,
dependency contracts and native symbol. A second portable replacement, absent
context, stale semantics or mismatching generated qualification produces a
specific blocker. Unselected conditional providers impose no requirement.
Candidate object admission and native receipt writing repeat the checks; portable
dispatch input validation additionally requires the context inventory to match
the actual proof plan. Rehashed selections with their blockers removed are
rejected by both native consumers.

The focused 32-test qualification, selection, candidate, native receipt and
provider group passes. Affected validation passes in 128.109 seconds, including
the selected repository, metadata, compiler and native checks. Metadata is
refreshed and whitespace validation passes. Evidence is under
`build/metapad-trial/exact-context-selection/`; the installed-file hash comparison
confirms no external trial or SDK pin changes. No full pilot/provider build or
original-PE execution was performed.

This establishes dependency admission, not conditional native activation.
Continuation proofs retain `activation_authorized: false` and direct provider
refinement facets remain incomplete. The next integration must bind and check
the exact context in strong dispatch/link evidence, demonstrate a positive linked
conditional replacement, and reject changed context selections. Metapad's caller
ownership and call-contract prerequisites also remain open.

## Conditional proof activation at the selected link (2026-09-06)

Strong dispatch entries now carry an exact-context receipt when the provider's
proof depends on an unchanged generated continuation. It binds the semantic
slice, implementation-selection snapshot, selected generated qualifications,
complete object inventories, unique strong symbol owners and final linked RVAs.
Registry preparation checks actual staged objects and symbol bindings; finishing
the receipt rejects a changed selection or absent linker-map symbol. Native
realization retains the provider's full context premise and checks exact receipt
coverage against generated definitions and linked object membership. Context
units cannot also be owned by a portable overlay.

The direct provider can record checked conditional refinement facets with an
explicit machine-derived context requirement. Local proof receipts retain
`activation_authorized: false`; unconditional jq authority still rejects them.
Only the selected link discharges the requirement and grants dispatch activation.
Operator diagnostics now say that continuation selection is required, without
asserting that a selection they have not inspected is unqualified. Checked call
contracts and composition through independently replaced context remain open.

The synthetic fixture under `build/metapad-trial/conditional-link/` runs the normal
proof engine on a body whose ECX difference is overwritten by its exact prefix.
All 72 retained solver queries pass (3.657 seconds of summed query time, with the
30-second diagnostic limit per query). The fixture then compiles the actual
source, overlay and exact continuation as PE32 objects, uses the production
selected-object and registry builders, links a PE32 DLL, and validates the final
dispatch receipt and realized-context bindings. The local proof remains false
for activation while the dispatch receipt is true. Qualifications and module
contracts are constructed test inputs: this is a proof/link integration fixture,
not the complete direct work-package provider workflow or a native application
realization. No PE was executed.

Earlier fixture attempts omitted canonical transfer metadata or the external
dispatcher needed to link the generic generated support. The corrected fixture
uses the standard transfer adapter and an empty dispatcher that returns
`SPX_CALL_UNIMPLEMENTED` for every call; the proved body/context have no calls.
The completed solver proof was retained throughout these link-setup corrections.
The final compile/link portion took 0.317 seconds with that proof already present,
excluding Nix startup; this is not an end-to-end workflow latency claim.

Focused receipt/operator tests pass (19 tests). Cases reject weak, duplicate,
missing or unselected context symbols/objects, changed selection snapshots,
independently replaced context, and removed or altered context data after both
receipt hashes are recomputed. The full native receipt parser is exercised for
positive and negative cases. The external trial hash comparison confirms no
source, proof intent, binding or SDK-pin changes; Metapad retains its three
caller/context prerequisites. No full pilot/provider build was performed.

Final affected validation passes in 120.380 seconds, including the applicable
solver, compiler/native and repository checks. An earlier run passed before the
selection-snapshot check; the follow-up first stopped on stale generated import
metadata, which was refreshed before the successful final run. Logs and exact
commands are retained as `affected-complete*`. `git diff --check` passes.

## Metapad continuation call-frame preparation (2026-09-06)

The existing sparse-stack argument checker already reconstructs the complete
physical frame from a checked fixed-arity ABI. An empty `argument_nodes` inventory
or partial `stack_inputs` inventory does not, by itself, prevent that preparation:
predecessor blocks may have staged the remaining arguments. On Metapad's retained
call at 0x578b, it produces argument offset `[0]` from no local stack snapshots.
At 0x580a it produces offsets `[0, 4]` from one locally staged word. The retained
diagnostic takes 1.686 seconds and remains non-authorizing; lstrlenA's indirect
target still needs a checked identity binding.

The kernel32 and windowing profiles now declare ABI-only frames for `lstrlenA`,
`lstrlenW`, `SetWindowTextA` and `SetWindowTextW`. A pinned IA-32 MinGW compiler probe
checks each function-pointer type, four-byte argument/result representations and
the emitted stdcall import decoration: four and eight bytes of arguments for the
two API families. The probe takes 0.149 seconds excluding Nix startup. Its source,
object, compiler identity, header dependencies, selected header hashes and lowered
canonical frames are retained under `build/metapad-trial/call-contracts/`.

This preparation does not claim that calls preserve memory or avoid callbacks.
The semantic contract checker rejects all four ABI-only entries because their
effect contracts are absent. The source profiles deliberately omit result
relations, memory footprints and world/callback effects. The focused environment
and header-ABI group passes 12 tests, including exact argument offsets, stack
cleanup and rejection of semantic admission.

The required next contracts differ. Microsoft documents that
[lstrlenA](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lstrlena)
reads a NUL-terminated string and returns zero for a null pointer; a portable
replacement must preserve that case as well as the string-memory relation.
[SetWindowTextA](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowtexta)
sends WM_SETTEXT when the target window belongs to the current process, so its
contract must cover window-message behavior and potential reentrancy rather than
classifying it as a leaf with no world effects. These semantic contracts and
their continuation proof remain open. No full pilot/provider build, SDK repin or
original-PE execution was performed.

The call-frame batch's affected validation passes in 83.384 seconds. Repository
metadata is current and whitespace validation passes. The final installed-file
comparison confirms that the external trial and its SDK pin are unchanged.

## Call-time public memory observations (2026-09-06)

The proof world now records a fresh symbolic address and its effective exact
byte before every service call, and compares that observation at source replay.
It checks all public bytes without a buffer scan or a copy of the sparse world.
This prevents a later store from hiding a difference visible at the call.
Machine-to-machine, machine-to-typed and typed-to-typed replay are covered;
each call gets an independent witness. Exposed caller-frame spans participate,
and private-frame cells retain their separate contracts. Typed replay checks
memory before output application and before the complete call-field assertion.

The comparison is conservative over all public memory. Precise callee read
footprints, pointer lifetime/permissions, output effects and callback/reentrancy
contracts remain open, and the continuation call guards remain in place. No
new source-level service API is required by this mechanism. The Python and jq
readers require `call_public_memory_snapshots_checked` and typed assertion
coverage; historical receipts missing the policy are superseded for the current
toolkit. The operator explains that an unrelated public-byte difference may need
a narrower checked read footprint.

The focused group passes 47 tests in 2.985 seconds, 11.228 seconds including Nix
startup. Eleven small CBMC runs use a 30-second limit each; production defaults
are unchanged. The tests include matching inputs followed by changed final
memory, a call-time difference repaired before exit, a difference only at the
second call, private versus exposed caller-frame bytes, and a removed-check
mutant that incorrectly accepts the bad program. An initial private-frame test
used a public address and correctly failed; its address was corrected.
Affected validation passes once in 197.083 seconds. Evidence and exact validated
input hashes are retained under `build/metapad-trial/call-memory/`.
The external trial's recorded files and SDK pin are unchanged. No full
pilot/provider build or original-PE execution was performed.

## Explicit import effects at semantic admission (2026-09-06)

The ABI-frame batch's rejection test used the legacy event converter, which has
no production consumers. An intake probe through the active canonical native
converter found that both retained Metapad call shapes were accepted with
`memory_effect`, `world_effect` and `callback_effect` equal to `none`, although
the selected ABI-only profiles declared no memory or world effect categories.
This was a converter intake result, not an authorized application realization;
the indirect lstrlen target remained an unproved diagnostic assignment.

The active native converter now requires explicit memory and world effect
categories. The semantic component frontend and Portable-C overlay builder use
the same check, preventing a missing field from becoming an effect-free claim.
The frontend emits `bound_external_call_effect_contract_missing` with the service
identity and missing field. Physical ABI lowering remains available. Declared
pure, read-only/resource and native-callthrough categories are preserved. The
check establishes presence only; correctness of footprints, outcomes, lifetimes,
callbacks and native realization still needs its own evidence. The Python and
jq contextual readers require `machine_import_effect_categories_explicit`.

The retained-call probe now rejects both inputs in 1.678 seconds, with unchanged
profile and transfer hashes. Evidence is in
`build/metapad-trial/call-contract-admission/{before,after}.json` and `probe.py`.
The focused 54-test group passes in 0.114 seconds; the explicit-category and
receipt group passes three tests in 0.015 seconds. The first affected run failed
after 212.650 seconds because an older string-service fixture supplied ABI-only
metadata while expecting semantic admission. Adjacent string, factory and
callback fixtures now declare their intended effects; their 11-test group passes
in 0.154 seconds. Final affected validation passes in 135.351 seconds, using
`validate-final.py`, `affected-final-result.json` and `final-input-hashes.json`.
Metadata is current and whitespace checks pass. The external trial's recorded
files and SDK pin are unchanged. No full pilot/provider rebuild or original-PE
execution occurred. The lstrlen string precondition and target binding,
SetWindowText callback contract and continuation-call admission remain open.


### Borrowed service inputs at the call boundary (2026-09-06)

The typed proof thunk had only arithmetic checks on borrowed input metadata,
while the production thunk realized the reference through the runtime. The
proof thunk now also checks issued origin, generation, permissions and bounds
before recording a service call. A byte NUL view must retain a readable zero
at its current visible final byte. This is a sufficient termination witness;
it does not compute first-NUL length, establish caller lifetime or admit wider
strings. Source arguments cannot manufacture an origin by asking the checker
to resolve their physical address. The existing continuation-call rejection
remains in place pending the remaining contracts.

Both receipt readers require `typed_service_borrowed_inputs_checked`. The
operator displays argument-specific reference and termination guidance.
The initial four-test generated-thunk group passes in 4.345 seconds, with 18
small CBMC queries capped at 30 seconds each. It exercises interior origins,
stale/foreign/forged metadata, missing access/runtime hooks, visible bounds,
current termination and later repairs. Two removed-check mutants admit invalid
inputs, confirming that the new checks are exercised. A broader run exposed one
old test looking for the replaced arithmetic check; it now checks that reference
realization precedes call recording. Final focused validation passes 34 tests in
6.327 seconds (7.721 seconds including Nix). Affected validation passes in
199.166 seconds with unchanged validated inputs. Metadata refresh, jq module
loading and whitespace checks pass. Commands, logs, source hashes and the final
installed-file comparison are under `build/metapad-trial/service-preconditions/`.
There was no full pilot/provider build, SDK repin or original-PE execution.

Static disassembly and retained canonical transfer records also identify a
caller-origin investigation path: frame allocation at `0x56b5`, a direct call
there from `0x5c49`, the text pointer loaded from caller EBP minus `0x14`, and
preceding internal calls to `0x5817` and `0x55b7`. The former routine contains
allocation, file-read and encoding-conversion calls; the latter transforms text
before normalization. `caller-leads.json` and the disassembly are diagnostic
only. These observations do not prove full predecessor coverage, heap/stack
disjointness, a string lifetime, or safety across the intervening calls.


### Public caller navigation over retained inputs (2026-09-06)

`expert semantic-diagnose --view callers` now returns direct internal call sites
for requested canonical entry units from retained machine IR. It includes
captured input expressions, instruction RVAs, source hashes, and exact file-line
and JSON-pointer locations. The input adapter and existing node index remain the
canonical readers; this is navigation, not another semantic authority engine.
Malformed or ambiguous roots fail explicitly. A bounded site list retains the
total count and reports truncation with exit 1. Exit 0 means a complete returned
direct inventory in the supplied input, not a closed caller set. Indirect calls,
callbacks, host entries and tail branches remain outside this query's resolution;
reachability and caller ownership are never inferred.

The first public Metapad smoke expectation assumed three sites from the manual
trace and failed because the query found five. Independent retained transfer-plan
inspection confirms the two additional sites: `0xb131` calls the buffer loader
at `0x5817`, and `0xb19c` calls the text transformer at `0x55b7`. The other sites
are `0x5c09`, `0x5c2f` and the normalizer's direct caller `0x5c49`. The complete
supplied Metapad input also contains 629 unresolved indirect-call sites; their
actual target sets are not inferred by this inventory.

Final public Metapad execution takes 9.069 seconds including the CLI rebuild,
and its unchanged repeat takes 4.007 seconds with identical JSON. Independent
retained GNU Hello machine IR returns 40 sites for its queried root in 5.021
seconds. A one-site limit returns one of those 40, marks truncation and exits 1
in 4.972 seconds. These timings include Nix invocation; no target evaluation,
pilot/provider rebuild, SDK repin or original-PE execution occurred.

Final focused validation passes 38 tests in 2.764 seconds (5.506 seconds including
Nix). Affected validation passes in 126.218 seconds, with unchanged validated
inputs. Generated metadata is current, whitespace checks pass, and external trial
files and the SDK pin match the preceding batch. Evidence, commands and source
hashes are retained under `build/metapad-trial/caller-navigation/`, with the final
public results in `public-final/` and the canonical comparison in
`canonical-crosscheck.json`. This verifies one diagnostic on two inputs, not an
independent end-to-end lifting or portability milestone.

The runtime already binds dynamic allocation locators to checked range contracts
and supports captured-frame invocation generations. Those mechanisms still need
a checked connection to this trial's incoming buffer and count views. The
selected GlobalAlloc native-callthrough row does not itself supply the required
portable allocation/lifetime theorem. The caller query is a route to those
proof obligations and cannot discharge them.


### Allocation generation exhaustion (2026-09-06)

A fixture using the generated native allocation-range functions reproduced stale
reference revival when the lifecycle generation counter saturated and an address
was released and reused. Registration now rejects exhaustion with diagnostic
`0x2103` before changing the range inventory, preserves existing live references,
and permits cleanup. Four focused tests include five bounded CBMC queries, an
arbitrary-counter case and a removed-guard mutant. A retained fixed-case proof
also passes and its IA-32 PE32 fixture compiles and links; neither that fixture
nor the original application was executed. This is not full runtime-link or
Metapad caller-lifetime qualification.

The first affected run caught the runtime module size limit. Extracting the
allocation and generation helpers preserves the full emitted C byte for byte.
Final focused validation passes 20 tests in 1.307 seconds (8.228 seconds including
Nix). Final affected validation passes in 122.724 seconds, with unchanged
validated source hashes. Evidence is retained under
`build/metapad-trial/allocation-lifetime/`. No full pilot/provider rebuild or
external trial SDK repin was performed. Checked release-success conditions and
partial-release semantics remain open prerequisites.


### Result-conditioned whole-range release (2026-09-06)

Checked machine-import profiles and typed operation effects now require explicit
release success and admitted argument constraints. The same codec feeds checked
site serialization, exact profile matching, native inventory construction and
runtime lowering. Existing release profiles were migrated: Boolean-returning
services use nonzero success, and CRT free uses every normal return. VirtualFree
is bounded to size zero and exactly MEM_RELEASE; partial decommit and placeholder
operations are rejected by capture before host callthrough. Result handling
rechecks argument constraints and preserves the tracked allocation on failure.
See [release conditions and API references](../call-protocols.md#whole-range-release-conditions).

Eight new tests exercise profile admission, checked-codec round trips, exact
profile disagreement, native inventory lowering and production C release bodies.
Seven CBMC queries, each capped at 30 seconds, cover arbitrary result words,
zero/nonzero/unconditional success, unrelated live origins, unsupported partial
calls, malformed rules and inconsistent snapshots. Removing either the success
check or the argument guard produces a counterexample. These fixtures do not
prove native target selection, allocator ownership or a portable API theorem.
The native bridge's production capture gate was inspected before callthrough.

The 74-test focused group passes in 3.359 seconds (11.909 seconds including Nix).
A complete generated runtime with release rules compiles to an IA-32 object in
0.089 seconds; this is compilation evidence, not a linked or executed candidate.
The initial affected gate failed because computed profile filenames were absent
from the filtered test source. Explicit test resources repaired that packaging
error without changing implementation. The corrected affected gate passes in
170.821 seconds with unchanged validated inputs and refreshed metadata.
Commands, hashes, logs and generated native sources are retained under
`build/metapad-trial/release-contracts/`. No pilot/provider rebuild, SDK repin or
original Metapad execution occurred. Trial file hashes and SDK pin match the
previous batch.

The remaining ownership work includes allocation-family and heap identity,
GlobalAlloc fixed/movable semantics and matching GlobalFree outcomes, and
connecting allocation/frame lifetimes to Metapad incoming views. General partial
page transitions, memory-bearing body-free lifetime summaries and continuation
call contracts remain unfinished. The full roadmap goal remains active.


### Allocation authorities across repeated call sites (2026-09-06)

The canonical runtime previously required an allocation/resource locator to
match exactly one producer rule. A retained two-site fixture reproduced the
unresolved locator. The retained Metapad transfer plan contains 23 resolved
GlobalAlloc import call sites, including the transformer's temporary allocation
at `0x55d1` and the buffer loader allocation at `0x5838`. This inventory is static
navigation evidence; the selected GlobalAlloc callthrough contract still does
not qualify a portable allocation origin.

Repeated sites can now share an authority only when their exact checked contract
identity and result shape agree. The identity binds the import/interface,
profile selection, ABI, disposition and normalized effects. Physical addresses,
target selectors and argument frame offsets remain site specific. Equal display
ids with different profile bindings, multiple output shapes, duplicate physical
sites, missing shared identities and competing object authorities are rejected.
The existing locator selector names the first producer in the checked group;
generated member rules bind that representative to the same object authority.
Each runtime allocation retains its own generation, address and producer RVA.

Six new tests cover checked inventory construction, group binding, renderer
validation and generated native registration/resolve/release bodies. Three new
CBMC queries, each capped at 30 seconds, check simultaneous allocations from
different sites, release and address reuse through another site, stale origins,
retained unrelated lifetimes and invalid group selectors. Restoring the former
one-site runtime comparison makes the positive group fixture fail. A complete
generated runtime with grouped producers compiles to an IA-32 object in 0.093
seconds. The object was not executed and is not a qualified target link.

The final focused group passes 43 tests in 4.001 seconds (5.436 seconds including
Nix). Affected validation passes in 120.333 seconds with unchanged validated
inputs and current generated metadata. Commands, source hashes, the initial
reproduction, Metapad site inventory and compile evidence are retained under
`build/metapad-trial/allocation-sites/`. Trial source/intent files and the SDK pin
match the preceding batch. No pilot/provider rebuild, SDK repin or original
Metapad execution occurred.

The proof world still uses invocation-scoped issued origins; this native binding
change is not an allocation API theorem or a general lifetime-bearing summary.
Metapad still requires allocator and release ownership contracts, a checked
connection to the incoming text/count views, and continuation service contracts.

## Native range ownership and heap identity

The ownership batch adds checked allocator families and optional captured owner
arguments to native range results/releases. CRT malloc/calloc/free and Win32
HeapAlloc/HeapFree provide separate concrete profile consumers. Native release
admission rejects a wrong family or heap, an untracked owned pointer, or an
interior pointer before host invocation. Failed host releases preserve issued
origins; successful releases expire them. Reused addresses accept a fresh owner
without reviving old references. Null allocations issue no range; non-null
zero-size owned allocations retain a releasable lifetime without byte authority.
Overlapping owned allocations and unowned overwrites of an owned base fail closed.

The active profile/site codec and runtime lowering preserve ownership. Rendering
rejects release/range metadata disagreements even when one ownership field was
removed. Typed operations reject owner arguments outside their own call frame.
Eight new tests include five 30-second-budget CBMC queries over actual generated
runtime bodies, including removed-owner and removed-family-check mutants. The
fixture bounds storage capacity and uses direct site matching; it does not prove
indirect target selection or the host allocator's implementation.

The 77-test focused group passes in 6.669 seconds (8.148 seconds including the
Nix shell invocation). A complete generated runtime with owner-tagged rules
compiles for IA-32 in 0.098 seconds. Its source SHA-256 is
`a5673aaf28de8c54b3400deba35f6e7d114acaad90d2d80d834b4df7ec714a02`;
its object SHA-256 is
`b0b5180ab072ddd3704bb9d953c6b59231ef79164cd15e30df60c93b4a1717f8`.
The object was neither linked into a qualified target nor executed.

Commands, input hashes, logs and installed-file comparisons are retained under
`build/metapad-trial/range-ownership/`. Metapad's recorded source/intent files and
SDK snapshot `/nix/store/mrgh4g1188scyhqzhz2cdn0bgm7vahii-source` are unchanged.
No pilot was rebuilt and the original PE was not executed. GlobalAlloc/GlobalFree
still lack the required portable allocation theorem. General proof-world
allocation transitions, caller lifetime composition, exceptional/concurrent heap
behavior and heap destruction/reuse remain open.

Affected validation passes in 279.98 seconds, with all recorded source hashes
unchanged. Generated metadata is refreshed and the whitespace check passes.
The initial focused run caught a fixture-only `NoneU` initializer; its corrected
run and the final 77-test group pass. The affected gate ran once for this batch.

## Selected range effects at the proof-service boundary

The normal external-import adapter previously retained ABI/argument information
but discarded the selected profile's effect payload. A synthetic resolved
contract declaring `dynamicRangeRelease` reached `_proof_call_specs` as an
ordinary scalar-response call. The reproduction deliberately assigns that effect
to an existing fixture import; it tests contract transport, not the behavior of
that library function. `before.json` records the admitted call and exact source
hashes. The current `after.json` reports
`proof_service_lifetime_effect_unsupported` before proof-world construction.

Bindings now carry `external_effect_contract`, and checked proof-call identities
and trusted adapter receipts retain the whole payload. Missing contracts and
missing categories fail closed. Declared range allocation/release, dynamic range
results and out-pointer range effects cannot use the current lifetime-free call
oracle. Five new admission/identity/reader tests and the existing real adapter fixture
cover this boundary. Synthetic external-call fixtures now state their effect
categories explicitly. The final 69-test focused group passes in 7.352 seconds
(15.359 seconds including shell/package preparation).

A fresh normal-exit proof through the full contextual engine takes 1.347 seconds.
Both Python and jq accept it and reject rehashed receipts with
`declared_external_range_effects_checked` missing or false. The initial reader
experiment used a unit fixture with only a partial descriptive model-bound
summary; it was unsuitable as positive reader evidence. `readers-final.log` and
`readers-result.json` instead record the complete normal-engine proof and the
three corresponding reader cases.

Evidence is retained under `build/metapad-trial/proof-lifetime-effects/`.
The installed Metapad files and SDK pin remain unchanged, and no pilot was
rebuilt. This repair makes an unmodeled lifetime effect an explicit proof blocker;
it does not provide a heap theorem. The next allocator integration still needs
shared proof-world birth/release transitions, initialization and fresh memory on
address reuse, borrowed-alias expiration, and checked caller ownership. Reviewed
GlobalAlloc/GlobalFree semantics and opaque-resource/callback effects remain
separate prerequisites. Historical receipts lacking the new policy are
insufficient for current authority.

The first affected run passed in 217.61 seconds. A subsequent audit exposed a
reader branch absent from that test coverage: typed-adapter receipts still
expected the old spec shape and renderer file list. The strict reader now checks
the new field and recomputes the behavior identity with the selected effect
payload; its renderer closure includes the new admission helper. A direct typed
receipt test accepts the current fixture and rejects rehashed effect loss,
contract changes and lifetime effects. Python and the jq adapter predicate agree
on all six cases in `typed-readers-result.json`. The complete normal-engine
receipt was reused for a final reader-only check; its proof was not rerun.

Final affected validation passes in 136.22 seconds, with unchanged recorded source
hashes, refreshed metadata and a passing whitespace check. The repeated gate was
required by the typed-reader repair after the first validation. All final reader
cases and both affected runs are recorded in `result.json`; no pilot rebuild, SDK
repin, native target execution or allocator qualification is claimed.


## Bounded allocation instances in the paired proof world

The existing sparse exact/source memory model now records bounded allocation
instances with family, owner, extent, initialization mode and logical generation.
Release checks the original base and ownership; failed releases preserve live
references, while successful releases expire all issued aliases. Birth records
write/shadow history floors, so reused storage receives fresh bytes instead of
inheriting its previous lifetime's writes. Zero initialization is explicit;
uninitialized bytes use a shared uninterpreted function of instance and offset.
Paired public memory equality includes lifetime state without comparing write
counts or history floors, allowing equivalent stores of different widths.

The first six lifecycle tests passed, but a new boundary regression demonstrated
that per-byte liveness alone allowed a two-byte read to escape a live allocation
into untracked memory. Full-span checking now rejects that access, entry from
untracked memory and spans crossing adjacent live allocations. It preserves an
access ending exactly at the boundary. Issued one-past references also retain
their original allocation identity when another live allocation begins at the
same address, and expire when their original owner is released.

Seven allocation tests execute nine small CBMC queries, including mutants that
remove the generation guard and the write/shadow history guard. Each query has
the existing 30-second diagnostic budget. The complete 52-test focused group
passes in 42.329 seconds, or 51.254 seconds including Nix preparation. Logs,
commands and checked source hashes are retained under
`build/metapad-trial/proof-allocation-lifetime/`. The failing boundary reproduction
is retained as `boundary-before.log`.

External-service admission still rejects declared allocation/release effects
with `proof_service_lifetime_effect_unsupported`. These primitives do not prove
freshness against all incoming memory or the complete native image, map logical
generations to native allocator generations, establish caller-owned heap ranges,
or carry heap state across proof cutpoints. They must be bound to checked API
contracts and both exact/source call paths before allocator calls can qualify.
Metapad's GlobalAlloc/GlobalFree and caller lifetime remain unqualified.

Affected validation passes in 208.119 seconds, with unchanged validated source
hashes and refreshed generated metadata. Final trial-file hashes and the SDK
snapshot match the preceding batch. No pilot/provider rebuild, SDK repin or
original Metapad execution occurred. `result.json` records these boundaries;
`verified-installed-state.json` records the external-file comparison.


## Guarded GlobalAlloc/GlobalFree native contracts

The selected GlobalAlloc contract now admits fixed allocations with flags 0 or
64, a nullable EAX result, the second argument's requested extent and the
`kernel32.global-fixed` family. Explicit initialization metadata distinguishes
arbitrary initial bytes from the zero-initialization flag. The opaque native
callthrough row was removed, leaving one selected kernel32 runtime contract.
GlobalFree now has an owned whole-range release effect on argument zero with
`eax_zero` success; failed release leaves the allocation registered.

The common allocation codec validates exact fields, uint32 masks, unique argument
indices, supported initialization modes and one admitted zero-initialization bit.
It is used by profile loading, the checked contract reader, active contract
conversion and native lowering. Native admission checks the captured flags before
host execution. Unsupported bits fail with `0x2221`; malformed capture/table
bounds fail with `0x2220`. This admits fixed pointer results only. Movable handles,
obsolete flag combinations, GlobalReAlloc, and extra capacity obtained through
GlobalSize remain outside the supported domain. API references and the exact
metadata are documented in `docs/call-protocols.md`.

Six new tests cover the real normalized profile and native inventory, all three
initialization modes, malformed contract mutations, continued contextual-proof
rejection, and actual native helper execution. Three CBMC queries include a
symbolic check over every flag word and a mutant that removes the admission mask.
Null results register nothing; zero-size instances remain releasable; failed
GlobalFree preserves the range; successful release retires it; the CRT family
cannot release a global allocation. The 83-test focused group passes in 7.678
seconds, or 15.150 seconds with Nix preparation. The initial fixture bypassed
profile normalization and lacked GlobalFree's generated ID; it was corrected to
consume the real selected profile and its binding. A subsequent nondeterministic
fixture declaration lacked the CBMC `nondet_` name; the final symbolic test uses
the recognized declaration. Both failed runs remain in the evidence directory.

The complete generated runtime with these real two-argument allocation and
one-argument release rules compiles for IA-32 in 0.108 seconds. No linked/native
qualification or execution is inferred from that compilation. The retained
Metapad disassembly supplies `0x40` immediately before its GlobalAlloc import at
RVA `0x55d1`; this is a local argument observation, not caller lifetime evidence.
Evidence, commands and validation input hashes are retained under
`build/metapad-trial/global-allocation-contracts/`.

The contextual call oracle still rejects both declared allocation effects.
Selected initialization metadata must be bound to the proof-world transitions,
fresh allocator results, caller-owned ranges and cross-cut lifetime state before
Metapad's caller can qualify. No full pilot/provider rebuild is performed for
this batch, and the external SDK pin is preserved.

The initial affected run stopped after 238.38 seconds on a stale callthrough
profile inventory test that still expected GlobalAlloc in the removed location.
That expectation was updated; the nine-test callthrough group then passed in
0.006 seconds. The allocation and native runtime sources were unchanged by this
repair. The first run's evaluation-cache receipt was also withheld because docs
changed during evaluation; that cache decision was not its test failure.

The corrected affected run passes in 139.477 seconds with unchanged validated
inputs and refreshed metadata. The final trial-file comparison confirms the
installed source, intents and SDK snapshot are unchanged. `result.json` retains
both affected outcomes, the focused result and the IA-32 compilation hashes.
No allocator Portable-C proof, caller lifetime qualification or pilot activation
is claimed.


## Allocation lifetime observations at service calls

The shared call snapshot previously retained only a public byte observation.
That was insufficient for the new allocation world: an early source release and
a later exact release can produce identical zero bytes and final lifetime state,
while presenting different live instances to a service. The common call snapshot
now saves allocation count and one independent allocation-index witness. Replay
checks the saved semantic fields against the source inventory at the call,
before the private-byte exemption. The same allocation comparator is used for
final world equality and excludes write/shadow history floors.

The snapshot stores one instance per call, not a nested copy of the allocation
table. The universally checked witness is independent of the byte address and
never enters a service response or input constraint. Machine exact recording,
machine source replay, typed source replay and typed exact recording all use the
existing common call-memory helpers. The correct exact lifetime is the recorded
call-time instance, even if exact execution has already released it by the time
source replay begins.

Six tests execute ten CBMC queries with the existing 30-second diagnostic budget.
They reject early release across all three supported record/replay combinations,
reject a late birth that repairs the final inventory, retain independent snapshots
for two calls, and accept equivalent stores with differing widths. Removing the
lifetime replay check makes the early-release counterexample pass, confirming
the old byte-only observation is insufficient. The first fixture attempt had no
argument offsets, which the existing service-spec parser rejects; the corrected
fixture uses a captured scalar argument. The final six-test group passes in
5.794 seconds. The full 60-test focused group passes in 50.249 seconds, or 58.264
seconds with Nix preparation.

Both Python and jq readers now require `call_allocation_lifetimes_checked: true`.
A fresh complete normal-engine proof takes 1.759 seconds. Both readers accept it
and reject rehashed receipts with the policy removed or false. Historical pilot
receipts without the policy remain insufficient for current activation. Evidence,
commands, source hashes and the three reader cases are retained under
`build/metapad-trial/call-allocation-lifetimes/`.

Allocator APIs remain blocked by `proof_service_lifetime_effect_unsupported`.
This shared-oracle prerequisite does not yet connect selected allocation
contracts to call transitions or prove incoming caller-owned heap ranges and
lifetime composition across cutpoints. The external trial stays pinned and no
full pilot/provider build or original Metapad execution is needed for this batch.

Affected validation passes in 218.560 seconds with unchanged recorded validation
inputs and refreshed metadata. The final external-file comparison confirms the
trial source, intents and SDK pin remain unchanged. `result.json` records the
focused, solver/reader and affected results; no pilot/provider rebuild or
original Metapad execution occurred.


## Hello ASCII comparison with native allocation references

Tracing allocator admission exposed a mismatch between reference representations.
The flat proof resolver uses the physical address as `object`, while the native
resolver returns a selected object ID, allocation generation and interior offset.
The Hello ASCII comparison's object-only shortcut was therefore unsafe for valid
native views: different slices can share one ID, as can different live allocation
instances distinguished by generation. The production `_view_projection_lines`
transports the native reference fields into the portable view unchanged.

A focused reproduction compiles the actual authored Hello source, generated
interface headers and shared portable reference runtime together with production
native allocation, resolution and realization bodies. Two references to addresses
4096 and 4097 resolve and realize successfully, share an object ID, and denote
strings starting with A and B. The old source returns zero before reading either
string, violating the expected -1 result. The source now calls
`spx_ref_difference` and requires zero distance before taking the shortcut.

Four CBMC tests pass in 0.784 seconds: shared-object/different-offset views,
different live allocation instances sharing an object class, identical native
locations with no reads or service calls, and a mutant restoring the failing
object-only condition. The 15-test compatibility group passes in 5.655 seconds,
or 7.038 seconds including Nix preparation. Each solver query uses the existing
30-second diagnostic budget. Evidence and input hashes are retained under
`build/reference-namespace/ascii-compare/`; `before.log` records the failure on
the previous source and `after.log` the corrected four-test group.

This test does not execute the original PE or establish a full pilot theorem.
The fixture's native allocation authority is explicit; general correspondence
between native metadata and the flat proof namespace remains unresolved. In
particular, equality of address-valued proof objects cannot by itself justify
numeric object-ID tests in native source, and incoming allocation ownership and
cross-cut reconstruction still need that correspondence. Allocator-call admission
remains blocked. The Hello source edit invalidates its previous source-bound
qualification; the full pilot is deferred to the integration checkpoint. Metapad's
installed files and external SDK pin are unchanged.

Affected validation passes in 79.930 seconds with unchanged recorded validation
and supporting source hashes, refreshed metadata and a passing whitespace check.
The final trial-file comparison confirms the installed Metapad source, intents
and SDK pin are unchanged. `result.json` records the source repair and its exact
validation boundary; no full pilot/provider build or original-PE execution was
performed.

### Native reference transport through typed services

The next batch repairs the existing typed service adapter's use of object IDs as
physical addresses. The production native resolver accepts the fixture's live
reference at address 4100 with a non-address 64-bit object ID and interior offset
4; the old proof adapter then incorrectly rejects it. `before.log` preserves that
counterexample. The adapter now uses the already-realized word for call arguments
and borrowed-interior return offsets. Return references preserve origin authority
permissions and must realize to the actual service result. Both proof and native
result lowering preserve full-width domain, object and generation fields.

The nine new test methods execute 26 bounded solver queries, including coverage
witnesses for successful return paths. They use generated adapters and the actual
native resolver/realizer bodies with explicit allocation authority. Cases cover
null returns, high identity bits, interior offsets, invalid and expired inputs,
and four mutations: object arithmetic in arguments, object arithmetic in result
constraints, truncated return IDs and altered authority permissions. The result
constraint mutation has no successful-path witness rather than a false passing
proof. Native allocation bookkeeping is exercised; no host allocation API or
original PE is executed. Fixture repairs retained in the logs include the exact
native selector, its string-comparison unwind bound, and production permission
metadata; the initial focused run also caught a stale rendered-text expectation.

The 46-test focused group passes in 16.675 seconds (18.054 including preparation).
The adapter implementation inventory now includes `bisimulation_service_preconditions.py`.
Python and the strong jq reader both accept the current inventory and reject six
rehashed missing, reordered, duplicate, wrong-version or malformed variants.
Evidence is under `build/reference-namespace/typed-services/`, including input
hashes, commands, reader cases and affected-validation results when complete.

This is service-boundary progress. The flat proof world's namespace, cutpoint
address expressions, connected-memory observations, incoming allocation ownership
and cross-cut lifetime reconstruction remain unresolved. Allocator calls remain
fail-closed. No full pilot/provider build or external-trial SDK update is part of
this batch.

The full affected batch passes in 231.503 seconds with unchanged inputs.
Final review then tightens the negative coverage test to require the explicit
`cbmc_nonvacuity_unwitnessed` / `FAILED` result, so a timeout or tool failure
cannot stand in for an unreachable return. Production inputs are unchanged;
`focused-coverage` and `affected-coverage` record validation of that test-only
update, separately from the completed full affected batch.

### Cutpoint and connected-memory reference transport

Proof consumers now use a shared ABI helper to realize the complete reference
without issuing a new origin. It checks requested visible storage against the
reference remainder and the complete physical object against the machine address
space. Cut contexts must realize to their projected address. Source byte reads
check their visible index; full-reference comparison starts at the object's
physical base, including the prefix before an interior view.

Connected wrappers record each input's address before the exact call and compare
its source-side realization before replay. A native fixture gives both worlds the
same reference tuple but different physical allocation bases; the new check
rejects it, and removing the check reproduces acceptance. An expired source
origin is also rejected despite identical metadata. These tests use generated
wrappers and the actual native allocation/resolution/realization bodies, with
64-bit domain/object IDs, interior offsets and explicit fixture authority. Plain
reference observations cover their remaining storage and canonical null values.

The memory regression uses the real proof world's range comparator. Its initial
fixture incorrectly expected a universal witness to select a particular differing
byte; the corrected test requires equality to fail for that byte and verifies
that the old interior-start comparison instead admits the mismatching prefix.
All successful native fixture paths have explicit coverage witnesses. Existing
cut-only fixtures now supply their explicit transport authority; they retain the
independent private-byte, extent, metadata, callback and context mutations.

The 67-test focused group passes in 57.249 seconds (65.631 with preparation).
`build/reference-namespace/cut-consumers/` retains commands, hashes, solver-test
logs and affected-validation results when complete. No full pilot/provider build,
Metapad SDK repin or execution of the original PE is part of this batch.

This removes address arithmetic in the cutpoint and connected-memory consumers.
The flat proof resolver and canonical requested/reference/NUL extents still need
a checked native namespace correspondence. Cut generation/offset reconstruction,
caller ownership and lifetime composition remain open; allocator calls remain
fail-closed. These local tests do not establish a native pilot qualification.

Affected validation passes in 199.005 seconds with unchanged validated and
supporting inputs. Metadata is refreshed, the final whitespace check passes,
and the installed Metapad file comparison is unchanged. `result.json` records
the nine new test methods, 38 solver queries including coverage, and the
remaining qualification boundaries.

## Separate issued reference identity from physical storage and lifetime

The production proof world now routes both flat resolution and realization
through issued-origin records that separate logical domain/object/generation,
physical object base, and the internal allocation lifetime token. Recording an
interior native tuple normalizes the base and checks the full extent. One logical
identity cannot move to another base or revive under a later allocation lifetime.
Realization uses the recorded base and lifetime token; allocation exclusion for
borrowed origins uses those physical fields too. Duplicate origins, including
different interior offsets, do not spend additional capacity. Extent/permission
variants remain separate records for compatibility with the existing flat model.

Nine new tests run 31 CBMC queries, including coverage witnesses and four mutants,
against the actual native allocation/resolution helpers and generated production
proof world. Cases cover full-width IDs, multiple allocations sharing one object
class, release/address reuse, incoming borrowed storage, conflicting mappings,
idempotence, forged metadata, symbolic storage/offsets, capacity exhaustion and
an object prefix that overlaps private storage before its public visible pointer.
The initial 64-test focused group passes in 56.127 seconds (57.539 including
preparation). The first capacity fixture asserted successful insertion past the
bound as well as the expected internal capacity failure; removing that competing
assertion selects the intended failure without changing the implementation.

The first affected run ended after 168.018 seconds on a code-generation test
that expected the private-range check inline in the resolver. The check now
lives in the shared recorder. The updated test follows the recording call, and
the added private-prefix solver case independently verifies the rejection.
The 21-test repair group passes in 18.495 seconds. Commands, input hashes,
logs and subsequent affected results are under
`build/reference-namespace/origin-records/`.

Four retained correspondence diagnostics also execute the real native code.
All four produce the expected explicit counterexample in under 0.3 seconds:
default re-resolution loses the enrolled native tuple; an unknown selector is
ignored by the proof resolver; the mapped realizer lacks a native authority's
interior-pointer restriction; and a valid native reference can realize without
prior resolution while the proof requires enrollment. These are recorded gaps,
not successful namespace proofs. The provider already parses and binds
`MachineObjectAuthorityV2`, but passes only rule IDs to overlay generation; the
contextual checker and proof-world renderer do not receive that authority
inventory. `integration-boundary.json` binds the inspected implementation files.

The next step must bind selected authority rules and justified live instances
through the normal checker, including selector ambiguity, canonical extents,
permissions, interior policy and incoming reference availability. It must then
preserve that relation through cuts and connected calls. Tuple enrollment alone
cannot justify general native-reference behavior or allocator-call admission.
The allocator blocker remains. No pilot/provider rebuild, Metapad SDK repin or
original-PE execution is part of this batch; the installed trial input hashes
match the preceding cut-consumer checkpoint.

Final affected validation passes in 146.189 seconds with unchanged validated and
supporting implementation inputs. Generated metadata is current and the final
whitespace check passes. `result.json` records the successful primitive tests
separately from the four unresolved namespace counterexamples; native namespace,
canonical native cut extents and allocator-call qualification remain false.

## Bind native object authority into the normal proof harness

The provider's parsed `MachineObjectAuthorityV2` now reaches the contextual
checker and existing proof-world renderer. Native resolution/realization was
extracted into `transfer/reference_namespace.py` and is shared by both runtimes.
The native rendered C remains byte-identical: before and after SHA-256 are
`3b59d282f768eea7226b2bd17ddfb99699103cc2d918870accd176a21ca9a2b6`.
The proof adapter realizes image-relative locators using the checked image base
and extent, and delegates selector filtering, ambiguity, canonical metadata,
interior/one-past and permission checks to that shared implementation.
Validated native tuples can be enrolled during realization without a prior
resolve call. The internal origin recorder preserves all runtime permission
bits, including execute metadata on image objects.

Every obligation retains the canonical authority core as a proof input with
the authority's identity hash. Models retain the parsed inventory and the
receipt world binds the same identity. Both readers require
`native_reference_authority_bound` and the bound input, rejecting predecessor
receipts. The Python reader also parses the inventory and reconstructs the
namespace helpers' unwind overrides from its rule count and selector byte
lengths. Exact-region and authored-source bounds stay at their existing values.
The input is written under proof diagnostics; no second memory engine or cache
was introduced.

Six new test methods cover canonical full-width IDs/extents/permissions,
realization without preceding resolution, unknown/ambiguous selectors, native
interior/one-past policy, unresolved runtime locators and normal-checker
integration. The first full-checker run exposed a missing JSON import, and the
next exposed the receipt reader's old exact model-field inventory. Both were
repaired. The 53-test focused group passes in 43.742 seconds (45.328 with
preparation). A retained normal-engine proof invokes an image lookup through
the generated runtime and passes in 2.100 seconds. Both readers accept that
receipt and reject five missing/false-policy, missing-inventory, wrong-world and
missing-input mutations after the enclosing receipt digest is refreshed.

The same normal checker gives an explicit counterexample when a lookup requires
an unqualified runtime locator. TLS, imported-data, captured-stack, allocation
and resource instances are not yet realized in the proof world. Consulting one
fails `spx-bisimulation-reference-locator-qualified`; it cannot silently fall
back to the flat namespace or treat an unknown instance as absent. Direct
diagnostics without native authority may still use the flat model, but cannot
satisfy the new strong receipt policy. The four preceding dynamic-origin
counterexamples are not claimed discharged for allocation instances.

Evidence is under `build/reference-namespace/authority-inputs/`, including the
retained normal proof, reader cases, byte comparison, commands and input hashes.
The installed Metapad source/intents/SDK pin match the preceding checkpoint.
No full pilot/provider rebuild or original-PE execution is part of this batch.
Native cut extent/generation reconstruction, caller-owned instances, allocator
freshness against the complete realized authority, and cross-cut lifetime
composition remain required before allocator admission and pilot qualification.

Affected validation passes in 236.243 seconds with unchanged validated inputs.
Generated metadata is refreshed, the final whitespace check passes, and the
installed Metapad comparison remains unchanged. `result.json` distinguishes the
image/reference-policy evidence from unqualified runtime instances, native cut
reconstruction and allocator calls.

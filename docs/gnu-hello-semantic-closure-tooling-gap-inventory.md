# GNU Hello semantic-closure tooling gap inventory

Status date: 2026-08-30

This inventory covers the current real GNU Hello
`linked-semantic-module-v1`. It groups blockers by the missing machine-derived
capability that can discharge them. A repeated blocker in several execution
contexts is not counted as several missing subsystems.

The audited artifact is
`/nix/store/gzgnix0434z6v7m47vfkh1msw275xz5g-spaghetti-extractor-gnu-hello-linked-semantic-module-v1/linked-semantic-module.json`.
It is incomplete and non-authorizing, with 4,498 reachable units, 6,056 edges,
63 fixed-point blockers, and closure identity
`118ae6fd855b860635ed661e289bfc4f73bb4f28088002cc2fdd64ae05c0216a`.

## Exact inventory

| Layer | Exact blockers | Distinct machine sites or forms | Missing capability |
| --- | ---: | ---: | --- |
| Qualified platform | 0 | All reachable x87 forms | Closed in the current qualified platform; concrete-oracle disputes no longer block Hello. |
| Closure callee effects | 12 | 2 narrow/wide formatting sites | Preserve a must-proven formatting-object identity through long-lived frame storage and shared summaries. |
| Closure external writes | 33 | 6 call sites | Preserve exact heap, frame, argument, and interior-object provenance at checked write boundaries. |
| Closure indirect targets | 18 | 18 sites in four structural groups | Preserve initialized code-pointer cells, resolve one lazy code-capability cell, and prove one bounded jump-table target set. |

The 63 fixed-point rows are not independent. Unresolved external writes invoke
the required conservative all-memory fallback. That destroys exact facts in
otherwise initialized writable code-pointer cells and accounts for much of
the indirect-target frontier. Closing only the derivative indirect sites would
either special-case Hello or incorrectly treat writable data as immutable.

## 1. Reachable x87 qualification (closed)

The earlier ten reachable platform holes were structurally complete
Lean-selected forms whose concrete-oracle qualification was `disputed`; they
were not missing decodes or transfer operations. They comprised:

- three stack binary forms: reverse-subtract with pop, subtract with pop, and
  divide without pop;
- three memory binary forms: float32 multiply, float32 reverse-divide, and
  float64 multiply;
- two int32 store forms, with and without pop; and
- two ordered EFLAGS compare forms, with and without pop.

The current `qualified-platform-v1` is complete, has no blockers, and has no
disputed forms. The Lean kernel remains authoritative where covered; concrete
executors remain veto/supporting evidence. No x87 work is on the current Hello
critical path.

## 2. Exact write-boundary provenance

The environment already contains checked physical frames and exact memory
footprints for every remaining external call. No import profile is absent.
What is missing is a must-proven object value at the machine argument slot.

| Source RVA | Function and call | Context rows | Missing fact |
| --- | --- | ---: | --- |
| `0x0000f9ad` | `___gdtoa` to `memcpy` | 3 | `___Balloc_D2A` result must remain the exact destination allocation; the source allocation and length field must remain correlated. |
| `0x00010245` | `___multadd_D2A` to `memcpy` | 22 | The new `___Balloc_D2A` object, old big-number object, and derived byte extent must survive the shared allocator/helper summaries. |
| `0x00013b20` | `___wcrtomb_cp` to `WideCharToMultiByte` | 2 | The caller output pointer and local stack views must remain distinct exact objects through frame-slot loads. |
| `0x00013da9` | `___mbrtowc_cp` to `MultiByteToWideChar` | 1 | Preserve the checked caller input/output object identities through the conversion wrapper. |
| `0x00013e73` | `___mbrtowc_cp` to `MultiByteToWideChar` | 1 | Preserve the same identities on the alternate one-unit path. |
| `0x00014318` | `__unlock_file` to `LeaveCriticalSection` | 4 | Prove the `FILE + 0x20` interior view, including the branch that distinguishes CRT standard streams from other `FILE` objects. |

This requires extensions to the existing reference interpretation, not a new
object registry:

1. Relational returned-object identities must instantiate an internal
   allocator summary at each exact caller without merging the exact result
   with unrelated allocation alternatives.
2. Exact object words stored in captured frame slots must remain must-facts
   across shared internal calls and loop joins. Missing paths may not be filled
   from surviving sparse may-information.
3. Interior-pointer derivation and comparisons must retain the parent object,
   offset, and branch-refined range needed by the checked footprint.
4. Checked memory-transfer providers such as `memcpy` already carry the
   canonical `byte_copy` read-to-write relation and transfer exact
   reference-bearing words when destination, source, and extent are exact.
   The live Hello failures occur before that relation can apply: their
   arguments have already become conflict/unknown values. Do not add another
   library model for this case.
5. Scalar extent reasoning should retain field-derived sizes where useful,
   but an unknown extent over an exact object must continue to invalidate the
   conservative object suffix. It cannot grant write authority by itself.

Rejected global call-string depth, alternative-limit inflation, generic
register-origin products, transient input-shape contexts, delayed fallbacks,
universal relational parameterization of every projected stack word, and
enumeration of every known object must not be reintroduced. They were slower,
schedule-sensitive, graph-pruning, or did not improve authority on the real
target. In particular, universal stack-word tokens reduced external-write rows
but pruned the real universe to 4,343 units and 5,826 edges while creating 114
callee-instantiation blockers; demand selection must be based on exact callee
reads instead.

## 3. Formatting-object summary instantiation

The 12 callee-effect blockers collapse to two actual calls:

- eight contexts at narrow RVA `0x0000c2b0`, calling
  `___pformat_putc` at `0x0000b3b0`; and
- four contexts at wide RVA `0x000123d0`, calling
  `___pformat_putc` at `0x00010dc0`.

At each site EBX is copied to EDX and the callee writes a field of that
formatting object. The callee summary is correct. Some full-program callers
have already lost the formatting-object identity before this instruction, so
the summary's object parameter cannot be rebound. An isolated replay with an
exact formatting object traverses the same helper and tail-call path with zero
blockers; no tail-call model is missing.

The required feature is demand-driven must-provenance for the exact
formatting-state frame slot. It should specialize or parameterize only the
existing summary dependency that is actually read by the callee, retain an
explicit conservative caller continuation, and preserve the complete root,
edge, and exception universe. Z3 may prove an opaque caller path infeasible,
but a solver result is supporting evidence over transfer-v2 constraints and
must not become a second semantic pipeline.

## 4. Indirect-target recovery

The 18 current sites have two remaining structural causes. The earlier pformat
jump-table proof is closed in this baseline.

| Sites | Structural source | Required capability |
| ---: | --- | --- |
| 17 | Initialized writable code cells and loader-written IAT cells, dominated by RVA `0x000200d0` pointing at `___acrt_iob_func` | Retain initialized/imported code capabilities when checked writes affect other exact objects. Re-inventory the small IAT subset after write-boundary provenance closes. |
| 1 | `____lc_codepage_func` through mutable cell RVA `0x000200ac` | Model the existing lazy initializer as an atomic stateful code-capability publication: finite internal fallbacks plus checked dynamic export resolution, followed by strong update and tail dispatch. |

The first 17 rows are initialized/imported function-pointer loads, not missing
x86 decodes. Their baseline code identities are present before unresolved
writes poison memory. They are therefore derivative until the six write sites
are fixed and replayed. The lazy cell is the remaining independent
target-recovery feature.

The lazy cell should reuse the existing loader-service contracts,
code-capability registry, memory state, and atomic publication semantics; it
must not introduce a runtime target annotation or a separate dynamic-call
authority. Z3 remains appropriate for future finite target-set enumeration,
but is not needed for the already-closed pformat table in this baseline.

## 5. Diagnostic tooling

The current receipt remains fail-closed and reports every final context row.
The following non-authorizing views now exist under
`expert semantic-diagnose`:

- `--view causes` groups repeated context rows by exact machine cause and
  carries callee-return failure reasons, register inputs, and parameter
  bindings;
- `--view invalidations` projects first observed whole-memory transitions and
  their downstream poisoned units and blocker rows;
- `--view slice` retains the exact transfer, neighboring edges, blockers, and
  decoded compact reference-fact catalog rows for one RVA, slices backward
  from the blocked effect, collapses repeated execution contexts, and maps
  physical call arguments to same-transfer or immediate-predecessor stack
  writers when the canonical transfer makes that relation explicit;
- `--view replay` evaluates one bounded operator-supplied transfer/state case
  through both the Python reference evaluator and independent Rust kernel and
  reports agreement without creating authority; and
- `--view delta` vetoes root changes or removed units, edges, and exceptions
  while reporting blocker additions and removals.

The paired replay has a focused allocator-plus-copy fixture.  It proves that
an exact allocation returned by a checked external call can flow directly into
the existing canonical `byte_copy` relation and produce the same copied
code-capability word in both kernels.  The diagnostic case is explicit input;
tests and replay remain veto-only and cannot fill a missing real-target fact.

At `0x00010245`, the effect-rooted slice collapses 22 blocker rows to one
machine demand.  Arguments zero and one are loaded from stack offsets zero and
four and have exact same-transfer writers; argument two has an exact writer at
stack offset eight in the sole direct predecessor `0x00010234`.  All three
writer values are register-derived.  This is the first cheap, machine-local
witness that the missing relation is the value stored in each physical frame
slot, not the existence of a checked `memcpy` rule.

These are views over the resident canonical semantic module and its one fixed
point. They must not be persisted as authority, consumed by native realization,
or become alternate closure inputs. Their purpose is to replace manual
whole-program archaeology and make a failed real-target experiment cheap to
understand.

## Recommended implementation order

1. Preserve a relational dependency only for the three effect-rooted physical
   frame slots at the two `memcpy` sites. Trace each writer value backward to
   the allocator result, old object, or extent; retain the ordinary
   conservative continuation wherever that exact chain does not close.
   Exercise the existing canonical `byte_copy` relation; do not create a
   second provider path.
2. Preserve exact caller/frame-slot objects for the narrow/wide conversion and
   formatter slices. Accept only a change that retains 4,498 units, 6,056
   edges, all checked exception continuations, Python/Rust parity, and reduces
   the corresponding blocker family.
3. Add interior-object comparison/range refinement for `FILE + 0x20` and close
   `LeaveCriticalSection` without declaring the CRT object or writable data
   immutable.
4. Replay the initialized/IAT indirect sites. Most should close as the
   conservative all-memory invalidations disappear; inventory any survivors
   from their new first-loss witnesses.
5. Keep the closed pformat table proof in regression coverage and implement
   the codepage lazy code-capability publication as one independent vertical
   slice.
6. Keep the now-complete x87 qualification campaign in the regression gates.
7. Run the full Hello semantic link, independent Python replay, native
   performance samples, target regression, Behavioral-C/native realization,
   Wine observation, deployment, and project completion gates.

Two full-Hello allocator experiments are explicitly rejected. Qualifying
external-allocation identities by the exact active frame produced 4,497 units,
6,054 edges, and the same 63 blockers. Renaming newly observed allocation
identities at an internal return boundary produced the identical regression.
Both Python and Rust implementations were reverted. Allocation names alone do
not preserve the downstream frame-slot/value dependency and must not be
reintroduced as a substitute for the effect-rooted relation above.

The current selected Hello work status also reports one
`provider_qualification_incomplete` blocker for the optional portable-C
provider. That is downstream of and separate from semantic closure. Clearing
the 63 fixed-point blockers will not by itself qualify that authored provider; it
must retain its own compile/refinement/service/ownership evidence or the
configuration must select generated Behavioral C for those symbols.

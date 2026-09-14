# Independent component lifting: Metapad milestone audit

Assessment: the small, hand-defined network demonstration meets the active goal's
four completion requirements under explicit trusted runtime contracts. This is
conditional local correctness with separately tested runtime applicability. It is
not general boundary-driven composition, universal runtime qualification, a strong
contextual-bisimulation receipt or native activation. The public products continue
to report those distinctions.

This audit supersedes earlier milestone-status paragraphs in the chronological
[current-goal journal](../current-goal.md). It does not complete the broader
[independent lifting plan](../independent-portable-lifting-plan.md). Checked general
split/merge, richer contract refinement, representation changes, unrelated-target
reuse and the Hello/jq/DX-Ball qualification path remain subsequent work.

## The actual network

| Authoring component | Original behavior | Dependency |
|---|---|---|
| Resource text | Operation rooted at `0x1284`; read the module handle, load into a shared image buffer and return its alias | Named output-service contract |
| Text cleanup | Complete operation rooted at `0x55b7`, covering 35 original transfers; allocate scratch, loop over mutable text, remove CRCRLF duplicates, copy back, release and optionally notify/focus | Checked resource summary and named allocation, memory and Win32 service contracts |
| Save preparation | Transfers `0x5c2a` and `0x5c34`; clean text and subtract the result from the current length word | Checked cleanup summary |
| Guarded UI replacement | Five transfers rooted at `0xb18e`; modes 2/3 bypass cleanup, then deliver current text to the current EDIT handle | Checked cleanup summary and named returning SendMessage relation |

The two consumers are distinct real application contexts. Structural incoming-edge
coverage is checked; reachability from every original application entry is not
claimed. The cleanup proof uses entry/loop/tail obligations and seven source proof
regions inside one ordinary-C function. They are not seven authoring components.
Machine continuation pushes and register transport stay outside the production C
API. Replacement groups concern compatible deployment of implementations and
adapters; no independent activation entitlement follows from these local proofs.

The exact transfer plan identity is
`33f6ad7e3e6b1541d59ed2279b14621e2cb9bcf7582b8957bbc6fd727acf2590`.
The original Metapad PE identity is
`685989bad8d8119eddbb49e36006d8ac9155c45d69dee060807368241c8e58ce`.
The [initial experiment](2026-09-07-independent-lifting-experiment.md) retains the
original decomposition inputs and costs; the evidence below checks the final state.

## Requirement-by-requirement result

| Active-goal requirement | Evidence and assessment |
|---|---|
| 1. Explicit boundary contracts and preserved original behavior | The validated cleanup operation summary includes complete interface/projection identity, current public bytes and aliases, live view permissions/extents, allocator separation and lifetime premises, private/public frames, normal and fault outcomes, ordered observations, normal continuation registers and a checked decreasing control rank. Its original cover contains all 35 owned transfers and the real resource call. Save admits all uint32 length values; UI preserves both bypass guards and all uint32 normal reply values. Memory faults do not borrow the normal-return register frame. **Met for the selected operation domain.** |
| 2. Ordinary C, local correctness, absent neighboring bodies, separate runtime compatibility evidence | Current production readers validate the real regional/composition and consumer proofs. Runtime cleanup/save/UI/resource sources bind to the exact proven C; both resource variants' generated headers also match. Consumer compilation inventories contain only their own authored C, original caller slice, generic support and paired proof model. They contain neither cleanup implementation. The cleanup summary imports the resource proof; consumer models omit the resource bodies too. Separate native tests exercise the generated adapters and actual services, with named runtime assumptions remaining trusted. **Met as a conditional proof and independent finite-validation demonstration; formal runtime qualification remains unverified.** |
| 3. Public edit, error detection, repair and meaningful neighboring implementation reuse | Actual `component check --source --local-contracts` artifacts detect wrong save arithmetic and a missing UI mode guard. Repairs reuse exact proofs. Changing resource retrieval from a word read to a four-byte loop is independently proved under the same complete contract; updated evidence propagates through cleanup to both consumers. Each consumer retains the same proof key, all proof files and compiled model with zero model/compiler/solver work. Actual Nix declarations change the supplier evidence input, so revalidation/rebinding is still required. **Met; this is more than an exact-repair cache hit.** |
| 4. Incompatible refinement and accurate visible invalidation | The public checked conjunction rule withdraws EDI preservation. Save reuses its proof because it overwrites EDI; UI reports the exact missing guarantee and produces no reused or new proof. Deliberately underdeclaring the UI requirement instead makes its real argument proof fail. Public JSON exposes required/available/missing facts, contract/evidence identities, named runtime assumptions, scope and non-authorizing status; plain text names the missing equality. **Met for this implemented refinement rule.** |

The refinement rule cannot add a guarantee or change non-frame contract terms.
Their full semantic identity remains bound; a matching C signature is insufficient.
No claim of general contract subtyping, automatic boundary recommendation or
arbitrary-target composition is part of this completion.

The final current-reader audit imports the baseline/error/repair/neighbor products
for both consumers and the selective-refinement products with processes and model
or header generation forbidden. It checks current producer bindings, every proof
file, real compiler inventories, public feedback, supplier evidence changes and
Nix input declarations. It completes in 43.439s with no proof execution. All 659
production Python modules match the public experiment's source snapshot.

## Runtime validation and its exact limit

The independent validation is deliberately weaker than universal runtime proof,
as allowed by the active goal's trusted-runtime approach. It validates concrete
premises against actual services without relabeling a conditional proof as strong.

The consumer fixture runs 15 cases on original and ordinary-C sides for each of
the exact proven normal and loop-edit resource implementations: 60 successful
original/C executions in total. It exercises actual GlobalAlloc/GlobalFree,
lstrlenA/lstrcpyA, SetFocus/SendMessageA, EDIT windows, LoadStringA and MessageBoxA.
Nine native allocation/image-origin function bodies match the production renderer.
It checks current contents, interior aliases, prefix/suffix frames, ownership
release, scratch expiry, callback-updated handles, integer boundaries, both mode
bypasses, normal continuation transport and exact effect/fault order. EDIT contents
survive borrowed-input mutation and release. Eight deliberate failures reject.

The original PE is mapped with SEC_IMAGE. Resource 31 and the caption come from its
actual sections. The resource view's section identity, generation, extent, offset,
permissions and address transport are checked. Removing native image admission
after unmapping rejects a saved reference. Image-address translation and raw
memory/stack admission remain fixture-owned; the test does not qualify a general
loader, relocation adapter or same-base unload/reload generation scheme. A local
CBT hook closes the fixture's own dialog. Arbitrary reentrancy, nonreturning calls,
invocation failures and original application reachability remain outside this
validation. Resource success and termination in these cases do not add a general
NUL postcondition to the resource or cleanup contracts.

The separate existing issued-reference test has been rerun against current inputs.
It exercises actual `GlobalAlloc(UINT32_MAX)` failure, preserving older allocations'
contents and identities; null-page/native admission; unavailable permissions;
wide offsets and crossing spans; release revocation; and nine negative controls.
Its 149 declared input paths match current bytes. This supplements the consumer
fixture's injected failure branches; neither test substitutes for local proofs.

The reusable runtime evidence consists of independent Nix test products and exact
source/body bindings. The local proof key does not depend on executing these tests.
It still depends on the named/versioned trusted runtime contract. Formal products
correctly retain `runtime_compatibility: unverified` and
`activation_authorized: false`.

## Measured edit and reuse costs

All times are seconds from retained public runs, checked against current producer
and input identities. Public command times start with prepared source packages;
source-input preparation and host/PE32 compilation for the wrong edits are recorded
separately (save: 0.0011/0.0600s; UI: 0.0013/0.0605s). They are not hidden inside a
claim of measured from-scratch binary preparation.

| Consumer | Public baseline | Model render | Dependency inventory | GOTO compile | Symbolic execution | SAT solving | Complete query |
|---|---:|---:|---:|---:|---:|---:|---:|
| Save | 24.536 | 0.000058 | 0.124 | 0.106 | 0.495 | 4.506 | 5.189 |
| UI | 21.687 | 0.000063 | 0.122 | 0.187 | 1.998 | 0.304 | 2.568 |

| Consumer | Wrong-edit public check | Repair | Compatible neighbor | Model bytes before/after neighbor |
|---|---:|---:|---:|---:|
| Save | 17.679 | 19.720 | 19.855 | 387,880 / 387,880 |
| UI | 14.454 | 19.224 | 20.040 | 861,641 / 861,641 |

Both neighbor runs generate/compile/solve zero models. Cleanup composition likewise
reuses all nine queries under the resource change (18.892s public latency). The
public guarantee withdrawal takes 20.782s; save reuses in 19.921s and UI identifies
the missing guarantee in 10.437s without a query. Recursive evidence validation
still accounts for about seven seconds in a consumer command. Independence does
not mean zero command cost.

The final native baseline prepares in 0.0374s, compiles twelve translation units
in 0.630s, links in 0.0401s and runs 30 executions in 7.783s including Wine/display
startup. The neighbor runtime takes 6.581s. No pilot or application proof model was
rebuilt to add this validation. Preparation, rendering, compiler, solver, evidence
reuse and native-link/runtime measurements remain separate in the retained logs.

## Validation and evidence index

Fifteen current native tests cover the consumer/resource network, earlier cleanup
adapters and the separate allocation contract. The 27 retained local-proof tests
have all 25 declared inputs current. Four repository gates pass. The repository
boundary shard still has exactly its two pre-existing failures and seven unchanged
size offenders; this is not a claim that the full repository test suite is green.
Unrelated dirty-tree work remains untouched; no commit, publication or activation
was performed.

Evidence is under `build/independent-lifting/practical-assurance/`:

- `independent-milestone-proof-audit-v1.json` and its script/log: current public
  evidence validation, source/model binding and real Nix dependency comparison.
- `milestone-public-production-snapshot-v1.json`: all production Python files match
  the snapshot used by the public workflow experiments.
- `public-cleanup-composition-v14/`, `public-cleanup-save-v5/`,
  `public-cleanup-replace-v2/`, `public-cleanup-contract-refinement-v1/`: actual
  public command outputs, flakes, source edits, proof products and timings.
- `consumer-resource-bindings-v1.json`, `consumer-resource-test-inputs-v2.json`,
  `consumer-resource-timings-v2.json`, `checkpoint-v120.json`: exact runtime/proof
  input binding, native outcomes and unchanged local proof reuse.
- `milestone-allocation-test-audit-v1.json`, `milestone-allocation-native-v1.log`:
  current actual allocation-failure test and all input hashes.
- `independent-milestone-completion-v1.json`: final requirement matrix, source and
  evidence hashes, gate products and completion state.

The retained examples use the supported command shape inside `nix develop`:

```sh
spaghetti-extractor component check metapad cleanup-save --source --local-contracts --target-flake path:./build/independent-lifting/practical-assurance/public-cleanup-save-v5/neighbor --local --json
spaghetti-extractor component check metapad cleanup-replace --source --local-contracts --target-flake path:./build/independent-lifting/practical-assurance/public-cleanup-contract-refinement-v1/consumer-replace --local
```

The first returns conditional source-check completion and reused proof work. The
second returns incomplete and names the missing EDI guarantee. These are retained
hand-defined target flakes, not an automatically generated component network.

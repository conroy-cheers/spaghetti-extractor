# Practical independent lifting: completion audit

Links into `build/` identify locally retained run artifacts, not repository source
files. They are excluded from generic Nix test shards; their existence was checked
locally when these links were refreshed on 2026-09-16.

The subsequent [larger jq path/value experiment](jq-path-network-assessment.md)
exercises four further operations and actual interpreter consumers, and records
ownership, preparation and invalidation shortcomings. It does not expand this
milestone’s qualification claims.

Status: bounded G1–G6 practical-workflow milestone accepted, 2026-09-16.
The implementation demonstrations, installed-CLI walkthrough and final validation
are reconciled below. Strong target/native-module qualification remains incomplete
and continues to block its corresponding activation, link, export and portability
claims. This audit covers the bounded [G1–G6 milestone](current-goal.md).
Earlier checkpoints retain their historical statuses; the final acceptance section
at the end supplies the current milestone decision and qualification limits.

All evidence paths below are relative to
`build/practical-lifting-2026-09-15/`. Historical executions retain their original
scope. `validation-v1/retained-evidence-audit.json` records current-reader checks
of 29 comparison results and three experimental manifests, including exact input,
output, binary and policy bindings. Re-reading evidence does not claim a fresh
execution. No practical comparison authorizes strong qualification.

| Requirement | Evidence and demonstrated scope | Acceptance and limits |
|---|---|---|
| G1: real operation, retained inputs and boundaries | jq concat at RVA `0x288b3`, append at `0x287bd`; retained native libjq, typed interfaces, adapters, source and caller cases. The concat loop exercises mutable arrays, sharing, copy-on-write, multiple services and caller contexts. Fixture READMEs state original identities and assumptions. | Passed in `installed-cli-v1` using the packaged CLI without source PYTHONPATH. |
| G1: supported C and proof eligibility | The existing restricted C profile, generated headers and `compile_commands.json` are used by public `component start/check`. `integrated-network-optional-v1` has six matching native cases and an actual unavailable source-proof rule. Profile/diagnostic failures are covered by source/check and comparison tests. | No universal C or Win32 support claim. |
| G2: edit, divergence, replay, repair | `integrated-network-wrong-v3`, `integrated-network-wrong-replay-v3` and `integrated-network-repaired-v3`; current network preparation also passes in `validation-v1/network-setup-baseline`. All retain actual native original observations and ordinary authored C. | Passed in `installed-cli-v1`, including replay after the editable source was repaired. |
| G3: isolated supplier and neighbor reuse | `supplier-network-audit-v3.json` and `supplier-body-inventory-v3.json` record a real supplier body edit/growth, complete original append body interception, absence of authored append from the isolated executable, zero isolated work and affected integration re-execution. | Preserve the exact body-absence scope; original libraries remain available for setup and observation. |
| G3: refinement and assumptions | `domain-refinement-v1` retains four excluded counterexamples, an excluded-case replay, five actual caller-assumption violations, and the repaired domain/integration. Refinement changes the input domain despite an unchanged C signature. | This checks declared word intervals and concrete caller observations, not arbitrary heap contracts. |
| G3: existing formal evidence reuse | `optional-memory-contracts-v2/baseline` and `reused` retain two existing source-memory proofs; reuse has zero formal compiler/model/solver work alongside concrete comparisons. | These are source frame/input-dependence proofs, not original/source equivalence. |
| G4: typed experimental selection and run | `experimental-network-optional-v1`, `domain-refinement-v1/experimental-repaired` and `representation-v2/experimental-handles` bind selected bodies, interfaces, adapters, runtime, policy, checks and actual binary. Actual unavailable-rule and CBMC-timeout runs are retained; a formal counterexample is rejected even when sampled cases match. | Current qualification, selection and native-realization readers reject these manifests. Qualified pilot realization remains a separate, unresolved obligation. |
| G4: fail-closed authority separation | Candidate tests reject mismatches, partial selections, unaccepted assumptions, stale headers/runtime/binary/suite, and experimental manifests at qualified readers. Suite and per-case gates use the typed admission path. | These gates do not make experimental execution portable or strongly qualified. |
| G5: second target interaction | `dxball-lifecycle-v1` executes the retained machine-derived DirectDraw-init tail through two actual failure/cleanup paths, checking eight state words, arguments/order, lifetime and return frame. Bug/replay/repair and zero-work reuse are retained. | Window-creation prefix, real Win32 services, callbacks and GUI execution remain outside this scoped oracle. |
| G5: bounded private representation change | `representation-v2` compares raw values and owned handles with identical authored C/interfaces and logical observations. Both components share one handle table. Mixed revisions and relabeled incompatible bytes reject before compilation; expiration/leak controls fail; the full selected group runs experimentally. | Group membership is reviewed, flat and explicit; byte agreement is not a compatibility theorem or inferred complete reader coverage. |
| G6: faulty fixtures and aliases | `validation-v1` rejects equal-content replacements that lose whole-array, slice or nested-object aliases, incorrect logical input contents, loss of a unique destination, and a wrong controlled-service argument. DX-Ball and handle-table controls exercise order/lifetime failures. | Original-side setup failure stops the comparison before the replacement runs; it cannot become a matching empty result. |
| G6: omissions, exclusions and false readiness | Comparison/domain/experimental tests cover missing observations, empty cases/domains, changed projections, dropped admitted cases, stale outputs, invalid profiles, timeouts and false qualification. | Keep failure categories and scopes explicit. |
| G6: costs and invalidation | Comparison and optional-proof receipts record preparation/compiler/model/solver/execution/link work, reuse and phase times. Unrelated growth does not enter the isolated dependency set. Refinement-history validation/copying and artifact hashing now have separate timings; hashing avoids unrelated runtime trees. | Phase totals are measurements, not a complete wall-clock profiler. Fresh phase and command wall times are retained in `installed-cli-v1/audit.json`. |
| G6: repository validation | All 33 repository checks pass after responsibility-based splits. Moved function/test ASTs and sampled generated C remain unchanged. Current practical and source/Metapad Nix suites pass 37 and eight tests respectively. | The eight final metadata/lint/registry, strong-admission, native-ingress/PE32 and platform gates pass. Pilot/native-module qualification failures and baseline attribution are recorded separately; those qualifications remain blocked. |

## Operator entry points

Use `nix develop` at the repository root for the pinned CLI, compiler and runners.
Run each Wine walkthrough inside one `spaghetti-headless-wayland` invocation
(for example, `spaghetti-headless-wayland bash walkthrough.sh`). This provides
an isolated Wayland desktop with Xwayland and keeps its environment stable across
checks intended to reuse evidence.
Each walkthrough starts from SDK packages, creates editable ordinary C and uses
public commands. No routine digest/model editing is required.

- [jq supplier edit, isolation and domain refinement](../tests/fixtures/jq-array-append/README.md)
- [jq representation group and experimental execution](../tests/fixtures/jq-value-transport/README.md)
- [DX-Ball failure/lifecycle comparison](../tests/fixtures/dxball-directdraw-lifecycle/README.md)
- [Connected DX-Ball initialization, shared state and blit workflow](../tests/fixtures/dxball-graphics-network/README.md): subsequent P4 checkpoint, 37 connected cases plus edit/replay/reuse and experimental assembly; controlled retained-C services, not native DirectDraw execution.
- [Hello allocation through its real quoting consumer](../tests/fixtures/hello-allocation-growth/README.md): 522 growth cases, 32 free-wrapper cases and 144 connected sequences, public edit/replay/reuse and three-unit experimental assembly. Actual growth replaces the simulated service; lower allocation and quoting-engine services remain controlled.
- [Native Hello quoting consumers](../tests/fixtures/hello-native-quoting/README.md): the same three C units execute inside actual PE32 callers, quoting engine, allocator and cleanup; 21 cases, public edit/replay/reuse and experimental assembly pass. The test-only loader boundary omits original startup/TLS; local supplier checks retain their host/controlled-service scopes.

The implementation retains the contextual-bisimulation contract, qualified native
admission, export and portability obligations. Passing component-driver tests in
Wine is not evidence that jq or DX-Ball is fully lifted or portable. Existing
strong pilot gates must be checked in their own scope before this milestone closes.

## Fresh installed-CLI acceptance checkpoint

[installed-cli-v1/walkthrough.py](../build/practical-lifting-2026-09-15/installed-cli-v1/walkthrough.py) ran 22 public CLI commands from writable SDK
packages, with `PYTHONPATH` removed. All expected exit codes passed. The actual
installed binary is
`/nix/store/dy63qnzcqawdysy6mrj2s7dggxfvpf0h-spaghetti-extractor-0.1.0/bin/spaghetti-extractor`.
Current readers validated all 16 comparison receipts and the experimental manifest;
the comparison engine hashes match the working source. This is a current-reader
check of exact executions, not a claim that every installed module matches later
unrelated edits.

The jq baseline matches five supplier, six integrated and eight isolated cases.
An ordinary compatible append edit reruns the supplier and real integration while
reusing all isolated cases. An index bug exposes a null gap at `$.result[2]`;
replay from retained inputs still fails after repairing the draft. The repaired
supplier/network and isolated consumer reuse matching evidence with zero compiler,
link, model, solver and execution calls. The optional jq rule reports unavailable.
The selected handle-representation network runs experimentally with six passed,
zero failed cases and binary SHA-256
`d2a0929a6631d7ece42984e30dcf65a3a0f9fb9ca107c8651ffb1fdc76c3d20c`.

DX-Ball matches eight cases. A wrong cooperative-level message changes four
observations at `$.services[3][2]`; retained replay fails after draft repair, and
the repaired source reuses its eight matching cases. This remains the scoped
machine-derived-C failure-tail oracle described above.

| Installed command | Wall seconds | Compiler calls | Execution calls | Link calls |
|---|---:|---:|---:|---:|
| jq supplier after compatible edit | 11.170 | 4 | 10 | 1 |
| jq real integration after supplier edit | 12.433 | 5 | 12 | 1 |
| jq isolated consumer after supplier edit | 0.367 | 0 | 0 | 0 |
| jq repaired integration reuse | 0.554 | 0 | 0 | 0 |
| DX-Ball repaired reuse | 0.626 | 0 | 0 | 0 |

All rows perform zero model/solver calls; that states scope, not proof success.
The audit separately records preparation, compiler, linking, execution, validation,
retention and hashing phase times. Wall times include Python startup and other
unclassified overhead and were measured alongside validation builds.

The ten root repository/native gates and the final 27 practical Nix regressions
pass (`validation-v1/repository-native-gates-v2.log` and
`validation-v1/nix-practical-final.log`). Subsequent pilot validation exposed two
issues: Hello's fixture symbol-dump pipeline could exit with SIGPIPE, and DX-Ball's
entry-register service target lacked typed proof transport. The shell extraction
now consumes its complete input. The register transport matches the production
thunk and retains target/non-null checks; ten targeted tests pass locally and in
Nix, including wrong-target, erased-check and malformed-recipe controls. Final
pilot and affected gate results after these changes are still pending.

On operator instruction, subsequent Wine launches use a headless Wayland desktop.
`headless-wayland-v1` retains an actual Weston headless session, its isolated
Xwayland display and a second six-case passing experimental run. The shared Nix
runner passes its real-compositor acceptance gate for exact stdout/stderr, streaming
stdin, exit status and cleanup. The gate is
`/nix/store/1fpr45dj1ribmyawxrv4a77yzip405da-spaghetti-extractor-headless-wayland-check`.
`headless-wayland-reuse-v1` verifies eight real jq cases in one such session: a
fresh check takes 9.126s and unchanged reuse takes 0.376s with zero compiler,
link, execution, model or solver work. Current readers validate both receipts.
The subsequent candidate-suite gate passes with a pinned Fontconfig setup.
The native-module gate now reaches qualified selection and fails because that
selection is incomplete; it does not activate a fallback. Pilot validation also
exposed jq continuation context missing from exact-C preparation. These remaining
authority-path failures must be resolved before final pilot/native acceptance.
The prior pilot process was explicitly stopped after its inputs changed, retaining
completed preparations and its log; no final pilot run is currently active.

## Remaining gate investigation

- `validation-v2/native-load-fault-gate-v2.log`: native-module hybrid realization
  still rejects an incomplete selection. The shared Behavioral-C renderer now
  checks each load before evaluating a dependent load, preventing a later access
  from clearing an earlier fault. The executable regression rejects the old
  renderer (`load-fault-negative.log`); 47 focused tests pass locally and in Nix
  (`load-fault-tests.log`, `nix-load-fault-tests.log`). The Nix test output is
  `/nix/store/s11xqrcyp1wcap4cj5g6yl4j8q4vkqz7-spaghetti-extractor-test-suite-affected`.
  The remaining counterexample places the returned interface object inside the
  private stack: the typed adapter rejects it while the original-side model
  returns normally. `native-interface-investigation.json` binds both before/after
  receipts and selected trace values. Establish consistent checked interface
  storage, contents and lifetime rules; do not add validity assumptions solely
  to exclude the failing inputs. Native registration now implements the declared
  object/vtable image-and-stack separation before either range is registered.
  `native-interface-storage-tests.log` retains four focused tests against the
  generated C, including arbitrary span geometry and the exact private-stack
  counterexample. Erasing its object guard makes the latter proof fail.
  `native-interface-regressions.log` and `nix-native-interface-tests.log` retain
  17 passing related tests; Nix output:
  `/nix/store/xhynsl4y77rs8ym8yr7qzms2dwjqja12-spaghetti-extractor-test-suite-affected`.
  `native-interface-runtime-gates.log` records passing native-ingress and PE32
  project gates under headless Wayland, plus metadata and lint. The native outputs
  are `/nix/store/0lnnvw8pw1j60a6i38v34p4wyrir96xq-spaghetti-extractor-native-ingress-runtime-check`
  and `/nix/store/zykhc5vm2hswyfv1ajg00756l5skkbq0-spaghetti-extractor-pe32-project-check`.
  `native-interface-repository-tests.log` records 37 passing repository/semantic
  boundary tests. The registration tests stub bookkeeping and memory reads to
  observe admission/ordering; they do not claim object backing or lifetime proofs.
  The proof response rule remains to be composed and checked.
- `validation-v2/continuation-context-tests.log` and `nix-context-tests.log`:
  20 focused tests pass. `jq-exact-context/` is fresh preparation from the retained
  transfer and binding inputs. It includes
  `semantic-transfer:original-cutpoint-00001cdb-00001ce8` as unowned proof context.
  Binding, exact-C, semantic-contract, work-package and direct-provider consumers
  now share that inventory. The Nix dependency predicate also supplies linked
  module facts for continuations. `jq-linked-context-gate-v2.log` advanced to
  a missing explicit `jv_copy` effect contract. That gap is now addressed by the
  shared `sdk.environment.nativeCallthroughProfile` constructor and the authored
  `targets/jq/intent/libjq-output-native-effects.json` input. The constructor binds
  both inputs, rechecks physical ABI agreement, and keeps the other 130 imports
  ABI-only. It retains the existing native call-through prerequisites and does
  not infer heap or lifetime guarantees from headers.
- `validation-v2/jq-explicit-effects-gate.log`: the profile and environment build,
  then the provider stops at `semantic_external_transducers.py` with a missing
  `parameter_index` for the raw `aggregate_result` recipe. That preparation error
  is now fixed by shared hidden-return normalization and complete word-record
  argument/result transport. `jq-record-preparation.log` and
  `jq-aggregate-preparation-costs.json` retain a satisfied semantic contract from
  the real pinned inputs and checked image metadata in 1.872s, with no compiler,
  model, solver, link or execution work. `jq-record-gate.log` has reached CBMC;
  it does not yet establish a satisfied proof. The independent retained-input
  Z3 experiment (`jq-retained-z3-v2.log`) completes with an **incomplete** provider:
  `/nix/store/ahkhgzjcpac0mbhi857r05n44fb6j5zv-spaghetti-extractor-jq-retained-z3-portable-c-work-package-provider-v2`.
  Nonvacuity passes; singleton bounds and pointer safety queries time out at 30s.
  `jq-z3-investigation.json` records separate compilation (0.308s), inventory,
  query and witness costs. Query sums include parallel work and are not wall
  time. The retained model has two calls, 18 static writes and 14 cached stack
  accesses; its main C file is 255,957 bytes. No speedup or solver success is
  claimed. The first Z3 attempt lacked Nix store-path context in the retained-input
  expression and failed before preparation; `-v2` binds those paths correctly.
  `jq-query-diagnostic/` recompiles the retained source inventory and captures a
  five-second verbose sample; it remains in symbolic execution, repeatedly
  traversing sparse byte/write and allocation-history helpers. An exploratory
  empty-allocation fast path in `jq-query-empty-allocation-fast-path/` also times
  out at 30s and has **not** been applied to the production engine.
  `jq-symex-profile.json` records both samples; their different limits and verbose
  logging preclude an end-to-end speed comparison. The next performance work
  should use these retained models to address symbolic memory expansion.
- `record-transducer-tests-v3.log` and `nix-record-tests-v2.log`: 40 tests pass,
  including complete record transport, missing/duplicate/unknown fields,
  uninitialized result projections, stale hidden-return geometry, single-word
  record substitutes and fail-closed rejection by the finite scalar expression
  renderer. The Nix output is
  `/nix/store/yhw1vspfribi0s1f6dhcnyj044n99asm-spaghetti-extractor-test-suite-affected`.
  The initial Nix attempt lacked the two target resources in its declared test
  inputs; the corrected testkit resource declaration is exercised by this pass.
  `record-root-gates.log` records passing metadata, lint and format-registry
  checks; `record-root-gates-final.log` repeats those gates after the final
  whitespace/metadata refresh. `record-repository-tests.log` records 33 passing
  repository-boundary tests, `record-semantic-boundary-tests.log` four semantic
  architecture tests, and `record-external-scope-tests.log` three external-scope
  regressions. `record-source-inventory.json` pins the final implementation and
  test bytes. Semantic preparation is not proof or activation authority.
- `effect-profile-tests-v2.log` and `nix-effect-profile-tests-v2.log`: six tests pass,
  covering physical disagreement, unknown imports, absent prerequisites, canonical
  ABI replacement, unselected ABI-only imports and an actual caller-memory effect
  change under an unchanged ABI. `effect-profile-root-gates.log` records passing
  SDK, metadata and lint gates; `effect-profile-repository-tests.log` records 37
  passing repository tests. `jq-effect-composition-costs.json` binds a measured
  preparation using the real retained 132-declaration ABI; no compiler, model,
  solver, link or execution work is performed by that composition.
- Initial `native-load-fault-gate.log` and `jq-linked-context-gate.log` attempts
  were rejected during evaluation because metadata refresh had not yet finished.
  Their `-v2` runs started after refresh completed. These initial errors do not
  constitute native or solver executions.
- `validation-v2/repository-fault-gates.log`: repository metadata, production
  lint, format registry and the compiled Behavioral-C differential gate pass.
  `repository-validation-v2.log` records 37 passing repository/semantic boundary
  tests in 16.682s. The first run found missing repository-map entries for this
  audit and the headless runner; both entries and the obsolete Xvfb description
  are corrected. These checks do not discharge the two remaining provider gates.
- The source-map correction is covered by 21 passing local refinement/stack tests;
  the native fixture now progresses beyond the former canonical-name error.
  The current authoritative completion state remains incomplete.

## Subsequent pilot recheck

`validation-v2/hello-dxball-gates.log` stops at Hello's real-scale assertion:
the dynamic import identity is unchanged, but the hard-coded loader-service
digest differs from the selected resolved contract. The gate now checks the
exact selected loader contract and its required dynamic-resolution behavior.
Replay, import/definition/relocation counts and the eight-second limit remain.
`hello-real-scale-retained/semantic-object-real-hello.json` records 4.848s;
`hello-real-scale-gate.log` records Nix success at
`/nix/store/syhg51s9srlzvrndjqv2yzj1k977z01g-spaghetti-extractor-gnu-hello-semantic-object-real-scale-check`.
The failed combined run cancelled DX-Ball; it is not a DX-Ball result.
`hello-dxball-gates-v2.log` records the subsequent `--keep-going` recheck, now terminal. Full pilot
acceptance remains pending, alongside native-module composition and jq proof.

The `hello-dxball-gates-v2.log` run subsequently exposes two Hello
failures: `bounded-string-length` raises `cut extent relation requires a captured
view` in `shared_view_initialization`, and startup-callback native realization
rejects an incomplete implementation selection. Exact failed derivations and
retained input references are in `hello-remaining-failed-derivations.json`.
Investigate the current cut captures/projections and the rejected provider facets;
reconstructing an entry pointer at a resumed cut would not establish preserved
contents or lifetime. The `--keep-going` process continued to collect independent
gates; no complete Hello or DX-Ball result is claimed here.

The bounded-string-length scan capture now uses the existing `bytes_view`
projection: the base comes from captured `ebx`, and its extent from captured
`maximum` in `ecx`. Entry-pointer reconstruction is not used. The regression
checks resumed admission and outgoing reference/visible extents against the real
intent, and rejects the previous bare-register capture. Three tests pass locally
(`hello-cut-view-tests-v2.log`) and in Nix (`hello-cut-view-nix-tests.log`, output
`/nix/store/5vdvip7zihzkmp4iwdm2b5qssmazwmv2-spaghetti-extractor-test-suite-affected`).
The first retained provider attempt (`hello-retained-cut-view.log`) correctly
rejects the old exact-C slice's stale bisimulation-intent binding. The revised
[hello-retained-cut-view.nix](../build/practical-lifting-2026-09-15/validation-v2/hello-retained-cut-view.nix) regenerates that small slice through the existing
constructor, retaining the original transfer plan and other inputs. Its provider
recheck is retained in `hello-retained-cut-view-v2.log`; renderer tests alone do
not establish its contextual proof.

The startup callback failure is specifically the checker-generated property
`spx_component_startup_callback_registration_00001137.no-body.spx_native_code_bridge_address`.
`hello-callback-diagnostic-reparse.json` binds the exact retained query and verified
stdout/stderr hashes. Re-parsing identifies an incomplete model; it is neither a
new solver run nor refreshed provider evidence. The backend distinguishes this
reserved property identity and matching description from an authored assertion.
Missing-body-only failures are incomplete; any separately reported failure stays
violated. Twenty-three focused tests pass locally (`cbmc-missing-body-tests-v2.log`)
and in Nix (`cbmc-missing-body-nix-tests.log`, output
`/nix/store/wg9l8j5ab3fan5k0g3w868rvzb2wbcnl-spaghetti-extractor-test-suite-affected`,
zero skips). Actual compiled regressions cover ordinary and stop-on-fail JSON,
an authored assertion with identical diagnostic text, and a separate mismatch
alongside a missing callee. Strong qualification still requires a complete proof.
The callback bridge's physical pointer, original code capability, service
observation and publication lifetime still need a checked correspondence; adding
a body that merely returns the original address would not discharge that work.
Seventeen related receipt, safety-partition, practical-contract and experimental
admission regressions pass (`cbmc-admission-regressions.log`, 219.746s). The
metadata, production-lint and format-registry Nix gates pass
(`cbmc-diagnostic-root-gates.log`), as do 37 repository/semantic architecture
checks (`cbmc-diagnostic-repository-tests.log`, 42.042s). These results validate
diagnostic handling and admission regressions; the unresolved pilot and native
composition gates remain required.

### Retained cut-scope and completed jq follow-up

The first regenerated Hello provider is
`/nix/store/bmdg13cs27k6lh1l16zn6hcg34mmgiql-spaghetti-extractor-hello-retained-cut-view-portable-c-work-package-provider-v2`.
It remains incomplete: the scan region is satisfied, but entry-to-scan violates
`spx-bisimulation-capture-extent:scan:buffer`. The exact retained counterexample
has entry ESP 1025 and reached ESP 1021 after `PUSH EBX`. Its native view has origin
extent 29184, offset 16388 and visible extent 256; those different extents are
legitimate. The failing clause applies invocation-private admission to the
lowered ESP. `hello-cut-scope-investigation.json` retains the receipt, diagnostic
values and per-query costs. The intent now uses the existing checked scope
projection `esp + 4`, preserving the invocation anchor across the cut without
changing cache anchoring. Nine tests pass locally (`hello-cut-scope-tests.log`,
4.804s) and in Nix (`hello-cut-scope-nix-tests.log`, output
`/nix/store/34l1kmkbbxwvjbi1gx2w9zj80w22wbpb-spaghetti-extractor-test-suite-affected`).
The compiled regression exercises the retained native view and rejects both
untransported scope and a changed visible extent. The provider recheck in
`hello-retained-cut-scope.log` subsequently completed as recorded below.
Metadata, production-lint and format-registry gates pass after the scope change
(`hello-cut-scope-root-gates.log`); `hello-cut-scope-inputs.json` pins its exact
intent and test source. These checks do not replace the pending provider proof.

The corrected scope provider has now finished:
`/nix/store/qapjd4cwq0q6llpjgp9xbyvljsm7ik75-spaghetti-extractor-hello-retained-cut-view-portable-c-work-package-provider-v2`.
Its qualification is complete; both entry and scan shards are satisfied.
`hello-cut-scope-acceptance.json` binds its artifacts and records acceptance by
`validate_complete_local_refinement` and the four existing strong jq checks for
qualification, contextual proof, cutpoint plan and exact-C slice. The audit script
is [audit-hello-cut-scope.py](../build/practical-lifting-2026-09-15/validation-v2/audit-hello-cut-scope.py); it performs no proof execution. This closes the
bounded-string-length component proof failure, not full Hello or native linkage.

Current readers also revalidate 29 retained milestone comparisons, the installed
walkthrough's 16 top-level comparisons plus two embedded experimental copies,
and three experimental manifests (`retained-evidence-audit-v2.log` and
`retained-evidence-audit.json`). The first audit attempt expected only 16 results
from a recursive scan and stopped after finding the two embedded copies; all
receipts loaded successfully. The corrected inventory explicitly checks both
counts. Formal reuse still records two reused source-memory queries with zero
formal work; mismatches, exclusions, unavailable rules, timeouts and false
assumptions retain their distinct statuses. This is current-reader validation
of historical executions, not a new Wine run.

The integrated jq CaDiCaL run has finished. The strong gate rejects the incomplete
provider
`/nix/store/x8vxzyn5c1yl7k67jjjchvmiqr8wnlf7-spaghetti-extractor-jq-jq-output-value-pipeline-portable-c-work-package-provider-v2`.
Nonvacuity passes in 0.934s; compilation takes 0.280s. Recursive safety splitting
produces 41 timeouts at 300 seconds per query, with 12,322s summed checker work and
a 3,313s query timeline. These elapsed queries combine symbolic execution and
solving; the sum is not wall time. `jq-cadical-completed-costs.json` retains exact
receipt binding and grouped costs. The remote-builder SSH attempt failed, but
the gate subsequently ran and rejected incomplete qualification; SSH is not the
reason the proof is incomplete. A further nonauthorizing retained-model diagnostic
removes allocation lookup (`jq-query-empty-allocation-lookup/diagnostic.json`);
it still times out during symbolic execution at 30 seconds. No production
optimization is justified by that experiment.

Hello program-name selection also fails before solving: connected replay for
`memory-regions-equal` lacks checked callee-entry and machine-state premises.
`hello-program-name-provider-derivation.json` retains exact inputs. The existing
guard is necessary to prevent replay from hiding callee state changes; resolving
this requires checked composition, not removing that guard.

`jq-query-full-slice/diagnostic.json` records a further experiment on the unchanged
retained CaDiCaL inputs: experimental CBMC full slicing still times out at 30s
after entering bounded model checking. Compilation takes 0.390s. This changes no
production checker command or receipt authority. Native interface investigation
also confirms that the current typed factory path reconstructs resource words
without modeling native post-call object/vtable registration. Runtime domain
guards alone do not establish paired contents, resource identity or lifetime.
The next composition work must bind those post-call rules on both sides rather
than adding an assumption merely to exclude the retained stack-overlap case.

### Strong-reader transformation rejection

Inspection of the pinned CBMC 6.9.0 source confirms that `--full-slice` performs
property-directed slicing, but explicitly warns that the analysis may be unsound.
The source was fetched through the existing Nix pin; the exact source path and
reader digest are retained in `strong-slicing-audit.json`. The earlier diagnostic
remains nonauthorizing irrespective of its performance.

The existing jq strong-proof predicate accepted the retained Hello proof after
inserting this flag into both assertion command variants, or into safety
discovery. It now rejects full slicing in every recorded query role, including
nonvacuity. `strong-slicing-audit.log` demonstrates that erasing this guard admits
both altered receipts, while the unmodified complete provider remains accepted.
Six tests pass locally (`strong-slicing-regressions.log`, 2.994s) and in Nix
(`strong-slicing-nix-tests.log`, output
`/nix/store/nf6gazip3ljhs4w3dpaylz70ryas9jr7-spaghetti-extractor-test-suite-affected`).
The regression generates a real valid component proof before mutating command
metadata. `strong-slicing-root-gates.log` records passing metadata, lint and format
registry checks. `strong-slicing-hello-acceptance.log` confirms current Python and
jq reader acceptance of the valid retained component provider.

An additional retained jq diagnostic reorders byte-log guards to test address
membership before allocation-history visibility. Both it and an unchanged
control time out at 30 seconds (`jq-cadical-query-history-last/diagnostic.json`,
`jq-cadical-query-baseline/diagnostic.json`). No production reordering was adopted.
The remaining native investigation finds that typed-call replay assumes runtime
admission succeeds (`SPX_CALL_OK`); post-call registration failures require
corresponding outcome transport, as well as storage and lifetime rules.

### Completed DX-Ball diagnostic checkpoint recheck

The combined Hello/DX-Ball run completed the DX-Ball provider at
`/nix/store/4910xqhls49w4jj2whwbwi1q3qd72zrc-spaghetti-extractor-dxball-directdraw-init-portable-c-work-package-provider-v2`.
Qualification and proof are **incomplete**, activation is false, and nonvacuity
is satisfied. The first diagnostic gate failed because its expectations still
named the old model capacities and an unpartitioned timeout query. Its exact
command is retained in `validation-v2/dxball-completed-gate-derivation.json`.
The Hello work finished later; its terminal result is recorded below.

The current Python contextual reader validates the receipt, including derived
model-bound summaries. The retained model has 72 selected units, seven internal
direct-call units, 11 call slots, and seven four-byte stack accesses at offsets
-12 through 12. The checkpoint now checks those current call/cache capacities and
all four terminal safety-query identities. It requires each timeout query's
status to be incomplete: an altered violated query retaining its old timeout
code passed the former projection, which omitted status, and now rejects.

[validation-v2/audit-dxball-checkpoint.py](../build/practical-lifting-2026-09-15/validation-v2/audit-dxball-checkpoint.py) reads the actual checkpoint expressions
from `targets/dxball/default.nix`. Its `dxball-checkpoint-audit.json` binds the
provider artifacts and gate block, validates the Python reader and all four jq
predicates, and checks rejection of activation, a violated query, a missing query,
a wrong property, failed nonvacuity and old capacities. Strong qualification
separately rejects the unmodified incomplete provider. The successful audit log
is `dxball-checkpoint-audit-v2.log`; the initial audit caught the omitted-status
defect. These are diagnostic checks, not altered proof receipts or fresh queries.

The audit extracts the exact shell checkpoint for [dxball-retained-checkpoint.nix](../build/practical-lifting-2026-09-15/validation-v2/dxball-retained-checkpoint.nix).
The Nix recheck passes using the retained provider and current jq modules:
`/nix/store/rh8bq2zh0a90i1yvm2ng34q2r3plf6mx-dxball-retained-directdraw-init-contextual-checkpoint`.
The command is `nix build --impure --no-link --print-out-paths --file
build/practical-lifting-2026-09-15/validation-v2/dxball-retained-checkpoint.nix`;
its log is `dxball-retained-checkpoint-v2.log`. The first attempt lacked a store
context for the jq directory and stopped before reading the proof; the corrected
recipe imports that directory with `builtins.path`. Rechecking performs zero
compiler, model, solver, link and Wine execution calls.

Retained provider costs are 3.859s compilation, 8.560s assertion inventory,
10.491s safety inventory, 0.920s baseline inventory, 6.140s loop inventory and
1.720s nonvacuity. Ten bounds and 33 pointer attempts time out, totaling 12,908.705s
of parallel safety work over a 3,335.295s query timeline. These timings include
symbolic execution and solving; they do not isolate solver decision time or
measure whole-build preparation/link time. No proof speedup is established.
The diagnostic checkpoint passes; full DirectDraw-init equivalence and activation
remain unavailable.

### Baseline attribution and complete Wine desktop sessions

`validation-v2/baseline-comparison-audit.json` binds five reproduced results
against an isolated `git archive` of commit
`8640cfea8c340c1781c1edbc4d4f10c3a457b2d0`. This is a boundary-level comparison
using retained real inputs, not a full historical target rebuild or a complete
regression audit. No proof or activation claim follows from baseline failure.

| Boundary | Baseline result | Current result and limitation |
|---|---|---|
| Hello program-name selection's memory-comparison dependency | `prepare_connected_models` rejects missing checked callee-entry and machine-state premises. | Identical captured inputs produce the identical rejection. The rejecting module's bytes, supplier C, interface and binding are unchanged. Ordinary supplier proof remains satisfied, but it supplies no additional caller contract. |
| Native interface provider preparation | Exact C regenerated by baseline code reaches `unit 'semantic-transfer:fixture-interface-record-factory' has no canonical RVA`. | The source-map correction already passes preparation and its focused tests; the retained interface-state counterexample still rejects qualification. The authored fixture and interface profile are unchanged. |
| jq output pipeline exact-C preparation | Rejects `exact-C continuations must be unowned declared proof context`. | Preparation succeeds in 1.228s with identical transfer-plan/binding hashes. The later strong provider still times out; successful preparation is not equivalence. |

The Hello commands are retained in [capture-hello-connected-inputs.py](../build/practical-lifting-2026-09-15/validation-v2/capture-hello-connected-inputs.py) and
[check-hello-connected-baseline.py](../build/practical-lifting-2026-09-15/validation-v2/check-hello-connected-baseline.py). The first stops the real provider at its
composition call, before model generation or solving; the second runs those exact
captured arguments with either checkout's Python modules. Their result files and
logs name the source module and hash. [run-native-provider-baseline.py](../build/practical-lifting-2026-09-15/validation-v2/run-native-provider-baseline.py) and
[run-jq-provider-baseline.py](../build/practical-lifting-2026-09-15/validation-v2/run-jq-provider-baseline.py) retain the corresponding input declarations and
reproductions. Baseline runs set `PYTHONPATH` to
`validation-v2/baseline-source/src`; current runs use the repository `src`.
The successful native reproduction log is `native-provider-baseline-v4.log`;
earlier attempts rejected a current-renderer slice, a missing explicit optional
argument and an output-directory collision before reaching the baseline error.
The jq logs are `jq-preparation-baseline.log` and
`jq-preparation-current-v2.log`. None of these reproductions invokes CBMC or Wine.

Inspection also found that three native-test runners launched Wine boot and the
application in separate headless sessions, then waited for wineserver outside
both. `native-ingress-runtime.nix`, `native-module.nix` and `pe32-project.nix` now
run all three phases inside one shared desktop. The candidate-suite and DX-Ball
installer already keep those phases together. Application timeouts and exit
status remain explicit; boot failure prevents application execution.

`validation-v2/wayland-session-gates.log` records passing current Nix native-ingress,
PE32 project, headless-desktop, metadata and lint gates. Content-addressed native
outputs remain:

- `/nix/store/0lnnvw8pw1j60a6i38v34p4wyrir96xq-spaghetti-extractor-native-ingress-runtime-check`
- `/nix/store/zykhc5vm2hswyfv1ajg00756l5skkbq0-spaghetti-extractor-pe32-project-check`

All 33 repository-boundary tests also pass in 27.857s
(`validation-v2/wayland-session-repository-tests.log`).

[check-native-module-desktop.py](../build/practical-lifting-2026-09-15/validation-v2/check-native-module-desktop.py) extracts the current native-module shell runner
and exercises it in a real Weston desktop with explicit Wine command stand-ins.
`native-module-desktop-audit.json` and `native-module-desktop-audit-v2.log` verify
one desktop for boot/application/server, application status 7 with the exact
loader trace, boot status 13 without application execution, paths containing
spaces, and compositor cleanup. The initial local attempt used an unavailable
`/bin/bash` shebang in its stand-ins; the successful run uses pinned Bash.
This checks shell/session transport, not native-module semantics. The separate
qualified native-module gate remains unsatisfied by the recorded interface proof.

### Strong admission, export binding and platform gate review

`validation-v2/strong-admission-gates.log` records current Nix acceptance for:

- Native realization: 12 tests, output
  `/nix/store/b9l7sczfnawi4h2ld718knnfhk9qr1nc-spaghetti-extractor-native-realization-v2-check`.
  The suite checks required linked objects/obligations, portable dispatch receipts,
  rejection of a rehashed source-only-authority policy, checked loader-resolved
  exports and exact export identity/contract binding. This is receipt/build-rule
  validation; it does not qualify an unresolved pilot implementation.
- Semantic providers: 22 tests, output
  `/nix/store/arjkjy370afgq75ip3y3kwnzf2894qwj-spaghetti-extractor-semantic-providers-check`.
  The suite checks qualification coverage, explicit total selection, distinct
  faithful/hybrid/portable modes, missing selections, contract freshness and
  native consumers rejecting rehashed selections with removed blockers.

The individual logs are `native-realization-admission-check.log` and
`semantic-providers-admission-check.log`. `platform-admission-root-gates.log`
records the qualified-platform gate and refreshed metadata/lint/format-registry
checks. The platform output is
`/nix/store/14swdn26s1sgcwqr8x4sc558vv87jbz0-spaghetti-extractor-qualified-platform-v1-check`.
The gate checks reproducible releases, bound kernel/ISA inventories, runtime and
native primitives, and explicit holes. Its ISA qualification inventory still has
446 qualified, three incomplete and one vetoed form out of 450. A passing platform
catalogue check is not whole-target portability or removal of those holes.

The public experimental test now checks rejection of its successfully executed
manifest by `SemanticProviderQualificationV2` and `ImplementationSelectionV2`,
as well as `NativeRealizationV2`, the common suite/per-case strong admission
reader. `experimental-admission-tests.log` records five passing local tests;
`experimental-admission-nix-tests.log` records five Nix tests with zero skips,
output `/nix/store/j9qpgf9zq3dqvxmhpsaqg12hz4k4hl2c-spaghetti-extractor-test-suite-affected`.
No production reader or qualification policy was relaxed.

[audit-experimental-admission.py](../build/practical-lifting-2026-09-15/validation-v2/audit-experimental-admission.py) also loads all three retained real jq network
manifests listed in the earlier evidence audit. `experimental-admission-audit.json`
binds each manifest and binary, confirms current experimental acceptance, and
records rejection by all three strong readers. The original optional-proof,
refined-domain and handle-representation networks retain their component-network
scope. This recheck performs zero compiler, model, solver, link and Wine calls;
it does not claim fresh execution, stronger proof or application export readiness.

### Operator handoff consistency review

The concat and append fixture READMEs no longer describe implemented finite-domain
refinement, experimental execution, representation changes or DX-Ball comparison
as future work. They link the corresponding public workflows and retain the
explicit limits on formal heap/lifetime composition and qualification. The
representation and DX-Ball commands assign package paths directly, and the
DX-Ball walkthrough identifies its host-executable retained-C oracle.

`validation-v2/walkthrough-doc-checks.json` records shell syntax checks for all
12 shell blocks across the four fixture READMEs and existence of their relative
links. `walkthrough-package-derivations.json` records successful current Nix
attribute evaluation for all seven public comparison packages. This is syntax,
link and package-resolution verification; the installed-CLI transcript and
retained executions above supply execution evidence. No pilot rebuild or new
comparison run was performed for these documentation edits.
`walkthrough-doc-metadata-gates.log` records passing metadata and format-registry
checks after the fixture documentation refresh.

### Terminal Hello/DX-Ball run

The combined `--keep-going` validation session 34269 is terminal with exit code 1.
No pilot validation process remains active. The final log is
`validation-v2/hello-dxball-gates-v2.log`; its SHA-256 and the completed Hello
string-comparison provider are bound in `hello-completed-gate-audit.json`.

The previously unresolved slow provider is
`/nix/store/vxwdmm9ry2dqdp7am03hf890ak5gzx5p-spaghetti-extractor-gnu-hello-ascii-string-compare-portable-c-work-package-provider-v2`.
Its recorded deriver matches the run's
`wcpda3cn9xmhvrvwa5vdsp7xviagwg8k` derivation, retained in
`hello-ascii-completed-provider-derivation.json`. Qualification remains incomplete;
both entry and scan shards are incomplete and both nonvacuity witnesses pass.
The current Python contextual reader validates the incomplete receipt.

The entry shard also contains **violated** queries for
`spx-bisimulation-capture-extent:scan:left` and
`spx-bisimulation-capture-extent:scan:right`. Exact failing-query paths and verified
stdout/stderr hashes are retained in the audit. The aggregate's incomplete status
must not hide those counterexamples or be reported as only a performance timeout.
The scan's recorded failures are timeouts. Further diagnosis must use these exact
models and traces before changing cut relations or attempting another provider.

Each shard records 38 queries. Entry has 5,875.863s of summed query work and a
3,128.837s local timeline; scan has 6,122.110s summed work and a 2,941.929s local
timeline. Summed work includes parallel queries and these local timelines are not
a full-build wall-clock measurement. [audit-hello-completed.py](../build/practical-lifting-2026-09-15/validation-v2/audit-hello-completed.py) reproduces the
reader checks and cost grouping without compilation, solving or Wine execution.

The aggregate also rejects startup-callback selection and program-name composition
as recorded above. It ran before the bounded-string-length scope correction and
DX-Ball diagnostic expectation update, so it also contains those historical
failures. Their later retained-input rechecks remain valid in their stated scopes;
this old aggregate does not undo those fixes or establish a current full Hello
acceptance. Strong pilot/native qualification remains unresolved.

### Hello comparator invocation-scope correction

`validation-v2/hello-ascii-scope-audit.json` binds the two original query outputs,
the original exact-C prologue, current intent and focused local/Nix results.
The prologue saves EDI, ESI and EBX, then reserves 16 bytes; scan ESP is entry
ESP minus 28. The right-capture trace has entry ESP 1051 and reached ESP 1023,
below the minimum admitted 1024. The left-capture trace has entry ESP 4412429
and reached ESP 4412401; lowering the private-frame anchor crosses the image-end
exclusion at 4411392. These are invocation-scope transport failures.

The actual scan intent now selects `{register: "esp", offset: 28}` through the
existing scope mechanism. Its digest is
`308ac332559072bd15651731d4e9d50347870d906e79783f7d6d0b4960c72a8e`.
The regression uses the production shared-view admission and cut-extent renderer
for both views at both trace geometries. Corrected scope passes; the old scope,
changed visible extents and nonzero NUL terminators reject. It is a focused
predicate check, not a replay of the entire original execution or an equivalence
proof. The bound full traces remain the evidence for the original failure.

Validation and reproduction:

- `PYTHONPATH="src:$PYTHONPATH" python -m unittest tests.unit.components.test_bisimulation_view_extent tests.unit.components.test_bisimulation_stack_scope -v`:
  ten tests pass in 3.731s; `hello-ascii-scope-tests.log`.
- After `nix run .#dev -- refresh`, the existing testkit shard selection in
  [hello-ascii-scope-tests.nix](../build/practical-lifting-2026-09-15/validation-v2/hello-ascii-scope-tests.nix) passes all ten tests with zero skips:
  `/nix/store/mnlbv39m92s6fyrz0kjl035113ghq027-spaghetti-extractor-test-suite-affected`.
- Repository metadata, production lint and format-registry checks pass;
  `hello-ascii-scope-root-gates.log`.
- `PYTHONPATH="src:$PYTHONPATH" python build/practical-lifting-2026-09-15/validation-v2/audit-hello-ascii-scope.py`
  rechecks trace hashes, ESP transport, exact test results and scope identity.

The retained recheck uses [hello-retained-ascii-scope.nix](../build/practical-lifting-2026-09-15/validation-v2/hello-retained-ascii-scope.nix) with existing executable
transfer-plan, interfaces, source packages and qualified ascii-to-lower supplier.
Only the current comparator exact-C slice and provider are rebuilt. The first
attempt correctly failed preparation because the diagnostic expression omitted
`dependencyBindingIntents`; `hello-retained-ascii-scope.log` retains that failure.
The corrected expression includes the existing supplier binding. Session 53503
is active with log `hello-retained-ascii-scope-v2.log` and resolved provider
`/nix/store/nqg1zc6g37c0nal381z4n2ml96qx1wvr-spaghetti-extractor-hello-retained-ascii-scope-portable-c-work-package-provider-v2.drv`.
No full-pilot rebuild, Wine execution or new qualification claim is involved.
The integrated provider result remains required before declaring this proof fixed.

### Interface-resource model admission audit

The current native-interface qualification gap extends beyond the returned
object's storage span. [validation-v2/audit-interface-resource-model.py](../build/practical-lifting-2026-09-15/validation-v2/audit-interface-resource-model.py) extracts
unmodified `spx_proof_realize_resource` and
`spx_native_realize_interface_resource` from the current renderers, supplies one
pinned interface class and one live instance, and compiles five cases with CBMC.
The valid instance is accepted by both. Four admission-agreement assertions fail:
stale generation, wrong class tag, expired instance and noncanonical nullable
resource. The proof helper accepts each while the native helper rejects it.

`interface-resource-model-audit.json` binds generated helper hashes, commands,
case source hashes and exact checker stdout/stderr hashes. Sources and raw outputs
are retained in `interface-resource-model/`. Each query takes less than a second;
frontend/model/solver time is measured together rather than presented as separate
costs. No linking, Wine execution or pilot rebuild is involved. The fixture's
class lookup is fixed; it does not check class-catalog lookup, backing memory,
factory publication, reference-counting or whole-provider equivalence.
Both extracted function bodies match the corresponding templates in baseline
commit `8640cfe`. This locates a pre-existing model gap; it is not a historical
whole-provider check or permission to accept the incomplete native selection.

Reproduce with:

```sh
PYTHONPATH=".:src:$PYTHONPATH" python build/practical-lifting-2026-09-15/validation-v2/audit-interface-resource-model.py
```

The next checked interface rule must compose the existing class/instance contract
and service transducers. It needs separate per-world instance state, canonical
nulls, exact class and generation checks, publication only after successful
registration, retirement on the declared lifecycle event, and matching failure
outcomes. Object/vtable storage and read effects remain additional obligations.
A reconstructed pointer or a hard-coded generation does not establish any of
these facts. Test the four retained invalid-resource cases and publication/failure
transitions before repeating the native provider; do not solve the observed
counterexample by assuming every factory return is valid. The practical DX-Ball
lifecycle comparison retains its existing, explicitly narrower execution scope.

### Practical exit evidence and executable editor commands

`validation-v2/public-authoring-audit.json` records fresh execution of all five
C11 syntax-check commands in the generated `compile_commands.json` files for the
public supplier, integrated network, isolated network and DX-Ball drafts. All
commands pass using their actual compiler, generated include directories and
current retained source. Commands, compiler/database/source hashes, stdout/stderr
and compiler costs are retained. This directly checks usable editor configuration;
it performs no original execution, link, model or solver work.

`validation-v2/practical-exit-evidence.json` revalidates 31 comparison receipts
and the 22-command installed-CLI walkthrough. It checks exact first divergences
in failed replay after draft repair, repaired results, zero isolated work after
supplier edits and bugs, and invalidation/re-execution of supplier and integration.
The reviewed supplier rewrite changes only its source and increases its size;
all other bound inputs remain equal. Running the pinned `nm` on both retained
binaries reproduces the authored supplier-presence/absence inventory.

The same audit checks the four excluded counterexamples under an unchanged
interface, failed caller assumptions, two reused source proofs, eight DX-Ball
lifecycle cases and the matching raw/handle logical observations with unchanged
authored interfaces and C. It validates the complete representation group and
binds the experimental run's actual binary, effective suite, six passing case
stdout/stderr files and candidate report. Each executed JSON observation matches
the corresponding retained handle comparison. These are checks of historical
execution artifacts, not fresh Wine execution or strong qualification.

Reproduce with `PYTHONPATH="src:$PYTHONPATH" python` followed by either
[build/practical-lifting-2026-09-15/validation-v2/audit-public-authoring.py](../build/practical-lifting-2026-09-15/validation-v2/audit-public-authoring.py) or
[build/practical-lifting-2026-09-15/validation-v2/audit-practical-exits.py](../build/practical-lifting-2026-09-15/validation-v2/audit-practical-exits.py).
Logs are `public-authoring-audit.log` and `practical-exit-evidence-v2.log`.
The ledger now records these specific verified facts rather than leaving every
practical exit at an undifferentiated audit-pending status. Remaining G1/G4/G6
requirements and strong pilot/native gates retain their separate evidence and
open obligations; this checkpoint does not complete the goal.

### Source-feedback and experimental eligibility exit checks

The current source-feedback and small Metapad original-comparison gate passes all
eight tests with zero skips:
`/nix/store/48i8nxk77i44r4z5n6rf0vcq0c550hfy-spaghetti-extractor-test-suite-affected`.
[validation-v2/source-authoring-exit-tests.nix](../build/practical-lifting-2026-09-15/validation-v2/source-authoring-exit-tests.nix) selects the existing tests through
the existing testkit manifest; `source-authoring-exit-tests.log` retains the run.
The tests exercise source-located compiler errors and repair, a dialect violation
that still compiles, actionable alternatives, stale source rejection, actual
Metapad source/original checks, wrong service arguments and stale compiled inputs.
The CLI index/realization lookup is supplied by the test fixture; the compiler,
original-comparison engine and solver actually run. This is separate from the
previously retained packaged-CLI walkthrough and native PE32 gates.

`practical-eligibility-audit.json` validates exact manifests, binaries, effective
suites, candidate reports and raw output hashes for three retained runs: real jq
with an unavailable rule, the bounded host memory fixture with a proof timeout,
and that fixture with two reused source proofs. All ten executed cases pass.
The timeout was deliberately forced with a `0.0001` second per-query deadline.
It demonstrates control flow and policy admission of a real timed-out checker
process; it is not evidence of performance at a useful budget or a jq heap proof.
The same audit makes a fresh public `candidate build` attempt using matching
sampled observations plus the retained formal disproof. The command rejects it
before creating an output. Source proofs retain their input/frame scope.

`experimental-input-negative-audit.json` exercises public `candidate test` on a
separate copy of the actual jq handle-network package. Seven altered inputs—linked
binary, authored source, adapter, interface identity, runtime library, accepted
policy and case suite—each reject with exit 2 before runtime preparation. Each
input is restored and the intact manifest revalidates between cases. The original
retained package is unchanged. No Wine, compiler, link or solver work occurs.

Reproduce with `PYTHONPATH="src:$PYTHONPATH" python` and either
[build/practical-lifting-2026-09-15/validation-v2/audit-practical-eligibility.py](../build/practical-lifting-2026-09-15/validation-v2/audit-practical-eligibility.py) or
[build/practical-lifting-2026-09-15/validation-v2/audit-experimental-inputs.py](../build/practical-lifting-2026-09-15/validation-v2/audit-experimental-inputs.py).
Logs are `practical-eligibility-audit.log` and
`experimental-input-negative-audit-v2.log`. Strong-reader rejection remains bound
by `experimental-admission-audit.json` and the current native-realization and
semantic-provider gates. Remaining G6 and strong pilot/native qualification work
is still open; these checkpoints do not authorize activation or complete the goal.

### Final practical regressions and callback baseline attribution

The current six-module practical regression group passes all 37 tests with zero
skips through the existing Nix testkit:
`/nix/store/y55hj8w9x9iyicmarxias3rp3291l7zz-spaghetti-extractor-test-suite-affected`.
It covers comparison/reuse, dependencies, domain refinement, representation
selection, optional source proofs and experimental admission. The selection is
retained in [validation-v2/practical-exit-tests.nix](../build/practical-lifting-2026-09-15/validation-v2/practical-exit-tests.nix), with its run in
`practical-exit-tests.log`. All 33 repository-boundary tests also pass in 17.282s;
`practical-exit-repository-tests.log` records the current run. These are scoped
repository/practical results, not passing aggregate pilot qualifications.

[prepare-callback-baseline.py](../build/practical-lifting-2026-09-15/validation-v2/prepare-callback-baseline.py) runs the archived baseline `8640cfe` provider
against the retained actual Hello callback inputs. It regenerates exact C using
that baseline and stops at the first checker invocation after compiling the
paired model. Exact-C preparation takes 2.109s; provider preparation and
compilation take 12.459s. No checker/solver or Wine process runs in that step.
The resulting workspace is `callback-baseline-b5ehwqy7` and the input declaration
and pending checker command are recorded in `callback-baseline-preparation.json`.

[audit-callback-baseline.py](../build/practical-lifting-2026-09-15/validation-v2/audit-callback-baseline.py) inspects that compiled GOTO with the existing
`goto-instrument` function inventory. The callback caller has a body and calls
`spx_native_code_bridge_address`; the bridge has `isBodyAvailable: false`.
`callback-baseline-audit.json` binds the compiled model, inventory, commands and
retained current missing-body query. This establishes the model gap in baseline
code using real retained inputs. It is not a baseline whole-target rebuild or a
successful callback proof. Strong callback qualification still requires a checked
bridge/service relation; no identity stub or admission waiver was introduced.

Reproduce preparation with the archived source directory first on `PYTHONPATH`:

```sh
PYTHONPATH="build/practical-lifting-2026-09-15/validation-v2/baseline-source/src:$PYTHONPATH" \
  python build/practical-lifting-2026-09-15/validation-v2/prepare-callback-baseline.py
PYTHONPATH="src:$PYTHONPATH" \
  python build/practical-lifting-2026-09-15/validation-v2/audit-callback-baseline.py
```

The retained comparator scope recheck remains active in session 53503. Final
reconciliation must use its terminal result and keep the outstanding native,
callback and connected-provider obligations explicit.

### Installed workflow freshness and cached test realization

`validation-v2/walkthrough-freshness-audit.json` reconciles the packaged public
walkthrough with the current Python source inventory. All 16 comparison receipts
validate with current readers and bind exactly the current comparison engine.
Twenty-five reviewed modules covering public dispatch, comparison, authoring,
optional contracts and experimental execution have identical bytes. Four imported
helper functions in otherwise changed modules also have identical ASTs.
The complete inventory records 13 changed and three newly added modules; this
does not assert that the whole installed toolkit matches the current checkout.
Changed native runtime, transfer, record transport and proof-provider behavior
still requires its separately recorded validation.

Both targeted Nix expressions were realized again against the current tree.
They resolved to the same passing outputs: 37 practical tests and eight
source-feedback/Metapad tests, all with zero skips. Nix initially printed plans
for unresolved content-addressed derivations, then reused their existing resolved
outputs without running a builder. These are current cached gate results, not
45 freshly executed tests. This distinction avoids scheduling redundant tests
based solely on `--dry-run` output.

Reproduce the input-freshness check and audit with:

```sh
nix build --impure --no-link --print-out-paths \
  --file build/practical-lifting-2026-09-15/validation-v2/practical-exit-tests.nix
nix build --impure --no-link --print-out-paths \
  --file build/practical-lifting-2026-09-15/validation-v2/source-authoring-exit-tests.nix
PYTHONPATH="src:$PYTHONPATH" \
  python build/practical-lifting-2026-09-15/validation-v2/audit-walkthrough-freshness.py
```

The exact realization outputs are retained in `practical-exit-tests-freshness.log`
and `source-authoring-exit-tests-freshness.log`; the audit binds those logs and
their test reports. `walkthrough-freshness-audit.log` records the audit result.
No Wine execution, pilot rebuild or qualification follows from this check.
The comparator is still running and has reached its scan-region queries; final
G6 reconciliation remains open.

### Terminal corrected comparator recheck

The retained-input comparator build in session 53503 has finished with exit 0.
Its output is
`/nix/store/8fssb6z1qa016dykxlpsjpwabisbyw7l-spaghetti-extractor-hello-retained-ascii-scope-portable-c-work-package-provider-v2`.
The provider and contextual proof remain **incomplete**, with activation false.
Nix build success here means the diagnostic provider artifact was produced; it
does not establish qualification. No validation build remains active.

`validation-v2/hello-ascii-terminal-audit.json` binds the actual deriver, corrected
intent, receipt, build log, all retained reusable query outputs and query timings.
The current contextual reader accepts the incomplete receipt. The complete-local
reader and both qualification predicates reject it; the proof-plan and exact-C
structural predicates pass. The complete-local reader's generic rejection text
mentions continuation/allocation-history premises, but this plan has neither:
the actual failing condition is its incomplete proof status.

| Region | Satisfied final queries | Timed-out final queries | Violated final queries | Query attempts | Summed query seconds | Query timeline seconds |
|---|---:|---:|---:|---:|---:|---:|
| Entry | 20 | 5 | 0 | 38 | 5,231.754 | 2,495.050 |
| Scan | 16 | 10 | 0 | 40 | 6,469.703 | 2,788.529 |

Nonvacuity passes in both regions. Every incomplete final query reports the
300-second timeout. The entry's right-view capture check now passes. Its left-view
capture and both scan capture checks time out. The previously retained extent
counterexamples therefore are not new counterexamples in this run, but the
unresolved checks still prevent claiming that the general capture obligations
are proved. The ten compiled scope regressions retain their narrower geometry
and mutation-control scope. Query sums include parallel work and retries; they
are not end-to-end elapsed time.

Reproduce the terminal audit without compiling, solving or running Wine:

```sh
PYTHONPATH="src:$PYTHONPATH" \
  python build/practical-lifting-2026-09-15/validation-v2/audit-hello-ascii-terminal.py \
  /nix/store/8fssb6z1qa016dykxlpsjpwabisbyw7l-spaghetti-extractor-hello-retained-ascii-scope-portable-c-work-package-provider-v2
```

The run is retained in `hello-retained-ascii-scope-v2.log`; the audit output is
`hello-ascii-terminal-audit.log`. The earlier failed scope/preparation attempts
remain historical evidence. Hello callback/connected composition, the native
interface model and jq/DX-Ball strong proof gaps remain explicitly unresolved;
this comparator artifact discharges none of their qualification obligations.

## Final G1–G6 acceptance

The bounded practical-workflow milestone is complete. The requirement table at
the start of this document records each exit's demonstrated scope. Final current
reader checks are retained in `validation-v2/practical-exit-evidence-final.log`
(31 comparison receipts, public commands, symbols, refinement, reuse and lifecycle
observations) and `retained-negative-evidence-final.log` (29 retained comparisons
and three experimental manifests, including the faulty-setup/alias controls).
These inventories overlap; they are not a claim of 60 independent comparisons.
The five generated compiler/editor commands still bind the current draft source,
compiler and compilation database bytes recorded in `public-authoring-audit.json`.

`practical-eligibility-final.log` records validation of the actual unavailable-rule,
forced-timeout and reused-proof runs plus a fresh public disproof veto.
`experimental-input-negative-final.log` records all seven stale-input rejections
before runtime preparation. `experimental-admission-final.log` records current
experimental acceptance of the three real jq manifests and their rejection by
qualification, implementation-selection and native-realization readers. These
checks rerun evidence validation and rejection paths, not the historical Wine
executions. The source-proof and forced-timeout limits described above remain.

`final-admission-reconciliation.log` records exit 0 for the following current
gate command:

```sh
nix build --no-link --print-out-paths \
  .#checks.x86_64-linux.repository-metadata \
  .#checks.x86_64-linux.production-python-lint \
  .#checks.x86_64-linux.format-registry \
  .#checks.x86_64-linux.native-realization \
  .#checks.x86_64-linux.semantic-providers \
  .#checks.x86_64-linux.qualified-platform \
  .#checks.x86_64-linux.native-ingress-runtime \
  .#checks.x86_64-linux.pe32-project
```

All eight gates pass. The current native-realization output is
`/nix/store/fpqjy8q1pvzkwm3a3lsayig4v81ckyvj-spaghetti-extractor-native-realization-v2-check`;
`final-native-realization.log` records 12 passing tests. The semantic-provider
output is
`/nix/store/wa94gayyigj3gx8n5qxqf1m6pnr1m1dm-spaghetti-extractor-semantic-providers-check`;
`final-semantic-providers.log` records 22 passing tests. The other six outputs
resolve to the previously recorded outputs. Nix reran metadata/lint/registry
checks and these two admission suites, while reusing the platform, native-ingress
and PE32 outputs. The configured remote builder was unavailable; the local
fallback completed. This reconciliation launched no new Wine or pilot execution.
The 37 practical and eight source/Metapad Nix tests remain current through their
separately recorded realization checks; all 33 repository-boundary tests pass.

Qualification remains a separate required action with unresolved obligations:

| Qualified scope | Current result and explanation |
|---|---|
| Hello comparator | Corrected scope regression passes; the terminal integrated proof retains 15 timed-out final queries and cannot activate. |
| Hello callback | The bridge has no checker body. An actual baseline compiled model reproduces that gap. |
| Hello memory-comparison caller | Identical baseline/current inputs reject for missing checked callee-entry and machine-state premises. |
| jq output pipeline | Current preparation advances past the baseline continuation error; the strong proof remains incomplete with safety-query timeouts. |
| DX-Ball DirectDraw initialization | The retained proof remains incomplete. The corrected diagnostic checkpoint passes while qualification still rejects. |
| Native-module interface fixture | Baseline preparation fails on named-unit transport; current preparation exposes the interface-state counterexample. The resource helpers' class/generation/lifetime disagreement is also present in baseline function bodies. |

The native fixture inputs are unchanged from `8640cfe`; its Nix test's changes
are confined to the required headless Wayland runner. Baseline investigations
reproduce the stated preparation/model gaps on retained inputs; they are not
historical full-target rebuilds. Renderer, ABI transport, scope and diagnostic
corrections have their focused regression and negative-control evidence above.
These explanations distinguish the known qualification gaps from the delivered
practical workflow without labeling any failed qualification gate as passed.

The accepted design explicitly permits the demonstrated component-network
execution under its typed experimental policy. Full qualified target activation,
native linkage, export and portability still require the existing strong gates.
No test, accepted assumption, conditional source proof or experimental manifest
has been promoted into that authority. No full application lift is claimed.
The final audit preserves the hand-defined boundaries, original-oracle limits,
independent states, controlled-dependency scope, representation group and phase
costs recorded above. All validation jobs are terminal. Unrelated dirty-tree work
is preserved; no commit, push or deployment was performed.

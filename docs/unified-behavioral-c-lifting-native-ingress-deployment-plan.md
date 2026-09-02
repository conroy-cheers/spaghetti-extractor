# Incremental Faithful Decompilation and Locally Proved Idiomatic Lifting

## Status and authority of this revision

This 2026-08-31 revision is the authoritative completion contract for the
repository. It preserves the original Behavioral-C, native-ingress, PE32
composition, deployment, observation, and component-lifting requirements, but
removes whole-program must-provenance closure from the faithful deployment
gate.

[`current-goal.md`](current-goal.md) is the concise active execution contract
for this plan. It records the current architectural interpretation, ordered
work, and immediate exit criteria without replacing or narrowing any
requirement in this document.

The keystone is `linked-semantic-module-v2` over
`executable-transfer-plan-v2`. The module separates three facts that the V1
path conflated:

1. a semantic hole, where reachable machine behavior is unknown;
2. a residual obligation, where behavior is known but a checked runtime or
   environment provider must supply a runtime-dependent fact; and
3. an analysis frontier, where optional must-analysis cannot prove a more
   precise value, target, or object identity.

Whole-program executability comes from mechanical Behavioral-C lowering plus
total qualified provider selection. Operator-authored idiomatic C replaces a
selected semantic slice only after local contextual refinement. A failed or
unfinished portable provider never invalidates the faithful generated-C
configuration and is never selected through silent fallback.

Everything after the `Superseded design and implementation journal` heading is
historical evidence. It records completed work, measurements, rejected
experiments, and preserved requirements, but its V1 contracts and remaining
steps are not authoritative where they conflict with this revision.

## Canonical execution and lifting path

```text
original PE + checked environment
                |
                v
        executable-transfer-plan-v2
                |
                v
       semantic-object-v1 package
                |
                v
       linked-semantic-module-v2
  definitions + may closure + typed obligations
          |                         |
          v                         v
 generated faithful C       selected semantic slice
          |                         |
 qualified runtime          operator-authored C
 providers                  + contextual proof
          |                         |
          +------------+------------+
                       v
          implementation-selection-v2
                       |
                       v
             native-realization-v2
                       |
                       v
        PE32 deployment and observation
```

`executable-transfer-plan-v2` remains the only executable semantic language.
No component, renderer, evaluator, runtime, ingress builder, or composer may
decode x86, adapt raw machine IR, or introduce another behavioral IR.

Four claims remain independently checkable:

1. `pe32-module-interface-v2` states original loader facts.
2. `linked-semantic-module-v2` states the original program meaning, the sound
   may-realization universe, semantic holes, and residual requirements.
3. `native-realization-v2` states the exact selected implementation and PE32
   composition.
4. candidate/project observation states what the loader actually saw.

Tests, CBMC examples, the host evaluator, Wine, Ghidra, Bochs, Unicorn, and
other differential oracles remain veto-only unless a contract below names a
specific checker as part of the trusted proof path.

## Canonical contracts

### Retained inputs

- Retain `executable-transfer-plan-v2`, `semantic-object-v1`,
  `pe32-module-interface-v2`, `external-environment-intent-v1`, the resolved
  environment, machine-object authority V2, `BoundarySchemaV1`,
  `TargetDataLayoutV1`, `PortableComponentInterfaceV5`, and component source
  package V3.
- Retain transfer-v2 as the direct semantic input to the veto-only evaluator
  and component proof kernel. Production Behavioral-C, semantic linking, and
  runtime planning consume transfer semantics only through the content-bound
  semantic object or linked semantic module; they may not adapt machine IR or
  invent a second executable representation.
- Retain the existing Python/Rust fixed point as optional analysis and proof
  support. It may narrow a domain or provide checked evidence, but an
  unresolved must-fact is not automatically a semantic hole.

### `linked-semantic-module-v2`

The V2 module:

- binds the exact semantic object, transfer universe, PE interface, resolved
  environment, objects, roots, direct edges, effects, outcomes, and evidence;
- gives every semantic definition a stable `definition_sha256`;
- computes a conservative may-reach realization universe, broadening an
  unknown internal dispatch to its closed compatible transfer-entry domain;
- requires a finite frame-compatible domain for every escaped callback or
  other native-address capability;
- records `semantic_holes`, `residual_obligations`, and non-authorizing
  `analysis_frontiers` separately;
- gives each residual obligation a stable identity, subject definitions or
  sites, semantic contract hash, admitted domain, evidence dependencies, and
  allowed provider kinds; and
- emits definition and obligation implementation requirements without
  selecting providers or claiming execution authority.

The initial residual-obligation classes are object/reference resolution,
mapped-memory access, external-write validation, internal code dispatch,
indirect external callthrough, callback capability publication,
loader-service resolution, guest atomics, lifecycle cleanup, checked
exceptions/outcomes, TLS, and private-stack support.

Only a closed target-independent classifier over canonical checked inputs may
derive an analysis frontier plus residual obligation. It must verify the exact
transfer operation and provider contract. Optional fixed-point blockers do not
enter the canonical module; an unknown canonical blocker remains a semantic
hole.

Production construction is stricter and simpler than the migration path that
preceded this revision:

- `semantic-object-v1` is the sole production input to the semantic linker;
  its content-bound members already contain the module interface, executable
  roots, transfer plan, resolved environment, object authority, symbols, and
  relocations. The original PE and a second behavioral-roots artifact are not
  link inputs.
- The linker performs only deterministic conservative graph closure over those
  declarations, plus exact transfer-v2 site inventory for typed residual
  obligations. It does not execute transfer semantics, solve values, or run a
  context-sensitive provenance analysis.
- `link_provenance` binds the may-link algorithm and exact root, relocation,
  and runtime-dependency inventories. No worklist limit, solver result, or
  optional diagnostic appears in the module identity.
- The Python/Rust must-provenance fixed point consumes the canonical inputs as
  a separate veto-only diagnostic. It may propose narrower slices or report
  counterexamples, but it cannot add or remove semantic definitions, admitted
  domains, obligations, holes, or completion authority.
- `analysis_frontiers` in the canonical module may contain only deterministic
  site-local frontiers derived from canonical checked inputs. Optional
  whole-program analysis output belongs in a separate diagnostic receipt.

### Providers, selection, and realization

`semantic-provider-qualification-v2` replaces V1. It binds a canonical
semantic-slice hash rather than the entire linked-module hash and contains:

- exact definition and residual-obligation contract hashes;
- dependency-contract hashes;
- selected native symbols, source hashes, object hashes, and tool identities;
- contextual-refinement, lifecycle, service, relation, induction, ownership,
  compilation, and object-binding proof results; and
- stable incomplete or violated blockers.

Provider kinds are `generated_behavioral_c`, `qualified_portable_c`,
`qualified_runtime`, `external_environment`, and `pinned_binary`. One provider
may implement a coherent multi-entry or recursive semantic slice.

`implementation-selection-v2` binds one linked module and explicitly selects
one provider for every active semantic definition and residual obligation. It
recomputes slice admission against the current module. Its modes are:

- `faithful`: generated Behavioral C owns every original definition;
- `hybrid`: portable or pinned providers explicitly replace selected
  definitions and generated C explicitly owns the rest; and
- `portable`: no active definition is owned by generated C.

`native-realization-v2` binds the module, selection, selected qualifications,
every linked object, runtime/ingress/SEH symbol, link map, relocations, PE
composition, decoded candidate interface, and candidate hash. Missing selected
objects or obligation providers fail closed.

### Component work packages and local proof

`component-work-package-v6` is a non-authorizing projection containing the
semantic-slice hash, definitions, operations, entries/exits, faithful-C source
slices, typed object views, services, callbacks, outcomes, lifecycle,
obligations, dependency contracts, proof classification, generated headers,
source skeleton, suggested tests, and ranked blockers.

The implementation modes are:

- `machine_overlay`, which operates over the original mapped representation;
  and
- `encapsulated_owned`, which may change representation only after proving
  exclusive ownership, absence of outside aliases, and a total state relation.

Component compatibility is contextual refinement over every boundary-admitted
initial state and environment response. The checker compares return and
outcome behavior, boundary-visible memory, ordered service/callback/allocation/
lifecycle/atomic/exception traces, persistent state, and any explicitly
observed address identities. Internal algorithms and representation may differ
when the state relation permits it.

Stateful components prove initialization, a persistent simulation relation
after every operation and reentrant callback, and finalization. Loops require
a checked bound or induction proof. Finite unwinding cannot authorize an
unbounded loop or reentrancy depth.

Initial concurrent portable support is limited to thread-confined components
and the existing opaque checked atomic API. Arbitrary shared non-atomic
representation replacement remains incomplete; faithful generated C continues
to implement those regions.

Source-level refinement is connected to deployed objects through a pinned
MinGW GCC/binutils trust profile. Qualifications bind exact compiler/checker
hashes and versions, C11/ABI flags, preprocessing inputs, sources, objects,
symbols, relocations, and object-policy checks. CBMC must check bounds,
pointers, leaks, division, signed overflow, conversions, shifts, and unwinding.
Disassembly and differential object checks remain vetoes. Per-object
translation validation is deferred and no stronger compiler claim is made.

## Operator workflow

The supported workflow is:

1. Analyze the PE and build the semantic module.
2. Build and observe an explicit `faithful` candidate.
3. Inspect `component-seed:<rva>` and `component:<id>` subjects through the
   unified boundary workbench.
4. Adopt a proposal into operator intent and a separate editable source
   skeleton.
5. Build the V6 work package and author C outside the generated baseline.
6. Run local contextual refinement and inspect minimized counterexamples.
7. Select the qualified provider in a hybrid configuration.
8. Rebuild, compose, observe, and test the deployed candidate.

Public commands remain `boundary status|inspect|propose|adopt|check`,
`component list|status|build|bind|check|relation`, and
`candidate list|status|build|check|test`. `candidate check` accepts faithful,
hybrid, and portable modes. Status reports semantic holes, analysis frontiers,
runtime obligations, provider qualifications, realization, deployment, and
observation separately.

## Ordered implementation

### 0. Preserve and rebaseline

- Preserve the dirty tree and all completed semantic-object/native-ingress
  work.
- Run focused semantic-link, provider, component, runtime, native-realization,
  Hello, jq, DX-Ball, and synthetic PE32/Wine checks through the Nix runner.
- Snapshot the current real-Hello 4,498-unit, 6,056-edge, 63-frontier baseline
  and retain all rejected must-analysis experiments as historical evidence.
- Restore the long-running goal with linked-semantic-module-v2 named as its
  keystone.

Exit: the revision governs and no diagnostic result has been promoted to
authority.

### 1. Split semantic completeness from analysis precision

- Implement the V2 codec, conservative may-link, definition hashes, obligation
  inventory, and fail-closed classifier.
- Move must-provenance losses to the diagnostic analysis view unless an exact
  classifier proves a semantic or provider requirement.
- Preserve root, direct-edge, exception, and outcome universes under every
  broadening.
- Migrate semantic status and diagnostics in one clean cut.

Exit: runtime-dependent but understood behavior can form a complete semantic
module; unknown semantics and unbounded native escape domains still block.

2026-09-01 correction checkpoint: this split is now structural rather than a
fixed-point policy convention. Production `linked-semantic-module-v2`
construction consumes only the packaged semantic object and runs a monotone
root/relocation/runtime-dependency may-link. The original PE and duplicate
behavioral-roots input were removed from that Nix phase. Independent replay
checks may-graph inclusion without executing the optional fixed point, and
architecture gates reject any closure or native worklist call from the
production linker. The previous attempt to cap the production worklist at
32,768 steps was removed because an analysis budget must never affect module
meaning or completeness.

The generous vertical slice also removed the dominant upstream export cost
without creating another artifact system. On the exact 36,005-unit libjq
input, a profiled final machine-IR export took 419.7 seconds; 326.3 seconds were
an accidental all-unit-starts by all-reachable-instructions overlap scan. A
deterministic interval sweep, one-time coverage-range merging, and shallow
reuse of immutable prepared semantics reduce the same export to 64.9 seconds.
All three outputs are byte-identical to the pre-change Nix artifacts. The real
jq and libjq V2 semantic modules subsequently build successfully; isolated
libjq semantic linking takes 20.6 seconds. They retain their honest
semantic-hole and residual-obligation inventories with zero optional-analysis
frontiers. Machine-IR preparation and final export now import their owning
modules directly, so an exporter-only edit cannot invalidate prepared units
through the former broad `reconstruction.ir` facade.

### 2. Realize faithful Behavioral C through qualified runtime obligations

- Render and compile the conservative realization universe.
- Generalize runtime planning and ingress to consume V2 obligations rather
  than a blocker-free V1 closure.
- Complete dynamic object/range/lifetime validation, internal logical-address
  dispatch, checked indirect external callthrough, callback bridge
  publication, loader-service capability registration, and the Hello lazy
  codepage cell.
- Emit V2 generated-C, runtime, environment, selection, and realization
  receipts.

Exit: real Hello and the synthetic PE32 fixtures build and run faithful native
candidates without requiring the current must-provenance frontier to vanish.

2026-08-30 checkpoint: V2 direct execution projection, semantic-object replay,
generated-C qualification, and the complete runtime-profile callback boundary
compiler are implemented. Real Hello now derives all four callback physical
protocols without target-authored duplication; its V1 ingress has only the
preserved 63 execution-closure blockers and correctly distinguishes callable
exception escape through `RaiseException` from process-root termination.

The callback-publication runtime now retains this compact representation all
the way into native realization. Fourteen Hello publications each refer to one
of four shared 7,937-target domains; the ingress plan does not construct the
111,118 site-by-target descriptors of the superseded path. One canonical
runtime projection validates domains, publications, grouped outcomes, physical
frames, lifecycle transducers, and bridge-family coverage for every consumer.
It emits deterministic ten-byte target trampolines and one full gateway per
physical frame family. Runtime C densely lowers the four domain-target tables,
while publication lookup uses the shared domain and a process-generation target
assignment rejects any attempt to give one logical target two unequal native
addresses. The module-runtime plan carries domains and publications directly,
and validates them against both checked external contracts and native ingress.

The earlier measured compact projection was 2,262,508 bytes and took 14.11
seconds with 809,180 KiB peak RSS. The former
`callback_domain_requires_compact_runtime_realization` blockers have therefore
been removed; the real-Hello V2 ingress gate now requires a complete plan with
zero blockers. Native linking and candidate execution remain milestone-2 exit
work and must still prove the generated runtime tables in the deployed image.
The first complete real-Hello plan is 2,261,080 bytes. Rendering its 31,748
domain-target rows takes 0.61 seconds for assembly and 2.99 seconds for runtime
C in a 129,508 KiB process; the outputs are 3,077,009 and 10,468,283 bytes.
The exact generated IA-32 assembly and C both compile with the pinned MinGW
toolchain (313 KiB and 43 MiB objects respectively). These size-heavy generated
tables deliberately spend RAM and object space to keep planning and lookup
fast; later sparse-state work may reduce initialized storage but must not
reintroduce site-by-target semantic artifacts.

2026-08-31 faithful-Hello checkpoint: real GNU Hello now links and executes as
an explicit faithful `native-realization-v2`. The exact receipt is complete,
has no blockers, and is ready for observation. Its 62,194,688-byte `hello.exe`
has SHA-256
`0bb922eb039f0c72700b80254f879ee00a4da08b07aac1dc55ce48b068a6af78`.
The deployment-facing headless-Wine suite binds that candidate hash, exits
zero, produces empty stderr, and observes the exact original PE text-mode
stdout `Hello, world!\r\n`. Direct execution of the original GNU Hello under
the same Wine environment independently confirmed the CRLF bytes; the earlier
LF-only test oracle was stale.

Three reusable semantic fixes close the path rather than special-casing Hello:

- The checked private stack is one per-thread region at least as large as the
  original PE stack reserve. Same-thread reentrancy grows naturally downward
  through that region. The 64-KiB value is a minimum-remaining admission guard,
  not a disjoint per-entry slice.
- Machine transfer kind and callee outcome are independent. A transfer-v2
  `outcome_external` terminator is a tail transfer even when the checked callee
  returns; its captured argument base skips the existing continuation word.
  Normal calls to no-return callees remain calls.
- `native-realization-v2` distinguishes a loader IAT address from a checked
  loader-resolved export. The dynamically resolved
  `msvcrt.dll!___lc_codepage_func` definition has no invented IAT RVA or linked
  RVA; its address binds the exact export identity and loader-service contract
  `3f7629809d32db3d4dc3f22610b47a44ff012065ce0079983cdf7e2da6a82a54`.

Independent semantic-object replay now reconstructs the resolver's admitted
dynamic code-export catalog as well as static machine imports. The real-Hello
gate checks the resulting inventory as 75 static semantic imports (73 ordinary
machine imports and two loader services) plus the one exact dynamic export,
rather than accepting a count-only change. Focused native-realization,
semantic-object, real-scale replay, realization, candidate-Wine, and full GNU
Hello aggregate gates pass. Milestone 2 still requires the synthetic PE32
fixture matrix before exit; real GNU Hello itself has crossed the faithful
native link and execution boundary.

2026-08-31 incomplete-runtime-qualification checkpoint: the V2 runtime
provider now distinguishes a checked planning refusal from a materializer or
compiler failure. A semantically incomplete module still emits an
unmaterialized qualification without attempting runtime planning. A
semantically complete module whose native-ingress/runtime planner returns a
canonical blocker inventory emits an incomplete qualification with zero
definition or obligation materializations, empty implementation choices, and
content hashes for its diagnostic ingress and runtime packages. It emits no
object manifest. Only the structured planning-refusal exception enters this
path; malformed diagnostics, stale hashes, compilation failures, and every
other materialization exception continue to abort.

The Hello-derived callback-registration fixture now uses the same V2
generated-C, external-environment, runtime, and selection providers as the
main workflow. Its linked semantic module is genuinely complete: 713 active
definitions comprise 621 generated-C, 76 external-environment, and 16 runtime
requirements, plus 27 residual runtime obligations and zero semantic holes.
Generated C and the external environment qualify all 697 definitions they
own. Native ingress rejects all 621 candidate targets because the fixture's
broad derived registration domain attempts to use each target through four
incompatible physical ABI equivalence classes. The runtime provider therefore
owns nothing, and faithful selection remains honestly incomplete with 16
missing definition selections and 27 missing obligation selections. This is
not a fallback or a semantic regression: the next vertical-slice work must
derive the exact callback capability domain and physical protocol rather than
granting one target multiple unequal native addresses.

Focused runtime-provider and semantic-link unit tests pass, including the
negative unstructured-failure case. The real GNU Hello aggregate, jq and
DX-Ball target aggregates, target-SDK check, Python module-closure freshness
check, and retired-architecture boundary all pass after the migration. jq and
DX-Ball remain incomplete for their previously recorded semantic and external
authority blockers; their runtime providers materialize no authority and
their selections do not silently fall back.

2026-08-31 callback-realization clean-cut checkpoint: callback capability
domains now have one realization independent of cardinality. The former
1,024-target threshold eagerly expanded small domains into native ingress
descriptors while preserving large domains for lazy publication. That second
path made the 621-target registration fixture appear to assign every transfer
entry through four incompatible physical ABIs before any callback was
published. Native ingress now preserves every checked callback may-domain as
one compact domain and publication. A generation-scoped runtime assignment
gives a target a bridge only when the checked publication selects it and still
rejects any later attempt to assign the same logical target an incompatible
physical frame. An architecture regression asserts that cardinality-dependent
callback realization cannot return.

The Hello-derived registration fixture consequently has a complete runtime
qualification for all 16 runtime definitions and 27 residual obligations, and
its faithful selection is total over all 713 definitions and 27 obligations.
Its ingress plan has three static ingresses, four compact callback domains,
four bridge families, fourteen publications, and no blockers. Exact runtime
assembly symbol checking is now derived from the checked SEH inventory rather
than requiring a gateway for modules with no SEH protocol. The resulting
70-object native realization is complete and observation-ready; its
4,986,368-byte candidate has SHA-256
`9eff59ae3ecf24729ab01b99b3bdb69945a51e2fd860974fa17b5f0438ec2262`.
The deployment-facing Wine suite observes exit zero, empty stderr, and the
exact `WriteFile` bytes `registered destructor ran\n`, proving the destructor
registration, checked callback publication, bridge invocation, and lifecycle
path in the deployed candidate.

2026-08-31 synthetic faithful-realization checkpoint: the comprehensive PE32
DLL fixture now closes the same V2 path without a test-authored realization
receipt. Its linked semantic module has 49 active definitions, two residual
runtime obligations, and zero semantic holes. Exact generated-C,
external-environment, and qualified-runtime providers form one total faithful
selection; the runtime qualification consumes the checked pinned-layout
authority for the fixture that observes numeric `Eip` and
`ExceptionAddress`.

The resulting `native-realization-v2` is complete and observation-ready. It
binds all 49 definitions, both obligations, 32 linked native objects, fifteen
static ingress bridges, the compact callback domain/publication, and the exact
pinned-layout requirement. The old test-only constructor that fabricated a V2
receipt around the V1 candidate has been deleted. Project observation and
completion now consume the real V2 receipt and the hash of its actual DLL.

The Wine host passes against that faithful V2 DLL and exercises named and
ordinal exports, aliases and holes, a writable data export with address
identity, combined TLS initialization and callback ordering, concurrent guest
atomics, same-thread reentrancy, checked nonlocal control, guest-handled divide
and access violations, host-import exceptions, continued host exceptions,
x87 context projection, unwind/finally ordering, and an escaped callback on a
foreign thread. The observed load graph and one-module project completion are
both complete and bind the same candidate hash. This also exposed and fixed a
shared receipt defect: pinned-layout authority binds the canonical resolved
environment identity, not the containing JSON file hash.

Milestone 2 is complete. Real GNU Hello and the generous synthetic PE32/Wine
fixture both build, execute, and complete through faithful V2 selection,
native realization, loader observation, and project completion. Subsequent
milestones may not restore the fabricated receipt or make V1 realization part
of the production path.

### 3. Generate reusable slices and operator work packages

- Score proposed boundaries by entries/exits, SCC closure, aliases, state,
  service/callback crossings, exceptions, induction, and expected proof cost.
- Generate semantic slices and V6 work packages directly from linked-module
  definitions and transfer-v2.
- Reuse V5 interfaces, relation IR, lifecycle, and induction implementations
  internally without emitting the overlapping V4/V5 public reducer stack.
- Extend the boundary workbench to component seed and component subjects.

Exit: an operator can start from an RVA and obtain an understandable editable
package without authoring machine hashes.

2026-08-31 reusable-slice vertical checkpoint: every configured Hello, jq, and
DX-Ball component now receives a `component-work-package-v6` and embedded
`semantic-slice-v2` directly from `linked-semantic-module-v2`, its packaged
transfer-v2 member, and the immutable Behavioral-C source map.  The V6 builder
does not consume component-contract V4, machine-binding V5, unit-inventory V1,
implementation receipts, or facet receipts.  It keeps owned definitions
separate from faithful-C context units, so a useful context excerpt cannot
silently enlarge replacement ownership.

The unified boundary workbench now exposes configured `component:<id>` and
`component-seed:<rva>` subjects.  An arbitrary unconfigured RVA is resolved on
demand from the checked proposal package and can be inspected, adopted, or
materialized as a non-authorizing editable package containing a README,
digest-free adoption intent, proposal inspection, public-header draft, and C
skeleton.  This deliberately avoids one Nix attribute per possible RVA and a
second component-discovery database.  Discovery rankings now report
entries/exits, SCC and alias structure, objects, services, callback and
exception crossings, atomics, induction needs, and expected proof cost.

The real GNU Hello `ascii-to-lower` package demonstrates one owned semantic
definition with two faithful-C context units, four dependency contracts, and
exact content bindings.  All ten configured Hello packages and the jq and
DX-Ball structural packages pass their target regression gates; boundary,
format-registry, Python-closure, metadata, and retired-architecture checks
cover the new path.  These packages remain non-authorizing and their tests are
veto-only.

Milestone 3 remains open for one intentional transitional dependency:
configured packages still recover operation intent from the existing
operator-authored V5 binding-intent file, although they no longer consume the
derived V5 binding receipt.  The digest-free adoption intent emitted for an
arbitrary seed must become the direct input to canonical V5 interface and V6
package generation before the public V4/V5 reducer path can be retired.
Milestone 4 must first qualify `ascii-to-lower` directly from its V6 slice and
source package; only then may later consumers migrate and the old reducers be
deleted.

### 4. Implement contextual provider refinement

- Extend the existing transfer-v2/CBMC harness for stateless, stateful,
  inductive, service/callback, atomic, and supported reentrant protocols.
- Treat environment results as nondeterministic within checked contracts.
- Enforce overlay versus encapsulated ownership rules.
- Emit semantic counterexamples showing the operation history, first divergent
  event, object generation/offset, and service response.
- Bind the proof to the pinned toolchain and exact deployed PE32 object.

Exit: small and medium components qualify without importing unrelated callers
or the whole-program must-analysis closure.

2026-08-31 direct contextual-refinement checkpoint: the real GNU Hello
`ascii-to-lower-enabled` configuration now bypasses the component-
implementation V4 reducer.  One authority phase consumes its V6 work package,
V5 human interface, source package V3, transfer-v2, resolved environment, and
the object authority owned by the semantic-object package.  It normalizes the
existing proof and overlay kernels in memory, runs CBMC over the exact
two-transfer contextual universe, compiles the authored source and generated
machine overlay with the pinned host/MinGW tools, and emits the existing
`semantic-provider-qualification-v2`; it introduces no replacement
implementation or facet-receipt format.

The qualification is complete with one definition, ten checked facets, exact
source/object/tool identities, a satisfied contextual-refinement receipt, and
no blockers.  Total hybrid selection replaces exactly that definition and
keeps generated Behavioral C explicit for every other definition.  Native
realization is complete and receipt-binds the portable objects.  A dedicated
Wine suite runs the resulting PE32 candidate and observes exit zero, empty
stderr, and `Hello, world!\r\n`.  The target gate checks the qualification,
proof, selection, realization, and candidate together.  During this vertical,
native realization also exposed and fixed unequal objects sharing an invented
source identity; every authored or generated translation unit now carries its
own exact source hash.

The initial direct admission class is deliberately narrow and semantic: one
stateless machine-overlay operation owning one definition, with no service,
callback, object, relation, or induction protocol.  Only a configuration whose
selection is exactly one such component uses the direct phase for this
checkpoint.  Broader configurations remain on the checked transitional path
until service/callback, object/view, persistent-state/relation, atomic, and
inductive contextual proof are migrated.  Milestone 4 is therefore in
progress, not complete.

### 5. Consolidate providers and scheduling

- Emit one portable provider qualification and object package per component,
  not one aggregate provider.
- Let one selection and realization consume any number of independently cached
  qualifications.
- Simplify the Nix component path to interface intent, slice/work package,
  source package, provider qualification, selection, and realization.
- Convert library behavior packs to the same provider path.
- Retire linked-module V1, provider V1, selection V1, realization V1,
  component-contract V4, machine-binding V5, implementation V4,
  dependency-graph V4, facet-receipt V1, and work-package V5 after all in-tree
  consumers migrate. Keep no compatibility aliases.

Exit: a component edit rebuilds only that qualification and its selected
realization descendants.

2026-08-31 public-SDK V1 clean-cut checkpoint: `sdk.workflow.pe32` already
constructed only V2 generated-C, external-environment, runtime, portable-C,
selection, and native-realization artifacts. The unused public
`sdk.candidate` constructors for V1 generated providers, implementation
selection, and native realization, together with the unexported V1 intrinsic
and portable-provider bindings, have now been removed. The V1 implementation
files remain only for the explicit migration fixture and diagnostic/unit
coverage; they are not reachable through the stable SDK. Target-SDK tests and
the architecture boundary assert that those constructor bindings cannot be
reintroduced. Focused Python tests, SDK construction, Python closure
freshness, and the retired-architecture check pass.

The candidate test execution gate has migrated in the same clean cut. Both
per-case execution and aggregate receipt construction now accept only
`native-realization-v2`; the synthetic Wine fixture emits V2, and the
architecture check rejects any reintroduction of V1 acceptance. Candidate
tests remain veto-only, but they can no longer execute a binary on the strength
of a retired realization receipt.

2026-08-31 independent-provider and checked-relation checkpoint: direct V6
qualification is now scheduled once per component rather than once per target
configuration.  Each provider emits only its own definition choices and exact
qualification/object package.  A configuration composes the generated-C
baseline with any number of those compact fragments; the selector permits only
the explicit replacement of a generated-C definition by one qualified
portable-C provider.  Portable/portable definition overlap and every
obligation overlap still fail closed.  Configurations whose dependency-closed
component set has not fully migrated remain on the existing checked aggregate
path, so partial migration cannot silently mix authority systems.

The direct proof kernel now distinguishes transfer-v2's sparse
`stack_inputs`---words written by the current transfer---from the complete
fixed-arity physical argument frame.  It reconstructs every checked ABI
argument as an ESP-relative load while retaining the sparse event rows as
machine evidence.  Component-operation service bindings contribute their
exact provider entry definitions to the local refinement universe.  Checked
external relations are specialized from the existing interaction-contract
catalog, require an authorizing interaction-contract receipt, bind the exact
machine event and service types, and enter the same CBMC contextual proof; no
test or relation intent grants authority by itself.

The real Hello `program-name-selection` provider consequently qualifies all
14 of its definitions against the checked two-argument `strrchr` relation and
the exact `memory-regions-equal` component operation.  Its independently
cached dependency provider qualifies two definitions.  One hybrid selection
replaces exactly those 16 definitions, leaves every other definition assigned
to generated C, selects all 117 runtime obligations, links both portable
object packages, and produces an observation-ready native realization.  The
portable reference/view ABI helpers live once in the shared module runtime;
there is no per-component runtime or target-specific adapter.

The full Hello aggregate and Wine suites now pass for faithful execution,
`ascii-to-lower`, `program-name-selection`, and
`startup-callback-registration`.  jq and DX-Ball target aggregates retain
their pre-existing honest incomplete authority states.  Target-SDK,
semantic-provider, format-registry, repository-metadata, Python-closure, and
retired-architecture gates pass.  This closes independent multi-provider
composition and the checked service/relation part of milestones 4--6.

The required synthetic `encapsulated_owned` vertical is also complete.  It
does not introduce another refinement language: the existing CBMC contextual
kernel proves the scalar state transition for every admitted initial state,
while one conservative admission receipt proves total ownership of every
active transfer, exact writable image-object partitions, absence of data
anchors and outside aliases, and a single process root with no callback,
exceptional, external, indirect, or concurrent ingress.  The generated
adapter imports the original state once into a distinct image-lifetime C
context and never writes the retired mapped cells back.  A native harness
observes two successive calls retaining private state while the original word
and write count remain unchanged; the same adapter compiles for host and
PE32.  Invalid loader-visible aliasing fails closed, and architecture gates
require this admission to remain attached to the one direct V6 qualifier and
the one existing refinement invocation.  Root and target flake checks pass.

This closes initial stateful persistent simulation for the deliberately
narrow thread-confined shape and the required representation-changing proof.
It does not yet close arbitrary reentrant protocols, general shared-state
replacement, or retirement of the transitional V4/V5 component reducers.

2026-08-31 reusable-library provider checkpoint: reusable behavior packs no
longer generate a public component contract V4, machine binding V5,
implementation V4, dependency record, or library-specific component object.
A checked island derives only the existing machine-binding intent V1 and V5
human interface; `linked-libraries.nix` derives the ordinary semantic slice
V2 and hands those inputs to the same
`portableCWorkPackageProviderV2` constructor used by operator-authored
components. The resulting qualification binds the behavior-pack manifest,
source qualification, and checked-island receipt as exact provenance
dependencies. Library status reads that ordinary provider qualification and
cannot infer authority from recognition or adoption records alone.

The generous GNU Hello vertical builds a real reusable `ascii-to-lower`
behavior pack from separately owned source, rechecks it against the exact
machine slice with CBMC, compiles its host and PE32 objects, and emits a
complete ten-facet semantic-provider qualification with no blockers. The full
Hello target and Wine candidates pass with this provider in the graph. The two
library-only V4/V5 Nix phases are removed, the generated-library component
format is retired, and architecture and unit gates prohibit the detour from
returning. This closes library-provider migration to the shared qualifier; it
does not claim that the remaining ordinary component V4/V5 consumers have
been retired.

2026-08-31 semantic-slice invalidation checkpoint: direct portable
qualification no longer consumes the V6 presentation work package or, for an
ordinary machine overlay, the complete linked semantic module. One
independently content-addressed `component-semantic-slice-v2` phase projects
the existing `semantic-slice-v2` from the canonical module and binding intent.
The qualifier reconstructs its internal proof view directly from that slice,
the interface and binding intents, source V3, transfer-v2, resolved
environment, and object authority. There is no new format, proof language,
cache manager, or semantic adapter artifact.

Module-wide facts remain explicit rather than being hidden behind the slice.
A component with a callback-handle projection still receives the linked module
to validate publication against the admitted callback domain, and an
`encapsulated_owned` component still receives it to prove total active-transfer
ownership and the single-root ingress shape. The real Hello derivation inputs
confirm the distinction: `ascii-to-lower` names the slice and no linked module
or work package, while `startup-callback-registration` names the same local
inputs plus the linked module. Architecture checks reject a work-package input
and require the linked input to remain optional.

Controlled tests prove that analysis-only changes and an unrelated new
definition leave the selected slice byte-identical, while a changed selected
definition remains stale and fails closed. A deliberately incomplete portable
qualification makes its hybrid selection incomplete but is not part of a
fresh faithful selection; the generated-C/runtime selection remains complete
and realization-ready. Forced local rebuilds with prepared inputs measured
5.94 seconds for `ascii-to-lower` and 13.51 seconds for the medium
`program-name-selection` provider, below the 60-second and five-minute gates.
The full GNU Hello target aggregate, including faithful and all three direct
Wine verticals, passes after the cut.

This closes the required cache-invalidation and faithful-fallback parts of the
generous vertical. General reentrant/shared representation changes, induction,
library-provider migration, and V4/V5 retirement remain open.

2026-08-31 direct-induction checkpoint: the three GNU Hello inductive lifts,
`bounded-string-length`, `last-path-component`, and `ascii-string-compare`,
now qualify as independent direct V6 semantic providers. The direct qualifier
reuses the existing exact machine-replay, cutpoint-relation, inductive-source,
certificate, and CBMC kernels; it reconstructs each referenced component
operation provider from that provider's interface intent, binding intent, and
semantic slice rather than reopening a public V4 contract or V5 machine
binding. The selected transfer universe is the exact union of consumer and
referenced-provider units. Induction declarations remain content-bound by the
direct internal binding and the emitted provider qualification binds both the
inductive refinement receipt and source plan.

The `string-pointer-enabled` target gate proves that every selected component
uses an independent direct provider, that no aggregate legacy provider is
present, and that all three induction facets and contextual refinements are
satisfied. The complete GNU Hello aggregate, including its Wine verticals,
passes after this cut. General reentrant/shared representation changes,
library-provider migration, and public V4/V5 retirement remain open.

2026-08-31 direct-V6 target and public-phase clean-cut checkpoint: all
configured GNU Hello, jq, and DX-Ball components now schedule their semantic
slices, V6 work packages, and direct portable-provider inputs without the
public component-contract V4, machine-binding V5, semantic-refinement V5,
implementation V4, dependency-graph V4, relation V5, external-sites V5, or
work-package V5 Nix phases. Those phase files have been deleted, the stable SDK
cannot name their former arguments, and the architecture gate rejects both
the deleted files and the old constructor names in production roots.

jq's authored `jv-array-comparator` and `jv-object-comparator` work packages
remain non-authorizing with the exact blockers
`machine_effect_service_callback_outcome_projection_unreviewed` and
`portable_interface_semantics_unreviewed`. DX-Ball's `directdraw-init` work
package retains the exact machine-effect/service/callback/outcome blocker.
Both target aggregates build through the direct V6 path; the migration has not
manufactured authority or reduced the semantic universe to improve status.

The direct proof path also now has one C ABI rather than a proof-only V2-shaped
facade and a separately compiled V5 shape. CBMC receives the same generated
`portable-component.h` and `portable-component-implementation.h` as host and
MinGW compilation. Checked references use one tagged 64-bit identity/layout,
byte and reference views share one named-field representation, callback
capabilities use the same `{physical_word, target_rva}` representation in the
proof harness and native overlay, and checked-reference status has one 32-bit
type. The full GNU Hello aggregate and Wine verticals pass after this cut.

The remaining retirement work is internal Python normalization and old test
fixture cleanup: the direct qualifier still reuses proof-kernel helper classes
whose historical module names and serializers expose V4/V5 terminology. Those
helpers must move to neutral in-memory models before the corresponding public
format codecs, V1 provider fixtures, and retired-format declarations are
deleted.

2026-08-31 internal component-reducer clean-cut checkpoint: the direct V6
qualifier now reconstructs retained machine-binding intent through
`binding_intent.py`, then uses format-free `NormalizedComponentContract` and
`NormalizedMachineBinding` values for the proof kernel and machine overlay.
Portable object compilation is a mechanical `portable_object.py` helper, and
inductive checking returns a non-serialized internal proof-facet result. None
of these models can be mistaken for an authorizing public component receipt.

The component-contract V4, machine-binding V5, implementation V4,
dependency-graph V4, implementation-facet V1, unit-inventory V1, and
work-package V5 codecs and tests are deleted. Their literals are retired
domain declarations with no production reader; the machine-binding intent
literal now names its actual retained codec. The two legacy portable-provider
Nix constructors and their V1/V2 implementation-reducer reader are deleted as
well. Architecture gates prohibit the modules, class names, constructors, and
production literals from returning.

The comprehensive PE32 DLL fixture no longer builds a second incomplete V1
portable/selection/realization graph beside its complete V2 deployment. It
still builds and runs the exact faithful V2 DLL, loader observation, and
project-completion chain. The native-DLL gate, full GNU Hello aggregate and
Wine verticals, jq and DX-Ball aggregates with honest blockers, format
registry, Python closure, and retired-architecture gates all pass after this
cut. Milestone 5 remains open only for the repository-wide linked-module,
provider, selection, and native-realization V1 codecs and developer fixtures;
the component V4/V5 reducer retirement is complete.

2026-09-01 semantic-provider/realization clean-cut checkpoint: milestone 5 is
complete. The production semantic may-link now returns only the closed
in-memory `SemanticLinkFactsV2` carrier and publishes
`linked-semantic-module-v2` directly. The public V1 module codec, compiler,
execution view, diagnostics, replay path, tests, and migration adapter are
deleted; V1 is a retired format tombstone with no reader. The aggregate V1
portable-provider runtime input and dispatch materializer are deleted as
well. Provider qualification V1, implementation selection V1, and native
realization V1 codecs, Nix constructors, and fixtures are retired in the same
clean cut.

All remaining library, runtime, project-status, SDK, and native-module
fixtures consume V2 objects. Architecture gates prohibit every removed module
and public V1 API, prohibit the optional must worklist from the production
linker, and require the conservative semantic-object link to feed the closed
V2 carrier. Focused semantic-link, provider, realization, SDK, format,
metadata, lint, and architecture checks pass. The real PE32/Wine native-module
vertical still links, executes, observes, and completes from an exact V2
realization after the retirement.

### 6. Pass the operator-first generous vertical slice

- Build and observe real GNU Hello in faithful mode while retaining the 63
  historical must-analysis rows only in the separate diagnostic receipt unless
  independently improved.
- Preserve the Hello-derived registration and synthetic DLL coverage for
  allocations, callbacks, TLS, reentrancy, foreign threads, atomics, SEH,
  nonlocal outcomes, exports, relocations, SafeSEH/CFG, and observation.
- Qualify three public-workflow Hello replacements:
  - `ascii-to-lower` as a small stateless component;
  - `program-name-selection` as a medium persistent-state/service component;
  - `startup-callback-registration` as a service/callback/lifecycle component.
- Add one synthetic `encapsulated_owned` proof rather than forcing an
  unsuitable real component to change representation.
- Prove that a failed replacement leaves the explicit faithful configuration
  buildable and that an unrelated module edit reuses a byte-identical slice
  qualification.

Performance gates are: prepared Hello V2 link below 5 seconds, optional full
must-analysis below 30 seconds CPU, warm status below 1.3 seconds, small
qualification below 60 seconds, and medium qualification below 5 minutes. RSS
is telemetry; prefer resident indexes and parallel work over compact/re-expand
machinery.

Exit: the public workflow demonstrates faithful deployment followed by three
independent, proved idiomatic replacements.

2026-09-01 corrected vertical-slice performance checkpoint: real GNU Hello
now links byte-identically from its content-bound semantic object in 3.7
seconds on the development host, below the five-second production budget. The
module is complete with 8,019 active definitions, 12,249 active relocations,
109 typed residual obligations, zero semantic holes, and zero optional-analysis
frontiers. The existing full must-analysis remains a separate diagnostic
budget; its earlier 23.97--24.09-second samples are retained as historical
performance evidence, not as module provenance.

The same production linker completed the real 36,005-transfer libjq semantic
object in 20.6 seconds after the former authorizing path remained CPU-bound for
more than fifteen minutes. It materialized all 36,304 active symbols, 51,809
active relocations, 412 runtime obligations, and 659 honest environment,
platform, loader-relocation, protocol, and provider holes. This validates the
generous vertical slice at materially larger scale without hiding jq's missing
authority.

The first end-to-end Hello rebuild took 2 minutes 22 seconds, but this is not
an invalidation regression: the preceding transfer/ISA fixes genuinely changed
the semantic object from 7,937 to 7,849 transfers and from 12,337 to 12,249
relocations. Inspection of the phase-closure constructor confirms that source
derivations depend on selected per-phase files rather than the generated index
digest, while the nominal 88-derivation ISA list converged through existing
content-addressed outputs. No cache subsystem or invalidation redesign is
justified by this measurement. Nix remains the sole persistent cache.

2026-09-01 canonical-spine scheduling checkpoint: the production
`linked-semantic-module.nix` constructor no longer accepts the original PE,
behavioral roots, must-worklist limit, CPU budget, or prepared-link budget.
Those inputs now exist only on the independently instantiated developer-role
performance derivation; the default SDK cannot schedule that veto-only work.
Python and Nix architecture gates enforce the one packaged semantic-object
input and reject decoder, transfer, PE, solver, or performance dependencies in
the direct linker. Linked definitions remain compact hashes and dependency
contracts rather than copied transfer bodies.

Focused semantic-object, linked-module, Behavioral-C differential, target-SDK,
metadata, and retired-architecture gates pass. Real GNU Hello remains complete
with 8,019 definitions, 12,249 active relocations, 109 residual obligations,
and zero holes or frontiers. Real libjq remains at 36,304 active symbols,
51,809 relocations, 412 obligations, 659 honest holes, and zero frontiers; its
post-cut build converged to the existing content-addressed module output.

### 7. Migrate targets and close deployment

- Migrate jq component packages without inventing missing `jv`, refcount,
  loop, callback, or ownership authority.
- Migrate DX-Ball `directdraw-init`, COM/vtable services, resources, callbacks,
  shared data, TLS/DLL lifecycle, exceptions, and multi-image relationships.
- Bind every multi-image code, data, forwarder, delay-import, and loader-service
  edge to completed module realizations and observed hashes.
- Refresh formats, module/test registries, documentation, and absence gates.
- Run `nix flake check`, `nix flake check ./targets`, target aggregates, PE32
  ingress/project suites, applicable Wine suites, metadata freshness,
  architecture boundaries, performance, and retired-format absence gates.

2026-09-01 target-migration checkpoint: GNU Hello and its three portable
replacement verticals pass through deployment and Wine observation. jq is a
target-owned two-module V2 project with stable honest private-ABI and
environment blockers; four newly selected exact x87 replays reduce libjq's
holes from 607 to 603 without changing its conservative universe. DX-Ball's
linked semantic module is complete with zero holes and 261 typed runtime
obligations. Its qualified runtime remains deliberately incomplete on exactly
the checked `RtlUnwind` and `UnhandledExceptionFilter` service protocols and
emits no source or linkable object. Milestone 7 therefore remains open on
generic native realization of those services, the remaining object/COM and
component review, deployment/observation, and the final repository gates.

Exit: faithful, hybrid, and portable completion use the same semantic module,
provider selection, realization, deployment, and observation chain.

## Completion definitions

- Semantic completion requires no may-reachable semantic holes and a typed
  residual obligation for every runtime-dependent effect.
- Faithful completion requires total generated-C definition ownership, total
  residual-provider selection, native realization, deployment, and candidate
  observation.
- Hybrid completion adds one or more locally proved portable providers.
- Portable completion permits no generated-C ownership in the conservative
  realization universe.
- Component qualification requires exact slice binding, contextual
  refinement, source safety, services, ownership, lifecycle, induction where
  needed, pinned toolchain, and deployed object binding.

## Assumptions and non-goals

- IA-32 PE32/Win32 remains the initial backend.
- Runtime discharge is valid only when total over the checked admitted domain;
  trapping an original-valid state is not faithful behavior.
- The conservative realization universe may exceed true reachability.
- General concurrent portable-state refinement and arbitrary unbounded
  reentrancy remain unsupported initially.
- Source proof plus the pinned MinGW toolchain is the chosen first compiler
  trust boundary; translation validation is deferred.
- Existing TLS, SEH, native ingress, PE composition, deployment, and candidate
  observation requirements remain mandatory.

## Superseded design and implementation journal

The remainder of this file is preserved verbatim as implementation history.
It is non-authoritative where it conflicts with the revision above.

## Revised outcome

The repository will converge on this path:

```text
                  qualified platform release
       ISA semantics + transfer templates + lowering + ABI/runtime
                                  │
original PE ── pe32-module-interface-v2
     │                            │
checked machine IR + external-environment intent
     │                            │
     └──────────────┬─────────────┘
                    ▼
             semantic-object-v1 package
       relocatable symbols + transfer-v2 bodies + typed effects
                    │
          environment and library semantic objects
                    │
                    ▼
          linked-semantic-module-v1
       one checked symbol resolution and one total closure
                    │
          ┌─────────┴──────────┐
          ▼                    ▼
 generated Behavioral C   qualified portable-C providers
          └─────────┬──────────┘
                    ▼
            native-realization-v1
     ABI thunks + shared runtime + link + PE composition
                    │
                    ▼
       independent candidate/project observation
```

Generated Behavioral C remains the only deployed fallback. Operator-authored
idiomatic C may replace selected semantic definitions only after independent
refinement qualification. Deployed execution is native C and reviewed PE32
assembly. Tests, the reference evaluator, Wine, emulators, solvers, and
differential oracles remain veto-only or supporting evidence and cannot grant
completion.

The pivot is a replacement, not an additional orchestration layer. Current
phase implementations may be reused temporarily inside the semantic compiler,
but their independently scheduled authority artifacts, graph reinstantiations,
adapters, and completion reducers must be removed after parity.

## Revised keystone success condition

`executable-transfer-plan-v2` remains the sole behavioral language and the
only production compilation of checked machine behavior. The architectural
keystone is now its checked enclosing object and link model:

- `semantic-object-v1` uses transfer-v2 as its only executable function-body
  language and adds only relocatable symbols, typed imports, objects,
  relocations, effects, outcomes, roots, evidence references, and explicit
  holes.
- `linked-semantic-module-v1` is produced by one semantic link and one total
  fixed point over those objects. Authority is validity of that linked module,
  not the agreement of a parallel authority workflow.
- The evaluator, closure kernel, Behavioral-C renderer, component refinement,
  runtime-feature selection, native realization, and deployment checks consume
  the same transfer-v2 bodies and stable semantic symbol identities.
- No target, component, runtime, ingress, or composer may decode x86, adapt raw
  machine IR, reconstruct behavior from an earlier receipt family, or introduce
  a second behavioral language.

The original goal is therefore preserved more strongly: machine behavior is
still compiled once into transfer-v2, while the systems formerly surrounding
that IR become ordinary checked object construction, semantic linking, native
linking, and independent observation.

## Genuine simplification boundary

Four independently checkable claims must remain separate:

1. `pe32-module-interface-v2` states loader facts decoded from the original
   image.
2. The linked semantic module states the original module's checked meaning.
3. Native realization states how that meaning was implemented and composed.
4. Candidate observation states what the loader actually saw.

Collapsing any pair would weaken verification. Everything between those
boundaries is subject to consolidation. In particular, external resolution,
object authority, boundaries, lifecycle, outcomes, callbacks, capabilities,
components, ingress, and runtime selection are not separate semantic
pipelines: they are typed symbols, storage regions, relocations, effects,
providers, or lowering decisions over the same semantic objects.

The semantic-object schema is closed and domain-owned. It is not a generic
graph database, plugin framework, mutable cache, daemon, or bag of arbitrary
metadata. A field is admitted only when it describes original semantics or
the checked evidence for one semantic definition independently of its chosen
native implementation.

## Canonical contracts after the pivot

| Contract | Revised decision |
|---|---|
| `pe32-module-interface-v2` | Retain as the independent original loader-fact authority, including full EAT, imports/delay imports, TLS, stack, resources, load config, SafeSEH, CFG, relocations, and pointer-bearing metadata classification. |
| `external-environment-intent-v1` | Retain as non-authorizing operator link input. Profile and interface packs become semantic declaration libraries. The analysis projection remains a non-authorizing view. |
| `qualified-platform-v1` | Add one target-independent release manifest binding decoder/classifier identity, normalized semantic forms, transfer-v2 templates, Lean qualification, veto-oracle observations, Behavioral-C lowerings, ABI profiles, and reviewed ingress/runtime primitive contracts. Exact generated runtime source, compiler, and object identities belong only to provider qualification and native realization, so implementation edits cannot invalidate original semantics. |
| `executable-transfer-plan-v2` | Retain as the sole behavioral body language. It is compiled once from checked machine IR and embedded or content-referenced by semantic objects without semantic adaptation. |
| `semantic-object-v1` | Add the sole relocatable semantic unit for extracted code/data, environment declarations, library behavior, and qualified implementation providers. |
| `linked-semantic-module-v1` | Add the sole resolved symbol table, object/effect model, root-provenance closure, implementation requirements, evidence inventory, and blocker authority for one original module. |
| Component source package v3 and V5 work package | Retain source v3 as authored input and V5 work packages as non-authorizing projections. Replace the overlapping contract/binding/implementation/dependency/activation stack with one semantic-provider qualification and one total implementation selection after all consumers migrate. |
| `semantic-provider-qualification-v1` | Add one receipt reducing compile, source, refinement, lifecycle, service, relation, induction, ownership, and exact native-object evidence for definitions a provider may implement. |
| `implementation-selection-v1` | Add a total semantic-symbol-to-provider selection. It is build input, not original semantic authority, and cannot change the linked module's behavior. |
| `native-realization-v1` | Add one receipt containing generated sources, provider objects, runtime primitives, ABI/SEH thunks, symbol ownership, link map, RVAs, relocations, composed PE surface, decoded candidate interface, and candidate hash. |
| Candidate/project observation | Retain as an independent load observation and project-completion input. It must bind actual module hashes, loader bases, imports, forwarders, and distribution membership to realizations. |

The current resolved-environment, execution-closure, machine-object-authority,
native-ingress, runtime-plan, build-plan, link-receipt, loader-surface,
deployment, and project-load contracts remain authoritative only during their
respective parity migrations. Their facts move into the linked semantic module
or native realization exactly once; their public formats and readers are then
retired rather than adapted indefinitely.

## Semantic-object and linker rules

`semantic-object-v1` contains:

- Exact input bindings and stable object, symbol, unit, transfer, instruction,
  event, RVA, and evidence identities.
- Function and data declarations with linkage, visibility, storage class,
  logical boundary type, optional physical frame, lifetime, and permissions.
- Transfer-v2 function bodies or qualified external semantic contracts; no
  third behavioral representation is permitted.
- Code, data, IAT, TLS, object-interior, callback, exception-continuation, and
  loader-service relocations with exact addends and required views.
- Derived read, write, atomic, allocation, lifecycle, callback, exception,
  nonlocal, termination, and runtime-primitive effects.
- Root declarations, evidence references, and explicit typed holes.

The semantic linker must:

- Resolve every symbol exactly once and reject duplicate, missing, ambiguous,
  code/data-confused, ABI-incompatible, or effect-incompatible definitions.
- Treat object authority as typed data definitions, regions, interiors,
  generations, permissions, storage classes, and data relocations.
- Treat code capabilities as typed function relocations carrying physical
  protocol, generation, escape, publication, and expiration rules.
- Treat normal, no-return, exceptional, and declared nonlocal outcomes as
  closed function effects; unknown control leaves an explicit hole.
- Run one deterministic worklist over process/DLL/TLS/export/callback/handler
  roots. Newly discovered callback or continuation roots resume the same
  worklist instead of constructing a derived authority workflow.
- Record root-provenance bitsets, reachable definitions and edges, reference
  facts, lifecycle transitions, effect requirements, evidence dependencies,
  and stable blockers.
- Admit authority only when every root-reachable symbol, relocation, semantic
  primitive, effect, outcome, and required external declaration is resolved
  and qualified.

Semantic objects never contain generated-C filenames, authored source layout,
provider selection, candidate RVAs, linker layout, candidate hashes, or test
results. Native realization never changes original semantic definitions.

## Dependency and implementation policy

- Reuse the current checked machine IR and transfer-v2 compiler. Do not add
  LLVM, MLIR, VEX, p-code, or another production IR.
- Reuse artifact-v3 canonical storage during migration, but do not expose each
  cheap compiler pass as a separate Nix derivation merely because it emits a
  typed record set.
- Keep Nix as the only persistent content-addressed cache. Do not add a mutable
  cache, database, background broker, internal Nix clone, or per-form
  derivation explosion.
- Reuse the existing Python phase logic initially inside one pure semantic
  compiler invocation. Reuse the current Rust transfer fixed point for the
  dense semantic-link/closure kernel and retain Python whole-result parity as
  a developer/test veto.
- Keep Z3 for bounded feasibility, target sets, and counterexamples; models
  must be reconstructed or certificate-checked before contributing evidence.
- Keep Lean as semantic qualification authority where covered, CBMC for
  portable-C refinement, and Bochs/Unicorn/Ghidra/Capstone as veto-only or
  proposal tools under their existing trust rules.
- Defer Remill, SoftFloat, LLVM, MLIR, PyVEX/angr, Triton, and Intel XED unless
  a separately measured capability gap justifies one dependency.

The intended Nix cache units are the qualified platform release, extracted
semantic-object package, linked semantic module, independently authored
provider qualifications, native realization, and observation/test products.
Large internal artifacts may retain canonical packs and stable hash buckets,
but those packs are storage, not public scheduling systems.

## Public SDK and operator interface

SDK v4 remains the sole target declaration interface during this pivot. Its
environment and lifting intent remain source inputs; its internally exposed
workflow products change to semantic objects, linked modules, provider
qualifications, selections, realizations, and observations. Targets do not gain
new semantic knobs.

Public commands remain:

- `boundary status|inspect|propose|adopt|check`
- `candidate build|status|check|test`

Subjects continue to use stable `kind:id` identities. `candidate status`
becomes a projection over a materialized linked-module summary, provider
qualifications, realization, and observation; it must not instantiate the
construction DAG merely to report existing blockers. Low-level semantic-object,
semantic-link, realization, observation, and replay checks replace the current
transfer/closure/build/composition/deployment expert sequence as consumers
migrate.

Performance policy is unambiguously speed-first on a RAM-rich reference host.
All governed semantic compilation, link, provider, realization, and test phases
should retain broad decoded working sets and use parallel work across all
available cores. Historical 512-MiB/1-GiB measurements and older sub-1-GiB
parity gates below are telemetry baselines, not current acceptance limits or
optimization targets. Peak RSS remains recorded only to explain performance;
there is no fixed RSS release veto. CPU time, wall time, available-core
utilization, incremental rebuild fan-out, and unchanged-status latency are the
gates. Prefer direct tables, redundant indexes, decoded forms, memoized
intermediates, long-lived solver contexts, prepared outputs, and concurrent
shards whenever they make those gates faster, even when the resident set grows
materially. Do not spend implementation effort compacting, serializing and
re-expanding, evicting, or recomputing live semantic state merely to lower RSS.
Memory work is warranted only after measured OOM or swapping harms throughput,
or when it independently improves latency. Rely on the host/Nix resource
boundary rather than adding a project memory manager, eviction policy, or
configurable semantic budget.

## Revised ordered implementation

### 1. Freeze the proven foundation and add pivot guardrails

- Preserve the complete dirty-tree implementation. Do not mechanically undo
  transfer-v2, native closure, Behavioral C, V5 components, generic ingress,
  shared runtime, PE composition, or observation work.
- Refresh exact Hello, jq, and DX-Ball blocker snapshots, current derivation
  counts, cold/warm status latency, closure timing/RSS, and generated format
  consumers before the first new contract.
- Preserve the existing deployment blocker for claimed Behavioral-C objects
  absent from the exact link receipt.
- Add architecture rules that new semantic-object code may consume behavior
  only from transfer-v2 and that the pivot cannot introduce a second object
  authority, closure, runtime dispatcher, cache, or legacy-format adapter in a
  production root.
- Record the current 4,495-unit/6,052-edge Hello closure, 59 blockers,
  three-sample sub-15-second/sub-1-GiB performance veto, synthetic PE32/Wine
  deployment, and the previously passing root/target aggregate checkpoints as
  parity baselines, not authority for the new path.

Exit: the old path remains reproducible, the new architecture has absence and
trust-boundary tests before implementation, and every later semantic change
has an exact comparison baseline.

### 2. Implement semantic-object-v1 without changing authority

- Define the closed schema, canonical codec, content identity, bounded parser,
  domain-owned format declaration, corruption matrix, and independent replay
  validator.
- Construct faithful module semantic objects directly from the exact transfer
  plan, structural inventory, module interface, and evidence references. Do
  not reread or decode machine IR outside the transfer compiler.
- Model function/data declarations, transfer bodies, objects, relocations,
  storage classes, types, physical frames, effects, outcomes, roots, evidence,
  and holes.
- Make the evaluator and Behavioral-C renderer consume transfer bodies through
  the semantic-object reader while retaining exact whole-plan parity.
- Prove byte-identical transfer bodies, source coordinates, event ordering,
  unit ownership, direct edges, entry targets, runtime requirements, and
  blockers for generated fixtures and real Hello.
- Keep the output explicitly non-authorizing until every required parity check
  passes; allow only a one-way migration exporter in test/developer closures.

Exit: semantic objects losslessly contain the current keystone behavior, no
consumer independently adapts machine IR, and the representation adds no
candidate or operator-authored semantics.

Implementation checkpoint (2026-08-27): the first authority-neutral
`semantic-object-v1` package slice is implemented. Its bounded canonical codec
binds an exact `pe32-module-interface-v2` member and an exact
`executable-transfer-plan-v2` member, projects stable function, section-object,
import, loader-relocation, root, evidence, and typed-hole identities, and
replays both upstream strict codecs before accepting the object. Transfer
bodies and plan-wide effect inventories are content-referenced rather than
serialized a second time; the Nix package uses store symlinks and the focused
gate proves byte identity, so the new cache unit does not duplicate the large
plan. The builder is fixed to `migration_shadow`, `authority = false`, and
`status = incomplete`; requiring authority fails closed. Corruption tests cover
outer-rehashed member, declaration, root, hole, and binding damage, and an
import-bearing PE fixture checks data objects and unresolved IAT relocations.
The domain owns its format declaration, is present in the generated registries,
and an architecture test forbids imports from machine IR, ISA decoding,
reconstruction, authority, components, or candidate realization.
Construction and replay are separately implemented: the veto-only replay
checker imports neither the constructor nor its projection helpers and rebuilds
the function, data, import, relocation, root, effect-reference, member, and
mandatory-hole coordinate sets directly from the two strict upstream members.
The veto-only evaluator and Behavioral-C package builder also have
semantic-object entrypoints. Generated cases, concrete observations, and
inspection are identical through the object reader on the checked fixture; all
Behavioral-C artifacts other than the deliberately different top-level input
binding are byte-identical to direct transfer-plan rendering.

Real-scale checkpoint (2026-08-27): the exact GNU Hello object now builds as a
normal SDK product. It binds the complete 38,490,869-byte transfer-plan member
by symlink rather than copying it and emits a 7,970,042-byte relocatable index:
7,937 transfers, 8,019 symbols, 7,944 definitions, 75 loader relocations, three
roots, two evidence bindings, and six explicit migration holes. The member is
byte-identical to the prior transfer product, so transfer bodies, source
coordinates, event ordering, ownership, direct edges, entry targets, runtime
requirements, and zero transfer blockers are identical by construction. The
independent Nix replay gate completed in 2.739 seconds at 400,992 KiB peak RSS,
inside its deliberately generous 8-second/512-MiB veto, with semantic-object
identity `1c84cbc433a775727074a3a55a1b15653dc9e390b2f4ce9d18e3cd850995f172`
and transfer-plan identity
`f8a02ffcac066f39faa0b14ca8a2bd44278faf6081f146b1ccd88a4947301131`.

The same SDK wiring built non-authorizing semantic packages directly for jq
(4,614 transfers, 4,741 symbols, 120 loader relocations) and DX-Ball (9,008
transfers, 9,108 symbols, 97 loader relocations). This is structural migration
only: their later authority blockers are not erased or converted into semantic
claims. Direct jq plus DX-Ball semantic builds scheduled 40 legacy prerequisite
derivations total. In contrast, requesting the Hello regression aggregate to
reach the same one-object product scheduled 445 derivations. A direct Hello
real-scale product needs 20 declared legacy prerequisites and built only its
new replay check when those prerequisites were warm. These measured fan-outs
are the cache/scheduling baseline that milestones 3 through 5 must collapse;
the new semantic object itself must not be split into per-symbol derivations.

Milestone 2 exit checkpoint (2026-08-27): target SDK workflows now schedule
Behavioral C only from `semantic-object-v1`; the direct transfer-plan option was
removed from the Nix renderer after migrating the synthetic native-module
fixture. The real Hello renderer remained ready and owned/lowered all 7,937
units while binding semantic object
`1c84cbc433a775727074a3a55a1b15653dc9e390b2f4ce9d18e3cd850995f172`
and the unchanged transfer plan. The complete native PE32 DLL/Wine deployment
and candidate-observation check also passed through this scheduled path. The
host evaluator is veto-only rather than a production phase; its semantic-object
entrypoint is the checked developer path and retains exact direct-plan parity.
An architecture gate prevents the scheduled renderer from regaining a
`transferPlan` input.

Milestone 2 is therefore complete without granting semantic authority. Logical
types, physical frames, resolved effects, evidence closure, object views, and
loader relocations remain explicit holes to be filled by qualified-platform
selection and the one semantic link in later milestones; the migration shadow
must remain incomplete until then.

### 3. Build one qualified-platform-v1 release

- Define the finite supported primitive inventory from the reviewed
  classifier, Lean semantic kernel, transfer-v2 operation templates, lowering
  registry, and runtime-provider catalog—not from target names or the current
  corpus.
- Bind every primitive's semantic form, decoder/classifier version,
  transfer-template identity, Lean qualification, veto-oracle observations,
  Behavioral-C lowering, x87/atomic helper, and required native provider.
- Prototype against the exact union of Hello, Hello-derived, jq, and DX-Ball
  forms, then prove that every target occurrence selects the same or a stricter
  qualification result as its current target-local campaign.
- Keep exact occurrence extraction and occurrence-bound evidence in each
  module object. Platform evidence must never claim that an occurrence exists
  in a target.
- Measure cold construction once and repeated target selection. Require target
  or component edits to leave the platform derivation identity unchanged.
- Migrate primary and derived-registration workflows, then delete target-local
  catalog proposal, enrichment, corpus, Lean-shard, Bochs, Unicorn, merge, and
  selection campaigns. Retain shared veto-oracle evidence only in the platform
  build/test closure.

Milestone 3 implementation checkpoint (2026-08-27): the repository now emits
one content-addressed, target-independent `qualified-platform-v1` migration
release from the shared Lean semantic-kernel binding and intrinsic source
registries. Its first closed catalog contains all 90 transfer-v2 primitives,
one centrally owned set of 14 transfer/runtime-provider trigger rules, total
Behavioral-C lowering coverage with zero rejections, and four explicitly
veto-only interpretation domains. The release is 74,877 bytes and has identity
`04e66b00f076fbade0bfb2c7369bac977f591ee7102a8d29951166de79f065a0`.
An independent replay reconstructs the operation, coverage, provider, kernel,
and classifier bindings without importing the release builder. A Nix check
builds the release under two unrelated derivation names and requires
byte-identical artifacts; every target SDK bundle now references the same
singleton release rather than instantiating a target copy. A warm root
selection took 0.436 seconds including Nix evaluation.

The checkpoint is deliberately non-authorizing and milestone 3 remains open.
The release records exact holes for the unpublished finite Lean ISA-form
catalog, unlinked physical ABI profiles, unlinked reviewed native primitives,
and unproven migration-corpus selection parity. Exact occurrence selection will
be folded into semantic-object construction in milestone 4 rather than emitted
as another per-target public artifact. The runtime-provider triggers formerly
duplicated by transfer planning and Behavioral C are now selected from the one
intrinsic registry with unchanged transfer-plan and Behavioral-C outputs.

The first full GNU Hello SDK replay after changing that foundational registry
scheduled 449 legacy derivations and passed. This is the measured invalidation
baseline—not an acceptable final architecture. It confirms why the remaining
milestone must replace target-local qualification campaigns and why milestones
4 and 5 must schedule one semantic compiler/link instead of injecting shared
implementation modules into hundreds of phase-specific Python closures.

The exact four-target migration reducer now closes its veto-only comparison.
Across Hello, Hello-derived registration, jq, and DX-Ball it found 449 unique
Lean semantic forms and 14,561 unique instruction encodings. Every form shared
by multiple targets had identical semantic text and status; the conservative
union contains 431 qualified, 15 disputed, three incomplete, and zero vetoed
forms, with zero parity blockers. This proves target-local result consistency,
not platform qualification: corpus-specific evidence hashes remain explicitly
noncanonical, and DX-Ball retains its 27 undecoded-region gaps.

The reducer and the ISA evidence projection now consume a strict compact
selection certificate instead of the occurrence-expanded selection authority.
For the four migration targets those inputs fell from 143,542,830 bytes to
562,716 bytes (255.1 times smaller) without changing projected ISA evidence.
The first cold parity build took 562.302 seconds because it deliberately rebuilt
the four legacy occurrence-expanded producers; the warm selection took 0.184
seconds. The producer-side cost and the 524-derivation evaluation fan-out remain
measured architecture debt and are removed only by the target-independent form
campaign and clean cut below. Milestone 3 therefore remains open.

Shared-campaign checkpoint (2026-08-27): the intrinsic migration seed now
contains one shortest checked representative for each of the same 449 forms.
All 449 representatives replay through the exact Lean decoder, then one shared
32-shard Lean/Bochs/Unicorn campaign qualifies the entire catalog. Its result
exactly matches the conservative four-target union: 431 qualified, 15 disputed,
three incomplete, zero vetoed, and structurally complete coverage for every
form. The current platform release has identity
`f0df8439074096f529ced1a8e5f3c739cac75183a4236b7f06cc15f37e62edda`,
contains 344,283 bytes, and carries explicit holes for the 15 disputed and
three incomplete oracle results rather than treating oracle agreement as
authority.

The shared worker emits the full 16,900,449-byte qualification transcript only
for diagnostics and, in the same checked pass, a 195,554-byte certificate with
identity `f82b27e0c959ebdfb10b8b2c450716ab56dbe7e57d27f4d4f80482f68116b8b7`.
The certificate binds classifier identity
`4e96ea3d814f9bc2b20068596fdcb88733cdcadbf41dfd3f07887c9a0f9eff2f`;
its content hash is
`567b94cda30b841777bc6bc3e51c25adfd6e876c43b438d449136959549ba56d`.
The release and independent replay consume that certificate, so normal platform
consumers do not parse or copy the occurrence-heavy transcript. The form
inventory is now independently content-addressed instead of entering through
the whole static-source tree, and all conformance shards share one checked
Python worker closure. The observed unchanged warm platform build is 0.091
seconds; the first shared cold construction was 243.426 seconds before the
compact certificate shortened the final reducer. A final clean-store cold
measurement remains required after the campaign code freezes.

Target-selection clean-cut checkpoint (2026-08-27): the strengthened
four-target reducer replayed the immutable final target-local campaign outputs
against the released platform and closed with receipt identity
`84d1df45004403989c35f5a393c14e8d39cfa96d57b59884d0c827b51777d07b`
and canonical content hash
`f9cdc037feab3f359396f92290121d7525cd59b99561ed6656e8b4b6ab058fdb`.
It compared all 449 semantic forms and 14,561 encodings, found exactly 431
qualified, 15 disputed, three incomplete, zero vetoed, and zero platform
inventory, semantic-text, status, profile, kernel, classifier, or exact-target
selection blockers.

Production target workflows now perform only exact Lean occurrence extraction
and select those occurrences from the one compact platform certificate. The
binary-specific catalog proposal, enrichment, corpus, 32 Lean shards, Bochs,
Unicorn, merge, selection-authority, and frontier Nix entrypoints are deleted;
the target SDK no longer exports migration campaign inputs. Repository and Nix
architecture gates require those entrypoints and exports to remain absent. A
target edit therefore cannot rebuild shared form qualification, while missing,
disputed, semantically mismatched, stale-classifier, and stale-PE selections
remain fail-closed.

Milestone 3 completion checkpoint (2026-08-27): the classifier-wide surface
review parses and accounts for all 95 constructors of the Lean
`InstructionSemanticForm`. The released allowlist contains 449 exact forms
across 85 supported constructors; ten constructors are explicitly unsupported,
and every unlisted form is rejected even when its constructor has other listed
forms. Constructor membership and test success never grant form authority. The
surface-review identity is
`c359881fd861b1734962ae4e5eec909de3f3adb5b9b09ad8b946c7fd8062e7ae`.

The platform now binds two closed IA-32 physical ABI profiles
(`pe32-i386-gnu-v1` and `pe32-i386-ms-v1`) and eight reviewed native primitive
providers covering code capabilities, guest atomics, ingress, object memory,
outcomes, SEH, TLS, and exact x87 replay. The provider catalog hashes declared
source resources without importing the runtime generator graph; its observed
Python closure is 106 files and approximately 2.1 MiB. Source review grants the
provider qualification. The native-ingress runtime/Wine check
`/nix/store/ld3231id5rcsih7sj13fxjgxrsxgyjxy-spaghetti-extractor-native-ingress-runtime-check`
and the full synthetic DLL/Wine check
`/nix/store/0y2qh4ar6p1fdrd2py7fsi10bck1vw24-spaghetti-extractor-native-module-check`
remain veto-only.

The resulting 366,553-byte `qualified-platform-v1` release is structurally
complete, target-independent, and authorizing, with identity
`c9ec765a1acb59f65af1a9fc4a50134e7518f5ed552e87cf022b3a95a11f6dad`.
Its 431 qualified forms are selectable. The 15 disputed and three incomplete
forms remain explicit per-entry blockers and cannot be selected; their two
summary hole rows describe unavailable oracle evidence, not missing platform
construction. The deterministic platform/replay check passes at
`/nix/store/gl9jcbwx1al2zkrcg38dick04qqiwyz7-spaghetti-extractor-qualified-platform-v1-check`.

The final production regressions pass on this direct selection path for the
Hello-derived registration fixture, real GNU Hello, jq, and DX-Ball at,
respectively,
`/nix/store/i3l86l1w6xmrjjy68k04xljdqhjz3bgq-spaghetti-extractor-target-corpus-boundary`,
`/nix/store/vlibmd6ah9dgwhr8n8h06jjnk2qh8p4h-spaghetti-extractor-gnu-hello-target-regression-checks`,
`/nix/store/aps07j17xk5q60yfhlkzxg6n2wkb71p5-spaghetti-extractor-jq-target-regression-checks`,
and
`/nix/store/4lywx47nal6wvl3xyp0r5bnldhng66qx-spaghetti-extractor-dxball-target-regression-checks`.
Milestone 3 is complete. Milestone 4 must fold the temporary occurrence
projection into semantic-object construction rather than introducing another
public per-target selection artifact.

Exit: adding a target normally performs only exact occurrence selection; one
platform catalog supplies all target-independent semantic and lowering
qualification without corpus-dependent authority.

### 4. Emit faithful relocatable semantic objects directly

- Make the machine frontend compile checked machine IR once into transfer-v2
  bodies and then package them with symbolic function/data definitions and
  relocations.
- Represent PE entrypoints, exports, imports, data anchors, TLS storage,
  callbacks, exception handlers, continuations, resources, and internal
  references as typed symbols and relocations bound to the independent module
  interface.
- Convert resolved semantic imports and generated runtime-support requirements
  into distinct declaration namespaces.
- Derive primitive lowering coverage by selecting the qualified platform; remove
  the separate fallback-capability analysis after parity.
- Preserve exact original RVA and occurrence identities for diagnostics while
  permitting relocatable semantic symbols and candidate code layout.
- Emit stable object packs and a compact module index in one content-addressed
  frontend result.

Exit: the extracted module is a relocatable semantic library whose only
function-body language is transfer-v2, and every evaluator, renderer,
component, and linker consumer reads that package.

Milestone 4 implementation checkpoint (2026-08-28): semantic-object
construction now performs exact qualified-platform occurrence selection as an
in-memory compiler operation. The constructor and the temporary legacy ISA
evidence projection call the same neutral selector; no public selection format,
Nix phase, mutable cache, or per-occurrence derivation was added. The object
binds canonical requirements, the complete target-independent platform,
qualification certificate, and exact occurrence selection as hashed package
members. Large occurrence rows remain package members while the main index
contains a compact content reference. Independent replay recomputes the
selection from the requirements and platform rather than trusting the stored
member. Hello, jq, and DX-Ball preserve their exact 21,109/11,606/24,615
occurrence inventories and their existing 10/10/37 unavailable-form blockers.

The relocatable index now separates three namespaces that the previous
workflow conflated: exact original loader IAT/delay-IAT slots, original
semantic function imports referenced by transfer-v2 call sites, and generated
runtime primitives required by transfer-v2 lowering. It projects typed direct
control, internal-call, external-call, indirect-call, and finite-control-target
relocations with stable source sites and code-capability views. Direct and
finite targets resolve only to exact transfer symbols; absent targets and
unresolved indirect calls remain typed holes for the root-aware semantic link.
PE data exports resolve through shared address-anchor symbols, and original TLS
template, zero-fill, index cell, and callback-array geometry are typed interior
anchors over their containing section objects. The independent replay checker
reconstructs every namespace, anchor, definition, relocation, count, and hole
from the strict transfer-plan and module-interface members.

Typed load-config projection is now part of that faithful frontend rather than
a later PE-realization concern. A real synthetic PE32 fixture exercises the
196-byte load-config revision with SafeSEH, CFG, long-jump, and EH-continuation
tables plus data and code pointer fields. The strict module-interface codec
checks the revision-derived pointer/table inventory, pointer kinds, target
locators, section identities, and realization policies. Semantic construction
then emits the load-config directory and nonempty tables as interior anchors,
and emits exact pointer, table-pointer, SafeSEH-handler, CFG-target,
nonlocal-continuation, and exception-continuation relocations. Null fields stay
explicitly resolved-null; missing transfer, object, or IAT identities remain
location-bearing link holes. Independent replay reconstructs these rows
without importing the production loader projector, and a corruption test proves
that changing an exception-capability role while preserving the outer
self-hash is rejected.

Original PE base relocations are now exact loader facts rather than deferred
composer input. The module interface records ordered blocks, padding slots,
PE32 relocation kinds, source RVAs, HIGHADJ adjustments, and preferred values;
its strict codec rejects stale counts, overlapping targets, malformed blocks,
and unsupported kinds. Semantic construction projects every non-padding entry
as an `image_base_relocation` from its containing function/data definition to
an exact function, data-object interior, or typed unresolved fragment. The
loader-mapped PE header bytes are also one read-only image-lifetime semantic
object, so legitimate references to DOS/NT/header fields resolve to their
actual mapped storage instead of becoming false holes. Independent replay
reconstructs the inventory and a focused PE32 fixture covers both a code target
and an interior header target. This is also the exact static internal-data-
reference inventory: a relocation slot is checked pointer evidence, while an
arbitrary integer constant is not. Dynamic and computed references remain word
expressions whose object/reference provenance is resolved once by the semantic
linker; no second constant-scanning pointer analysis will be introduced.

PE resources are now exact typed semantic storage rather than opaque composer
input. The module interface decodes a bounded resource tree with canonical
directory ordering, UTF-16LE names, numeric IDs, root-relative directory and
data-entry links, image-RVA payload links, exact payload bytes, code pages, and
mapped locators. Malformed, cyclic, duplicated, unreachable, executable, or
partially mapped forms fail closed. Semantic construction emits distinct
directory, name, data-entry, and content anchors plus typed root-relative and
image-RVA relocations; independent replay reconstructs all of them. The real
DX-Ball image exercises five directories, six entries, two payloads totalling
764 bytes, nine anchors, and eight locally resolved resource relocations. Hello
and jq honestly expose empty resource surfaces.

Checked exceptional-transition authority is also packaged directly into the
semantic object instead of being rediscovered by execution closure or ingress.
Every exact fault occurrence has a stable `exception_transition` declaration
bound to its authority manifest, native exception shape, guard, disposition,
state projection, and source transfer. Authorizing rows have definitions;
handled rows additionally emit typed handler, resumption, and ordered unwind
code-capability relocations, while missing authority remains an occurrence-
specific hole. The independent replay reloads the authority artifact and
reconstructs this projection without importing the production projector. Real
GNU Hello contributes three checked terminating divide transitions, jq one,
and DX-Ball 35; the focused projector fixture covers handler, continuation,
unwind, and non-authorizing paths.

The mandatory Hello-derived registration object is now an explicit GNU Hello
regression product rather than an unevaluated workflow attribute. Its gate
independently replays 621 transfer bodies, 109 qualified forms, all 1,523 exact
occurrences, 1,157 typed relocations (including 263 locally resolved base
relocations), three TLS anchors, the mapped-header object, and the registered
destructor definition at RVA 5184; it passes at
`/nix/store/9msgz049zfxviafplr5wcbsd5h8ppgk0-spaghetti-extractor-gnu-hello-derived-registration-semantic-object-check`.
The focused semantic-object Nix gate passes at
`/nix/store/s7022hwr03794zi89yz65d445g7arzmf-spaghetti-extractor-semantic-object-v1-check`.

At real scale, GNU Hello now has 7,937 transfer bodies, 7,951 definitions,
8,102 symbols, 12,334 typed relocations (including all 1,162 original base
relocations resolved locally), 21,109 exact ISA occurrences, and 113 honest
holes. Its index independently replays in 3.973 seconds at 433,328 KiB peak
RSS, within the unchanged 8-second/512-MiB generous veto, at
`/nix/store/i9nzy48dvx1a0vvs8m2r8qj7b31q7axz-spaghetti-extractor-gnu-hello-semantic-object-real-scale-check`.
jq now exposes 4,614 transfers, 4,626 definitions, 4,868 symbols, and 7,087
typed relocations, including 662 locally resolved base relocations, with 89
holes. DX-Ball exposes 9,008 transfers, 9,056 definitions, 9,243 symbols, and
12,327 typed relocations with 278 holes, including its resource tree,
pre-existing decode gaps, and 18 unresolved finite targets. Their
blocker meaning was preserved rather than converted into authority. The final
Hello, jq, and DX-Ball regression aggregates pass at, respectively,
`/nix/store/4p043ll1sg2qpqm4fvjd1y7cz8jvmk38-spaghetti-extractor-gnu-hello-target-regression-checks`,
`/nix/store/my81d29as7mnv2gw3s621mn77qxsph2n-spaghetti-extractor-jq-target-regression-checks`,
and
`/nix/store/agbjpank6hy447ics91hrlmvr7frbzvc-spaghetti-extractor-dxball-target-regression-checks`.

Milestone 4 is complete. One content-addressed semantic-object construction
invocation now packages the already checked transfer-v2, module-interface,
qualified-platform, loader, resource, base-relocation, and exceptional-
transition members with the relocatable index; no consumer recompiles machine
semantics or owns an alternate adapter. Relocations carry their exact required
code-capability or object-reference view, while concrete boundary and object
views remain milestone 5 link selections rather than being duplicated into
each relocatable object. The
combined three-target
regression still evaluated 696 legacy derivations after the semantic objects
were already built; that measured downstream authority/component/status fan-out
is migration debt for the semantic linker, not a reason to split semantic
objects into smaller public scheduling units.

### 5. Implement one semantic linker and total module closure

- Convert external profile/interface packs into semantic declaration libraries
  and compile `external-environment-intent-v1` into link selections and policy,
  not a second semantic model.
- Move checked boundary schemas, physical frames, object regions/interiors,
  imports, services, callback protocols, lifecycle, outcomes, exceptional
  transitions, code capabilities, and loader services into typed definitions,
  relocations, and effects.
- Extend the existing Rust fixed point to resolve the linked object graph and
  compute all root provenance, indirect targets, callbacks, continuations,
  reference states, lifecycle effects, and runtime requirements in one
  deterministic worklist.
- Discover registered callbacks and nonlocal/exception continuations in that
  same worklist; eliminate the primary-versus-derived workflow split.
- Retain the Python reference as a whole-linked-module parity oracle only.
- Compare exact reachable units/edges, target sets, external contracts,
  object/reference facts, lifecycle transitions, outcomes, witnesses,
  evidence dependencies, and blocker locations against the current resolved
  environment, object authority, and execution closure.
- Permit a result to be stricter, but never remove or weaken a blocker without
  new independently checked evidence.
- Flip authority for the synthetic module and Hello only after exact parity;
  then remove authority-graph scheduling, IFD pack routing, graph
  reinstantiation, derived-registration authority, and superseded independent
  closure/object/environment authorities from their production roots.

Exit: one linked-semantic-module artifact is the complete original-program
authority, and completion is equivalent to a fully resolved, qualified,
root-complete semantic link with no reachable holes.

Implementation checkpoint (2026-08-28): the first closed
`linked-semantic-module-v1` compiler and codec are now scheduled for every
target. One content-addressed invocation validates the semantic-object package,
runs the sole transfer-v2 closure kernel, resolves typed semantic symbols and
relocations, closes non-code reachability, attaches exact root provenance, and
emits both the linked module and a temporary byte-identical closure projection.
Valid but incomplete external environments produce valid incomplete modules;
their exact blockers are preserved under one link blocker rather than being
rejected, duplicated, or converted into authority. Unresolved import inventory
rows with no checked boundary are not misrepresented as external contracts.

The link now attributes every reachable function, external declaration,
runtime primitive, data/IAT/object symbol, effect, and object-authority rule to
one or more canonical roots. Runtime providers are selected from reachable
transfer bodies rather than the plan-wide inventory. A typed relocation fixed
point propagates data and IAT reachability and provenance without treating a
mere code address as executable reachability. The strict parser rejects
noncanonical provenance, stale counts, reachable rootless symbols or effects,
object/symbol disagreement, unresolved complete-module edges, and incomplete
implementation coverage.

An independent veto-only replay does not invoke the production linker. It
reconstructs exact input bindings, symbol resolutions, transfer witnesses,
runtime and external effects, indirect external targets, typed relocation
resolution, the complete relocation-driven provenance fixed point, object
authority and anchors, implementation requirements, and preserved blockers.
It rejects a structurally valid rehashed module whose provider selection or
relocation target was altered. Exact replay plus byte-identical closure parity
passes for GNU Hello, jq, and DX-Ball.

The native fixed point now also records exact per-root provenance for every
reachable control edge in the same evaluation that produces closure-v2. The
linked module maps those rows to stable semantic function symbols and rejects
missing, invented, duplicated, noncanonical, stale-identity, or disconnected
edges. Root-spawning `callback_escape` edges are modeled explicitly: their
provenance is the newly created target callback root, which must name that
target symbol, rather than falsely attributing the callback invocation to the
registering function's ordinary root set. The Python reference records the
same target-context roots, and the independent replay recomputes the complete
closure and exact edge-root rows for whole-result parity. A focused two-unit
fixture rejects both malformed root provenance and a structurally valid,
rehashed edge-kind substitution. The compatibility closure remains byte-
identical outside content bindings. After the resolved environment became a
content-bound semantic-object member, the Hello closure identity intentionally
advanced to
`eabf8d617c49c3aa619d3e6584315c51e789b3a61ff45561991184ef7855f2e8`.
Removing only `bindings` and `closure_sha256` from the pre-cut and post-cut
closures produces the same canonical SHA-256
`1223d7b76435e57ed32b5fa89a244c456464b7e7265abbac5b731fbcc4f747cb`;
blockers, witnesses, metrics, and exception continuations remain exact.

The same native invocation now performs the first non-control semantic-link
worklist as well. A bounded private projection transports only already
validated symbol declarations, definition kinds, checked external-contract
digests, qualified runtime-provider selections, typed relocation endpoints,
and direct provider/external source associations; it is neither persisted nor
scheduled as another format. After the transfer-v2 fixed point closes, Rust
resolves every semantic function, object, runtime, and external symbol,
resolves direct and finite-indirect relocation target sets, propagates
non-executable reachability and root provenance through typed relocations, and
emits exact symbol/relocation blockers. Production module construction now
uses those native facts. The former Python symbol and relocation fixed point
recomputes the whole result only as a same-derivation parity veto, and any
symbol, resolution, target set, reachability bit, root set, status, or blocker
disagreement fails closed. A negative fixture corrupts an otherwise valid
native fact row and requires rejection. An architecture gate requires the
same-pass native worklist in the production writer and forbids regression to
the closure-only call. GNU Hello, jq, and DX-Ball all preserve their exact
module identities, counts, closure identities, and honest blocker sets across
this authority flip.

Reference-state facts are now first-class output of that same native
invocation rather than a closure-only Python projection. The link carries one
canonical catalog of reference atoms, boundary/object bindings, memory keys,
memory ranges, and allocation identities plus compact index sets for every
reachable `(unit, root)` state. Its checked wire codec preserves the full
signed and unsigned endpoint range used by PE32-relative coordinates without
forcing the in-memory hot path to use large arbitrary-precision objects. The
Python evaluator recomputes the exact whole result only as a veto. Callback
registries snapshot incoming states before mutation, so widening cannot alias
and retroactively change a queued predecessor.

Variable-stack objects use one conservative identity per captured-frame owner
and allocation site. The former identity recursively embedded the incoming
reference and offset history; real jq therefore accumulated worklist-order-
dependent identities tens of kilobytes long. Allocation-site abstraction may
merge repeated dynamic allocations and therefore conservatively adds aliasing,
but cannot remove a possible alias. It makes the fixed point confluent across
the Python and Rust schedules and gives exact jq parity at 280 states and 792
worklist steps. Applying the same transfer twice is idempotent in both kernels,
and the independent jq replay passes at
`/nix/store/1nmzpdrwzfws4alxdb0vvfwzd5wnk6il-spaghetti-extractor-jq-linked-semantic-module-independent-replay`.

Machine object authority is now derived inside semantic-object construction
from the already bound module interface and emitted as an exact content-bound
package member. Its authority identity, canonical content digest, evidence row,
and module-interface binding are checked independently. Production semantic
linking, the compatibility closure, and downstream compatibility consumers all
open that member; no separate production object-authority derivation feeds the
module graph. The architecture gate prevents that ownership split from
returning. A code-only PE may correctly have an empty static image-object
registry, while runtime-created captured-stack and external objects remain
governed by their typed dynamic rules.

The implementation and format ownership now match that package ownership.
`machine-object-authority-v2` and the checked object-relative reference model
live under `semantic_objects`; the component subsystem consumes them and only
retains component capability lifecycle/rendering. All semantic-link, transfer,
candidate, component, fixture, and test imports were migrated in one clean cut,
and the old `components/object_authority.py` path is absent. This removes the
semantic-object package's backward dependency on components and makes the
repository boundary that forbids component imports from semantic objects pass.
The now-unused standalone `pe32-machine-object-authority.nix` constructor and
public SDK leaf are also removed: object authority has exactly one production
construction path, as a content-bound semantic-object member.
The clean cut passes 167 focused semantic-object, semantic-link, component,
runtime, ingress, format, SDK, and operator tests. The semantic-object, SDK,
format-registry, repository-metadata, and architecture gates pass at
`/nix/store/39k1nyr3x3qjbdxy6mk89hggli3rpv29-spaghetti-extractor-semantic-object-v1-check`,
`/nix/store/5n5rnachsndrwyiid5q05cz3c93pq2fy-spaghetti-extractor-target-sdk-check`,
`/nix/store/sr8z69hxivhxwnj0hq00wbywv1dyd334-spaghetti-extractor-format-registry-check`,
`/nix/store/rgdxa8s3sxldj1clnsqpbn7w09ni01jb-spaghetti-extractor-repository-metadata-freshness`,
and
`/nix/store/1bhln7va03lndb80d9g21758vwdsn0ky-spaghetti-extractor-retired-architecture-boundary`.
Real project status still reports the exact honest inventories: Hello 74, jq
73, and DX-Ball 37 blockers.

The current real outputs remain honestly incomplete. GNU Hello module identity
`b04452dba34d43d180ee168548b6da9c9c36f0ac93a4c04bf9ee894c041a3194`
contains 8,102 symbols, 6,052 reachable semantic edges, 12,334 relocations,
4,632 reachable symbols, 4,495 reachable transfer units, six roots, 92
remaining holes, 6,057 reference facts, and 74 blockers. jq identity
`23fc75f25391a00dd12b5ccd77db57b51ba463da93268c19f73087b64942a893`
contains 4,868 symbols, 284 semantic edges, 7,087 relocations, 390 reachable
symbols, 237 reachable units, five roots, 79 holes, 262 reference facts, and 73
blockers, including every exact external-environment blocker. DX-Ball identity
`b60d7b37aa49bb34a86fb2d6838efc7d715b1b2ee1d034151d1de92a8db55856`
contains 9,243 symbols, 965 semantic edges, 12,327 relocations, 811 reachable
symbols, 760 reachable units, one root, 271 holes, 760 reference facts, and 37
blockers. Every
reachable symbol, edge, effect, and represented object in all three outputs
has nonempty exact root provenance; no target blocker was erased to make this
true.

The first full Hello semantic-link benchmark exposed redundant simultaneous
Python representations: 23,846 ms CPU and 1,246,760 KiB peak RSS. The unified
compiler now loads and validates the semantic object once and passes its
already-bound provider inventory to the native closure kernel instead of
parsing the 38.5-MiB transfer plan two additional times. With the unchanged
30,000-ms/1-GiB budgets, packaging reference and object facts initially
measured 27,425 ms CPU and 1,046,024 KiB peak RSS, leaving only 2,552 KiB of
headroom. After deriving the checked context, the native worklist reads the
exact transfer member itself; retaining the already decoded 38.5-MiB source
payload beside the typed transfers was therefore a duplicate lifetime. The
linker now releases that projection before entering Rust. Exact module bytes
remain unchanged, while the current combined-regression Hello samples measure
a worst 26,027 ms CPU, 26,388 ms wall, and 1,002,896 KiB peak RSS. jq measures
5,842 ms CPU, 5,919 ms wall, and 345,820 KiB; DX-Ball measures 10,424 ms CPU,
10,443 ms wall, and 722,404 KiB. These are standard target veto gates, not
authority evidence.
The independent Python whole-result replay is deliberately slower and remains
a separate veto derivation; it is not on the production semantic-link path and
cannot grant authority.

The transitional content-addressed closure projection initially isolated
semantic-module-only invalidation while consumers migrated. That projection is
now retired. The semantic linker consumes the native fixed-point receipt in
memory, retains its status, identity, and blockers with the linked symbol and
effect tables, and removes the construction-local JSON before publishing the
package. Independent replay reruns the fixed point from the packaged transfer
member and checked roots, cross-checks it with the Python evaluator, and
compares it directly with linked tables. The performance veto compares the
complete linked module bytes. Neither check accepts or publishes a compatibility
closure artifact, and architecture gates prevent that surface from returning.

The strengthened focused gate passes at
`/nix/store/k485x200pkvmkvpgbxfw83answrazxj9-spaghetti-extractor-linked-semantic-module-v1-check`.
The complete target regression aggregates, including production link,
byte-parity, exact independent replay, and performance vetoes, pass at
`/nix/store/5d6dp90giyw6mzln85af87labp4kq4w1-spaghetti-extractor-gnu-hello-target-regression-checks`,
`/nix/store/q91vqmcf4zqcx6bz7a106y84bbmj47ff-spaghetti-extractor-jq-target-regression-checks`,
and
`/nix/store/18mw1dx2bvy6jhrgk8j9zpb90kb253if-spaghetti-extractor-dxball-target-regression-checks`.
The refreshed repository-metadata, format-registry, and architecture gates
also pass; the latter is
`/nix/store/l3xj1cswq46gvg85gq01mw8y158rjd6s-spaghetti-extractor-retired-architecture-boundary`.

Project status has now flipped from the legacy
`authority-diagnostics-v3` reducer to the linked semantic module. The old
`project-status-v2` format and its authority/frontier adapter are absent from
production roots. `project status` is a one-subject, non-authorizing
`operator-work-status-v1` projection whose only semantic phase input is the
materialized `linked-semantic-module.json`; the subject's authority bit reports
the underlying semantic link, while the view itself always has no authority.
The previously boundary-owned work-status format is now domain-neutral and is
shared by boundary and module views rather than duplicated. Project status uses
the common content-addressed Python phase constructor and one shared Python
source closure across targets. The constructor now accepts an already checked
source closure so repeated homogeneous phases do not create target-local copies
of identical interpreter source.

The real views preserve the exact module identities and honest blocker counts:
GNU Hello emits 74 blockers at
`/nix/store/3zqdpibz7sb8ssbzfngc58b05d8l6svx-spaghetti-extractor-gnu-hello-semantic-module-work-status-v1`,
jq emits 73 at
`/nix/store/lkc2s55kmb1gljbjkpr80qnpj26pxp1g-spaghetti-extractor-jq-semantic-module-work-status-v1`,
and DX-Ball emits 37 at
`/nix/store/58nsd2a63dsw1qvpqn3r69hh9f3bvcrk-spaghetti-extractor-dxball-semantic-module-work-status-v1`.
The jq phase manifest contains exactly one declared semantic input, the
6,182,005-byte linked module, and no authority, component, candidate, or test
receipt. A direct strict Hello projection measures 935 ms elapsed and 149,656
KiB peak RSS. The project-status SDK, boundary-workbench, build-infrastructure,
format-registry, repository-metadata, and architecture gates pass; the current
SDK and architecture outputs are
`/nix/store/7y2slssy4brwc7zr01px9m2zd73mnqbf-spaghetti-extractor-target-sdk-check`
and
`/nix/store/gnzfvk3y4ix173l9aln7i3ln3m4sfamj-spaghetti-extractor-retired-architecture-boundary`.

The separate `runtime-frontier-report-v1` projection had no semantic or public
command consumer; it only filtered the same legacy authority diagnostics that
project status previously adapted. Its Python codec, Nix phase, SDK constructor,
workflow product, bundle artifact, fixture, and tests are retired rather than
ported. Semantic runtime requirements and their blockers are already explicit
linked-module effects and blockers. Configuration-specific runtime readiness
will be reported from provider selection and native realization, where it can
be checked against the chosen implementation. An architecture absence check
prevents the redundant report from returning. This retirement preserves the
three module blocker inventories above and removes one system without adding a
replacement format or cache.

The same clean-cut audit found `authority-diagnostics-v3` to be an orphaned
cross-phase reducer after project status moved to the semantic module. No
production gate, candidate, component, or operator command consumed it: the
authority workflow built it solely for the SDK to re-export. Its Python codec,
Nix phase, SDK fixture and artifact field, and unit tests are therefore retired.
Its wire literal remains declared only as a retired domain-owned format, so the
format registry rejects any production reader. The transitional final-authority
graph and gate remain intact for semantic-link parity; only their redundant
diagnostic projection has been removed. Architecture checks require both old
implementation files to remain absent and prohibit recreating the workflow
attribute.

This consumer flip does not yet solve upstream evaluation fan-out. A combined
three-target status evaluation still planned 390 transitional derivations
before content-addressed semantic outputs coalesced and only the three new
status leaves executed. That is direct evidence that the legacy authority DAG
and target-local qualified-platform scheduling must be removed from semantic
object construction; adding another status cache would hide rather than solve
the remaining architectural problem.

The resolved external environment has now crossed the same ownership boundary
as object authority. Its bounded closed codec lives in `external/resolved.py`,
separate from the intent compiler in `external/environment.py`, and the exact
resolved payload is a content-bound semantic-object member with independently
checked identity, content digest, evidence, and module/profile/intent bindings.
Every checked external-function symbol projects the selected logical boundary
schema, `PhysicalCallFrameV3`, and environment-contract digest. The production
semantic linker, independent replay, compatibility closure, and performance
veto open only that member; none accepts an independently scheduled resolved-
environment input. Architecture gates enforce that input cut and prohibit a
second resolved-environment reader inside semantic linking.

External contracts have now crossed the declaration boundary as well. Every
checked original loader slot and external semantic function declaration carries
the exact selected environment-contract digest, the optional exact
loader-service-contract digest, and a `machine_import` or `loader_service`
role. The production linker consumes those declaration fields directly; it no
longer rebuilds an identity-to-contract join from the resolved environment.
The same native invocation receives a compact, total declaration catalog
derived independently from the content-bound environment member and rejects
any missing, invented, or contradictory declaration digest before computing
link authority. Executable external-call rules retain their exact declaration
lineage, but remain a narrower adapter catalog: a statically checked contract
whose effects cannot yet be lowered is preserved as an honest execution
blocker, not rejected as a malformed declaration. Loader-service identity is
now selected only by explicit checked profile metadata, never inferred from a
familiar API name such as `LoadLibraryA`.

Definition evidence has crossed that boundary too. The semantic object owns
one canonical, content-bound evidence catalog and every semantic definition
carries a sorted list of indices into that catalog. Transfer definitions bind
the exact transfer plan, their exact qualified-platform inputs when they use a
qualified ISA occurrence, and exceptional-transition authority when relevant;
object and loader-surface definitions bind the exact module interface and
machine-object authority. The linker preserves those same indices on every
reachable implementation requirement. Strict construction, the optimized
same-pass link view, and independent replay derive the dependencies separately
and reject missing, invented, reordered, out-of-range, or stale dependencies.
The representation adds only compact integer indices, not copied receipts or a
second evidence graph.

Object view and generation interpretation now closes in the same linked table.
Each linked object derives one generation policy from the already-authoritative
locator, generation seed, and lifetime: image, thread, invocation, provider-
anchor, allocation, or resource epoch. Optional typed data-export views are
canonical projections of the existing authority anchors, not a new authored
catalog. The public codec checks every authority-rule field, anchor, typed
view, generation policy, semantic-symbol binding, reachability bit, and root
set; independent replay reconstructs the policies and views from the bound
machine-object authority. This is semantic-link closure only. Native
realization must still prove that its object resolver implements each selected
generation mode before deployment can authorize execution.

The current real semantic-module identities after that clean cut are
`83fb7e93e15ade770d56d1b862fdebdee755463530ceba8dfb313d1c2f55deb5`
for GNU Hello,
`47bae64bef8bb3429f3eea21b2157ea2022576f17f5e7fb1136f4a34e1ff98a7`
for jq, and
`05eefdaf5fc9fedb42499ae95c893768776fa77c6755f5ebe400d76dce7b3918`
for DX-Ball. Their structural counts and blocker inventories remain 8,102
symbols/4,632 reachable/74 blockers, 4,868/390/73, and 9,243/811/36
respectively. Hello's 71 external-function symbols all carry checked logical
schemas and physical frames; jq carries them for 57 of 117 and DX-Ball for 82
of 86. Missing rows remain explicit environment blockers rather than inferred
authority. Exact independent replay, closure parity, and performance vetoes
pass for all three targets. Project status remains incomplete with 74/73
blockers for Hello and jq; DX-Ball now has 36 because the former name-inferred
`LoadLibraryA` loader-service blocker was invalid metadata, not missing
authority.

The environment member changes only content bindings in the Hello compatibility
closure. Its new identity is
`eabf8d617c49c3aa619d3e6584315c51e789b3a61ff45561991184ef7855f2e8`;
deleting `bindings` and `closure_sha256` from the pre-cut and post-cut payloads
gives the identical canonical digest
`1223d7b76435e57ed32b5fa89a244c456464b7e7265abbac5b731fbcc4f747cb`.
Blockers, witnesses, metrics, and exception continuations are byte-identical.

The performance veto now compares generated module and closure files directly
with exact bytewise file comparison instead of retaining two additional
canonical byte buffers. The current-source GNU Hello gate passes at
`/nix/store/0dn5nlsy7qzkndlgy050ac4xl7bxl4v0-spaghetti-extractor-gnu-hello-linked-semantic-module-performance-check`:
the worst of three isolated samples is 23,046 ms CPU, 23,351 ms wall, and
753,620 KiB peak RSS under the 30-second speed-first CPU guard. This remains a
real reduction without a cache or weaker comparison. Observed link memory is
below 1 GiB, while CPU and repeated scheduling dominate; the RSS figure is now
retained as diagnostic history rather than a release threshold. A
focused request for that gate still found 264 missing transitional derivations;
the recent three-target replay/parity/performance request scheduled 339
derivations and the full post-evidence-dependency regression evaluation
scheduled 706. After adding only the linked-object view/generation projection,
the Hello target still scheduled 534 derivations and the jq/DX-Ball pair 256.
Those results reinforce the architectural cut: absorb the
remaining fact families into semantic-object construction and the one link
worklist, then retire their legacy scheduling.

Milestone 5 remains open. Control edges, symbol and relocation resolution,
reachability, root provenance, reference states, lifecycle/effect provenance,
object-rule bindings, and per-definition runtime-provider requirements now
close in one native invocation. Object authority and the resolved environment
are content-bound semantic-object members, and production linking no longer
fully decodes transfer-v2 in both Python and Rust. External profile and
interface selections are now exact semantic declarations rather than a second
link-time semantic join. Every definition and reachable implementation
requirement now names its exact evidence dependencies through the semantic
object's canonical evidence catalog. Object views and generation policies now
close exactly in the linked semantic table, while native realization of those
policies remains fail-closed. Exceptional transitions now enter the same
closure through a typed function-to-transition activation relocation. A
reachable checked transition therefore receives exact root provenance and an
implementation requirement with its transfer/resolved-environment evidence;
an unresolved activated transition is a link blocker. The current real-Hello
link has one root-reachable transition (of three), selects a `native_realizer`
provider for it, preserves 74 honest blockers, and has semantic-module identity
`2beca1e3359c8ff5cca5b431801cf29945fa1bbad86b04d9c8370736c7a37c72`.
Native realization of that selected exception contract remains open. Authority
has now flipped at the closure seam for the Hello-derived registration vertical
and every SDK target. `semantic-object-v1` is a structurally complete
`checked_relocatable` with `authority = false`; its holes are link inputs rather
than a reason for the object package itself to masquerade as incomplete. Only
`linked-semantic-module-v1` may authorize reachable roots. The target SDK no
longer instantiates an independent execution-closure parity derivation, the
Hello-derived fixture reads the closure emitted by semantic linking, and an
architecture gate prevents either scheduling path from returning. Exact
independent semantic-object and semantic-link replay remain vetoes.

The flipped real-Hello semantic object has identity
`f27fbaf9bf1e88b948d93b409b249cb7b78e1ba3cfa5d48b48a2512546172ffc`;
its linked module retains 8,102 symbols, 4,633 reachable definitions, and 74
honest blockers. The derived-registration linked closure is complete and
authorizes its 266 reachable units with zero blockers. Removing the target
parity rerun reduced a cold changed-tree Hello regression request only from 534
to 531 scheduled derivations. That small but genuine clean cut confirms that
the dominant cost is still the legacy authority/component graph needed to
construct the semantic object, not closure recomputation. Milestone 5 remains
open until native realization implements the selected object-generation and
exception contracts and the remaining legacy fact families leave production
roots. The final post-fix Hello aggregate passes under the expanded speed-first
guard; its current three-sample semantic-link veto records 20,523 ms worst CPU,
20,600 ms worst wall, and 753,480 KiB peak RSS, with a declared maximum of
67,108,864 KiB.

Direct exception/callback cut checkpoint (2026-08-28): transfer-v2 now owns a
canonical digest for every fault occurrence. Generic process-root exception
semantics are compiled once from those occurrences plus the content-bound
resolved launch policy and stored as a compact checked semantic-object
relation. Semantic linking and execution closure reuse that resident relation;
they neither reopen `exceptional-transitions-v5` nor reparse transfer-v2 for
exception discovery. Target SDK semantic-object construction has no direct
exception-authority edge.

Callback transport follows the same rule. The selected runtime profile
provides the canonical provider callback protocol, while transfer-v2 proves the
exact non-sentinel registration occurrence and callback word. The normal SDK
derives checked physical-frame evidence directly from those already-required
inputs; target callback declarations no longer schedule `callback-authority-v4`
or its parametric fixed-point prerequisites. Root reachability, callback target
ownership, escape lifetime, and capability selection remain one-pass
linked-semantic-module obligations. On the real GNU Hello semantic-object gate,
the cold missing-derivation inventory fell from 219 to 88 while preserving the
same 7,937 transfers, 8,102 symbols, 12,337 relocations, three terminal divide
transitions, and complete checked callback protocol. This is a graph cut, not a
cache: unknown or sentinel-only registrations produce the stable
`exact_callback_binding_unresolved` blocker. Architecture checks forbid either
authority-v3 side edge from returning to target semantic construction.

The same clean cut passes the full jq and DX-Ball regression aggregates. Their
current linked identities are
`5aa8fc368d1e7261945770c66dec1350183d494300689e772f7fba8ca6f65ddd`
and `de9ee940b8173662f13e2567c95898025aef7a1eb1a075b908740f47d6fe5d35`;
their blocker inventories remain exactly 73 and 36. The exception-activation
guard deliberately applies only to a newly reachable unresolved semantic
definition. Loader/IAT symbols remain governed by the external-contract and
loader-storage policies, so typed reachability does not duplicate them as
generic unresolved symbols. A jq regression caught and rejected that accidental
double classification during the cut. Focused Python and native-kernel tests
now pin both sides of the distinction. Current jq and DX-Ball semantic-link
vetoes respectively measure 2,304/2,316 ms worst CPU/wall at 266,420 KiB RSS
and 6,459/6,471 ms at 549,720 KiB RSS.

The synthetic PE32 DLL vertical now constructs a strict, content-bound resolved
environment before its checked semantic object. Checked handled, unwind, and
resumption protocols are closed fields of that environment; transfer-v2 owns
the executable fault occurrence, guard, native exception shape, and target
identity. The semantic object joins those two resident inputs directly, so no
exception-authority artifact or migration member exists. The environment binds
the module interface's embedded canonical identity, target ABI/layout, fixture
intent and runtime profiles; machine calls use the same public canonical
boundary lowerer as normal environment resolution. The still-migrating ingress
contract separately retains the exact module-interface file hash that its codec
requires. Its
semantic object is a complete checked relocatable with identity
`51ecae6a1acea1965eb686f32f4f85caa9cd2bc98a9d252fa8e4c32fbe608494`,
71 symbols, 40 definitions, 257 relocations, and five evidence entries. The
linked module has identity
`33403889b84ba45724fbcda81c59df5e4bb83702df82cf82e551d1a457ba3a4a`;
it preserves seventeen distinct executable roots, including two export aliases
at one RVA and one callback root derived from the checked callback-registration
boundary, while the writable data export remains an object anchor rather than
an executable root. Its checked exception transitions close all prior
exception blockers and make 22 units, 34 symbols, nine edges, and 31 compact
reference facts reachable. A real, otherwise unused original `ExitProcess`
anchor now gives the loader and the retiring runtime planner one exact IAT slot;
it is not a fabricated semantic import. The module remains honestly incomplete
on four linked facts: the shared qualified-platform selection and its three
runtime-provider selections. The legacy fixture's symbolic one-byte transfer
spans cannot be presented as real ISA qualification; the real decompilation
vertical must replace them before this module can authorize execution. The full
native-module DLL/Wine gate and
independent PE32 project gate pass at
`/nix/store/pvs0kp743pbfn7byzrcbmxdp1b2rdbix-spaghetti-extractor-native-module-check`
and
`/nix/store/zykhc5vm2hswyfv1ajg00756l5skkbq0-spaghetti-extractor-pe32-project-check`.
This validates the semantic-object boundary inside the generous native vertical
without claiming that the legacy build/link/deployment consumers have already
been replaced by `native-realization-v1`.

Environment-owned exception clean-cut checkpoint (2026-08-29):
`resolved-external-environment-v1` now owns the exact checked exception
protocol catalog, including occurrence, handler, resumption, unwind targets,
and state projection. The direct exception compiler validates that catalog
against transfer-v2 and produces the sole compact transition relation. The
semantic-object package, independent replay, execution-closure API, synthetic
native fixture, and Nix constructors no longer accept or package an
`exceptional-transitions-v5` side artifact. Architecture checks reject its
return to semantic construction. Focused environment, transfer, semantic
object, semantic-link, and native-realization suites pass; the complete
synthetic PE32 DLL/Wine vertical and the complete real GNU Hello target
aggregate pass after the clean cut. Hello's current aggregate still schedules
328 nominal derivations in its transitional component/authority tail. That is
now the measured next removal target: preserve large resident semantic indexes
and collapse the duplicated authority-v3 and target-local ISA producers rather
than caching or memory-throttling their graph.

Direct internal-call premise checkpoint (2026-08-29): V5 component refinement
no longer accepts `call-boundary-contracts-v3`. For component-operation
services it resolves the target from the total component graph, verifies the
target unit in the one transfer-derived proof view, and instantiates the
existing canonical PE32 normal-return ABI premise in memory. The receipt binds
that premise's content hash and the exact target-unit projection. An
architecture gate forbids the authority-v3 side input from returning. Focused
component tests and the full GNU Hello aggregate pass. Dependency tracing now
shows one remaining authority-v3 entrance into component production:
`canonical-external-sites-v3`; its transitive path is the reason the nominal
aggregate still contains the call-boundary, parametric, target-certificate,
and sharded machine-IR graph. The next clean cut must derive those four Hello
external-call service bindings from transfer-v2 plus the resolved environment,
then delete that last entrance rather than retaining the old site IDs as a
second semantic namespace.

Direct external-call checkpoint (2026-08-29): component binding intent now
selects an external service by exact transfer unit, event index, and physical
import identity. Semantic refinement and portable-C overlay construction
validate that selector against the transfer proof view and one strictly parsed
`resolved-external-environment-v1`, building the call frame and result relation
in the same resident process. The four Hello bindings for `strrchr`, `memcmp`,
`Sleep`, and `SetUnhandledExceptionFilter` no longer carry external-site IDs.
The component workflow no longer constructs an external-site slice or admits
the canonical external-site authority artifact, and an architecture gate
prevents that side edge from returning. Focused component tests and the full
GNU Hello aggregate pass. The aggregate fell from 328 to 216 scheduled
derivations, a 112-derivation (34 percent) reduction achieved by deleting a
semantic pipeline rather than adding a mutable cache. The remaining
authority-v3 dependency is isolated to the legacy library-recognition and
adoption path; migrate that path to linked semantic definitions before
retiring the old external-site codec and producer globally.

Library-crossing checkpoint (2026-08-29): checked library-island activation no
longer accepts canonical external-site or indirect-target-certificate
artifacts. It validates each exact external transfer against the strictly
parsed resolved environment and each indirect island exit against the checked
finite-control route inventory already embedded in transfer-v2. Checked finite
routes outside the island establish inbound edges; an outside indirect
transfer without such a route is now an explicit incomplete blocker rather
than an assumed non-edge. Receipts bind the resolved-environment identity and
finite-route inventory hash. Focused library activation and linked-library Nix
tests pass, and an architecture gate prevents the two authority-v3 crossing
inputs from returning. At this checkpoint the separate target-ABI evidence
extractor still read parametric-summary and canonical-external-site artifacts;
the following clean cut removes it and those codecs.

Library-ABI clean-cut checkpoint (2026-08-29): library production no longer
constructs target ABI evidence by independently joining authority-v3
parametric summaries and canonical external sites. Checked island activation
no longer treats a catalog-declared ABI as evidence for the target machine
operation. Every attempted adoption therefore reports
`target_operation_physical_abi_unresolved` until the selected definition's
physical ABI qualification is supplied by `linked-semantic-module-v1` itself.
This deliberately preserves an honest blocker because there are no current
in-tree adoption intents; it removes the final library-specific authority-v3
semantic path without manufacturing authority or adding a replacement ABI
artifact. The public null placeholders and optional Nix/Python inputs are now
gone as well. The target ABI extractor, matcher, compatibility and legacy
adapters, canonical-external-site and parametric-summary record families, and
their tests are physically removed. Declaration ingestion remains an
operator-only catalog path and cannot accept extracted target facts. The old
match-resolution format is domain-owned and retired, and architecture gates
prevent the deleted pipeline from returning.

Target-authority instantiation checkpoint (2026-08-29): the SDK no longer
instantiates `authority-workflow.nix` for each PE32 target. Candidate release
acceptance no longer imports or scopes `isa-qualification-v3`; it strictly
parses the exact `linked-semantic-module-v1`, requires the module's newly bound
`module_execution_closure_sha256` to equal the structural receipt's closure,
and reduces the linked module's checked authority state directly. Platform ISA
qualification and target occurrence selection were already bound into the
semantic object and linked holes, so this deletes a second release-policy
projection without weakening coverage. Intrinsic provider construction now
receives the selected qualified platform unconditionally from the same
semantic-object path rather than depending on whether the old authority graph
happened to emit generated ISA evidence. An architecture gate rejects any
return of target authority-workflow instantiation, authority-graph release
inputs, or target-local ISA artifact readers. The SDK also no longer exposes
the generic `analysis.authority` constructor; an architecture gate prevents
that public surface from returning. The old target-local exact-unit,
semantic-index, and ISA-qualification implementation files and their developer
tests have now also been removed. The synthetic native-module fixture had been
emitting an empty-instruction ISA artifact that no consumer read; deleting
that inert artifact preserves the same fixture semantics while removing the
last production reachability edge. Focused policy/link/SDK tests,
the architecture and metadata gates, and the full GNU Hello aggregate pass;
Hello schedules 216 derivations after the public-constructor cut.

Authority-workflow source checkpoint (2026-08-29): after proving there were no
remaining target or SDK consumers, the repository physically removes
`authority-workflow.nix`, its target graph-manifest and final-gate builders,
and all thirteen exclusive callback, exception, external-site, indexed-target,
ISA, normal-call, parametric-summary, standard-evidence, and implementation-
capability Nix input wrappers. Absence gates replace architecture checks that
previously inspected those files. Canonical semantic ISA requirements remain
the single target occurrence selection feeding `semantic-object-v1`; tests now
exercise that phase directly. The generic artifact-v3 Nix scheduler,
source-plan, dynamic machine-IR reinterning path, and their developer-only
fixtures are now retired too: no target consumed them, while linked-semantic-
module invalidation tests already cover the active cache boundary. The Python
artifact-set codec remains a storage implementation where active formats use
it, not a public semantic pipeline. Focused SDK, ISA, policy, link, library,
and component tests pass (82 tests).

Authority-input namespace checkpoint (2026-08-29): the remaining
`authority_inputs/` package contained no authority producer. Its exact binding,
finite-value, launch, and indirect-replay implementations now live directly in
`reconstruction/`; control-disposition and PE32 stack-ABI helpers live in
`external/`; exact ISA requirements and target selection live in
`qualified_platform/`. All production, Nix, benchmark, and unit consumers were
migrated in the same cut, the old package is physically absent, and no adapter
or compatibility import remains. A focused 142-test cross-domain suite passes
with an empty production-unreachable module set.

Authority-package completion checkpoint (2026-08-29): the last Python
`authority/` leaf built catalog-call contracts from a second target/library ABI
matching path, but no checker or adoption phase consumed its output. The phase,
SDK artifact exposure, Nix inputs, codec, tests, and package are now removed;
the old contract-set format is registered as retired in the ABI domain.
Physical ABI catalogs remain proposal/declaration inputs, while target ABI
authority must be supplied by linked semantic definitions. The repository now
has no standalone Python authority package.

### 6. Convert components and libraries to semantic providers

- Generate V5 work packages as views over linked semantic symbols, objects,
  services, lifecycles, outcomes, and exact faithful-C source slices.
- Represent each authored portable-C component as source v3 plus one
  `semantic-provider-qualification-v1` binding exact compiled symbols to the
  semantic definitions it refines.
- Reduce compile, source, machine/semantic binding, CBMC refinement, lifecycle,
  services, relations, induction, ownership, and exact object hashes in that
  qualification.
- Make dependencies ordinary unresolved semantic symbols and make
  `implementation-selection-v1` a total, exclusive selection of generated C,
  portable C, pinned binary, or checked external provider for every reachable
  definition.
- Prohibit runtime activation and silent fallback. Portable mode requires zero
  root-reachable generated-C selection; hybrid mode requires explicit generated
  ownership for every remaining definition.
- Migrate all qualified Hello components, DX-Ball `directdraw-init`, jq's
  structural packages, and library behavior packs through the same provider
  mechanism without inventing missing authority.
- Remove the overlapping component contract, binding, implementation reducer,
  dependency graph, activation plan, adapter, and library-specific provider
  families after all consumers migrate.

Exit: components and behavior packs are ordinary qualified implementation
providers for semantic symbols, and changing authored C cannot invalidate the
original linked semantic module.

Milestone 6 implementation checkpoint (2026-08-28): the repository now owns
closed codecs for `semantic-provider-qualification-v1` and
`implementation-selection-v1`. A qualification binds one exact linked module,
provider artifact, proof-facet receipts, semantic definitions, native symbols,
source hashes, object hashes, and per-definition evidence dependencies. Missing
or unfinished refinement, lifecycle, service, relation, induction, source, or
native-object evidence is a canonical incomplete blocker rather than a schema
error; only a complete qualification is selectable. Selection is an explicit,
total semantic-symbol-to-provider map. Hybrid mode never chooses generated C
implicitly, portable mode rejects every selected generated-C definition, and
an incomplete linked module always keeps realization closed.

Selection derivations depend only on qualifications named by the choices. An
unselected provider qualification is not an input and changing it does not
change the selection artifact or schedule downstream work. This is the
speed-first invalidation boundary: independent authored components can compile
and qualify in parallel, while selecting one does not pull every alternative
provider into the realization closure. The transfer package initializer also
became lazy, so ordinary semantic linking no longer imports the host-only
diagnostic evaluator into operator or authority phase closures.

The synthetic PE32 DLL vertical projects its real compiled portable object into
an incomplete provider qualification with identity
`dcd0c253a3ee9210ba93099d6e5b7351d5156cb3fe965d5b7df897ee4f520e0f`.
All seventeen owned definitions have exact source, object, native-symbol, and
linked-evidence bindings. The old fixture does not contain independent
refinement, lifecycle, service, relation, or induction receipts, so those five
facets remain explicit blockers. Its partial selection has identity
`3708989439d6ea1bef466738086dc80c47fe8321484292055e1d3b329d132a04` and
is correctly incomplete on those facets, seventeen still-unselected semantic
requirements, and the linked module's platform/runtime authority. Building
this projection exposed and fixed a prior discrepancy: the legacy closure
manually reached the escaped callback, while the canonical environment profile
omitted callback action/delivery facts. The one-pass semantic linker now derives
the callback root and effect directly from the checked boundary. The complete
native link/composition/Wine/deployment/observation migration gate still passes
without treating that legacy path as semantic authorization.

The same vertical now has a complete generated-Behavioral-C provider
qualification with identity
`f88f80310daea25e9357dc63671ee102bd7ba7e401331cff1bfa887e18f3db62`.
It compiles only the twenty-one immutable per-function translation units into
deterministic PE32 objects and excludes the old dispatch/runtime/support units,
which belong to native realization. Those objects cover all twenty-two linked
transfer definitions; the one shared native function is accepted only because
both semantic definitions bind identical source and object proofs. Independent
functions compile concurrently under the speed-first policy. The associated
explicit selection has identity
`1a40cc94d183b8a220b524186b6ad3c1a1256a8268c9556d771f20b981b7b69c`:
all twenty-two generated definitions are selected, and its only remaining
rows are twelve missing non-transfer providers plus the honestly incomplete
linked module. Rebuilding after concurrent compilation reproduced the exact
content-addressed provider output. Focused qualification/selection tests,
format and repository metadata, production closure/lint, architecture absence,
and the full composed PE32 DLL/Wine/deployment/observation gate pass.

All thirty-four implementation choices in that linked module are now explicit.
The checked resolved environment qualifies four external definitions under
qualification
`465db815edd2b3efc641f7589852b93a439883faef256278ac2586cf6c7cb830`;
the reviewed generic x86 SEH gateway and its exact linked object qualify five
exception-transition definitions under
`628976f8f2f1624c41300e10b30010ca6083c75f9ae484c4d8dba20b3032192e`.
Three runtime-primitive definitions have exact compiled source, object, and
native-symbol bindings, but their platform qualification
`3fe167360c102aa090b64ef03f04bf8cab2b401be4e8abd3fb341e72e7ff34ef`
remains incomplete: the legacy runtime presence receipt is veto-only and the
fixture's symbolic instruction spans cannot supply qualified-platform
authority. The total selection identity is
`a310231097dd4011897f40b6cb34cd6f88410433c9dbbbde37828133543885b4`.
It retains all thirty-four structurally valid choices in its receipt while
correctly withholding realization for exactly the incomplete linked module and
runtime-platform qualification; there are no missing-choice blockers.

This intrinsic-object projection is explicitly a migration parity bridge: it
copies three exact source/object pairs out of the still-running legacy native
link so provider identities and total selection can be validated now. It must
not become the final producer, because that would make selection depend on the
link it is intended to drive. `native-realization-v1` must compile or reuse the
same provider objects directly from their selected packages, prove byte/hash
parity, switch the vertical to that direction, and then remove this projection
and the legacy build/link back-edge.

Real-slice provider checkpoint (2026-08-28): the Hello-derived MinGW
registration fixture now constructs its generated provider and selection through
the public SDK v4 constructors. The linked semantic module has identity
`9ca67a0b214b3dd47164f920fc0531d55d7ad2ee970c6742d39ca3204baa4d20`, is
complete and execution-authorizing, and contains 266 reachable transfer
definitions among 341 total implementation requirements. Its exact
qualified-platform selection is present. The stricter semantic linker initially
reported three direct-control holes at `000012f7:00001303`,
`000014bf:000014cc`, and `000013fe:00001406`. They exposed a same-pass joining
bug rather than absent authority: these are syntactic fallthroughs after the
checked no-return imports `_amsg_exit`, `ExitProcess`, and `exit`. Python, Rust,
and independent replay now derive direct-relocation reachability from the exact
edge fixed point rather than from source-unit reachability. All three edges stay
in the immutable inventory as `unresolved_unreachable`; the module has no
blockers or unresolved reachable relocations.

The corrected generated provider qualification
`e444378d328301f102bb24097150e3456e6a78c2d05904577a64f76b49f00dc5` covers
all 266 reachable definitions while compiling only twenty unique per-function
PE32 objects. This exposed and fixed an important ownership and performance bug:
the Behavioral-C package may contain decoded but unreachable functions, so
provider construction must select sources from linked reachable requirements
rather than attempt to compile and own the entire source map. Its selection
`26fe1918c2a7d3fe7babacbd8fd2353e6a1ffd736f21aa556d190a00d13639ed`
retains all 266 valid generated choices and reports exactly the 75 non-generated
requirements as unfinished; it has no linked-module or provider-qualification
blocker. The full GNU Hello target regression gate passed the preceding
projection, and the corrected narrow linked-module and provider gates now pass
independently.

That validation also measured a transitional performance problem: a small
provider-layer change scheduled 538 derivations in the aggregate Hello gate on
two consecutive runs. More RAM cannot repair this invalidation fan-out. The
pivot must therefore preserve large in-memory indexes and parallel compilation
inside the few intended cache units, while collapsing the legacy per-receipt
derivation tail as consumers move to linked semantic modules, independent
provider qualifications, one native realization, and observation. No memory
reduction work is justified unless it lowers wall/CPU time or prevents the
host from completing the work without OOM or sustained swap thrashing.

### 7. Consolidate ingress, runtime, linking, and PE composition into native realization

- Derive guest dispatch directly from reachable transfer definitions and
  per-site finite target sets in the linked semantic module.
- Derive native entry/export/TLS/callback/exception thunks from typed root
  symbols and physical frames using the single reviewed IA-32 bridge template.
- Derive object tables, code-capability generations, TLS layout, private stack,
  atomics, lifecycle cleanup, outcomes, SEH gateways, and runtime-provider
  objects from reachable semantic effects.
- Preserve loader-lock-safe bootstrap, same-thread reentrancy, foreign-thread
  TLS, escaped capability publication, transactional writeback, abandoned-frame
  cleanup, deterministic overflow, process termination, callable exception
  escape, continuation, and optional pinned-layout rules already implemented.
- Compile immutable Behavioral C for unselected transfer definitions and exact
  portable-C provider objects, link once, and compose the loader surface once.
- Emit `native-realization-v1` binding all sources/objects, semantic symbols,
  provider selections, bridge equivalence, runtime primitives, linked RVAs,
  relocations, EAT/imports/TLS/resources/SafeSEH/CFG/load config, decoded
  candidate interface, linker map, and candidate hash.
- Retire native-ingress plan, runtime plan/package qualification, build plan,
  link receipt, loader-surface receipt, and module-deployment formats after
  exact field and failure parity. Keep the original module interface and
  independent observation separate.

Exit: one native realizer lowers a valid linked semantic module to a composed
PE, and no semantic interpreter, alternate dispatch registry, generated
support DLL, or target-specific bridge is present.

Milestone 7 contract checkpoint (2026-08-28): the repository now owns the
domain format and closed codec for `native-realization-v1`. The receipt records
selected provider definitions, exact linked native-object hashes and their
semantic-symbol ownership, typed linked/import/object-anchor addresses,
bridge-equivalence classes and physical-frame hashes, runtime qualification,
TLS and private-stack facts, link/map/relocation/section identities, loader
surface identities, decoded candidate-interface identity, and exact candidate
bytes. It is deliberately not a list of legacy ingress, build, link,
loader-surface, and deployment receipts.

The builder derives fail-closed blockers for incomplete or stale linked modules
and selections, missing or extra symbol realizations, provider/selection drift,
unselected provider definitions, missing bridge classes, and—critically—every
selected non-external provider object that is absent from the native-object
inventory under the same semantic symbol. Production writing obtains provider
definitions only by parsing exact provider qualifications and rechecks the
candidate file's size and SHA-256. Codec, negative, format-registry, repository
metadata, Python closure/lint, and retired-architecture gates pass. The contract
is not yet a milestone exit: the synthetic realizer must next produce these
facts directly while linking selected provider objects, after which the legacy
receipt projection and back-edge can be removed.

The first generous-vertical migration projection now passes as a blocking part
of the native-module check. Its current receipt identity is
`136f1fad4b24b0fd1e50f2b3fe16b24431b049835a8a467e016053d79123bb93`;
it binds four provider qualifications, all thirty-four selected semantic
symbols, thirty-three exact linked objects, all sixteen ingress bridge classes,
and the exact 93,184-byte candidate with SHA-256
`1389d680bfa5d4f184c3bab4f714b6ceb9c3362ff130532f9363944d42d7a67e`.
All twenty-one distinct generated-provider function objects occur byte-for-byte
in the linked object inventory under their selected semantic symbols. The
receipt remains honestly incomplete for the incomplete synthetic semantic
module and platform selection, three unresolved migration-only native-symbol
addresses, and the declared legacy-link projection. This proves the important
object-selection parity without granting authority or disguising the remaining
direction reversal. The target SDK now also exposes the domain constructor as
`sdk.candidate.nativeRealization`; production workflows can migrate to one
public receipt boundary without importing its implementation module directly.

The first dependency direction has also been reversed. Native-realizer and
runtime-platform qualifications no longer copy their proof objects out of the
legacy linked skeleton. They independently compile the three exact
content-bound runtime/ingress sources with the deterministic PE32 proof profile;
their object hashes are byte-identical to the corresponding objects in the old
link. Consequently the total implementation selection no longer depends on the
native link that it must eventually drive. The realization writer now rejects a
selected non-external provider object unless the exact bytes are materially
present in that provider's qualification package, and then separately rejects
it if those bytes are absent from the linked module. This gives the remaining
cut a strict direction: selected package object to native link to realization,
with the old link retained only as the current parity consumer.

The transitional native linker now follows that direction. It loads the total
selection and exact provider qualifications, resolves their materialized object
manifests, stages twenty-four unique selected objects directly, and fails unless
the complete selected object set is consumed. All twenty-two Behavioral-C
function translation units and the three intrinsic runtime/ingress sources use
provider-package objects; the duplicate faithful function object is staged only
once per source occurrence while remaining one content identity. Only nine
unselected realization-infrastructure sources are still compiled inside the
link derivation. The resulting linked payload remains byte-for-byte identical
at SHA-256
`3ab133514f8d9e35431b545ae4af12edcc686c09c782095e5604debc93104f02`,
and composition still emits the identical candidate hash recorded above. The
synthetic Wine/deployment/project vertical passes after the flip. What remains
legacy is the surrounding build-plan, linked-skeleton, link-receipt, composer,
and deployment fact flow—not the direction or identity of selected executable
objects. The next cut is therefore to move those nine infrastructure objects
and composition facts behind the native-realization producer, then delete the
transitional formats instead of wrapping them.

Generated-only generous-vertical checkpoint (2026-08-28): the actual synthetic
link now selects generated Behavioral C for every one of its twenty-three
reachable transfer definitions and selects no portable component. Its total
selection contains thirty-six explicit choices: twenty-three generated
definitions, four external-environment definitions, five native exception
realizers, and four qualified-platform/runtime definitions. Twenty-four unique
selected provider objects plus eight candidate-local realization objects enter
the link; no selected provider object is missing from the native inventory.
The resulting 94,720-byte DLL has SHA-256
`e349f8ce6fef2837faef22e1c4a339d80a4d125eb20f0c25bca3c951d47fb5e3`,
and its `native-realization-v1` projection has identity
`2790f270a78aa1d5a45194071292e9fa4af519a4ec8bf490bf9fa4bd68492562`.
The complete Nix/Wine vertical passes TLS ordering and mutation, concurrent
atomic compare/exchange, nested ingress, reentrant imports, declared nonlocal
outcomes, guest and host exception exchange, checked unwind/finally behavior,
continuable pinned-context resumption, callback registration, foreign-thread
callback delivery, and one-shot capability expiry. These behaviors now come
from canonical transfer actions, checked frames, and the shared capability
registry rather than a portable fixture overlay.

This is strong execution parity but not milestone-7 authority. The realization
remains correctly incomplete for the synthetic linked module's four missing
qualified runtime primitives and one reachable qualified-platform hole, the
corresponding incomplete total selection, four migration-only native-symbol
addresses, and the remaining legacy-link projection. In particular, the
passing Wine process is veto evidence and cannot close those facts. The next
clean cut must make the native-realization producer own the eight remaining
candidate-local infrastructure objects and all link/composition facts, consume
only the linked semantic module plus total selection, and then remove the old
build-plan/link-receipt/skeleton/composer/deployment chain.

The same checkpoint makes the speed policy operational. A semantic fixture
change still fans out across roughly sixty Nix derivations even though selected
provider objects are content-addressed and independently reusable; an
assertion-only edit reuses the expensive products in seconds. Therefore retain
decoded transfers, closure indexes, solver state, compiler processes, and
object manifests aggressively, use all available cores, and make the linked
semantic module, selected provider packages, and native realization the few
coarse cache units. RSS is diagnostic rather than an authority or release
limit. Do not add a memory-saving reconstruction layer, per-fact derivation
graph, internal memory manager, or scheduler: collapse the transitional public
phases so unchanged semantic and provider content bypasses their work
altogether.

Realization-object ownership checkpoint (2026-08-28): the same coarse
intrinsic/realization package now compiles and content-binds all eleven native
sources that are not immutable per-function Behavioral C. Three of those
objects realize selected platform or exception definitions; the other eight
are realization infrastructure: generic module bridges, behavioral dispatch
and support, checked atomics and capability glue, runtime layout and bindings,
and generic native-ingress execution. Compilation uses eleven parallel jobs
under the same deterministic PE32 profile. The transitional linker receives
the package's self-hashed object manifest, rejects stale/duplicate source or
object bindings, and requires every declared realization object to be consumed.

Consequently the actual synthetic link now compiles zero source files. It
stages twenty-four unique selected-provider objects and eight realization
infrastructure objects, with all thirty-two object bytes produced before and
independently of the link derivation. The linked manifest records the exact
realization-object receipt and contains no
`compiled_in_candidate_derivation` row. Candidate bytes remain identical at
SHA-256
`e349f8ce6fef2837faef22e1c4a339d80a4d125eb20f0c25bca3c951d47fb5e3`,
and the full Nix/Wine/deployment/observation gate still passes. Corruption of a
materialized realization object is covered by a focused fail-closed unit test.
This closes executable-object ownership and moves compiler work to the intended
coarse reusable cache unit. It does not yet close milestone 7: the old linker,
composer, and deployment receipts still produce the link and loader facts that
`native-realization-v1` projects, and the same qualified-platform blockers
remain honest.

Direct link/composition fact checkpoint (2026-08-28): the synthetic
`native-realization-v1` producer no longer reads `native-module-link-receipt-v2`.
It parses the exact linker map bound by the native-build manifest, checks every
realized symbol against a unique compatible PE32 section, and derives the
section-table identity directly from the linked payload. Transfer and exception
symbols and every ingress bridge must lie in executable sections; a runtime
primitive may deliberately bind a checked data symbol. The PE composer likewise
accepts the self-hashed native-build manifest directly. It rechecks the exact
ingress, load-image contract, resolved environment, object authority, payload,
linker map, and relocation bindings before composing and records no legacy link
receipt input. The candidate remains byte-identical and the complete Wine and
observation vertical passes.

All thirty-six selected semantic symbols and all sixteen bridge classes now
receive addresses from that direct map, eliminating the four former
`migration_native_symbol_address_unresolved` blockers. The direct-fact
intermediate realization identity was
`fb54b44d6725c0a8ed6b15b677bfd12ef876e6d9d53190db8c85ac58fe1cd452`;
it had exactly four honest blockers: the incomplete linked semantic module, the
corresponding incomplete implementation selection, the missing qualified-
platform binding, and the still-separate composer projection. No object, symbol,
bridge, link-map, or relocation uncertainty remains hidden behind those
blockers.

This removes the old build plan and link receipt from both the executable link
and composition dependency direction. They are still scheduled only by the
unmigrated loader-surface/deployment parity receipts and their explicit test
assertions. The realization's sole migration blocker was consequently narrowed
from legacy native linking to the still-separate composer/deployment projection.

Composition ownership checkpoint (2026-08-28): composition and candidate
decoding now execute inside the same coarse native-realization phase. That phase
emits the composed `fixture.dll`, composition manifest, candidate load-image
contract, decoded module interface, and `native-realization-v1` together. The
independent Wine host loads the realization-owned DLL rather than the legacy
composer output; an exact byte comparison still requires the two paths to agree
during migration. The candidate remains 94,720 bytes with SHA-256
`e349f8ce6fef2837faef22e1c4a339d80a4d125eb20f0c25bca3c951d47fb5e3`.
The realization identity is now
`8eac97d4438ce773a9fa8e17ab2f858397b2fe4cf5dce7b265716885fcaf8195`,
and its only migration blocker is the legacy deployment/completion projection;
the other three blockers remain the honest synthetic qualified-platform,
linked-module, and selection authority holes. The next cut is therefore
observation/deployment binding, not another build or composition abstraction.

Observation-binding checkpoint (2026-08-28): project completion now accepts an
exact `native-realization-v1` directly as the target-owned candidate record,
rejects any image supplied through both realization and legacy deployment, and
checks the independently observed candidate hash against the realization-owned
DLL. The synthetic Wine distribution copies that DLL directly. Its one-module
project completion remains incomplete only because the realization itself is
honestly incomplete; observation no longer requires a legacy deployment
receipt to restate the same candidate identity. The old deployment route
remains temporarily as an explicit byte/failure-parity consumer until the
reusable native-realization constructor owns the currently inline synthetic
link/composition orchestration.

Reusable realization checkpoint (2026-08-28): that orchestration now belongs
to the public `nix/native-realization.nix` constructor and the production
`native_realization.build` module. The constructor consumes the linked semantic
module, total selection, exact provider qualifications and precompiled objects,
Behavioral-C and shared-runtime packages, structural selection, original
interface, ingress/environment/object inputs, and runtime qualification. In one
content-addressed phase it links the exact objects, emits the payload/map/
relocation inventory, composes the PE, emits the candidate load contract,
decodes the candidate interface, derives selected symbol/bridge/object/link/
loader facts, and writes `native-realization-v1`.
The 400-line fixture-local realization program has been removed, and an
architecture gate rejects its return.

The complete external Wine host and direct project-observation vertical still
passes with candidate SHA-256
`e349f8ce6fef2837faef22e1c4a339d80a4d125eb20f0c25bca3c951d47fb5e3`.
The reusable realization identity is
`3e78ad05b15141a61bda59101adf4905e88a6e32cedf36864743f76429ced728`.
Its blockers are now exactly the three honest upstream holes:
`linked_semantic_module_incomplete`,
`implementation_selection_incomplete`, and
`qualified_platform_binding_missing`. No migration-only build, link,
composition, deployment, symbol-address, or observation blocker remains in the
new path. Legacy deployment products are now parity/test consumers only and
can be removed after their remaining assertions are migrated.

Synthetic legacy-tail retirement checkpoint (2026-08-28): after the reusable
realization and direct observation passed, the PE32/Wine vertical removed its
standalone Behavioral-C completion gate, native build plan, native link
receipt, duplicate composer, duplicate candidate decoder, loader-surface
receipt, release-acceptance receipt, module deployment, and deployment-based
project completion. Equivalent assertions now inspect the realization-owned
build manifest, composition manifest, decoded candidate interface, observed
load graph, and realization-based project completion directly. An architecture
gate prevents those retired constructors from returning to this vertical.

The candidate hash, Wine behavior, loader-surface assertions, and honest three
realization blockers remain unchanged. A fresh request for the native-module
gate fell from 62 scheduled derivations before the cut to 42 afterward, a
32-percent reduction without a mutable cache, hidden scheduler, weaker
verification, or additional public artifact. This is the intended speed-first
effect of making one native realization the cache and ownership boundary.

Link-ownership checkpoint (2026-08-28): the public realization constructor now
executes the deterministic native link itself rather than accepting a separately
scheduled `native-linked-skeleton-v1`. The synthetic fixture no longer imports
`native-linked-skeleton.nix`; its realization directory owns the link manifest,
payload, linker map, relocation inventory, composition outputs, decoded
interface, candidate, and receipt. The architecture gate rejects reintroduction
of a separate linked-skeleton phase in this vertical. The complete Wine and
observation gate passes with the same candidate and realization identities,
while a fresh request schedules 40 derivations rather than the post-deployment-
retirement 42 or the pre-consolidation 62. The remaining fan-out is upstream
semantic/provider qualification and independent observation, not a second
native build/deployment chain.

Intrinsic-provider checkpoint (2026-08-28): the synthetic vertical no longer
contains its 380-line private compiler for external-environment,
native-realizer, and qualified-platform providers. The public
`nix/intrinsic-semantic-providers.nix` constructor now compiles the eleven
shared runtime/ingress sources in parallel, validates their exact PE/COFF
symbols, emits one object manifest, derives the three content-bound provider
qualifications, and extends generated-C choices to the total requirement
universe. Unknown platform primitives and conditionally absent typed-x87
handlers produce incomplete definitions with missing-object blockers; they
never gain authority from a platform catalog alone. When a qualified platform
is supplied, its identity must exactly match the linked semantic module.

The full synthetic native/Wine/observation gate still schedules 40
derivations, produces byte-identical candidate SHA-256
`e349f8ce6fef2837faef22e1c4a339d80a4d125eb20f0c25bca3c951d47fb5e3`
and, after adding the explicit provider materialization state, realization
identity
`d26228c84fe47e52111615658ee941be464df2b557205977da9c0d0eb7d4c19f`,
and retains exactly the three honest realization blockers above. An
architecture gate now forbids fixture-local intrinsic-provider compilation.
The target SDK now instantiates that constructor and the generated-C provider
directly. It also owns one configuration-level portable-C provider through
`nix/portable-c-semantic-provider.nix`; component packages no longer create a
second selection mechanism. Generated-C compilation is shared once per target,
while portable and intrinsic qualifications vary only where configuration
ownership or environment evidence varies.

Provider-selection checkpoint (2026-08-28): semantic selection no longer
depends on shared-runtime rendering, runtime qualification, native ingress, or
PE32 object compilation. The same intrinsic qualification contract has two
evidence states: `compiled` binds the eleven exact objects used by native
realization, while `unavailable` emits the same stable definitions with empty
object hashes and incomplete facets. Portable implementations without an
object manifest use the same rule. Incomplete resolved environments emit an
incomplete external-contract facet, and linked requirements with no allowed
provider kind remain explicitly unselected. Zero-definition unused provider
qualifications are permitted but cannot satisfy a requirement and do not enter
the selected qualification inventory. These are fail-closed states of one
provider system, not status-only adapters or alternate implementations.

The real target projections now materialize without attempting the legacy
runtime/deployment tail. Hello selects 4,633 symbols and reports four aggregate
blockers; jq selects 326 and reports 68, including its 64 exact requirements
with no allowed provider; DX-Ball selects 811 and reports three. All remain
honestly incomplete. The synthetic materialized native/Wine path remains
byte-identical and still schedules 40 derivations. The target requests still
advertise nominal closures of 413, 151, and 155 derivations respectively, even
though content-addressed reuse means only a small tail rebuilds. That fan-out
and the repeated 30--60 second Nix evaluation are now the principal status-path
performance defect. The next clean cut is a compact materialized target status
receipt plus one shared target-flake evaluation/aggregate request, followed by
replacement of the legacy deployment tail with public native realization.
Running independent target evaluations concurrently is allowed and useful on
the RAM-rich reference host, but it is not the final caching design: observed
Nix evaluation-cache SQLite contention reinforces that shared evaluation and
coarser content boundaries are preferable to a project-owned cache manager.

Status clean-cut checkpoint (2026-08-28): the separate
`candidate-status-v2` reducer and format are retired. Candidate status now uses
the same domain-neutral `operator-work-status-v1` projector as project status,
with exactly two semantic inputs: the materialized linked module and one exact
`implementation-selection-v1`. It emits separate module and configuration
subjects, so it does not pretend that selection grants semantic authority.
Structural-executable-v2, activation-v4, runtime, realization, and candidate
test metadata are absent from the status closure. The public default command
also skips the operator-index evaluation and reads its materialized default
status directly. On the real GNU Hello target, the first changed-tree
materialization took 89.1 seconds while closing the remaining provider tail;
the unchanged second build took 194 ms and the complete public CLI path took
230 ms, both below the 1.3-second warm budget. The view reports the exact 4,633
selected symbols and four provider-selection blockers alongside the module's
69 blockers. The SDK fixture proves activation and test-only mutations do not
change candidate-status identity, while a provider-selection change does.

The ordinary test harness and canonical phases now use the host/Nix resource
boundary directly. The obsolete 1.9/4/8-GiB tiers, per-phase memory arguments,
and project-level runaway guard are absent. Resource classes remain scheduling
and cache-topology metadata only; peak RSS is diagnostic, while decoded
modules, indexes, memo tables, solver state, and prepared outputs may stay
resident whenever that improves wall time.

Linked-package checkpoint (2026-08-28): `linked-semantic-module-v1` is now a
validated package view over the exact members already owned by
`semantic-object-v1`. It publishes store symlinks for transfer-v2, module
interface, object authority, resolved environment, and optional checked
members beside the linked module and its closure; it neither copies their
bytes nor defines another format. Strict loading validates the semantic object,
all member identities/content hashes, and every linked binding once, then keeps
the resolved member table in memory for constant-time reuse. Native consumers
use this package directly. Transitional closure-only consumers retain one tiny
content-addressed projection: its focused mutation test proves that a linked
view change can preserve closure bytes, so the projection prevents that change
from invalidating hundreds of legacy descendants. Remove it only after those
consumers migrate to the semantic module; aliasing it to the whole package
would be superficial simplification and a serious cache regression.

Native realization now derives the original interface, transfer plan, object
authority, resolved environment, qualified-platform identity, and execution
closure from that one package. Its public Nix constructor no longer accepts
those duplicate inputs, and an architecture gate prevents them returning. The
synthetic PE32 DLL link, Wine observation, and project-completion slice passes
after this cut; a changed-source run completed in 23.3 seconds and an unchanged
run remains a store lookup. The fixture's export and callback physical
protocols have since moved into `resolved-external-environment-v1`, so the
historical hand-authored execution-closure override is gone as well. Native
ingress and shared runtime now use the exact closure packaged beside the linked
semantic module.

Target-native exposure checkpoint (2026-08-28): SDK v4 now exposes one
`native-realization-v1` derivation per component configuration. The build path
materializes the same intrinsic-provider contract, produces a build-only total
selection bound to those exact objects, and feeds the linked package plus
provider packages to the one native realizer. The existing unmaterialized
intrinsic qualifications and selection remain the cheap fail-closed status
view; candidate status does not depend on compiler objects, runtime rendering,
or realization. Enumerating Hello's nine native configurations takes about
0.2 seconds.

Forcing real Hello's default `string-pointer-enabled` realization is not yet a
successful candidate build. The first changed-tree request spent 3 minutes 7
seconds evaluating the remaining authority/component graph, scheduled 421
derivations, then stopped fail-closed when shared-runtime generation observed
the exact native-ingress plan was incomplete (the current plan has 62 boundary
and root-authority blockers). This is useful vertical evidence: the public
coarse realization unit is wired without weakening authority, but it also
confirms that neither more RAM nor the realizer itself can remove the legacy
evaluation fan-out. Candidate build remains on the existing checked path until
the generic ingress authority closes. The next cut must move those call/root
facts into the semantic module and retire their authority-v3/component producer
tail; it must not cache the 421-node graph or make incomplete ingress runnable.

Target deployment-tail retirement checkpoint (2026-08-29): ordinary SDK
candidate build, acceptance, and Wine-test paths now consume the exact
`native-realization-v1` derivation and verify its candidate hash directly.
They no longer construct or reduce a parallel static candidate, structural
execution receipt, native build plan, linked skeleton, link receipt, loader
surface receipt, module deployment, or release-acceptance receipt. The twelve
standalone Nix constructors for that chain are deleted, and an architecture
gate requires their absence. Multi-image project workflow generation now
selects native realizations directly; the project completion codec retains its
temporary deployment reader only for the isolated PE32 parity fixture.

The synthetic PE32 link, Wine observation, and realization-based project
completion gate pass after the cut, as do the focused SDK and candidate-suite
checks. Real Hello remains correctly unbuildable because its realization is
incomplete; `candidate build` now fails at that one receipt rather than running
the retired completion chain. Following the broad source and orchestration
moves in this working tree, one cold status materialization scheduled 161
derivations and a default candidate dry-run scheduled 166. These are migration
invalidation observations, not steady-state budgets. Direct status evaluation
was 1.33 seconds before materialization and the unchanged public status path
was 0.113 seconds afterward. This reinforces the speed-first policy: keep the
complete semantic working set and content-addressed packages resident, spend
available RAM on parallel work, and reduce invalidation breadth rather than
reconstructing compact shadow state.

Native build-fact clean-cut checkpoint (2026-08-29): native realization now
compiles selected provider objects directly and emits one non-authorizing
`native-realization-build-manifest-v1` inside its output. The optional native
module build-plan branch, standalone link receipt, `native-linked-skeleton-v1`
manifest, Python `candidate.native_module` codec, and their production/test
readers are removed; their literals are registered as retired. The composer
accepts exactly the realization build manifest and no alternate link-fact
source. The compiler likewise requires a linked semantic module, one total
implementation selection, selected provider qualifications, and one exact
realization-object inventory; it no longer accepts structural-executable,
activation-plan, supplemental-component-object, or legacy build-plan inputs.
The obsolete structural/release policy codec and fixture-only receipt producer
are also deleted. The synthetic PE32/Wine/observation gate, focused runtime and
realization tests, metadata, format, architecture, and Python-closure gates all
pass after this cut. This is a real reduction in systems: compiler/linker facts
remain data inside realization, while no second artifact can authorize or
redirect execution.

Provider-dispatch clean-cut checkpoint (2026-08-29): portable-C provider
qualification now derives ownership directly from the selected V4
implementation records and exact object overlays; it no longer consumes or
hashes a component activation plan. Shared runtime accepts at most one
content-bound portable semantic-provider qualification and its exact object
manifests. It validates every `original:function:*` definition against one
overlay/native symbol, derives entry versus subsumed-member dispatch there,
and treats every other transfer definition as generated Behavioral C. The
synthetic selection-to-activation parity derivation and the activation artifact
copied into every runtime package are removed. This cuts a configuration-wide
cache edge: changing an obsolete activation view cannot rebuild provider
qualification or native runtime, while changing selected implementation source,
object, or provider identity still does. Focused provider/runtime tests and the
full synthetic Nix/Wine/observation vertical pass after the cut.

Component-activation retirement checkpoint (2026-08-29): after provider and
runtime consumers migrated, `component-activation-plan-v4` became a duplicate
total-ownership view. It is now retired. Component dependency graphs retain
configuration and portable-root checks; `implementation-selection-v1` is the
only total per-unit ownership decision and is the fact consumed by native
realization. The activation codec, constructor, SDK artifact and operator
families, fixture producer, and test readers are removed rather than wrapped.
This preserves fail-closed missing/overlapping ownership at the executable
provider-selection boundary while deleting two configuration-indexed
derivations per component configuration.

ISA invalidation checkpoint (2026-08-29): the qualified-platform graph no
longer accepts the broad `isaSource` tree. Every preparation, shard, oracle,
qualification, and release worker already had an exact checked Python module
closure, so the broad parameter and its non-null assertion were dead execution
inputs that nevertheless invalidated all 32 Lean shards on unrelated static
Python changes. Removing that edge requires no cache service and keeps the
entire parallel campaign available to RAM. Content-addressed shard results are
reused; only genuinely affected exact module closures or ISA resources re-key
qualification.

Linked-runtime and checked-continuation checkpoint (2026-08-29): shared runtime
generation now accepts one linked-semantic-module package as its semantic input
and opens transfer-v2, resolved environment, object authority, and the exact
fixed-point facts owned by that module. Its Nix surface
no longer accepts four separately keyed semantic paths. Native realization has
also removed its optional execution-closure override, and architecture gates
prevent both seams returning. The still-separate native-ingress artifact is a
typed lowering product during migration, not a second semantic source; it is
derived only from the module-owned link and checked environment.

Linked-native-consumer clean cut (2026-08-29): the linked module now retains
the one source fixed point's status, content identity, and blockers inside its
own closed payload. Native ingress and shared runtime derive reachable units,
direct edges, finite indirect targets, callbacks, exception continuations, and
nonlocal transitions directly from linked symbols and effect tables. They no
longer open `module-execution-closure.json`; an architecture gate prevents that
sidecar read from returning. The compatibility projection is now retired:
independent replay recomputes the fixed point transiently from packaged
semantics and compares it directly with linked tables. This adds no persistent
artifact or production semantic pass and makes the linked semantic module
genuinely subsume the fixed point it already used.

The cut also preserves the distinction between semantic completeness and
realization completeness. Missing runtime/provider selections remain linked
implementation blockers, but they do not masquerade as fixed-point blockers
and therefore cannot prevent the intrinsic provider package from being built
to resolve them. The synthetic PE32 DLL/Wine/observation vertical passes with
this separation. Native ingress and runtime receipts now bind the linked-module
identity while retaining the source fixed-point digest as provenance.

The Hello performance and independent-replay vetoes are intentionally no
longer dependencies of the broad target-regression link farm. Under unrelated
parallel component builds, the unchanged semantic-link benchmark measured
about 33 seconds; run alone it measured 20.8 seconds under the unchanged
30-second CPU limit. The independent replay separately consumed more than 100
seconds and about 1 GiB while the ordinary regression waited. These are
independent release checks, not prerequisites for component/status iteration.
Both remain explicit target artifacts and must be run for release; the limits
were not raised and normal target work retains full parallelism.

The compatibility execution-closure projection is removed from the linker,
SDK, target artifact and regression sets. Replay and performance checks now use
the linked module directly. This prevents a transitional serialization from
becoming a second public semantic surface or routine cache root after native
consumers have moved to linked symbols.

The standalone module-execution-closure Nix phase and its public focused gate
are now removed. The closure codec is construction-local to semantic linking
and independent replay; only the linked semantic module persists. Real Hello's
v2 replay passes with the exact fixed-point digest bound in its receipt, and
the post-cut performance veto passes at 25.107 seconds worst CPU and 843,296
KiB peak RSS under the unchanged 30-second limit.

The synthetic environment now owns its export and callback physical protocols
and both forms of checked exceptional control. A handler-bearing protocol
authorizes guest SEH dispatch; a handler-free protocol with an exact resumption
unit authorizes a continuable exception to escape a callable root, be handled
on the same host thread, recapture its projected physical context, and resume
only that guest continuation. Transfer-v2, the Python closure, the resident
Rust kernel, closure validation, native ingress, and generated runtime all
accept and independently validate that one representation. The bridge registry
also now keys physical-frame equivalence by semantic target, so equal ABIs for
different targets cannot accidentally share one native address while equal
uses of the same target still do.

Numeric `ExceptionAddress` and `Eip` fields remain ordinary semantic
projections in the linked module; semantic closure no longer pretends that the
later candidate layout is already known. Native ingress separately requires a
unique content-bound pinned-layout authority covering the observed fields and
the exact source/resumption RVAs before materializing original numeric values.
Missing, duplicated, stale, unreachable, or module/environment-mismatched
continuations and pinned authorities fail closed. This separation removes a
false semantic blocker without weakening the deployment gate.

The complete synthetic DLL/Wine/observation gate passes at
`/nix/store/6zh549lq2fwha4hc6x4lg2jlpz408gw6-spaghetti-extractor-native-module-check`.
It exercises external continuation, guest-handled divide and access faults,
host-import exceptions, pinned context modification, TLS, callbacks, shared
data, atomics, composition, realization, and observed completion through the
canonical linked closure. Focused exception/ingress/runtime unit suites,
linked-module replay at
`/nix/store/8nl5sx3i263a59sff024w6sygksb2l36-spaghetti-extractor-linked-semantic-module-v1-check`,
metadata, and retired-architecture gates pass. The real GNU Hello aggregate
also passes at
`/nix/store/17b2n3g9g6mhxhcb2vcbg3fganb2h24b-spaghetti-extractor-gnu-hello-target-regression-checks`.

That Hello request took more than a minute merely to enumerate its changed
target graph and scheduled 204 derivations after the semantic-kernel change.
This is the remaining performance problem: source-closure and receipt fan-out,
not resident semantic memory. Available RAM should be spent on parallel shards
and one broad decoded/indexed working set. The next speed clean cut is to narrow
Python source closures and finish moving legacy receipt consumers behind the
linked module and native realization; adding eviction, compact/re-expand
cycles, or a project cache manager would preserve the expensive graph rather
than remove it.

Speed-first fixture clean-cut checkpoint (2026-08-29): the RAM constraint is
explicitly relaxed. There is no active RSS acceptance cap; direct decoded
tables, redundant indexes, memoized intermediates, persistent solver state,
and concurrent shards are preferred whenever they reduce latency. The
synthetic PE32 fixture no longer writes a second hand-authored native-ingress
plan or a separately keyed shared runtime. Its bootstrap qualification, final
runtime, project load plan, realization assertions, and Wine observation all
consume the environment-derived ingress and linked semantic module. Portable C
now names stable semantic target RVAs through the shared code-capability
registry; only that registry maps them to native bridge addresses and publishes
escaped callback generations. An architecture gate rejects reintroduction of
the fixture-local ingress/runtime paths.

This cut found a real drift hidden by the duplicate plan: its handwritten
handled-exception escape dispositions disagreed with the canonical checked
environment, even though the canonical gateway behavior passed Wine. The
shadow assertion was deleted rather than teaching two producers to agree. The
focused runtime suite passes 13 tests; the complete PE32 DLL, external host,
Wine, realization, and observation gate passes at
`/nix/store/qbb6306dj151dm4471gm77751jjhbjcr-spaghetti-extractor-native-module-check`;
metadata, production lint, and the retired-architecture gate also pass. A warm
native-module request completes in 1.53 seconds on the reference host, but Nix
still enumerates 22 transitional derivations. The next performance cut is
therefore to fuse the bootstrap/final qualification choreography into the
coarse provider/realization cache unit and narrow its Python source closure,
not to reduce its resident set.

Speed-first provenance and invalidation checkpoint (2026-08-29): the qualified
platform no longer hashes candidate ingress/runtime renderer modules. It owns
the eight stable target-independent native primitive contracts and their veto
obligations; the materialized intrinsic-provider receipt now binds those exact
contract hashes together with every generated source, compiler, runtime
qualification, and compiled object. This is a relocation of implementation
identity to its real consumer, not weaker authority. A checked Python-closure
allowlist prevents the qualified platform from reacquiring realization code.

The common content-addressed Python phase also emits build provenance through
an independently addressed output instead of placing `phase-manifest.json`
inside the semantic/package output. Provenance remains exact and available to
receipt gates, while an implementation-only edit that reproduces identical
artifact bytes can converge on the same semantic cache identity. A repeat of
the original runtime-docstring invalidation probe now leaves the complete GNU
Hello aggregate, qualified-platform release, both semantic objects, both
linked modules, and both Behavioral-C packages at byte-identical derivation
paths; before this cut it changed all of them. The architecture test verifies
the separation, and the build-infrastructure fixture verifies that provenance
is absent from the semantic output and present at its dedicated path.
The full synthetic PE32 DLL, generated/portable providers, shared runtime,
native realization, Wine execution, observed load graph, and completion gate
passes at
`/nix/store/d4nqhiqyk8ms9mq0x3jgrkh6nfdkpr67-spaghetti-extractor-native-module-check`.
The real GNU Hello regression passes at
`/nix/store/84d4mp57ibfn2y7bcyb0aa85xws1cyk8-spaghetti-extractor-gnu-hello-target-regression-checks`;
once rooted, an unchanged request completes in 0.11 seconds on the reference
host. The floating content-addressed graph can still print its 204-node
resolution inventory on the first request, but no work is rebuilt.

The memory policy is deliberately permissive rather than merely cap-free:
available RAM should be consumed whenever doing so plausibly lowers latency.
Keep decoded PE/transfer objects, closure relations, reverse indexes, solver
contexts, generated source fragments, and compiled shard metadata resident
together; memoize by canonical content identity and run independent work at
full useful parallelism. RSS remains telemetry only. Optimize memory only for
observed OOM or swap-induced slowdown, never for an aesthetic footprint target.

Semantic capability clean-cut checkpoint (2026-08-29): callback capability
identity now belongs to `linked-semantic-module-v1`. The link materializes each
reachable callback target with its semantic capability ID, source effect,
protocol, lifetime, original RVA, target symbol, and root provenance, but no
bridge symbol or candidate address. Portable-component qualification consumes
that resident linked package directly and resolves the target through the one
shared runtime code registry at execution. It no longer schedules or hashes a
standalone native-ingress plan, and the Hello callback binding was migrated
from the retired `callback-v3` selector to the exact linked capability. This
turned Hello's callback component compile facet from `incomplete` to `checked`.
The focused 64-test semantic/component/Nix suite, synthetic PE32 DLL/Wine gate
at `/nix/store/ndf31mzif1q3rzk8cyjdqmzyc193bdmr-spaghetti-extractor-native-module-check`,
and real GNU Hello regression at
`/nix/store/zrkppg3p3sq1v6sh03czpbp1w9bvgns7-spaghetti-extractor-gnu-hello-target-regression-checks`
pass. Architecture checks reject any restored component-to-ingress artifact
edge. Native realization still derives the physical bridge registry; project
load planning is the next remaining standalone ingress consumer.

Mixed-provider native-realization checkpoint (2026-08-31): the synthetic PE32
DLL now exercises the configuration the production architecture actually
needs. Its total selection maps 16 transfer definitions to one compiled
portable-C provider object and retains seven definitions as generated
Behavioral-C fallback. Five content-deduplicated generated function objects
and the portable object are linked into one candidate; there is no runtime
fallback or duplicate generated implementation for a replaced definition.

Native realization derives two selection-specific support sources from the
same implementation-selection receipt. A filtered Behavioral-C dispatcher
retains total semantic-universe queries while removing calls and relocations
to definitions selected from portable C. One realization-owned provider
registry binds the selected portable definitions into the shared dispatch
table. This removes the need for a standalone component runtime and makes the
exact selected definitions, rather than every definition offered by every
qualification, the facts recorded in the native-realization receipt.

The vertical exposed and closed a second cross-system defect in checked SEH.
After the generated gateway captured and unwound a real IA-32 divide fault,
the recovery portal correctly placed the authorized guest-handler frame on
the module private stack, but the generic stack validator admitted only the
captured host stack. Stack validation now recognizes exactly the active
exception handler-frame base under its frame and SEH generation. All memory
access remains independently gated by the checked exception-object
transducer, so this grants no general private-stack authority.

The composed candidate now passes under Wine with the actual portable `DIV`
fault, x87/context projection, nested finally effects, checked guest handler,
pinned `Eip`/`ExceptionAddress` update, authorized continuation, access
violation, host-import exception, TLS, callback, reentrancy, and data/atomic
paths. The implementation selection and realization remain honestly
incomplete for the fixture's deliberately absent platform qualification and
pinned deployment authority; observation does not manufacture those facts.
The exact integration outputs are:

- native module and Wine observation:
  `/nix/store/bgb1w5qw6afrr66gpis8dndgj7j9l47v-spaghetti-extractor-native-module-check`;
- native-realization contract suite:
  `/nix/store/ywb9y909dhjhnv222cgfnhdchdm8synv-spaghetti-extractor-native-realization-v1-check`;
- native ingress/runtime suite:
  `/nix/store/ld3231id5rcsih7sj13fxjgxrsxgyjxy-spaghetti-extractor-native-ingress-runtime-check`;
- PE32 project composition and observation:
  `/nix/store/zykhc5vm2hswyfv1ajg00756l5skkbq0-spaghetti-extractor-pe32-project-check`.

This closes the generated/portable/shared-runtime/ingress/composition
interaction required before the mandatory generous vertical slice.

V2 project-link clean-cut checkpoint (2026-08-31): project load planning now
accepts only closed `linked-semantic-module-v2` package files. The SDK,
single-module workflow, multi-image PE32 fixture, and synthetic native DLL all
pass each image's V2 package directly; the planner no longer imports the V1
codec or reconstructs a path to a separately scheduled ingress artifact.

For code edges, the V2 import-use effect supplies the checked importer frame
identity and the module-owned resolved environment supplies its validated
physical frame. The provider's V2 export-capability effect supplies the
provider frame. The planner hashes only their physical transport and stack
discipline, excluding semantic subject and identity fields, and rejects a
mismatch. For data edges, it joins the provider's V2 active-object inventory
with the exact object rules and data anchors in the packaged semantic object,
then checks importer permissions and minimum extent. Each project image now
records both the semantic and content identities of its resolved environment,
and cross-image target ABI/data-layout disagreement fails closed.

This migration exposed and fixed a V2 codec defect: a data IAT use was
incorrectly required to carry an external callable-contract hash. V2 now
requires that hash and callable definition only for code uses; data uses bind
the loader slot plus object permissions, extent, and provider anchor without
borrowing callable authority. The real multi-image fixture proves both a code
edge and a writable data edge through V2, Windows/Wine loading, observed graph,
and completion. The synthetic mixed-provider DLL proves the same V2 load-plan
consumer alongside callbacks, TLS, exceptions, and checked native ingress.
The passing content-addressed outputs are:

- multi-image PE32 project:
  `/nix/store/zykhc5vm2hswyfv1ajg00756l5skkbq0-spaghetti-extractor-pe32-project-check`;
- mixed-provider native DLL/Wine observation:
  `/nix/store/rkvn4wpm81y0mb5n36n8zafiifhf1plp-spaghetti-extractor-native-module-check`.

Architecture guards now reject a V1 project-planner import, a project SDK that
does not select V2, or a Nix planner that reconstructs a conventional
`linked-semantic-module.json` member beneath a separately keyed directory.
Milestone 7 remains open only for the V2 native-realization/deployment receipt
cut and the eventual removal of V1 after every remaining production consumer
has migrated.

### 8. Pass the mandatory generous vertical slice

Use all three existing complementary fixtures as one blocking pivot gate.

#### Real GNU Hello

- Build from the real PE interface, exact semantic objects, linked environment,
  qualified platform, full closure, generated-C fallback, and qualified
  portable providers.
- Preserve exact evidence that the linked-but-uncalled MinGW TLS-destructor path
  through original RVA `0xAB86` is unreachable in stock Hello.
- Use generic process ingress and shared platform runtime with no Hello-specific
  bridge, target annotation, interpreter, unrestricted dispatch, or runtime
  fallback.
- Produce native realization, decoded candidate interface, one-module project
  observation, and applicable Wine output/exit evidence.

#### Hello-derived MinGW registration fixture

- Preserve the positive allocation-backed registration path that stores and
  recovers the destructor at `0xAB86` without an RVA annotation.
- Require the same semantic linker, generated C, generic ingress, native
  realization, observation, and Wine assertion that the destructor ran in the
  checked order.

#### Synthetic PE32 DLL and external host

- Preserve DllMain/TLS lifecycle, named/ordinal exports, aliases, holes, data
  anchors/interiors, imports, callbacks, reentrancy, foreign threads, atomics,
  exceptional and declared-nonlocal outcomes, SEH escape/handling,
  continuations, pinned layout, relocations, resources, SafeSEH/CFG/load
  config, composition, deployment, and candidate observation.
- Keep the host external and veto-only; it cannot supply target authority.

#### Negative and performance gates

- Reject unauthorized stored RVAs, incompatible frames, expired capabilities,
  unresolved/duplicate symbols, relocation-kind conflicts, missing generated
  or portable objects, stale qualifications/realizations, candidate mutation,
  unsupported loader metadata, unknown outcomes, stack exhaustion, and
  unqualified numeric-address dependence.
- Retain the three-sample Hello closure veto below 15 seconds CPU. Record peak
  RSS without gating or optimizing for it; high-but-fast resident use is the
  intended trade. Treat OOM or swapping as a performance diagnosis to address
  only if observed on the reference host, not as grounds for a speculative
  memory budget or compact/re-expand architecture.
- From prepared semantic objects, require semantic linking and validation below
  30 seconds on the same reference host, unless a stricter existing CPU budget
  applies. Prefer a faster representation even when it uses materially more
  memory.
- Require a materialized unchanged `candidate status --local` to return within
  the existing 1.3-second warm budget without evaluating the construction DAG.
- Demonstrate that target/component/runtime edits do not rebuild the qualified
  platform and that component or realization edits do not rebuild the linked
  original semantics.
- Record and require a material reduction from the nominal 439-derivation
  Hello replay tail; do not accept a new internal scheduler merely hiding the
  same graph inside another public system.

Exit: real Hello and the synthetic DLL close semantic, realization,
observation, negative, differential, Wine, and performance gates through the
new architecture.

### 9. Migrate jq, DX-Ball, and multi-module projects

- Migrate jq aggregate `jv`, refcount/lifecycle, callback, loop, relation, and
  induction packages to semantic symbols and provider qualifications while
  retaining every unresolved authority hole honestly.
- Migrate DX-Ball `directdraw-init`, COM/vtable calls, resources, callbacks,
  shared data, TLS/DLL lifecycle, exception boundaries, and target-owned
  images without target-specific runtime machinery.
- Treat each EXE/DLL as a linked semantic module and validate multi-image code,
  data, forwarder, dynamic-resolution, ABI, extent, and loader-service edges by
  semantic linking of their exported declarations.
- Keep Windows/Wine authoritative for actual loading, search, ordinary imports,
  forwarders, TLS callbacks, and DLL lifecycle. Validate the observed
  distribution and every target-owned module hash against its realization.
- Preserve current blocker meaning. Repository migration, hybrid module
  completion, and zero-generated-C portable completion remain distinct.

Exit: all targets use semantic objects, provider selection, native realization,
and independent observation; Hello is complete, and jq/DX-Ball remain complete
or incomplete only for genuine target evidence and implementation holes.

### 10. Retire superseded systems and run final gates

- Remove the authority phase graph, IFD routing/composition machinery,
  target-local ISA campaigns, independent resolved-environment/object/closure
  authorities, derived-registration workflow, fallback-capability analysis,
  overlapping component contract stack, separate ingress/runtime/build/link/
  deployment choreography, production interpreter remnants, old PE composer
  paths, retired SDK inputs, and retired expert commands.
- Retain transfer-v2, the neutral evaluator, Python semantic-link reference,
  and differential/minimization tooling only in their declared production or
  developer/test roles.
- Generate the domain-owned format registry, Python/Rust module indexes, test
  manifests, target metadata, repository map, architecture documentation, and
  operator documentation from the final active roots.
- Add absence checks for retired literals/readers/modules, raw machine-IR
  consumers outside the frontend, target-local oracle campaigns, duplicated
  semantic opcode switches, unrestricted dispatch, runtime activation,
  alternate object/closure registries, mutable caches, and source-only
  completion.
- Run `nix flake check`, `nix flake check ./targets`, full unit/corruption/
  differential/benchmark suites, PE32 ingress/TLS/SEH/composition/project
  integration, applicable Wine suites, generated-metadata freshness,
  architecture boundaries, invalidation fixtures, and retired-system absence
  checks.
- Record final cold/warm times, RSS, artifact sizes, derivation/invalidation
  counts, target blocker snapshots, realization hashes, decoded loader
  surfaces, observed distributions, and remaining honest blockers.

Exit: every original requirement is discharged through the smaller object and
link architecture. A module is complete only when qualified transfer coverage,
linked semantic closure, selected provider refinement, native realization,
decoded candidate identity, static release assurance, and independent observed
deployment all agree.

## Revised test and acceptance matrix

- **Semantic objects:** canonical encoding, stable identities, bounded parsing,
  exact transfer round-trip, symbol and relocation integrity, evidence binding,
  explicit holes, stale hashes, duplicate definitions, and corruption cases.
- **Qualified platform:** target independence, complete primitive inventory,
  decoder/Lean/lowering/provider agreement, disputed-oracle preservation,
  occurrence selection, x87 and atomic helpers, and tool-version invalidation.
- **Semantic linking:** imports/services, physical/logical ABI, code/data
  ambiguity, object regions/interiors, TLS, callbacks, capability generations,
  all roots, indirect targets, lifecycle, exceptional/nonlocal outcomes,
  handler continuation, fixed-point closure, and blocker parity.
- **Providers:** source v3 coverage, host/PE32 compilation, CBMC refinement,
  services, relations, induction, ownership, exact object occurrence, hybrid
  mode, and portable mode.
- **Native realization:** Behavioral C, source maps, per-site dispatch, ABI
  bridges, reentrancy/concurrency, TLS, object identity, atomics, SEH, outcomes,
  private stack, linker map, relocation inventory, EAT/imports/resources,
  SafeSEH/CFG/load config, and candidate hash.
- **Observation:** decoded candidate interface, actual loader base, imports,
  forwarders, TLS/DLL behavior, distribution membership, target-owned hashes,
  stale/mutated candidates, and multi-image edges.
- **Trust:** evaluators, Wine, tests, Z3, Ghidra, Capstone, Bochs, Unicorn, and
  optional oracles may veto or contribute independently checked evidence; a
  successful run alone never grants authority.

## Revised assumptions and non-goals

- IA-32 PE32/Win32 remains the only production backend during this plan.
- Windows/Wine loader behavior remains authoritative for imports, forwarders,
  TLS, DLL entry, module search, and actual load bases.
- Candidate code addresses may differ from original addresses; exact numeric
  equality requires explicit pinned-layout authority and observed realization.
- Loader-visible data identity is preserved through typed object anchors,
  mapped bytes, relocations, and actual IAT pointers.
- Generated faithful C is immutable. Operator-authored C exists only in
  separately hashed source packages and cannot alter original semantic bodies.
- No project-wide broker, generated support DLL, global runtime code registry,
  simulated scheduler, global engine lock, production interpreter, mutable
  cache, generic graph database, or second semantic IR is introduced.
- Existing dirty-tree work is preserved and migrated; the pivot does not erase
  completed implementation evidence.
- Format changes are intentional clean cuts. Temporary one-way parity exporters
  are non-authorizing, test/developer-only, and removed at the authority flip.
- The goal remains incomplete until all ten revised milestones and final
  deployment-only criteria close.

## Historical pre-pivot implementation ledger

Everything from this heading to the end of the file is preserved as the
pre-pivot plan and implementation journal. Its measurements, hashes, completed
tests, known blockers, and soundness discoveries remain evidence for parity.
Its contract choices and future steps are superseded by the revised sections
above.

### 1. Reconcile the current migration and restore a trustworthy baseline

- Preserve the entire dirty tree and classify current changes as retained
  foundation, provisional implementation, or retirement candidate; do not
  restart the original migration.
- Re-run focused smoke, format/build infrastructure, transfer, component V5,
  native module, PE project, and native-ingress tests before changing
  contracts.
- Refresh Hello, jq, and DX-Ball status snapshots while preserving blocker
  identity and meaning.
- Confirm existing SDK v4, module-interface-v2, external-environment, format
  registry, Nix phase constructors, V5 component contracts, native link
  receipts, composer, deployment, and project observations before extending
  them.
- Keep the immediate deployment blocker for behavioral-C objects absent from
  the link receipt.
- Add architecture checks forbidding raw machine-semantics consumers outside
  the transfer compiler, unrestricted RVA dispatch, runtime component fallback,
  unmanaged public format literals, and new production interpreter paths.
- Add non-authorizing elapsed-time, peak-RSS, unit/node/edge, worklist,
  widening, and artifact-size metrics to relevant phase outputs.
- Record the temporary diagnostic `ud2` in native ingress as a mandatory
  vertical-slice removal.

Exit: the focused baseline is reproducible, every current target remains
honestly incomplete or complete for the same reason, and subsequent failures
can be attributed to the new clean cuts.

### 2. Implement executable-transfer-plan-v2

- Define the typed core expression/effect/terminator model and strict canonical
  codec in the existing `transfer` domain.
- Make the transfer compiler the only production adapter from exact machine IR.
- Preserve exact event ordering, memory-action graphs, calls, outcomes, atomics,
  undefined identities, and source coordinates.
- Lower flag calculations into core expressions and preserve qualified x87
  operations as explicit intrinsics.
- Emit stable blockers for unsupported operations, malformed widths, missing
  effect order, unknown outcomes, stale bindings, duplicate IDs/RVAs, and
  incomplete machine semantics.
- Produce unit inventory, direct edges, entry targets, runtime-provider
  requirements, and exact-universe hashes from the compiled plan.
- Compare v1 and v2 on all currently qualified units and generated corruption
  cases.
- Migrate every renderer, evaluator, component checker, build phase, and
  diagnostic reader, then retire transfer-plan-v1 without an alias.

Exit: every deployed or checked machine semantic fact flows through
transfer-plan-v2, with exact inventory parity and no remaining production
reader of v1.

### 3. Consolidate semantic consumers behind one interpretation framework

- Define one operation registry describing names, sorts, widths, arity,
  canonical encoding, and required domain coverage.
- Implement domains for concrete diagnostic evaluation, behavioral-C emission,
  definedness, Z3 reconstruction, and reference/provenance analysis.
- Generate a coverage matrix requiring every core operation to be validated and
  handled or explicitly rejected by every domain.
- Ensure no domain decodes x86 or adapts machine IR independently.
- Emit stable per-behavioral-function translation units, source maps,
  lowering/coverage receipts, and build manifests.
- Move common generated helpers into the shared runtime instead of repeating
  them in every translation unit.
- Retain the host evaluator solely for inspection, fuzzing, differential cases,
  and mismatch minimization.
- Validate concrete evaluator versus generated C for registers, flags, x87,
  memory, aliasing, atomics, calls, faults, and outcomes.

Exit: deleting or changing any operation handler produces a coverage or
differential failure, and generated C is wholly derived from serialized
transfer-plan-v2.

### 4. Implement reference provenance and module-execution-closure-v2

- Implement a bounded reference lattice distinguishing bottom, exact/bounded
  scalar alternatives, unknown scalar, object/interior references, guest code
  references, external function references, and conflicts.
- Interpret storage through machine-object-authority-v2 locators for image
  sections, TLS, captured stack, IAT data, allocation-site objects, and
  resources.
- Preserve guest code-reference identity across authorized stores, loads,
  copies, merges, and permitted pointer arithmetic.
- Use bounded finite target sets; overflow, code/data ambiguity, incompatible
  object rules, or widening beyond the configured bound produces an exact
  blocker.
- Run one deterministic worklist over roots, transfers, reference states,
  resolved external contracts, lifecycle rules, calls, callbacks, exceptions,
  and continuations.
- Emit reachable units/edges, finite indirect targets per site, external
  contracts, native callback escapes, exception continuations, runtime
  providers, lifecycle effects, and dependency witnesses.
- Independently check root completeness, rule witnesses, terminal
  classification, target membership, and fixed-point closure.
- Validate from the actual stock Hello call graph that its linked MinGW TLS
  destructor machinery, including the indirect call near original RVA
  `0xAB86`, has no reachable registration caller and is therefore correctly
  excluded from the deployment closure. Add a Hello-derived registration
  fixture, compiled with the same MinGW machinery, that deliberately invokes
  the public registration path, stores a destructor in the allocation-backed
  list, and recovers it at the indirect call without a target annotation.
- Migrate consumers, then retire root closure, callback authority,
  indirect-target certificates, static replay, and runtime target passthrough
  as independent production authorities; retain only useful non-authorizing
  views.

Exit: stock Hello closes with the unused destructor frontier excluded by exact
reachability, the Hello-derived registration fixture passes that stored
frontier without a target annotation, and unrelated jq and DX-Ball blockers
remain honest.

Implementation checkpoint (2026-08-25): transfer-v2 reference interpretation,
interprocedural pre-call state propagation, nullable allocation joins, sparse
baseline memory, return dependencies, deterministic reverse-postorder
scheduling, and checked external write effects are implemented. Resolved
external environments lower machine-import profiles once into canonical
boundary schemas, target layouts, physical frames, memory views, callback
protocols, and out-pointer relations; the closure consumes those artifacts
instead of independently adapting raw ABI fields. Each analyzed call context
receives a canonical stack-frame object, aligned derived objects retain their
frame owner, returned local references expire, nonlocal writes propagate
through summaries, and exact external out pointers enter the same object
reference domain.

The earlier 4.4-second/1,070-unit stock-Hello checkpoint was an
under-approximation: it projected only the compiler's sparse `stack_inputs`
inventory across an internal CALL and discarded other physical outgoing stack
stores. Complete caller-stack projection exposed the honest graph: a cached
run reached about 2,300 units in 28.2 seconds and reported six causal checked
write-footprint failures plus 22 derivative indirect-target failures. A compact
relational call-parameter representation is now complete as an analysis-local
field of the existing closure state; it is not a
new public artifact or authority system. Sparse relational loads now resolve
through exact caller-object bindings in the same fixed point, including aligned
derived identities, so the earlier demand side table and repeated whole-program
discovery passes have been removed. Focused tests prove exact caller writeback,
physical positive-stack-offset aliasing, conservative parameter equality,
conditional memory effects, aligned parameter loads, dynamic out-pointer
creation, and bounded exact `REP MOVS` code-reference copying. Ambiguous or
oversized repeated writes still invalidate fail closed.

Conditional control discovery uses monotone graph growth and deterministic
reverse-postorder priorities. A second, static-priority scheduler is retained
only as a test oracle. Public dependency witnesses now contain stable
unit/context provenance only; transient abstract input/output hashes and
worklist-step counts are explicitly observational because their values can
vary with a valid convergence schedule without changing authority. The
validator rejects either transient hash if it is reintroduced into a witness.
On 2026-08-25 both schedulers produced byte-identical non-metric stock-Hello
receipts and semantic receipt hash
`13985bb50c57542f6e279ae00b40f220155701068ef5f46c69358298e1d3675f`:
3,402 units, 4,638 edges, 416
function contexts, 403 return summaries, 1,194 relational bindings, and 42
honest blockers. Those blockers are 23 unresolved reachable indirect targets,
12 unresolved callee-effect instantiations, and seven external write-footprint
failures. After compact slotted states and a reusable mutable transfer-state
view, the dynamic and static schedules take about 138,232 and 138,073 worklist
steps respectively and complete the closure in roughly 36--37 seconds. Step
counts, time, and RSS are observational and excluded from the semantic hash.

The closure state carries explicit monotone allocation-existence and
memory-effect facts, relational parameter and physical caller-frame aliases,
canonical disjoint invalidation intervals, bounded exact repeated-copy effects,
and an owned dynamic-stack region when an exact variable ESP adjustment cannot
retain a concrete base. Return summaries now fail closed when a relational
callee effect cannot be instantiated; they do not silently poison all memory
and continue. Internal calls project the complete contiguous explicit outgoing
PE32 stack prefix in addition to sparse compiler-declared inputs, so lazy frame
aliases and reusable summaries observe the same arguments. That projection now
has a named 4,096-byte qualification limit. Reachable checked stack state at or
beyond the limit emits the stable
`outgoing_stack_projection_bound_exceeded` blocker; it is no longer a hidden
under-approximation. An attempted sparse projection of every caller-memory
cell was rejected: holes changed the coordinate origin and made the result
schedule-dependent (the two schedulers disagreed at 30 versus 42 blockers).
After restoring the monotone contiguous-prefix rule, an independent static
replay again produced exact semantic hash
`13985bb50c57542f6e279ae00b40f220155701068ef5f46c69358298e1d3675f`,
4,638 edges, 13,011 stable witnesses, and the same 42 blocker identities in
138,073 steps. Only observational metrics differed.

Representative joins are associative with and without baseline image memory.
Pure object-identity parsers are memoized, temporary expression evaluation uses
a zero-copy state view, and unchanged explicit memory maps are shared across
invalidation-only joins. Measured exact-state join caches, transfer caches,
invalidation caches, `immutables.Map`, and a PyO3 normalization-loop extraction
were slower or increased memory and were removed. Dynamic relational
input-shape context partitioning resolved several blockers but was also removed:
it keyed authority on transient worklist history and therefore produced
schedule-dependent contexts. Nullable relational parameters were likewise
removed after failing to improve the remaining sites. Raising call-string
sensitivity from one to two was also rejected: it doubled the work to 270,990
steps and 896 contexts, took 77.3 seconds, retained all 12 callee-effect
blockers, and added three write blockers. A clean single-process measurement
of the retained one-deep implementation peaks near 540 MiB RSS.
At that checkpoint the memory gate was satisfied, but the sub-15-second
closure gate remained open. A fresh profile recorded 368 million Python calls: enqueue and
state joining consumed 64.0 profiled seconds, reference effect application
24.2 seconds, and state joining alone 58.0 seconds. This materially dominant
kernel satisfies the dependency policy's threshold for native promotion. The
existing PyO3 crate now contains a private batched reference-state lattice
kernel with strict bounds and fail-closed parsing; Nix builds it and full-state
differential cases match the Python reference for baseline invalidation,
callbacks, relations, constraints, ownership, and effect metadata. The same
crate now parses `executable-transfer-plan-v2` directly rather than receiving a
second adapted semantic model. Its operation inventory is checked against the
canonical Python registry, and unknown operations fail closed. On stock Hello
it validates 7,937 transfers, 136,837 expressions, 164,825 effects, 1,074
calls, and 313 x87 intrinsics in about 0.28 seconds including process startup.

A private, non-artifact context projection carries only already checked roots,
reference catalog, object bytes, boundary contracts, initial states, policies,
and authority bindings into that resident kernel. On stock Hello it validates
three roots, 7,937 guest RVAs, seven objects, 76 external calls, 9,685 initial
memory cells, and three initial states. Native expression and basic effect
evaluation over the real roots currently matches the Python reference, and
generated differential cases cover scalar/reference expressions, memory and
register effects, bounded repeated effects, and representative external-call
writes and allocations. The native slice now also matches module-handle and
dynamic-export loader-service results, merged checked contracts for indirect
external calls, typed x87 register/flag/memory provenance effects, and
recursive captured-stack and relational-memory resolution. Its strict parser
validated all 313 typed x87 intrinsics in the stock-Hello plan, while native
and Python root effects remained byte-identical across 59 expression values.
Call-input snapshots, unresolved-write observations, and checked return
overrides are now resident effect-interpreter outputs in preparation for the
fixed point. A first private resident worklist now matches the Python fixed
point for generated direct/branch fixtures, including deterministic joins,
deferred branch-edge discovery, exact scalar/reference branch refinement, and
finite indirect guest-target propagation. It emits explicit temporary blockers
instead of approximating missing semantics. Canonical call-string contexts,
bounded physical stack projection, relational call-parameter bindings,
caller-coordinate writeback, return-summary dependencies/replay, returning
external tail summaries, terminal-call suppression, and callback-root
scheduling are now resident too. Generated call/return differential cases,
including a callee write through an ancestor-frame parameter, match every
Python input state and edge exactly.

On stock Hello the resident kernel now emits the complete canonical receipt,
not a frontier projection. It matches the Python reference's semantic receipt
and hash exactly after removing only the three declared observational metrics:
3,402/3,402 reachable RVAs, 4,638/4,638 edges, 13,011 witnesses, callback
metadata and escapes, external contracts, lifecycle effects, all semantic
metrics and policies, and all 42 blockers byte-for-byte. Those blockers remain
23 unresolved indirect sites, 12 callee-effect instantiation failures, and
seven unresolved external-write footprints. Generated tests compare the
static and dynamic reference schedules after removing the same observational
metrics; both produce the same semantic receipt. The native dynamic scheduler
takes 138,219 visits versus the Python static oracle's 138,073, but the count
is observational and deliberately excluded from authority identity.

Shared immutable memory keys, values, alternatives, and the three lattice
constants reduced retained stock-Hello state from about 1.85 GiB to below the
1-GiB gate without adding a persistent-map dependency; a measured `im-rc`
experiment was slower and was removed. The actual content-addressed Nix target
receipt completed in 14,693 ms with 1,022,860 KiB peak RSS and semantic hash
`dcb491e0a4e426d42d0685dde6a3619fa6cb86d75d5f85f447ce2989463d5c83`.
This supersedes the otherwise identical `13985…` checkpoint because the
resolved environment now binds the exact transfer plan directly instead of
ceremonially binding final, call-boundary, and callback authority artifacts.
The target gate fixes that hash, inventory, blocker and witness counts, and the
sub-15-second/sub-1-GiB budgets. Full LTO did not improve the workload and was
also removed.

The native receipt kernel is now the sole production implementation used by
the module-execution-closure writer and Nix phase. Missing native support fails
closed; there is no Python production fallback. The deterministic Python fixed
point remains only as the reference oracle for schedule and whole-receipt
differential tests, and explicit receipt checking replays through the same
native production kernel. The independently compiled Hello-derived MinGW
registration fixture still recovers its stored destructor without an RVA
annotation. Milestone 4's remaining work is consumer retirement: remove the
superseded root-closure, callback-authority, indirect-target-certificate,
static-replay, and runtime-target-passthrough authority paths only after every
consumer has migrated to this receipt.

Native ingress is now the first retired-authority consumer to complete that
cut. `native-ingress-plan-v2` reads unit identity only from the exact
transfer-plan-v2 file, reachability and callback escapes only from the bound
module-execution-closure receipt, and physical ABI/lifecycle facts only from
the exact resolved-external-environment catalog bound by that closure. It no
longer rereads checked boundary package directories, machine IR, launch-root
closure, or callback-authority, and it no longer synthesizes a callback call
protocol. The ingress receipt binds the resolved-environment file explicitly;
an architecture gate rejects reintroduction of its former package-list input.
An incomplete execution closure now produces a content-addressed incomplete
ingress plan carrying every canonical blocker instead of failing the
derivation. The real Hello receipt binds the exact transfer and closure files,
preserves all 42 closure blockers, derives the checked unhandled-exception
filter capability at RVA 43424, and reports two missing checked callback
protocols for the remaining finite callback escapes. The downstream
structural-executable-v2 receipt also builds and remains honestly incomplete
on those closure blockers and blocked implementation ownership.

The production runtime planner has completed the same consumer clean cut. Its
canonical compiler joins only the exact transfer plan, module execution
closure, resolved external environment, native ingress plan, and total
component activation plan. The candidate and exact-runtime Nix paths no longer
re-read machine IR, canonical-external-site records, callback authority, root
closure, indirect-target certificates, parametric summaries, or raw profile
packs to reconstruct runtime behavior. Runtime qualification is scoped per
component configuration, so a portable overlay cannot inherit a receipt for a
different dispatch surface. `shared-module-runtime-package-v2` is now the sole
runtime source package and owns the runtime plan, runtime C and assembly,
layout, and ingress sources directly. The public runtime-core package phase,
its package writer, and the alternate machine-IR runtime compiler have been
deleted. Only rendering/layout helpers remain behind the canonical planner;
architecture checks reject restoration of the retired compiler, package, or
production inputs.

Implementation checkpoint (2026-08-26): the canonical transfer plan now
contains and validates exact finite-control-route inventories recovered by the
checked machine pipeline. Both the native production kernel and the Python
reference evaluator now consume those routes from the same validated transfer
plan and apply the same fail-closed conflict rule; neither repeats a weaker
indirect-target interpretation. A whole-receipt parity veto is part of the
existing closure performance gate, so a second semantic pipeline cannot drift
silently. On stock Hello both evaluators now produce byte-identical semantic
receipts after removing only the three declared observational metrics. The
shared receipt has hash
`f3e845d1e2a4642d2785a87d3810007dcc2ae8823050150c09d46c1e2c775195`,
4,495 units, 6,052 edges, 40 indirect sites, 16,109 stable witnesses, and 59
honest blockers: 21 unresolved indirect targets, 20 unresolved external-write
footprints, and 18 unresolved callee-effect instantiations. The formerly
unresolved terminal divide is now represented by its checked terminating
exception transition rather than a blocker.
Implementation checkpoint (2026-08-27): the larger honest graph now closes
the final execution-closure performance gate without hiding any reachable
route. Invocation-scoped text interning, compact invalidation owner indexes,
stable fingerprinted memory keys, and fingerprint-keyed internal memory and
written-memory tables reduced three fresh real-Hello runs to 14,484 ms,
14,482 ms, and 14,438 ms CPU with 865,296 KiB worst peak RSS. Every run retained
4,495 units, 6,052 edges, 489 function contexts, 181,836 worklist steps, 59
honest blockers, and canonical closure hash
`0ac5ff85fc01bdf88c0356be8619ac5ca544437056b14739329f893b6a918afd`.
The content-addressed target gate now requires all three samples, rather than
the former best-of-two rule, below 15 seconds and 1 GiB; the governed Nix
derivation passes those limits and whole-receipt Python parity. Serialized
memory rows remain lexically canonical, so the internal lookup change does
not alter the receipt. The Python reference remains a developer/test veto
only; it is not a deployed backend or a production performance path.

The single shared V5 proof closure now binds the union of component roots and
the exact operation exit units as checked boundary cutpoints. It still records
the canonical outcome at each exit but does not recursively claim behavior
beyond the component interface. The real Hello proof closure is complete at
104 units, 126 edges, 17 contexts, 149 worklist steps, and zero blockers; its
finite-selector exit records all twelve checked transfer-v2 targets. V5
refinement executes transfer-v2 directly, including canonical atomic effects
and scalar-width operations, while its remaining induction projection is a
non-authorizing one-way normalization from the serialized plan. The host
evaluator, behavioral-C renderer, symbolic validator, finite-path checker, and
induction adapter now agree that `sign_extend` operands are `(width, value)`.

The full `target-gnu-hello` regression gate passes with every authored V5
component qualified, including finite-selector, both inductive string
components, and atomic compare/exchange. Hybrid fallback ownership is derived
as a normal V5 binding intent and exact component unit inventory, then bound by
file hash into the generated behavioral-C implementation; it does not use a
special fallback ownership contract. Milestone 4 still retains the explicit
consumer-retirement work above, and the passing target regression is not yet a
deployment or milestone-8 Wine completion.

Implementation checkpoint (2026-08-26): milestone 5's guest/native authority
split has started at the actual dispatch ABI. The canonical runtime compiler
now projects every checked closure indirect site into an immutable record of
its source transfer, canonical call-event or terminator identity, and exact
sorted guest target set. The behavioral-C event ABI carries the source
transfer RVA, and computed calls and jumps resolve through that exact site
record. The native resolver no longer treats membership in the module-wide
transfer inventory as authority. Unknown sites and other globally valid but
site-disallowed transfer RVAs fail closed; only after guest resolution fails
may the separately checked native external/callback path apply.

The synthetic canonical runtime slice now contains two valid behavioral
transfers while its indirect terminator authorizes only one. Its serialized
runtime plan and generated C table preserve that distinction, and an
architecture regression asserts that the resolver does not consult the global
transfer count. The native-module fixture now builds a real PE32 original,
derives canonical environment, closure, ingress, activation, behavioral-C,
and shared-runtime packages, and runs the actual native build-plan compiler and
linker. The resulting linked-skeleton manifest binds the exact closure and has
no runtime-core-package input. A process root without a checked process-
termination support import now fails closed rather than emitting a latent
termination path. The internal linked skeleton is deliberately not executed as
a deployed Wine candidate: loader composition must first realize its imports,
relocations, and loader surface.

Focused canonical-runtime and activation tests, native ingress/model tests,
the strengthened `native-module` Nix integration check, the retired-
architecture gate, and the full `target-gnu-hello` check pass together. The
runtime now keeps independent, locked generations per exact callback
capability, supports overlapping invocation generations, rejects foreign
threads for nonescaped generations, atomically publishes escaped generations,
and expires one-shot, replacement, resource-event, thread, and process
lifetimes without a global engine lock. Exact registration-site identity is
preserved even when several capabilities share one target and bridge address.

The Wine runtime acceptance fixture now invokes a reviewed 12-byte `stdcall`
DllMain frame through the same generic assembly bridge as exports and
callbacks. It checks process attach, thread detach/reattach, thread-local and
process-wide capability expiry, image-generation invalidation, and rejection
of capability publication after process detach. Loader lifecycle effects are
committed only after successful semantic execution and preserved-state/stack
checks. Nonempty generic BoundaryLifecycleV1 effects remain an explicit
blocker unless their checked resource borrow can be projected exactly through
the same physical-frame transducer; they are never silently discarded.

Allowed outcomes are now executable authority at ingress rather than unused
table metadata. A normal return from a no-return-only boundary is rejected,
and each bridge carries an exact flattened inventory of the SEH protocols it
may use. Both synthesized transfer faults and hardware exceptions consult that
per-bridge inventory; an otherwise matching module-global SEH protocol cannot
handle a fault for a boundary that did not authorize it. The Wine fixture
vetoes both the no-return violation and this cross-boundary SEH escalation.
The ordinary ingress-finish failure path now restores the captured host frame
and returns a deterministic failure instead of executing the diagnostic trap;
the exceptional-recovery invariant trap and portal sentinels remain pending.
Callback publication is transactional as well: a newly activated generation
is owned by the current ingress until the checked outgoing call commits it.
Normal failure, recovered hardware exceptions, and unwind notifications expire
all still-uncommitted generations for the abandoned ingress; successful
escaped registrations are explicitly committed, while invocation-local
registrations are revoked. The Wine fixture exercises both rollback and commit
and confirms that a recovered exception cannot leak its pre-fault capability.

The shared runtime plan/layout modules and active formats have completed their
clean-cut rename. The obsolete 1,170-line runtime-core test fixture was also
removed; native-ingress tests now use a focused 181-line fixture module. The
native-module integration fixture now continues past the internal linked
skeleton through the sole public PE composer. Its real MinGW PE interface,
derived section object authority, ingress plan, qualified behavioral-C
package, portable overlay, shared runtime, production skeleton, relocation
inventory, and native link receipt are content-bound in one chain. The
composer regenerates the candidate loader surface, a second interface decode
and loader-surface-v2 receipt agree with it, and Wine executes the composed
candidate with exit status zero. A content-addressed observation runner records
the exact candidate hash and loader trace, verifies that the target image and
every imported DLL occurred in that trace, and emits a qualified one-module
observed-load graph. This exposed and fixed stale runtime qualification logic:
runtime symbols may live in any canonical runtime C unit, and a valid
`typed_native_x87_handler: false` value is no longer mistaken for a failed jq
query. It also removed the integration check's duplicate ad-hoc linker in
favor of the production native-linked-skeleton path.

This synthetic fixture does not claim a complete module deployment: its one
transfer is intentionally synthetic and therefore lacks genuine original ISA
qualification. The deployment reducer must not be satisfied by invented test
authority. Complete deployment and project completion remain blocking work for
the real Hello and DLL vertical slices, where exact static authority can close.

The stock-Hello qualification campaign subsequently exposed two concrete x87
soundness defects rather than being bypassed. The Lean kernel's extended-80
encoder had used an implicit-leading-bit binary encoding for an explicit-
integer-bit format, and subtraction negated a NaN before selecting its payload.
Both are corrected. The Bochs adapter now reconstructs the full architectural
tag word for every nonempty register, matching the FSAVE-style contract rather
than comparing Bochs's abridged internal tags. Across the complete 323-form,
21,109-occurrence Hello campaign this removed every Lean veto: 313 forms are
qualified and ten remain honestly disputed because Bochs and Unicorn disagree
on x87 exception-status bits. Hello's primary frontiers fell from the original
118 to 77 and dependent occurrences from 305 to 182; the remaining 38 ISA
frontiers are those unresolved external-oracle disputes.

The same investigation closed a native-ingress completeness hole. The generic
bridge previously captured only GPRs and EFLAGS. It now captures and
transactionally restores the complete x87 stack and environment on success or
failure. Its FNSAVE conversion also now respects the actual split encoding:
the tag word names physical registers while the 80-byte register area is in
logical ST(0)..ST(7) order. The correction is shared by ingress and outgoing
native x87 helpers. The Wine acceptance suite enters with ST(0)=1.0, verifies
that exact canonical input, returns ST(0)=2.0, and observes 2.0 in the host;
the complete native-module link/composition/observation integration check also
passes with the corrected runtime.

The temporary generated `ud2` paths are also gone. Exceptional recovery now
retains the immutable host capture before invoking guest recovery and restores
that frame with a deterministic failure result if finalization rejects the
recovered state. Only an impossible missing-capture invariant uses the Windows
fast-fail interrupt. Exception portal symbols are inert address anchors and
fast-fail if executed; missing process-termination authority likewise cannot
fall into an illegal-instruction diagnostic loop.

Physical frame handling is now an explicit derived transducer rather than an
implicit consequence of copying registers. Each ingress descriptor projects
its checked frame slots onto the one faithful capture representation and binds
that projection by hash. GPR, EFLAGS, x87, and callee-entry stack fragments are
covered; XMM/custom banks, abstract memory slots, unknown phases, and mismatched
stack coordinates produce a stable incomplete-ingress blocker. The runtime
consumes the same projection and validates every input and output stack range
against the captured host stack before executing guest C. The reviewed
12-byte DllMain frame exercises three real stack arguments under Wine.

The shared runtime's reference callbacks now consume the exact
`machine-object-authority-v2` artifact. The authority is a required
content-bound runtime-package input, is copied into the package inventory, is
revalidated during native build, and must match the authority ID named by the
ingress plan. Generated C tables preserve each rule's domain, object,
generation, extent, permissions, locator offset, and interior-pointer policy.
Resolution and realization no longer synthesize whole-image, whole-stack,
TEB-window, or dynamic-allocation origins. Loader-relative image, module-TLS,
resolved-data-import, and invocation-local captured-stack locators are realized
exactly. A data-import rule is
bound to the resolved environment's exact module IAT-slot identity and reads
the loader-written provider pointer from mapped memory before applying its
checked anchor offset; an absent or stale slot fails closed. A captured-stack
rule binds one exact checked physical-frame identity, resolves relative to the
immutable caller ESP already held by the active TLS ingress frame, validates
its full extent against the saved host stack bounds, and uses that frame's
dynamic generation. Nested ingress therefore selects its own frame, and the
reference expires automatically when the existing frame chain is popped or
abandoned. Equivalent physical frames that share one bridge are represented
by one bridge-local selector set rather than duplicate native addresses.
Unknown frame IDs, non-stack kinds, non-invocation lifetimes, absent active
frames, overflow, or out-of-bounds extents fail closed. The real PE32
link/composition/Wine observation slice passes with this single authority
registry, and the ingress Wine suite exercises successful concurrent
captured-stack lookup plus rejection after frame teardown. External-allocation
and range-backed resource locators now bind one exact checked external-call
contract to the existing external-range lifecycle: the range supplies its live
base, checked size, generation, and release event, while the sole object rule
supplies its stable domain/object identity, permissions, slice offset, and
extent. Multiple live objects from the same contract share the stable object
identity but receive distinct lifecycle generations; realization selects the
exact live generation and a released generation expires. Unknown or multiply
matched contracts and multiple object rules claiming one range contract
produce stable blockers. The generated 32-bit runtime, full PE
link/composition, and Wine observation gates pass with the combined table
layout. Focused binding tests cover allocation and resource success plus
missing and ambiguous contract selection; a package test also verifies that an
unknown allocation contract remains incomplete. Resource identities created
only by provider callback/event protocols still require those lifecycle events
to feed this same range registry; they are not silently treated as permanent
memory objects.

The shared runtime ABI and V5 overlay path now carry an optional
exact authority-rule selector on every reference resolution. V5 bindings
normalize selectors as `{authority_id, rule_id}` pairs; implementation checks
reject duplicate, unused, unavailable, or unknown rule identities, and
generated state, view, and external-reference-result transducers pass the
selected rule directly to the sole runtime registry. Unselected projections
remain explicit null-selector calls and retain unique-origin resolution rather
than gaining implicit authority. A generous Hello target rebuild covers every
authored component, while a focused program-name-selection slice proves both
selector emission across state/view/service-result boundaries and fail-closed
rejection of a stale rule. Actual process argv, allocation, and resource
selectors remain empty until their runtime locators have genuine authority;
the migration does not invent those objects.

Portable-component implementation reduction now binds the exact canonical
`machine-object-authority-v2` digest into both its compile and machine-binding
facet receipts whenever an authority registry is supplied. The reducer also
requires that registry's original-PE binding to equal the component machine
binding. Changing an object rule, selector target, permission, extent, or
lifetime therefore changes the implementation receipt rather than being
validated against an unrecorded ambient artifact. Generated library components
with no object selectors may still be constructed before module object
authority exists; they receive no implicit selector or authority claim.

The native provenance and deployment contracts have now made their planned
clean cut. `native-module-build-plan-v2` and
`native-module-link-receipt-v2` are the sole active link contracts;
`pe32-module-deployment-v3`, `pe32-project-load-plan-v2`, and
`pe32-project-completion-v3` are the sole active deployment/project contracts.
All in-tree Python, Nix, fixture, and SDK readers migrated together. Their
superseded literals remain only as retired domain declarations, and the format
registry plus retired-architecture gate reject any production reader that
reintroduces them. Native PE link/composition/Wine observation, two-image
project planning/completion, format-registry, and retired-boundary checks pass
on the new literals.

The Behavioral-C artifact family has completed the same cut. Plan, package,
lowering, coverage, build-manifest, runtime-qualification, and completion are
now active only at v2 and bind `executable-transfer-plan-v2`; source-map and
presentation layout intent remain at v1 because their contracts did not
change. Every in-tree gate, fixture, and unit reader migrated before the seven
v1 literals were declared retired. Differential C/evaluator coverage, shared
build infrastructure, native link/composition/Wine observation, format
registry, and retired-reader checks pass with the v2 package chain.

`pe32-module-deployment-v3` now takes the exact
`module-execution-closure-v2` artifact as a first-class input rather than
trusting its identity only through the link receipt. It validates the closure's
canonical digest and closed authority state, requires its transfer-plan binding
to match the deployed plan, requires the v2 link receipt to bind that same
closure file, and records the closure in the deployment's own content-bound
input catalog. This closes the keystone transfer → closure → link → deployment
edge directly. The 439-derivation GNU Hello regression passes after the
Behavioral-C v2 and native/deployment contract cuts, so no target-local reader
still depends on the retired literals.

The current jq and DX-Ball target regressions also pass on the consolidated
contracts without changing their authority conclusions. jq retains its
structural, lifecycle, callback, and semantic blockers. DX-Ball compiles its
9,008-function Behavioral-C package and retains missing exact cutpoints as
`execution_edge_outside_exact_universe` closure blockers. That DX-Ball slice
exposed and closed a canonical-consumer divergence: the native reference-plan
parser had rejected finite-control routes whose checked target was absent from
the lowered transfer universe even though both closure algorithms define that
condition as a non-authorizing blocker. The parser now retains the route, and
the native blocker payloads for roots, edges, finite-route conflicts, stack
projection, recursion, and worklist exhaustion match the Python reference
schema. A differential regression proves the out-of-universe route cannot
authorize execution. This preserves evidence instead of inventing a cutpoint
or aborting before closure analysis can explain the missing authority.

`machine-object-authority-v2` and the three live interaction-contract formats
are now typed entries in the component domain's generated format registry
rather than grandfathered string constants. Registry generation therefore
checks their owner, codec, active state, and reader inventory, closing the
format-infrastructure exception around the sole object registry.

The authority graph now has one proposal-independent checked indexed-table
primitive shared by proposal construction and checker replay. It proves a
selector bound on every direct predecessor path, substitutes exact register
and flag outputs (including stack-loaded byte and dword selectors), requires
one immutable `PE32CodePointerSlotV3` per table element, and resolves every
slot to one exact unit identity. Structural target rows are no longer used to
seed these proposals. On stock Hello this closes all seven previously
identified switch tables (RVAs 0x374a, 0x382f, 0x3f00, 0x408a, 0x5898,
0x5e3f, and 0x12eef) as authorizing parametric summaries with exact support
dependencies. They are beyond the current root-reachable frontier, so the
honest module closure remains 4,495 units, 6,052 edges, 59 blockers, and
16,109 witnesses; only its content hash changes.

The exceptional-transition path now obeys the same canonical-IR constraint.
Each transfer source binds the exact machine-unit content digest, each
`divide_if` carries its exact authority-graph fault index, and the narrow
transfer-domain join accepts `exceptional-transitions-v5` only when its PE,
unit content, stable transition identity, and fault identity all agree. The
Python and native closure kernels emit the same authorizing transition digest,
canonical operation, and causal root-RVA set. Canonical operation-registry
metadata owns the mapping from `divide_if` to the native PE32 exception code;
the authority graph still exclusively owns infeasibility, handler, and terminal
dispositions. Native ingress now derives its checked outcome/SEH protocols,
portal symbols, and exception-escape support requirement from those closure
rows. The former Nix and CLI outcome/SEH inputs have been deleted and an
absence gate prevents their return. The resolved environment separately
catalogs the checked `RaiseException` runtime-support contract from the
canonical transfer requirements, while the composer imports it only when a
root-reachable checked terminal outcome requires escape.

The old raw-machine-IR C expression/transition renderer and its parallel
`c_domains` tables have also been deleted. The canonical transfer renderer now
imports only a semantic-free C helper-text module, and an absence gate names
both retired modules. This removes a complete alternate lowering path rather
than merely renaming it.

On stock Hello the one reachable integer-divide fault is now an exact checked
terminal continuation rather than a manufactured test waiver: the exception
blocker count falls from one to zero while all unrelated indirect-target,
external-write, and callee-effect blockers retain their meaning. Checked
handled transitions without a state certificate remain deliberately incomplete
on `checked_exception_handler_state_projection_unavailable`; the later V4 cut
below adds the first checked no-unwind handler-state path without granting x87,
exception-record object, or unwind-composition authority.

The final exceptional-outcome vertical-slice regression originally bound
closure digest `c3d1d5c193d22f93a97c3e081f493fb05f4036d5a94a82868b08e89b843ff0e6`;
the canonical access-violation registry extension now binds
`23ca43d066042ebf5ea424708e00b18a4dfbe62127cbc26c02b8a9569dd0e342`:
4,495 reachable units, 6,052 edges, 16,109 witnesses, 181,836 worklist steps,
and the same 59 unrelated blockers (21 indirect targets, 20 external write
footprints, and 18 callee-effect instantiations).  Its sole exception row binds
the exact transition digest and canonical `divide_if` operation to process
root RVA `0x1420`.  A separate target gate verifies that native ingress derives
the continuable `0xC0000094` SEH identity, process-root termination policy,
candidate portal, and separately tagged process-termination support contract
from that row. Callable-root escape alone requires the generated
`kernel32.dll!RaiseException` support import; a process-root terminal exception
does not. The full GNU Hello regression passes with these stronger checks;
this does not waive the remaining 59 blockers.

The canonical closure context now also carries each checked external-memory
write's optional `machine-object-authority-v2` rule selector. Resolution
accepts the selector only when it names an exact authority rule, and the
Python and native fixed-point kernels require every contributing object or
object-view atom to have that identity. Unknown selectors produce the stable
`external_memory_write_authority_selector_unknown` contract blocker; a
runtime provenance mismatch remains an
`unresolved_external_memory_write_footprint` blocker instead of widening to a
different object. Matching, mismatching, malformed, and Python/Rust parity
tests pass. A from-source GNU Hello target rebuild also passes without
changing the pinned closure digest or its 59-blocker inventory.

Boundary lifecycle lowering now follows the same consolidation rule. A
nonempty `BoundaryLifecycleV1` is no longer rejected merely for being
nonempty: transient shared and mutable borrows of a checked resource value are
lowered into the existing physical-frame transducer when one complete
identity word is available in an ingress GPR or callee-entry stack slot. The
derived table is content-bound to both lifecycle and physical-frame identity,
validated again before C generation, and preflighted before semantic
execution. Ownership transfers, nested field paths, partial words, unsupported
locations, and plain untyped values remain exact blockers. The current Hello
exception callback therefore remains honestly incomplete with
`lifecycle_value_not_resource`; its argument is still a plain checked value,
not an invented `exception_context` resource. The native-ingress Wine suite,
102 focused canonical transfer/runtime tests, and a fresh full GNU Hello
target rebuild pass with this stronger boundary. This is one section of the
generic ingress transducer, not a new lifecycle runtime.

Implementation checkpoint (2026-08-26): the production Python domains have
been split behind their existing public facades so that closure, provenance,
semantic-path, native-ingress, native-runtime, and parametric-dataflow
responsibilities remain independently reviewable without introducing another
artifact, authority, or semantic adapter. Repository architecture checks now
enforce those boundaries and pass without relaxed size limits. The retired
Candidate Authority V3, load-image candidate, callback-specific authority, and
v3 external-runtime projection modules and tests have been removed. New Nix
phases use the shared content-addressed phase constructor, and the generated
domain-owned format registry now covers the sole object registry and live
interaction contracts.

The full root flake passes after these clean cuts, including the
canonical transfer evaluator and renderer, native reference-kernel parity,
V5 component refinement, behavioral-C differential coverage, native PE32
link/composition/Wine observation, format freshness, repository metadata,
architecture boundaries, and retired-system absence checks. jq and DX-Ball
retain their previously verified honest conclusions; DX-Ball still lowers its
9,008-function package and reports out-of-universe targets as blockers rather
than parser failures. The stock-Hello closure still has exactly 4,495 units,
6,052 edges, 16,109 witnesses, and 59 blockers. Its digest changed from the
earlier `f3e845...` checkpoint only because the evidence receipt deliberately
binds the refactored checker source: all 7,937 callback-authority record IDs
and every semantic closure row are unchanged. The exact provenance-bound
digest at that checkpoint was `c3d1d5...`; after adding canonical checked
access violations without changing Hello's graph or blocker inventory, the
current digest is
`23ca43d066042ebf5ea424708e00b18a4dfbe62127cbc26c02b8a9569dd0e342`.
The complete 589-check target flake passes from the final split source,
including jq, DX-Ball, all Hello V5 refinements, native/Python whole-receipt
parity, and the two-sample native closure resource gate. A split regression in
nested projected-value decoding was caught by the real Hello inductive
components and is now covered by a focused total-substitution test. The
benchmark phase also now renders one escaped argument vector instead of a
multiline optional shell fragment, so fixture and derived modes cannot omit
their explicit CPU or RSS limits through newline interpolation.

The canonical runtime-plan contract has made a further clean cut to
`module-runtime-plan-v3`. The former callback-passthrough class and serialized
inventory were always empty in the canonical compiler, had no runtime
consumer, and overlapped the checked code-capability registry. They are now
removed rather than retained as a nominal subsystem. The v3 parser requires
the exact top-level and count schemas and validates every reconstructible
count against its bound inventory; a v2-shaped extra passthrough field fails
closed. The domain registry marks v2 retired with no readers, and Python and
Nix absence gates prevent the class, field, policy token, or retired literal
from returning to production. This reduces the number of interacting runtime
concepts without changing executable behavior: all callback activation,
publication, expiry, ABI, and bridge identity remains owned by the one code-
capability registry. The same cut removes the plan's constant semantic-
coverage, execution-policy, module-image-policy, relocation-policy, and
authority-disclaimer objects. None had a downstream consumer: complete
semantic input is already enforced by loading the bound transfer plan, x87
address realization carries its own exact per-operation binding, and
relocation completeness is checked at link/composition. Keeping those
ceremonial fields would have advertised systems that did not exist. The
unused module-entry and code-target model are gone as well: entry authority
already belongs to the bound ingress plan, while guest and native code targets
already belong to the exact site-scoped dispatch and capability registries.
The duplicate input-transfer count and unreconstructible indirect-call
diagnostic were removed, leaving one transfer count and only inventory-backed
runtime counts. External-site rows now have an exact nested schema as well;
the always-null outer protocol, argument-count, out-interface, raw-instruction,
and contract-required copies were removed. Their one authoritative versions
remain in the checked external contract and canonical transfer plan, so the
runtime plan no longer serializes parallel descriptions that could drift.
Active validators, receipts, and diagnostics now use shared/module-runtime
terminology exclusively; the retired runtime-core literals remain only in the
format registry, and an architecture gate rejects both that terminology and
the former `EngineRep` model in production code.

An explicit consumer audit did not pretend that every older authority phase
was already removable. Launch-root closure, callback authority, indirect-
target certificates, and static replay still qualify upstream machine,
exceptional-transition, and checked external-boundary facts. They therefore
remain evidence producers until those inputs migrate. They are no longer
allowed to become downstream execution systems: an architecture gate rejects
their imports from the canonical transfer/closure packages and rejects their
phase receipts in Behavioral-C, runtime, ingress, link, composition, or
deployment Nix phases. This preserves necessary authority while making the
single-IR consumer boundary mechanically enforceable.

Post-cut verification passes the full root flake, the complete 589-check
target flake, the real PE32 native-module link/composition/Wine observation
fixture, native ingress, format freshness, production lint, repository
metadata, compile-all, whitespace, and the strengthened architecture gates.

The native-module fixture has now made the next vertical-slice clean cut: the
separate trivial deployed EXE has been replaced by a target DLL exercised by
an external MinGW host. Its exact original interface contributes a real
DllMain entry and an EAT with ordinal base 2, named ordinals 2 and 4 aliasing
one code target, an ordinal-3 hole, and a writable ordinal-5 data export. The
sole machine-object-authority registry derives that data anchor from the exact
non-executable image section and the ingress plan carries its loader-relative
locator, permissions, offset, and available extent directly into composition.
The same original DLL now has an eight-byte TLS template containing a nonzero
fixture pattern, sixteen bytes of declared zero fill, its original index cell,
and four ordered callbacks (two fixture callbacks plus the MinGW TLS
callbacks). The runtime is appended after the aligned original TLS extent and
its private stack is raised to the original DLL's two-megabyte stack reserve.
Every original callback gets a normal canonical transfer unit and the same
reviewed 12-byte generic TLS-callback bridge; no original callback address is
left live in the composed callback array.
Canonical transfer-v2 units and a total activation covering entry, export, and
callback units are linked through
the shared runtime and
generic ingress into the one public composer. Wine loads the composed DLL,
thereby invoking its generic 12-byte stdcall DLL-entry bridge, resolves both
names and ordinal 2 to the one linked export bridge, observes the hole as
absent, calls the portable implementation, resolves the data export by name
and ordinal to one mapped address, verifies its original bytes, mutates it,
and observes the same mutation through the ordinal pointer before unloading
the module. The callbacks use their checked module-handle stack argument to
record a deterministic rolling order witness in that same data anchor; the
external host verifies the exact four-callback process-attach order after
DllMain has run. The decoded candidate and loader-surface receipt independently
verify the original TLS prefix, combined extent, index, linked callback order,
and relocations. A second code export then drives eight external host threads
through the same linked DLL. Windows supplies each thread with the combined
TLS layout and invokes the generic TLS/DllMain thread attach/detach path. The
portable operation uses an actual IA-32 compare/exchange loop directly on the
shared mapped data anchor; after 4,000 concurrent calls the host observes the
exact final value through its loader-returned data pointer. This is real host
concurrency with independent per-thread ingress state and no scheduler,
broker, global engine lock, or simulated atomic history. The
third code export exercises same-thread nested ingress: its portable component
calls the already-linked faithful-C export through that export's one stable
generic bridge address, and the external host observes the nested result after
both ingress frames unwind. This closes deployed reentrancy through the
thread-local frame chain without a callback-specific adapter or singleton
active state. Two further exports exercise the checked SEH path. One returns a
canonical `divide_if` exceptional outcome; the runtime transports it through a
separately tagged, composer-built `RaiseException` support import, Wine's host
handler changes `EDI`, ingress immediately recaptures that physical context,
and the authorized guest resumption unit observes the change before restoring
the callable frame. The other performs a real IA-32 divide-by-zero inside the
linked portable component. The generated per-frame gateway catches it on the
private stack, selects the checked source-RVA protocol, and runs its authorized
guest handler and resumption units without exposing the exception to the host.
The candidate load config and loader-surface receipt bind the live gateway RVA
in the generated SafeSEH table.

The same module now also models a real callback registration site in the
canonical transfer plan and resolved environment. Its finite callback target,
physical frame, escape root, content-addressed capability, and one-shot
process-lifetime rule join exactly before runtime generation. A portable
registration overlay atomically activates and commits that capability, returns
the one stable linked callback bridge, and the external host invokes it from a
foreign Windows thread. The callback receives that thread's independent PE TLS
context and returns through generic ingress; a second invocation observes the
fail-closed value because the one-shot generation expired. The
loader-surface receipt and candidate-observed graph close over the exact DLL
hash. The host is bound as observation-runner evidence and is not linked into
the target or represented as a target-owned module. The fixture generator
fails closed if export ingress is requested without an exact original module
interface, and the Wine assertion on the ordinal hole is a deployed negative
mutation rather than a parser-only check. This consolidates DLL entry, export
geometry, linking, composition, and observation in the existing native-module
gate; it does not add another fixture pipeline.

The DLL slice now also crosses the deployment-only completion boundary. Its
instruction-free synthetic semantic units receive an exact, vacuous ISA
inventory qualification that refuses any decoded instruction, its portable
implementation is selected through a checked V4 dependency graph, and the
normal static release reducer emits the candidate-bound release-acceptance
receipt. The resulting `module-deployment-v3` binds the transfer plan,
execution closure, Behavioral-C completion, selected portable component,
resolved environment, object authority, ingress, runtime qualification, link
receipt, loader surface, structural receipt, release receipt, decoded
interface, and exact DLL hash. The one-module `project-completion-v3` then
consumes only that deployment and the Wine-observed load graph and verifies
that the observed target-owned hash is the deployed hash. While adding this
gate, the old project reader was found to enforce the retired narrower
deployment surface. Writer and all readers now share one domain-owned
`module-deployment-v3` structural codec, eliminating that duplicated contract
inventory rather than merely synchronizing two lists.

The deployed DLL slice now also proves that checked access violations travel
through the keystone IR rather than through a runtime-only exception table.
Ordinal 11 is owned exclusively by generated Behavioral C while the other
behavioral units remain in the portable-C overlay, making the activation and
dependency graph genuinely hybrid. Its exact machine fault compiles to the
canonical `access_violation_if(condition, operation, address)` effect. The
operation registry owns the continuable `0xC0000005` identity and the two
Win32 exception-parameter indexes; closure authority, the reference evaluator,
the Behavioral-C renderer, and native closure kernel all consume that same
effect. The shared runtime records the checked write operation and address,
generic ingress raises the exception through the separately tagged support
import, and the external Wine host verifies parameters `[1, 0x1badb002]`,
modifies `EDI`, continues on the same thread, and observes the authorized guest
resumption result. The broader closure differential initially vetoed the
change because the supporting native kernel still carried the preceding
operation-registry digest. Its parser and fixed point now recognize the new
canonical effect, and a native/Python receipt-parity regression covers the
checked access-violation continuation. This is an expansion of the one
transfer language and one generic ingress path, not an access-fault subsystem.

The same DLL now covers the complementary guest-handled hardware path. A
second access-violation export remains portable C and performs a real invalid
IA-32 write on the checked private stack. Its canonical
`access_violation_if` transition is `handled`, the per-frame generic SEH
gateway captures Wine's native exception before it reaches the host, selects
the source-RVA protocol, enters the authorized guest handler, and resumes
through the checked continuation. The external host deliberately installs no
handler for this call and observes the normal guest result. The link receipt
binds its exception portal and the loader surface retains the live gateway in
SafeSEH. Generated escape and real hardware handling therefore share one
canonical exception identity and one ingress mechanism.

The DLL slice now also closes the external-callee side of that guest-handled
path. Ordinal 13 is a generated Behavioral-C unit whose sole call is compiled
from checked machine IR into the canonical transfer call record. That record
owns the exact four stack arguments for the original semantic
`kernel32!RaiseException` import and the canonical `divide_if` exception
inventory authorized at that call site. Generated C stages those arguments
below the incoming return address before entering the ordinary checked outgoing
bridge; the original caller frame is therefore preserved while Wine executes a
real external callee that raises on the same thread. The resolved environment
and composed import table retain two separately tagged uses of the same loader
identity: one original semantic import for the guest call and one generated
runtime-support import for callable exception escape. The runtime plan stores
the original slot as an IAT RVA and derives its loaded address from
`__ImageBase`, which fixes the latent preferred-base assumption exposed by
ASLR when this first real semantic import executed.

When the external exception returns through the per-frame gateway, generic
recovery restores the outgoing-call chain, x87 stack, initialization state,
and nested-call depth to marks captured at ingress before dispatching the
authorized guest handler and continuation. The external host installs no
handler and observes the normal checked result from that continuation. This
proves that an original imported callee can fault, be recovered by guest SEH,
and resume through the same transfer, environment, ingress, and runtime
contracts as generated and hardware faults; it introduces no import-specific
exception adapter or secondary semantic table. After the clean cut, all 385
root-flake checks and all 589 target-flake checks pass, including the Wine
module observation and the full Hello, Hello-derived registration, jq, and
DX-Ball rebuilds. Stock Hello retains its pinned closure digest
`23ca43d066042ebf5ea424708e00b18a4dfbe62127cbc26c02b8a9569dd0e342`.

At that checkpoint, remaining milestone-5 work was still substantial: complete checked physical
reference transduction for the blocked locator kinds and selectors, remaining
ownership/nested lifecycle transitions,
declared nonlocal routing, and full unwind/finally cleanup without recreating a
second semantic pipeline. The generous DLL slice now covers reentrancy,
foreign-thread escaped callback activation/expiration, checked callable-root
divide and access-violation escape with continuation, and a guest-handled
hardware divide, hardware access fault, and original-import exception in the
candidate-observed module. Subsequent checkpoints below close deployed nested
handler selection and checked unwind/resumption execution; machine-derived
handler/scope extraction and the full declared-nonlocal inventory remain open.
existing generic-runtime coverage remains necessary but is not a substitute
for closing those authorities in deployed modules that actually require them.

The generic PE32 ingress gateway now resolves Windows' exact
`EstablisherFrame` back to the one ingress frame whose private-stack slice owns
that registration record. SEH search can therefore pass an unhandled inner
fault to an authorized outer ingress descriptor while retaining the inner
fault's canonical source RVA. Recovery abandons every intervening frame
through one cleanup primitive, restores its runtime execution marks, and
expires its uncommitted capability generation before invoking the outer guest
handler. The Wine runtime slice exercises a real nested hardware divide: the
inner descriptor has no SEH authority, the outer descriptor handles it, the
guest continuation returns normally, and the abandoned inner capability is
unobservable. Unwind notifications use the same exact establisher mapping and
cleanup primitive rather than blindly popping the current depth. This closes
generic nested-handler selection and abandoned-frame lifecycle cleanup.

Checked finally/termination effects also remain on the keystone path. Each
ordered `unwind_effect_ids` entry must resolve to a reachable transfer identity
in the exact `executable-transfer-plan-v2`; the ingress plan carries only its
content-bound ID-to-RVA projection, and the shared runtime dispatches those
units through the ordinary selected implementation table before the guest
handler. Unknown, unreachable, duplicate, unreferenced, or failed effects stop
the outcome fail-closed. The candidate-observed composed DLL now links two
portable effect units, runs them inner-before-outer for each of its three
guest-handled exception forms, and makes its handler reject an ordering error.
This closes the native executor and composed-module ordering slice without an
unwind-specific semantic backend. Deriving those ordered IDs from real
machine SEH scope/unwind authority, rather than the synthetic fixture's
already-checked protocol, remains required for general milestone-5 closure.
After the ordered-unwind extraction slice, all 382 root-flake checks and the
target-flake checks passed. The subsequent checked state-projection slice
first changed Hello's pinned closure digest when the canonical continuation
row gained its explicit null projection. The V4/V5 resumption clean cut then
changed the pin when that same terminal row gained explicit null resumption
identity/RVA fields. The domain-owned exception-format clean cut later changed
only the content-bound exceptional-transition phase-source and manifest
bindings. The call-occurrence completion then added explicit
`occurrence_kind = "effect"` and `call_index = null` identity to Hello's
existing continuation row and changed the exceptional-transition and resolved
environment bindings. After removing those two new fields and the changed
content bindings, the decoded receipt is otherwise byte-identical to the
preceding pinned artifact. The current pin is
`0ac5ff85fc01bdf88c0356be8619ac5ca544437056b14739329f893b6a918afd`.
Decoded transition records compare byte-for-byte with the preceding artifact;
its 4,495 units, 6,052 edges, 16,109 witnesses, 181,836 worklist steps, and 59
unrelated blockers are unchanged.

The production-authority contract is now a clean cut through
`exception-evidence-v4`, its V4 closure certificate, and
`exceptional-transitions-v5`. The checked handler certificate can bind the
handler, ordered `unwind_units`, the six-part state projection, and one exact
`resumption_unit_id` plus its semantic-unit content digest. The authority phase
independently joins the handler, every cleanup unit, and the resumption unit
against the semantic index, records those exact dependencies, preserves cleanup
order, and fails closed on a missing, stale, duplicate, or contradictory unit.
Older checked-handler methods remain valid with their deliberately narrower
meaning; no ingress configuration is allowed to enrich them.

The exception wire schemas now have one domain owner in
`spaghetti_extractor.authority.formats`. The generated registry marks the V4
evidence record, V4 closure certificate, and V5 transition record active and
marks the V3 evidence/certificate plus V3 and short-lived V4 transition
records retired. The authority codec and transfer-plan join import those
owned declarations instead of copying literals. Registry checks forbid a
retired schema reader in production, while the architecture gate separately
forbids the retired short graph kinds `exception-evidence-v3`,
`exceptional-transitions-v3`, and `exceptional-transitions-v4`; it does not
forbid the deliberately stable singular identity prefix
`exceptional-transition-v3:<digest>`. The root full suite passes after the
production-closure metadata refresh.

The transfer-domain join accepts only the V5 transition record, resolves the
resumption identity to the exact transfer/RVA inventory, and rejects
resumption for a noncontinuable native exception. The Python fixed point and
native reference kernel both compose projected fault state through each
ordinary unwind return summary, through the ordinary handler return summary,
and finally across an `exception_resumption` edge. Their whole canonical
receipts are byte-for-byte equal. Native ingress copies the checked resumption
identity and RVA only from that deployment-bound closure row; the shared
runtime executes the same content-bound target it already uses for ordinary
dispatch. This supersedes the earlier V4 transition checkpoint without
changing the stable per-fault `exceptional-transition-v3:<digest>` identity,
whose exact fault identity did not change.

The same V4 authority certificate can now bind an exact six-part handler-state
projection for registers, EFLAGS, x87, stack, exception-record fields, and
`CONTEXT`. Both the Python analysis and native reference kernel capture the
exact abstract state immediately before the faulting transfer effect. For a
handled transition with no unwind units, they project supported register,
EFLAGS, and stack coordinates into a handler context rooted in the original
causal root and add an ordinary `exception_handler` closure edge. A focused
vertical test proves that a pre-fault `eax` value reaches the handler while
unprojected registers become unknown, and a native/Python receipt comparison
proves identical fixed-point behavior.

Ordered cleanup transfers now remain on that same fixed point rather than
forming an exception-only evaluator. Each checked unwind identity resolves to
its exact transfer RVA, receives the preceding projected state through an
`exception_unwind` edge, and contributes its ordinary interprocedural return
summary before the next cleanup or handler is enqueued. Missing return summaries
and uninstantiable effects retain the explicit
`checked_exception_unwind_state_composition_unavailable` blocker. A two-cleanup
vertical test proves inner-before-outer edges and value flow, and the native
kernel produces a byte-for-byte identical receipt.

The next canonical-analysis slice materializes the supported IA-32
`EXCEPTION_RECORD` and `CONTEXT` views as ordinary reference-analysis objects,
plus the checked five-word handler frame that points to them. Exception code,
flags, parameter count, access-violation operation/address parameters, selected
integer registers, EFLAGS, ESP, and `ContextFlags` all come from the checked
pre-fault state and the transfer operation's one canonical native-exception
metadata row. Neither Python nor Rust contains a second exception-code map.
A handler vertical test follows `[esp+4]` to `ExceptionCode` and `[esp+12]` to
`CONTEXT.Eax`, then proves the value reaches its continuation; the native and
Python kernels continue to emit byte-for-byte identical receipts.

This remains a partial authority closure, not an inference shortcut. The older
handler certificate still reports
`checked_exception_handler_state_projection_unavailable`; x87 and unknown
record/context fields report
`checked_exception_handler_state_projection_unsupported`. Numeric
`ExceptionAddress` or `Eip` observations retain the exact
`numeric_original_exception_address_requires_pinned_layout` blocker.

Native ingress now realizes the bounded case in which the checked protocol
binds both the guest handler and an exact guest resumption. Each ingress frame
owns the active object addresses and projection masks; recovery materializes
the IA-32 20-word exception record, 50-word `CONTEXT`, and five-word handler
frame on that thread's checked private stack. Generated semantic memory access
consults the per-frame gate before ordinary stack authority: selected record
fields are read-only, selected context fields are readable and writable,
`ContextFlags` is read-only, cross-field or unselected access fails, and nested
same-thread ingress scans the active frame chain from inner to outer. After the
handler, its local register state is discarded, only selected `CONTEXT`
writeback is applied to the saved pre-handler state, and execution enters the
content-bound resumption RVA. The Wine ingress fixture proves a real hardware
divide whose guest handler reads `ExceptionCode`, writes `CONTEXT.Eax`, and
whose authorized resumption observes the new value. The generated Behavioral-C
native-module fixture carries the same runtime feature through linking,
composition, Wine observation, deployment, and project completion.

The authority-to-execution vertical is covered independently at every seam. A
focused authority test emits the V4 evidence certificate with exact handler,
ordered cleanup, projection, and resumption digests. A five-unit closure case
proves fault → inner cleanup → outer cleanup → handler → resumption state flow,
and its Python and Rust receipts compare byte-for-byte after metrics. The
production ingress derivation then proves it cannot substitute a resumption
from the fixture or operator configuration. The synthetic composed DLL remains
a veto-only execution fixture: it demonstrates the selected checked target in
the linked, composed, Wine-observed deployment but grants no authority to a
real module. The focused 444-test authority/closure/ingress batch and the full
root test-suite gate pass after the V4/V5 clean cut.

The exception-record object now supports one canonical, bounded chain rather
than a primary-only special case. Authority, the Python closure, the Rust
reference kernel, ingress derivation, and the native runtime share the path
vocabulary `ExceptionRecord[N].Field`, with a four-record total bound. A nested
projection is valid only at an exact checked external-call occurrence; a
direct synthetic fault cannot invent a source chain. Parent pointer fields are
selected implicitly, every selected record is materialized contiguously in
per-ingress scratch above the still-intact 64-KiB usable private-stack slice,
and the native gateway rejects truncation, cycles, missing links, surplus
links, and a fifth record. Nested numeric `ExceptionAddress` remains blocked
without an address-mapping authority. Primary-only protocols keep their prior
exact null-pointer rule and byte-stable closure behavior.

This is an extension of the existing checked exception-object memory gate, not
a new exception heap or evaluator. A focused call-origin handled transition
now compares the complete Python and Rust closure receipts byte-for-byte; the
negative closure cases prove direct-source and over-depth rejection. The
generated IA-32 runtime check compiles, links, and passes its Wine suite. That
suite now calls `ntdll!RtlRaiseException` with a real two-record chain on the
checked private stack; the generic gateway copies it while the native records
are live, the guest handler follows the rewritten local pointer and verifies
the nested code and terminal null, and the checked resumption returns normally.
The full native-module fixture also passes linking, composition, Wine
observation, deployment, and project completion with the enlarged stack-slice
ABI. This deployed chain is veto-only execution coverage and does not
manufacture semantic authority.

This does not invent missing continuation authority. A handled protocol with
record/context fields but no resumption retains
`native_ingress_exception_object_materialization_unavailable` with
`required_authority = checked_guest_resumption`; the renderer independently
rejects such a handcrafted plan. Nested `ExceptionRecord` projection and
writable `Eip` resumption initially remained fail-closed until their own
authority and runtime rules existed. The focused checkpoint passed 46
authority, closure, ingress, and architecture tests plus production lint,
metadata, module-execution-closure, native-ingress-runtime, native-module,
Wine, and deployment gates.

The pinned-layout follow-up closes the previous pre-link self-assertion hole
without pretending that an operator-supplied promise proves its future
candidate. The clean-cut `pinned-code-layout-authority-v2` binds only the
original image, canonical resolved-environment identity, required load base,
selected numeric fields, and exact source/candidate RVA equality. It cannot
contain the not-yet-existing candidate or linker-map hash. Unreferenced
authorities and authorities for another original image make ingress planning
incomplete. Module deployment supplies the post-link realization: it binds the
actual original and candidate hashes, actual linker-map hash, every required
RVA equality, and the decoded candidate base. The candidate-observed project
receipt then checks the actual loader base. Missing bindings, a stale
environment, candidate mutation, or relocation away from the required base
fail closed at their owning phase.

The generic exception-object transducer now admits a checked `CONTEXT.Eip`
field only under that pinned policy. It materializes the source address and,
after the guest handler, accepts either the unchanged source address or the
one content-bound resumption address; any other `Eip` write fails closed before
logical resumption dispatch. Numeric projections and the protocol's observed
field inventory must agree exactly. Focused model tests plus production lint,
native-ingress Wine, linked/composed module Wine observation, deployment, and
project completion pass. The later positive vertical closes loader-base and
candidate-observation realization without forcing the high-RVA Behavioral-C
payload itself into original code slots.

The runtime-side follow-up starts with a genuine consolidation rather than a
fifth projection of the same layout. Thread-header, ingress-frame,
machine-state, diagnostic, runtime-context, and private-stack geometry now has
one Python owner in `native_ingress_runtime_abi.py`; model validation, assembly,
header, and C-source renderers import it. The same owner renders the complete
TLS region catalog. A repository architecture test rejects any copied ABI
assignment in another native-ingress module, and production lint, metadata,
native-ingress runtime, native module composition, Wine observation, and
deployment completion all pass after the consolidation. Any later exception
object region must therefore extend this one ABI instead of becoming an
independent layout system.

The public SDK boundary path has also completed its evidence-input clean cut.
A target protocol boundary now contains only its stable `kind:id` subject and
layout intent. The SDK obtains the semantic intent from
`external-environment-intent-v1` and injects the workflow-owned validated
`executable-transfer-plan-v2`, original binary, and callback-authority artifact
into the internal checker. The checker takes its exact machine-IR digest only
from the canonical plan and derives callback protocol identity from the intent
subject. GNU Hello no longer threads those facts back out through its target
definition. SDK assertions reject extra protocol-boundary fields, and
architecture gates prevent target declarations from reintroducing the removed
evidence inputs or the checker from accepting raw machine IR. This reduces the
boundary path to one owner for intent, one owner for checked evidence, and the
same keystone semantic universe without changing its authority result.

The V5 component contract path now observes the same clean cut. Unit-inventory
and contract phases consume `executable-transfer-plan-v2` plus the independent
structural-unit artifact; they derive original PE, machine-IR, manifest, exact
unit-universe, and unit-RVA bindings from the validated plan instead of opening
the raw PE or machine IR again. The component workflow no longer accepts a raw
machine-IR argument. Unit inventories retain their upstream digest fields so
existing authority meaning is unchanged, while repository tests and the
architecture gate reject any direct machine-IR input being restored to either
phase. This makes the keystone plan the sole semantic input to component
binding rather than merely another receipt carried beside an independent
adapter.

Native linking has likewise stopped carrying raw machine IR as a parallel
candidate-build input. `native-linked-skeleton` and its public Python build API
now validate the structural-executable receipt, PE identity, behavioral-C
package, runtime, and implementation closure against the canonical transfer
plan's content and semantic bindings. The plan remains bound to its upstream
machine IR and manifest, but linking cannot reopen either input or reinterpret
them. Architecture and API-contract tests make this a permanent boundary. The
separate recovered-executable-data contract remains because it supplies mapped
original bytes and PE realization data intentionally excluded from the
semantic transfer IR; it is content-bound back to the plan's machine universe.
Candidate deployment and exact-runtime construction receive that narrow
contract directly, rather than retaining access to the enclosing machine-IR
package.

Reusable-library adoption follows the same rule. Its V5 authority phase now
derives unit ordering, entry/exit projections, PE identity, and machine/manifest
digests from validated transfer records. The checked-island receipt is joined
to those bindings, but the phase receives neither the original PE nor raw
machine IR. Library recognition remains a separate upstream analysis and does
not gain authority from this consolidation. The adoption checker itself also
uses transfer calls, terminators, and direct-control edges for boundary
crossings, external-event coverage, and indirect-exit requirements, so there
is no earlier raw-machine authority pass hiding in front of V5 construction.
Both library authority steps use the shared content-addressed JSON phase
constructor, removing the last bespoke shell/PYTHONPATH wrapper from this
adoption path.

A broad repository gate now permits raw machine-package loading only in the
named component-discovery and library-recognition proposal modules. Candidate,
component authority, library authority, boundary, and external-environment
domains fail if they introduce another machine-IR JSONL loader. This is the
architecture-level enforcement that `executable-transfer-plan-v2` is the
keystone rather than a convention followed by current call sites.

The synthetic composed DLL remains a separately checked execution fixture and
cannot grant production authority. Hello's terminal divide transition has no handler projection, keeps
the same 59 unrelated blockers, and the V5 clean cut now binds transition digest
`5286f368dd0247ce78b88603eae5c39626e5f6e15d61ad3b190085ac9ae7bd35`
and portal `spx_exception_portal_5286f368dd0247ce78b88603`.
The initial no-unwind and ordered-cleanup checkpoints remain recorded above.
After bounded exception-object materialization and the runtime-ABI
consolidation, the fresh 2026-08-27 acceptance run passes all 385 root-flake
checks and all 589 target-flake checks. These include exact native/Python
closure-receipt parity, PE32 ingress/project integration, composed-module Wine
execution, full Hello/derived-registration, jq, and DX-Ball rebuilds,
production lint, metadata freshness, reviewability limits, and
retired-architecture absence gates. The exception C templates now live in a
dedicated renderer, leaving the primary runtime source emitter at 1,561 lines
without a reviewability-limit waiver. This checkpoint closes the bounded
exception-object slice without introducing an exception-only evaluator. The
later x87 and process-root checkpoints below extend it; current milestone-5
exception gaps are machine-derived real-target handler/scope/resumption
evidence, the remaining nonlocal/unwind inventory, and any lifecycle or
object-authority forms still blocked by the target corpus.

Implementation checkpoint (2026-08-27): one generous declared-nonlocal
vertical now follows the keystone path end to end. `executable-transfer-plan-v2`
supplies the internal call, nonlocal terminator, and continuation; the Python
and Rust closure kernels agree on one exact active-ancestor transition in
`module-execution-closure-v2`, including the abandoned captured-stack frame
and empty checked unwind sequence. Behavioral C propagates the nonlocal status
through its ordinary recursive call frames, restoring each abandoned caller
ESP before the authorized ancestor consumes the pending route. The shared
runtime carries the exact transition table, rejects unknown or ambiguous
routes, and qualifies `outcome.nonlocal` only when the table is nonempty. This
does not introduce a second dispatcher or authority artifact.

The synthetic PE32 DLL assigns the caller, callee, and continuation to actual
generated Behavioral-C ownership, exports the caller through generic native
ingress, links the exact generated objects, composes the EAT, and observes the
result through Wine. The full native-module gate passes through loader-surface,
deployment, and candidate-observed project completion while retaining the
existing TLS, callback, atomics, reentrancy, data-export, and SEH cases. A
compiled host-C test independently exercises the same recursive propagation,
and malformed/unknown reference outcomes remain fail closed. This fixture is
veto-only and grants no production authority. General machine-derived
nonlocal discovery, multi-frame nonempty unwind/finally cleanup, persisted
abandoned-frame reference invalidation, and real-target coverage remain open;
unknown, ambiguous, out-of-universe, or root-escaping transitions remain
blockers.

Performance follow-up (2026-08-27): retaining full abstract caller states for
every call context made declared-nonlocal support impose work even on plans
with no nonlocal terminator, and the Rust kernel independently recomputed an
expensive callee projection when composing a known return and again when
enqueueing that callee. The Python and Rust fixed points now omit active-frame
retention when the canonical transfer plan contains no nonlocal outcome, and
the Rust kernel reuses the same per-visit projection just as the Python
reference already did. An isolated three-sample stock-Hello run retained the
exact 4,495 units, 6,052 edges, 489 contexts, and 181,836 steps in every
receipt; CPU times were 14,178 ms, 14,029 ms, and 14,018 ms, worst wall time
was 14,244 ms, and worst process peak RSS was 897,520 KiB. This is below the
unchanged 15-second/1-GiB veto. The full content-addressed Hello target gate
subsequently passed, including whole-receipt Python parity and its governed
three-sample performance derivation. Its end-to-end incremental replay still
took 20 minutes 55 seconds because changing the native closure kernel altered
the shared Python phase closure and rebuilt both primary and
derived-registration authority/ISA graphs plus 439 downstream derivations.
That is a cache-boundary and duplicated-evidence problem, not closure-kernel
runtime, and remains an effectiveness issue to fix without adding another
semantic pipeline.

Cache-boundary follow-up (2026-08-27): the monolithic PyO3 package was the
source of that invalidation fan-out. It combined artifact serialization, ABI
solving, library retrieval, and the transfer fixed point, so changing only the
last implementation changed the Python environment of every Nix phase. The
package is now split at the existing semantic boundary: the general native
accelerator contains artifact/ABI/library operations, while
`spaghetti-extractor-transfer-native` contains only the dense projection and
fixed point over the same serialized `executable-transfer-plan-v2`. General
phases receive the former environment; only the execution-closure phase,
developer test runner, and installed operator package receive the latter.
This is a build boundary, not another semantic system or artifact: both the
Python reference and native kernel still consume transfer-v2, and the native
result remains subject to exact whole-receipt parity. A governed architecture
check proves that the general phase environment cannot import the transfer
kernel and that the transfer environment contains both packages. Cold builds
of the separated packages took about 14 seconds for the general accelerator
and 47 seconds for the transfer kernel; focused core/transfer tests (53 tests,
one skipped optional case), the module-execution-closure gate, and the new
dependency-boundary gate pass. A transfer-kernel source edit therefore no
longer invalidates decoding, authority, ISA, component, or status phases.
The generous Hello replay exposed and closed one missed consumer: the
root-restricted component-proof closure was still receiving the general
environment. `component-workflow.nix` now requires the transfer environment
explicitly for that construction while its ordinary V5 phases retain the
general environment. The first one-time migration replay reached that exact
fail-closed import error after 16 minutes 26 seconds; after correcting it, the
mostly cached full Hello regression gate passed in 5 minutes 1 second,
including both closure constructions, the three-sample 15-second/1-GiB veto,
all V5 refinements, and the aggregate target checks. This validates the split
on a generous real-target vertical rather than only unit fixtures.

The replay also confirms the next effectiveness bottleneck. Hello still
constructs primary and derived-registration ISA qualification campaigns; the
primary `machine-ir-isa-selection-authority` phase alone remained CPU-bound
for slightly over three minutes, and a downstream closure identity change
still presents a nominal 439-derivation component/receipt tail before
content-addressed reuse closes it. Even after the target aggregate was warm,
an ordinary `candidate status gnu-hello --local` did not return within one
minute because it evaluates/realizes the enclosing graph rather than reading a
compact materialized status receipt. The next performance clean cut is
therefore to content-address target-independent ISA oracle evidence separately
from target projections, share it between primary and derived workflows, and
make read-oriented status consume an already-materialized compact receipt.
Repeated performance qualification remains a release veto, not a prerequisite
for status display.

Speed-first acceptance update (2026-08-28): link and closure work may use
substantially more memory when that buys lower latency. The governed semantic
link budget is 30 seconds of CPU and execution closure retains its 15-second
CPU budget. Peak RSS is measured but has no fixed pass/fail ceiling; only OOM
or sustained swap thrashing is an operational memory failure. This does not
relax canonicality, exact replay, or fail-closed validation. It explicitly
permits a phase to retain fully decoded canonical members, denormalized indexes,
resolved joins, memoized fingerprints, solver contexts, and output-ready
projections at the same time when that removes parsing or traversal. Prefer a
single large content-bound working set over memory-saving reconstruction,
eviction, compact-and-reexpand cycles, or multiple independently validated
representations. Persisted artifacts remain canonical and compact where that
does not cost hot-path latency; working-set shape is non-authorizing. The
benchmark codecs continue to report peak RSS, but their fixed RSS arguments and
failure branches are retired so a fast implementation cannot fail for using
otherwise available RAM.

Memory-policy implementation checkpoint (2026-08-28): the ordinary shard
runner no longer exports a memory limit or turns peak RSS into a verdict. It
records `peak_rss_kib` for diagnosis and gates only test correctness. The suite
aggregate no longer reinterprets resource classes as memory authority. This is
a deletion of policy and machinery, not a new cache subsystem: canonical
phases may retain one decoded, indexed, content-bound working set for as long
as their process needs it, while Nix remains the only persistent cache.
Any earlier checkpoint in this document that reports a fixed 1-GiB RSS veto is
historical evidence, not current acceptance policy. New semantic-module work
must optimize for latency first and may deliberately exchange substantially
more resident memory for fewer parses, traversals, joins, or derivations. RAM
capacity is not a design budget: rely on the host or Nix boundary for genuine
exhaustion, keep reusable decoded/indexed state resident, and do not introduce
eviction, compact shadow forms, or a project memory manager unless measured
swapping or OOM establishes a real need.

Speed-dominant working-set clarification (2026-08-29): available RAM is
intentionally generous, so retaining the complete decoded semantic module is
the default rather than an exceptional optimization. A hot phase should keep
its member table, dense identity maps, reverse edges, resolved provenance,
closure worklists, solver contexts, provider selection, and output projection
resident together when doing so avoids a second parse or traversal. Do not
spend CPU compressing, evicting, paging between project-owned forms, or
reconstructing facts merely to reduce peak RSS. Prefer process-local memoized
views keyed by the canonical member digest; they are non-authorizing views of
one semantic module, not new artifacts or cache systems. Persist only the
canonical module and independently required receipts through Nix. Performance
work is judged primarily by CPU time, wall time, invalidation fan-out, and
repeated-work counts; RSS remains telemetry unless the host actually swaps or
fails allocation.

The semantic-link performance receipt consequently carries only the CPU
acceptance budget. It still reports per-sample and peak RSS observations, but
does not encode even a nullable RSS budget: absence of a memory limit is part
of the checked architecture, not a large default that later phases may treat
as authority.

RAM-rich execution-policy confirmation (2026-08-29): speed takes precedence
over reducing the resident set by a wide margin. Production phases may retain
the complete decoded module, multiple directly useful indexes and projections,
solver contexts, generated fragments, and independent veto working sets at the
same time. Use all useful core parallelism even when aggregate RSS is several
times one worker's resident set. Do not introduce configurable memory tiers,
an eviction loop, a compact/re-expand hot path, or a mutable project cache.
Only measured allocation failure or sustained swapping justifies memory work,
and such work must improve end-to-end latency rather than merely lower a
telemetry number.

The first blocker trace under this policy retained the full Python reference
state for real Hello (4,495 reachable units, 6,052 edges, 181,836 worklist
steps, about 658 MiB RSS) and followed the initialized `.data` word at RVA
`0x200d0`. The loader image correctly classifies its value as the exact guest
code capability for RVA `0x143a0`; no PE decoding or initial-memory fact is
missing. Precision is lost only after `parse_options` joins a loop-back return
whose transitive summary contains an unresolved external write. The primitive
origins are the already checked `WideCharToMultiByte` and
`LeaveCriticalSection` footprints; their unresolved pointer arguments then
propagate `all_memory_invalidated` through internal summaries and erase the
otherwise exact code-pointer cell. More RAM cannot close this authority gap,
and globally widening the alternative lattice was already measured to make it
slower. The next precision experiment must therefore correlate only the
machine-used pointer inputs needed by these checked footprints, retain the
conservative fallback continuation, and prove unchanged root, exception, and
edge reachability in both Python and Rust before it may replace the current
result. It must not mark writable `.data` immutable or special-case the Hello
cell.

Parallel-veto implementation checkpoint (2026-08-29): the three independent
whole-module semantic-link samples and the three native execution-closure
samples now run concurrently in isolated forked workers. Each worker still
recomputes from the exact canonical inputs, compares its entire result with the
canonical artifact, reports its own process CPU/wall/RSS observations, and can
only veto. The verdict remains the worst CPU sample; no sample result grants
authority. On real GNU Hello the concurrent semantic-link veto passed with
26,879 ms worst CPU, 28,194 ms worst per-sample wall, and 751,960 KiB worst
per-worker RSS. Its wall cost is now approximately one sample instead of the
former sum of three, deliberately exchanging about three worker working sets
for lower release-gate latency. The same full target gate measured jq at
2,875 ms CPU, 2,881 ms wall, and 267,204 KiB per worker, and DX-Ball at
6,872 ms CPU, 6,964 ms wall, and 548,928 KiB per worker; all three target
aggregates passed. A separate diagnostic raised the global
reference-alternative bound from 16 to 256; it exceeded two minutes and about
900 MiB before termination while leaving the dominant unknown-scalar/exact-
reference join shape unchanged. Therefore do not globally inflate the lattice.
Spend memory on selective correlation and independently useful resident
indexes, not on alternatives that increase fixed-point work without closing
authority.

Relational-input rejection checkpoint (2026-08-29): a diagnostic extension
made dynamic-allocation pointers and unknown checked stack words unconditional
relational call parameters. On real Hello the native closure's apparent
blocker count fell from 59 to 30 and all external-write blockers disappeared,
but reachable units fell from 4,495 to 3,403, reachable edges from 6,052 to
4,634, and the checked exception continuation disappeared. Worklist steps rose
from 181,836 to 287,605. The reduced blocker count was therefore caused partly
by deferred callee-effect instantiation pruning downstream behavior, not by
closing authority, and the implementation was removed. Preserve this design
constraint: selective input correlation must keep an explicitly conservative
fallback continuation reachable and must preserve root/exception reachability;
it must not turn unresolved summary instantiation into silent graph truncation.
This leaves a two-phase conservative fallback inside the one closure algorithm
as a possible correctness experiment, but not as an assumed performance win.
Globally symbolic arguments and deeper call strings remain rejected.

Conservative-return checkpoint (2026-08-29): the one closure fixed point now
keeps a caller continuation reachable when a checked callee summary exists but
a relational memory effect cannot be rebound.  The continuation retains only
independently restorable register and callback facts, marks all guest memory
and memory effects invalid, drops dependent relations and constraints, and
keeps the exact `unresolved_callee_effect_instantiation` blocker.  It cannot
authorize execution.  Python and the Rust kernel implement the same rule, and
a focused regression proves that a non-memory result remains available while
memory is conservatively invalidated.  On real Hello this preserved all 4,495
reachable units, 6,052 edges, 59 fixed-point blockers, and the checked
exception continuation; the truthful closure identity became
`257ee5eff29faac169596ec0c329d4a37a9e5ba6805e7fbe2085760676eeaede`.
This closes the earlier graph-truncation defect without a second pass, cache,
context dimension, or authority path.
The isolated three-sample performance veto passed at 21,276 ms worst CPU,
21,372 ms worst wall, and 852,876 KiB peak RSS.  The added conservative state
therefore remains comfortably inside the 30-second speed budget; its resident
memory is telemetry, not a veto.  The complete root test aggregate, the real
GNU Hello target check, and independent Hello replay all pass with this rule;
the recurring Fontconfig cache warnings in the hermetic PE32 project check are
non-fatal and do not affect its successful result.

A paired high-RAM correlation trial then made opaque words relational only for
parameter identities already observed in a checked callee summary.  The broad
precursor again pruned the complete registration fixture from 266 to 259
reachable units and was rejected.  The demand-selected version restored the
fixture and the full Hello graph, but produced the identical closure digest,
blockers, and precision as the fallback-only implementation.  It was removed:
resident state is welcome when it eliminates work or closes real authority,
but a zero-benefit correlation mechanism is still architectural cost.

Affine input-word product rejection checkpoint (2026-08-29): a separate
diagnostic relation tracked equality with a function-entry register through
register moves, constant address offsets, stack saves/restores, memory cells,
and checked internal-call summaries without changing the concrete reference
value used for feasibility.  Focused save/restore and opaque `[input + 32]`
fixtures passed, but the generous real-Hello replay disproved the design.  The
broad product preserved 4,495 units and 6,052 edges while increasing
callee-effect instantiation blockers from 18 to 172 and worklist steps from
181,836 to 196,965.  Restricting relational memory effects to equalities that
had already survived a checked call reduced the regression to 30 blockers and
182,963 steps, but left all original 18 `___pformat_putc`/wide-putc failures
unchanged and added twelve new sites.  Exact pre-call inspection showed no
surviving entry-word equality in any failing state: the formatting-state
pointer is copied through long-lived frame storage and control joins, not a
simple preserved input word at that point.  The Python product, fixtures, and
all transport fields were removed before any Rust or public-format change.
Do not add a generic register-origin lattice for this problem.  A future fix
must use the existing object/reference memory semantics to retain the exact
formatting-state object through its frame slot, and must improve the real
blocker inventory before being mirrored or retained.

Object-scoped unknown-write rejection checkpoint (2026-08-29): a subsequent
experiment kept the unresolved external-write veto but replaced global memory
invalidation with whole-object ranges for shared objects and captured-stack
objects transitively reachable from the checked call arguments.  The
Hello-derived registration fixture remained complete at 266 units, 319 edges,
zero blockers, and 567 worklist steps, so the rule did not repeat the earlier
control-pruning defect.  Full GNU Hello nevertheless rejected it: the graph
and checked exception continuation remained exact at 4,495 units and 6,052
edges, but callee-effect instantiation blockers increased from 18 to 25,
worklist steps from 181,836 to 218,347, and the independent Python evaluation
took 201 seconds at about 990 MiB RSS.  Whole-object ranges created additional
interprocedural range-rebinding obligations and did not retain the one needed
formatting-state relation.  The Python rule and its focused fixture were
removed without a Rust or public-format change.  Do not represent an unknown
external write by enumerating every presently known object.  The remaining 20
external-write blockers arise at only four machine sites: two `memcpy` sites,
one `WideCharToMultiByte` site, and one `LeaveCriticalSection` site.  Close
their actual checked pointer/extent provenance or retain their causal veto;
do not exchange one global unknown for a larger set of synthetic range facts.

Delayed-fallback rejection checkpoint (2026-08-29): the closure next withheld
the already-required conservative return state until the exact relational
fixed point became quiescent, then enabled only the still-uninstantiable
callers in monotone waves.  This tested whether provisional fallbacks were
irreversibly poisoning summaries that later became exact without introducing
a second fixed point or representation.  The registration fixture again
remained byte-for-byte complete.  Real Hello produced the identical closure
identity, 4,495 units, 6,052 edges, checked exception continuation, and exact
59-blocker split, with 182,268 rather than 181,836 worklist steps.  Therefore
all 18 callee instantiation failures are final under the present reference
facts; none is merely a transient scheduling artifact.  The scheduling change
was removed.  Do not add phases or retractable state for this frontier.  The
next useful change must improve the machine-derived pointer facts reaching the
four external-write sites or leave their vetoes honest.

Input-shape specialization rejection checkpoint (2026-08-29): with the fixed
RSS ceiling already removed, a second experiment gave each exact checked
dynamic-allocation argument shape its own callee context and left opaque
invocations in the generic context. Allocation identities are finite and
call-site-derived, so this was the cleanest deterministic version of spending
RAM on selective correlation. A focused looping call fixture proved exact
Python/Rust parity and showed precise and opaque invocations remaining
separate. Real Hello nevertheless regressed: reachable units increased only
from 4,495 to 4,517 and edges from 6,052 to 6,079, while closure blockers rose
from 59 to 60, worklist steps from 181,836 to 260,787, worst three-sample CPU
from about 22.8 seconds to 30.4 seconds, and per-worker RSS from about 752 MiB
to 832 MiB. The checked exception continuation remained reachable, so this was
not the earlier pruning failure; it was simply more fixed-point work for no
authority gain. The implementation and fixture were removed. Do not add
context dimensions merely because memory is available. Spend RAM only on
memoized results and resident indexes that remove computation; judge any
precision dimension by whole-target wall/CPU and authority improvement.

Immutable-context memoization checkpoint (2026-08-29): the Python reference
evaluator and Rust native kernel now compute each function-context identity
and captured-stack-frame identity once when constructing the immutable
context, then retain those strings with the context. Previously every
parameter binding, return composition, exception projection, blocker, and
witness could reserialize the same root/function/call-string tuple and SHA-256
it again. Real Hello preserved the exact 4,495 reachable units, 6,052 edges,
59 closure blockers, checked exception continuation, 181,836 worklist steps,
and semantic closure identity while worst three-sample CPU fell from 22,864 ms
to 20,732 ms and worst wall from 23,475 ms to 20,817 ms. Peak per-worker RSS
rose only from 752,224 to 753,188 KiB. This 9.3% CPU reduction is the intended
speed-first trade: retained derived data inside the existing semantic object,
with no new format, cache service, authority path, or invalidation boundary.
A follow-up parent-to-child context lookup cache improved CPU by only 0.1%,
slightly worsened wall time, and was removed. Add memoized views only when a
generous vertical slice proves material repeated computation was eliminated.

Semantic-effect consolidation checkpoint (2026-08-28): runtime primitive
requirements are now a canonical, typed `semantic-object-v1` effect relation.
Each provider has one sorted row binding its declared platform symbol to the
exact semantic function symbols that require it. External provenance uses the
object's existing checked `external_call` relocations. The semantic linker and
native reference kernel consume those facts directly; their former private
`provider_sources` and `external_sources` projections have been removed, and
an architecture gate prevents their return. Independent replay still derives
the same facts from transfer-v2 and therefore remains a genuine veto rather
than trusting the new projection.

A deliberately generous Hello experiment first represented the runtime facts
as 17,266 additional relocation rows. It increased relocation count from
12,334 to 29,600, grew the module to roughly 31 MiB, and regressed the worst
link sample to 23,821 ms CPU and 1,016,564 KiB RSS. That shape was rejected.
The grouped relation retains five provider rows and 17,266 exact source-symbol
bindings without changing the structural relocation inventory. The final
real-target replay preserves Hello's 8,102 symbols, 12,334 relocations, 4,632
implementation requirements, and 74 blockers; jq preserves 4,868 / 7,087 /
390 / 73; DX-Ball preserves 9,243 / 12,327 / 811 / 37. All three exact
independent-replay and compatibility-closure parity gates pass. Their worst
three-sample semantic-link results are respectively 23,865 ms at 981,356 KiB,
3,622 ms at 345,008 KiB, and 9,071 ms at 721,236 KiB. Focused codec/link tests,
the Rust kernel check, target SDK, format registry, metadata freshness, and
retired-architecture gate also pass.

This cut removes a semantic side channel but does not itself provide the large
speedup sought. Hello remains close to its earlier compact result, which
locates the dominant remaining cost in repeatedly decoding and validating the
full transfer-v2 member in Python and again in the native kernel. The next
milestone-5 performance cut is a content-bound compact link view emitted with
the semantic object and consumed by the native worklist in one parse. Its
independent replay must continue to reconstruct and compare that view from the
full canonical transfer plan; it must not become a second executable IR or
weaken object validation.

The first follow-up removes one proven duplicate without changing a format.
The production builder had already decoded and range-checked all seven compact
reference-index sets for every same-pass native fact, then immediately invoked
the public linked-module parser and decoded the identical strings again. The
builder now tells that final in-process shape check that the indexes are
already validated; public and persisted-artifact parsing remains fully strict.
Hello's exact output, independent replay, and closure parity are unchanged,
while its worst three-sample CPU time falls from 23,865 ms to 23,180 ms (about
2.9%) at 985,456 KiB peak RSS. jq and DX-Ball retain exact replay and closure
parity with worst samples of 3,540 ms / 345,152 KiB and 9,013 ms / 721,260 KiB.
This is deliberately a local elimination of repeated work, not a trusted fast
path or another receipt.

Object-member consolidation checkpoint (2026-08-28): semantic linking no
longer accepts resolved-environment or object-authority values alongside the
semantic object, even as private Python parameters. It opens the exact checked
members owned by `SemanticObjectV1`. The semantic object now serializes the
total object-rule-to-symbol relation as `object_symbol_bindings`; strict replay
reconstructs it from machine-object-authority-v2 and the semantic declaration
table, and the native worklist consumes that relation directly. This removes
another independently reconstructed linker join without introducing a new
artifact or object registry.

The real cut binds all 7 Hello rules, all 7 jq rules, and all 3 DX-Ball rules
to exact semantic data symbols. New linked-module identities are
`3ba1e11f43d1e08a137f72d8834c184af09c356c4096f4c1d42db7e4c1935fd3`,
`5a7e87299ca02740c8d1e20d902e14b0c5fbcefe74d957c3ab059cbe61cff1b9`,
and `0d3ca3e8952269333cdb47f8216b4f138de08bdca034f64f357268eb56e2f338`.
Their symbol, relocation, reachable-unit, implementation-requirement, and
blocker counts remain exactly 8,102 / 12,334 / 4,495 / 4,632 / 74; 4,868 /
7,087 / 237 / 390 / 73; and 9,243 / 12,327 / 760 / 811 / 37. For each target,
deleting only `bindings` and `closure_sha256` from the pre-cut and post-cut
compatibility closures yields identical canonical bytes. Independent replay
and closure parity pass for all three. An isolated three-sample Hello run has
22,814 ms worst CPU, 22,908 ms worst wall, and 981,984 KiB peak RSS under the
speed-first CPU policy; RSS is recorded but not gated.

Content-bound link-view checkpoint (2026-08-28): the production semantic-link
operation no longer performs a full Python replay of the 38.5-MiB transfer
member immediately before passing the same member to the native worklist.
`SemanticObjectV1.load_link_view` verifies the existing semantic-object
self-hash, every exact member/content binding, the transfer-plan self-hash,
the strict module-interface, environment, object-authority, platform, and
exception members, and the compact link identities. It is not a new artifact
or executable representation. Public semantic-object parsing and independent
semantic-link replay continue to use the full strict loader.

The fast path is authority-safe because the same native invocation now
reconstructs and compares all transfer-derived compact facts used by linking:
the exact function universe, grouped runtime-provider dependencies, direct
control, internal/external/indirect calls, and finite-control relocations.
Corrupting either dependency or relocation relation fails before the fixed
point result can be accepted. Loader/object/environment facts remain checked
by their smaller typed codecs. An architecture gate permits the link view at
the one production call site only and forbids its use by independent replay.

On real GNU Hello, strict semantic-object loading alone took 4.676 seconds,
while the content-bound link view took 2.319 seconds. The byte-identical
three-sample semantic link then fell from 22,816 ms to 20,278 ms worst CPU
(about 11.1%), with 20,331 ms worst wall and 757,544 KiB peak RSS. A trial
that reserialized transfer-v2 again inside Rust merely repeated the already
content-bound self-hash check and erased most of this gain, so it was removed;
native semantic validation and compact-fact recomputation remain intact.
The same exact-output benchmark improves jq from 3,540 ms to 2,164 ms worst
CPU (about 38.9%) and DX-Ball from 9,013 ms to 6,120 ms (about 32.1%). Their
peak RSS values are 266,496 KiB and 540,960 KiB. All three runs compare the
new linked module and compatibility closure byte-for-byte with the pre-cut
canonical artifacts, so the performance change does not alter blocker meaning
or root-provenance closure.

External-callee exception occurrences now use the keystone path rather than a
second exception inventory. The semantic index appends each checked canonical
call operation to its existing total fault inventory; generic evidence records
the exact occurrence but remains incomplete and non-authorizing by default.
`exceptional-transitions-v5` may authorize the occurrence only by joining its
unit, event index, operation, and content digest to the same transfer-v2 call.
Both Python and native fixed points then propagate the checked
handler/unwind/resumption transition, while an absent join still emits
`reachable_call_exception_authority_missing` with the exact unit, instruction,
call index, call kind, and unresolved operation inventory. This extends the
existing semantic-index schema without creating another artifact family.

The native realization also retains one mechanism. Behavioral C stamps the
exact call instruction RVA into the existing `original_rva` state only while
invoking an exception-capable call, preserves it on an exceptional return, and
restores the transfer-entry RVA after a normal return. Ingress derivation joins
the continuation's occurrence identity back to exactly one transfer-v2 call
and emits that instruction RVA as the SEH portal selector. Independent tests
use a transfer at `0x1000` with its call at `0x1004`, so falling back to the unit
RVA is detected on either side. Missing or ambiguous joins fail closed. The
Python/native receipt tests, 89 focused exception/closure/ingress/Behavioral-C
tests, and the composed DLL link, Wine observation, deployment, and project
completion gate pass after this cut. Machine-derived real-target
handler/scope/resumption evidence remains the general authority gap; the
synthetic DLL cannot grant it.

The process-root terminal path is now executable through the generic ingress
bridge as well. Ingress support-import derivation distinguishes an unhandled
`terminate_process_root` protocol from callable-root exception escape, so an
EXE terminal fault no longer acquires an unused `RaiseException` import. The
generated descriptor records `process_entry` explicitly: it may establish the
initial image root while ordinary lifecycle-neutral exports and callbacks still
require an active image generation. After checked unwind, the runtime maps the
canonical divide, access-violation, or external fault to the shared terminal
status and invokes the already-qualified process-termination support path. A
Wine parent/child acceptance case proves the process entry exits with the exact
divide terminal code and never returns; the existing DLL callable-escape case
continues to require and exercise `RaiseException`. Focused unit, native
ingress Wine, native-module link/composition/observation, production-lint,
metadata-freshness, and retired-architecture checks pass after this cut.
The generous real-target confirmation then rebuilt GNU Hello through both full
ISA-qualification campaigns and all 439 downstream derivations, including the
content-bound closure performance budget, every V5 work package and selected
implementation, native ingress planning, and the aggregate target regression
gate. It passed without a Hello-specific exception bridge or an exception
escape support import.

The same clean cut then rebuilt jq and DX-Ball through their complete target
regression aggregates. Both generated V4 evidence and V5 transition artifacts,
resolved their checked environments, compiled behavioral C from transfer-v2,
and retained their pre-existing incomplete authority/ownership meaning. jq's
aggregate boundary and operator-whole component path passed; DX-Ball's DirectX
boundary, `directdraw-init` V5 interface, object authority, and startup-extended
activation path passed. Neither target acquired handler or resumption authority
from the migration.

Checked x87 handler projection now closes without pretending the provenance
lattice is a floating-point evaluator. The exceptional-transition domain owns
one typed vocabulary for the complete x87 stack and environment; Python
closure, native closure, and ingress rendering consume it, while unknown field
names remain exact projection blockers. Because an x87 value cannot itself be
an object or code reference, the reference fixed point carries no second x87
semantics and no longer emits the artificial
`x87_reference_projection_unavailable` blocker. Executable x87 behavior still
comes only from transfer-v2 and the qualified shared runtime. A Python/native
whole-receipt test includes an `all` projection, and the Wine ingress fixture
enters a real hardware divide with extended-80 `ST(0)=1.0`; its authorized
guest handler observes the exact pre-fault value after gateway capture. The
candidate-observed composed DLL repeats that proof through its portable
hardware-fault operation and shared guest handler, with the x87 projection
present in the deployment-bound ingress plan. The module-execution-closure,
native-ingress Wine, native-module deployment,
production-lint, metadata, Rust-format, and architecture gates pass for this
slice.

The keystone compiler now also proves exact occurrence coverage for the two
event families that could previously disappear between checked machine IR and
transfer-v2. Every aggregate external-event index must occur exactly once in
the instruction schedule, and every aggregate memory-event occurrence must be
owned by either an emitted canonical memory/atomic action or one exact checked
`typed_x87` operation. Duplicate or omitted events produce stable
`external_event_coverage_mismatch` or `memory_event_coverage_mismatch`
blockers. Typed x87 replay does not emit a second memory action: the compiler
instead checks that its proposal-level ordered inventory has the same event
identity and read/write direction, is a nonempty subset of the exact decoded
operand, and then records those occurrences as covered by the single typed
operation. Focused positive and negative tests cover this distinction. The
stronger invariant initially exposed GNU Hello's x87 accounting gap; after the
single-owner fix, full GNU Hello, jq, and DX-Ball target aggregates all pass
without changing their authority or ownership conclusions.
The first fresh root aggregate then rejected the enlarged transfer compiler at
1,715 lines. No waiver was added: typed-x87 event-shape validation moved beside
the typed x87 model, instruction/aggregate call-boundary normalization gained a
small dedicated transfer-domain owner, and the compiler returned to 1,586
lines (1,591 after adding the mixed-schedule call regression). Repository
reviewability, lint, metadata, architecture, differential,
execution-closure, PE32 project, native-module Wine/deployment/observation, and
the complete 342-derivation root aggregate pass after that consolidation.

Pinned continuable `CONTEXT.Eip` writeback now has one composed and observed
address path rather than a runtime-only numeric convention. For every pinned
protocol that projects `Eip`, native ingress still derives a stable linked
continuation portal for the live CFG/EH registry, but numeric exception fields
do not falsely identify that high-RVA bridge as original code. The sole PE
composer realizes one generic module-base pointer in the shared runtime.
Selected `ExceptionAddress` and `Eip` values are materialized as that actual
base plus the canonical source or resumption RVA, and recovery accepts only
those two authority-bound values before dispatching the corresponding transfer.
Semantic execution therefore remains in the transfer-v2 guest registry; no
low-RVA linker alias or second dispatch path exists.

The positive vertical is now end to end. The composed Behavioral-C DLL uses a
fixed reviewed `0x68000000` launch policy, its guest handler validates both
numeric fields from a real hardware divide, writes `Eip` to the authorized
resumption address, and completes through the canonical resumption transfer.
`pe32-load-observation-v2` records Wine's actual module base. Deployment binds
the exact candidate hash, linker-map hash, authority-v2 RVA inventory, and
canonical resolved-environment identity; project completion checks the
observed hash, environment identity, and actual base. A relocated observation
is a stable `observed_pinned_layout_base_mismatch`. The direct Wine fixture also
retains the source-retry case, proving that unchanged/source `Eip` selects the
source transfer rather than the alternate resumption. Both fixtures are
veto-only and grant no authority beyond their explicit checked inputs.

Derivation-free Python-source checkpoint (2026-08-28): the speed-first policy
now applies to phase implementation code as well as semantic data. The checked
Python module index records the exact SHA-256 of every module. Nix computes the
role/source-class closure from that index, rejects any selected module whose
source hash is stale, and imports the exact module/resource files as one
filtered source path. A separately content-addressed evaluation-time manifest
retains the phase role, roots, resource inventory, per-file hashes, and build
manifest binding. The former per-consumer Python copy/AST-validation
`runCommand` is gone; repository metadata freshness remains the one full AST
reconstruction check. This removes implementation packaging jobs without a
mutable cache, daemon, broad all-source dependency, or weaker standalone
fail-closed behavior. RAM is not a release optimization target: canonical
phases may retain decoded and indexed state until the host/Nix resource
boundary when that reduces wall time.
The real Hello recursive realization graph correspondingly drops from 1,882
derivations with 126 Python-closure nodes to 1,756 with none; 50 repeated exact
closure evaluations take 0.345 seconds with traversal rooted at `src/`.
The equivalent missing-output request schedules 294 jobs instead of 420, while
direct warm evaluation remains effectively flat at 37.786 seconds versus the
previous 36.9-second observation.

Semantic-input ownership checkpoint (2026-08-28): transfer-v2 compilation and
target ISA occurrence selection no longer belong to or emerge from
`authority-workflow.nix`. The SDK compiles `executable-transfer-plan-v2`
directly from the checked machine-IR package, derives one checked
`machine-ir-isa-requirements-v2` input against the qualified Lean kernel, and
passes both into semantic-object construction. The transitional authority
workflow may consume the exact ISA requirements for its occurrence projection,
but it cannot regenerate them or re-export transfer-v2. Architecture checks
enforce both dependency directions.

On real GNU Hello, the moved ISA input is canonically identical to the former
requirements payload: 323 forms and 21,109 occurrences with requirements
identity
`004ea5868ebcbf1476821aa3971ef7ccfe30409ff87033281817e5d24250209f`.
The native-realization closure retains 1,756 total derivations because the two
canonical producers replace two legacy producers one for one, but authority-
named nodes fall from 14 to 12 and no authority-named transfer or ISA-
requirements derivation remains. Warm realization evaluation is 39.009
seconds. This is a dependency-direction prerequisite for deleting the reducer,
not yet a fan-out reduction claim.

### 5. Split guest dispatch from native capabilities and finish the shared runtime

- Generate guest dispatch as immutable original-RVA → transfer → selected
  linked-symbol tables, including per-site allowed indirect target sets.
- Permit an internal indirect call only when its loaded guest code reference
  belongs to that site's closure-derived target set.
- Generate native capabilities only for process/DLL/TLS entry, exports, escaped
  callbacks, and authorized exception continuations.
- Bind native capabilities to checked physical frames, bridge-equivalence IDs,
  lifecycle generations, escape/expiration rules, and stable native addresses.
- Reject a capability used through incompatible physical ABIs; equivalent uses
  share one bridge.
- Generate one PhysicalCallFrame-driven IA-32 ingress template for all roles,
  with complete capture, TLS/frame-chain lookup, lifecycle/object/capability
  validation, checked argument transduction, private-stack execution,
  transactional writeback, outcome dispatch, and exact restoration.
- Preserve original TLS bytes and zero fill, append aligned runtime TLS,
  maintain callback order, and reuse or create the TLS index cell.
- Support same-thread reentrancy, foreign-thread TLS initialization, escaped
  capability publication, shared mapped bytes, checked guest atomics,
  deterministic private-stack overflow, and loader-lock-safe initialization.
- Complete normal, no-return, exceptional, and declared nonlocal outcomes;
  unknown nonlocal transfers fail closed.
- Complete SEH gateway capture, guest handler dispatch, unwind/finally cleanup,
  callable escape, process-root termination, continuable context recapture, and
  optional pinned numeric-address authority.
- Remove singleton active runtime state, global callback stacks,
  callback-specific bridges, runtime schedulers/brokers, and the temporary
  diagnostic `ud2`.

Exit: arbitrary RVAs and expired/incompatible capabilities fail closed, nested
and foreign-thread entry work through the generic bridge, and no interpreter or
runtime broker is linked.

### 6. Bind V5 components and libraries through static implementation selection

- Retain the current V5 interface/source/binding/work-package and V4
  implementation/dependency/activation families.
- Bind each operation directly to canonical transfer IDs, closure-derived
  entries/exits, object selectors, required services, callbacks, lifecycle
  rules, and allowed outcomes.
- Keep operation-symbol mappings total and exclusive; remove single-entry and
  adapter-generated semantic paths.
- Reduce compile, source, machine binding, semantic refinement, lifecycle,
  services, ownership, relation, and optional induction facets into one
  implementation record.
- Make the total activation plan choose exactly one implementation per owned
  unit: generated behavioral C, portable C, pinned binary, external
  environment, or blocked.
- Resolve generated-versus-portable selection at build time; prohibit runtime
  activation and silent fallback.
- Migrate existing qualified Hello components, including `ascii-to-lower`,
  through the static symbol map.
- Produce library behavior packs through the same
  contract/binding/implementation/dependency path while keeping recognition and
  operator adoption non-authorizing.
- Convert standalone component runtimes into harnesses over the shared runtime.

Exit: Hello links at least one qualified portable component alongside exact
generated-C fallback ownership, and the link plan contains one implementation
for every owned unit.

### 7. Rebind linking, PE composition, deployment, and project completion

- Make native-module-build-plan-v2 bind transfer plan, execution closure,
  object authority, external environment, activation plan, guest dispatch,
  native ingress, runtime qualification, and every generated/authored source
  and object.
- Make native-module-link-receipt-v2 bind exact object hashes, symbols/RVAs,
  bridge equivalence, sections, linker map, explicit relocation inventory, and
  final linked skeleton.
- Reject any behavioral-C or component completion whose exact object is absent
  from the link receipt.
- Keep one public composer over the internal skeleton. Generate entrypoint, EAT
  holes/aliases/code/data/forwarders, combined TLS, original/support imports,
  IAT metadata, relocations, resources, SafeSEH, CFG, and load-config pointers
  from decoded interfaces and linked symbols.
- Fail closed on unsupported pointer-bearing directories, load-config versions,
  delay-load forms, handler/CFG tables, ambiguous code/data imports, and
  incomplete relocation inventories.
- Emit loader-surface-v2 and module-deployment-v3 receipts binding the decoded
  candidate hash and every upstream authority/receipt.
- Make project load plan v2 check code protocols, data-anchor
  permissions/extents, forwarded final providers, loader-service evidence, and
  target-owned module hashes.
- Make project completion v3 consume deployments and candidate observations
  exclusively; a single module becomes a one-module project automatically.

Exit: the composer contains no semantic interpreter, all linked claims are
object-backed, and modifying the candidate or any bound receipt invalidates
deployment/project completion.

### 8. Pass a mandatory generous vertical slice

Use three complementary fixtures as one blocking gate.

#### Real GNU Hello

- Build from the actual PE interface and resolved environment.
- Prove from exact closure evidence that the linked but uncalled
  allocation-backed TLS-destructor path through `0xAB86` is unreachable in the
  stock binary; do not force it into the closure.
- Use generic process ingress, shared runtime, generated behavioral C for
  complete fallback ownership, and the qualified `ascii-to-lower` portable
  overlay.
- Produce build plan, link receipt, composed PE, module deployment, one-module
  project completion, and candidate-observed hash.
- Run the existing Wine output/exit suite.
- Require no Hello-specific bridge, target annotation, interpreter,
  unrestricted dispatch, or runtime fallback.

#### Hello-derived MinGW registration fixture

- Build with the same MinGW TLS destructor registration and execution
  machinery used by stock Hello, but include a real caller that registers a
  destructor and drives the list execution path through `0xAB86`.
- Recover the stored target solely from transfer-v2 reference provenance,
  allocation/object authority, and lifecycle rules.
- Require the generated behavioral-C backend, generic process ingress, shared
  runtime, deployment receipts, candidate observation, and a Wine assertion
  that the registered destructor ran in the checked order.
- Keep the fixture generic and independently reusable; it must not add an RVA
  annotation, Hello-only runtime hook, or alternate dispatch path.

#### Synthetic target DLL plus external host harness

- Exercise `DllMain` process/thread attach/detach, original TLS
  template/zero-fill/index, and multiple callbacks.
- Exercise named and ordinal exports, aliases, holes, a data-export
  anchor/interior view, and loader-owned imports.
- Exercise same-thread reentrant callbacks, foreign-thread callbacks with
  independent TLS, expiration, shared mutation, and atomic compare/exchange.
- Exercise guest-handled faults, host-import exceptions handled by guest SEH,
  exceptions escaping an export to a host handler, and one continuable checked
  context modification.
- Exercise EAT, TLS, relocations, SafeSEH/CFG/load config, link receipt,
  composition, deployment, and observed candidate hash.
- Treat the host harness as external-environment test infrastructure, not a
  target-owned runtime or support DLL.

#### Mandatory negative mutations

Reject unauthorized stored RVAs, incompatible physical frames for one
capability, expired callbacks, missing generated objects, stale link/deployment
receipts, post-link candidate mutation, unsupported pointer-bearing metadata,
unknown nonlocal outcomes, private-stack exhaustion, and numeric
original-address dependence without pinned authority.

#### Performance gate

From cached machine IR, require transfer compilation/validation below 5
seconds, execution closure below 15 seconds, combined canonical-IR Python work
below 30 seconds, and unchanged warm target status within the existing
1.3-second budget. Record peak RSS without imposing a fixed project ceiling;
OOM and sustained swap thrashing remain operational failures. Measure three
paired runs on the same host.
Prefer retained decoded state, dense indexes, direct tables, reverse indexes,
worklists, and wider shared working sets whenever they reduce CPU or wall-clock
latency; optimize invalidation and derivation fan-out before compacting memory
or introducing another implementation language.

Exit: both Hello and the DLL suite pass authority, deployment, observation,
negative, and performance gates. Differential tests remain veto-only and
cannot substitute for any receipt.

### 9. Migrate jq, DX-Ball, and complete multi-image behavior

- Generate jq V5 interfaces, bindings, work packages, and operation skeletons
  for its aggregate `jv`, lifecycle/refcount, callback, loop, and induction
  boundaries.
- Compile jq's aggregate and callback packages while retaining exact blockers
  wherever lifecycle, alias, callback, or semantic authority is absent.
- Migrate DX-Ball's `directdraw-init` first, then COM/vtable calls, resources,
  callbacks, shared data, TLS/DLL lifecycle, and SEH boundaries.
- Exercise DX-Ball's real single target-owned executable with loader-owned
  DirectX/Win32 providers, forwarded providers, dynamic resolution, resources,
  and observed distribution hashes. The installed 1.09 distribution contains
  no target-owned DLL, so do not manufacture one.
- Exercise target-owned multi-image code/data edges, forwarding, lifecycle,
  and observed hashes in the generic synthetic PE32 EXE/DLL project fixture;
  bind that fixture through the same project contracts used by DX-Ball.
- Do not invent operator intent, types, lifecycle rules, or portable
  implementations merely to close status.
- Preserve the distinction between repository migration, hybrid module
  completion, and zero-generated-C portable completion.
- Require portable mode to have zero root-reachable generated-C ownership;
  hybrid mode may use generated fallback but every unit still has explicit
  ownership.

Exit: all targets consume the consolidated contracts; Hello is deployed
complete, jq's structural/compile path is migrated with honest blockers, and
DX-Ball exercises the required multi-image and Win32/DirectX surfaces without
target-specific runtime machinery.

Jq V5 structural and compile checkpoint (2026-08-29): all 20 preserved
operator component boundaries now have content-bound V5 interface intents,
exact transfer-v2 unit selections, V4 contracts/V5 machine bindings, faithful-C
source slices, public headers, and operation skeletons. The old selectors were
used only to recover their exact unit ranges; no signature, effect, service,
callback, lifecycle, or outcome authority was inferred. Every binding remains
incomplete with the explicit
`portable_interface_semantics_unreviewed` and
`machine_effect_service_callback_outcome_projection_unreviewed` blockers.
The aggregate `output-value-pipeline` and callback
`math-error-callback-dispatch` additionally have independently hashed source
V3 packages. Their authored translation units and generated conformance units
compile under both host C11 and PE32 C11 with warnings as errors, while the
machine-overlay and semantic-refinement facets remain incomplete and neither
implementation is selected. The full jq target regression aggregate passes at
`/nix/store/q8vyacik93933wwh83assg7nngjb6ix3-spaghetti-extractor-jq-target-regression-checks`.
Current status remains honestly incomplete: the module subject has 72 blockers
and the default configuration subject has 68; the structural migration did not
turn compilation or tests into authority.

The same slice removed an accidental all-to-all refinement dependency. An
ordinary non-inductive component refinement previously bound every component
contract even though provider contracts are only read by the induction path.
It now binds only its own contract; the measured jq aggregate refinement edge
dropped from 20 component-contract derivations to one, and the nominal focused
build tail dropped from 136 to 97 derivations without a cache, new format, or
semantic shortcut. Inductive refinements retain their explicit provider inputs.

Component-proof working-set checkpoint (2026-08-29): the temporary internal
proof-kernel adapter no longer translates the complete target transfer
universe once per component refinement. It validates the one content-bound
component proof closure, translates only its exact `reachable_units`, and
fails closed if any closure identity is absent from transfer-v2. The temporary
manifest records both the projected and source-universe counts so accidental
whole-module projection remains visible, and the architecture gate prevents
restoring it. This changes no authority artifact and adds no cache, IR, or
derivation: it is a narrower in-process view of the already selected canonical
semantics. On the real targets the working rows fall from 7,937 to 104 for
GNU Hello, 4,614 to 23 for jq, and 9,008 to 94 for DX-Ball. The full target
regressions, including their honest incomplete blockers, pass at
`/nix/store/c170z63k21rxp84iwg6rhrpiznhmf615-spaghetti-extractor-gnu-hello-target-regression-checks`,
`/nix/store/67y8vjgmbvm8n9rmrg27h2kxda7djlqm-spaghetti-extractor-jq-target-regression-checks`,
and
`/nix/store/irzh2k3ndawdqyd9z0q4wffk6h2cxs9c-spaghetti-extractor-dxball-target-regression-checks`.
The compatibility adapter remains a retirement target: the end state is for
component refinement to execute transfer-v2 directly, not to preserve even a
small second representation.

Direct component-refinement clean cut (2026-08-29): that retirement is now
implemented. V5 refinement loads the exact checked transfer plan and component
closure once, retains the selected rows in memory, and passes their canonical
`transfer_v2` bodies directly to the symbolic path executor. The serialized
proof-unit JSONL, proof manifest, temporary directory, and
serialized transfer-proof-projection subsystem are deleted. Only narrow call-event
and atomic-authority views are derived for the checked logical boundary that
needs them; they are not executable bodies and cannot replace transfer-v2.
Semantic-contract bindings now name the exact transfer-plan and closure hashes
instead of laundering them through synthetic machine-IR hashes. Architecture
checks require the direct path and forbid the retired files and literals. This
is the intended simplification: one fewer format, file, parser, serializer,
digest layer, and per-component temporary I/O path, while keeping the same
closure scope and fail-closed checks. The first real-Hello run exposed the one
remaining induction helper that still read projected control fields; it now
derives SCC edges and guards directly from canonical transfer terminators and
expression nodes rather than restoring the adapter. Twenty-nine focused
ordinary/inductive refinement tests pass, as do the complete target regression
aggregates at
`/nix/store/h3h77d54n22s79ip306zwl7ns1d658a4-spaghetti-extractor-gnu-hello-target-regression-checks`,
`/nix/store/jl5mrf64mhbyp3r0hjd8xha5bhzngwmp-spaghetti-extractor-jq-target-regression-checks`,
and
`/nix/store/khfl7lsfrx2ssapdyi7ycxwpv2jx1i39-spaghetti-extractor-dxball-target-regression-checks`.

DX-Ball V5 and project checkpoint (2026-08-29): the five exact startup
cutpoints and `directdraw-init` are now all indexed V5 component inputs. Each
startup component binds its one original transfer-v2 unit and remains blocked
on unreviewed portable semantics plus machine effect/service/callback/outcome
projection. `directdraw-init` preserves its reviewed V5 resource/service
interface, binds exactly 86 original units in the historical `0xCC60..0xD006`
range, and carries one explicit machine-projection blocker. Its source was
ported from the retired context typedef to the generated V5 type; both the
authored translation unit and generated conformance unit compile cleanly under
host and PE32 C11. The portable implementation is still incomplete because
the machine overlay, service event binding, environment, and semantic
refinement are not checked, and it is not selected. The full DX-Ball target
regression passes at
`/nix/store/3167zy4mql0qhkyp11hrbzg2ar8p7xlm-spaghetti-extractor-dxball-target-regression-checks`.
Its blocker meaning remains exact: 36 module blockers and three default
configuration blockers.

Inspection of the installed 1.09 distribution proves that `DXBall.exe` is the
only target-owned PE32 image; the remaining files are assets plus an unrelated
16-bit uninstaller. Accordingly, DX-Ball continues to exercise its real
loader-owned DirectX/Win32 imports and resource distribution without a fictive
DLL. The generic two-target-image PE32 fixture is the multi-image authority
gate. It now explicitly requires exactly one target code edge and one target
data edge; its DLL also exposes forwarders, aliases, holes, interior data
anchors, TLS callbacks, and shared atomics, while its Wine harness checks
dynamic `GetProcAddress` code/data/ordinal/forwarder resolution and pointer
identity. Project load planning, observation, completion, and Wine execution
pass at
`/nix/store/zykhc5vm2hswyfv1ajg00756l5skkbq0-spaghetti-extractor-pe32-project-check`.

Linked multi-image planning checkpoint (2026-08-29): project load planning no
longer accepts a parallel module-interface map or any native-ingress plan. It
loads one packaged `linked-semantic-module-v1` for each target-owned image and
obtains the exact member interface, code-export physical frames, and data
anchors from that resident package. Code export aliases sharing one RVA now
share one content-addressed semantic export capability; the capability is
address-free and contains no native bridge or candidate RVA. The generic
project fixture now constructs real semantic objects and linked modules for
both its EXE and DLL before resolving its code and data IAT edges, and an
architecture gate prevents restoration of the raw-interface or ingress input.
Its deliberately tiny transfer bodies remain developer test inputs and do not
claim that the original fixture C was recovered; the Wine suite remains a veto,
not authority.

During the clean cut, the synthetic native-module suite requires exact parity
between the old derived ingress projection and the linked module's export
frames and data anchors. The native PE32/TLS/SEH/Wine realization gate passes
at
`/nix/store/vp0r63v2x8i13fnky5l2ygnh549llzdx-spaghetti-extractor-native-module-check`,
and the real GNU Hello regression passes at
`/nix/store/qla1606qf5spiflj7vqlahva92r8d22l-spaghetti-extractor-gnu-hello-target-regression-checks`.
Importer-use clean-cut checkpoint (2026-08-29): the project
`edgeAuthorities` input is removed from the Python API, low-level CLI, Nix
phase, SDK, and fixture. Each importing `linked-semantic-module-v1` now derives
one content-addressed `import-use-v1` record per reachable IAT slot directly
from transfer-v2 and its checked machine-import contract. Code uses bind the
importer's complete physical frame. Direct data reads, writes, and atomics bind
the exact byte offset, width, combined permissions, minimum extent, source
transfer, root provenance, and expression/effect site. Duplicate code slots,
mixed code/data use, non-exact pointer transforms, and dynamically sized string
accesses fail closed. The project linker compares this importer record with the
provider linked module's export capability or data anchor; it never derives
requirements from the provider or from test results. Delay-IAT cells share the
same typed inventory.
The independent linked-module replay separately reconstructs the complete
import-use row set from serialized transfer-v2 and rejects omissions,
inventions, stale frames, or provenance drift; it remains veto-only and is not
called by production linking.

The two-image fixture now places a real checked Ping call plus direct loader-
written SharedValue IAT read/write flow in its canonical app transfer. Its PE32
load plan, candidate observation, completion, forwarder/data checks, and Wine
execution pass at
`/nix/store/zykhc5vm2hswyfv1ajg00756l5skkbq0-spaghetti-extractor-pe32-project-check`.
The full synthetic native realization and independent linked replay pass at
`/nix/store/lpm28mmr55yv2418j63781kbw3qknv7r-spaghetti-extractor-native-module-check`.
Production semantic linking computes one compact importer-use syntax view while
the already-decoded transfer member is resident, then releases only the broad
JSON tree before entering the dense native fixed point. Measurement rejected
retaining that broad tree because it made the real slice slower; this release
is a latency optimization, not a memory target. Final root provenance is bound
onto the compact view after the fixed point, with no transfer reparse, mutable
cache, daemon, or memory manager. A constant-to-exact-IAT prefilter skips full
expression/effect traversal for irrelevant transfers. The projection itself
takes 72 ms CPU on real GNU Hello. The complete GNU Hello regression passes at
`/nix/store/4gnxk8mh0qzw89hsw7qvv2mp4ap0lqfj-spaghetti-extractor-gnu-hello-target-regression-checks`;
its final concurrently scheduled three-sample semantic-link veto measured
27,168 ms worst CPU, 32,049 ms worst per-worker wall, and 845,496 KiB peak RSS.
An isolated run of the same optimized linker measured 21,540 ms CPU and 21,626
ms wall. Only the 30,000 ms CPU budget is authoritative; RSS remains
unconstrained telemetry and wall time remains observational. Internal
implementation is split by import-use, capability, reference-fact, and
project-edge ownership so this reuse does not become a second semantic system.

Native-ingress scheduling clean-cut checkpoint (2026-08-29): the standalone
`nix/native-ingress-plan.nix` producer is deleted, with no wrapper or
compatibility alias. The target SDK no longer constructs or exposes
`nativeIngressPlan`/`moduleNativeIngressPlan`, and target bundles no longer
publish a native-ingress artifact. `native-ingress-plan-v2` survives only as an
internal lowering member derived from the packaged `linked-semantic-module-v1`
inside the materialized intrinsic-provider package and subsequently consumed
from that exact package by native realization. Complete linked modules proceed
directly from that member to the unified C/assembly runtime sources. An
incomplete linked module produces an honest incomplete intrinsic-provider
projection containing only the content-bound ingress member and its blockers;
it emits no runtime source and grants no execution authority. This keeps
diagnostic/status paths
buildable without manufacturing a second ingress product or semantic path.
The real GNU Hello exceptional-ingress check reads that runtime-owned member,
while the synthetic DLL/EXE realization uses the same member for linking,
composition, TLS, SEH, and Wine observation. Focused SDK, format-registry,
metadata, Python-lint, retired-architecture, and repository-boundary checks
pass. The complete synthetic PE32/Wine gate passes at
`/nix/store/lpm28mmr55yv2418j63781kbw3qknv7r-spaghetti-extractor-native-module-check`,
and the real GNU Hello regression passes at
`/nix/store/mf8yv5kjz8wq96axx6cl7bgbx954qg6z-spaghetti-extractor-gnu-hello-target-regression-checks`.

Intrinsic-realization consolidation checkpoint (2026-08-29): the public
shared-runtime, exact-runtime, and runtime-qualification Nix phases are now
deleted with no aliases. The materialized intrinsic-provider package derives
the internal ingress/runtime lowering from its packaged
`linked-semantic-module-v1`, renders the reviewed C/assembly sources, compiles
and checks the exact eleven intrinsic objects in parallel, and owns the
resulting external-environment, native-realizer, and platform provider
qualifications. Native realization consumes that one provider package rather
than separately keyed runtime source, object-manifest, or qualification
inputs. The provider also no longer accepts a separately scheduled resolved
environment: it retrieves and validates the exact environment member already
bound by the linked semantic module. This prevents stale cross-pairing and
makes the module the only semantic input to realization lowering. Incomplete
modules retain only diagnostic ingress/blocker and unmaterialized-provider
evidence; they emit no runtime source or execution authority.

Behavioral C is correspondingly only the immutable faithful source, coverage,
source-map, and build-manifest package. Its former v2 runtime-qualification and
completion receipts are retired declarations, not active artifacts; exact
runtime authority is the selected native-realizer qualification bound into
`native-realization-v1`. Architecture gates reject the three deleted phases,
the old SDK arguments, separate resolved-environment input, and production use
of either retired v2 receipt literal. The focused 87-test suite, repository
metadata, format registry, Python lint, and retired-architecture gates pass.
The refreshed synthetic PE32 DLL/EXE, TLS, SEH, composition, observation, and
Wine vertical passes at
`/nix/store/8j86wi7l2lmaiyxckyihp8pp2nx5lpxx-spaghetti-extractor-native-module-check`;
the SDK gate passes at
`/nix/store/pls4sfqbkmxnc1hjad83p0kd2vc8081y-spaghetti-extractor-target-sdk-check`;
and real GNU Hello passes at
`/nix/store/qsy85f0j2111qf8g1v1sdds4kc6ljq0d-spaghetti-extractor-gnu-hello-target-regression-checks`.
This clean cut deliberately spends available RAM on resident decoded module
state and parallel compilation. CPU time, wall time, repeated work, and Nix
invalidation fan-out are the optimization targets; RSS remains telemetry and
cannot veto a correct fast build absent actual swapping, OOM, or allocation
failure.

Provider-object direct-link checkpoint (2026-08-29): native realization no
longer accepts the immutable Behavioral-C source package or the internal
shared-runtime source package, discovers source include closures, or compiles
any C/assembly fallback. The generated-C provider owns exact function objects,
each portable-C provider is a self-contained package containing its exact PE32
objects and source/implementation receipt, and the materialized intrinsic
provider owns the exact reviewed runtime, ingress, SEH, support, and layout
objects. Native realization validates and stages the content-addressed union
selected by `semantic-implementation-selection-v1`, links it once, and binds
every object digest into the realization receipt. The former candidate source
closure/compilation module is deleted, and architecture gates reject its
return or any direct Behavioral-C/runtime source input at the realization
boundary. There is no fallback: an absent or stale selected object fails before
linking.

This is both a system reduction and the fundamental compilation-cache
boundary. Each provider compiles once; configuration realizations that select
the same qualified bytes reuse the same object package, while the linker phase
does only staging, linking, composition, decoding, and observation. The build
manifest records 24 selected-provider objects and the deduplicated intrinsic
realization union in the synthetic vertical, with zero
`compiled_in_candidate_derivation` rows. Focused 60-test validation, repository
metadata, format registry, production Python lint, and retired-architecture
checks pass. The complete PE32 DLL/EXE, export/data, TLS, SEH, composition,
independent observation, and Wine vertical passes at
`/nix/store/lry4kbq5wpg9cvhz9s8mg4mwwwid7j7l-spaghetti-extractor-native-module-check`;
the SDK gate passes at
`/nix/store/pls4sfqbkmxnc1hjad83p0kd2vc8081y-spaghetti-extractor-target-sdk-check`;
and real GNU Hello passes at
`/nix/store/3c15d3y5h0z7pbd3xykvcvx36f0w7rhk-spaghetti-extractor-gnu-hello-target-regression-checks`.

Single-provider-selection checkpoint (2026-08-29): the SDK no longer builds a
lightweight `unavailable` intrinsic-provider package and preliminary
implementation selection beside the materialized provider and native
selection. Each configuration now has exactly one intrinsic-provider package
and one `semantic-implementation-selection-v1`; the same exact selection feeds
operator status and native realization. The sole provider package derives its
internal ingress/runtime lowering and materializes objects when the linked
module is complete. If that lowering is blocked, the same package emits
incomplete qualifications with empty object evidence, so status remains cheap
and fail-closed without a parallel provider system. The public Nix constructor
always owns materialization inputs, and its former unmaterialized branch and
public Python entry point are gone. Architecture gates forbid restoration of
the duplicate package/selection maps.

This deletes two configuration-indexed derivations and removes the possibility
that status and realization select different qualification identities. A warm
combined synthetic-native and real-Hello request evaluates in 0.096 seconds on
the validation host. The exact synthetic PE32/Wine result remains
`/nix/store/lry4kbq5wpg9cvhz9s8mg4mwwwid7j7l-spaghetti-extractor-native-module-check`,
showing that the candidate bytes and observed behavior converge unchanged; the
real GNU Hello regression with its honest incomplete selection passes at
`/nix/store/shqhlspn27baf7rgxjmy9wz5p19cspyf-spaghetti-extractor-gnu-hello-target-regression-checks`.
The shared SDK migration also preserves jq and DX-Ball's honest incomplete
provider/blocker states at
`/nix/store/zf10qj1whg2hc101dq15pbbh4f7ydggc-spaghetti-extractor-jq-target-regression-checks`
and
`/nix/store/xhd1kqj9syy4nwylm7vz46g7zg5brbll-spaghetti-extractor-dxball-target-regression-checks`.

Qualified-platform cache-identity checkpoint (2026-08-29): the Lean proof
kernel is now imported through an exact `fileset.toSource` rooted at the Lean
tree instead of a plain nested dirty-flake path. A controlled edit to the
unrelated Behavioral-C package leaves both the ISA semantic-kernel derivation
and complete qualified-platform derivation unchanged at
`h06gwjnxpk0ky0gyn0vb10g5gr45k32n` and
`hcf45smqgv6c86znz3rd8apqqb65p2zn`, respectively. The one-time transition
realized the two kernel bindings and converged on the existing
content-addressed 32-shard campaign in 29.300 seconds; immediate repeat
realization took 0.063 seconds. This removes a fundamental false invalidation
edge without changing proof sharding, adding a cache service, or trading speed
for memory. An architecture/unit gate requires the independent Lean fileset so
the broad source dependency cannot silently return.

Direct component-transfer checkpoint (2026-08-29): V5 refinement now selects
the exact transfer identities bound by each component contract and executes
their canonical transfer-v2 bodies directly. The former proof JSONL projection
is deleted, induction control edges come from canonical transfer terminators,
and the component-only `module-execution-closure-v1` derivation and all of its
workflow inputs are removed. Transfer-v2's own finite-control route inventory
is the sole target authority; local path construction fails closed if selected
control escapes the contract, and explicit induction includes exact provider-
contract rows. The module-wide linked closure remains the only root-provenance
closure used by semantic linking and deployment. Architecture gates prevent
either the proof projection or component-only closure pipeline from returning.

This clean cut removes an aggregate derivation, repeated closure serialization
and validation, and five false workflow dependencies without adding a cache,
format, scheduler, or second semantic view. RAM remains available for resident
transfer indexes and solver state; RSS is telemetry rather than a veto. The
focused 61-test refinement suite and SDK/native gates pass at
`/nix/store/pls4sfqbkmxnc1hjad83p0kd2vc8081y-spaghetti-extractor-target-sdk-check`
and
`/nix/store/lry4kbq5wpg9cvhz9s8mg4mwwwid7j7l-spaghetti-extractor-native-module-check`.
The real target regressions preserve their previous authority and blocker
meaning at
`/nix/store/lhin4cmkj5y6jalpvkmwjnmb2gvb4xwk-spaghetti-extractor-gnu-hello-target-regression-checks`,
`/nix/store/mspi7zq18r5bsn20p1bw8wq1zx4fr6b9-spaghetti-extractor-jq-target-regression-checks`,
and
`/nix/store/8jrszfk601ny75595iii8apc0j7m9nh6-spaghetti-extractor-dxball-target-regression-checks`.

Component-contract phase-fusion checkpoint (2026-08-29): the exact
`component-unit-inventory-v1` remains a separately hashed checked artifact, but
its standalone Nix/Python producer is deleted. The V5 contract phase now loads
transfer-v2 once, validates the selected unit geometry once, and emits the
inventory, contract, and machine binding together. This removes a redundant
full-plan parse and process per component while keeping each component as its
own content-addressed cache boundary. The workflow exposes the inventory
sidecar through the same SDK view, so consumers migrate without a compatibility
producer. Architecture gates require the fused producer and forbid restoration
of the old phase.

The clean-cut target graphs remove 12 scheduled derivations for GNU Hello, 21
for jq, and 6 for DX-Ball (202 to 190, 189 to 168, and 132 to 126). Their exact
post-fusion regressions pass at
`/nix/store/k21nlx3nklm5jjd127g7npqxwii3rfzq-spaghetti-extractor-gnu-hello-target-regression-checks`,
`/nix/store/98n01x79c5phl5b170n08kn41fpmwcxd-spaghetti-extractor-jq-target-regression-checks`,
and
`/nix/store/jz8mwxvzssnpzsxss7abfgcfvps9rvfn-spaghetti-extractor-dxball-target-regression-checks`.

Linked semantic package-consumption checkpoint (2026-08-29): portable
component and adopted-library implementation qualification no longer receives
transfer-v2, the resolved environment, or machine-object authority as parallel
inputs to the linked semantic module. It loads all three through
`LinkedSemanticModuleV1.require_member`, after the package identity and member
hashes have been validated once. This turns the canonical semantic module into
a real dependency boundary, removes redundant cross-pairing checks and three
broad Nix edges per implementation, and prevents stale mixtures that were
representable only because the same semantics arrived through multiple APIs.
The phase also no longer receives the entire Behavioral-C package just to find
its runtime header. The exact runtime ABI moved from the candidate namespace to
the neutral transfer domain; Behavioral-C generation and portable compilation
render the same source definition independently into their own output or
temporary compile trees. A fallback-C layout or unit change therefore cannot
invalidate every portable component, while a real ABI source change still
does. No phase, package, cache, or public format was added. Architecture and
unit gates forbid both direct semantic-member inputs and the broad
Behavioral-C dependency from returning.

The V5 semantic-refinement phase now uses that package boundary as well. Its
public constructor takes one linked semantic module rather than separately
scheduled transfer-v2 and resolved-environment inputs, and loads both through
validated members before selecting the contract-bound rows. The component
workflow consequently has no resolved-environment argument. This preserves the
independent per-component CBMC cache boundary and exact proof kernel while
eliminating another stale cross-pairing state and two redundant authority
edges. Incomplete linked modules remain inspectable because packaging and
member validation do not claim execution authority.

Library adoption now follows the same rule: checked-island authority takes a
linked semantic module and reads transfer-v2 and the resolved environment from
its validated package. The linked-library orchestrator drops its dead
Behavioral-C argument and its separately threaded environment argument.
Structural-unit geometry remains explicit for V5 component generation because
that is an independent structural artifact, not a duplicate semantic-module
member. Recognition remains non-authorizing, and no library-specific semantic
facade is introduced.

V5 library-component authority also loads transfer-v2 through the linked
module. The linked-library constructor consequently exposes exactly one
target-semantic input, plus the still-independent structural-unit artifact;
transfer, environment, and Behavioral-C parameters are absent-gated. Folding
the structural artifact into the semantic module is deliberately deferred
until its relationship to transfer-v2 unit geometry is made exact, avoiding a
cosmetic merge that would merely put unrelated systems in a package.

Canonical component-input checkpoint (2026-08-29): the compiled V5 interface
package is now the only downstream interface input. Contract/binding,
refinement, implementation, work-package, induction-provider, and dependency-
graph phases no longer bypass that content-addressed boundary by rereading raw
operator intent. This is a cache-edge correction, not another adapter: the raw
intent has one consumer, the interface compiler, and equivalent canonical
interfaces reuse every downstream result.

The operator work-package phase also drops its target-wide transfer-plan input
and parser. Its baseline geometry comes from the exact separately hashed unit
inventory already bound by the component machine binding; immutable source
and line identity still come from Behavioral C's checked source map. Portable
dependency graphs no longer declare or open transfer-v2, Behavioral-C
manifests/coverage, or structural units, because only hybrid mode constructs a
generated-C remainder. The graph modes stay separate so this cut improves,
rather than collapses, portable cache isolation. Architecture gates enforce
all three input boundaries. GNU Hello, jq, and DX-Ball retain their exact
post-fusion regression outputs at
`/nix/store/sq4qvxkb6sb1k38igvjljk7f56l3ap6w-spaghetti-extractor-gnu-hello-target-regression-checks`,
`/nix/store/98n01x79c5phl5b170n08kn41fpmwcxd-spaghetti-extractor-jq-target-regression-checks`,
and
`/nix/store/jz8mwxvzssnpzsxss7abfgcfvps9rvfn-spaghetti-extractor-dxball-target-regression-checks`.

### 10. Retire superseded systems and run final gates

- Remove transfer v1; fragmented root/callback/target authorities;
  runtime-core/engine/interpreter packages; hybrid runtime activation;
  callback-specific runtime; old component readers/adapters; old
  composer/object-graph/relocation-anchor paths; retired SDK inputs; and
  retired expert commands.
- Retain only the neutral transfer evaluator in developer/test closures.
- Refresh the domain-owned format registry, Python module index, test manifest,
  target metadata, repository map, and architecture/operator documentation.
- Add absence checks for retired format literals, modules, globals, commands,
  runtime fallback, interpreter loops, unrestricted target resolution, and
  duplicated semantic opcode switches.
- Run:
  - `nix flake check`
  - `nix flake check ./targets`
  - smoke, full, and benchmark suites
  - PE32 native-ingress, TLS, SEH, loader-surface, and project suites
  - applicable Wine Hello and DLL suites
  - generated metadata freshness
  - architecture-boundary and retired-format checks
- Record final cold/warm timing, RSS, artifact size, target statuses,
  deployments, observed hashes, and remaining honest blockers.

Exit: all ten milestones and all final gates pass. A module is complete only
when canonical transfer coverage, execution closure, selected component
authority, runtime qualification, native ingress, exact linking, loader
composition, static assurance, decoded candidate hash, and candidate-observed
deployment all agree.

## Historical pre-pivot test scenarios and completion rules

- Canonical codecs: malformed widths/arity, stale hashes, duplicates,
  unsupported operations/versions, noncanonical encoding, and incomplete
  inventories.
- Provenance: image/TLS/stack/IAT/allocation/resource references, interior
  pointers, stored guest code references, bounded alternatives, conflicting
  code/data use, and unauthorized targets.
- Components: V5 projection/lifecycle validation, source v3 operation coverage,
  host/PE32 compilation, CBMC refinement, services, relations, induction,
  ownership, hybrid mode, and portable mode.
- Runtime: every ingress role, equivalent bridge sharing, incompatible ABI
  rejection, nested entry, concurrent foreign threads, lifecycle generations,
  detach/reload, abandoned-frame cleanup, atomics, TLS ordering, loader-lock
  safety, and stack exhaustion.
- SEH: divide/access faults, host-import faults, export escape, continuation,
  nested handlers, unwind/finally ordering, process termination, portal mapping,
  and pinned-address rejection.
- PE/project: EAT names/ordinals/aliases/holes/data/forwarders, imports/delay
  imports, TLS, resources, relocations, SafeSEH, CFG, load config, cross-image
  code/data edges, forwarded providers, dynamic resolution, and observed
  distribution hashes.
- Authority: tests, Wine, evaluator, Z3 counterexamples, Ghidra, emulators, and
  optional oracles may veto or supply checked evidence only; none grants
  completion by successful execution alone.

## Historical pre-pivot assumptions and defaults

- IA-32 PE32/Win32 remains the only production backend during this plan.
- Windows/Wine loader behavior remains authoritative for imports, forwarders,
  TLS, DLL entry, and module search.
- Candidate code addresses may differ from original addresses; checked
  semantic mappings preserve identity. Exact numeric equality requires
  pinned-layout authority.
- Loader-visible data identity is preserved through mapped object anchors and
  actual IAT pointers.
- Generated C is immutable; operator-authored C exists only in separately
  hashed component source packages.
- No project-wide broker, generated support DLL, global code registry,
  simulated scheduler, global engine lock, or production interpreter is
  introduced.
- The existing dirty-tree work is preserved and adapted rather than discarded.
- Optional third-party dependencies remain out of scope unless a later measured
  and separately approved capability gap justifies them.
- Version changes are clean cuts with no compatibility aliases.
- The active goal remains incomplete until all ten milestones and final
  deployment-only criteria close.

Intrinsic qualification/native-realization clean-cut checkpoint (2026-08-29):
provider selection now closes semantic implementation identity before any
intrinsic code is generated. `intrinsic-semantic-providers.nix` emits only the
external-environment, reviewed-native, and qualified-platform semantic
qualifications plus total choices. It has no compiler, Behavioral-C source,
component-object, ingress, runtime, or object-manifest edge. Native and
qualified-platform definitions name their stable reviewed realization symbols;
their exact generated source, compiled object, linked RVA, and section evidence
is closed once by `native-realization-v1`, rather than being duplicated in the
selection receipt.

The generated-C provider carries an exact content-bound reference to the
Behavioral-C package it qualified, and the portable-C provider carries the exact
checked runtime-dispatch manifests already used to qualify its objects. Native
realization therefore derives those physical inputs exclusively through the
selected provider qualifications. It opens the linked semantic module once,
derives ingress and runtime in the same process, retains the full decoded and
rendered working set, compiles the eleven independent support sources in
parallel, links the exact selected-provider and realization-object union,
composes the PE32 module, and emits the sole physical receipt. The former
materialized intrinsic-provider package, its object manifest, and the
`intrinsicProviderPackage` cross-binding are absent-gated. The synthetic PE32
DLL/Wine path, production lint, and retired-architecture gate pass after the
cut. This is a speed-first high-RAM design: RSS remains diagnostic, and memory
is optimized only when measured swapping, OOM, or latency regression justifies
it.

## Implementation checkpoint: speed-first scheduling clean cut

The obsolete Nix/Python target authority graph and its memory-tier invalidation
fixture have been removed. Incremental invalidation is now exercised at the
linked semantic-module boundary, so cache identity follows semantic content
rather than a duplicated phase topology. Structural and SCC work classes remain
only as deterministic parallel/cache partitioning hints: fixed `memory_mib`,
`memoryLimitMiB`, environment limits, and `ulimit` enforcement are forbidden.
The implementation deliberately retains decoded/indexed semantic state and
lets the host/Nix scheduler report genuine exhaustion; it will not add a
project eviction manager or fixed RAM budget without measured OOM or swap
evidence.

The corresponding global source retirement is also complete. Removing the
target registry exposed 54 Python modules with no production consumer: the
final reducer, root/exception/induction/memory/target/external-site checkers,
their fixed-point helpers, target-local ISA/evidence adapters, and the
transfer-side exceptional-authority join. Those modules and their isolated
tests were deleted rather than hidden behind a replacement coordinator. The
former active v4/v5 exception evidence formats are retained only as retired
declarations owned by `semantic_objects/formats.py`; production exception
semantics come directly from transfer-v2 plus the resolved environment. An
architecture gate prevents the old producers and adapters from returning, and
the production-module reachability check is again total.

The new-path Nix phases now use the shared content-addressed constructor for
generated Behavioral-C provider qualification, the singleton qualified-
platform ISA corpus, linked-module independent replay, and semantic-link
performance observations. This keeps their separate cache boundaries but
deletes repeated environment/provenance boilerplate. The semantic-kernel
binding also has one domain-owned format declaration. Focused Python checks and
the linked-semantic-module, qualified-platform, semantic-provider, and complete
native PE32/Wine integration gates pass after the cut.

DX-Ball external-boundary checkpoint (2026-08-29): the target now selects its
declared `pe32-i686-msvc` ABI instead of inheriting the MinGW default.  Resolved
environment construction selects machine-import contracts from the union of
runtime and interface packs through the same ambiguity-checking loader, so the
existing checked DirectDrawCreate and ordinal DirectSoundCreate factory
contracts now close their actual IAT identities without a target adapter.
Interface catalogs remain the same canonical pack input; duplicate runtime or
interface identities still fail closed.

The canonical callback rule and both Python/Rust closure kernels now support a
checked `argument_pointee` source plus a `provider_resource` instance.  This
covers `RegisterClassA` reading `WNDCLASSA.lpfnWndProc` at its checked byte
offset and preserves a stable instance key without an RVA annotation.  A
focused synthetic transfer proves that the stored guest pointer becomes a
reachable callback capability.  Explicit `callback_effect: none` is accepted
as no callback, and absent contracts in an honestly incomplete environment no
longer produce redundant `malformed_*` blockers.  DX-Ball's default module
status consequently falls from 36 mixed blockers to 31 exact blockers: 18
unresolved indirect targets, ten unresolved external write footprints, the
two genuinely unmodelled kernel exception imports, and the still-unbound
window-service machine boundary.  Its target regression passes at
`/nix/store/igv3jg5d4isgh5czyxg0346rg17wn74p-spaghetti-extractor-dxball-target-regression-checks`.

The window-service blocker has since been removed without routing the package
through a second single-call protocol workflow.  Resolved-environment
construction now opens every physical frame already emitted by a checked
multi-frame service schema and applies one shared binding rule against the
selected module imports and callback protocols.  The same rule is rerun by the
closed resolved-environment codec, so editing a claimed profile, authority
frame, callback source, or cross-frame relationship and recomputing the outer
hash still fails closed.  A machine word may be narrowed to an authored typed
view such as the 16-bit `ATOM` in EAX, but the view cannot move or widen the
physical value.

DX-Ball's `RegisterClassA` frame now binds the actual
`user32.dll!RegisterClassA` IAT contract, while the WndProc frame binds that
contract's `win32-window-procedure-ansi` callback protocol.  The resolver also
proves the interaction between them: argument zero points to the checked
40-byte `WNDCLASSA`, byte offset four is the typed `lpfnWndProc` field, that
field's function type is exactly the callback frame's type, callback argument
zero is the declared provider resource, and the selected registration
lifetime/delivery policy is content-bound in the link.  DX-Ball's resolved
environment therefore retains only the two honestly unmodelled kernel
exception imports; the full target still remains incomplete on its separate
18 indirect-target and ten external-write-footprint frontiers.  jq uses the
same rule to bind `__setusermatherr` and its callback while its three internal
`jv_*` service frames remain explicitly unbound rather than receiving invented
machine authority.

The same checkpoint corrected jq's authored registration signature against
the selected machine contract.  The real module imports
`msvcrt.dll!__setusermatherr`, but that function has no physical result; the
old typed frame incorrectly claimed that EAX returned the previous handler.
The V5 schema now declares the exact void result, so both the import frame and
`msvcrt-user-math-error-handler` callback frame bind uniquely and their
argument-word registration, singleton instance, lifetime, and delivery policy
form one checked callback link.  No portable-component authority was inferred.
Jq remains honestly incomplete with 61 unresolved reachable imports and the
three internal `jv_copy`, `jv_dumpf`, and `jv_free` service frames; the former
callback-relationship crash and blocker are absent.

Callback-link derivation now returns deterministic relationship issues beside
the links instead of using exceptions to represent missing authority.  The
resolved-environment producer serializes each issue as an exact blocker, and
the closed codec rederives both links and issues and requires the corresponding
blocker.  Thus a structurally valid work package with an absent, ambiguous, or
malformed registering frame remains inspectable but cannot become complete.
A focused regression mutates `RegisterClassA` to an unselected
`RegisterClassW` frame and proves that resolution is incomplete and parseable,
not an aborted build.  Seven external-environment unit tests pass, as do the
full jq and DX-Ball aggregates at
`/nix/store/s7lzv5ywv6pnb898lm0pr9cprx86zqi3-spaghetti-extractor-jq-target-regression-checks`
and
`/nix/store/3vn6c6b9mfwcff25im9jkccmnz4f205d-spaghetti-extractor-dxball-target-regression-checks`.
DX-Ball's resolved environment now has exactly the two unmodelled
`UnhandledExceptionFilter` and `RtlUnwind` imports; its checked
`RegisterClassA`/WndProc service has no remaining blocker.

This target work also exposed and removed a false performance edge.
Qualified-platform-v1 had content-bound the complete reference-provenance
implementation as an unverified veto-source field even though it needs only
the total transfer-operation coverage declaration.  That declaration now has
one small domain-owned module, used by platform replay and Behavioral-C
coverage.  The linked semantic module remains the sole consumer that executes
the full reference fixed point and native parity kernel.  Architecture checks
forbid any closure/provenance implementation module from re-entering the
qualified-platform Python closure, so callback/object analysis changes no
longer invalidate target-independent ISA qualification.  No cache, adapter,
or second provenance semantics was added.

DX-Ball coupled cutpoint/classification checkpoint (2026-09-01): the module
interface producer's canonical seven-field empty EAT is now accepted exactly
by external-environment resolution. Empty slots alone cannot disguise stale
geometry or a contradictory DLL identity. This removes a generic producer /
consumer mismatch without adding a target special case.

DX-Ball then exposed a deeper ordering defect in the existing semantic
pipeline. Its optimized CRT `memcpy` and `memmove` implementations place
absolute jump tables, padding, and code in the same executable section. The
first materialization fixed point recovered part of the target inventory, but
froze it before executable-data and overlapping-decode classification exposed
the complete rooted selector domains. The final control pass could therefore
name 19 exact target RVAs after it was too late to create their unit
cutpoints. This was not missing ISA semantics and did not justify a target
profile or a second analyzer.

Cutpoint materialization now refreshes the existing classification and finite
dataflow only when its current closure stalls, then continues the same bounded
fixed point. A content digest detects stability, the final classified result
is reused by export rather than recomputed, and every refresh is recorded in
the machine-IR manifest. On real DX-Ball the refresh materializes 21 qualified
units for 12 target RVAs, then reaches a stable 9,022-unit classified
inventory with zero conflicts and no recovered jump table lacking a unit
binding. The linked semantic module retains 14 roots and 259 typed residual
obligations while direct edges expand from 11,577 to 11,591, active symbols
from 9,255 to 9,269, and active relocations from 12,257 to 12,287. All 38
derivative relocation holes disappear; total holes fall from 53 to 15. A
target-owned checkpoint pins the exact counts and the two remaining
environment blockers, `UnhandledExceptionFilter` and `RtlUnwind`. Full jq and
DX-Ball target aggregates pass after the generic change; no jq universe was
pruned. The next capability is checked external nonlocal/SEH service handling,
first exercised in the synthetic PE32 DLL project.

Checked external-service checkpoint (2026-09-01): the two remaining imports
now use one closed service-protocol field carried by the existing machine
profile, resolved environment, linked semantic effect, residual-obligation,
and canonical runtime-plan records. This is a typed extension of the canonical
boundary rather than a service-specific adapter or second phase topology.
`RtlUnwind` binds its exact four-word stdcall frame to target-frame,
target-instruction, exception-record, and return-value operands; its only
allowed outcome is `nonlocal`, its continuation target is a checked guest code
capability, and its declared effects are x86 SEH unwind plus abandoned-frame
lifetime invalidation. It is deliberately not lowered as a returning call to
the host `RtlUnwind` from the checked private stack.

`UnhandledExceptionFilter` binds one checked eight-byte
`EXCEPTION_POINTERS` root, the nested checked exception-record and x86
`CONTEXT` referents, read/write context authority, and the same-thread
relationship to the image-lifetime filter registered by
`SetUnhandledExceptionFilter`; loader-owned fallback remains explicit. Closed
profile, environment, checked-contract, linked-module, and runtime parsers
rederive these facts and reject disposition, arity, physical-frame, outcome,
or protocol disagreement.

The real DX-Ball resolved environment is now complete. Its linked semantic
universe remains exactly 14 roots, 11,591 direct edges, 9,269 active symbols,
and 12,287 active relocations. The two service holes become one
`checked_external_nonlocal_service` and one
`checked_external_exception_object_service` residual obligation, so the
runtime-obligation count rises from 259 to 261 while total holes fall from 15
to four. The remaining holes are independently qualified-platform gaps:
`fcos` at RVA `0xd6cc`, `fsin` at `0xd6d9`, `fistp qword` at `0xe569`, and
`fdiv qword` at `0x10145`.

No runtime authority is inferred from the checked service descriptions. Until
the generic native implementations are qualified, canonical runtime planning
emits exact `external_service_runtime_unsupported` blockers for both residual
obligations; malformed service obligations fail closed. Focused profile,
environment, semantic-link, and runtime tests pass, as does the full DX-Ball
target aggregate. The next service step remains the synthetic PE32 DLL
vertical for unwind, registered-filter invocation, continuation/failure
policy, and abandoned-frame cleanup before those runtime blockers may close.

Standalone-ingress and project-composer clean-cut checkpoint (2026-08-29):
native ingress is no longer a public independently constructed artifact.  The
`expert candidate-native-ingress-plan` command and the raw
`candidate.native_ingress.write_native_ingress_plan` export are removed; the
only production route derives ingress from one already validated
`linked-semantic-module-v1` as an internal part of `native-realization-v1`.
The raw constructor remains private only for focused codec and fail-closed
tests.  Architecture, command-surface, and retired-interface checks prevent
the side-input API from returning.

Removing that API exposed a test-only PE32 project composer which fabricated
complete ingress, object-authority, environment, build, map, and relocation
receipts around an existing synthetic DLL.  It has been deleted rather than
adapted.  The multi-image project test now plans and observes the original
loader-valid DLL and lets Windows/Wine own its imports, exports, data anchors,
forwarders, and TLS callbacks.  Its semantic objects and linked modules remain
the checked planning inputs, while no forged native-realization authority is
granted by the execution fixture.  The full PE32 project/Wine gate passes with
the original DLL, proving that the duplicate composer contributed no behavior
or authority.  Production PE composition is now invoked only by the single
native-realization builder.

Relational callee-saved-word checkpoint (2026-08-29): the canonical transfer
fixed point now preserves caller correlation for IA-32 EBX, EBP, ESI, and EDI
across shared callee summaries. Each checked call substitutes an analysis-local
word token for those four inputs and rebinds a directly returned token to that
caller's exact abstract word. This does not assume ABI preservation: an
instruction or external contract that changes the register destroys or joins
the token through the ordinary transfer semantics. It also grants no object
authority: derived memory keys still instantiate only from exact object
bindings, and an unknown or conflicting caller remains fail-closed.

The focused mixed-caller regression has one exact object caller and one
conflicting caller traverse the same wrapper and helper contexts. The exact
caller retains its write authority while only the conflicting caller receives
`unresolved_callee_effect_instantiation`. The independently implemented Rust
kernel and Python reference evaluator agree under the linked-module replay
gate. The Hello-derived registration slice remains complete at 266 reachable
units, 319 edges, and zero blockers.

On real GNU Hello the change preserves the exact 4,495-unit/6,052-edge universe
and reduces the blocker inventory from 59 to 54: callee-effect blockers fall
from 18 to 12, external-write blockers rise from 20 to 21 because one formerly
hidden reachable boundary is now reported at its proper site, and the 21
indirect-target blockers are unchanged. Native closure identity is
`0dc7f77d742a5175c02820c4d450a8d7b3e4c3359dc713a8dee79d217a0ea45e`.
The native three-sample performance gate passes its 30-second CPU budget at
22,529--22,564 ms CPU and 22,622--22,649 ms wall time; peak RSS is telemetry
only and measured 930,620 KiB. The Python diagnostic took 120.5 seconds with
177,121 worklist steps, down from 182,535. This is accepted as a precision and
worklist improvement without introducing a new analysis system; remaining
blockers continue to represent real unresolved authority.

The remaining 12 callee-effect blockers were then replayed with parameter-
instantiation diagnostics enabled. All are the same checked condition in three
shared contexts: MinGW's narrow or wide `pformat_putc` helper writes the word at
offset 32 of the formatting object supplied in EDX, while the blocked caller
has no binding for the helper summary's `register:3` object parameter. Other
callers do provide an exact transient object and compose successfully. Treating
the unbound caller as harmless, or parameterizing its unknown word without an
object identity, would authorize a write to an unknown object. These 12 rows
are therefore genuine missing object authority rather than another correlation
loss; no widening was made. Future closure work should address their upstream
formatting-object provenance or an exact machine-derived object selector, not
weaken return-summary instantiation.

Formatting-object provenance follow-up (2026-08-29): the initial suspicion
that compiler-generated tail jumps into narrow and wide `pformat_int` were
losing function context was rejected by a smaller semantic replay.  Starting
the same `pformat_emit_efloat` transfer body with one exact formatting object
preserves that object through `pformat_emit_float`, `pformat_putc`, the
epilogue, the physical-stack-reusing jump into `pformat_int`, and the later
helper call with zero blockers.  A tail-call adapter or replacement execution
context would therefore add machinery without repairing the actual loss.

The full-program diagnostic instead shows that EDX is already conflicting at
the earlier `pformat_putc` calls.  Some collapsed callers project the format
argument exactly while others provide an opaque or absent stack projection;
the sparse relational-binding map records the exact alternatives that exist,
but it is not proof that the missing paths carry the same object.  Filling the
physical stack cell from that surviving sparse binding would silently convert
may-information into must-authority.  The fixed point consequently retains
the 12 blockers.  Further progress must prove those caller paths infeasible or
derive their stack argument from checked machine/object facts; it must not add
tail-call semantics or treat an absent binding as an exact object.

Finite-alternative scaling rejection checkpoint (2026-08-29): because RAM is
telemetry rather than a veto, the full Hello reference closure was replayed
with the existing object/reference alternative bound raised from 16 to 64.
This kept the same 4,495 units and 6,052 edges but did not remove a single
blocker: the result remained 12 callee-effect, 21 external-write, and 21
indirect-target blockers.  Worklist steps increased from 177,121 to 357,572
and Python wall time from about 120 seconds to 205 seconds, with peak RSS about
1.06 GiB.  The experiment is rejected on speed and precision grounds.  The
remaining loss is not finite-set capacity; it is missing must-provenance on
particular joined caller paths.  The production bound remains 16.

Object-scoped repeat-write checkpoint (2026-08-29): the canonical provenance
semantics no longer treats every `rep movs`/`rep stos` with an unknown repeat
count as a write to arbitrary guest memory.  When the destination alternatives
are exclusively exact machine objects, the evaluator conservatively
invalidates the possible suffix or prefix of those objects according to the
direction flag; an unknown direction invalidates each whole destination
object.  Scalar, mixed, or otherwise ambiguous destinations retain the
all-memory fallback.  This is the same object-range rule already used for
checked external writes, not a new analysis domain.

Focused tests prove that an unknown-count copy destroys facts in its exact
destination object while preserving an unrelated code-pointer cell.  Python
and the independently implemented Rust kernel emit byte-identical state, and
all 38 transfer-value/native-reference unit tests pass.  On real GNU Hello the
reachable universe remains exactly 4,495 units and 6,052 edges.  The frontier
also remains 54 blockers (12 callee effects, 21 external writes, and 21
indirect targets), showing that the previously observed `rpl_strerror`
`rep movsl` was a genuine precision defect but not the dominant source of the
remaining loss.  The new closure identity is
`87757855d84edb6f4e9cbd8497c5706686e644353ac3f2fba04b53fc7081d822`.

The causal inventory of every remaining real-Hello semantic-module blocker is
maintained in
[`gnu-hello-semantic-closure-tooling-gap-inventory.md`](gnu-hello-semantic-closure-tooling-gap-inventory.md).
It is part of this plan's milestone-4/5 exit work. Raw context-row counts must
not be treated as independent features: the inventory identifies the exact
x87 qualification campaign, object-provenance families, derivative initialized
code-pointer sites, bounded jump table, lazy code-capability cell, and missing
non-authorizing blocker-trace tooling that must close before Hello can
authorize execution.

Hello causal-diagnostic checkpoint (2026-08-30): the current canonical link
contains 4,498 reachable units, 6,056 edges, and 63 fail-closed fixed-point
blockers. The qualified-platform campaign and the pformat jump-table proof are
now closed; neither remains on the Hello critical path. The remaining rows are
12 callee-summary instantiation failures, 33 checked external-write footprint
failures, and 18 indirect targets. The write rows collapse to six machine call
sites, and 17 of the indirect rows are initialized or loader-written code
cells downstream of the conservative all-memory fallback. One lazy codepage
capability cell remains independent.

The non-authorizing `expert semantic-diagnose` workbench now projects exact
machine causes, observed all-memory invalidation fan-out, decoded per-RVA
transfer/reference neighborhoods, and closure deltas directly from the
packaged `linked-semantic-module-v1` and its transfer-v2 member. It introduces
no receipt, authority bit, semantic input, or second fixed point. Rust now
reports the exact register inputs, parameter bindings, and failure reason for
callee-summary instantiation, and the Python/Rust parity gate still compares
the canonical closure.

Full-state replay established two important negative results. First, the exact
formatting object reaches the formatter helper and its frame slot before the
interprocedural cycle becomes poisoned; the final callee blockers are
derivative, so another tail-call or formatter adapter would be wrong. Second,
`memcpy` already has the canonical checked `byte_copy` relation in both
evaluators; the relation cannot apply only because allocation/source/extent
arguments have already lost must-provenance. The next authorizing change must
therefore be a demand-driven proof over existing transfer-v2 definitions that
retains exact returned-allocation and frame-slot object dependencies across
the cycle. It may use Z3 for feasibility/counterexamples, but it must feed the
one fixed point and preserve its complete root, edge, exception, and outcome
universe. Global context shapes, alternative widening, delayed fallbacks, and
optimistic test-derived authority remain rejected.

Universal relational-stack-word rejection checkpoint (2026-08-30): applying
the existing callee-saved-word token rule to every checked outgoing stack word
was tested in both Python and Rust and rejected on the real target. It reduced
external-write blocker rows from 33 to 13, but created 114 callee-summary
instantiation failures, one callback-target blocker, and pruned the reachable
universe from 4,498 units/6,056 edges to 4,343 units/5,826 edges. The change was
fully reverted. This is evidence that stable parameter identities alone are
insufficient: relational stack dependencies must be selected from the exact
callee reads and must retain a conservative continuation for callers that
cannot bind them. A universal stack product is now explicitly outside the
implementation direction.

Checked-stack-input rejection checkpoint (2026-08-30): narrowing the same
experiment to the machine-derived `call.stack_inputs` set is still not a valid
demand analysis. With the existing object-shaped token it reduced the graph to
4,357 units and 5,852 edges and produced 127 blockers. Giving the token a
separate non-authorizing word kind fixed the control-flow unsoundness and
restored the exact 4,498-unit/6,056-edge universe, but every provisional
dereference of an actually unknown caller word then failed correctly at return
substitution: 89 callee-effect blockers, 33 external-write blockers, and 18
indirect-target blockers. A final variant used one opaque stack identity for
both exact-object and unknown callers while leaving exact scalar and code
values untouched. It also preserved all 4,498 units and 6,056 edges, but
expanded callee-effect failures to 137 while reducing external-write rows only
from 33 to 27; the 18 indirect blockers were unchanged. The six removed rows
did not justify 125 new failures. All forms were reverted.

This establishes that syntactic callee reads are not the required demand set.
The next implementation must start at a blocked effect or target and slice
backward through transfer-v2 definitions to a particular allocation return or
frame-slot object, retaining a conservative path when that proof does not
close. It must not parameterize all values merely because a callee reads them,
and it must not represent an opaque word as object authority.

Bounded demand-replay checkpoint (2026-08-30): the non-authorizing semantic
diagnostic workbench now executes one explicitly supplied transfer-v2 state and
reference catalog through both the Python evaluator and independent Rust
kernel.  The transport is bounded, uses the packaged canonical transfer plan,
and emits no format, receipt, or authority bit.  A focused vertical fixture
performs a checked allocation followed by the existing `byte_copy` external
effect and proves that both kernels copy the same code-capability word into the
new object.  The linked-semantic-module Nix gate runs this fixture with the
native extension; ordinary Python-only runs skip it rather than substituting a
different evaluator.

The slice view is now rooted at the actual blocked effect rather than merely
the containing RVA.  It traces serialized expression operands, resolves
physical stack arguments through canonical `stack_inputs`, identifies exact
same-transfer and immediate-predecessor stack writers, and collapses repeated
execution-context rows while retaining their distinct observed abstract
values.  On real Hello, all 22 `memcpy` blockers at `0x00010245` become one
machine demand: offsets zero and four are written in the blocked transfer and
offset eight in its sole direct predecessor `0x00010234`.  The formatter rows
root at physical register EDX, while an indirect site roots at its exact load
expression.  This confirms that a selective stored-value dependency is the
next missing semantic relation.

Two narrower allocator hypotheses were implemented in paired Python/Rust form,
measured on the real target, rejected, and fully reverted.  Exact-frame-
qualified external allocation identities yielded 4,497 units, 6,054 edges,
and the same 63 blockers.  Renaming a new allocation observed in an internal
return register yielded the identical result.  The immutable accepted baseline
remains 4,498 units, 6,056 edges, 63 blockers, and closure identity
`118ae6fd855b860635ed661e289bfc4f73bb4f28088002cc2fdd64ae05c0216a`.
These experiments prove that object naming by itself neither carries the
allocation/frame-slot relation nor preserves the full universe.  The next
authorizing change must be selected by the effect-rooted writer chain and must
retain the normal conservative path when the chain is not exact.

Pinned-header ABI vertical checkpoint (2026-09-01): the SDK now has one
generic, content-addressed Clang header-to-machine-ABI phase rather than a jq
adapter.  It derives canonical `BoundarySchemaV1`, `TargetDataLayoutV1`, and
`PhysicalCallFrameV3` records from pinned installed headers, including hidden
structure returns, by-value aggregates, and x87 returns, while deliberately
emitting no semantic memory effects or authority.  The jq project applies it
to the installed `jq.h` and `jv.h` and obtains 132 exact public declarations.
The real jq-to-libjq project now proves physical compatibility for 44 of its
47 target-owned import edges.  The remaining three edges are precisely the
non-public declarations `jq_realpath`, `jq_testsuite`, and
`jv_tsd_dtoa_ctx_init`; they remain fail-closed instead of being guessed from
names or implementation C.

The exact ABI split changed one jq transfer partition without changing its
covered bytes, entry, or exit.  The sole stale V5 component binding was
migrated cleanly from two adjacent transfer IDs to their one exact replacement,
with binding identity
`0cd5ba7c0b8d7a98611ce40576baa64a237f604a3b9afb936a91bc84fedbf2dc`.
All other bindings remained current.  The full jq target regression passes at
`/nix/store/d8q80dl8jai8xvwzp7csj20vdkrxslm1-spaghetti-extractor-jq-target-regression-checks`,
and the project load plan remains honestly incomplete with five blockers: two
incomplete resolved environments and the three non-public cross-image ABI
edges above.

Qualified `FABS` vertical checkpoint (2026-09-01): the first real libjq ISA
hole is now closed through the existing canonical path rather than a target
special case.  Static extraction recognizes `FABS` only as logical guidance,
emits the exact-byte checked x87 replay, transfer-v2 consumes the already
canonical typed x87 operation, and the reviewed Lean decoder/executor clears
the extended-precision sign bit exactly.  The finite qualified-platform
inventory contains the new Lean-owned semantic form; the shared 32-shard Lean
campaign and independent Bochs/Unicorn oracles qualify it.  A focused negative
one case is bit-exact between Lean and Unicorn.

On the real 36,005-unit libjq image this raises compiled transfer coverage from
35,875 to 35,896 and reduces semantic blockers from 130 to 109, with exactly
21 qualified `FABS` typed replays and no lost unit.  The new transfer plan is
`/nix/store/chvccv209iibyywrcnd6a1a1d8zh3yy4-spaghetti-extractor-jq-libjq-executable-transfer-plan-v2`;
the project load plan is
`/nix/store/7hr0vb7nr5qakd010cp1v11fp2gz54h1-spaghetti-extractor-jq-load-plan-v2`.
The remaining exact instruction inventory is 16 `frndint`, 14 x87 constant
loads, 16 x87 conditional moves, 8 `sahf`, 8 rotates, and 47 other x87
arithmetic/transcendental forms.  Future classifier changes should batch
coherent reviewed families to amortize the intentionally global platform
requalification; after this clean rebuild the unchanged project load plan
reuses all content-addressed products in 0.082 seconds.  No mutable cache,
alternate IR, test-derived authority, or target-specific runtime was added.

Reusable jq host-contract and honest-project checkpoint (2026-09-01): the jq
root and libjq workflows now consume shared reviewed contracts for the public
Win32/MSVCRT console APIs that were absent from the runtime pack, plus a small
public Oniguruma runtime pack for `onig_set_parse_depth_limit`. The pinned
`__wgetmainargs` contract carries the exact wide argument/environment pointer
vector shapes; string, stream, console-mode, locale/TLS, allocation, and opaque
resource effects remain explicitly classified. No private libjq prototype was
invented. The three service frames for `jv_copy`, `jv_free`, and `jv_dumpf`
were corrected from direct main-image functions to their actual imported
identities and now bind to the already generated pinned-header machine ABIs.

The jq root retains all 14 roots, 5,709 direct control edges, 7,026 active
relocations, and 89 residual obligations while semantic holes fall from 105 to
21. libjq retains all 197 roots, 46,084 direct edges, 51,809 relocations, and
412 obligations while holes fall from 659 to 607. The remaining root
environment blockers are exactly the non-public `jq_realpath`, `jq_testsuite`,
and `jv_tsd_dtoa_ctx_init` ABIs. The two-image load plan remains honestly
incomplete with five blockers: one incomplete resolved environment per target
image and the three corresponding private cross-image edges. A target-owned
gate pins those blocker identities and the conservative counts. The public
bundle now exports linked semantic-module derivations rather than invalid
content-addressed interior-path strings, and both selectors evaluate and build.
The full jq regression gate passes. Authored jq components remain explicitly
blocked on their unreviewed semantic and service/callback/outcome projections.

DX-Ball semantic-completion and runtime-frontier checkpoint (2026-09-01): the
cutpoint/classification fixed point now materializes every recovered optimized
CRT jump-table target without pruning the may-universe. The two formerly
untyped environment holes, `RtlUnwind` and `UnhandledExceptionFilter`, are
reviewed external-service protocols with exact physical frames, object views,
outcomes, capability relationships, and lifecycle effects. Four final target
x87 gaps use the shared qualified-platform exact native-replay provider rather
than a DX-specific decoder or semantic path. The broader platform selection
retains 27 non-active unsupported Lean forms as honest diagnostic issues.

The resulting linked module is complete with 14 roots, 11,591 direct control
edges, 9,269 active symbols, 12,287 active relocations, 261 residual
obligations, zero semantic holes, and zero analysis frontiers. The same four
shared x87 selections reduce libjq from 607 to 603 holes while preserving its
197 roots, 46,084 direct edges, 51,809 relocations, and 412 obligations. This
cross-target change is pinned as a semantic-provider improvement, not inferred
from a lower blocker count.

Two fail-closed runtime defects exposed by the real module are fixed. Resource
callback lifetimes preserve their exact `end_event` in the content-bound
obligation and reject absent or misplaced events. A runtime plan that is
semantically well formed but not yet realizable now produces only its checked
module and ingress plans plus an incomplete non-authorizing package; source
rendering stops before C or assembly generation, so no partial runtime can
enter provider selection or a native link receipt. DX-Ball's process
termination policy is bound to its original loader-written Kernel32
`ExitProcess` IAT slot. The qualified-runtime gate pins the only remaining
native blockers as:

- `win32-rtl-unwind-v1`, a checked external nonlocal service; and
- `win32-unhandled-exception-filter-v1`, a checked external exception-object
  service.

The existing module-runtime plan now carries one compact
`external_service_routes` inventory projected directly from these linked
obligations. It preserves the complete protocol contract and exact admitted
sites: two `RtlUnwind` sites and one `UnhandledExceptionFilter` site. Runtime
blockers derive from those same rows, and validation rejects a ready plan with
an unrealized route. This is the common dispatch seam; it adds no artifact,
semantic language, or target adapter and avoids reconstructing service meaning
from the expanded generic callthrough table.

The required inventory is published as `module-runtime-plan-v6`; V5 is a
retired format tombstone rather than an in-place schema mutation. All in-tree
producers, validators, runtime providers, realization consumers, fixtures, and
targets migrated in the same cut. The format registry, complete GNU
Hello/Wine matrix, jq target, and DX-Ball target pass on V6.

These must be realized as two entries in one generic checked external-service
dispatch table over the existing ingress, capability, object, TLS, SEH,
context, transactional-writeback, continuation, and nonlocal-routing
machinery. `RtlUnwind` must validate the target frame and code capability,
perform checked x86 unwind notifications and abandoned-lifetime cleanup, and
resume only an authorized target. `UnhandledExceptionFilter` must validate the
nested `EXCEPTION_POINTERS` object, invoke an active registered guest filter on
the same host thread through its capability, transact checked context
writeback, or use the loader-owned fallback only when no guest filter exists.
Ordinary host callthrough is not an admissible substitute for either service.

The runtime-plan vertical also reveals a measured representation and
invalidation defect: indirect external calls currently expand each site over
the complete admitted loader target domain, yielding roughly 14,000 repeated
site-by-target rows for DX-Ball. A small support-policy change reevaluated 123
phases. The runtime V6 format-only clean cut then scheduled 236 Hello phases
and 228 phases across jq and DX-Ball and unnecessarily rebuilt the
qualified-platform release and Behavioral-C providers. After the two service
transducers pass the synthetic PE32 DLL/Wine
fixture and DX-Ball gate, replace those rows with compact site references to
one global content-addressed external target/contract catalog. The change must
retain the identical checked may-domain and semantic identities, introduce no
new cache or IR, and demonstrate lower runtime-plan size and narrower Nix
invalidation before acceptance.

Checked-service and normalized-runtime checkpoint (2026-09-01): both service
transducers now use the generic runtime path. The guest FS exception head is a
virtual machine datum distinct from the native x86 SEH gateway chain; guest
records live in the bounded captured invocation stack. Checked `RtlUnwind`
walks that guest chain, invokes younger handlers with the exact unwind flag and
checked exception/context/frame objects, invalidates abandoned lifetimes, and
resumes only the authorized continuation. Registered unhandled-exception
filters use the same capability, object-view, thread, and outcome machinery.
The synthetic PE32 DLL/Wine project and DX-Ball runtime gate pass with both
routes realized and zero runtime blockers. Identical authority repeated by
overlapping exact transfer entry slices is coalesced; any disagreement in
contract, argument, target, invocation, or lifetime remains an ambiguity
blocker.

The measured representation defect is closed by `module-runtime-plan-v7`.
V7 is a lossless normalization of the V6 relation, not a new authority: the
planner retains expanded facts in RAM, the serialized plan stores one
content-addressed target-contract catalog and deduplicated checked-domain
table, and each physical site names one domain. Validation reconstructs and
checks every former row before runtime lowering. DX-Ball retains all 25,064
site-target pairs while the plan falls from 115,277,024 to 10,851,144 bytes
(90.6 percent), represented by 426 physical sites, 286 target contracts, and
92 domains. A target gate pins those counts and a 16-MiB upper bound. V6 is a
retired registry tombstone; all in-tree consumers migrated in the same cut.

The earlier 123/228/236 figures described floating content-addressed dry-run
graph visibility, not executed invalidation. A controlled comment-only change
to the DX target retained the exact derivation identities of the transfer
plan, qualified platform and ISA graph, semantic object, linked module,
generated provider, and qualified runtime provider; only target lint and
regression leaves changed. An unchanged target build completed in 0.09 seconds
without running a builder even though Nix printed the 123-node floating graph.
Future invalidation evidence must compare derivation identities and executed
builders, not this dry-run list alone. The role-checked module closures and Nix
remain the sole cache/reuse system.

Component review-frontier checkpoint (2026-09-01): the direct V6 work package
now embeds a content-bound review frontier inside the existing unreviewed
machine-projection blocker. This is a projection of
`executable-transfer-plan-v2`, not another artifact or semantic pipeline. It
contains exact call records and dependency-closed expression nodes, exact
memory-write effects, and exact control outcomes. Nested identities, ordering,
coverage counts, and the non-authorizing policy are checked on read. The only
automated service suggestions are exact normalized import-name matches, are
explicitly presentation-only, and cannot populate a binding or qualify a
provider. The frontier remains visible through the existing boundary
inspection because blocker details are preserved there.

On real DX-Ball this exposes that the current `directdraw-init` selection and
the authored interface/source are not the same operation. The selected region
contains 86 transfers, 38 calls (18 named external, 17 indirect, and three
internal), 123 writes, and the complete preceding Win32 window-creation path.
Its named imports include `LoadIconA`, `LoadCursorA`, `GetStockObject`,
`RegisterClassA`, `CreateWindowExA`, `UpdateWindow`, and `SetFocus` before
`DirectDrawCreate` and the repeated error paths. By contrast, the authored C
accepts an already-created window and models only six DirectDraw/error
services. All six therefore remain unmapped and the blocker remains. A
target-owned gate pins the frontier policy, counts, exact named-import
inventory, and presentation-only suggestions.

The next component clean cut must make one operator-visible choice: either
model and implement the full window-plus-DirectDraw operation, or select the
DirectDraw tail and bind every live-in/global object and exit explicitly. It
must not silently treat the current six services as a total effect inventory.
Only after that choice should the common COM/vtable and external-write object
selectors be added and proved in the synthetic PE32 project. This correction
preserves the original intent of small contextual refinement while preventing
a convenient but semantically false component qualification.

DirectDraw-tail and live-interface checkpoint (2026-09-02): the operator
choice is now explicit and favors the small contextual replacement. The
authored `directdraw-init` interface and C source remain DirectDraw-only; its
binding now selects the unique single-entry suffix at RVA `0xcd5c` rather than
the complete window-construction function at `0xcc60`. The excluded prefix has
one edge into the suffix, from `0xcd5a`. The selected inventory falls from 86
to 65 exact transfers and now contains 27 calls, 83 memory writes, six return
exits, and two internal calls. A distinct content-bound blocker records the
unreviewed captured-frame/register live-ins, window and interface global
objects, outcome projections, internal effects, and complete interface-method
service mapping. The existing machine-projection blocker and all six unmapped
services remain. The target-owned gate pins the new boundary and no portable
authority is inferred from the smaller inventory.

The canonical callable-domain seam now reaches native runtime planning for
non-callback interface methods. Interface method targets and stable class
identities are cataloged from the linked domain; factory and method
out-interface writes register the actual object pointer, vtable pointer,
class, and generation. Dynamic callthrough accepts a method only when its live
receiver and exact vtable slot match, and it applies preserve/release
lifecycle rules. Loader imports and interface methods share the same physical
indirect site because kind is a target-contract fact, not a site fact.
Serialized resolution evidence refers to the canonical method digest rather
than embedding the method again. On real DX-Ball that removes 3,087,238 bytes
from the diagnostic runtime plan (18,203,481 to 15,116,243) while retaining
426 physical sites, 1,368 target contracts, 92 checked domains, and all 162,478
site-target pairs under the 16-MiB gate.

This checkpoint does not claim callback-bearing interface methods. All 20
such methods remain in the canonical may-domain and each produces an exact
`interface_callback_callthrough_runtime_unsupported` blocker, covering
`EnumAttachedSurfaces`, `EnumDisplayModes`, `EnumOverlayZOrders`, and
`EnumSurfaces` over five DirectDraw interface generations. The qualified
runtime provider now publishes the incomplete checked plan/package and emits
no source instead of raising an unstructured exception or pruning those
members. Focused runtime suites, the standalone PE32 ingress/Wine suite, and
the complete DX-Ball target gate pass.

The next clean vertical must first exercise factory output, live method
dispatch, nested output registration, mutation, release, stale-generation
rejection, linked-symbol binding, and receipt identity in a synthetic PE32
fixture. It must then lower callback-bearing methods through a compact
protocol/publication catalog derived directly from the same callable domains
and reuse the generic callback ingress and capability registry. It must not
generate one bridge per site/member pair or introduce another semantic
artifact. Only after both verticals pass may the runtime/package formats make
their clean cut and the 20 DX blockers be removed.

Non-callback interface deployment checkpoint (2026-09-02): that first
vertical is complete. A real `fixture-provider.dll` supplies loader-imported
`FixtureCreate` and a four-slot `IFixture` vtable. The original machine path
and generated candidate call the factory through the actual loader-written
IAT, register the returned object, clone and register a nested object, mutate
and observe its value, release both objects, then retain a method address and
prove that an attempted post-release invocation is rejected by the candidate
before entering the provider. The Wine host asserts exact aggregate provider
call traces for the successful and stale paths, so a convenient return-value
substitution cannot pass.

No fixture-specific runtime mechanism was added. The vertical corrected the
shared outgoing bridge table to retain tagged interface-method catalog
identities, made exact loader/interface selectors dominate a physical-frame
wildcard at the same indirect site, and based saved caller state on the stable
captured frame rather than a transfer-local stack value. Receipt gates now
pin the single four-method interface catalog, factory out-interface relation,
seven catalog-referenced indirect runtime obligations, 37 transfers, 13
external sites, eight checked domains, all 76 site-target pairs, 71 selected
definitions, 11 obligations, 17 bridges, preserved factory import, composed
loader surface, and candidate-observed project hash. Focused canonical-runtime
tests and the complete synthetic native-module Wine gate pass.

The fixture's binary-producing phase is intentionally input-addressed and
disables generic fixups. Floating content-addressed output finalization was
observed rewriting an embedded output-path reference in PE/COFF auxiliary
material after the producer computed exact binary hashes. The exact produced
PE bytes remain the content-bound input to every higher semantic phase, which
continues to use normal content-addressed reuse. This avoids a false receipt
without introducing a cache or alternate semantic identity.

The remaining clean vertical is callback-bearing interface callthrough. It
must derive a compact callback protocol/publication catalog from the same
callable domains, publish the callback argument through the existing generic
code-capability registry, use the existing callback ingress bridge and checked
physical frame, and enforce invocation lifetime and expiration. The same
provider fixture must demonstrate same-thread re-entry and fail-closed stale
use before the runtime/package clean cut is made or any of DX-Ball's 20 exact
blockers are removed.

Callback-interface and V8 normalization checkpoint (2026-09-02): that
vertical is complete on the same provider DLL, generic ingress, capability,
object, TLS, runtime, link, composition, deployment, and observation path.
Header-derived callback signatures produce checked PE32 callback frames and
result protocols; unsupported callback result shapes fail closed. The provider
publishes the checked callback argument, performs same-thread candidate
re-entry, receives its result, and retains an invocation-local bridge only to
prove that post-return use is rejected. Temporary interface object/vtable
ranges follow the same generation and are removed without disturbing reused
authority.

The clean cut is `module-runtime-plan-v8`. Ordinary callback registration
publications remain scoped to their exact instruction and checked external
contract. Interface callback publications are scoped once to the canonical
method-contract digest because the selected interface target and exact
physical site bridge already establish the site/member relation. DX-Ball now
contains 764 ordinary checked-site publications and 20 interface-method
publications, rather than 5,824 redundantly expanded publication rows.

V8 also factors the one identical 9,022-RVA callback target list formerly
embedded in 49 checked contracts into a content-addressed callback-target
domain. The serialized contract retains its original digest; validation
losslessly restores `target_rvas` and verifies that digest before any runtime
lowering. This retains all 426 physical sites, 1,408 target contracts, 92
checked domains, 167,558 site-target pairs, 13 physical callback domains, and
117,286 domain-target memberships. The plan is ready with zero blockers and
falls from 20,259,876 bytes before these V8 normalizations to 15,524,398 bytes,
below the existing 16-MiB gate. V7 is a retired registry tombstone after every
producer, validator, renderer, runtime provider, fixture, and target migrated.

The native PE32 provider/Wine deployment and observation gate, focused
runtime and environment suites, complete DX-Ball target gate, format registry,
metadata, import-smoke, and retired-architecture gates pass. The remaining
DX-Ball component blockers still describe the unreviewed 65-transfer
`directdraw-init` contextual boundary; no component authority was manufactured
from runtime completion.

Measured performance now points beyond JSON normalization. Qualified runtime
generation remains a serial two-to-three-minute, full-CPU phase at roughly
4.2 GiB RSS. The generated 117,286 static domain-target trampolines dominate a
roughly 56-MiB ingress source and 170-MiB runtime object. The next permitted
experiment is a bounded generation-scoped bridge-slot realization over the
existing physical-frame domains. It must retain exact target membership,
stable published addresses, concurrent and reentrant use, escape and expiry,
content-bound receipts, deterministic exhaustion, and the existing semantic
plan. It is acceptable only with a material measured codegen/runtime-provider
speedup; it must not become a cache, broker, target-specific pruning rule, or
second callback authority system.

DirectDraw review and realization-storage checkpoint (2026-09-02): no dynamic
bridge allocator or additional artifact was needed for the first experiment.
The existing V6 work package consumes the linked module's admitted callable
domains and emits non-authorizing method candidates only for the exact
syntactic indirect form `load(add32(receiver, constant-slot-offset))`. Seven
of the 65-transfer suffix's fourteen indirect calls meet that criterion and
produce 130 candidate rows; the other seven are the direct `ESI` live-in used
for `ShowWindow`. This presentation evidence does not assert receiver
provenance or populate service bindings. It also exposes missing `GetCaps`,
surface/clipper construction and attachment calls, two internal effects, and
the authored-versus-machine outcome mismatch. `directdraw-init` remains
honestly incomplete.

Native realization retains the same fixed-stride static trampoline address
for every virtual domain target and the same per-target capability generation.
Only repeated C storage is factored: 27 distinct ingress descriptors are
selected through 39 ranges for all 117,286 targets; nine interface callback
argument ranges replace 81,199 repeated rows; mutable capability state moves
to zero-initialized BSS, while immutable lifetime/end-event ranges remain
checked. The complete DX-Ball target passes with a 5,836,877-byte,
409,653-line ingress C source and 2,391,618-byte MinGW object, down from the
descriptor-only 30,860,315-byte source and 156,594,016-byte object without
pruning a target. The measured full gate was 181 seconds, not materially
better than the prior 174-second sample. Therefore artifact inflation is
fixed, but the performance exit is not: profile phase time before considering
dynamic slots, and accept further complexity only for a measured dominant
cost.

Canonical V8 runtime-reuse checkpoint (2026-09-02): profiling showed that the
compact public plan was being expanded twice inside one runtime-provider
process. Runtime validation and external-range planning each recreated all
167,558 site-target rows and repeatedly parsed contracts already represented
by the 1,408-entry target catalog and 92 checked domains. One internal
`ValidatedExternalInventoryV8` view now validates that existing serialized
catalog once and is handed directly from plan validation to range planning.
The legacy expanded projection remains only as a compatibility function for
tests and inspection. This is in-process structural reuse of the canonical
plan, not a persisted cache, new receipt, or second semantic carrier.

The exact standalone DX runtime render improved from 142.399 to 111.515
seconds, a 21.7% reduction, with the full 117,286 callback targets, 167,558
site-target pairs, and ready status intact. Most decisively, the rebuilt
runtime-provider derivation resolves to the identical content-addressed output
`/nix/store/za45cya0h4139yyjs80pnhwh95f743bg-spaghetti-extractor-dxball-semantic-qualified-runtime-provider-v2`.
Thus its public plans, generated sources, objects, manifests, and receipts are
byte-for-byte unchanged. Native ingress, the complete PE32/Wine module gate,
and the full DX target pass after the cut.

The combined full-gate rebuild took 388.81 seconds, but a controlled
invalidation experiment disproved the initial attribution to an over-broad
Python source closure. A comment-only edit confined to
`candidate/runtime.py`, followed by the checked module-index refresh, changed
only the qualified runtime provider and downstream aggregates. The exact DX
transfer-plan, semantic-object, Behavioral-C, and linked-semantic-module
derivation identities were unchanged; reverting the probe restored the
original runtime and aggregate identities. The broad earlier rebuild was
caused by the same optimization cut's changes to shared external-contract
code, which genuinely participates in upstream environment construction.
Retain the existing role-checked per-phase closures, add a regression assertion
for this dependency cut, and do not add another cache or closure system.
Further runtime micro-optimization must target the measured remaining phase
costs; dynamic bridge allocation remains unjustified.

DirectDraw checked-transducer checkpoint (2026-09-02): exact disassembly,
transfer events, the resolved external environment, and the V6 review frontier
show that the remaining component work is not merely a list of COM method
names. The selected tail needs a reusable checked service transducer capable
of representing the `DirectDrawCreate` HRESULT plus out-interface resource,
stack-local descriptor and output cells, generation-checked interface-method
receivers, the `GetCaps` bit/global effects, and exact scalar outcomes. It also
needs the captured `ShowWindow` code capability, window/interface object
selectors, six zero-failure/one-success exits, and two internal effects. The
target binding and its index now content-bind those distinct requirements.
The next implementation vertical must exercise the generic factory,
stack-local, receiver-generation, and result-projection path synthetically
before DirectDraw adopts it; no target-specific bridge or second service ABI
is permitted.

Checked interface-service slice (2026-09-02): the first half of that vertical
is complete without introducing another provider or refinement path. The
resolved external environment now owns one canonical method-digest index.
Component semantic checking selects an exact indirect-call event and requires
its syntactic vtable slot, fixed PE32 ABI, logical/physical arity, live resource
receiver, class/generation contract, and scalar EAX result to agree with that
catalog. It then materializes the method as the existing
`checked_external_call_events` service kind with a typed interface identity,
so existing path exploration and contextual refinement consume it directly.

The component renderer uses the same method digest to realize the receiver's
profile, interface class, object identity, and generation, reads the exact
vtable slot, and invokes the existing generic indirect-call dispatcher. A
shared runtime callback performs the live-resource lookup; there is no COM- or
DirectDraw-specific bridge. Focused semantic/refinement/renderer tests and the
component, environment, native-runtime, synthetic PE32 DLL/Wine module,
production-lint, source-closure, metadata, and complete GNU Hello and DX-Ball
target gates pass. The complete jq two-module migration gate also passes with
its existing honest blockers unchanged. The isolated GNU Hello semantic replay
remains below its existing veto at 4.545 seconds and 510,200 KiB RSS. The
remaining half of the vertical is still fail-closed:
factory HRESULT plus out-interface publication, stack-local descriptor/result
cells, transactional writeback, and resource-valued service results are not
yet represented and must be completed before the DirectDraw binding is
adopted.

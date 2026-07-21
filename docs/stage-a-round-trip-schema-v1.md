# Stage A Round-Trip Qualification Schemas v1

This document records the stable Phase 0 boundaries implemented by
`spaghetti_extractor.roundtrip_fuzz`. These artifacts qualify Stage A; none of
them independently authorizes an equivalence `pass`.

## Acceptance Authority

The only positive acceptance authority is the Lean-kernel-checked theorem:

```text
StageA.GeneratedRelational.candidatePE32ProgramsEquivalent
```

The round-trip runner invokes the ordinary public sequence:

```text
stage-a-generate-map                 untrusted mapping proposal
stage-a-generate-relation-contract  untrusted relation proposal
stage-a-prepare-relational          deterministic proof graph
stage-a-build-relational            Nix Lean build and theorem audit
```

A case receives `pass` only when the final build report selects the exact
theorem above, reports Lean trust level zero, and passes the theorem-identity
audit. Corpus expectations, semantic generator metadata, linker maps, and
runner status fields have no proof authority.

## Corpus Manifest

`stage-a-roundtrip-corpus-v1` binds:

- generator version and root seed;
- capability profile;
- exact compiler, target, and linker identity;
- a unique, shard-stable list of case-manifest paths and hashes;
- expected counts for `pass`, `violated`, and `incomplete` cases.

Paths are canonical relative POSIX paths. Absolute paths, `..`, duplicate case
identities, stale hashes, out-of-range shards, unknown fields, and count
mismatches fail before analysis.

## Case Manifest

`stage-a-roundtrip-case-v1` binds:

- stable semantic case identity and semantic-program hash;
- parent seed, semantic template, and transformations;
- expected disposition;
- one isolated mutation for negative cases;
- capability and expected proof-family inventories;
- every source, object, PE, map, proposal, and contract artifact by role, size,
  relative path, and SHA-256;
- deterministic replay command and shard.

Positive cases must expect `pass` and omit a mutation. Supported negative cases
must expect `violated`, name a checked witness family, and declare exactly one
semantic mutation. Capability-boundary negatives must expect `incomplete` and
name the expected reason family.

## Semantic Program

`stage-a-roundtrip-semantic-program-v1` is a typed generator input, not proof
authority. Phase 0 includes explicit-width scalar values, stack adjustments,
stack writes, static objects, direct jumps, returning external calls, and
terminating external calls. References and control targets are checked before
lowering.

The Phase 0 program is lowered independently to two real PE32 assemblies. The
candidate contains a reachable layout-only no-op. The qualification lane uses
clang 21.1.8 with the `i686-pc-windows-msvc` target and lld-link 21.1.8. The
current link uses MinGW's `libkernel32.a` as an import library rather than a
Windows SDK import library; this is recorded as a qualification limitation,
not hidden as an MSVC SDK build. Regeneration in different directories must
produce identical artifact hashes.

The semantic program is retained as untrusted corpus ground truth. Stage A
still parses exact PE bytes and proves the submitted relation independently.

## Case Results

`stage-a-roundtrip-case-result-v1` records:

- expected and actual disposition;
- whether the expectation matched;
- phase cache keys, hits, durations, and output hashes;
- final theorem and authority when accepted;
- complete nonempty proof frontiers;
- runner or input errors.

`stage-a-roundtrip-run-result-v1` aggregates cases. Any negative final `pass`
is fatal even if another field claims the case matched its expectation.
Internal errors never satisfy an expected `incomplete` case.

Warm proof reuse requires an exact runner input binding. Successful proof reuse
also requires the exact final theorem and Lean trust checks in the persisted
verdict.

## Violation Witness

`stage-a-violation-witness-v1` binds:

- original, candidate, normalized relation-contract, and decoded-behavior
  hashes;
- capability profile, obligation ID, and witness family;
- original and candidate semantic IDs, region indices, RVAs, exact bytes, and
  paths;
- complete relevant concrete register, flag, memory, path-guard, and world
  pre-state bindings;
- failed relation atom and conflicting effects;
- observation or external event index;
- deterministic replay command.

`stage-a-violation-check-v1` is the required Lean audit. A checked violation
requires trust level zero, the approved axiom set, an exact generated violation
theorem identity, matching witness and semantic hashes, and exact bytes at both
bound PE locations. Raw solver `sat`, unchecked Python comparison, stale bytes,
or a fabricated status field cannot produce `violated`.

The result is described as the **first proved mismatch under this witness**.
Source-level cause hints and repair actions are diagnostics and do not belong
to the trusted witness.

## Opaque Stage B Bundle

`stage-b-opaque-input-bundle-v1` materializes an isolated directory containing
only declared static Stage A exports and explicit manual annotations. It
requires at least a reference contract and state machine.

The bundle rejects:

- the original PE;
- original runtime traces;
- generator semantic programs or seeds;
- ground-truth maps and transformation history;
- private lowering metadata;
- symlinks, stale hashes, escaping paths, and undeclared files.

Stage B round-trip execution must use this isolated bundle as its complete
input directory. Proof-core mode may consume a generator-known map as an
untrusted proposal; that exception does not apply to Stage B.

## Phase 0 Canary

The checked generated canary performs a no-CRT lockstep sequence through
`GetStdHandle`, `WriteFile`, and `ExitProcess`, with a compiler-style internal
call/return, an input-dependent branch, stack memory, and static relocations.
It is deliberately small enough for rapid proof iteration while exercising
the real launch and external-environment boundaries. Its candidate adds a
reachable state-preserving no-op before the terminating call.

The semantic lowerer emits an explicit nonreturn fallback loop after a call
declared `terminates`. This gives the binary a mapped architectural return
address while the external-environment theorem proves that continuation
unreachable under the declared API contract. Opaque binaries which place trap
padding directly after a nonreturn call still require a generic terminal-frame
proof and must remain `incomplete` until one exists.

The final theorem passed through the distributed Nix graph with Lean trust
zero. The next qualification step is the multi-template positive/negative
corpus. Compiler-generated C, a Windows SDK import-library lane, automatic
checked violation production, and the opaque Stage B round trip remain later
gates.

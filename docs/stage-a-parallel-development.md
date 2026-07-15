# Parallel Stage A Development

Stage A improvements should be parallelizable without creating multiple versions
of the proof model. Parallel work is organized around versioned artifacts and
reviewed Lean interfaces. The final acceptance theorem remains a serial
integration boundary.

Every prepared proof emits `stage-a-interface-manifest.json`. Its digest is part
of `prepared-proof.json`, and the Nix build rejects a missing or changed
manifest. The generated manifest is the machine-readable inventory of:

- public schema versions;
- phase artifact ownership and cache boundaries;
- reviewed Lean declarations used between phases;
- parallel workstreams and their integration fixtures;
- the single workstream allowed to integrate final acceptance.

The same inventory can be generated without preparing a binary proof:

```console
spaghetti-extractor stage-a-export-interfaces --out stage-a-interfaces.json
```

## Stable Interfaces

The following are compatibility boundaries. A change to their meaning requires
a schema or profile version change, migration tests, and an update to the
generated interface manifest.

- `stage-a-relation-contract-v1`
- `stage-a-protocol-callback-control-v1`
- `stage-a-external-environment-profile-v1`
- `stage-a-relational-proof-ir-v1`
- `stage-a-relational-segment-certificate-v1`
- `StateRel` and `StaticProofContext`
- `RelationalSegmentRefinement`
- `WorldExternalProtocolEnvironment`
- `ProtocolCallbackTargetProfile`
- `CallbackRunningProductNodeStepRefined`
- `WholeProgramCertificate`
- `pe32ProgramsEquivalent`

Python phases must consume normalized, typed boundary objects where a model is
available. A phase must not depend on undocumented keys inserted into a mutable
dictionary by an earlier phase. New fields fail closed until normalization,
analysis, generated proof data, and Lean checking all support them.

## Workstreams

The generated manifest defines the current path ownership. The intended lanes
are:

1. Instruction extraction and checked decoding.
2. Register, memory, stack, and runtime-frame analysis.
3. Stateful external protocols and callbacks.
4. Product control and segment composition.
5. Contract normalization and actionable diagnostics.
6. Lean module graph, Nix scheduling, and proof caching.
7. Acceptance integration.

The first six lanes can proceed concurrently. Acceptance integration is the
merge point: it may consume new certificates, but it must not manufacture proof
facts or accept a Python status assertion. `pe32ProgramsEquivalent` remains the
only pass authority.

Some physical files are still shared kernel dependencies. An agent that needs
to change a declaration outside its owned paths should first add or extend a
narrow interface in its owned module. Moving proof logic into
`relational/lean/acceptance.py` or `RelationalCertificates.lean` is reserved for
actual composition changes.

## Work Packet

A parallel Stage A task should state:

- the blocker category it closes;
- the artifact or Lean interface it owns;
- input and output schema versions;
- the generic fixture demonstrating the capability;
- expected cache invalidation;
- whether jq should change only as an integration result.

Each task must add a small generic fixture before relying on jq. It must preserve
fail-closed behavior for unsupported instructions, ambiguous mappings, unknown
targets, missing environment behavior, and uncheckable solver evidence. A jq
specific transfer rule is not an acceptable work packet.

## Integration Order

1. Normalize and type-check the changed public contract.
2. Run the workstream's small generic fixture.
3. Run a direct Python test only when it is a sub-second pure-analysis smoke
   check. Use the matching `stage-a-relational-tests-*` Nix target for the
   authoritative phase suite.
4. Run the representative whole-program acceptance fixtures through the
   per-case Nix derivation graph.
5. Build the changed Lean module closure. The test derivations consume the
   independently cached `stage-a-relational-kernel-cache`; generated proof
   modules remain separate content-addressed outputs.
6. Regenerate jq artifacts only when an extraction or contract input changed.
7. Run the full remote Nix proof graph as the completeness gate.

Downstream Stage B work consumes the exported reference contract and its
versioned evidence, not private Python planner state. This lets Stage B skeleton,
repair, and diagnostics work proceed while Stage A capabilities improve behind
stable artifact versions.

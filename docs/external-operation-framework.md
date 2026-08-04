# External Operation Framework

Spaghetti Extractor represents imports, COM methods, C operation tables,
resolver-produced function pointers, and registered callbacks with one bounded
machine-level operation model. Library names and C declarations are useful
metadata, but they are not proof authority.

## Artifact Boundary

The framework deliberately separates three artifacts:

1. `stage-a-external-operation-profile-v2` identifies operations, machine ABI,
   argument count, selectors, output origins, and the environment contract used
   at the call boundary.
2. `stage-a-external-operation-contract-v1` bounds memory footprints and
   relational-world effects. Stage A must prove that paired environments
   implement this contract; recognizing an operation never proves its behavior.
3. `stage-b-source-operation-catalog-v1` selects a readable C spelling. It is
   non-authoritative and cannot contribute to Stage A acceptance.

Profiles are normalized and content-hashed. Unknown fields, dangling selectors,
unsupported ABI shapes, unbounded footprints, unresolved resolver outputs, and
undeclared callback protocols fail closed.

Legacy interface profiles can be converted to operation identities and known
out-parameter writes, but the resulting environment contracts remain
`incomplete`. They may guide target recovery and source rendering; they cannot
close control or call refinement until the missing memory and world effects are
authored explicitly.

## Selectors

An operation may be selected by an exact import, a table view and slot, a named
result of another resolver operation, or a registered callback protocol. Table
views explicitly distinguish an object containing a table pointer from a direct
C table pointer. Both layouts use the same provenance and target-resolution
engine.

Output rules may produce resource/table views or callable operation targets in
a return register or bounded out-argument. A success guard remains attached to
the value until the corresponding path condition is established. Joins retain a
bounded finite set; exceeding the budget produces `incomplete`.

Callback-registration effects identify both the callback argument and callback
protocol. Static analysis emits exact argument-origin and target evidence for a
nested external frame. Lean must replay that evidence against exact machine
semantics and the relational world.

## Lean Authority

`StageA.RelationalExternalOperation` checks profile shape, exact table-slot
resolution, paired value-origin resolution, operation identity, argument count,
and the presence of a relational environment premise. The final theorem must
consume a paired call boundary and an environment-refinement witness. Neither a
Python recovery result nor a source rendering can authorize equivalence.

## Stage B Rendering

The source catalog renders already recovered operation evidence:

```console
spaghetti-extractor stage-b-render-source-operations \
  --operation-profile operation-profile.json \
  --catalog source-operation-catalog.json \
  --operations recovered-operations.json \
  --out source-operation-rendering.json
```

Missing or ambiguous renderings become deterministic repair items. Rendering
does not execute or trace the original binary and remains subject to final
candidate validation. Resolver results and registered callbacks share a typed
function-pointer rendering form; callback knowledge does not require a
library-specific source emitter.

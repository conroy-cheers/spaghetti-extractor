# Semantic Components

A component is an operator-reviewed grouping of machine-IR units with an
explicit interface. It may represent one block, a procedure, a dispatch table,
a library island, or an entire subsystem. Components are the unit of progressive
lifting into portable C.

## Lifecycle

1. `stage-b-discover-components` proposes bounded coarsenings from machine IR.
2. `stage-b-select-components` materializes reviewed declarations.
3. `stage-b-build-component-catalog` validates membership and boundaries.
4. Interface analysis records inputs, outputs, memory footprints, control
   outcomes, external operations, and fallback policy.
5. `stage-b-create-component` creates an editable source workspace.
6. `stage-b-check-component` runs bounded source checks, normally through CBMC.
7. `stage-b-qualify-component` binds the checked evidence to exact source and
   interface hashes.
8. `stage-b-promote-components` emits an override registry for the generated
   baseline.

Discovery never authorizes replacement. Ambiguous membership, missing effects,
unbounded values, unsupported control, stale source, or mismatched interfaces
remain `incomplete`.

## Interface Shape

A useful component contract records:

- stable component and machine-unit identities;
- entry and exit outcomes;
- typed scalar and pointer inputs;
- returned values and out parameters;
- read/write memory ranges and alias assumptions;
- global state touched;
- external/import operations;
- callback registrations or invocations;
- resource ownership/lifetime effects;
- exceptional or unsupported outcomes;
- fallback behavior before any observable write.

Machine registers may appear at the initial boundary. Coarsening should move the
boundary outward until those values can be represented as C parameters, local
state, globals, or typed resources. Components that inherently depend on exact
addresses or unusual machine behavior may be replaced as larger handwritten
islands with a portable source-level contract.

## Source Evolution

The generated baseline preserves behavior in a low-level form. A normal lifting
sequence is:

```text
machine transfer -> small component -> procedure -> subsystem -> idiomatic API
```

Each step retains a complete machine-IR fallback for every region not yet
replaced. Component promotion must not reopen rooted control, executable
semantics, external effects, or implementation coverage. Library recognition
can replace many components at once when a constellation of functions, data,
imports, and call shapes matches a pinned catalog. A partial match remains a
hypothesis.

All Wine-backed checks must use a headless X/Wayland session, such as
`xvfb-run -a`, must never execute the original binary, and must be gated behind
the complete static hybrid contract.

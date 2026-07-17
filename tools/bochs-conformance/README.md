# Bochs ISA conformance backend

This directory implements the pinned Bochs executor used by Stage A's
evidence-only ISA conformance checks. Bochs is an independent veto oracle. Its
observations can reject a Lean semantic implementation, but they never close a
Stage A proof obligation.

The Nix package builds Bochs 3.0 with this instrumentation linked at compile
time, builds a minimal protected-mode guest, and installs only the strict batch
runner as a public executable. The runner:

- boots one headless guest for the whole corpus;
- enters flat 32-bit protected mode with controlled GDT, IDT, segments, PIC,
  x87 reset state, and no paging;
- injects each supported case through a private machine protocol;
- executes exactly one instruction;
- emits machine-readable observations for independent mask checking by
  `isa_conformance_bochs.py`;
- records the pinned package, CPU model, configuration, runner, guest, corpus,
  and report hashes in each Nix shard's execution manifest.

The backend does not run or trace an original application binary. It consumes
only synthetic or hardware-generated instruction cases.

## Current capability

The initial qualified profile deliberately admits only PE32 register/flags
forms of `01 /r` with `mod=3` and `05 id`. This covers the pinned `6601` and
`6605` SingleStepTests/80386 shards. Memory, faults, branches, non-flat segment
state, x87, and every other encoding return `unsupported`; they are never
approximated or silently accepted.

Build the full current Bochs corpus check with:

```console
nix build .#stage-a-isa-conformance-bochs-80386 --no-link
```

The next capability increments should add explicit state and observation
support in this order: memory accesses and writes, architectural fault vectors,
segment descriptors and limits, x87 state, then additional reviewed opcode
families. Each increment requires a small focused fixture before adding a
hardware-corpus shard.

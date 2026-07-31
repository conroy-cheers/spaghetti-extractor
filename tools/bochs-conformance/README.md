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

The private protocol supports generic one-instruction register, flags, bounded
memory, and near-control observations. It does not contain a mnemonic or
opcode-family allowlist. Bochs' decoder metadata admits scalar GPR/immediate
and ordinary memory operands, while runtime instrumentation enforces the
declared state boundary:

- at most 32 non-overlapping mapped regions and 64 KiB per case;
- mapped addresses inside the controlled 16 MiB guest RAM and outside the
  injected instruction;
- every linear access wholly contained in one declared region;
- writes permitted only for `rw` or `rwx` regions;
- exact reinjection of every mapped byte before every case;
- a final snapshot of every mapped region;
- branch/call/return class from Bochs callbacks plus the architectural next
  EIP.

Protocol v5 executes each target instruction with CPL 3, supports a controlled
GDT-backed FS selector and hidden base, and injects and observes the complete
x87 state represented by the canonical corpus:

- control, status, and full tag words;
- the 11-bit last opcode and 32-bit instruction/data pointers;
- eight exact 80-bit registers in x86 little-endian memory form.

The corpus register list is logical `ST(0)` through `ST(7)`. The adapter rotates
those values through the TOP field when reading or writing Bochs' physical
register array. Every case receives a fresh x87 state, so a prior case cannot
leak stack contents, tags, or exception state into the next one. Inputs that
cannot be represented exactly, malformed observations, unsupported x87 faults,
and x87 accesses outside declared memory remain fail-closed.

The canonical schema does not expose the legacy FCS/FDS selector fields. The
adapter initializes them deterministically to zero. They are not returned as
observations and therefore cannot be used as qualification evidence. Extending
the schema is required before selector-sensitive environment behavior can be
qualified.

The runner returns `unsupported` for undeclared accesses, permission
violations, unsupported translations, and inputs outside these bounds. This is
an oracle containment policy, not x86 memory protection: paging remains off in
the controlled guest.

The private protocol captures divide-error (`#DE`, vector 0) faults before
guest exception delivery. It emits the faulting EIP, general registers,
EFLAGS, and every mapped-memory snapshot as a complete `control=fault`,
`fault=divide_error` observation, then redirects directly to the harness
decode loop. All other exception vectors remain fail-closed unsupported.

Single-instruction `REP` string operations execute within the same bounded
memory policy. Vector registers, I/O, far control, system effects, LDT-backed
FS state, and x87 or other architectural fault classes beyond the reviewed
observations remain explicitly unsupported.

Build the full current Bochs corpus check with:

```console
nix build .#stage-a-isa-conformance-bochs-80386 --no-link
```

The next capability increments should add other reviewed architectural fault
classes and separately versioned vector-register profiles. Each increment
requires a small focused fixture before adding a hardware-corpus shard.

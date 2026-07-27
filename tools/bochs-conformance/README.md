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

The runner returns `unsupported` for undeclared accesses, permission
violations, unsupported translations, and inputs outside these bounds. This is
an oracle containment policy, not x86 memory protection: paging remains off in
the controlled guest.

Architectural fault-state capture, nonzero FS selectors/bases, x87, vector
registers, I/O, far control, repeated instructions, and system effects remain
explicitly unsupported. Fault diagnostics retain the Bochs exception vector,
but do not claim a complete fault observation until recoverable pre-delivery
state is implemented.

Build the full current Bochs corpus check with:

```console
nix build .#stage-a-isa-conformance-bochs-80386 --no-link
```

The next capability increments should add recoverable architectural fault
observations, per-case segment descriptors and FS state, x87 state, then
separately versioned vector-register profiles. Each increment requires a small
focused fixture before adding a hardware-corpus shard.

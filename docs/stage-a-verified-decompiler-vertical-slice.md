# Stage A Verified Decompiler Vertical Slice

## Completion Goal

This slice is complete when Stage A can take one real jq x86 PE32 code
cluster, lift it into a mechanically checked semantic contract, lower that
contract into ugly but implementable C, compile the generated C through the
current Stage B toolchain, and validate the compiled candidate region against
the original Stage A contract without original-binary runtime tracing.

The accepted result must prove that the selected jq cluster is no longer
blocked by signature guessing or decompiler pseudocode. Any remaining failures
must be outside the selected cluster, source-mapped, and reported as smaller
downstream obligations.

## Purpose

The long-term objective is to make Stage A useful as the proof-producing front
end of a formally verified decompiler. Stage A should not only report that a
candidate binary differs from jq; it should emit contracts detailed enough for
Stage B to generate ugly C directly.

This vertical slice tests that architecture on one small but real jq region:

```text
original jq machine code
  -> Stage A semantic block/cluster contract
  -> checked low-level IR transfer function
  -> C-shaped contract
  -> generated ugly C
  -> compiled candidate
  -> Stage A validation against the original contract
```

## Selected Initial Cluster

Use the jq register-ABI call cluster that previously exposed the gap between
Stage A knowledge and Stage B C lowering:

- caller: `section-gap--text-0498`
- callee: `section-gap--text-0202`
- feature: internal register-carried direct call
- expected call setup:
  - `eax = ebx + 0x1c`
  - `edx = 1`
  - `ecx = ebx`
  - direct call target is `section-gap--text-0202`

This is intentionally narrow but not artificial. It exercises real jq code,
internal compiler ABI behavior, register-carried arguments, call target
recovery, source mapping, and the candidate validation loop.

## Deliverables

### 1. Stage A Semantic Region Contract

Add a Stage A artifact for the selected region that records the machine-level
behavior needed for implementation:

- region identity, RVA span, function/block aliases, and source-map id
- inputs: registers, stack slots, flags, and memory locations read
- outputs: registers, stack slots, flags, and memory locations written
- preconditions: required readable/writable memory ranges and alignment facts
- preserved and clobbered registers
- direct callsites, call targets, stack deltas, and register-carried arguments
- CFG exits and successor obligations
- import, thunk, padding, and section-gap classifications if present
- proof status and exact blockers for unsupported instructions or effects

The contract must be emitted as machine-readable JSON and linked from the
normal Stage A reference contract or proof inventory.

### 2. Checked Low-Level IR

Introduce a minimal IR subset that is small enough to verify for this slice:

- register move
- immediate load
- integer add with fixed-width wrapping semantics
- address calculation
- direct call boundary
- explicit preserved/clobbered register set
- explicit memory read/write summaries

For the selected cluster, Stage A must emit an IR transfer function equivalent
to the recovered x86 behavior, for example:

```text
tmp0 = add32(ebx_in, 0x1c)
eax_call = tmp0
edx_call = 1
ecx_call = ebx_in
call section-gap--text-0202(eax_call, edx_call, ecx_call)
```

Stage A must mechanically validate that the x86 region semantics imply the IR
transfer function under the recorded preconditions. If the proof cannot close,
the result is `incomplete`, not an accepted slice.

### 3. C-Shaped Contract

Lower the checked IR into an ugly-C contract that Stage B can implement without
guessing prototypes. The first version can use an explicit state object rather
than source-like function signatures:

```c
struct stageb_x86_state {
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    uint32_t esi;
    uint32_t edi;
    uint32_t ebp;
    uint32_t esp;
};

void section_gap_0498_contract(struct stageb_x86_state *s) {
    s->eax = s->ebx + 0x1c;
    s->edx = 1;
    s->ecx = s->ebx;
    section_gap_0202_contract(s);
}
```

The contract must keep the mapping back to original register, memory, CFG, and
callsite obligations so Stage B can report precise repair items.

### 4. Generated Ugly C

Teach Stage B to generate C from the C-shaped contract for the selected region.

Allowed in this slice:

- fixed-width integer types
- explicit state structs
- explicit memory helper calls
- explicit goto-style CFG
- conservative `volatile` use where required by the contract
- compiler attributes such as `noinline`, `used`, `noclone`, `optimize`, and
  section placement

Disallowed in this slice:

- raw byte transcription as the semantic implementation
- opaque whole-block asm islands as the semantic implementation
- original-binary execution or tracing during repair iteration
- accepting an unchecked decompiler prototype as proof of ABI correctness

Small compiler/linkage scaffolding is allowed only if it is reported separately
from the semantic C implementation and does not weaken Stage A validation.

### 5. C Contract Equivalence Check

Add a local checker for the selected IR subset:

```text
generated C contract transfer == Stage A IR transfer
```

For this slice, it is enough to cover moves, immediates, wrapping addition,
address calculation, direct call boundary setup, and preserved/clobbered
register summaries. The checker may be SMT-backed or Lean-backed, but it must
emit proof inventory entries and fail closed on unsupported C constructs.

### 6. Candidate Binary Validation

Compile the generated C through the current Stage B jq candidate path and run
the existing Stage A candidate validation against the selected region.

The validation must prove:

- the candidate establishes the required call inputs at the call boundary
- the direct call target matches the Stage A contract
- stack delta and cleanup behavior match
- preserved/clobbered registers match
- memory effects are equal or conservatively summarized
- the selected repair item disappears from `stage-b-explain-delta` or is
  replaced by a strictly smaller downstream obligation

## Implementation Steps

1. Add a region-contract schema for checked Stage A semantic contracts.
2. Emit the selected jq cluster contract from the existing reference contract
   evidence and recovered callsite inventory.
3. Add the minimal low-level IR and an x86-to-IR validation path for the
   selected instruction subset.
4. Add proof inventory entries for the x86-to-IR validation result.
5. Lower the checked IR into a C-shaped contract with explicit state inputs and
   outputs.
6. Generate ugly C for the selected region from the C-shaped contract.
7. Add the local C-contract equivalence checker for the IR subset.
8. Compile the jq Stage B candidate and run the Stage A contract delta.
9. Assert that the selected cluster's previous ABI/callsite repair item is gone
   or reduced to a smaller source-mapped obligation.
10. Document any unsupported instruction, memory, or compiler-lowering feature
    discovered during the slice as a new explicit follow-on contract family.

## Validation Commands

The exact command surface may evolve while this slice is implemented, but the
validated path should include:

```sh
nix develop .#test --command python -m unittest discover -s tests -p 'test_stage_[ab].py'
nix build .#checks.x86_64-linux.stage-b-jq-contract-smoke-check --no-link
nix build .#checks.x86_64-linux.stage-b-jq-contract-delta-check --no-link
```

Add focused unit tests for:

- region-contract schema validation
- x86-to-IR lifting for move, immediate, add, address calculation, and direct
  call boundary setup
- fail-closed behavior for unsupported instructions or ambiguous memory effects
- C-shaped contract emission from the checked IR
- generated C source mapping back to the original jq block and callsite
- Stage B delta ranking when the selected cluster is fixed or still incomplete

## Definition Of Done

The vertical slice is accepted only when all of the following are true:

- Stage A emits the selected jq region contract.
- Stage A mechanically validates the selected x86 region against the emitted IR.
- Stage B emits ugly C from the checked C-shaped contract.
- The generated C compiles in the current jq Stage B candidate path.
- Stage A validates the compiled candidate region against the original contract.
- No original-binary runtime tracing is used.
- No unchecked Lean markers, unchecked assumptions, or hidden waivers are
  accepted as proof.
- The Stage B delta for the selected cluster is gone or strictly reduced.
- Remaining jq failures are outside the selected cluster and are source-mapped.

## Non-Goals For This Slice

- Full jq reimplementation.
- Idiomatic C recovery.
- Complete type recovery.
- Complete global/data-structure reconstruction.
- General decompilation of arbitrary x86 instructions.
- Solving every hidden sret, varargs, jump-table, or runtime CRT case.
- Replacing the existing Stage A binary equivalence validation gate.

## Follow-On Slices

After this slice proves the end-to-end path, extend the verified decompiler one
feature family at a time:

1. Leaf arithmetic block with flags and conditional exit.
2. Memory load/store block with alias preconditions and lvalue summaries.
3. Hidden sret or out-param callsite.
4. Switch or jump-table dispatch cluster.
5. Small loop with explicit loop-carried state.
6. Function-pointer callsite with a recoverable target set.
7. Import or varargs bridge callsite.
8. Runtime CRT helper cluster that currently appears as candidate-validation
   call-target mismatch.

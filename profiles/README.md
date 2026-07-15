# External Environment Profiles

External environment profiles are reusable machine-level interface schemas for
Stage A's lockstep external boundary. They keep calling-convention and memory
footprint data outside the generic proof core.

`stage-a-generate-relation-contract --external-profile PROFILE`:

1. requires `stage-a-external-environment-profile-v1`;
2. validates every declared contract, including declarations not imported by
   the current binary pair;
3. rejects duplicate contract IDs and import identities;
4. selects only exact import identities present in both PE import tables; and
5. reports selected, ignored, covered, and uncovered common imports.

The option may be repeated to compose disjoint profiles. Profile ids and
selected import identities must be unique across the set. Stage A validates
each profile independently, rejects overlaps, and then assigns deterministic
contract ids in command-line order. This lets platform and library contracts
remain separately owned without requiring a target-specific aggregate file.

Selection does not prove an external call. Reachable call sites must still have
checked argument recovery, ABI transfer, memory footprints, world effects, and
paired-environment refinement before Lean can use them in the whole-program
theorem. Missing or ambiguous evidence remains `incomplete`.

`pe32-kernel32-lockstep-v1.json` is deliberately small. It contains ABI and
caller-memory effect schemas for nine Kernel32 calls encountered in the current
generic PE32 integration target. It does not claim to model Kernel32 or Windows
operationally. The final theorem remains conditional on external environments
that satisfy these schemas; changes to a schema alter the relation-contract
hash and invalidate dependent proof artifacts.

APIs whose correctness requires an unsupported world feature remain absent.
Callback registration is not approximated as an opaque resource. The supported
registration effect consumes one related machine argument, resolves both
concrete addresses to one checked static code-map target, and prepends the pair
to an ordered relational callback inventory. All other world components must be
preserved. Invocation still requires a separately checked nested external frame;
registration alone does not authorize callback execution.

`pe32-msvcrt-lockstep-v1.json` starts the CRT lifecycle profile with `free`,
`atexit`, and the non-returning `_amsg_exit` boundary. The `free` contract
requires one cdecl pointer argument and removes the uniquely matching paired
dynamic range; a null pointer is an exact no-op. It does not treat deallocation
as an unconstrained memory mutation or leave a released range silently live in
the relational world. The `atexit` contract requires one cdecl callback pointer
and records a checked mapped callback pair in LIFO registration order. `exit`
uses the stateful `protocol` disposition rather than immediate termination
because it may invoke those callbacks. Contract generation retains that
declaration for precise diagnostics, but whole-program acceptance rejects it
until the paired returned/callback/terminated action proof is present.

Machine-call contracts default to `"disposition": "returns"`. A reviewed
`"terminates"` contract still requires exact lockstep import identity and
related machine arguments, but produces an external observation followed by a
distinct terminal execution state. It cannot declare a successor stack delta,
memory effect, footprint, or relational-world update; malformed combinations
fail contract validation and Lean's independent shape check. The transition
does not query either external environment for a return result. This is suitable
only when the imported call cannot return under the selected environment
profile. The declaration is an explicit theorem assumption, not inferred from
an API name by the generic proof core.

`"protocol"` is a reviewed declaration surface for stateful, well-bracketed
interactions. It must use `"world_effect": "none"`; world changes belong to
the checked sequence of protocol actions rather than one opaque call result.
The declaration alone never authorizes acceptance. Until Stage A emits and
checks those action cases, the acceptance plan reports
`external_protocol_refinement_incomplete`, and Lean independently rejects the
contract's shape.

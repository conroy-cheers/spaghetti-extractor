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
For example, callback registration is not approximated as an opaque resource;
it requires a checked callback target and nested-frame protocol first.

`pe32-msvcrt-lockstep-v1.json` starts the CRT lifecycle profile with `free` and
the non-returning `_amsg_exit` boundary. The `free` contract requires one cdecl
pointer argument and removes the uniquely matching paired dynamic range; a null
pointer is an exact no-op. It does not treat deallocation as an unconstrained
memory mutation or leave a released range silently live in the relational
world.

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

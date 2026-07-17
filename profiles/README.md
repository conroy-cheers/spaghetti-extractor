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

Footprint sizes may use `bounded_terminated` for aligned sentinel-delimited
input, or `argument_or_bounded_terminated` when a count word selects between an
explicit element count and sentinel scanning. These forms name the source
argument, source offset, unit width, exact sentinel bytes, and a finite unit
bound. Lean scans pre-call memory at unit-aligned positions, includes the first
matching sentinel in the extent, and rejects null sources, address-space wrap,
and bound exhaustion. The selector form multiplies a non-sentinel count by the
declared unit width with the same PE32 overflow checks. Memory-dependent sizes
are footprint-only and are rejected for allocation-result relations. They
authorize no call by themselves: a pointer relation, readable paired contents,
matching termination evidence, and external-environment refinement are still
required.

`pe32-kernel32-lockstep-v1.json` is deliberately small. It contains ABI and
caller-memory effect schemas for nine Kernel32 calls encountered in the current
generic PE32 integration target. It does not claim to model Kernel32 or Windows
operationally. The final theorem remains conditional on external environments
that satisfy these schemas; changes to a schema alter the relation-contract
hash and invalidate dependent proof artifacts.

`pe32-kernel32-console-lockstep-v1.json` adds the bounded console protocol used
by the no-CRT WinAPI hello fixture: `GetStdHandle`, `WriteFile`, and terminal
`ExitProcess`. The `WriteFile` contract reads exactly the requested source
range and permits only its optional four-byte count output to change. The
return from `GetStdHandle` is a paired opaque resource; concrete handles do not
need to be equal across the two executions.

APIs whose correctness requires an unsupported world feature remain absent.
Callback registration is not approximated as an opaque resource. The supported
registration effect consumes one related machine argument, resolves both
concrete addresses to one checked static code-map target, and prepends the pair
to an ordered relational callback inventory. All other world components must be
preserved. Invocation still requires a separately checked nested external frame;
registration alone does not authorize callback execution.

`pe32-msvcrt-lockstep-v1.json` starts the CRT lifecycle profile with `free`,
`atexit`, the non-returning `_amsg_exit` boundary, `__set_app_type`, and the
process-lifetime storage accessors `__p___winitenv`, `__p__fmode`, and
`__p__commode`. The accessors demonstrate the generic
`dynamic_range_base` result relation: `EAX` must name both sides of one checked
paired range, the range must contain at least four bytes, and its first word
must satisfy `related_word`. The result relation carries a checked allocation
size expression, typed required-word relations, and explicit nullability. The
declaration is data-driven; the proof core
does not dispatch on the CRT symbol name. `malloc` and `calloc` use the same
generic result relation with argument-derived allocation sizes. Their
`newDynamicRanges` memory effect permits changes only in ranges newly added by
the checked world transition and preserves all previously visible addresses.
`memcpy` demonstrates the returning argument-range transfer family. Its three
cdecl machine words are recovered from the thunk boundary, `EAX` must remain a
related word, the source range is read-only, and writes are framed to the
destination range with the third argument as the byte extent. This is not a C
prototype in the proof core: the profile supplies only ABI words, machine-level
footprints, result locations, and world effects. A site with a missing argument
word is rejected before Lean generation, and Lean's contract-aware decoder
independently reconstructs exactly the selected contract's argument count from
the PE bytes.
Object word shapes remain call-site invariants, rather than API-wide layouts;
the paired environment and continuation `StateRel` must establish every shape
that later code reads. The `free` contract
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

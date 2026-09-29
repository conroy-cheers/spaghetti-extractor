# jq execution lifecycle

The 27 existing public operations in `native-entries.json` manage a `jq_state`:
creation/destruction, compile/start/reset, attributes, callbacks, error and halt
outcomes. The additional existing `_jq_path_append` entry lets the getpath
builtin update that same state's path tracking; its three value arguments are
consumed and its result is an owned reference. `jq_next` remains the independently
lifted interpreter. Private stack,
frame, reset and bytecode optimization helpers stay inside ordinary C.

`state-layout.h` retains the interpreter's exact state and frame definitions;
preparation checks their correspondence. Stack positions are signed offsets
within the live shared stack allocation. They are not reconstructed pointers or
copied heap snapshots. Allocation growth moves the same logical stack, and
reset/destruction release its owned values and frames. The stack uses the same
value/allocation provider as its existing consumer, including release.

`jq_init` returns an owned state or null. `jq_teardown` nulls its caller's slot
before destroying owned state and tolerates an already-null slot. Compile
replaces the previous bytecode; start discards pending results, resets errors,
and consumes its supplied input. Attribute setters consume values; getters
return owned references. Callback functions and data remain borrowed while
registered. Message callbacks consume their message; input callbacks return an
owned value. Callers keep borrowed code text alive throughout compilation.
Mutation/reentry into the same executing state, asynchronous destruction,
concurrent state access, stack exhaustion and allocation failure are outside the
compared consumer profile. Separate states may be interleaved.

The public jq header declares `jq_get_attrs`, but the pinned implementation has
no definition for it; this boundary does not invent one. Compiler, bytecode,
location, value and allocation operations remain executable neighboring services.
The default diagnostic callback uses the platform stream provider; it is not a
claim about terminal/locale compatibility. The separately documented binary
stream and filesystem profiles still apply to complete programs.

Native comparisons replace and trap these 28 entry bodies, while original stack
helpers required by the native interpreter remain available. Portable assembly
removes all superseded `execute.c` definitions, including now-unused helpers.
The native adapters preserve general registers other than return values to
respect optimized native callers; EFLAGS and SIMD/x87 preservation are outside
that adapter's guarantee. Ordinary production C uses the host ABI.

The consumer observes two contexts, repeated/abandoned starts, recompilation,
callback identities and events, attributes, bytecode, halt outcomes, retained
input aliases and final allocation lifetime. These are finite behavioral
comparisons with source-assisted authoring, not checked formal summaries or
whole-program qualification.

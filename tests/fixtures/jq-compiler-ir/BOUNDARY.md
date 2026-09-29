# jq instruction graphs and binding

This module supplies the 58 existing operations declared by `compile.h`, except
`block_compile`, which remains the independently lifted bytecode compiler. The
operation names and native signatures are retained in `native-entries.json`.
The generated request record carries those arguments without copying or
reconstructing the pointed-to graph. Private construction/binding helpers stay
inside ordinary C; they are not additional component or native entry APIs.

The shared `instruction-layout.h` is the exact definition already used by the
bytecode compiler. Instructions form doubly linked lists, with nested blocks,
binding/branch aliases, value constants, symbols, callback descriptors and retained
source locations. These fields preserve their meanings across parser, binder,
module loader and lowerer. A block is a handle into this live graph, not a copied
heap. `compiled` and bytecode positions are written later by the lowerer.

Ownership follows the existing C API:

- Constructors transfer supplied value/block ownership into their result.
  Joining/appending and syntax generators splice or consume input graphs; old
  handles are not independent owners after those calls.
- Kind/shape/metadata queries borrow their graph; value queries return owned
  references. `block_take_imports` mutates its owner and transfers extracted data.
- Binding operations borrow binder handles while modifying matching references
  in graph bodies. Returned composed graphs own the resulting instruction lists.
  Aliases such as `bound_by`, branch targets and nested scopes must be preserved.
- `gen_location` retains the source location for previously unlocated nodes.
  Names are copied where the native code copies them. C callback descriptors
  remain borrowed until the compiler has copied the selected function table.
- `block_free` recursively releases graph-owned symbols, values and location
  references. Shared binding/branch links are references, not extra owning edges.

Callers must supply the well-formed graph shapes expected by the respective
native operation. Cyclic owning lists, overlapping owned blocks and dangling
binders are not admitted. No new safety or failure semantics are invented for
inputs on which the target asserts or has undefined behavior. Allocation failure,
asynchronous callbacks, concurrent graph mutation and stack exhaustion are outside
the compared scope.

Opcode metadata, location services, value operations and allocation remain
executable C dependencies. The native adapter binds private services by reviewed
RVA and formats variadic location diagnostics before forwarding them. Both sides
use one controlled process environment. Native consumers compile and execute
real programs in two independent jq states, inspect bytecode graphs/metadata,
observe callbacks and retained input aliases, and release all state.
String duplication and matching-name disposal use the existing unguarded strdup
and free services, so native observation covers both acquisition and release.
This retains the target's unguarded allocation-failure behavior.

Native comparison traps all 58 selected entry bodies. Original private helpers
shared with the unmodified native lowerer remain available to that neighbor.
Portable assembly removes the superseded `compile.c` definitions, including
dead lowering helpers already replaced by the bytecode compiler. Declared entry
symbols and removed helper definitions are distinct sets.

Native entry compatibility is stronger than a C signature: the pinned lowerer
keeps ECX live across its call to the leaf `gen_noop`. The comparison adapters use
GCC's `no_caller_saved_registers` with general-register-only code generation,
preserving general registers other than ABI return values. This is native entry
glue only; the portable C and production adapters use their ordinary platform
ABI. EFLAGS, SIMD/x87 state, other optimized calling conventions and asynchronous
entry are not generally covered by this adapter. Native faults are reported as
unsuccessful observations, without waiting in an interactive debugger.

This is source-assisted C authoring and finite behavioral comparison. The shared
layout and service declarations are not checked formal summaries; source-profile
eligibility does not grant proof or whole-program qualification.

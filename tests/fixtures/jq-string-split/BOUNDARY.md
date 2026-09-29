# Split two live string inputs

`run(value, separator)` consumes both owned string references and returns an owned
array of strings. The parameters may share an allocation with separate owned
references; retained aliases keep their contents. Lengths are at most INT32_MAX.
The empty-separator branch admits well-formed UTF-8 text, including embedded NUL.
Malformed text with an empty separator, invalid kinds and corrupt allocations
are excluded. Arbitrary byte contents are admitted with a nonempty separator.
The normal jq parser supplies well-formed text; raw C callers must meet this
boundary. This restriction is an explicit assumption, not a checked invariant.

The complete pinned PE32 `jv_string_split` body occupies RVA `0x2bac0..0x2bfb5`,
including three assertion tails. The source side traps this body. Its loop and
service order were reviewed against disassembly with pinned upstream C assistance.
Empty text returns an empty array. Adjacent and terminal separators produce empty
items. Empty separator splits by Unicode character. Substring and character
construction precede append; both inputs are released at the end. Integer offsets
avoid the original loop's out-of-allocation pointer arithmetic after a final miss.

The existing `contents`, `create` and `release` declarations, string view, live-value
transport and allocation observer are reused. Views borrow actual heap contents
until release. Additional services expose array construction/append, validity,
empty-string construction and character construction. Their C adapters contain
no splitting or search algorithm. The slice component's preallocated-empty
constructor is deliberately not reused: it has different allocation behavior.

The local driver observes result contents, retained aliases/reference counts and
allocation lifetimes. An interpreter case calls the replacement through `split`.
Single-threaded execution, live objects and the original allocator/reference
counter/interpreter remain dependencies. Allocation failure, callbacks, reentrancy
and concurrency are unobserved. Finite comparisons are experimental evidence;
these declarations and generated runtime checks are not formal memory summaries.

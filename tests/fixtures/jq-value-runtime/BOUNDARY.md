# jq shared value-runtime boundary

Forty-one existing entries cover immediate values, invalid values and messages,
array construction/append/concatenation, string storage/mutation/formatting/hashing,
object creation/mutation/iteration and reference-count reads. The forty
operations share the ordinary C payload definitions in value-runtime.c. Both
variadic formatting entries transport a live va_list to one implementation.

This is source-assisted from pinned jq 1.8.1 under COPYING. Values retain the
existing kind tags, payload layouts and consuming jv conventions. Kind queries,
reference-count queries, string-byte access and object iteration borrow input.
Iteration returns owned references to keys and values. String bytes are borrowed
only while the payload remains alive and unmoved; mutation may allocate and
invalidate such pointers. Explicit retained aliases force copy-on-write. Cached
hashes are invalidated by string edits. No pointer reconstruction establishes
ownership, contents or lifetime.

Array storage, numeric values, object allocation/unsharing/release, allocation,
Unicode conversion and the hash-seed runtime remain executable dependencies.
Object growth transfers references into the new table and releases only the old
table. Hashing reads little-endian words explicitly instead of casting byte
storage to host words. The same seed and once-initialization state is shared with
neighboring routines. The component does not create another seed or claim to
lift its entropy provider. The native fixture initializes then fixes that shared
seed before allocating keys, on both comparison sides.

Native entry hooks disable the selected original entry bodies. Explicit adapters
use the reviewed private object constructor/unshare ABIs. Private helpers still
needed by original neighbors are not claimed as absent. Authored C stays portable;
native calling conventions and standalone assembly are ordinary external adapters.
The comparison observes byte-exact values, aliases, reference counts, hashes,
iteration and residual allocation effects, including actual compiler/interpreter
consumers. It does not weaken the separate formal-qualification requirements.

The profile assumes valid jv handles, API-appropriate kinds and lengths, live
borrowed buffers and valid variadic arguments. It excludes corrupted handles,
allocation failure, pointer-valued printf output, concurrent mutation of shared
payloads and a changed floating-point environment. Invalid UTF-8 input and the
documented replacement behavior are included. Platform formatting/entropy and
Unicode libraries remain explicit runtime dependencies. Finite comparisons and
assumptions are not universal equivalence claims or activation authority.

The release entry dispatches all valid kinds to the owning destructor and
consumes one reference. It recursively reaches the existing array, numeric and
object lifecycle providers; nested original jv_free bodies are disabled in the
native comparison. Standalone assembly keeps array-storage as the public jv_free
provider and supplies backend_free only for its guarded non-array service. This
is a restricted invocation of the checked dispatch, not an inferred replacement
from a matching signature. Its array service forwards to selected array storage.


The slice-bounds refinement consumes the value and object descriptor (including
its start/end values) through existing services. Arrays use element counts and
strings use codepoint counts. Null bounds default, NaNs and infinities retain
the original conversion behavior, and fractional ends round upward. Both output
pointers must be valid writable integers; they may alias each other. They remain
unchanged on error. Retained aliases to input values survive all consuming calls.
The native adapter preserves the reviewed private hidden-result ABI. Normal
get/set/delete consumers and direct error/sentinel cases exercise this boundary.

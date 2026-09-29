# jq equality, containment and merging

Five operations consume two owned `jv` references. `equal`, `identical` and
`contains` return an integer in `comparison`; `merge` and `merge_recursive`
return an owned value in `value`. Merge inputs must be objects. Equality and
identity also accept invalid values, as the native low-level API does. Callers
retain aliases with `jv_copy`; returned values can be released independently.

The shared `jv` handle ABI carries kind/allocation flags, offset, size and the
pointer/number union. This component depends on those handle fields, but not
the private allocation layouts for arrays, strings or objects. It uses existing
value accessors, object iteration, copy-on-write mutation and numeric comparison.
Object presence is separate from its stored value: a slot containing an invalid
value must not be mistaken for a missing slot. String containment is bytewise,
including embedded NUL. Array containment is recursive and not multiplicity
matching. Object merging retains the target's shallow/recursive distinction.

The pinned target's equality shortcut ignores the offset of equal-length views
sharing one allocation. Preserve that behavior instead of silently correcting
it. Identity checks the offset and compares the complete immediate union bytes;
positive/negative zero can therefore be equal without being identical. The
native scenarios create real shared views and exercise these distinctions.

Native comparison replaces and traps five public bodies and their exclusive
numeric/array/object relation helpers. Shared string equality remains available
to native object lookup. Numeric comparison, handle ownership and C accessors
are executable dependencies, not checked formal summaries. Observations cover
results, retained aliases, backing identity, reference counts and final heap
lifetime. Finite cases do not qualify allocation failures, all invalid payloads,
stack exhaustion or arbitrary representation changes.

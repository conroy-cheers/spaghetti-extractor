# Hand-defined shared-buffer boundary

This is the ordinary-C candidate and canonical interface for Metapad's actual
resource-text helper, RVA `0x1284`–`0x12a7`. It reads the current module cell,
calls the declared service with the same 500-byte shared buffer, ignores the
scalar service result, and returns that buffer. It promises no NUL termination.

The files preserve the inputs from
`build/independent-lifting/real-network/resource-text/`. The canonical interface
intent digest is
`42063d3cf2f366744d828c5cea84693ca7558b1d80b531cf97b80972840eeceb`.
The original PE digest is
`685989bad8d8119eddbb49e36006d8ac9155c45d69dee060807368241c8e58ce`;
the exact transfer-plan digest is
`1d1eb428e0fd4a37fc41090ca8904cf83597ce561d3de2be773cf5618c798781`.
The repository test needs no binary extraction or pilot build.

`test_hand_defined_boundaries.py` compiles the candidate with the normal generated
headers. Its deliberately small service fixture checks that successive callers
share storage, old returned views observe later writes, and each call reads the
current module value. The fixture supplies writes and scalar outcomes; it is
not an implementation or checked model of LoadStringA. Untouched nonzero bytes
make accidental initialization or an invented terminator visible.

These are concrete source behavior checks, not equivalence or lifetime proofs.
The interface's `complete` status means its declarations are complete. It does
not establish a frame, alias theorem, service semantics, termination or provider
qualification. In particular, the interface types alone do not encode the
required result-to-state alias theorem. Fixed shared-image native state/result
transport now checks the unique matching state binding and the full returned
descriptor, but local checked composition remains open. The source's provisional access-failure return also
remains unqualified. Update these gaps when the corresponding rules land;
do not freeze unsupported behavior as the intended final API.

`test_shared_state_views.py` runs the actual candidate through the state and
result transducers with a controlled runtime and service. It checks repeated
calls and current aliases, stale generation rejection, changed descriptors and
bindings, and refusal to persist a borrowed runtime. A separate service-free
transport fixture compiles the complete operation overlay for host and PE32;
this does not supply the real helper's missing service contract. The solver
fixture stores only three observed cells within the declared 500-byte origin.
All twelve finite corruption cases run separately with safety checks, avoiding
an unnecessarily merged symbolic pointer graph. Neither the origin fixture nor
these concrete scenarios prove general image lifetime or service behavior.

`test_borrowed_state_admission.py` retains `initial: null` as borrowed state in
the proof kernel, checks its entry/exit binding, and uses the full paired engine
on a small operation that copies a current module byte into the shared buffer.
The source cannot replace that byte with zero, and missing origin authority is
rejected. That operation is a test of arbitrary initial-memory correspondence;
its transfer body is explicitly different from the actual service-calling helper.
Its satisfied contextual gate is scoped to the fixture world and provides no
native qualification for Metapad.

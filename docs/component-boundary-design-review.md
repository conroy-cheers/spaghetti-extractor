# Review: boundary design across target families

Status: design review, 2026-09-08. This review corrects and extends the
[proposed design](component-boundary-design.md). It grants no proof or runtime
authority. Engine changes remain paused during this review.

## 1. Verdict

The first draft was a useful decomposition of responsibilities, but was **not
comprehensive enough to support a broad-target adequacy claim**. Several issues
were missing semantic distinctions, not just absent implementation features:

| Finding | Why the original wording was insufficient | Required correction |
|---|---|---|
| Storage aliasing | One store per object can duplicate bytes shared through different mappings | Separate logical objects, mappings and backing storage |
| Open behavior | Matching complete outcomes does not specify readiness, choice ownership or deadlock | Causal, branching matching under all admitted environment inputs |
| Pending work | Call return can occur before buffer/resource obligations end | Enduring request/borrow state with completion and cancellation transitions |
| Nonlocal control | An exceptional return tag does not describe cleanup or resumption | Explicit partial effects, unwind and checked resumption entries |
| Frame locality | Disjoint bytes do not guarantee independence from allocator state or interference | Context-extension and stability premises |
| Long-running objects | Bounded total history is exhausted even with one live allocation | Checked history abstraction, including stale identities and wrap behavior |
| Environment closure | Individually consistent assumptions can be incompatible when composed | Joint assumption discharge against the actual admitted environment |
| Portability | Different platforms can expose different service, arithmetic and identity behavior | Explicit observation/environment and language profiles |

These corrections are incorporated into the main design. They make the design
more defensible; they do not amount to a general soundness proof. Progress
toward many independently liftable units should be measured against a capability
and interaction matrix, not inferred from several examples using the same
sequential image-memory model.

## 2. Inspection and evidence limits

This review inspected the current design, plans, canonical boundary and native
ingress documentation, selected Hello/jq/DX-Ball interface intents, and the
following implementation responsibilities:

- `components/bisimulation_reference_origins.py` binds an issued identity to
  a base/lifetime; its concrete policy rejects moving that identity. This is a
  valid restricted realization, not a general mapping/backing-store abstraction.
- `components/bisimulation_allocation_cuts.py` explicitly bounds incoming
  history. The design must distinguish this bound from a bound on live objects.
- `candidate/outcomes.py` already distinguishes normal, no-return, exceptional
  and nonlocal outcomes, with SEH resumption/unwind fields. The new component
  design must compose that existing meaning rather than invent a return-only
  exception model.
- [Checked atomics](atomics.md) require the selected event-graph correspondence
  and restrict the machine profile. A sequential shared-state contract cannot
  silently replace those requirements with interleaving or C atomics.
- `transfer/x87.py` models explicit typed x87 operations and control state.
  Machine floating point is not automatically ordinary host `double` semantics.
- The jq `output-value-pipeline`, DX-Ball `directdraw-init`, and Hello
  `program-name-selection` intents provide concrete navigation into value/service,
  resource and returned-reference cases. Their declared status or signature is
  not evidence that the expanded rules in this review are implemented.

No fresh pilot qualification or full repository validation was run for this
review. Small executable countermodels below check the design reasoning only.
API facts are checked against primary documentation and cited beside their use.

## 3. Fundamental semantic corrections

### R1. Define the observer and environment before claiming equivalence

The theorem should state its admitted original environments, portable
environments, relation between them and observations to be preserved. A native
client may observe pointer equality, thread-local state, callbacks, errors or
intermediate shared memory. A platform service backend may translate calls,
but must prove that translation under the selected observation relation.

This prevents two opposite failures: equating incompatible behaviors because
their signatures match, and unnecessarily requiring identical internal bytes
where a checked abstraction is available. Observation policy is part of proof
authority; an operator cannot weaken it locally to make a rewrite pass.

The private-memory argument must quantify over all admitted observers, including
native consumers that compute addresses rather than receive typed pointers.
Code loading, a published callback or an escaped reference can enlarge that set.
Checked closure of entries and observers is required at composition, with exact
ownership and dynamic-target rules retained. Unknown code is not automatically
harmless because no static edge was recovered.

For an unsupported region, a checked exact implementation may remain a supplier
only with a qualified boundary contract. An opaque external assumption can
support conditional exploration, but cannot authorize whole-program replacement.
This is essential for gradual lifting without pretending that a partial graph
is a closed program.

### R2. Distinguish allowed input, internal choice and output

Consider two servers. After emitting `ready`, P accepts either request `b` or
`c`. Q secretly commits to accepting just one before emitting `ready`. Their
successful trace sets both contain `ready,b,ok` and `ready,c,ok`. Nevertheless,
an environment can send the other request after Q commits and cause rejection
or blocking. Successful complete traces alone miss the distinction.

At related states the rule must preserve admitted input readiness and match
observable steps with the right quantifier order: for every admitted environment
choice and relevant actual step, obtain a match based on the history so far.
The matcher cannot choose the request, discard a branch, or use a future
completion value to decide an earlier output. Apply the required reverse
matching too; specification refinement is not itself bisimulation.

The shared oracle used by a supported paired proof must be justified as a
coupling of the same admitted environment behavior. Merely making both sides
read one symbolic array does not establish that all actual behaviors are covered.
Input responsiveness, internal divergence, deadlock and successful termination
are separate obligations when observable in the selected domain.

This uses the input/output distinction developed in
[Interface Automata](https://www.csd.uoc.gr/~hy565/docs/pdfs/papers/interface_automata.pdf).
Its existence-of-a-compatible-environment criterion is insufficient for our
qualification: here the actual admitted environment must discharge the joint
assumptions for all its executions. We are not adopting optimistic pruning of
unwanted original executions.

### R3. Object identity does not uniquely identify storage

Two read/write mappings at different virtual addresses can expose the same
backing bytes. Microsoft documents coherence of local mapped views and also
exceptions for remote files and ordinary file I/O. Thus a universal rule that
each mapping has independent memory is wrong, and universal coherence of all
access paths is also wrong. The selected mapping/service contract must decide.
[MapViewOfFile](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile).

Use three related notions: logical object/reference validity, virtual mapping
and backing-cell identity. Permissions and lifetime can differ by mapping.
Unmapping A may invalidate references through A while B still exposes the same
storage. Copy-on-write changes the backing association at the specified granularity.
Subobjects and custom allocator arenas similarly require overlapping structural
views without manufacturing independent bytes or duplicate ownership.

A reserve/commit/decommit protocol cannot be represented by one boolean `live`.
For example, reserving address space does not provide committed storage; later
page transitions change accessibility. Keep those distinctions in the selected
memory capability instead of forcing every ordinary heap proof to expand them.
[VirtualAlloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc).

Do not collapse logical generations, mapping generations and backing lifetime
into one counter. Conversely, do not add three counters to every runtime object
without a real consumer: the design requires semantic distinctions, with a
minimal identity mapping for the currently supported simple heap domain.

### R4. Footprints require locality and temporal stability

Suppose C allocates the last available block in a bounded allocator. Adding a
disjoint live allocation to its context can change success into failure without
changing any input byte C reads. A byte-only footprint incorrectly suggests
that the added context is irrelevant. Allocation availability and identity
choices belong to the relevant environment/resource dependencies.

For a framed predicate F, require that admitted local and environmental
transitions preserve F. For concurrent interference relation E, this includes
`F(s) and E(s,s') implies F(s')` wherever F is retained. Each operation's actual
guarantee must preserve its neighbors' relied-upon conditions. A no-write
declaration is insufficient when another actor writes, frees, remaps or publishes
the storage during an interaction.

World relations must also survive admissible extension: fresh objects or
requests extend the correspondence without reinterpreting old escaped values.
A different existential witness at each cut is unsound if those witnesses
disagree about a reference or hidden state still used by the context. Structural
recursion needs a guarded/inductive rule; finite acyclic dependency discharge
does not justify general mutually recursive summaries.

### R5. Outstanding obligations outlive a call

An asynchronous write can return while its buffer is still borrowed. The API
requires that buffer to remain valid and unused until the operation completes.
Model submission separately from completion; the operation's return cannot
restore permissions or retire the request.
[WriteFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile).

Cancellation is another transition, not completion. A cancellation request may
race with normal completion or another error, and CancelIoEx does not wait for
the operation to finish. The OVERLAPPED storage cannot be reused merely because
the cancellation request returned successfully.
[CancelIoEx](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelioex).

The minimal request relation records identity/generation, borrowed ranges,
pending/completed state, completion delivery authority and possible dispositions.
The call stack and the pending-request set are distinct. Thread exit, handle
closure, cancellation, duplicate completion and resource reuse all need the
selected protocol's treatment. Cross-thread completion is an interaction with
the relevant interference and memory-order rules, not a fresh ordinary call.

This is also the structure needed for deferred callbacks, timers, message
payloads and registered buffers. It is a correction to the contract model even
if asynchronous supplier qualification is implemented after the first real
sequential network.

### R6. Reentrancy, concurrency and loader phase are separate axes

SendMessage can invoke a same-thread window procedure directly. During a
cross-thread send, the sender can process incoming nonqueued messages while
waiting. A synchronous API is therefore not a proof of non-reentrancy.
[SendMessage](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendmessage).

For every interaction specify permitted reentry, thread relation, suspended
frame, invariant phase and outstanding capabilities. If the original permits
reentry while an invariant is open, the component must expose the weaker phase
relation or use another proved representation; rejecting the actual callback
through a stronger precondition cannot qualify it.

Concurrent access also requires the selected memory model. The store-buffering
example in the finite checks below admits both reads seeing zero under a small
TSO model but not under sequential consistency. This illustrates why replacing
machine actions with arbitrary host-C loads or a sequential interleaving can
lose behaviors. The formal x86-TSO model explicitly includes store buffers.
[Owens, Sarkar and Sewell](https://www.cl.cam.ac.uk/techreports/UCAM-CL-TR-745.html).

The repository's current [atomic policy](atomics.md) is stricter than arbitrary
concurrent refinement. Preserve that policy until a reviewed composition rule
and backend justify more transformations. Undefined data races in authored C
cannot stand in for defined admitted machine behavior.

Initialization/shutdown phase and lock context are dependencies too. DllMain
executes under the loader lock and has restrictions on operations that can
reenter the loader or cause deadlock. A service summary suitable after startup
may be invalid during DLL initialization.
[DLL best practices](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-best-practices).

### R7. Unwind and resume cannot be folded into a return code

An operation can write a field, raise an exception, run cleanup while unwinding,
and transfer to a handler outside its normal call chain. A continuable exception
may instead resume. The system supports both hardware/software exceptions and
termination handlers; cleanup semantics are part of control flow.
[SEH](https://learn.microsoft.com/en-us/windows/win32/debug/structured-exception-handling),
[exception handling](https://learn.microsoft.com/en-us/windows/win32/debug/exception-handling).

Use the existing outcome/SEH authority to relate partial memory effects, handler
selection, unwound frames, released resources, expired stack references and
resumption state. A handler resume point inside a region is an entry requiring
coverage. A normal-return invariant is insufficient when cleanup can observe
the partially updated state. `longjmp`, fibers or other nonlocal transfers need
their own supported protocol; a generic exceptional tag does not supply it.

Native exception addresses and return/function-pointer identity can also expose
code layout. Preserve the existing pinned-layout requirements where applicable.
Do not infer a new freedom to move code from a high-level exception type.

### R8. Ambient state and portability must be explicit

GetLastError observes per-thread state. Adding an adapter helper between a
failing call and that observation may change behavior even if all explicit
arguments and output buffers match. Its update/preservation rules belong in
the selected service contract.
[GetLastError](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror).

The same design issue applies to `errno`, locale, current directory, environment
variables, stream state and floating-point control, when actually read or
modified. Depend on the relevant projections rather than expanding one global
process-state model into every proof. Shared resource identity matters: separate
handles can refer to one resource state while having different handle lifetimes.

The portability profile must name integer widths and wrap behavior, shifts,
alignment, endianness, encoding, pointer representation, padding/object-byte
observations and floating-point behavior. For example, a proof using a native
x87 helper does not qualify an arbitrary host `double` rewrite. Native compiler
options, ABI lowering and linked runtime implementations stay in evidence binding.

Separate two achievements: removing machine-shaped source while retaining
qualified platform adapters, and exporting a portable program with qualified
service replacements on another platform. Broad target coverage needs both;
changing externally observable behavior during a port is a different claim.

### R9. Bounded live state is not bounded history

A loop may allocate, use and release one object forever. Its live set is bounded
by one; its allocation history and monotonically increasing identity counter
are not. Copying all retired rows at every cut eventually exhausts a fixed
bound. This is an expressiveness problem for event loops and streaming programs,
not just a performance problem.

A checked history abstraction can retain the identities still observable and
a summary preventing stale references from becoming valid. If no stale aliases
remain, an induction may forget more history. If identifiers wrap, their actual
reuse behavior must be proved safe or retained as a bounded domain obligation.
An unbounded mathematical fresh-name supply cannot silently implement a wrapping
native counter. The same concern applies to callback and request generations.

Ghost snapshots can also grow indefinitely if every past call creates a new
retained `old` memory. Keep only snapshots required by current invariants and
prove the soundness of forgetting/summary transitions. The useful scaling bound
is on active dependencies and protocol state, not elapsed execution length.

### R10. Reuse and compatibility need three separate checks

1. A cached consumer theorem is still about the same admitted premises,
   observation policy, code/model and checker semantics.
2. Current suppliers discharge those premises jointly, including environment,
   representation, lifetime, progress and interference assumptions.
3. Selected implementations remain equivalent to the exact original behaviors
   and are linked through the existing native authority chain.

A postcondition strengthened from `result in {0,1}` to `result=0` may preserve
an old client's property yet remove original nondeterminism. That is safe reuse
of a theorem only if independent pair qualification still supplies equivalence;
it is not permission to drop behavior. Similarly, an extra no-callback or
single-thread assumption is a changed contract even if no C signature changes.

Dependency selection must include all admitted assumptions and their closure,
not just facts mentioned in a displayed assertion. A proof region change may
leave the external contract unchanged, but adjacent transport proofs must be
redone. A whole-C-file hash may currently force broader local recompilation;
claim finer caching only after isolating the relevant artifact boundaries and
measuring actual regenerated models. Do not weaken binding to manufacture reuse.

## 4. Coverage matrix for target families

These rows are acceptance classes, not statements that the listed programs are
qualified. The first three have in-repository intent anchors; later rows specify
hand-defined stress cases before selecting unrelated real consumers.

| Target family / anchor | Required boundary capabilities | Combined case that must pass |
|---|---|---|
| Hello / program-name selection | Terminated readable views, interior aliases, shared result lifetime | Select an interior name, retain it, consume it through another operation |
| jq / output-value pipeline | Aggregate transport, shared value ownership, stream effects and failure | Copy/dump/release across two consumers, including a changed implementation |
| DX-Ball / directdraw initialization | Resource identity, partial initialization, service ordering and failure cleanup | Fail after one acquisition; retain correct caller ownership and cleanup |
| Editor / Metapad cleanup network | Mutable loop, allocations, actual callers, multiple cuts | End-to-end local edit/refine/reuse with full predecessor admission |
| GUI / nested messages | Synchronous callbacks, reentrant frames, intermediate invariants | Send while state is open; nested callback reads or mutates it |
| DLL / plugin host | Loader phase, exports, unload, dynamic targets and function identity | Publish callback, attempt unload with outstanding use, then valid teardown |
| File/network service | Asynchronous borrow, cancellation, partial completion, thread handoff | Cancel races with completion while a buffer alias remains reachable |
| Database / mapped storage | Backing aliases, page state, shared access and exceptions | Write through one mapping, read through another, unmap only the first |
| Multithreaded worker / reference count | Atomic semantics, visibility, lifecycle and interference stability | Publish data then release/consume under the selected machine memory model |
| Numeric/media code | Floating-point mode, vector/unaligned access and explicit backend semantics | Same arithmetic inputs under distinct control/rounding state |
| Parser / custom allocator | Subobjects, arena ownership, recursion and escaped interior references | Reuse an arena while a stale interior reference is retained |
| Long-running event loop | Induction, bounded active state, summarized history and fairness domain | Many allocate/free and callback cycles without accumulating proof history |

Also cover binary reconstruction limits: unresolved indirect entries, packed or
self-modifying code, dynamically generated code, unusual calling conventions,
variadic calls and unsupported ISA behavior. A boundary declaration cannot
repair missing original semantics. Report these separately from contract
expressibility and local proof failures; do not claim a target supported just
because the source authoring interface can name its operations.

## 5. Acceptance strategy and revision to sequencing

Keep the real sequential network as the immediate implementation milestone.
Broad review does not justify building every Windows capability before returning
to it. However, reserve the corrected semantics now so the first implementation
does not hard-code assumptions that prevent later target classes.

Use a capability vector rather than a single universal boundary mode:
memory/backing model, ownership/lifetime, interaction timing, thread/interference,
outcomes, progress and language/platform profile. These are semantic selections
within existing interfaces and evidence, not a proposed new public format.
A combination is supported only when its interaction rules are checked; proving
each capability separately does not prove their combination.

The following combined cases are mandatory before broad-target claims:

1. Mutable alias + loop cut + allocation failure + two real callers.
2. Shared returned alias + later mutation/release + repeated component calls.
3. Open invariant + synchronous callback + exceptional unwind/resumption.
4. Pending I/O + cancellation race + alias lifetime + thread completion.
5. Multiple mappings + differing permissions + unmap/remap + frame preservation.
6. Long-running allocation/release + escaped stale identity + history abstraction.
7. Representation change + remaining native observer + compatible selection.
8. Multiple dependency levels + changed semantic fact + actual cache invalidation.

For each, retain positive and adversarial examples, complete admitted domains,
semantic feature selections and separate represented/transported/proved/composed/
editable/native/export status. A supported subset can be useful without claiming
the rest. Unsupported combinations must fail before body omission or activation.

Validate three kinds of evidence separately:

- **Rule justification:** prove transport coverage and open-summary substitution
  for the supported calculus, including world extension, frame stability and
  the selected divergence/interference semantics. Existing matched finite
  regions provide a starting subset; an unsliced finite check is not a proof of
  unbounded recursion or concurrency.
- **Implementation checks:** compare proof and runtime lowering, reject missing
  obligations and stale premises in independent readers, and use small exhaustive
  cases plus negative mutations of adapters/relations. Do not only test the same
  helper implementation against itself.
- **Real workflows:** qualify actual caller premises and linked artifacts, then
  measure body absence, parent-model growth, proof reuse and interactive cost on
  several different targets. Passing the calculus does not establish ergonomics.

Current design disposition: R1-R10 are addressed as explicit design obligations;
they are not marked implemented. The component network can proceed through its
supported sequential gates once design review is complete. Asynchronous,
concurrent, abstract-layout and nonlocal combinations require their named rules
and consumer evidence before being enabled. The retained pilot, export and
repository obligations remain unchanged.

## 6. Executable adversarial review models

This self-contained Python block checks small countermodels to the rejected
design shortcuts. It does not implement repository semantics, bind a binary or
prove a meta-theorem. The TSO model has two single stores and loads, ordinary
coherent locations and FIFO buffers of length at most one; it says nothing about
the remainder of IA-32 or C concurrency. Run by extracting this block with Python 3.

The review run passes all eight countermodel classes. It finds two readiness
counterexamples despite equal successful traces. Exhaustive exploration visits
13 states in the sequentially consistent model and 34 in the small TSO model;
only the latter admits both reads observing zero. Retained executable/output
copies are under `build/boundary-design-review/broad-target-countermodels.*`;
the fenced code is the reproducible source of this finite review experiment.

```python
from collections import deque
from itertools import product
import json

# Different mappings share storage, but have separate mapping lifetime.
backing = [0]
mapping = {"a": (0, True), "b": (0, True)}
backing[mapping["a"][0]] = 9
assert backing[mapping["b"][0]] == 9
mapping["a"] = (0, False)
assert mapping["b"][1] and backing[mapping["b"][0]] == 9
wrong_independent_stores = {"a": [9], "b": [0]}
assert wrong_independent_stores["b"][0] != backing[0]

# Successful traces hide Q's commitment and inability to accept another input.
p_success = {(request, "ok") for request in ("b", "c")}
q_success = {(commit, "ok") for commit in ("b", "c")}
assert p_success == q_success
q_stuck = [(commit, request) for commit, request in product(("b", "c"), repeat=2)
           if commit != request]
assert len(q_stuck) == 2

# Cancellation requests do not close outstanding borrow obligations.
edges = {"pending": ("cancel_requested", "ok", "error"),
         "cancel_requested": ("ok", "aborted", "error")}
borrowed = {"pending", "cancel_requested"}
terminal = {"ok", "aborted", "error"}
assert "cancel_requested" in borrowed
assert set(edges["cancel_requested"]) == terminal
assert not (borrowed & terminal)

# A disjoint allocation can affect failure without modifying input bytes.
available = lambda occupied: 1 - occupied
assert available(0) == 1 and available(1) == 0

# Total history grows despite a live-set bound of one; wrapping can revive names.
live = peak = 0
history = []
for generation in range(1, 9):
    live += 1
    peak = max(peak, live)
    history.append(generation)
    live -= 1
assert peak == 1 and live == 0 and len(history) == 8
native_generations = [1 + (i % 3) for i in range(4)]
assert native_generations[0] == native_generations[-1]

# Ambient error state and dropped original choices remain observable.
original_error, adapter_clobbered_error = 5, 0
assert original_error != adapter_clobbered_error
assert {0} < {0, 1}  # narrowing a unary result set is not equivalence

def store_buffering(buffered):
    # pc0, pc1, mem_x, mem_y, read_y, read_x, pending_x, pending_y
    initial = (0, 0, 0, 0, -1, -1, -1, -1)
    queue, seen, outcomes = deque([initial]), {initial}, set()
    while queue:
        state = queue.popleft()
        p0, p1, x, y, r0, r1, bx, by = state
        if p0 == p1 == 2 and bx == by == -1:
            outcomes.add((r0, r1))
        next_states = []
        for thread in range(2):
            pc = state[thread]
            if pc == 0:
                nxt = list(state)
                nxt[thread] = 1
                nxt[(6 if buffered else 2) + thread] = 1
                next_states.append(tuple(nxt))
            elif pc == 1:
                nxt = list(state)
                nxt[thread] = 2
                nxt[4 + thread] = y if thread == 0 else x
                next_states.append(tuple(nxt))
            if buffered and state[6 + thread] != -1:
                nxt = list(state)
                nxt[2 + thread] = nxt[6 + thread]
                nxt[6 + thread] = -1
                next_states.append(tuple(nxt))
        for nxt in next_states:
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    return outcomes, len(seen)

sc, sc_states = store_buffering(False)
tso, tso_states = store_buffering(True)
assert sc == {(0, 1), (1, 0), (1, 1)}
assert tso == sc | {(0, 0)}
print(json.dumps({"authorizing": False, "countermodel_classes": 8,
                  "readiness_counterexamples": len(q_stuck),
                  "SC_states": sc_states, "TSO_states": tso_states,
                  "SC_outcomes": sorted(sc), "TSO_outcomes": sorted(tso),
                  "scope": "finite design countermodels, no target qualification"},
                 indent=2))
```

## 7. Final pass: composition, interpretation and evolution

This pass changes perspective from platform capabilities to the process of
introducing and evolving boundaries. It inspects total provider selection,
exact-context constraints, work-package binding and relation lens checking,
then challenges assumptions about interpretation, replacement and proof reuse.
The cases below are additional design requirements, not newly implemented rules.

### F1. Interpret only the active variant and demanded memory

Consider machine behavior `if (n == 0) return 0; else return byte_at(p);`.
For `n == 0`, an unmapped `p` need not fault because it is never dereferenced.
An adapter that eagerly constructs a nonempty readable view before checking
`n` excludes that execution. Rejecting a malformed view is safe for a narrower
contract, but cannot qualify the original operation over its wider caller domain.

This is common beyond zero lengths: tagged unions, sentinel handles, optional
out-parameters and flag-dependent structures all have inactive interpretations.
GetProcAddress illustrates why a pointer-typed parameter is not necessarily a
string: it also accepts an ordinal encoded in the low word.
[GetProcAddress](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress).

Boundary interpretation needs checked discriminants, branch-local definedness
and phased access. Do not evaluate inactive union members or demand liveness
for a branch that uses no memory. Keep any raw representation needed later in
the machine relation, while exposing a typed sum/optional value to ordinary C.
No generic raw-address escape hatch is required in the portable interface.
Ambiguous or unsupported interpretations remain explicit, rather than guessed
from SDK pointer types or familiar names.

### F2. Adapter validation has its own observable behavior

Suppose the original writes `a=1`, then faults on a second write; its handler
observes the updated `a`. An adapter that validates both destinations first
and faults without writing changes that observation. Conversely, partial
writeback is wrong when the original promised an all-or-nothing transition.

The current boundary transducer's transactional realization is a scoped
mechanism. It must not be generalized into a theorem that all operation effects
are transactional. Qualify each transformation under its actual entry domain:
guards may be proved unable to fail at the relevant phase, or explicit ordered
effects and exceptional outcomes must preserve the partial state. Under
interference, validation followed by use also needs a stability argument.

The same applies to instrumentation. A generated adapter can allocate, touch
guarded memory, consume stack, alter ambient errors or synchronize. Proof-only
ghost observations may be erased, but production bridge work needs a proof of
the required observational transparency and resource bounds. It must not create
a failure that the original could not have in the admitted domain. This extends
the existing native/runtime gates; it is not a demand that both implementations
use identical instruction counts or physical resources under every environment.

### F3. Local representation witnesses must fit together

Suppose three local proofs each choose an encoding bit for the same shared
object. Their pairwise requirements are `a != b`, `b != c`, and `c != a`.
Every edge has a satisfying witness; there is no joint assignment over bits.
Pairwise compatibility or equal interface names alone cannot compose them.

Bind shared invariant instances and representation parameters consistently
across the selected network. A provider qualification proves the supplied
relation under explicit parameters; selection either unifies those parameters
or consumes checked conversion laws. Conversions around cycles must preserve
the required observations and ownership, rather than accumulate a different
representation when returning to the same interface.

This need not expand a global heap in every proof. Most instances can refer to
one canonical representation convention with symbolic local parameters; only
actual shared constraints need joint discharge. The existing selection layer
already rebinds slices against the current module and enforces total definition
selection. Extend that responsibility for representation coherence instead of
inventing a separate activation authority.

COM provides a concrete identity-sensitive case: querying IUnknown from interfaces
of the same object must return the same physical pointer. Giving every portable
interface wrapper a fresh identity can violate this despite correct method
results. Identity normalization and wrapper reuse need checked laws and lifetime.
[QueryInterface rules](https://learn.microsoft.com/en-us/windows/win32/com/rules-for-implementing-queryinterface).

### F4. Partial abstraction is useful; complete abstraction must be adequate

An unordered multiset can describe some facts about a sequence but cannot
determine its first element. A rewrite from `[1,2]` to `[2,1]` preserves the
multiset while a caller that reads element zero distinguishes it. Similarly,
mathematical numeric equality, a logical record or an abstract JSON value may
omit signed zero, initialized representation bytes, iteration order or output
format details that a particular operation exposes.

Do not require every abstraction to characterize every algorithm completely.
A partial abstraction may support a conservative summary with extra possible
outcomes. But any claimed deterministic conclusion or exact replacement must
be justified by the information retained in its paired relation. If a summary
forgets order, it cannot promise a specific first element. Hidden relational
state can retain the distinction without exporting it in the C interface.

Persistent formats add observers across executions. A layout written to a file,
shared protocol or saved state can be read by a remaining native client or a
later run. An internal layout change is not automatically a persistent-format
change. Preserve the serialization contract or supply separately qualified
conversion/admission; in-memory replacement-group compatibility is insufficient.
No new format is needed for these facts if the existing service/environment
contracts can bind them.

### F5. Resource transitions are not merely allocation and release

Resizing can fail while leaving the old object alive, succeed without movement,
or succeed with a new location and preserved prefix. Ownership, current bytes,
extent and alias validity depend on the selected outcome. Treating resize as
unconditional free followed by allocation can destroy the original object on
failure. HeapReAlloc explicitly preserves the old block on failure and supports
an in-place-only mode.
[HeapReAlloc](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heaprealloc).

Add resize/move/adopt/transfer as reviewed state-transition compositions when
consumers demand them, not as unchecked synonyms for existing primitives.
Preserve the defined prefix, initialization of any extension, allocator family
and owner, and the validity of every exposed alias under the actual API/C
semantics. Do not infer alias validity solely because the numeric base is
unchanged. A custom arena reset, ownership transfer or resource import likewise
needs its exact lifecycle meaning rather than a fresh generation by convention.

### F6. Absence is a dependency too

A theorem may rely on no callback at a site, no native observer of a field,
no other writer, or completeness of an indirect target set. These are facts
about a checked universe. Recording only present callee/contract edges loses
the reason that an absent edge was safe to omit.

Bind each such fact to its scope and authoritative inventory/closure. Discovering
a new entry, enabling a plugin, changing export visibility or qualifying another
indirect target must revalidate the affected absence facts. The unchanged local
conditional theorem may still be reusable; its old composition discharge is
not automatically current. Immutable original inputs can avoid repeated work,
but refined knowledge about them must not silently reuse a stronger old claim.

The operator must also see provenance: an authored conjecture, assumed external
contract, structurally checked projection, supplier-proved guarantee and
root-discharged premise are distinct statuses. A successful proof under an
operator's hypothesis cannot promote that hypothesis into an established fact.
Refining one convenient precondition should show which real callers are now
excluded before an operator mistakes fewer proof failures for progress.

### F7. Safe partial adoption is a semantic operation

A shared-tail or multi-entry region may be an excellent proof unit while current
native ownership is coarser. Keep its entry/continuation tags and checked cuts;
do not claim independently replaceable code merely because it has a separate
solver query. Extracting a component requires routable entry/exit transport and
complete ownership, or a coordinated replacement group. It must not force every
internal cut into a permanent state-machine API.

Fallback belongs in the existing explicit selection plan. Once a replacement
has performed an observable write or call, restarting the original from entry
can duplicate effects. A supported fallback would need a related resume state
and coverage, or a pre-effect admission decision with unchanged state. The
repository already forbids silent fallback inside selected authored components;
retain that rule. A structurally convenient local proof is not permission for
runtime retry, speculative switching or hot replacement.

An interactive acceptance case should deliberately attempt an unsupported cut
or representation and recover by moving/merging it, retaining C edits and
explanations. Reporting `incomplete` is a safety property; repeatedly forcing
operators to abandon ordinary C or edit internal hashes is an ergonomics failure.

### F8. Evidence integrity is not semantic independence

Current inspection shows several distinct checks: relation lens laws,
work-package hashes, exact-context constraints and current-module selection.
Keep their claims separate:

| Check | Establishes | Does not establish alone |
|---|---|---|
| Hash/source/slice binding | This result belongs to these exact inputs | The encoded theorem is sound |
| Required assertion inventory | Expected checks were requested and retained | Each named assertion expresses its intended obligation |
| Lens law | The supported observer/realizer round trips under its theory | Full effect/fault/lifetime behavior of the operation |
| Local paired proof | Its theorem under recorded domain and assumptions | Actual caller admission or coherent network selection |
| Native/link receipt | The selected qualified artifacts are realized as checked | Unsupported platform semantics or an unrelated export backend |

Two readers using the same mistaken semantic rule do not provide independent
evidence for that rule. For new rules, retain independently derived counterexamples
and positive cases that test observable semantics, not only matching assertion
names. Runtime/proof lowerings need equivalence checks, and primitive assumptions
need a small explicit trusted base. An actual bug in a rule invalidates its
dependent evidence even if all hashes and interfaces remain well formed.

Work-package adoption must use an immutable checked snapshot and compare it
with the current source/intent before committing. A result that finishes after
another edit stays bound to its old snapshot. Reused theorems, refreshed supplier
discharge and installed native artifacts should be separately visible. Existing
transaction and Nix mechanisms are the implementation home; no new evidence
service is proposed.

### F9. Test decomposition laws, not just more targets

Useful adversarial transformations include:

| Transformation | Required result |
|---|---|
| Rename an object or view while preserving its checked identity mapping | Same semantic result; representation bookkeeping is not an observation |
| Add an inactive invalid pointer behind a proved zero-length branch | Preserve success without a new dereference |
| Add a genuinely irrelevant framed object | Preserve the local result under the frame rule's resource premises |
| Split and then merge a cut | Preserve reachable entries, outcomes and progress |
| Route through an identity adapter | Preserve observations, fault order and ownership |
| Compose three independently checked representation edges | Accept only a jointly coherent instantiation |
| Add an observer outside a previously closed set | Invalidate the relevant absence/closure discharge |
| Grow a callee under an unchanged supplied contract | Preserve the parent theorem model and reuse its query results |
| Change the backing store, fault policy or primitive meaning under the same names | Reject stale dependent evidence |

These are metamorphic properties with explicit premises, not unconditional
requirements that every rewrite preserve behavior. Allocation-address choices,
resource pressure and identity-sensitive clients can make an apparently harmless
transformation observable; the checked premise must expose that fact.

Pairwise feature coverage is a useful starting point, but F3 shows why higher-order
combinations need attention. Use hand-defined cases that cross at least three
responsibilities, then integrate the relevant combinations into actual consumer
networks. Automatic boundary recommendations remain deferred.

### F10. A stopping rule for design work and a useful success criterion

This pass adds obligations at existing semantic boundaries; it does not reveal
a need for a second executable IR or a universal heap/VM proof. Freeze the core
concepts now for the next bounded implementation milestone. Reopen a design
decision when a concrete consumer or counterexample exposes an inadequacy, and
record that change against the same acceptance cases.

The first real network must demonstrate both sides of useful independence:
an ordinary local C change that keeps neighboring queries reusable, and an
invalid change that produces a specific, recoverable diagnostic. Include active
versus inactive pointer interpretation and at least one changed closure premise
when they are exercised by the selected consumer. Do not build all F1-F9
capabilities before returning to that network.

Use existing performance budgets in
[performance and invalidation](performance-and-invalidation.md). Measure operator
work as well as solver time: manual machine fields required, repeated fact
entry, source churn caused by moving a cut, and whether a new target needs new
engine code for facts already expressible by the supported rules. A design that
only rejects difficult targets safely is not yet a generally useful lifting tool.

The result is a more comprehensive design with explicit limitations, not a
proof that arbitrary targets will be tractable or completely supported. Broad
claims require the prior capability matrix, these composition/evolution laws,
actual target workflows and the retained native/export/repository exits.

## 8. Finite checks for the final pass

These countermodels check the examples in section 7. They are separate from
production tests and do not establish a general rule or target qualification.

The final review run passes all eight countermodel classes. All eight Boolean
representation assignments are rejected jointly despite satisfiable individual
edges. Of four pointer/length cases, one distinguishes eager validation from
the original; the conditional adapter agrees on all four. Reproducible code is
below, with retained copies under
`build/boundary-design-review/final-pass-countermodels.*`.

```python
from itertools import product
import json

# Each representation edge can be satisfied, but the three cannot jointly.
triples = list(product((0, 1), repeat=3))
edges = [lambda a,b,c: a != b, lambda a,b,c: b != c, lambda a,b,c: c != a]
assert all(any(edge(*v) for v in triples) for edge in edges)
joint = [v for v in triples if all(edge(*v) for edge in edges)]
assert not joint

# A zero-length original path never demands pointer validity.
def original(length, readable):
    return 0 if length == 0 else (7 if readable else "fault")
def eager_adapter(length, readable):
    return original(length, readable) if readable else "fault"
def conditional_adapter(length, readable):
    return 0 if length == 0 else original(length, readable)
inputs = list(product((0, 1), (False, True)))
eager_mismatches = [v for v in inputs if original(*v) != eager_adapter(*v)]
assert eager_mismatches == [(0, False)]
assert all(original(*v) == conditional_adapter(*v) for v in inputs)

# Staging all guards changes the state observed after a later fault.
partial_write_then_fault = {"a": 1, "outcome": "fault"}
prevalidate_then_fault = {"a": 0, "outcome": "fault"}
assert partial_write_then_fault != prevalidate_then_fault

# A partial abstraction cannot determine observations it forgets.
x, y = (1, 2), (2, 1)
assert sorted(x) == sorted(y) and x[0] != y[0]

# Failed resize preserves the old block, unlike free-before-allocate.
old = {"live": True, "bytes": [3, 4]}
correct_failure = {"live": True, "bytes": [3, 4]}
wrong_failure = {"live": False, "bytes": []}
assert correct_failure == old and wrong_failure != old

# New observers invalidate an absence premise despite unchanged local code.
before, after = frozenset({"reader_a"}), frozenset({"reader_a", "reader_b"})
local_code_before = local_code_after = "same source"
assert local_code_before == local_code_after and before != after
assert ("reader_b" not in before) and not ("reader_b" not in after)

# Retrying from entry after one visible effect duplicates the effect.
original_trace = ["write", "return"]
fallback_trace = ["write"] + original_trace
assert fallback_trace != original_trace

# A lossless transport can still be the wrong effectful adapter.
encode = decode = lambda value: value ^ 1
assert all(decode(encode(v)) == v for v in (0, 1))
assert ["return"] != ["extra_call", "return"]

print(json.dumps({"authorizing": False, "countermodel_classes": 8,
                  "representation_assignments": len(triples),
                  "joint_representation_witnesses": len(joint),
                  "conditional_pointer_cases": len(inputs),
                  "eager_pointer_mismatches": len(eager_mismatches),
                  "scope": "finite final-review examples only"}, indent=2))
```

# Composable Component Lifting

## Nullable view parameters in authored C

A nullable view parameter uses a present `const spx_view_v5 *` descriptor. A
machine null pointer becomes the checked all-zero reference inside that
descriptor; it does not become a null descriptor pointer. In the admitted domain,
test `options->base.object == 0U` to choose a default object. A null view supplies
no readable bytes or accessors. A live view uses its checked accessors and retains
its origin, permissions, current contents and lifetime; the descriptor pointer
alone establishes none of those facts.

For example, the real Hello quoting-style draft uses
`options->base.object != 0U ? options : &context->state.defaults`.
Testing only `options` instead was rejected by both local operation proofs.
The current image-backed proof does not establish admission for stack or heap
options passed by other routines; those caller contracts must be checked.

`component check TARGET COMPONENT --source --local-contracts` now checks a
service-free interface combining fixed shared byte views, nullable remaining-origin
byte parameters and scalar results. It uses the existing source-contract evidence
and command path. The checker proves source definedness, the readable/writable
frame and dependence of results and final memory on the supplied inputs. Logical
origins may overlap; reads observe current bytes after writes through an alias.
The production reference accessors check generations, permissions and bounds.
Null supplies the same all-zero descriptor as the production adapter.

This rule keeps arbitrary origin extents and observes final memory at an arbitrary
address. Its sparse capacity of eight write events is a checked resource limit;
overflow or an undischarged loop unwind assertion leaves the theorem unproved.
The shared view's declared extent remains a frame even when its underlying origin
is larger. No stack-object lifetime, original equivalence, connected summary or
activation follows from this local result. Those composition premises are still
required. Existing fixed-parameter and service-interaction rules retain their
separate domains. The real quoting fixture is in
`tests/fixtures/hello-quoting-state/`.

An existing source-check product can also select `originalComparison` with a
complete exact slice, the operation's canonical binding and an explicit machine
domain. For the service-free object shape this checks the actual original leaf
against the checked authored object, including unsigned 32-bit scalar/void
results, current memory, the return word, stack adjustment and the architectural frame. Incoming
views can describe live caller-owned storage; their current bytes and aliases
remain related. The Hello character setter exercises this path with all seven
original transfers and a witnessed 48-byte input at callee entry ESP+20.

This result remains conditional on live inputs and separation from the private
callee frame. It is not an incoming-object lifetime proof or a connected summary.
The public result retains `qualified_connected_summary: false` and unverified
runtime compatibility. The paired-call engine now supports explicit live local
byte storage, current-content comparison and alias-preserving mutation transport.
The retained complete quoting-caller experiment exercises this rule with the
setter bodies absent and the generated V5 source interface. Its full conditional
proof passes, with an unverified following quoting service. The public caller
checker now accepts the typed local-object definition and checks the complete
consumer under those premises. Escape/expiration, following-service applicability
and native admission remain required. See the
[local-object rule](portable-c-contextual-bisimulation.md#caller-local-byte-objects-in-paired-calls).

### Scoped local byte views

Generated interfaces include `portable-component-local-bytes.h` for C storage
borrowed by a service during its enclosing lifetime:

```c
#include "portable-component-local-bytes.h"

uint8_t bytes[48] = {0};
spx_local_bytes_v5 owner = {0};
spx_view_v5 view;
if (spx_local_bytes_open(&owner, bytes, sizeof(bytes), 3U, &view) == 0U) {
    /* Pass &view to a compatible service; keep owner and bytes alive. */
    spx_local_bytes_close(&owner);
}
```

`spx_local_bytes_view` makes bounded slices with narrowed permissions. Closing and
reopening a still-live owner advances its generation and rejects old views.
The shared reference runtime supplies the read/write callbacks across translation
units. Owner identity is opaque and is not an original machine address. Neither
closing nor a generation check makes a dangling C owner safe; references escaping
the enclosing lifetime require a separate checked rule.

The public finite caller checker accepts typed caller-local object declarations
for the checked live-object supplier rule. The ordinary source uses this helper;
the caller definition supplies the physical correspondence:

- `native_memory` entries with `storage: "private_bytes"` give a typed original
  address, byte extent and read/write grants. `boundary.private_byte_capacity`
  bounds their actual backing storage. Uninitialized reads, wrapping spans and
  insufficient capacity fail checks.
- `boundary.local_views` entries give `id`, byte-pointer `type_id`, typed
  `address` and `extent`, and `permissions`. A service's `views` mapping names
  these entries. Actual source storage, current bytes and alias correspondence
  are checked at each call.
- The checked supplier provides its ABI, footprint, private-write frame and
  return facts through the existing evidence reader. Other services require
  explicit unverified runtime contracts and complete object footprints. A
  declaration cannot stand in for supplier evidence or establish an escaping
  view's lifetime.

A complete return observation checks the original return outcome, return word
and stack adjustment. Unsigned 8- and 16-bit operation arguments use their C
signature's defined narrowing from the original 32-bit input. All compiled
assertions, language-safety and loop obligations remain required through the
existing partitioned proof engine; retained results replay the same inventories.
Compatible dependency evidence can reuse a caller proof only after the current
contract and exact inputs validate.

For a non-null fixed writable operation parameter, the original-comparison
`machine_domain` can request `initializes: [{"parameter": "output", "offset": 0,
"extent": 48}]`. The checker proves that every requested byte has an actual write
on both the original and authored sides before normal return. A writable view,
matching output memory, or an abstract service write does not establish this
guarantee. Source-only frame certificates do not establish it either. The complete
paired evidence binds the requested spans before the supplier reader exports them.

The caller derives initialization facts from that checked supplier evidence and
marks only those spans initialized after its successful paired invocation. Merely
allowing writes leaves other private bytes uninitialized. Fixed write-only views,
void services and distinct 32-bit entry-register arguments use the existing
interfaces and binding format. A void service has no native result register;
its separately checked preserved-register frame still applies. A caller can use
only scoped local views, with no artificial incoming public view. These rules
currently require normal-return suppliers; terminal services and lifetime
transitions still require their own checked composition.

The retained real setter edit exercises that path with newly checked C, rather
than only changed test receipts. It preserves the consumed facts and all caller
proof bytes, with caller rendering and compiler/solver execution forbidden during
reuse. Wrong C and a freshly checked same-signature contract lacking a required
register guarantee are both rejected. This remains conditional caller assurance;
it does not supply following-service or native activation evidence.

Exact-slice preparation can stop traversal at explicit `summary_entry_rvas`
(`summaryEntryRvas` in the existing SDK `exactCSlice` builder). It retains the
actual call edges and continuations, requires every declared boundary to occur,
and omits those callee bodies. This keeps preparation independent of callee
growth. Omission grants no proof or native-selection authority.

The [complete Hello caller fixture](../tests/fixtures/hello-quoting-state/caller/README.md)
uses these fields with an ordinary 48-byte array. The current retained public
experiment passes with arbitrary admitted stack addresses and input bytes;
the smaller regression fixture explicitly fixes the stack address and supplies
supplier facts as test premises. Neither discharges the following quoting
service's applicability or authorizes native activation.

### Shared context views in public caller definitions

The finite caller checker accepts fixed readable or read/write byte views in
interface `state`, with `initial: null`. In the existing caller definition, name
each state mapping `state.FIELD` in `boundary.views`; a service's `views` mapping
can refer to that same name. Addresses and extents remain typed relation
expressions, or checked `supplier_view` mappings. Operation parameter views keep
their existing unqualified names. No extra artifact or generated C model is
required to author this distinction.

Ordinary C accesses `context->state.FIELD` and passes its descriptor to compatible
services. The checker initializes the descriptor from the declared physical
mapping, shares current bytes with every overlapping parameter/state view, and
checks descriptor and backing-storage frames. Mutable bytes can change through
the dependency call; a source read before that call cannot substitute for a read
after it. State does not imply immutable contents or a fresh allocation.
The checked context belongs to this operation's admitted invocation; this rule
does not establish persistent lifetimes across separate invocations.

This rule retains one protocol state and rejects nullable state, write-only state,
non-fixed extents, explicit initial-value claims, lifecycle transitions and
effects requiring other rules. A passing caller proof remains conditional on the
supplier/runtime premises; the declaration does not establish incoming lifetime
or authorize activation. Caller-local byte objects still need public definition
and storage transport support. The real save-caller regression exercises fixed
shared views and a mutable length through this public checking path, with supplier
facts supplied as explicit test premises.

### Borrowed C records in public caller definitions

Configured `component check TARGET COMPONENT --source --local-contracts` checks
using `finite-paired-caller-v1` can now declare `boundary.records`. The source
package may contain one ordinary C translation unit and authored headers. Header
bytes and their dependencies are bound to the proof; reserved checker headers,
preprocessor overrides, source-location macros and hidden header storage reject.

The record relation contains:

- `header`: the bound authored header defining the nominal opaque C structs.
- `types`: native byte extents and field mappings. A field's `path` contains C
  member names and constant array indices; `offset` belongs to the native
  layout. `word`, `byte` and typed `reference` fields carry explicit mutability;
  references also declare nullability. `subobjects` relate embedded records to
  the same parent fields. An empty field list represents actual byte storage
  unless the type explicitly selects the identity representation below.
- `objects`: a named incoming inventory with typed native addresses and fixed
  counts. Repeated references decode to the same actual C object or subobject.
- `projections`: logical C records whose fields come from separate native
  addresses or framed computed values, such as a context grouping several globals.
- `state`: mappings from opaque interface-state fields to those objects.
- `lifetime: "operation"`: an explicit incoming lifetime requirement.

See the [actual quoting declarations](../tests/fixtures/hello-quoting-state/slots/record_layout.py)
and [small complete caller](../tests/unit/components/record_caller_fixture.py).
Ordinary C reads and writes its own fields. The checker relates incoming contents
to the existing physical byte world, observes current contents at calls, applies
declared service byte effects, and checks pointer identity and field/context frames.
Changing native offsets is different from reordering the authored C fields.
Header edits invalidate the affected proof; unchanged exact evidence reuses
without caller model, compiler or solver work.

The actual execution model retains its PE32 compiler policy. A separately bound
C11 type-check translation unit checks nominal field/subobject types: the current
`goto-cc` Windows parser does not support `_Generic`. No component operation
executes in that type-check compiler mode. Host/PE32 compilation is separate from
second-architecture equivalence or execution evidence.

This first rule has a fixed inventory that remains live for the operation.
`runtime_contract.record_lifetime` exposes that unverified premise. Distinct
overlapping fields, allocation/release, changing inventories and escaped lifetimes
need further checked rules. Do not treat a chosen count as an established bound
on a full target's inputs. The scalar callable-summary reader rejects record
proofs until callable lifetime and enclosing memory transport are implemented.
A passing local check still does not authorize activation.

The internal record transport also supports pre-copy field snapshots alongside
the sparse world's bulk copy/fill effects. Copies preserve earlier C field bytes
through overlapping writes and later field changes; ordered service effects
observe pending updates before final writeback. Snapshot slots are bounded by
memory events, independently of returned address identities. Readonly-field and
complete-hook checks remain required. This primitive has focused semantic tests,
and the actual combined Hello growth region passes its complete conditional
check. Readonly fields prove whole-field nonoverlap with service byte effects
before skipping writeback. Bulk hooks also support preserved byte-history spans;
current C fields and snapshots remain visible, and their C frames are checked
separately. This does not establish general resizable C arrays, allocation/lifetime
transitions or a public checked allocator summary. Bulk initialization-observer
transport remains unsupported. See the
[current checkpoint](current-goal.md#checked-record-snapshots-through-actual-growth--2026-09-21).

### Passing an opaque identity to a checked scalar supplier

An opaque pointer used only for equality and service arguments can have a record
type with `"representation": "identity"`, `"extent": 0`, and empty `fields` and
`subobjects`. Its `objects` entries each have `count: 1` and a typed native-address
expression. Null remains null, and equal incoming addresses decode to the same C
identity even when declared through different entries. Source dereferences fail
the generated zero-size object's bounds checks. An identity cannot be embedded
as storage or used for projected fields.

This separates a value such as a buffer identifier from permission to access
buffer contents. It establishes neither live native storage nor allocation
generation; those obligations belong to the consuming service and memory rules.
Ordinary represented records retain their existing lifetime premise.

For a checked unsigned-scalar supplier, the existing `suppliers` entry can
explicitly bind that identity:

```json
"parameter_transport": {
  "allocation_token": {"parameter": "buffer", "relation": "record-address"}
}
```

Here `allocation_token` belongs to the supplier and `buffer` belongs to the
consumer's service signature. Every parameter must be covered exactly once.
The service's source argument projection names `buffer`; its physical value is
derived from the checked record relation, never a C pointer-to-integer cast.
All supplier entry premises, actual ABI arguments, current memory, private frames,
normal outcomes and dependency evidence still pass through the existing paired
caller rule. Missing transport, different types, arithmetic projections and
unfulfilled supplier premises reject. The relation participates in proof identity
and invalidation. A compatible supplier-body edit can reuse the caller proof.

An unchanged unsigned-scalar parameter can use `"relation": "scalar"` in that
mapping. If only the result changes representation, omit `parameter_transport`:
the parameter declarations and their unsigned types must then match exactly.
One checked unsigned supplier result can become an opaque identity with:

```json
"result_transport": {"relation": "record-address"}
```

The source result must use an identity-only record type without access, extent or
resource claims. At the actual paired return, the checker adds the returned
address to its canonical identities. Null and aliases with incoming or earlier
returned addresses are preserved. The checked call bounds limit the required
token inventory; operators do not enumerate future addresses. Ordinary C can
retain the pointer, compare it, publish it in a represented field and pass it to
another service. Dereferencing it still fails. A nonnullable source result must
also pass the existing nonnull result assertion; transport supplies no such
guarantee by itself.

A runtime service with the same identity result representation uses this return
rule too, while its declared behavior remains an explicit unverified premise.
The return relation names an address, not an allocation: it proves no fresh
generation, storage contents, successful allocation, release or native lifetime.
An allocator that reuses an address produces the same address identity. Storage
and lifetime rules must separately justify any stronger observations.

The rule does not export a stateful caller summary, supply a production native
adapter, or authorize activation. The retained Hello release-region check uses
the actual quoting service signature and `_rpl_free` summary; the complete quoting
operation still needs growing arrays, lifetime transitions and enclosing memory
composition.

### Ordinary local C records at service calls

`boundary.local_records` uses layouts from `boundary.records.types` for actual
caller-owned C storage. Each entry names an `id`, `type_id`, native `address`
relation and `permissions` (read 1, write 2, or both 3). The native extent comes
from the record layout. A service's optional `records` map associates a parameter
with this local declaration; for example `{"count": "new-count"}` for `grow_slots`.
The [quoting declaration](../tests/fixtures/hello-quoting-state/slots/record_layout.py)
maps `new-count` to entry ESP minus 32 bytes. C remains ordinary C:

```c
struct spx_opaque_quote_word_v5 new_count = { state->count };
slots = services->grow_slots(environment, old_slots, &new_count,
                            additional, maximum);
```

The adapter checks the actual C object's liveness and permissions, packs fields
at their native offsets, and uses the existing paired-call object rule to compare
contents and apply service writes. It writes results back before C continues.
Exact aliases share one backing; different C objects cannot counterfeit an
original alias. C field positions may differ from native offsets. No manual C
byte-view owner, cast to a native address, or generated wrapper is required in
the authored implementation.

The current rule requires complete native field coverage; native padding and
partial overlaps between different representations need explicit additional
relations. A local record cannot also impersonate an incoming public object.
Reference fields use the checked incoming-object identity map and require a
layout for the referenced type; graphs of references between local records need
additional transport rules.
The visible `runtime_contract.local_record_lifetime` retains the unverified
requirement that a synchronous service does not retain the reference. Successful
local transport does not establish escape, asynchronous use, allocation,
callable-summary export or native admission.

## Whole-target manual partition inventory

`boundary inventory TARGET --partition FILE --semantic-module PACKAGE/linked-semantic-module.json
--bindings BINDING-INDEX --interfaces INTERFACE-INDEX --output REPORT` audits manually
chosen ranges against retained canonical inputs. Optional repeated `--qualification`
arguments expose checked definition coverage and exact machine-context dependencies.
Missing transfers, overlapping owners and partial-transfer cuts cannot pass as a
complete partition. The report retains storage, runtime obligations and unresolved
semantics separately. Exit 0 means structural coverage only; neither this plan nor
its report authorizes activation. See the [complete Hello inventory](whole-target-independent-lifting.md)
for a real partition, measured costs, limitations and the next implementation steps.

## Editing configured component contracts

Ordinary V6 work packages now contain editable `interface.json` and `binding.json`,
plus `bisimulation.json` and `relation.json` when their intents are configured. These are canonical
declarations bound to the package's immutable baseline, not checked summaries.
The interface includes the complete schema, state, services, effects, projections
and lifecycle declarations; the binding retains ownership and machine projections.

```sh
spaghetti-extractor boundary inspect TARGET component:COMPONENT
spaghetti-extractor boundary propose TARGET component:COMPONENT --output build/draft
# Edit interface.json, binding.json, optional bisimulation.json/relation.json and src/component.c.
spaghetti-extractor boundary adopt TARGET component:COMPONENT --input build/draft --output build/reviewed
# Or apply the reviewed declarations to the configured local target:
spaghetti-extractor boundary adopt TARGET component:COMPONENT --input build/draft --apply --target-flake ./targets
```

Adoption checks the current work-package identity, normalizes derived digests and
exports the existing canonical interface/binding indexes, optional proof/relation intents
and a draft component configuration. It leaves the edited package unchanged and
refuses a nonempty destination. The exported indexes/configuration describe the
reviewed component only; they do not replace or merge the target's other entries.
With `--apply`, the SDK's operator index identifies the actual canonical input
paths. The command merges the reviewed declarations into those indexes, preserving
other entries, configuration and replacement groups. It checks both the current
package and the local declaration baselines, serializes cooperating authoring
commands, stages all writes and rolls back caught write failures and keyboard
interrupts. A hard process termination can leave recovery files under
`.component-review-*`; another application refuses to proceed until that
interrupted transaction is recovered. This is not an atomic multi-file filesystem
commit for concurrent readers or non-cooperating writers.

An optional `relation.json` uses the existing `ComponentRelationIntentV1` format.
Adoption regenerates its self-digest, checks the component and operation identities,
and applies its `relation_intent` reference alongside any cutpoint changes. An
existing relation cannot silently disappear from a reviewed draft; an intervening
local relation edit rejects application before any files are changed.

For the supported scalar, empty-frame/context-independent summary shape, authored
`normal_exit_postcondition` predicates now select exactly the exported guarantees.
Each predicate must pass the source checker and be bound to the complete local
machine/source proof before qualification. No authored intent means the existing
automatic candidate discovery remains in use. With an authored intent, additional
discovered facts are not silently exported. A logical `true` predicate can express
a deliberately weak export; it does not establish zero preservation. Unsupported
predicates or unproved requested guarantees reject. Shared-view relations retain
their existing separate checked derivations.

Small connected tests demonstrate that withholding a previously checked scalar
guarantee changes the consumed contract and invalidates the caller's dependent
property even with identical supplier C. The real Hello lowercase provider also
qualifies with that weaker export; a false export rejects. Its real comparison
caller fails the `left_folded` invariant in a public regional check. The public
supplier proposal/application/check cycle passes for both the weaker contract
and restoration, preserving C and neighboring files. Complete candidate checking
against the weaker contract is still running; restored caller/native admission
is not established by the supplier check alone.

Application reports the configured C files and draft source path. It does not
install draft C: review/copy the authored implementation into the reported files,
using `portable-component-implementation.h` in place of the work-package's
`component.h`, then run `component check --source` and the complete component check.
No proof, qualification or enabled selection is produced by adoption. The connected
public proof/refinement/invalidation/selection walkthrough remains unfinished.

Configured review preserves each operation's ownership, entries, exits and
continuation context. Internal cuts may be edited within that operation; moving
ownership between components needs a separately checked partition proposal.
Changed source projections and contracts still need semantic checking, and a
declared cut split or merge still needs coverage, transport and progress proofs.
The tool rejects stale baselines, missing original cutpoint inputs, foreign cuts
and mismatched interface/projection value inventories. It does not infer contract
compatibility from a stable signature. Existing caller-definition packages retain
their `caller-contract.json` workflow.

The retained Hello walkthrough in
`build/hello-loop-header-2026-09-20/configured-workflow/` exercises the public
inspect/propose/edit/adopt commands on the real comparison package without a pilot
rebuild. Its small operator flake exposes only that retained package and no proof
or activation products. Renaming an internal cut and its source marker produces
a normalized draft; changing operation ownership rejects. This demonstrates
editing and normalization, not proof of the edited source or a completed G3.
The subsequent `configured-application/` walkthrough uses the actual Hello SDK
paths and a disposable target copy to apply the declaration, check every preserved
source/neighbor hash, and reject stale reapplication. Its validation binds 67
passing tests across six Nix shards and the SDK plus five repository gates.

## Ordinary regional proof diagnostics

For a configured component with an ordinary proof provider, a focused check uses
the same contracts, engine and obligations as the complete check:

```sh
spaghetti-extractor component check TARGET COMPONENT --source
spaghetti-extractor component check TARGET COMPONENT --region OPERATION/sync:CUT --query-timeout 120
# Repeat --region to select more obligations; --json emits the contextual receipt.
# Use the Evidence directory reported by the focused check.
spaghetti-extractor component check TARGET COMPONENT --reuse-proof /path/to/evidence
```

Use the operation and cut IDs from the canonical binding and bisimulation intent.
Entry obligations use `OPERATION/entry:UNIT-ID`. Unknown or duplicate selections
reject. This ordinary diagnostic path needs no `--conditional` runtime contract.
Source-only checks cannot be combined with region selection; the conditional
workflow and its separate source-entry timeout retain their existing semantics.

The ordinary contextual receipt binds `models.diagnostic_selection`. Every
planned region remains present: an omitted region is explicitly incomplete with
no compiled model or execution evidence. Even selecting every region cannot make
the diagnostic aggregate satisfied or enable activation; a violated region still
reports a violation. No qualification,
implementation choices or production objects are emitted. The command returns
exit 1 for a valid diagnostic result; malformed inputs/tool failures return 2.
Individual checked regions can still be satisfied or violated.

Existing exact-query reuse can consume executed queries from a validated
diagnostic during a later complete check, under the same compiled bytes, tools,
arguments and retained output bindings. Deferred regions offer no reusable
execution evidence. This is query reuse, not zero-model/compiler-work caller
proof reuse. Current preparation still generates the region models before
scheduling selected execution, so a focused check is not a promise of zero
preparation cost for omitted regions.
Pass that package directory explicitly with `--reuse-proof DIR` for complete or
focused ordinary checks. Local packages are snapshotted into the Nix store; store
packages retain their closure. Foreign, malformed or conditional proof packets
reject. Well-formed evidence that does not match the current query is a cache
miss, and the affected checks run normally. Complete checking still discharges
all obligations and runs provider qualification; reuse grants no separate
authority. `--json` on a complete check emits the qualification, returning 0 for
complete and 1 for incomplete. A complete qualification still needs combined
selection and native-link admission. Source, conditional and concrete comparison
modes cannot be combined with `--reuse-proof`.

The provider API retains `previousQueryEvidence`; the SDK `proofCheckFor` product
accepts an optional retained store path and optional region selection. The retained Hello walkthrough in
`build/hello-loop-header-2026-09-20/ordinary-regional-check/` passes source checking
and `compare/sync:left_folded`, defers four other regions and emits no qualification.
The subsequent `public-complete-check/` walkthrough discharges all five regions,
reuses 138 query results from that region, and qualifies/links the pair in hybrid
Hello. It retains the exact executable-bound receipt; it is not full portable Hello.

Candidate selection and building can also use explicit retained evidence:

```sh
spaghetti-extractor candidate status TARGET --configuration CONFIG --reuse-proof COMPONENT=/path/to/evidence --json
spaghetti-extractor candidate build TARGET --configuration CONFIG --reuse-proof COMPONENT=/path/to/evidence
```

Repeat `--reuse-proof COMPONENT=DIR` for other selected components. The SDK's
`selectionFor` and `realizationFor` products rebuild the current provider graph
with those evidence hints, including current supplier qualifications. Unknown,
unselected or duplicate component keys reject. Each packet must bind its named
component and ordinary proof mode. Changing C or a consumed contract still
requires checking against the new inputs; an old qualification does not select
the previous implementation. Native realization retains the ordinary target-input,
receipt and executable-hash gates. Experimental comparison options cannot be
combined with proof hints.

The candidate-hint CLI/SDK tests and actual Hello graph-invalidation evaluation
pass. Public candidate hints on retained Hello inputs now reuse the complete
caller proof with zero model/compiler/solver work and pass real selection/native
admission. The incorrect local C edit with the same hint is still being checked.
This runtime fixture uses the real builders; the full SDK graph and checked
candidate wrapper are tested separately. Evidence is in
`build/hello-loop-header-2026-09-20/candidate-proof-hints/runtime-positive-validation.json`.

## Practical original/source execution

An SDK-prepared concrete fixture supports ordinary C editing and comparison
without requiring an applicable formal proof rule:

```sh
spaghetti-extractor component start TARGET COMPONENT --comparison-package PACKAGE --output build/draft
spaghetti-extractor component status TARGET COMPONENT --comparison-package build/draft
spaghetti-extractor component check TARGET COMPONENT --comparison-package build/draft --output build/check
spaghetti-extractor component status TARGET COMPONENT --comparison-result build/check
spaghetti-extractor component check TARGET COMPONENT --comparison-package build/check/inputs --reuse-comparison build/check --rerun --output build/replay
spaghetti-extractor component check TARGET COMPONENT --comparison-package build/draft --reuse-comparison build/check --output build/reused
```

Prepare `PACKAGE` with `sdk.lifting.comparisonPackage` using existing interface and
source products plus explicit original-side/test adapters. Start supplies generated
headers, editor/compiler configuration and authoring guidance. Check applies the
supported C profile, compiles/links, executes separate original/source cases and
retains exact inputs, JSON observations, diagnostics and phase costs. Replay uses
those retained inputs even after the working source is repaired. The printed
replay command uses `--reuse-comparison ... --rerun`: valid compiled objects are
retained, while the original case selection executes again. A suite replay keeps
its order because earlier cases can establish files or Wine state needed by the
failure. If the original check selected one case with `--case`, replay keeps that
selection. Choosing a single case from a failed suite is a separate investigation
from fresh runtime state; it may not reproduce the failure. The same flags can recheck a
previously passing case without forcing a clean compilation. Compiler, header or
environment changes still invalidate affected objects. Optional formal checks
keep their own existing reuse rules; `--rerun` requests fresh concrete execution.

For repeated editing, replace `--output DIR` with `--history build/checks` and run
the same command after each change. Every check gets a separate ordinary result
directory; the last completed result supplies automatic reuse unless explicitly
overridden by `--reuse-comparison`. A relative `latest` symlink points to the new
terminal result, including mismatches and compiler failures. It is a navigation
convenience, not a passing-status marker or a new evidence format. `status`, source
export and replay keep their existing receipt validation. Printed replay commands
name the specific check directory, so later runs cannot change their inputs.
Preparation errors leave `latest` unchanged. One history belongs to one target/
component and allows one running check at a time. Keep it outside the editable
package and use the headless lifting shell for Wine comparisons. Optional formal
checks carry forward through the existing reuse path; history does not reset them.

When starting from a retained result, add `--history-baseline RESULT` to seed an
empty history. It is ignored once that history has a completed check, so the same
command follows subsequent edits and can keep working after the initial result
moves. `component start --comparison-result RESULT` and experimental reopening
print this repeatable command automatically. `--reuse-comparison RESULT` remains
an explicit override for a particular check.

To try a new input already supported by the driver, add `--case NAME
--case-arguments '["argument", "another argument"]'` to a comparison check.
The JSON value must be an array of strings. The result retains the new named
case in its existing input plan without modifying the editable package. A name
already bound to different arguments rejects. This is a single-case run from
fresh runtime state; the driver and admitted boundary still determine supported
inputs and required setup. Printed replay uses the retained plan, so the extra
option is not needed again. To include the input in future full-suite checks,
use `component start` on the matching result's `inputs/`, optionally with
`--reuse-source` for current authored C, then check that expanded workspace.
The [operator guide](component-workflow.md#try-another-input) gives a real example.

Use `component status --comparison-result DIR` to inspect an existing result
without rerunning its cases. It validates the retained evidence and shows the
recorded status, first difference, surrounding observation record (or a small
array window), full observation paths and replay command. Excerpts are bounded;
the original observations remain available in the retained files. This is useful
after repairing the workspace, since the result still describes its saved inputs.
Inspection does not evaluate current edits or decide whether evidence is reusable.
It exits successfully when the result is readable, including a recorded mismatch;
`--json` returns the unchanged receipt and its recorded `status`. Inspection
launches no compiler, solver, target-provider build or Wine process. Use
`check` for a new comparison and its pass/failure exit status.

See the
[real jq walkthrough](../tests/fixtures/jq-array-concat/README.md) for an executable
example with aliases, shared values and controlled dependency outcomes.

The [byte-length boundary trial](../tests/fixtures/jq-string-byte-length/README.md)
illustrates a manual interface-design pitfall: a contents service was implemented
by calling the very operation being lifted. Its declaration did not reveal that
dependency. A shared C view of the reviewed live allocation removes the recursion,
while the portable body keeps the existing contents/release interface. Local
editing, a release defect with unchanged return values, neighbor reuse and source
program execution then work without new checker or compiler machinery.

Start also writes `generated/workspace.md` and a corresponding page under each
`dependencies/NAME/generated/`. These pages gather operation inputs/results,
shared types and representation files, lifecycle conventions, service contracts
and executable adapters, outcomes, assumptions, neighbor requirements and example
observations from the existing package. Follow their links to the C, headers and
boundary notes. Shared object definitions remain in those inputs; the guide does
not create another contract to maintain.

`component list TARGET --comparison-package WORK` lists the selected units and
their caller requirements using local inputs. Inspect any selected unit with
`component status TARGET COMPONENT --comparison-package WORK`, including suppliers
whose identity differs from the package entry. The default overview shows its
C/shared-input files, signatures, service/supplier/adapter mapping, outcomes,
assumptions and callers. `--details` shows the full boundary and source navigation;
`--json` retains the complete structured view. Both text views keep the selected
identity in their refresh commands and print the enclosing consumer's check
command. Driver/case information and optional reuse
previews still belong to the enclosing selection. They are not independent local
evidence for a supplier. The JSON view keeps the package entry in `component_id`,
adds `selected_component_id`, and exposes caller requirements in each unit's
`consumers` list. Neither command runs a compiler or target build.

`component start TARGET COMPONENT --comparison-package WORK --output EDIT`
also accepts a selected supplier. It keeps the existing consumer selection and
test setup, points the editor and generated guide at the named unit, and prints
the enclosing consumer's check command. This is a focused editing workspace,
not an inferred independent fixture. With `--reuse-source`, only that supplier's
C travels into the current consumer; unrelated source-workspace edits stay out
and existing contract compatibility checks still apply. Experimental packages
without a retained local comparison use this same path; packages with a local
setup continue to reopen it.

In the full guide and `--details`, operations and generated-bridge services link to candidate C definitions
with line numbers. Each definition lists the calls written in its body and links
to matching local helper definitions, including shared headers. This makes it
easier to review an adapter's dependencies when establishing a boundary. Status
rescans the current selected C/header files without invoking a compiler; `--json`
includes `source_navigation` and hashes of the scanned inputs. These are lexical
navigation results: preprocessing, macros, indirect calls and linker resolution
still require inspection. Missing or multiple candidates do not prove absence,
independence or compatibility, and the view does not control comparison admission
or evidence reuse.

Each operation also shows the resource roles declared for its concrete comparison,
including normal and nonlocal count allowances. These come directly from the
existing comparison settings, even when no checked interface lifecycle is present.
For example, jq string slicing consumes its input reference, produces the result
and permits one stranded reference on its observed allocation-failure path.
Those declarations support practical local work without being presented as proved
lifetimes. Refine their source settings, not the generated guide.

`compile_commands.json` covers both authored C and comparison adapter C. Each file
gets its own component's generated headers and include paths, including selected
neighbors. Editors and the recorded syntax-check commands therefore work while
writing native transport and observation adapters as well as the portable body.
Adapter compiler success remains separate from the portable source profile and
original-versus-replacement behavior.

The root workspace page also supplies commands for the first check, a later C
edit with result reuse, and source-library export. Commands use absolute workspace
paths so they still work after changing directories. The page explains retained
failure replay, program-library updates and any Wine desktop requirement.

`component status --comparison-package DIR` reads the current declarations locally,
without target-provider evaluation, compilation or program execution. Add `--details`
for the full current guide, or `--json` for the complete projection, including optional local contracts and input
fingerprints. It validates the package and retained tool/oracle files; it is not
an assurance check and reports `assurance: not-evaluated`. The generated Markdown
is a snapshot from start; use status after changing a boundary. Guide files do
not participate in comparison/proof authority. Requirements, replacement groups
and package-level examples remain distinct: the example list does not establish
per-neighbor coverage or contract compatibility.

Before selecting an edited supplier, preview its declared contract against the
one retained by its consumer:

```sh
spaghetti-extractor component status TARGET CONSUMER \
  --comparison-package build/consumer-draft \
  --dependency-package SUPPLIER=build/supplier-draft
```

The preview names changed declaration sections and exact shared-file paths, plus
direct and transitive consumers in the selected network. Add `--json` for complete
old/proposed values. It is read-only and runs no compiler, program or solver.
Bundled dependency defaults are listed separately from explicitly selected edits;
this inspection does not resolve conflicting implementations. An unchanged declared
contract is not a behavioral compatibility or evidence-reuse result.

For example, changing a DX-Ball `runtime.h` comment changes the frozen
`representation.inputs.runtime-contract` bytes. The preview names both files and
the `graphics-initialize/reset` consumer. That allows an operator to review the
actual difference and prepare the appropriate current boundary. Exact input
binding remains conservative; comments are not automatically classified as
semantically irrelevant. A check also reports these changes before replacing
the retained supplier files or invoking the compiler.

When revising a boundary, prepare a new package through the same authoring API,
then carry your current implementation into a fresh workspace:

```sh
spaghetti-extractor component start TARGET COMPONENT \
  --comparison-package build/revised-package --reuse-source build/draft \
  --output build/revised-draft
spaghetti-extractor component check TARGET COMPONENT \
  --comparison-package build/revised-draft --reuse-comparison build/check \
  --output build/revised-check
```

With another comparison workspace, `--reuse-source` copies the selected component's
declared authored C/header selection, including added, removed or renamed files.
The revised package supplies the interface, assumptions,
adapters, cases and selected neighbors. Both input workspaces remain intact; editor
configuration and headers are regenerated in the new output. The target/component
identity must match. Existing header roles come from the revised package; new
declared private helper headers retain their role. New paths cannot replace
unowned inputs, and original oracle files remain protected. This is source preparation, not a
contract-compatibility or evidence-reuse claim. The following check reports actual
invalidation and reruns affected comparisons under the existing rules. Changes to
input projections during domain refinement can require a fresh baseline.
Run Wine comparisons inside `spaghetti-headless-wayland`, as above.

To add, remove or rename the authored C/header files themselves, use
`revise_comparison_package(package=..., output=..., source_files={...})`. The
mapping is the complete new authored file set, relative to `source/`, with paths
to your C/header inputs just as in `prepare_comparison_package`. This retains the
existing oracle, adapters, cases and selected neighbors instead of reconstructing
the whole preparation call. Superseded authored files are removed from the new
workspace; the input workspace stays intact. Oracle inputs and other file roles
cannot be replaced through this mapping. Shared representation references still
need their named inputs, and a changed interface still needs explicit revision.
See the [local refactor example](component-workflow.md#establish-your-own-boundary).

A refactored supplier can return to its consumer through `--dependency-source`.
That operation carries its declared C file additions/removals/renames and new
private helper headers while retaining the consumer's adapters and other selected
bodies. Declared private headers can change with implementation C; other existing
authored headers and the boundary still have to match. Status
lists the changed file selection; start regenerates editor commands and checking
rebuilds the affected inputs. Unowned consumer files cannot be overwritten.

`--reuse-source project/lifted` also accepts an exported source library, including
edited C. It imports only the selected component into an unverified draft; other
components may also be under edit. Declared private headers can accompany C edits.
Other boundary and shared inputs must match the chosen comparison package.
It accepts a file refactor already declared through the authoring API and retained
in the source export, removing superseded C and updating build/editor inputs.
Changes to other headers or contracts still use boundary refinement; unrecorded
file additions/removals require a revised source selection first. Importing leaves the library and
its old provenance untouched; run a local comparison before publishing the edit.

To prepare a caller workspace with an edited supplier before running comparisons,
use the same dependency selection on start:

```sh
spaghetti-extractor component start TARGET CALLER \
  --comparison-package build/caller-package --reuse-source build/current-caller \
  --dependency-package SUPPLIER=build/edited-supplier --output build/selected-caller
spaghetti-extractor component check TARGET CALLER \
  --comparison-package build/selected-caller --output build/selected-check
```

Omit `--reuse-source` when there is no separate caller edit to carry. The supplier
selection uses the existing exact contract, representation and transitive-choice
checks. Start materializes the selected C, bridges, generated headers and editor
guides without compiler or execution work. Inputs stay intact; a rejected supplier
does not publish a draft with stale defaults. The workspace contains a snapshot,
so later external supplier edits need another explicit selection. Behavior and
evidence reuse are determined by the subsequent check; preparation supplies no
semantic compatibility or qualification claim.

The [fresh jq string-length trial](../tests/fixtures/jq-string-length/README.md)
uses this workspace while defining an additional real boundary from existing
shared string services, then exercises local edits, discrepancy replay, neighbor
reuse and source-program integration. Establishing a boundary still requires
surrounding-code analysis. The guide makes that recorded knowledge available for
ordinary local work; it does not infer missing semantics.

### Author a new comparison boundary

`component start TARGET COMPONENT --interface-intent FILE --output DIR` opens a
C workspace directly from a reviewed `ComponentInterfaceIntentV1` JSON file.
It supplies typed stubs, the same generated headers used by comparison, and editor
syntax commands before a driver exists. `--operation-symbol OPERATION=SYMBOL`
selects entry names; `--compiler FILE` selects the syntax compiler. No target
registration, build or comparison is performed. The [first-time workflow](component-workflow.md)
explains how to supply execution inputs afterwards using the authoring API below.

Existing selections can be revised through `revise_comparison_package` without
recreating their execution setup. Its optional `component_id` selects a supplier;
`reviewed_requirements` names the affected caller requirements for a contract
change. Source/adapters/header paths are relative to the selected unit. The
[supplier revision walkthrough](component-workflow.md) carries a jq refactor and
assumption refinement through its retained consumer and standalone source project.
Root execution and shared-group changes retain their existing revision paths.

For first-time manual setup, the documented Python authoring API accepts an
existing `ComponentInterfaceIntentV1` object and ordinary C files directly:

```python
from pathlib import Path
from spaghetti_extractor.components.comparison_package import (
    prepare_comparison_package, retained_comparison_environment,
)

prepare_comparison_package(
    interface_package=boundary,  # ComponentInterfaceIntentV1, or its package path
    source_files={"component.c": Path("component.c")},
    operation_symbols={"run": "lifted_operation"},
    target_id="my-target", component_id=boundary.component_id,
    adapter_files={"driver.c": Path("driver.c")},
    include_files={"native-api.h": Path("native-api.h")},
    original_files=["runtime/original.dll"], oracle_kind="native-original",
    cases=[{"id": "retained-case", "arguments": ["case-input"]}],
    observation_fields=["result", "memory_after", "interactions"],
    assumptions=["The adapter's declared input, state and interaction scope"],
    scope="Manually reviewed operation boundary and retained cases",
    output=Path("build/operation-package"),
    **retained_comparison_environment(Path("build/retained-runtime-package")),
)
```

The variable `boundary` is a reviewed declaration, constructed with the existing
full interface API or `service_authoring.component_interface` for a single
operation. The latter selects reusable `ServiceDefinition` declarations and their
resource roles; see [C service authoring](#reusable-c-service-authoring). The driver
implements the original/source entry adapters and emits the chosen observations.
Preparation publishes the package after its inputs, declarations and generated
headers validate. If it fails, the destination stays absent or empty: correct
the input and retry the same call. Existing populated workspaces are preserved.
For a recipe that generates adapters or prepares several components, wrap the
complete recipe in `comparison_package.comparison_preparation(output)` and write
its outputs beneath the yielded staging directory. Successful exit publishes the
directory; an exception discards the staged work. The
[jq index preparer](../tests/fixtures/jq-string-indexes/prepare.py) demonstrates
this small wrapper. Print or retain final workspace paths after leaving it.
The example's DLL, C files and case encoding are operator inputs, not generated
target semantics. A complete real recipe is the
[controlled jq caller](../tests/fixtures/jq-path-controlled/README.md).
The [connected DX-Ball graphics recipe](../tests/fixtures/dxball-graphics-network/README.md)
reuses the same API for shared sprite tables, mutable surface identity and ordered
resource-service interactions. It includes fresh setup, ordinary C editing,
retained discrepancy replay, neighbor reuse and experimental assembly without a
per-unit toolkit extension. Its retained-C oracle and controlled services remain
explicit assumptions.

To prepare an independent comparison for a component already selected in a
network, reuse its recorded boundary and C rather than reconstructing them:

```python
from spaghetti_extractor.components.comparison_environment import retained_component_inputs

network = Path("build/program-workspace")
with retained_component_inputs(network, component_id="my-component") as inputs:
    prepare_comparison_package(
        **inputs,
        adapter_files={"driver.c": Path("local-driver.c"),
                       "services.c": Path("reviewed-services.c")},
        original_files=["runtime/original.dll"], oracle_kind="native-original",
        cases=[{"id": "local-case", "arguments": ["case-input"]}],
        observation_fields=["result", "memory_after", "interactions"],
        scope="Reviewed independent execution setup",
        output=Path("build/local-package"),
        **retained_comparison_environment(network),
    )
```

`inputs` retains the selected interface, authored C/private-header roles, shared
headers, assumptions, input domain, representation, resource/service declarations
and service-binding configuration. It preserves existing supplier requirements.
Pass `retain_dependencies=True` to select their current bodies/adapters from this
network, or provide matching supplier selections explicitly. The existing
composition resolver follows declared requirements, deduplicates shared suppliers
and preserves applicable synchronous recursion declarations. A recursive back-edge
uses the local entry body under the required entry contract. It does not infer
missing calls or establish recursion progress. The source
package is temporary, so perform preparation inside the context. This uses the
existing formats and the `source/` and `headers/` layout emitted by preparation;
custom include layouts require explicit authoring inputs.

The helper does not copy the enclosing program's driver, oracle declaration,
cases, observations or evidence. Neighbor bodies are included only when explicitly
requested through `retain_dependencies=True` or separate selections. Review the local input
construction, transport, service implementation and observations yourself. An
adapter that calls the component under comparison does not establish independence.
The [DX-Ball local recipe](../tests/fixtures/dxball-graphics-network/prepare-local.py)
demonstrates a local blit check using only its selected network, without the
original per-component package or repeated interface/service declarations.
The [jq getter recipe](../tests/fixtures/jq-path-network/prepare-local.py) also
retains the current storage/string suppliers, preserving neighboring edits without
the original supplier packages. Preparation's `dependencies=[{"id": "supplier",
"package": network}]` can select a named nested unit and its declared supplier
closure; naming the package entry keeps the existing complete-package behavior.

For optional operation-level reference accounting, use the authoring helper:

```python
from spaghetti_extractor.components.resource_authoring import component_resource_checks

checks = component_resource_checks(
    boundary, consumes=["value", "needle"], produces=["result"],
    resource_kind="jq-reference", provider_domain="libjq",
    service_id="value-transport",
    interaction_contract_id="string-indexes.reference-transfer",
    instrumented_sides=["source"],
    unobserved=["Native allocation internals and borrowed byte reads"],
    nonlocal_allowances={"nomem": {"max_untransferred": 3, "max_retained": 0}},
)
# Pass checks as resource_checks=checks to prepare_comparison_package.
```

The named inputs are consumed references; they may alias the same backing object.
The result is a produced reference. Plain numeric values may remain unlisted.
The helper resolves the operation signature, constructs the existing canonical
lifecycle and validates it with the existing runtime-check rules before package
preparation. C transport, shared-object contents and observations remain explicit
operator inputs. Outstanding-reference limits are declarations to check; they
do not establish behavior of an unexercised failure path.

`operation_id` defaults to `run`, capacities to 4096 tokens/256 frames, and normal
`max_untransferred`/`max_retained` to zero. Sides and unobserved effects are explicit.
For heterogeneous resource classes or several operation contracts, use the full
existing lifecycle/check API. The supported counter instrumentation still covers
top-level consumed parameters and produced results; this helper adds no new rule.
Borrowed views retain their own service contracts and C observations.

Binding IDs default to `parameter.NAME` and `result.NAME`. During migration,
`binding_ids={"parameter.value": "value", "result.result": "result"}` can preserve
the IDs in an existing recipe. This preserves generated identities without manual
hash editing. The jq slice, length, byte-length and index recipes demonstrate it;
new recipes normally use the defaults. These are authoring declarations, with the
same experimental assurance status as the existing resource checks.

For a declaration revision of an existing valid package, use
`comparison_package.revise_comparison_package(package=existing, output=revised,
assumptions=[...])`. It retains the current C, fixtures, tools, originals and
selected suppliers, and regenerates headers and the composition graph. Start an
editable workspace from the result with `component start --comparison-package`;
this refreshes editor commands and the boundary guide for its new location.

Supported declaration keywords are `assumptions`, `scope`, `cases`,
`observation_fields`, `operation_symbols`, `input_domain`, `representation`,
`resource_checks`, `service_catalog`, `service_bridge`, `requirements`,
`recursion_groups`, `export_adapters`, `local_shared_contract`, `program_driver` and
`private_headers`. Omitted values
are retained; `None` removes an optional declaration. Supply a newly constructed
`ComponentInterfaceIntentV1` as `interface=boundary` to revise the interface for
the same component. Existing parsers and generators validate the result before
the new package is published. This is authoring, without execution or assurance.
Frozen requirements are retained unless explicitly replaced. After reviewing a changed
supplier, use `component start TARGET CALLER --comparison-package WORK
--refine-requirement REQUIREMENT=SUPPLIER --output REFINED_WORK`. Repeat the option
for each named requirement. It also works when reopening an experimental package.
Preparation recipes can pass `refine_requirements={"CONSUMER/REQUIREMENT": supplier_package}`
to the same revision helper. Bare names refer to existing root requirements;
qualified names address any selected caller's existing requirement. Shared and
transitive consumers can be reviewed together in one revision. For example, jq
can name both `path-get/get` and `path-set/get` against the revised `value-get`.
Only those named requirements change. Missing reviews are reported together, and
the caller's C, adapters, cases and notes remain. Bundled suppliers whose declared
contracts match keep the network's selected bodies; explicit supplier selections
take precedence. This preserves independent neighboring implementation edits.
Reviewed refinement also imports a newly declared supplier from the incoming
package's closure. Every added unit must have a requirement path in the final
selection; unreviewed existing consumers remain frozen. This supports lifting a
retained service locally and returning that expanded caller to its existing
network. Ordinary implementation replacement cannot add those boundaries.
Unknown requirements, duplicate aliases and conflicting supplier packages reject.
An incoming package cannot retarget or remove an explicitly reviewed requirement;
prepare that caller change separately. The existing selection and
representation checks apply. An ordinary `start --dependency-package` or check
still cannot accept a changed contract. Named refinement and a raw `requirements`
declaration are alternative authoring inputs. This prepares an unassured configuration whose
affected comparisons must run again. The
[operator guide](component-workflow.md#establish-your-own-boundary) shows a short
revision recipe without reconstructing unchanged preparation arguments.

Use `private_headers=["source/helpers/value.h"]` for authored headers used only by
the component implementation. This option is accepted by initial preparation and
revision (`privateHeaders` in the Nix comparison-package helper). Named files must
be authored headers and cannot be shared representation or original inputs.
Header-use isolation is an operator declaration, not a proved property. The role
is visible in component/export guides and retained in snapshots; strong source
checks still bind all header bytes. C-only selection can carry private-header
edits, additions and removals, while changing an existing header's role requires
explicit requirement refinement. Source updates also require boundary acceptance
when an existing header changes role. New edits and compiled dependents then use
the existing comparison and invalidation rules.

For shared input changes across an existing representation group, pass
`representation_updates={GROUP: {"revision": NEW_REVISION, "inputs": {NAME: FILE},
"reviewed_requirements": ["CONSUMER/REQUIREMENT", ...]}}`. The helper follows the
declared group and replaces those named inputs in every selected member, retaining
implementation C and adapters. It requires explicit review of each requirement
whose supplier contract changes, including transitive callers. Missing reviews
name the affected requirements; failed preparation publishes no partial package.
Unselected group members remain absent, and original oracle inputs cannot be
rewritten through this mapping. This is manual refinement, with new comparisons
required. It does not infer compatibility from a matching field or signature.
The [shared-layout recipe](../tests/fixtures/dxball-graphics-network/README.md#revise-the-shared-portable-layout)
uses the same operation before or after regrouping complete components.

To select a newly lifted service in an existing caller, pass `dependencies` using
the same selections returned by `bind_dependencies`. Pass that caller's reviewed
`requirements` as well, retaining its existing requirements when adding edges.
`component_id` can select an already bundled caller; its C binding and new
requirements can be revised without rebuilding a separate local fixture or
altering the enclosing execution setup. Selection additions use the same resolver
as root revisions; removing global selections still requires a root revision.
The resolver imports exported adapters and transitive suppliers, keeps current
selected C and rejects conflicting shared implementations. It does not silently
update another caller's requirements. Omitted requirements remain frozen;
`dependencies=[]` retains the current selection. To regroup operations, explicitly
pass `remove_dependencies=["OLD_COMPONENT", ...]` together with reviewed replacement
packages and the full revised root requirements. This drops those current selections
before resolution; it does not erase any caller's requirements or program entries.
Dangling consumers reject, and a supplied caller cannot silently reimport a removed
unit. An explicit selection may replace a removed unit with the same identity.
Original inputs, caller C and unrelated selections remain. The
[DX-Ball grouping example](../tests/fixtures/dxball-graphics-network/README.md#group-complete-operations)
uses multi-entry interfaces to combine complete reset/bind operations, retaining
the initializer and blit implementations. New comparisons are required for the
changed boundaries; this is not a proof-region split or compatibility proof.
Review any interface, `service_bridge`, adapter or header changes needed to call
the new supplier and supply them in the same revision. Selection alone neither
wires a service nor demonstrates that a case executes it. The caller's ordinary
C, cases and notes remain unless explicitly revised. No previous behavioral
evidence is inherited by adding a supplier.

To change executable setup while retaining the selected C and neighbors, the same
helper accepts `adapter_files`, `include_files`, `link_files` and `runtime_files`.
Each replaces its complete root role using the same relative-name-to-file mapping
as preparation; omission retains the role and `{}` clears it. Use `compiler`,
`runner` and `server` for explicit tool changes (`None` clears runner/server).
For example, `native_environment()` supplies those tool/link/runtime arguments.
Changing pinned oracle files also requires an explicit `original_files` list of
reviewed package paths, optionally with `oracle_kind`; the helper binds their
new bytes. Without that declaration, changed or removed original inputs reject.
The result passes existing validation and publishes transactionally, so a failed
revision can be corrected and retried at the same destination. Selected source,
neighbor contracts and frozen requirements are preserved unless separately revised.

The [DX-Ball native recipe](../tests/fixtures/dxball-graphics-network/native.py)
uses this path to supply its reviewed native driver and runtime while retaining
the operator's component edits. It no longer rewrites generated plans, tool/oracle
hashes, composition or headers. Image ranges, native calling conventions, state
transport and meaningful observations remain reviewed adapter inputs. Run affected
comparisons after a driver revision; changing an oracle does not reuse its old
behavioral evidence or establish equivalence between the two oracles.

For another independent program entry, pass
`program_entry_packages={"component-id": reviewed_local_package}` to the same
revision helper. It requires a `program_driver`, adds the named roots to its
entry list, and imports their exported adapters and transitive selections through
the existing composition resolver. Current selected C, contracts and caller
requirements remain in place. Shared suppliers are retained once; conflicting
contracts or selected implementations reject, so resolve those choices explicitly
before combining the packages. An independent entry does not become an invented
call from the main component. Reviewed C still binds its native entry and state;
selection alone does not show that a program case executes it.
The [Hello program recipe](../tests/fixtures/hello-program/comparison.py) uses
this argument for its separately edited string-conversion entry.

For fresh pinned tool/runtime inputs without an existing comparison directory,
use `nix develop .#lifting` and the
[Hello/DX-Ball handoff](../tests/fixtures/hello-handoff/README.md). The installed
`components.comparison_environment.native_environment()` helper supplies the
existing factory's PE32 compiler, runner, link and runtime arguments from that
shell; `host_environment()` supplies host-C tools. Explicit retained packages
remain supported. These APIs work outside the toolkit checkout. No new comparison
format or assurance policy is used.

When a reviewed comparison already provides the services needed by a new
component, reuse its executable inputs through the same factory:

```python
from spaghetti_extractor.components.comparison_environment import retained_service_inputs

services, shared = retained_service_inputs(
    Path("build/reviewed-string-workspace"),
    names=["contents", "release"], native_symbol="fixture_string_byte_length",
    adapters=["string-services.c", "value-runtime.c", "allocation-observer.c"],
    headers=["jv.h", "jq.h", "string-native.h", "string-storage.h",
             "value-transport.h", "value-runtime-impl.h", "allocation-observer.h",
             "COPYING.jq", "pe32-entry-hook.h", "pe32-import-hook.h"],
)
shared["adapter_files"]["driver.c"] = Path("driver.c")
shared["include_files"]["BOUNDARY.md"] = Path("BOUNDARY.md")
# Build the new interface using services, then pass **shared to
# prepare_comparison_package alongside the new component's explicit inputs.
```

File names are relative to the reviewed package's `adapters/` and `headers/`.
For a connected package, `component_id="string-slice"` selects that unit's service
declarations and bindings. File lists still refer to the package's root roles.
Use an explicit mapping when inputs live in several selected units:

```python
services, shared = retained_service_inputs(
    Path("build/path-network"), component_id="string-slice",
    names=["contents", "release"], native_symbol="fixture_string_indexes",
    adapters={"value-runtime.c": "adapters/value-runtime.c",
              "allocation-observer.c": "adapters/allocation-observer.c"},
    headers={"value-transport.h": "headers/value-transport.h",
             "string-native.h": "dependencies/string-slice/headers/string-native.h"},
)
# Add the reviewed contents adapter and remaining headers, then author the new
# operation/driver/cases. The complete string-indexes recipe shows these inputs.
```

Mapping keys are destination names; values are paths relative to the whole
package. An adapter must already be selected somewhere in that package; authored
component bodies cannot silently become reused adapters. Header mappings may
select reviewed shared files from elsewhere in the package. The helper imports
only the named files and selected service definitions, not the supplying
component's implementation or its requirements. If an adapter also implements
unrelated entries, factor the needed service in ordinary C before reusing it.

To select services from several components or choose local names, use explicit
`COMPONENT/SERVICE` references instead of `component_id`:

```python
services, shared = retained_service_inputs(
    Path("build/path-network"),
    names={"contents": "string-slice/contents", "retain": "value-get/copy"},
    native_symbol="fixture_new_operation",
    adapters=reviewed_adapter_files, headers=reviewed_header_files,
)
```

Each local name retains the selected definition's complete contract and C adapter
specification. Shared type layouts and transports must agree exactly; the helper
does not resolve conflicting representations or infer a common ABI. This form
retains only transports referenced by the selected service schemas, so add any
entry-only transports explicitly. `service_catalog(services)` keeps one copy of
an exact contract referenced by multiple local aliases and rejects conflicting
contracts with the same identity. The new interface still records those local
names: revising an existing component requires regenerating its schema-bound
lifecycle declarations and checking affected consumers. `revise_comparison_package`
regenerates the bindings of existing operation resource checks automatically when
their input/result declarations and recursively referenced types remain exact.
Roles, limits and observation gaps stay unchanged; changed values/types need
explicitly reviewed `resource_checks`. No compatibility or previous assurance
follows from the rename.

The returned service definitions retain their exact contracts; `shared` contains
the existing tool/runtime arguments, selected files, catalog, transports and
service bindings, including outcomes and context parameters. The new native
wrapper symbol is explicit. Define the new operation, types, implementation,
driver, cases, observations, oracle and assumptions yourself. Nothing here
inherits evidence or establishes compatibility or adapter independence. Inspect
the selected service C through the workspace's source links: an adapter may call
the very operation being replaced. The complete
[jq byte-length recipe](../tests/fixtures/jq-string-byte-length/README.md) shows
this setup with four local files and a reviewed shared workspace, without sibling
fixture paths or repeated bridge wiring.

For an operator project in another directory, enter the same environment with
`nix develop /path/to/spaghetti-extractor#lifting`. Python imports and the public
CLI come from the installed toolkit when there is no local source checkout.
Keep the project's ordinary C, shared declarations, native inputs and preparation
recipe there; use the same `component start/status/check` and `candidate export`
commands. The installed jq handoff in `build/installed-component-workflow-2026-09-22/`
records this sequence through a local edit, native-program defect replay, repair
reuse and source-library compilation. It uses already reviewed operator inputs,
not automatic boundary discovery or a new independent usability study.

Prepared-example reproduction and previously unprepared boundary authoring are
separate acceptance tests. The latter must record manual analysis/adapter effort
and any tooling gaps, as specified in
[H1](whole-target-independent-lifting.md#h1h3-operator-handoff-and-program-execution).
The [string-conversion trial](../tests/fixtures/hello-string-conversion/README.md)
now records that first preparation, its retained boundary workspace, ordinary C,
local memory/service comparisons, edit/replay/reuse and normal Hello execution.
It uses these APIs and target adapters without changing checker, production
artifact-reader or compiler machinery; its manual effort and limits are reported.

For a retained machine-C oracle, recover only your reviewed original ranges:

```python
from pathlib import Path
from spaghetti_extractor.components.comparison_original import recover_original_c

recovered = recover_original_c(
    original=Path("DXBall.exe"),
    expected_sha256="191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f",
    boundaries={0xbc90: [(0xbc90, 0xbc99), (0xbc99, 0xbcb8), (0xbcb8, 0xbcbb)]},
    output=Path("build/reset-original"),
)
```

Keys are entry RVAs; pairs are half-open instruction ranges. Select those ranges
manually from the original's control flow, listing shared tails once. Internal
cuts remain control-flow details rather than synthetic component APIs. The helper
uses the existing extractor, normalizer and Behavioral-C renderer; callers no
longer wire those internal stages together. It writes the selected C, runtime
headers, original semantic inputs and `recovery.json` with a C source map, input
identity and separate preparation/extraction/lowering/rendering costs.

The C uses the existing machine runtime ABI. Supply reviewed entry frames, memory
and external services in the original-side driver, then pass the generated files
to `prepare_comparison_package` as oracle adapters/headers with
`oracle_kind="retained-c"`. Bind the original image and generated semantic inputs
in `original_files`. Keep recovery timings outside those semantic inputs; the
[DX-Ball recipe](../tests/fixtures/dxball-graphics-network/README.md) demonstrates
that handoff. The source map helps review the selected instructions; it does not
establish complete operation ownership or prove the oracle's equivalence.
Unsupported semantics report the offending range without publishing a partial C
selection. An executable `native-original` driver remains a separate supported
choice; it does not require successful retained-C recovery.

Native comparison drivers can reuse the installed interception and process-observation
headers without depending on repository test fixtures:

```python
from spaghetti_extractor.components.comparison_environment import (
    native_environment, native_adapter_headers,
)

tools = native_environment()
headers = {"native-api.h": Path("native-api.h"), **native_adapter_headers()}
# Pass **tools and include_files=headers to prepare_comparison_package.
# Add the original DLL and its import library explicitly to runtime_files/link_files.
```

Select one header with `native_adapter_headers("pe32-entry-hook.h")` or
`native_adapter_headers("pe32-import-hook.h")`. They preserve the existing
`spx_fixture_*` C API for synchronous, single-threaded PE32 comparisons. Entry
redirection checks the reviewed instruction prefix and traps the supplied body
range; import redirection forwards to the original resolved import when requested.
The operator still determines native calling conventions, complete ranges, image
identity, shared-memory transport and meaningful observations. These helpers are
comparison instrumentation, not portable application backends. Run every Wine
check inside `spaghetti-headless-wayland`.

For a reviewed operation, generate the repeated entry setup from the
pinned image instead of copying opcode bytes into each driver:

```python
from spaghetti_extractor.components.comparison_original import native_entry_header

entry_header = Path("build/native-entry.h")
entry_header.write_text(native_entry_header(
    original=Path("libjq-1.dll"),
    expected_sha256="50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d",
    module="libjq-1.dll", entry_rva=0x28fc3, end_rva=0x292ff,
))
headers["native-entry.h"] = entry_header
```

Include that header in the native driver and call
`spx_install_component_entry((void (*)(void))counted_indexes)` on the replacement
side after the DLL is loaded. Check its return value; zero means installation
failed; abort the comparison if installation fails. The generated function supplies the pinned entry prefix, saved-body
storage, the existing redirect helper and verification that the rest of the
selected range is trapped. Its installer name is configurable; `module=None`
selects the main process image. Installation is single-use per generated helper.

For an operation with separate cold fragments, pass their reviewed half-open
ranges with `additional_ranges=((0x14628, 0x14630),)`. The entry range receives
the jump; every additional range is trapped. Ranges must be disjoint and lie in
file-backed executable sections. The generated prefix includes complete PE32
HIGHLOW relocation words and adjusts them for the loaded image base. Operators
do not need to copy relocated addresses into the adapter.

When one adapter works with either an isolated routine DLL or the main program,
call `spx_install_component_entry_at(image, replacement)` with the loaded image
address. `spx_install_component_entry_intact()` checks that the entry still has
its jump and the removed body ranges remain trapped. Both names follow the
configured installer name. The [Hello string recipe](../tests/fixtures/hello-string-conversion/README.md)
uses these calls for its existing local and normal-program consumers. Keep the
generated header in one adapter translation unit; installation state is local to
that translation unit. This is synchronous, single-threaded comparison setup.

The operator supplies the half-open body range, correct replacement ABI and
executable state/observations. Keep the image in `original_files`; generated glue
does not establish complete operation ownership or equivalent behavior. Unsupported
ranges and non-x86 images reject during preparation. Shared tails, alternate
entries, other relocation kinds and relocations crossing the entry range still
use explicit reviewed C bindings. The three jq string recipes use this helper with their existing
boundaries and real interpreter consumers; no native code recovery or pilot
rebuild is needed to generate the header.

Use `native_adapter_headers("pe32-process-observer.h")` when a C driver needs to
compare a terminating child. The existing `spx_fixture_observe_process` API accepts
an executable path, writable Windows command line and timeout, returning exact
DWORD exit status and raw stdout/stderr through `spx_fixture_process_result`.
It inherits environment/cwd, provides NUL stdin and retains at most 16 KiB per
stream. Launch, capture, overflow and timeout failures remain errors; they are not
observed program outcomes. Cross-stream ordering is not captured. This optional
header comes from the installed toolkit; no repository fixture path is needed.
The default header selection remains entry/import only.

For an isolated routine comparison against an original PE32 executable, prepare
a loader-compatible image through the installed API:

```python
from spaghetti_extractor.components.comparison_pe32_program import prepare_routine_image
from spaghetti_extractor.util import write_json

report = prepare_routine_image(Path("original.exe"), Path("work/routines.dll"))
write_json(Path("work/image-preparation.json"), report)
# Bind the original EXE, routines.dll and report in original_files when preparing
# the comparison package. Supply the DLL in runtime_files for the C driver.
```

The helper changes only four loader-header fields: the DLL flag, entry point,
checksum and original TLS directory. Every section byte remains identical, and
the report records original/prepared hashes and the exact edits. The original
program entry and TLS initialization are omitted; imported DLLs still use ordinary
Windows loader initialization and relocation. Only unsigned x86 PE32 executable
inputs are supported. Output must differ from the original.

The operator must review the image identity and define each routine's ABI, complete
body ranges, shared-state initialization, memory transport and observations in C.
Loading this image does not establish those premises or program equivalence.
The Hello string-conversion and stream-close recipes use this facility without
importing another target recipe. The quoting recipe separately adds its reviewed
body/header declarations. Those declarations are target analysis, not something
the loader helper infers. Use the program path below when original startup and
TLS must execute.

For mixed original/lifted program execution, the installed PE32 import helper
loads an authored observer/replacement DLL through a named export:

```python
from spaghetti_extractor.components.comparison_pe32_program import add_experimental_import

report = add_experimental_import(
    Path("original.exe"), Path("components.dll"), "component_anchor",
    Path("selected.exe"),
)
```

It preserves the existing section bytes, import address tables, entry point,
relocation directory and TLS directory. The DLL's adapters determine which
components execute; adding an import alone replaces no component. The helper
requires an unsigned PE32 executable with an entry point, existing imports and
spare section-header space. Bound imports and duplicate requested DLL imports
are rejected. It writes the prepared executable and a report binding the original,
DLL and output bytes. This is experimental assembly, separate from qualified
native composition and portable program backends.

Hello normal-entry, string-conversion and standalone-oracle recipes and the
DX-Ball native comparison use this same installed helper. An operator can keep
the reviewed target recipes/C and retained inputs in another directory, using the
installed toolkit instead of importing repository test fixtures. The external
handoff in `build/installed-program-helper-2026-09-23/` reproduces both retained
program images byte-for-byte and exercises one existing case on each target.
Hello runs through normal startup/TLS; DX-Ball retains its controlled component
entry and services. This checks the handoff, not newly defined boundaries or
broader runtime/portability coverage.

For repeated component editing against a PE32 **program**, the same import helper
is available through the comparison package instead of a separate build/run loop.
Pass this optional declaration to `prepare_comparison_package`:

```python
program_driver={
    "kind": "pe32-import", "image": "runtime/original.exe",
    "library": "components.dll", "symbol": "component_anchor",
}
```

A program can independently enter several selected components. Set optional
`entries` to their sorted, unique component identities, including the package's
own `component_id`. Select their implementations through the existing
`dependencies` argument and provide explicit `requirements` containing actual
reviewed dependencies; omit invented requirements between independent entries.
Every other selected component must remain reachable through declared requirements
from at least one entry. Existing contract, shared-representation and recursion
checks still apply. The generated workspace and composition graph show the entry
set separately from caller edges.

This declares program participation, not a new production API or proof of service
compatibility. Ordinary C adapters still implement entry hooks, shared state and
cross-component service bindings. All selected inputs bind the program comparison;
an edit invalidates that integration even when no other component calls the edited
entry. Local evidence for unchanged components can still reuse. Generated
`comparison-selection.h` defines `SPX_COMPARISON_PROGRAM` for program packages so
adapters can share one program observer while retaining local routine drivers.

The image must be listed in `runtime_files` and bound by `original_files`. The
selected C and adapters compile into the named DLL; its named export must exist.
`component check` prepares and launches `build/comparison.exe` using the declared
runner, passing `original` or `source` followed by the case arguments. Adapters
still decide what runs and emit the ordinary JSON observations. The declaration
does not imply normal startup: an adapter that redirects entry must say so in its
scope and assumptions. Run Wine inside `spaghetti-headless-wayland` as usual.

The normal retained result binds the original image, observer DLL, prepared
program, case outputs and preparation report. Public replay, dependency selection,
compiler reuse and source export work unchanged. A source export contains the
selected portable C and service contracts; the PE driver remains comparison
infrastructure. The [DX-Ball native recipe](../tests/fixtures/dxball-graphics-network/native.py)
now only prepares this package; checking and diagnosis use public commands.

To run a program with its **actual command-line arguments and output**, add
`"process": {"exit_codes": [0, 1], "drive": "P"}` to that same `program_driver` declaration.
The accepted codes are runner-observed process statuses; list the ordinary success
and error outcomes needed by the cases. Each case's `arguments` becomes the whole
argument list, without a selection prefix. The observer reads
`SPX_COMPARISON_SIDE=original|source` and writes the relative path supplied by
`SPX_COMPARISON_REPORT`. Its JSON report has this envelope:

```json
{
  "side": "source",
  "exit_code": 0,
  "observations": {"live_objects": [], "shared_bytes": [7, 9]},
  "diagnostics": {"selected_calls": 1}
}
```

The optional `drive` maps a private Windows drive to the runtime directory and
executes, for example, `P:\hello.exe`. Use one uppercase letter from D to Y and
a managed Wine server. This keeps the executable pathname stable when the
comparison or experimental package moves. The mapping is checked around execution;
it does not normalize path-dependent program behavior. Without it, the host
output-directory path remains an input, so relocation can change allocations,
diagnostics or output. Adding a drive to an old workspace requires a fresh
comparison under that invocation; old observations are not rewritten.

The existing result compares exit status, raw stdout/stderr bytes and
`observations` as `state`. Set `observation_fields` to
`["exit_code", "stdout", "stderr", "state"]`. Selection-specific call counts
belong in `diagnostics`; they are retained without equality comparison. The C
observer owns state normalization and checks that required hooks executed.
Missing reports, unaccepted exits and observer errors fail the check. Declared
service telemetry still goes through the existing interaction checks; it is not
treated as application stderr. Scalar fixture `input_domain` constraints are not
available in this mode; program arguments and environment assumptions define the
declared cases.

Each case also runs the untouched original. Its output and exit status must match
the instrumented original before a source comparison can pass. All three sides
use the same executable pathname with separate runtime files and Wine prefixes;
runtime input changes and unexpected working-directory files reject. This is a
bounded synchronous process driver, not an OS snapshot or a general file-system,
signal or concurrent-process observer. The target's C adapter must declare those
limits and provide the relevant memory/lifetime/interaction observations.

`component check`, `status`, dependency selection, printed replay commands and
object reuse apply to this mode as usual. Raw streams and observer reports are in
`cases/NNNN-{plain,original,source}.*`. The
[Hello normal-entry example](../tests/fixtures/hello-program/README.md) uses it for
real startup, TLS and argument-error paths. Source export works for matching
selections. Experimental candidate builds also retain PE program drivers and their
authored DLLs from matching comparisons. They reuse those exact binaries without
compilation or relinking. `candidate test --experimental-package` preserves normal
program arguments and the executable basename, sets the source observer selection,
and compares the retained memory/state report as well as output and exit status.
Missing reports and state-only differences fail even when visible output matches.
It runs the selected mixed program; the original control comparison remains in
the retained evidence. The existing explicit policy and required local component
checks still apply. Use `candidate export` for portable source assembly.

Export a matching selection for conventional source integration:

```sh
spaghetti-extractor candidate export TARGET --comparison build/check --comparison build/other-check --output build/source
make -C build/source CC=cc AR=ar
```

This reuses V3 source packages, preserving authored C, exact compiled headers,
interfaces, assumptions, contract requirements and available license/boundary
documents. Duplicate identical selections collapse; conflicting bodies or contracts,
known mismatches, stale receipts and source changes during export reject. The output
must be a new or empty directory outside the comparison inputs.

Start at the exported `README.md`: it links to `components/COMPONENT/README.md`
beside each implementation. These generated guides collect operation signatures,
source locations, shared types, services, lifecycle declarations, assumptions,
neighbor requirements and recorded comparison examples. Links remain local when
the project moves. Partial updates refresh the combined selection's guides without
needing retained neighbors' comparison directories or rebuilding their C.
Keep personal notes in another file; generated guides describe the exported
snapshot and do not assess subsequent edits. Native bindings are labeled examples,
and native drivers/replay inputs remain in the separate comparison results.

The handoff also retains original input identities and each component's
`comparison_binding_references` alongside its exact service catalog. References
describe the compared environments; several comparisons of the same C component
can legitimately use different adapters. They are not portable backend selections.
No comparison driver, original binary or native runtime is copied.

Each newly exported comparison also records its entry `component_id`. A supplier's
generated edit/check instructions use that caller entry when no independent local
comparison was supplied. `component start` still focuses the supplier's C, and
`--update-components --component` publishes only that unit. Older exports remain
readable; their guides direct the operator to the actual check command printed
when opening the workspace, without assuming the supplier has its own fixture.

Source assembly can now use the exported library without reopening comparison
packages or requiring their native tool paths. After reviewing the backend's
adapters, transports and outcomes, use the same `service_bridge` specification
described under [C service authoring](#reusable-c-service-authoring):

```python
from spaghetti_extractor.candidate.source_export_bindings import (
    load_source_export, render_source_service_bridges,
)

selection = load_source_export(project / "lifted")
# reviewed_bindings maps selected component IDs to explicit service_bridge specs.
bridges = render_source_service_bridges(
    project / "lifted", bindings=reviewed_bindings,
)
for component, (c_source, coverage) in bridges.items():
    # Include the component API and your adapter declarations in this C file.
    write_binding(component, c_source, coverage)
```

The reader checks inventoried source bytes, existing V3 source packages,
interfaces and service-contract bindings. Batch generation validates the library
once, then uses the existing C bridge generator. The caller supplies C declarations,
service implementations, entry wiring and build rules; `write_binding` above is
application code. Original reference hooks, live-object/lifetime assumptions and
ABI behavior do not transfer automatically to the new backend. The generated
coverage reports those adapter obligations. Source provenance and successful
generation do not validate program behavior or grant qualification.

Older exports remain readable, with explicit bindings supplied by the caller.
Re-export retained comparisons to obtain the new binding references and original
identities; recompiling or rerunning the original is unnecessary when that
evidence remains valid. The [jq source recipe](../tests/fixtures/jq-portable/README.md)
now accepts `--source-export` for this handoff, retaining its reviewed backend
selection and normal program-validation obligations.

After a checked implementation edit, refresh an assembled library explicitly:

```sh
spaghetti-extractor candidate export TARGET --comparison build/updated-check --output project/lifted --update-components
```

If you edited C directly under `project/lifted/components/COMPONENT/sources`,
bring it back through the existing local boundary first:

```sh
spaghetti-extractor component start TARGET COMPONENT --comparison-package build/local-package --reuse-source project/lifted --output build/draft
spaghetti-headless-wayland spaghetti-extractor component check TARGET COMPONENT --comparison-package build/draft --output build/updated-check
```

For a supplier already selected in a consumer, `component start`, `status` and
`check` also accept `--dependency-package COMPONENT=project/lifted`. This imports
only that component's C draft under the consumer's current interface, shared
headers and assumptions, preserving its adapters and all neighboring selections.
It needs no separate supplier comparison package. Status names the changed files;
the ensuing consumer check supplies integration evidence, not an invented local
fixture or inherited assurance. Use boundary refinement for changed headers,
contracts or source-file layouts.

The source project supplies the current C; the comparison package supplies its
original oracle, adapters, cases and boundary. Import does not reuse old assurance
for changed bytes. After a match, the update command above accepts those same C
bytes back into the library. Rebuild and exercise the affected program workload.

`--update-components` refreshes every component in the supplied comparisons,
including their selected dependencies. Use a local comparison to replace just one
unit. Other components retain their exact source, boundary and comparison
provenance from the existing library; their comparison workspaces are unnecessary.
The CLI lists refreshed and retained components. This does not claim a new passing
integration result for the combined selection. New exports retain per-component
build inputs. Older exports with the previous generated Makefile migrate without
running it; an unrecognized recipe needs a full export first.

The existing `--update` mode still requires the complete, unchanged component set.
Partial updates may also add explicitly reviewed components. Both modes require
unchanged declared boundaries, service requirements and shared/header inputs
unless explicitly reviewed. After refining
and comparing a changed boundary, review its effects on the application/backend
bindings, then name each affected component explicitly:

```sh
spaghetti-extractor candidate export TARGET --comparison build/refined-check --output project/lifted --update-components --accept-boundary-change COMPONENT
```

Repeat `--accept-boundary-change` for other affected components. The rejection
lists unreviewed components and changed fields or shared/header paths. The flag
accepts those files and declarations into the existing library; it does not prove
contract compatibility, validate the backend or bypass conflicting local edits.
To add a compared component, combine `--update-components --component NEW_ID`
with `--accept-boundary-change NEW_ID`. The command lists added components and
records them in `update.added_components`, while preserving existing sources,
comparison provenance and eligible build outputs. Review and supply application
entry bindings, remove any superseded backend body and update application build
rules separately; the exporter does not infer platform integration. After reviewing
a regrouped selection, `--remove-component OLD_ID` with `--update-components` retires
the named source package. Repeat the flag for other superseded components. A removal
must name an existing component absent from the incoming selection; retained callers
must no longer require it. Only unchanged managed files and named build outputs are
removed. Operator notes remain, conflicting C edits reject, and the backup retains
the old library. The archive is invalidated even if no remaining C needs recompiling,
so retired objects cannot remain linked. Removals are recorded in
`update.removed_components`. Incoming implementations require
matching comparisons, and affected program tests rerun.
Partial updates also check retained caller requirements and shared representation
groups against the combined selection. If a contract changes, include the reviewed
consumer/group comparisons rather than inheriting their old requirements silently.

The update preserves operator files and retains the previous library as a sibling
backup, printed by the command. Locally edited managed files reject unless their
bytes already equal the incoming checked files. Conflicting new paths, symlink
parents and concurrent edits reject. A failed publication restores the prior tree;
the successful backup also preserves old build products and late editor writes.
Changed components lose their named object/dependency files, and the archive is
rebuilt. Unchanged components retain their ordinary make outputs and input mtimes;
a changed generated Makefile conservatively invalidates all library objects in a
full update. Partial updates regenerate the recognized recipe from each unit's
explicit build inputs, so a local source-file split or include change need not
invalidate other units.
Other files under `build/` remain. This reuse assumes the same compiler, flags and
external headers; clean when those change. Rebuild with `make` and rerun affected
integration. Preserved build outputs do not supply correctness evidence.
The source export records the accepted boundary fields, update and backup names
without granting new evidence authority. A declaration-only change can reuse all
compiled objects while still requiring fresh program validation. These backups
are diagnostic history, not active application sources.

The result is `liblifted.a`. Supply an application entry and executable bindings
for its services, state and representations. Build each component adapter against
its own generated interface in a separate translation unit; the generated support
types are not a combined multi-interface header. `source-export.json` records
provenance and outstanding integration, with no qualification or activation
authority. Comparisons of an earlier fixture do not validate a different backend,
compiler or architecture. Select matching `CC`/`AR` tools and run `make clean` when
changing toolchains or flags. The [Hello source recipe](../tests/fixtures/hello-source/README.md)
demonstrates relocation and records the actual application/runtime work still needed.
The [standalone component round trip](../tests/fixtures/hello-standalone/README.md#edit-a-component-and-update-the-assembled-program)
exercises this update after local C checking, neighbor reuse, discrepancy replay
and repair, while preserving application/backend edits and actual program behavior.

`source_files` includes authored headers, which undergo the same C profile check
as authored translation units. Use `include_files` for explicitly trusted adapter
headers. Direct sources use the existing source-package builder internally;
`source_package` remains supported and cannot be combined with direct sources or
an overriding symbol map. No manual interface/source hash editing is needed.
The runtime helper revalidates the retained package and returns only its compiler,
runner/server and link/runtime file mappings, preserving relative paths. It does
not inherit cases, adapters, assumptions, interfaces or selected component bodies.
The original oracle files and their role are explicitly chosen in the new recipe.
Generated packages use the same start/check/replay/selection commands and SDK
format as before. This avoids an intermediate source/interface packaging script;
it does not replace boundary design or executable memory/lifetime transport.

`--reuse-comparison` revalidates prior matching evidence and consumed dependencies.
When reusable, it retains past observations with zero new compiler/link/execution
calls; changed inputs trigger a normal check and visible invalidation reasons.
This does not infer contract compatibility or recheck external live state. Concrete
receipts remain non-authorizing, including reused receipts. Experimental selection
and strong qualification are separate obligations.

The same `--reuse-comparison` request also enables per-translation-unit object
reuse when observations must be rerun. `build/compilation.json` is retained build
metadata under the existing comparison receipt: it binds the compiler, compiler
environment, options, generated/read inputs, object bytes and include-search probes.
A source edit recompiles its consumers; other object files are copied from the
validated previous result. An invalidated comparison still relinks and executes.
Changed checker, observation or contract inputs do not become valid merely because
the objects were reusable. Full observation reuse skips compilation, linking and
execution together.

Literal includes and include-existence tests record candidate paths, including
missing headers and ignored search directories. Adding a header that shadows an
old include therefore invalidates the affected translation unit. Header changes
outside every effective compiler input and still-valid lookup may reuse retained
observations; their exact new bytes remain in the snapshot and `input_sha256s`,
with `ignored_unread_headers` explaining the decision. Readers revalidate that
exclusion. The graph's impact report excludes those established unread changes.

This precise path currently requires the provisioned immutable Nix toolchain/store
and understood preprocessing. Computed includes, real trigraphs, time-dependent
macros, precompiled headers outside the immutable store, and untracked compiler
loader/plugin/profile/implicit-file mechanisms fall back to compilation with a
visible reason. Ordinary compilation remains available. Relative source/include
paths keep `__FILE__` stable between snapshots. Phase timings distinguish compiler
work, cache validation/indexing/retention, linking, execution and evidence work;
`retained_bytes` counts bound inputs, build artifacts and observations, excluding
transient runtimes and the receipt itself.

Wine comparisons create fresh private prefixes for the original and source sides.
Their prefix initialization runs concurrently with at most two workers; every
startup must succeed before the ordered cases begin. Cases still share state
within their own side. Registry and relative working files are separate between
sides; absolute host paths and external services are not sandboxed. No prefix or
server is reused across comparison runs. Failure or cancellation stops and joins
startup commands before server shutdown and disposable-prefix removal.

`runtime-startup` timing rows retain each command's duration, runtime label and
cancellation status. `runtime-startup-wall` records the elapsed interval covering
those commands. It explicitly overlaps `runtime-startup`: do not add both, or
sum concurrent command durations and describe them as wall time. Runtime engine
changes invalidate prior comparison context through the existing evidence rules.

Comparison packages can explicitly select authored dependencies with their own
existing interfaces, sources and fixture bridges. Each unit is compiled and given
editor diagnostics against its own generated header. Use
`--dependency-package COMPONENT=DIR` to check an edited supplier under the exact
retained interface and assumptions; a changed contract requires explicit refinement.
For ordinary C edits, `--dependency-source COMPONENT=DIR` on start/check/status
imports only that unit's authored C from a component workspace, a containing
network workspace or a source project. The consumer retains its adapters and
other selected bodies, even if the supplied workspace bundles older suppliers or
unfinished neighboring C. The complete contract (including requirements) and
existing boundary headers must match. Declared implementation C file refactors
and new private helper headers are carried with the selected unit. The existing snapshot/checker binds
the resulting C; this is an unverified draft, with no inherited assurance.
Use package selection for reviewed adapter/bundled-body changes and boundary
refinement for contract or header changes. Python callers express the same choice
as `dependency_packages={"NAME": SourceDraft(Path("WORK"))}` with `SourceDraft`
from `components.comparison_source_draft`; no new evidence format is introduced.
The [jq supplier walkthrough](../tests/fixtures/jq-array-append/README.md) demonstrates
separate supplier checks, isolated consumer reuse, integration invalidation and
replay of a selected supplier bug after repair.

Composed comparison packages resolve selected suppliers transitively. A package
can export its bridge paths with `export_adapters` (`exportAdapters` in the Nix
SDK); consumers then select `{id, package}` without repeating bridge wiring.
Selecting a composed package brings in its suppliers, with one copy of each
consistent implementation. Conflicting direct and transitive selections reject.
`--dependency-package` accepts a composed replacement and checks its nested
selections too; changing topology requires an explicit package refinement.
When replacing several units together, an explicitly named replacement supplies
that unit's global body, overriding copies bundled by the other replacement
packages. This does not depend on argument order. All copies must retain the
existing contract, and conflicting bundled bodies without an explicit choice
still reject. For example, selecting edited `storage-set` and `storage-release`
packages uses the new release body even when the setter package contains its
previous body; its interface, assumptions, representation and requirements must
remain compatible with the retained comparison.

Explicit `requirements` bind a supplier's exact boundary contract: interface,
operation symbols, assumptions, domain, resource/service contracts and shared
representation bytes. A requirement has `id`, `supplier`, `contract_sha256`,
`kind` and `service`. `service` requirements name an existing interface service;
`consumer` requirements describe integration consumers, and `internal`
requirements describe recursion within the same component. The Python
`comparison_composition.requirement` helper records a reviewed supplier binding.
An unchanged function signature alone never establishes compatibility.

The comparison preparer's `representation` declaration uses the existing
replacement `group`, an explicit `revision` and named shared `inputs` under the
component's include directories. Bind every source and adapter copy that defines
the shared layout. All selected members must agree on those bytes and declarations.
Partial groups can have local comparisons; experimental assembly requires the
complete group. A coherent declaration checks selection consistency, not semantic
correctness of a conversion. Regenerate affected requirements through the authoring
API and rerun their comparisons after a representation change.

The [jq descriptor migration](../tests/fixtures/jq-array-storage/README.md#private-descriptor-representation-change)
shows ordinary C conversions, generated group bindings, mixed-selection rejection,
a replayable conversion defect and repair. Its real path consumers rerun after
the layout change; an unchanged native-service check reuses. It explicitly retains
the backing heap layout still consumed by native code. Representation-independent
operation signatures alone cannot remove those remaining readers or their layout
requirements.

The retained `composition` graph and operator output show requirement provenance
and contract identities. Cycles require an explicit `recursion_groups` declaration
(`recursionGroups` in Nix), with sorted `members`, an `id`,
`mode: synchronous-comparison` and `progress: unproved`. This supports concrete
recursive execution; other modes reject. No synthetic production API is needed
for an internal recursive call. Discovering a cycle does not prove progress.

With `--reuse-comparison`, `selection_impact` identifies changed unit inputs and
their transitive integration consumers. Unchanged unit inputs are not a proof
reuse claim: retained evidence is admitted separately under exact bindings.
The graph records declared requirements, not a verified C call graph or checked
summary. Full comparison input binding still protects integration invalidation
when a fixture has dependencies outside its declared graph.

### Experimental component-check requirements

To resume work from a packaged experiment, use `component start TARGET COMPONENT
--experimental-package EXPERIMENT --output WORKSPACE`. The component name selects
its retained comparison setup; operators do not need to locate numbered receipt
directories. The usual workspace and editor guides are regenerated, and the
printed check command includes its retained comparison for reuse. The command
also prints how to reopen the main program with this workspace selected. Existing
source-carrying and dependency-selection options apply; this is preparation of an
unverified draft, with no compilation or execution. The experiment stays unchanged.

The main component opens the program/network comparison. Other units require their
own retained component receipt. If only network evidence is present, the diagnostic
offers the main workspace and identifies the missing local setup. Selection alone
cannot reconstruct the unit's independent oracle, input transport or service setup.

Prepare the existing policy from retained comparisons through the public CLI:

```sh
spaghetti-extractor candidate policy TARGET --comparison PROGRAM_CHECK \
  --configuration my-experiment --component-comparison SUPPLIER=LOCAL_CHECK \
  --output build/experiment-policy
```

Review `build/experiment-policy/README.md` and `experimental-policy.json`, then
use the printed build command. The guide exposes each component's assumptions,
domains, services, resource declarations and representation requirements, with
links to its interface and comparison. It separates the main network comparison
from additional component receipts and names missing required checks. Policy
preparation reads existing evidence; it neither compiles nor runs a candidate.
No internal Python imports or manual digest calculation are required.

By default the draft requires a matching receipt for every selected component.
Repeat `--network-only COMPONENT` to explicitly rely on selected network cases
for named components other than the main comparison. Every supplied receipt is still checked, including one for a
network-only unit. The draft allows the existing non-disproved formal statuses;
the guide reports actual statuses separately. Original runtime dependencies are
allowed only when present in the supplied comparisons. Preparing this policy is
not activation: the later build validates the selection against the policy chosen
by the operator. Compatible C edits can reuse the policy; changed assumptions or
accepted declarations need a newly reviewed policy. No output directory is overwritten.

The experimental policy's `required_components` always names the complete selected
network. By default, every selected component also needs its matching comparison
receipt. An explicit optional `required_component_checks` list can name a subset
when program/network comparisons provide the intended practical evidence. The
main comparison remains mandatory, and any supplied component receipt is checked
against the exact selected implementation and boundary, even if not required.
All assumptions, services, resource declarations and representation groups still
need the existing policy acceptance. The CLI names components supported only by
the selected network cases; that does not establish independent local assurance
or that every operation was exercised. This choice cannot replace strong
qualification, erase a known counterexample, or admit a mismatching comparison.

### Experimental suite admission reuse

`candidate build --experimental-comparison NEW_CHECK --reuse-experimental PREVIOUS
--component-comparison EDITED=FRESH_CHECK --output NEXT` preserves the previous
experimental policy and automatically retains matching component receipts. It
always takes the executable and main comparison from `NEW_CHECK`. Selected source,
headers and contract bindings determine which additional receipts can reuse;
changed receipt bindings need explicit fresh checks. A missing changed receipt rejects before
publishing the new directory and identifies the required CLI argument. Every
selected receipt still passes ordinary experimental admission. Unchecked units
that the existing policy explicitly accepts through network evidence remain in
that category; reuse does not create local assurance for them.

An explicit `--experimental-policy FILE` replaces the reused policy for a reviewed
declaration change. The main component, selected component set, original inputs
and comparison tools must match the previous experiment; other selections use
ordinary preparation. The previous package is never updated in place. Build costs
record the previous manifest and reused receipt IDs separately from the executable
reuse, without adding qualification authority. Reusing evidence is independent of
whether a new main comparison reuses objects or reruns program workloads.

`candidate test --experimental-package` performs full policy, component evidence,
implementation and executable admission once per run. Before and after every case,
it checks the complete retained package's contents and directory membership,
external compiler/tool inputs, include-lookup states, actual runtime files and
effective suite. Each case still checks its own behavioral observations and
resource/service traces. Normal-entry program cases also retain the C observer's
report and check state plus cleaned raw streams with the existing comparison
reader; state-only failures are listed in the CLI and `program-observations.json`.
A changed input stops the run, including a change during
its last case; matching output cannot conceal stale evidence or changed policy.

This decision is private to the current invocation. A direct
`run_experimental_case` performs fresh full admission, and a new suite never
inherits a previous process's success. Content hashes determine reuse, so restoring
timestamps or preserving file sizes does not hide edits. Unknown optional compiler
inventory uses the full reader repeatedly; its `reuse_limitation` is recorded in
admission timings instead of blocking an otherwise eligible experimental run.
No new authority artifact, weaker policy or proof status is involved.

The package snapshot is deliberately conservative: even changes to unconsumed
files in that retained package stop the current run. External compiler reads use
the same retained-path mapping as ordinary admission. Actual read bytes and
symlink targets are checked; include probes retain absence/identity checks.
This is a run-local optimization of evidence validation, separate from component
contract compatibility and cross-run comparison/object reuse.

## Resource diagnostics under a selected contract

Comparison setup accepts `resource_checks` in Python, or `resourceChecks` in
`sdk.lifting.comparisonPackage`. It binds canonical boundary lifecycle declarations,
explicit token/frame capacities, instrumented sides, coverage gaps, and per-operation
allowances for untransferred or deliberately retained references. The current
operation rule accounts for consumed input references and produced results; other
operation lifecycle shapes fail with an unsupported-instrumentation diagnostic.
Borrowing, copying and consuming services use the shared value-transport observer.

The generated runtime tracks reference tokens, generations and nested frames.
Each case retains resource events separately from its behavioral observations.
A lost reference is reported and preserved; the observer does not free it to
repair the program. An explicitly permitted original leak remains visible without
becoming a blanket admission failure. Exceeding the selected allowance is a failed
contract premise, even when JSON outputs match. Capacity or generation exhaustion
is an instrumentation limitation, not evidence of a new target bug.

Both experimental selection and fresh experimental execution reject failed or
unresolved resource premises. The project policy must explicitly bind each
selected declaration through `accepted_resource_checks`; a stable signature or
unchanged textual assumptions do not accept changed resource effects. Runtime
resource reports and behavioral reports retain separate statuses and bindings.

This observes transport references, not a universal heap. Immediate values may
also occupy transport slots. Native allocation internals and native object lifetime
generations remain unobserved; jq pointer values are only diagnostic alias hints.
The existing jq cases separately compare retained contents and subsequent reads.
See the [instrumented jq workflow](../tests/fixtures/jq-path-network/README.md) and
[explicit expired-memory fixture](../tests/fixtures/behavior-faithful-memory/README.md).
No resource observation supplies strong proof or activation authority.

## Supported source and formal comparison products

An explicitly configured source-edit product can compare ordinary C against a
retained source baseline:

```sh
spaghetti-extractor component check TARGET COMPONENT --source --compare-baseline
```

The target exposes `components.units.COMPONENT.sourceEditCheck` and lists
`sourceEditCheck` in that unit's operator products. Use
`nix/component-source-edit-check.nix` with `interfacePackage`, `sourcePackage`,
`baselineInterfacePackage`, `baselineSourcePackage` and a manual `boundary`:

```nix
boundary = {
  operation_id = "cleanup";
  source = "cleanup.c";
  entry = { position = "after"; text = "  /* exact complete entry line */\n"; };
  exits = {
    next = { position = "before"; text = "  /* exact complete next line */\n"; };
    tail = { position = "before"; text = "  /* exact complete tail line */\n"; };
  };
};
```

Replace the example text with lines already present in both sources. Anchors
must be unique complete lines (or consecutive lines), with at least two named
exits. Proof markers are inserted into copies, then checked to erase back to
both compiled ordinary sources. This defines a proof region within an operation;
it does not add production functions or split replacement ownership.

The current profile permits finite scalar branching and newly introduced private
nonescaping scalar storage. Wider state, service or representation edits report
incomplete. Both host and PE32 source portability checks still run. Optional
`previousSourceEdit` supplies a previous product for exact local-query reuse.
Optional `baselineConditionalPacket` supplies the actual
`conditional-engine-result.json`; the reader checks its source and full
interface identity, including the regenerated logical proof-interface digest,
and preserves its assumptions, obligation statuses, coverage
selection and pending boundary requirements. Missing, stale or unsupported
baseline evidence is reported separately from the source comparison. Logical
projections requiring additional machine-contract context remain unsupported by
this baseline bridge.

A complete source-edit status means the supported source comparison and source
portability checks passed. It does not import the baseline application proof,
complete an unresolved baseline, reuse neighboring application proofs, or
authorize supplier export or activation. This command cannot be combined with
`--conditional` or `--local-contracts`.

To require a checked embedding in a retained application's proof environment,
configure the full engine output and select one compiled baseline obligation:

```nix
baselineConditionalEvidence = previousProvider.engineDerivation;
baselineObligation = "sync:loop";
baselineQueryTransport = true; # Optional: carry completed bounded property checks.
```

This replaces `baselineConditionalPacket`. Preserve the original Nix output's
reference closure: its diagnostic compilation paths still refer to the original
source package and exact-C inputs. Copying the diagnostic tree as an unrelated
flake source can lose those references and must report incomplete.

The checker first reproduces the original GOTO model byte for byte, then checks
both ordinary/marked source pairs and the complete context around the changed
region. The local query must be identical in the ordinary and baseline proof
environments. If this requested embedding is unsupported, local scalar success
alone cannot complete the command. The extra context work is currently material
to latency; see [measurements](performance-and-invalidation.md).

The `baseline_context` result retains the original assurance and obligation
status, model and interface digests, and local-query binding. Without
`baselineQueryTransport`, it supplies only the checked embedding. With that option,
it also reparses published successful property-query processes and checks the
complete CBMC-processed context, including generated assertion predicates,
property IDs and backward-GOTO loop IDs. Unknown query modes report incomplete.
The supported query scope has explicit unwind bounds and disabled unwinding
assertions: transported results remain bounded checks under the original runtime
contracts. Missing, failed, coverage and unfinished application queries acquire
no result through this rule. Limits naming loops absent from both checked models
are retained and identified as inactive.

`query_transport` records the original process binding and output separately
from the edited-model correspondence. It never rewrites a cache key to claim
CBMC ran on the edited model. `previousSourceEdit` may also reuse a processed
context after current validation of its exact four model digests, query policy,
source comparison and retained artifacts. The encompassing application obligation
and pending boundary requirements retain their original statuses. Activation,
strong receipts and neighboring complete-component theorem reuse remain separate.

Explicit conditional checks with no pending boundary requirements also emit `conditional-refinement-result.json`
(`spaghetti-extractor-conditional-contextual-refinement-v1`). It runs the shared
contextual proof validators with a required, exact runtime-contract selection;
its receipt and each model, proof-input and execution layer bind that selection.
The normal `contextual-refinement-v2` reader rejects these conditional records.
Successful auxiliary frames and wider-entry theorems can be checked under the
same explicit selection against retained solver/GOTO bytes. Failed or missing
auxiliary facts do not become guarantees because the main proof passed.

This artifact is a conditional component theorem. The diagnostic engine packet
remains the public feedback and exact-query-reuse input. Neither artifact grants
native activation, and supplier use additionally requires checked source-summary, postcondition
and entry/frame rules. The conditional shared-supplier path now applies those
rules with explicit runtime assumptions and retained solver/GOTO evidence.
`providerComponents.ID.conditionalRefinement` is available only in a conditional
work-package check and is mutually exclusive with ordinary qualification inputs.
All supplier assumptions must occur exactly in the caller's selected contract
set; a revision or semantic-hash change is not accepted as compatibility.
Complete local consequences still reject continuation and allocation-history
premises that have no component-composition discharge. Conditional supplier
loading currently supports the existing checked shared-state leaf contract;
transitive shared-state suppliers remain outside that implemented domain.

The public conditional checker can investigate a binding with authored pending
requirements, provided normalization finds no structural inconsistency. It
retains the exact requirements in the diagnostic packet's input and result,
and displays them separately from local proof obligations. Passing the local
obligations does not discharge those requirements: feedback remains incomplete
and no conditional supplier theorem is emitted. Unknown requirements are never
assumed true. Missing operation authority, inconsistent services and invalid
contracts still stop preparation; the default qualification gate is unchanged.
Completed local queries may be reused under their existing exact model/evidence
rules while requirements are refined. That reuse does not prove the requirements
or establish compatibility of a changed component contract.

Configured products can expose `conditionalCheckFor` alongside `conditionalCheck`
to accept focused requests through the same Nix provider:

```sh
spaghetti-extractor component check TARGET COMPONENT --conditional \
  --region 'cleanup/sync:allocated' --query-timeout 60
```

`--region` is repeatable and names an operation plus an existing obligation ID
from the check details. Unknown or duplicate selections reject before solver
execution. `--query-timeout` controls each query, including subdivision retries;
it is not a deadline for the command. The provider accepts `selectedObligations`
as canonical `{ operation_id, obligation_id }` rows, or its
`conditionalCheckFor { obligations = [...]; queryTimeoutSeconds = 60; }`
function can supply the public product directly.

Focused checks retain the complete prepared model/coverage inventory and compile
only selected regions. Other regions have explicit incomplete scheduling records,
with no compiled-model or execution digest. Feedback reports the selected result
and deferred coverage separately. A focused check always withholds supplier
theorem export, including when all requested queries pass. Completed selected
queries can be reused; deferred regions supply no query evidence. These are proof
regions within the authored component, not new production APIs or independently
liftable components.

Components are the supported unit of candidate reconstruction work. They let an operator replace
one exact machine region, a procedure-sized group, or a larger subsystem while
every other structural unit remains owned by the machine-IR fallback.

The current canonical operator artifact is `component-work-package-v6`, a
non-authorizing content-addressed `semantic-slice-v2` projection from
`linked-semantic-module-v2`.  Its owned definitions are distinct from the
faithful-C context shown to the operator.  Portable authority is
`semantic-provider-qualification-v2`; the direct path runs contextual
refinement, generates the machine overlay, and compiles the PE32 objects from
the V6 package without consuming a component-contract V4, machine-binding V5,
or component-implementation V4 artifact.  Total
`implementation-selection-v2` then explicitly selects that provider or the
generated Behavioral-C provider for every definition.

GNU Hello's `ascii-to-lower` is the first deployed direct vertical.  The
program-name, callback-registration, induction, and reusable-library verticals
exercise the same path. jq and DX-Ball also emit direct V6 work packages, but
their unresolved machine-effect and portable-interface reviews remain explicit
blockers. The public V4 contract/implementation/dependency DAG has been removed.
Some proof-kernel types still carry historical names internally; they are
in-memory implementation details and must not be serialized or exposed as a
second component system.

## Two Graphs

For a draft continuation relation, `continuation_unit_ids` names unowned exact
units retained in `transfer_ids` alongside the owned `unit_ids`. Public review
keeps replacement membership unchanged; canonical proof input generation checks
the referenced context. The bounded common-prefix proof compares both executions
through that exact context. A local proof can pass while provider qualification
remains incomplete: dispatch/link validation must preserve the required context
behavior before activation. Calls without checked context contracts remain
unsupported. An unproved dead-register annotation cannot waive state checks.

The machine-IR graph is canonical. Component boundaries do not alter it. The
authored component catalog is a work graph over exact machine-unit membership.
Alternative groups may overlap, but one selected configuration may not: every
structural unit has exactly one implementation owner.

This is what makes local work possible without a complete understanding of the
target. Selecting one component does not require lifting its callers, callees,
or unrelated regions first.

## Canonical Lifecycle

Artifact version numbers describe individual wire formats, not one global
component generation. New boundary-aware components use
`PortableComponentInterfaceV5`, which references the shared canonical schema,
checked operation projections, and lifecycles. Source package V3 remains the
implementation package. The interface is machine-free; exact machine meaning
lives in the checked binding intent and its content-addressed semantic slice.

The component DAG produces these independently cached artifacts:

1. `v5Interfaces.<id>`: the checked human-facing operation and boundary schema.
2. `bindingIntentPaths.<id>`: reviewed operation-to-definition projections,
   services, callbacks, lifecycles, object selectors, and honest blockers.
3. `sourcePackages.<id>`: exact authored source bytes plus one C symbol per
   operation.
4. `v6SemanticSlices.<id>`: the independently cached, content-addressed subset
   of `linked-semantic-module-v2` needed to refine the component.
5. `v6WorkPackages.<id>`: a non-authorizing operator package containing the
   interface, semantic slice, immutable faithful-C context, skeleton, required
   dependencies, suggested veto tests, and current blockers.
6. A direct `portable-c-work-package-provider-v2` qualification compiles the
   source for host and PE32, checks the exact ABI and source profile, runs the
   contextual CBMC/refinement, relation, induction, lifecycle, service, and
   ownership kernels that apply, and publishes native objects only when all
   required authority closes.
7. Component-operation service edges are expanded directly from binding intent;
   every selected dependency must itself have a qualified direct provider.
8. `semanticImplementationSelections.<configuration>` is the sole total
   definition-ownership decision. It selects portable objects or immutable
   generated Behavioral C with no implicit per-component fallback.
9. Native realization links selected objects beside generated Behavioral C
   through the one shared runtime and dispatch registry.
   The runtime validates that registry structurally but does not duplicate the
   later provider-selection decision; the payload-bound dispatch/link receipt
   owns exact provider, object, symbol, and RVA authority.

Callback authority is a semantic link fact, not a native-ingress input to a
component. `linked-semantic-module-v2` materializes each reachable callback as
a content-bound code capability with its original target RVA, protocol,
lifetime, target symbol, and root provenance. Component refinement validates
its logical handle against that registry and emits only the semantic target
RVA. At execution, the shared runtime resolves that RVA through the one native
code registry. Bridge symbols and candidate addresses therefore remain native
realization details and cannot enter a component contract or source package.

### One Semantic Boundary

Authored components, adopted libraries, generated Behavioral C, runtime
providers, and the external environment all qualify definitions in the same
semantic-module namespace. A consumer binds the provider operation and semantic
slice identity, never a native object address. Changing presentation-only work
package content therefore does not invalidate contextual proof; changing an
operation's checked semantics does.

Library recognition and adoption remain distinct non-authorizing stages. An
adopted behavior pack uses the same direct provider qualifier and publishes the
same V2 qualification/object records as operator-authored source. Configuration
and runtime code do not interpret recognition-specific receipts. External sites
remain explicit checked environment providers because the operating system is
not a hidden component implementation.

`hybrid` permits generated Behavioral-C ownership for unlifted definitions.
`portable` requires zero generated-C ownership in the selected root-reachable
definition closure. Neither mode permits a selected authored component to
silently fall back.

The component DAG emits no standalone runtime. It generates direct machine-state
overlays, copies exact authored source, cross-compiles PE32 objects, marks owned
units in the total activation plan, and forbids silent fallback inside an
enabled component. Native linking combines those selected objects with immutable
generated behavioral C and the module's one shared runtime.

### Portable Component Interface V5

Portable interface V5 defines typed operations, framework-managed instance
state, protocol states, logical resources, effects, injected services, objects,
lifecycles, callbacks, and checked outcomes without exposing a machine ABI or
raw function pointer. It contains no x86 registers, raw
addresses, PE ranges, import IDs, or
external-site identities. Authored source may not define mutable global state.

The stable component ID and generated C interface namespace are separate. For
example, component `directdraw-init` uses interface namespace
`dxball_directdraw_init`. Receipts bind both explicitly instead of requiring an
operator-facing ID to be a C identifier.

The DX-Ball DirectDraw pilot exercises typed COM services and many joined
cutpoints. Its target-owned success-tail effects remain explicit and
nonauthorizing until their connected-definition or faithful-continuation
boundary is proved.

### Source Contract

Every authored source package is V3 and maps each V5 operation ID to one C
symbol. Single-entry source packages and adapter-specific ABIs are rejected.
Borrowed references, interior pointers, services, callbacks, effects, and
outcomes are expressed by the V5 interface and its checked machine binding,
then imported through the shared runtime boundary transducer.

## Static Refinement Loop

`boundary adopt TARGET component-seed:RVA --input REVIEW --output NEW_DIR`
exports reviewed interface/binding edits for both new and already configured
seeds. A configured seed must retain its component identity. The command checks
the current proposal and exact membership, rejects stale reviews and nonempty
outputs, and preserves draft status and blockers. Installing the exported inputs
into the target remains a separate edit; existing source files are preserved.

One logical effect may reference multiple machine facts, including distinct
writes on loop and terminal paths. Effect references are uniquely identified
and ordered by `(effect_id, unit_id, family, index)`. Repeating the same fact
identity, even with a different digest, is rejected. These references remain
reviewed inputs; behavioral proof and provider qualification are still required.

A review directory may also contain editable `bisimulation.json` in the canonical
component-bisimulation-intent format. Adoption refreshes its self-digest, checks
the component and operation identities and keeps every cut inside the selected
region. It exports `bisimulation/COMPONENT.json` and its lifting-intent reference
in the same transaction as the interface and binding. Invalid formats, extra
fields and symbolic links reject the export. This checks the proposed input's
structure; source markers, invariants and equivalence still need the proof engine.
No binding blocker is removed and no proof receipt is imported by adoption.

If `component check TARGET ID` has no qualification product, it reads the
available canonical binding intent and reports its declared blockers and artifact
path. The suggested development-status command preserves the target flake and
local-build selection. A stale or foreign binding is rejected before displaying
its blockers; an empty blocker list never grants qualification.

When a mutable callee lacks the machine-state premise required at a call,
`component check` follows the qualification-bound proof dependency to the
supplier's wider-entry and cut/exit frame results. It names the operation and
segment, distinguishes a violated premise from an absent one, and prints the
recorded supplier proof identity. This navigation does not turn a local result
into activation authority. Failure of a stronger composition premise alone
does not disprove the supplier's ordinary equivalence; the operator may need
a different boundary or a more general checked state relation.

For mutable leaf operations, the bisimulation intent can propose
`"machine_clobbers": ["ecx", "edx", "esi"]` alongside its existing syncs.
This is an ordered list of machine fields for supplementary proof queries,
not a change to the Portable-C interface. The checker must prove preservation
of every other field at cuts and exits; declared results remain related to
the source result. Every consumed segment needs positive evidence. At a call,
the original side may produce any values in those fields, so a caller that
depends on an unmodeled value will fail its own proof. Declaring a field dead
does not prove it dead. Stack-pointer, private-memory and object-lifetime
changes require their own checked rules.

The same intent can propose `"private_stack_writes": [{"offset": -8, "bytes": 1}]`
for residual original stack writes, separately from logical view permissions.
Offsets are relative to operation-entry ESP; the initial range is limited to
`[-1024, 4096)`. The checker must establish write confinement, a stable ESP at
cuts and the corresponding wider-entry theorem before any caller can consume
the footprint. The original caller then receives arbitrary bytes in those
ranges and must prove that they are harmless to its own behavior. The source
caller does not receive matching arbitrary writes. A changing stack anchor or
an observed residual byte needs further reasoning; the declaration grants no
waiver. Public diagnostics navigate the declared private and clobber premises
instead of requiring the older identity frames for those operations.

Use borrowed memory views when an operation must observe updates made through an
alias during its execution. Scalar state imported at entry is a snapshot; it
cannot represent a word that must be read after overlapping writes. View bases
may use a checked 32-bit register plus signed displacement, with the same modular
address calculation in production and proof. Caller ownership, extent, liveness
and equivalence obligations still require qualification.

Portable source may be authored and compiled from only its reviewed interface.
This development derivation is intentionally small and nonauthorizing: it does
not depend on proposal discovery, resolved machine membership, rooted authority,
or another component's intent.

Activation adds an exact machine binding. The toolkit builds a forced-cutpoint
graph with an entry obligation and authored acyclic or cyclic sync obligations.
Every exact cycle must be cut. Additional acyclic syncs use the same checked
relation and barrier mechanism. Each shard relates arbitrary admitted interface inputs and typed
service responses to the corresponding exact Behavioral-C segment; it does not
enumerate complete paths. One compiled GOTO model is shared by formula-sliced
authored assertions, inventoried paired language-safety partitions, and
nonvacuity witnesses. A concrete mismatch is `violated` with its stable cutpoint and
property location. Missing semantics, timeout, an unwitnessed relation, or
unrepresentable state is `incomplete`. Operator-authored examples and expected
outputs cannot enter this authority path.

A `finite_control_target` result may replace a recovered indirect jump only
when its selector expression, closed target inventory, table bytes, and target
addresses are already machine-derived and checked. The binding assigns portable
logical route values to that exact target set. Materialization expands every
checked selector value into a route, static refinement assumes only the proven
entry domain, and runtime lowering rejects values outside that domain before it
maps the logical route back to the exact machine continuation. A stale table,
selector expression, inventory digest, or non-bijective route map fails closed.

## Contextual Bisimulation

New and migrated Portable-C operations use the universal contextual cutpoint
system described in
[`portable-c-contextual-bisimulation.md`](portable-c-contextual-bisimulation.md).
It proves ordinary connected C directly against an exact Behavioral-C slice,
uses forced entry and checked acyclic or cyclic sync labels as proof barriers, and
materializes no complete paths. The legacy finite-domain and
`init`/`step`/`finish` mechanisms do not
authorize a provider once that operation has migrated.

## Legacy Evidence

This section describes the migration path for older logical C adapters.
`structural-draft-v1` organizes work but never authorizes replacement.

`bounded-equivalence-v1` uses a declared finite input domain. The current
`exhaustive-finite-domain-v1` producer compiles the portable C and compares it
against concrete evaluation of the exact machine IR for every case. It never
executes the original binary. A concrete mismatch is `violated` and includes
the source-level arguments, expected value, and observed value. Unsupported
semantics, an excessive domain, compiler failure, timeout, subprocess crash, or
malformed evidence protocol is `incomplete`. Object-view cases compare the
logical result and the complete reviewed register, flag, memory-write, and
control completion. The C evaluator runs in an isolated subprocess, so a bad
replacement is a localized evidence failure rather than a crashed build
orchestrator. Finite-domain evidence proves only the declared bounded domain;
it is not a universal function theorem.

## Configuration Safety

- Enabled components with exact checked activation authority use portable source.
- Draft, missing, or incomplete components retain generated Behavioral-C
  ownership.
- Every unselected semantic definition retains generated Behavioral-C
  ownership.
- Overlapping ownership is rejected.
- Enabled component members may not fall back individually.
- Whole-program candidate generation requires structural executability; release
  acceptance additionally requires ISA qualification and the activation-bound
  universal component/dependency gate. Candidate-only tests are optional veto
  diagnostics.

Reviewed interfaces may avoid copying long synthesized effect inventories by
using `adapter_effects.inherit_synthesized_except`. Each exclusion names one
exact family, machine-unit ID, and effect index that is represented elsewhere
by a logical result or explicit completion. Missing, duplicate, or stale
references fail contract construction, and the final interface checker still
requires every synthesized effect to have exactly one owner.

## Public Interface

Targets normally use `sdk.workflow.pe32`, then inspect
`workflow.components`. Low-level construction remains available as
`sdk.lifting.components` for tooling tests.

```nix
environment = sdk.environment.pe32 {
  id = "program-win32";
  profilePacks = [ runtimeProfile ];
  interfacePacks = [ ];
  launchProfile = launchProfile;
  boundaryIntents = { };
  support.processTermination = null;
};

workflow = sdk.workflow.pe32 {
  original = originalExe;
  targetId = "program";
  binaryIdentity = "program.exe";
  externalEnvironment = environment;
  lifting = {
    boundaries = [ ];
    components = {
      intent = ./intent/components.json;
      operatorRoot = ./intent;
      sourceRoot = ./source;
    };
    libraries = { packs = [ ]; adoptionRoot = ./intent/libraries; };
  };
  backend = { kind = "behavioral-c"; sourcePresentation = null; };
  analysisLimits = { maxUnits = 512; maxCandidatesPerSeed = 12; };
};

workPackage =
  workflow.components.v6WorkPackages."ascii-to-lower";
selection =
  workflow.semanticImplementationSelections."one-enabled-component";
candidate = workflow.nativeRealizations."one-enabled-component";
```

For an authored portable unit, `component build` realizes the independent
compile receipt. `component status --development` reports the local
contract/source/evidence progress without pulling realization authority.
`component status` reports the strongest available checked implementation and
dependency state, and `component check` requires those machine-derived facts.
Draft units remain independently compilable; configurations remain authority
gated.

`component check --source --local-contracts` reports a detected local proof
counterexample as `violated`; a timeout or unsupported model remains
`incomplete`. A counterexample remains visible even if another local obligation
times out. Diagnostics identify the operation and proof kind. Local success
still grants no provider or connected-summary authority. For selected shared
services, text output names the contract and its identity; JSON also includes
its ABI and effect-contract digests under `local_contract.service_dependencies`.
These identify the selected premises, rather than establish compatibility or
independent runtime validation. The existing fixed-view shared-service model
does not yet admit allocation/release lifetimes or arbitrary dynamic views.

A manually configured `sourceCheck` can prepare an authored service-call boundary
using `sourceCallRegions = ./source-call-regions.json` in
`nix/component-source-check.nix`. The file is an array of the existing manual
source anchor records:

```json
[{
  "operation_id": "cleanup",
  "source": "cleanup.c",
  "entry": {"position": "before", "text": "      spx_view_v5 message = context->services->resource_text(context->services->context, 31U);\n"},
  "exits": {
    "next": {"position": "after", "text": "      spx_view_v5 message = context->services->resource_text(context->services->context, 31U);\n"}
  }
}]
```

`component check TARGET COMPONENT --source --json` exposes `source_call_regions`.
Each prepared projection binds the complete source/interface, inert marker
correspondence, compiled cut instructions, actual service arguments, context type
and live result local. Models, include inventories and compiler outputs are
retained in `source-call-region-models/`. Unsupported effects/control or stale
anchors produce `incomplete`. The current projection admits one unconditional
view-returning service call with uint32 constant arguments; general regions and
live-state transport require the wider cut engine.

For a graph of manual proof regions, the same constructor accepts
`sourceRegionGraphs = ./source-region-graphs.json`. Each array element uses the
same `operation_id`, `source`, `entry` and `exits` anchors, plus `regions`: a
nonempty list selecting which declared cuts start regions. The primary anchor
is named `entry`; the other cut names come from `exits`. Every selected region
is followed to the next declared cut or C return. Back edges between regions
are supported; an internal cycle produces a diagnostic requesting another cut.
For example, cuts around a cleanup loop, its copy branch, its cursor advance and
its tail can select `regions = [ "entry", "copy", "advance" ]`, leaving the tail
explicitly unselected.

`component check TARGET COMPONENT --source --json` exposes `source_region_graphs`.
Each graph reports edges, direct or computed call dependencies, referenced
storage, incoming edges into region interiors, uncovered scope and semantic
digests for individual regions. Compiler labels and constant routing immediately
before a cut belong to that cut, so joins do not invent overlapping ownership.
The digests retain typed operands and control flow while excluding absolute
instruction positions. A changed region can therefore preserve neighboring
region bindings. This does not itself reuse a correctness proof or establish
contract compatibility. Complete compiler inputs and inventories are retained
in `source-region-graph-models/`, and the feedback reader reconstructs the graph
from them without compiling or solving.

Graph preparation does not prove liveness, boundary-state transport, memory
contracts, progress or original/source equivalence. Calls remain unqualified
dependencies. Selected proof regions are not automatically authoring components
or replacement groups, and partial coverage cannot authorize activation.

A `sourceContractCheck` product can consume a prepared graph with
`nix/component-source-region-check.nix`. Supply `sourcePreparation`, `exactSlice`,
`contract`, and optionally `previous`; invoke it through
`component check TARGET COMPONENT --source --local-contracts --json`.
The entry contract `local-text-cleanup-entry-v1` is illustrated by
`tests/fixtures/metapad-cleanup-entry/local-contract.json`. It requires the real
function entry, checked length/allocation/byte-access expressions and a closed
prefix up to the loop cut. The comparison executes the actual short-input path,
checks allocation arguments and faults, and captures the complete scratch view,
cursor/count state, saved machine frame and eight refined loop-memory predicates.
Concrete length/allocation implementations and incoming lifetimes remain explicit
runtime premises. Other services or public context accesses report incomplete.

The iteration contract is `local-byte-compaction-step-v1`, illustrated by
`tests/fixtures/metapad-cleanup-iteration/local-contract.json`. It names selected
regions, entry/exit cuts and original RVAs, ordinary local cursor/count/view roles,
machine registers, private cells and clobbers. This is a conditional iteration
profile, not a general arbitrary-region theorem interface. Only byte-view access
calls are supported within the selected step. Early C returns must be the
UINT32_MAX fault outcome; other return values need a separate outcome contract
and are rejected before proof compilation. Other services need their own
checked composition contracts.

The same product accepts the terminal `local-text-cleanup-tail-v1` profile in
`tests/fixtures/metapad-cleanup-tail/contract.json`. Its manually selected cuts
must cover the complete terminal closure, including ordinary returns. Supply the
checked resource supplier separately:

```nix
sourcePreparation = sourceCheck.derivation;
exactSlice = retainedCleanupTail;
contract = ./cleanup-tail-contract.json;
dependencies.resource_text = resourceText.sourceContractCheck;
previous = previousCleanupTailCheck; # Omit for the first check.
solver = "cadical";
timeoutSeconds = 300;
```

The tail profile admits the supported byte accesses and copy, release,
resource-text, message and focus interactions. It checks the exact original call
edge, complete supplier reference and private frame, and compiled source effects.
Other service shapes, pointer aliases and unmodeled context reads report
incomplete. This profile still encodes a specific stack/view convention; it is
not a general boundary language for arbitrary services or heaps.

The consumer model omits both resource-supplier bodies. Its proof key binds the
complete checked supplier domain, while the output separately binds the current
implementation receipt. A requalified implementation with an equal domain can
reuse the consumer theorem; changing admission or dependency contracts requires
rechecking or reports an unsupported composition. Feedback exposes dependencies
under `local_contract.region_comparison.dependencies`. Host C callback type
checking precedes GOTO compilation, and its exact inputs are retained with the
proof. Conditional success does not qualify concrete runtime services or compose
the cleanup entry, loop and tail into a complete component.

`tests/fixtures/metapad-authored-call/cleanup-regions.json` defines one shared
manual graph for the complete ordinary cleanup operation. Place this object in
the array supplied as `sourceRegionGraphs`, then use that same preparation for
the entry, loop and tail products. The entry selects `entry` and `prefix_iter`
and exits at `loop`; the loop selects `loop`, `copy` and `advance` and exits at
`tail`; the tail selects `tail` and `tail_iteration`. Match these names in each
contract and select loop runtime revision 3. Proof markers and entry/exit observers
remain confined to comparison copies of the source.

Graph feedback reports `uncovered_reachable_instruction_count` separately from
`uncovered_instruction_count`. The latter also includes compiler records after
returns. Zero uncovered reachable instructions establishes structural coverage
under the graph's C-return convention; it does not establish lifetime, progress,
state compatibility or functional correctness. Even successful local proofs on
the same complete graph require checked composition before they establish the
complete component theorem.

For the supported cleanup profiles, `nix/component-source-composition-check.nix`
consumes `regions = { entry = ...; loop = ...; tail = ...; }` and optional
`previous`. Expose its derivation as the component's `sourceContractCheck` to use
`component check --source --local-contracts`. This phase imports complete current
regional evidence and extracts spatial assumptions from the actual proved models;
its own model contains no application or neighboring bodies. It compares existing
entry admission with the loop/tail requirements, then checks an explicit proposed
caller/allocator envelope and a nonempty-domain witness. `previous` can reuse these
queries after current regional receipts are revalidated and rebound.

The composition phase also checks private-byte transport. It lowers the actual
proved private read/write clauses to cell-layout tables, then uses a fixed recipe
to establish correspondence with one arbitrary byte-backed private object.
Individual stores preserve the relation and all other bytes; entry/loop/tail
transport preserves saved registers, the return word, count and partial-word
temporaries. The checker imports the fixed recipe and parses its retained tables
without regenerating the model. This is conditional representation transport,
not physical memory accessibility or object lifetime qualification.

Current public-memory transport is checked separately. The composition rule
instantiates the successor's incoming byte function with the predecessor's
current contents at every physical address. Both sides use that same function;
discarding write history does not discard its resulting bytes. At the tail cut,
the zero-suffix representation must equal those contents under the predecessor's
checked zero-suffix guarantee. The query checks arbitrary bytes, physical aliases
and all eight public-memory predicates. Exact regional guarantees, consumer
premises and the tail's byte reader are bound into the reusable proof key. This
rule neither reconstructs objects from pointers nor establishes their lifetime.

Live descriptor transport checks the six actual view accessors and the tail's
write guard against separate live opaque contexts. Public reference fields remain
exact. The complete owned source graph is also checked for scratch-grant issuance,
use and revocation, with all seven source regions covered. Normal returns require
revocation; fault returns retain their actual grant state. Neither check proves
physical allocation lifetime or deallocation success. Feedback includes four
named versioned runtime requirements for persistent borrow storage, hook frames,
non-retaining services and release outcomes, each explicitly unverified.

Feedback is under `local_contract.region_composition`. Additional requirements
distinguish caller stack/text/image separation from future allocator placement.
Selecting the proposed envelope does not establish these requirements for any
actual caller. The public result therefore remains `incomplete` (CLI exit 2), even
when its spatial, private-byte, current-memory and descriptor implications succeed. Physical
private-frame compatibility, descriptor lifetime, concrete services and complete operation composition remain
separate obligations. No extra production function or component boundary is added.

The comparison executes the actual ordinary C and exact original region under
an explicit current-memory relation, checks exit state and preserved registers,
whole public memory, and progress/invariant preservation on a repeated cut.
Compiled transport checks every selected source instruction and its automatic
state restoration; private observer code can assert but cannot mutate source
state. Partial source cuts are merged for the local comparison by erasing only
checked inert markers. Authoring components and production APIs stay unchanged.

`local_contract.region_comparison` reports the selected scope, named runtime
premises and proof reuse. The key binds selected typed region semantics, interface,
original bytes, contract, headers, tools and engine code. An outside-source edit
must undergo fresh source preparation; if selected semantics remain unchanged,
evidence import rechecks current compiled transport against the retained local
model without model generation, compilation or solving. This establishes reuse
of a proof region inside a component; it does not count that region as another
independently lifted authoring component. A successful comparison still reports
`whole_component_complete = false`, `runtime_compatibility = "unverified"` and
`activation_authorized = false`. Entry admission, remaining coverage, allocation
and lifetime premises, and runtime qualification require separate evidence.

**Preparation is not a functional proof.** A changed ID may prepare successfully
and still fail the separate original/source comparison. Feedback explicitly
reports `functional_correctness_checked = false` and no activation authority.
A `sourceContractCheck` product can consume that preparation using
`nix/component-source-call-check.nix`:

```nix
{
  sourcePreparation = sourceCheck.derivation;
  exactSlice = originalCallerSlice;
  supplier = checkedOriginalSupplier;
  contract = ./caller-contract.json;
  previous = previousCallerCheck; # null for a fresh comparison
}
```

The contract selects the prepared region, original entry/call/return RVAs,
service identity, private-stack span and live word inventory, and the returned
reference representation. See `tests/fixtures/metapad-call-comparison/contract.json`
for the retained Metapad example. Admission derives readable/writable image views,
clobbers and child stack requirements from the checked supplier, rejecting a
supplier whose private frame exceeds the caller's admitted storage. It does not
silently narrow the caller's original inputs to accommodate a new supplier.

`component check TARGET COMPONENT --source --local-contracts --json` reports
`local_contract.caller_comparison`, including region status, reuse counts,
supplier domain/receipt identities and the named runtime assumptions. A compatible
supplier implementation edit retains the exact caller proof without generating,
compiling or solving the consumer again. A changed contract requires rechecking;
an incompatible caller domain rejects before those steps. Preparation remains an
independent product shared by these cases. The current checker supports one
constant-argument, borrowed-image call region, with a checked normal cdecl
supplier. Successful regional proof leaves `whole_component_complete = false`,
`runtime_compatibility = "unverified"` and `activation_authorized = false`.
Surrounding reachability, coverage/progress, runtime compatibility and replacement
qualification require separate evidence.

The two complete-operation profiles `cleanup-save-paired-operation-v1` and
`cleanup-replace-paired-operation-v1` also accept an optional `native_memory`
inventory in `caller-contract.json`. They execute the original slice and ordinary
C through a common native-memory adapter. Omitting the inventory selects the
existing profile's compatibility default; an explicit inventory replaces that
default completely. The public JSON feedback shows the normalized inventory at
`local_contract.caller_comparison.native_memory`.

Each entry names an access, its typed address expression, byte width, permissions
and storage class. For example, one entry in the UI inventory is:

```json
{
  "id": "edit-window",
  "address": {
    "op": "const", "sort": {"kind": "bitvector", "width": 32},
    "args": [], "attributes": {"value": 4260184}
  },
  "width": 4, "read": true, "write": false, "storage": "public"
}
```

The implemented subset permits 1–32 entries, widths 1/2/4, unsigned typed address
arithmetic and explicitly bound entry-phase registers in the existing relation
IR. Arbitrary C predicates and unbound machine phases/selectors are rejected.
Public accesses use corresponding current physical bytes; overlapping public
views preserve aliases. Private slots must be initialized before reads or
continuation transport, lie within the enclosing boundary's private frame, and
be separate from public views and other slots. These are checked assertions,
not assumptions granted by writing `"storage": "private"`.

After a definition edit, run the same `component check --source --local-contracts`
command. Missing reads/writes produce `spx-caller-readable-frame` or
`spx-caller-writable-frame` failures in the actual original execution. A semantic
change invalidates the consumer proof; row reordering and an explicit spelling
of the same default preserve its key. A supplied `previous` product can reuse
the exact repaired proof. The original source preparation and neighboring
supplier evidence remain separate inputs.

Feedback also shows `native_calls` and `source_services`. These are derived from
the checked supplier, the compiled interface and the named runtime contracts;
they are not freely editable ABI guarantees in `caller-contract.json`. The shared
native dispatcher checks the real event identity, incoming stack, initialized
argument words and selected normal-return frame. Fault returns receive no normal
frame guarantees. Direct argument-slot lookup retains address and initialization
checks, with a general lookup when the address expression has a different shape.

The caller no longer pins the whole supplier contract to one known hash. After
replaying the checked supplier evidence, a closed compatibility reader normalizes
supported facts: typed entry predicates, selected normal-frame guarantees, native
view mappings, return/fault transport, and memory/observation correspondence.
Unrecognized legacy predicates or semantic forms fail before model generation.
Recognized prose markers identify the existing producer's implemented rule; they
are not independently accepted as proof. Runtime requirements remain named,
exactly bound and explicitly unverified. Changes to those premises conservatively
invalidate the consumer theorem; arbitrary semantic implication is not implemented.

Only requested normal-frame facts enter the local model. Withdrawing unused EDI
preservation can therefore retain save's theorem; UI still requires that fact.
Image views, private-frame bounds and excluded normal results come from normalized
supplier inputs. The entire consumed service value contract and types are checked,
including fixed native view extents; a matching C signature alone is insufficient.
The finite caller rule now checks supported stateless interface semantics directly; it does not select a caller by a target profile or interface hash.

The portable service adapters derive C signatures from the interface and use
typed scalar/view projections. They compare complete view descriptors and hooks
against independent snapshots before invoking the paired service. The common
operation adapter checks the source context, service table and view descriptors
after execution. A view address does not establish current contents, termination
or lifetime; those remain separate memory and service premises. Unsupported
service projections and stateful context transport fail explicitly.

The `finite-paired-caller-v1` contract supplies component/operation identity,
entry and owned RVAs, native memory, call sites, source service mappings, required
supplier facts, admission and continuation observations as data. Both real caller
fixtures use `caller-contract.json`; their production Python builders are retired.
The checker derives its proof entry, seals supplier return/outcome guarantees,
and validates declared ownership against the exact slice. Runtime import contracts
remain explicitly named and unverified. No field accepts an executable C predicate.

The target SDK accepts `callerCompositions.<componentId>` in `target.pe32Bundle`.
Each entry names `definition`, `exactSlice`, and `supplier`; optional `previous`
names earlier caller evidence for reuse. It supplies the existing
`component check TARGET COMPONENT --source --local-contracts` product and tracks
the definition as a target asset. The ordinary source-check product remains the
shared preparation dependency, so boundary/supplier edits do not rebuild it.
Unknown component IDs and unsupported combinations fail during evaluation.

For several checked live-object dependencies, replace the definition's
`service_id`/`required_frame` pair with a `suppliers` object, for example
`{"initialize":{"required_frame":["eax"]},"update":{"required_frame":["ebx"]}}`.
Supply `callerComposition.supplier = { initialize = constructorCheck;
update = setterCheck; };` in the SDK (a service-keyed path dictionary in the
Python entry point). The evidence and definition keys must match exactly. Each
checked supplier must match its actual original call target and complete value
interface; declared runtime premises cover only the other services. A supplier
cannot simultaneously have checked and assumed authority. Work-package inspection
and `component start` show every dependency and its requested frame.

Several entries in `native_calls` may use the same service `id`. Keep one entry
for that service in `source_services`, `boundary.services` and the supplier map;
set its `maximum_calls` and the total `call_capacity` to checked execution bounds.
Each native site still supplies its exact event, argument projection, incoming
stack transport and applicability obligations. Duplicate dispatch keys, missing
owned direct-call edges, different projected arities and wrong supplier targets
reject. The current live-object rule requires a common derived footprint and
typed view mapping across those sites. Call-scoped returned byte views have the
conditional rule below; allocation and longer lifetimes need further rules.
These bounds remain assertions, not admission filters.
Zero-argument services use an empty projected argument list. They retain result,
memory, event and ordering checks, and acquire no special termination authority.

An indirect external call uses `event.kind = "indirect"` and the original
zero `target_rva` placeholder. Its explicit unverified runtime premise supplies
`captured_target_projection`, using the existing 32-bit entry-register or
image-slot projection:

```json
{"kind":"static_slot","at":"entry","width":32,"rva":205284}
```

An entry-register projection snapshots that register at operation entry. An
image-slot projection defaults to reading the current slot at each call, as the
ordinary typed service adapter does. To preserve an original target captured
once, set `target_sampling: "operation_entry"` alongside the projection in the
runtime premise. Production external providers use the same optional field
alongside `target_projection`. Explicit `"service_call"` retains the default.
The generated operation context stores the entry value and read fault separately
for each service and invocation. Later calls use that capture; nested invocations
have separate storage. A capture fault remains a fault even if memory later
becomes readable. A null capture remains invalid even if the slot later changes.
The native checker requires every actual indirect target to match the selected
sampling rule and checks slot readability, range and private-frame separation.
The paired trace additionally compares the actual code target at every call
position. Current-slot sampling must prove that a previously saved original target
still matches the current slot. Entry sampling permits later slot mutation while
checking the actual original target at each call. Declaring a slot does not
assume its immutability. Author the projection and sampling only in the runtime
premise; native-call and boundary guarantees are derived and reject overrides.
Both fields are bound into compatibility and reuse evidence. Resumed contextual
proof regions currently reject operation-entry sampling until a checked transport
rule carries the capture across the cut; they must not resample at a cut. Splitting
properties of a complete finite caller retains its complete entry execution.

These checks transport code targets. They do not identify a DLL export, authorize
an import, or establish a returned object's contents or lifetime. Changing the
projection invalidates the caller proof. Register/slot public fixtures verify
body absence, exact receipt reuse and rejection of malformed or changed targets.
The retained Hello checks exercise the real prologue/first errno call and the
second call with an explicit incoming invariant; intervening state transport and
the complete quoting operation remain open.

An explicit runtime premise can return a nonnull fixed byte view using
`returned_view = { contents = "current-memory"; lifetime = "until-next-call";
private_frame = "disjoint"; };`. The service signature supplies the extent and
permissions. Every actual invocation chooses its own address. Accesses use the
existing current-byte world, so equal or overlapping returned ranges share bytes;
no fresh contents or stable result address are assumed. The returned grant ends
at the next service invocation. A saved source view used after that point fails
the lifetime assertion. Its reference identifies a span, not an allocation or a
new heap generation. Escaping views, nullable/dynamic extents, allocation and
lifetime across calls remain unsupported by this rule.

Optional `separate_from` entries contain typed `address` and `extent` relations.
They are explicit runtime assumptions, not inferred from a read-only parameter or
an import-slot declaration. The checker proves the result domain has an available
nonnull span before assuming a result in it; contradictory exclusions cannot
make the proof vacuous. This matters for Hello: an unrestricted errno range can
overlap the import slot, changing its current target when the caller writes zero.
An explicit separation premise requires actual runtime evidence before native
use. Operation-entry target capture avoids needing that premise merely to preserve
a previously loaded target. `status` remains `unverified`; authoring a returned-view declaration
does not supply that evidence.

The same public caller check accepts void operations and `suppliers = {}` when
every dependency has an explicit runtime premise. Complete original ownership,
entry/return observations and scope checks still run without a checked supplier.
An empty runtime `objects` list means no readable or writable public-byte effects
under that premise. It does not prove the implementation has that frame.

Compatibility and invalidation consume each supplier's checked facts separately
from implementation receipts. A compatible edit to one supplier reuses the whole
caller proof after validating current evidence for all suppliers. Changed
initialization or other consumed guarantees require rechecking. The implemented
network rule composes live-object suppliers with normal returns and the checked
terminal-service outcomes described below. Termination premises remain visible
in each consumed supplier contract. Lifetime transitions and other supplier
families require further composition rules. This remains conditional local
assurance without activation.

Complete finite caller checks can also supply another caller's `suppliers` map.
The reader replays `caller-comparison/result.json` and derives the implemented
normal-return scalar composition rule. It preserves the original identity,
memory effects, entry requirements, register frame and transitive runtime
premises. Each entry requirement is checked at the actual native call. An
ordinary C body can change without invalidating neighbors when those consumed
facts stay equal and the new implementation's proof passes.

A supplier requirement can additionally contain `bindings`, mapping each of the
supplier boundary's universally quantified values to an existing typed relation
expression. This allows, for example, a protected memory interval to include a
caller's live storage without adding artificial parameters to the C API. The
callee must be proved for all admitted bindings; every call must establish its
admission. Choosing a protected interval does not prove that the actual runtime
respects it. That premise remains visible and unverified until native admission.

The current exported caller rule supports scalar arguments and void/scalar normal
returns. Derived footprints can depend on actual call arguments, with current
readable-byte and alias checks at each invocation. Exporting such a caller again
requires an enclosing footprint independent of those internal call arguments;
the reader diagnoses the missing checked envelope. Persistent views, lifecycle
changes, terminal outcomes and richer state transport need their applicable
checked rules. These limits do not change the existing live-object supplier rule.

For a local object operation with an explicit terminating service, the same SDK
source-check product accepts the conditional premise and exact original events:

```nix
sdk.lifting.sourceCheck {
  inherit namePrefix targetId componentId interfacePackage sourcePackage;
  localContracts = true;
  terminalServices = ./terminal-services.json;
  originalComparison = {
    inherit exactSlice bindingIntent machineDomain;
    serviceBindings = ./service-bindings.json;
  };
  localContractUnwind = 64;
  localContractTimeoutSeconds = 60;
}
```

The restricted rule requires zero-argument void terminal services and explicit
unverified runtime premises; a void signature alone supplies no termination fact.
The original comparison uses the supplied exact import events. The SDK's bound
SMT solver also enables complete source-dependence and object-comparison
partitions. Inspect all blockers and retained evidence: the timeout is a limit
per query, not a successful bounded result. Source frame, language safety and
progress remain required. The real Hello constructor passes this checker and
now supplies the complete `_quotearg_n_style_colon` caller alongside the independently
checked character setter. `callerComposition.supplier` supplies both evidence
packages; the checker derives their outcomes and footprints. Do not add terminal
or initialization guarantees to the authored caller definition. Initialization
spans and native register/stack guarantees apply only on normal return. A terminal
call checks the complete paired prefix, original nonlocal exit, public memory and
the live source context before stopping. A void signature alone never stops a call.

The retained real SDK workflow is under
`build/hello-quoting-state-2026-09-21/initialization-composition/terminal-caller-network/`.
Its compatible setter edit reuses the caller without model/compiler/solver work.
The following `_quotearg_n_options` service and CRT termination environment remain
explicitly unverified; this complete conditional result grants no native admission.

Retained-input consumers can use the same public SDK directly:

```nix
sdk.lifting.sourceCheck {
  inherit namePrefix targetId componentId interfacePackage sourcePackage;
  localContracts = true;
  callerComposition = {
    definition = ./caller-contract.json;
    inherit exactSlice supplier;
    # previous = earlierCallerCheck;
  };
  localContractTimeoutSeconds = 60;
}
```

Preparation is automatic; no caller-specific Python or Nix phase is needed.
The definition still needs to be authored explicitly. Bundle configuration also
passes it into the existing V6 work package. `boundary inspect` shows its declared
scope, requested supplier facts and unverified runtime assumptions; `--json`
includes the complete definition under `requirements.caller_definition`.
`component start --output DIR` copies `caller-contract.json` beside the C skeleton
and records the dependencies in its editing plan. Materialization validates the
package/file hashes and the definition's association with owned units, operation
and services. This checks editing inputs, not the definition's semantic correctness.
`sdk.lifting.workPackage` exposes the same builder with optional `callerDefinition`.
For a retained exact slice, it can derive ownership bookkeeping from the definition
and linked plan without a handwritten native binding:

```nix
sdk.lifting.workPackage {
  inherit namePrefix componentId interfacePackage sourcePackage linkedSemanticModule;
  inherit exactSlice;
  callerDefinition = ./caller-contract.json;
}
```

Use `sdk.lifting.interface` and `sdk.lifting.sourcePackage` to prepare its interface
and ordinary C. The source checker accepts canonical `components/ID.c` paths.
The exact-slice inventory, plan binding and file bytes are checked. Derived unit,
transfer and entry associations remain explicitly incomplete: the package reports
`caller_definition_requires_local_check` and does not invent native parameter or
exit projections. The existing explicit `bindingIntent`/`behavioralCPackage` route
is also supported.

For a configured component, `boundary propose TARGET component:ID --output DIR`
materializes the same writable package. After editing its `caller-contract.json`,
use `boundary adopt TARGET component:ID --input DIR --output FILE` to export the
declaration to the configured definition file. Adoption checks the editing baseline
against the current package and preserves the destination if scope checks fail.
It neither checks semantic compatibility nor authorizes activation; run the local
caller check afterward. The real save/UI work-package experiment exercises this
route through public SDK functions and commands: wrong C and boundary edits fail,
repairs pass, and compatible supplier changes reuse neighboring proofs without
consumer model/compiler/solver work. Runtime evidence loading still incurs cost.
The common checker also consumes validated borrowed-image suppliers. Declare all
supplier state views with the existing `supplier_view` references; their physical
bindings and the service result alias are derived from the checked transition.
A view-valued caller operation declares `boundary.result_view` naming the existing
operation view that its result must equal. The checker asserts the complete result
descriptor and backing-storage correspondence; it does not reconstruct contents
from a pointer. Only whole fixed-extent returned views are supported by this rule.

At actual calls, the supplier's private writes and return word must be separate
from every initialized caller continuation slot and public view. Initialization
comes from actual native writes. An unwritten slot can overlap a callee frame and
be used by a later caller write; reading it before that write fails. Exit relations can
observe a private slot with the typed logical parameter `private.<slot-id>`; reading
an uninitialized slot fails. These observations use current private storage, not
the public-byte function. The ID-31 resource prefix exercises a real view return
and transport of the pending caption, flags and argument through the public SDK
and CLI, including wrong-edit rejection and neighbor proof reuse.
Its extended two-transfer fixture also passes the returned view to MessageBoxA
after reading the current window. The import retains named, unverified runtime
and string-termination requirements.

Runtime service requirements and image lifetime assumptions remain explicit and
unverified. Neither this rule nor a matching signature supplies NUL termination,
allocation or lifetime-change guarantees. The reserved ID-97 error notice was
added after freezing the production rule, using only an interface, boundary
definition, actual original slice and ordinary C. Its public source and work-package
checks reject wrong edits and reuse proofs after repair or compatible supplier
changes. Refining its caption view from 1 to 500 bytes requires a new proof despite
unchanged C signature types. See the
[acceptance audit](baselines/2026-09-15-reusable-caller-composition.md) for evidence
and the retained runtime and activation limits.
Conditional supplier admission remains under the existing operation
guards. Neither an inventory nor its local proof establishes concrete memory
lifetime, surrounding reachability or activation authority.

The shared outer caller engine now consumes the typed `boundary` shown in public
feedback: incoming values, guarded admission, physical view bindings, service
ordering and bounds, exit partitions, and continuation observations. There are no separate save/UI model renderers or profile dispatch branches. The engine still executes the exact original slice and authored
C. A separate entry-witness query must establish that the admitted domain is
nonempty, and the correctness query must pass every property. Empty admission
stops checking before the full caller query; missing or overlapping exits fail
`spx-boundary-outcome-partition`. Neither test establishes caller reachability.

Definitions can reference a checked supplier image view with
`{"id": "caption", "supplier_view": "caption"}`. The checker derives its address
and extent from current facts. A `supplier_admission` block binds the supplier's
entry parameters and an optional typed guard, then expands its checked predicates
using the existing relation IR. It avoids copying those predicates into every
caller. Neither reference grants a guarantee: mandatory native call assertions
recheck all supplier premises against the current call frame and current memory,
including private-input exclusion and private-output containment. Removing the
admission block cannot silently remove those assertions. Fixed portable view
extents are also checked against the instantiated views.

View correspondence includes the backing context's runtime pointer, physical
address, extent and permissions, the access runtime's hooks and domain pointer,
and that domain's world, address, extent and permissions. These are checked before
abstract service calls and at the source exit, against separate snapshots. Merely
retaining the view's descriptor and function pointers does not preserve the
mapping to current memory. A changed mapping fails `spx-source-view-storage`.

A manually configured `sourceContractCheck` product can additionally compare a
complete fixed-image shared-service leaf with its original Behavioral-C. The
existing `nix/component-source-check.nix` constructor accepts:

```nix
originalComparison = {
  exactSlice = exactCPackage;
  bindingIntent = ./binding.json;
  machineDomain = ./machine-domain.json;
};
```

This requires `localContracts = true`, an explicit `sharedContract` with selected
service bindings, and no component dependencies yet. The domain file declares
the image base/size, admitted private stack accesses/writes and register clobbers.
The checker validates source profile and compiled opacity evidence, links the
same authored GOTO object into the paired model, and checks the exact original
files and compiler inputs. It does not recompile authored C under different proof
headers. The existing public command remains
`component check TARGET COMPONENT --source --local-contracts`.

JSON feedback includes `local_contract.original_comparison`; detailed models,
input bindings and raw query evidence live under `original-comparison/` in the
product. Functional differences are `violated`; stale or unsupported inputs and
timeouts are `incomplete`. A passing comparison is conditional on its named
borrowed-image runtime contract and reports runtime compatibility as unverified.
Successful feedback also exposes `transition_domain_sha256`, after independently
reading the retained source/original evidence. This identifies the consumed
behavior/interface/runtime domain separately from the implementation receipt.
A changed signature is not its only invalidation trigger: private frames,
service assumptions and original behavior identity also matter. This domain is
an input to conditional caller experiments; public source-bound caller composition
is not implemented yet.
It cannot authorize a provider, qualified connected summary or activation. The ordinary
resource-text service profile proves alias/effect equivalence without a NUL
output premise; a caller requiring a string must discharge that invariant
separately. This is currently a leaf capability, not transitive composition.

An internal experimental world lowering implements the named
`issued-reference-access` runtime contract, revision 2. It derives the origin
capacity and native allocation-class guards from checked inputs, requires
interior-pointer support in every authority rule, and checks issued metadata,
current lifetime, permissions, offset arithmetic and null policy on access.
It omits native re-realization while retaining resolution, origin issuance,
memory and allocation transitions. Its generated C requires a contract-digest
compilation marker supplied by explicitly conditional obligation execution.
The existing evidence cache binds that selection; strong readers reject the
result and any extracted conditional frame certificate.

The independently selectable `allocation-byte-projection:2` generator takes one
allocation snapshot per byte lookup and preserves the original ordering of
private writes, public writes and shadow bytes. It retains separate history
floors, imported current contents, fresh initialization and call/summary oracle
identities. With this selection alone, the existing native reference resolver
remains active. With both selections, each generated lowering requires its own
contract-digest compilation marker. Generation rejects unknown or mismatched
contracts even though the generic evidence cache can retain externally authored
conditional identities.

The independently selectable `world-reference-summary:2` generator implements
checked PE32 image/allocation namespace lookup and context validation. Its native
comparison checks cover bounded layouts, status, aliases, extent, permissions,
lifetime, failure outputs and unchanged world contents. These checks do not
establish universal platform correctness. Revision-1 regional evidence does not
prove the combined revision-2 model.

For a configured `conditionalCheck` product, `component check TARGET ID
--conditional [--json]` runs contextual checking under the exact selected runtime
contracts. It reports `complete`, `incomplete` or `violated`, names the contract
revisions and digests, and explicitly grants no activation authority. The option
is exclusive with `--source` and `--local-contracts`. Targets without a configured
product report that absence instead of silently changing proof modes.

Configure the existing `sdk.candidate.portableCWorkPackageProviderV2` builder
with its ordinary component inputs plus `runtimeAssurance` (an implemented
selection) and `conditionalTargetId`. Publish its `derivation` as the unit's
`conditionalCheck` product in the operator target and index. The builder exposes
`conditionalEngineResult` and `engineDerivation` for inspection. The proof phase
retains exact inputs and assurance; a separate operator phase renders feedback.
Changing presentation therefore does not require rebuilding the proof phase.
The conditional exit emits no provider qualification, object manifest or
replacement choices. It does not perform native linking or discharge all
portability obligations. Existing supplier admission still applies during
preparation; conditional checking does not admit stale neighboring receipts.
Unchanged whole-engine outputs can be reused by Nix. To reuse completed queries
while checking again, pass the earlier `engineDerivation` directory through
`previousQueryEvidence`; the feedback derivation does not carry query outputs.
Conditional packets remain separate from ordinary contextual-refinement receipts.
The importer checks the packet, model/obligation correspondence and exact runtime
selection. Each query hit additionally requires identical compiled bytes, tools,
arguments and retained output, reparsed by the current checker. Changed contracts
invalidate reuse; missing queries run again and cached counterexamples remain
counterexamples. An ordinary proof cannot import a conditional packet.
The current source include path is part of compiled-model identity, so moving an
otherwise identical source package may invalidate reuse. Reusing a query is not
admitting its packet as a checked supplier summary; that composition remains
unimplemented. Presentation reuse must not be reported as neighboring-proof reuse.
JSON feedback exposes auxiliary checks under `details.composition_facts`; text
feedback lists the unavailable ones. `complete` means the ordinary contextual
obligations passed under the named runtime contracts. It does not imply that
every optional wider-entry or frame candidate passed. Each caller must still
establish the facts required by its selected composition rule. An unresolved
auxiliary query may rerun after an exact repair even when all ordinary queries
reuse, so inspect these results when diagnosing edit latency.
The fixed-view source check and whole-component qualification retain their
existing meanings.

For a configured unit that has no source yet, `component start` is the only
public source transition. `--output DIR` hash-checks the V6 package, its semantic
slice, generated files, and faithful-C excerpts before copying the whole package
into a writable directory. `--apply` is deliberately narrower: it accepts only
a writable local target, requires `target.json` to declare
`paths.component_sources`, refuses existing source, rewrites the package-local
header include to the canonical V5 implementation header, and updates the
existing `component-lifting-intent-v1` source row and digest. A process lock,
same-filesystem staging, preflight checks, and rollback make the two-file
application an atomic command-level transaction. Component seeds remain
non-authorizing proposals until an operator authors their canonical interface,
binding, and lifting-intent row; the retired component-adoption receipt is not
produced.

Each indexed candidate configuration fixes its mode. Hybrid configurations
allow checked fallback; portable configurations require wholly portable
ownership throughout the checked root-reachable projection. `candidate build`
consumes that configuration's checked selection and the target's static release
gate. There is no separate public candidate-check product or mode override;
diagnostic dependency reports cannot make a candidate executable.

`candidate status` keeps those two questions separate. `exact-selection`
reports whether every required definition and obligation has one checked
provider. The accompanying definition/obligation coverage counts selected
`qualified_portable_c`, `generated_behavioral_c`, `qualified_runtime`,
`external_environment`, and `pinned_binary` providers and reports portable
progress independently. Thus an exact Behavioral-C-backed selection is complete
without being mislabeled as decompilation progress.

Pure component qualification depends only on its selected machine-IR units and
checked component artifacts. A component that declares an external-site service
also depends on the canonical target/ABI evidence for that site. Neither path
depends on root-scoped target ISA qualification or final candidate acceptance; those
remain release-level gates.

`runtime` above is exactly the runtime package consumed by the default-compiler
candidate. Building it does not pull an executable candidate into its closure.
`workflow.components.v6SemanticSlices`,
`workflow.components.v6WorkPackages`,
`workflow.semanticImplementationSelections`, and
`workflow.nativeRealizations` provide the corresponding
configuration-indexed families. The operator-facing interface
also exposes independently cached work packages, status reports, and checks for
every leaf or group, plus runtime/status/check products for each configuration.

Adding a target should not require generic Python or Nix changes. A reusable
capability gap must be implemented in the toolkit and covered by a small
target-independent fixture before a validation target relies on it.

## Library Islands

`library status` and `library inspect` discover ABI-compatible whole-library
islands. `library adopt --island ... --recipe ...` writes a content-bound V1
adoption intent for an available reusable behavior pack; `--draft` records an
operator recipe that still needs static qualification. Discovery, adoption,
checked-island authority, and generated component construction are separate
content-addressed phases.

An adopted island becomes executable only when the canonical checker closes
identity, every crossing boundary, and the selected implementation, then emits
a complete generated ordinary component. The component runtime consumes that
package through the same ownership, adapter, semantic-contract, and compilation
path as an operator-authored component. Unselected or incomplete islands do not
block the target and retain machine-IR fallback ownership.

Automatic generated-component materialization currently covers stateless,
nonvariadic scalar ABIs with register or stack arguments and scalar results.
Stateful services, variadic calls, hidden return storage, out-parameters, and
externally visible effects fail closed until the behavior pack supplies an
explicit checked machine-to-portable mapping template.

### Reusable C service authoring

`components.service_authoring.ServiceDefinition.create` defines a service's
signature, canonical lifecycle roles, declared effects, outcomes and synchronous
call protocol once. It produces existing `BoundarySchemaV1`, `BoundaryLifecycleV1`
and `InteractionContractV1` values; `service_catalog` returns the existing
interaction catalog. `component_interface` selects these definitions into a
single operation or a named group with shared context state. Richer protocols,
projections and operation lifecycle bindings still use the full V5 API.
The contract digest appears in the interface binding: a changed effect,
resource role or outcome is a contract change even with an unchanged C signature.
Unreferenced library types are excluded from the service schema's dependencies.

For whole-value resource roles, name the consumed/borrowed parameters and whether
the result is produced. `service_resource_roles` prepares the same explicit
`resources` list; the service's existing lifecycle validator still checks it:

```python
from spaghetti_extractor.components.service_authoring import service_resource_roles

parameters = [("key", "jv_value"), ("owner", "jv_value"), ("index", "i32")]
roles = service_resource_roles(
    parameters, borrows=["key"], consumes=["owner"], produces=True,
    resource_kind="jq-reference", provider_domain="libjq",
)
# ServiceDefinition.create(..., parameters=parameters, result="jv_value",
#                          resources=roles, ...)
```

Roles follow parameter order, then the result, preserving the role IDs and
contract identity of equivalent full declarations. `borrows` means
`borrow_shared`; unlisted parameters receive no resource role. The helper does
not infer ownership from C types or enforce exclusive access. Keep the full
`resources` list for nested fields, mutable borrows or different resource
classifications. Live-memory transport and service semantics remain explicit C
adapter responsibilities. The jq [object lookup](../tests/fixtures/jq-object-get/prepare.py)
and [path service library](../tests/fixtures/jq-path-network/services.py) use this
form; the latter retains its nested result-field declaration alongside it.

For a boundary owning several entry points, pass `operations` instead of the
single `parameters`/`result` signature. The same C context can hold their shared
state; callers and adapters determine that context's lifetime. For example:

```python
from spaghetti_extractor.components.service_authoring import (
    OperationDefinition, component_interface, value,
)

boundary = component_interface(
    component_id="counter",
    types=[{"id": "u32", "kind": "integer", "signed": False, "width_bits": 32},
           {"id": "unit", "kind": "void"}],
    services={},
    operations={
        "add": OperationDefinition(parameters=[("amount", "u32")], result="u32"),
        "read": OperationDefinition(parameters=[], result="u32"),
        "reset": OperationDefinition(parameters=[], result="unit"),
    },
    state=[{"value": value("total", "u32"), "initial": None}],
)
# prepare_comparison_package(..., interface_package=boundary,
#     operation_symbols={"add": "counter_add", "read": "counter_read",
#                        "reset": "counter_reset"}, ...)
```

The C adapter initializes `context.state.total` and preserves the context between
related calls; `initial=None` supplies no initial-value assertion. The helper
derives the existing signatures and identity projections. Each named operation
defaults to no services: select its permitted local names explicitly with
`allowed_services=["allocate", "allocation_failed"]`. Nullability uses that
operation's `nullable_parameters` and `nullable_result` fields. Services retain
their complete existing schemas and contracts. Invalid service selections and a
mixture of named entries with the single-entry signature are rejected.

This convenience form uses the existing synchronous `ready` protocol, with no
inferred operation lifecycle, effects or memory invariants. More elaborate
protocols/projections/lifecycle declarations use `ComponentInterfaceIntentV1`.
State values use the same explicit `value`/`initial` declarations as that full API.
Private helpers remain ordinary C; naming several entries neither creates
separate components nor establishes their machine-code coverage.
The [Hello allocation declaration](../tests/fixtures/hello-checked-allocation/declarations.py)
uses this form for eight entries sharing one private failure helper. It retains
the earlier interface identity and generated C exactly. Its optional `schema_id`
preserves a previously authored schema name during migration; new boundaries
normally use the generated default.

To establish another boundary around existing services, reuse declarations from
a workspace instead of importing the Python recipe that originally authored them:

Use `component list TARGET --comparison-package WORK --services` to find them, or
add `--service QUERY` for matching signatures, lifecycle/effect declarations and C
adapter locations. The [discovery workflow](component-workflow.md) explains exact
contract grouping and the explicit review of adapter/transport inputs. `--json`
provides the full matched contracts and component context for a preparation script.

```python
from pathlib import Path
from spaghetti_extractor.components.comparison_package import load_comparison_package
from spaghetti_extractor.components.service_authoring import (
    component_interface, service_catalog, services_from_interface,
)

plan, existing = load_comparison_package(Path("build/string-workspace"))
services = services_from_interface(existing, plan["service_catalog"],
                                  names=["contents", "release"])
types = [t.to_payload() for t in existing.schema.types if t.kind != "function"]
boundary = component_interface(component_id="string-length", types=types,
    parameters=[("value", "jv_value")], result="i32", services=services)
# Pass boundary and service_catalog(services).to_payload() to
# prepare_comparison_package with this operation's C, adapters and cases.
```

Selection uses local service names and preserves the full bound declarations:
types, nullability, lifecycle, effects, outcomes, protocol and unobserved behavior.
A changed contract cannot substitute merely because its signature matches.
Adapters, live-object transport, the new operation's lifecycle and test coverage
are explicit inputs to the new boundary; selecting declarations does not inherit
another component's evidence. The helper uses the same catalog reader as generated
C bridges. It also accepts an interface and catalog from a source export, without
requiring the original native tools or preparation script.

For direct selection from an exported library, use
`candidate.source_export_bindings.services_from_source_export(project,
names={"LOCAL_NAME": "COMPONENT/SERVICE", ...})`. It reads the exported interfaces
and catalogs, permits separately reported C drafts and checks shared declarations.
`component list TARGET --source-project DIR --service QUERY` locates the services
and their boundary guides. Recorded comparison adapters remain examples; neither
command chooses current backend bindings or carries comparison evidence. See the
[source-library workflow](component-workflow.md#establish-your-own-boundary).

Services with no value parameters or result use `parameters=[]`, `result='unit'`:
their C signature is `void(void)`. Their interaction contract has empty type and
port lists while retaining its declared effects, outcomes and exact binding.
No dummy argument is required for a terminal callback or other effect-only call.
Unknown port references and type bindings still reject, and nonlocal delivery
still requires an observed handler scope. The
[Hello allocation family](../tests/fixtures/hello-checked-allocation/README.md)
uses this for allocation failure without exposing its private shared tail as an API.

`nullable_parameters=['old_block']` and `nullable_result=True` explicitly admit
optional opaque C objects in `ServiceDefinition.create` and `component_interface`.
Both default to nonnull. The component constructor preserves the selected service
values exactly; changing nullability changes the contract binding without changing
the C pointer ABI. Invalid names, duplicate declarations and nullable scalar/void
values are rejected. These declarations do not establish pointee contents or
lifetime. The [Hello growth example](../tests/fixtures/hello-allocation-growth/README.md)
uses a nullable old allocation, a nonnull count cell and a nonnull normal result.

The [native Hello consumer recipe](../tests/fixtures/hello-native-quoting/README.md)
reuses that source and bridge with actual lower services and native callers.
It demonstrates public editing, discrepancy replay and experimental integration
without another proof rule or component body. Its PE32 C adapter supplies the
reviewed ABI/layout and live native objects; this remains an explicit runtime
dependency. The same local interface does not turn a controlled host comparison
into a native or whole-program proof.

The [complete Hello quoting engine](../tests/fixtures/hello-quote-engine/README.md)
extends this pattern to a substantial loop with live input/output and mask aliases,
recursive restyling, truncation and locale conversion. Its ordinary C uses eight
explicit synchronous services and call-scoped byte proxies. Actual native callers
execute it with the original algorithm body trapped. A local engine edit leaves
the controlled caller comparison reusable while the native integration reruns.
These are tested boundaries with documented extent/lifetime premises, not checked
memory summaries. The example also records the remaining native services and the
observed locale widths, rather than inferring semantics from a locale's name.

The [stateful conversion family](../tests/fixtures/hello-multibyte/README.md)
composes beneath that engine using the same dependency graph. Four operations
share reviewed live state and byte proxies; two implicit conversion cells become
distinct context fields. Output/state/input aliases preserve identity and access
order, including a write before actual abort. Local comparisons and both real
consumer levels expose a state-only defect even when character results agree.
The lower CRT remains an explicit service. Native C/Japanese contexts and a
controlled UTF-8 context remain distinct, as do executable adapters and checked
memory summaries. This is a reusable author/edit/replay pattern with manual ABI
work, not a claim of arbitrary host conversion-state or startup compatibility.

`prepare_comparison_package` accepts `service_catalog` and `service_bridge`.
For initial dependency selection, the public
`comparison_composition.bind_dependencies` helper returns its existing
`dependencies` and `requirements` arguments together:

```python
from spaghetti_extractor.components.comparison_composition import bind_dependencies

bindings = bind_dependencies(
    services={"grow_slots": growth_package, "release_buffer": free_package},
    consumers={"render_after_update": rendering_package},
)
# Pass **bindings alongside the other prepare_comparison_package arguments.
```

Service keys name the caller's interface services. Consumer keys name reviewed
integration requirements that are not services of that interface. Package paths
supply component identities and complete contract bindings, including assumptions,
input domains, resource/service declarations and representation bytes. The helper
uses existing readers and adds no artifact or composition rule. Repeated uses of
one package share its selected unit; conflicting paths for one component identity
or duplicate requirement names reject. The caller still chooses exported C
adapters and their executable meanings through the existing package API.

To bind a supplier already selected in a network, use the same `{id, package}`
selection accepted by preparation:

```python
network = Path("build/graphics-work")
state = {"id": "graphics-state", "package": network}
bindings = bind_dependencies(
    services={"reset": state, "bind": state},
    consumers={"blit": {"id": "graphics-blit", "package": network}},
)
```

Both services share one selected state implementation. The helper reads the named
unit's current contract; preparation imports its declared supplier closure and
selected adapters without the network's unrelated callers or driver. An optional
`adapters` mapping chooses explicit C bridges through the existing preparation
API. Conflicting paths or adapter choices for one component require a consistent
selection. No standalone supplier folder or manual contract hash is needed.

This is a setup/refinement action, not a compatibility test. Keep the resulting
requirements frozen while editing implementations; use `--dependency-package`
for a replacement. A changed contract then rejects even when its C signature is
unchanged. Regenerating requirements is an explicit contract refinement and can
invalidate consumer evidence. Internal recursion continues to require its explicit
declaration and unproved-progress status; the helper does not infer it.

The bridge specification has three fields:

- `adapters`: selected service names mapped to `symbol`, `kind` (`native` or
  `portable`), and `outcomes` (declared outcome names to C predicate symbols).
  A sole unconditional outcome uses `null`. Optional `context: true` passes the
  service context as the adapter's first argument. Optional `declare: true` emits
  an `extern` function prototype before the wrapper, using the selected native
  transport types (or portable types for `kind: portable`) and context argument.
  Use it for a separately defined adapter or supplier entry. Include its type
  declarations first; macros and custom calling conventions keep explicit C
  declarations instead. The generated prototype does not check an external
  implementation's ABI or semantics.
- `transports`: boundary type IDs mapped to `native_type`, `take`, `borrow` and
  `pack` C names. Declared whole-value consume/borrow/produce roles select the
  conversion mechanically. Integer and binary32/binary64 scalars pass directly.
- `native_symbol`: the operation entry generated around the authored `run`, or
  `None` in Python (`null` in JSON) for operator-owned C entries.

The Nix SDK exposes the same inputs as `serviceCatalog` and `serviceBridge` on
`sdk.lifting.comparisonPackage`. Packages generate `comparison-service-bridge.h`
and `service-coverage.json` beside their existing C declarations. A small C
translation unit includes target adapter declarations followed by the generated
bridge. Shared code generates wrappers, service-table wiring, entry transport,
resource frame hooks, outcome partition checks and call/return observations.
The [jq service definitions](../tests/fixtures/jq-path-network/services.py) and
[native conversion helpers](../tests/fixtures/jq-path-network/native-services.h)
show the complete current consumer.

Grouped or stateful components use the manual-entry form. It generates service
wrappers and three C helpers in the same `comparison-service-bridge.h`:

- `spx_COMPONENT_bind_services(void *context)` returns the populated service table
  and forwards the supplied adapter context. Replace `COMPONENT` with the component's
  C identifier, for example `checked_allocation`.
- `spx_COMPONENT_services_begin()` and `spx_COMPONENT_services_end()` emit the
  bound catalog's service-scope observations around the operator's entry calls.

The operator's C initializes and retains the component context, performs entry
dispatch, transports arguments/results, and calls those scope helpers. The
generator does not reset shared state or guess context lifetime. Existing nonlocal
handler observations still close unwound service scopes; returning paths call the
end helper. Declared operation resource frames, if used with manual entries, remain
adapter-owned and subject to the existing resource checks. Generated coverage
names these responsibilities. Automatic entry generation still requires the
stateless single `run` form and explains the manual-entry alternative on rejection.

The [Hello allocation adapter](../tests/fixtures/hello-checked-allocation/bridge.c)
uses these helpers around eight entries and its existing allocation-failure
handler. Its preparation recipe now passes the normal `service_bridge` declaration
instead of generating a separate header and manually formatting trace records.
The same specification works with `render_source_service_bridges` on an exported
source project. `retained_service_inputs(..., native_symbol=None, ...)` selects
reviewed services for another manually entered component without inventing a
wrapper function. A generated table supplies neither object transport nor the
meaning of platform services; those remain reviewed C adapters and observations.

The checker validates nested service scopes, selected contract identities,
call/return ordering and declared outcomes from retained stderr. Missing,
malformed, unbound or unfinished traces leave applicability incomplete. A selected
entry need not execute in every composed case; zero calls are shown in coverage.
Generated predicates must select exactly one outcome on return. Predicate semantics
and native effects remain adapter-owned assumptions, checked only by the evidence
actually supplied. Service checks join resource applicability without changing
behavioral observations; retained traces are rechecked before reuse or experimental
admission. Experimental policy explicitly accepts each selected service catalog
via `accepted_service_catalogs` (component ID to catalog digest).

Current automatic authoring supports integer and binary32/binary64 scalars,
records, nominal opaque C object pointers, synchronous returns and the explicit
nonlocal adapter protocol below. Opaque types
retain their exact nominal schema identity; the generator does not grant pointee
contents, aliases, extent or lifetime. These remain explicit C adapter obligations
in `service-coverage.json`, independent of formal-rule availability. A service-free
operation can use the generated entry bridge without an empty or fictitious catalog.
The [jq array storage fixture](../tests/fixtures/jq-array-storage/README.md) exercises
shared objects and real allocation through these adapters.
The [DX-Ball graphics fixture](../tests/fixtures/dxball-graphics-network/README.md)
transports real sprite objects and aliases through an opaque state parameter,
then checks initialization through an actual blit consumer. C adapters and
observations check its resource use and selected synchronous window mutations;
the generated protocol checker alone does not establish those semantics.
Unsupported async protocols, native conversion of nested resource fields,
missing transport roles and incomplete outcome mappings reject before compilation.
Portable adapters can handle nonmechanical record conversion, with that ownership
visible in generated coverage. This is not a general effect/lifetime proof system:
declared effects and successful concrete protocol checks are not checked summaries,
full semantic equivalence, or activation authority.

Binary32/64 declarations use `float`/`double`; generated headers check storage,
radix, precision, exponent range and subnormal support and reject fast/finite-math
builds. Floating service adapters require exact native function pointer types,
including context and result types, so implicit conversions cannot hide an ABI
mismatch. Unsupported binary16/extended formats fail during rendering. These are
C representation and signature checks, not proofs of floating arithmetic,
signaling-NaN payloads or the floating environment. The pinned host and PE32
fixtures exercise quiet NaNs, infinities, signed zero, subnormals and conversions.
The jq numeric index helper now lives in authored C using a binary64 accessor;
NaN is explicit and clamping precedes defined integer conversion.

### Adapter-delivered nonlocal outcomes

`ServiceDefinition.create(..., outcomes=['return'], nonlocal_outcomes=['nomem'])`
declares a service that can return normally or leave through a C handler. This
selects `synchronous-return-or-nonlocal`; ordinary definitions retain their existing
identity and protocol. Adding a nonlocal permission changes the contract even when
the C signature is unchanged. Return predicates still describe only normal returns.

The selected package generates `comparison-services.h` and, when needed, one
shared `comparison-services.c`. A C adapter supplies the actual callback and
`setjmp`/`longjmp`; the tooling does not synthesize a replacement return value:

```c
uint32_t handler = spx_service_handler_begin();
if (setjmp(landing) == 0) {
    run_selected_operation();
} else {
    spx_service_handler_catch(handler, "nomem");
}
spx_service_handler_end(handler);
```

This is driver/adapter code, outside the component dialect. Generic drivers use
`SPX_COMPARISON_NONLOCAL` to detect whether the runtime is selected. Catch is
recorded after the actual jump. As required by C, changed automatic locals must
not be read after `longjmp` unless their storage/qualification permits it; the jq
fixture keeps inspected state in persistent storage.

Process termination can also be observed with an ordinary C supervisor while the
outer comparison command still exits normally. The
[native Hello terminal recipe](../tests/fixtures/hello-native-quoting/README.md#actual-fatal-diagnostics-and-process-termination)
uses the installed `pe32-process-observer.h` helper to compare exact
child exit codes and binary streams. It rejects capture overflow, timeout and
launch errors. After the child has actually terminated, its C adapter forwards
reserved service-trace records and transports the observed nonlocal outcome to
the supervisor's own handler. The existing reader still validates contract IDs,
scope nesting and allowed outcomes. This does not authorize treating arbitrary
nonzero outer-command exits as successful comparisons or inventing completion for
an unobserved/truncated child. The recipe documents its target-specific diagnostic
and initialization premises; the helper is not a general process-state model.

An uninstrumented parent can finish before invoking any selected supplier. A
completed observed handler admits that empty service trace, reports zero call
coverage and explicitly records that no supplier behavior was exercised. This
does not establish supplier conformance. Missing streams, incomplete handlers,
unbalanced calls/scopes and a root service catalog without any observed service
scope remain incomplete. A declaration alone cannot repair those failures.

The reader saves the exact enclosing call/scope instances at handler entry. It
checks that every interrupted service declares the observed nonlocal outcome,
then closes only that interrupted suffix. An inner handler can therefore catch a
supplier's failure while its parent service still returns normally. Equal stack
depth with a different caller instance is rejected, as are unknown outcomes,
stale handlers and missing completion events. There must be a recorded interrupted
service; a failure wholly outside selected boundaries is not evidence about their
nonlocal protocol. Handler instrumentation is single-threaded and bounded to
256 nested handlers; exhaustion is a failed instrumentation run.

Resource frames opened inside the handler are ended with explicit `unwind` events.
They still report retained and untransferred references. By default they enforce
the same allowances as normal completion. An existing resource-check contract can
declare bounded counts for a named nonlocal outcome:

```json
{
  "max_untransferred": 0,
  "max_retained": 0,
  "nonlocal_allowances": {
    "nomem": {"max_untransferred": 2, "max_retained": 0}
  }
}
```

This is an excerpt of a resource-check rule; its existing operation and canonical
lifecycle bindings remain required. The optional map is nonempty, uses explicit
outcome names and bounds both counts by the selected instrumentation capacity.
It changes contract identity and invalidates dependent evidence. Ordinary returns
still use the ordinary counts. The reader defers an interrupted frame's count
check until the matching handler catch, preserving the exact enclosing resource
frame identities. Missing catches, activity during unfinished unwind and unwinding
an enclosing frame reject. The service reader also requires every interrupted
service to permit that outcome. An allowance for another outcome does not apply.

These counts are declared applicability premises, not established native lifetime
facts. The jq failure cases independently compare retained values, alias/reference
observations and actual residual allocations against the original. Their ordinary
returns still allow zero untransferred tokens, while sampled nonlocal exits can
strand references on both sides. Diagnostics retain those references even when
the named allowance is satisfied. Unwinding does not release native objects or
silently accept a false lifecycle premise. Outputs, reachable memory, callback
context and actual allocation lifetime need their own observations/adapters.
This is checked concrete protocol behavior, not an exception-safety or heap proof.
Async completion, arbitrary reentrancy, SEH/C++ unwinding and whole-program callback
coverage remain outside this protocol.

### Optional local shared-service assurance

`prepare_comparison_package(local_shared_contract=...)` (Nix SDK
`localSharedContract`) selects the existing shared-view theorem when the operator
runs `component check --comparison-package DIR --local-contracts`. Its fields are
`relation_intent` (the existing ready-for-check component relation),
`maximum_calls`, `maximum_memory_events`, and optional existing `service_contracts`.
Capacities are checked model limits, not silent restrictions on admitted inputs.
The relation and source bytes are bound in the separate formal result.

The current rule covers fixed nonnullable shared byte views, one protocol state,
integer scalar service arguments/results, ordered synchronous service effects,
and an authored returned-state-view relation. It checks memory frame and input
dependence with the existing semantic engine; services satisfy explicit modeled
footprints. It does not prove the original machine implementation, native service
internals, general heap lifetimes, or all jq resource semantics. Unsupported shapes
report `unavailable` with zero model/solver work. Floating interfaces can execute
and compare while this particular proof rule remains unavailable.

A selected false property is reported independently of matching concrete samples.
The resource-text example detects a wrong alias on an unsampled input. Unchanged
source/premises reuse the exact local evidence with zero compiler/model/solver
work; changed premises invalidate it. This root-local optional check is not
imported as a supplier summary or automatically applied to every selected body.
Original memory-safety defects are not blanket admission failures; choosing an
inapplicable local premise cannot establish composition or activation authority.

Authored include-guard exemptions require application-owned identifiers. Reserved
compiler/proof macros (including `__CPROVER__`, `_WIN32` and `__GNUC__`) remain
conditional compilation and are rejected; guards cannot hide host/proof variants.

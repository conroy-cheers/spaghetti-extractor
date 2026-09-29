# Complete Hello quoting-slot operation

The subsequent [allocation-growth walkthrough](../../hello-allocation-growth/README.md)
selects the actual `xpalloc` operation beneath this consumer and passes a three-unit
experimental assembly. This fixture's default configuration retains the earlier
controlled-growth comparison as a separate regression.

This is ordinary authored C for the complete `_quotearg_n_options` operation at
RVA `0x4eb3`: 40 retained machine transfers, including the cold invalid-index
abort, ten call sites and the actual `_rpl_free` child at `0x1b34`. It exercises
persistent slot-table state and buffer allocation/replacement across calls.
The original PE is
`71b228f2babc9d3b4095ecf355db676c8ed8b45a7c8a7d350f47e962b4bf554c`;
the retained transfer-plan SHA-256 is
`7be11fac9ce1488cc893f7ac30ba9fde00e23a2fa92cf8f2e2c882965b77be11`.

`quote-slots.c` implements the whole operation, with a typed persistent context,
ordinary pointer fields and explicit services. Runtime-owned errno storage uses
the existing four-byte, call-scoped view interface and ordinary C word helpers;
it is reacquired for the final write. `quote-objects.h` proposes the other objects'
logical representation. The source passes the existing host/PE32 compilation and
C-profile checker. In the host comparison a slot occupies 16 bytes and options
occupy 56 bytes, versus 8 and 48 bytes in the original PE32 layout. The fixture's
explicit conversion tests this representation change; it is not a checked
representation theorem or permission to select these replacements.

The original side executes the unmodified retained Behavioral-C bodies for both
quoting and free. The source side executes the separately authored C for both,
through `release-bridge.c`. The remaining services are controlled fixtures. The
quoting engine's actual private ABI is EAX/EDX/ECX for the first three arguments,
followed by six stack words. The growth service's typed slot counts correspond
to original eight-byte elements; this correspondence still needs a checked
adapter. Neither callee bodies nor native runtime applicability are proved away
in this comparison.

The corpus contains 128 sequences and 446 complete invocations. It covers both
table-growth sites, static-to-dynamic and existing dynamic tables, in-place and
relocating growth, existing contents and nonzero new storage, buffer replacement
and reuse, argument/output aliases, changing errno cells, free-induced errno
changes, service mutation of options, 32-bit result-size wrap, allocation failure
and invalid-slot termination. All ten parent and six free-wrapper call sites are
observed. Each sequence preserves state across up to four calls and changes
machine caller registers. These are controlled entry contexts, not proofs of
the operation's five real direct callers and three tail callers.

The fixture compares complete represented public storage, service order and
arguments, state visible at calls, results/outcomes, and modeled object liveness
and generations. Original normal returns additionally check the saved registers,
stack and actual return word. Freed storage remains explicit bytes in the
fixture arena; an opaque source pointer is not dereferenced as a freed host
object. This permits observing scoped stale-buffer behavior without host C UB.
Partial aliases between typed records, unrestricted heaps, reentrancy and
concurrency remain outside the experiment. Address/undefined-behavior sanitizers
cover the executed corpus only.

## Reproduce with retained inputs

The public finite caller checker now accepts one C translation unit with bound
authored headers. `record_layout.py` supplies the manual PE32 field relations for
these unchanged C types, including the embedded character mask and the logical
state that groups noncontiguous globals. A checked record relation lives in the
existing caller definition's `boundary.records`; it is not a new proof authority.

The first implemented rule covers a fixed incoming inventory that stays live for
the operation. It checks actual C field types, incoming contents, canonical
pointer aliases, byte-buffer contents, call-time mutations and field/context
frames. Native offsets and C field positions are independent. It supports
ordinary C member access and array indexing inside the declared inventory.
Distinct overlapping fields, changing inventories, allocation/release and
escaped lifetimes require further rules. A local record proof cannot currently
be exported through the scalar callable-summary reader.

`tests/unit/components/record_caller_fixture.py` uses this exact header in a small
two-call original/C proof, with arbitrary incoming values and buffer aliases.
That is an engine regression, not a proof of this complete quoting operation.
The actual quoting source and all declared field/subobject types also compile
under the host and PE32 compilers, retaining the 16/56 versus 8/48 byte layouts.

The generic `boundary.local_records` rule now transports the ordinary
`struct spx_opaque_quote_word_v5` local passed as `&new_count`. `record_layout.local_count()`
records its actual native location: call ESP plus `0x4c`, or operation entry ESP
minus 32. The checker verifies field contents and permissions through the
existing paired-object rule, preserves exact aliases and writes service results
back into the C fields. The service's no-escape premise remains unverified.

The following retained-input check executes the original from its actual entry
`0x4eb3`, covering the prologue, errno read and both `xpalloc` sites. The complete
authored C runs to the same growth call. A proof-only assertion observes its saved
errno local; the checker otherwise retains the authored algorithm. The existing
borrowed-view runtime supplies current errno bytes, including aliases with public
globals. Volatile registers and flags can change after the errno call.

The query verifies saved errno, preserved native input words, the count pointer,
incoming count contents, all five ABI arguments and field writeback for an
arbitrary shared service result. Its explicit admission selects the growth
branch and separates the nonwrapping private stack from the accessed globals.
It imposes no fixed slot-array bound. It stops before allocation returns, leaves
later regions and native admission open, and authorizes neither replacement.
The three negative options must produce their respective counterexamples.

```sh
python tests/fixtures/hello-quoting-state/slots/check_growth_count.py \
  build/hello-quoting-state-2026-09-21/quoting-slots/exact build/quoting-growth-cut
# Repeat in fresh directories with --wrong-errno, --wrong-count or --wrong-offset.
```
Full quoting still needs the growth/release, callable memory and
runtime rules listed below. The finite object count is a declared model shape;
it must not silently become a restriction on the full operation's admitted inputs.

`check_growth_memory.py` checks the next region, from a successful growth return
at `0x4f2c` or `0x505c` through the clearing call at `0x4f54`. It executes the
retained original and the complete authored C to that call. The successful growth
contract preserves the old prefix and supplies arbitrary new bytes; the caller
must copy the initial static slot when applicable and clear exactly the new range.
Other public bytes may change arbitrarily except the explicitly preserved
table/count and initial-slot globals; this does not silently frame allocator
metadata or retired storage.
Static, relocated and in-place cases each require a nonempty-domain witness.
Counts remain symbolic within nonwrapping PE32 storage, with no fixed slot limit.

The existing sparse byte world now has explicit snapshot-copy and constant-fill
events. Reverse lookup follows copies into earlier history, so subsequent source
writes do not alter a copy. Event capacity bounds operations, independently of
array lengths. In the byte-only mode, each write checks the preserved global span.
Current-record hooks now have an internal checked snapshot implementation;
the definite-initialization observer still requires a separate bulk transport
rule and rejects explicitly.

```sh
python tests/fixtures/hello-quoting-state/slots/check_growth_memory.py \
  build/hello-quoting-state-2026-09-21/quoting-slots/exact build/quoting-growth-memory
# Repeat in fresh directories with --mutation wrong-copy or --mutation wrong-clear.
# To offer exact prior query evidence, add --previous build/quoting-growth-memory
# while choosing a fresh output directory. Preparation and compilation still run.
```

The retained byte-only positive and both negative runs are under
`build/hello-quoting-growth-memory-2026-09-21/`. The complete positive regional
check takes 218.214s on fresh evidence. The subsequent run reuses 29 exact queries
and reruns three admission witnesses; including compilation and import it takes
24.276s. It is not zero model/compiler/solver-work reuse. The terminal audit
regenerates inputs and replays both proof and counterexamples without proof tools.

This continuation experiment uses the existing complete compiled-property
checker, including safety and loop coverage. Growth success, contents, liveness,
separation and the normal clearing effect are explicit service premises. It does
not establish the allocator's implementation, allocation/release generations,
failure behavior, applicability of the resumed cut, or general resizable C-array
transport. The saved errno prefix is checked by the preceding experiment; these
two experiments have not been composed into a full caller theorem. Neither one
authorizes activation or changes the production component boundary.

`--record-snapshots` uses the shared record renderer for the static initial slot,
its opaque buffer identity and the persistent count, including the nominal C
field checks. It preserves the unchanged full `quote-slots.c` and uses snapshot
effects for the actual static-slot copy. The new transport passes eight focused
tests, including overlapping copies against an independent byte-array oracle
and ordered service writes. Readonly fields check whole-field nonoverlap before
skipping writeback. Preserved byte-history spans still check every recorded
effect; current C fields and snapshots retain their separate representation and
frame checks. This does not establish a growing typed-array or allocator lifetime
rule.

The retained `build/hello-quoting-record-snapshots-2026-09-21/positive-v4/`
experiment passes compilation, all three domain witnesses and the complete
regional property check. The latter takes 340.657s; the experiment takes
360.415s. `wrong-copy-v4/` rejects at the copied-size assertion, and
`wrong-clear-v4/` rejects the clearing arguments. `reuse-v4/` takes 22.565s,
imports 41 exact queries and runs the three admission witnesses. Compilation
still runs. `terminal-audit.json` binds all four results and the 71 passing
affected tests/six repository gates, with read-only evidence replay.

Earlier `positive-v2/` safety timeouts and the subsequent `positive-v3/`
prefix/suffix-assertion timeout are retained with their exploratory SAT/SMT
probes. The frame changes above resolve those regional checks without narrowing
symbolic counts. General resizable C arrays, growth failure/lifetimes,
entry-to-continuation applicability and complete-operation composition remain
required before this can become a qualified quoting replacement.

`--connected --record-snapshots` extends this experiment from the actual entry
at `0x4eb3`, through errno capture, either growth site, static-slot copying and
the normal clearing return, to count publication at the real `0x4f62` barrier.
The existing exact-slice emitter retains all forty owned transfers and inserts
that forced label. The unchanged ordinary C receives a proof-only marker before
selected-slot indexing; its production interface is unchanged. The relation
checks argument/option identities, saved errno, caller registers/private words,
table/count publication, service order and the public byte frame. The local
growth count uses the existing checked C-record pack/unpack transport.

```sh
python tests/fixtures/hello-quoting-state/slots/check_growth_memory.py \
  build/hello-quoting-state-2026-09-21/quoting-slots/exact \
  build/quoting-growth-connected --record-snapshots --connected
# Repeat in fresh directories with --mutation wrong-publication or
# --mutation wrong-saved-errno. --previous still reuses exact queries only.
# Add --prepare-only in a fresh directory to emit and compile the identical
# model for focused diagnosis without proof queries or admission witnesses.
```

`model-preparation.json` binds the prepared inputs, model, tools and separate
phase costs. It is explicitly non-authorizing and supplies no complete proof.
Use it to diagnose a failing property before repeating the full checker.

For a small admitted case, add `--concrete-case static`, `moved` or `inplace` to
the connected command. This fixes the listed addresses, counts, scalar inputs
and observation byte; other incoming memory values and caller registers remain
symbolic. The exact restrictions are retained in `concrete_inputs`. The checker
also requires a witness that both implementations actually reach the continuation,
in addition to the input-domain witness. The complete property checker still
checks the restricted model's assertions, language safety and loop obligations.

These are **case diagnostics**, not a symbolic growth proof, a whole-memory proof
for arbitrary probes or three exhaustive input partitions. Their records always
have `input_scope: concrete-case-diagnostic` and `universal_region_complete: false`.
Omitting the option retains the original symbolic domain. A matching case never
authorizes activation; an incorrect count publication or saved errno can produce
a concrete counterexample without waiting for the unrestricted solver query.

The connected experiment is under
`build/hello-quoting-growth-connection-2026-09-21/`. Its complete property check
and negative/reuse results must be terminal before claiming this connection.
The initial bounds and subsequent record-pointer timeouts remain explicit
incomplete results. Fixed event slots and direct callbacks preserve the actual
stored event/count relation; capacity and snapshot-frame assertions remain
mandatory. Service effects follow checked domain guards, whose assertions also
remain in the complete inventory. An intentionally incorrect guard rejects.
Earlier producer-bound regional receipts above are historical after these edits.

Successful growth, related live storage and synchronous service behavior remain
explicit premises. The C record inventory represents the initial slot and count;
the symbolic array contents use the sparse byte world. General growing C arrays,
allocation failures/generations/lifetimes, subsequent selected-slot accesses,
full quoting and native admission still require the rules below.

The existing public caller checker also checks the actual release-call transfer
`0x4fc3` through its normal continuation at `0x4fcf`. `check_release_transport.py`
retains that original transfer and projects the unchanged source release call
into a proof-only region. It consumes the current checked `_rpl_free` summary
with the supplier body absent. `parameter_transport` relates the ordinary opaque
buffer pointer to the supplier's scalar allocation token. The zero-extent
identity representation preserves null/aliases while granting no readable bytes
or native lifetime.

```sh
python tests/fixtures/hello-quoting-state/slots/check_release_transport.py \
  build/hello-quoting-state-2026-09-21/quoting-slots \
  /path/to/current/preserve-errno-free-component-source-call-check \
  build/quoting-release-transport
```

The checked incoming relation identifies ESI as the buffer and separates the
private stack from the resolved errno import slot. The proof covers the actual
stack argument, saved continuation word, register frame, public memory and normal
continuation. Wrong references and missing entry premises reject; omitting the
interface transport rejects before compilation. Unchanged evidence reuses with
zero model/compiler/solver work. The fixture separately retains the rejected
stack/import overlap instead of silently declaring that runtime premise proved.

This region does not grant a new production API or establish the preceding
quoting state, concrete free/CRT/TLS applicability, release generations, returning
allocated identities or the complete operation. Fresh regional checking takes
6.943s and unchanged proof reuse 4.168s in the retained experiment under
`build/hello-quoting-reference-transport-2026-09-21/`.

The retained input directory contains `exact/`, `rpl-free-exact/` and the earlier
`rpl-free-authoring/` package. The checked slice manifests and all original
member hashes are validated before packaging. The commands below use the same
retained inputs as the current checkpoint; output directories must be new.
Use the repository development environment, including the host and PE32 C
compilers, and `PYTHONPATH=.:src:$PYTHONPATH` when running from the checkout.

```sh
retained=build/hello-quoting-state-2026-09-21/quoting-slots
experiment=build/hello-quoting-reproduction
python3 tests/fixtures/hello-quoting-state/slots/prepare.py "$experiment/authoring"
python3 tests/fixtures/hello-quoting-state/slots/package.py \
  "$experiment/authoring" "$retained" "$experiment/public"
python3 -m spaghetti_extractor component start gnu-hello quote-slots \
  --comparison-package "$experiment/public/quoting" --output "$experiment/public/draft"
python3 tests/fixtures/hello-quoting-state/slots/walkthrough.py "$experiment/public"
```

The walkthrough uses public `component check` commands and records exact commands,
phase costs, diagnostics and evidence hashes. It checks the corpus, reuses an
unchanged result, edits the selected free-wrapper implementation, rejects wrong
quoting C, repairs it and rejects a same-signature changed supplier contract.
Unchanged/repair comparisons perform no compiler, link, execution, model or
solver work. A supplier edit recompiles one of seven translation units, then
reruns the integrations. These are comparison-cache results, not neighbor proof
reuse. Compiler-loader overrides are removed only from fixture subprocesses so
the existing compiler dependency cache can validate its actual inputs.

For a sanitized paired run, or three deliberate negative implementations:

```sh
python3 tests/fixtures/hello-quoting-state/slots/compare.py \
  "$experiment/authoring" "$retained" "$experiment/sanitized" --sanitize
python3 tests/fixtures/hello-quoting-state/slots/compare.py \
  "$experiment/authoring" "$retained" "$experiment/wrong-order" --mutation late-size-store
```

The other mutations are `no-elide-nul` and `skip-clear`. Each mismatch exits 1;
fixture failures exit 2. The ordinary public comparison reports first differing
observations and retains replayable inputs. `--local-contracts` currently reports
the formal check **unavailable** for this persistent opaque-object interface,
with zero formal model/compiler/solver work. No Wine application or pilot rebuild
is needed for these commands.

## Release, allocation and pointer publication

`check_buffer_replacement.py` retains the four actual transfers from `0x4fc3`
through the `0x4fec` continuation and the corresponding unchanged source
statements. It consumes a current checked `_rpl_free` supplier with its body
absent, then checks a runtime allocator's returned identity and publication in
the actual slot record. The allocator premise allows arbitrary byte effects
outside the protected slot and continuation frame. It does not prove allocation
success, failure/nonreturn behavior, storage contents or native lifetime.

```sh
python3 tests/fixtures/hello-quoting-state/slots/check_buffer_replacement.py \
  build/hello-quoting-state-2026-09-21/quoting-slots \
  "$current_supplier" build/hello-buffer-replacement-reproduction
```

`current_supplier` is the root of a current SDK `preserve-errno-free`
source-call-check product. The checkpoint's reproducible SDK expression and
terminal output path are retained under
`build/hello-quoting-returned-identities-2026-09-21/sdk/`.
Fresh conditional checking takes 115.398s; unchanged reuse takes 4.421s with no
model/compiler/solver work. Wrong pointer publication rejects. These are regional
proofs, not a synthetic production API or a complete quoting replacement.

## Required checked transport

The next implementation must consume these same real operations through the
existing proof/interface/lifetime infrastructure:

1. Relate the original global table pointer/count and eight-byte slot records to
   persistent typed C objects, including contents, identity, offsets, aliases,
   frames and generations. Retain references across calls without reviving dead
   storage or treating a decoded pointer as initialized contents.
2. Relate `xpalloc` growth and `memset` clearing to the typed operations. Preserve
   old elements on success, initialize exactly the new range, distinguish
   in-place growth from replacement and retain terminal failure outcomes.
3. Transport actual buffer references into the checked scalar free-wrapper
   contract and back from allocation; discharge release applicability. Preserve
   the slot-size store before free/allocation and the buffer store before the
   second quote call, as well as cached flags and reread option fields.
4. Summarize the complete caller with a checked memory envelope over all service
   invocations. Prove caller-body absence and compatible neighbor proof reuse;
   discharge runtime and native-adapter premises before activation.

All G1–G7 in `docs/whole-target-independent-lifting.md` remain required. Finite
comparisons, source compilation and declarations do not close these obligations.

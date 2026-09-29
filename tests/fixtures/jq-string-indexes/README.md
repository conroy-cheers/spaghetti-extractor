# Establish a two-input component using shared live-object services

This previously unprepared jq operation tests whether a new boundary can reuse
the existing string view and reference transport. `jv_string_indexes` consumes
two possibly aliased string references, searches in a loop, builds an array and
runs beneath the real interpreter. The local workspace needs no neighboring
lifted implementation or new checker rule.

[BOUNDARY.md](BOUNDARY.md) records the reviewed native body, ownership, contents,
service ordering, malformed-byte behavior and limits. [indexes.c](indexes.c)
contains the ordinary C algorithm. The only new service adapter is the nine-line
[indexes-native.h](indexes-native.h), which composes number construction and
array append. Existing contents/release declarations, C views, live-value transport
and allocation observations are reused with `retained_service_inputs`.

Entry installation now uses `native_entry_header` with the reviewed RVA range and
pinned DLL. Preparation derives the expected bytes and generates saved-body/hook
setup; the driver supplies its typed replacement and observes actual calls. Byte
length and codepoint length use the same helper. This removes repeated native
setup, while the operation boundary, ABI and memory observations stay operator-owned.

The preparer now uses `component_resource_checks` to name consumed inputs and the
produced result. It shares the existing lifecycle validator and format; the recipe
keeps its original binding IDs so generated inputs stay unchanged. The helper
removes manual lifecycle-payload construction without inferring ownership or
requiring exclusive access to the aliased strings. See the
[authoring API](../../../docs/components.md#author-a-new-comparison-boundary).

The operator still specifies the two consuming parameters, produced result,
lower-service outcomes and meaningful observations. That is real manual work:
the initial trial used 38 lines of algorithm, 83 of driver, 78 of preparation and
29 of boundary notes, before the shared authoring helpers above. Most preparation
concerns the operation and its cases; no new heap
transport, proof model, artifact format or compiler support is needed. The source
and native disassembly assist this analysis; it is not an independent human
usability study or automatic recovery.

## Prepare and work locally

Use a current [byte-length workspace](../jq-string-byte-length/README.md) containing
the shared string view and reviewed pinned native runtime. Copy this directory's
files into your own operator project if desired; the preparer reads no sibling
fixture directory. In `nix develop /path/to/spaghetti-extractor#lifting`:

```sh
python prepare.py /path/to/byte-length-workspace prepared
spaghetti-extractor component start jq string-indexes \
  --comparison-package prepared/string-indexes --output work
spaghetti-extractor component status jq string-indexes --comparison-package work
spaghetti-headless-wayland spaghetti-extractor component check jq string-indexes \
  --comparison-package work --output checked
```

The complete recipe uses `comparison_preparation` to stage its generated bridge,
package and preparation notes together. A rejected declaration or missing input
leaves `prepared` absent or empty, so fix the recipe and retry the same command.
An existing populated workspace is preserved.

Edit `work/source/indexes.c`, then offer `--reuse-comparison checked` to the next
check. The generated workspace guide exposes borrowed views, both owned inputs,
services, examples and assumptions. Cases cover unique and retained references,
two inputs sharing an allocation, overlapping matches, raw NUL/malformed bytes,
empty/longer patterns and an interpreter `indices` consumer.

For the focused edit/diagnose/replay example:

```sh
spaghetti-headless-wayland python walkthrough.py \
  /path/to/byte-length-workspace /tmp/indexes-workflow
```

It checks one compatible loop edit, removes one release to expose a lifetime
defect, repairs the source, replays the saved defect and exports the checked C.
The wrong version returns the same indexes but leaves seven native blocks live
in the retained-reference case. Both reference and allocation observations are
available; result equality alone would miss the defect. All Wine processes run
inside the headless Wayland desktop.

## Start from the selected path network

An operator who has the connected path workspace can establish this boundary
without finding the earlier byte-length package:

```sh
python prepare.py /path/to/path-network prepared --services-component string-slice
spaghetti-extractor component start jq string-indexes \
  --comparison-package prepared/string-indexes --output work
spaghetti-headless-wayland spaghetti-extractor component check jq string-indexes \
  --comparison-package work --case retained --history checks
```

The recipe selects `contents` and `release` from that named component, preserves
their exact declarations and uses explicit file mappings for the shared value
transport, allocation observer and headers. The new search algorithm, native
entry, driver and cases remain local operator inputs. No neighboring component
body or earlier comparison evidence is imported.

The reviewed network adapter bundled the contents reader with slice-entry
installation. [network-contents.c](network-contents.c) isolates the needed reader
in ordinary C, retaining the original byte-length lower service. That small manual
adapter is necessary; merely selecting declarations would not supply it. The
algorithm and driver are the same as in the standalone-service recipe above.
Use `--case program` after editing to exercise the existing interpreter consumer.
This is another preparation route for the existing component, not a new component
or a new-boundary generality claim.

The installed handoff is retained at
`build/component-network-services-2026-09-24/checkpoint.json`. Preparation takes
0.576s; the compatible edit compiles one file and reuses seven. The missing-release
defect still yields the correct positions but leaves seven native allocations
live, is diagnosed and replays after repair. The interpreter consumer passes with
five replacement calls and all eight compiled units reused. The source library
also builds with the host compiler. These results use the existing retained and
program cases; no pilot rebuild or additional case matrix was needed.

## Carry the checked C into the source program

Add `--extra-comparison /tmp/indexes-workflow/repaired` to the
[portable jq assembly command](../jq-portable/README.md). The source recipe removes
the original search definition, generates its binding from the retained service
declarations and supplies the small `indexes-native.h` backend adapter explicitly.
The ordinary exported library contains implementation inputs; it does not supply
all native fixture helpers as a portable backend. The first assembly attempt
omitted this header, and the compiler identified the missing dependency. The
corrected recipe includes it for this selection only.

Build and run using the existing source-project instructions. The new operation
can then follow the normal partial-export/update workflow; unchanged neighbors
retain their previous C and comparisons. The parser, VM, allocator and other
unlifted jq services remain an explicit source-assisted backend.

Evidence is retained at `build/jq-string-indexes-2026-09-23/`. The first local result
took 285s from the first retained disassembly, including authoring and execution
but excluding earlier exploration. Automatic preparation took 0.239s. The focused
public workflow took 25.375s; the compatible edit compiled one C file, and the
restored check reused without compilation or execution. These are development
measurements, not human benchmarks. Nonlocal allocation failure, arbitrary
callbacks/concurrency and stronger qualification remain unobserved here.

The corrected standalone assembly passes the same five-search workload through
normal CLI execution on x86-64 and AArch64 under QEMU. Each run records five calls
to the replacement; build symbol inventories confirm that the original search
definition is absent from the backend. This is focused integration evidence for
the new selection, not a rerun of the previous full jq case matrix.

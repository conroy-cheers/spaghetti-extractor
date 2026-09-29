# Connected DX-Ball graphics workflow

This is the second practical target after the jq storage/path network. Operators
define four boundaries, write ordinary C, compare against retained machine-derived
C, edit a supplier, reuse unaffected comparisons, replay discrepancies and build
an explicitly experimental assembly. It uses the existing interface, service,
comparison, dependency and candidate APIs. No proof-engine or checker extension
was added for these components.

Adapter precondition failures identify their C function, file/line and violated
condition. For example, corrupting the initialization flag reports
`adapters/runtime.c:119 (dx_caps): state->initialized==1 && state->capability_mode==0`
alongside the last service event. `component status --comparison-result` and
retained replay preserve that context after the editable C is repaired. An
aborted adapter remains an incomplete comparison. The diagnostic wrapper is
private to the runtime implementation and leaves shared contracts unchanged.

The normal continuation matters: the older
[early-failure fixture](../dxball-directdraw-lifecycle/README.md) never reaches the
table reset, current-surface binding or a real resource consumer. The pinned
initializer calls both reset and bind before returning success. Its primary output
is at **VA `0x4349ac`**, and its backbuffer output is at **VA `0x4349b4`**. The older
draft's mapping and omitted calls cannot be treated as a complete initialization
replacement. This experimental network has separate component identities and
does not qualify or silently update that old portable-provider selection.

## Manual boundaries and observed state

| Component | Original entry | Responsibility and boundary |
|---|---|---|
| `graphics-initialize` | RVA `0xcd5c` | Real DirectDraw initialization tail; owned normal/failure continuations, resource services, reset and bind calls. Entry frame has saved ESI/EBX at offsets 0/4 and return address at `0x218`. |
| `graphics-reset` | RVA `0xbc90` | Clear 255 sprite slots and one count in each of three banks. Preserve the six following words per bank. |
| `graphics-bind` | RVA `0xbd60` | Store the supplied word as current surface; the original itself neither dereferences nor validates it. |
| `graphics-blit` | RVA `0xbd90` | Read the current bank's sprite, its source surface and rectangle; call BltFast on the current destination with flags `0x11`. |

These are actual original operations, not synthetic production APIs. Internal
cuts used to recover the reset loop do not become public components. All four
share a representation group because their C state representation is coupled.

If only the retained-C initializer network is available, prepare a local blit
workspace without its original per-component package:

```sh
python tests/fixtures/dxball-graphics-network/prepare-local.py NETWORK build/blit-package
spaghetti-extractor component start dxball graphics-blit \
  --comparison-package build/blit-package --output build/blit-work
spaghetti-extractor component check dxball graphics-blit \
  --comparison-package build/blit-work --history build/blit-checks
```

The recipe uses `retained_component_inputs` to preserve the selected boundary,
shared layouts, service configuration and C. It explicitly chooses the existing
local driver branch, oracle/runtime adapters and `seed-7` case. Those choices
remain operator responsibilities. Return edits to the network with
`--dependency-source graphics-blit=build/blit-work`; use its matching result for
the usual partial source-project update. The installed handoff at
`build/component-local-setup-2026-09-24/` detects/replays a wrong coordinate,
repairs it, reuses neighboring compilation and updates the existing library.
It adds no native DirectDraw execution or qualification claim.

After declaring a C file refactor with `revise_comparison_package`, the component
itself can also be reopened using `component start --reuse-source REFACTORED_WORK`
or `--reuse-source SOURCE_PROJECT` with its existing local comparison package.
Retired C is removed and editor/build inputs follow the new selection; the local
driver and neighbors remain in place. The installed handoff at
`build/component-root-refactor-2026-09-24/` splits blit into an entry and private
helper, imports the exported helper rename, detects/replays a wrong rectangle
extent, repairs it and updates the connected source library with neighbor reuse.

The machine banks occupy three `0x418`-byte rows at VA `0x433d18`. The portable
representation contains real pointers to constructed sprite objects, a count and
six retained words per row. C adapters explicitly transport contents and sharing
between those objects and mapped PE addresses. The pointer conversion alone is
not evidence of preserved contents or lifetime. The fixture compares every bank
slot/count/tail, eleven scalar state words, ordered service arguments/results,
live resources, each window's lifetime/hidden state and controlled blit effects.
It checks original return frames and rejects unknown machine reads, writes,
calls, invalid pointers and invalid resource uses. Adjacent untouched surface
slots contain checked sentinels.

On successful initialization, an explicit outside-scope sprite loader places a
sprite backed by the newly created backbuffer in one bank. The actual blit routine
consumes it using the initialized primary surface; another actual bind operation
changes the destination to the backbuffer, followed by a second blit. This tests
the connection between initialization, mutable shared state and consumers.
The fixture-owned loader is a retained environment dependency, not a lifted loader
or an added call in the initializer.

The 37 connected cases include both signs of nonzero failure at seven stages,
clipper modes 0/1/2, both capability-bit values, a failed caps call whose written
output the original still consumes, and selected synchronous window mutations
during hide/message calls. Nonnegative creation statuses publish their resource
even when nonzero status then takes the failure path. The original leaves those
resources live; the replacement must not invent cleanup. Eight cases independently
exercise each smaller unit. Local bank/slot and object-validity premises remain
explicit rather than becoming blanket memory-safety or borrow rules.

## Reproduce from retained inputs

For fresh setup, enter `nix develop .#lifting` and omit `BASE`:

```sh
python tests/fixtures/dxball-graphics-network/walkthrough.py \
  /path/to/original/DXBall.exe /tmp/dxball-graphics-workflow
```

The [shared handoff recipe](../hello-handoff/README.md) documents one-time original
input provisioning and accepted results on both targets. With no base, preparation
uses the existing extractor/normalizer/renderer to recover all 65 initializer blocks
from `targets/dxball/intent/bindings-v5/directdraw-init.json` and the pinned PE.
The binding, semantic inputs and generated initializer are retained together.
Preparation now calls the installed `comparison_original.recover_original_c`
helper with the reviewed ranges. It no longer imports the extractor, normalizer
and renderer internals separately. The helper reports preparation, extraction,
lowering and rendering costs; timing fields stay outside bound comparison inputs.
The fresh C hash is `5a93c067026241bdaf66dd2b71e0c851d6b28cd5925b3da3fd617c85f8a62aee`;
all 37 original observations match the previous retained oracle. This is finite
oracle comparison, not strong qualification of the newly rendered initializer.

For an external operator project, keep `prepare.py`, `declarations.py` and this
directory's C/header files together. Copy the reviewed initializer binding too,
and supply it explicitly instead of relying on the repository layout:

```sh
python prepare.py DXBall.exe packages --initializer-boundary directdraw-init.json
spaghetti-extractor component start dxball graphics-reset \
  --comparison-package packages/graphics-reset --output reset
spaghetti-extractor component check dxball graphics-reset \
  --comparison-package reset --output reset-checked
```

Run inside `nix develop /path/to/spaghetti-extractor#lifting`. This setup needs
the original image and reviewed operator files, not an earlier comparison result
or a pilot build. The shared helper does not discover boundaries, create runtime
adapters or qualify its generated C. Unsupported instructions leave no partial
generated selection and identify the failing original range.

The complete recipe stages recovery, generated adapters and all four packages
before publishing the output directory. If preparation fails, correct the
reported operator input and rerun the same command; no partial output needs
removal. Existing nonempty outputs are preserved. For example, a missing
`initialize.c` is detected after the three smaller units have been prepared,
but none of that incomplete selection is published. The installed-toolkit
handoff at `build/component-preparation-retry-2026-09-24/` exercises that late
failure, correction, local C editing, consumer comparison and source export.
This uses the existing `comparison_preparation` helper, with no new toolkit API.

The installed external handoff at `build/component-original-preparation-2026-09-23/`
prepares this network in 0.413s with identical generated C, semantic inputs and
source locations. Focused public edit/reuse/consumer/defect/replay/repair/export
commands pass; the local edit compiles one file in a 0.627s check and the unchanged
neighbor reuses with zero execution or compilation. This checks the setup handoff
using retained C and controlled services, not normal game execution.

Use the repository development environment. `BASE` is an existing host-C
`directdraw-lifecycle-comparison-package` (or a retained result's `inputs`);
`PE` is the original DX-Ball executable. No pilot rebuild is part of an edit.

```sh
BASE=build/practical-lifting-2026-09-15/dxball-lifecycle-v1/nix-package-check/inputs
PE=build/dxball-lifecycle-2026-09-22/inputs/DXBall.exe
python tests/fixtures/dxball-graphics-network/walkthrough.py \
  "$BASE" "$PE" /tmp/dxball-graphics-workflow
```

The executable must have SHA-256
`191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f`;
the retained initializer C is independently pinned in `prepare.py`. The same
original is available through the target's pinned archive/installer recipe.
Any installation or other Wine process must run in a headless Wayland desktop.
This comparison itself runs host C and launches no Wine or graphics driver.

Both setup paths use the existing semantic extractor, transfer normalizer/compiler
and Behavioral-C renderer for the three small helper bodies. Their manually
specified spans, machine bytes/semantic inputs, generated files and PE binding
are retained in `original-helpers/`. This is an experimental retained-C oracle,
not a new qualified transfer-plan artifact. Unsupported extraction fails rather
than substituting a handwritten original algorithm.

For individual work, prepare once and use the public commands directly:

```sh
python tests/fixtures/dxball-graphics-network/prepare.py \
  "$BASE" "$PE" /tmp/dxball-graphics-packages
spaghetti-extractor component start dxball graphics-reset \
  --comparison-package /tmp/dxball-graphics-packages/graphics-reset \
  --output /tmp/dxball-reset-draft
spaghetti-extractor component check dxball graphics-reset \
  --comparison-package /tmp/dxball-reset-draft --output /tmp/dxball-reset-check
spaghetti-extractor component check dxball graphics-initialize \
  --comparison-package /tmp/dxball-graphics-packages/graphics-initialize \
  --dependency-package graphics-reset=/tmp/dxball-reset-draft \
  --output /tmp/dxball-network-check
```

`component start` supplies generated headers and editor configuration. Edit ordinary
C under `source/`; use a new result directory and `--reuse-comparison` to offer an
earlier result. Changed source causes the appropriate local/integration recheck.
Before a dependency check, `component status dxball graphics-initialize
--comparison-package /tmp/dxball-graphics-packages/graphics-initialize
--dependency-package graphics-reset=/tmp/dxball-reset-draft` previews changed
declarations and shared files without compilation. A stale shared header now names
its exact path and the `graphics-initialize/reset` consumer. Review the difference,
then use `component start --reuse-source` with the revised reset package to preserve
local C. The preview does not automatically accept a contract change.
Unchanged neighbors retain their own comparison results. Replay a failed case
from the failed result's immutable `inputs` directory, even after repairing the
working draft. The walkthrough records these commands, constructs the existing
experimental policy from the selected packages, and calls `candidate build
--experimental-comparison` followed by `candidate test --experimental-package`.

If a handed-off experiment has only network evidence for bind or blit, a matching
local check can be attached with `candidate build --reuse-experimental` and
`--component-comparison`. The resulting experiment can reopen that unit by name
with `component start --experimental-package`. Follow the
[local-check handoff](../../../docs/component-workflow.md#add-a-local-check-to-an-existing-experiment).
The retained `graphics-bind` trial uses this recipe unchanged, checks its eight
local cases, and preserves the existing native program binary and neighboring
reset receipt. No new program run is needed merely to retain the local evidence.

## Delivered checkpoint and limits

`build/dxball-lifecycle-2026-09-22/workflow-v1/` records 22 commands and 17 comparisons.
All 37 connected cases pass initially and after repair; the four-unit experimental
assembly passes all 37 again. The fixture checks that all four selected authored
operations execute on success. Formal checking is `not-requested` throughout.

A compatible reverse-order reset edit compiles one of fifteen network translation
units, reuses fourteen objects and reruns the affected integration. Unchanged bind
and blit checks reuse with zero compiler/link/execution/model/solver work. Clearing
254 instead of 255 slots gives a retained discrepancy at `$.banks[0][254]`, locally
and through the consumer. Capturing the window before cleanup changes the later
message argument at `$.services[6][1]`, despite equal return values. Both defects
replay after the draft is repaired; restored inputs reuse their earlier results.

Preparation takes 0.346s; the compatible supplier check takes 0.598s, connected
recheck 1.852s, unchanged bind/blit reuse 0.481s/0.524s, and repaired network reuse
1.178s. Experimental execution takes 2.678s. The complete recipe takes 26.473s.
These are development measurements, not benchmarks. Phase costs are retained in
the comparison results; model and solver work are zero.

The existing eight-case early-failure regression passes freshly. Final integrated
validation (`validation-v2/`) passes 76 tests across eight Nix shards without
failures, errors or skips, plus all six repository/SDK gates. The initial stale
format-registry failure is retained; regeneration adds this walkthrough as a
consumer of the existing experimental policy format, with no new format.

Manual work remains substantial: 80 lines of lifted operation C, 22 lines of
shared-state C, 39 lines of service declarations, and 455 lines of runtime/driver
C including declarations. The 180-line preparer includes bounded original-helper
recovery and calls existing package APIs; the 161-line walkthrough is a regression
recipe over public commands. None modifies toolkit internals or handwritten
generated identities. This demonstrates reuse across a different kind of target,
not that arbitrary component setup has become effortless.

Resource lifetime and argument checks here live in the C adapters and compared
observations. The service catalog's protocol checks do not constitute checked
memory/resource summaries. Synchronous window mutation is an explicit service
scenario; arbitrary callback bodies, nested reentrancy and scheduling are not
implemented by this fixture. The optional native comparison below now challenges
the retained-C oracle with the actual x86 bodies. There is still no actual COM
driver, framebuffer-equivalence check, window-creation prefix, full game assembly
or second-architecture execution. The transport, controlled environment and
observer remain assumptions. Strong qualification/link/export obligations remain
unchanged.

## Revise the shared portable layout

Private C layout can change without changing the original PE layout or inventing
new public operations. The existing adapters map named fields to the original
machine locations and preserve sprite contents and aliases. For example, copy
`graphics-state.h` into the operator project and move the bank count and retained
words before its slot array:

```c
struct dx_sprite_bank {
  uint32_t count;
  uint32_t retained[6];
  struct dx_sprite *slots[255];
};
```

After reviewing that change against the C adapters, prepare the whole affected
representation group with [revise-layout.py](revise-layout.py). `PACKAGES` contains
the existing local packages named by the consumer's `dxball-graphics` group:
`graphics-reset`, `graphics-bind`, `graphics-blit` and `graphics-initialize`, or
the three-component selection after combining reset/bind as `graphics-state`.
The optional consumer is an edited or native initializer workspace:

```sh
python tests/fixtures/dxball-graphics-network/revise-layout.py \
  PACKAGES /tmp/graphics-state.h portable-sprite-count-first-v2 \
  /tmp/graphics-layout --consumer /tmp/graphics-work
spaghetti-extractor component start dxball graphics-reset \
  --comparison-package /tmp/graphics-layout/graphics-reset --output /tmp/reset-layout
spaghetti-extractor component check dxball graphics-reset \
  --comparison-package /tmp/reset-layout --case seed-7 --output /tmp/reset-layout-check
spaghetti-extractor component start dxball graphics-initialize \
  --comparison-package /tmp/graphics-layout/graphics-initialize --output /tmp/consumer-layout
spaghetti-extractor component check dxball graphics-initialize \
  --comparison-package /tmp/consumer-layout --case seed-7 \
  --reuse-comparison /tmp/previous-consumer-check --output /tmp/consumer-layout-check
```

Use the lifting shell. If the consumer uses the native oracle, run its check
inside `spaghetti-headless-wayland`. The recipe invokes existing authoring APIs;
it preserves the consumer's selected C and dependency adapters, the local case
drivers, original inputs and operator notes. It supplies the reviewed header to
every selected member and refines its affected caller requirements together,
including transitive callers. The shared revision API takes input names and
explicitly reviewed `consumer/requirement` names; it derives their bindings and
rejects unreviewed requirements before publishing the prepared packages.
Mixing old and new group members is rejected before execution. Local checks can
still use one member with its own declared inputs and services.

For the regrouped selection, use `graphics-state` in place of `graphics-reset`
in the local commands, and accept `graphics-state`, `graphics-blit` and
`graphics-initialize` when updating the source library. The same layout recipe
follows the declared group, so it needs no editing after that regrouping.

This is an explicit representation review. Ordinary implementation edits continue
to use just the component's existing workspace. A change to field meaning,
ownership or lifetime needs corresponding adapter and boundary work; moving field
declarations cannot establish those facts.

To carry the compared group into an existing source library, review its consuming
application/backend bindings and update all affected members:

```sh
spaghetti-extractor candidate export dxball --comparison /tmp/consumer-layout-check \
  --output /tmp/graphics-source --update-components \
  --accept-boundary-change graphics-reset --accept-boundary-change graphics-bind \
  --accept-boundary-change graphics-blit --accept-boundary-change graphics-initialize
make -C /tmp/graphics-source
```

The updater retains operator files and a previous-library backup. Changed header
consumers rebuild; matching compiled neighbors can reuse. Existing program
comparisons must be repeated for changed bindings. The export is a source library,
not a complete game or proof of representation compatibility.

The retained `build/component-layout-handoff-2026-09-24/` trial follows this path
with an existing bind edit and operator notes. The local reset, connected retained-C
consumer and original-x86 consumer all match on `seed-7`; all four selected native
replacements execute under headless Wayland. The source library rebuilds four
objects for the layout change, then none when its comparison provenance is updated
from the native result. It retains the redirected-entry/controlled-services scope.

The subsequent `build/component-shared-inputs-2026-09-24/` handoff uses the
three-component regrouping below, retains an existing reset-loop edit, and moves
the bank fields back to slots-first order. The same local/consumer/native case
and source-library update pass without changing the recipe for that selection.

## Group complete operations

The reset and bind entries may be managed together as `graphics-state`. Both
existing entry points and algorithms remain; the initializer's two services now
select that one supplier. Blit and initializer C stay unchanged. This changes
component ownership, without cutting either operation's control flow or adding
production entry points.

After reviewing the local packages and selected consumer, run [regroup.py](regroup.py)
in the lifting shell:

```sh
python tests/fixtures/dxball-graphics-network/regroup.py \
  PACKAGES CONSUMER /tmp/grouped-graphics
spaghetti-extractor component start dxball graphics-state \
  --comparison-package /tmp/grouped-graphics/graphics-state --output /tmp/state-work
spaghetti-extractor component check dxball graphics-state \
  --comparison-package /tmp/state-work --case seed-7 --output /tmp/state-check
spaghetti-extractor component start dxball graphics-initialize \
  --comparison-package /tmp/grouped-graphics/graphics-initialize --output /tmp/grouped-work
spaghetti-extractor component check dxball graphics-initialize \
  --comparison-package /tmp/grouped-work --case seed-7 \
  --reuse-comparison PREVIOUS_CHECK --output /tmp/grouped-check
```

The local driver exercises reset followed by bind and observes shared state.
The connected driver retains its original calls and observations. A native
`CONSUMER` stays native; run that check inside `spaghetti-headless-wayland`.
The recipe uses existing multi-entry interfaces and the revision API's explicit
dependency removal/reselection. It also revises the representation group's member
list coherently. Original inputs, selected algorithms and caller notes are retained;
the two supplier context type names and their C bridge reflect the new ownership.

Carry the passing selection into the existing source library with explicit review
of its new component, affected boundaries and retired components:

```sh
spaghetti-extractor candidate export dxball --comparison /tmp/grouped-check \
  --output /tmp/graphics-source --update-components \
  --remove-component graphics-reset --remove-component graphics-bind \
  --accept-boundary-change graphics-state --accept-boundary-change graphics-blit \
  --accept-boundary-change graphics-initialize
make -C /tmp/graphics-source
```

Update application/backend includes to use `graphics-state` for both entries and
recheck the consumer. Superseded source files and build objects leave the current
selection; operator notes and a full previous-library backup remain. Conflicting
edits or a caller that still requires a removed supplier reject the update.
No old comparison is promoted to evidence for the regrouped boundary. The same
explicit preparation/export path supports a hand-defined split with new packages;
the walkthrough here demonstrates grouping complete entries, not a general CFG
split/merge proof.

The retained `build/component-regrouping-2026-09-24/` handoff passes the local,
connected host and original-x86 `seed-7` comparisons. The library update preserves
initializer/blit object bytes and mtimes, compiles only the two grouped C files,
and removes the old reset/bind objects. A consumer linked against the exported
archive reproduces the same observations. The original-x86 run uses the lifting
shell and headless Wayland; broader game execution remains outside this example.

## Refactor implementation files within a component

The grouped `graphics-state` component can keep its boundary while moving the
bank-reset loop into a private C helper. Declare the complete authored file set
with `revise_comparison_package(source_files=...)`, including the retained
`bind.c` and `graphics-state.h`, the renamed reset entry and its helper C/header.
Then use the ordinary supplier handoff:

```sh
spaghetti-extractor component status dxball graphics-initialize \
  --comparison-package /tmp/graphics-work \
  --dependency-source graphics-state=/tmp/refactored-state
spaghetti-extractor component check dxball graphics-initialize \
  --comparison-package /tmp/graphics-work \
  --dependency-source graphics-state=/tmp/refactored-state \
  --case seed-7 --history /tmp/refactor-checks
spaghetti-extractor candidate export dxball --comparison /tmp/refactor-checks/latest \
  --output /tmp/graphics-source --update-components --component graphics-state
make -C /tmp/graphics-source
```

Status lists added and retired files. The consumer keeps its adapters, initializer
and blit C; the exported library keeps unrelated build outputs and operator files.
New helper headers can accompany this refactor. Declare implementation-only
headers with `private_headers=["source/helpers/reset-bank.h"]` in the preparation
or revision API so later helper edits remain local. Changing a shared header or
a declared boundary still needs the corresponding review.

The retained `build/component-c-files-2026-09-24/` handoff follows this path.
The existing local and connected `seed-7` cases pass; a wrong count in the helper
is detected, and repair compiles one file while retaining fourteen objects. The
source library rebuilds only the grouped component and can return to the old
consumer through `--dependency-source` with the same boundary and chosen C.

The subsequent `build/component-private-headers-2026-09-24/` handoff classifies the
existing helper header once through explicit `reset`/`bind` requirement refinement
and reviewed source update. Its helper rename and inline helper edit then use
ordinary local/consumer checks and source updates. Editing that header directly
in the exported project also works: a wrong count is detected and repaired,
while the initializer/blit library objects and notes remain intact. The declaration
records the reviewed scope of header use; it is not an isolation proof.

## Compare a workspace selection with the original x86

The optional [native recipe](native.py) accepts each of the four reviewed graphics
packages, including the initializer's selected edited suppliers. It requires no previous passing result
and executes neither side. Continue using the fast host-C
comparison for local editing; use this integration step to compare the same C
with the pinned original instructions. Prepare current packages as above first:
older retained runtimes without the native adapter seam require a fresh package
definition. The recipe preserves the workspace's runtime/services, driver,
cases, interfaces and C. It does not overwrite local adapter edits.

`native.py`, `native-runtime.c` and the retained package can also live together
in an operator directory outside the checkout. The recipe uses the installed
preparation, interception-header and runtime APIs; `component check` calls the
shared PE program helper. No `tests.fixtures` import is needed. The earlier
external handoff in `build/installed-program-helper-2026-09-23/` exercises this
arrangement on `seed-1`; it reuses the reviewed boundary and C.

The recipe uses `revise_comparison_package` to replace the root driver, headers,
tools and runtime inputs. Selected C edits and neighboring components remain in
place; original image selection is explicit. The shared helper derives hashes,
composition and generated headers, and failed revision leaves the destination
ready to retry. The later `build/component-driver-revision-2026-09-24/` handoff
preserves the old recipe's consumed C/adapter/runtime inputs and a local bind edit,
then passes the public native `seed-7` check, unchanged reuse and source export.
This is the existing redirected-entry/controlled-services scope.

```sh
# In nix develop .#lifting, after preparing the connected graphics packages:
python tests/fixtures/dxball-graphics-network/native.py prepare \
  /tmp/dxball-packages/graphics-initialize /tmp/dxball-native-package
spaghetti-extractor component start dxball graphics-initialize \
  --comparison-package /tmp/dxball-native-package --output /tmp/dxball-native
spaghetti-headless-wayland spaghetti-extractor component check dxball graphics-initialize \
  --comparison-package /tmp/dxball-native --output /tmp/dxball-native-check
```

After an edit, use the same public `component check` with
`--reuse-comparison /tmp/dxball-native-check` and a new output directory. Select a
locally edited supplier with `--dependency-package graphics-reset=RESET_WORKSPACE`.
Run related commands in the same headless development environment for reuse.
The ordinary result names the first differing JSON observation and prints a
replay command over its retained inputs. `component status --comparison-result`
inspects it without execution; `candidate export --comparison` exports matching
selected C. There is no separate native bundle, run command or receipt format.

The package declares `program_driver` with the original image, observer DLL name
and export. The shared comparison engine links the observer, adds its import to
the program and binds both artifacts. Compilation caches and observation/service
checks are the same ones used by host-C and native-DLL comparisons.

For an isolated operation, substitute its package and identity:

```sh
python tests/fixtures/dxball-graphics-network/native.py prepare \
  /tmp/dxball-packages/graphics-reset /tmp/reset-native-package
spaghetti-extractor component start dxball graphics-reset \
  --comparison-package /tmp/reset-native-package --output /tmp/reset-native
spaghetti-headless-wayland spaghetti-extractor component check dxball graphics-reset \
  --comparison-package /tmp/reset-native --output /tmp/reset-native-check
```

The same commands work for `graphics-bind` and `graphics-blit`. Each local package
compiles only that unit's authored C and its adapters. It needs no other lifted
component implementation. The original executable still contains the other x86
bodies; the case driver calls the selected entry, and source execution traps all
four original bodies. Shared-state setup and controlled services remain declared
dependencies. Local checks may have an incomplete representation group; assembling
the group still requires compatible layouts and all selected members.

Switching the oracle also changes the recipe's recorded experimental assumptions.
Before selecting a new native unit into an existing caller, inspect the proposed
contract with `component status --dependency-package COMPONENT=WORKSPACE`. Review
and adopt the named requirement with `component start ...
--refine-requirement reset=/tmp/reset-native --output /tmp/refined-caller`, then
check the revised caller. This is a one-time declaration review, not a claim that a stable
signature proves compatibility. Subsequent implementation edits use the same
contract and normal `--dependency-package` selection.

The [independent native walkthrough](native-workflow.py) checks the three local
units, explicitly refines their initializer consumer, edits only reset, reuses
the bind/blit results, checks the actual consumer, detects/replays a memory defect,
and exports/builds the selected C library:

```sh
spaghetti-headless-wayland python tests/fixtures/dxball-graphics-network/native-workflow.py \
  /tmp/dxball-packages /tmp/dxball-local-native-workflow
```

For an external operator project, keep `native-workflow.py`, `native.py` and
`native-runtime.c` together and enter the installed lifting environment. All
comparison inputs are retained beneath the output; no proof or extraction pilot
is rebuilt during the edit sequence.

`build/dxball-independent-native-2026-09-23/` retains the external installed-tool
run: all eight existing cases pass for each of reset, bind and blit, with only its
own authored body compiled and its own entry counter incremented. A reset loop
rewrite passes locally and in the selected successful initializer consumer; only
the changed file compiles. Bind/blit reuse costs **0.469s / 0.511s** with zero new
execution. The missing-slot defect, printed replay, repaired reuse and source
library export/build also pass. The complete command sequence takes **60.708s**.
Preparation and the explicit caller review cost **0.428s / 0.106s** separately.
This reuses the existing driver, transport and compiler facilities without new
tool internals. It does not expand the component network or run normal game entry.

DX-Ball has a fixed image base and no relocation table. The recipe uses the
existing experimental PE import helper, preserving original section bytes,
to load a comparison DLL into the original program. It redirects process entry
to the case driver; **normal game startup is not executed**. The original side
calls the four unchanged x86 bodies, including initialization's real reset/bind
calls. The replacement side traps those original body ranges and runs the selected
portable C. No machine-derived C body is linked into this observer.

The [native C adapter](native-runtime.c) supplies the reviewed initialization
entry frame and translates the same globals, banks, sprite contents and aliases.
Controlled COM/Win32 services reuse the existing C implementation. Shared state
is imported before each service and callback mutations are exported before the
original resumes. Resource identities are normalized for comparison; these are
controlled live objects, not actual DirectDraw resources. Arbitrary callbacks,
concurrency, driver effects and unrelated memory remain outside this boundary.

The earlier `build/dxball-native-components-2026-09-23/final-workflow/` records all 37 existing
cases matching in 10.598s. A public reset edit clearing only 254 slots gives the
same `$.banks[0][254]` discrepancy against actual x86 after the working draft is
repaired. Its native preparation compiles one file and reuses nine objects;
single-case replay takes 4.590s. The fresh host-C comparison also passes all 37
cases. This is a bounded integration step, not another component or graphics
fidelity campaign. Initial native adapter work remains manual.

The current public workflow is retained in
`build/component-program-driver-2026-09-23/`. Using the installed toolkit outside
the checkout, preparation takes **0.315s** and all 37 cases match in **26.597s**.
Selecting the independently edited reset workspace detects the same missing-slot
defect in **6.165s**, compiling one file and reusing nine objects. The printed
replay command still detects it after the working C is repaired (**4.888s**, no
compilation). Restoring the baseline reuses all observations in **0.817s**, with
zero compiler/link/execution/model/solver work. Retained-result inspection and
source-library export/build also pass. These measurements include the explicitly
recorded Wine startup costs; no pilot is rebuilt.

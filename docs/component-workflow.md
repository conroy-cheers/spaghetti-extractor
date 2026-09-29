# Work on one component

The normal loop is: define a boundary, write C, compare, inspect differences,
repair, then run affected consumers and update the source project. Surrounding
code matters when establishing or changing the boundary. Ordinary implementation
edits use the inputs, objects, services and assumptions recorded in the workspace.

The source project may build a Windows executable and retain Windows runtime
dependencies through its recorded service interfaces and C adapters. Completing
a lift does not require a replacement operating-system backend or a non-Windows
port. See the [current delivery scope](current-goal.md).

Component definitions and boundaries are target-specific. Win32/COM execution,
DirectSound integration, platform resource handling and reusable scenario and
observation mechanisms belong to the shared Wine test environment. The sound
bank/setup consumers now use its reusable DirectSound backend. It sees candidate
binaries and platform interactions; the comparison runner owns original/replacement
labels. Other Win32 families still need shared support rather than new bespoke
platform implementations. The [shared environment guide](shared-wine-test-environment.md)
records its authoring API, supported surface, migration and explicit limits.

End-to-end execution must not be the only way to expose a supported class of
semantic errors. Reduce each integration discrepancy to a retained component,
boundary or runtime-service check, using a small connected consumer when state
or lifetime spans operations. Record the inputs, interactions and observation
that distinguish the original and replacement. A missing case is a coverage gap;
inability to express, drive or observe it without the full application is a
boundary or tooling gap. Fix that gap before claiming support for the affected
behavior. A passing full-application rerun alone does not close it. Finite checks
cannot guarantee that no new discrepancy will ever be discovered.

This guide uses existing commands and a small DX-Ball operation. It compares
against recovered machine-derived C with controlled graphics services. It does
not run DirectDraw or the game, and its results are finite experimental evidence.
The [native comparison](../tests/fixtures/dxball-graphics-network/README.md#compare-a-workspace-selection-with-the-original-x86)
and [Hello normal-entry example](../tests/fixtures/hello-program/README.md) show
how to extend validation through original instructions and actual program entry.
The native DX-Ball package uses these same `component start/check/status` commands,
supplier selection, discrepancy replay and source export. Its preparation recipe
changes the oracle and program driver once; subsequent C edits need no separate
native build/run script. It accepts reset, bind and blit separately as well as
their initializer consumer. Local native checks require only the selected unit's
C and declared state/services. Wine checks run inside `spaghetti-headless-wayland`.
Hello's normal-entry package now uses this public loop too, preserving the actual
arguments and comparing exit status, raw output and reported allocation/TLS state.
An untouched-original run checks that the observer preserves visible behavior.
Prepare the program adapter once; local edits and program replay then use the same
commands and retained results as component checks.
Program packages can name several independent entry components. Their selection
is separate from caller requirements; editing any selected entry reruns the
affected program comparison. The Hello guide demonstrates this with quoting and
string conversion, using one observer and the same public commands.

## Prepare once

If you received an experimental package, reopen a selected component by name:

```sh
spaghetti-extractor component start TARGET COMPONENT \
  --experimental-package EXPERIMENT --output build/component-work
```

This restores its retained boundary, original adapter, C, cases and editor guides.
It prints a check command with the matching comparison already selected for reuse.
When a separate local setup is available, it also prints the command to return
the edited component to the program. Original preparation
folders are unnecessary. The workspace is an editable draft; opening it does not
compile, run or qualify code. `--reuse-source` and `--dependency-package` work as
with an ordinary comparison package.

Reopening the experiment's main component restores its program/network workspace.
A unit supported only by network evidence opens for editing inside that existing
selection, with editor commands and a guide focused on its C. The printed check
still names the program/network entry; independent checks need a local driver,
oracle and cases. The opening message makes that scope explicit.
All Wine checks must still run inside the headless desktop described below.

From the repository root, enter `nix develop .#lifting`. The shell supplies the
installed toolkit, Python and C compilers. For an external operator project use
`nix develop /path/to/spaghetti-extractor#lifting` instead.

Use an already retained pinned `DXBall.exe`, or obtain it once:

```sh
nix build --out-link build/dxball-original-input \
  ./targets#legacyPackages.x86_64-linux.targets.dxball.input.original
```

Prepare the reviewed example without a previous comparison result or a proof
build. Substitute your retained binary path if applicable:

```sh
python tests/fixtures/dxball-graphics-network/prepare.py \
  build/dxball-original-input/DXBall.exe build/graphics-packages
spaghetti-extractor component start dxball graphics-reset \
  --comparison-package build/graphics-packages/graphics-reset --output build/reset
spaghetti-extractor component status dxball graphics-reset --comparison-package build/reset
```

The recipe checks the binary identity and recovers the reviewed original bodies.
It prepares four connected components; the workspace above is for one of them.
This is a prepared-example rehearsal. Defining your own boundary is described
below; it does not require extending the checker or editing generated hashes.

Open these files in your editor:

| File | Use |
|---|---|
| `build/reset/source/reset.c` | Edit the portable implementation. |
| `build/reset/generated/workspace.md` | Review inputs, shared objects, services, outcomes, assumptions, cases and links to adapter C. |
| `build/reset/source/graphics-state.h` | Inspect the shared representation; changing it is a boundary change. |
| `build/reset/AUTHORING.md` | Read the supported C dialect and alternatives for restricted constructs. |
| `build/reset/compile_commands.json` | Give your editor the component's compiler and include paths. |

Generated headers are refreshed by the toolkit. Edit your C and reviewed authoring
inputs; generated guide text does not change the boundary. Run `component status`
again to inspect current source and declarations without compiling or executing.

For a connected workspace, list the selected components and inspect one by name:

```sh
spaghetti-extractor component list dxball --comparison-package build/graphics-work
spaghetti-extractor component status dxball graphics-blit \
  --comparison-package build/graphics-work
```

The default overview shows that component's C and shared-input files, operation
signatures, service-to-supplier/adapter mappings, outcomes, caller requirements,
assumptions and unobserved behavior. It gives a few examples and the appropriate
check command. It omits repeated source-navigation candidates, full fingerprints
and the complete case list, keeping an ordinary local edit readable as the network
grows. Add `--details` for the full current boundary, lifecycle/effect declarations
and source navigation; the generated workspace guide remains the full snapshot.
Its refresh command keeps the same component selected. Both views and the listing
use local inputs; neither builds target products nor runs a case. Edit/reuse and
proposed-contract previews remain visible in the overview when requested.
With `--json`, the view identifies the package entry as `component_id` and the
inspected unit as `selected_component_id`; `units` retains the full selection.
Caller requirements are also available in each unit's `consumers` list.

Open a selected supplier for editing by using the same component name on start:

```sh
spaghetti-extractor component start jq value-get \
  --comparison-package build/path-work --output build/getter-edit
```

The workspace retains the existing network, adapters and cases. Start prints the
getter's C paths and boundary guide, prepares editor commands for that component,
and prints a check using the same component name:

```sh
spaghetti-headless-wayland spaghetti-extractor component check jq value-get \
  --comparison-package build/getter-edit --history build/getter-checks
```

This runs the enclosing `path-set` selection. No separate local
fixture is needed to begin editing and checking through that consumer. This does
not create an independent getter comparison or change the package's entry identity.
Text output identifies that consumer; JSON receipts, replay commands and history
reuse retain its identity. Switching between a selected supplier name and the
entry name does not change the cases, observations or eligible reuse. Unknown
component names are rejected before execution.
Use the local setup below when independent cases are required.

To reopen the current consumer with only that component's edited C:

```sh
spaghetti-extractor component start jq value-get \
  --comparison-package build/path-work --reuse-source build/getter-edit \
  --output build/getter-next
```

In a supplier-focused start, `--reuse-source` uses
the existing C-only handoff: unrelated caller/supplier edits in the source workspace
are not imported, and boundary changes still require explicit refinement. The
same behavior is available from `--experimental-package` when a selected component
has no retained local comparison; a retained local setup remains the preferred
choice when one exists. The output identifies which check scope was opened.

The driver, examples and any reuse preview still describe the enclosing package.
The view prints its consumer check command; it does not claim that a network
comparison independently checked the selected supplier. A separate local check
uses the setup described below. Selected caller names such as `path-get/get` are
also the names used when explicitly reviewing a changed supplier requirement.

Once you have a baseline result (see [Edit and diagnose](#edit-and-diagnose)),
add it after an edit to see changed C, adapters and contracts,
affected consumers in this selection, and compiled-file cache eligibility:

```sh
spaghetti-extractor component status dxball graphics-reset \
  --comparison-package build/reset --reuse-comparison build/reset-baseline
```

Use the same `--case NAME` as the intended check; both default to all cases.
`--dependency-package COMPONENT=DIR` includes a proposed compatible supplier or
exported C draft in this preview. The command reads current inputs and retained
evidence without compiling or executing. It uses the checker's actual snapshot,
compiler-dependency and reuse rules. Changed compiler settings may invalidate cached
objects even when a neighbor's source and contract are unchanged; those findings
are shown separately. Desktop connection changes alone preserve compiled objects,
while runtime observations are checked again. The check still validates the source
profile and any selected formal checks. Separate program integration may need its own rerun, and
a consumer result does not establish independent local assurance for its neighbors.

Contract previews show declaration-level changes, including named operation inputs,
types, nullability, service/resource rules and caller requirements. Parameter and
record-field order changes stay visible even when every name and C type is the same.
Interface files and exact hashes remain linked; `--json` retains full old/new values
and their `declaration_changes`. These are differences to review, not a compatibility
verdict. A selected-supplier revision that needs caller review prints the proposed
changes alongside the missing requirement names before publishing any workspace.

## Add a local check to an existing experiment

A handed-off experiment may contain a component with only network-level evidence.
Prepare its local adapter and cases using the same boundary and selected C. For
the DX-Ball example above, the existing recipe already prepares an independent
`graphics-bind` setup:

```sh
spaghetti-extractor component start dxball graphics-bind \
  --comparison-package build/graphics-packages/graphics-bind --output build/bind
spaghetti-extractor component check dxball graphics-bind \
  --comparison-package build/bind --output build/bind-check
spaghetti-extractor candidate build dxball \
  --experimental-comparison EXPERIMENT/comparison \
  --reuse-experimental EXPERIMENT \
  --component-comparison graphics-bind=build/bind-check \
  --output build/experiment-with-bind
spaghetti-extractor component start dxball graphics-bind \
  --experimental-package build/experiment-with-bind --output build/bind-next
```

The new experiment retains that local setup and prints the ordinary edit/check
commands when reopened by name. Packaging reuses the existing program binary,
policy and unchanged neighboring receipts. It checks that the local result covers
the exact selected implementation and boundary. When those inputs are unchanged,
adding local evidence needs no new program comparison. After a C or boundary edit,
supply the corresponding new program comparison instead of `EXPERIMENT/comparison`.

If the original local package is unavailable, use
`comparison_environment.retained_component_inputs` with the network workspace
or an experiment's `comparison/inputs` directory. It carries the selected unit's
boundary, shared headers, service configuration and C into the existing preparation
API. A supplier-focused `component start` now writes an editable recipe beside
that unit, at `<workspace>/dependencies/<component>/prepare-local.py`.
Fill in its `local_fixture()` with the local adapter files, original entry,
cases, observations and scope, then run it in the lifting shell:

```sh
python build/getter-edit/dependencies/value-get/prepare-local.py \
  --output build/getter-local-package
```

The recipe reuses the current unit's interface, C, shared headers, services,
assumptions, declared supplier closure and the workspace's execution environment.
It does not inherit the caller's cases or produce evidence. Additional adapter
headers have explicit names; replacing a retained shared header needs deliberate
boundary refinement. The script stays editable and reopening that workspace
preserves it. It lives outside compiler include/source inputs, so editing this
setup recipe alone does not invalidate the consumer comparison. A prepared local
package is still checked and integrated through the ordinary public commands.

The [authoring example](components.md#author-a-new-comparison-boundary) shows
the explicit local driver/oracle/case inputs. The reviewed DX-Ball blit setup can
be prepared directly from a retained-C initializer network:

```sh
python tests/fixtures/dxball-graphics-network/prepare-local.py \
  build/graphics-work build/blit-local-package
spaghetti-extractor component start dxball graphics-blit \
  --comparison-package build/blit-local-package --output build/blit-local
spaghetti-extractor component check dxball graphics-blit \
  --comparison-package build/blit-local --history build/blit-local-checks
```

Subsequent C edits return to the network with
`--dependency-source graphics-blit=build/blit-local`. Existing supplier requirements
stay explicit; the helper does not silently flatten or discard them.

For a component that calls other selected components, pass
`retain_dependencies=True` to the helper. It selects the existing supplier bodies
and adapters from this same network through their declared requirements. It keeps
shared suppliers once, preserves their current edits and retains relevant declared
recursion groups. It does not require the suppliers' old preparation directories.
The reviewed jq getter recipe demonstrates this handoff:

```sh
python tests/fixtures/jq-path-network/prepare-local.py \
  build/jq-path-work build/getter-local-package
spaghetti-extractor component start jq value-get \
  --comparison-package build/getter-local-package --output build/getter-local
```

Run its printed check command inside the headless Wayland desktop. Return an edit
to the path consumer with `--dependency-source value-get=build/getter-local`.
The selection follows declared requirements, not inferred C calls. Local checking
still uses the explicitly chosen driver, original implementation and observations;
shared representation groups can remain incomplete until program assembly.

The local fixture still needs operator-defined inputs, state transport, services
and observations; a network receipt cannot manufacture them. The earlier example reuses
the reviewed retained-C fixture, while its program receipt compares against the
original x86. Those evidence scopes remain distinct. The installed handoff at
`build/component-network-local-2026-09-23/` exercises these commands without
changing tool internals or rebuilding a pilot.

## Edit and diagnose

For ordinary repeated edits, run the same command after each C change:

```sh
spaghetti-extractor component check dxball graphics-reset \
  --comparison-package build/reset --history build/reset-checks
```

To resume an existing result, `component start TARGET COMPONENT
--comparison-result RESULT --output WORK` prints a repeatable history command
with `--history-baseline RESULT`. The first check can reuse that retained work;
later checks reuse the history's newest result. The initial result's location is
no longer needed once the history has a completed check. Opening an experimental
package uses the same handoff. The generated `AUTHORING.md` keeps this command
beside the editable C.

Each run creates a separate retained comparison and automatically supplies the
previous completed result for reuse. The normal input, contract, compiler and
execution checks still decide what can reuse. `build/reset-checks/latest` points
to the newest completed result, including a mismatch or compiler failure; it does
not mean passing. Inspect it with `component status --comparison-result`, or use
it with source export after a match. The check prints its specific retained path,
and replay commands use that path so a later check cannot retarget a discrepancy.

Keep history outside the editable package. A preparation error leaves `latest`
unchanged; completed compiler failures retain eligible objects for the repair.
Checks sharing one history serialize through a process lock; a second invocation
reports that the first is still running. `--rerun` requests fresh execution, and
`--reuse-comparison RESULT` explicitly overrides the automatic previous-result
choice, including an initial `--history-baseline`. A stale or invalid latest
result is reported rather than silently replaced with the initial baseline.
Case selection, supplier selection and optional checks use their usual
flags. For Wine, run this same command inside the headless lifting shell.

For explicitly named results, the equivalent steps are below.

Establish the existing comparison first:

```sh
spaghetti-extractor component check dxball graphics-reset \
  --comparison-package build/reset --output build/reset-baseline
```

The operation clears 255 sprite slots and a count in each of three banks, while
preserving adjacent state. As a diagnostic exercise, change `slot < 255` to
`slot < 254` in `source/reset.c`, then check the edit:

```sh
spaghetti-extractor component check dxball graphics-reset \
  --comparison-package build/reset --reuse-comparison build/reset-baseline \
  --output build/reset-wrong
spaghetti-extractor component status dxball graphics-reset \
  --comparison-result build/reset-wrong
```

The check exits with a mismatch and identifies a bank slot that was left uncleared.
It retains both observations and prints a replay command. Normal-program output
differences also show an escaped byte excerpt and its offset; line endings and
target-encoding bytes are preserved. State differences retain their structured
context and observer-report links. `status` inspects that
saved result without rerunning it. Restore `255` in the editable C, then execute
the printed replay command: it must still show the defect from the retained wrong
inputs. Replay preserves the original case selection and order, including earlier
suite setup, and reuses eligible compiled objects.

When whole-program execution exposes a discrepancy, reduce it to a retained
component, boundary or small connected-consumer case. Capture the relevant
input bytes, aliases, lifetime, shared state and ordered interactions; the
regression must reproduce the defect before the fix and pass afterwards without
starting the full application. Check observer and adapter failures the same way.
The [DX-Ball damage example](dxball-damage-continuation.md) reduces an unbound
surface observation failure to a local startup case.

When a provider retains a shared object, adapters must also preserve fields the
component did not change. Keep a baseline for the last imported C view separately
from snapshots used for observation, and publish only changed fields. Copying a
whole cached header back during a callback can overwrite provider updates to
private queue links. The [MDS stream example](dxball-mds-stream-continuation.md)
reproduces that transport error in a local provider-interleaving case. This is
field preservation, not a substitute for synchronization when both parties write
the same field; such interactions need an explicit boundary and schedule.

Include environmental inputs in that reduction. Clocks, random choices, external
state and callbacks can change an otherwise correct component's outputs. Supply
corresponding inputs to both sides and observe their order, arguments and results;
do not discard differing application output to hide unequal inputs. The
[gameplay example](dxball-gameplay-continuation.md) connects the actual native
paddle helper to either frame implementation without starting the game. It
reproduces a live drawing difference with unequal random inputs, identifies the
input divergence before the graphics effect, and matches all four sprite choices
when inputs correspond. Its normal-game check explicitly controls that helper's
clock/random boundary while retaining the application state and pixel comparisons.

The [brick/effect continuation](dxball-brick-actions-continuation.md) applies this
to two more environment dependencies: random pickup creation and the frame's
palette deadline. Small consumers execute the actual native helpers, compare
their memory and service effects, and deliberately vary inputs to reproduce the
integration differences. Supplying equal inputs resolves the comparison without
changing lifted behavior or removing application observations. This reduction is
manual operator work using ordinary adapters; automatic extraction is not required.

A newly discovered input is a coverage gap. An interaction or state that cannot
be expressed or executed locally is a tooling gap, and should be addressed before
continuing that lift. Ordinary edits must not depend on access to a runnable
whole target. Integration tests can discover new cases; finite local comparisons
cannot promise that no unseen case will ever differ.

Input drivers and observers should follow retained component boundaries too.
The [DX-Ball application shell](dxball-application-continuation.md) exposed a
controller that counted an instruction inside the original WinMain. Replacing
WinMain bypassed that instruction and stalled the test's input schedule. Counting
outer frame calls through entry/return boundaries restored the same workload
without changing the lifted C or dropping observations. The independent shell
consumer covers setup failure, termination, message errors and callback-driven
cleanup that this workload does not reach. Harness implementation assumptions
must not become hidden requirements on the replacement's internal control flow.

The [display initializer](dxball-display-continuation.md) similarly inlines a
private destination-binding store. Its normal observer reads the actual binding
at component completion instead of requiring a call to the old helper. Such a
projection must preserve the observation's timing and read actual state; it must
not insert the expected result. Independent cases trap native helper fallback,
and a deliberately wrong store is diagnosed locally. Observers should remain
valid when private helpers are inlined or reorganized within the agreed boundary.

Use connected checks before whole-program execution when a boundary shares
mutable objects with its caller. The [ball-motion example](dxball-ball-motion-continuation.md)
connects two gameplay frames to actual movement, allocation and removal over the
same records. Its standalone consumers replay native-derived observations on
x86-64 and AArch64 without the game, Wine or a graphics backend. A runnable
whole target is not required for ordinary implementation edits.

An adapter that publishes only changed fields must retain the exact values used
to populate its C view as the write baseline. Reading provider-owned fields again
can misclassify a concurrent provider update as a C edit and overwrite it. The
[MDS stream cases](../tests/fixtures/dxball-mds-stream/README.md) reproduce both
provider updates after a callback and updates during view capture locally.

Normal PE program comparisons capture the application's Windows stdout/stderr
handles before its entry and TLS execute. Wine and host-library stderr remains
in `cases/NNNN-SIDE.host.stderr`; `.stdout` and `.stderr` retain the application
bytes. Generated service and resource instrumentation is streamed separately to
`.trace`, with its own 64 MiB bound; it does not consume the application streams'
8 MiB limits. The capture recognizes the existing reserved `SPX_SERVICE`,
`SPX_SERVICE_SCOPE`, `SPX_SERVICE_HANDLER` and `SPX_RESOURCE` line prefixes,
including when pipe reads split a prefix. No Wine warning text is filtered.
Both the untouched-original control and the selected replacement use this capture,
as do experimental candidate runs built from these results. The launcher and
completion report, trace bytes and existing service/resource checks are bound
alongside the evidence. Missing, truncated or overflowing capture cannot fall
back to mixed output or pass as empty application output. Older retained
comparisons and their retained launchers keep their original stream interpretation.

This observes redirected standard streams, not console screen buffers,
`OutputDebugString`, frames or audio. The existing process observer bounds each
stream at 8 MiB, requires inherited pipes to close within the case deadline, and
owns descendant cleanup. Programs needing interactive consoles or longer-lived
child processes need an appropriate execution adapter.

Declare writable application data in the normal program driver's `process`:

```json
{
  "exit_codes": [0],
  "mutable_files": ["state.dat", "output.bin"]
}
```

An existing `runtime_files` entry with that filename supplies its initial bytes;
otherwise the file starts absent. Each comparison side gets private copies, and
changes persist between cases in their declared order. Replay starts from the
retained initial inputs. Program images and libraries remain immutable. Files not
declared mutable remain checked inputs, and unexpected new working files fail.

After each run, the runner compares declared files' presence, size and content
hashes alongside application output and reported state. This includes the
untouched-original control, so observer-induced file changes are detected too.
Exact bytes live in `cases/NNNN-SIDE.files/`; `.files.json` records presence and
hashes. These snapshots enter the existing result binding and reuse path, and
experimental candidate runs use the same observation rules. An empty file differs
from an absent file. A changed file produces a difference under `$.files` even
when application stdout, stderr and exit status agree.

This uses the current flat runtime layout: ordinary filenames directly in the
working directory, matched without case distinctions, with at most 64 MiB per
observed file. Subdirectories, file metadata, registry state and external paths
are outside this observation boundary. `tmp` remains private scratch space.
Working-file validation failures retain a comparison result and identify unexecuted
sides/cases instead of discarding the partial run.

Every semantic discrepancy discovered in a full application run should become a
retained local regression at its responsible component, boundary or runtime
service. Preserve the triggering inputs, relevant shared state, interaction order
and observations. Reproduce the difference against the original entry bodies and
the replacement without needing the full application workflow. Shared objects,
callbacks and teardown can require a small connected consumer spanning several
operations; a single function test is not always an adequate boundary.

A previously untested input or interaction is a coverage gap when the existing
local facilities can express and execute it. If they cannot represent the state,
drive the interaction or observe the difference without the full application,
treat that as a tooling or boundary-definition gap. A passing end-to-end rerun
alone does not close it. Keep discovered cases available to targets without an
automatable UI or representative full-program workload. This is a practical
regression requirement, not a claim that finite tests discover every possible
defect or establish formal equivalence.

Boundary review should also look for inputs that normal execution happens to
hide. A native read before initialization can make old stack or heap contents
observable. Perturb those bytes in a retained local case while keeping the
declared inputs fixed; differing observations expose an incomplete boundary.
Represent the relevant bytes explicitly and identify their producer before
claiming composition. A replay adapter that seeds the bytes demonstrates local
diagnosis, but does not establish their transport after callers are recompiled.
The [DX-Ball warning investigation](dxball-warning-boundary-investigation.md)
records this distinction using actual native operations, without a game run.

The [queued-event refinement](dxball-event-memory-continuation.md) follows those
inputs through live memory aliases, wrapped coordinates, callbacks and expiry in
a small connected consumer. Its deliberate wrong-memory-write case is diagnosed
locally and its source consumers run without the original program or Wine.

For a runtime failure or timeout, feedback lists each side's exit status and
whether another side was not run. It names the last parsed source service event
when available and shows a short stderr tail with a link to the complete log.
Instrumentation records are omitted from that excerpt, not from retained evidence.
The last event provides trace context; an incomplete observation still needs
diagnosis and is not reported as a completed value comparison. The same feedback
is available through `component status --comparison-result` without execution.

To see which retained cases observed a selected component's service scope, name
that component inside the consumer result:

```sh
spaghetti-extractor component status jq array-indexes \
  --comparison-result build/path-check
spaghetti-extractor component status jq array-indexes \
  --comparison-result build/path-check --case program-array-indexes --json
```

This compact view lists case inputs, consumer/resource outcomes, source scope
observations and trace paths. It can show that a passing consumer case observed no
scope for the component being edited. A shared service catalog is identified as
ambiguous; absent or incomplete instrumentation cannot establish whether the
component ran. Scope starts record adapter activity, not operation counts or
branch coverage. Use the observations to choose relevant examples and inspect
their inputs, while keeping the boundary's other cases available.

Add `--details` to obtain the same view for the comparison entry. `--case` filters
only this display; the printed replay command keeps the original consumer, case
selection and order. The boundary command opens the selected unit's retained
interface and adapters. Inspection performs no compilation or execution. Focused
JSON is an inspection view; entry inspection without `--details` or `--case`
continues to return the original receipt with `--json`.

Give adapter precondition failures a concrete origin. The DX-Ball adapter's
private check wrapper reports the condition, relative source file, line and C
function, for example `adapters/runtime.c:119 (dx_caps): state->initialized==1 && state->capability_mode==0`.
The existing stderr feedback displays this directly; no checker extension or new
observation format is needed. Follow that location in the retained comparison's
`inputs/` when diagnosing or replaying it. The
[C implementation](../tests/fixtures/dxball-graphics-network/runtime.c) captures
`__FILE__`, `__LINE__`, `__func__` and the condition text while evaluating the
condition once. Keep implementation diagnostics private where possible so
improving a message does not require redefining shared component contracts.

Check the repaired workspace with a new output directory:

```sh
spaghetti-extractor component check dxball graphics-reset \
  --comparison-package build/reset --reuse-comparison build/reset-baseline \
  --output build/reset-repaired
```

The result reports actual compilation, execution and reuse. Keep each result
directory: its `inputs/`, observations and receipt make edits and failures
replayable. Restored or unchanged inputs can reuse prior observations; add
`--rerun` when you want fresh execution. Changed tools or environment may require
revalidation. Do not use a copied result or a matching function signature as
evidence for changed assumptions.

The normal report leads with the outcome and actual work, then names invalidation
reasons, changed units and failures. Unchanged neighbors and contract bindings are
summarized. Follow its `boundary details` command to inspect the focused component's
retained interface, assumptions, services and callers. Full receipts remain available
without another run through `component status TARGET ENTRY --comparison-result
RESULT --json`; use the comparison entry name for that receipt. A selected supplier
still has consumer evidence unless checked through its own local comparison.

For a compiler error, repair your editable workspace and pass the failed result
to `--reuse-comparison` on the next check. Successful compilations and still-valid
neighboring objects are retained even if the first edited file fails. The repair
recompiles affected files, links and runs the selected cases. Compiler failure
supplies no matching behavior to reuse. The failure report prints this recovery
hint, and `component status --reuse-comparison FAILED_RESULT` previews eligible
objects before retrying.

These DX-Ball checks use host C. Any comparison that uses Wine must run inside
`spaghetti-headless-wayland`, for example:

```sh
spaghetti-headless-wayland spaghetti-extractor component check TARGET COMPONENT \
  --comparison-package PACKAGE --output build/check
```

The desktop includes a private software audio device, so Wine's audio APIs work
without host sound hardware or a user audio service. Desktop/audio diagnostics
stay separate from captured application streams. Closing the desktop stops both
services. This environment tests API behavior and buffer contents; it does not
measure audible output or hardware timing.

For repeated checks, run `spaghetti-headless-wayland --interactive bash` in an
interactive terminal and keep the sequence in that shell. It provides a terminal
with live output, job control and resizing. Ctrl-C interrupts the foreground job;
`exit` closes the desktop. Interactive stdout and stderr share the terminal; omit
`--interactive` when separate captured streams are needed by a script.
Refresh an older pinned lifting profile with the profile command below to obtain
this option. A new desktop/session can invalidate cached execution evidence, but
its display/audio connection variables no longer force unchanged
C files to recompile. Pass `--reuse-comparison PREVIOUS_RESULT` to retain eligible
objects across desktop launches and fresh `lifting` shells. Outside pure Nix
builds, the compiler uses its default temporary directory instead of inheriting
the shell's disposable directory variables. Pure builds retain those variables
for Nix's input-path filtering. Compiler flags and other build inputs still
invalidate affected compilation; runtime evidence still tracks the full execution
environment. Use the `lifting` development shell for these runs.

The compiler and linker also run without the operator launcher's `PYTHONPATH`,
`PYTHONHOME`, `PYTHONHASHSEED`, `PYTHONNOUSERSITE` and `PYTHONDONTWRITEBYTECODE`.
Moving the toolkit's Python import path alone therefore preserves eligible C
objects. Runtime comparisons still receive those settings and rerun when the
execution environment changes. A compiler wrapper that uses Python helpers must
supply their import environment itself. Other toolchain inputs remain tracked.

The compiler and linker also omit `SHLVL`, the shell-nesting counter. Running
through another shell or redirecting a command's output therefore does not make
that counter a new compiler input. Runtime processes still inherit and fingerprint
it normally.

When updating the toolkit during component work, retain the Nix development
environment separately. From the checkout root, create the profile once:

```sh
nix develop --profile build/lifting-environment .#lifting --command true
```

Use that profile for later checks from the same checkout:

```sh
nix develop ./build/lifting-environment --command spaghetti-headless-wayland \
  python -m spaghetti_extractor component check TARGET COMPONENT \
  --comparison-package WORKSPACE --history CHECKS
```

Replace the uppercase names with your component and directories. The shell hook
makes `python -m spaghetti_extractor` load the current checkout while the profile
retains its compiler, Python/native dependencies and Wine environment. The shell's
installed `spaghetti-extractor` executable remains the version captured by the
profile. Refresh the profile deliberately with the first command when changing
toolchains or dependencies; Python-only toolkit edits need no profile refresh.

Fresh `.#lifting` environments are stable for an unchanged toolkit. Re-evaluating
the shell after a toolkit package update also changes its compiler flags and
search path, which legitimately invalidates the exact compiler fingerprint.
Retaining the environment avoids that coupling. In the retained jq trial, switching
toolkit versions and editing one supplier compiled one file and reused 35 objects
across fresh headless desktops. Runtime observations still reran. Flags, tools,
consumed headers and other actual compiler inputs retain their existing checks.

## Try another input

You can try inputs supported by the existing driver without editing a package
or rebuilding its preparation recipe. For this example, use seed 42 with the
driver's ordinary six-argument service scenario:

```sh
spaghetti-extractor component check dxball graphics-reset \
  --comparison-package build/reset --case seed-42 \
  --case-arguments '["42","0","0","1","0","0"]' \
  --reuse-comparison build/reset-repaired --output build/reset-input-42
```

This runs one case from fresh runtime state. The result's `inputs/` retains its
definition alongside the existing cases, so printed replay works normally. The
editable workspace stays unchanged. An existing case name with different arguments
is rejected; use a new name. Arguments still need to obey the driver's convention
and the boundary's admitted inputs; this option supplies neither new transport
nor missing setup.

To keep inputs for future suite checks, start from your current workspace and
import the saved case definitions. A result containing a discrepancy is useful
here too; your current C and neighboring implementations stay selected:

```sh
spaghetti-extractor component start dxball graphics-reset \
  --comparison-package build/reset --reuse-cases build/reset-input-42 \
  --output build/reset-expanded
spaghetti-extractor component check dxball graphics-reset \
  --comparison-package build/reset-expanded --reuse-comparison build/reset-input-42 \
  --output build/reset-expanded-check
```

Repeat `--reuse-cases DIR` to collect cases from several results or comparison
packages. Existing cases keep their order; new cases append in import order.
Identical names and arguments coalesce, while a name with different arguments
is rejected: give that input a distinct name before importing it. The inputs must
belong to the same target and comparison entry, including when editing a supplier
through a consumer's workspace.

To import hand-written or generated inputs directly, save a JSON list such as
`operator-cases.json`:

```json
[
  {"id": "operator-seed-42", "arguments": ["42", "0", "0", "1", "0", "0"]},
  {"id": "operator-seed-99", "arguments": ["99", "0", "0", "1", "0", "0"]}
]
```

Then open a workspace containing those cases:

```sh
spaghetti-extractor component start dxball graphics-reset \
  --comparison-package build/reset --case-file operator-cases.json \
  --output build/reset-cases
```

Run the printed `next:` command to check the expanded suite. Repeat `--case-file`
for more files; each must contain a nonempty list with distinct case names and
string arguments. Existing cases come first, followed by `--reuse-cases` imports,
then case files in their supplied order. Identical definitions across these
sources coalesce; conflicting names are rejected before publishing the workspace.
Arguments are copied into the workspace, so later checks and replay do not need
the original JSON files. C, driver and boundary remain selected as before.

You can also use `--comparison-result RESULT` with either import option. Its
printed command checks the entire expanded suite, even when the saved result
checked just one case, and seeds the new check history with that result for reuse.

Only argument definitions are imported. The current driver, boundary and
assumptions determine how to interpret them; review those if the setup has
changed. Observations, old C and assurance status are not imported. The suite
reruns because its case selection changed; eligible compiled objects can reuse.
Suite order matters when earlier cases create runtime state. Collect any needed
setup cases as well and check their order in `generated/workspace.md`.

## Exercise consumers and export

The initializer consumes reset, so check it with your selected workspace:

```sh
spaghetti-extractor component status dxball graphics-initialize \
  --comparison-package build/graphics-packages/graphics-initialize \
  --dependency-package graphics-reset=build/reset
spaghetti-extractor component start dxball graphics-initialize \
  --comparison-package build/graphics-packages/graphics-initialize \
  --dependency-package graphics-reset=build/reset --output build/graphics-work
spaghetti-extractor component check dxball graphics-initialize \
  --comparison-package build/graphics-work --output build/graphics-checked
spaghetti-extractor candidate export dxball --comparison build/graphics-checked \
  --output build/graphics-source
make -C build/graphics-source
```

Status previews contract differences. Start retains the selected suppliers in
the caller workspace without executing them; checking runs that selection without
needing to repeat the dependency flags. The selection is a snapshot. To import a
later supplier edit, start another workspace with `--dependency-package` and
`--reuse-source build/graphics-work` to preserve caller edits, or select it on a
check directly. Changed contracts require explicit boundary refinement; an
unchanged declaration alone does not establish the new body's correctness.

For an ordinary implementation edit, import only the named supplier's C:

```sh
spaghetti-extractor component check jq path-set \
  --comparison-package build/path-work \
  --dependency-source value-get=build/value-work --history build/path-checks
```

`--dependency-source` also works on start and status. The source can be a local
component workspace, another network workspace containing that component, or an
exported source project. Only the named unit's authored C is imported; the
consumer retains its adapters and other selected implementations. This matters
when a middle component's workspace still contains old suppliers or unrelated C
under edit. Contract declarations and existing boundary headers must
match the consumer's reviewed boundary. Changes to shared headers, layouts,
services or assumptions use boundary refinement. Check the affected consumer after the
import; a C draft supplies no independent assurance by itself.

For ordinary file refactors, name the changes when starting the next draft:

```sh
spaghetti-extractor component start jq value-get \
  --comparison-package build/path-work \
  --source-file source/accessor.c=edited/accessor.c \
  --source-file source/helpers/relative-index.c=edited/relative-index.c \
  --source-file source/helpers/relative-index.h=edited/relative-index.h \
  --remove-source source/get.c \
  --private-header source/helpers/relative-index.h \
  --output build/path-refactored
```

Names include `source/` and are relative to the focused component, without its
`dependencies/COMPONENT/` prefix. Repeat `--source-file` to add or replace files;
`--remove-source` retires listed authored files from the new draft. Unchanged
authored files, boundary headers, adapters, cases, notes and neighboring C stay
selected. The command updates file inventories and editor inputs without running
a compiler. Checking and source publication remain separate steps.

Keep listed original files in a comparison workspace until the tools retire
them. You may write new files beside the current C and explicitly
adopt each with `--source-file source/NAME=PATH_TO_THAT_FILE`; its bytes must still
match the copied draft. Unlisted files are never picked automatically, and files
from elsewhere cannot overwrite unowned workspace files. With `--reuse-source`,
these edits apply to the imported file selection. In an exported source project,
you may physically rename or delete an implementation file first, then name its
retirement with `--remove-source`; public/shared headers must remain intact.
Interface-only authoring also supports these file options before a comparison
inventory exists.

`--private-header` classifies new helper headers. Existing header roles are
retained, so this cannot reclassify or change shared/boundary headers. Use the
reviewed boundary-refinement API for those changes. Select the imported body with
`--reuse-source` when combining it with focused file edits. The existing
`revise_comparison_package(source_files=...)` API remains available for replacing a
complete authored file set. No command requires editing derived hashes by hand.

Declare implementation-only headers when preparing the component with
`private_headers=["source/helpers/reset-bank.h"]`. Their contents can then change
with ordinary C edits, including from an exported source workspace. The guide
lists these headers separately. Other authored headers remain boundary inputs.
Shared representation and original-oracle inputs cannot use this private role.
This records the operator's analysis of header use; it does not prove isolation
from every possible external consumer.

For an existing component, use `revise_comparison_package(private_headers=[...])`
and explicitly refine the affected caller requirements once. Changing a header's
role cannot happen through a C-only import. An existing source library similarly
needs `--accept-boundary-change COMPONENT` for that role change. Subsequent edits
to the declared private headers use the ordinary check and source-update commands.

Use `--dependency-package` when you intend to select the supplied package's
adapters and bundled suppliers together. An explicit `--dependency-source` for
another named component takes precedence over its bundled body, under the same
contract checks as other explicit choices. Each component may be named by only
one of these options. New workspaces reopened from an experiment print the C-only
handoff command for ordinary local edits.

The exported component's README now records the comparison entry used for its
examples. Its generated commands open that component for editing, check the
recorded entry (which may be a caller), and publish only the edited component.
Use the retained comparison's `inputs/` or its writable workspace as the local
package. If choosing a different caller setup, use the check command printed by
`component start`. Older exports without entry metadata also direct you there.

If you edited a supplier directly in the exported C project, the same selection
option accepts that source project:

```sh
spaghetti-extractor component status dxball graphics-initialize \
  --comparison-package build/graphics-work \
  --dependency-package graphics-bind=build/graphics-source
spaghetti-extractor component start dxball graphics-initialize \
  --comparison-package build/graphics-work \
  --dependency-package graphics-bind=build/graphics-source \
  --output build/graphics-from-source
spaghetti-extractor component check dxball graphics-initialize \
  --comparison-package build/graphics-from-source --output build/graphics-source-check
```

Only the named supplier's authored C is imported. Its interface, shared headers
and assumptions must match the consumer's existing boundary; its adapters and
other selected bodies stay in place. Other components can remain under edit in
the source project. Status lists changed files before execution. Check also accepts
the selection directly. This lets a unit without a separate local fixture run
through its existing consumer. It produces integration evidence; defining an
independent comparison still needs its own local inputs, adapter and observations.

The source export contains the connected C, interfaces, required services and a
conventional Makefile. It is a component library. A runnable application also
needs its entry point, unlifted dependencies and platform backends. The
[standalone Hello](../tests/fixtures/hello-standalone/README.md) and
[partial jq project](../tests/fixtures/jq-portable/README.md) demonstrate that next
step, including program comparisons and another architecture.
Both preparation recipes accept `--source-export LIBRARY`. The source handoff,
reviewed application/backend C and pinned upstream inputs are sufficient for
assembly; native comparison workspaces are kept separately for future local edits.

For a retained mixed native/lifted program, first prepare its policy with
`candidate policy TARGET --comparison PROGRAM_CHECK --configuration NAME
--component-comparison COMPONENT=LOCAL_CHECK --output POLICY_DIRECTORY`.
Review the generated assumptions/declarations guide and use its printed build
command. Missing required local checks are listed. `--network-only COMPONENT`
explicitly permits network evidence for a named supplier; it does not hide a
supplied incompatible receipt or establish coverage of unexecuted operations.
The command computes the existing policy bindings without manual hashes.

Use `candidate build TARGET
--experimental-comparison PROGRAM_CHECK --experimental-policy POLICY --output
EXPERIMENT`, supplying required local results through `--component-comparison
COMPONENT=CHECK`. This packages the already-compared program and authored DLL.
Then run `candidate test TARGET --experimental-package EXPERIMENT --output RUN`
inside the headless Wayland desktop. Normal-entry programs keep their original
arguments and compare reported state as well as exit status and raw streams.
Declare `program_driver.process.drive` during preparation when the experiment
must survive relocation; otherwise its host pathname can change program behavior.
The [experimental policy](components.md#experimental-component-check-requirements)
can explicitly choose which separate local checks it requires, while retaining
the full selected network's comparison and assumptions. The CLI lists components
without a separate check.
This experimental package retains original platform/runtime dependencies; the
standalone source project is the portability path.

After a local C edit, check the edited unit and its affected program consumer.
Package the new program comparison while retaining the previous experiment's
policy and unchanged component receipts:

```sh
spaghetti-extractor candidate build TARGET --experimental-comparison PROGRAM_EDITED_CHECK \
  --reuse-experimental PREVIOUS_EXPERIMENT \
  --component-comparison EDITED_COMPONENT=LOCAL_EDITED_CHECK --output NEXT_EXPERIMENT
```

The new comparison supplies the updated executable and DLL. Unchanged component
receipts are copied from the previous experiment without compiling or running
those checks again. A receipt for a changed implementation or boundary cannot
reuse; supply its matching fresh check, named by the CLI if omitted. Units already
accepted through network evidence keep that explicit status. Use `--experimental-policy FILE` as
well if accepted declarations changed. The previous experiment stays intact.
Reuse requires the same selected component set, main component, original inputs
and comparison tools; prepare a new selection if those change. This automates
evidence selection, not contract compatibility or proof reuse.

Open the exported library's `README.md`, then its linked component guide. Each
`components/COMPONENT/README.md` keeps the boundary beside the C: inputs and state,
shared objects, required services, assumptions, dependencies and recorded examples.
The dependency section links direct suppliers and the components whose declared
requirements depend on this unit. Shared-representation and recursive-group members
link to their own boundaries; other components remain available through the library
index. These relationships come from the exported declarations, so they describe
this selection rather than every possible application caller. Use them when
reviewing a boundary change; ordinary C edits can retain the existing contracts.
Source links work after moving the project. Guides refresh on export, including
retained neighbors during partial updates; they describe the saved selection, not
unchecked editor changes. Keep personal notes separately. Original adapters and
replay inputs remain in the local comparison workspace.

You can also edit the C in that standalone project directly. Import the selected
component into a local comparison draft, then check it using the existing oracle:

```sh
spaghetti-extractor component start TARGET COMPONENT \
  --comparison-package build/local-package --reuse-source project/lifted \
  --output build/project-edit
spaghetti-headless-wayland spaghetti-extractor component check TARGET COMPONENT \
  --comparison-package build/project-edit --output build/project-edit-check
```

This carries edited C without manually copying files or editing hashes. It reads
only the selected unit's C and declared private headers, even if neighbors are
being edited. A file refactor declared through `component start --source-file`
or `revise_comparison_package` and
retained in the export carries back too: old C files are removed, new directories
are created, and editor/build inputs follow the new selection. The local adapter,
cases and selected neighbors stay in place. Imports are unverified drafts;
changes to other headers and contracts still use boundary refinement. For files
added or renamed directly in the exported project, add the file-selection options
to the same import command:

```sh
spaghetti-extractor component start TARGET COMPONENT \
  --comparison-result LOCAL_CHECK --reuse-source project/lifted \
  --source-file source/entry.c=project/lifted/components/COMPONENT/sources/source/entry.c \
  --source-file source/helper.c=project/lifted/components/COMPONENT/sources/source/helper.c \
  --source-file source/helper.h=project/lifted/components/COMPONENT/sources/source/helper.h \
  --private-header source/helper.h --remove-source source/old.c \
  --output build/project-refactor
```

Other authored files remain selected; unlisted additions must be named explicitly.
The exported `source/old.c` may already have been removed. The command also works
when COMPONENT is a supplier in LOCAL_CHECK: the printed check exercises its
existing consumer. After a matching result, the partial export update below adopts
the compared helper files, retires the old file, and retains neighboring builds.
An edit made after the comparison still blocks overwriting that file. The source
export's old provenance stays unchanged until publication.

Use further `--comparison` arguments to export separately checked selections.
For an assembled source program, prefer [`candidate apply`](component-assembly-updates.md):
it combines the export operations below with the existing target assembly recipe
and optional build/workload commands in a staged project. A failed assembly or
check leaves the working project unchanged. Entry refinements and component
regrouping use the same action as ordinary implementation edits.

After compatible edits, `candidate export --update-components` refreshes an
existing library using only the changed units' comparisons, retaining the other
exported components and application work. Add `--component COMPONENT` (repeatable)
to publish only named units from a matching consumer comparison:

```sh
spaghetti-extractor candidate export jq --comparison CHECKED_CONSUMER \
  --output SOURCE_PROJECT --update-components --component path-get
```

This preserves unfinished C edits in unselected neighbors, including their mtimes.
The command and generated guides identify those drafts; their previous source
hashes and comparison records remain unchanged. A consumer comparison stays
consumer evidence, not an independent local check. Unchecked drafts must be
compared and published before source-provenance validation accepts the whole
library. Ordinary source editing/building remains available. Header, boundary and
source-layout changes still require the authoring/refinement workflow.

Without `--component`, each supplied comparison contributes all its selected units.
`--update` remains available for a complete selection. Run affected program comparisons after an
update. Independently checked unchanged neighbors can reuse their own results;
the consuming program may still need to run again.

After a boundary refinement, review the application's service/state bindings and
pass `--accept-boundary-change COMPONENT` with `--update` for each affected
component. For the reset/initializer refinement below, name both
`graphics-reset` and `graphics-initialize`. Rejections list the changed components
and fields. The update preserves application work and a previous-library backup;
it records the reviewed changes without claiming compatibility. Run affected
program comparisons after updating.

To extend an existing project, use the same partial update after reviewing the
new component's application/backend bindings:

```sh
spaghetti-extractor candidate export jq --comparison STRING_INDEX_CHECK \
  --output SOURCE_PROJECT --update-components --component string-indexes \
  --accept-boundary-change string-indexes
```

Existing components, comparison records, compiled objects and operator files are
retained. Wire the new entry into the application, remove any superseded backend
body, update build inputs, then rebuild and exercise affected program workloads.
The export adds checked C; it does not infer those bindings. The [jq source walkthrough](../tests/fixtures/jq-portable/README.md)
demonstrates this addition using retained native evidence and an existing build.
For entries already reviewed in that recipe, `python
tests/fixtures/jq-portable/refresh.py PROJECT` handles binding generation, backend
definition removal and build/provenance updates in place. It preserves compiled
neighbors and offers proposed files for resolving local edits. For a new jq entry,
`--bindings FILE` supplies the reviewed entry symbol, backend definition file,
adapter headers and any caller service-symbol overrides. Preparation and refresh
retain those choices with the project so later work does not need their original
files or a shared recipe edit. See the
[array-search example](../tests/fixtures/jq-array-indexes/portable-bindings.json).
New services still need explicit C integration. Rebuild and exercise the added
entry afterwards; source binding choices alone do not establish compatibility.

After regrouping operations, retire their superseded source packages explicitly:

```sh
spaghetti-extractor candidate export TARGET --comparison REGROUPED_CHECK \
  --output SOURCE_PROJECT --update-components \
  --remove-component OLD_COMPONENT --accept-boundary-change NEW_COMPONENT
```

Repeat the options for the affected components. Include reviewed comparisons for
callers whose requirements changed; a retained caller cannot keep requiring a
removed supplier. Removal cannot name an incoming component. Only inventoried,
unchanged exported files are removed: conflicting C edits reject the update,
operator notes remain, and the previous project is backed up. The old component's
objects and the archive are invalidated so obsolete symbols cannot survive in
`liblifted.a`; matching neighbors retain their objects. Review application/backend
wiring, rebuild and rerun affected workloads. This changes a source selection,
not the assurance attached to any unchecked code.

## Establish your own boundary

Write down the operation's original instructions and entry/exit contexts. Decide
what the component owns, what remains outside it and which callers exercise it.
Internal control-flow cuts need not become public C functions. Then record:

| Knowledge needed locally | Existing authoring input |
|---|---|
| Inputs, results, shared objects and operations | `ComponentInterfaceIntentV1`, or `service_authoring.component_interface` for single or grouped operations. |
| Layout, contents, sharing, ownership and lifetime | Shared C headers/views, resource declarations and explicit assumptions. |
| Optional accounting for consumed/produced references | `resource_authoring.component_resource_checks`, with explicit value names, resource classification and outstanding-reference limits. |
| External calls, callbacks, effects and outcomes | Reusable `ServiceDefinition` declarations plus executable C adapters. |
| Original entry, native ABI and value transport | Original-side driver and generated service bindings with reviewed C adapters. |
| Inputs and observations to compare | Case arguments and driver observations, including relevant memory and interaction effects. |
| Authored neighbors and replacement groups | `bind_dependencies` and explicit representation declarations. |

Cross-platform observations may need a reviewed logical view of an object whose
physical layout changes. Identify the actual object and its lifetime, then compare
its relevant contents, aliases and effects; matching sizes or reconstructed
pointers alone are insufficient. Keep physical observations available for diagnosis.
The [jq cold-context example](../tests/fixtures/jq-portable/README.md#allocation-failure-in-this-source-backend)
uses ordinary C and allocation-generation queries to compare a live nine-pointer
context on Win32 and 64-bit hosts. It preserves exact comparisons for other
allocations and still detects a reference-count defect. No new proof model or
checker extension is required for that concrete observation.

Emit the logical view in the ordinary C driver so the same observations work with
public check/status/replay and source-program comparisons. Keep raw measurements
in diagnostic output. The [string-slice consumer recipe](../tests/fixtures/jq-string-slice/README.md#use-the-failure-consumer-in-the-ordinary-component-workspace)
demonstrates this without adding a target-specific comparator. Describe selected
case setup and observation limits in comparison scope. Add an assumption to the
component contract only when implementations or callers depend on that premise:
doing so changes the contract and can require caller refinement. Merely adding a
consumer case should preserve an otherwise unchanged boundary.

For a driver that emits JSON directly, the installed `spx-observation.h` handles
integer formatting, hex byte spans and nested arrays/objects. Add it to the
preparation recipe's existing `include_files`:

```python
from spaghetti_extractor.components.comparison_environment import observation_headers

include_files = {**existing_headers, **observation_headers()}
```

Inside the C driver, after capturing the component's result and relevant state:

```c
#include "spx-observation.h"

/* result, bytes/length and event_words/count are explicitly chosen observations. */
spx_observer out = spx_observe_begin(stdout);
spx_observe_i64(&out, "result", result);
spx_observe_bytes(&out, "bytes", bytes, length);
spx_observe_u32s(&out, "event_words", event_words, count);
return spx_observe_finish(&out) ? 0 : 2;
```

The byte span must be readable; it becomes a lowercase hex string without losing
NULs or non-text bytes. Signed/unsigned 64-bit integers remain exact JSON numbers.
Use `spx_observe_array` or `spx_observe_object` for nested containers and
`spx_observe_end` to close each; array elements use `NULL` instead of a field name.
`spx_observe_finish` closes the root object and reports unclosed containers,
nesting beyond 32 levels or output failure. Check its return value. Capture any
state that output calls could alter, such as `errno`, before writing. Field names
must be valid UTF-8 and unique within their object. Existing comparison parsing
and field selection apply unchanged.

Choose contents, identities, lifetimes and interactions explicitly in the driver;
the helper only writes their selected values. Logical views and the treatment of
pointers or floating values remain reviewed C adapter work. The allocation and
graphics drivers use this same header; drivers already using a suitable JSON
library can keep it.

The [manual authoring API](components.md#author-a-new-comparison-boundary) accepts
these declarations and ordinary C files. `prepare_comparison_package` derives
identities, generates headers and packages the executable comparison. Start the
resulting workspace and use the same edit/check/replay/export loop above. Keep
your preparation recipe and C in an operator project; imports of toolkit test
fixtures are not required by the API.

Use the generated C prototype when starting an implementation. The implicit
component context is separate from an explicit input named `context`; generated
contexts and bridge locals choose unused names while keeping declared input names.
This avoids renaming a sensible boundary merely to work around generated C.
Changing a declared input name still counts as a boundary revision; changing a
local name in the implementation does not.

When an executable comparison setup is already available for the declared
boundary, attach your interface-first C with the ordinary source import:

```sh
spaghetti-extractor component start TARGET COMPONENT \
  --comparison-package PREPARED --reuse-source AUTHORED --output WORK
```

`AUTHORED` is the workspace created with `--interface-intent`. Its current
`source/` C and headers are copied without executing `prepare.py`. The interface
and any supplied service catalog/assumptions must match exactly; existing shared headers and their comparison roles stay
fixed. The selected comparison supplies target/runtime choices, operation symbols,
assumptions, adapters and cases. Its compiler/link check still verifies that the
authored C supplies the chosen entry symbols. Importing C carries no evidence.
Use `--comparison-result CHECK` to attach its retained setup and reuse baseline.
A supplier can use `--dependency-source COMPONENT=AUTHORED` with its existing
consumer's status/start/check commands; other bodies and adapters stay selected.

If declarations differ, review the comparison-boundary revision or reopen the C
using the selected interface with `--interface-intent ... --reuse-source AUTHORED`.
Matching function signatures alone do not establish matching boundaries. New
fixture setup still uses the generated preparation recipe and authoring APIs;
an interface-only workspace supplies neither an original oracle nor observations.

Before declaring new lower services, browse those already present in a workspace:

```sh
spaghetti-extractor component list jq --comparison-package work --services
spaghetti-extractor component list jq --comparison-package work --service contents
spaghetti-extractor component list jq --comparison-package work \
  --service jq.string.create --service jq.string.release --json
```

`--service QUERY` implies the service inventory and matches component names, local
service names, exact contract identities or C adapter symbols. Repeated queries
include any match. The overview groups exact bound declarations; the filtered
view adds signatures, ownership roles, outcomes, effects, unobserved behavior and
local C definition candidates. An existing consumer is listed as using a service,
not as implementing it; a selected supplier is named separately when declared.
`--json` includes the full contracts, transports, assumptions and available
adapter/header directories for each matched component. Follow the printed
`component status --details` command for its complete local context.

This reads the existing interfaces and source navigation without executing tools.
Identical signatures with different effects remain different contracts, and an
identical contract does not establish compatibility of C adapters. Source locations
are lexical candidates, not an inferred compiler dependency closure. After review,
pass the component ID, local service names and explicit C file choices to
`retained_service_inputs`; no new service-bundle artifact or assurance is created.
The string-split trial's contents/constructor declarations and DX-Ball's controlled
blit services can both be found this way.

An exported source library supports the same browsing without its comparison
folders or original runtime:

```sh
spaghetti-extractor component list jq --source-project project/lifted --services
spaghetti-extractor component list jq --source-project project/lifted --service contents
```

Use the directory containing `source-export.json`. The ordinary listing links
each component's boundary guide; filtered service views include recorded comparison
adapter examples and their receipt identities. These examples do not select the
program's current backend. Ordinary C drafts are identified separately and do not
prevent reuse of their unchanged declarations. Changed boundary/shared inputs
still require the existing review and export workflow.

Select declarations from one or more exported components with explicit local names:

```python
from spaghetti_extractor.candidate.source_export_bindings import services_from_source_export

services = services_from_source_export(Path("project/lifted"), names={
    "contents": "string-length/contents",
    "release": "string-byte-length/release",
})
```

Pass these definitions to `component_interface` as below. Shared types and exact
contract identities must agree. Choose C headers, executable adapters, transport,
observations and the original comparison inputs separately; this helper imports
declarations only. It creates neither a comparison result nor assurance for a
changed implementation. The source library can therefore supply boundary knowledge
before a new component has an executable comparison setup.

The interface builder reuses the value types carried by those service declarations,
including nested records and nominal opaque objects. Declare only additional local
types instead of copying a neighboring component's entire schema:

```python
boundary = component_interface(
    component_id="string-byte-length", services=services,
    parameters=[("value", "jv_value")], result="i32",
    types=[dict(id="i32", kind="integer", width_bits=32, signed=True)],
)
```

Here the reviewed `contents` and `release` services supply `jv_value`, its fields
and the borrowed string-view declaration. Omit `types` when services already
carry every needed value type. To define a related lower service, use
`ServiceDefinition.create(types=service_types(services, types=[...]), ...)` from
the same `service_authoring` module. Equal declarations merge by type identity;
incompatible declarations report the type and both origins. Explicit existing
type lists remain supported without changing their boundary identities.
This shares declarations, not the neighboring implementation or proof evidence.
Native layouts, contents, lifetime and adapter behavior remain reviewed inputs.

When connecting a separately defined supplier through an existing service bridge,
set its reviewed `symbol` and `declare=True` in the adapter specification. The
generator derives the `extern` prototype from that service's selected C transport
and optional context argument; no caller C rewrite is needed merely to add the
prototype. The [object-lookup connection](../tests/fixtures/jq-object-get/README.md#connect-the-existing-native-comparison-network)
uses this with an unchanged caller adapter. Custom calling conventions, macros and
semantic conversions still use explicit C adapters. A declaration alone does not
establish a compatible supplier.

For a new service, `service_resource_roles(parameters, consumes=[...],
borrows=[...], produces=True, resource_kind=..., provider_domain=...)` replaces
repeated whole-value lifecycle dictionaries. These are explicit operator choices;
`borrows` declares shared borrowing. Pass the returned list as
`ServiceDefinition.create(resources=...)`. Parameter order and the existing
contract format are preserved. Use full role dictionaries for nested paths or
mixed resource classifications; see [service authoring](components.md#reusable-c-service-authoring).

Reuse observation code as ordinary C too, when the call shape and caller context
match. The [jq two-value driver](../tests/fixtures/jq-value-transport/README.md#reusable-comparison-driver-for-two-owned-values)
handles two consumed values, retained aliases, result/reference/allocation
observations and an interpreter consumer. Array search and string split supply
small entry wrappers and JSON case arguments; new ordinary cases need no driver
edit or compilation. Its `unique` mode avoids retaining consumed inputs, while
`unique-address` opts into an additional raw-storage relationship observation.
Append uses a small callback to preserve its existing input admission rule.
Its boundary is explicit: it does not cover raw malformed memory or nonlocal
failure. Other state/interaction shapes
continue to use operator-owned drivers through the same preparation API.

You can begin writing C before the comparison driver exists. Save the reviewed
interface produced by `component_interface(...).to_payload()` or the full
`ComponentInterfaceIntentV1` API, then start directly from that declaration:

```sh
spaghetti-extractor component start my-target my-component \
  --interface-intent my-component-interface.json \
  --operation-symbol run=lifted_operation --output build/my-component-c
```

This needs no registered target, machine recovery, compiler invocation or prepared
test fixture. It writes `interface.json`, generated API headers, typed operation
stubs in `source/component.c`, an editable `prepare.py` recipe, editor commands and
authoring instructions. `authoring.json` keeps the C entry names, editor compiler
and private helper-header roles. Replace
each `#error` with ordinary C. `AUTHORING.md` gives a syntax command; optional
`--compiler FILE` selects that compiler. Without symbol overrides, entries are named
`lifted_COMPONENT_OPERATION` with dots/hyphens replaced by underscores. Repeat
`--operation-symbol` for grouped entries, whose definitions share the declared
context. Existing populated workspaces are preserved; revised declarations use a
new output directory.

Check the portable C before writing a comparison driver, from the lifting shell:

```sh
spaghetti-extractor component check my-target my-component \
  --source --authoring-workspace build/my-component-c
```

This uses the existing C-profile checker and host/PE32 compilation on the current
`source/` C and headers, including newly added helpers. It regenerates declarations
from `interface.json` and the saved entry choices, and retains support headers as
compilation inputs. It needs no target registration, provider build, original
execution or configured `prepare.py`. The default feedback is temporary, so the
same command can be repeated after edits. Add `--output NEW_DIRECTORY` to retain
the checked source snapshot, compiler/profile diagnostics and phase timings, or
`--json` for structured feedback. The selected adapter compiler's syntax command
remains in `AUTHORING.md`; this source check uses both compilers from the lifting
shell and excludes adapter C. Compilation/profile success supplies no link,
memory-transport, behavioral or proof evidence.

Practical admission uses the selected compilers and inspects every authored object
for persistent storage. Formal source eligibility is reported separately; ordinary
macros and conditionals do not prevent practical comparison. Add `--compiler-view`
with `--output` to retain active C, definitions, line markers and consumed inputs
for each compiler. Concrete checks with `--comparison-package` also support the
flag. Keep editing/exporting original C, not the derived platform-specific view.
See [compiler-backed practical C](compiler-backed-practical-c.md) for the complete
generated-parser, refactor, defect-replay and integration workflow.

For writable module or thread state, supply `--state-owners FILE` alongside
`--interface-intent`. The workspace retains ownership, sharing and cleanup
assumptions in `state-owners.json`; ordinary C/runtime code implements them.
See [stateful component workflow](stateful-component-workflow.md) for the schema,
single-provider assembly, local edits and jq allocator example. These declarations
enable practical execution and do not change formal qualification.

Keep service meaning and assumptions beside the C before building a comparison:

```sh
spaghetti-extractor component start my-target my-component \
  --interface-intent my-component-interface.json \
  --service-catalog services.json --assumption-file admitted-state.md \
  --operation-symbol run=lifted_operation --output build/my-component-c
```

`services.json` is the existing `service_catalog(services).to_payload()`, including
definitions selected from another workspace or source library. It must bind
exactly the interface's services. Repeat `--assumption-file` to retain separate
premises; each file becomes one assumption string. The workspace keeps these as
`service-catalog.json` and `assumptions.json`, and `BOUNDARY.md` presents operations,
shared types/state, service lifecycle roles, effects, outcomes and those premises.
Without a supplied catalog or assumptions, the guide identifies the missing
knowledge; it does not infer unrestricted inputs or service behavior.

The generated preparation recipe reads the local copies, so their original
locations are no longer needed. Interface revision with `--reuse-source` carries
them forward and regenerates the guide. Review inherited assumptions and supply
replacement files when the boundary changes; `--assumption-file` replaces the
inherited list. A revision removing all services drops the unused catalog.
Attaching this C to an existing comparison requires any supplied catalog and
assumptions to match that selected boundary. Changed premises need boundary
review. These files describe the contract; adapters, memory transport, observations
and behavioral evidence still come from executable comparison preparation.

Prepare the reviewed service binding and adapter C before that fixture is complete:

```sh
spaghetti-extractor component start my-target my-component \
  --interface-intent my-component-interface.json --service-catalog services.json \
  --service-bridge bindings.json --adapter-file bridge.c=adapters/bridge.c \
  --resource-checks resources.json \
  --include-file native.h=headers/native.h --output build/my-component-c
```

`bindings.json` contains the existing `service_bridge` arguments: `adapters`,
`transports` and `native_symbol`. It can come from a reviewed
`retained_service_inputs` selection. Native/portable adapter symbols, transport
functions, context arguments and outcome predicates remain explicit choices.
The same generator used by comparisons writes `generated/comparison-service-bridge.h`
and its coverage description. Include it once, after the portable implementation
header and the native types/adapter declarations it uses. Grouped/stateful entries
use `native_symbol: null` and the existing manually authored entry support.

Adapter and support names are relative to `adapters/` and `headers/`. The generated
recipe lists the copied inputs, and editor/syntax commands include adapter C and
its headers. `--compiler FILE` selects the intended ABI, such as the lifting
shell's PE32 compiler for Windows adapters. Creating the workspace runs no compiler.

For operation resource accounting, the optional `--resource-checks FILE` retains
the existing settings produced by `resource_authoring.component_resource_checks`
or the full lifecycle declaration API. The workspace keeps `resource-checks.json`,
shows its roles, limits and unobserved effects in `BOUNDARY.md`, and generates
`comparison-resources.h` and `.c` using the comparison runtime generator. Service
catalogs also generate the existing `comparison-services.h` and, when nonlocal
outcomes are declared, its handler runtime C. Adapters can therefore include and
syntax-check against this support before executable preparation. Editor commands
include the generated C; the comparison factory regenerates and links it, so keep
it out of authored source/adapter lists. Actual handler scopes, object transport,
runtime/link inputs, cases and observations remain explicit preparation work.
Early syntax success does not check memory transport, lifetime or original behavior.

Reopening with `--reuse-source` retains current adapter C, support files and
binding choices, then regenerates the bridge against the selected interface.
Review the adapter bodies when changing declarations. Remove obsolete files in
the old draft before reopening, and provide a new `--service-bridge` for changed
bindings. C-only attachment to an existing comparison continues to use that
comparison's adapters; adopt adapter changes explicitly through
`revise_comparison_package(adapter_files=..., include_files=..., service_bridge=...)`.
Resource settings also survive reopening. The existing revision rules rebind them
across unrelated schema changes while the operation's inputs, results and reachable
types remain unchanged. Changed values or types require reviewed settings supplied
with `--resource-checks`; retained declarations do not establish compatibility.
Any resource settings supplied during C-only attachment must match the selected
comparison boundary, alongside its service catalog and assumptions.
The regression handoff exercises first adapter preparation, a local adapter edit,
comparison and deliberate defect detection through these same facilities.

While designing that interface, carry your existing C into a revised workspace:

```sh
spaghetti-extractor component start my-target my-component \
  --interface-intent revised-interface.json --reuse-source build/my-component-c \
  --output build/my-component-c-v2
```

This selects the current `.c` and `.h` files under the old authoring workspace's
`source/`, including nested helpers and edits made since it was created. It
regenerates declarations, editor commands and the source list in `prepare.py`.
The old workspace stays intact. Existing operations retain their C names and the
editor retains its compiler from `authoring.json`; new operations get default
names. `--operation-symbol` and `--compiler` override those choices. A missing
retained compiler reports how to select a replacement instead of silently
switching the adapter ABI. Moving a workspace and reopening it regenerates editor
paths while keeping the choices. Reopening reads setup data without executing the
old `prepare.py`. Older workspaces without `authoring.json` need custom symbols,
compiler and private-header choices supplied once.

Private helper-header roles follow surviving source files. Add roles with
`--private-header`, or review an intentional role change in `authoring.json`
before reopening. These are authoring choices; comparison attachment still uses
the selected boundary's header roles and execution setup. Carrying C does not
determine whether it implements the revised interface.
Use `generated/component-skeleton.c` to inspect the new operation signatures,
then adapt your implementation. Syntax checking covers every selected C file.

`--source-file source/NAME=FILE` adds or replaces authored inputs and
`--remove-source source/NAME` retires them, both for initial interface authoring
and when reusing a workspace. To start with your own entry filename, remove
`source/component.c` and supply your entry with `--source-file`. Declare private
helper headers with `--private-header source/NAME` for the proposed boundary.
The new comparison recipe starts unconfigured: review existing adapters, original
inputs and observations against the revised interface before bringing them over.
Once an executable comparison exists, use its boundary-revision workflow below
to preserve that setup and review affected consumers.

The workspace has no original/source comparison or assurance result. Its generated
`prepare.py` carries the interface, source files, identity and operation symbols
into the existing `prepare_comparison_package` API. List helper C/headers in its
`source_inputs()`. Fill in `comparison_inputs()` with an explicit host or native
environment, reviewed adapters, service/shared-memory transport, original inputs,
cases, observations and assumptions. Run `python prepare.py --output /path/to/comparison`
in the lifting shell. The recipe is ordinary editable Python with paths relative
to its directory; preparation copies current inputs and does not run either side.
Set `oracle_kind` to `native-original`, `retained-c` or `fixture` according to the
original being compared; choosing a host compiler does not choose the oracle.
Generated headers are regenerated by preparation and are not authored source.
Then open/check the prepared comparison using the ordinary workflow. When an
execution setup already exists, `component start --source-file NAME=FILE` or
`revise_comparison_package(source_files=...)` can bring this C into it while
retaining the original and selected neighbors.

The [new jq string-split walkthrough](../tests/fixtures/jq-string-split/README.md)
uses this sequence on a previously unprepared operation: select reusable string
services, generate the prototype, author C, attach direct/interpreter observations,
diagnose a dropped output field and update a normal source program. It needs no
new tool internals. Its preparation recipe, small C adapters and recorded setup
costs also show the manual work that remains before ordinary local editing begins.

The [shared-object lookup walkthrough](../tests/fixtures/jq-object-get/README.md)
takes the same workflow into a live mutable object table. Its complete consuming
operation borrows the actual table, walks collision chains, copies the result and
releases its inputs. The shared layout/lifetime rules accompany the C, and the
existing value/path callers reach the replacement through normal program entry.
Manual boundary and adapter preparation remains necessary; no checker or compiler
extension is needed for this trial.

The [object-deletion handoff](../tests/fixtures/jq-object-delete/README.md) reuses
that layout for mutation. Its copy-on-write service returns both the owned object
and a view into that returned allocation; the caller then edits bucket links in
ordinary C. A deliberately skipped copy produces the right result while corrupting
a retained alias, which the existing observations diagnose and replay. The same
component integrates under real interpreter consumers on two architectures while
neighboring component objects reuse. This is an executable boundary example;
the ownership declaration alone does not supply the copy or preserve memory.

One component can own several entry points and their private shared code.
The [practical module and assembly workflow](component-module-workflow.md) carries
those grouped operations through portable source assembly, and explains immutable
static storage admission separately from formal source eligibility.
Use `component_interface(operations={...}, state=[...])` with
`OperationDefinition` values to declare each entry's parameters, result,
nullability and allowed services, plus shared context fields. The
[grouped authoring example](components.md#reusable-c-service-authoring) shows the
declaration; Hello's allocation recipe uses it for eight related entries.
Pass every entry's C symbol in `operation_symbols`. The driver supplies context
initialization/lifetime and the reviewed original entries. Ordinary private C
helpers need no synthetic component or service declaration.
For generated service bindings around such entries, set `service_bridge`'s
`native_symbol` to `None`. The existing generator supplies the service table and
scope helpers; your entry adapter keeps control of shared state, lifetime and
dispatch. The [allocation adapter](../tests/fixtures/hello-checked-allocation/bridge.c)
shows this setup, and the same bindings can be generated from the exported source
project. No custom trace-formatting or header-generation script is required.
Grouped components still replace as one named dependency. The
[native allocation handoff](../tests/fixtures/hello-checked-allocation/README.md#native-consumer-integration)
selects the new C and exported adapter through `component start --dependency-package`,
then checks an existing quoting consumer without changing its C or boundaries.
Use the change preview to distinguish edited component inputs from build-environment
invalidation; those can require different amounts of compilation.

If package preparation rejects an input or declaration, fix it and retry the
same output path; failed preparation leaves no partial package behind. Recipes
that also generate adapters or several packages can use the existing preparation
staging helper as shown in the [authoring API](components.md#author-a-new-comparison-boundary).
The DX-Ball recipe above stages its complete four-component selection this way,
so a late failure can be corrected and retried without deleting earlier packages.

When using retained machine C as the original-side oracle, the installed
`comparison_original.recover_original_c` helper accepts your reviewed image digest,
entry RVAs and instruction ranges. It produces original C, runtime headers and
source locations through the existing semantic engine. The [authoring example](components.md#author-a-new-comparison-boundary)
shows the call; the DX-Ball preparation recipe uses it. Manual operation ownership,
entry frames and executable memory/service adapters remain your inputs. Native
original execution is also supported and does not depend on this recovery step.

Native drivers can select installed C helpers through `native_adapter_headers`:
for a reviewed PE32 operation, `native_entry_header` reads the expected
entry bytes from the pinned executable and generates the hook/storage/trap-check
glue. Explicit additional ranges cover cold fragments; HIGHLOW prefix relocations
follow the loaded image base. Pass its header to package preparation and call its installer from the
driver. The [authoring example](components.md#author-a-new-comparison-boundary)
shows this setup. Entry ranges, native signatures, state transport and meaningful
observations remain explicit operator decisions. Shared tails and alternate
entries still use manual C bindings.

The installed headers provide
entry/import interception and optional `pe32-process-observer.h` for a terminating
child's exit status and raw streams. The [native authoring API](components.md#author-a-new-comparison-boundary)
documents their inputs and limits. They need no checkout-relative fixture files;
the operator still supplies the target ABI, live-state transport and observations.
Run those comparisons in the headless Wayland desktop.

Reuse reviewed executable services with `retained_service_inputs`, choosing their
adapters and headers explicitly. The [jq byte-length recipe](../tests/fixtures/jq-string-byte-length/README.md)
shows four local files using a shared workspace. Inspect the chosen adapter C:
that trial found an adapter which called the operation being replaced and had to
factor a shared object view first. A pointer or declaration alone does not supply
contents or lifetime behavior.
When starting from a connected workspace, select the service owner with
`component_id` and use destination-to-package-path mappings for shared C and
headers. The [string-search recipe](../tests/fixtures/jq-string-indexes/README.md#start-from-the-selected-path-network)
uses the named string component and the network's value transport directly;
it needs no historical per-component preparation folder. Service reuse still
requires reviewing adapter dependencies and defining the new entry and examples.
When a boundary needs services from several components, `retained_service_inputs`
also accepts `names={"retain": "value-get/copy", "release": "path-get/release"}`.
Omit `component_id` in this form. Each key is the new component's local C service
name; each value explicitly selects a declaration and binding in the same
workspace. Complete service contracts retain their identities, including resource
roles, effects and outcomes. Exact shared types and transport choices merge;
conflicting layouts or transports report an error instead of choosing one by
order. The selected C adapters and headers still need explicit file mappings and
review. No supplying component body or evidence is imported.

Local aliases can share an exact contract: `service_catalog` retains it once and
rejects two different contracts with the same identity. This does not make a
rename compatible with an existing component boundary. Generate its new interface
and adapt the C member names, then recheck affected consumers before integration.
Boundary revision rebinds existing resource declarations for unchanged operation
values and types as described below. Additional transports needed
only by the new operation's entry remain explicit recipe inputs.

The [two-input search recipe](../tests/fixtures/jq-string-indexes/README.md) extends
that same view and transport to possibly aliased owned inputs and a growing array
result. Its new adapter only combines number construction and append; the local
algorithm, lifecycle declarations and cases are ordinary operator files. It also
shows why standalone assembly must supply each lower-service adapter explicitly,
even when the component's own C exports successfully.

For a declaration change within an existing workspace, edit its
`revise-boundary.py`, or `<workspace>/dependencies/<component>/revise-boundary.py` for a selected
supplier. `component start` creates this recipe and links it from the boundary
guide. Its `boundary_changes(unit)` receives the current component declaration;
return only the fields you intend to change. It uses `revise_comparison_package`
to retain omitted C, adapters, cases, tools and neighboring implementations.
An empty recipe reports what to edit and creates no output.

An interface revision retains operation resource roles, allowances, instrumentation
sides and observation gaps when its input/result declarations and all referenced
types are unchanged. The lifecycle builder regenerates their schema bindings, so
adding or renaming a service need not repeat the ownership declaration or involve
digest editing. A removed operation, changed value declaration or changed declared
type requires explicit `resource_checks` in the revision. Supply those through
the usual resource-authoring API after reviewing the new roles. The new boundary
still needs caller review and comparison; no previous result is inherited.

Run the recipe with `--output NEW_PACKAGE`. If contracts change, its diagnostic
names the affected caller requirements and declaration differences. Review those
call sites, then repeat with one `--review-requirement CONSUMER/REQUIREMENT` for
each reviewed edge. For example, a getter shared by the two path operations uses:

```sh
python build/path-work/dependencies/value-get/revise-boundary.py \
  --output build/path-revised-package \
  --review-requirement path-get/get --review-requirement path-set/get
```

These names record your review; they do not prove compatibility. Follow the
printed `component start` command to refresh the revised workspace, then compare
the affected consumer and review source-project integration. Reopening preserves
the editable recipe. It reads current declarations, so review its proposed changes
again before applying it to an already revised workspace. Interface proposals can
use an edited copy of the interface through `ComponentInterfaceIntentV1.parse`;
the recipe shows the call. Do not edit saved hashes or composition records.

Preparation scripts can also call `revise_comparison_package` directly. For
example, after reviewing the driver's setup:

```python
from pathlib import Path
from spaghetti_extractor.components.comparison_package import (
    load_comparison_package, revise_comparison_package,
)

package = Path("build/reset")
plan, _ = load_comparison_package(package)
revise_comparison_package(
    package=package, output=Path("build/reset-revised-package"),
    assumptions=[*plan["assumptions"],
                 "The driver establishes the graphics state before entering reset."],
)
```

Start an editable workspace from that prepared package to refresh its editor
commands and boundary guide. Then check it with `--reuse-comparison` to see which
work can reuse. The helper regenerates derived metadata; do not edit contract
hashes or the saved composition graph. Existing callers retain their requirements
and reject a changed supplier contract until explicitly refined. No behavioral
result is inherited merely by revising declarations.

Use that same helper when moving the selected C into a reviewed native or program
driver. Supply complete `adapter_files`, `include_files`, `link_files` or
`runtime_files` mappings for the root roles you need to replace; omitted roles
and neighboring components stay intact. Tools and `program_driver` can also be
revised explicitly. If the original-side inputs change, supply reviewed
`original_files` and, when needed, `oracle_kind`. The helper derives their hashes,
regenerates composition/headers and rejects incomplete setups before publishing.
The [DX-Ball recipe](../tests/fixtures/dxball-graphics-network/native.py) demonstrates
the handoff from retained-C comparisons to original x86 execution without manual
plan editing. New drivers still need reviewed ABI/state transport and observations;
their comparisons must run before the revised configuration has behavioral evidence.

To add another independent entry to that program, pass
`program_entry_packages={"string-conversion": string_workspace}` with its reviewed
driver declaration. The helper retains the current selection, imports the new
entry's exported C adapter and dependencies, and regenerates the existing entry
list and graph. It preserves caller requirements; a new program entry need not
be a call from another component. Shared selection conflicts require an explicit
choice before assembly. The [Hello example](../tests/fixtures/hello-program/README.md#add-an-independently-edited-program-entry)
shows this handoff with ordinary component editing and normal program execution.

After reviewing the changed assumption against the initializer's use of reset,
refine that caller requirement and open its editable workspace in one command:

```sh
spaghetti-extractor component start dxball graphics-initialize \
  --comparison-package build/graphics-work \
  --refine-requirement reset=build/reset-revised-package \
  --output build/graphics-refined-work
spaghetti-extractor component check dxball graphics-initialize \
  --comparison-package build/graphics-refined-work \
  --reuse-comparison build/graphics-checked --output build/graphics-refined-check
```

The option names the caller's requirement, visible in `component status`.
Repeat it for each reviewed requirement. The dependency preview shows added/removed
assumptions so long existing lists do not hide the changed premise. The revision imports the
chosen supplier and updates only the named requirements. Caller C, adapters,
cases, notes and unrelated selections stay intact; editor commands and guides
are regenerated. This also works when reopening an `--experimental-package`.
Other consumers of the changed contract still require their own
review. Name them in the same revision with `CONSUMER/REQUIREMENT`, for example
`--refine-requirement path-set/get=build/value-get-revised` and
`--refine-requirement path-get/get=build/value-get-revised` in jq's selected network.
Bare names continue to refer to the package entry. Missing caller reviews are
reported together; duplicate aliases and conflicting supplier choices reject.
Existing callers retain their C and adapters. Bundled suppliers with unchanged
contracts keep the network's current implementations, so an older supplier
workspace cannot silently undo an independent neighboring edit. Explicitly named
supplier choices take precedence. Separate inner-caller preparation remains useful
when its own interface or C adapter also changes.
If that prepared caller now requires a newly lifted supplier, named refinement
imports its declared closure too. The [jq array-search handoff](../tests/fixtures/jq-array-indexes/README.md)
demonstrates a new local unit returning through both callers of `value-get` while
preserving independently edited neighboring C. Ordinary C-only replacement keeps
its existing boundaries and cannot introduce such a supplier.

Preview that proposal before applying the refinement:

```sh
spaghetti-extractor component status jq path-set \
  --comparison-package build/path-network \
  --dependency-package value-get=build/getter-with-array-search
```

The preview marks newly introduced suppliers as `added`, shows their proposed
direct and transitive consumers, and prints a command to inspect each new unit's
boundary, adapters and assumptions in the proposed package. Current consumers
are shown separately when they differ. This works before the new supplier belongs
to the network and does not change the selection or run a comparison. Each
proposal is inspected separately; conflicting selections still need resolution.
Apply the reviewed requirements with `component start --refine-requirement`, then
check the resulting consumer. Ordinary unreviewed replacement remains rejected.

This records the operator's decision and schedules new comparisons, without
claiming that the contracts have been proved compatible. A changed experimental
configuration also needs review of its policy before assembly. Preparation recipes
can use `revise_comparison_package(refine_requirements={"reset": supplier})` for
the same operation; the command needs no Python script or manual hash changes.

When a retained service has been lifted, add its reviewed component to the caller
without reconstructing the caller's full package:

```python
from spaghetti_extractor.components.comparison_composition import bind_dependencies

package = Path("build/path-caller")
plan, _ = load_comparison_package(package)
addition = bind_dependencies(services={"length": Path("build/storage-length")})
revise_comparison_package(
    package=package, output=Path("build/path-with-length"),
    dependencies=addition["dependencies"],
    requirements=plan.get("requirements", []) + addition["requirements"],
    # Supply reviewed service_bridge/adapter/header changes here when needed.
)
```

This also works inside a selected network: pass `component_id="value-get"` and
use that component's current requirements, adapters and service bridge. Its
editable `dependencies/value-get/revise-boundary.py` exposes the same fields.
The enclosing driver, cases, callers and other selected bodies remain in place;
there is no need to manufacture a separate getter comparison first. The resolver
still rejects unused additions, conflicting shared selections and unresolved
requirements. Changed incoming boundary contracts retain their named-review
requirement. The [object lookup handoff](../tests/fixtures/jq-object-get/README.md#connect-the-existing-native-comparison-network)
shows the C wiring and focused recipe.

If the supplier is already selected in another network, the binding can instead
name it there:

```python
addition = bind_dependencies(services={
    "length": {"id": "storage-length", "package": Path("build/path-network")},
})
```

This freezes the named supplier's current contract and selects its existing
implementation and declared suppliers. Several requirements can share that same
selection. The enclosing network's other callers, driver and evidence are not
imported. This works for new component preparation as well as the revision above.

The named service must already be declared by the interface, or be introduced
through an explicit `interface` revision. Executable C bindings must route it to
the selected supplier; adding an edge does not implement that route. Existing
selections and caller edits remain, and transitive suppliers are imported through
the existing resolver. Conflicting shared choices reject before publication.
This adds selections; it does not automatically
refine another consumer's contract. Start/check the prepared selection, then use
ordinary local edits and dependency selection again. The
[jq controlled caller](../tests/fixtures/jq-path-controlled/README.md#add-lifted-services-to-an-edited-caller)
demonstrates this transition with existing array storage and reviewed C bindings.

For a reviewed regrouping, also pass `remove_dependencies=["OLD_COMPONENT", ...]`
to retire those selections before resolving the new `dependencies` and complete
`requirements`. Existing consumers and program entries must still resolve; nothing
silently deletes their requirements or substitutes a native body. Explicitly
reselect a component if its own boundary changes in the same revision. Unrelated
selection, caller C, fixtures and notes remain. The
[DX-Ball grouping walkthrough](../tests/fixtures/dxball-graphics-network/README.md#group-complete-operations)
combines two existing entries into one component and carries that choice into the
existing source project. This is component ownership of complete operations;
internal proof-region splits have separate transport, coverage and progress rules.

When changing a shared representation input, revise the selected group together:

```python
revise_comparison_package(
    package=Path("build/consumer"), output=Path("build/revised-layout"),
    representation_updates={"shared-state": {
        "revision": "reviewed-layout-v2",
        "inputs": {"layout": Path("my-component/state.h")},
        "reviewed_requirements": ["consumer/state", "worker/state"],
    }},
)
```

Use the input names and caller requirements shown by the existing boundaries.
Review the C and adapters before accepting each affected requirement; the helper
reports missing reviews and derives the new bindings. It updates every selected
member that declares this group without rewriting implementation C or importing
absent members. Correct rejected inputs and retry the same destination. Start and
check the revised workspaces, then update the source project with explicit boundary
acceptance. The [DX-Ball walkthrough](../tests/fixtures/dxball-graphics-network/README.md#revise-the-shared-portable-layout)
applies a reviewed layout change to both its original and regrouped selections.

For a local C refactor, `revise_comparison_package` also accepts `source_files`:

```python
revise_comparison_package(
    package=Path("build/local-work"), output=Path("build/refactored-package"),
    source_files={
        "operation.c": Path("my-component/operation.c"),
        "helpers.c": Path("my-component/helpers.c"),
        "helpers.h": Path("my-component/helpers.h"),
    },
)
```

Supply the complete authored C/header set, including unchanged authored layout
headers. Names are relative to the package's `source/` directory. The helper
removes superseded authored files and preserves the interface, oracle, adapters,
cases, dependencies and operator notes. Start/check the resulting package through
the same commands; a file split does not create new components or service APIs.
Only matching current inputs can reuse prior results. Oracle inputs and unowned
files cannot be overwritten through this operation.

You can also revise a supplier directly inside its current consumer workspace;
an independent local fixture is not required. For example, after opening the jq
array-search supplier, retain its consumer and review the getter's requirement:

```python
plan, _ = load_comparison_package(Path("build/path-work"))
unit = next(row for row in plan["dependencies"] if row["id"] == "array-indexes")
revise_comparison_package(
    package=Path("build/path-work"), output=Path("build/path-revised"),
    component_id="array-indexes",
    source_files={
        "search.c": Path("array-search/search.c"),
        "machine-index.h": Path("array-search/machine-index.h"),
    },
    private_headers=["source/machine-index.h"],
    assumptions=[*unit["assumptions"],
        "Live-allocation observations preserve original residual allocations; no leak freedom is promised."],
    reviewed_requirements=["value-get/indexes"],
)
```

`component_id` selects the existing unit. Interface, service/resource declarations,
input domain, C files and adapter/header mappings use that unit's namespace.
`adapter_files` retains the selected supplier's `bridges/` role. File mappings are
complete replacements for their role, just as in root revision. The enclosing
driver, oracle, cases, tools and other implementations stay in place. Use a root
revision for execution/selection changes and `representation_updates` for a shared
layout change across members.

Only changed incoming contracts need `reviewed_requirements`. Preparation reports
all missing `CONSUMER/REQUIREMENT` names and leaves the destination absent; review
those call sites before retrying. A matching signature alone does not justify that
review, and recording it does not prove compatibility. Reopen the selected unit
with `component start jq array-indexes --comparison-package build/path-revised` and
an output directory, then use its printed **path-set consumer** check. This supplies
consumer evidence, not an independent array-search comparison. When exporting the
refinement, include the supplier and the consumers whose requirement declarations
changed, with explicit boundary acceptance for each; the remaining component C
and objects can stay intact.

When a shared C layout changes, revise its representation group together. The
[DX-Ball layout walkthrough](../tests/fixtures/dxball-graphics-network/README.md#revise-the-shared-portable-layout)
reorders existing bank fields while preserving the four selected implementations,
original PE layout and explicit contents/alias transport. Its preparation recipe
uses the same revision API, supplies the header once to all members, and refines
the consumer's affected requirements. Local checks remain possible for each unit;
the assembled selection must use a consistent group. Ordinary C edits with an
unchanged layout do not require this group-wide preparation.

Source export requests `--accept-boundary-change COMPONENT` for changed boundary
headers or existing header roles. New private helper files and edits to headers
already declared private use the ordinary implementation-update path. Review
shared header use by application/backend bindings.
The partial exporter regenerates that unit's build recipe and preserves unchanged
neighbors. Run affected program workloads after publication.

Use full preparation for a different component identity or an assembly that
removes or repartitions existing units. [`component start --reuse-source`](components.md#practical-originalsource-execution)
can carry local C into newly prepared inputs. Contract compatibility is a
separate question from whether C has the same signature. Manual analysis and
adapters are expected; needing a new checker, compiler rule or artifact format for
an ordinary component is a tooling gap to record.

## Understand the result

Keep compared behavior, assumptions and proved properties distinct. The default
comparison workflow does not require universal formal closure. Optional local
proofs add their own findings; qualification and native activation retain their
separate [strong acceptance requirements](whole-target-independent-lifting.md#required-implementation-and-acceptance-g1g7).

Start with useful retained/generated inputs, meaningful observations and actual
consumers. Measure first-boundary analysis and adapter work separately from warm
edits. Broader case matrices and pilot rebuilds should resolve a concrete question
about changed behavior, integration or portability.

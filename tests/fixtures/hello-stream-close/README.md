# Previously unprepared stream-close boundary

This operator trial lifts Hello's complete `close_stream`, RVA `0x6894..0x68f8`,
from the pinned PE's disassembly. Before the trial only its partition entry and
the existing portable output backend were present. No component, comparison
package or authored algorithm was reused. The existing interface/service APIs,
generated bridge, native image loader and entry/import hooks supply the machinery.
No checker, artifact, compiler, Nix expression or proof rule is added for this unit.

Read [BOUNDARY.md](BOUNDARY.md) in the editable workspace before changing C. A
shared [stream view](../portable-runtime/stream-view.h) carries the existing live
handle; generated borrow/consume transport uses that same view. Consuming it
invalidates aliases of the view. Independent fabricated views, all possible FILE
aliasing and heap correspondence are not thereby checked. The C algorithm knows
neither the native FILE layout nor platform errno constants.

## Fresh setup and local work

Use `nix develop .#lifting` and the pinned original from the
[Hello handoff](../hello-handoff/README.md). No previous comparison is required:

```sh
python tests/fixtures/hello-stream-close/prepare.py \
  build/hello-original-input/bin/hello.exe build/hello-stream-packages
spaghetti-extractor component start gnu-hello stream-close \
  --comparison-package build/hello-stream-packages/stream-close \
  --output build/hello-stream-draft
spaghetti-headless-wayland spaghetti-extractor component check gnu-hello stream-close \
  --comparison-package build/hello-stream-draft --output build/hello-stream-check
```

The seven cases include 216 controlled combinations across two identities and
five real MSVCRT file scenarios: pending writes, reads, prior stream errors,
closed descriptors with no pending data and closed descriptors with pending data.
Observations include results, errno, service order/arguments/results, consumption,
controlled memory frames and actual file contents. The original executes native
instructions; the source selection poisons the complete original operation body.
The pending helper and actual CRT services remain explicit lower dependencies.
The recipe uses the installed `prepare_routine_image` API, without importing the
quoting fixture's Python code. To prepare outside the checkout, stage this
recipe/C/declarations and the shared `portable-runtime/stream-view.h`, then use
the installed toolkit and pinned original. The image retains the original section
bytes while omitting startup/TLS; the C driver supplies the declared local state.

## Edit, reuse and integrate

Prepare/check the connected and string selections using the
[program](../hello-program/README.md) and
[string-boundary](../hello-string-conversion/README.md) recipes, plus the pinned
upstream archive and original-program oracle in the
[standalone instructions](../hello-standalone/README.md). Then run:

```sh
spaghetti-headless-wayland python tests/fixtures/hello-stream-close/walkthrough.py \
  build/hello-program-workflow/program-repaired build/hello-string-workflow/repaired \
  build/hello-stream-packages/stream-close build/hello-program-workflow/neighbor-reused \
  build/hello-standalone-oracle build/hello-upstream build/hello-stream-workflow
```

The walkthrough authors a different C decision tree, recompiles one unit and
reuses its allocation neighbor with zero new work. Public source export/update
preserves application/backend files and notes. A premature errno clear is caught
on a real failed close (73 becomes 0), refused by the updater, replayed from the
retained bad inputs after draft repair, then repaired with zero new work. A
post-close access is rejected by the adapter with `borrow after consumption` and
exit 77; the comparison is **incomplete**, not a passing or proved lifetime claim.

The assembled program calls this same authored component during normal shutdown.
Its adapter supplies the portable stream backend and platform error predicate.
The complete 82-case program suite passes before and after the local edit. An
integration adapter that discards the failure result is caught through actual
`/dev/full` output: exit status and diagnostics differ. Its retained bad executable
still fails after the adapter is repaired; the rebuilt repaired program passes.
All Wine execution remains in the headless Wayland desktop.

## Effort and gaps

Evidence is retained under `build/hello-stream-boundary-2026-09-22/`.
The agent interval from recorded investigation start to the first matching local
comparison is 578.834s; initial repository inspection is excluded. This is not a
human usability measurement. Automatic preparation of the final boundary takes
0.263s; the successful prepared workflow takes 72.035s. Its local edit/check takes
5.523s and the unchanged neighbor 2.107s. See the performance ledger for phase costs.

The authored algorithm is 15 C lines; native transport/scenarios/observations are
141, the program adapter 33, declarations 27 and preparation 59 Python lines.
Generated interface and service code is excluded. Counts show where manual work
lies; they are not comparable productivity scores across different components.
The initial strict compiler check caught misleading indentation. The first
program build caught an omitted adapter-only shared header: source export retains
authored C dependencies, so the assembly recipe must separately include its shared
backend inputs. The corrected recipe includes that header once in the backend.

The trial needed manual ABI/service analysis, executable observations and an
assembly adapter, but no per-unit tool internals. The existing generated bridge
already removed repeated wrapper code. Further convenience tooling should target
actual repeated setup work, while keeping these semantic adapter choices explicit.
It does not establish broad Win32 readiness, general FILE behavior, native terminal
output or complete strong qualification.

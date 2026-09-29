# DX-Ball Windows C delivery

Practical delivery checkpoint, 2026-09-29. DX-Ball now has a standalone Windows
source project containing the lifted application C, owned state, Windows SDK
adapters, resources and assets. It builds without the original executable or
workbench and exercises all five scenes through normal entry. This completes
the practical DX-Ball lifting goal within the documented comparison and runtime
scope. It does not claim equality for every possible original failure execution.

Windows runtimes are intentional dependencies. Wine in a headless Wayland desktop
is the preferred validation environment. Non-Windows porting, a second desktop
backend and universal formal qualification are outside this delivery criterion.

## Source handoff and local work

The retained source archive is
`build/dxball-program-scenes-windows-2026-09-29/dxball-windows-source.tar.gz`,
SHA-256 `8c7046a3bc74f50b7831fe62155ff107fe2dcdf0b300486307e0eb91f11e2310`.
It contains 1,107 files, including 46 assets, with no executables or compiled
objects. Its `WINDOWS.md` describes Make/MinGW-w64 builds and local editing.
Extraction, checksum verification and a build outside the repository passed;
all resulting executable section bytes match the checked handoff build.

The selection contains 49 components and 190 exported operations, supported by
1,180 retained original/C comparison cases. Components use shared object types
and recorded service boundaries. Operators can edit the source project directly
or use the existing component check/edit/replay and `candidate apply` workflow.
Unchanged component sources, records and compiled objects remain reusable.
No original DX-Ball application source was used for these implementations.

The source executable retains Win32, DirectDraw, DirectSound and WinMM. These
dependencies do not represent unlifted application logic. The shared Wine backend
observes candidate binaries and platform interactions; it does not know which
candidate is original or lifted.

## Application inventory review

The final review uses the pinned original image and existing manual boundaries,
not another extraction or qualification pilot. Evidence and the review script
are under `build/dxball-completion-review-2026-09-29/`.

- All 190 selected operation entries are accounted for, including the separately
  prepared MDS loader/parser/events and sprite loader. Two selected entries are
  the CRT random generator and seed setter, deliberately expressed in C to retain
  their algorithm.
- Seven private helper bodies are expressed inside existing C components:
  five typed removal helpers, the WAV descriptor helper and sprite-bank reset.
- Nine startup forwarding thunks and eight additional zeroing bodies are
  accounted for by ordinary program-state initialization. The ninth zeroing body
  is already an exported operation. They need no synthetic production APIs.
- Six gaps contain switch tables and alignment bytes referenced by the reviewed
  application instructions. After these classifications there are no unexplained
  bytes in the reviewed application span, RVA `0x1000..0xdbe0`, or unclassified
  direct call/branch targets. CRT and Windows calls retain explicit runtime
  ownership. Indirect COM and callback behavior still relies on its recorded
  boundaries; this inventory is not a complete indirect-transfer proof.

The review found five half-open range endpoints that stopped one byte early:
two paddle returns, one particle return and two particle backward jumps. The
preparation recipes now include those bytes. All 21 paddle and 20 particle cases
match after fresh preparation through the public check command, inside headless
Wayland. The application C is unchanged. These reruns are part of the existing
1,180 cases, not additional coverage counted twice. The older receipts remain
bound to their original ranges and are not relabeled as checking the correction.

## Program evidence

Retained normal-entry runs exercise title, menu, gameplay, editor and score scenes,
board saving/navigation, progression, cleanup and shutdown. Original and source
candidates use the same external desktop workloads and private assets. Complete
board/score files, three editor images and both score images match. A paused
gameplay image also matches. Animated return-menu captures differ only within the
explicitly recorded moving-dot and ball regions; these wall-clock observations
do not establish deterministic rendering equality.

Seven local SDK-adapter checks cover MIDI completion, reset, callback requeue,
provider-owned header updates and failed opening. The queue-link and flag errors
found in the preceding adapter reproduce without game startup. Component C did
not need a correction. These checks and the source handoff are retained evidence;
the completion review does not repeat all earlier workloads.

The integration details, commands and evidence locations are in the
[source-program integration record](dxball-standalone-integration.md) and
[assembly guide](../tests/fixtures/dxball-standalone/README.md).

## Explicit fidelity limits

The boundary system can expose historical state without the standalone assembly
being able to reproduce that state's original history. The following cases
remain outside the practical equivalence claim:

| Original behavior | Standalone boundary and limit |
|---|---|
| Frame `GetStatus` fails without writing its output. The word initially contains incoming volatile ECX, retained by `push ecx`. | The SDK adapter reports unsupported status history. Reading the replacement's own stack would not reproduce the original word. |
| Audio restore tests a status word at original entry ESP minus `0x104`; a failed call can leave it untouched. | The component accepts explicit history. The standalone owner's initial value does not establish correspondence to every native stack history. |
| A malformed WAV supplies data without a preceding format chunk, retaining a pointer at original entry ESP minus four. | The component accepts format history. The standalone binding does not reconstruct the original pointer's contents or lifetime. |
| Wrapped or unsafe accesses escape the reviewed live board, pending and saved-board objects. | Known aliases are transported. Unmapped addresses produce a capability diagnostic; that exit is not asserted equal to the original fault or access. |

Arbitrary asynchronous schedules, allocation histories and device failures are
also not exhaustively covered by the finite checks. Defaults and diagnostics
must remain distinguishable from preserved native behavior. Existing strong
qualification standards are unchanged and no qualification is inferred here.

These limits do not require a non-Windows runtime and are not hidden work items
in the practical delivery exit. Further fidelity work should be driven by a
concrete unsupported use case or observed discrepancy, with a local reproduction.

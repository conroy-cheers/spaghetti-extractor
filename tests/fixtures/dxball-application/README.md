# DX-Ball application shell

Four native entries become ordinary C in `shell.c`: WinMain's message loop,
window dispatch, instance acquisition and release. The [boundary](BOUNDARY.md)
records shared state, opaque resources, callbacks, output initialization and
the original semaphore/cleanup quirks. Platform setup and other remaining native
services have explicit adapters. This is not yet a portable desktop backend.

The local consumer invokes the original entry bodies under controlled services.
It needs the pinned executable to compare, but does not launch the game, create
a window or initialize DirectDraw. Its 28 cases cover initialization failures,
nonlocal process exit, message schedules, reentrancy, cursor failure, signed
message return bits, focus/power events and callback-sensitive resource release.
Inputs, ordered interactions, before/after state, identities, lifetime and full
palette bytes are observed. The exported consumer needs neither Wine nor the
original image.

Use the existing development environment. Retained shared input is the latest
normal comparison package, including its `source/scene-state.h` and transitive
shared headers. For the September 28 continuation this is
`build/dxball-event-memory-2026-09-28/normal-check/inputs`.

```sh
python tests/fixtures/dxball-application/prepare.py /path/to/DXBall.exe \
  /path/to/normal-check/inputs /tmp/dx-shell
spaghetti-headless-wayland spaghetti-extractor component check dxball application-shell \
  --comparison-package /tmp/dx-shell/application-shell --output /tmp/dx-shell-check
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/dx-shell-check --accept-boundary-change application-shell \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-application/assemble.py {project} /tmp/dx-shell-check' \
  --check-command 'make -j2' --check-command 'python check-shell.py'
```

Use a copy of the preceding 33-component source project. `candidate apply`
retains the previous project and rejects failed assembly/check commands. Set
the existing AArch64 `CC`/`AR` and use
`--check-command 'python check-shell.py --runner /path/to/qemu-aarch64'` for the
other architecture. All prior component definitions, objects and consumer
binaries can be retained unchanged.

For a meaningful deliberate defect, copy the comparison workspace and replace
`!services->get_message(user,state,&message)` with
`services->get_message(user,state,&message)!=1`. Check `--case get-message-error`.
The local interaction trace must differ: the original continues after minus
one. The checker retains both traces and a replay command. Do not change the
production C or rely on the full game's workload to reach that input.

The optional normal integration uses the existing platform and whole network:

```sh
python tests/fixtures/dxball-application/prepare-normal.py \
  /tmp/dx-shell-check/inputs /path/to/normal-check/inputs /tmp/dx-shell-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball application-shell \
  --comparison-package /tmp/dx-shell-normal/package --output /tmp/dx-shell-normal-check
```

This rebuilds the small input controller, not the pilot. It counts outer frame
calls at the common native frame entry and waits for their return, using hardware
breakpoints. It does not depend on a call-site instruction in replaced WinMain,
nor count a wrapper's nested original-body invocation twice. The input schedule
and preceding application observations are retained. Platform-generated messages
and raw OS handles are covered through controlled local comparisons rather than
treated as deterministic values in this normal workload. Entry counters remain
diagnostics, not branch coverage or proof authority.

Every semantic discrepancy found during integration must be expressible as a
local or small connected case. Missing cases are coverage gaps; inability to
represent, drive or observe them is a boundary/tooling gap. Finite comparisons
cannot guarantee that no unseen input will differ.

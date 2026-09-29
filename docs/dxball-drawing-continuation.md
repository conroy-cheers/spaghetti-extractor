# DX-Ball drawing continuation — 2026-09-27

The next public-workflow lift adds three native entries: destination selection at
`bd60`, transparent sprite drawing at `bd90`, and opaque drawing at `bdd0`.
The ordinary C component reuses the existing live sprite objects and font state.
Its graphics service carries the actual sprite object so that the source
rectangle's alias and service-side writes survive the boundary. There are no new
checker, compiler, artifact or proof-engine facilities.

The [reproducible recipe](../tests/fixtures/dxball-sprite-drawing/README.md) and
[manual boundary](../tests/fixtures/dxball-sprite-drawing/BOUNDARY.md) were authored
from the pinned executable/disassembly and existing C fixtures. No original
DX-Ball source or third-party implementation was consulted.

All fifteen new native comparisons pass. They observe exact call arguments and
results, signed coordinate encodings, mutable rectangle/width/selection state,
neighboring font behavior and cleanup. The original machine bodies are replaced
with traps on the selected side. Service error results remain observable.

`candidate apply` adds the unit to the existing asset/font source project, passes
assembly and both workloads, and publishes a seven-component project implementing
thirteen entries. All six existing implementations/interfaces are unchanged.
Five component records gain comparison references, while the loader record stays
identical. The incremental build compiles only the new operation, bridge and
consumer and reuses thirteen existing objects. The source consumers match all
21 retained cases on x86-64 and AArch64 under QEMU.

Normal-game execution now also selects the previously lifted font renderer.
All three runs exit zero, and 128 outer graphics calls plus 32 metric calls match.
The source executes destination selection nine times and transparent drawing 340
times; glyph/line/center entry wrappers execute 1/13/4 times. Metrics and cleanup
also run. Opaque drawing does not execute in this particular live workload and
retains its local native-case evidence. Actual allocation, sprite objects and
DirectDraw services are used, with original startup/TLS preserved.

The controlled standalone consumers do not constitute the full game. The live
probe observes only a prefix of calls, lacks frame/audio observation, and uses
wall-clock input/closure: total original/source drawing counts differ. These
limits remain explicit. No new significant tooling blocker was found; the DX-Ball
translation goal remains active. Remaining work includes sprite capture/restoration,
application event handling, game logic, platform backends and whole-game assembly.

Evidence root: `build/dxball-drawing-continuation-2026-09-27/`:

- `prepared/`, `check/`: public authoring and fifteen matching native cases.
- `normal-prepared/`, `normal-check/`: connected normal-entry comparison, selected
  entry counters and separate Wine/host logs.
- `program.apply-b_pdadzv/`: passing apply receipt, prior project and build/workload
  logs; `program/` is the published source project.
- `arm-program/`, `arm-build.log`: source-only AArch64 build and consumers.
- `validation.json`, `tree-audit.json`: verified scope and unrelated-tree preservation.

All Wine applications ran in headless Wayland. No pilot rebuild or formal
qualification campaign was needed for this continuation.

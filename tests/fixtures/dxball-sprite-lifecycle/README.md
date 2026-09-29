# DX-Ball sprite capture and restoration

This continuation adds capture at RVA `be10` and bank restoration at `bd00` to
the connected loader/font/cleanup workflow. The ordinary C and manual
[boundary](BOUNDARY.md) come from the pinned executable and disassembly; no
original DX-Ball source is used. No checker or compiler infrastructure changes
are needed. The reusable asset comparison adapter now supports repeated opens.

Use the tools/Python from `nix develop .#lifting` and the existing
[loader package](../dxball-sprite-font/README.md) and
[drawing source project](../dxball-sprite-drawing/README.md):

```sh
python tests/fixtures/dxball-sprite-lifecycle/prepare.py \
  /path/to/DXBall.exe /tmp/dx-assets/sprite-loader /tmp/dx-lifecycle
spaghetti-headless-wayland spaghetti-extractor component check dxball sprite-lifecycle \
  --comparison-package /tmp/dx-lifecycle/sprite-lifecycle --output /tmp/dx-lifecycle-check
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/dx-lifecycle-check --accept-boundary-change sprite-lifecycle \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-sprite-lifecycle/assemble.py {project} /tmp/dx-lifecycle-check' \
  --check-command 'make -C {project}' \
  --check-command 'python {project}/check.py' \
  --check-command 'python {project}/check-drawing.py' \
  --check-command 'python {project}/check-lifecycle.py'
```

All sixteen new native cases pass, including surface creation/copy failures,
describe retries, shared rectangle writes, null slots/surfaces, mode filtering,
the final bank slot and repeated real-file loads. Captured/restored memory,
pixels, ordered calls, outcomes and subsequent font/cleanup behavior are observed.
The source side traps the original operation entries. Existing source units and
interfaces are retained; this is a finite comparison, not universal qualification.

The resulting eight-component project implements fifteen native entries. All 37
retained cases pass on x86-64 and AArch64 under QEMU. Fifteen of sixteen existing
active objects are reused; only the common asset consumer is rebuilt alongside
the new component, bridge and consumer. The checked apply transaction retains the
previous project. The first failed transaction caught an inconsistent adapter
observation of the initial file-state field and did not publish the failed update.

Portable consumers need a C toolchain, Python and the shipped data files, without
Wine, the original executable or the lifting toolkit. Set `CC`/`AR` for another
architecture and pass `--runner` to each check script. Graphics services remain
controlled; this is a subsystem source project.

The live-game recipe uses real native allocation, file and DirectDraw services,
selects all eight components and preserves original entry/TLS:

```sh
python tests/fixtures/dxball-sprite-lifecycle/prepare-normal.py \
  /tmp/dx-lifecycle/sprite-lifecycle /tmp/dx-drawing/sprite-drawing \
  /path/to/game-assets /tmp/dx-lifecycle-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball sprite-lifecycle \
  --comparison-package /tmp/dx-lifecycle-normal/package --output /tmp/dx-lifecycle-normal-check
```

The controller reads pinned image state for readiness and sends window messages;
it never changes application memory. Reports keep selected-entry counters so
preparing a replacement cannot be mistaken for exercising it. Consult the
[continuation evidence](../../../docs/dxball-capture-continuation.md) for the live
result and remaining limits. Every Wine invocation requires headless Wayland.

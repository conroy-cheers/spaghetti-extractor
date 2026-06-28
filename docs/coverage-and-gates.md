# Coverage And Gates

Dynamic coverage is stored by test ID, observed module, module SHA256 when
resolvable, private RVA block/edge records, and report-facing stable labels.
Standard DynamoRIO `drcov` provides useful bootstrap basic-block coverage only.
The required coverage collector must trace dynamic basic blocks, CFG edges, and
call edges for the target Windows process or DLL harness. Gate requirements are
target-aware: new catalogs store target manifest metadata and use its oracle
suites, private harness suites, mutation kinds, and data-state kind lists.
Legacy catalogs without target metadata continue to use the Halo CE defaults.
The primary Halo runtime path is now a declarative Windows VM running Windows
`bin32\drrun.exe` against the original `haloce.exe` and `haloceded.exe`; Wine
probes remain compatibility diagnostics.

Use `nix run .#haloce-windows-vm-bundle` to generate the private libvirt XML,
Autounattend file, first-logon provisioning script, Windows guest trace script,
snapshot helpers, and host trace wrapper. The guest provisioning script enables
WinRM/OpenSSH, installs virtio/SPICE tools when staged, installs DynamoRIO,
stages the private Halo runtime, and writes `C:\HaloTrace\guest-ready.json`.
The host wrapper defaults `HALOCE_WINDOWS_VM_PASSWORD` to the generated local VM
password unless a regenerated bundle uses a different credential.
For non-Halo targets, the equivalent wrapper defaults come from the target
manifest's `[windows_vm]` table, including `admin_user`, `admin_password`,
`password_env`, `skip_reports_env`, `default_trace_target`,
`runtime_stage_dir`, and `runtime_stage_aliases`.
The guest trace script runs Windows `bin32\drrun.exe` with `halo_trace.dll` and
writes JSONL logs under `C:\HaloTrace\logs`.
Use the generated `scripts/prove-guest-trace.sh` wrapper, or call
`python -m haloce_catalog prove-windows-guest-trace` directly, for the normal
host-side workflow. It runs the guest trace, copies only the selected test's
result/log/part files, ingests the JSONL, and fails unless the expected module
has mapped block, CFG-edge, and call-edge rows. Pass `--skip-reports` or set
`HALOCE_WINDOWS_VM_SKIP_REPORTS=1` for fast iteration when report regeneration
is not needed.

Use the SPICE/QXL display profile for unattended install, provisioning,
dedicated-server tracing, and recovery. Do not treat QXL-only `haloce.exe`
client traces as gameplay coverage: the client needs a real Direct3D-capable
adapter to reach useful rendered menu/game paths. For PCI passthrough client
traces, generate or redefine a runtime VM with `--display-mode gpu-only` and
the selected `--gpu-pci-address` values after the guest disk has been
provisioned. That mode emits no emulated video adapter, so Windows must
initialize the passthrough GPU; the host must have the PCI functions bound to
`vfio-pci` before the VM starts.
Use `python -m haloce_catalog check-vfio-host --pci-address ...` after reboot
to verify the selected GPU functions, required kernel parameters, IOMMU groups,
reset hooks, and `vfio-pci` binding before starting the GPU-only domain.

After copying guest logs back to the host, ingest them with
`python -m wincr ingest-trace --db ... --log ...`. Gate evidence
requires the expected module SHA256 plus nonzero mapped dynamic block, CFG-edge,
and call-edge rows for the original PE. Public specs and reports should continue
to refer to stable labels; private module hash/RVA mappings stay private.
When a stable label is promoted into an internal routine contract, the same
coverage rule applies: the private oracle mapping must prove which original
module/RVA was exercised, while public reports expose only the label,
behavioral contract, and test evidence.

Use `HALOCE_RUN_WINE_TRACE_SMOKE=1 python -m unittest
tests.test_trace_wine_smoke` with `HALOCE_WINE_SMOKE_ROOT` set from
`nix run .#halo-trace-win32-smoke-root` for the public 32-bit PE proof target.
A passing smoke test proves the generated fixture can be cataloged, traced under
Wine, mapped by PE SHA256/RVA, and required to produce dynamic blocks, CFG
edges, and call edges. A pre-fixture `wine-preloader` signal failure is a public
minimal reproducer for the current Wine/DynamoRIO blocker. This diagnostic proof
does not replace the private Halo CE oracle trace.

The repository also builds `.#halo-trace-client-win32`, a MinGW 32-bit
`halo_trace.dll` linked against the pinned Windows DynamoRIO SDK. On the current
local Wine runtimes, Windows `drrun.exe` can create the target process but
fails before injection, while AppInit registration under WOW64 produces no
trace. Treat that as diagnostic evidence only; coverage credit still requires a
trace that contains the expected PE module SHA256 plus nonzero block, CFG-edge,
and call-edge rows.

Use `nix run .#halo-trace-wine-probe` to compare the pinned Wine stable and
WOW64 commands against the same public fixture. Use
`python -m haloce_catalog probe-wine-trace --smoke-root ... --wine-command ...`
for custom Wine builds/configurations. The probe writes one trace log per
candidate under `build/wine-trace-probes/traces/`, persists each candidate in
`trace_probe_results`, and regenerates
`build/wine-trace-probes/reports/coverage.json` plus `coverage.md`. These rows
record command, return code, timeout status, raw expected-module records, mapped
catalog rows, compact observed-module samples, direct non-instrumented PE
launch results, isolated or caller-provided `WINEPREFIX`, failures, tool
versions, and runtime provenance, making Wine runtime switches auditable before
changing the required coverage path. A direct launch pass with a traced-launch
failure means the candidate Wine build can run the fixture, but does not yet
prove DynamoRIO coverage. For real 32-bit Wine targets, prefer
`nix run .#halo-trace-wine-probe-i386-late`; its current-DR runner uses
`bin32/drrun -late` without child following by default so fresh-prefix Wine
service processes do not hide the target PE trace. Enable child following only
for cases where the target executable is known to hand off to another process.
The flake app also uses `--isolate-catalog-build`, `--isolate-trace-proof`, and
a file-backed direct Wine warm-up; this is the proven shape for avoiding Wine
bootstrap traces in the current runtime.
Nix Wine shell wrappers are normalized to their hidden ELF `WINELOADER` path
for tracing, with both wrapper and loader paths retained in provenance.
They do not satisfy `coverage-complete`; only ingested custom trace block,
CFG-edge, and call-edge rows can cover static control-flow items.

Use `nix run .#halo-trace-wine-probe-dr8-i386-late` for the pinned legacy
control: Linux DynamoRIO 8.0.0-1, `bin32/drrun`, a real 32-bit/i386 Wine
process, and `-late` injection. Current local evidence is still failing: direct
Wine 11.0 PE launch passes in a win32 prefix, but DR8 exits 255 from an internal
SIGSEGV before writing module records. DR8 stock `drcov` with `-late` exits 0
for the same style of process but writes only empty process logs, while early
injection hits glibc stack-smash/rseq failures. Keep this result visible as
compatibility evidence, not waived or covered dynamic control-flow evidence.

Keyboard/mouse gameplay stimuli can be captured with
`python -m haloce_catalog record-input --device ... --out ...` and replayed with
`python -m haloce_catalog replay-input --force --log ...`. These fixtures are
black-box process-test inputs. Keep raw captures private until reviewed, because
they may contain incidental desktop keystrokes or mouse movement unrelated to
Halo. Record traces with `--test-id` and `--scenario` so the private fixture can
be tied back to an oracle process-test row without publishing the raw input log.
Input replay is useful for repeatability, but coverage credit still requires the
corresponding Windows-guest DynamoRIO module hash plus RVA trace from the
original PE. Use `python -m haloce_catalog emit-qmp-input --log ... --out ...`
to convert private evdev captures into QMP `input-send-event` JSONL for
deterministic VM driving, then `python -m haloce_catalog replay-qmp-input
--log ... --domain <libvirt-domain>` or the generated
`scripts/replay-qmp-input.sh` wrapper to send the timed QMP events.

Objective gates:

- `catalog-complete`: every included/candidate executable section is covered by executable ranges, every executable range is covered by non-overlapping `executable_byte_classes`, no non-waived byte-class rows remain `unknown`, no functions remain unclassified, no label-bearing entities are missing labels, every included/candidate binary has passing LLVM plus rizin/radare2 static cross-check evidence, and no unresolved dynamic module names remain.
- `coverage-complete`: all included functions, basic blocks, CFG edges, and call edges are dynamically covered or explicitly waived.
- `interface-complete`: every static or dynamically observed platform endpoint has `mock_status = complete` plus passing `success`, `failure`, and `error_path` interface test-case rows. Use `record-mock-interface-suite` to seed evidence for the built-in public mock endpoint registry; unmodeled imports remain open.
- `data-state-complete`: known map/profile/save/packet/config structures and state machines have `spec_status = complete`, `fixture_status = complete`, and passing required data-state test-case rows. Map/profile/save/packet/config codecs require `fixture`, `malformed_input`, and `round_trip`; state machines require `fixture`, `malformed_input`, and `transition`.
- `oracle-complete`: original binaries have auditable passing oracle rows for every required black-box process suite (`client-startup`, `dedicated-server-console`, `map-discovery-loading`, `profile-save-config`, `loopback-networking`, `logging-errors`, and `representative-client-launch`) plus the private original-code harness suite (`private-internal-harness`). Process-suite rows require evidence, command text, and a fixture or trace artifact path.
- `mutation-effective`: each required mutation category has a killed `record-mutation-test` row. Required categories are `wrong_implementation`, `inverted_branch`, `skipped_external_call`, `corrupted_serializer`, `bad_packet_codec`, and `changed_mock_api_behavior`.
- `private-artifact-complete`: the latest `export-private-artifacts`/`export-dirty-corpus` dirty corpus has root `dirty-specs.*` and `dirty-tests.*` review indexes, private module packets, module disassembly packets, routine packets, dirty routine-contract drafts for every included/candidate module and function, and per-basic-block packets for every static block. Each block packet must include private identity, static/dynamic context, block-local disassembly, decompiler availability status, instruction metadata, p-code/data-flow/xref sidecars, semantic summary, and a clean rewrite template. The corpus also has per-row `review/` packets and clean derivation templates for every recorded behavior contract, behavior observation, process observation, internal routine contract, oracle row, interface case, data/state case, mutation case, internal harness, and harness run. These packets are dirty review input and may include raw RVAs, module hashes, disassembly, p-code, decompiler output, value traces, raw sidecar logs/results, and private oracle/harness details. `validate-dirty-corpus` must pass before the corpus is treated as ready for human/LLM cleanup.
- `dirty-reimplementation-ready`: the latest dirty corpus additionally has `reimplementation-plan.json/.md`, `cli-index.json`, offline `review-html/` output, routine semantic/decompiler status/p-code artifacts, block instruction/p-code/data-flow/xref/semantic-summary artifacts, and every reimplementation task links at least one private evidence file.
- `publication-clean`: generated public specs only include reviewed publication-safe internal routine contracts. Draft, rejected, and private-only routine material remains available in the private dirty corpus but is filtered from `specs.json` and `specs.md`.
- `reproducible`: reports include binary hashes, catalog version, custom tracer version, test IDs, required tool versions, non-empty test-run provenance, and the exact locked `nix-haloce` input source used for private reference/resource material.

Waived blocks remain visible. They are never counted as dynamically covered.

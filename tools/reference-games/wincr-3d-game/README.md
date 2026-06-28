# WinCR 3D Reference Game

This is a small public Win32 target for exercising the generic clean-room toolkit
before applying it to larger closed-source programs.

The game builds two observable PEs from one source:

- `wincr-3d-game.exe --json` emits a deterministic transcript suitable for
  black-box behavior contracts, clean-room implementation tests, and coverage
  tracing.
- `wincr-3d-game-window.exe --window-smoke --frames N` opens the Win32/GDI
  window path with scripted input and exits after `N` frames for offscreen
  interface/oracle tests.

The window fixture is cataloged as an excluded support PE. The deterministic
console PE is the included runtime target used for clean-room behavior and
coverage gates.

Build it through the flake with `nix build .#wincr-3d-reference-game`. The target
manifest and behavior contract are installed next to the binary under
`share/wincr/reference-games/wincr-3d-game`.

The checked-in `expected/*.json` files are behavior fixtures captured from the
original PE under Wine. A clean-room implementation can be compared with:

```sh
wincr compare-json-behavior \
  --expected-json tools/reference-games/wincr-3d-game/expected/orbit-seed7-180.json \
  --test-id orbit-seed7-180 \
  -- ./candidate.exe --json --scenario orbit --frames 180 --seed 7
```

`cleanroom_candidate.py` is a public implementation written from the behavior
contract. It is not used as the oracle. It demonstrates that the contract and
fixtures are precise enough for an independent implementation to reproduce the
observed transcript exactly:

```sh
python tools/reference-games/wincr-3d-game/cleanroom_candidate.py \
  --contract tools/reference-games/wincr-3d-game/behavior-contract.json \
  --json --scenario orbit --frames 180 --seed 7
```

The generated public spec can also drive all recorded JSON observations without
separate expected-file paths:

```sh
wincr compare-json-spec-observations \
  --spec-json build/reference-games/wincr-3d-game/reports/specs.json \
  --contract-id wincr.reference.3d-game \
  -- python tools/reference-games/wincr-3d-game/cleanroom_candidate.py \
    --contract "{contract_json}" --json \
    --scenario "{observed.scenario}" \
    --frames "{observed.frames}" \
    --seed "{observed.seed}"
```

The same generated spec also carries process observations for usage text,
default arguments, ignored unknown options, missing-value fallback, scenario
truncation, numeric coercion, stdout/stderr, and exit codes:

```sh
wincr compare-process-spec-observations \
  --spec-json build/reference-games/wincr-3d-game/reports/specs.json \
  --contract-id wincr.reference.3d-game \
  -- python tools/reference-games/wincr-3d-game/cleanroom_candidate.py \
    --contract "{contract_json}" "{input.argv}"
```

After packet-local clean templates have been rewritten and reviewed, the
derived clean spec can be run as one aggregate conformance suite:

```sh
json_template='["python","tools/reference-games/wincr-3d-game/cleanroom_candidate.py","--contract","{contract_json}","--json","--scenario","{observed.scenario}","--frames","{observed.frames}","--seed","{observed.seed}"]'
process_template='["python","tools/reference-games/wincr-3d-game/cleanroom_candidate.py","--contract","{contract_json}","{input.argv}"]'
wincr run-clean-spec-suite \
  --spec-json build/reference-games/wincr-3d-game/clean-derived/specs.json \
  --contract-id wincr.reference.3d-game \
  --json-command-template-json "$json_template" \
  --process-command-template-json "$process_template" \
  --artifact-dir build/reference-games/wincr-3d-game/cleanroom-compare/clean-derived-suite
```

The reference behavior contract also declares public
`coverage_requirements.required_records`. `validate-clean-specs` enforces these
requirements after derivation, so missing JSON/process observations, mutation
evidence, or representative data/interface records fail before the clean spec is
accepted.

The flake app `wincr-3d-reference-observe` rebuilds the catalog, captures
original-PE behavior under Wine, runs an offscreen window startup oracle through
Xvfb, compares the clean-room candidate against the public fixtures and the
generated `specs.json` JSON and process observations, records data/state
evidence, records mutation-kill evidence for representative wrong
implementations, exports the private dirty corpus, and validates that private
corpus for review-packet/evidence integrity. The default output target is the
private dirty intermediate under `private/reference-games/wincr-3d-game/artifacts`,
including root `dirty-specs.*` and `dirty-tests.*` review indexes.

For the repo-owned reference target only, set `WINCR_3D_REFERENCE_DERIVE_CLEAN=1`
when running the app to additionally promote the generated templates as reviewed,
derive and validate `build/reference-games/wincr-3d-game/clean-derived/specs.json`,
and compare the clean-room candidate against that derived clean spec.

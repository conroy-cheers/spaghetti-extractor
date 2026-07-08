# Plan

## Goal

Produce a fully verified jq reimplementation by repeatedly converting the
Stage A reference contract into small, source-mapped Stage B repair tasks.

The success condition is not pretty source. It is a candidate binary that
satisfies the Stage A contract for the original jq binary. Candidate-only public
behavior tests are kept as a red-flag backstop after Stage A passes.

## Boundary

Stage A owns binary-faithfulness evidence:

- PE layout, imports, relocations, image base, entry point, bitness;
- executable byte coverage;
- function ranges;
- blocks and direct CFG edges;
- roots, jump-table targets, import thunks, padding and alignment;
- ABI/callsite evidence;
- proof obligations, statuses, blockers, waivers, and Lean evidence.

Stage B owns source repair:

- C skeleton generation and fixups;
- function prototype and ABI repair;
- global/data reconstruction where needed;
- candidate-only crash/debug analysis;
- source-mapped repair reports.

Stage B does not trace or execute the original binary during iteration.

## Workflow

1. Build the canonical jq Stage A artifacts:

   ```sh
   nix build .#stage-a-jq-fixtures-check --no-link
   ```

2. Prepare a local slice workspace:

   ```sh
   nix run .#wincr-slice -- --work-dir build/wincr-slices prepare jq --realize-nix
   ```

3. Pick a focused contract item:

   ```sh
   nix run .#wincr-slice -- --work-dir build/wincr-slices next jq --top-k 20
   ```

4. Rebuild the local candidate outside Nix:

   ```sh
   nix run .#wincr-slice -- --work-dir build/wincr-slices build jq \
     --region <id> \
     --command-json '["./scripts/build-jq-candidate.sh"]'
   ```

5. Check the focused slice against cached Stage A feedback:

   ```sh
   nix run .#wincr-slice -- --work-dir build/wincr-slices check jq \
     --region <id> \
     --json
   ```

6. Repeat until focused checks and then global contract checks are clean.

7. Run the full Nix check set:

   ```sh
   nix flake check
   ```

## Iteration Rules

- Do not run original-output comparisons during Stage B repair.
- Do not spend time on runtime tests while Stage A reports unresolved contract
  failures for the candidate.
- Keep Ghidra output cached unless the skeleton generator or bootstrap export is
  intentionally being refreshed.
- Use the trivial contract smoke before expensive checks.
- Prefer local compile/check scripts for repeated candidate changes; use Nix for
  dev environment setup and canonical contract/full-suite validation.

## Current Nix Surface

- `.#wincr-tools`
- `.#stage-a-fixtures-check`
- `.#stage-a-jq-fixtures`
- `.#stage-a-jq-fixtures-check`
- `.#stage-b-jq-skeleton`
- `.#wincr`
- `.#wincr-slice`

Anything outside this surface should justify itself against the workflow above.

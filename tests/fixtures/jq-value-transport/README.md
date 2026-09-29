# Shared jq value representation experiment

## Reusable comparison driver for two owned values

[binary-driver.h](binary-driver.h) is ordinary operator-owned C support for a
common call shape: consume two `jv` references and return one owned value.
[Array search](../jq-array-indexes/driver.c) and
[string split](../jq-string-split/driver.c) now use 9- and 10-line wrappers that
name the original entry, replacement entry and admitted kinds. They supply their
own reviewed `native-entry.h`, shared value transport and allocation observer.
The helper changes no production operation or checker rule.

Copy `binary-driver.h` beside the other reviewed headers when preparing a new
comparison. Select it with `include_files`, the small entry wrapper with
`adapter_files`, and `observation_fields=["samples", "allocation_lifetime"]`.
The prepared package is self-contained; it does not look up this fixture directory
during checking. The recipes in this checkout find the shared header in the
sibling `jq-value-transport` directory; an external operator project should keep
that header with its own reusable C inputs and point its recipe there.

Each case supplies three arguments after the checker-supplied side:

| Mode | First argument | Second argument | Behavior |
|---|---|---|---|
| `retained` | Left JSON value | Right JSON value | Call once; keep and observe both input aliases. |
| `aliased` | Left JSON value | `null` | The second owned input is another reference to the first allocation. |
| `unique` | Left JSON value | Right JSON value | Keep no additional input references; observe the result and pre-call reference counts. |
| `unique-address` | Left JSON value | Right JSON value | Also observe whether a same-kind heap result uses the left input's former address. |
| `batch` | JSON array of `[left, right, optional_alias_bool]` rows | `null` | Call for each row, optionally sharing its inputs. |
| `program` | jq filter | Input JSON | Exercise the entry under the real interpreter; collect exactly one output. |

The third argument is the mode shown above. Batch rows remain live during the
batch, so their stored values add retained references; they are part of this
driver's caller context. Each sample records the result, both aliases' contents
and their reference counts. Program samples contain the interpreter output and
null direct-input observations. Allocation/lifetime accounting covers the selected
driver execution; it is not attributed to the component alone. The source side
also checks that the replacement was actually called.

The unique modes do not inspect consumed inputs after the call: their post-call
input fields are null. `input_references` records the pre-call counts, which lets
the operator verify the intended ownership context. `unique-address` captures
integer address bits while the input is live and compares them with the live
result. It never dereferences an expired input. This same-address observation
does not prove preserved contents or lifetime; an allocator may recycle addresses.
Use it only when that relationship is part of the reviewed boundary. Ordinary
`unique` mode permits implementation changes that preserve its selected values
and allocation/lifetime observations without requiring the same storage address.

The [append handoff](../jq-array-append/README.md#shared-driver-and-unique-owner-context)
demonstrates this distinction. Holding an extra reference temporarily forces a
copy while keeping the result unchanged. The ordinary unique case matches; the
explicit address case reports a mismatch and can replay it. This is an
observation choice, not a global prohibition on copying or representation changes.

A driver can use `SPX_JQ_ANY_VALID` for a parameter that accepts any valid `jv`.
An optional `case_fields(left_json, right_json, mode)` callback validates additional
case conditions and emits extra root JSON fields followed by commas. It runs
before entry installation and allocation accounting and returns zero to continue
or a nonzero status to reject the case. Append uses it to retain the existing
length admission check and `input_words` observation. Other wrappers pass `NULL`.

New ordinary inputs need no driver edit or compilation. For example:

```sh
spaghetti-headless-wayland spaghetti-extractor component check jq array-indexes \
  --comparison-package work --reuse-comparison baseline \
  --case operator-overlap --case-arguments '["[1,1,1]","[1,1]","retained"]' \
  --output overlap-check
```

The result retains that extra case in `inputs/`. Reopen those inputs to include it
in later checks. Existing workspaces keep their previous cases until explicitly
revised. Changing this shared C header invalidates affected driver compilations;
changing only case data preserves eligible compiled files.

To retain several hand-written or generated inputs together, use
`component start jq array-indexes --comparison-result baseline --case-file cases.json --output expanded`.
The file is a list of `{"id": "name", "arguments": ["left JSON", "right JSON", "mode"]}`
objects using the modes above. The printed check command runs the expanded suite;
the workspace retains its argument data and existing C. See
[case-file import](../../../docs/component-workflow.md#try-another-input) for the
complete format and ordering. The walkthrough in
`build/component-case-files-2026-09-24/` adds a shared-record input and a generated
batch through this command, then reuses the matching result on the next check.

The installed handoff is in `build/component-shared-driver-2026-09-24/checkpoint.json`.
It retains the six existing array/string comparison cases, adds the example above
with zero compilation, and detects/replays a missing release while output positions
remain unchanged. Repair reuses the matching receipt without compilation or execution.
This helper assumes valid JSON-representable values, the selected ownership context,
synchronous calls and the reviewed native runtime. Raw malformed bytes, nonlocal
allocation failure and other call shapes need a suitable explicit driver.
It does not establish preserved heap contents from pointer transport or supply
formal summaries. Existing specialized drivers remain available for those scopes.

## Shared value representation

Concat and append keep their ordinary authored C and existing generated V5
interfaces. Their selected bridge now passes `spx_jv_value_v2` directly between
components. The baseline transports native PE32 `jv` bytes. The alternative
transports a tagged slot and generation into a shared table that owns the actual
`jv` reference. It does not reconstruct contents or ownership from a pointer.

`value-transport.h` defines ownership operations: pack accepts an owned reference,
take transfers it once, borrow inspects a live value, and finish rejects remaining
owned entries. Copy and consuming jq operations preserve their existing reference
semantics. The table holds 32 simultaneously owned values, rejects generation
overflow, and diagnoses stale/double-transferred tokens and unreleased values.
This is bounded, single-threaded fixture infrastructure. Actual native libjq still
provides value storage, allocation, copy-on-write and primitive operations. It is
not a replacement for jq's heap implementation or a universal memory theorem.

The real cases compare result contents, retained input aliases, nested shared
objects, slices, reference counts and a unique destination that permits in-place
writes. The original side still calls the actual pinned PE32 libjq. Both
representations must produce identical logical observations; their token bytes
are deliberately not used as an equality oracle.

## Replacement group

Both component plans use the existing structural group definition shape:

```json
{
  "representation": {
    "group": {
      "id": "jq-array-values",
      "label": "Shared private array values",
      "members": ["array-concat", "array-append"]
    },
    "revision": "owned-handles-v1",
    "inputs": {
      "transport": "headers/value-transport.h",
      "implementation": "headers/value-runtime-impl.h"
    }
  }
}
```

The raw version is `raw-jv-v1`. Members name production components, not proof
regions. The group determines which selected implementations must agree on the
private representation; it does not merge the components or demand a synthetic
production function. Group membership is an explicit reviewed declaration, not
an inferred complete inventory of every reader in an application.
This initial comparison surface has one representation declaration per unit and
flat component selections; it does not expand nested groups or infer overlapping
ownership domains.

The shared selection checker compares group meaning, revision and exact bytes of
all named shared inputs. Inputs must belong to each component's include tree.
A stable signature or matching revision label is insufficient. Mixed selections
fail before compiler execution. Editing shared inputs requires a coherent group
selection and fresh affected checks. Ordinary body edits retain the same group
meaning and use the existing comparison invalidation machinery.

A standalone member can still be checked locally: the CLI displays missing group
members. That conditional result cannot authorize an experimental configuration.
The experimental policy must explicitly accept the representation for each member,
the complete group must be selected, and every selected implementation must match
its retained local check plus the real integration check. No declaration or test
becomes a checked compatibility theorem or strong qualification receipt.

## Public workflow

Run these commands in `nix develop`, inside one headless Wayland session.
For a scripted walkthrough, use `spaghetti-headless-wayland bash walkthrough.sh`
with the commands below in that script. Keep the same desktop session across
checks intended to reuse evidence: starting a new compositor changes the bound
execution environment and correctly invalidates that reuse.

Build the two handle-based packages through the existing SDK:

```sh
APPEND_PACKAGE=$(nix build --no-link --print-out-paths \
  ./targets#legacyPackages.x86_64-linux.targets.jq.target.array-append-handles-comparison-package)
NETWORK_PACKAGE=$(nix build --no-link --print-out-paths \
  ./targets#legacyPackages.x86_64-linux.targets.jq.target.array-concat-handles-comparison-package)
```

With those paths assigned and the project CLI available, create drafts and check
them:

```sh
spaghetti-extractor component start jq array-append \
  --comparison-package "$APPEND_PACKAGE" --output /tmp/append-handles
spaghetti-extractor component start jq array-concat \
  --comparison-package "$NETWORK_PACKAGE" --output /tmp/concat-handles
spaghetti-extractor component check jq array-append \
  --comparison-package /tmp/append-handles --output /tmp/append-handles-check
spaghetti-extractor component check jq array-concat \
  --comparison-package /tmp/concat-handles \
  --dependency-package array-append=/tmp/append-handles \
  --output /tmp/concat-handles-check
spaghetti-extractor candidate build jq \
  --experimental-comparison /tmp/concat-handles-check \
  --component-comparison array-append=/tmp/append-handles-check \
  --experimental-policy tests/fixtures/jq-value-transport/experimental-policy.json \
  --output /tmp/jq-handles-experiment
spaghetti-extractor candidate test jq \
  --experimental-package /tmp/jq-handles-experiment --output /tmp/jq-handles-run
```

The existing `array-append-comparison-package` and
`array-concat-integrated-comparison-package` expose the raw baseline. Selecting a
raw append draft into the handle network rejects the changed contract. Relabeling
that draft without changing its runtime still rejects different shared bytes.

For an ownership error, remove `services->copy(environment, value)` from append's
length calculation and pass `value` directly. Length consumes the owned handle;
the later set diagnoses its expiration. Removing concat's release of `right`
instead diagnoses an unreleased owned value. Restore the ordinary C and rerun.
Rechecking the unchanged repaired group can reuse its prior matching evidence.

Retained commands, transcripts and audits are under
`build/practical-lifting-2026-09-15/representation-v2/`. The earlier v1 retains a
compiler integration failure caused by the pinned jv header's unused static
helper. The shared runtime now exposes the actual validity operation, retaining
strict compiler diagnostics rather than weakening the warning flags.

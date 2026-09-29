# jq path services and standalone source delivery

The 2026-09-27 continuation resolves the remaining lexical path dependency using
the existing component and assembly workflow. Program support, file input and
module search share an ordinary C Windows path provider. No checker, compiler,
artifact format, proof rule or source-assembly engine changes were needed.

## Shared path contract and actual consumers

Program support gains three original entries: `jq_realpath`, `dirname` and
`basename`. The path library adapts Wine 11.0 lexical normalization and MinGW-w64
13.0.0 path-part behavior with retained licenses and source identities. It
separates path syntax from the host namespace provider. The C remains independent
of jq; its header states ownership, aliases and the dirname scratch lifetime.

The implementation preserves the original 260-byte canonicalization capacity,
nonexistent paths, drive-relative/current-directory behavior, UNC roots, dot and
space normalization, and failure returning the original input. The POSIX adapter
maps logical Windows drives and shares to declared host directories. NUL maps to
`/dev/null`; other device I/O and full Win32 filesystem semantics remain outside
the profile. UTF-8/single-byte syntax is supported; DBCS is excluded. ASCII case
folding is separate from general Unicode case equivalence. Mapping declarations
must correspond to the filesystem and cannot race calls.

The first assembled run found sixteen genuine module failures. Canonicalization
now produced Windows drive/UNC names, but module search still used its POSIX
leading-slash test. The failed `candidate apply` transactions retained their
proposals and left the working projects unchanged. Reopening the existing
module-loader comparison and editing its private path helper resolved the
mismatch. All hosts now use the shared `PathIsRelativeA` byte rule. No new public
component operation or checker rule was needed for that private helper.

**104 program-support, 25 file-input and 25 module-loader native cases match.**
Original entries and selected private bodies are disabled in source comparisons.
The observations include output bytes, path aliases, buffer frames, input
reference preservation, diagnostics, live consumers and allocation lifetime.
CRT dirname scratch allocation is separate from observed jq allocations and has
an explicit module owner; it is not presented as proof of heap equivalence.

**Both x86-64 and AArch64/QEMU match 324 CLI cases and 32 live-value scenarios.**
The new normal-entry cases exercise drive-absolute, drive-relative and case-folded
file names, nonexistent-parent normalization, raw/slurp input, nested imports,
mapped UNC files/modules, missing mappings, empty names and NUL. The runner maps
the same host directories into Wine and the portable namespace and retains their
file hashes. All Wine execution uses a headless Wayland desktop.

The projects retain 42 host and 43 ARM components; ARM retains its existing
separately selected string-hash component. All **39/40 unaffected component
records and 493/499 component files** are unchanged. **186/187 objects** retain
both bytes and mtimes; sixteen change or are added. The old util object contains
no functions, and each selected path entry has exactly one final provider.

## Costs

No pilot preparation/rebuild, model generation or solver work was performed.
Retained binaries, cases and comparison inputs were reused. Costs below are
seconds from the exact retained runs; compiler phase values sum child work and
are not wall time. Manual analysis and authoring were not separately timed.

| Check | Preparation | Compiler | Link | Case execution |
| --- | ---: | ---: | ---: | ---: |
| Program support | 0.021 | 0.735 | 0.064 | 15.197 |
| File input | 0.010 | 0, cached | 0.064 | 3.303 |
| Module loader | 0.014 | 0.982 | 0.064 | 6.615 |

Wine startup adds approximately 3.6–4.0 seconds of wall time per comparison.
Incremental program builds take 0.816 seconds on the host and 11.936 on ARM.
Whole-program runs take 17.238 and 32.388 seconds respectively.

## Retained evidence

The clean delivery audit passes. `jq-portable-host-source.tar.gz` and
`jq-portable-arm-source.tar.gz` contain source-only projects with conventional
Makefiles, generated configure, local component guides, licenses and an explicit
library inventory. The archives are about 3 MB each. `deliver.py` omits objects,
native binaries, cached builds and previous proposals; it requires review of the
actual remaining backend members before packaging.

Both archives were extracted into new directories and built from scratch using
ordinary Make commands. The execution traces show no extractor, Python, Nix or
Wine subprocesses in either build. Configure/C toolchains and standard POSIX
utilities remain build dependencies. No source inputs changed during compilation.
Fresh builds take **53.013 seconds on x86-64 and 265.054 on AArch64**, including
configure and bundled libraries. These one-time delivery costs are separate from
the sub-second/12-second incremental builds above.

Both clean binaries again match **324 CLI and 32 live-value cases**, with every
selected component reached. The link audit confirms one provider per declared
entry, absence of all retired backend definitions, and only five backend archive
members carrying retained code: three forwarding accessors in `jv.o`, Gay's
conversion library, two decNumber library objects and the generated Flex lexer.
Oniguruma is a separate library. The selected language parser explicitly retains
Bison-generated tables/actions plus component adaptations; the old backend parser
object is not linked. Generator versions, grammar/source references and licenses
are included. These reused libraries are not claimed as handwritten lifts.

The clean builds use the toolchains' dynamic platform C runtimes. An initial
optional static-link attempt found no installed static libc and is retained as
a toolchain limitation; no source change was needed for the normal build. The
delivered artifacts are portable source projects, not universal binary packages.

This completes the bounded **practical, source-assisted jq delivery attempt**.
It does not complete broad arbitrary-Win32 readiness or strong qualification.
The runtime profile remains explicit, including filesystem, terminal, encoding,
threading and allocation-frontier limits. No significant lifting-tool limitation
remains at this stopping point.

Repository metadata, production Python lint and format-registry checks pass,
along with fixture Python syntax and whitespace checks. Unrelated starting edits
are preserved. The earlier strong proof obligations are neither rerun nor
claimed by these practical results.

`build/jq-path-services-lifting-2026-09-27/` contains:

- `support/final/`, `file-namespace/checked/`, `module/checked/`: native evidence.
- `program/`, `arm-project/`: incrementally updated working projects.
- `host-final-build/`, `arm-final-build/`, and matching `*-run/`: program receipts.
- `host-integrated-run/`, `arm-integrated-run/`, and failed `*.apply-*` projects:
  the real module-search discrepancy before repair.
- `prepare-module.py`, `apply.py`, `verify.py`, `result.json`: retained local edit,
  assembly, reuse and link audit recipes/results.
- `jq-portable-*-source.tar.gz`, `relocated/`, `delivery-*-build/`,
  `delivery-*-run/`, `verify-delivery.py`: clean source archives, build execution
  traces, unchanged-input checks, normal-entry comparisons and library audit.
- `tree-audit.json`, `validation.json`: repository checks and exact dirty-tree
  preservation against the starting 2,498-file inventory.

The reusable C, native comparison recipes, namespace runner and clean delivery
recipe live under `tests/fixtures/portable-runtime`, `jq-program-support`,
`jq-file-input` and `jq-portable`. The module-loader edit reopens its retained
public comparison workspace; its source is exported in both delivered projects.

Formal qualification remains separate from practical source delivery. These are
finite behavioral comparisons and explicit runtime assumptions. They do not
establish arbitrary Win32 portability or universal correctness.

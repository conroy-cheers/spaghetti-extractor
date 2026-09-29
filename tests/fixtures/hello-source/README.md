# Hello source handoff and remaining program closure

The public `candidate export` command exports the existing compared C selection
through canonical V3 source packages. It produces a conventional Makefile and
`liblifted.a`, without original PE/DLL files, fixture drivers or the extractor as
a build dependency. The export is a component library; Hello's application entry
and runtime/service bindings are separate integration work. The subsequent
[standalone recipe](../hello-standalone/README.md) supplies that work and tests
x86-64/AArch64 execution within an explicit Windows-1252 environment scope.

Use the matching connected comparison from the
[program recipe](../hello-program/README.md) and string comparison from the
[new-boundary trial](../hello-string-conversion/README.md). Inside `nix develop
.#lifting`, the reproducible check is:

```sh
python tests/fixtures/hello-source/walkthrough.py \
  build/hello-program-workflow/program-repaired \
  build/hello-string-workflow/local-repaired build/hello-source-handoff
```

For direct use:

```sh
spaghetti-extractor candidate export gnu-hello \
  --comparison build/hello-program-workflow/program-repaired \
  --comparison build/hello-string-workflow/local-repaired --output build/hello-source
cd build/hello-source
make CC=cc AR=ar
```

The standalone recipe accepts this handoff with `--source-export`; include a
matching `stream-close` comparison in the export for its shutdown backend. Source
assembly then needs only the library, the reviewed application/backend C and the
pinned option-scanner archive. Keep comparison workspaces separately for future
local edits; they are not assembly or build inputs.

The walkthrough copies the project outside the checkout, builds with ordinary
`make`, C compiler and archiver, and checks every selected operation's symbol.
It supplies no Python/module/Nix build variables to that build. The tools on this
machine are Nix-provisioned; this is not a claim to have tested a separate OS image
without a Nix store. The generic integration test also deletes the comparison
workspace before compiling and executing a two-component consumer with an explicit
portable binding. It does not run Hello itself.

The source packages retain exact compiled headers, authored C, interfaces, boundary
narratives and licenses. `source-export.json` records comparison identities,
contracts, requirements, representation/resource constraints and missing integration.
Known mismatches, stale inputs, conflicting selections and edits during copying
reject. Rebuilding or editing outside the workbench does not transfer the old
comparison or qualification to the new artifact. Run `make clean` when changing
toolchains or flags; this conventional build is not the workbench's compiler cache.

## Application dependency inventory

Inspection used the same pinned Hello executable as the preceding recipes. The
mixed normal-entry recipe supplies these original responsibilities. The standalone
follow-up implements them for its declared environment; wider runtime coverage
remains separate:

| Responsibility | Current evidence and required delivery |
| --- | --- |
| Application control | `_main` at RVA `0x14548..0x14628` resets state, sets the program name/locale and close handler, parses options, allocates/converts/prints/frees the greeting, then exits. Author this control around the existing lifted allocation/conversion operations. |
| Option loop and presentations | `_parse_options` at `0x1587..0x1720` and `_print_help` at `0x1440..0x1587` still execute as original code. Preserve short groups, long options/abbreviations, ordering, operand/error handling, help/version text and environment effects. |
| Reusable option service | Original `rpl_getopt_long` and its shared state still implement scanning/permutation and diagnostics. Supply a reviewed portable backend or lift it; a same-named host function alone does not establish compatibility. |
| Locale and conversion | Lifted conversion still calls the lower CRT service. Native `C`, Japanese code-page behavior and controlled UTF-8 are distinct contexts. The target's four-byte state is not a host `mbstate_t` layout. |
| Output, errors and termination | `__mingw_wprintf`, diagnostic formatting, `close_stdout`, errno, allocation failure, buffering and exit remain platform responsibilities. Exercise output failure and memory/service effects, not only successful greeting text. |
| Startup and source assembly | Existing DLL experiments execute original startup/TLS. A standalone source application needs explicit replacement runtime initialization and no application-code fallback. Its compiler/runtime and backend evidence are separate from PE receipts. |

The standalone investigation corrected an earlier attribution here: with Wine's
Unix launcher under `LC_ALL=C`, `café` becomes `cafC)` **before main entry**. This
is input transport, not later Hello output conversion. MSVCRT's default locale is
also selected from Windows rather than Unix `LC_ALL`. The new recipe records
Windows narrow-byte arguments independently before application execution, checks
actual original main entry and supplies identical bytes to the portable process.
Program-name/path diagnostics and text-mode line endings likewise need explicit
transport; successful text alone did not reveal the intermediate UTF-16 mismatch.

The follow-up supplies source and real program execution on two architectures for
that bounded configuration. Additional locales and runtime conditions remain
unsupported; the broader practical goal and separate G1–G7 strong-assurance
objective remain open. More component fixtures cannot replace those missing paths.

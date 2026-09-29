# String conversion workspace

This manually reviewed component owns the complete `rpl_mbsrtowcs` entry at
Hello RVA `0x29a4..0x2b28`, its cold fragment `0x14628..0x14630`, and the use of
its implicit four-byte state at `0x30300`. The pinned input hash is in the package.
The partition row identified the operation; disassembly supplied its behavior.
This is an agent-run first preparation, not an independent human usability study.

| Boundary knowledge | Local authoring rule |
| --- | --- |
| Input | A live pointer-to-pointer cursor into a NUL-terminated readable byte span. |
| Output | Optional live array of target-width `uint16_t`, with at least `limit` words. |
| State | Optional live four-byte conversion state. NULL selects the component's distinct implicit cell. |
| Shared layouts | `multibyte-objects.h` defines the existing byte/state/word proxies; `string-objects.h` adds only the live cursor. No copied heap or reconstructed lifetime. |
| Aliases | Input bytes can share output's `uint16_t` backing allocation. An explicit state can name the implicit cell. State/output and cursor/output overlaps are excluded. |
| Service | `decode16(output,input,size,state)` receives live proxies, returns consumed bytes, zero for NUL, or target error sentinels. This consumer admits size 1–5. |
| Outcomes | Written character count; `UINT32_MAX` with target errno 42; incomplete decoder result forwards non-returning `invalid_state`/CRT abort. |
| Counting | NULL output ignores limit, copies state, leaves cursor and original state unchanged, but still observes decoder errors and errno. |
| Writing | Updates state/output each step; updates cursor on limit exhaustion or error; clears cursor after decoded NUL. Output words after the write frontier retain their contents. |
| Environment | Synchronous single-threaded calls; real C/Japanese CRT contexts and separately labeled controlled service outcomes. Array byte extents and cursor differences fit signed 32 bits; output limit is below `2^30`. No volatile memory, invalid pointers or overflow. |

Main is a real caller: it sizes an allocation with `strlen`, then invokes writing
conversion once. Count-only calls and resumptions are additional local contexts
exposed by the actual operation; the program workloads do not exercise them.
Together these test distinct state treatment, a loop and mutable shared memory.
Ordinary implementation edits need only this contract, the C file and examples.
Changing these assumptions requires re-review of callers and adapters.

Examples and generated cases are in the package's case list and retained driver:
empty, ASCII, embedded terminator, Japanese multibyte input, malformed sequences,
eight reproducible generated strings, limits 0/1/2/8, count/write/overlapping
storage, explicit/implicit/explicit-alias state, and resuming a partial conversion.
Observations include full input/output frames, cursor, errno, both states and
ordered call-time decoder effects. Controlled incomplete results execute actual
CRT abort in supervised child processes with a pre-abort memory snapshot.

Local comparisons retain the native decoder. Program integration reaches whichever
decoder the connected selection installs. That relationship is tested execution,
not body-independent proof or checked contract compatibility. A stable C signature
alone is insufficient. The comparison's assumptions and evidence remain visible.

The five-byte length bound follows four explicit terminator checks and the original
`strnlen1(p+4,1)` call. Its result is always one for readable ordinary memory;
authored C folds that helper without retaining its original algorithm body.
The target's two-byte words and four-byte state are explicit representation
choices, not assumptions about host `wchar_t` or `mbstate_t`.
The signed extent bound is deliberate: the machine computes writing counts with
an arithmetic shift of a byte-pointer difference. This trial does not establish
the operation's behavior for allocations reaching that signed-overflow frontier.

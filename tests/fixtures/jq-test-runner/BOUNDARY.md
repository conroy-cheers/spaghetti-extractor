# jq internal test runner

This is the existing --run-tests feature, including value checks, test-file
processing, start-state regression checks and all three pthread workers. It is
source-assisted from pinned jq 1.8.1 under COPYING. Decimal-number and threaded
branches are included explicitly; host configuration cannot silently omit them.

The operation consumes library directories and borrows valid argument strings.
The --skip and --take options require their value argument, as in the original
defined input domain. Values, parser/compiler/interpreter operations, allocation,
stdio output, random formatting choices and pthread execution are shared services.
Workers own separate jq/parser instances; borrowed stack data survives until join.
Tests do not mutate the same jq context concurrently. Thread failure assertions
and runtime failure outcomes remain in C; finite comparisons cover successful
worker startup and ordinary malformed test files, not all resource failures.

Input uses the existing Windows file/text provider and the process stdin decoder.
Named test files always use text mode; stdin retains the CLI-selected binary mode.
The original named FILEs remain open until CRT shutdown. The portable provider's
decoder wrapper has the same process lifetime here. Replacing this with eager
close would change a separate resource-lifetime decision.

The native comparison uses real jq startup and process termination. It disables
the complete original test-runner object, including helpers, and checks byte-exact
stdout/stderr, actual exit status and thread create/join counts. An untouched
original also checks that the observer is transparent. Ordinary CLI cases exercise
the standalone replacement on both architectures. These are practical behavioral
comparisons; they are not universal proof or permission for strong activation.

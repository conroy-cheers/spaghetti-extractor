# Last-brick warning boundary

The pinned DX-Ball image has SHA256
`191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f`.
Preparation at `0x408c20` and drawing at `0x408ed0` borrow the existing progression,
brick/motion/board, gameplay and sprite-bank objects. The deadline is gameplay's
`warning_sound`; y and remaining frames belong to progression. The new warning
view owns x and the shared source rectangle. No original source was consulted.

Preparation takes an explicit, invocation-local historical input: native entry
ESP -28 supplies y, -24 row and -20 column and initial x when the scan finds no
byte other than zero/two. The C snapshots this input before services, avoiding
uninitialized locals and host stack dependence. It does not repair the native
empty-board behavior or impose an unsupported tile restriction. The input is
separate from mutable public state; services do not alias private native locals.
It describes entry state, not an output contract for arbitrary future reuse of
the released native stack. Each caller must supply its next invocation's input.

`history.h` projects the reviewed native gameplay-frame producers into those
three words. The frame's incoming EBP/ESI are explicit original-environment
values. Paddle's final sprite call supplies row and its retained vertical offset;
frame sprite calls and pickup sprite calls have distinct saved-register layouts.
Particle describe/lock preserve descriptor words 20..22 and partial writes across
lock retries. Empty lists preserve preceding history. These are adapter effects,
not new game operations. The provider must be checked in an actual connected
consumer before it authorizes assembly; an untested helper alone supplies no
composition evidence. Normal platform wrappers must carry this state explicitly,
not read their own recompiled stack or cast host function pointers.

Queue receives the raw coordinate words and may use the refined original-address
read service, including its declared `memory-fault` outcome. The direct warning
consumer observes queue requests with controlled services; it does not consume
out-of-grid events or establish general portable memory mapping. Read access and
subsequent event processing keep their own boundaries. Audio, queue, explosion,
particle and rendering services can synchronously mutate public state. Their
order and subsequent reloads are observed. Services return normally in the direct
cases; fault propagation needs an appropriate nonlocal consumer.

Clock/random results are explicit inputs. Integer operations wrap at 32 bits;
signed comparisons and halving use the existing portable helpers. Sprite objects
and surfaces remain live at each dereference. Drawing passes the live source
rectangle to blit, then constructs its damage rectangle using current shared
coordinates and dimensions. Mutations to frame count during callbacks survive
until the final decrement. No concurrency or arbitrary writes into private
caller frames are assumed by these cases.

Original/source comparisons and portable execution provide finite practical
assurance. Declarations are not checked heap summaries or formal qualification.
Every semantic integration discrepancy must remain reproducible through local
or small connected consumers. Complete game/platform delivery remains required.

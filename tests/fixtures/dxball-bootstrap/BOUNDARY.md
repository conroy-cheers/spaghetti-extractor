# First-frame and palette initialization

Selected complete machine bodies are first-frame initialization
`0x40ad10..0x40ae1f`, initial palette setup `0x4022b0..0x402313`, and surface clear
`0x402710..0x402761` in the pinned DX-Ball image (SHA-256
`191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f`). No original
application source is used.

The component borrows the existing application, scene, title, flow and PCX
palette objects. Their identities remain stable within a call. Surface, device
and palette handles can change during services; the component reloads them where
the original reloads globals. Aliases `flow.primary/back` and `title.primary/back`
refer to the same resources. Overlay and palette publication is observable even
on a nonzero creation status; no cleanup is invented. The original clears RGB
in both palettes but preserves each flag byte. Failure to create the overlay
terminates with status 1. The selected termination service does not return.

The descriptor boundary includes precisely the defined DirectDraw fields: size,
flags, caps, width and height for overlay creation; rectangle, effect size,
fill color and blit flags for clear. Fields that the original leaves uninitialized
and the selected API does not consume are not made meaningful by zeroing C
storage. A platform or callback that reads those fields needs an explicit history
contract. Native call adapters bind these component services; they do not implement
another DirectDraw test backend. Normal execution uses actual DirectDraw objects.

Scores, boards, seeding and clocks remain explicit services. Normal execution
uses the selected score/board C and current native runtime services. Local cases
record their ordered calls and synchronous changes to the shared state. The
refresh measurement makes exactly 32 vertical-blank calls, reloading the device
each time, ignores their statuses and uses unsigned elapsed arithmetic with a
strict `> 400` comparison. Exactly-one fast mode overrides the result; other
nonzero fast modes do not. The final clock call publishes `last_refresh` even if
its callback changes other state. Absolute clock values are local inputs and
normal-run diagnostics, not deterministic whole-program observations.

The clear body ignores its platform status, so its abstract return is void. It
always supplies rectangle `(0,0,640,480)`, flags `0x400`, effect size 100 and the
full 32-bit color. Local callbacks record all these defined inputs and palette,
resource and scalar state before/after effects. The resource mapping observes
live published objects; constructing a pointer alone is not a lifetime proof.

Finite comparisons and real consumers provide experimental evidence. These
operations do not supply a production portable clock, random generator, graphics
backend or standalone game entry point. Those remain on the integration worklist.

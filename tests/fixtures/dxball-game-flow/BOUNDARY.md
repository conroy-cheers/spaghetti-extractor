# Frame, scene dispatch and recovery

Authority is DXBall.exe SHA-256
191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f.
No original game source is consulted. Native cdecl entries are frame ab10,
key abf0, enter ac60, leave aca0, redraw aad0, check-surfaces aa50,
restore aaa0 and shutdown ae50. Only frame has an observed return value (one).
The other callers discard EAX; their portable operations return void.

The shared state names the current and requested scenes, pending transition,
first-frame flag, windowed/refresh flags, audio state, three graphics objects and
the existing sprite asset state. Scene IDs 0..4 dispatch to menu, game, options,
scores and splash; other unsigned values dispatch nothing. Windowed/first-frame
and transition flags test nonzero, while refresh tests exactly one. Fields remain
32-bit words. The shutdown first-frame test deliberately retains the binary's
direction, even though it may appear surprising.

Synchronous services may change this state. The implementation reloads requested
scene after leaving, current scene for entering, and audio/back/overlay identities
after earlier callbacks. It clears pending only after entering and clears overlay
after Release, including callback writes. No lifetime is inferred from a pointer.
Native adapters retain actual object identity, storage and reference ownership;
the controlled adapter keeps tombstones for observations.

Surface status is GetBltStatus(1); only HRESULT 0x887601c2 triggers recovery in
fullscreen mode. Recovery stops at the first nonzero Restore HRESULT, then calls
the existing sprite restoration component and dispatches scene redraw. Audio
GetStatus supplies a written status word; its HRESULT is ignored by the binary.
The service exposes that word, requires it to be written, and Restore runs only
when bit two is set. A failing call leaving the output uninitialized is outside
this boundary's admitted domain. Scene/platform initialization remains a service.

The native comparison retains actual dispatcher bodies and replaces only declared
scene/platform service entries with ordinary C adapters. Source runs trap selected
dispatcher bodies and reuse existing sprite restoration, loader, font and cleanup
components. Cases observe ordered services, callback mutations, shared sprite
contents, file/graphics effects and final cleanup. These are finite behavioral
comparisons, not universal proof, game-loop scheduling or complete gameplay.

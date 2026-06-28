# Media, Graphics, Audio, And Network Service Interfaces

Clean-room implementation work should model these interfaces by behavior, not by
copying implementation expression:

- D3D/DDraw/GDI/windowing/gamma: device creation, mode selection, lost-device paths, cursor/window focus behavior, and failure codes.
- DirectInput: device enumeration, acquire/unacquire, polling, buffered input, and missing-device behavior.
- DirectSound/WINMM: device enumeration, buffer creation, playback state, volume, failure paths, and shutdown ordering.
- Winsock/GameSpy/Keystone: DNS, sockets, server discovery, authentication/service calls, timeouts, retries, malformed packets, and offline behavior.
- Bink: open/close, frame stepping, skipped video, audio sync, and missing/corrupt media behavior.
- CRT/TLS/heap/runtime behavior: allocation, locale, floating-point mode, TLS callbacks, atexit ordering, and crash-safe cleanup.

Each endpoint needs success, failure, and error-path tests before
`interface-complete` can pass.

The public mock package now provides deterministic behavior models for these
families:

- `MockGraphics`: display mode enumeration/selection, window focus, gamma ramp,
  lost-device, reset, and present behavior.
- `MockDirectInput`: device enumeration, acquire/unacquire, polled state, and
  buffered input events.
- `MockDirectSound`: device enumeration, buffer creation, play/stop, volume, and
  missing-device behavior.
- `MockNetworkServices`: DNS resolution plus GameSpy/Keystone-style request,
  offline, timeout, and missing-response behavior.
- `MockBink`: media open/close, frame stepping, end-of-stream, missing media,
  and corrupt media behavior.
- `MockRuntime`: heap allocation/free, TLS values, atexit ordering, locale, and
  floating-point mode state.

`record-mock-interface-suite` records the public success, failure, and
error-path evidence rows for known mocked endpoints. It does not waive or hide
unknown imports; those remain open in `interface-complete`.

These mocks are intentionally behavior-level. They do not encode original
instruction sequences, decompiler text, or private harness internals.

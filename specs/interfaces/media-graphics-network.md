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

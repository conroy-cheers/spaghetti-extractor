# Detailed Oracle Suite

The detailed suite describes behavior that a future clean-room runtime must
satisfy. The original binaries must pass the same suite under the declarative
Wine prefix before a clean-room implementation is judged against it.

Initial process-level suites:

- `client-startup`: launch client with non-networked startup options, suppress video where possible, assert process lifetime, log/config effects, registry reads/writes, and module load set.
- `dedicated-server-console`: launch `haloceded.exe`, feed command scripts, assert console output, config parsing, map-cycle behavior, and clean shutdown.
- `map-discovery-loading`: enumerate stock maps, malformed map fixtures, missing-map errors, and selected multiplayer/single-player load paths.
- `profile-save-config`: create/read/update/delete profile, save, controls, video, audio, and network configuration state without storing real user secrets.
- `loopback-networking`: establish local client/server discovery, connection, packet exchange, timeout, retry, and disconnect behavior.
- `logging-errors`: verify filesystem paths, log formats, error codes, and failure behavior for missing files, denied writes, invalid registry values, and unavailable network endpoints.

Private harness suites may call routines that process tests cannot reach. Those
harnesses must still execute original PE code and produce behavior-derived
fixtures/results that do not leak proprietary expression. Specs and tests should
refer to stable labels; raw module-hash/RVA mappings stay in private catalog
data and can be removed during a later sanitization pass.

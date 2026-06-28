# Mutation Effectiveness Spec

Mutation evidence proves the detailed specs and tests reject representative
wrong clean-room implementations. It is not original-binary code coverage, and
it must not store decompiled bodies, copied pseudocode, original assets, or
instruction-level proprietary expression.

Internal routine contracts need mutation pressure too. When a routine label has
a sanitized behavioral API, add mutations that violate its preconditions,
postconditions, side effects, state transitions, serializers, or error paths.
The evidence should cite the public contract label and fixture/test that killed
the mutation, not the private module-hash/RVA mapping.

Record behavior-derived evidence with:

```sh
python -m haloce_catalog record-mutation-test \
  --db build/catalog/catalog.db \
  --mutation-kind corrupted_serializer \
  --target-label data_map_cache_file_header_... \
  --test-id cache-header-corrupted-serializer \
  --status killed \
  --fixture-path private/mutation/cache-header-corrupted-serializer.json \
  --evidence "round-trip and malformed-input tests reject the corrupted serializer"
```

Required mutation kinds:

- `wrong_implementation`: a representative implementation that returns the wrong observable result.
- `inverted_branch`: a conditional decision is inverted for a labeled behavior path.
- `skipped_external_call`: an observed platform/interface call is omitted.
- `corrupted_serializer`: a map/profile/save/config serializer or codec corrupts fields.
- `bad_packet_codec`: a network packet codec accepts, rejects, or emits the wrong bytes.
- `changed_mock_api_behavior`: an interface mock changes documented success, failure, or error-path behavior.

`mutation-effective` passes only when every required kind has at least one
`killed` mutation test case. Survived, planned, and invalid cases remain visible
as unresolved evidence and cannot satisfy the gate.

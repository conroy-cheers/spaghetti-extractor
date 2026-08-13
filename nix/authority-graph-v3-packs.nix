{
  pkgs,
  pythonEnv,
  pythonSource,
  contentAddressed ? true,
}:

let
  lib = pkgs.lib;
  python = "${pythonEnv}/bin/python3";
  caAttrs = lib.optionalAttrs contentAddressed { __contentAddressed = true; };
  sanitize =
    value:
    lib.concatStrings (
      map (character: if builtins.match "[A-Za-z0-9.+_-]" character != null then character else "-") (
        lib.stringToCharacters value
      )
    );

  mkSchedulePack =
    {
      name,
      packKind,
      identityBucket,
      resourceClass,
      itemIds,
      items,
      dependencies ? [ ],
      resource,
      timing,
    }:
    let
      core = {
        format = "spaghetti-extractor-schedule-pack-v3";
        schema_version = 3;
        pack_kind = packKind;
        identity_bucket = identityBucket;
        resource_class = resourceClass;
        item_ids = itemIds;
        inherit
          dependencies
          items
          resource
          timing
          ;
      };
      packId = "schedule-pack-v3:${builtins.hashString "sha256" (builtins.toJSON core)}";
      payload = core // {
        pack_id = packId;
      };
      payloadJson = builtins.toJSON payload;
      derivation =
        pkgs.runCommand (sanitize name)
          (
            {
              preferLocalBuild = false;
              allowSubstitutes = true;
            }
            // caAttrs
          )
          ''
            set -euo pipefail
            mkdir -p "$out"
            printf '%s' ${lib.escapeShellArg payloadJson} > "$out/pack.json"
          '';
    in
    {
      inherit
        derivation
        itemIds
        packId
        payload
        resource
        timing
        ;
      manifest = "${derivation}/pack.json";
    };

  mkDependencySchedulePack =
    {
      name,
      identityBucket,
      resourceClass,
      selectedSccIds,
      nodes,
      expectedSccs,
      scopeSha256,
      resource,
      timing,
      memoryLimitMiB ? 768,
    }:
    let
      core = {
        format = "spaghetti-extractor-dependency-schedule-pack-v3";
        schema_version = 3;
        identity_bucket = identityBucket;
        resource_class = resourceClass;
        selected_scc_ids = selectedSccIds;
        inherit
          nodes
          expectedSccs
          scopeSha256
          resource
          timing
          ;
      };
      packId = "dependency-schedule-pack-v3:${builtins.hashString "sha256" (builtins.toJSON core)}";
      derivation =
        pkgs.runCommand (sanitize name)
          (
            {
              nativeBuildInputs = [ pythonEnv ];
              preferLocalBuild = false;
              allowSubstitutes = true;
              SPAGHETTI_PHASE_MEMORY_LIMIT_MIB = toString memoryLimitMiB;
            }
            // caAttrs
          )
          ''
            set -euo pipefail
            export PYTHONHASHSEED=0
            export PYTHONDONTWRITEBYTECODE=1
            export LC_ALL=C.UTF-8
            export SOURCE_DATE_EPOCH=1
            export PYTHONPATH=${pythonSource}/src
            ulimit -v ${toString (memoryLimitMiB * 1024)}
            mkdir -p "$out"

            ${python} - \
              ${lib.escapeShellArg (builtins.toJSON nodes)} \
              ${lib.escapeShellArg (builtins.toJSON expectedSccs)} \
              ${lib.escapeShellArg (builtins.toJSON selectedSccIds)} \
              ${lib.escapeShellArg scopeSha256} \
              ${lib.escapeShellArg packId} \
              ${toString identityBucket} \
              ${lib.escapeShellArg resourceClass} \
              ${lib.escapeShellArg (builtins.toJSON resource)} \
              ${lib.escapeShellArg (builtins.toJSON timing)} \
              "$out/schedule.json" \
              "$out/pack.json" <<'PY'
            from __future__ import annotations

            import pathlib
            import sys

            from spaghetti_extractor.artifact_set_v3 import (
                DependencyNodePlanV3,
                DependencySchedulingManifestV3,
                canonical_json_bytes_v3,
                parse_canonical_json_v3,
            )


            (
                nodes_json,
                expected_sccs_json,
                selected_scc_ids_json,
                scope_sha256,
                pack_id,
                identity_bucket,
                resource_class,
                resource_json,
                timing_json,
                schedule_output,
                pack_output,
            ) = sys.argv[1:]
            node_payloads = parse_canonical_json_v3(
                nodes_json.encode("ascii"), location="dependency pack nodes"
            )
            expected_sccs = parse_canonical_json_v3(
                expected_sccs_json.encode("ascii"), location="dependency pack SCCs"
            )
            selected_scc_ids = parse_canonical_json_v3(
                selected_scc_ids_json.encode("ascii"), location="selected dependency SCCs"
            )
            resource = parse_canonical_json_v3(
                resource_json.encode("ascii"), location="dependency pack resources"
            )
            timing = parse_canonical_json_v3(
                timing_json.encode("ascii"), location="dependency pack timing"
            )
            nodes = tuple(DependencyNodePlanV3.parse(row) for row in node_payloads)
            resource_by_members = {
                tuple(row["members"]): row["resource_class"] for row in expected_sccs
            }

            def classify(members):
                try:
                    return resource_by_members[tuple(members)]
                except KeyError as exc:
                    raise SystemExit(
                        f"local dependency schedule produced unexpected SCC {members!r}"
                    ) from exc

            plan = DependencySchedulingManifestV3.create(
                scope_sha256, nodes, resource_class=classify
            )
            plan.validate(
                {row.node_id: row.dependencies for row in nodes},
                expected_records={row.node_id: row.records for row in nodes},
            )
            if [row.to_payload() for row in plan.sccs] != expected_sccs:
                raise SystemExit("local dependency schedule differs from validated SCC closure")
            observed_scc_ids = {row.scc_id for row in plan.sccs}
            if not set(selected_scc_ids) <= observed_scc_ids:
                raise SystemExit("dependency pack selects SCCs outside its validated closure")

            pathlib.Path(schedule_output).write_bytes(plan.to_bytes())
            pathlib.Path(pack_output).write_bytes(canonical_json_bytes_v3({
                "format": "spaghetti-extractor-dependency-schedule-pack-v3",
                "schema_version": 3,
                "pack_id": pack_id,
                "identity_bucket": int(identity_bucket),
                "resource_class": resource_class,
                "selected_scc_ids": selected_scc_ids,
                "closure_scc_ids": [row.scc_id for row in plan.sccs],
                "plan_id": plan.plan_id,
                "resource": resource,
                "timing": timing,
            }))
            PY
          '';
    in
    {
      inherit
        derivation
        memoryLimitMiB
        packId
        resource
        selectedSccIds
        timing
        ;
      itemIds = selectedSccIds;
      payload = core // {
        pack_id = packId;
      };
      manifest = "${derivation}/pack.json";
      schedule = "${derivation}/schedule.json";
    };

  bundleArtifactShards =
    {
      name,
      artifacts,
      expectedKind,
      expectedRecordIds,
      memoryLimitMiB ? 512,
    }:
    assert builtins.isList artifacts && artifacts != [ ];
    assert builtins.isList expectedRecordIds;
    let
      # This JSON intentionally carries dependency string contexts for every
      # member artifact. builtins.toFile rejects derivation references, so this
      # one adapter remains a derivation-backed store file.
      artifactsFile = pkgs.writeText "${name}-artifacts.json" (builtins.toJSON (map toString artifacts));
      expectedIdsFile = builtins.toFile "${name}-expected-record-ids.json" (builtins.toJSON expectedRecordIds);
      derivation =
        pkgs.runCommand (sanitize name)
          (
            {
              nativeBuildInputs = [ pythonEnv ];
              preferLocalBuild = false;
              allowSubstitutes = true;
              SPAGHETTI_PHASE_MEMORY_LIMIT_MIB = toString memoryLimitMiB;
            }
            // caAttrs
          )
          ''
            set -euo pipefail
            export PYTHONHASHSEED=0
            export PYTHONDONTWRITEBYTECODE=1
            export LC_ALL=C.UTF-8
            export SOURCE_DATE_EPOCH=1
            export PYTHONPATH=${pythonSource}/src
            ulimit -v ${toString (memoryLimitMiB * 1024)}
            mkdir -p "$out"

            ${python} - \
              ${artifactsFile} \
              ${lib.escapeShellArg expectedKind} \
              ${expectedIdsFile} \
              "$out/artifact" \
              "$out/bundle-result.json" <<'PY'
            from __future__ import annotations

            import pathlib
            import sys

            from spaghetti_extractor.artifact_set_v3 import (
                canonical_json_bytes_v3,
                parse_canonical_json_v3,
                write_artifact_bundle_v3,
            )


            artifacts_file, expected_kind, expected_ids_file, output, receipt = sys.argv[1:]
            artifacts = parse_canonical_json_v3(
                pathlib.Path(artifacts_file).read_bytes(), location=artifacts_file
            )
            expected_ids = parse_canonical_json_v3(
                pathlib.Path(expected_ids_file).read_bytes(), location=expected_ids_file
            )
            manifest = write_artifact_bundle_v3(
                pathlib.Path(output),
                (pathlib.Path(path) for path in artifacts),
                expected_ids,
                expected_kind=expected_kind,
            )
            pathlib.Path(receipt).write_bytes(canonical_json_bytes_v3({
                "format": "spaghetti-extractor-artifact-bundle-result-v3",
                "artifact_id": manifest.artifact_id,
                "artifact_kind": manifest.artifact_kind,
                "manifest_sha256": manifest.manifest_sha256,
                "member_count": len(manifest.members),
                "record_count": manifest.record_count,
                "status": manifest.status,
            }))
            PY
          '';
    in
    {
      inherit derivation memoryLimitMiB;
      artifact = "${derivation}/artifact";
      manifest = "${derivation}/artifact/manifest.json";
      result = "${derivation}/bundle-result.json";
    };

  mergeArtifactShards =
    {
      name,
      artifacts,
      expectedKind,
      expectedRecordIds,
      dependencyArtifacts ? null,
      memoryLimitMiB ? 1536,
    }:
    assert builtins.isList artifacts && artifacts != [ ];
    assert builtins.isList expectedRecordIds;
    let
      artifactsFile = pkgs.writeText "${name}-artifacts.json" (builtins.toJSON (map toString artifacts));
      expectedIdsFile = builtins.toFile "${name}-expected-record-ids.json" (builtins.toJSON expectedRecordIds);
      dependencyArtifactsFile = pkgs.writeText "${name}-dependency-artifacts.json" (builtins.toJSON (
        if dependencyArtifacts == null then
          null
        else
          lib.mapAttrs (_: value: toString value) dependencyArtifacts
      ));
      derivation =
        pkgs.runCommand (sanitize name)
          (
            {
              nativeBuildInputs = [ pythonEnv ];
              preferLocalBuild = false;
              allowSubstitutes = true;
              SPAGHETTI_PHASE_MEMORY_LIMIT_MIB = toString memoryLimitMiB;
            }
            // caAttrs
          )
          ''
            set -euo pipefail
            export PYTHONHASHSEED=0
            export PYTHONDONTWRITEBYTECODE=1
            export LC_ALL=C.UTF-8
            export SOURCE_DATE_EPOCH=1
            export PYTHONPATH=${pythonSource}/src
            ulimit -v ${toString (memoryLimitMiB * 1024)}
            mkdir -p "$out"

            ${python} - \
              ${artifactsFile} \
              ${lib.escapeShellArg expectedKind} \
              ${expectedIdsFile} \
              ${dependencyArtifactsFile} \
              "$out/artifact" \
              "$out/merge-result.json" <<'PY'
            from __future__ import annotations

            import itertools
            import pathlib
            import sys

            from spaghetti_extractor.artifact_set_v3 import (
                ArtifactSetReaderV3,
                ArtifactSetWriterV3,
                canonical_json_bytes_v3,
                parse_canonical_json_v3,
                value_codec_v3,
            )


            (
                artifacts_file,
                expected_kind,
                expected_ids_file,
                dependency_artifacts_file,
                output,
                receipt,
            ) = sys.argv[1:]
            artifacts = parse_canonical_json_v3(
                pathlib.Path(artifacts_file).read_bytes(), location=artifacts_file
            )
            expected_ids = parse_canonical_json_v3(
                pathlib.Path(expected_ids_file).read_bytes(), location=expected_ids_file
            )
            dependency_artifacts = parse_canonical_json_v3(
                pathlib.Path(dependency_artifacts_file).read_bytes(),
                location=dependency_artifacts_file,
            )
            readers = [ArtifactSetReaderV3(pathlib.Path(path)) for path in artifacts]
            prototype = readers[0].manifest
            if prototype.artifact_kind != expected_kind:
                raise SystemExit(
                    f"merged artifact kind mismatch: expected {expected_kind!r}, "
                    f"observed {prototype.artifact_kind!r}"
                )
            invariant_fields = (
                "artifact_kind",
                "status",
                "bindings",
                "value_codec",
                "pack_compression",
                "max_pack_bytes",
                "bucket_count",
            )
            for reader in readers[1:]:
                mismatches = [
                    field
                    for field in invariant_fields
                    if getattr(reader.manifest, field) != getattr(prototype, field)
                ]
                if mismatches:
                    raise SystemExit(
                        "artifact shards cannot be merged because manifest fields differ: "
                        + ", ".join(mismatches)
                    )

            if dependency_artifacts is None:
                output_dependencies = prototype.dependencies
                for reader in readers[1:]:
                    if reader.manifest.dependencies != output_dependencies:
                        raise SystemExit(
                            "artifact shards have different dependencies and no "
                            "aggregate dependency inventory was supplied"
                        )
            else:
                output_dependencies = tuple(
                    ArtifactSetReaderV3(pathlib.Path(path)).dependency_binding(name)
                    for name, path in sorted(dependency_artifacts.items())
                )

            writer = ArtifactSetWriterV3(
                artifact_kind=prototype.artifact_kind,
                bindings=prototype.bindings,
                dependencies=output_dependencies,
                status=prototype.status,
                max_pack_bytes=prototype.max_pack_bytes,
                value_codec=value_codec_v3(prototype.value_codec),
            )
            manifest = writer.write(
                pathlib.Path(output),
                itertools.chain.from_iterable(reader.iter_records() for reader in readers),
            )
            merged = ArtifactSetReaderV3(pathlib.Path(output))
            merged.validate_completeness(expected_ids)
            pathlib.Path(receipt).write_bytes(canonical_json_bytes_v3({
                "format": "spaghetti-extractor-artifact-merge-v3",
                "artifact_id": manifest.artifact_id,
                "artifact_kind": manifest.artifact_kind,
                "manifest_sha256": manifest.manifest_sha256,
                "record_count": manifest.record_count,
                "shard_count": len(readers),
                "status": manifest.status,
            }))
            PY
          '';
    in
    {
      inherit derivation memoryLimitMiB;
      artifact = "${derivation}/artifact";
      manifest = "${derivation}/artifact/manifest.json";
      result = "${derivation}/merge-result.json";
    };

  projectArtifactRecords =
    {
      name,
      artifact,
      expectedKind,
      expectedRecordIds,
      memoryLimitMiB ? 768,
    }:
    assert builtins.isList expectedRecordIds && expectedRecordIds != [ ];
    let
      expectedIdsFile = builtins.toFile "${name}-expected-record-ids.json" (builtins.toJSON expectedRecordIds);
      derivation =
        pkgs.runCommand (sanitize name)
          (
            {
              nativeBuildInputs = [ pythonEnv ];
              preferLocalBuild = false;
              allowSubstitutes = true;
              SPAGHETTI_PHASE_MEMORY_LIMIT_MIB = toString memoryLimitMiB;
            }
            // caAttrs
          )
          ''
            set -euo pipefail
            export PYTHONHASHSEED=0
            export PYTHONDONTWRITEBYTECODE=1
            export LC_ALL=C.UTF-8
            export SOURCE_DATE_EPOCH=1
            export PYTHONPATH=${pythonSource}/src
            ulimit -v ${toString (memoryLimitMiB * 1024)}
            mkdir -p "$out"

            ${python} - \
              ${lib.escapeShellArg (toString artifact)} \
              ${lib.escapeShellArg expectedKind} \
              ${expectedIdsFile} \
              "$out/artifact" \
              "$out/projection-result.json" <<'PY'
            from __future__ import annotations

            import pathlib
            import sys

            from spaghetti_extractor.artifact_set_v3 import (
                ArtifactSetReaderV3,
                ArtifactSetWriterV3,
                canonical_json_bytes_v3,
                parse_canonical_json_v3,
                value_codec_v3,
            )


            source_arg, expected_kind, expected_ids_file, output, receipt = sys.argv[1:]
            expected_ids = parse_canonical_json_v3(
                pathlib.Path(expected_ids_file).read_bytes(), location=expected_ids_file
            )
            if (
                not isinstance(expected_ids, list)
                or not expected_ids
                or expected_ids != sorted(set(expected_ids))
                or not all(isinstance(row, str) and row for row in expected_ids)
            ):
                raise SystemExit("projected record IDs must be sorted, unique, and nonempty")
            reader = ArtifactSetReaderV3(pathlib.Path(source_arg))
            prototype = reader.manifest
            if prototype.artifact_kind != expected_kind:
                raise SystemExit(
                    f"projected artifact kind mismatch: expected {expected_kind!r}, "
                    f"observed {prototype.artifact_kind!r}"
                )
            selected = set(expected_ids)
            records = tuple(
                record for record in reader.iter_records() if record.record_id in selected
            )
            observed = sorted(record.record_id for record in records)
            if observed != expected_ids:
                raise SystemExit(
                    f"artifact projection is incomplete: expected {expected_ids!r}, "
                    f"observed {observed!r}"
                )
            writer = ArtifactSetWriterV3(
                artifact_kind=prototype.artifact_kind,
                bindings=prototype.bindings,
                dependencies=prototype.dependencies,
                status=prototype.status,
                max_pack_bytes=prototype.max_pack_bytes,
                value_codec=value_codec_v3(prototype.value_codec),
            )
            manifest = writer.write(pathlib.Path(output), records)
            projected = ArtifactSetReaderV3(pathlib.Path(output))
            projected.validate_completeness(expected_ids)
            pathlib.Path(receipt).write_bytes(canonical_json_bytes_v3({
                "format": "spaghetti-extractor-artifact-projection-v3",
                "source_artifact_id": prototype.artifact_id,
                "artifact_id": manifest.artifact_id,
                "artifact_kind": manifest.artifact_kind,
                "manifest_sha256": manifest.manifest_sha256,
                "record_count": manifest.record_count,
                "status": manifest.status,
            }))
            PY
          '';
    in
    {
      inherit derivation memoryLimitMiB;
      artifact = "${derivation}/artifact";
      manifest = "${derivation}/artifact/manifest.json";
      result = "${derivation}/projection-result.json";
    };
in
{
  inherit bundleArtifactShards mergeArtifactShards mkDependencySchedulePack mkSchedulePack projectArtifactRecords;
}

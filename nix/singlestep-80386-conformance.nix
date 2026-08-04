{
  lib,
  runCommand,
  fetchurl,
  jq,
  python3,
  spaghetti-extractor,
  opcodeFiles ? [
    "6601"
    "6605"
    "6629"
    "6631"
    "6639"
    "6685"
    "6689"
    "668B"
    "66B8"
  ],
  opcodeHashes ? {
    "6640" = "sha256-vSs2WrfdEWboqtkKPTx0XntyHtMbIZHLSe1o8GdrqbE=";
    "6646" = "sha256-VMIc+dAW+BoEXgWWo69pegedazTffVajrhWSfY0HKX0=";
    "6648" = "sha256-ZhWtekjRX8KPyt2dnyI/uPDxgVGfSDuDl+YwataqvWA=";
    "F8" = "sha256-4b5wfFGAdfDRbS57SpMZs9zqgGaa0m12+V+2LidLPMw=";
    "FC" = "sha256-c4PkNOXzsqzsl9s6Xng7uc7iPMJBZbnLQ1crq+5Yu74=";
    "FD" = "sha256-k4ifpZV8uGSNA7GJwdhuOCmOWv5ECX7ep3dP0WS1UWU=";
    "6601" = "sha256-JRUro0fHoK0nK7SPmQNaLA/K2evHFYbmCCTNruR+KEg=";
    "6605" = "sha256-81bxHlKFQiLcAL3fv2Sho995+SqZj3GfogwsMpeKgSM=";
    "6629" = "sha256-DpTZuNfcD44WPQTqDM86KmprBmFE9Mivf3NOpsSg48A=";
    "6631" = "sha256-Yy1e5UEW6iRpKAjB5b9KSB79MAbOFk9XkqMEEwcXq2g=";
    "6639" = "sha256-w4VJxx1HtFMzqco4x4HGsgyPEFnfwZHsD/iggLFvULI=";
    "6685" = "sha256-HMf22w2ujhu3OliTka8AMtwNhSW5ZBwlLGJeSeCYTwc=";
    "6689" = "sha256-/oA9deB6jRRw43qpLVgF/GVl3vXFXTpwXgA9XkPnty4=";
    "668B" = "sha256-37+gr7NaiGdJErlPh6RQXSkEPi7pSvTXZ6glQaWi/B0=";
    "66B8" = "sha256-++rheaBDYzxZF/Yu+xcIk/DlsFnXzLRO5V/NxxlE/dk=";
  },
  shardCount ? 16,
  shardIndices ? lib.range 0 (shardCount - 1),
  maxCases ? null,
}:

let
  sourceRepository = "https://github.com/SingleStepTests/80386";
  sourceRevision = "655b1e947b5ce52d99fb7538095a7eb78874e89f";
  sourceRevisionShort = builtins.substring 0 12 sourceRevision;
  sourceRawBase = "https://raw.githubusercontent.com/SingleStepTests/80386/${sourceRevision}";

  converterRepository = "https://github.com/dbalsom/moo";
  converterRevision = "c438962d2b30856817d8e59bd5f0f4c628596ca8";
  converterHash = "sha256-rfqoV0gRHp5o+eU1ob2Q2Mk3f9jLKHhKkCkpUjpEt7g=";
  converterScript = fetchurl {
    name = "moo2json-${builtins.substring 0 12 converterRevision}.py";
    url = "https://raw.githubusercontent.com/dbalsom/moo/${converterRevision}/python/moo2json.py";
    hash = converterHash;
  };

  metadataHash = "sha256-P1vfVwOEiu49bu0I9N/5g5OBIAVL2KSVSjGxV7nQ1xs=";
  metadataCsv = fetchurl {
    name = "singlestep-80386-${sourceRevisionShort}-80386.csv";
    url = "${sourceRawBase}/80386.csv";
    hash = metadataHash;
  };

  revocationsHash = "sha256-B3U4/MB2zMm0Cv84RknEWcc60uKlcFN7XJTPAqMsS1Q=";
  revocations = fetchurl {
    name = "singlestep-80386-${sourceRevisionShort}-revocation-list.txt";
    url = "${sourceRawBase}/revocation_list.txt";
    hash = revocationsHash;
  };

  unknownOpcodes = builtins.filter (opcode: !(builtins.hasAttr opcode opcodeHashes)) opcodeFiles;
  invalidOpcodes = builtins.filter (
    opcode: builtins.match "(66|67)*(0F)?[0-9A-F][0-9A-F](\\.[0-9A-F]+)?" opcode == null
  ) opcodeFiles;
  invalidShardIndices = builtins.filter (
    index: !(builtins.isInt index && index >= 0 && index < shardCount)
  ) shardIndices;

  opcodeSources = lib.genAttrs opcodeFiles (
    opcode:
    fetchurl {
      name = "singlestep-80386-${sourceRevisionShort}-${opcode}.MOO.gz";
      url = "${sourceRawBase}/v1_ex_real_mode/${opcode}.MOO.gz";
      hash = opcodeHashes.${opcode};
    }
  );

  selectedFixedOutputHashes = {
    converter = converterHash;
    metadata = metadataHash;
    revocations = revocationsHash;
    opcodes = lib.genAttrs opcodeFiles (opcode: opcodeHashes.${opcode});
  };

  selectionHash = builtins.substring 0 12 (
    builtins.hashString "sha256" (builtins.toJSON opcodeFiles)
  );

  convertedSources =
    runCommand "singlestep-80386-converted-${sourceRevisionShort}-${selectionHash}"
      {
        nativeBuildInputs = [
          jq
          python3
        ];
        passthru = {
          inherit
            converterRevision
            opcodeSources
            sourceRevision
            ;
        };
      }
      ''
        mkdir -p "$out/json"
        install -m 0444 ${metadataCsv} "$out/80386.csv"
        install -m 0444 ${revocations} "$out/revocation_list.txt"
        converted_hashes="$TMPDIR/converted-hashes.jsonl"
        : > "$converted_hashes"

        ${lib.concatMapStringsSep "\n" (opcode: ''
          ${python3}/bin/python3 ${converterScript} \
            ${opcodeSources.${opcode}} \
            "$out/json/${opcode}.json"
          ${jq}/bin/jq -e \
            'type == "array" and length > 0 and all(.[]; has("idx") and has("hash"))' \
            "$out/json/${opcode}.json" > /dev/null
          converted_sha256="$(sha256sum "$out/json/${opcode}.json" | cut -d ' ' -f 1)"
          ${jq}/bin/jq -n \
            --arg opcode ${lib.escapeShellArg opcode} \
            --arg sha256 "$converted_sha256" \
            '{($opcode): $sha256}' >> "$converted_hashes"
        '') opcodeFiles}

        ${jq}/bin/jq -n \
          --arg source_repository ${lib.escapeShellArg sourceRepository} \
          --arg source_revision ${lib.escapeShellArg sourceRevision} \
          --arg source_directory "v1_ex_real_mode" \
          --arg converter_repository ${lib.escapeShellArg converterRepository} \
          --arg converter_revision ${lib.escapeShellArg converterRevision} \
          --arg converter_script "python/moo2json.py" \
          --argjson opcode_files '${builtins.toJSON opcodeFiles}' \
          --argjson fixed_output_hashes '${builtins.toJSON selectedFixedOutputHashes}' \
          --argjson converted_json_sha256 "$(${jq}/bin/jq -s 'add' "$converted_hashes")" \
          '{
            format: "spaghetti-extractor-sst80386-source-v1",
            source: {
              repository: $source_repository,
              revision: $source_revision,
              directory: $source_directory,
              metadata: "80386.csv",
              revocations: "revocation_list.txt",
              opcode_files: $opcode_files
            },
            converter: {
              repository: $converter_repository,
              revision: $converter_revision,
              script: $converter_script
            },
            hashes: {
              fixed_output_sha256_sri: $fixed_output_hashes,
              converted_json_sha256: $converted_json_sha256
            }
          }' > "$out/provenance.json"
      '';

  mkImport =
    opcode: shardIndex:
    let
      shardName = "shard-${toString shardIndex}-of-${toString shardCount}";
      upstreamFile = {
        repository = sourceRepository;
        revision = sourceRevision;
        path = "v1_ex_real_mode/${opcode}.MOO.gz";
        fetch_sha256_sri = opcodeHashes.${opcode};
      };
      converter = {
        repository = converterRepository;
        revision = converterRevision;
        script = "python/moo2json.py";
        fetch_sha256_sri = converterHash;
      };
    in
    runCommand "singlestep-80386-${lib.toLower opcode}-${shardName}"
      {
        nativeBuildInputs = [
          jq
          spaghetti-extractor
        ];
        passthru = {
          inherit
            convertedSources
            converterRevision
            opcode
            shardCount
            shardIndex
            sourceRevision
            ;
        };
      }
      ''
        mkdir -p "$out"
        spaghetti-extractor stage-a-import-80386-conformance \
          --tests-json ${convertedSources}/json/${opcode}.json \
          --metadata-csv ${convertedSources}/80386.csv \
          --revocations ${convertedSources}/revocation_list.txt \
          --source-revision ${sourceRevision} \
          --shard-index ${toString shardIndex} \
          --shard-count ${toString shardCount} \
          ${lib.optionalString (maxCases != null) "--max-cases ${toString maxCases}"} \
          --out "$out/corpus.json" \
          --manifest-out "$TMPDIR/import-manifest.json"

        ${jq}/bin/jq \
          --arg manifest_path "$out/manifest.json" \
          --arg source_provenance "${convertedSources}/provenance.json" \
          --argjson upstream_file '${builtins.toJSON upstreamFile}' \
          --argjson converter '${builtins.toJSON converter}' \
          '.source.upstream_file = $upstream_file
           | .source.converter = $converter
           | .source.provenance_manifest = $source_provenance
           | .outputs.manifest = $manifest_path' \
          "$TMPDIR/import-manifest.json" > "$out/manifest.json"

        ${jq}/bin/jq -e \
          --arg opcode ${lib.escapeShellArg opcode} \
          --argjson shard_index ${toString shardIndex} \
          --argjson shard_count ${toString shardCount} \
          '.status == "complete"
           and .source.revision == "${sourceRevision}"
           and .source.converter.revision == "${converterRevision}"
           and .source.converted_test_file == ($opcode + ".json")
           and .selection.shard_index == $shard_index
           and .selection.shard_count == $shard_count
           and .corpus.case_count > 0' \
          "$out/manifest.json" > /dev/null
        ${jq}/bin/jq -e \
          '.format == "stage-a-isa-conformance-corpus-v1" and (.cases | length) > 0' \
          "$out/corpus.json" > /dev/null
      '';

  importDerivations = lib.genAttrs opcodeFiles (
    opcode:
    builtins.listToAttrs (
      map (shardIndex: {
        name = toString shardIndex;
        value = mkImport opcode shardIndex;
      }) shardIndices
    )
  );

  importIndex = lib.concatMap (
    opcode:
    map (shardIndex: {
      inherit opcode;
      shard_index = shardIndex;
      shard_count = shardCount;
      corpus = "${opcode}/shard-${toString shardIndex}-of-${toString shardCount}/corpus.json";
      manifest = "${opcode}/shard-${toString shardIndex}-of-${toString shardCount}/manifest.json";
    }) shardIndices
  ) opcodeFiles;

  aggregateSelectionHash = builtins.substring 0 12 (
    builtins.hashString "sha256" (
      builtins.toJSON {
        inherit
          maxCases
          opcodeFiles
          shardCount
          shardIndices
          ;
      }
    )
  );

  aggregate =
    runCommand "singlestep-80386-conformance-${aggregateSelectionHash}"
      {
        passthru = {
          inherit
            convertedSources
            converterRevision
            importDerivations
            opcodeFiles
            shardCount
            shardIndices
            sourceRevision
            ;
        };
        meta = {
          description = "Sharded PE32 conformance subset of SingleStepTests/80386";
          longDescription = ''
            Hardware-generated SingleStepTests/80386 vectors converted from pinned
            per-opcode MOO files and imported into evidence-only PE32 conformance
            corpora. The package has no Stage A proof authority.
          '';
          platforms = spaghetti-extractor.meta.platforms or lib.platforms.all;
        };
      }
      ''
        root="$out/share/spaghetti-extractor/singlestep-80386-conformance"
        mkdir -p "$root"
        ln -s ${convertedSources}/provenance.json "$root/source-provenance.json"

        ${lib.concatMapStringsSep "\n" (
          opcode:
          lib.concatMapStringsSep "\n" (
            shardIndex:
            let
              imported = importDerivations.${opcode}.${toString shardIndex};
              relative = "${opcode}/shard-${toString shardIndex}-of-${toString shardCount}";
            in
            ''
              mkdir -p "$root/${relative}"
              ln -s ${imported}/corpus.json "$root/${relative}/corpus.json"
              ln -s ${imported}/manifest.json "$root/${relative}/manifest.json"
            ''
          ) shardIndices
        ) opcodeFiles}

        cat > "$root/index.json" <<'JSON'
        ${builtins.toJSON {
          format = "spaghetti-extractor-sst80386-corpus-set-v1";
          source_provenance = "source-provenance.json";
          source_revision = sourceRevision;
          converter_revision = converterRevision;
          import_index = importIndex;
          max_cases = maxCases;
          opcode_files = opcodeFiles;
          shard_count = shardCount;
          shard_indices = shardIndices;
          trust = {
            role = "isa_conformance_evidence_only";
            proof_authority = false;
            closes_stage_a_proof = false;
          };
        }}
        JSON
      '';
in
assert lib.assertMsg (opcodeFiles != [ ]) "opcodeFiles must not be empty";
assert lib.assertMsg (
  lib.unique opcodeFiles == opcodeFiles
) "opcodeFiles must not contain duplicates";
assert lib.assertMsg (
  invalidOpcodes == [ ]
) "opcodeFiles contains invalid uppercase opcode keys: ${builtins.toJSON invalidOpcodes}";
assert lib.assertMsg (
  unknownOpcodes == [ ]
) "opcodeHashes is missing selected opcodes: ${builtins.toJSON unknownOpcodes}";
assert lib.assertMsg (shardCount > 0) "shardCount must be positive";
assert lib.assertMsg (shardIndices != [ ]) "shardIndices must not be empty";
assert lib.assertMsg (
  lib.unique shardIndices == shardIndices
) "shardIndices must not contain duplicates";
assert lib.assertMsg (
  invalidShardIndices == [ ]
) "shardIndices must be integers within shardCount: ${builtins.toJSON invalidShardIndices}";
assert lib.assertMsg (
  maxCases == null || (builtins.isInt maxCases && maxCases > 0)
) "maxCases must be null or a positive integer";
aggregate

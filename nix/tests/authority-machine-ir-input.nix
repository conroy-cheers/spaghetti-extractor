{ pkgs, pythonEnv, pythonSource }:

let
  binary = pkgs.writeText "authority-source-plan-fixture.exe" "MZfixture";
  unit = id: start: end: targets: marker: {
    format = "stage-a-machine-ir-v2";
    record_kind = "unit";
    inherit id;
    status = "qualified";
    source = {
      original = {
        rva_start = start;
        rva_end = end;
      };
      instruction_bytes_sha256 = builtins.hashString "sha256" marker;
    };
    control = {
      kind = if targets == [ ] then "return" else "direct_jump";
      direct_targets = targets;
      has_indirect_target = false;
    };
  };
  mkMachineIr = name: marker:
    pkgs.writeText "${name}.jsonl" (
      builtins.toJSON (unit "unit:a" 4096 4112 [ 4112 ] marker) + "\n"
      + builtins.toJSON (unit "unit:b" 4112 4128 [ ] "stable-b") + "\n"
    );
  mkInput = marker:
    import ../authority-machine-ir-input.nix {
      inherit pkgs pythonEnv pythonSource binary;
      name = "authority-machine-ir";
      binaryIdentity = "fixture.exe";
      machineIr = mkMachineIr "authority-machine-ir" marker;
    };
  base = mkInput "base-a";
  repeated = mkInput "base-a";
  changed = mkInput "changed-a";
  drvPath = value: builtins.unsafeDiscardStringContext value.drvPath;
  shardFor = input: unitId:
    builtins.head (
      builtins.filter (
        key: builtins.elem unitId input.shards.${key}.expectedRecordIds
      ) (builtins.attrNames input.shards)
    );
  baseAShardKey = shardFor base "unit:a";
  changedAShardKey = shardFor changed "unit:a";
  baseBShardKey = shardFor base "unit:b";
  changedBShardKey = shardFor changed "unit:b";
  baseAShard = base.shards.${baseAShardKey}.artifact;
  changedAShard = changed.shards.${changedAShardKey}.artifact;
  baseBShard = base.shards.${baseBShardKey}.artifact;
  changedBShard = changed.shards.${changedBShardKey}.artifact;
in
assert base.plan == repeated.plan;
assert base.plan.machine_ir_source_sha256 != changed.plan.machine_ir_source_sha256;
assert drvPath baseAShard != drvPath changedAShard;
assert baseAShardKey == changedAShardKey;
assert baseBShardKey == changedBShardKey;
assert baseAShardKey == baseBShardKey || drvPath baseBShard == drvPath changedBShard;
assert base.expectedRecordIds == [ "unit:a" "unit:b" ];
assert base.plan.unit_count == 2;
pkgs.linkFarm "authority-machine-ir-input-check" [
  {
    name = "plan.json";
    path = "${base.preparation}/plan.json";
  }
  {
    name = "unit-a";
    path = baseAShard;
  }
  {
    name = "unit-b";
    path = baseBShard;
  }
]

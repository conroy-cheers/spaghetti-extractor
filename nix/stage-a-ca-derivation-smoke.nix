{
  nixpkgs,
  system ? builtins.currentSystem,
  producerRevision ? "a",
}:

let
  pkgs = import nixpkgs { inherit system; };
  semanticSummary = pkgs.runCommand "stage-a-ca-semantic-summary"
    {
      __contentAddressed = true;
      outputs = [ "out" "audit" ];
      inherit producerRevision;
    }
    ''
      mkdir -p "$out" "$audit"
      printf '%s\n' stable-semantic-summary > "$out/summary"
      printf '%s\n' "$producerRevision" > "$audit/producer-revision"
    '';
in
pkgs.runCommand "stage-a-ca-summary-consumer"
  {
    inherit semanticSummary;
    passthru = { inherit semanticSummary; };
  }
  ''
    mkdir -p "$out"
    cp "${semanticSummary}/summary" "$out/summary"
  ''

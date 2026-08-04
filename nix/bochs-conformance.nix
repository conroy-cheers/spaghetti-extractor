{
  lib,
  stdenv,
  bochs,
  libtool,
  makeWrapper,
  pkg-config,
  python3,
  instrumentationSrc,
}:

let
  expectedBochsVersion = "3.0";
  expectedBochsSourceHash = "sha256-y29UK1HzWizJIGsqmA21YCt80bfPLk7U8Ras1VB3gao=";
  instrumentationDir = "instrument/spaghetti-extractor";
  instrumentationSource = lib.cleanSource instrumentationSrc;
  runnerName = "spaghetti-bochs-conformance-runner";
  rawBochsRelativePath = "libexec/spaghetti-extractor/bochs-conformance/bochs-raw";
  runnerSupportRelativePath = "libexec/spaghetti-extractor/bochs-conformance/runner-support";
  guestRelativePath = "libexec/spaghetti-extractor/bochs-conformance/guest.img";

  configureFlags = [
    # The conformance executor has no interactive or graphical frontend.
    "--without-rfb"
    "--without-vncsrv"
    "--with-nogui"
    "--without-sdl2"
    "--without-term"
    "--without-wx"
    "--without-x"
    "--without-x11"

    "--disable-ltdl-install"
    "--disable-readline"
    "--disable-xpm"
    "--disable-cpp"
    "--disable-docbook"
    "--disable-plugins"

    # This is a compile-time Bochs instrumentation library, not a plugin.
    "--enable-instrumentation=${instrumentationDir}"

    # Keep memory callbacks exact. Bochs documents bx_instr_lin_access as
    # incompatible with repeat-speedups.
    "--disable-repeat-speedups"
    "--disable-all-optimizations"
    "--disable-handlers-chaining"
    "--disable-idle-hack"
    "--disable-trace-linking"

    # Fixed CPU build profile. The executor runs protected 32-bit fixtures,
    # while x86-64 remains compiled in because the selected Haswell CPUID
    # model is a 64-bit-capable processor.
    "--enable-cpu-level=6"
    "--enable-x86-64"
    "--enable-fpu"
    "--enable-avx"
    # Bochs 3.0's AVX library compiles AVX10 sources that depend on the EVEX
    # decoder fields. The runtime Haswell CPU model still gates EVEX off.
    "--enable-evex"
    "--enable-configurable-msrs"
    "--disable-smp"
    "--disable-vmx"
    "--disable-svm"

    # The instrumentation executor owns stepping and result emission.
    "--disable-debugger"
    "--disable-debugger-gui"
    "--disable-gdb-stub"
    "--disable-x86-debugger"
    "--disable-iodebug"
    "--enable-logging"
    "--enable-a20-pin"
    "--enable-largefile"
    "--disable-large-ramfile"
    "--disable-show-ips"

    # Device models are not part of single-instruction ISA conformance.
    "--disable-busmouse"
    "--disable-cdrom"
    "--disable-clgd54xx"
    "--disable-pci"
    "--disable-usb"
    "--disable-usb-ehci"
    "--disable-usb-ohci"
    "--disable-usb-xhci"
    "--disable-voodoo"
    "--disable-e1000"
    "--disable-es1370"
    "--disable-ne2000"
    "--disable-pnic"
    "--disable-sb16"
  ];

  packageMetadata = {
    format = "spaghetti-extractor-bochs-conformance-package-v1";
    bochs = {
      version = expectedBochsVersion;
      sourceHash = expectedBochsSourceHash;
    };
    instrumentation = {
      source = "tools/bochs-conformance";
      compiledDirectory = instrumentationDir;
      mode = "compile-time";
    };
    runner = {
      source = "tools/bochs-conformance/${runnerName}";
      program = "bin/${runnerName}";
      rawBochs = rawBochsRelativePath;
      rawBochsEnvironmentVariable = "SPAGHETTI_BOCHS_RAW";
      guest = guestRelativePath;
      guestEnvironmentVariable = "SPAGHETTI_BOCHS_GUEST";
      supportDirectory = runnerSupportRelativePath;
    };
    execution = {
      displayLibrary = "nogui";
      headless = true;
      repeatSpeedups = false;
      smp = false;
    };
    cpu = {
      architecture = "x86";
      executionMode = "protected-32";
      level = 6;
      models = [
        "corei7_haswell_4770"
        "p2_klamath"
      ];
      i686CatalogChip = "PENTIUMPRO";
      i686ExecutionModel = "p2_klamath";
      i686ExecutionModelIsSuperset = true;
      x86_64Compiled = true;
      fpu = true;
      avx = true;
      evexCompiled = true;
    };
    trust = {
      role = "isa_conformance_evidence_only";
      proofAuthority = false;
      closesStageAProof = false;
    };
    inherit configureFlags;
  };
in
assert lib.assertMsg (bochs.version == expectedBochsVersion) ''
  bochs-conformance requires pinned nixpkgs Bochs ${expectedBochsVersion}, got ${bochs.version}
'';
assert lib.assertMsg (bochs.src.outputHash == expectedBochsSourceHash) ''
  bochs-conformance received an unexpected Bochs source hash:
    expected ${expectedBochsSourceHash}
    got      ${bochs.src.outputHash}
'';
stdenv.mkDerivation (finalAttrs: {
  pname = "bochs-conformance";
  version = expectedBochsVersion;

  src = bochs.src;

  nativeBuildInputs = [
    libtool
    makeWrapper
    pkg-config
    python3
  ];

  inherit configureFlags;

  postPatch = ''
    instrumentation_source=${lib.escapeShellArg (toString instrumentationSource)}
    instrumentation_target=${lib.escapeShellArg instrumentationDir}

    for required_file in \
      instrument.cc \
      instrument.h \
      Makefile.in \
      build-guest.sh \
      guest/boot.S \
      guest/boot.ld \
      guest/guest.S \
      guest/guest.ld \
      ${lib.escapeShellArg runnerName}; do
      if [ ! -f "$instrumentation_source/$required_file" ]; then
        echo "bochs-conformance: missing tools/bochs-conformance/$required_file" >&2
        echo "pass instrumentationSrc = ./tools/bochs-conformance with the instrumentation ABI and public runner files" >&2
        exit 1
      fi
    done

    rm -rf "$instrumentation_target"
    mkdir -p "$instrumentation_target"
    cp -R "$instrumentation_source"/. "$instrumentation_target"/
  '';

  enableParallelBuilding = true;

  preConfigure = ''
    bash ${instrumentationDir}/build-guest.sh "$TMPDIR/bochs-conformance-guest" >/dev/null
  '';

  postInstall = ''
    raw_dir="$out/$(dirname ${lib.escapeShellArg rawBochsRelativePath})"
    runner_support="$out/${runnerSupportRelativePath}"
    public_runner="$out/bin/${runnerName}"

    mkdir -p "$raw_dir" "$runner_support"
    mv "$out/bin/bochs" "$out/${rawBochsRelativePath}"
    cp "$TMPDIR/bochs-conformance-guest/guest.img" "$out/${guestRelativePath}"

    # Preserve adjacent modules and data used by the public runner, but keep
    # them outside PATH. Only the wrapped protocol entrypoint is public.
    cp -R ${lib.escapeShellArg (toString instrumentationSource)}/. "$runner_support"/
    chmod +x "$runner_support/${runnerName}"
    patchShebangs "$runner_support/${runnerName}"
    makeWrapper "$runner_support/${runnerName}" "$public_runner" \
      --set SPAGHETTI_BOCHS_RAW "$out/${rawBochsRelativePath}" \
      --set SPAGHETTI_BOCHS_GUEST "$out/${guestRelativePath}" \
      --set BXSHARE "$out/share/bochs"

    metadata_dir="$out/share/spaghetti-extractor/bochs-conformance"
    mkdir -p "$metadata_dir"
    cat > "$metadata_dir/package-metadata.json" <<'EOF'
    ${builtins.toJSON packageMetadata}
    EOF
  '';

  passthru = {
    inherit
      configureFlags
      instrumentationDir
      instrumentationSource
      guestRelativePath
      packageMetadata
      rawBochsRelativePath
      runnerName
      runnerSupportRelativePath
      ;
    cpuProfile = packageMetadata.cpu;
    headless = true;
    repeatSpeedups = false;
    upstreamBochs = bochs;
  };

  meta = bochs.meta // {
    description = "Bochs 3.0 headless x86 ISA conformance executor";
    longDescription = ''
      A pinned, single-CPU, headless Bochs 3.0 build with the Spaghetti
      Extractor instrumentation library compiled in. It is an untrusted ISA
      conformance oracle and has no candidate qualification authority.
    '';
    mainProgram = runnerName;
  };
})

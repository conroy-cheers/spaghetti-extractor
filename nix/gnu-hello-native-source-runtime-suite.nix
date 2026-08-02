{ programName ? "hello.exe" }:

assert builtins.isString programName && programName != "";

let
  eol = "\r\n";
  lines = values: builtins.concatStringsSep eol values + eol;
  longGreeting =
    "W" + builtins.concatStringsSep "" (builtins.genList (_: "u") 439) + "hhh!";
  cLocale = {
    LANGUAGE = "";
    LC_ALL = "C";
    LC_MESSAGES = "";
    LANG = "";
  };
in
{
  format = "stage-b-functional-suite-v1";
  target_name = "gnu-hello";
  suite_id = "gnu-hello-2.12.3-candidate-functional";
  suite_name = "GNU Hello 2.12.3 candidate functional suite";
  suite_kind = "curated_expected_output";
  suite_scope = "upstream-applicable";
  upstream_suite = true;

  coverage = {
    source = "GNU Hello 2.12.3 and bundled gnulib sources";
    source_kind = "source_derived_expected_output";
    source_revision = "2.12.3";
    required_suite_ids = [ "gnu-hello-2.12.3-candidate-functional" ];
    upstream_cases = [
      "hello-1"
      "greeting-1"
      "greeting-2"
      "traditional-1"
      "operand-1"
      "last-1"
    ];
    excluded_upstream_cases = {
      "atexit-1" =
        "requires the Unix /dev/full device, which is unavailable to a WinPE process";
    };
  };

  cases = [
    {
      id = "default-greeting";
      args = [ ];
      env = cLocale;
      expected_returncode = 0;
      expected_stdout = lines [ "Hello, world!" ];
      expected_stderr = "";
    }
    {
      id = "help";
      args = [ "--help" ];
      env = cLocale;
      expected_returncode = 0;
      expected_stdout = lines [
        "Usage: ${programName} [OPTION]..."
        "Print a friendly, customizable greeting."
        ""
        "  -t, --traditional       use traditional greeting"
        "  -g, --greeting=TEXT     use TEXT as the greeting message"
        ""
        "      --help     display this help and exit"
        "      --version  output version information and exit"
        ""
        "Report bugs to: bug-hello@gnu.org"
        "GNU Hello home page: <https://www.gnu.org/software/hello/>"
        "General help using GNU software: <https://www.gnu.org/gethelp/>"
      ];
      expected_stderr = "";
    }
    {
      id = "version";
      args = [ "--version" ];
      env = cLocale;
      expected_returncode = 0;
      expected_stdout = lines [
        "hello (GNU Hello) 2.12.3"
        "Copyright (C) 2026 Free Software Foundation, Inc."
        "License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>."
        "This is free software: you are free to change and redistribute it."
        "There is NO WARRANTY, to the extent permitted by law."
        ""
        "Written by Karl Berry, Sami Kerola, Jim Meyering,"
        "and Reuben Thomas."
      ];
      expected_stderr = "";
    }
    {
      id = "invalid-option";
      args = [ "--definitely-invalid" ];
      env = cLocale;
      expected_returncode = 1;
      expected_stdout = "";
      expected_stderr = lines [
        "${programName}: unrecognized option '--definitely-invalid'"
        "Try '${programName} --help' for more information."
      ];
    }
    {
      id = "traditional-1";
      args = [ "--traditional" ];
      env = cLocale;
      expected_returncode = 0;
      expected_stdout = lines [ "hello, world" ];
      expected_stderr = "";
    }
    {
      id = "greeting-1";
      args = [ "-g" "Nothing happens here." ];
      env = cLocale;
      expected_returncode = 0;
      expected_stdout = lines [ "Nothing happens here." ];
      expected_stderr = "";
    }
    {
      id = "greeting-2";
      args = [ "--greeting=${longGreeting}" ];
      env = cLocale;
      expected_returncode = 0;
      expected_stdout = lines [ longGreeting ];
      expected_stderr = "";
    }
    {
      id = "last-1";
      args = [ "-t" "-g" "my hello" ];
      env = cLocale;
      expected_returncode = 0;
      expected_stdout = lines [ "my hello" ];
      expected_stderr = "";
    }
    {
      id = "operand-1";
      args = [ "first" "second" ];
      env = cLocale;
      expected_returncode = 1;
      expected_stdout = "";
      expected_stderr = lines [
        "${programName}: extra operand: first"
        "Try '${programName} --help' for more information."
      ];
    }
  ];
}

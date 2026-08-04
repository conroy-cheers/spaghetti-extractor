#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <io.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "jq.h"
#include "jv.h"

#define JQ_REIMPLEMENTATION_VERSION "1.8.1"
#define JQ_REIMPLEMENTATION_CONFIG                                                \
  "--disable-static --disable-dependency-tracking "                              \
  "--prefix=/nix/store/lypn7q2f81s2cnw57ysq50lpa2hd3d2h-"                      \
  "stage-a-jq-original-i686-w64-mingw32-1.8.1 "                                 \
  "--bindir=/nix/store/lypn7q2f81s2cnw57ysq50lpa2hd3d2h-"                      \
  "stage-a-jq-original-i686-w64-mingw32-1.8.1/bin "                             \
  "--sbindir=/nix/store/lypn7q2f81s2cnw57ysq50lpa2hd3d2h-"                     \
  "stage-a-jq-original-i686-w64-mingw32-1.8.1/bin "                             \
  "--datadir=/nix/store/lypn7q2f81s2cnw57ysq50lpa2hd3d2h-"                     \
  "stage-a-jq-original-i686-w64-mingw32-1.8.1/share "                           \
  "--mandir=/nix/store/lypn7q2f81s2cnw57ysq50lpa2hd3d2h-"                      \
  "stage-a-jq-original-i686-w64-mingw32-1.8.1/share/man "                       \
  "--build=x86_64-unknown-linux-gnu --host=i686-w64-mingw32 "                   \
  "build_alias=x86_64-unknown-linux-gnu host_alias=i686-w64-mingw32 "           \
  "CC=i686-w64-mingw32-gcc "                                                    \
  "'CFLAGS=-O2 -fno-align-functions -fno-align-labels -fno-align-loops "        \
  "-fno-align-jumps -g0 -fno-asynchronous-unwind-tables -fno-ident "            \
  "-fno-inline -fno-inline-functions -fno-inline-small-functions -fno-ipa-cp "  \
  "-fno-ipa-sra -fno-ipa-icf' LDFLAGS=-Wl,-Map,jq-original.map"

enum cli_option {
  CLI_SLURP = 1 << 0,
  CLI_RAW_INPUT = 1 << 1,
  CLI_NULL_INPUT = 1 << 2,
  CLI_RAW_OUTPUT = 1 << 3,
  CLI_RAW_OUTPUT_ZERO = 1 << 4,
  CLI_ASCII_OUTPUT = 1 << 5,
  CLI_COLOR_OUTPUT = 1 << 6,
  CLI_MONOCHROME_OUTPUT = 1 << 7,
  CLI_SORT_KEYS = 1 << 8,
  CLI_FROM_FILE = 1 << 9,
  CLI_NO_OUTPUT_NEWLINE = 1 << 10,
  CLI_UNBUFFERED = 1 << 11,
  CLI_EXIT_STATUS = 1 << 12,
  CLI_SEQUENCE = 1 << 14,
  CLI_DUMP_DISASSEMBLY = 1 << 15
};

enum jq_status {
  STATUS_OK = 0,
  STATUS_FALSE_OR_NULL = -1,
  STATUS_SYSTEM_ERROR = 2,
  STATUS_COMPILE_ERROR = 3,
  STATUS_NO_OUTPUT = -4,
  STATUS_RUNTIME_ERROR = 5
};

typedef enum parse_action {
  PARSE_RUN,
  PARSE_HELP,
  PARSE_VERSION,
  PARSE_CONFIGURATION,
  PARSE_TESTS,
  PARSE_ERROR
} parse_action;

typedef struct cli_state {
  jq_state *jq;
  jq_util_input_state *inputs;
  jv positional;
  jv named;
  jv library_paths;
  const char *program;
  int options;
  int parser_flags;
  int jq_flags;
  int dump_flags;
  int file_count;
  int tests_index;
} cli_state;

extern void jv_tsd_dtoa_ctx_init(void);
extern int jq_testsuite(jv, int, int, char **);
extern jv jq_realpath(jv);
extern int onig_set_parse_depth_limit(unsigned int);
extern jq_input_cb resolved_input_callback
    __asm__("__imp__jq_util_input_next_input_cb");

static void write_bytes(FILE *stream, const char *bytes, size_t length,
                        int console_output) {
  if (console_output) {
    DWORD written = 0;
    WriteFile((HANDLE)_get_osfhandle(_fileno(stream)), bytes, (DWORD)length,
              &written, NULL);
  } else {
    fwrite(bytes, 1, length, stream);
  }
}

static void print_usage(FILE *stream, int short_form) {
  fprintf(stream,
          "jq - commandline JSON processor [version %s]\n"
          "\nUsage:\tjq [options] <jq filter> [file...]\n"
          "\tjq [options] --args <jq filter> [strings...]\n"
          "\tjq [options] --jsonargs <jq filter> [JSON_TEXTS...]\n\n"
          "jq is a tool for processing JSON inputs, applying the given filter "
          "to\nits JSON text inputs and producing the filter's results as JSON "
          "on\nstandard output.\n\n"
          "The simplest filter is ., which copies jq's input to its output\n"
          "unmodified except for formatting. For more advanced filters see\n"
          "the jq(1) manpage (\"man jq\") and/or https://jqlang.org/.\n\n"
          "Example:\n\n\t$ echo '{\"foo\": 0}' | jq .\n"
          "\t{\n\t  \"foo\": 0\n\t}\n\n",
          JQ_REIMPLEMENTATION_VERSION);
  if (short_form) {
    fputs("For listing the command options, use jq --help.\n", stream);
    return;
  }
  fputs("Command options:\n"
        "  -n, --null-input          use `null` as the single input value;\n"
        "  -R, --raw-input           read each line as string instead of JSON;\n"
        "  -s, --slurp               read all inputs into an array and use it "
        "as\n                            the single input value;\n"
        "  -c, --compact-output      compact instead of pretty-printed output;\n"
        "  -r, --raw-output          output strings without escapes and quotes;\n"
        "      --raw-output0         implies -r and output NUL after each "
        "output;\n"
        "  -j, --join-output         implies -r and output without newline "
        "after\n                            each output;\n"
        "  -a, --ascii-output        output strings by only ASCII characters\n"
        "                            using escape sequences;\n"
        "  -S, --sort-keys           sort keys of each object on output;\n"
        "  -C, --color-output        colorize JSON output;\n"
        "  -M, --monochrome-output   disable colored output;\n"
        "      --tab                 use tabs for indentation;\n"
        "      --indent n            use n spaces for indentation (max 7 "
        "spaces);\n"
        "      --unbuffered          flush output stream after each output;\n"
        "      --stream              parse the input value in streaming fashion;\n"
        "      --stream-errors       implies --stream and report parse error as\n"
        "                            an array;\n"
        "      --seq                 parse input/output as application/json-seq;\n"
        "  -f, --from-file           load the filter from a file;\n"
        "  -L, --library-path dir    search modules from the directory;\n"
        "      --arg name value      set $name to the string value;\n"
        "      --argjson name value  set $name to the JSON value;\n"
        "      --slurpfile name file set $name to an array of JSON values read\n"
        "                            from the file;\n"
        "      --rawfile name file   set $name to string contents of file;\n"
        "      --args                consume remaining arguments as positional\n"
        "                            string values;\n"
        "      --jsonargs            consume remaining arguments as positional\n"
        "                            JSON values;\n"
        "  -e, --exit-status         set exit status code based on the output;\n"
        "  -b, --binary              open input/output streams in binary mode;\n"
        "  -V, --version             show the version;\n"
        "  --build-configuration     show jq's build configuration;\n"
        "  -h, --help                show the help;\n"
        "  --                        terminates argument processing;\n\n"
        "Named arguments are also available as $ARGS.named[], while\n"
        "positional arguments are available as $ARGS.positional[].\n",
        stream);
}

static void print_option_hint(void) {
  fputs("Use jq --help for help with command-line options,\n"
        "or see the jq manpage, or online docs  at https://jqlang.org\n",
        stderr);
}

static int option_like(const char *text) {
  return text[0] == '-' &&
         (text[1] == '-' || isalpha((unsigned char)text[1]));
}

static int consume_option(const char **text, char short_name,
                          const char *long_name, int short_form) {
  if (short_form) {
    if (short_name != 0 && **text == short_name) {
      ++*text;
      if (**text == '\0') {
        *text = NULL;
      }
      return 1;
    }
    return 0;
  }
  if (strcmp(*text, long_name) == 0) {
    *text = NULL;
    return 1;
  }
  return 0;
}

static int add_named_once(cli_state *state, const char *name, jv value) {
  if (jv_object_has(jv_copy(state->named), jv_string(name))) {
    jv_free(value);
    return 0;
  }
  state->named =
      jv_object_set(state->named, jv_string(name), value);
  return 1;
}

static int require_arguments(int index, int argc, int count,
                             const char *message) {
  if (index + count < argc) {
    return 1;
  }
  fputs(message, stderr);
  print_option_hint();
  return 0;
}

static parse_action parse_options(cli_state *state, int argc, char **argv) {
  int strings_after_filter = 0;
  int json_after_filter = 0;
  int options_done = 0;

  for (int index = 1; index < argc; ++index) {
    if (options_done || !option_like(argv[index])) {
      if (state->program == NULL) {
        state->program = argv[index];
      } else if (strings_after_filter) {
        state->positional =
            jv_array_append(state->positional, jv_string(argv[index]));
      } else if (json_after_filter) {
        jv parsed = jv_parse(argv[index]);
        if (!jv_is_valid(parsed)) {
          fputs("jq: invalid JSON text passed to --jsonargs\n", stderr);
          jv_free(parsed);
          print_option_hint();
          return PARSE_ERROR;
        }
        state->positional = jv_array_append(state->positional, parsed);
      } else {
        jq_util_input_add_input(state->inputs, argv[index]);
        ++state->file_count;
      }
      continue;
    }
    if (strcmp(argv[index], "--") == 0) {
      options_done = 1;
      continue;
    }

    const char *text = argv[index];
    int short_form = text[1] != '-';
    text += short_form ? 1 : 2;
    while (text != NULL) {
      int raw_file;
      if (consume_option(&text, 's', "slurp", short_form)) {
        state->options |= CLI_SLURP;
      } else if (consume_option(&text, 'r', "raw-output", short_form)) {
        state->options |= CLI_RAW_OUTPUT;
      } else if (consume_option(&text, 0, "raw-output0", short_form)) {
        state->options |=
            CLI_RAW_OUTPUT | CLI_RAW_OUTPUT_ZERO | CLI_NO_OUTPUT_NEWLINE;
      } else if (consume_option(&text, 'j', "join-output", short_form)) {
        state->options |= CLI_RAW_OUTPUT | CLI_NO_OUTPUT_NEWLINE;
      } else if (consume_option(&text, 'c', "compact-output", short_form)) {
        state->dump_flags &= ~(JV_PRINT_TAB | JV_PRINT_INDENT_FLAGS(7));
      } else if (consume_option(&text, 'C', "color-output", short_form)) {
        state->options |= CLI_COLOR_OUTPUT;
      } else if (consume_option(&text, 'M', "monochrome-output", short_form)) {
        state->options |= CLI_MONOCHROME_OUTPUT;
      } else if (consume_option(&text, 'a', "ascii-output", short_form)) {
        state->options |= CLI_ASCII_OUTPUT;
      } else if (consume_option(&text, 0, "unbuffered", short_form)) {
        state->options |= CLI_UNBUFFERED;
      } else if (consume_option(&text, 'S', "sort-keys", short_form)) {
        state->options |= CLI_SORT_KEYS;
      } else if (consume_option(&text, 'R', "raw-input", short_form)) {
        state->options |= CLI_RAW_INPUT;
      } else if (consume_option(&text, 'n', "null-input", short_form)) {
        state->options |= CLI_NULL_INPUT;
      } else if (consume_option(&text, 'f', "from-file", short_form)) {
        state->options |= CLI_FROM_FILE;
      } else if (consume_option(&text, 'L', "library-path", short_form)) {
        if (jv_get_kind(state->library_paths) == JV_KIND_NULL) {
          state->library_paths = jv_array();
        }
        if (text != NULL) {
          state->library_paths = jv_array_append(
              state->library_paths, jq_realpath(jv_string(text)));
          text = NULL;
        } else if (!require_arguments(
                       index, argc, 1,
                       "-L takes a parameter: (e.g. -L /search/path or "
                       "-L/search/path)\n")) {
          return PARSE_ERROR;
        } else {
          state->library_paths = jv_array_append(
              state->library_paths, jq_realpath(jv_string(argv[++index])));
        }
      } else if (consume_option(&text, 'b', "binary", short_form)) {
        fflush(stdout);
        fflush(stderr);
        _setmode(_fileno(stdin), _O_BINARY);
        _setmode(_fileno(stdout), _O_BINARY);
        _setmode(_fileno(stderr), _O_BINARY);
      } else if (consume_option(&text, 0, "tab", short_form)) {
        state->dump_flags &= ~JV_PRINT_INDENT_FLAGS(7);
        state->dump_flags |= JV_PRINT_TAB | JV_PRINT_PRETTY;
      } else if (consume_option(&text, 0, "indent", short_form)) {
        char *end = NULL;
        long indent;
        if (!require_arguments(index, argc, 1,
                               "jq: --indent takes one parameter\n")) {
          return PARSE_ERROR;
        }
        errno = 0;
        indent = strtol(argv[index + 1], &end, 10);
        if (errno != 0 || indent < -1 || indent > 7 ||
            isspace((unsigned char)argv[index + 1][0]) ||
            end == argv[index + 1] || *end != '\0') {
          fputs("jq: --indent takes a number between -1 and 7\n", stderr);
          print_option_hint();
          return PARSE_ERROR;
        }
        state->dump_flags &= ~(JV_PRINT_TAB | JV_PRINT_INDENT_FLAGS(7));
        state->dump_flags |= JV_PRINT_INDENT_FLAGS(indent);
        ++index;
      } else if (consume_option(&text, 0, "seq", short_form)) {
        state->options |= CLI_SEQUENCE;
      } else if (consume_option(&text, 0, "stream", short_form)) {
        state->parser_flags |= JV_PARSE_STREAMING;
      } else if (consume_option(&text, 0, "stream-errors", short_form)) {
        state->parser_flags |= JV_PARSE_STREAMING | JV_PARSE_STREAM_ERRORS;
      } else if (consume_option(&text, 'e', "exit-status", short_form)) {
        state->options |= CLI_EXIT_STATUS;
      } else if (consume_option(&text, 0, "args", short_form)) {
        strings_after_filter = 1;
        json_after_filter = 0;
      } else if (consume_option(&text, 0, "jsonargs", short_form)) {
        strings_after_filter = 0;
        json_after_filter = 1;
      } else if (consume_option(&text, 0, "arg", short_form)) {
        if (!require_arguments(
                index, argc, 2,
                "jq: --arg takes two parameters (e.g. --arg varname value)\n")) {
          return PARSE_ERROR;
        }
        add_named_once(state, argv[index + 1], jv_string(argv[index + 2]));
        index += 2;
      } else if (consume_option(&text, 0, "argjson", short_form)) {
        if (!require_arguments(
                index, argc, 2,
                "jq: --argjson takes two parameters (e.g. --argjson varname "
                "text)\n")) {
          return PARSE_ERROR;
        }
        if (!jv_object_has(jv_copy(state->named),
                           jv_string(argv[index + 1]))) {
          jv parsed = jv_parse(argv[index + 2]);
          if (!jv_is_valid(parsed)) {
            fputs("jq: invalid JSON text passed to --argjson\n", stderr);
            jv_free(parsed);
            print_option_hint();
            return PARSE_ERROR;
          }
          add_named_once(state, argv[index + 1], parsed);
        }
        index += 2;
      } else if ((raw_file = consume_option(&text, 0, "rawfile", short_form)) ||
                 consume_option(&text, 0, "slurpfile", short_form)) {
        const char *kind = raw_file ? "rawfile" : "slurpfile";
        if (index + 2 >= argc) {
          fprintf(stderr,
                  "jq: --%s takes two parameters (e.g. --%s varname "
                  "filename)\n",
                  kind, kind);
          print_option_hint();
          return PARSE_ERROR;
        }
        if (!jv_object_has(jv_copy(state->named),
                           jv_string(argv[index + 1]))) {
          jv data = jv_load_file(argv[index + 2], raw_file);
          if (!jv_is_valid(data)) {
            data = jv_invalid_get_msg(data);
            fprintf(stderr, "jq: Bad JSON in --%s %s %s: %s\n", kind,
                    argv[index + 1], argv[index + 2], jv_string_value(data));
            jv_free(data);
            return PARSE_ERROR;
          }
          add_named_once(state, argv[index + 1], data);
        }
        index += 2;
      } else if (consume_option(&text, 0, "debug-dump-disasm", short_form)) {
        state->options |= CLI_DUMP_DISASSEMBLY;
      } else if (consume_option(&text, 0, "debug-trace=all", short_form)) {
        state->jq_flags |= JQ_DEBUG_TRACE_ALL;
      } else if (consume_option(&text, 0, "debug-trace", short_form)) {
        state->jq_flags |= JQ_DEBUG_TRACE;
      } else if (consume_option(&text, 'h', "help", short_form)) {
        return PARSE_HELP;
      } else if (consume_option(&text, 'V', "version", short_form)) {
        return PARSE_VERSION;
      } else if (consume_option(&text, 0, "build-configuration", short_form)) {
        return PARSE_CONFIGURATION;
      } else if (consume_option(&text, 0, "run-tests", short_form)) {
        state->tests_index = index + 1;
        return PARSE_TESTS;
      } else {
        if (short_form) {
          fprintf(stderr, "jq: Unknown option -%c\n", text[0]);
        } else {
          fprintf(stderr, "jq: Unknown option --%s\n", text);
        }
        print_option_hint();
        return PARSE_ERROR;
      }
    }
  }
  return PARSE_RUN;
}

static void debug_callback(void *opaque, jv input) {
  int flags = *(int *)opaque;
  jv_dumpf(JV_ARRAY(jv_string("DEBUG:"), input), stderr,
           flags & ~JV_PRINT_PRETTY);
  fputc('\n', stderr);
}

static void stderr_callback(void *opaque, jv input) {
  int flags = *(int *)opaque;
  if (jv_get_kind(input) == JV_KIND_STRING) {
    write_bytes(stderr, jv_string_value(input),
                (size_t)jv_string_length_bytes(jv_copy(input)),
                (flags & JV_PRINT_ISATTY) != 0);
  } else {
    input = jv_dump_string(input, 0);
    fputs(jv_string_value(input), stderr);
  }
  jv_free(input);
}

static int run_filter(cli_state *state, jv input) {
  int status = STATUS_NO_OUTPUT;
  jv result;

  jq_start(state->jq, input, state->jq_flags);
  while (jv_is_valid(result = jq_next(state->jq))) {
    if ((state->options & CLI_RAW_OUTPUT) != 0 &&
        jv_get_kind(result) == JV_KIND_STRING) {
      if ((state->options & CLI_ASCII_OUTPUT) != 0) {
        jv_dumpf(jv_copy(result), stdout, JV_PRINT_ASCII);
      } else if ((state->options & CLI_RAW_OUTPUT_ZERO) != 0 &&
                 strlen(jv_string_value(result)) !=
                     (size_t)jv_string_length_bytes(jv_copy(result))) {
        jv_free(result);
        result = jv_invalid_with_msg(jv_string(
            "Cannot dump a string containing NUL with --raw-output0 option"));
        break;
      } else {
        write_bytes(stdout, jv_string_value(result),
                    (size_t)jv_string_length_bytes(jv_copy(result)),
                    (state->dump_flags & JV_PRINT_ISATTY) != 0);
      }
      status = STATUS_OK;
      jv_free(result);
    } else {
      status = (jv_get_kind(result) == JV_KIND_FALSE ||
                jv_get_kind(result) == JV_KIND_NULL)
                   ? STATUS_FALSE_OR_NULL
                   : STATUS_OK;
      if ((state->options & CLI_SEQUENCE) != 0) {
        write_bytes(stdout, "\036", 1,
                    (state->dump_flags & JV_PRINT_ISATTY) != 0);
      }
      jv_dump(result, state->dump_flags);
    }
    if ((state->options & CLI_NO_OUTPUT_NEWLINE) == 0) {
      write_bytes(stdout, "\n", 1,
                  (state->dump_flags & JV_PRINT_ISATTY) != 0);
    }
    if ((state->options & CLI_RAW_OUTPUT_ZERO) != 0) {
      write_bytes(stdout, "\0", 1,
                  (state->dump_flags & JV_PRINT_ISATTY) != 0);
    }
    if ((state->options & CLI_UNBUFFERED) != 0) {
      fflush(stdout);
    }
  }

  if (jq_halted(state->jq)) {
    jv exit_code = jq_get_exit_code(state->jq);
    jv message;
    if (!jv_is_valid(exit_code)) {
      status = STATUS_OK;
    } else if (jv_get_kind(exit_code) == JV_KIND_NUMBER) {
      status = (int)jv_number_value(exit_code);
    } else {
      status = STATUS_RUNTIME_ERROR;
    }
    jv_free(exit_code);
    message = jq_get_error_message(state->jq);
    if (jv_get_kind(message) == JV_KIND_STRING) {
      write_bytes(stderr, jv_string_value(message),
                  (size_t)jv_string_length_bytes(jv_copy(message)),
                  (state->dump_flags & JV_PRINT_ISATTY) != 0);
    } else if (jv_is_valid(message) &&
               jv_get_kind(message) != JV_KIND_NULL) {
      message = jv_dump_string(message, 0);
      fprintf(stderr, "%s\n", jv_string_value(message));
    }
    fflush(stderr);
    jv_free(message);
  } else if (jv_invalid_has_msg(jv_copy(result))) {
    jv message = jv_invalid_get_msg(jv_copy(result));
    jv position = jq_util_input_get_position(state->jq);
    if (jv_get_kind(message) == JV_KIND_STRING) {
      fprintf(stderr, "jq: error (at %s): %s\n", jv_string_value(position),
              jv_string_value(message));
    } else {
      message = jv_dump_string(message, 0);
      fprintf(stderr, "jq: error (at %s) (not a string): %s\n",
              jv_string_value(position), jv_string_value(message));
    }
    status = STATUS_RUNTIME_ERROR;
    jv_free(position);
    jv_free(message);
  }
  jv_free(result);
  return status;
}

static char *parent_directory(const char *path) {
  size_t length = strlen(path);
  char *copy = malloc(length + 1);
  char *last = NULL;
  if (copy == NULL) {
    return NULL;
  }
  memcpy(copy, path, length + 1);
  for (char *cursor = copy; *cursor != '\0'; ++cursor) {
    if (*cursor == '/' || *cursor == '\\') {
      last = cursor;
    }
  }
  if (last == NULL) {
    copy[0] = '.';
    copy[1] = '\0';
  } else if (last == copy) {
    last[1] = '\0';
  } else {
    *last = '\0';
  }
  return copy;
}

static void configure_output(cli_state *state) {
  if (_isatty(_fileno(stdout))) {
    DWORD mode;
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    if (GetConsoleMode(output, &mode)) {
      state->dump_flags |= JV_PRINT_ISATTY;
      if (getenv("ANSICON") != NULL ||
          SetConsoleMode(output, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
        state->dump_flags |= JV_PRINT_COLOR;
      }
    }
    if ((state->dump_flags & JV_PRINT_COLOR) != 0) {
      const char *no_color = getenv("NO_COLOR");
      if (no_color != NULL && no_color[0] != '\0') {
        state->dump_flags &= ~JV_PRINT_COLOR;
      }
    }
  }
  if ((state->options & CLI_SORT_KEYS) != 0) {
    state->dump_flags |= JV_PRINT_SORTED;
  }
  if ((state->options & CLI_ASCII_OUTPUT) != 0) {
    state->dump_flags |= JV_PRINT_ASCII;
  }
  if ((state->options & CLI_COLOR_OUTPUT) != 0) {
    state->dump_flags |= JV_PRINT_COLOR;
  }
  if ((state->options & CLI_MONOCHROME_OUTPUT) != 0) {
    state->dump_flags &= ~JV_PRINT_COLOR;
  }
}

static int compile_program(cli_state *state, const char *argv0) {
  char *origin = parent_directory(argv0);
  int compiled;
  jv arguments;

  if (jv_get_kind(state->library_paths) == JV_KIND_NULL) {
    state->library_paths = JV_ARRAY(jv_string("~/.jq"),
                                    jv_string("$ORIGIN/../lib/jq"),
                                    jv_string("$ORIGIN/../lib"));
  }
  jq_set_attr(state->jq, jv_string("JQ_LIBRARY_PATH"), state->library_paths);
  state->library_paths = jv_null();
  if (origin == NULL) {
    fputs("jq: error: out of memory\n", stderr);
    return 0;
  }
  jq_set_attr(state->jq, jv_string("JQ_ORIGIN"), jv_string(origin));
  free(origin);
  jq_set_attr(state->jq, jv_string("VERSION_DIR"),
              jv_string(JQ_REIMPLEMENTATION_VERSION));

  arguments = JV_OBJECT(jv_string("positional"), jv_copy(state->positional),
                        jv_string("named"), jv_copy(state->named));
  state->named = jv_object_set(state->named, jv_string("ARGS"),
                               jv_copy(arguments));
  if (!jv_object_has(jv_copy(state->named),
                     jv_string("JQ_BUILD_CONFIGURATION"))) {
    state->named = jv_object_set(
        state->named, jv_string("JQ_BUILD_CONFIGURATION"),
        jv_string(JQ_REIMPLEMENTATION_CONFIG));
  }

  if ((state->options & CLI_FROM_FILE) != 0) {
    char *program_origin = parent_directory(state->program);
    jv source = jv_load_file(state->program, 1);
    if (!jv_is_valid(source)) {
      source = jv_invalid_get_msg(source);
      fprintf(stderr, "jq: %s\n", jv_string_value(source));
      jv_free(source);
      free(program_origin);
      return 0;
    }
    jq_set_attr(state->jq, jv_string("PROGRAM_ORIGIN"),
                jq_realpath(jv_string(program_origin == NULL ? "." :
                                                          program_origin)));
    free(program_origin);
    compiled = jq_compile_args(state->jq, jv_string_value(source),
                               jv_copy(state->named));
    jv_free(source);
  } else {
    jq_set_attr(state->jq, jv_string("PROGRAM_ORIGIN"),
                jq_realpath(jv_string(".")));
    compiled = jq_compile_args(state->jq, state->program,
                               jv_copy(state->named));
  }
  jv_free(arguments);
  return compiled;
}

static int final_exit_status(int status, int last_result, int exit_status) {
  if (!exit_status) {
    return status > 0 ? status : 0;
  }
  if (status != STATUS_NO_OUTPUT) {
    return status < 0 ? -status : status;
  }
  if (last_result < 0) {
    return -STATUS_NO_OUTPUT;
  }
  return last_result == 0 ? -STATUS_FALSE_OR_NULL : STATUS_OK;
}

static int jq_cli_main(int argc, char **argv) {
  cli_state state = {0};
  parse_action action;
  int status = STATUS_NO_OUTPUT;
  int last_result = -1;
  int bad_write;

  setlocale(LC_ALL, "");
  onig_set_parse_depth_limit(1024);
  jv_tsd_dtoa_ctx_init();
  fflush(stdout);
  fflush(stderr);
  _setmode(_fileno(stdout), _O_TEXT | _O_U8TEXT);
  _setmode(_fileno(stderr), _O_TEXT | _O_U8TEXT);

  state.positional = jv_array();
  state.named = jv_object();
  state.library_paths = jv_null();
  state.dump_flags = JV_PRINT_INDENT_FLAGS(2);
  state.inputs = jq_util_input_init(NULL, NULL);
  state.jq = jq_init();
  if (state.jq == NULL || state.inputs == NULL) {
    perror("jq_init");
    status = STATUS_SYSTEM_ERROR;
    goto cleanup;
  }

  action = parse_options(&state, argc, argv);
  if (action == PARSE_HELP) {
    print_usage(stdout, 0);
    status = STATUS_OK;
    goto cleanup;
  }
  if (action == PARSE_VERSION) {
    printf("jq-%s\n", JQ_REIMPLEMENTATION_VERSION);
    status = STATUS_OK;
    goto cleanup;
  }
  if (action == PARSE_CONFIGURATION) {
    printf("%s\n", JQ_REIMPLEMENTATION_CONFIG);
    status = STATUS_OK;
    goto cleanup;
  }
  if (action == PARSE_TESTS) {
    status = jq_testsuite(
        state.library_paths,
        (state.options & CLI_DUMP_DISASSEMBLY) != 0 ||
            (state.jq_flags & JQ_DEBUG_TRACE) != 0,
        argc - state.tests_index, argv + state.tests_index);
    state.library_paths = jv_null();
    goto cleanup;
  }
  if (action == PARSE_ERROR) {
    status = 2;
    goto cleanup;
  }

  configure_output(&state);
  if (!jq_set_colors(getenv("JQ_COLORS"))) {
    fputs("Failed to set $JQ_COLORS\n", stderr);
  }
  if (state.program == NULL && (state.options & CLI_FROM_FILE) == 0 &&
      (!_isatty(_fileno(stdout)) || !_isatty(_fileno(stdin)))) {
    state.program = ".";
  }
  if (state.program == NULL) {
    print_usage(stderr, 1);
    status = 2;
    goto cleanup;
  }
  if (!compile_program(&state, argc > 0 ? argv[0] : "jq.exe")) {
    status = STATUS_COMPILE_ERROR;
    goto cleanup;
  }
  if ((state.options & CLI_DUMP_DISASSEMBLY) != 0) {
    jq_dump_disassembly(state.jq, 0);
    fputc('\n', stdout);
  }
  if ((state.options & CLI_SEQUENCE) != 0) {
    state.parser_flags |= JV_PARSE_SEQ;
  }
  if ((state.options & CLI_RAW_INPUT) != 0) {
    jq_util_input_set_parser(state.inputs, NULL,
                             (state.options & CLI_SLURP) != 0);
  } else {
    jq_util_input_set_parser(state.inputs, jv_parser_new(state.parser_flags),
                             (state.options & CLI_SLURP) != 0);
  }
  jq_set_input_cb(state.jq, resolved_input_callback, state.inputs);
  jq_set_debug_cb(state.jq, debug_callback, &state.dump_flags);
  jq_set_stderr_cb(state.jq, stderr_callback, &state.dump_flags);
  if (state.file_count == 0) {
    jq_util_input_add_input(state.inputs, "-");
  }

  if ((state.options & CLI_NULL_INPUT) != 0) {
    status = run_filter(&state, jv_null());
  } else {
    jv input;
    while (jq_util_input_errors(state.inputs) == 0 &&
           (jv_is_valid(input = jq_util_input_next_input(state.inputs)) ||
            jv_invalid_has_msg(jv_copy(input)))) {
      if (jv_is_valid(input)) {
        status = run_filter(&state, input);
        if (status <= 0 && status != STATUS_NO_OUTPUT) {
          last_result = status != STATUS_FALSE_OR_NULL;
        }
        if (jq_halted(state.jq)) {
          break;
        }
      } else {
        jv message = jv_invalid_get_msg(input);
        if ((state.options & CLI_SEQUENCE) == 0) {
          status = STATUS_RUNTIME_ERROR;
          fprintf(stderr, "jq: parse error: %s\n", jv_string_value(message));
          jv_free(message);
          break;
        }
        fprintf(stderr, "jq: ignoring parse error: %s\n",
                jv_string_value(message));
        jv_free(message);
      }
    }
  }
  if (jq_util_input_errors(state.inputs) != 0) {
    status = STATUS_SYSTEM_ERROR;
  }

cleanup:
  bad_write = ferror(stdout);
  if (fclose(stdout) != 0 || bad_write) {
    fprintf(stderr, "jq: error: writing output failed: %s\n", strerror(errno));
    status = STATUS_SYSTEM_ERROR;
  }
  jv_free(state.positional);
  jv_free(state.named);
  if (jv_get_kind(state.library_paths) != JV_KIND_INVALID) {
    jv_free(state.library_paths);
  }
  jq_util_input_free(&state.inputs);
  jq_teardown(&state.jq);
  return final_exit_status(status, last_result,
                           (state.options & CLI_EXIT_STATUS) != 0);
}

int wmain(int argc, wchar_t **wide_argv) {
  char **argv = calloc((size_t)argc + 1, sizeof(*argv));
  int result;
  if (argv == NULL) {
    return STATUS_SYSTEM_ERROR;
  }
  for (int index = 0; index < argc; ++index) {
    int bytes = WideCharToMultiByte(CP_UTF8, 0, wide_argv[index], -1, NULL, 0,
                                    NULL, NULL);
    argv[index] = malloc((size_t)bytes);
    if (argv[index] == NULL ||
        WideCharToMultiByte(CP_UTF8, 0, wide_argv[index], -1, argv[index],
                            bytes, NULL, NULL) == 0) {
      for (int previous = 0; previous <= index; ++previous) {
        free(argv[previous]);
      }
      free(argv);
      return STATUS_SYSTEM_ERROR;
    }
  }
  result = jq_cli_main(argc, argv);
  for (int index = 0; index < argc; ++index) {
    free(argv[index]);
  }
  free(argv);
  return result;
}

#include "hello.h"

#include <errno.h>
#include <stddef.h>
#include <string.h>

static const char *const usage_suffix = " [OPTION]...";

const char *hello_program_name(const char *path) {
  const char *result = path;
  const char *cursor;

  if (path == NULL || path[0] == '\0') {
    return "hello.exe";
  }
  for (cursor = path; *cursor != '\0'; ++cursor) {
    if (*cursor == '/' || *cursor == '\\') {
      result = cursor + 1;
    }
  }
  return result[0] == '\0' ? "hello.exe" : result;
}

static hello_options option_error(FILE *errors, const char *program_name,
                                  const char *message, const char *argument,
                                  int quote_argument) {
  hello_options result = {HELLO_ACTION_ERROR, NULL, 0};

  if (argument == NULL) {
    fprintf(errors, "%s: %s\n", program_name, message);
  } else if (quote_argument) {
    fprintf(errors, "%s: %s'%s'\n", program_name, message, argument);
  } else {
    fprintf(errors, "%s: %s%s\n", program_name, message, argument);
  }
  fprintf(errors, "Try '%s --help' for more information.\n", program_name);
  return result;
}

hello_options hello_parse_options(int argc, char **argv, FILE *errors) {
  hello_options result = {HELLO_ACTION_GREET, NULL, 0};
  const char *program_name = hello_program_name(argc > 0 ? argv[0] : NULL);
  int index;

  for (index = 1; index < argc; ++index) {
    const char *argument = argv[index];

    if (strcmp(argument, "--") == 0) {
      ++index;
      break;
    }
    if (strcmp(argument, "--help") == 0) {
      result.action = HELLO_ACTION_HELP;
      return result;
    }
    if (strcmp(argument, "--version") == 0) {
      result.action = HELLO_ACTION_VERSION;
      return result;
    }
    if (strcmp(argument, "--traditional") == 0) {
      result.greeting = NULL;
      result.traditional = 1;
      continue;
    }
    if (strncmp(argument, "--greeting=", 11) == 0) {
      result.greeting = argument + 11;
      result.traditional = 0;
      continue;
    }
    if (strcmp(argument, "--greeting") == 0) {
      if (++index == argc) {
        return option_error(errors, program_name,
                            "option '--greeting' requires an argument", NULL, 0);
      }
      result.greeting = argv[index];
      result.traditional = 0;
      continue;
    }
    if (argument[0] == '-' && argument[1] != '\0') {
      const char *option = argument + 1;
      while (*option != '\0') {
        if (*option == 't') {
          result.greeting = NULL;
          result.traditional = 1;
          ++option;
          continue;
        }
        if (*option == 'g') {
          ++option;
          if (*option != '\0') {
            result.greeting = option;
          } else if (++index < argc) {
            result.greeting = argv[index];
          } else {
            return option_error(errors, program_name,
                                "option requires an argument -- ", "g", 1);
          }
          result.traditional = 0;
          break;
        }
        if (argument[1] == '-') {
          return option_error(errors, program_name, "unrecognized option ",
                              argument, 1);
        }
        {
          char short_option[2] = {*option, '\0'};
          return option_error(errors, program_name, "invalid option -- ",
                              short_option, 1);
        }
      }
      continue;
    }
    break;
  }

  if (index < argc) {
    return option_error(errors, program_name, "extra operand: ", argv[index], 0);
  }
  return result;
}

void hello_print_help(FILE *output, const char *program_name) {
  fprintf(output, "Usage: %s%s\n", program_name, usage_suffix);
  fputs("Print a friendly, customizable greeting.\n"
        "\n"
        "  -t, --traditional       use traditional greeting\n"
        "  -g, --greeting=TEXT     use TEXT as the greeting message\n"
        "\n"
        "      --help     display this help and exit\n"
        "      --version  output version information and exit\n"
        "\n"
        "Report bugs to: bug-hello@gnu.org\n"
        "GNU Hello home page: <https://www.gnu.org/software/hello/>\n"
        "General help using GNU software: <https://www.gnu.org/gethelp/>\n"
        "Report GNU Hello translation bugs to "
        "<https://translationproject.org/team/>\n",
        output);
}

void hello_print_version(FILE *output) {
  fputs("hello (GNU Hello) 2.12.3\n"
        "Copyright (C) 2026 Free Software Foundation, Inc.\n"
        "License GPLv3+: GNU GPL version 3 or later "
        "<https://gnu.org/licenses/gpl.html>.\n"
        "This is free software: you are free to change and redistribute it.\n"
        "There is NO WARRANTY, to the extent permitted by law.\n"
        "\n"
        "Written by Karl Berry, Sami Kerola, Jim Meyering,\n"
        "and Reuben Thomas.\n",
        output);
}

static int hello_finish_output(const char *program_name, int status) {
  if (fflush(stdout) == EOF || ferror(stdout)) {
    int saved_errno = errno;

    fprintf(stderr, "%s: write error", program_name);
    if (saved_errno != 0) {
      fprintf(stderr, ": %s", strerror(saved_errno));
    }
    fputc('\n', stderr);
    return 1;
  }
  return status;
}

int main(int argc, char **argv) {
  const char *program_name = hello_program_name(argc > 0 ? argv[0] : NULL);
  hello_options options = hello_parse_options(argc, argv, stderr);

  switch (options.action) {
  case HELLO_ACTION_HELP:
    hello_print_help(stdout, program_name);
    return hello_finish_output(program_name, 0);
  case HELLO_ACTION_VERSION:
    hello_print_version(stdout);
    return hello_finish_output(program_name, 0);
  case HELLO_ACTION_ERROR:
    return hello_finish_output(program_name, 1);
  case HELLO_ACTION_GREET:
    break;
  }

  if (options.greeting != NULL) {
    puts(options.greeting);
  } else if (options.traditional) {
    puts("hello, world");
  } else {
    puts("Hello, world!");
  }
  return hello_finish_output(program_name, 0);
}

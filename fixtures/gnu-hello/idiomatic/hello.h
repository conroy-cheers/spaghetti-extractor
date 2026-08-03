#ifndef SPAGHETTI_EXTRACTOR_GNU_HELLO_H
#define SPAGHETTI_EXTRACTOR_GNU_HELLO_H

#include <stdio.h>

typedef enum hello_action {
  HELLO_ACTION_GREET,
  HELLO_ACTION_HELP,
  HELLO_ACTION_VERSION,
  HELLO_ACTION_ERROR
} hello_action;

typedef struct hello_options {
  hello_action action;
  const char *greeting;
  int traditional;
} hello_options;

const char *hello_program_name(const char *path);
hello_options hello_parse_options(int argc, char **argv, FILE *errors);
void hello_print_help(FILE *output, const char *program_name);
void hello_print_version(FILE *output);

#endif

/* Source-assisted from pinned jq 1.8.1; see COPYING. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define HAVE_PTHREAD 1
#define USE_DECNUM 1
#include "test-input.h"
#include "windows-files.h"
spx_input *spx_runtime_stdin(void);
#include "jv.h"
#include "jq.h"

void spx_test_values(void);
static void run_jq_tests(jv, int, spx_input *, int, int);
static void run_jq_start_state_tests(void);
#ifdef HAVE_PTHREAD
static void run_jq_pthread_tests(void);
#endif

int portable_jq_testsuite(jv libdirs, int verbose, int argc, char* argv[]) {
  spx_input *testdata = spx_runtime_stdin();
  int skip = -1;
  int take = -1;
  spx_test_values();
  if (argc > 0) {
    for(int i = 0; i < argc; i++) {
      if (!strcmp(argv[i], "--skip")) {
        skip = atoi(argv[i+1]);
        i++;
      } else if (!strcmp(argv[i], "--take")) {
        take = atoi(argv[i+1]);
        i++;
      } else {
        testdata = spx_input_open(argv[i], 1);
        if (!testdata) {
          perror("fopen");
          spx_test_exit(1);
        }
      }
    }
  }
  run_jq_tests(libdirs, verbose, testdata, skip, take);
  run_jq_start_state_tests();
#ifdef HAVE_PTHREAD
  run_jq_pthread_tests();
#endif
  return 0;
}

static int skipline(const char* buf) {
  int p = 0;
  while (buf[p] == ' ' || buf[p] == '\t') p++;
  if (buf[p] == '#' || buf[p] == '\n' || buf[p] == 0) return 1;
  return 0;
}

static int checkerrormsg(const char* buf) {
  return strcmp(buf, "%%FAIL\n") == 0;
}

static int checkfail(const char* buf) {
  return strcmp(buf, "%%FAIL\n") == 0 || strcmp(buf, "%%FAIL IGNORE MSG\n") == 0;
}

struct err_data {
  char buf[4096];
};

static void test_err_cb(void *data, jv e) {
  struct err_data *err_data = data;
  if (jv_get_kind(e) != JV_KIND_STRING)
    e = jv_dump_string(e, JV_PRINT_INVALID);
  if (!strncmp(jv_string_value(e), "jq: error", sizeof("jq: error") - 1))
    snprintf(err_data->buf, sizeof(err_data->buf), "%s", jv_string_value(e));
  jv_free(e);
}

static void run_jq_tests(jv lib_dirs, int verbose, spx_input *testdata, int skip, int take) {
  char prog[4096] = {0};
  char buf[4096];
  struct err_data err_msg;
  int tests = 0, passed = 0, invalid = 0;
  unsigned int lineno = 0;
  int must_fail = 0;
  int check_msg = 0;
  jq_state *jq = NULL;

  int tests_to_skip = skip > 0 ? skip : 0;
  int tests_to_take = take;

  jq = jq_init();
  assert(jq);
  if (jv_get_kind(lib_dirs) == JV_KIND_NULL)
    lib_dirs = jv_array();
  jq_set_attr(jq, jv_string("JQ_LIBRARY_PATH"), lib_dirs);

  while (1) {
    if (!spx_input_gets(prog, sizeof(prog), testdata)) break;
    lineno++;
    if (skipline(prog)) continue;
    if (checkfail(prog)) {
      must_fail = 1;
      check_msg = checkerrormsg(prog);
      jq_set_error_cb(jq, test_err_cb, &err_msg);
      continue;
    }
    if (prog[strlen(prog)-1] == '\n') prog[strlen(prog)-1] = 0;

    if (skip > 0) {
      skip--;
      goto next;
    } else if (skip == 0) {
      printf("Skipped %d tests\n", tests_to_skip);
      skip = -1;
    }

    if (take > 0) {
      take--;
    } else if (take == 0) {
      printf("Hit the number of tests limit (%d), breaking\n", tests_to_take);
      break;
    }

    int pass = 1;
    tests++;
    printf("Test #%d: '%s' at line number %u\n", tests + tests_to_skip, prog, lineno);
    int compiled = jq_compile(jq, prog);

    if (must_fail) {
      jq_set_error_cb(jq, NULL, NULL);
      if (compiled) {
        printf("*** Test program compiled successfully, but should fail at line number %u: %s\n", lineno, prog);
        goto fail;
      }
      char *err_buf = err_msg.buf;
      while (spx_input_gets(buf, sizeof(buf), testdata)) {
        lineno++;
        if (skipline(buf)) break;
        if (check_msg) {
          if (buf[strlen(buf)-1] == '\n') buf[strlen(buf)-1] = '\0';
          if (strncmp(buf, err_buf, strlen(buf)) != 0) {
            if (strchr(err_buf, '\n')) *strchr(err_buf, '\n') = '\0';
            printf("*** Erroneous program failed with '%s', but expected '%s' at line number %u: %s\n", err_buf, buf, lineno, prog);
            goto fail;
          }
          err_buf += strlen(buf);
          if (*err_buf == '\n') err_buf++;
        }
      }
      if (check_msg && *err_buf != '\0') {
        if (strchr(err_buf, '\n')) *strchr(err_buf, '\n') = '\0';
        printf("*** Erroneous program failed with extra message '%s' at line %u: %s\n", err_buf, lineno, prog);
        invalid++;
        pass = 0;
      }
      must_fail = 0;
      check_msg = 0;
      passed += pass;
      continue;
    }

    if (!compiled) {
      printf("*** Test program failed to compile at line %u: %s\n", lineno, prog);
      goto fail;
    }
    if (verbose) {
      printf("Disassembly:\n");
      jq_dump_disassembly(jq, 2);
      printf("\n");
    }
    if (!spx_input_gets(buf, sizeof(buf), testdata)) { invalid++; break; }
    lineno++;
    jv input = jv_parse(buf);
    if (!jv_is_valid(input)) {
      printf("*** Input is invalid on line %u: %s\n", lineno, buf);
      goto fail;
    }
    jq_start(jq, input, verbose ? JQ_DEBUG_TRACE : 0);

    while (spx_input_gets(buf, sizeof(buf), testdata)) {
      lineno++;
      if (skipline(buf)) break;
      jv expected = jv_parse(buf);
      if (!jv_is_valid(expected)) {
        printf("*** Expected result is invalid on line %u: %s\n", lineno, buf);
        goto fail;
      }
      jv actual = jq_next(jq);
      if (!jv_is_valid(actual)) {
        jv_free(expected);
        jv_free(actual);
        printf("*** Insufficient results for test at line number %u: %s\n", lineno, prog);
        pass = 0;
        break;
      } else if (!jv_equal(jv_copy(expected), jv_copy(actual))) {
        printf("*** Expected ");
        jv_dump(jv_copy(expected), 0);
        printf(", but got ");
        jv_dump(jv_copy(actual), 0);
        printf(" for test at line number %u: %s\n", lineno, prog);
        pass = 0;
      }
#ifdef USE_DECNUM
      jv as_string = jv_dump_string(jv_copy(expected), rand() & ~(JV_PRINT_COLOR|JV_PRINT_REFCOUNT));
      jv reparsed = jv_parse_sized(jv_string_value(as_string), jv_string_length_bytes(jv_copy(as_string)));
      assert(jv_equal(jv_copy(expected), jv_copy(reparsed)));
      jv_free(as_string);
      jv_free(reparsed);
#endif
      jv_free(expected);
      jv_free(actual);
    }
    if (pass) {
      jv extra = jq_next(jq);
      if (jv_is_valid(extra)) {
        printf("*** Superfluous result: ");
        jv_dump(extra, 0);
        printf(" for test at line number %u, %s\n", lineno, prog);
        invalid++;
        pass = 0;
      } else {
        jv_free(extra);
      }
    }
    passed += pass;
    continue;

fail:
    invalid++;

next:
    while (spx_input_gets(buf, sizeof(buf), testdata)) {
      lineno++;
      if (skipline(buf)) break;
    }
    must_fail = 0;
    check_msg = 0;
  }
  jq_teardown(&jq);

  int total_skipped = tests_to_skip;

  if (skip > 0) {
    total_skipped = tests_to_skip - skip;
  }

  printf("%d of %d tests passed (%d malformed, %d skipped)\n",
    passed, tests, invalid, total_skipped);

  if (skip > 0) {
    printf("WARN: skipped past the end of file, exiting with status 2\n");
    spx_test_exit(2);
  }

  if (passed != tests) spx_test_exit(1);
}


static int test_start_state(jq_state *jq, char *prog) {
  int pass = 1;
  jv message = jq_get_error_message(jq);
  if (jv_is_valid(message)) {
    printf("*** Expected error_message to be invalid after jq_start: %s\n", prog);
    pass = 0;
  }
  jv_free(message);

  jv exit_code = jq_get_exit_code(jq);
  if (jv_is_valid(exit_code)) {
    printf("*** Expected exit_code to be invalid after jq_start: %s\n", prog);
    pass = 0;
  }
  jv_free(exit_code);

  if (jq_halted(jq)) {
    printf("*** Expected jq to not be halted after jq_start: %s\n", prog);
    pass = 0;
  }

  return pass;
}

// Test jq_state is reset after subsequent calls to jq_start.
static void test_jq_start_resets_state(char *prog, const char *input) {
  printf("Test jq_state: %s\n", prog);
  jq_state *jq = jq_init();
  assert(jq);

  int compiled = jq_compile(jq, prog);
  assert(compiled);

  // First call to jq_start. Run until completion.
  jv parsed_input = jv_parse(input);
  assert(jv_is_valid(parsed_input));
  jq_start(jq, parsed_input, 0);
  assert(test_start_state(jq, prog));
  while (1) {
    jv result = jq_next(jq);
    int valid = jv_is_valid(result);
    jv_free(result);
    if (!valid) { break; }
  }

  // Second call to jq_start.
  jv parsed_input2 = jv_parse(input);
  assert(jv_is_valid(parsed_input2));
  jq_start(jq, parsed_input2, 0);
  assert(test_start_state(jq, prog));

  jq_teardown(&jq);
}

static void run_jq_start_state_tests(void) {
  test_jq_start_resets_state(".[]", "[1,2,3]");
  test_jq_start_resets_state(".[] | if .%2 == 0 then halt_error else . end", "[1,2,3]");
}


/// pthread regression test
#ifdef HAVE_PTHREAD
#define NUMBER_OF_THREADS 3
struct test_pthread_data {
    int result;
};

static int test_pthread_jq_parse(jq_state *jq, struct jv_parser *parser)
{
    int rv = 0;
    jv value;

    value = jv_parser_next(parser);
    while (jv_is_valid(value)) {
        jq_start(jq, value, 0);
        jv result = jq_next(jq);

        while (jv_is_valid(result)) {
            jv_free(result);
            result = jq_next(jq);
        }
        jv_free(result);
        value = jv_parser_next(parser);
    }
    jv_free(value);
    return rv;
}

static void *test_pthread_run(void *ptr) {
    int rv;
    jq_state *jq;
    const char *prg = ".data";
    const char *buf = "{ \"data\": 1 }";
    struct test_pthread_data *data = ptr;

    jq = jq_init();
    if (jq_compile(jq, prg) == 0) {
        jq_teardown(&jq);
        return NULL;
    }

    struct jv_parser *parser = jv_parser_new(0);
    jv_parser_set_buf(parser, buf, strlen(buf), 0);
    rv = test_pthread_jq_parse(jq, parser);

    data->result = rv;

    jv_parser_free(parser);
    jq_teardown(&jq);
    return NULL;
}

static void run_jq_pthread_tests(void) {
    pthread_t threads[NUMBER_OF_THREADS];
    struct test_pthread_data data[NUMBER_OF_THREADS];
    int createerror;
    int a;

    memset(&threads, 0, sizeof(threads));
    memset(&data, 0, sizeof(data));

    // Create all threads
    for (a = 0; a < NUMBER_OF_THREADS; ++a) {
        createerror = spx_test_thread_create(&threads[a], NULL, test_pthread_run, &data[a]);
        assert(createerror == 0);
    }

    // wait for all threads
    for(a = 0; a < NUMBER_OF_THREADS; ++a) {
        if (threads[a] != 0) {
            spx_test_thread_join(threads[a], NULL);
        }
    }

    // check results
    for(a = 0; a < NUMBER_OF_THREADS; ++a) {
        assert(data[a].result == 0);
    }
}
#endif // HAVE_PTHREAD

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "input-stream.h"
#include "jv_alloc.h"
#include "windows-files.h"
struct jq_util_input_state {
  jq_util_msg_cb err_cb;
  void *err_cb_data;
  jv_parser *parser;
  spx_input *current_input;
  char **files;
  int nfiles;
  int curr_file;
  int failures;
  jv slurped;
  char buf[4096];
  size_t buf_valid_len;
  jv current_filename;
  size_t current_line;
};

static void fprinter(void *data, const char *fname) {
  fprintf((FILE *)data, "jq: error: Could not open file %s: %s\n", fname, strerror(errno));
}

// If parser == NULL -> RAW
jq_util_input_state *portable_jq_util_input_init(jq_util_msg_cb err_cb, void *err_cb_data) {
  if (err_cb == NULL) {
    err_cb = fprinter;
    err_cb_data = stderr;
  }
  jq_util_input_state *new_state = jv_mem_calloc(1, sizeof(*new_state));
  new_state->err_cb = err_cb;
  new_state->err_cb_data = err_cb_data;
  new_state->slurped = jv_invalid();
  new_state->current_filename = jv_invalid();

  return new_state;
}

void portable_jq_util_input_set_parser(jq_util_input_state *state, jv_parser *parser, int slurp) {
  assert(!jv_is_valid(state->slurped));
  state->parser = parser;

  if (parser == NULL && slurp)
    state->slurped = jv_string("");
  else if (slurp)
    state->slurped = jv_array();
  else
    state->slurped = jv_invalid();
}

void portable_jq_util_input_free(jq_util_input_state **state) {
  jq_util_input_state *old_state = *state;
  *state = NULL;
  if (old_state == NULL)
    return;

  /* The original destroy abandons an active FILE until CRT shutdown. Keep
   * that lifetime, while discarding our extra decoder wrapper. */
  if (old_state->current_input && !spx_input_borrowed(old_state->current_input))
    (void)spx_input_detach(old_state->current_input);
  if (old_state->parser != NULL)
    jv_parser_free(old_state->parser);
  for (int i = 0; i < old_state->nfiles; i++)
    jv_mem_free(old_state->files[i]);
  jv_mem_free(old_state->files);
  jv_free(old_state->slurped);
  jv_free(old_state->current_filename);
  jv_mem_free(old_state);
}

void portable_jq_util_input_add_input(jq_util_input_state *state, const char *fname) {
  state->files = jv_mem_realloc(state->files, (state->nfiles + 1) * sizeof(state->files[0]));
  state->files[state->nfiles++] = jv_mem_strdup(fname);
}

int portable_jq_util_input_errors(jq_util_input_state *state) {
  return state->failures;
}

static const char *next_file(jq_util_input_state *state) {
  if (state->curr_file < state->nfiles)
    return state->files[state->curr_file++];
  return NULL;
}

static int jq_util_input_read_more(jq_util_input_state *state) {
  if (!state->current_input || spx_input_eof(state->current_input) || spx_input_error(state->current_input)) {
    if (state->current_input && spx_input_error(state->current_input)) {
      // System-level input error on the stream. It will be closed (below).
      // TODO: report it. Can't use 'state->err_cb()' as it is hard-coded for
      //       'open' related problems.
      fprintf(stderr,"jq: error: %s\n", strerror(errno));
    }
    if (state->current_input) {
      if (spx_input_borrowed(state->current_input)) {
        spx_input_clear(state->current_input);
        // perhaps we can read again; anyways, we don't spx_input_close(stdin)
      } else {
        spx_input_close(state->current_input);
      }
      state->current_input = NULL;
    }
    const char *f = next_file(state);
    if (f != NULL) {
      jv_free(state->current_filename);
      state->current_line = 0;
      if (!strcmp(f, "-")) {
        state->current_input = spx_runtime_stdin();
        if (!state->current_input) { state->err_cb(state->err_cb_data, f); state->failures++; }
        state->current_filename = jv_string("<stdin>");
      } else {
        state->current_input = spx_input_open(f, 1);
        state->current_filename = jv_string(f);
        if (!state->current_input) {
          state->err_cb(state->err_cb_data, f);
          state->failures++;
        }
      }
    }
  }

  state->buf[0] = 0;
  state->buf_valid_len = 0;
  if (state->current_input) {
    char *res;
    memset(state->buf, 0xff, sizeof(state->buf));

    while (!(res = spx_input_gets(state->buf, sizeof(state->buf), state->current_input)) &&
           spx_input_error(state->current_input) && errno == EINTR)
      spx_input_clear(state->current_input);
    if (res == NULL) {
      state->buf[0] = 0;
      if (spx_input_error(state->current_input))
        state->failures++;
    } else {
      const char *p = memchr(state->buf, '\n', sizeof(state->buf));

      if (p != NULL)
        state->current_line++;

      if (p == NULL && spx_input_eof(state->current_input)) {
        size_t i;

        /*
         * XXX We don't know how many bytes we've read!
         *
         * We can't use getline() because there need not be any newlines
         * in the input.  The only entirely correct choices are: use
         * fgetc() or fread().  Using fread() will complicate buffer
         * management here.
         *
         * For now we check how much spx_input_gets() read by scanning backwards for the
         * terminating '\0'. This only works because we previously memset our
         * buffer with something nonzero.
         */
        for (i = sizeof(state->buf) - 1; i > 0; i--) {
          if (state->buf[i] == '\0')
            break;
        }
        state->buf_valid_len = i;
      } else if (p == NULL) {
        state->buf_valid_len = sizeof(state->buf) - 1;
      } else {
        state->buf_valid_len = (p - state->buf) + 1;
      }
    }
  }
  return state->curr_file == state->nfiles && !state->current_input;
}

jv portable_jq_util_input_next_input_cb(jq_state *jq, void *data) {
  (void)jq;
  return portable_jq_util_input_next_input((jq_util_input_state *)data);
}

// Return the current_filename:current_line
jv portable_jq_util_input_get_position(jq_state *jq) {
  jq_input_cb cb = NULL;
  void *cb_data = NULL;
  jq_get_input_cb(jq, &cb, &cb_data);
  if (cb != spx_input_callback_entry()) spx_input_callback_assertion();
  if (cb != spx_input_callback_entry())
    return jv_invalid_with_msg(jv_string("Invalid jq_util_input API usage"));
  jq_util_input_state *s = (jq_util_input_state *)cb_data;

  // We can't assert that current_filename is a string because if
  // the error was a JSON parser error then we may not have set
  // current_filename yet.
  if (jv_get_kind(s->current_filename) != JV_KIND_STRING)
    return jv_string("<unknown>");

  jv v = jv_string_fmt("%s:%lu", jv_string_value(s->current_filename), (unsigned long)s->current_line);
  return v;
}

jv portable_jq_util_input_get_current_filename(jq_state* jq) {
  jq_input_cb cb=NULL;
  void *cb_data=NULL;
  jq_get_input_cb(jq, &cb, &cb_data);
  if (cb != spx_input_callback_entry())
    return jv_invalid_with_msg(jv_string("Unknown input filename"));
  jq_util_input_state *s = (jq_util_input_state *)cb_data;
  jv v = jv_copy(s->current_filename);
  return v;
}

jv portable_jq_util_input_get_current_line(jq_state* jq) {
  jq_input_cb cb=NULL;
  void *cb_data=NULL;
  jq_get_input_cb(jq, &cb, &cb_data);
  if (cb != spx_input_callback_entry())
    return jv_invalid_with_msg(jv_string("Unknown input line number"));
  jq_util_input_state *s = (jq_util_input_state *)cb_data;
  jv v = jv_number(s->current_line);
  return v;
}


// Blocks to read one more input from stdin and/or given files
// When slurping, it returns just one value
jv portable_jq_util_input_next_input(jq_util_input_state *state) {
  int is_last = 0;
  jv value = jv_invalid(); // need more input
  do {
    if (state->parser == NULL) {
      // Raw input
      is_last = jq_util_input_read_more(state);
      if (state->buf_valid_len == 0)
        continue;
      if (jv_is_valid(state->slurped)) {
        // Slurped raw input
        state->slurped = jv_string_concat(state->slurped, jv_string_sized(state->buf, state->buf_valid_len));
      } else {
        if (!jv_is_valid(value))
          value = jv_string("");
        if (state->buf[state->buf_valid_len-1] == '\n') {
          // whole line
          state->buf[state->buf_valid_len-1] = 0;
          return jv_string_concat(value, jv_string_sized(state->buf, state->buf_valid_len-1));
        }
        value = jv_string_concat(value, jv_string_sized(state->buf, state->buf_valid_len));
        state->buf[0] = '\0';
        state->buf_valid_len = 0;
      }
    } else {
      if (jv_parser_remaining(state->parser) == 0) {
        is_last = jq_util_input_read_more(state);
        jv_parser_set_buf(state->parser, state->buf, state->buf_valid_len, !is_last);
      }
      value = jv_parser_next(state->parser);
      if (jv_is_valid(state->slurped)) {
        if (jv_is_valid(value)) {
          state->slurped = jv_array_append(state->slurped, value);
          value = jv_invalid();
        } else if (jv_invalid_has_msg(jv_copy(value)))
          return value; // Not slurped parsed input
      } else if (jv_is_valid(value) || jv_invalid_has_msg(jv_copy(value))) {
        return value;
      }
    }
  } while (!is_last);

  if (jv_is_valid(state->slurped)) {
    value = state->slurped;
    state->slurped = jv_invalid();
  }
  return value;
}

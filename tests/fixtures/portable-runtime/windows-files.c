#define _POSIX_C_SOURCE 200809L
#include "windows-files.h"
#include "windows-paths.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#else
#include <dirent.h>
#endif

struct spx_input {
    FILE *file;
    int text_mode;
    int owned;
    int ended;
};

#ifndef _WIN32
static unsigned char fold(unsigned char c) {
    return c >= 'A' && c <= 'Z' ? (unsigned char)(c + ('a' - 'A')) : c;
}

static int same_name(const char *a, const char *b) {
    while (*a && *b && fold((unsigned char)*a) == fold((unsigned char)*b)) {
        ++a;
        ++b;
    }
    return *a == *b;
}
#endif

char *spx_file_resolve(const char *path) {
    char *resolved = spx_path_to_host(path);
    if (!resolved) return NULL;
#ifndef _WIN32
    size_t length = strlen(resolved);
    for (size_t i = 0; i < length; ++i)
        if (resolved[i] == '\\') resolved[i] = '/';
    struct stat info;
    if (stat(resolved, &info) == 0) return resolved;
    if (errno != ENOENT && errno != ENOTDIR) {
        int error = errno;
        free(resolved);
        errno = error;
        return NULL;
    }
    /* Resolve each segment, including parents whose spelling differs. Exact
     * spelling wins; ambiguous folded names are rejected, never guessed. */
    size_t start = resolved[0] == '/' ? 1 : 0;
    while (start < length) {
        while (resolved[start] == '/') ++start;
        if (!resolved[start]) break;
        size_t end = start;
        while (resolved[end] && resolved[end] != '/') ++end;
        char separator = resolved[end];
        resolved[end] = 0;
        if (stat(resolved, &info) != 0) {
            if (errno != ENOENT && errno != ENOTDIR) goto fail;
            char preceding = start ? resolved[start - 1] : 0;
            if (start) resolved[start - 1] = 0;
            const char *parent = start == 0 ? "." : start == 1 ? "/" : resolved;
            DIR *directory = opendir(parent);
            if (start) resolved[start - 1] = preceding;
            if (!directory) goto fail;
            char *matched = NULL;
            int error = 0;
            struct dirent *entry;
            errno = 0;
            while ((entry = readdir(directory))) {
                if (!same_name(entry->d_name, resolved + start)) continue;
                if (matched) { error = EEXIST; break; }
                matched = malloc(end - start + 1);
                if (!matched) { error = ENOMEM; break; }
                memcpy(matched, entry->d_name, end - start + 1);
            }
            if (!error && errno) error = errno;
            closedir(directory);
            if (error || !matched) {
                free(matched);
                errno = error ? error : ENOENT;
                goto fail;
            }
            memcpy(resolved + start, matched, end - start + 1);
            free(matched);
        }
        resolved[end] = separator;
        start = end;
    }
#endif
    return resolved;
#ifndef _WIN32
fail: {
    int error = errno;
    free(resolved);
    errno = error;
    return NULL;
}
#endif
}

int spx_file_stat(const char *path, struct stat *result) {
    char *resolved = spx_file_resolve(path);
    if (!resolved) return -1;
    int status = stat(resolved, result), error = errno;
    free(resolved);
    errno = error;
    return status;
}

spx_input *spx_input_attach(FILE *file, int text_mode, int owned) {
    spx_input *input = malloc(sizeof(*input));
    if (!input) return NULL;
#ifdef _WIN32
    /* Decoding below operates on bytes, even when the host is Windows. */
    if (_setmode(_fileno(file), _O_BINARY) == -1) {
        int error = errno;
        free(input);
        errno = error;
        return NULL;
    }
#endif
    *input = (spx_input){file, text_mode, owned, 0};
    return input;
}

spx_input *spx_input_open(const char *path, int text_mode) {
    char *resolved = spx_file_resolve(path);
    if (!resolved) return NULL;
    struct stat info;
    if (stat(resolved, &info) == 0 && S_ISDIR(info.st_mode)) {
        free(resolved);
        errno = EACCES;
        return NULL;
    }
    FILE *file = fopen(resolved, "rb");
    int error = errno;
    free(resolved);
    errno = error;
    if (!file) return NULL;
    spx_input *input = spx_input_attach(file, text_mode, 1);
    if (!input) {
        error = errno;
        fclose(file);
        errno = error;
    }
    return input;
}

static int next_byte(spx_input *input) {
    if (input->ended) return EOF;
    int c = fgetc(input->file);
    if (c == EOF || (input->text_mode && c == 0x1a)) {
        input->ended = c == EOF ? 1 : 2;
        return EOF;
    }
    if (input->text_mode && c == '\r') {
        int next = fgetc(input->file);
        if (next == '\n') return '\n';
        if (next != EOF) ungetc(next, input->file);
    }
    return c;
}

size_t spx_input_read(void *buffer, size_t length, spx_input *input) {
    unsigned char *bytes = buffer;
    size_t count = 0;
    while (count < length) {
        int c = next_byte(input);
        if (c == EOF) break;
        bytes[count++] = (unsigned char)c;
    }
    return count;
}

char *spx_input_gets(char *buffer, int capacity, spx_input *input) {
    if (capacity <= 0) return NULL;
    int count = 0;
    while (count < capacity - 1) {
        int c = next_byte(input);
        if (c == EOF) break;
        buffer[count++] = (char)c;
        if (c == '\n') break;
    }
    if (!count && capacity != 1) return NULL;
    buffer[count] = 0;
    return buffer;
}

int spx_input_eof(const spx_input *input) {
    return input->ended || feof(input->file);
}

int spx_input_error(const spx_input *input) { return ferror(input->file); }
int spx_input_borrowed(const spx_input *input) { return !input->owned; }

void spx_input_clear(spx_input *input) {
    /* clearerr clears the stdio indicators, not the CRT descriptor's Ctrl-Z
     * end marker. All aliases of a stream must retain that same marker. */
    if (input->ended != 2) input->ended = 0;
    clearerr(input->file);
}

int spx_input_close(spx_input *input) {
    int status = input->owned ? fclose(input->file) : 0;
    free(input);
    return status;
}

FILE *spx_input_detach(spx_input *input) {
    FILE *file = input->file;
    free(input);
    return file;
}

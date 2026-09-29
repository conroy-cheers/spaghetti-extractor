/* Windows lexical paths, adapted from Wine 11.0 dlls/ntdll/path.c.
 * Copyright 2002, 2003, 2004 Alexandre Julliard
 * Copyright 2003 Eric Pouech
 * LGPL-2.1-or-later; see COPYING.LGPL-2.1. The environment is supplied separately;
 * this byte implementation admits UTF-8 and single-byte path encodings. */
#include "windows-paths.h"
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int separator(char c) { return c == '/' || c == '\\'; }
static char fold(char c) { return c >= 'a' && c <= 'z' ? (char)(c - ('a' - 'A')) : c; }
int spx_path_is_relative(const char *path) {
    return !path || !*path || (path[0] != '\\' && path[1] != ':');
}
static size_t unc_prefix(const char *path) {
    size_t i = 2;
    while (path[i] && !separator(path[i])) ++i;
    while (separator(path[i])) ++i;
    while (path[i] && !separator(path[i])) ++i;
    while (separator(path[i])) ++i;
    return i;
}
static char *join(const char *prefix, const char *suffix, int slash) {
    size_t a = strlen(prefix), b = strlen(suffix);
    if (a > SIZE_MAX - b - 2) { errno = ENOMEM; return NULL; }
    char *result = malloc(a + b + 2);
    if (!result) return NULL;
    memcpy(result, prefix, a);
    if (slash && a && !separator(result[a - 1])) result[a++] = '\\';
    memcpy(result + a, suffix, b + 1);
    return result;
}

/* Preserve the target runtime's treatment of dots, spaces, roots and repeated
 * separators. In particular this is lexical, not a filesystem realpath. */
static void collapse(char *path, size_t mark) {
    char *p, *next;
    for (p = path; *p; ++p) if (*p == '/') *p = '\\';
    next = path + (mark ? mark : 1);
    for (p = next; *p; ++p)
        if (*p != '\\' || next[-1] != '\\') *next++ = *p;
    *next = 0;
    p = path + mark;
    while (*p) {
        if (*p == '.') {
            if (p[1] == '\\') {
                next = p + 2;
                memmove(p, next, strlen(next) + 1);
                continue;
            }
            if (!p[1]) {
                if (p > path + mark) --p;
                *p = 0;
                continue;
            }
            if (p[1] == '.' && (p[2] == '\\' || !p[2])) {
                next = p + (p[2] ? 3 : 2);
                int final = !p[2];
                if (p > path + mark) {
                    --p;
                    while (p > path + mark && p[-1] != '\\') --p;
                    if (final && p > path + mark) --p;
                }
                memmove(p, next, strlen(next) + 1);
                continue;
            }
        }
        while (*p && *p != '\\') ++p;
        if (*p == '\\') {
            if (p > path + mark && p[-1] == '.') memmove(p - 1, p, strlen(p) + 1);
            else ++p;
        }
    }
    while (p > path + mark && (p[-1] == ' ' || p[-1] == '.')) --p;
    *p = 0;
}

static int equal_device(const char *name, size_t size, const char *device) {
    if (strlen(device) != size) return 0;
    for (size_t i = 0; i < size; ++i) if (fold(name[i]) != device[i]) return 0;
    return 1;
}
static char *device_name(const char *path, int *recognized) {
    *recognized = 0;
    const char *name = path, *end;
    if (path[0] && path[1] == ':') name += 2;
    for (const char *p = name; *p; ++p) if (separator(*p)) name = p + 1;
    for (end = name; *end && *end != '.' && *end != ':'; ++end) {}
    while (end > name && end[-1] == ' ') --end;
    size_t size = (size_t)(end - name);
    int match = equal_device(name, size, "AUX") || equal_device(name, size, "CON") ||
        equal_device(name, size, "NUL") || equal_device(name, size, "PRN") ||
        equal_device(name, size, "CONIN$") || equal_device(name, size, "CONOUT$");
    if (size == 4 && name[3] >= '1' && name[3] <= '9')
        match |= equal_device(name, 3, "COM") || equal_device(name, 3, "LPT");
    if (!match) return NULL;
    *recognized = 1;
    char *result = malloc(size + 5);
    if (!result) return NULL;
    memcpy(result, "\\\\.\\", 4);
    memcpy(result + 4, name, size);
    result[size + 4] = 0;
    return result;
}

char *spx_path_expand(const char *path) {
    if (!path || !*path) return spx_path_current();
    const char *nonspace = path;
    while (*nonspace == ' ') ++nonspace;
    if (!*nonspace) { errno = EINVAL; return NULL; }
    size_t mark = 0;
    char *result = NULL, *current = NULL;
    int unc = separator(path[0]) && separator(path[1]);
    int local = unc && (path[2] == '.' || path[2] == '?') && (!path[3] || separator(path[3]));
    if (!unc) {
        int recognized;
        result = device_name(path, &recognized);
        if (recognized) return result;
    }
    if (local) {
        result = path[3] ? join("", path, 0) : join("\\\\.\\", "", 0);
        mark = 4;
    } else if (unc) {
        result = join("", path, 0);
        mark = unc_prefix(path);
    } else if (path[1] == ':' && separator(path[2])) {
        result = join("", path, 0);
        mark = 3;
    } else {
        current = spx_path_current();
        if (!current) return NULL;
        const char *suffix = path;
        if (path[1] == ':') {
            suffix += 2;
            if (current[1] != ':' || fold(current[0]) != fold(path[0])) {
                free(current);
                current = spx_path_drive_current(path[0]);
                if (!current) return NULL;
            }
        } else if (separator(path[0])) {
            size_t root = current[1] == ':' ? 2 : unc_prefix(current);
            current[root] = 0;
            result = join(current, path, 0);
        }
        if (!result) result = join(current, suffix, 1);
        if (result) mark = result[1] == ':' ? 3 : unc_prefix(result);
        free(current);
    }
    if (!result) return NULL;
    collapse(result, mark);
    return result;
}

char *spx_path_full(char *buffer, const char *path, size_t capacity) {
    char *full = spx_path_expand(path);
    if (!full) return NULL;
    size_t length = strlen(full);
    if (length >= capacity) { free(full); errno = ERANGE; return NULL; }
    memcpy(buffer, full, length + 1);
    free(full);
    return buffer;
}

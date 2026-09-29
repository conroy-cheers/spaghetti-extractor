#define _POSIX_C_SOURCE 200809L
#include "windows-paths.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <direct.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

static char upper(char c) { return c >= 'a' && c <= 'z' ? (char)(c - ('a' - 'A')) : c; }
static char *copy(const char *text) {
    size_t size = strlen(text) + 1;
    char *result = malloc(size);
    if (result) memcpy(result, text, size);
    return result;
}

char *spx_path_drive_current(char drive) {
#ifdef _WIN32
    char name[] = "=X:";
    name[1] = drive;
    DWORD size = GetEnvironmentVariableA(name, NULL, 0);
    if (size) {
        char *result = malloc(size);
        if (!result) return NULL;
        DWORD count = GetEnvironmentVariableA(name, result, size);
        if (count && count < size) return result;
        free(result);
    }
#else
    char name[] = "SPX_WINDOWS_CWD_X";
    name[sizeof(name) - 2] = upper(drive);
    const char *value = getenv(name);
    if (value && *value) return copy(value);
#endif
    char root[] = "X:\\";
    root[0] = drive;
    return copy(root);
}

char *spx_path_current(void) {
#ifdef _WIN32
    return _getcwd(NULL, 0);
#else
    const char *configured = getenv("SPX_WINDOWS_CWD");
    if (configured && *configured) {
        if ((configured[0] && configured[1] == ':' &&
             (configured[2] == '/' || configured[2] == '\\')) ||
            (configured[0] == '\\' && configured[1] == '\\')) return copy(configured);
        errno = EINVAL;
        return NULL;
    }
    char *cwd = getcwd(NULL, 0);
    if (!cwd) return NULL;
    const char *root = getenv("SPX_WINDOWS_DRIVE_Z");
    if (!root || !*root) root = "/";
    size_t prefix = strlen(root);
    while (prefix > 1 && root[prefix - 1] == '/') --prefix;
    const char *suffix = cwd;
    if (prefix > 1) {
        if (strncmp(cwd, root, prefix) || (cwd[prefix] && cwd[prefix] != '/')) {
            free(cwd); errno = EXDEV; return NULL;
        }
        suffix += prefix;
    }
    size_t size = strlen(suffix);
    char *result = malloc(size + 4);
    if (result) {
        memcpy(result, "Z:", 2);
        if (size) memcpy(result + 2, suffix, size + 1);
        else memcpy(result + 2, "\\", 2);
        for (char *p = result; *p; ++p) if (*p == '/') *p = '\\';
    }
    free(cwd);
    return result;
#endif
}

char *spx_path_to_host(const char *path) {
#ifdef _WIN32
    (void)&upper;
    return copy(path);
#else
    /* Empty _fullpath means cwd, but an empty fopen name is not a directory. */
    if (!*path) { errno = ENOENT; return NULL; }
    char *full = spx_path_expand(path);
    if (!full) return NULL;
    char *name = full;
    int extended = !strncmp(name, "\\\\?\\", 4) || !strncmp(name, "\\\\.\\", 4);
    if (extended) name += 4;
    const char *root = NULL, *suffix = NULL;
    char variable[] = "SPX_WINDOWS_DRIVE_X";
    if (name[0] && name[1] == ':' && name[2] == '\\') {
        char drive = upper(name[0]);
        if (drive < 'A' || drive > 'Z') { errno = ENOENT; goto fail; }
        variable[sizeof(variable) - 2] = drive;
        root = getenv(variable);
        if (!root && drive == 'Z') root = "/";
        suffix = name + 3;
    } else if (extended && upper(name[0]) == 'U' && upper(name[1]) == 'N' &&
               upper(name[2]) == 'C' && name[3] == '\\') {
        root = getenv("SPX_WINDOWS_UNC_ROOT");
        suffix = name + 4;
    } else if (!extended && name[0] == '\\' && name[1] == '\\') {
        root = getenv("SPX_WINDOWS_UNC_ROOT");
        suffix = name + 2;
    } else if (extended && strlen(name) == 3 && upper(name[0]) == 'N' &&
               upper(name[1]) == 'U' && upper(name[2]) == 'L') {
        free(full);
        return copy("/dev/null");
    } else {
        errno = ENOTSUP;
        goto fail;
    }
    if (!root || !*root) { errno = ENOENT; goto fail; }
    if (*root != '/') { errno = EINVAL; goto fail; }
    size_t a = strlen(root), b = strlen(suffix);
    char *result = malloc(a + b + 2);
    if (!result) goto fail;
    memcpy(result, root, a);
    if (a && result[a - 1] != '/') result[a++] = '/';
    memcpy(result + a, suffix, b + 1);
    for (char *p = result + a; *p; ++p) if (*p == '\\') *p = '/';
    free(full);
    return result;
fail:
    free(full);
    return NULL;
#endif
}

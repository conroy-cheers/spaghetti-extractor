#include <windows.h>
#include <stdio.h>

int main(void) {
    HKEY key;
    DWORD disposition, value = 0, size = sizeof(value), type = 0;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\SpaghettiRuntimeIsolation", 0, NULL, 0,
            KEY_READ | KEY_WRITE, NULL, &key, &disposition) != ERROR_SUCCESS) return 2;
    LONG status = RegQueryValueExA(key, "counter", NULL, &type, (BYTE *)&value, &size);
    if (status != ERROR_FILE_NOT_FOUND &&
            (status != ERROR_SUCCESS || type != REG_DWORD || size != sizeof(value))) return 3;
    DWORD next = value + 1;
    if (RegSetValueExA(key, "counter", 0, REG_DWORD, (BYTE *)&next, sizeof(next)) != ERROR_SUCCESS) return 4;
    if (RegCloseKey(key) != ERROR_SUCCESS) return 5;
    unsigned prior = 0;
    FILE *file = fopen("marker", "r");
    if (file) {
        if (fscanf(file, "%u", &prior) != 1) return 6;
        if (fclose(file)) return 6;
    }
    file = fopen("marker", "w");
    if (!file) return 7;
    if (fprintf(file, "%u\n", prior + 1) < 0 || fclose(file)) return 8;
    printf("{\"registry\":%lu,\"file\":%u}\n", (unsigned long)value, prior);
    return 0;
}

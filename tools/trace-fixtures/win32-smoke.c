#include <windows.h>

volatile int halo_trace_sink;

static DWORD
smoke_sleep_ms(void)
{
    char value[32];
    char *end = value;
    DWORD parsed = 0;

    if (GetEnvironmentVariableA("HALO_TRACE_SMOKE_SLEEP_MS", value, sizeof(value)) == 0)
        return 3000;
    while (*end >= '0' && *end <= '9') {
        parsed = parsed * 10 + (DWORD)(*end - '0');
        ++end;
    }
    if (end == value || *end != '\0')
        return 3000;
    return parsed;
}

__attribute__((noinline)) static int
halo_trace_leaf(int value)
{
    int mixed = value * 2 + 1;
    if (value == 3)
        mixed += 7;
    return mixed;
}

int
main(void)
{
    int total = 0;
    int index;
    const char message[] = "halo trace win32 smoke\n";
    DWORD written = 0;

    for (index = 0; index < 6; ++index)
        total += halo_trace_leaf(index);

    halo_trace_sink = total;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), message, sizeof(message) - 1, &written, NULL);
    Sleep(smoke_sleep_ms());
    return total == 43 ? 0 : 1;
}

/* Bounded, test-only process observation. Child outcomes are data; observer
 * failures are not outcomes. No sandbox, proof summary or production launcher.
 * Invoke only inside the owning headless Wayland/Wine session. */
#ifndef SPX_FIXTURE_PE32_PROCESS_OBSERVER_H
#define SPX_FIXTURE_PE32_PROCESS_OBSERVER_H
#include <windows.h>
#include <stdint.h>
#include <string.h>

#ifndef SPX_PROCESS_OUTPUT_CAPACITY
#define SPX_PROCESS_OUTPUT_CAPACITY 16384U
#endif
enum spx_process_status {
  SPX_PROCESS_OK, SPX_PROCESS_SETUP, SPX_PROCESS_SPAWN, SPX_PROCESS_IO,
  SPX_PROCESS_OVERFLOW, SPX_PROCESS_TIMEOUT, SPX_PROCESS_WAIT
};
typedef struct {
  enum spx_process_status status;
  DWORD error, exit_code;
  unsigned char out[SPX_PROCESS_OUTPUT_CAPACITY], err[SPX_PROCESS_OUTPUT_CAPACITY];
  DWORD out_size, err_size;
} spx_fixture_process_result;

/* Optional bounded sink for observers with additional output channels. The
 * sink owns append limits and sets an observer failure on any incomplete write. */
#ifdef SPX_PROCESS_CONSUME_OUTPUT
static int SPX_PROCESS_CONSUME_OUTPUT(int stream, const unsigned char *bytes, DWORD size,
    spx_fixture_process_result *result);
#else
static inline int spx_fixture_consume_output(int stream, const unsigned char *bytes, DWORD size,
    spx_fixture_process_result *result) {
  unsigned char *destination = stream ? result->err : result->out;
  DWORD *used = stream ? &result->err_size : &result->out_size;
  if (size > SPX_PROCESS_OUTPUT_CAPACITY - *used) {
    result->status = SPX_PROCESS_OVERFLOW; return 0;
  }
  memcpy(destination + *used, bytes, size); *used += size; return 1;
}
#define SPX_PROCESS_CONSUME_OUTPUT spx_fixture_consume_output
#endif

static inline int spx_fixture_drain_pipe(HANDLE pipe, int stream,
    int *closed, spx_fixture_process_result *result) {
  DWORD available, received;
  unsigned char bytes[16384];
  if (*closed) return 1;
  if (!PeekNamedPipe(pipe, NULL, 0, NULL, &available, NULL)) {
    DWORD error = GetLastError();
    if (error == ERROR_BROKEN_PIPE) { *closed = 1; return 1; }
    result->status = SPX_PROCESS_IO; result->error = error; return 0;
  }
  if (!available) return 1;
  if (available > sizeof(bytes)) available = sizeof(bytes);
  if (!ReadFile(pipe, bytes, available, &received, NULL) || !received) {
    result->status = SPX_PROCESS_IO; result->error = GetLastError(); return 0;
  }
  return SPX_PROCESS_CONSUME_OUTPUT(stream, bytes, received, result);
}

/* image is explicit; command is a writable, correctly Windows-quoted full
 * command line including argv[0]. No shell interpretation. Inherits the caller's
 * environment/cwd and only these three standard handles. Per-stream byte order
 * is retained; ordering between stdout and stderr is deliberately not claimed.
 * The job owns descendants and is killed on close, including error/timeout paths.
 * A descendant retaining a pipe cannot silently turn into a successful result. */
static inline int spx_fixture_observe_process(const wchar_t *image, wchar_t *command,
    DWORD timeout_ms, spx_fixture_process_result *result) {
  SECURITY_ATTRIBUTES security = {sizeof(security), NULL, TRUE};
  STARTUPINFOEXW startup; PROCESS_INFORMATION process;
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
  HANDLE out_read = NULL, out_write = NULL, err_read = NULL, err_write = NULL;
  HANDLE input = INVALID_HANDLE_VALUE, job = NULL;
  SIZE_T attributes_size = 0;
  int attributes_ready = 0, started = 0, out_closed = 0, err_closed = 0;
  ULONGLONG beginning = GetTickCount64();
  memset(result, 0, sizeof(*result)); result->status = SPX_PROCESS_SETUP;
  memset(&startup, 0, sizeof(startup)); startup.StartupInfo.cb = sizeof(startup);
  memset(&process, 0, sizeof(process)); memset(&limits, 0, sizeof(limits));
  if (!image || !*image || !command || !*command || !timeout_ms) goto cleanup;
  if (!CreatePipe(&out_read, &out_write, &security, 0) ||
      !CreatePipe(&err_read, &err_write, &security, 0) ||
      !SetHandleInformation(out_read, HANDLE_FLAG_INHERIT, 0) ||
      !SetHandleInformation(err_read, HANDLE_FLAG_INHERIT, 0)) goto system_error;
  input = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
      &security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (input == INVALID_HANDLE_VALUE) goto system_error;
  job = CreateJobObjectW(NULL, NULL);
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if (!job || !SetInformationJobObject(job, JobObjectExtendedLimitInformation,
      &limits, sizeof(limits))) goto system_error;
  InitializeProcThreadAttributeList(NULL, 1, 0, &attributes_size);
  startup.lpAttributeList = HeapAlloc(GetProcessHeap(), 0, attributes_size);
  if (!startup.lpAttributeList) goto system_error;
  if (!InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &attributes_size)) goto system_error;
  attributes_ready = 1;
  HANDLE handles[] = {input, out_write, err_write};
  if (!UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
      handles, sizeof(handles), NULL, NULL)) goto system_error;
  startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
  startup.StartupInfo.hStdInput = input;
  startup.StartupInfo.hStdOutput = out_write; startup.StartupInfo.hStdError = err_write;
  result->status = SPX_PROCESS_SPAWN;
  if (!CreateProcessW(image, command, NULL, NULL, TRUE,
      CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
      NULL, NULL, &startup.StartupInfo, &process)) goto system_error;
  started = 1; result->status = SPX_PROCESS_SETUP;
  if (!AssignProcessToJobObject(job, process.hProcess) ||
      ResumeThread(process.hThread) == (DWORD)-1) goto system_error;
  CloseHandle(out_write); out_write = NULL; CloseHandle(err_write); err_write = NULL;
  CloseHandle(input); input = INVALID_HANDLE_VALUE;
  for (;;) {
    if (!spx_fixture_drain_pipe(out_read, 0, &out_closed, result) ||
        !spx_fixture_drain_pipe(err_read, 1, &err_closed, result)) goto cleanup;
    DWORD waited = WaitForSingleObject(process.hProcess, 0);
    if (waited == WAIT_FAILED) {result->status = SPX_PROCESS_WAIT; goto system_error;}
    if (waited == WAIT_OBJECT_0 && out_closed && err_closed) {
      if (!GetExitCodeProcess(process.hProcess, &result->exit_code)) {
        result->status = SPX_PROCESS_WAIT; goto system_error;
      }
      result->status = SPX_PROCESS_OK; goto cleanup;
    }
    if (GetTickCount64() - beginning >= timeout_ms) {
      result->status = SPX_PROCESS_TIMEOUT; goto cleanup;
    }
    Sleep(1);
  }
system_error:
  result->error = GetLastError();
cleanup:
  if (started && result->status != SPX_PROCESS_OK) TerminateProcess(process.hProcess, 125);
  if (job) CloseHandle(job);
  if (started) {
    if (WaitForSingleObject(process.hProcess, 2000) != WAIT_OBJECT_0 && result->status == SPX_PROCESS_OK)
      result->status = SPX_PROCESS_WAIT;
    CloseHandle(process.hThread); CloseHandle(process.hProcess);
  }
  if (attributes_ready) DeleteProcThreadAttributeList(startup.lpAttributeList);
  if (startup.lpAttributeList) HeapFree(GetProcessHeap(), 0, startup.lpAttributeList);
  if (input != INVALID_HANDLE_VALUE) CloseHandle(input);
  if (out_read) CloseHandle(out_read);
  if (out_write) CloseHandle(out_write);
  if (err_read) CloseHandle(err_read);
  if (err_write) CloseHandle(err_write);
  return result->status == SPX_PROCESS_OK;
}
#endif

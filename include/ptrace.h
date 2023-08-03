#ifndef PTRACE
#define PTRACE

typedef union ptrace_data ptrace_data;
bool ptrace_wait_syscall(pid_t pid);
char* ptrace_get_string(pid_t pid, void* addr, size_t size);
void ptrace_write_string(pid_t pid, void* addr, char* string);
void ptrace_clear_buffer(pid_t pid, void* addr, int size);
void ptrace_write_int(pid_t pid, void* addr, int value);

#endif

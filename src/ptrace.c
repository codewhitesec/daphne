#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include <sys/user.h>
#include <sys/wait.h>

#include <syscall.h>
#include <sys/reg.h>
#include <sys/ptrace.h>

/*
 * Some of the following data structures were copied from the
 * following gist:
 *
 *  https://gist.github.com/caiorss/339b00fc8ab1b3d1d46ed9167ccbaeeb
 */

/*
 * Union: ptrace_data
 * ----------------------------
 *   Helper to better process results from PTRACE_PEEKDATA calls
 *
 *   Fields:
 *     data:        long representation of the return value
 *     bytes:       byte representation of the return value
 *
 */
typedef union ptrace_data {
        long data;
        char bytes[sizeof(long)];
} ptrace_data;

/*
 * Function: ptrace_wait_syscall
 * ----------------------------
 *   Stops the tracee on the next entry to or next exit from
 *   a syscall. If a syscall was successfully intercepted, the
 *   function returns true.
 *
 *   Parameters:
 *     pid              pid of the tracee
 *
 *   Returns:
 *     true if syscall was intercepted, false if process exited
 */
bool ptrace_wait_syscall(pid_t pid)
{
    long result;
    int  status;

    for (;;)
    {
        result = ptrace(PTRACE_SYSCALL, pid, 0, 0);
        waitpid(pid, &status, 0);

        if (WIFEXITED(status))
        {
            return false;
        }

        if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80)
        {
            return true;
        }
    }

    return false;
}

/*
 * Function: ptrace_get_string
 * ----------------------------
 *   Obtain a string from process memory of the tracee via
 *   PTRACE_PEEKDATA. Process memory is read in junks of
 *   sizeof(long). Reading large amount of data using this
 *   technique is not recommended.
 *
 *   Parameters:
 *     pid              pid of the tracee
 *     addr             virtual address to read from
 *     size             size to read
 *
 *   Returns:
 *     pointer to a buffer that contains the data. Must
 *     be freed by the caller
 */
char* ptrace_get_string(pid_t pid, void* addr, size_t size)
{
    size_t long_size = sizeof(long);
    int    steps  = size / long_size;
    char*  result = malloc((size + 1) * sizeof(char));
    char*  paddr = result;

    int ctr = 0;
    ptrace_data pdata;

    while (ctr < steps)
    {
        pdata.data = ptrace(PTRACE_PEEKDATA, pid, addr + ctr * long_size, 0);
        memcpy(paddr, pdata.bytes, long_size);
        paddr = paddr + long_size;
        ctr++;
    }

    steps = size % long_size;

    if (steps != 0)
    {
        pdata.data = ptrace(PTRACE_PEEKDATA, pid, addr + ctr * long_size, 0);
        memcpy(paddr, pdata.bytes, steps);
    }

    result[size] = '\0';
    return result;
}

/*
 * Function: ptrace_set_string
 * ----------------------------
 *   Write a string to the process memory of the tracee.
 *   This is done by using PTRACE_POKEDATA and writes data
 *   as junks of sizeof(long).
 *
 *   Parameters:
 *     pid              pid of the tracee
 *     addr             virtual address to write to
 *     string           string to write (needs to be null terminated)
 *
 *   Returns:
 *     void
 */
void ptrace_set_string(pid_t pid, void* addr, char* string)
{
    int ctr = 0;
    int size = strlen(string) + 1;

    size_t long_size = sizeof(long);
    int    steps  = size / long_size;

    while (ctr < steps)
    {
        ptrace(PTRACE_POKEDATA, pid, addr + ctr * long_size, *(long*)(string + ctr * long_size));
        ctr++;
    }

    steps = size % long_size;

    if (steps != 0)
    {
        ptrace_data pdata;

        pdata.data = ptrace(PTRACE_PEEKDATA, pid, addr + ctr * long_size, 0);

        pdata.data = pdata.data >> steps * 8;
        pdata.data = pdata.data << steps * 8;

        long last_value = *(long*)(string + ctr * long_size);
        last_value += pdata.data;

        ptrace(PTRACE_POKEDATA, pid, addr + ctr * long_size, last_value);
    }
}

/*
 * Function: ptrace_clear_data
 * ----------------------------
 *   Write null bytes to the process memory of the tracee.
 *   This is done by using PTRACE_POKEDATA and writes data
 *   as junks of sizeof(long).
 *
 *   Parameters:
 *     pid              pid of the tracee
 *     addr             virtual address to write to
 *     size             number of null bytes to write
 *
 *   Returns:
 *     void
 */
void ptrace_clear_data(pid_t pid, void* addr, int size)
{
    int ctr = 0;

    size_t long_size = sizeof(long);
    int    steps  = size / long_size;

    while (ctr < steps)
    {
        ptrace(PTRACE_POKEDATA, pid, addr + ctr * long_size, 0);
        ctr++;
    }

    steps = size % long_size;

    if (steps != 0)
    {
        ptrace_data pdata;

        pdata.data = ptrace(PTRACE_PEEKDATA, pid, addr + ctr * long_size, 0);

        pdata.data = pdata.data >> steps * 8;
        pdata.data = pdata.data << steps * 8;

        ptrace(PTRACE_POKEDATA, pid, addr + ctr * long_size, pdata.data);
    }
}

/*
 * Function: ptrace_write_int
 * ----------------------------
 *   Write an int value to the specified address within the
 *   specified process.
 *
 *   Parameters:
 *     pid              pid of the tracee
 *     addr             virtual address to write to
 *     value            the int value to write
 *
 *   Returns:
 *     void
 */
void ptrace_write_int(pid_t pid, void* addr, int value)
{
    long original = ptrace(PTRACE_PEEKDATA, pid, addr, 0) & 0xffffffff00000000;
    ptrace(PTRACE_POKEDATA, pid, addr, original + value);
}

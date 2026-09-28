/*
 * Research launcher: deny common socket syscalls before execing an untrusted
 * child. This is NOT a sandbox. It leaves filesystem and many other effects
 * available and is architecture-specific by design.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__x86_64__)
#define EXPECTED_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define EXPECTED_ARCH AUDIT_ARCH_AARCH64
#else
#error "This research probe supports only x86_64 and aarch64 Linux"
#endif

#define DENY_SYSCALL(nr) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA))

static int install_filter(void) {
    struct sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, EXPECTED_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
#ifdef __X32_SYSCALL_BIT
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, __X32_SYSCALL_BIT, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
#endif
        DENY_SYSCALL(__NR_socket),
#ifdef __NR_socketpair
        DENY_SYSCALL(__NR_socketpair),
#endif
#ifdef __NR_connect
        DENY_SYSCALL(__NR_connect),
#endif
#ifdef __NR_accept
        DENY_SYSCALL(__NR_accept),
#endif
#ifdef __NR_accept4
        DENY_SYSCALL(__NR_accept4),
#endif
#ifdef __NR_bind
        DENY_SYSCALL(__NR_bind),
#endif
#ifdef __NR_listen
        DENY_SYSCALL(__NR_listen),
#endif
#ifdef __NR_sendto
        DENY_SYSCALL(__NR_sendto),
#endif
#ifdef __NR_sendmsg
        DENY_SYSCALL(__NR_sendmsg),
#endif
#ifdef __NR_sendmmsg
        DENY_SYSCALL(__NR_sendmmsg),
#endif
#ifdef __NR_io_uring_setup
        DENY_SYSCALL(__NR_io_uring_setup),
#endif
#ifdef __NR_io_uring_enter
        DENY_SYSCALL(__NR_io_uring_enter),
#endif
#ifdef __NR_io_uring_register
        DENY_SYSCALL(__NR_io_uring_register),
#endif
#ifdef __NR_pidfd_getfd
        DENY_SYSCALL(__NR_pidfd_getfd),
#endif
#ifdef __NR_process_vm_readv
        DENY_SYSCALL(__NR_process_vm_readv),
#endif
#ifdef __NR_process_vm_writev
        DENY_SYSCALL(__NR_process_vm_writev),
#endif
#ifdef __NR_ptrace
        DENY_SYSCALL(__NR_ptrace),
#endif
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {
        .len = (unsigned short)(sizeof(instructions) / sizeof(instructions[0])),
        .filter = instructions,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        return -1;
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
}

static int install_write_restriction(const char *writable_path) {
#if defined(__NR_landlock_create_ruleset) && defined(__NR_landlock_add_rule) && \
    defined(__NR_landlock_restrict_self)
    int abi = (int)syscall(__NR_landlock_create_ruleset, NULL, 0,
                           LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 1) return -1;

    __u64 handled = LANDLOCK_ACCESS_FS_WRITE_FILE |
                    LANDLOCK_ACCESS_FS_REMOVE_DIR |
                    LANDLOCK_ACCESS_FS_REMOVE_FILE |
                    LANDLOCK_ACCESS_FS_MAKE_CHAR |
                    LANDLOCK_ACCESS_FS_MAKE_DIR |
                    LANDLOCK_ACCESS_FS_MAKE_REG |
                    LANDLOCK_ACCESS_FS_MAKE_SOCK |
                    LANDLOCK_ACCESS_FS_MAKE_FIFO |
                    LANDLOCK_ACCESS_FS_MAKE_BLOCK |
                    LANDLOCK_ACCESS_FS_MAKE_SYM;
    if (abi >= 2) handled |= LANDLOCK_ACCESS_FS_REFER;
    if (abi >= 3) handled |= LANDLOCK_ACCESS_FS_TRUNCATE;

    struct landlock_ruleset_attr ruleset_attr = {
        .handled_access_fs = handled,
    };
    int ruleset_fd = (int)syscall(__NR_landlock_create_ruleset,
                                  &ruleset_attr, sizeof(ruleset_attr), 0);
    if (ruleset_fd < 0) return -1;

    int directory_fd = open(writable_path, O_PATH | O_CLOEXEC);
    if (directory_fd < 0) {
        close(ruleset_fd);
        return -1;
    }
    struct landlock_path_beneath_attr path_attr = {
        .allowed_access = handled,
        .parent_fd = directory_fd,
    };
    int add_result = (int)syscall(__NR_landlock_add_rule, ruleset_fd,
                                  LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0);
    int add_errno = errno;
    close(directory_fd);
    if (add_result != 0) {
        close(ruleset_fd);
        errno = add_errno;
        return -1;
    }

    int restrict_result = (int)syscall(__NR_landlock_restrict_self,
                                       ruleset_fd, 0);
    int restrict_errno = errno;
    close(ruleset_fd);
    if (restrict_result != 0) {
        errno = restrict_errno;
        return -1;
    }
    return 0;
#else
    (void)writable_path;
    errno = ENOSYS;
    return -1;
#endif
}

static void close_inherited_fds(void) {
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0)
        limit.rlim_cur = 65536;
    for (rlim_t fd = 3; fd < limit.rlim_cur; ++fd)
        close((int)fd);
}

int main(int argc, char **argv) {
    const char *writable_path = NULL;
    int command_index = 1;
    if (argc >= 3 && strcmp(argv[1], "--writable-dir") == 0) {
        writable_path = argv[2];
        command_index = 3;
    }
    if (argc <= command_index + 1 || strcmp(argv[command_index], "--") != 0) {
        fprintf(stderr, "usage: %s [--writable-dir PATH] -- executable [args...]\n", argv[0]);
        return 2;
    }
    close_inherited_fds();
    if (writable_path != NULL && install_write_restriction(writable_path) != 0) {
        fprintf(stderr, "install Landlock write restriction failed: errno=%d\n", errno);
        return 125;
    }
    if (install_filter() != 0) {
        perror("install seccomp network-deny filter");
        return 125;
    }
    execvp(argv[command_index + 1], &argv[command_index + 1]);
    perror("execvp");
    return 126;
}

# Seccomp probe: deny direct sockets while keeping the broker pipe

The network-namespace experiment could not run in this container (`bwrap --unshare-net` and `unshare --net` both returned `Operation not permitted`). As a narrower follow-up, this experiment installs a Linux seccomp-BPF filter in a child before `execve` of Python.

## Reproducible result

`experiments/process_boundary/seccomp_no_network.c` sets `no_new_privs`, closes inherited file descriptors above standard input/output/error, installs an architecture-checked syscall filter, and executes its target. The filter returns `EPERM` for socket creation and common network syscalls, and denies io_uring setup/entry/registration and selected cross-process memory/ptrace syscalls. The test launches a Python child that reads one line from stdin, writes a response to stdout, and attempts `socket.socket(AF_INET, SOCK_STREAM)`. The launcher also has an optional `--writable-dir PATH` mode which applies the narrow Landlock write policy described in [the follow-up probe](SECCOMP_LANDLOCK_PROBE.md).

Observed in this Linux x86_64 container:

```text
PIPE_OK:approved broker channel
SOCKET_DENIED:1
```

The existing host can therefore retain a pipe-based request channel while this particular child cannot create a new socket through the filtered syscalls.

## Descriptor boundary probe

Two local loopback tests make the descriptor assumptions explicit:

- A connected TCP socket passed to the launcher as fd 3 is closed before `exec`; the child gets `EBADF` on `write(3, ...)`, and the loopback peer receives no payload.
- If the host instead connects that socket directly to the child's stdout, the child can send a payload using ordinary `write(1, ...)`. The launcher preserves descriptors 0–2 to keep broker IPC working, and seccomp does not block writes to an already-open descriptor.

So the filter closes the tested inherited-fd path above stderr, but it cannot decide whether stdin/stdout are a trusted broker pipe or a socket wired to an external peer. Correct descriptor setup is part of the trusted launcher boundary. Even with pipes, the broker must parse and authorize every request as hostile input.

`python -m unittest discover -s tests -q` collects 68 tests here; 67 pass and the combined Landlock test is skipped because `landlock_create_ruleset` returns `ENOSYS`. The seccomp test is skipped on non-Linux systems or when `gcc` is missing.

## What this does and does not show

This is evidence that a host-side OS mechanism can block one direct effect class without changing Python syntax. It does not establish complete mediation. The child still has broad filesystem access and other system calls; file writes, shared resources, CPU/timing channels and other unmodeled effects remain possible. The pipe is only safe if the host treats its contents as untrusted requests and validates every operation. The launcher is architecture-specific and is not security-reviewed production code.

The Linux kernel documentation explicitly states that syscall filtering “isn't a sandbox”; it is a mechanism for reducing the kernel interface exposed to an application, to be combined with other controls. The filter also inherits through `fork`/`clone` and `execve` when those calls are allowed, which is why the probe denies the socket path before starting Python. See [Seccomp BPF](https://docs.kernel.org/userspace-api/seccomp_filter.html) and [No New Privileges](https://docs.kernel.org/userspace-api/no_new_privs.html).

## Research implication

This weakens the claim that a new language is required to block raw sockets: a restricted Python process plus an OS syscall filter can block the tested path. It does not solve the harder problem of identifying and mediating every effect, protecting host secrets, or containing filesystem and process interactions. Those remain deployment and trusted-host obligations. The right next comparison is to compose seccomp with filesystem and identity restrictions on a host that permits namespace creation, then test a stated finite effect inventory.

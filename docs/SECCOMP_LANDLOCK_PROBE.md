# Seccomp + Landlock filesystem probe

This is a follow-up to the [seccomp network probe](SECCOMP_NETWORK_FILTER_EXPERIMENT.md). It tests whether a Python child can keep a pipe-based broker channel, create a file inside one explicitly allowed workspace, and is denied a write outside that directory, while the seccomp filter also denies new network sockets.

The launcher option is:

```text
seccomp_no_network --writable-dir WORKSPACE -- python seccomp_landlock_probe.py WORKSPACE OUTSIDE_PATH
```

The Landlock ruleset handles filesystem write, create, remove, rename/link, and truncate rights supported by the reported Landlock ABI. It grants those rights only beneath the supplied workspace. Other filesystem rights are not handled by this probe. It composes this policy with the existing seccomp syscall filter and `no_new_privs`; it does not change the process UID/GID or isolate namespaces.

## Result in this environment

On the current Linux x86_64 execution container, `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` returns `-1` with `errno=ENOSYS` (38). The C launcher reports `install Landlock write restriction: Function not implemented`; its headers define the Landlock interface, but the running environment does not expose the syscall to this process. The combined test therefore skips its positive assertions here. The separate seccomp socket-denial test still passes.

This is an unavailable experiment, not a failed Landlock policy and not a successful filesystem confinement result. `python -m unittest discover -s tests -q` collects 66 tests; 65 pass and the combined positive test skips because of `ENOSYS`.

## Limits and next measurement

The probe does not establish a complete filesystem boundary: it only handles a selected set of write-related rights. Reads remain allowed, and already-open file descriptors are not retroactively restricted by Landlock. It does not reduce process identity, constrain CPU or timing, or block unmodeled kernel interfaces. Landlock rules add restrictions to existing access controls, but the host must still establish the intended trust base and manage inherited resources carefully.

The next useful run is on a Linux host exposing Landlock, ideally with a permitted network namespace and a dedicated unprivileged UID. Verify the positive pair of outcomes (write in workspace succeeds; write outside fails), then add explicit probes for inherited descriptors, symlink/hard-link behavior, process creation, and broker requests. Until those run, the combined confinement claim remains unverified. See the [Linux Landlock userspace API](https://docs.kernel.org/userspace-api/landlock.html), [Landlock LSM documentation](https://docs.kernel.org/security/landlock.html), and [No New Privileges](https://docs.kernel.org/userspace-api/no_new_privs.html).

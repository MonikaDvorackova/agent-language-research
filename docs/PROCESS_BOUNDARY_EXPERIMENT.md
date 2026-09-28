# Process-boundary experiment: a subprocess still bypasses the broker

This experiment tests the next unresolved claim: does putting an agent in a separate process make a host-side effect check complete? It uses a local TCP listener as a fake external tool. No external network destination is contacted.

## Setup

`comparison/process_boundary.py` implements a host broker that dispatches only when an exact `(recipient, value_name)` grant exists. `experiments/process_boundary/direct_socket_agent.py` is an adversarial child process. It opens a raw socket directly to a supplied TCP endpoint without calling the broker. The unit test starts a listener on `127.0.0.1`, launches the child with `subprocess`, and confirms the listener receives the private test payload.

Results:

| Probe | Observed result |
|---|---|
| Broker request with no exact grant | Rejected before transport |
| Broker request with exact grant | Dispatched through the supplied transport |
| Separate Python child with direct loopback socket | Reaches the fake external listener without broker mediation |
| `bwrap --unshare-net ...` in this execution container | Fails: `Creating new namespace failed: Operation not permitted` |
| `unshare --net true` in this execution container | Fails: `unshare failed: Operation not permitted` |
| Separate seccomp probe (see next document) | Blocks creation of new sockets but leaves filesystem and other effects available |

The final two results describe this particular container, not Linux generally. Linux network namespaces can isolate networking resources when namespace creation is permitted; see the [network namespaces manual](https://man7.org/linux/man-pages/man7/network_namespaces.7.html) and [Bubblewrap documentation](https://github.com/containers/bubblewrap/blob/main/README.md).

## Interpretation

The broker's policy is effective only for requests that use the broker. Merely launching arbitrary Python in a subprocess does not remove its direct network path. Therefore this experiment cannot claim complete mediation or a `PROVED` end-to-end security result. For an unrestricted Python agent, the relevant property remains `UNKNOWN` unless the deployment environment independently blocks all unmediated effect channels.

The experiment does **not** implement a complete sandbox, prevent all filesystem/process/IPC effects, restrict inherited credentials, or test a successful network namespace. The inability to create a namespace prevents the positive namespace-isolation test here. A separate [seccomp syscall-filter probe](SECCOMP_NETWORK_FILTER_EXPERIMENT.md) blocks one raw socket path, but leaves other effect channels open. An attempted [seccomp + Landlock write restriction](SECCOMP_LANDLOCK_PROBE.md) cannot be positively tested in this container because Landlock syscalls return `ENOSYS`. It would be misleading to infer that a language alone fixes this: an interpreter for a restricted effect language still needs a trusted host and an operating-system boundary that prevents code outside the interpreter from performing unmediated effects.

## Next experiment

Repeat on a disposable Linux host where an unprivileged network namespace can be created. Run the child with no network interface, a minimal read-only filesystem, no inherited secrets, and only a narrow broker IPC channel. Verify both that broker-authorized effects succeed and that raw sockets, alternate IPC, child processes, file writes, and inherited handles cannot reach a sink. Treat every untested channel as unresolved. A language-level claim becomes relevant only if the same enforcement cannot be expressed by a restricted Python worker plus this trusted host boundary.

Run the local deterministic probes from the repository root with `python -m unittest discover -s tests -q` (64 tests). The successful loopback bypass is expected evidence, not a passing security guarantee.

# Process crash and outbox recovery probe

29 September 2026. This probe closes the local crash/retry experiment for the SQLite approval outbox. It is a deterministic test of the failure interval after a downstream commit and before the host records delivery.

## Setup

The parent process creates a request-bound approval and commits one effect intent to the host SQLite database. A child process opens that database and a separate SQLite-backed fake receiver. The receiver commits the effect transaction, then writes a marker and blocks before returning to `dispatch_pending`. The parent waits for that marker, kills the child process, reopens both databases, and retries the pending intent with the same idempotency key.

This uses actual process termination (`Popen.kill`), not an exception standing in for lost acknowledgment. The two SQLite databases represent independently durable host and receiver state; they are not one atomic transaction.

## Result

The test passes. After the child is killed:

- the host intent is still pending with zero completed dispatch attempts;
- the receiver database contains one committed effect;
- the approval remains consumed.

After a fresh `ApprovalStore` and receiver object are opened and dispatch is retried:

- the host marks the intent delivered;
- the receiver still contains exactly one effect for the key;
- the approval is not reissued or consumed a second time.

This establishes recovery for this exact local failure point when the receiver durably deduplicates a key and binds it to the same action and payload. It does not establish exactly-once behavior across arbitrary providers.

## Limits

- The receiver is a local SQLite fake, not a payment, model, or tool API.
- The test covers process death after receiver commit and before host acknowledgment. It does not test power loss, storage-controller behavior, database corruption, network partitions, concurrent dispatch workers, or receiver retention/expiry of idempotency keys.
- SQLite durability depends on its configuration and the filesystem. This test uses defaults and does not claim hardware-level durability.
- No provider's actual idempotency contract was exercised.
- Payload and approval data remain plaintext in this prototype.

The probe shows that ordinary Python plus transactional storage can recover from the tested process crash under an explicit downstream idempotency assumption. It does not provide evidence that new language syntax is needed.

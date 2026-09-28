# Single-use approval transaction probe

This experiment tests a narrow host-side protocol using Python's standard-library SQLite support. An approval is bound to a token, subject, action, and exact payload. `consume_and_record` runs under `BEGIN IMMEDIATE`, marks the approval consumed, and inserts a uniquely keyed effect intent in the same transaction.

## Results

The deterministic tests establish that:

- a matching approval creates one intent, and replay is rejected;
- a mismatched request does not consume the approval;
- two concurrent consumers produce one accepted request and one denial;
- a database abort while inserting the intent rolls back both the approval consumption and intent insertion.

The outbox extension retries pending intents. Its fake downstream receiver stores an idempotency key and the effect row in its own SQLite transaction. If the receiver is temporarily unavailable, the intent remains pending. If the receiver commits the effect but its acknowledgment is lost, retrying the same key leaves exactly one effect row and marks the intent delivered. Reusing a key for a different action/payload is rejected.

When opening a database created by the earlier approval-only probe, the store adds the delivery-state columns and treats existing intents as pending.

## What this does not guarantee

The table is an intent ledger, not a real external action. The fake receiver exercises one outbox/idempotency protocol, but SQLite cannot atomically commit the host's transaction with a real payment, network call, or tool effect. A process may crash after the intent commits but before delivery, or after a downstream service acts but before the host records completion. The tested fake receiver gets one observable effect under retries because it atomically deduplicates by key. This guarantee depends on the real downstream API providing the same durable idempotency contract; this probe does not show that a payment or tool provider does.

The prototype also stores tokens and payloads in plaintext, assumes both database files are controlled by the trusted host, uses single-process polling without leases, and has no authenticated human identity or revocation mechanism. The simulated lost acknowledgment is a controlled exception, not a killed process. A process-kill/restart test and a real downstream idempotency contract remain open. It demonstrates that replay-safe intent recording and retry reconciliation are feasible with ordinary Python and transactional stores under these assumptions. It does not justify new syntax or establish production authorization.

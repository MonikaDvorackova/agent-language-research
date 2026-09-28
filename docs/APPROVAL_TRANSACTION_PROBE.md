# Single-use approval transaction probe

This experiment tests a narrow host-side protocol using Python's standard-library SQLite support. An approval is bound to a token, subject, action, and exact payload. `consume_and_record` runs under `BEGIN IMMEDIATE`, marks the approval consumed, and inserts a uniquely keyed effect intent in the same transaction.

## Results

The deterministic tests establish that:

- a matching approval creates one intent, and replay is rejected;
- a mismatched request does not consume the approval;
- two concurrent consumers produce one accepted request and one denial;
- a database abort while inserting the intent rolls back both the approval consumption and intent insertion.

## What this does not guarantee

The table is an intent ledger, not an external action. SQLite cannot atomically commit a payment, network call, or tool effect in the same transaction. A process may crash after the intent commits but before delivery, or after a downstream service acts but before the host records completion. End-to-end exactly-once execution therefore needs an idempotent downstream operation or a carefully designed outbox/reconciliation protocol; this probe does not implement one.

The prototype also stores tokens and payloads in plaintext, assumes the database file is controlled by the trusted host, uses a single local SQLite database, and has no authenticated human identity or revocation mechanism. It demonstrates that replay-safe intent recording is feasible with ordinary Python and a transactional store under these assumptions. It does not justify new syntax or establish production authorization.

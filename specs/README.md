# Formal Specs

This folder contains a minimal TLA+ spec for the hash-chained audit log plus policy ordering.

## Invariants

- NoGaps: record indices are contiguous.
- PrevHashMatches: each record links to the prior hash.
- NoDuplicateIndex: a fork with the same index is impossible.
- PolicyBeforeExecute: an execute event must be preceded by an allow policy decision for the same action.

## Model checking (optional)

1) Install the TLA+ tools (TLC).
2) Open `audit_chain.tla`.
3) Set finite constants:
   - Hash = {"h0", "h1", "h2"}
   - Actions = {"swap.execute", "wallet.send"}
4) Run TLC to check `Invariant`.

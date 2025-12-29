------------------------------- MODULE audit_chain -------------------------------
EXTENDS Naturals, Sequences

(\* Assurance model for an append-only audit chain with policy ordering. *)

CONSTANTS Hash, Actions

VARIABLES log

Event == [kind: {"policy", "execute"}, action: Actions, allow: BOOLEAN]

Record == [index: Nat, prev: Hash, hash: Hash, event: Event]

Init == log = << >>

Append(r) ==
  /\ r \in Record
  /\ IF Len(log) = 0 THEN r.prev = ""
     ELSE r.prev = log[Len(log)].hash
  /\ r.index = Len(log) + 1
  /\ log' = Append(log, r)

Next == \E r \in Record : Append(r)

NoGaps == \A i \in 1..Len(log): log[i].index = i

PrevHashMatches == \A i \in 1..Len(log):
  IF i = 1 THEN log[i].prev = "" ELSE log[i].prev = log[i-1].hash

NoDuplicateIndex == \A i, j \in 1..Len(log): log[i].index = log[j].index => i = j

PolicyBeforeExecute == \A i \in 1..Len(log):
  log[i].event.kind = "execute" =>
    \E j \in 1..i-1:
      /\ log[j].event.kind = "policy"
      /\ log[j].event.action = log[i].event.action
      /\ log[j].event.allow = TRUE

Invariant == NoGaps /\ PrevHashMatches /\ NoDuplicateIndex /\ PolicyBeforeExecute

Spec == Init /\ [][Next]_log

THEOREM Spec => []Invariant
=================================================================================

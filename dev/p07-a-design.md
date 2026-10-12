# P07-A design: pure bounded analysis

Recorded before implementation, 2026-10-12, on main `0665c09` (P06 PR #33 merged).

1. Public `paclo.window` owns tumbling counts/bytes; public `paclo.dns` owns
   decoded-packet normalization and UDP DNS correlation. Both expose `init`,
   `step`, `advance`, `finish`; DNS also exposes `packet-time-us` and
   `packet->event`. No new framework or internal namespace is needed.
2. Windows consume `{:time-us integer :group EDN-key :captured-bytes integer}`.
   DNS consumes a projected EDN map with time, kind, ID, IP version, UDP,
   source/destination IP strings and integer ports, plus optional question/rcode.
   Unknown input keys are excluded from retained DNS state. No packet/array/error
   object is retained. Window group keys are immutable EDN scalars/vectors; metadata is discarded.
3. Time is integer microseconds, allowing negative epoch times. Native seconds
   must be integer and usec in 0..999999. Missing/invalid times throw `ex-info`;
   no legacy/floating/wall-clock fallback. Arithmetic promotes with `+'`, `-'`,
   `*'`, including boundaries/deadlines/counters; arbitrary precision is supported.
4. Watermarks start at nil and advance explicitly, monotonically nondecreasing.
   Neither input maxima nor processing clocks advance them. DNS rejects events
   before its watermark with a diagnostic; windows compare the window deadline.
5. Windows align to epoch zero with floor division, including negative times.
   They are `[start,end)` and finalize when watermark >= end + lateness.
   Results are one `:window` event per nonempty window, with a groups map.
6. Window out-of-order input remains eligible until its deadline, including
   windows not previously seen. Finalized inputs produce `:late-event`, never
   reopen windows. DNS response-before-query produces `:unmatched-response` and
   is not buffered/replayed. These are deliberate ordered-stream semantics.
7. DNS exact key: version, UDP, ID, oriented client/server endpoints, normalized
   qname, qtype, qclass. Require all three question fields for pairing. Missing
   fields produce `:ambiguous-question`, with no pending entry or guessed match.
   Only standard opcode 0, at most one question and unfragmented UDP/53 are
   supported. Reuse parse's header and optional dns-ext's question annotation.
8. Identical pending queries within timeout mean retransmission, using the
   minimum observed query event time and counting retries. Different questions
   are distinct keys. Identical overlapping transactions cannot be distinguished
   on the wire; this is a retry assumption, not a claim to distinguish them.
   Completed/expired keys enter bounded quarantine until query deadline plus
   `:reuse-delay-us` (defaults to timeout). Queries there report `:id-reuse`;
   responses report `:duplicate-or-expired-response`. After watermark releases
   quarantine, reuse is allowed. Correctness assumes the caller's watermark and
   finite timeout/reuse horizon; arbitrarily delayed identical traffic cannot
   be disambiguated. No permanent history is retained.
9. Required positive bounds: window `:max-windows`, `:max-groups` (total pairs);
   DNS `:max-pending`, `:max-retired`. Width/timeout/reuse delay are positive;
   lateness nonnegative (default zero). Capacity violations throw, never evict.
   Cardinality bounds do not bound caller-supplied string/key size. Advance
   releases expired pending and quarantine. Retries never extend retention.
10. Each transition returns `{:state map :events vector}` with only new results.
    DNS match includes query/response, integer RTT, retransmissions and key;
    negative RTT is classified and consumes the query, never made positive.
    Responses at/after query deadline yield timeout plus unmatched classification.
    Stale retries beyond a retained deadline report `:expiry-required`.
    Finish emits remaining windows as `:complete? false`, DNS queries as
    `:unfinished`, clears retained state and marks it finished. Finish is
    idempotent; step/advance after finish throw. Errors use EDN ex-data with
    stable `:reason`; diagnostics are ordinary per-call events.
11. CLI migration, displays, CSV/JSONL, quantiles, Top-N and execution adapters
    remain P07-B. Exact all-history statistics need their own bounded design.
12. P06 flow keys/aggregate-rf stay unchanged. DNS transaction keys are distinct
    from flow identity. Analysis composes through ordinary reduction/transduction;
    all capture ownership, cancellation, fan-out and output remain caller policy.

Expiry scans retained entries; ordered output costs O(N log N) for N retained
entries. Window count accounting is O(1). Output
ordering is ascending window start, and DNS deadline then canonical key for
advance/finish. No output history is stored. A future measured index optimization
is separate from P06 performance issue #34 and from this API contract.

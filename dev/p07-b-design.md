# P07-B CLI migration contract

Recorded before implementation on main `2e15af7` (PR #35 merged).
No public library API change; P06 performance issue #34 remains separate.

## RTT contract

| Concern | Before | After |
| --- | --- | --- |
| Invocation | Positional BPF/topN/mode/metric/format/alert; `_` skips | Preserve; validate numeric values and flags |
| pairs | Smallest RTT first; nil RTT; all rows retained | Smallest exact RTT first; deterministic endpoint/ID/question ties; retain only topN candidates |
| stats/qstats | All pair maps retained; percentiles nearest rank | Same output keys and nearest rank; retain integer RTT samples up to max-samples; qstats groups up to max-qnames |
| RTT/average | Uses absent sec/usec; average truncates sum | Native ts-sec/ts-usec; integer microseconds; convert at display; exact mean before conversion |
| Matching | Header reparsed; ID and unordered endpoints; guessed question | dns packet projection and strict oriented question key; ambiguous/negative/late/unmatched results counted, never pairs |
| Retry/reuse | Ignore repeated query; immediately reuse completed ID | Earliest query time, retry count; bounded retired quarantine |
| Filters | Filter completed display rows | Same prefix semantics; exclude from statistics; still correlate all inputs |
| RCODE/alert | Frequencies and NXDOMAIN+SERVFAIL threshold | Preserve real matched-pair denominator; execution metadata excluded |
| Format | EDN vector/map or JSONL rows | Preserve data shape; execution/analysis diagnostics on stderr |
| Bounds | Unbounded pending, rows, groups | max-pending/max-retired 100000 each; max-samples 1000000; max-qnames 100000; topN <= max-samples |

## QPS contract

| Concern | Before | After |
| --- | --- | --- |
| Meaning | Full-decode DNS packets with a non-nil selected group | Preserve packet counting; never use DNS transaction correlation |
| Groups | rcode/rrtype/qname/suffix/client/server; client/server meant source/destination | Same groups; client/server use decoded QR to orient query and response IP roles |
| Bytes | Captured caplen | Preserve; window captured-bytes |
| Time | Floating milliseconds, fallback, truncation division | Exact native microseconds; floor-aligned epoch windows; millisecond display |
| Formats | EDN/JSONL/CSV, t/key/count/bytes | Preserve; ties ordered by printed key after time and descending count |
| Punycode | Decode only when whole name starts xn-- | Decode any xn-- label; preserve normalized name on failure and optional warning |
| Empty buckets | Could lose simultaneous groups and loop unbounded | Keep all groups; bounded preflight count; fill only wholly empty windows with :_all |
| Empty per key | Could silently abandon fill | Complete Cartesian fill or fail before output; precedence over empty-buckets |
| max-buckets | Truncate output after unbounded retention | Bound finalized output rows AND total final filled rows; fail instead of truncating |
| Window bounds | Unbounded map | max-windows 10000, max-groups 200000 (active window/group pairs); independent of max-buckets 200000 |
| Warning | warn-buckets-threshold | Preserve positive warning threshold and metadata |

## Time, memory and execution

Both CLIs keep the maximum native event time of delivered packets. Before each
input, advance the core to max-time minus `--reorder-us` (default 0), then step.
This releases expired state before admitting new keys across idle gaps. Max-time
never falls; clocks never control analysis. Window allowed-lateness is fixed at
zero: reorder-us is applied exactly once. DNS events older than watermark are
late; QPS accepts an event until its window end is at/before watermark. Response
before query is never buffered. EOF calls finish; QPS includes the open tail
window, counts it in stderr metadata, and does not claim watermark closure.

All diagnostics are counters, not retained events. RTT pairs hold at most topN
small projected matches; stats/qstats hold at most max-samples integer RTTs in
total. qstats alone holds at most max-qnames groups. No raw packet is retained.
QPS holds active windows plus at most max-buckets finalized rows; empty fill is
preflighted with promoting arithmetic before allocation. These are entry bounds;
caller-supplied string size and output serialization also have costs. At finite
limits exact statistics fail rather than silently lose samples. Streaming output
and approximate quantiles are future independent choices.

Sync uses reduce-packets. Async uses one owning reduce-packets producer, a fixed
bounded channel, stop-aware blocking puts, and offer! for dropping. A dropping
buffer cannot report losses, so it is not used. A shared reducer handles both.
Producer errors propagate; consumer exceptions close stop/channel and join the
producer. Timeout 0 is deterministic and delivers zero packets. Cancellation
stops source reads, not merely consumption; wall time only controls delivery.
Metadata reports delivered/read/dropped/cancelled, complete? and analysis counts.
Dropped/cancelled results are explicitly incomplete; ordinary EOF is complete
as a delivered-packet report (not proof of complete network transactions).

No stdout is emitted until successful finish, ranking and fill. Capacity/source/
analysis errors exit 5 with no result; invalid flags/numbers exit 4, missing
input 2, missing invocation 1, invalid enums 3. Cancel/drop output is allowed
with exit 0 and incomplete metadata on stderr. Async metadata never becomes a
DNS pair. Buffer capacity is positive, timeout/reorder nonnegative; all retention
bounds and bucket width positive. Analysis is identical for the same delivered
packet order and options. No lazy capture producer is abandoned.

Offline input now runs to EOF rather than inheriting the capture API's default
100-packet/10-second limits (old QPS inherited both; old RTT inherited 10 seconds).
The adapter supplies an effectively unbounded, overflow-safe duration; only
explicit async timeout/cancellation or a report limit ends delivery early.

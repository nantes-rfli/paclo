# Performance measurement

Paclo separates performance measurement from optimization. The runner
establishes reproducible offline and staged live-capture baselines before a
fast path becomes part of the public API.

## Profiles

| Profile | Offline input | Runs | Live duration | Purpose |
| --- | ---: | ---: | ---: | --- |
| `quick` | 50,000 packets | 1 warm-up + 1 measured | 2 seconds | CI smoke |
| `reference` | 1,000,000 packets | 1 warm-up + 5 measured | 15 seconds | Baseline |
| `stress` | 10,000,000 packets | 1 warm-up + 5 measured | 60 seconds | Sustained load |

Reference input cases cover 64-byte UDP, 512-byte TCP, and alternating
64/512-byte traffic. PCAPs are generated deterministically under the selected
output directory and are not committed to the repository.

## Offline

```bash
clojure -M:perf \
  --mode offline \
  --profile quick \
  --output target/perf-quick
```

The runner starts a separate JVM for every case and scenario:

- `raw-seq`: the public lazy-sequence API without decode
- `sync-loop`: the internal synchronous libpcap loop
- `raw-reduce`: the public synchronous reducer without decode
- `full-decode`: the compatible packet map and full decoder
- `full-reduce`: the compatible decoder through the synchronous reducer
- `flow-aggregate`: full decode followed by flow-key aggregation
- `flow-reduce`: flow-key aggregation through the synchronous reducer
- `flow-project`: numeric flat flow projection without full decode
- `write-pipeline`: raw read followed by PCAP output

`sync-loop` is a measurement probe, not a public fast API.

## Loopback live capture

```bash
clojure -M:perf \
  --mode live \
  --profile quick \
  --device lo0 \
  --port 39053 \
  --output target/perf-live-quick
```

The runner sends dedicated UDP traffic to the selected port and compares:

- the legacy, explicitly buffered, and buffered-immediate queue paths
- synchronous raw and full-decode reduction without an intermediate queue
- bounded dropping raw and full-decode queues

Reference runs sweep target rates from 10k to 1M packets per second. The load
generator adds one sender thread per target 100k pps, capped at eight, and
reports the realized aggregate send count. Use `--scenarios`, `--rates`,
`--duration-ms`, `--warmups`, and `--runs` to create a smaller comparison.

The portable `pcap_stats` counters are recorded as `received`, `dropped`, and
`interface-dropped`. These counters have platform-specific semantics. In
particular, macOS loopback may count both directions even when Paclo emits one
packet per sent datagram. Compare the same device and operating system across
revisions rather than treating sender and `received` counts as universally
identical.

Live results report each observable stage separately:

```text
sender -> libpcap/kernel -> paclo queue -> consumer
```

The counters include sent, capture received, capture delivered, kernel and
interface drops, queue enqueued and dropped, consumer processed and gap,
queue blocking events/time, and maximum queue depth. Internal loopback runs
also calculate sender-to-consumer loss. A run is sustainable when every
applicable loss/drop rate is at most 0.1%.

The buffered paths use the inactive-handle `pcap_create` API and remain
explicit opt-ins:

```clojure
(core/packets {:device "en0"
               :buffer-size (* 16 1024 1024)
               :immediate? true})
```

Omitting both keys preserves the existing `pcap_open_live` behavior.

The lazy sequence retains its bounded blocking queue by default. A dropping
queue is an explicit overload policy:

```clojure
(core/packets {:device "en0"
               :queue-cap 4096
               :queue-mode :dropping
               :on-queue-stats println})
```

`on-queue-stats` receives final queue counters. Dropped packets are not
returned to the consumer.

## Real-NIC measurement

For a real NIC, run the receiver and the exact-count generator on separate
hosts. Choose an offered rate, duration, and packet count before the run. For
example, 250,000 pps for 60 seconds is exactly 15,000,000 packets.

Start the receiver first:

```bash
clojure -M:perf \
  --mode live \
  --profile reference \
  --source external \
  --device en0 \
  --filter "udp dst port 39053" \
  --scenarios live-sync-raw \
  --rates 250000 \
  --expected-packets 15000000 \
  --duration-ms 75000 \
  --warmups 0 \
  --runs 1 \
  --output target/perf-live-en0
```

Then start the sender on the other host, replacing the destination address:

```bash
clojure -M:perf-generator \
  --host 192.0.2.10 \
  --port 39053 \
  --packets 15000000 \
  --rate 250000 \
  --frame-size 64 \
  --senders 4 \
  --start-delay-ms 10000
```

The generator exits unsuccessfully if it cannot complete every send and emits
an EDN report containing the exact sent count, elapsed time, and realized pps.
Keep that report with the receiver's `results.edn` and `results.json`.
`--start-delay-ms` gives the receiver JVM time to open and activate libpcap;
increase it on slower hosts and include the delay in the receiver duration.

`--expected-packets` marks the receiver result as `:external-expected` and
enables sender-to-consumer loss in the same 0.1% sustainability decision used
for loopback runs. To avoid accidentally reusing one generator run across
multiple captures, this mode requires exactly one scenario, zero warm-ups, and
one measured run. Without `--expected-packets`, external capture remains
capture-pipeline-only and cannot pass the end-to-end sustainability gate.

The receiver duration should include enough lead time to start the remote
generator. Use the offered rate and the generator's realized rate to describe
load; receiver `sustained-processed-pps` uses the full capture duration and
therefore includes that lead time.

Live capture may require OS permission to open the capture device. It is not a
required CI performance threshold.

## Results

The output directory contains `results.edn` and `results.json`, both with
schema version `2`. Each measured run records:

- packets/sec, MB/sec, and ns/packet
- processed packet and byte counts
- decode errors
- thread allocation when supported by the JDK
- GC count and time
- peak memory-pool usage
- process CPU time
- Git, OS, architecture, JDK, Clojure, libpcap, and JVM metadata

Live output additionally includes `stage-counts`, `queue-stats`,
`sustainability`, and the highest passing result observed for each scenario.
Schema version 2 is not intended to be read as schema version 1 without an
explicit compatibility layer.

The reference profile reports median, minimum, and maximum values. The current
CI job checks that the quick profile completes and reports consistent counts;
it does not enforce a throughput threshold until stable baselines have been
collected.

## Initial reference baseline

The first one-million-packet, 64-byte UDP reference run on the Intel reference
Mac produced these medians:

| Scenario | Packets/sec | Allocated bytes/packet |
| --- | ---: | ---: |
| raw lazy seq | 1,219,657 | 1,074 |
| raw synchronous reduce | 1,580,619 | 768 |
| compatible full lazy decode | 119,227 | 8,251 |
| compatible full synchronous decode, optimized | 298,899 | 4,568 |
| compatible flow aggregation | 108,310 | 9,085 |
| numeric flow projection | 1,024,250 | 1,248 |

These numbers justified the synchronous reducer and flow projection. Profiling
the compatible decoder identified address formatting and object creation—not
`ByteBuffer` operations—as the dominant cost. Replacing address `format`
calls more than doubled compatible full-decode throughput, so a wholesale
offset-parser replacement was not adopted.

An opt-in payload-suppression experiment was also rejected because it reduced
throughput and increased allocation in the reference case.

The first 60-second `lo0` stress probe used the 16 MiB immediate path with
eight sender threads. The generator realized 369,234 pps, Paclo processed
22,154,013 datagrams at 366,899 pps, and both libpcap drop counters remained
zero. Peak heap was approximately 67 MB. This establishes a zero-drop floor,
not the maximum sustainable rate, because the local generator did not realize
its one-million-pps target.

## Phase-5 live baseline

A three-second comparison on the same Intel reference Mac exercised
synchronous, bounded-blocking, and bounded-dropping raw paths at requested
rates of 100k, 250k, and 500k pps. At the highest request, the local generator
realized and Paclo processed approximately 257k, 265k, and 266k pps
respectively. All observable loss/drop counters remained zero. These are
generator-limited zero-drop floors, not maximum capture rates.

A controlled overload probe used a 64-entry queue and a 100 microsecond
consumer delay at a realized 50k pps:

| Queue policy | Processed | Queue drops | Blocking events | Blocking time |
| --- | ---: | ---: | ---: | ---: |
| blocking | 14,248 | 0 | 14,152 | 1.793 s |
| dropping | 7,815 | 42,185 | 0 | 0 s |

The blocking case processed only 28.5% of sent traffic despite zero reported
kernel and queue drops. This is why loopback sustainability also checks
sender-to-consumer loss instead of relying only on libpcap drop counters.

## `flow-topn` fast-path adoption

A local acceptance probe ran the synchronous `flow-topn` CLI against the same
one-million-packet, 64-byte UDP reference file. The timed region excluded JVM
startup and namespace loading:

| Implementation | Elapsed | Packets/sec |
| --- | ---: | ---: |
| Compatible full decode plus materialized packet vector | 8.514 s | 117,459 |
| Synchronous numeric projection plus direct aggregation | 1.463 s | 683,673 |

This is a 5.82x throughput improvement and removes the intermediate vector
containing every packet. It is an acceptance probe rather than a five-run
reference median. The normalized EDN/JSONL contract and synchronous/async smoke
tests remain unchanged.

## Optimization gates

The first candidate is a synchronous reducing path. It should only be promoted
to `paclo.core/reduce-packets` when the reference profile shows at least one of:

- 15% higher raw or flow throughput
- 20% lower allocation

Later candidates are live capture tuning and, only if measured targets remain
unmet, an opt-in borrowed-buffer API, batching, parallel decode, or mmap.
See the project roadmap for their order and compatibility constraints.

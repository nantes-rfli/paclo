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
- managed single-consumer raw and full-decode capture paths
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

Wait until the receiver prints `[perf] capture ready`. This signal is emitted
only after the worker JVM has opened libpcap and installed the BPF filter.
Then start the sender on the other host, replacing the destination address:

```bash
clojure -M:perf-generator \
  --host 192.0.2.10 \
  --port 39053 \
  --packets 15000000 \
  --rate 250000 \
  --frame-size 64 \
  --senders 4
```

The generator exits unsuccessfully if it cannot complete every send and emits
an EDN report containing the exact sent count, elapsed time, and realized pps.
Keep that report with the receiver's `results.edn` and `results.json`.
`--start-delay-ms` remains available for scripted coordination, but it is a
sender-side delay rather than a readiness check. Prefer the receiver's
explicit ready signal for manual runs. Include any intentional lead time in
the receiver duration.

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

## v1.3 bounded fan-out live gate

The v1.3 public fan-out gate was completed on 2026-08-01 using Linux x86_64,
JDK 21.0.12, libpcap 1.10.4 with TPACKET_V3, and a separate generator JVM.
The tracked `paclo.dev.perf-generator` realized approximately 400k pps with
eight senders. The receiver used a 128 MiB buffered libpcap ring, a bounded
blocking managed-capture queue, and the core.async-backed fan-out runtime.

| Scenario | Generator | Fan-out interval | Complete consumers | Intended branch drop | Kernel/queue drop | Allocation |
| --- | ---: | ---: | --- | ---: | ---: | ---: |
| two blocking branches | 399,986 pps | 391,773 pkt/s | left/right 2,000,000 | 0 | 0 / 0 | 1,136.0 B/packet |
| slow dropping branch | 399,974 pps | 383,730 pkt/s | fast 1,000,000 | slow 999,936; delivered 64 | 0 / 0 | 926.1 B/packet |

Both results exceed the historical approximately 369k pps live floor. The
dual run delivered every packet to both branches and stayed below the 1,250
bytes/packet allocation ceiling. The slow run delivered every packet to the
fast branch while isolating all overload to the configured 64-entry dropping
branch. Branch blocking/drop counters and final statistics satisfied their
invariants.

Linux loopback `pcap_stats.received` counted both directions and therefore
reported 4,000,000 and 2,000,000 respectively; Paclo's exact delivered counts
were 2,000,000 and 1,000,000. Both libpcap drop counters were zero. A 16 MiB
immediate-mode probe overloaded TPACKET_V3, so the passing buffered-ring
configuration is an explicit platform tuning choice rather than a new
default.

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

### Separate-host real-NIC probe

A separate Ubuntu 24.04 generator (`192.168.4.70`, wired 1 GbE) sent 64-byte
UDP frames to the Intel reference Mac (`192.168.4.28`, `en1` Wi-Fi). Each
reference probe sent for 15 seconds after capture readiness:

| Offered rate | Sent | Processed | End-to-end loss | Result |
| ---: | ---: | ---: | ---: | --- |
| 1,000 pps | 15,000 | 15,000 | 0% | pass |
| 5,000 pps | 75,000 | 75,000 | 0% | pass |
| 7,500 pps | 112,500 | 112,500 | 0% | pass |
| 8,750 pps | 131,250 | 129,433 | 1.384% | fail |
| 10,000 pps | 150,000 | 149,308 | 0.461% | fail |

The 60-second stress confirmation at 7,500 pps processed 449,991 of 450,000
datagrams (0.002% end-to-end loss), with zero reported kernel, interface,
queue, or consumer-gap drops. Peak heap was approximately 66.5 MB; seven GC
collections consumed 5 ms.

This establishes 7,500 pps as a sustained end-to-end floor for this particular
wired-to-Wi-Fi path, not Paclo's capture ceiling. The non-monotonic loss at
8,750 and 10,000 pps, combined with zero internal drop counters, indicates
path variability. A wired-to-wired run is still required for a real-NIC
capture limit comparable to the loopback baseline.

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

## v1.2 managed-capture smoke

The initial v1.2 implementation smoke ran the managed raw and compatible
full-decode paths on macOS loopback at an offered 1,000 pps for one second:

| Scenario | Sent | Processed | Queue drops | Decode errors | Result |
| --- | ---: | ---: | ---: | ---: | --- |
| managed raw | 1,000 | 1,000 | 0 | 0 | pass |
| managed full decode | 1,000 | 1,000 | 0 | 0 | pass |

Both scenarios met the 0.1% sustainability rule with no observed end-to-end,
kernel, interface, queue, or consumer-gap loss. Environment: macOS 15.4.1,
Intel x86_64, JDK 21, and libpcap 1.10.1. This is an implementation smoke, not
the reference or sustained acceptance result.

### Managed separate-host real-NIC acceptance probe

The v1.2 acceptance probe reused the Ubuntu 24.04 wired sender
(`192.168.4.70`, `enp8s0`) and Intel reference Mac receiver
(`192.168.4.28`, `en1` Wi-Fi). The receiver used a 16 MiB immediate capture
buffer, a 1,024-entry blocking managed queue, and the
`udp dst port 39053` BPF filter. Every sender run began only after the receiver
reported capture readiness.

The one-second raw and full-decode smoke runs each processed all 1,000 sent
datagrams with no observed internal drop or decode error. Longer 15-second
probes produced:

| Scenario | Offered rate | Sent | Processed | End-to-end loss | Result |
| --- | ---: | ---: | ---: | ---: | --- |
| managed raw | 1,000 pps | 15,000 | 15,000 | 0% | pass |
| managed raw | 5,000 pps | 75,000 | 74,758 | 0.323% | fail |
| managed raw | 7,500 pps | 112,500 | 112,341 | 0.141% | fail |
| managed full decode, first probe | 1,000 pps | 15,000 | 11,296 | 24.693% | fail |
| managed full decode, repeat | 1,000 pps | 15,000 | 15,000 | 0% | pass |
| managed full decode | 5,000 pps | 75,000 | 74,791 | 0.279% | fail |
| managed full decode | 7,500 pps | 112,500 | 98,194 | 12.716% | fail |

All of these probes reported zero kernel, interface, queue, and consumer-gap
drops. Full decode also reported zero decode errors. The pass/fail reversals
at the same 1,000 pps load and the absence of an internal drop location make
this a path-variability observation rather than evidence of a managed queue or
decoder limit.

The common passing rate, 1,000 pps, was then exercised for 60 seconds:

| Scenario | Sent | Processed | End-to-end loss | Maximum queue depth | Peak heap |
| --- | ---: | ---: | ---: | ---: | ---: |
| managed raw | 60,000 | 56,707 | 5.488% | 32 | 66.8 MB |
| managed full decode | 60,000 | 56,159 | 6.402% | 197 | 62.7 MB |

These sustained probes also reported zero kernel, interface, queue, and
consumer-gap drops. Raw performed one GC in 1 ms; full decode performed five
GCs in 4 ms. The bounded queue depths, stable heap peaks, and absence of
consumer gaps validate the managed lifecycle under a 60-second real-NIC run,
but the wired-to-Wi-Fi path did not re-establish a 0.1% end-to-end sustained
floor. The earlier v1.1 result remains a historical observation, not a
repeatable current guarantee. A wired-to-wired probe is still required before
attributing a real-NIC throughput ceiling to Paclo.

## Optimization gates

The first candidate is a synchronous reducing path. It should only be promoted
to `paclo.core/reduce-packets` when the reference profile shows at least one of:

- 15% higher raw or flow throughput
- 20% lower allocation

Later candidates are live capture tuning and, only if measured targets remain
unmet, an opt-in borrowed-buffer API, batching, parallel decode, or mmap.
See the project roadmap for their order and compatibility constraints.

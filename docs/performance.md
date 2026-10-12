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

## Optimization decisions and historical results

Keep the current measurement profiles, result schema, and 0.1% live-drop
classification described above when evaluating proposed changes. Do not treat
an earlier generator-limited throughput result as a hardware-independent floor.

The historical initial reference baselines, v1.2/v1.3 measurements, adopted or
rejected optimizations, and the former 15% throughput / 20% allocation
promotion criteria are preserved in
[historical performance evidence](archive/performance-results.md).
New optimization investigations remain conditional on measured shortfalls;
the accepted [development plan](../dev/codex-plan.md) defines their scope.

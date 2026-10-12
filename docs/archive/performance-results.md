# Historical performance and roadmap measurement evidence

This is archived evidence from the pre-reorganization documentation, not a current
throughput guarantee or a new API contract. Preserve recorded conditions, numbers,
conclusions, and limitations. For live measurement instructions and current result
schema, see [performance measurement](../performance.md).

## Results and historical optimization decisions from performance.md

### Initial reference baseline

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

### v1.3 bounded fan-out live gate

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

### Phase-5 live baseline

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

### `flow-topn` fast-path adoption

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

### v1.2 managed-capture smoke

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

### Optimization gates

The first candidate is a synchronous reducing path. It should only be promoted
to `paclo.core/reduce-packets` when the reference profile shows at least one of:

- 15% higher raw or flow throughput
- 20% lower allocation

Later candidates are live capture tuning and, only if measured targets remain
unmet, an opt-in borrowed-buffer API, batching, parallel decode, or mmap.
See the project roadmap for their order and compatibility constraints.

## Historical performance track from ROADMAP.md

### Performance track (historical)

The performance track preserves the v1 data-first API and advances only when
the preceding measurement gate provides evidence for the next change.

1. [x] Establish reproducible offline and loopback-live baselines.
2. [x] Compare the queue/lazy-seq path with a synchronous reducing path.
3. [x] Add opt-in flow projection and reduce allocation.
4. [x] Profile the parser and adopt only evidence-backed compatible changes.
5. [x] Tune live capture buffers and report drop location.
6. [ ] Consider borrowed buffers, batching, parallel decode, or mmap only if the
   earlier phases do not meet the documented throughput targets.

North-star targets on the reference Mac are 1.5M pps raw read, 1M pps flow
projection, 200k pps compatible full decode, and a continuously improving
60-second live rate below 0.1% drop. Phase-1 measurements may revise these
targets when the reason and baseline are documented.

The first reference run reached all three offline targets: 1.58M pps raw,
1.02M pps flow projection, and 299k pps compatible full decode. Parser
profiling did not justify replacing the compatible parser with a second
offset-based implementation. Phase 5 therefore remains focused on sustained
live drop behavior; phase 6 stays conditional rather than becoming default
scope.

The first 60-second buffered-immediate `lo0` probe sustained approximately
369k processed pps with zero reported kernel or interface drops and about
67 MB peak heap. The local UDP generator, rather than capture, limited this
probe. Phase 5 added direct, bounded-blocking, and bounded-dropping comparison
profiles; sender, libpcap, queue, and consumer stage counters; a 0.1%
sustainability classifier; and an external-generator profile for real-NIC or
separate-host tests. Controlled overload now distinguishes queue drops from
blocking backpressure.

The first separate-host probe used an Ubuntu 24.04 wired sender and the Intel
Mac's Wi-Fi interface. It sustained 7,500 pps for 60 seconds at 0.002%
end-to-end loss with no observable Paclo drop. This validates the external
measurement path but remains network-path limited; a wired-to-wired run is
still needed to find the real-NIC capture maximum.

The v1.2 managed-capture probe reused that path. Raw and full-decode managed
captures each processed an exact 15,000-packet run at 1,000 pps, but repeated
15- and 60-second results varied substantially despite zero observable
kernel, interface, queue, consumer-gap, or decode drops. The 60-second runs
kept bounded queue depths and approximately 63-67 MB peak heap. This validates
the managed lifecycle and records the required real-NIC observation, while
confirming that the current wired-to-Wi-Fi path cannot provide a repeatable
end-to-end throughput floor.

The v1.3 bounded fan-out track adds `paclo.stream/fan-out`, `branch`, and
`stats` as a small backend-neutral public surface. Combined offline runs
validated two blocking consumers, slow-branch drop isolation, bounded heap,
and the 1,250 bytes/packet allocation ceiling. A Linux separate-JVM live gate
then realized approximately 400k pps: dual fan-out delivered 2,000,000 packets
to each branch at approximately 392k pkt/s, and slow-dropping delivered all
1,000,000 packets to the fast branch at approximately 384k pkt/s. Both runs
reported zero kernel and managed-queue drops. This clears the historical 369k
live floor; packaging and release checks remain the final v1.3 work.

Phase 6 remains a post-v1.1 conditional investigation. Borrowed buffers,
batching, parallel decode, and mmap should be attempted only when a measured
workload remains below target after the compatible Phase 1-5 paths.

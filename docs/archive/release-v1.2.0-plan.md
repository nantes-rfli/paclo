# Paclo v1.2.0 implementation plan

v1.2.0 turns the v1.1 measurement and synchronous-processing foundation into
controlled, observable capture execution.

## Release objective

Deliver both:

1. synchronous result-plus-statistics processing; and
2. explicitly owned, externally stoppable, single-consumer managed capture.

Existing v1.x packet maps and the behavior of `packets` and `reduce-packets`
remain compatible.

## Public additions

- `paclo.core/reduce-packets-report`
- `paclo.core/start-capture`
- `paclo.core/capture-packets`
- `paclo.core/stop-capture!`
- `paclo.core/capture-stats`

Managed capture handles are opaque and implement `java.io.Closeable`. The
implementation type and its fields are not public API.

## Execution models

| Workload | Preferred API | Queue/background thread |
| --- | --- | --- |
| Interactive, bounded inspection | `packets` | Yes |
| Offline or synchronous live aggregation | `reduce-packets` | No |
| Synchronous result plus execution evidence | `reduce-packets-report` | No |
| Long-running or externally stopped capture | managed capture | Yes |

## Statistics contract

Schema version 1 contains:

- execution state and source
- start and elapsed time
- captured, enqueued, delivered, processed, and decode-error counts when
  applicable
- queue capacity, depth, high-water mark, drops, and blocking
- final portable libpcap counters for live capture when available
- one terminal stop reason
- a data-only error class and message

Unavailable observations use `nil`; they are not reported as zero.

## Lifecycle contract

- source open and BPF installation complete before `start-capture` returns
- one managed capture has one packet stream and one consumer
- `stop-capture!` is asynchronous and idempotent
- `close` is idempotent and waits for producer termination
- shutdown works while a blocking queue is full
- close abandons remaining queued packets
- final statistics remain readable after close
- startup failure does not return a handle or leak libpcap resources

## Explicit non-goals

- multiple consumers, fan-out, or pub/sub
- per-consumer queues and drop accounting
- dynamically replacing BPF
- pause and resume
- borrowed buffers or zero-copy packet maps
- batching, parallel decode, or mmap
- PCAPNG

## Implementation slices

1. Add schema-versioned synchronous capture reporting.
2. Add a managed internal capture boundary around the libpcap handle.
3. Make blocking queue shutdown cancellation-aware.
4. Add the public opaque handle and single-consumer facade.
5. Add lifecycle, concurrency, error, and offline fixture tests.
6. Add managed scenarios to the performance runner.
7. Run loopback and separate-host real-NIC acceptance probes.
8. Complete compatibility, static-analysis, packaging, and release gates.

## Acceptance gates

- all existing v1.x tests remain unchanged and pass
- new lifecycle and statistics contract tests pass
- clj-kondo and Eastwood report no new warnings
- Linux/macOS, JDK 17/21, and x86_64/arm64 required jobs pass
- synchronous performance regression is no greater than 5% on the reference
  profile
- close completes within five seconds, including a full blocking queue
- sustained managed capture does not show unbounded thread or heap growth
- loopback and real-NIC observations are recorded in `docs/performance.md`
- generated jar, POM, Clojars dry-run, and cljdoc API surface are verified

## Release-state checklist

- [x] Internal statistics and stop-reason model
- [x] `reduce-packets-report`
- [x] Managed Closeable capture
- [x] Single-consumer packet stream
- [x] Explicit stop and cancellation-aware queue shutdown
- [x] Contract and lifecycle tests
- [x] Initial user and API documentation
- [x] Managed performance-runner scenarios
- [x] Loopback acceptance result
- [x] Separate-host real-NIC acceptance result
- [x] Full static/compatibility/package gates
- [x] Release metadata, tag, Clojars, GitHub Release, and cljdoc verification

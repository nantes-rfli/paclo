<!-- markdownlint-disable MD013 -->
# Paclo v1.4.0 release notes — draft

**Unpublished candidate; publication date not confirmed.** v1.3.0 remains the
latest stable version on Clojars/GitHub. The [Publish dry-run](../dev/release-1.4.0-dry-run.md)
passed, including inspection and JDK 17/21 consumers of its actual JAR.
These notes are ready for final release review; publication requires separate
authorization, confirmed release-day metadata and validation of that final commit.

Paclo v1.4.0 prepares packet preservation and bounded analysis for ordinary
Clojure data workflows. It includes P01–P08 and merged correctness, lifecycle,
performance and distribution fixes. P09/P10 and new optional integrations,
borrowed buffers, batching, parallel decode and mmap are outside this release.

## Highlights

- Preserve native packet time and captured/original lengths through Classic PCAP
  rewrites. Select a single native DLT/snaplen explicitly for non-Ethernet output.
- Compose ordered per-pipeline DNS/TLS annotation functions with `:extensions`;
  omission preserves the existing dynamic global registration behavior.
- Inspect additive structured diagnostics while retaining existing error strings
  and schema-version-1 statistics. Native read failures are distinct from EOF.
- Reuse canonical IPv4/IPv6 flow keys, exact bounded aggregates and deterministic
  Top-N via `paclo.flow`; use pure `paclo.window` and `paclo.dns` state transitions
  with explicit integer-microsecond event time, watermarks and finite limits.
- Decode Ethernet/VLAN, SLL/SLL2, Raw IP and NULL/LOOP IPv4/IPv6 on Linux/macOS.
  Unsupported explicit framing stays available raw and fails decoding explicitly.
- Read/write ordered PCAPNG sections, interfaces, owned option octets, exact ticks
  and absent timestamps through `paclo.pcapng`. Preserve known semantics by
  default; loss/authoring modes are explicit. Output uses exclusive atomic
  publication on supported Linux/macOS filesystems, with no unsafe fallback.
- Fix the managed native stop/close race and reduce measured Flow allocation,
  DNS premature expiry scans and full-decode address formatting costs.
- Ship Java 17-compatible binding classes (major 61), built with `--release 17`
  even on JDK21; CI runs one candidate JAR in independent JDK17/21 consumers.

## Migration from v1.3.0

The approved policies retain Writer correctness/strict validation (D1) and exact
bounded DNS reports/explicit failures (D2). Existing function names/arities and
CLI formats remain, but input acceptance and analytical results can change.

Classic Writer prefers complete `:ts-sec/:ts-usec` over legacy `:sec/:usec`.
Partial capture time, invalid selected values, inconsistent lengths, mismatched
DLTs and caplen above snaplen fail explicitly. To intentionally retime a capture,
remove both capture-time keys and supply a complete valid legacy pair; repair
stale producer metadata rather than discarding it to bypass validation.

DNS RTT uses actual native microseconds and strict question-aware correlation;
old nil RTTs, fractional means and pair counts may differ. DNS QPS counts packets
per bucket, with client/server grouped by QR role. Full offline input replaces
accidental early caps. Exact reports/empty fill either fit configured bounds or
fail before stdout. Exit codes 1–4 retain their meanings; DNS source/analysis/
capacity failures use 5. Dropped/cancelled reports can exit 0 with `:complete?
false` diagnostics. Wrappers must check nonzero exits and report completeness.
Flow's separate `--max-flows` defaults to 100000 and exhaustion propagates a
nonzero JVM exit; it does not use DNS code 5.

See the complete [migration guide](migration-from-1.3.md),
[public API contract](cljdoc-api-contract.md) and [PCAPNG guide](pcapng.md).
The [CHANGELOG](../CHANGELOG.md#140-unreleased) has the detailed change inventory.

## Availability and limits

Keep the [README installation coordinates](../README.md#install) at v1.3.0 until
publication. A local `PACLO_VERSION=1.4.0` JAR is a candidate, not evidence of a
Clojars release. The development default is `1.4.0-SNAPSHOT`. The published
v1.3.0 JAR contains Java21 bytecode; Java17 users of that version need a source
build. v1.4.0's packaged classes restore the advertised Java17 baseline.

[Issue #37](https://github.com/nantes-rfli/paclo/issues/37) stays open and
non-blocking: repeated actual retired-key expiry and long production-trace
validation remain. [Issue #44](https://github.com/nantes-rfli/paclo/issues/44)
has merged offline Ethernet Full improvements (9.1–76.1% transformation,
9.6–32.3% native reads in the recorded investigation); JIT/thermal/retention
limits and negative controls remain. This does not establish Flow speedup,
recovery of every historical result or sustained live/NIC throughput.

Legacy lazy `packets` abandonment can retain its producer/native source; own
prefixes with managed `with-open` or synchronous `reduced`. Published packet
arrays remain mutable and shared, so consumers must treat them as read-only.
PCAPNG preserves supported known semantics, not byte-identical files or all
private/opaque meanings. Native core PCAPNG reads still lose rich metadata and
normalize time to microseconds. Other OSes and live performance targets have
not been validated by offline CI.

Review the [final acceptance checklist](../dev/release-1.4.0-checklist.md) for
quality evidence, the final PR's commit-specific checks and remaining publication
steps. The completed dry-run validates its recorded source only; any changed
release commit requires fresh validation before separately authorized publication.

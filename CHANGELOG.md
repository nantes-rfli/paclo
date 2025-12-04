# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - v0.3.0 (work in progress)

### Added
- TLS ClientHello SNI/ALPN decode extension (`paclo.proto.tls-ext`) and example `examples.tls-sni-scan` (EDN/JSONL).
- REPL pipeline benchmark sample numbers for small / mid (50k) / large (100k) synthetic PCAPs.
- Synthetic PCAP generator `make-synth-pcap` to reproduce benchmark inputs (count/caplen configurable).
- Property test to assert decode_ext isolates exceptions yet keeps later hooks running.

### Docs
- `docs/extensions.md` stability notes for decode_ext hooks (map-only apply, exception isolation, API compatibility).
- Roadmap updated to reflect Phase B progress and outstanding tasks; mid-size REPL turnaround numbers added; proto-dns split draft added (`dev/proto-dns-split-plan.md`).
- README REPL turnaround section now lists small/mid/large pipeline-bench samples.
- Examples docs/help text aligned (`dns-summary` alias hint, `tls-sni-scan` formats/tips).

### Fixed
- `examples.dns-summary` help text now references the required `:dns-ext` alias.
- `examples.tls-sni-scan` accepts skipped optional args via `_` and emits consistent format errors.
- BPF arg `_` now correctly treated as "unset" in `examples.pcap-filter` / `flow-topn` / `pcap-stats` to match Usage tips.


## Versioning / SemVer

This project follows [SemVer](https://semver.org/).
Until **v1.0.0**, **minor versions may include breaking changes**.
Patch versions never do.

## [0.2.0] - 2025-08-24

### Added

- `:xform` transducer support in `core/packets`.
- BPF DSL extensions: `:proto` (`:ip/:ipv4/:ip6/:ipv6`), `:src-net/:dst-net`, `:port-range` variants.
- `core/list-devices` facade and minimal test.
- Golden PCAP round-trip tests and error propagation tests.

### Changed

- Documentation: added roadmap and README Quick Start.

### Fixed

- Stabilized AI_HANDOFF generation and primary links (ROADMAP added).

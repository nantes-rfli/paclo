# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `:xform` transducer support in `core/packets`.
- BPF DSL extensions: `:proto` (`:ip/:ipv4/:ip6/:ipv6`), `:src-net/:dst-net`, `:port-range` variants.
- `core/list-devices` facade and minimal test.
- Golden PCAP round-trip tests and error propagation tests.

### Changed
- Documentation: added roadmap and README Quick Start.

### Fixed
- Stabilized AI_HANDOFF generation and primary links (ROADMAP added).

## [0.2.0] - YYYY-MM-DD
> **Planned**: Tagging this release will happen once CI on `main` is green and README/cljdoc badges are in place.

### Notes
- First OSS-ready baseline (core I/O + BPF + minimal L2/L3/L4 decode).
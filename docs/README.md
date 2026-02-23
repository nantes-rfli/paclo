# Paclo Docs Index

Paclo is a Clojure library that makes PCAP I/O and BPF DSL easy to use from idiomatic Clojure code.
This page is the entry point to the documentation set.

## Quick links

- User Guide: ./usage.md
- Getting Started / Quick Start: ../README.md#quick-start
- Examples (CLI): ../README.md#run-the-examples
- Decode extensions: ./extensions.md
- Public API contract (cljdoc sync): ./cljdoc-api-contract.md
- Migration guide (0.4 -> 1.0): ./migration-0.4-to-1.0.md
- v1.0.0-rc release checklist: ./release-v1-rc-checklist.md
- Roadmap: ./ROADMAP.md
- v1.0 API freeze draft (Phase H): ./v1-phase-h-freeze-draft.md
- API on cljdoc: <https://cljdoc.org/d/org.clojars.nanto/paclo/CURRENT>

## Common tasks

- Read PCAP with filter: ../README.md#quick-start (sample at dev/resources/fixtures/sample.pcap)
- Write BPF DSL expressions: ../README.md#bpf-dsl-examples-extended
- Write / transform PCAP (EDN/JSONL meta): ../README.md#pcap-filter-edn--jsonl-meta
- Add decode hooks: ./extensions.md

## Development & verification

- Run tests: `clj -M:test`
- Compile Java sources (if present): `clojure -T:build javac`
- Supported environments: see README “Compatibility Matrix (v1.0 target)”

## Release info

- Current stable tag: v1.0.0
- deps.edn usage: README “Install” section

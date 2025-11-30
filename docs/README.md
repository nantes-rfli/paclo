# Paclo Docs Index

Paclo is a Clojure library that makes PCAP I/O and BPF DSL easy to use from idiomatic Clojure code. This page is the entry point to the documentation set.

## Quick links
- Getting Started / Quick Start: ../README.md#quick-start
- Examples (CLI): ../README.md#run-the-examples
- Decode extensions: ./EXTENSIONS.md
- Roadmap: ./ROADMAP.md
- API on cljdoc: https://cljdoc.org/d/io.github.nantes-rfli/paclo/CURRENT

## Common tasks
- Read PCAP with filter: ../README.md#quick-start
- Write BPF DSL expressions: ../README.md#bpf-dsl-examples-extended
- Write / transform PCAP (EDN/JSONL meta): ../README.md#pcap-filter-edn--jsonl-meta
- Add decode hooks: ./EXTENSIONS.md

## Development & verification
- Run tests: `clj -M:test`
- Compile Java sources (if present): `clojure -T:build javac`
- Supported environments: see README “Supported Environments”

## Release info
- Current stable tag: v0.2.0
- deps.edn usage: README “Install” section

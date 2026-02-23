# Paclo Docs

This is the public documentation index for Paclo.

## Start here

- Getting started and install: `../README.md`
- Usage guide: `./usage.md`
- Decode extensions: `./extensions.md`
- Public API contract (v1.0): `./cljdoc-api-contract.md`
- Migration guide (0.4 -> 1.0): `./migration-0.4-to-1.0.md`
- Roadmap and release status: `./ROADMAP.md`
- API on cljdoc: <https://cljdoc.org/d/org.clojars.nanto/paclo/CURRENT>

## User-facing command references

- CLI examples are documented in `../README.md` and `./usage.md`.
- DNS extension examples use `-M:dev:dns-ext` in repository-local runs.

## Development and verification

- Run tests: `clojure -M:test`
- Run static checks: `clojure -M:eastwood` and `clj-kondo --lint src test dev`
- Run performance gate: `clojure -M:perf-gate`

## Notes

Some historical planning memos may remain in Japanese and are not part of the public API/usage docs.
The files listed in "Start here" are the canonical, maintained user-facing set.

# Paclo Roadmap

This roadmap tracks release objectives, acceptance criteria, and current progress.
It is intentionally concise and focuses on user-visible outcomes.

## North star

"Make PCAP processing feel native in Clojure data workflows (EDN/maps/seq/transducers)."

## Release timeline

- `v0.2` (completed): OSS baseline (`:xform`, BPF DSL expansion, minimal L2/L3/L4 decode, CI hardening)
- `v0.3` (completed, 2025-12-05): data-first UX improvements and decode extension stabilization
- `v0.4` (completed, 2025-12-10): DNS observability tooling (`dns-topn`, `dns-qps`, async behavior)
- `v1.0.0` (released, 2026-02-23): API freeze and stable release artifacts

## v1.0 completion status

The v1.0 release roadmap is complete.

Completed release artifacts:

- [x] `v1.0.0-rc` and `v1.0.0-rc.1` tags/releases
- [x] `v1.0.0` tag and GitHub Release (latest)
- [x] Clojars publish pipeline and release publication (`org.clojars.nanto/paclo`)
- [x] cljdoc publication confirmed (`CURRENT` page and successful build)
- [x] Migration guide (`docs/migration-0.4-to-1.0.md`)
- [x] Public API contract (`docs/cljdoc-api-contract.md`)
- [x] Compatibility matrix and performance gate integrated into CI

## Quality gates in place

- Required CI matrix for Linux/macOS and JDK 17/21
- arm64 CI job enabled as required gate
- Performance gate (`clojure -M:perf-gate`) with warn/fail thresholds
- Dependency audit (`nvd-clojure`) in GitHub Actions
- Lint/static checks (`eastwood`, `clj-kondo`) and regression tests

## Current focus (post-1.0)

`v1.0` is shipped; next work is maintenance and incremental improvements.

- [ ] Stabilize arm64 success rate against long observation windows
- [ ] Keep publish/release automation healthy (token rotation, workflow maintenance)
- [ ] Continue documentation polish for user-facing pages and examples
- [ ] Add optional integrations only as opt-in aliases (no heavy default dependencies)

## Notes

- Public user docs are maintained in English (`README.md`, `docs/README.md`, `docs/usage.md`, `docs/extensions.md`).
- Internal planning notes may exist separately and are not part of the public API contract.

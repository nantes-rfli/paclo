# v1.0.0-rc Release Checklist (Historical)

This checklist records the minimum gates that were used before `v1.0.0-rc` and final `v1.0.0`.
It is preserved as release history and as a template for future release candidates.

## 1. Preconditions

- [x] `docs/cljdoc-api-contract.md` matched implementation
- [x] `docs/migration-0.4-to-1.0.md` reflected latest migration steps
- [x] `CHANGELOG.md` included `1.0.0-rc` notes
- [x] `docs/ROADMAP.md` reflected actual P3 progress

## 2. Local gates

Executed from repository root:

```bash
clojure -M:test
clojure -M:eastwood
clj-kondo --lint src test dev
clojure -M:perf-gate
clojure -M:dev:dns-ext -m examples.dns-topn test/resources/dns-sample.pcap
clojure -Sdeps '{:deps {cljdoc/cljdoc {:mvn/version "0.0.1315-c9e9a7e"}}}' -M -e "(require 'cljdoc.doc-tree) (println :cljdoc-loaded)"
```

Recorded result on 2026-02-23:

- `clojure -M:test`: 185 tests / 504 assertions / 0 failures / 0 errors
- `clojure -M:eastwood`: warnings only, exit 0
- `clj-kondo --lint src test dev`: 0 errors / 0 warnings
- `perf-gate`: pass (`679.6ms`, warn `1000ms`, fail `1200ms`)

## 3. CI gates

- [x] `CI` workflow green on main (`run: 22296353769`, 2026-02-23)
- [x] `Dependency Audit` green, no critical CVEs (`run: 21812860426`, 2026-02-09)
- [x] arm64 monitoring and promotion report workflow added

Historical arm64 promotion snapshot (2026-02-23):

- `sample_count=7`, `window_covered=false`
- `success_rate=0.714`, `rerun_rate=0.0`, `max_duration_ratio=2.104`
- `eligible_for_required_gate=false`

## 4. Tagging and release publication

```bash
git tag v1.0.0-rc.1
git push origin v1.0.0-rc.1
```

Completed items:

- [x] Draft prerelease created for `v1.0.0-rc` and `v1.0.0-rc.1`
- [x] `v1.0.0-rc.1` published as prerelease
- [x] Migration link included in release notes
- [x] cljdoc publication verified

## 5. v1.0 finalization

- [x] Added `## [1.0.0] - 2026-02-23` to `CHANGELOG.md`
- [x] Created and pushed `v1.0.0` tag
- [x] Published `v1.0.0` GitHub Release (latest)
- [x] Added Clojars publish workflow (`.github/workflows/publish.yml`)
- [x] Verified cljdoc at <https://cljdoc.org/d/org.clojars.nanto/paclo/CURRENT>

Reference URLs:

- `v1.0.0` release: <https://github.com/nantes-rfli/paclo/releases/tag/v1.0.0>
- cljdoc build: <https://cljdoc.org/builds/99557>

# v1.1.0 Release Checklist

This checklist makes the `v1.1.0` release repeatable and keeps irreversible
Clojars publication separate from validation.

## 1. Release metadata

- [x] `CHANGELOG.md` contains `1.1.0` notes dated 2026-07-27
- [x] README dependency examples use `1.1.0`
- [x] the public API contract includes `reduce-packets` and live queue options
- [x] the development fallback version is `1.1.0-SNAPSHOT`
- [x] the roadmap records completed performance phases and defers Phase 6

## 2. Local gates

Run from the repository root:

```bash
clojure -T:build javac
clojure -M:test
clojure -M:eastwood
clj-kondo --lint src test dev
clojure-lsp clean-ns --dry
clojure-lsp format --dry
dev/script/mdlint.sh
clojure -M:perf-gate
clojure -M:perf --mode offline --profile quick --output target/perf-v1.1.0
PACLO_VERSION=1.1.0 clojure -T:build jar
```

Confirm the release artifact and embedded Maven metadata:

```bash
test -f target/paclo-1.1.0.jar
test -f target/classes/META-INF/maven/org.clojars.nanto/paclo/pom.xml
grep -F "<version>1.1.0</version>" \
  target/classes/META-INF/maven/org.clojars.nanto/paclo/pom.xml
```

## 3. CI and publish dry-run

- [x] the release-preparation PR is green on every required CI job
- [x] the latest dependency-audit run has no release-blocking finding
- [x] the release-preparation PR is merged to `main`
- [x] the publish workflow dry-run succeeds on the exact `main` commit
- [x] the dry-run artifact contains the `1.1.0` jar and POM

After merging the preparation PR, run:

```bash
gh workflow run publish.yml \
  --ref main \
  -f version=1.1.0 \
  -f dry_run=true
```

The dry-run performs source/version validation, tests, the performance gate,
and the release build. It does not contact Clojars.

Recorded preparation results on 2026-07-27:

- unit tests: 220 tests / 596 assertions / 0 failures / 0 errors
- Eastwood: completed with existing performance/reflection warnings, exit 0
- clj-kondo: 0 errors / 0 warnings
- fresh-build performance gate: 381.4 ms (`warn=1000`, `fail=1200`)
- offline quick profile: all 27 case/scenario combinations completed
- release jar/POM: `1.1.0` coordinates and public namespaces verified
- Dependency Audit: successful
  ([run 30229618446](https://github.com/nantes-rfli/paclo/actions/runs/30229618446))
- release-preparation CI: successful
  ([run 30231852757](https://github.com/nantes-rfli/paclo/actions/runs/30231852757))
- publish dry-run on `e04e2dc`: successful
  ([run 30235197389](https://github.com/nantes-rfli/paclo/actions/runs/30235197389))

## 4. Tag and publish

Resolve and review the exact commit before creating the tag:

```bash
git switch main
git pull --ff-only origin main
git status --short
git log -1 --oneline
git tag -a v1.1.0 -m "v1.1.0"
git push origin v1.1.0
```

Pushing the tag starts the publish workflow with publication enabled. Confirm
that it publishes `org.clojars.nanto/paclo:1.1.0`.

If the tag-triggered workflow fails before Clojars accepts the artifact, use
the manual recovery path:

```bash
gh workflow run publish.yml \
  --ref main \
  -f version=1.1.0 \
  -f dry_run=false
```

Do not use the recovery path after Clojars reports a successful publication;
released coordinates are immutable and cannot be overwritten.

## 5. Release verification

- [x] Clojars shows `org.clojars.nanto/paclo:1.1.0`
- [x] cljdoc builds and serves version `1.1.0`
- [x] a clean consumer project resolves the Clojars coordinate
- [x] the Git tag resolves to the release-preparation commit
- [x] the GitHub Release is published as the latest stable release
- [x] the roadmap release status is updated from candidate to released

Recorded release results on 2026-07-27:

- tagged commit: `e04e2dc882af572fdfcc642271d5864505b246bb`
- Clojars publication: successful
  ([run 30235324243](https://github.com/nantes-rfli/paclo/actions/runs/30235324243))
- clean consumer resolution: downloaded the `1.1.0` POM and JAR and loaded
  `paclo.core/reduce-packets`
- cljdoc: build `108392` completed with eight namespaces and the
  [v1.1.0 documentation](https://cljdoc.org/d/org.clojars.nanto/paclo/1.1.0)
  serves successfully
- GitHub Release:
  [v1.1.0](https://github.com/nantes-rfli/paclo/releases/tag/v1.1.0)

After Clojars succeeds, create the GitHub Release:

```bash
gh release create v1.1.0 \
  --verify-tag \
  --title v1.1.0 \
  --generate-notes
```

If a release defect is discovered, do not move the tag or replace the Clojars
artifact. Correct it with a new patch release.

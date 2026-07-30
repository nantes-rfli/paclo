# v1.2.0 Release Checklist

This checklist makes the `v1.2.0` release repeatable and keeps irreversible
Clojars publication separate from validation.

## 1. Release metadata

- [x] `CHANGELOG.md` contains `1.2.0` notes dated 2026-07-30
- [x] README dependency examples use `1.2.0`
- [x] the public API contract includes synchronous reports and managed capture
- [x] the development fallback version is `1.2.0-SNAPSHOT`
- [x] the roadmap records the completed v1.2 implementation and acceptance work

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
clojure -M:perf --mode offline --profile quick --output target/perf-v1.2.0
PACLO_VERSION=1.2.0 clojure -T:build jar
```

Confirm the release artifact and embedded Maven metadata:

```bash
test -f target/paclo-1.2.0.jar
test -f target/classes/META-INF/maven/org.clojars.nanto/paclo/pom.xml
grep -F "<version>1.2.0</version>" \
  target/classes/META-INF/maven/org.clojars.nanto/paclo/pom.xml
```

Recorded local results on 2026-07-30:

- unit tests: 236 tests / 675 assertions / 0 failures / 0 errors
- Eastwood: 56 existing performance/reflection warnings / 0 exceptions
- clj-kondo: 0 errors / 0 warnings
- clojure-lsp clean and format dry-runs: no changes
- Markdown lint: successful
- performance gate: 549.9 ms (`warn=1000`, `fail=1200`)
- offline quick profile: all 27 case/scenario combinations completed
- release jar/POM: `1.2.0` coordinates and public namespaces verified
- post-implementation `main` CI: successful
  ([run 30530828070](https://github.com/nantes-rfli/paclo/actions/runs/30530828070))

## 3. CI and publish dry-run

- [ ] the release-preparation PR is green on every required CI job
- [x] the latest dependency-audit run has no release-blocking finding
- [ ] the release-preparation PR is merged to `main`
- [ ] the publish workflow dry-run succeeds on the exact `main` commit
- [ ] the dry-run artifact contains the `1.2.0` jar and POM

After merging the preparation PR, run:

```bash
gh workflow run publish.yml \
  --ref main \
  -f version=1.2.0 \
  -f dry_run=true
```

The dry-run performs source/version validation, tests, the performance gate,
and the release build. It does not contact Clojars.

Recorded validation results on 2026-07-30:

- Dependency Audit on post-implementation `main`: successful
  ([run 30531457081](https://github.com/nantes-rfli/paclo/actions/runs/30531457081))

## 4. Tag and publish

Resolve and review the exact commit before creating the tag:

```bash
git switch main
git pull --ff-only origin main
git status --short
git log -1 --oneline
git tag -a v1.2.0 -m "v1.2.0"
git push origin v1.2.0
```

Pushing the tag starts the publish workflow with publication enabled. Confirm
that it publishes `org.clojars.nanto/paclo:1.2.0`.

If the tag-triggered workflow fails before Clojars accepts the artifact, use
the manual recovery path:

```bash
gh workflow run publish.yml \
  --ref main \
  -f version=1.2.0 \
  -f dry_run=false
```

Do not use the recovery path after Clojars reports a successful publication;
released coordinates are immutable and cannot be overwritten.

## 5. Release verification

- [ ] Clojars shows `org.clojars.nanto/paclo:1.2.0`
- [ ] cljdoc builds and serves version `1.2.0`
- [ ] a clean consumer project resolves the Clojars coordinate
- [ ] the Git tag resolves to the release-preparation commit
- [ ] the GitHub Release is published as the latest stable release
- [ ] the roadmap release status is updated from candidate to released

After Clojars succeeds, create the GitHub Release:

```bash
gh release create v1.2.0 \
  --verify-tag \
  --title v1.2.0 \
  --generate-notes
```

If a release defect is discovered, do not move the tag or replace the Clojars
artifact. Correct it with a new patch release.

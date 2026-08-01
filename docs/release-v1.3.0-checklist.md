# v1.3.0 Release Checklist

This checklist makes the `v1.3.0` release repeatable and keeps irreversible
Clojars publication separate from validation.

## 1. Release metadata

- [x] `CHANGELOG.md` contains `1.3.0` notes dated 2026-08-01
- [x] README dependency examples use `1.3.0`
- [x] the public API contract includes `packet-xf` and bounded stream fan-out
- [x] the development fallback version is `1.3.0-SNAPSHOT`
- [x] the roadmap records the completed v1.3 implementation and acceptance work

## 2. Local gates

Run from the repository root:

```bash
clojure -T:build javac
clojure -T:build javac-test
clojure -T:build junit
clojure -T:build spotbugs
clojure -T:build checkstyle
clojure -T:build jacoco
JACOCO_MIN_LINE=0.25 clojure -T:build jacoco-gate
clojure -M:test
clojure -M:eastwood
clj-kondo --lint src test dev
clojure-lsp clean-ns --dry
clojure-lsp format --dry
dev/script/mdlint.sh
clojure -M:perf-gate
clojure -M:perf --mode offline --profile quick --output target/perf-v1.3.0
PACLO_VERSION=1.3.0 clojure -T:build jar
```

Confirm the release artifact and embedded Maven metadata:

```bash
test -f target/paclo-1.3.0.jar
test -f target/classes/META-INF/maven/org.clojars.nanto/paclo/pom.xml
grep -F "<version>1.3.0</version>" \
  target/classes/META-INF/maven/org.clojars.nanto/paclo/pom.xml
jar tf target/paclo-1.3.0.jar | grep -F paclo/stream.clj
```

Recorded local results on 2026-08-01:

- Clojure tests: 273 tests / 1,020 assertions / 0 failures / 0 errors
- Java tests: 8 tests / 0 failures
- SpotBugs and CheckStyle: successful
- JaCoCo: 41.1% line coverage / 25.0% release gate passed
- Eastwood: 56 existing performance/reflection warnings / 0 exceptions
- clj-kondo: 0 errors / 0 warnings
- clojure-lsp clean and format dry-runs: no changes
- Markdown lint: 0 issues
- performance gate: 373.0 ms (`warn=1000`, `fail=1200`)
- offline quick profile: all 27 case/scenario combinations completed
- release JAR/POM: `1.3.0` coordinates and `paclo.stream` verified
- release JAR SHA-256:
  `132afade1c548f570959a4973e62d3161909e51262ff7708fcdd4bc301b11966`

## 3. CI and publish dry-run

- [x] the release-preparation PR is green on every required CI job
- [x] the latest dependency-audit run has no release-blocking finding
- [x] the release-preparation PR is merged to `main`
- [x] the publish workflow dry-run succeeds on the exact `main` commit
- [x] the dry-run artifact contains the `1.3.0` jar and POM

After merging the preparation PR, run:

```bash
gh workflow run publish.yml \
  --ref main \
  -f version=1.3.0 \
  -f dry_run=true
```

The dry-run performs source/version validation, tests, the performance gate,
and the release build. It does not contact Clojars.

Recorded pre-release audit result on 2026-08-01:

- latest Dependency Audit: successful
  ([run 30531457081](https://github.com/nantes-rfli/paclo/actions/runs/30531457081));
  v1.3 adds no dependency
- release-preparation CI: successful
  ([run 30685082830](https://github.com/nantes-rfli/paclo/actions/runs/30685082830))
- merged release commit: `623220872b7abfe53ae52acf31000036906375ee`
- publish dry-run: successful
  ([run 30685465835](https://github.com/nantes-rfli/paclo/actions/runs/30685465835))
- dry-run JAR/POM: `1.3.0` coordinates and `paclo.stream` verified; JAR
  SHA-256
  `2e0e62f70ec3f6c6d8e8476c4822a2be73ac126044ab036b4106df306145ab14`

## 4. Tag and publish

Resolve and review the exact commit before creating the tag:

```bash
git switch main
git pull --ff-only origin main
git status --short
git log -1 --oneline
git tag -a v1.3.0 -m "v1.3.0"
git push origin v1.3.0
```

Pushing the tag starts the publish workflow with publication enabled. Confirm
that it publishes `org.clojars.nanto/paclo:1.3.0`.

If the tag-triggered workflow fails before Clojars accepts the artifact, use
the manual recovery path:

```bash
gh workflow run publish.yml \
  --ref main \
  -f version=1.3.0 \
  -f dry_run=false
```

Do not use the recovery path after Clojars reports a successful publication;
released coordinates are immutable and cannot be overwritten.

Recorded publication result on 2026-08-01:

- tagged commit: `623220872b7abfe53ae52acf31000036906375ee`
- Clojars publication: successful
  ([run 30687829044](https://github.com/nantes-rfli/paclo/actions/runs/30687829044))
- published JAR SHA-256:
  `65a98348320ad905939e72fbf825b57111d704057698718863487edd22797a1b`
  (workflow artifact and Clojars download match)

## 5. Release verification

- [x] Clojars shows `org.clojars.nanto/paclo:1.3.0`
- [x] cljdoc builds and serves version `1.3.0`
- [x] a clean consumer project resolves the Clojars coordinate
- [x] the Git tag resolves to the release-preparation commit
- [x] the GitHub Release is published as the latest stable release
- [x] the README and roadmap status are updated from candidate to released

After Clojars succeeds, create the GitHub Release:

```bash
gh release create v1.3.0 \
  --verify-tag \
  --title v1.3.0 \
  --generate-notes
```

Verify that a clean consumer can require `paclo.stream` and resolve the public
`fan-out`, `branch`, and `stats` vars. If a release defect is discovered, do
not move the tag or replace the Clojars artifact. Correct it with a new patch
release.

Recorded verification results on 2026-08-01:

- clean consumer resolution downloaded the `1.3.0` POM and JAR from Clojars
  and loaded `paclo.stream/fan-out`, `branch`, and `stats`
- cljdoc build
  [108984](https://cljdoc.org/builds/108984) successfully imported 11
  namespaces, including the
  [paclo.stream API](https://cljdoc.org/d/org.clojars.nanto/paclo/1.3.0/api/paclo.stream)
- GitHub Release:
  [v1.3.0](https://github.com/nantes-rfli/paclo/releases/tag/v1.3.0)

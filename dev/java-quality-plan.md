# Java Quality Plan (JNR/libpcap Layer)

## Goal
Keep the small Java/JNR boundary safe, testable, and easy to debug.

## Completed
- JUnit coverage for offline open/read path.
- AutoCloseable wrappers (`PcapHandle`, `BpfProgram`).
- Centralized error handling (`PcapErrors`).
- Build-time `javac` checks with strict flags.
- SpotBugs, Checkstyle, JaCoCo, and Javadoc tasks wired into tooling.

## Quality Gates
- Unit/integration: `clojure -T:build javac-test && clojure -M:junit`
- SpotBugs: `clojure -M:spotbugs -m paclo.dev.spotbugs`
- Checkstyle: `clojure -M:checkstyle -m paclo.dev.checkstyle`
- JaCoCo: `clojure -M:jacoco -m paclo.dev.jacoco`
- Javadoc: `clojure -T:build javadoc`

## Notes
- libpcap runtime package is required on CI and local machines.
- Keep Java APIs minimal and push policy decisions to Clojure.

## Next Actions
1. Add one negative-path integration test for `pcap_open_live` failure mapping.
2. Keep JaCoCo threshold conservative until Java code size grows.

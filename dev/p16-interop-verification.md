# P16: External PCAP/PCAPNG interoperability

## Scope and provenance

Started from fetched main `4a113c60184128df442f3fa152ebf0390cedc6a5` on
2026-10-18 (Asia/Tokyo); the exact baseline is also in the
[local execution evidence](p16-interop-evidence.json).
PR #76 is unmerged, Issue #77 remains open, and core.async stays **1.6.681**.
No P14-B/C, P17, P09/P10, release, tag, publication or merge is included.
P16 is **implemented and verified**, with independent review pending in
[PR #78](https://github.com/nantes-rfli/paclo/pull/78).

This adds an executable integration gate, not just an investigation. No Paclo
implementation defect was reproduced in the selected matrix, so no production
or public API change is justified. Existing preserve/loss/author and explicit
error contracts remain authoritative. See [the user guide](../docs/pcapng.md).

All packet data is generated locally from six short header templates in
[verify_interop.py](script/verify_interop.py): RFC 5737 IPv4 addresses
192.0.2.1 → 192.0.2.2, UDP 12000 → 53, zero payload, fixed UTC timestamps.
Checksums are deliberately zero: this is a container/interoperability test,
not transport checksum validation. No live interface, third-party traffic,
secret, downloaded capture or redistributability restriction is involved.
One mixed-section case reuses the existing P08 synthetic big-endian section
(10.0.0.1 → 10.0.0.2), explicitly replacing its colliding private option code.
The generator and its inputs can be redistributed under the repository license.

The maintained script needs Python 3 and the six external tools below. Java
bindings must already be compiled. No Python packet library, daemon, capture
permission or new production dependency is needed. Missing tools/assertions
fail the gate. Existing P08 tests retain detailed format/security boundaries;
P16 complements them with actual external serialization and re-interpretation.

## Reproduction and oracles

From the repository root, with a **new** output directory:

```bash
bash dev/script/codex.sh doctor
bash dev/script/codex.sh prepare
python3 dev/script/verify_interop.py /tmp/paclo-interop
```

The script runs [the Clojure integration assertions](paclo/dev/interop.clj)
using `clojure -M:dev -m paclo.dev.interop OUTPUT_DIRECTORY`. Every subprocess
has a timeout and its complete argv, exit, stdout and stderr are saved in
`commands.json`, including failures. `environment.json` records CPU/OS, source
revision/dirty files, harness hashes, tool paths/full versions. `paclo.json`
records tests, output inventory, actual JVM/JNR and loaded libpcap image/version.
`manifest.json` is an independent physical input oracle; `sha256.json` identifies
that execution's files, and `success.json` exists only after all checks pass.

Generated PCAPNG SHB hardware/OS/application strings, source paths and tool
versions vary between executions. We promise reproducible generation steps and
semantic assertions, not identical file hashes across machines/tool versions.
No generated captures or multi-megabyte command log are committed; all files
are uploaded as CI artifacts, including failed runs.

Representative actual commands (the script supplies absolute paths):

```bash
text2pcap -q -t ISO -l 113 -N p16-113 -F pcapng link-113.txt link-113-pcapng.pcapng
text2pcap -q -t ISO -m 64 -F pcap link-1.txt snap64.pcap
tcpdump -n -r link-1-nsecpcap.pcap -w tcpdump-1.pcap 'udp dst port 53'
editcap -s 42 --capture-comment 'P16 section comment' -a '1:first comment' link-1-pcapng.pcapng editcap-snap.pcapng
mergecap -a -I none -w links.pcapng link-1-pcapng.pcapng link-101-pcapng.pcapng
tshark -n -r comments.pcapng -T fields -e frame.time_epoch -e frame.cap_len -e frame.len -e frame.comment
```

text2pcap emits both microsecond/nanosecond PCAP and nanosecond PCAPNG directly;
tcpdump independently filters and serializes each framing type. editcap creates
truncated packets with original lengths/comments; mergecap creates multiple IDBs.
Declared lab mutations concatenate external sections, swap Classic headers to
big endian, add binary timestamp resolution/offset/options/NRB/unknown blocks,
append a repeated comment TLV to editcap output, and damage final records.
This avoids requiring the newer `--preserve-packet-comments` flag absent from
Ubuntu Wireshark 4.2; the external-tool version is not upgraded for that flag.
These are explicitly mutations of external output,
not claims that tcpdump or editcap authored arbitrary options or malformed data.
For mixed-endian PCAPNG, the second section has the P08 provenance above.

The Python physical parser derives packet bytes/lengths, DLT mapping and exact
integer tick projection independently of Paclo. Clojure compares native results
and metadata events to it, checks source EOF/cleanup, then writes both formats.
The PCAPNG Writer result must match every supported semantic field/options/opaque
body under the existing independent wire oracle, allowing section-length
normalization. tshark consumes every supported input and every Paclo output;
tcpdump additionally consumes all Classic outputs to EOF. Physical output
records independently verify bytes and lengths. Byte equality is never the
blanket PCAPNG acceptance criterion.

## Executed matrix

Local gate: **32 valid inputs, 4 malformed inputs, 45 Writer outputs; five
Clojure integration tests / 377 assertions, zero failures/errors**.

| Representative input | Native path | Metadata path / Writer / external interpretation |
| --- | --- | --- |
| Ethernet, SLL, SLL2, Raw IP, NULL, LOOP; micro/nano PCAP and nano PCAPNG (18) | Correct bytes, DLT, lengths, floored usec, BPF accept/reject, EOF | All six PCAPNG framing types retain ticks and metadata; both Writers read externally |
| tcpdump filtered Classic files, all six framings (6) | Same packet oracle and EOF | Classic Writer keeps the six-key subset with selected native DLT |
| editcap truncation/capture comment plus repeated-comment TLV mutation (1) | caplen 42, wire length 64, no metadata | Ordered raw comments, nano ticks and original interface snaplen retained; explicit comment drop counted |
| mergecap two identical interfaces (1) | All four packets, interface identity lost | IDs 0/1 and both descriptors retained |
| mergecap mixed LINKTYPE / snaplen (2) | Explicit error before first packet; both IDBs precede packets | All four packets and descriptors preserved; external re-read succeeds |
| Concatenated external sections (1) | Four packets, sections lost | Qualified section IDs and restarted interface IDs retained |
| Classic big-endian nanosecond header mutation (1) | Correct values, microsecond projection | Classic output read by tshark/tcpdump |
| Binary 2^-10, offset +7, exact ticks, comments, unknown options, NRB/unknown block (1) | Microsecond projection, opaque data omitted | Exact ticks/options/opaque bytes retained in preserve; explicit lossy counts; author mode validated |
| Mixed little/big-endian sections (1) | Two-packet prefix then explicit native error | Three packets and section order retained; external re-read succeeds |
| Cut PCAP / cut PCAPNG / invalid trailer / undefined interface (4) | One-packet prefix then error, never normal EOF | PCAPNG errors retain existing reasons; failed write never publishes destination and removes temp |
| Publication with actual editcap input | Classic output retains its documented non-atomic behavior | Destination absent throughout source reduction, visible on successful completion, exclusive destination protection; previous output unchanged on refusal |

`core/reduce-packets-report` with `:error-mode :pass` exposes the valid prefix
and failed stats. The throwing path is separately asserted for unsupported
mixed layouts. The metadata path never invokes native libpcap or BPF.
SPB/time absence, unsupported PB/DSB, packet ceilings, injection of flush/close/
publication failures and bounded-heap long streams remain covered by existing
P08 tests rather than duplicated in this small external-tool matrix.

## Findings and compatibility decisions

1. **Native restrictions, no Paclo defect:** mergecap emits both IDBs before
   packets, so mixed LINKTYPE/snaplen errors have an empty prefix on measured
   libpcap 1.10.1. The mixed-endian section case has a two-packet prefix. Preserve
   the error contract; use `open-source` for these valid layouts. Raw IP's file
   LINKTYPE 101 remains native DLT 12 on the measured supported systems.
2. **Private-option collision, no Paclo repair:** Wireshark 4.6.8 rejects
   historical P08 rich EPB option 0x8001 of length eight as
   `Darwin option 0x8001 length expected 4, actual 8` (editcap warns but exits 0, tshark
   exits 14). Paclo treats that private field as opaque unknown under its current
   contract. P16 uses 0xf123 for its synthetic unknown option. We did not change
   historical fixtures or silently drop/interpret their private data. Explicit
   `:drop #{:unknown-options}` is available when the caller accepts losing all
   unknown options; the new gate verifies removal and exact aggregate counts.
3. **External rewrite limitation:** editcap 4.6.8 removes the unknown block and
   IDB/EPB unknown options from `rich.pcapng`. It retains resolution 0x8a and
   offset +7 but changes ticks from **1740800000129** to **1740800007296**.
   tshark shows the original **1700000007.125976562** becoming
   **1700000014.125000000** after editcap alone. This is observed outside Paclo;
   no claim of an acceptable semantic round trip or root-cause fix is made for
   that rewrite. macOS CI Wireshark 4.6.9 reproduces the same change. Ubuntu's
   Wireshark 4.2.2 instead removes the offset option and yields
   `1700000007.125000000`: it also loses one binary tick of fractional precision,
   but does not retain the extra offset. These are version-specific external
   behaviors, not a portable normalization contract. Paclo's direct preserve
   output retains the original exact ticks/options/opaque bytes and external interpretation. The gate saves both
   metadata inventories in `normalization.json`; differing external versions
   may behave differently, so their normalization is recorded, not required.
4. **Opaque records are tool-dependent:** a copyable custom block in an initial
   local probe appeared as an extra 16-byte tshark record; libpcap skipped it.
   The final two-packet rich case instead uses an empty NRB plus unknown block.
   This supports the existing no-complete-packet-coverage caveat; it does not
   justify interpreting opaque contents or broadening the public API.
5. **Loss is explicit:** the comment case removes exactly four comment options
   on local Wireshark 4.6.8; the test derives counts from the actual source so
   tool-added comments remain covered. Rich loss reports exactly two opaque
   blocks and three unknown options, with all retained semantics checked.
   Classic output intentionally loses nanosecond digits/container metadata.

No minimum supported format or public error text changed. Larger private-option
interpretation or a native PCAPNG backend replacement is not justified by this
matrix. A Wireshark upstream report for the offset/binary rewrite can use the
synthetic reproducer; no message to upstream was sent as part of this task.

## Tool and platform identity

| Executed environment | External tools / source | Actual native identity | Result |
| --- | --- | --- | --- |
| Local macOS 15.4.1, Darwin 24.4.0, x86_64, Intel i7-8700B @ 3.20GHz, Temurin 21.0.12.1+1 | Wireshark official app bundle 4.6.8 (v4.6.8-0-ge677bf052328): text2pcap/editcap/mergecap/tshark/capinfos; Homebrew tcpdump 4.99.7 | Paclo `/usr/lib/libpcap.A.dylib` 1.10.1; tshark 1.10.1; tcpdump 1.11.0 | Passed; JSON evidence linked above |
| CI Ubuntu 24.04, Linux6.17.0-1022-azure x64, AMD EPYC9V45, Temurin21.0.12.1+1 | Ubuntu Wireshark 4.2.2 (`4.2.2-1.1build3`), tcpdump4.99.4 | Paclo `/lib/x86_64-linux-gnu/libpcap.so.1.10.4`,1.10.4 TPACKET_V3; tshark/tcpdump also1.10.4 | Passed |
| CI macOS26.6.2 ARM64, Apple M1(Virtual), Temurin17.0.20.1+1 | Official Wireshark 4.6.9 (`v4.6.9-0-g2d548b197c75`) app via cask fetch; Apple tcpdump4.99.1/158 | Paclo `/usr/lib/libpcap.A.dylib`,1.10.1; tshark/tcpdump also1.10.1 | Passed |
| CI Ubuntu24.04, Linux6.17.0-1022-azure ARM64, Neoverse-N2, Temurin21.0.12.1+1 | Ubuntu Wireshark 4.2.2 (`4.2.2-1.1build3`), tcpdump4.99.4 | Paclo `/lib/aarch64-linux-gnu/libpcap.so.1.10.4`,1.10.4 TPACKET_V3; tshark/tcpdump also1.10.4 | Passed |

Implementation `255320d` passes **all 16 CI jobs** in
[CI39136856171](https://github.com/nantes-rfli/paclo/actions/runs/39136856171).
[CI evidence JSON](p16-ci-evidence.json) retains per-platform versions, CPU/OS,
actual native/JVM identity, source/harness hashes, tests, normalization inventories
and same-JAR consumer hashes. Each of the three platform gates independently
passes 32 valid inputs, 4 malformed inputs, 45 outputs and 377 assertions. Their
existing suites pass 13 JUnit tests and 493 Clojure tests (19,136 assertions on
Linux, 19,130 on macOS). Full generated files/commands remain in the run's
`p16-interop-*` artifacts.

Upstream references: [text2pcap manual](https://www.wireshark.org/docs/man-pages/text2pcap.html),
[editcap manual](https://www.wireshark.org/docs/man-pages/editcap.html),
[mergecap manual](https://www.wireshark.org/docs/man-pages/mergecap.html).
The generator uses flags present in the actually executed tools, rather than
assuming that current online documentation describes every packaged version.
CI installs only Ubuntu distribution tshark/wireshark-common/tcpdump alongside
existing libpcap-dev, or fetches/checksums the signed upstream macOS bundle through its cask definition.
macOS mounts the image read-only and copies only the app to a temporary directory,
verifying its code signature; it does not install the cask's capture-helper packages.
Install steps print actual package identity; full runtime versions are artifacts.

## Verification and remaining limits

- `bash dev/script/codex.sh doctor` and `prepare`: pass on local JDK21.
- `python3 dev/script/verify_interop.py /tmp/paclo-p16-portable`: pass as above.
  CPU identity via sysctl required sandbox escalation; no interface was opened.
- `bash dev/script/codex.sh check`: JUnit 13/13; existing Clojure suite 493 tests /
  19,130 assertions; offline smoke four packets / 438 bytes, all pass.
- Kondo: zero errors/warnings; Eastwood completes without exceptions; LSP
  clean-ns/format dry runs unchanged. Markdown 55 files/zero errors. All 40
  maintained documentation examples pass; parser tests 16/16 and link tests 9/9
  (`TMPDIR=/private/tmp` avoids the existing macOS symlink-temp test issue).
- Performance: first contended run fails at 1653.6ms; isolated rerun passes
  at 581.3ms against unchanged 1000/1200ms warning/failure budgets. No speedup claim.
- Package and clean independent JDK21 consumer pass for implementation a13028b;
  JAR SHA-256 `7b90891d674235863f7ce664a7e767dabd84a943731070b1132a92eca222da3a`.
- Initial CI39136407960 exposes a test-harness portability issue: Ubuntu's
  editcap 4.2 lacks `--preserve-packet-comments`. The final script uses the
  declared TLV mutation instead of that flag; the revised local gate passes
  the same 377 assertions. Corrected implementation CI39136856171 passes all 16
  jobs, including the app-only macOS setup and all three external gates.
- CI's unchanged mid-50k performance gate passes at 707.5ms. Documentation 40
  examples, SpotBugs/CheckStyle/JaCoCo, static checks, performance shards/merger,
  JDK25 source experiment and same-JAR17/21/25 consumers (including 25 debug/deny)
  all pass. The five consumer reports identify the same JAR SHA-256
  `4eeec15c5ae424870c7e584de2c46ad1e1e7ed23b5deaacdaa479b6a1e563908`,
  built at CI merge-ref `99268acc19695ce54ce4dd2d4f42f7d362e1da54`.
  The final evidence-only PR head is checked separately in PR78 before handoff.

CI retains all existing JDK17/21, JDK25 experiment, same-JAR consumers, static/
coverage checks, documentation examples and performance jobs. External gates
are added to the three existing platform jobs; the aggregate now also requires
Linux ARM64. No performance budget or coverage threshold is weakened.

Local JDK17/25 and ARM64 execution are unavailable in this checkout; the CI
evidence above supplies the three named platform configurations and the unchanged
Linux x64 JDK25 experiment separately. P16 does not test the full OS/CPU/JDK
Cartesian product: other external-tool configurations, including Linux ARM64
JDK17/25, macOS ARM64 JDK21/25 and Linux x64 JDK17, remain unverified by this gate
(the existing separate JAR consumers still run 17/21/25).
No Windows/BSD, live capture, NIC throughput, real production traffic diversity,
compressed file support, arbitrary private blocks/options, independent JDK25
external-tool matrix or long-running capture performance is established here.
Offline/generated inputs do not validate live capture performance. Independent
review must precede merge.

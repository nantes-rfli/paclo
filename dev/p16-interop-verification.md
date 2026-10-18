# P16: External PCAP/PCAPNG interoperability

## Scope and provenance

Started from fetched main `4a113c60184128df442f3fa152ebf0390cedc6a5` on
2026-10-18 (Asia/Tokyo); the exact baseline is also in the
[local execution evidence](p16-interop-evidence.json).
PR #76 is unmerged, Issue #77 remains open, and core.async stays **1.6.681**.
No P14-B/C, P17, P09/P10, release, tag, publication or merge is included.

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
editcap --preserve-packet-comments -a '1:second comment' editcap-snap.pcapng comments.pcapng
mergecap -a -I none -w links.pcapng link-1-pcapng.pcapng link-101-pcapng.pcapng
tshark -n -r comments.pcapng -T fields -e frame.time_epoch -e frame.cap_len -e frame.len -e frame.comment
```

text2pcap emits both microsecond/nanosecond PCAP and nanosecond PCAPNG directly;
tcpdump independently filters and serializes each framing type. editcap creates
truncated packets with original lengths/comments; mergecap creates multiple IDBs.
Declared lab mutations concatenate external sections, swap Classic headers to
big endian, add binary timestamp resolution/offset/options/NRB/unknown blocks,
and damage final records. They are explicitly mutations of external output,
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
| editcap truncation and repeated packet/capture comments (1) | caplen 42, wire length 64, no metadata | Ordered raw comments, nano ticks and original interface snaplen retained; explicit comment drop counted |
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
   that rewrite. Paclo's direct preserve output retains the original exact
   ticks/options/opaque bytes and external interpretation. The gate saves both
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
| CI Linux x64 / JDK21 | Ubuntu packages; exact versions pending CI | Pending actual loaded library report | Pending |
| CI macOS ARM64 / JDK17 | Official Wireshark cask + OS tcpdump; exact versions pending CI | Pending actual loaded library report | Pending |
| CI Linux ARM64 / JDK21 | Ubuntu packages; exact versions pending CI | Pending actual loaded library report | Pending |

Upstream references: [text2pcap manual](https://www.wireshark.org/docs/man-pages/text2pcap.html),
[editcap manual](https://www.wireshark.org/docs/man-pages/editcap.html),
[mergecap manual](https://www.wireshark.org/docs/man-pages/mergecap.html).
The generator uses flags present in the actually executed tools, rather than
assuming that current online documentation describes every packaged version.
CI installs only Ubuntu distribution tshark/wireshark-common/tcpdump alongside
existing libpcap-dev, or the signed upstream macOS bundle through its cask.
Install steps print actual package identity; full runtime versions are artifacts.

## Verification and remaining limits

- `bash dev/script/codex.sh doctor` and `prepare`: pass on local JDK21.
- `python3 dev/script/verify_interop.py /tmp/paclo-p16-local-final`: pass as above.
  CPU identity via sysctl required sandbox escalation; no interface was opened.
- `bash dev/script/codex.sh check`: JUnit 13/13; existing Clojure suite 493 tests /
  19,130 assertions; offline smoke four packets / 438 bytes, all pass.
- Static checks, documentation execution, performance gate and PR CI: in progress;
  actual results will be appended to the work log before handoff.

CI retains all existing JDK17/21, JDK25 experiment, same-JAR consumers, static/
coverage checks, documentation examples and performance jobs. External gates
are added to the three existing platform jobs; the aggregate now also requires
Linux ARM64. No performance budget or coverage threshold is weakened.

Local JDK17/25 and ARM64 execution are unavailable in this checkout; CI evidence
must supply those platforms and the unchanged JDK25 experiment separately.
No Windows/BSD, live capture, NIC throughput, real production traffic diversity,
compressed file support, arbitrary private blocks/options, independent JDK25
external-tool matrix or long-running capture performance is established here.
Offline/generated inputs do not validate live capture performance. Independent
review must precede merge.

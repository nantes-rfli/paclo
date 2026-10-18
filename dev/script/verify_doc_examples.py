#!/usr/bin/env python3
"""Execute tagged code fences in maintained documentation against offline PCAPs.

Run after compiling Paclo's Java bindings:
    python3 dev/script/verify_doc_examples.py

Requires Clojure CLI and libpcap. No live capture or network traffic is used.
Historical documentation under docs/archive is intentionally excluded.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import re
import shlex
import subprocess
import sys
from typing import NamedTuple

ROOT = Path(__file__).resolve().parents[2]
# Separate Clojure subprocesses keep examples isolated; limit contention on CI.
MAX_WORKERS = 3
REQUIRE = (
    "(require '[clojure.edn :as edn] '[paclo.core :as core] '[paclo.stream :as stream] '[paclo.pcapng :as pcapng] "
    "'[paclo.flow :as flow] '[paclo.window :as window] '[paclo.dns :as dns] '[examples.dns-rtt :as rtt] '[examples.dns-qps :as qps] "
    "'[paclo.core :refer [packet-xf packets]] "
    "'[paclo.proto.dns-ext :as dns-ext] '[paclo.proto.tls-ext :as tls-ext])"
)
MARKER = re.compile(r"<!-- paclo-doc-test: ([a-z][a-z0-9-]*) -->")
FENCE = re.compile(r"```([a-zA-Z0-9_-]+)")


class Check(NamedTuple):
    label: str
    language: str
    predicate: str = ""


# The predicates check real PCAP I/O results, rather than merely loading forms.
CHECKS = {
    "repl-inspect": Check(
        "REPL closed packet inspection", "clojure",
        '(= [{:caplen 82 :src "10.0.0.1" :dst "1.1.1.1" :protocol :udp} '
        '{:caplen 178 :src "1.1.1.1" :dst "10.0.0.1" :protocol :udp}] result)',
    ),
    "repl-flow": Check(
        "REPL filtered bidirectional flow", "clojure",
        '(= {:stop-reason :eof :captured 4 '
        ':summary {:seen 2 :aggregated 2 :skipped 0} '
        ':top [{:flow {:ip-version 4 :protocol 17 :src-ip 16843009 :src-port 53 '
        ':dst-ip 167772161 :dst-port 58555} '
        ':packets 2 :captured-bytes 260 :wire-bytes 260}]} result)',
    ),
    "repl-dns": Check(
        "REPL explicit DNS transactions", "clojure",
        '(= {:questions ["example.com" "google.com"] '
        ':transactions [{:kind :match :qname "example.com" :rtt-us 15817 :rcode 0} '
        '{:kind :match :qname "google.com" :rtt-us 10241 :rcode 0}] :pending 0} result)',
    ),
    "repl-roundtrip": Check(
        "REPL filtered Classic PCAP round trip", "clojure",
        '(= {:packets 2 :captured-bytes 260 :preserved? true} result)',
    ),
    "migration-classic-time": Check(
        "Migration Classic timestamp selection", "clojure",
        '(= [{:ts-sec 1700000000 :ts-usec 123 :caplen 60 :len 60} '
        '{:ts-sec 1700000001 :ts-usec 456 :caplen 60 :len 120} '
        '{:ts-sec 1700000002 :ts-usec 789 :caplen 60 :len 120}] result)',
    ),
    "migration-invalid-time": Check(
        "Migration rejects uncertain capture time", "clojure",
        '(= {:rejected true :verified-time {:ts-sec 1700000001 :ts-usec 456}} result)',
    ),
    "usage-offline-prefix": Check(
        "Usage safely closed offline prefix", "clojure",
        '(and (= 2 (count result)) (every? :decoded result))',
    ),
    "pcapng-preserving-writer": Check(
        "PCAPNG preserving writer", "clojure",
        '(and (= 3 (:packets result)) (= :complete (get-in result [:report :status])) '
        '(= :known-semantics (get-in result [:report :fidelity])) '
        '(= {} (get-in result [:report :loss-counts])) '
        '(= 7 (get-in result [:report :blocks-written])) '
        '(= 644 (get-in result [:report :bytes-written])))',
    ),
    "pcapng-authoring-writer": Check(
        "PCAPNG authoring writer", "clojure", '(= [{:ticks 1N}] result)',
    ),
    "pcapng-packet-analysis": Check(
        "PCAPNG mixed-section packet decoding", "clojure",
        '(= [:ethernet :raw-ip] result)',
    ),
    "pcapng-event-inspection": Check(
        "PCAPNG event-preserving inspection", "clojure",
        '(= [[:section nil] [:interface nil] '
        '[:packet {:ticks 1700000000123456789N}] [:interface nil] '
        '[:packet {:ticks 1740800000129N}] [:opaque-block nil] [:packet nil]] result)',
    ),
    "pcapng-error-status": Check(
        "PCAPNG explicit error status", "clojure",
        '(= {:reason :undefined-interface :state :failed :events 2} result)',
    ),
    "readme-null-loop-full": Check(
        "README NULL/LOOP full decode", "clojure",
        '(= [{:linktype 0 :link :null :af 2 :ip 4} '
        '{:linktype 108 :link :loop :af 2 :ip 4}] result)',
    ),
    "usage-null-loop-flow": Check(
        "Usage NULL/LOOP bounded flow", "clojure",
        '(and (= [#{0} #{108}] (mapv :linktypes result)) '
        '(every? #(= #{4 6} (:versions %)) result) '
        '(every? #(= {:seen 14 :aggregated 14 :skipped 0} (:summary %)) result))',
    ),
    "readme-raw-ip-full": Check(
        "README Raw IP full decode", "clojure",
        '(= {:linktypes #{12} :links #{:raw-ip} :versions #{4 6}} result)',
    ),
    "usage-raw-ip-flow": Check(
        "Usage Raw IP bounded flow aggregate", "clojure",
        '(and (= #{4 6} (:versions result)) (= #{12} (:linktypes result)) '
        '(= 8 (reduce + (map :packets (:top result)))))',
    ),
    "readme-cooked-decode": Check(
        "README SLL/SLL2 decoding", "clojure",
        '(= [{:linktype 113 :link :linux-sll :ip :ipv4 :port 53} '
        '{:linktype 276 :link :linux-sll2 :ip :ipv4 :port 53}] result)',
    ),
    "usage-cooked-flow": Check(
        "Usage SLL2 bounded flow aggregate", "clojure",
        '(and (= #{4 6} (:versions result)) (= #{276} (:linktypes result)) '
        '(= 8 (reduce + (map :packets (:top result)))))',
    ),
    "readme-explicit-pcap-writer": Check(
        "README explicit native-DLT writer", "clojure",
        '(and (= 3 (:count result)) (= [113 113 113] (:linktypes result)) (:preserved? result))',
    ),
    "usage-explicit-pcap-writer": Check(
        "Usage explicit native-DLT round trip", "clojure",
        '(and (= 3 (:count result)) (= [113 113 113] (:linktypes result)) (:preserved? result))',
    ),
    "usage-bounded-dns-cli": Check(
        "Bounded DNS CLI reports", "clojure",
        "(and (= 2 (:pairs result)) (= 13.029 (:average-ms result)) (= 4 (:dns-packets result)))",
    ),
    "readme-time-window": Check(
        "README pure time window", "clojure",
        '(and (= 1 (count result)) (= 0 (:start-us (first result))) '
        '(= 1000000 (:end-us (first result))) (:complete? (first result)) '
        '(= {:packets 1 :captured-bytes 128} (get-in result [0 :groups :dns])))',
    ),
    "usage-time-windows": Check(
        "Usage offline time windows", "clojure",
        '(and (:same? result) (zero? (:retained result)) '
        '(= 4 (reduce + (map #(get-in % [:groups :dns :packets]) (:events result)))) '
        '(every? :complete? (:events result)))',
    ),
    "usage-dns-correlation": Check(
        "Usage offline DNS correlation", "clojure",
        '(and (zero? (:pending result)) (= [:match :match] (mapv :kind (:transactions result))) '
        '(every? #(= (:rtt-us %) (- (get-in % [:response :time-us]) '
        '(get-in % [:query :time-us]))) (:transactions result)))',
    ),
    "readme-flow-analysis": Check(
        "README bounded flow analysis", "clojure",
        '(and (seq result) (= 4 (reduce + (map :packets result))) '
        '(every? #(and (:captured-bytes %) (:wire-bytes %) '
        '(integer? (get-in % [:flow :protocol]))) result))',
    ),
    "usage-flow-analysis": Check(
        "Usage composable flow analysis", "clojure",
        '(and (:same? result) (= {:seen 4 :aggregated 4 :skipped 0} (:summary result)) '
        '(= 2 (count (:top result))))',
    ),
    "usage-linktype-raw": Check(
        "Usage non-Ethernet raw linktype", "clojure",
        '(and (= [113 113 113] (:linktypes result)) '
        '(= [66 2 64] (:captured-lengths result)) '
        '(= [nil :short-frame :malformed-packet] '
        '(mapv #(-> % first :reason) (:diagnostics result))) (not (:flow-has-bytes? result)))',
    ),
    "usage-structured-diagnostics": Check(
        "Usage structured diagnostics", "clojure",
        '(and (= (vec (repeat 4 :extension-exception)) (:reasons result)) '
        '(:edn-roundtrip? result) (zero? (:decode-errors result)))',
    ),
    "usage-explicit-extensions": Check(
        "Usage explicit DNS extensions", "clojure",
        '(and (= 4 (count result)) (every? #(= "DNS message" %) result))',
    ),
    "extensions-ordered-selection": Check(
        "Ordered explicit extensions with duplicates", "clojure",
        '(and (= 4 (count result)) (every? #(= [[:annotated :annotated] "DNS message"] %) result))',
    ),
    "extensions-fan-out": Check(
        "Independent DNS/TLS fan-out extensions", "clojure",
        '(and (= 5 (count (:dns result)) (count (:tls result))) '
        '(some #(= "DNS message" (get-in % [:decoded :l3 :l4 :app :summary])) (:dns result)) '
        '(not-any? #(get-in % [:decoded :l3 :l4 :app :sni]) (:dns result)) '
        '(some #(= "example.com" (get-in % [:decoded :l3 :l4 :app :sni])) (:tls result)) '
        '(not-any? #(= "DNS message" (get-in % [:decoded :l3 :l4 :app :summary])) (:tls result)))',
    ),
    "usage-pcap-roundtrip": Check(
        "Usage PCAP metadata round trip", "clojure",
        "(and (= 3 (:count result)) (:preserved? result) (:truncated? result))",
    ),
    "offline-quick-start": Check(
        "README offline quick start", "clojure",
        "(and (= 2 (count result)) (every? #(contains? % :ts-sec) result))",
    ),
    "readme-packet-xf": Check(
        "README packet-xf flow", "clojure",
        "(and (vector? result) (seq result) (every? map? result))",
    ),
    "usage-packet-xf": Check(
        "Usage packet-xf flow", "clojure",
        "(and (vector? result) (seq result) (every? map? result))",
    ),
    "usage-early-reduced": Check(
        "Usage synchronous early reduced", "clojure",
        "(and (= 2 (count result)) (every? #(contains? % :caplen) result))",
    ),
    "readme-bounded-fan-out": Check(
        "README bounded fan-out", "clojure",
        "(and (= 4 (:archive-count result)) (= 4 (:metrics-count result)) (= 4 (get-in result [:stream :source :received])))",
    ),
    "usage-bounded-fan-out": Check(
        "Usage bounded fan-out", "clojure",
        "(and (= 4 (:archive-count result)) (= 4 (:metrics-count result)) (= 4 (get-in result [:distribution :source :received])))",
    ),
    "api-contract-packet-xf": Check(
        "API contract packet-xf flow", "clojure",
        "(and (vector? result) (seq result) (every? integer? result))",
    ),
    "readme-dns-quick-check": Check("README DNS quick check", "bash"),
}

# These cannot be removed when adding future documented examples.
REQUIRED_IDS = frozenset({
    "repl-inspect",
    "repl-flow",
    "repl-dns",
    "repl-roundtrip",
    "migration-classic-time",
    "migration-invalid-time",
    "readme-raw-ip-full",
    "usage-raw-ip-flow",
    "readme-cooked-decode",
    "usage-cooked-flow",
    "readme-null-loop-full",
    "usage-null-loop-flow",
    "readme-explicit-pcap-writer",
    "usage-explicit-pcap-writer",
    "usage-bounded-dns-cli",
    "readme-time-window",
    "usage-time-windows",
    "usage-dns-correlation",
    "readme-flow-analysis",
    "usage-flow-analysis",
    "usage-linktype-raw",
    "usage-structured-diagnostics",
    "usage-explicit-extensions",
    "extensions-ordered-selection",
    "extensions-fan-out",
    "usage-pcap-roundtrip",
    "offline-quick-start",
    "readme-packet-xf",
    "usage-packet-xf",
    "usage-early-reduced",
    "readme-bounded-fan-out",
    "usage-bounded-fan-out",
    "api-contract-packet-xf",
    "readme-dns-quick-check",
})


class Snippet(NamedTuple):
    path: Path
    language: str
    code: str


def maintained_markdown(root):
    """Only the root README and current docs; never execute historical examples."""
    yield root / "README.md"
    docs = root / "docs"
    if docs.is_dir():
        for path in sorted(docs.rglob("*.md")):
            if "archive" not in path.relative_to(docs).parts[:-1]:
                yield path


def discover(root=ROOT, checks=CHECKS, required_ids=REQUIRED_IDS):
    """Find explicitly registered code fences; fail closed on any inconsistency."""
    if not required_ids <= checks.keys():
        raise AssertionError("missing required check definitions: " +
                             ", ".join(sorted(required_ids - checks.keys())))
    found = {}
    for path in maintained_markdown(root):
        lines = path.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            marker = MARKER.fullmatch(line.strip())
            if not marker:
                if line.lstrip().startswith("<!-- paclo-doc-test:"):
                    raise AssertionError(f"{path}:{i + 1}: malformed test marker")
                continue
            name = marker.group(1)
            if name not in checks:
                raise AssertionError(f"{path}:{i + 1}: unregistered test ID: {name}")
            if name in found:
                raise AssertionError(f"{path}:{i + 1}: duplicate test ID: {name}")
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1
            opening = FENCE.fullmatch(lines[j].strip()) if j < len(lines) else None
            if not opening:
                raise AssertionError(f"{path}:{i + 1}: test marker must precede a code fence")
            language = opening.group(1)
            if language != checks[name].language:
                raise AssertionError(f"{path}:{j + 1}: {name} requires {checks[name].language}, got {language}")
            closing = j + 1
            while closing < len(lines) and lines[closing].strip() != "```":
                closing += 1
            if closing == len(lines):
                raise AssertionError(f"{path}:{j + 1}: unclosed code fence for {name}")
            code = "\n".join(lines[j + 1:closing]).strip()
            if not code:
                raise AssertionError(f"{path}:{j + 1}: empty code fence for {name}")
            found[name] = Snippet(path, language, code)
    missing = checks.keys() - found.keys()
    if missing:
        raise AssertionError("missing documentation test IDs: " + ", ".join(sorted(missing)))
    return found


def dns_argv(code):
    """Parse one documented CLI command; never execute a shell or shell syntax."""
    if len(code.splitlines()) != 1:
        raise ValueError("DNS quick check must be a single Bash command")
    lexer = shlex.shlex(code, posix=True, punctuation_chars=";&|<>")
    lexer.whitespace_split = True
    argv = list(lexer)
    if any(token and set(token) <= set(";&|<>") for token in argv):
        raise ValueError("DNS quick check cannot use shell operators")
    if any("$" in token or "`" in token for token in argv):
        raise ValueError("DNS quick check cannot use shell expansion")
    if len(argv) != 4 or argv[:3] != ["clojure", "-M:dev:dns-ext", "-e"]:
        raise ValueError("DNS quick check must be a single clojure -M:dev:dns-ext -e command")
    if "paclo.proto.dns-ext" not in argv[3] or ":dns-ext-ok" not in argv[3]:
        raise ValueError("DNS quick check must register the DNS extension and print :dns-ext-ok")
    return argv


def execute(label, argv):
    print(f"\n$ {shlex.join(argv)}", flush=True)
    completed = subprocess.run(
        argv,
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    if completed.stdout:
        print(completed.stdout.rstrip(), flush=True)
    if completed.stderr:
        print(completed.stderr.rstrip(), file=sys.stderr, flush=True)
    if completed.returncode != 0:
        raise RuntimeError(f"{label}: exit {completed.returncode}")
    print(f"PASS: {label}", flush=True)
    return completed.stdout


def run_doc_expression(label, code, predicate):
    expr = (
        "(try "
        f"(let [result (do\n{code}\n)] "
        f"(when-not {predicate} "
        f'(throw (ex-info "documentation result check failed" '
        f'{{:example "{label}" :result result}}))) '
        f'(println :doc-example-ok "{label}")) '
        "(finally (shutdown-agents)))"
    )
    stdout = execute(
        label,
        ["clojure", "-M:dev:dns-ext", "-e", REQUIRE, "-e", expr],
    )
    if ":doc-example-ok" not in stdout:
        raise RuntimeError(f"{label}: success marker missing")


def run_dns_quick_check(label, code):
    stdout = execute(label, dns_argv(code))
    if ":dns-ext-ok" not in stdout:
        raise RuntimeError(f"{label}: expected output missing")


def main():
    found = discover()
    # The CLI writes shared .cpcache files. Prepare this alias serially before
    # independent JVMs read it; concurrent cold starts can observe a partial cp.
    execute("Prepare documentation classpath", ["clojure", "-P", "-M:dev:dns-ext"])
    # Run all checks even if one fails. Isolated JVMs retain real-PCAP checks.
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        checks = {}
        for name, check in CHECKS.items():
            code = found[name].code
            if check.language == "bash":
                future = pool.submit(run_dns_quick_check, check.label, code)
            else:
                future = pool.submit(run_doc_expression, check.label, code, check.predicate)
            checks[future] = check.label
        failures = []
        for future in as_completed(checks):
            try:
                future.result()
            except Exception as exc:
                failures.append(f"{checks[future]}: {exc}")
    if failures:
        raise RuntimeError("Failed documentation examples:\n" + "\n".join(failures))
    print(f"\nPASS: {len(CHECKS)} documentation examples", flush=True)


if __name__ == "__main__":
    main()

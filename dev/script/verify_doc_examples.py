#!/usr/bin/env python3
"""Execute the actual maintained P01 documentation snippets on an offline fixture.

Run after compiling Paclo's Java bindings:
    python3 dev/script/verify_doc_examples.py

Requires Clojure CLI and libpcap. No live device or network traffic is used.
"""

from pathlib import Path
import shlex
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
REQUIRE = "(require '[paclo.core :as core] '[paclo.stream :as stream] '[paclo.core :refer [packet-xf packets]])"


def extract_clojure(path, after):
    """Get the first Clojure code fence following a unique documentation marker."""
    text = (ROOT / path).read_text(encoding="utf-8")
    if text.count(after) != 1:
        raise AssertionError(f"{path}: expected exactly one occurrence of {after!r}")
    start = text.index(after) + len(after)
    opening = text.find("```clojure\n", start)
    if opening < 0:
        raise AssertionError(f"{path}: Clojure code fence not found after {after!r}")
    opening += len("```clojure\n")
    closing = text.find("\n```", opening)
    if closing < 0:
        raise AssertionError(f"{path}: unclosed Clojure code fence")
    return text[opening:closing].strip()


# The predicates check results from real PCAP I/O instead of merely loading forms.
EXAMPLES = [
    (
        "README offline quick start",
        "README.md",
        "## Quick start",
        "(and (= 2 (count result)) (every? #(contains? % :ts-sec) result))",
    ),
    (
        "README packet-xf flow",
        "README.md",
        "For transformations outside the capture APIs",
        "(and (vector? result) (seq result) (every? map? result))",
    ),
    (
        "Usage packet-xf flow",
        "docs/usage.md",
        "## Composable packet transformations",
        "(and (vector? result) (seq result) (every? map? result))",
    ),
    (
        "Usage synchronous early reduced",
        "docs/usage.md",
        "For example, collect just two packet summaries:",
        "(and (= 2 (count result)) (every? #(contains? % :caplen) result))",
    ),
    (
        "README bounded fan-out",
        "README.md",
        "To feed two independent consumers",
        "(and (= 4 (:archive-count result)) (= 4 (:metrics-count result)) (= 4 (get-in result [:stream :source :received])))",
    ),
    (
        "Usage bounded fan-out",
        "docs/usage.md",
        "## Bounded fan-out (v1.3)",
        "(and (= 4 (:archive-count result)) (= 4 (:metrics-count result)) (= 4 (get-in result [:distribution :source :received])))",
    ),
    (
        "API contract packet-xf flow",
        "docs/cljdoc-api-contract.md",
        "- Output: a transducer, suitable for",
        "(and (vector? result) (seq result) (every? integer? result))",
    ),
]


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


def run_doc_expression(label, path, marker, predicate):
    code = extract_clojure(path, marker)
    expr = (
        "(try "
        f"(let [result (do {code})] "
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


def run_dns_quick_check():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    commands = [
        line.strip()
        for line in text.splitlines()
        if line.startswith("clojure -M:dev:dns-ext -e ")
        and ":dns-ext-ok" in line
    ]
    if len(commands) != 1:
        raise AssertionError("README DNS quick check should contain one command")
    stdout = execute("README DNS quick check", shlex.split(commands[0]))
    if ":dns-ext-ok" not in stdout:
        raise RuntimeError("README DNS quick check: expected output missing")


def main():
    for example in EXAMPLES:
        run_doc_expression(*example)
    run_dns_quick_check()
    print(f"\nPASS: {len(EXAMPLES) + 1} documentation examples", flush=True)


if __name__ == "__main__":
    main()

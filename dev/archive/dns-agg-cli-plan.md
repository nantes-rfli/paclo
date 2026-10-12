# DNS Aggregation CLI Plan (Phase E)

## Scope
Two developer tools under `examples/`:
- `dns-topn`: rank DNS/TLS dimensions (rcode, rrtype, qname, sni, alpn, etc.).
- `dns-qps`: bucket DNS traffic over time.

## CLI Rules
- Optional args can be skipped with `_`.
- Output formats: `edn | jsonl | csv`.
- Async mode is opt-in (`--async`, buffer mode, dropping mode, timeout cancel).
- Punycode conversion is opt-in and failure-tolerant.

## Output Contracts
- `dns-topn` rows: `{:key .. :count .. :bytes .. :pct ..}`.
- `dns-qps` rows: `{:t .. :key .. :count .. :bytes ..}`.
- Metadata must be printed to stderr for smoke tests.

## Validation
- Smoke tests live in `test/examples/smoke_test.clj`.
- Fixtures: `test/resources/dns-sample.pcap`, `dns-synth-small.pcap`, and TLS SNI/ALPN samples.
- README and docs must show one minimal command per tool.

## Next Actions
1. Keep CLI flags backward-compatible through v1.0.0.
2. Add one large-file async regression test for timeout and drop counters.
3. Keep CSV headers and field order stable.

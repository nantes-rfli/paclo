# Pipeline Plan (Phase A/B)

## Goal
Validate `packets -> xform -> write-pcap!` performance and reliability for typical replay workflows.

## Baseline (historical)
- decode=false, 100k packets, drop<60B: ~0.37s
- decode=true, 100k packets: ~1.36s
- dns-sample (4 packets): ~7.9ms

## Direction
- Keep transform logic in transducers.
- Avoid unnecessary map retention in hot paths.
- Reuse buffers and minimize allocations in write paths.
- Preserve predictable behavior for `:max`, `:decode?`, and error handling.

## Tooling
- Benchmark entrypoint: `examples.pipeline-bench`.
- Optional GC logging via runtime flags.
- Verify both throughput and output correctness.

## Next Actions
1. Add one benchmark profile for async pipelines.
2. Record results in README only when deltas are significant.
3. Keep micro-bench scripts simple and reproducible.

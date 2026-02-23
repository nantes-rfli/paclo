# decode-ext API Plan (Phase B)

## Goal
Provide a stable post-decode hook API so optional protocol enrichers can be added without changing `paclo.core/packets`.

## Design
- Hook shape: `packet-map -> packet-map`.
- Hooks run only when `:decoded` exists and `:decode-error` is absent.
- Public operations: `register!`, `unregister!`, `installed`, `apply!`, `with-hooks`.
- Invalid hook output (`nil` or non-map) is ignored.
- Hook failures are swallowed by default; optional `:on-error` can receive diagnostics.

## Contract
- Hook execution order follows registration order.
- Re-registering the same key moves that key to the end.
- `unregister!` removes both handler and order entry.
- Base decode result must stay intact unless a hook explicitly updates fields.

## Current Status
- API implemented in `paclo.decode-ext`.
- DNS and TLS enrichers integrate through this API.
- Core behavior covered by tests in `test/paclo/decode_ext_test.clj`.

## Next Actions
1. Keep hook API as internal-stable until v1.0.0.
2. Add one focused test for `with-hooks` nesting behavior.
3. Keep docs in `docs/extensions.md` aligned with real behavior.

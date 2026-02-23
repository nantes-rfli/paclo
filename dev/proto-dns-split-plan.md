# DNS Extension Split Notes (2025-12-04)

## Decision
Do not split DNS extension into a separate artifact before v1.0.0.

## Rationale
- Current package size does not justify artifact complexity.
- Operational overhead (release, CI, dependency matrix) is higher than benefit.
- Existing `:dns-ext` alias already provides optional loading behavior.

## Revisit Trigger
Re-evaluate split only if one of these happens:
1. Extension dependency graph grows materially.
2. Release cadence diverges between core and DNS extension.
3. Users request independent versioning.

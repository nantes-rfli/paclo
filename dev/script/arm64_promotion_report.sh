#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   dev/script/arm64_promotion_report.sh [lookback_days] [min_success_rate] [max_rerun_rate] [max_duration_ratio]
#
# Example:
#   dev/script/arm64_promotion_report.sh 14 0.95 0.05 1.5

LOOKBACK_DAYS="${1:-14}"
MIN_SUCCESS_RATE="${2:-0.95}"
MAX_RERUN_RATE="${3:-0.05}"
MAX_DURATION_RATIO="${4:-1.5}"

repo="$(gh repo view --json nameWithOwner -q .nameWithOwner)"
default_branch="$(gh repo view --json defaultBranchRef -q .defaultBranchRef.name)"
workflow_id="$(gh api "repos/${repo}/actions/workflows" --jq '.workflows[] | select(.path==".github/workflows/ci.yml") | .id')"
cutoff_iso="$(date -u -v-"${LOOKBACK_DAYS}"d +"%Y-%m-%dT%H:%M:%SZ")"

samples_file="$(mktemp)"
: > "${samples_file}"

for page in 1 2 3 4 5 6 7 8 9 10; do
  rows="$(
    gh api "repos/${repo}/actions/workflows/${workflow_id}/runs?branch=${default_branch}&status=completed&per_page=100&page=${page}" \
      | jq -r --arg cutoff "${cutoff_iso}" '.workflow_runs[] | select(.created_at >= $cutoff) | "\(.id)\t\(.created_at)\t\(.run_attempt // 1)"'
  )"

  [ -z "${rows}" ] && continue

  while IFS=$'\t' read -r run_id created_at run_attempt; do
    [ -z "${run_id}" ] && continue
    jobs="$(gh api "repos/${repo}/actions/runs/${run_id}/jobs?per_page=100")"

    arm_conclusion="$(echo "${jobs}" | jq -r '.jobs[] | select(.name=="arm64-monitor") | .conclusion' | head -n 1)"
    [ -z "${arm_conclusion}" ] && continue

    arm_duration="$(
      echo "${jobs}" \
        | jq -r '.jobs[] | select(.name=="arm64-monitor") | if (.started_at and .completed_at) then ((.completed_at|fromdateiso8601)-(.started_at|fromdateiso8601)) else null end' \
        | head -n 1
    )"
    x64_duration="$(
      echo "${jobs}" \
        | jq -r '.jobs[] | select((.name|contains("compatibility-matrix")) and (.name|contains("linux-jdk21"))) | if (.started_at and .completed_at) then ((.completed_at|fromdateiso8601)-(.started_at|fromdateiso8601)) else null end' \
        | head -n 1
    )"

    jq -n \
      --argjson run_id "${run_id}" \
      --arg created_at "${created_at}" \
      --argjson run_attempt "${run_attempt}" \
      --arg arm_conclusion "${arm_conclusion}" \
      --argjson arm_duration_sec "${arm_duration:-null}" \
      --argjson x64_duration_sec "${x64_duration:-null}" \
      '{run_id:$run_id,created_at:$created_at,run_attempt:$run_attempt,arm_conclusion:$arm_conclusion,arm_duration_sec:$arm_duration_sec,x64_duration_sec:$x64_duration_sec}' \
      >> "${samples_file}"
  done <<< "${rows}"
done

if [ ! -s "${samples_file}" ]; then
  jq -n --arg cutoff "${cutoff_iso}" --argjson lookback_days "${LOOKBACK_DAYS}" '{
    lookback_days: $lookback_days,
    cutoff_iso: $cutoff,
    sample_count: 0,
    eligible_for_required_gate: false,
    note: "No arm64-monitor samples found in lookback window"
  }'
  rm -f "${samples_file}"
  exit 0
fi

jq -s \
  --arg cutoff "${cutoff_iso}" \
  --argjson lookback_days "${LOOKBACK_DAYS}" \
  --argjson min_success_rate "${MIN_SUCCESS_RATE}" \
  --argjson max_rerun_rate "${MAX_RERUN_RATE}" \
  --argjson max_duration_ratio "${MAX_DURATION_RATIO}" \
  '
  def pct(n; d): if d==0 then 0 else (n/d) end;
  . as $rows
  | ($rows|length) as $total
  | ($rows|map(select(.arm_conclusion=="success"))|length) as $success
  | ($rows|map(select(.run_attempt>1))|length) as $rerun
  | ($rows|map(select(.arm_duration_sec!=null and .x64_duration_sec!=null and .x64_duration_sec>0) | (.arm_duration_sec / .x64_duration_sec))) as $ratios
  | ($rows|map(.created_at)|min) as $earliest
  | {
      lookback_days: $lookback_days,
      cutoff_iso: $cutoff,
      sample_count: $total,
      earliest_sample: $earliest,
      window_covered: ($earliest <= $cutoff),
      success_rate: (pct($success; $total)),
      rerun_rate: (pct($rerun; $total)),
      max_duration_ratio: (if ($ratios|length)==0 then null else ($ratios|max) end),
      thresholds: {
        min_success_rate: $min_success_rate,
        max_rerun_rate: $max_rerun_rate,
        max_duration_ratio: $max_duration_ratio
      },
      eligible_for_required_gate: (
        ($earliest <= $cutoff)
        and (pct($success; $total) >= $min_success_rate)
        and (pct($rerun; $total) < $max_rerun_rate)
        and ((if ($ratios|length)==0 then 999 else ($ratios|max) end) <= $max_duration_ratio)
      )
    }
  ' "${samples_file}"

rm -f "${samples_file}"

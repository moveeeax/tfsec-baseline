#!/usr/bin/env bash
# tfsec-baseline scan runner.
#
# 1. Audits the accountable suppressions file (fails on expired / unjustified waivers)
#    and the inline skip comments in TARGET (fails on any without a matching waiver).
# 2. Merges the curated baseline skip-list with the active, audited waivers.
# 3. Runs checkov with the custom rules and writes SARIF for code scanning.
#
# Env / args:
#   TARGET        directory to scan            (default: .)
#   SUPPRESSIONS  suppressions YAML            (default: .tfsec-baseline/suppressions.yaml)
#   SARIF         SARIF output path            (default: results.sarif)
#   SOFT_FAIL     "true" -> always exit 0      (default: false)
#   INLINE        unwaived inline skips: error|warn|off  (default: error)
#   TODAY         override date for the audit  (default: real today)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${TARGET:-${1:-.}}"
SUPPRESSIONS="${SUPPRESSIONS:-.tfsec-baseline/suppressions.yaml}"
SARIF="${SARIF:-results.sarif}"
SOFT_FAIL="${SOFT_FAIL:-false}"
INLINE="${INLINE:-error}"
CONFIG="${CONFIG:-$HERE/baseline/checkov.yaml}"
CHECKS_DIR="$HERE/baseline/checks"

audit_args=(--file "$SUPPRESSIONS")
if [ -n "${TODAY:-}" ]; then
  audit_args+=(--today "$TODAY")
fi

# Read the human-maintained baseline skip-list out of the config file.
baseline_skips="$(python3 - "$CONFIG" <<'PY'
import sys, yaml
with open(sys.argv[1]) as fh:
    cfg = yaml.safe_load(fh) or {}
print(",".join(cfg.get("skip-check", []) or []))
PY
)"

waiver_skips=""
if [ -f "$SUPPRESSIONS" ]; then
  echo ">> auditing suppressions: $SUPPRESSIONS"
  # A broken/expired waiver is a hard failure — do not let a stale skip through.
  python3 "$HERE/tools/suppression_audit.py" "${audit_args[@]}" \
    --scan-inline "$TARGET" --inline "$INLINE"
  waiver_skips="$(python3 "$HERE/tools/suppression_audit.py" "${audit_args[@]}" --emit-checkov-skips)"
else
  echo ">> no suppressions file at $SUPPRESSIONS (nothing to waive)"
  if [ "$INLINE" != "off" ]; then
    # No waiver file means no inline skip can be covered; still report them.
    echo ">> auditing inline skips in: $TARGET"
    python3 "$HERE/tools/suppression_audit.py" --file /dev/null \
      --scan-inline "$TARGET" --inline "$INLINE"
  fi
fi

skips="$baseline_skips"
[ -n "$waiver_skips" ] && skips="${skips:+$skips,}$waiver_skips"
echo ">> effective skip-check: ${skips:-<none>}"

set +e
checkov -d "$TARGET" \
  --framework terraform \
  --external-checks-dir "$CHECKS_DIR" \
  ${skips:+--skip-check "$skips"} \
  --output cli --output sarif --output-file-path console,"$SARIF" \
  --compact
rc=$?
set -e

echo ">> checkov exit: $rc  (SARIF: $SARIF)"
if [ "$SOFT_FAIL" = "true" ]; then
  exit 0
fi
exit "$rc"

#!/usr/bin/env bash
# codescan — multi-language security scan (SAST + secrets + dependencies).
#
# usage: scripts/codescan.sh [path] [-o outdir]
#
# env:
#   FAIL_ON_SECRETS=1  exit 1 if gitleaks finds a secret (default 1)
#   FAIL_ON_SAST=0     exit 1 if semgrep finds anything     (default 0)
#   SARIF=0            also emit SARIF for GitHub code scanning (default 0)
set -uo pipefail

TARGET="${1:-.}"
[ "${TARGET:0:1}" = "-" ] && TARGET="."
[ -d "$TARGET" ] || { echo "not a directory: $TARGET" >&2; exit 2; }
TARGET="$(cd "$TARGET" && pwd)"

OUT="${OUT:-$TARGET/.codescan}"
while [ $# -gt 0 ]; do
  case "$1" in -o|--out) OUT="$2"; shift 2;; *) shift;; esac
done
mkdir -p "$OUT"

FAIL_ON_SECRETS="${FAIL_ON_SECRETS:-1}"
FAIL_ON_SAST="${FAIL_ON_SAST:-0}"
SARIF="${SARIF:-0}"

echo "target : $TARGET"
echo "reports: $OUT"
echo

RULES=(--config=p/security-audit --config=p/secrets --config=p/owasp-top-ten)

echo "[1/3] semgrep (SAST)"
semgrep scan "${RULES[@]}" --metrics=off --quiet \
  --json -o "$OUT/semgrep.json" "$TARGET" 2>"$OUT/semgrep.log"
[ "$SARIF" = "1" ] && semgrep scan "${RULES[@]}" --metrics=off --quiet \
  --sarif -o "$OUT/semgrep.sarif" "$TARGET" 2>>"$OUT/semgrep.log"
SG=$(jq '.results | length' "$OUT/semgrep.json" 2>/dev/null || echo "?")

echo "[2/3] gitleaks (secrets)"
gitleaks detect --source "$TARGET" --no-banner --exit-code 0 \
  --report-format json --report-path "$OUT/gitleaks.json" >"$OUT/gitleaks.log" 2>&1 \
  || gitleaks dir "$TARGET" --no-banner --exit-code 0 \
       --report-format json --report-path "$OUT/gitleaks.json" >"$OUT/gitleaks.log" 2>&1
GL=$(jq 'length' "$OUT/gitleaks.json" 2>/dev/null || echo "?")

echo "[3/3] trivy (deps, IaC, misconfig)"
trivy fs --scanners vuln,secret,misconfig --quiet \
  --format json -o "$OUT/trivy.json" "$TARGET" 2>"$OUT/trivy.log"
[ "$SARIF" = "1" ] && trivy fs --scanners vuln,secret,misconfig --quiet \
  --format sarif -o "$OUT/trivy.sarif" "$TARGET" 2>>"$OUT/trivy.log"
TV=$(jq '[.Results[]?.Vulnerabilities[]?] | length' "$OUT/trivy.json" 2>/dev/null || echo "?")

echo
echo "================ SUMMARY ================"
printf "semgrep code findings : %s\n" "$SG"
printf "gitleaks secrets      : %s\n" "$GL"
printf "trivy vulnerabilities : %s\n" "$TV"
echo

if [ "$SG" != "?" ] && [ "$SG" != "0" ]; then
  echo "-- semgrep by severity --"
  jq -r '.results | group_by(.extra.severity)[] | "\(.[0].extra.severity)\t\(length)"' "$OUT/semgrep.json"
  echo
  echo "-- top findings --"
  jq -r '.results | sort_by(.extra.severity) | reverse | .[:25][] |
    "[\(.extra.severity)] \(.check_id | split(".") | last)\n    \(.path):\(.start.line)\n    \(.extra.message | gsub("\n";" ") | .[0:150])"' \
    "$OUT/semgrep.json"
fi

if [ "$TV" != "?" ] && [ "$TV" != "0" ]; then
  echo
  echo "-- trivy critical/high --"
  jq -r '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL" or .Severity=="HIGH")] | .[:25][] |
    "[\(.Severity)] \(.PkgName) \(.InstalledVersion) — \(.VulnerabilityID)\n    fixed in: \(.FixedVersion // "no fix")"' \
    "$OUT/trivy.json"
fi

if [ "$GL" != "?" ] && [ "$GL" != "0" ]; then
  echo
  echo "-- secrets --"
  jq -r '.[:25][] | "[\(.RuleID)] \(.File):\(.StartLine)  (commit \(.Commit[0:8] // "worktree"))"' "$OUT/gitleaks.json"
fi

echo
echo "Full reports: $OUT/"

RC=0
if [ "$FAIL_ON_SECRETS" = "1" ] && [ "$GL" != "?" ] && [ "$GL" != "0" ]; then
  echo "FAIL: $GL secret(s) detected." >&2; RC=1
fi
if [ "$FAIL_ON_SAST" = "1" ] && [ "$SG" != "?" ] && [ "$SG" != "0" ]; then
  echo "FAIL: $SG SAST finding(s)." >&2; RC=1
fi
exit $RC

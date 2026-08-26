#!/usr/bin/env bash
# VulnerableApp runtime regression — platform APIs only, not lab exploits.
# Usage: BASE_URL=http://127.0.0.1:9090/VulnerableApp ./e2e_apis.sh
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:9090/VulnerableApp}"
BASE_URL="${BASE_URL%/}"
BODY="$(mktemp)"
trap 'rm -f "$BODY"' EXIT INT TERM

say() { printf '%s\n' "$*"; }
fail() { say "ERROR: $*"; exit 1; }

http_code() {
  curl -sS "$@" -o "$BODY" -w '%{http_code}'
}

assert_code() {
  got="$1"
  want="$2"
  what="$3"
  case ",$want," in
    *",$got,"*) say "ok $what -> $got" ;;
    *)
      say "body preview:"
      head -c 400 "$BODY"; echo
      fail "$what expected one of [$want], got $got"
      ;;
  esac
}

wait_ready() {
  say "==> Wait platform JSON at $BASE_URL/allEndPointJson"
  i=0
  while [ "$i" -lt 90 ]; do
    code="$(curl -sS -o "$BODY" -w '%{http_code}' "$BASE_URL/allEndPointJson" || true)"
    if [ "$code" = "200" ]; then
      say "app_ready"
      return 0
    fi
    i=$((i + 1))
    sleep 2
  done
  fail "allEndPointJson not 200 after wait"
}

wait_ready

say "==> Legacy UI"
code="$(http_code "$BASE_URL/")"
assert_code "$code" "200" "GET /"

say "==> Vulnerability catalog (UI backbone — not a lab exploit)"
code="$(http_code "$BASE_URL/allEndPointJson")"
assert_code "$code" "200" "GET /allEndPointJson"
python3 - <<PY
import json
d=json.load(open("$BODY"))
assert isinstance(d, list) and len(d) >= 5, (type(d), len(d) if isinstance(d, list) else d)
print(f"allEndPointJson_count={len(d)}")
PY

code="$(http_code "$BASE_URL/VulnerabilityDefinitions")"
assert_code "$code" "200" "GET /VulnerabilityDefinitions"
python3 - <<PY
import json
d=json.load(open("$BODY"))
assert isinstance(d, list) and len(d) >= 5, (type(d), len(d) if isinstance(d, list) else d)
print(f"VulnerabilityDefinitions_count={len(d)}")
PY

say "==> Scanner ground-truth endpoints (DAST/SAST metadata, not attack)"
code="$(http_code "$BASE_URL/scanner/dast")"
assert_code "$code" "200" "GET /scanner/dast"
python3 - <<PY
import json
d=json.load(open("$BODY"))
assert isinstance(d, list) and len(d) >= 5, (type(d), len(d) if isinstance(d, list) else d)
print(f"scanner_dast_count={len(d)}")
PY

code="$(http_code "$BASE_URL/scanner/sast")"
assert_code "$code" "200" "GET /scanner/sast"
python3 - <<PY
import json
d=json.load(open("$BODY"))
assert isinstance(d, list) and len(d) >= 1, (type(d), d[:1] if isinstance(d, list) else d)
print(f"scanner_sast_count={len(d)}")
PY

code="$(http_code "$BASE_URL/scanner/metadata")"
assert_code "$code" "200" "GET /scanner/metadata"

code="$(http_code "$BASE_URL/sitemap.xml")"
assert_code "$code" "200" "GET /sitemap.xml"
grep -q 'urlset' "$BODY" || fail "sitemap.xml missing urlset"

say "==> Runtime API regression PASSED"

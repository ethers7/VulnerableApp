#!/usr/bin/env bash
# VulnerableApp runtime regression — platform APIs only, not lab exploits.
# Usage: BASE_URL=http://127.0.0.1:9090/VulnerableApp ./e2e_apis.sh
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:9090/VulnerableApp}"
BASE_URL="${BASE_URL%/}"
OUT_DIR="${E2E_JUNIT_DIR:-test-results}"
export BODY
BODY="$(mktemp)"
CASES="$(mktemp)"
trap 'rm -f "$BODY" "$CASES"' EXIT INT TERM

say() { printf '%s\n' "$*"; }
fail() { say "ERROR: $*"; exit 1; }

record() {
  name="$1"
  ok="$2"
  detail="${3:-}"
  printf '%s\t%s\t%s\n' "$name" "$ok" "$detail" >>"$CASES"
  if [ "$ok" = "1" ]; then
    say "ok $name${detail:+ -> $detail}"
  else
    say "FAIL $name${detail:+ -> $detail}"
  fi
}

http_code() {
  curl -sS "$@" -o "$BODY" -w '%{http_code}'
}

assert_code() {
  got="$1"
  want="$2"
  what="$3"
  case ",$want," in
    *",$got,"*) record "$what" 1 "$got" ;;
    *)
      say "body preview:"
      head -c 400 "$BODY"; echo
      record "$what" 0 "expected [$want] got $got"
      ;;
  esac
}

json_ok() {
  python3 -c "$1"
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
if json_ok 'import json,os; d=json.load(open(os.environ["BODY"])); assert isinstance(d,list) and len(d)>=5; print("count",len(d))'; then
  record "allEndPointJson_shape" 1
else
  record "allEndPointJson_shape" 0
fi

code="$(http_code "$BASE_URL/allEndPoint")"
assert_code "$code" "200" "GET /allEndPoint"
if grep -q '<pre>' "$BODY"; then
  record "allEndPoint_html_pre" 1
else
  record "allEndPoint_html_pre" 0 "missing <pre>"
fi

code="$(http_code "$BASE_URL/VulnerabilityDefinitions")"
assert_code "$code" "200" "GET /VulnerabilityDefinitions"
if json_ok 'import json,os; d=json.load(open(os.environ["BODY"])); assert isinstance(d,list) and len(d)>=5; print("count",len(d))'; then
  record "VulnerabilityDefinitions_shape" 1
else
  record "VulnerabilityDefinitions_shape" 0
fi

say "==> Scanner ground-truth endpoints (DAST/SAST metadata, not attack)"
code="$(http_code "$BASE_URL/scanner/dast")"
assert_code "$code" "200" "GET /scanner/dast"
if json_ok 'import json,os; d=json.load(open(os.environ["BODY"])); assert isinstance(d,list) and len(d)>=5; print("count",len(d))'; then
  record "scanner_dast_shape" 1
else
  record "scanner_dast_shape" 0
fi

HDRS="$(mktemp)"
code="$(curl -sS -D "$HDRS" -o "$BODY" -w '%{http_code}' "$BASE_URL/scanner")"
assert_code "$code" "200" "GET /scanner"
if grep -qi '^Deprecation:' "$HDRS"; then
  record "scanner_deprecation_header" 1
else
  record "scanner_deprecation_header" 0 "missing Deprecation"
fi
if grep -qi '^Sunset:' "$HDRS"; then
  record "scanner_sunset_header" 1
else
  record "scanner_sunset_header" 0 "missing Sunset"
fi
rm -f "$HDRS"

code="$(http_code "$BASE_URL/scanner/sast")"
assert_code "$code" "200" "GET /scanner/sast"
if json_ok 'import json,os; d=json.load(open(os.environ["BODY"])); assert isinstance(d,list) and len(d)>=1; print("count",len(d))'; then
  record "scanner_sast_shape" 1
else
  record "scanner_sast_shape" 0
fi

code="$(http_code "$BASE_URL/scanner/metadata")"
assert_code "$code" "200" "GET /scanner/metadata"

code="$(http_code "$BASE_URL/sitemap.xml")"
assert_code "$code" "200" "GET /sitemap.xml"
if grep -q 'urlset' "$BODY"; then
  record "sitemap_urlset" 1
else
  record "sitemap_urlset" 0 "missing urlset"
fi

say "==> Scanner benchmark comparator (empty findings — no lab exploit)"
code="$(curl -sS -o "$BODY" -w '%{http_code}' \
  -H 'Content-Type: application/json' \
  -d '{"tool":"remedia-gate","scanType":"DAST","findings":[]}' \
  "$BASE_URL/scanner/benchmark")"
assert_code "$code" "200" "POST /scanner/benchmark empty findings"
if json_ok 'import json,os; d=json.load(open(os.environ["BODY"])); assert isinstance(d,dict) and d.get("tool")=="remedia-gate" and "coverage" in d and "totalExpected" in d; print("coverage",d.get("coverage"),"totalExpected",d.get("totalExpected"))'; then
  record "scanner_benchmark_shape" 1
else
  record "scanner_benchmark_shape" 0
fi

code="$(curl -sS -o "$BODY" -w '%{http_code}' \
  -H 'Content-Type: application/json' \
  -d '{"findings":[]}' \
  "$BASE_URL/scanner/benchmark")"
assert_code "$code" "400" "POST /scanner/benchmark missing tool"

mkdir -p "$OUT_DIR"
export CASES OUT_DIR
python3 - <<'PY'
import os, time, xml.etree.ElementTree as ET
cases = []
with open(os.environ["CASES"]) as f:
    for line in f:
        line = line.rstrip("\n")
        if not line:
            continue
        name, ok, detail = line.split("\t", 2)
        cases.append((name, ok == "1", detail))
out = os.path.join(os.environ["OUT_DIR"], "functional-junit.xml")
suite = ET.Element(
    "testsuite",
    name="vulnerableapp_live_http",
    tests=str(len(cases)),
    failures=str(sum(1 for _, ok, _ in cases if not ok)),
    timestamp=time.strftime("%Y-%m-%dT%H:%M:%S"),
)
for name, ok, detail in cases:
    tc = ET.SubElement(suite, "testcase", classname="vulnerableapp.live", name=name)
    if not ok:
        fail = ET.SubElement(tc, "failure", message=detail or "failed")
        fail.text = detail
ET.ElementTree(suite).write(out, encoding="utf-8", xml_declaration=True)
failed = [n for n, ok, _ in cases if not ok]
if failed:
    print("FAILED:", ", ".join(failed))
    raise SystemExit(1)
print("functional_ok")
PY

say "==> Runtime API regression PASSED"

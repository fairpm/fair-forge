# 📋 slsa-attest.sh

> Generates a SLSA v1.0 in-toto provenance attestation for a package, with a gap analysis showing which SLSA level requirements are met and which are missing.

**TL;DR:** Produces a portable, verifiable record of what this scan confirmed about the package's build. The attestation is an observer report — it documents what the toolkit could verify, not what it directly witnessed.

---

## 🎯 Purpose

SLSA (Supply chain Levels for Software Artifacts) provides a framework for describing how trustworthy a software build is. `slsa-attest.sh` generates a SLSA v1.0 in-toto statement that:

- Documents the artifact's SHA-256 digest
- Records the builder identity and policy URI (if provided)
- Describes the build context (source repo, commit, trigger)
- Assesses which SLSA level requirements (L0–L3) are satisfied
- Embeds an observer disclaimer because the toolkit did not witness the build

This output is useful as an audit artefact: stored alongside the package, it captures the state of provenance evidence at the time of evaluation.

---

## 🔧 Options

| Flag | Description |
|---|---|
| `-s, --silent` | Suppress progress messages |
| `-j, --json` | JSON output to stdout |
| `-sj, -js` | Silent + JSON |
| `-v, --verbose` | Show additional detail |
| `-l, --level N` | SLSA level to assert: 0–3 (default: 0) |
| `-o, --output-dir DIR` | Directory for output files |
| `--no-file` | Output to stdout only; do not write files |
| `--builder-id URI` | Builder identity URI (required for L1+) |
| `--policy-uri URI` | Policy or trust root URI (required for L1+) |
| `--disclaimer-uri URI` | Observer disclaimer URI |
| `--source-type TYPE` | Archive source type |
| `--source-repo URL` | Source repository URL |
| `--source-commit SHA` | Source commit hash |
| `--source-ref REF` | Source git ref |
| `--build-trigger TYPE` | Build trigger type |
| `--build-id ID` | CI run ID |
| `--meta-json FILE` | Path to toolkit meta.json (enriches attestation with scan results) |
| `--version` | Print version and exit |

---

## 🏆 SLSA Level Requirements

| Level | Requirements | Flags needed |
|---|---|---|
| L0 | Artifact digest + observer disclaimer (always produced) | None |
| L1 | + Builder ID declared + Policy URI declared | `--builder-id`, `--policy-uri`, `--level 1` |
| L2 | + Source repo verified + Commit hash recorded | `--source-repo`, `--source-commit`, `--level 2` |
| L3 | + Hermetic build declared + Signed provenance | Requires upstream attestation; see notes |

The script assesses which level is actually satisfied by the provided context and reports any gaps in `remediation[]`.

---

## 📤 Output

Two files are produced:

| File | Contents |
|---|---|
| `<n>.slsa-L<N>.provenance.json` | SLSA v1.0 in-toto statement (the attestation itself) |
| `<n>.slsa-assessment.json` | Gap analysis — which requirements are met/missing |

The assessment file is what `sbom-toolkit.sh` merges into `meta.json` under the `slsa_attestation` key.

---

## 💡 Examples

```bash
# Observer-only (L0) — minimum useful output
./slsa-attest.sh akismet.5.3.zip

# L1 with builder and policy
./slsa-attest.sh \
  --level 1 \
  --builder-id https://github.com/actions/runner \
  --policy-uri  https://your-org.example/package-policy \
  akismet.5.3.zip

# L2 with full source context
./slsa-attest.sh \
  --level 2 \
  --builder-id  https://github.com/actions/runner \
  --policy-uri  https://your-org.example/package-policy \
  --source-repo github.com/Automattic/akismet \
  --source-commit abc123def456 \
  --source-ref refs/tags/5.3 \
  akismet.5.3.zip
```

---

## ⚠️ Known Limitations

- The generated attestation is **not cryptographically signed**. For full SLSA L2+, sign the attestation with `cosign` or equivalent after generation.
- L3 hermetic build verification cannot be assessed by the toolkit — it requires the build system itself to make this claim. The assessment will always mark L3 as not satisfiable from an observer position.
- The observer disclaimer is always embedded. Downstream systems that consume SLSA attestations should check for this disclaimer and handle observer attestations differently from build-system-generated ones.

---

<sub>Scripts licensed MIT · Documentation [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) · © Package Profiler Contributors</sub>

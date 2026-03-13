# vuln-scan-risk.jq — CVSS-weighted risk scoring from Grype output
#
# Input:  Grype JSON  (.matches array required)
# Output: {
#   weighted_risk, cvss_critical, cvss_high, cvss_medium, cvss_low, cvss_negligible,
#   vuln_counts: {critical, high, medium, low, negligible, unknown, total},
#   scoring_notes: {method, cvss_version, unscored_vulns, weights}
# }
#
# Weights: Critical×100, High×25, Medium×5, Low×1, Negligible×0.1
# CVSS preference: 3.1 > 3.0 > 2.0 > first available

[.matches[] |
    {
        severity: (.vulnerability.severity // "Unknown"),
        cvss: (
            first(
                (.vulnerability.cvss[]? |
                 select(.version == "3.1") |
                 .metrics.baseScore),
                (.vulnerability.cvss[]? |
                 select(.version == "3.0") |
                 .metrics.baseScore),
                (.vulnerability.cvss[]? |
                 select(.version != null) |
                 .metrics.baseScore),
                0
            )
        )
    }
] as $items |

# Severity counts
{
    critical:   ([  $items[] | select(.severity == "Critical")   ] | length),
    high:       ([  $items[] | select(.severity == "High")       ] | length),
    medium:     ([  $items[] | select(.severity == "Medium")     ] | length),
    low:        ([  $items[] | select(.severity == "Low")        ] | length),
    negligible: ([  $items[] | select(.severity == "Negligible") ] | length),
    unknown:    ([  $items[] | select(
                        .severity != "Critical" and
                        .severity != "High" and
                        .severity != "Medium" and
                        .severity != "Low" and
                        .severity != "Negligible"
                    ) ] | length)
} as $counts |

# CVSS sums per severity
{
    critical:   ([ $items[] | select(.severity == "Critical")   | .cvss ] | add // 0),
    high:       ([ $items[] | select(.severity == "High")       | .cvss ] | add // 0),
    medium:     ([ $items[] | select(.severity == "Medium")     | .cvss ] | add // 0),
    low:        ([ $items[] | select(.severity == "Low")        | .cvss ] | add // 0),
    negligible: ([ $items[] | select(.severity == "Negligible") | .cvss ] | add // 0)
} as $sums |

# Unscored: items where cvss == 0 and severity is known
([ $items[] | select(.cvss == 0 and (.severity == "Critical" or .severity == "High" or
                                      .severity == "Medium"   or .severity == "Low"   or
                                      .severity == "Negligible")) ] | length) as $unscored |

{
    weighted_risk: (
        ($sums.critical   * 100) +
        ($sums.high       *  25) +
        ($sums.medium     *   5) +
        ($sums.low        *   1) +
        ($sums.negligible *   0.1)
    ),
    cvss_critical:   $sums.critical,
    cvss_high:       $sums.high,
    cvss_medium:     $sums.medium,
    cvss_low:        $sums.low,
    cvss_negligible: $sums.negligible,
    vuln_counts: ($counts + {total: ($counts.critical + $counts.high + $counts.medium +
                                     $counts.low + $counts.negligible + $counts.unknown)}),
    scoring_notes: {
        method:        "cvss_weighted",
        cvss_version:  "3.1_preferred",
        unscored_vulns: $unscored,
        weights:        "Critical×100 High×25 Medium×5 Low×1 Negligible×0.1"
    }
}

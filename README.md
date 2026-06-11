# Serverless Forensics: Automated Compromise Detection via Welch's t-test

## Dataset Description

This repository contains the raw statistical dataset
(`serverless-forensics-t-test.csv`) used for the inferential
quantitative evaluation discussed in Section 4 of the manuscript.

Runtime telemetry was captured from an experimental, multi-component
AWS serverless testbed architecture. Logs were ingested via Amazon
CloudWatch and metric filters were applied to extract functional
attributes under both controlled baseline (non-compromised) and
active adversary exploit (compromised) conditions across four
application-layer vulnerability vectors:

1. Event Injection
2. Broken Authentication
3. Sensitive Data Exposure
4. Security Misconfiguration

---

## Dataset Structure

The dataset consists of **48 independent runtime observations**:
n = 6 per group (compromised / non-compromised) per attack scenario,
across 4 scenarios.

| Column | Description |
|---|---|
| `group` | Operational state: `compromised` or `non-compromised` |
| `attack_scenario` | The targeted vulnerability exploit scenario |
| `duration_ms` | Primary dependent variable — total Lambda execution time (ms) |
| `avg_incidence_rate` | CWE average incidence rate for the attack class |
| `total_occurrences` | Total NVD occurrence count for the attack class |

---

## Statistical Alignment

Four independent Welch's t-tests were conducted — one per attack
scenario — with Bonferroni correction applied to control familywise
Type I error (α_adj = 0.05 / 4 = 0.0125).

| Attack Scenario | t | df_W | p (adj.) | Cohen's d |
|---|---|---|---|---|
| Event Injection | 37.55 | 9.92 | < 0.001 | 21.68 |
| Broken Authentication | 26.89 | 6.42 | < 0.001 | 15.53 |
| Sensitive Data Exposure | 22.25 | 8.93 | < 0.001 | 12.85 |
| Security Misconfiguration | 31.03 | 8.21 | < 0.001 | 17.91 |

All adjusted p-values survive Bonferroni correction. Mean execution
durations in compromised environments ranged from 3.1× to 6.5×
greater than non-compromised baselines across all four scenarios.

Per-scenario Levene's test results indicated equal variances
(p > 0.05 in all cases); however, Welch's t-test was retained as
the primary test for conservatism and methodological consistency.

---

## Threshold-Based Classification

Under both midpoint and μ_nc + 2σ_nc threshold strategies, the
framework achieved

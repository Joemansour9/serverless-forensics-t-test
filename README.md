# Serverless Forensics: Welch's t-test Dataset

Dataset supporting the paper "Serverless Forensics: A Statistical Analysis of
Execution Telemetry Under Controlled Attack Conditions" (Mansour,
Shanmugam, Yeo).

## File

`serverless_forensics_final.csv` — 96 rows, one per Lambda invocation.

## Columns

| Column | Description |
|---|---|
| `group` | Experimental condition: `compromised` or `non-compromised` |
| `attack_scenario` | One of four OWASP-derived attack scenarios: Event Injection, Broken Authentication, Sensitive Data Exposure, Security Misconfiguration |
| `duration_ms` | AWS Lambda execution duration (ms), captured via CloudWatch — the primary dependent variable analyzed with Welch's t-test |
| `avg_incidence_rate` | Average CWE incidence rate (%) for the corresponding attack category, from the MITRE CWE / NVD mapping (see Table 1 of the paper). Constant across all 12 rows within a scenario — this is a scenario-level value, not per-invocation. |
| `total_occurrences` | Total NVD vulnerability record count for the corresponding CWE cluster, as of the query date (see Table 1 of the paper). Also scenario-level, not per-invocation. |

## Structure

n = 12 independent invocations per condition (compromised / non-compromised)
per attack scenario, across 4 scenarios = 96 total observations.

## Reproducing the analysis

For each attack scenario, a Welch's t-test (unequal-variance, two-tailed) was
computed comparing `duration_ms` between the `compromised` and
`non-compromised` groups, with Bonferroni correction (α = 0.05/4 = 0.0125)
applied across the four scenarios. See Sections 3.4 and 4.6–4.7 of the paper
for full methodology.

## License

CC BY 4.0

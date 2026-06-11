# Serverless Forensics: Automated Compromise Detection via Welch's t-test

Replication dataset and analysis for the paper *Serverless Forensics: Automated Compromise Detection via Welch's t-test* (Mansour, Shanmugam & Yeo, submitted to *Cybersecurity*, Springer Nature).

## Repository Contents

| File | Description |
|---|---|
| `serverless_forensics_final_v13.csv` | Raw execution duration telemetry (96 observations) |

## Dataset Structure

The CSV contains 96 observations across four AWS Lambda attack scenarios, 12 compromised and 12 non-compromised invocations per scenario.

| Column | Description |
|---|---|
| `group` | `compromised` or `non-compromised` |
| `attack_scenario` | One of four OWASP-derived attack classes |
| `duration_ms` | Lambda function execution duration (ms) |
| `avg_incidence_rate` | CWE average incidence rate for the attack class |
| `total_occurrences` | NVD total CVE occurrences for the attack class |

## Attack Scenarios

- Event Injection
- Broken Authentication
- Sensitive Data Exposure
- Security Misconfiguration

## Key Results

| Attack Scenario | t | df_W | Cohen's d | p |
|---|---|---|---|---|
| Event Injection | 7.73 | 13.21 | 3.16 | <0.001 |
| Broken Authentication | 8.92 | 17.06 | 3.64 | <0.001 |
| Sensitive Data Exposure | 12.44 | 15.05 | 5.08 | <0.001 |
| Security Misconfiguration | 11.21 | 18.95 | 4.58 | <0.001 |

Bonferroni-adjusted significance threshold: α = 0.0125. All four null hypotheses rejected.

## Replication

```python
import pandas as pd
from scipy import stats

df = pd.read_csv('serverless_forensics_final_v13.csv')

for scenario in df['attack_scenario'].unique():
    comp = df[(df['attack_scenario']==scenario) & (df['group']=='compromised')]['duration_ms']
    noncomp = df[(df['attack_scenario']==scenario) & (df['group']=='non-compromised')]['duration_ms']
    t, p = stats.ttest_ind(comp, noncomp, equal_var=False)
    print(f'{scenario}: t={t:.2f}, p={p:.6f}')
```

## Authors

- Joe Mansour — Charles Darwin University / IBM Infrastructure
- Bharanidharan Shanmugam — Charles Darwin University (corresponding)
- Kheng Cher Yeo — Charles Darwin University

## License

Data released for academic replication purposes. Please cite the associated paper if you use this dataset.# Serverless Forensics: Automated Compromise Detection via Welch's t-test

Replication dataset and analysis for the paper *Serverless Forensics: Automated Compromise Detection via Welch's t-test* (Mansour, Shanmugam & Yeo, submitted to *Cybersecurity*, Springer Nature).

## Repository Contents

| File | Description |
|---|---|
| `serverless_forensics_final_v13.csv` | Raw execution duration telemetry (96 observations) |

## Dataset Structure

The CSV contains 96 observations across four AWS Lambda attack scenarios, 12 compromised and 12 non-compromised invocations per scenario.

| Column | Description |
|---|---|
| `group` | `compromised` or `non-compromised` |
| `attack_scenario` | One of four OWASP-derived attack classes |
| `duration_ms` | Lambda function execution duration (ms) |
| `avg_incidence_rate` | CWE average incidence rate for the attack class |
| `total_occurrences` | NVD total CVE occurrences for the attack class |

## Attack Scenarios

- Event Injection
- Broken Authentication
- Sensitive Data Exposure
- Security Misconfiguration

## Key Results

| Attack Scenario | t | df_W | Cohen's d | p |
|---|---|---|---|---|
| Event Injection | 7.73 | 13.21 | 3.16 | <0.001 |
| Broken Authentication | 8.92 | 17.06 | 3.64 | <0.001 |
| Sensitive Data Exposure | 12.44 | 15.05 | 5.08 | <0.001 |
| Security Misconfiguration | 11.21 | 18.95 | 4.58 | <0.001 |

Bonferroni-adjusted significance threshold: α = 0.0125. All four null hypotheses rejected.

## Replication

```python
import pandas as pd
from scipy import stats

df = pd.read_csv('serverless_forensics_final_v13.csv')

for scenario in df['attack_scenario'].unique():
    comp = df[(df['attack_scenario']==scenario) & (df['group']=='compromised')]['duration_ms']
    noncomp = df[(df['attack_scenario']==scenario) & (df['group']=='non-compromised')]['duration_ms']
    t, p = stats.ttest_ind(comp, noncomp, equal_var=False)
    print(f'{scenario}: t={t:.2f}, p={p:.6f}')
```

## Authors

- Joe Mansour — Charles Darwin University / IBM Infrastructure
- Bharanidharan Shanmugam — Charles Darwin University (corresponding)
- Kheng Cher Yeo — Charles Darwin University

## License

Data released for academic replication purposes. Please cite the associated paper if you use this dataset.

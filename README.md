# Serverless Forensics: Automated Compromise Detection via Welch's t-test

## Dataset Description
This repository contains the raw statistical dataset file (`serverless-forensics-t-test.csv`) utilized to perform the inferential quantitative evaluation discussed in Section 4 of the manuscript. 

The tracking telemetry was captured from an experimental, multi-component AWS serverless testbed architecture. Runtime logs were ingested via Amazon CloudWatch and metric filters were applied to extract functional attributes under both controlled baseline (non-compromised) and active adversary exploit (compromised) conditions across four key application-layer vulnerability vectors:
1. Event Injection
2. Broken Authentication
3. Sensitive Data Exposure
4. Security Misconfiguration

## Dataset Structure
The dataset consists of **48 independent runtime observations** split equally between the experimental groups ($n = 24$ for the compromised environment; $n = 24$ for the non-compromised environment). 

The columns within the CSV file map directly to the univariate statistics and parameters detailed in the paper:
* **Group:** Classification of the operational state (`compromised` vs. `non-compromised`).
* **Attack Type:** The targeted vulnerability exploit scenario.
* **Serverless Duration (ms):** The primary dependent runtime variable reflecting the total execution time of the cloud function handler. These values directly generated the descriptive central tendencies in **Table 3** ($\mu = 1712.83\text{ ms}$ for compromised samples vs. $\mu = 373.95\text{ ms}$ for baseline samples).
* **Incidence Rate / Occurrences:** Complementary vulnerability tracking factors cross-referenced with Common Weakness Enumeration (CWE) root cause mappings (**Table 1**).

## Statistical Alignment
The data explicitly reflects the unequal population variances ($\sigma^2_{\text{non-compromised}} = 13945.87$ vs. $\sigma^2_{\text{compromised}} = 4088.20$) that led to the rejection of homoscedasticity via Levene's Test ($F(1, 46) = 6.260, p = 0.016$). 

Consequently, this dataset provides the empirical mathematical foundation validating the application of **Welch's $t$-test** adjustments ($df = 35.42$, calculated test statistic $t = 48.84$, two-sided significance $p < 0.001$), leading to the definitive rejection of the null hypothesis ($H_0$) as presented in **Table 4**.

"""
analysis.py -- Reproduces the statistical analyses reported in
"Serverless Forensics: A Statistical Analysis of Execution Telemetry
Under Controlled Attack Conditions" (Mansour, Shanmugam, Yeo) directly
from the raw dataset serverless_forensics_final.csv.

Reproduces:
  - Descriptive statistics per scenario/group (mean, SD, SE, skewness, kurtosis)
  - Per-scenario Welch's t-tests with Bonferroni correction, 95% CIs,
    Cohen's d, and Levene's test for variance heterogeneity
  - Threshold classification under the midpoint strategy and the
    mu_nc + 2*sigma_nc strategy (in-sample)
  - Leave-one-out cross-validation (LOOCV) of the midpoint strategy

Usage:
    python analysis.py [path/to/serverless_forensics_final.csv]

Requires: pandas, numpy, scipy
"""

import sys
import math

import numpy as np
import pandas as pd
from scipy import stats

SCENARIOS = [
    "Event Injection",
    "Broken Authentication",
    "Sensitive Data Exposure",
    "Security Misconfiguration",
]
ALPHA = 0.05
N_TESTS = 4
ALPHA_ADJ = ALPHA / N_TESTS


def load_data(path):
    df = pd.read_csv(path)
    required = {"group", "attack_scenario", "duration_ms"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Dataset is missing required columns: {missing}")
    return df


def get_group(df, scenario, group):
    return df.loc[
        (df.attack_scenario == scenario) & (df.group == group), "duration_ms"
    ].to_numpy()


def cohens_d(a, b):
    na, nb = len(a), len(b)
    sa, sb = np.std(a, ddof=1), np.std(b, ddof=1)
    pooled_sd = math.sqrt(((na - 1) * sa**2 + (nb - 1) * sb**2) / (na + nb - 2))
    return (np.mean(a) - np.mean(b)) / pooled_sd


def welch_ci_and_df(a, b, conf=0.95):
    """95% CI for the mean difference (a - b) and Welch-Satterthwaite df."""
    na, nb = len(a), len(b)
    ma, mb = np.mean(a), np.mean(b)
    va, vb = np.var(a, ddof=1), np.var(b, ddof=1)
    se = math.sqrt(va / na + vb / nb)
    df_w = (va / na + vb / nb) ** 2 / (
        (va / na) ** 2 / (na - 1) + (vb / nb) ** 2 / (nb - 1)
    )
    t_crit = stats.t.ppf(1 - (1 - conf) / 2, df_w)
    diff = ma - mb
    return diff, diff - t_crit * se, diff + t_crit * se, df_w


def descriptive_stats(df):
    print("=" * 88)
    print("DESCRIPTIVE STATISTICS (duration_ms, per scenario/group)")
    print("=" * 88)
    rows = []
    for scenario in SCENARIOS:
        for group in ["compromised", "non-compromised"]:
            vals = get_group(df, scenario, group)
            n = len(vals)
            mean = vals.mean()
            sd = vals.std(ddof=1)
            se = sd / math.sqrt(n)
            # NOTE: uses scipy's default (population/biased) skewness and
            # kurtosis estimators to match the values reported in the paper.
            skew = stats.skew(vals)
            kurt = stats.kurtosis(vals)  # excess kurtosis, Fisher's definition
            rows.append(
                dict(scenario=scenario, group=group, n=n, mean=mean, sd=sd, se=se,
                     skewness=skew, kurtosis=kurt)
            )
            print(
                f"{scenario:28s} {group:16s} n={n:2d}  mean={mean:8.2f}  sd={sd:7.2f}  "
                f"se={se:6.2f}  skew={skew:6.3f}  kurt={kurt:6.3f}"
            )
    return pd.DataFrame(rows)


def welch_tests(df):
    print()
    print("=" * 88)
    print(f"WELCH'S T-TESTS, BONFERRONI-CORRECTED (alpha_adj = {ALPHA}/{N_TESTS} = {ALPHA_ADJ})")
    print("=" * 88)
    results = []
    for scenario in SCENARIOS:
        c = get_group(df, scenario, "compromised")
        nc = get_group(df, scenario, "non-compromised")

        t_stat, p_val = stats.ttest_ind(c, nc, equal_var=False)
        diff, ci_lo, ci_hi, df_w = welch_ci_and_df(c, nc)
        d = cohens_d(c, nc)
        lev_f, lev_p = stats.levene(c, nc)

        sig = "significant" if p_val < ALPHA_ADJ else "NOT significant"
        results.append(dict(
            scenario=scenario, diff_ms=diff, ci_lo=ci_lo, ci_hi=ci_hi,
            t=t_stat, df_w=df_w, p=p_val, cohens_d=d, levene_F=lev_f, levene_p=lev_p,
        ))
        print(
            f"{scenario:28s} diff={diff:7.2f} ms  95%CI=[{ci_lo:7.2f}, {ci_hi:7.2f}]  "
            f"t={t_stat:6.2f}  df_W={df_w:5.2f}  p={p_val:.2e} ({sig})  "
            f"d={d:.2f}  Levene F={lev_f:.3f} (p={lev_p:.3f})"
        )
    return pd.DataFrame(results)


def midpoint_thresholds(df):
    return {
        s: (get_group(df, s, "compromised").mean() + get_group(df, s, "non-compromised").mean()) / 2
        for s in SCENARIOS
    }


def mu_plus_2sigma_thresholds(df):
    return {
        s: get_group(df, s, "non-compromised").mean() + 2 * get_group(df, s, "non-compromised").std(ddof=1)
        for s in SCENARIOS
    }


def classify(df, thresholds, label):
    """In-sample classification under a fixed per-scenario threshold dict."""
    print()
    print("=" * 88)
    print(f"THRESHOLD CLASSIFICATION -- {label} (in-sample)")
    print("=" * 88)
    agg = dict(TP=0, FP=0, FN=0, TN=0)
    for scenario in SCENARIOS:
        c = get_group(df, scenario, "compromised")
        nc = get_group(df, scenario, "non-compromised")
        thresh = thresholds[scenario]
        tp = int((c >= thresh).sum())
        fn = len(c) - tp
        tn = int((nc < thresh).sum())
        fp = len(nc) - tn
        agg["TP"] += tp; agg["FP"] += fp; agg["FN"] += fn; agg["TN"] += tn
        print(f"{scenario:28s} threshold={thresh:8.2f} ms  TP={tp:2d} FP={fp:2d} FN={fn:2d} TN={tn:2d}")

    total = sum(agg.values())
    acc = (agg["TP"] + agg["TN"]) / total
    sens = agg["TP"] / (agg["TP"] + agg["FN"])
    spec = agg["TN"] / (agg["TN"] + agg["FP"])
    print(
        f"{'AGGREGATE':28s} {'':19s} TP={agg['TP']:2d} FP={agg['FP']:2d} "
        f"FN={agg['FN']:2d} TN={agg['TN']:2d}  "
        f"accuracy={acc:.4f} ({agg['TP']+agg['TN']}/{total})  "
        f"sensitivity={sens:.4f}  specificity={spec:.4f}"
    )
    return agg, acc, sens, spec


def loocv_midpoint(df):
    """Leave-one-out cross-validation of the midpoint threshold strategy.

    For each held-out observation, the compromised/non-compromised group
    means (and therefore the midpoint threshold) are recomputed from the
    remaining 11 observations in that observation's own group, combined
    with the full 12 observations of the other group -- then the held-out
    observation is classified against that refitted threshold.
    """
    print()
    print("=" * 88)
    print("LEAVE-ONE-OUT CROSS-VALIDATION -- Midpoint strategy")
    print("=" * 88)
    agg = dict(TP=0, FP=0, FN=0, TN=0)
    for scenario in SCENARIOS:
        c = get_group(df, scenario, "compromised")
        nc = get_group(df, scenario, "non-compromised")
        n = len(c)
        s_agg = dict(TP=0, FP=0, FN=0, TN=0)

        for i in range(n):
            train_c = np.delete(c, i)
            thresh = (train_c.mean() + nc.mean()) / 2
            if c[i] >= thresh:
                s_agg["TP"] += 1
            else:
                s_agg["FN"] += 1

        for i in range(n):
            train_nc = np.delete(nc, i)
            thresh = (c.mean() + train_nc.mean()) / 2
            if nc[i] >= thresh:
                s_agg["FP"] += 1
            else:
                s_agg["TN"] += 1

        for k in agg:
            agg[k] += s_agg[k]
        print(f"{scenario:28s} TP={s_agg['TP']:2d} FP={s_agg['FP']:2d} FN={s_agg['FN']:2d} TN={s_agg['TN']:2d}")

    total = sum(agg.values())
    acc = (agg["TP"] + agg["TN"]) / total
    sens = agg["TP"] / (agg["TP"] + agg["FN"])
    spec = agg["TN"] / (agg["TN"] + agg["FP"])
    print(
        f"{'AGGREGATE':28s} TP={agg['TP']:2d} FP={agg['FP']:2d} FN={agg['FN']:2d} TN={agg['TN']:2d}  "
        f"accuracy={acc:.4f} ({agg['TP']+agg['TN']}/{total})  "
        f"sensitivity={sens:.4f}  specificity={spec:.4f}"
    )
    return agg, acc, sens, spec


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "serverless_forensics_final.csv"
    df = load_data(path)

    if len(df) != 96:
        print(f"WARNING: expected 96 rows, found {len(df)}.")

    descriptive_stats(df)
    welch_tests(df)
    classify(df, midpoint_thresholds(df), "Midpoint")
    classify(df, mu_plus_2sigma_thresholds(df), "mu_nc + 2*sigma_nc")
    loocv_midpoint(df)


if __name__ == "__main__":
    main()

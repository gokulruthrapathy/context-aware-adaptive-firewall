"""Metrics expose their denominators and return None for undefined rates."""
import numpy as np
from scipy.stats import beta
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix,
    precision_recall_fscore_support, average_precision_score, roc_auc_score, log_loss)


def rate(numerator, denominator):
    return float(numerator / denominator) if denominator else None


def policy_metrics(is_attack, actions):
    y, a = np.asarray(is_attack, dtype=bool), np.asarray(actions)
    if y.ndim != 1 or a.shape != y.shape or not np.isin(a, [0, 1, 2, 3]).all():
        raise ValueError("Expected aligned binary labels and action codes 0..3")
    na, nb = int(y.sum()), int((~y).sum())
    ab, ac = int(((a == 3) & y).sum()), int(((a >= 2) & y).sum())
    bb, bd = int(((a == 3) & ~y).sum()), int(((a >= 2) & ~y).sum())
    return dict(attack_count=na, benign_count=nb, attack_blocked=ab,
        attack_contained=ac, benign_blocked=bb, benign_disrupted=bd,
        attack_blocking=rate(ab, na), attack_containment=rate(ac, na),
        benign_false_block=rate(bb, nb), benign_disruption=rate(bd, nb))


def binomial_interval(k, n, confidence=0.95):
    """Exact Clopper-Pearson interval, conditional on independent flows."""
    if n == 0:
        return [None, None]
    alpha = 1 - confidence
    return [float(beta.ppf(alpha/2, k, n-k+1)) if k else 0.,
            float(beta.ppf(1-alpha/2, k+1, n-k)) if k < n else 1.]


def with_intervals(metrics):
    result = dict(metrics)
    for name, numerator, denominator in [
        ("attack_blocking", "attack_blocked", "attack_count"),
        ("attack_containment", "attack_contained", "attack_count"),
        ("benign_false_block", "benign_blocked", "benign_count"),
        ("benign_disruption", "benign_disrupted", "benign_count")]:
        result[name+"_ci95"] = binomial_interval(metrics[numerator], metrics[denominator])
    return result


def expected_calibration_error(y, p, bins=10):
    y, p = np.asarray(y, dtype=float), np.asarray(p, dtype=float)
    ids = np.minimum((p*bins).astype(int), bins-1)
    return float(sum((ids == i).mean() * abs(y[ids == i].mean()-p[ids == i].mean())
                     for i in range(bins) if (ids == i).any()))


def classifier_metrics(y, pred, classes, is_attack, p_attack):
    precision, recall, f1, _ = precision_recall_fscore_support(y, pred, labels=classes, average="macro", zero_division=0)
    binary_ok = np.unique(is_attack).size == 2
    return dict(accuracy=float(accuracy_score(y, pred)), macro_precision=float(precision),
        macro_recall=float(recall), macro_f1=float(f1),
        class_order=list(classes), confusion_matrix=confusion_matrix(y, pred, labels=classes).tolist(),
        per_class=classification_report(y, pred, labels=classes, output_dict=True, zero_division=0),
        attack_auroc=float(roc_auc_score(is_attack, p_attack)) if binary_ok else None,
        attack_average_precision=float(average_precision_score(is_attack, p_attack)) if binary_ok else None,
        attack_brier=float(np.mean((np.asarray(is_attack)-p_attack)**2)),
        attack_ece=expected_calibration_error(is_attack, p_attack))


def paired_bootstrap_f1(y, pred_base, pred_context, classes, repeats=500, seed=42, groups=None):
    """Paired resampling of the same test rows, or capture groups when supplied."""
    y, a, b = map(np.asarray, (y, pred_base, pred_context))
    if len(y) == 0 or a.shape != y.shape or b.shape != y.shape:
        raise ValueError("Paired predictions must be nonempty and aligned")
    class_index={label:i for i,label in enumerate(classes)}
    y,a,b=[np.array([class_index[label] for label in arr],dtype=np.int32) for arr in [y,a,b]]
    def score(target,predicted):
        support=np.bincount(target,minlength=len(classes))
        predictions=np.bincount(predicted,minlength=len(classes))
        tp=np.bincount(target[target==predicted],minlength=len(classes))
        return float(np.divide(2*tp,support+predictions,out=np.zeros(len(classes),dtype=float),where=(support+predictions)>0).mean())
    delta=score(y,b)-score(y,a)
    rng = np.random.default_rng(seed)
    group_ids = np.unique(groups) if groups is not None else None
    if group_ids is not None and len(group_ids)<2:
        return dict(delta_macro_f1=delta,
            ci95=[None,None],repeats=0,unit="capture file",seed=seed,
            reason="Fewer than two independent capture groups; cluster uncertainty is not estimable")
    group_rows = {g: np.flatnonzero(np.asarray(groups) == g) for g in group_ids} if groups is not None else None
    deltas = []
    for _ in range(repeats):
        ix = (np.concatenate([group_rows[g] for g in rng.choice(group_ids, len(group_ids), replace=True)])
              if groups is not None else rng.integers(0, len(y), len(y)))
        deltas.append(score(y[ix],b[ix])-score(y[ix],a[ix]))
    return dict(delta_macro_f1=delta,
                ci95=np.quantile(deltas,[.025,.975]).tolist(), repeats=repeats,
                unit="capture file" if groups is not None else "flow", seed=seed)

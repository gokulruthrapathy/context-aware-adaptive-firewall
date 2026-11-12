"""Explicit, independently testable risk scores and simulated action decisions."""
from dataclasses import dataclass, asdict
from itertools import product
import numpy as np

ACTIONS = np.array(["Allow", "Monitor", "Rate-limit", "Block"])


@dataclass(frozen=True)
class Thresholds:
    monitor: float = 25.0
    rate_limit: float = 60.0
    block: float = 79.0

    def __post_init__(self):
        values = np.array([self.monitor, self.rate_limit, self.block], dtype=float)
        if not np.isfinite(values).all() or not (0 <= self.monitor < self.rate_limit < self.block <= 100):
            raise ValueError("Thresholds must satisfy 0 <= monitor < rate_limit < block <= 100")


def attack_probability(probabilities, classes, benign="BENIGN"):
    p = np.asarray(probabilities, dtype=float)
    classes = list(classes)
    if p.ndim != 2 or p.shape[1] != len(classes) or len(set(classes)) != len(classes):
        raise ValueError("Probability columns must correspond exactly to unique class names")
    if classes.count(benign) != 1:
        raise ValueError("Exactly one benign class is required")
    if not np.isfinite(p).all() or (p < 0).any() or (p > 1).any() or not np.allclose(p.sum(axis=1), 1, atol=1e-5):
        raise ValueError("Invalid probability distribution")
    return np.clip(1 - p[:, classes.index(benign)], 0, 1)


def risk_score(p_attack):
    p = np.asarray(p_attack, dtype=float)
    if not np.isfinite(p).all() or ((p < 0) | (p > 1)).any():
        raise ValueError("Attack probabilities must be finite and in [0, 1]")
    return 100.0 * p


def decide(scores, thresholds=Thresholds()):
    """Inclusive lower bounds. Invalid scores are rejected, never silently allowed."""
    s = np.asarray(scores, dtype=float)
    if not np.isfinite(s).all() or ((s < 0) | (s > 100)).any():
        raise ValueError("Risk scores must be finite and in [0, 100]")
    return np.searchsorted([thresholds.monitor, thresholds.rate_limit, thresholds.block], s, side="right")


def select_policy(scores, is_attack, benign_budget=0.05, grid=None):
    """Maximize containment subject to benign disruption budget, using policy split only.

    Ties: higher attack blocking, lower false-blocking, lower disruption, then
    lexicographically smaller cutoffs. Monitor does not count as containment.
    """
    from .metrics import policy_metrics
    y = np.asarray(is_attack, dtype=bool)
    if not 0 <= benign_budget <= 1 or not y.any() or y.all():
        raise ValueError("Policy selection requires both classes and a valid benign budget")
    if grid is None:
        # Monitor is fixed: the objective contains no observation-workload cost.
        grid = [Thresholds(25, r, b) for r, b in product([30,40,50,60,70,80,90,95,99,99.9], [40,50,60,70,79,80,90,95,99,99.9,100]) if r < b]
    rows = []
    for thresholds in grid:
        metrics = policy_metrics(y, decide(scores, thresholds))
        rows.append({**asdict(thresholds), **metrics, "feasible": metrics["benign_disruption"] <= benign_budget})
    feasible = [r for r in rows if r["feasible"]]
    if not feasible:
        # No test-informed relaxation: explicitly return no selected policy.
        return None, rows
    best = min(feasible, key=lambda r: (-r["attack_containment"], -r["attack_blocking"], r["benign_false_block"], r["benign_disruption"], r["monitor"], r["rate_limit"], r["block"]))
    return Thresholds(best["monitor"], best["rate_limit"], best["block"]), rows

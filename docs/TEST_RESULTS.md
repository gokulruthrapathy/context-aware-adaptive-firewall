# Historical version 0.1 software checks

This records the original run, not the current test count. Current execution
evidence is saved with the version 0.2 notebook results; see V2_WORKFLOW.md.

Final source: 17 tests passed using `python -m pytest -q` in the isolated Python 3.12.14 environment.

Tests cover risk boundaries, invalid probabilities, denominator behavior, policy infeasibility, training-only transformations, feature order, zero denominators, causal time ties and expiry, uniform-reference update masks, float32 deduplication, attempted labels, paired bootstrap behavior, timestamp partition boundaries, and the complete train/freeze/evaluate/verify/score workflow.

The integration fixture is synthetic and is used only to test software behavior. It is not included in research performance tables. Real-data experiment verification is recorded separately under each results directory.

Final run: 17 passed in 11.43 seconds. Three pandas deprecation warnings concern future removal of the round-trip CSV parsing argument; the exact executed pandas version is pinned. No test failures occurred.

All four complete result directories independently reconciled successfully: 18 model/seed bundles each, with 19,948 randomized test rows and 6,985 chronological test rows. Checks cover model/source hashes, split IDs, labels, probability order, risk, actions, policy numerators and class-by-action totals.

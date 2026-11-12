# What remains before an IEEE journal submission

Version 0.2 audit fixes, executed CPU notebook and new development results are
documented in docs/V2_WORKFLOW.md and docs/V2_RESULTS.md. Independent confirmation
and a supported research contribution remain outstanding.

## Current conclusion

The supplied presentation and screenshot do not establish a reproducible implementation. This package replaces that missing implementation with new, inspectable code and real pilot experiments. It does not demonstrate that the original slide metrics were correct, and it does not establish a publishable original contribution by itself.

IEEE requires original research, accurate data reporting and appropriate attribution. A working DNN plus hand-selected thresholds is an experimental baseline, not automatically a new scientific method. Choose a specific journal and establish a defensible contribution against relevant recent work before calling the study submission-ready.

## Implemented in this package

| Capability | Evidence |
|---|---|
| Public data provenance and fixed archive | URL, SHA-256 and complete stream audit |
| Explicit label semantics | Attempted attacks map to BENIGN; label counts exported |
| Conservative feature-vector deduplication and conflict exclusion | Data audit and row-signature partitioning |
| Separate train/tune/calibration/policy/test records | Saved split manifests and counts |
| Train-only preprocessing | Saved medians, rate caps, scaler and feature order |
| Baseline and engineered/history DNN variants | 78, 92 and 100 features with controlled architecture |
| Conventional comparators | Random forest, logistic regression and prior-only classifier |
| Checkpoint selection | External tuning log loss and epoch histories |
| Binary probability calibration | Dedicated calibration records and Brier/ECE reports |
| Explicit risk and decision boundaries | Tested formulas and inclusive lower bounds |
| Validation-only policy search | Full candidate export and fixed benign budget |
| Frozen held-out evaluation | Model hashes and frozen selection manifest |
| Repeated seeds and uncertainty | Three seeds, paired row/capture bootstrap and binomial intervals |
| Per-class and policy evidence | Confusion matrices, probabilities, row IDs and class-by-action counts |
| Chronological distribution-shift challenge | Separate binary temporal protocol |
| Reproducible result figures | Saved PNG/PDF figures generated from result files |

## Remaining research work, prioritized

1. **Establish and test a novel contribution.** Compare recent, closely related context-aware IDS/policy methods, then state one falsifiable hypothesis. A possible research direction is improved blocking under a specified benign-disruption budget using causal traffic context. The current pipeline tests pieces of that hypothesis but does not prove novelty. Report negative outcomes.
2. **Increase independent evidence.** Add an independently collected dataset or a controlled cloud testbed, with documented schema mapping and attack semantics. Two partitions or protocols from CICIDS2017 are not two independent datasets. The archive used here is the corrected 2021 version; repeat critical results on the newer corrected release and document differences.
3. **Use full-stream history and deployment-realistic timing.** The current context sees a sampled stream. Replay the complete completed-flow stream to test observation density, flow-completion delay, memory growth and throughput. Full-flow statistics cannot substantiate prevention before a flow completes. If early prevention is claimed, implement and evaluate prefix-flow features with matching training data.
4. **Strengthen split and uncertainty design.** Add source/session-grouped evaluations, independent days/captures and multiple independent environments. Audit near duplicates. Five or fewer source-file clusters are insufficient for strong generalization claims. Very rare classes require more representative data, not invented or redistributed test samples.
5. **Validate policy effectiveness.** Rate-limit plus Block is an action-assignment proxy here. A real containment claim requires measured attack success/failure, application goodput, benign latency, packet loss and enforcement delay in an isolated authorized testbed. Monitor overhead also needs measurement. Implement an OS/cloud adapter only after defining that lab's operating system and topology.
6. **Improve selection methodology if required by the contribution.** Add prespecified nested validation or grouped cross-validation, comparable tuning budgets across methods and calibrated uncertainty constraints. The current policy budget is a validation point estimate and may fail after distribution shift. Do not retune on an already observed test set.
7. **Add targeted robustness studies.** Perturb plausible measurement noise, missing data and traffic-mix shifts. If adversarial robustness, zero-day detection, concept drift or continuous learning is claimed, implement the corresponding threat model and controlled experiments. These claims are currently unsupported. A quantum model, RNN or LSTM is not required simply because the slides mention it.
8. **Complete the manuscript against a named journal's scope.** Document problem, contribution, related work, equations, data and label policy, split design, baselines, ablations, uncertainty, compute budget, limitations and reproducibility. Verify every bibliography entry against its primary publication. Replace inconsistent live-enforcement claims and the slide figures with results generated from the saved artifacts.
9. **Prepare the submission materials.** Confirm author contributions, author order, affiliations, corresponding author, consent from every co-author, data/code licenses, funding and conflict disclosures. Use the chosen journal's current template and submission checklist. IEEE's current policy requires disclosure of AI-generated content, including code, in the acknowledgments. Identify the AI system and its specific contribution and have the author team verify the content. The author team must approve the final manuscript.

## Claims that are currently defensible

- A reproducible offline experiment was implemented and executed on a specified public corrected flow dataset, if the corresponding run-complete markers are present.
- Specific models, sampled partitions and risk policies achieved the numerical results in the saved reports.
- History features use only strictly earlier completed retained flows and no true labels.

## Claims that are not established

- Journal-level novelty, superiority to the current state of the art, live cloud security effectiveness, first-packet prevention, automatic live firewall updates, broad zero-day generalization, continuous adaptation/retraining, or reproduction of the original deck's 95.23% containment.
- A universal 5% benign disruption guarantee. That is a validation selection target, not a deployment guarantee.
- Independent replication merely from changing random seeds or evaluating another split of the same capture.

## Primary references

- IEEE ethical requirements: https://journals.ieeeauthorcenter.ieee.org/become-an-ieee-journal-author/publishing-ethics/ethical-requirements/
- IEEE article structure: https://journals.ieeeauthorcenter.ieee.org/create-your-ieee-journal-article/create-the-text-of-your-article/structure-your-article/
- IEEE submission and AI-content disclosure policy: https://journals.ieeeauthorcenter.ieee.org/become-an-ieee-journal-author/publishing-ethics/guidelines-and-policies/submission-and-peer-review-policies/
- Original dataset: https://www.unb.ca/cic/datasets/ids-2017.html
- Corrected 2021 release and caveats: https://intrusion-detection.distrinet-research.be/WTMC2021/tools_datasets.html
- Later correction study: https://intrusion-detection.distrinet-research.be/CNS2022/index.html
- Attempted-label guidance: https://intrusion-detection.distrinet-research.be/CNS2022/Dataset_Download.html

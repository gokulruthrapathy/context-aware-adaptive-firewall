# Package contents, version 0.2

Includes current source, configurations, tests, CI workflow, runnable Colab notebook,
locally executed notebook, documentation, historical manuscript draft, all four
preserved original studies (72 model bundles), and the two new CPU development
studies (36 bundles). Results retain source snapshots, frozen policies, model hashes,
probabilities, decisions, metrics, figures, verification and completion records.

The new run is `results/research_v2_20261112T052723Z_6ce995/`; its parent also contains
the software-test log, installed packages, combined tables, state demonstration and
an independent policy-count check. See docs/V2_RESULTS.md for interpretation.

The package excludes raw/prepared datasets, Python environments, caches, Git metadata
and generated package metadata. Original local datasets remain in data/raw and
data/prepared; a new immutable preparation is in data/prepared_v2. After moving the
package, use the notebook to download, hash-check and prepare the public data.

PACKAGE_MANIFEST.json records SHA-256 of included files except itself. Versioned
archives are preserved. The older firewall-research.zip predates this release.

Repository: https://github.com/gokulruthrapathy/context-aware-adaptive-firewall
Development branch: research-fixes-colab. New results reuse examined benchmark
partitions and are not independent confirmation. No journal submission, online
adaptation or live firewall enforcement has been performed.

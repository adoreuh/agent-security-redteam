# External Dataset Catalog

External deepfake detection datasets registered as **probe/evaluation only**.
They do NOT enter the V5 core training graph.

## Usage Policy

1. **Probe-only:** These datasets are used only for external pressure testing
   of the forensic pipeline, NOT for training or fine-tuning.
2. **No label pollution:** External labels never leak into the WeChat path
   attribution training split.
3. **Split isolation:** External data is partitioned by source dataset;
   never mixed with V5's WeChat internal training data.
4. **Real-fake pairing:** When available, real-fake pairs MUST preserve
   same-source relationships to prevent shortcut learning.

## Registered Datasets

### DeepfakeBench
- **Source:** https://github.com/SCLBD/DeepfakeBench
- **Content:** Unified preprocessing, training configs, frame-level AUC
- **Protocols:** In-domain, cross-domain evaluation
- **Use:** External baseline for comparison only
- **Status:** Not downloaded (reference only)

### DF40 (NeurIPS 2024)
- **Source:** https://arxiv.org/abs/2406.13495
- **Content:** 40 forgery techniques
- **Protocols:** Cross-forgery, cross-domain, unknown forgery/domain, one-vs-all
- **Key finding:** Complex SOTA methods not significantly better than Xception
  baseline in new settings
- **Use:** Baseline reference; confirms need for independent evaluation
- **Status:** Not downloaded

### Deepfake-Eval-2024
- **Source:** https://arxiv.org/abs/2503.02857
- **Content:** 45h video, 56.5h audio, 1,975 images; 88 websites, 52 languages
- **Key finding:** SOTA AUC drops ~50% (video), ~48% (audio), ~45% (image)
  vs older benchmarks
- **Use:** Evidence that academic benchmarks ≠ real-world robustness
- **Status:** Not downloaded

### GenD
- **Source:** https://arxiv.org/abs/2508.06248
- **Content:** Vision encoder fine-tuning (~0.03% params), 32-frame sampling
- **Performance:** 91.2/91.4/91.6 AUROC (CLIP/PE/DINO variants)
- **Key finding:** Same-source real-fake pairing reduces shortcut learning
- **Use:** Architectural reference; validates pairing requirement
- **Status:** Not downloaded

## Integration Points

- External benchmark results go in `reports/external_benchmarks/`
- Probe evaluation scripts go in `probes/`
- No external dataset labels enter `v5_core/training/`

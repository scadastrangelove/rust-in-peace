# Canary fixtures

`results_sample/` is a pre-baked results directory in the same shape that
`vuln-pipeline run canary` would produce — one `result.json` per planted bug,
each with a PoC that genuinely crashes the canary binary under ASAN.

It exists so you can try `vuln-pipeline patch` (and `report`) without first
burning find-agent tokens:

```bash
vuln-pipeline patch targets/canary/fixtures/results_sample --model <model>
```

Output lands in `targets/canary/fixtures/results_sample/reports/bug_NN/`.
Delete that `reports/` subdir between runs if you want a clean slate.

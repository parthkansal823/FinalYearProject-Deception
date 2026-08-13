# Cost table change log

Every entry here is a re-freeze of `config/costs.yaml`. Entries dated after
the first traffic generation are a methodological red flag and must be
justified in the paper's limitations section (spec §6.5, §7.3).

## 2026-08-13

- **reason:** Phase 0 initial freeze, before any traffic generation
- **previous digest:** `PENDING_INITIAL_FREEZE`
- **new digest:** `45ceb0e8c5915583342f67e9e1ae20815e805e47f51516b6ad2780050a0c2e57`
- **matrix:** `{"attack": {"bait": 8.0, "divert": -20.0, "pass": 25.0}, "benign": {"bait": 1.0, "divert": 200.0, "pass": 0.0}}`
- **fusion:** `{"bias": 0.0, "epsilon": 1e-06, "method": "logit_linear", "w_automation": 0.0, "w_malice": 1.0}`

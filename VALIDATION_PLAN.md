# Validation plan

PICEE-PA v1.0 is a design proposal. A credible next version should test the proposal rather than add more prose.

## Baselines

1. Agent with ordinary IAM/tool permissions and conventional logs.
2. Agent governed by an existing runtime/policy stack without PICEE-PA administrative fields.
3. PICEE-PA profile mapped to the same runtime.

## Hypotheses and metrics

- H1: lower unauthorized-action rate and privilege amplification.
- H2: faster and more complete incident reconstruction using AEB.
- H3: AEE/AEB portability across at least two enforcement backends.
- H4: meaningful-approval UI improves detection compared with checkbox approval.
- H5: delegation attenuation limits recursive privilege growth.

Measure false allow/deny, bypass rate, reconstruction time/completeness, overhead, approval quality, rollback success, drift detection and developer effort.

## Required adversarial scenarios

Prompt injection, confused deputy, shared credentials, privilege escalation, tool/schema poisoning, policy TOCTOU, recursive delegation, irreversible side effects, audit tampering, data exfiltration, shadow agents and model/tool version drift.

## Publication threshold

Do not call PICEE-PA “validated” until the implementation, test dataset, configurations and results are publicly reproducible and at least one independent reviewer/implementer has challenged the results.

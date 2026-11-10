---
name: add-assessment-rule
description: Add or change an apim-assess assessment rule with authoritative Microsoft grounding, applicability, evidence, a deterministic evaluator, and focused tests. Use for YAML catalog entries, rule evaluators, severity or threshold changes, and WAF or MCSB mappings within the active iteration.
---

# Add or change an assessment rule

## Confirm scope and grounding

1. Read `docs\project-scope.md`, the rule catalog and active iteration in
   `docs\project-plan.md`, and `.github\copilot-instructions.md`.
   Do not add a later iteration's collector or rule to unblock current work.
2. Inspect the existing rule schema, evaluator registry, snapshot and
   findings models, scoring logic, and nearby tests. Reuse those contracts.
   If they do not exist yet, build only the minimal rule-engine foundation
   authorized by Iteration 1; do not create an alternate rule framework.
3. Reuse the catalog's stable rule ID. For a genuinely new requirement,
   check for duplicate coverage before introducing a new ID and document
   its relationship to the approved scope.
4. Verify the recommendation with current Microsoft Learn service guidance,
   APIM REST and policy references, and the APIM MCSB baseline as applicable.
   Confirm Classic versus v2 tiers, gateway type, protocol, region, and API
   version support. Record reference URLs and relevant capability limits.
5. Use WAF pillar codes `REL`, `SEC`, `COST`, `OPS`, and `PERF`; distinguish
   the Well-Architected Framework from a web application firewall. Map MCSB
   controls only when the evidence supports that control, not by analogy.

## Define the decision before the evaluator

Write down:

- The condition being assessed and its business impact.
- Required signals and their source, including collection coverage.
- Positive and negative evidence, plus unavailable or unsupported signals.
- Applicable environments, SKUs, gateways, and workload types.
- Default severity, allowed thresholds, waiver behavior, and remediation.

Keep unsupported, not-applicable, and unknown outcomes distinct from a
verified pass or failure using the engine's existing result model. If the
current model cannot represent missing evidence safely, address that
contract within the approved slice rather than guessing a healthy default.
Configuration alone does not prove runtime enforcement or reachability.

## Implement using existing contracts

1. Add or update the YAML metadata with ID, title, pillar and supported
   MCSB mappings, severity, applicability, description, business impact,
   remediation, Microsoft reference URLs, and evaluator binding. Follow the
   actual schema and its validators; do not invent parallel field names.
2. Implement a deterministic Python evaluator over the sanitized snapshot
   or effective policy model. Do not call Azure or an LLM from a rule.
   Honor the engine's environment, waiver, and threshold handling.
3. For XML policy rules, use resolved sections and execution context.
   Account for `<base />`, fragments, and conditional branches; a policy
   name appearing in raw XML is not proof of effective protection.
4. Emit resource-scoped, sanitized evidence and actionable remediation.
   Preserve existing IDs and result contracts, and avoid double-counting
   one finding in pillar or portfolio scores.
5. Preserve severity and scoring when optional AI narratives are enabled.

## Verify and hand off

1. Add focused cases for a failure, a pass, unavailable evidence, and
   relevant applicability boundaries. Cover threshold edges, inherited
   policy context, or waivers when the changed behavior depends on them.
2. Load the rule through the real catalog and evaluator dispatch path, not
   only by calling its evaluator directly. Check that evidence, severity,
   scoring, and report output remain consistent where affected.
3. Run supported targeted tests and relevant configured checks. Use
   synthetic sanitized fixtures; never save live secrets as test data.
4. Summarize the rule ID, grounding references, decision logic, applicability,
   and checks. Return to the active delivery task; this skill does not
   independently push, open a PR, merge, or advance an iteration.

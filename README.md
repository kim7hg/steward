<p align="center">
  <img src="assets/logo.png" alt="Steward" width="200">
</p>

# Steward

Runtime governance for AI systems.

A steward does not execute the system. A steward decides what the system is allowed to do, when it must stop, and who is accountable.

```bash
cat response.txt | steward evaluate --contract contract.yaml
# Exit 0: PROCEED | Exit 1: ESCALATE | Exit 2: BLOCKED
```

---

## The Problem

As AI systems gain autonomy, governance can no longer live outside the system. Policies describe intent but don't enforce behavior. Evaluations score outputs but don't stop actions. "Human-in-the-loop" collapses at scale.

When automation moves faster than accountability, trust collapses.

The question is no longer *"Can the system do this?"*

It's *"Who answers when it does?"*

---

## Runtime Governance

Steward answers three questions—deterministically:

1. **Should this proceed?**
2. **Should a human intervene?**
3. **Should automation stop—now?**

These map to three states with a strict dominance order:

| State | Meaning | Dominance |
|-------|---------|-----------|
| **BLOCKED** | Boundary violated—stop immediately | Highest |
| **ESCALATE** | Uncertainty detected—human decides | Middle |
| **PROCEED** | All conditions met—continue | Lowest |

`BLOCKED > ESCALATE > PROCEED`—non-configurable, by design.

If any lens returns BLOCKED, the outcome is BLOCKED. No negotiation. No override.

---

## Governance Guarantees

**Accountability as data** — Every contract requires an explicit `accountable_human`. Responsibility is enforced, not implied.

**Uncertainty as a governance signal** — Low confidence does not guess. It deterministically escalates to a human.

**Evidence as an invariant** — A BLOCKED decision without cited evidence is invalid. Enforcement requires justification.

**Governance is not intelligence** — Governance is constraint, escalation, and ownership. Synthesis is policy, not persuasion.

---

## How It Works

```
Contract + Output → [5 Lenses in parallel] → Synthesizer → PROCEED | ESCALATE | BLOCKED
                                                               │
                                     confidence = min(all lenses), evidence required
```

Human-authored contracts define criteria. Five lenses evaluate independently—no debate, no persuasion, no shared state. A deterministic synthesizer reduces findings to a verdict.

LLMs assist evaluation. Policy decides outcomes.

No scoring. No probabilistic judgment. No hidden discretion.

---

## Quick Start

### CLI

```bash
steward evaluate --contract contract.yaml --output response.txt --format json
```

Exit codes: `0` PROCEED, `1` ESCALATE, `2` BLOCKED, `3` Error

#### Deterministic Evaluation

For reproducible results (golden tests, audits, debugging), use the `--evaluated-at` flag:

```bash
steward evaluate --contract contract.yaml --output response.txt \
    --evaluated-at 2025-12-20T00:00:00Z
```

This produces identical JSON output for the same inputs, including the timestamp.

### Rust

```rust
use steward_core::{Contract, Output, evaluate};

let contract = Contract::from_yaml_file("contract.yaml")?;
let output = Output::text("Your order #12345 shipped yesterday.");
let result = evaluate(&contract, &output)?;

match result.state {
    State::Proceed { .. } => { /* continue */ }
    State::Escalate { decision_point, .. } => { /* present to human */ }
    State::Blocked { violation } => { /* stop, notify accountable_human */ }
}
```

#### Deterministic Evaluation

For reproducible results, use the `*_at` API variants:

```rust
use chrono::{DateTime, Utc};
use steward_core::{Contract, Output, evaluate_at};

let timestamp: DateTime<Utc> = "2025-12-20T00:00:00Z".parse()?;
let result = evaluate_at(&contract, &output, timestamp)?;
// result.evaluated_at is now 2025-12-20T00:00:00Z
```

### Python

```python
from steward import Contract, Output, evaluate

contract = Contract.from_yaml_file("contract.yaml")
output = Output.text("Your order #12345 shipped yesterday.")
result = evaluate(contract, output)

if result.is_blocked():
    print(f"BLOCKED: {result.violation.rule_id}")
```

### TypeScript

```typescript
import { Contract, Output, evaluate, isBlocked } from '@steward/core';

const contract = Contract.fromYamlFile('contract.yaml');
const output = Output.text('Your order #12345 shipped yesterday.');
const result = evaluate(contract, output);

if (isBlocked(result.state.stateType)) {
  console.log(`BLOCKED: ${result.state.violation.ruleId}`);
}
```

### Julia

```julia
# Julia binding via C ABI
using Steward

contract = Steward.Contract.from_yaml_file("contract.yaml")
output = Steward.Output.text("Your order #12345 shipped yesterday.")
result = Steward.evaluate(contract, output)

if Steward.is_blocked(result)
    println("BLOCKED: ", result.violation.rule_id)
end
```

---

## Example Contract

```yaml
name: "Customer Support Response"

intent:
  purpose: "Generate helpful responses to customer inquiries"
  never_optimize_away:
    - id: "N1"
      rule: "Human escalation path"

boundaries:
  may_do_autonomously:
    - id: "A1"
      rule: "Answer factual questions about products"
  must_escalate_when:
    - id: "E1"
      rule: "Customer explicitly requests human agent"
  invalidated_by:
    - id: "B1"
      rule: "Customer PII exposed in response"

accountability:
  answerable_human: "support-escalation@company.com"
```

Every contract names an accountable human. This is not metadata—it is the enforcement target.

---

## Domain Packs

Contracts for regulated industries with compliance mapping:

| Domain | Contract | Regulations |
|--------|----------|-------------|
| **Healthcare** | [healthcare.yaml](contracts/healthcare.yaml) | HIPAA, GINA, 42 CFR Part 2 |
| **Finance** | [finance.yaml](contracts/finance.yaml) | SEC Reg BI, Advisers Act, FINRA |
| **Legal** | [legal.yaml](contracts/legal.yaml) | ABA Model Rules, Privilege |
| **Education** | [education.yaml](contracts/education.yaml) | FERPA, COPPA, IDEA |
| **HR** | [hr.yaml](contracts/hr.yaml) | Title VII, ADA, EEOC AI Guidance |

See [Compliance Mapping](docs/compliance-mapping.md) for detailed regulatory coverage.

---

## Architecture

```
steward-core (deterministic, NO LLM)      steward-runtime (optional LLM)
├── 5 independent lenses                  ├── Provider registry
│   ├── Dignity & Inclusion               ├── Parallel orchestration
│   ├── Boundaries & Safety               ├── Circuit breaker + budgets
│   ├── Restraint & Privacy               └── Fallback chain
│   ├── Transparency & Contestability
│   └── Accountability & Ownership        Language bindings
├── Synthesizer (strict policy)           ├── Python (PyO3)
└── Evidence linking                      ├── Node.js (napi-rs)
                                          └── Julia (C ABI)
```

The core is deterministic. Even when models assist evaluation, synthesis remains policy—not intelligence.

---

## What Steward Is Not

**Not an LLM-as-a-judge** — Criteria are human-authored. Models that grade themselves hide accountability.

**Not a quality scorer** — Numeric scores obscure boundary violations and invite threshold gaming.

**Not a recommendation engine** — ESCALATE surfaces decisions to humans without ranking them.

**Not a replacement for human judgment** — Steward identifies when human judgment is required. It never substitutes for it.

Most AI safety tools answer: *"Is this output acceptable?"*

Steward answers: *"Should this action occur at all, should a human intervene, or must automation stop—now?"*

This distinction is architectural, not philosophical.

---

## Contract Validation

Contracts are validated against a JSON Schema before parsing. Invalid contracts fail fast with clear error messages:

```bash
$ steward contract validate invalid.yaml
Contract validation failed: Missing required field 'intent.purpose'
```

The schema is embedded at compile time from `spec/contract.schema.json`, ensuring validation works offline and matches the expected contract structure.

---

## Documentation

| Document | Description |
|----------|-------------|
| [Steward Design](docs/Steward.md) | Architecture, governance calculus, and lens specifications |
| [Blueprint Specs](docs/steward-blueprint-specs.md) | Authoritative specification |
| [Compliance Mapping](docs/compliance-mapping.md) | Regulatory requirements by domain |
| [Contract Schema](spec/contract.schema.json) | JSON Schema for contracts |

---

## Installation

```bash
# Rust
cargo install --path crates/steward-cli

# Python
cd bindings/python && maturin develop

# Node.js
cd bindings/node && npm run build

# Julia
cargo build --release -p steward-julia
```

*Package registry publishing (crates.io, PyPI, npm) coming soon.*

---

## Context / Related Work

### Policy and Governance Context

The EU Cyber Resilience Act (CRA) introduces the concept of "open-source software stewards" as legal entities responsible for supporting the cybersecurity of FOSS used in commercial products. This governance model—and its implications for fairness, accountability, and transparency—was examined at [ACM FAccT 2025](https://dl.acm.org/doi/10.1145/3715275.3732032) as a novel but still ambiguous approach to software governance.

### How Steward Differs

Steward is not a policy role, certification body, or institutional steward.

It is a **runtime governance primitive**.

Where policy frameworks define *who* is responsible, Steward defines *how* responsibility is enforced at execution time:

- Human-authored contracts, not implicit norms
- Deterministic evaluation, not probabilistic judgment
- Evidence-backed verdicts, not advisory signals
- Explicit `accountable_human` fields, not diffuse responsibility

Steward is designed to close the accountability gap that informal or institutional stewardship models may leave open—by enforcing governance *inside* agentic AI systems, not around them.

### Relevant Sources

| Source | Description |
|--------|-------------|
| [FAccT'25: Stewardship in FOSS Governance](https://dl.acm.org/doi/10.1145/3715275.3732032) | Tridgell & Singh examine "software stewards" under the EU CRA |
| [EU Cyber Resilience Act](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act) | Regulation introducing cybersecurity requirements for digital products |
| [Responsible AI Pattern Catalogue](https://dl.acm.org/doi/10.1145/3626234) | ACM collection of best practices for AI governance |
| [Closing the AI Accountability Gap](https://dl.acm.org/doi/10.1145/3351095.3372873) | Raji et al. on internal algorithmic auditing frameworks |

Steward does not introduce new principles of governance. It makes existing principles enforceable at runtime.

---

## License

MIT

---

<p align="center">
  Built by <a href="https://agenisea.ai">Agenisea AI™</a> 🪼
</p>

# steward-runtime

Optional LLM-assisted runtime for Steward contract evaluation.

## Overview

`steward-runtime` provides async orchestration for parallel lens evaluation with optional LLM assistance. It builds on `steward-core`'s deterministic evaluation with:

- **Parallel Fan-Out**: All 5 lenses execute concurrently via `tokio::join!`
- **Deterministic Fan-In**: Synthesizer applies strict policy rules (no LLM)
- **Resilience**: Circuit breaker, token budgets, timeouts per lens
- **Fallback Chain**: Cache → Simpler Model → Deterministic → Escalate

## Configuration

Runtime configuration is provided via `RuntimeConfig`. All fields have sensible defaults.

### Example Configuration (YAML)

```yaml
runtime:
  enabled: true
  default_provider: "anthropic"

  # Determinism
  determinism:
    # Fixed timestamp for reproducible evaluations
    # Matches CLI's --evaluated-at flag
    evaluated_at: "2025-12-20T10:00:00Z"

  # Timeouts
  timeouts:
    global: "30s"
    lens_default: "10s"
    llm_call: "15s"
    per_lens:
      TransparencyContestability: "15s"

  # Token budgets
  budgets:
    global_max_tokens: 5000
    per_lens:
      DignityInclusion: 1000
      BoundariesSafety: 1000
      RestraintPrivacy: 500
      TransparencyContestability: 1500
      AccountabilityOwnership: 500

  # Circuit breaker
  circuit_breaker:
    failure_threshold: 3
    recovery_timeout: "30s"

  # Retry configuration
  retry:
    max_retries: 2
    initial_backoff: "100ms"
    max_backoff: "2s"
    multiplier: 2.0

  # Cache configuration
  cache:
    enabled: true
    ttl: "1h"
    max_entries: 10000

  # Fallback chain (executed in order until one succeeds)
  fallback:
    - Cache
    - SimplerModel:
        model: "claude-haiku-4-5"
    - Deterministic
    - EscalateWithUncertainty
```

### Determinism Configuration

For reproducible evaluations (golden tests, audits, debugging), configure a fixed timestamp:

```rust
use chrono::{TimeZone, Utc};
use steward_runtime::RuntimeConfig;

let mut config = RuntimeConfig::default();
config.determinism.evaluated_at = Some(
    Utc.with_ymd_and_hms(2025, 12, 20, 10, 0, 0).unwrap()
);
```

This mirrors the CLI's `--evaluated-at` flag, ensuring parity between CLI and runtime usage.

### Configuration Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable/disable runtime |
| `default_provider` | string | `"anthropic"` | Default LLM provider |
| `determinism.evaluated_at` | DateTime | None | Fixed timestamp for determinism |
| `timeouts.global` | Duration | `30s` | Global evaluation timeout |
| `timeouts.lens_default` | Duration | `10s` | Default per-lens timeout |
| `budgets.global_max_tokens` | u32 | `5000` | Maximum tokens across all lenses |
| `cache.enabled` | bool | `true` | Enable evaluation caching |
| `cache.ttl` | Duration | `1h` | Cache entry TTL |

## Usage

### Basic Usage

```rust
use steward_runtime::{RuntimeOrchestrator, RuntimeConfig};
use steward_core::{Contract, Output};

// Create orchestrator with default config
let config = RuntimeConfig::default();
let orchestrator = RuntimeOrchestrator::new(provider, config);

// Evaluate
let contract = Contract::from_yaml_file("contract.yaml")?;
let output = Output::text("AI generated response");
let result = orchestrator.evaluate(&contract, &output, None).await?;
```

### With Deterministic Timestamp

```rust
use chrono::{TimeZone, Utc};

let mut config = RuntimeConfig::default();
config.determinism.evaluated_at = Some(
    Utc.with_ymd_and_hms(2025, 12, 20, 10, 0, 0).unwrap()
);

let orchestrator = RuntimeOrchestrator::new(provider, config);
// All evaluations will use the fixed timestamp
```

## Architecture

```
                    ┌──────────────────────────────┐
                    │     CONTRACT + OUTPUT        │
                    └──────────────┬───────────────┘
                                   │
                    ═══════════════╪═══════════════
                         FAN-OUT (parallel)
                    ═══════════════╪═══════════════
            ┌──────────┬───────────┼───────────┬──────────┐
            ▼          ▼           ▼           ▼          ▼
       ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐
       │Dignity │ │Boundary│ │Restraint│ │Transp. │ │Account.│
       │ Agent  │ │ Agent  │ │ Agent  │ │ Agent  │ │ Agent  │
       └────────┘ └────────┘ └────────┘ └────────┘ └────────┘
            │          │          │          │          │
                    ═══════════════╪═══════════════
                         FAN-IN (collect)
                    ═══════════════╪═══════════════
                                   │
                    ┌──────────────────────────────┐
                    │         SYNTHESIZER          │
                    │  (deterministic, no LLM)     │
                    └──────────────────────────────┘
```

## Relationship to steward-core

| Concern | steward-core | steward-runtime |
|---------|--------------|-----------------|
| LLM calls | **Never** | Optional |
| Determinism | Always | Configurable |
| Parallelism | Sequential | `tokio::join!` |
| Resilience | N/A | Circuit breaker, budgets |
| Caching | N/A | Built-in |

The runtime uses `steward-core` for:
- Contract parsing and validation
- Deterministic lens evaluation (fallback)
- Synthesis (always deterministic, no LLM)

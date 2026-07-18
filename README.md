# tfsec-baseline

> A ready-to-adopt IaC security baseline, not a wall of noise.

**Status:** 🚧 In development

## Overview

Curated tfsec/checkov policy pack with a sane suppression workflow.

## Features

- Opinionated ruleset tuned to reduce false positives
- Documented, auditable suppression pattern
- Custom rules for tagging and encryption defaults
- GitHub Action + pre-commit integration
- SARIF output for code scanning

## Stack

tfsec/checkov + custom rules; GitHub Actions.

## Usage

```hcl
- uses: cybercapybara/tfsec-baseline@v1
```

## License

MIT

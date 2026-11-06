# tfsec-baseline

[![ci](https://github.com/moveeeax/tfsec-baseline/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/tfsec-baseline/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.11%2B-blue)
![checkov](https://img.shields.io/badge/checkov-3.4.3-informational)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

An opinionated Terraform security baseline for [checkov](https://www.checkov.io/) —
tuned to run **clean on a well-formed module**, with an *accountable* suppression
workflow and two custom rules for the things default rulesets miss (mandatory tags,
encrypted-by-default). Ships as a GitHub Action with SARIF output for code scanning.

The problem it solves: a security scanner that fires 30 findings on a perfectly
reasonable module trains everyone to ignore it. This baseline skips the opinion-level
noise, keeps the controls that matter, and makes every waiver carry a name and an
expiry date so suppressions can't quietly rot.

## What it does

- **Curated ruleset** (`baseline/checkov.yaml`) — skips a small, documented set of
  opinion-level checks (lifecycle config, event notifications, mandated cross-region
  replication) that generate noise, not security signal.
- **Custom rules** (`baseline/checks/`) — `CKV_TFSEC_1` requires `Owner` + `Environment`
  tags on billable resources; `CKV_TFSEC_2` requires `aws_ebs_volume.encrypted = true`.
- **Accountable suppressions** — waivers live in one YAML file where the schema forces
  a `justification`, an `owner` and an `expires` date. `suppression-audit` fails CI when
  a waiver is malformed or past its expiry, and emits the live waivers as the checkov
  `--skip-check` list. One source of truth, no drift.
- **No inline bypass** — the audit also greps the scanned Terraform for inline skip
  comments (`#checkov:skip=`, `#tfsec:ignore:`, `#trivy:ignore:`) and fails on any
  that the waiver file doesn't back.
- **SARIF output** — uploads to GitHub code scanning.

## How it works

`scripts/scan.sh` is the entrypoint. It (1) audits the suppressions file and the inline
skip comments in the target, (2) merges the
baseline skip-list with the active, non-expired waivers, and (3) runs checkov with the
custom rules, writing both CLI and SARIF output.

The key design choice is that suppressions are **data, not comments**. A bare
`#checkov:skip=CKV_AWS_18` in a `.tf` file is invisible and immortal. Here the same
waiver is a row that a linter can reason about — so "we log centrally, revisit in Q1"
becomes an enforceable statement that expires on a date:

```yaml
suppressions:
  - id: CKV_AWS_18
    paths: [examples/good]
    justification: "access logging is delivered centrally by the platform CloudTrail trail"
    owner: platform-security
    expires: "2028-12-31"
```

## Usage

As a GitHub Action:

```yaml
- uses: moveeeax/tfsec-baseline@v0
  with:
    directory: infra/
    suppressions: .tfsec-baseline/suppressions.yaml
    sarif-file: results.sarif
    inline: error        # unwaived inline skip comments: error | warn | off
```

Locally:

```console
$ pip install -r requirements.txt
$ TARGET=examples/good SUPPRESSIONS=examples/suppressions.valid.yaml bash scripts/scan.sh
>> auditing suppressions: examples/suppressions.valid.yaml
suppression-audit: 1 active waiver(s), 0 error(s), 0 warning(s)
OK: all waivers are justified, owned and unexpired.
>> effective skip-check: CKV2_AWS_61,CKV2_AWS_62,CKV2_AWS_64,CKV_AWS_144,CKV_AWS_18
Passed checks: 20, Failed checks: 0, Skipped checks: 0
>> checkov exit: 0  (SARIF: results.sarif)
```

Audit suppressions on their own:

```console
$ python3 tools/suppression_audit.py --file examples/suppressions.invalid.yaml
suppression-audit: 0 active waiver(s), 3 error(s), 0 warning(s)
  ERROR row 1 [CKV_AWS_18]: waiver expired on 2024-01-01 — re-justify or fix the finding
  ERROR row 2 [CKV_AWS_21]: 'justification' must explain the risk (>= 15 chars)
  ERROR row 2 [CKV_AWS_21]: 'owner' is required so a waiver has a name attached
```

### Inline skip comments

A comment such as `#checkov:skip=CKV_AWS_18` silences the scanner without going through
the waiver file. `--scan-inline <dir>` walks every `.tf` file under `dir` (skipping
`.terraform/` and `.git/`) and looks for these directives inside `#` and `//` comments:

| Directive | Scanner |
| --- | --- |
| `checkov:skip=<id>` | checkov |
| `bridgecrew:skip=<id>` | checkov (older alias) |
| `tfsec:ignore:<id>` | tfsec |
| `trivy:ignore:<id>` | trivy |

Each one is an error unless an active waiver row has the same check id and lists a path
that is the file or a directory containing it (paths resolve against the working
directory). An expired or malformed waiver covers nothing. The inline comment can stay
once the row exists; the row is what carries the owner and the expiry.

```console
$ python3 tools/suppression_audit.py --file examples/suppressions.valid.yaml --scan-inline infra/
suppression-audit: 1 active waiver(s), 1 error(s), 0 warning(s)
suppression-audit: 1 inline skip(s), 0 covered by a waiver
  ERROR infra/main.tf:2 [CKV_AWS_20]: inline `checkov:skip=CKV_AWS_20` has no matching waiver — move it to the suppressions file
```

`--inline warn` reports them without failing, and `--inline off` skips the scan. In the
action and `scripts/scan.sh` the scan always runs on the scanned directory, controlled by
the `inline` input (`INLINE` env), default `error`; it runs even when there is no
suppressions file. Trivy ids (`AVD-AWS-0089`) are accepted as waiver ids so trivy skips
can be waived too.

## Repository layout

| Path | What |
| --- | --- |
| `action.yml` | Composite GitHub Action |
| `baseline/checkov.yaml` | Curated skip-list (the opinion) |
| `baseline/checks/` | Custom rules: mandatory tags, EBS encryption |
| `tools/suppression_audit.py` | The accountable-suppression linter |
| `scripts/scan.sh` | Runner: audit → merge skips → checkov + SARIF |
| `examples/good`, `examples/bad` | A clean module and a deliberately insecure one |
| `tests/` | pytest suite for the audit tool |

## Development

```console
$ pip install -r requirements.txt
$ pytest -q
```

## License

MIT — see [LICENSE](LICENSE).

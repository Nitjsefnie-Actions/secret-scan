# secret-scan

A SHA-pinnable GitHub composite action that scans a repository's working tree
and whole git history for secrets with gitleaks, with no file exempt by its
path alone.

## Usage

Pin the action to a reviewed full commit SHA from this repository. The
`# vX.Y.Z` comment after the pin names the release carrying that SHA; the
version comment is documentation, never the pin itself, so do not substitute a
mutable branch or tag.

```yaml
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: Nitjsefnie-Actions/secret-scan@f6b0956e1bfea8aec4a4524032c3e7bbbc35b28b # v1.1.0
```

## What it checks

`Nitjsefnie-Actions/secret-scan` runs gitleaks 8.30.1 on a Linux x64 runner
over the whole git history, so it needs a full-history checkout, and over the
checked-out working tree, every top-level entry but `.git`. Both scans use the
same config and ignore list, the tree scan reports even when the history scan
has findings, and a finding in either fails the action; either way it puts back
the checkout files it moves aside, so later steps see the tree it found, and one
it cannot put back fails the step and stays under `$RUNNER_TEMP`. Each writes a
gitleaks JSON report, `[]` when clean and the findings when red:
`$RUNNER_TEMP/secret-scan-report/history.json` and `tree.json`, for an
`actions/upload-artifact` step with `if: ${{ !cancelled() }}`, so it runs
after a red scan, and `path: ${{ runner.temp }}/secret-scan-report`. Secrets
are redacted there, but a history finding names its commit's author, email and
message. It then scans a Slack bot token it assembles at run time under that
config and fails unless the scan exits 1 with a `RuleID:` finding line, so a
config whose rules miss that token fails too. It downloads the binary and that
release's default rules, each checked against its digest, and reads
`.gitleaks.toml` and `.gitleaksignore` from the commit the change is judged
against: a pull request's base, a push's previous tip, otherwise the default
branch's tip. It refuses a config there that sets `[extend] path`. With no
config there, or one setting `useDefault = true`, it runs the default rules
without the allowlists that exempt a file by its path alone.

## Inputs

The action takes no inputs.

## Development and community

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, exact checks and commit
attribution. Use the shipped issue and PR templates. Participation follows
[Contributor Covenant 2.1](CODE_OF_CONDUCT.md). Report vulnerabilities
privately as described in [SECURITY.md](SECURITY.md). Code is
[MIT licensed](LICENSE).

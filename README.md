# secret-scan

A SHA-pinnable GitHub composite action that scans a repository's whole tree
and git history for secrets with gitleaks, with no file exempt by its path
alone.

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
      - uses: Nitjsefnie-Actions/secret-scan@<sha> # v1.0.0
```

## What it checks

`Nitjsefnie-Actions/secret-scan` runs gitleaks 8.30.1 over the whole tree and
history on a Linux x64 runner, so it needs a full-history checkout. It
downloads the binary and that release's default rules, each checked against its
digest, and reads `.gitleaks.toml` and `.gitleaksignore` from the commit the
change is judged against: a pull request's base, a push's previous tip,
otherwise the default branch's tip. It refuses a config there that sets
`[extend] path`. With no config there, or one setting `useDefault = true`, it
runs the default rules without the allowlists that exempt a file by its path
alone.

## Inputs

The action takes no inputs.

## Development and community

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, exact checks and commit
attribution. Use the shipped issue and PR templates. Participation follows
[Contributor Covenant 2.1](CODE_OF_CONDUCT.md). Report vulnerabilities
privately as described in [SECURITY.md](SECURITY.md). Code is
[MIT licensed](LICENSE).

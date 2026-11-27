# Security

Report vulnerabilities privately through a
[security advisory on this repository](https://github.com/Nitjsefnie-Actions/secret-scan/security/advisories/new).
Include the action commit SHA, the calling workflow, and the observed behavior
needed to reproduce the problem. Use a repository you control and keep
sensitive details out of public issues.

The action and this repository's workflows are in scope, especially any way a
judged change can exempt its own finding from the scan or make the scan pass
without reading the whole history.

The scan's gitleaks config and ignore list come only from the commit the
change is judged against (a pull request's base, a push's previous tip,
otherwise the default branch's tip), never from the judged tree. Executable
code comes only from the pinned action's `github.action_path`.

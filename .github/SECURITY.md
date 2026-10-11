# Security policy

## Supported versions and current limits

ArkenSec Agent Smith is unreleased development software. There is no supported product version, supported installer or production-security guarantee yet. Do not use this development base with client evidence or against real targets. Managed Kali, execution isolation, durable evidence and the full supported three-OS workflow are qualification milestones, not properties established by this source repository.

Inherited OMP tools can execute on the host. An application-specific state directory is not a sandbox or a security-testing authorization boundary. Do not point the development build at personal account homes or import credentials from other agents.

## Report privately

Use [GitHub private vulnerability reporting](https://github.com/ArkenSecAI/agent-smith/security/advisories/new). Do **not** open a public issue containing vulnerability details, exploit material for a live target, credentials or customer evidence. Ordinary non-security bugs and feature proposals can use public issues.

Provide the exact revision/build, OS/runtime, affected component, expected and observed behavior, and a minimal synthetic reproduction. Clearly distinguish a hypothesis from an observed result. Redact secrets and private identifiers before submission. Do not perform additional testing outside systems you own or are explicitly authorized to assess.

Repository maintainer **@davidsly4954** is responsible for private triage, acknowledgement, coordination and disclosure decisions. There is no guaranteed acknowledgement/fix deadline or backup maintainer. The maintainer will agree an appropriate disclosure plan with the reporter; submission does not authorize public disclosure by an automated agent or a CVE request.

The reporting feature is enabled. The complete synthetic external-report → maintainer notification → private acknowledgement/confidentiality check has not yet been exercised and is deferred until after publication when users or an authorized reporter are available. Enabling the feature is not proof that notifications reached a human; the deferred check is not a passed test. If the reporting form is unavailable, do not post the sensitive report publicly: open only a content-free request for a working private contact and wait for the maintainer.

Upstream vulnerabilities should be coordinated with the affected upstream maintainer without exposing another party's confidential report. This fork does not operate OMP's or any provider's security-response program.

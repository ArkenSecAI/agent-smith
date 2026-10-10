# Contributing to ArkenSec Agent Smith

This is an unreleased development fork of OMP. Read [the roadmap](docs/agent-smith-roadmap.md), [security policy](.github/SECURITY.md) and [development commands](docs/agent-smith-development.md) before changing the project. Source availability is not a supported security product or permission to test third-party targets.

## Scope first

Keep one logical change per pull request. Small bug fixes and documentation improvements can be proposed directly; discuss architecture, execution authority, state/evidence schemas, dependencies and broad behavior changes in an issue before implementation. Do not use the upstream OMP issue automation or Discord as this fork's approval process.

Before a task/build, record its classification, affected interfaces and paths, acceptance checks and integration workflow. For agent-assisted work, record the implementation and independent review model/runtime/effort and the legitimate account route. Choose them per task; model names do not grant authorization or justify a billing/authentication fallback. Do not introduce a second general agent loop or import another application's account homes.

## Human responsibility and evidence

AI assistance is allowed, but the submitter must understand and review the result. Explain what changed and why in your own words. Exercise the changed path and report the exact scenario and observed result; a green build alone does not establish correct runtime behavior. Preserve errors, partial results and limitations. For fixes, keep a deterministic failing-before/passing-after regression where practical. Tests should catch consumer-visible boundaries, invariants and errors—not merely copied strings, wiring or mocks echoing inputs.

Use only owned, synthetic or explicitly licensed fixtures. Never submit real customer data, tokens, signed-in account homes, private histories or confidential vulnerability reports. Never run a live security test as part of a contribution. Report security issues privately as described in SECURITY.md.

## Integration and review

Use an isolated task branch/worktree or explicitly disjoint paths. Stage explicit paths only, preserve unrelated work and sign maintainer-authored commits. Main integration is serial. A reviewer independent of that slice's author must review the exact commit/tree and actual check evidence. A changed subject invalidates that review. Resolve required findings before fast-forward integration; do not force-push or bypass signing, review or secret scanning to make a build pass.

The maintainer, @davidsly4954, controls integration and publication. Public contribution CI is unprivileged and has no provider credentials, signing keys or self-hosted virtualization access. Workflow, trust-root, dependency and release-policy changes require particular review against the trusted base; candidate-controlled checks cannot authorize their own policy changes. A signature or provenance record identifies origin/integrity, not correctness, legal clearance or independent third-party certification.

No public binary/package release, hosted service deployment or upstream package publication follows automatically from a contribution. Release artifacts require the roadmap's later qualification and human authorization.

## Licensing

Contributions intentionally submitted for inclusion in Agent Smith are MIT-licensed where the contributor owns the rights. Preserve all upstream and third-party copyrights, licenses and notices. You must have the right to submit the work; identify any external code/data/assets and its exact source and license. No CLA or mandatory DCO is currently required. AI generation does not waive provenance or licensing responsibilities.

The MIT license does not relicense Kali packages, models, rules, firmware or separately licensed dependencies. Do not copy third-party character art, logos or other proprietary assets for the project name. No response/merge schedule or future volunteer capacity is promised.

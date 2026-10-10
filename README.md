# ArkenSec Agent Smith

**Unreleased development software — not a supported security product or installer release.**

Agent Smith is ArkenSec's open-source security-research companion, developed as a focused fork of [OMP](https://github.com/can1357/oh-my-pi). It is intended to work alongside your normal IDE/coding agent, not replace it.

The fixed product goal is a human-led agent/TUI with a managed **local, full VM-backed broad Kali environment**, **both Kali MCP and HexStrike MCP**, persistent separate projects, real interactive terminals, and useful CPU-only local reasoning while normal development tools remain active. The first supported release must cover **Windows x86-64, Apple Silicon macOS and Linux x86-64**, and all four workflow families:

- Web applications and APIs.
- Networks and infrastructure.
- Authorized exploitation and CTF labs.
- Reverse engineering and binaries.

These are release requirements, **not capabilities already qualified by this development repository**. The P1 work establishes the fork's application identity/state, maintained development build and review/CI boundaries. VM management, both MCP execution paths, project-bound authority, evidence durability, useful local inference and full workflow qualification follow the [roadmap](docs/agent-smith-roadmap.md).

## Development

Use [the maintained development instructions](docs/agent-smith-development.md). Do not run upstream global-install snippets or replace your existing `omp` installation. The application command is `agent-smith`; its own settings/state use `.agent-smith` and app-scoped overrides. No signed-in OMP, Claude, Codex or other account home is shipped or imported as setup.

Inherited tools can still execute on the **host**. Separate application state is **not** VM containment, target authorization, a safe sandbox, encryption or a supported production-security boundary. Develop only with synthetic/owned fixtures; do not load client material or assess live targets with this early build.

Provider adapters in the inherited source are not service entitlement. Only documented, permitted interfaces with the user's legitimate account may be qualified. No copied subscription tokens, provider-refusal evasion, required hosted account or silent remote assistance satisfies the local/offline requirements.

## Source and licensing

Upstream base: OMP **v18.4.8**, immutable commit [`717f97f4d22b3d65c4a4eef6a744255d46f4d1a6`](https://github.com/can1357/oh-my-pi/tree/717f97f4d22b3d65c4a4eef6a744255d46f4d1a6). Upstream Git ancestry, MIT copyright/permission text and additional third-party notices are preserved. Agent Smith-owned additions are MIT-licensed; see [LICENSE](LICENSE), [NOTICE](NOTICE) and [THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt).

Internal upstream workspace/package identifiers and historical documentation may retain OMP names. They identify origin and implementation, not an Agent Smith support promise or instructions to use another project's release infrastructure. Native dependencies, Kali/tool images, models, firmware and rules have separate rights and qualification requirements. Nothing here claims they are all MIT or already bundled.

The [source-origin and rights inventory](docs/agent-smith-source-rights.md) records retained notices, concrete dependency exceptions and unresolved inherited source rights. Publication is not cleared by the root MIT license, a successful local build or a scanner baseline.

This is an independent ArkenSec project, maintained by [@davidsly4954](https://github.com/davidsly4954) under [ArkenSecAI](https://github.com/ArkenSecAI). The name is not an affiliation or endorsement claim. No third-party character art, logos or proprietary branding assets are supplied as Agent Smith branding.

## Contributing and security

- [Contribution and exact-pin review policy](CONTRIBUTING.md).
- [Private vulnerability reporting and current security limits](.github/SECURITY.md).
- [Milestones and support boundaries](docs/agent-smith-roadmap.md).

Do not put credentials, customer evidence or vulnerability details in public issues. Public source publication is separate from a supported release; no supported v1 is claimed before full qualification and the release gate.

# Agent Smith roadmap and release contract

ArkenSec Agent Smith is an **unreleased development project**. Public source is an early collaboration milestone, not a supported security product. No supported v1, hardware minimum, VM-containment guarantee or qualified provider route is claimed by this roadmap.

## Fixed first-release scope

1. A companion to the user's existing IDE and coding agent, not a replacement.
2. A focused OMP fork reusing its agent loop, TUI, sessions, providers and native context mechanisms.
3. Managed **local, full VM-backed Kali**, not a mandatory cloud or remote Kali worker.
4. **Both Kali MCP and HexStrike MCP**, integrated with the same execution supervision and capability contracts.
5. A broad preinstalled toolkit across all four workflow families, not a minimal image users must assemble manually.
6. Supported Windows x86-64, Apple Silicon macOS and Linux x86-64 rows, with exact OS/hardware limits established by actual qualification.
7. Web/API, network/infrastructure, authorized exploitation/CTF labs, and reverse engineering/binary analysis.
8. Real interactive Kali terminals plus browser/proxy/debugger/selected graphical interfaces where the workflow needs them; a full desktop is optional.
9. Human-led ownership by default, bounded optional agent operation, explicit takeover and meaningful stop/reconnect behavior.
10. Separate persistent projects, not multiple chats over one shared mutable engagement workspace.
11. Useful CPU-only fully local reasoning while Kali and representative IDE/browser/development services remain active; a classifier or endpoint health check is insufficient.
12. Qualified local/self-hosted, cloud API and genuinely permitted subscription routes; account entitlement and provider terms are independent of source licensing.
13. Native/upstream-first Token Shredder/context efficiency. A learned classifier is optional and must beat simpler processing on whole-task value.
14. Owned/authorized research and professional engagements with separate target scope, credentials, evidence, retention and model-data permissions. This is not a hosted client portal/PTaaS platform.
15. Truthful findings: distinguish hypotheses, tool assertions, confirmed/disproven findings, incomplete work and unknown outcomes. Preserve original evidence for human review.

Owned code is MIT; dependencies/assets keep their own licenses. Reports are editable human-reviewed **Markdown plus structured JSON and deliberately selected evidence bundles**. A built-in HTML/PDF report renderer is not an initial requirement.

## Gate order

| Stage | Depends on | Required result | Current disposition |
|---|---|---|---|
| P0 — execution readiness | — | Shared contracts, threat/fixture plan, actual ownership/capacity and exercised development workflow | Readiness completed; not product qualification |
| P1 — development fork and CI | P0 | Exact licensed OMP base, app-scoped identity/state, maintained build/package path, protected review/CI, source inventory, verified private reporting and authorized public development source | In progress; source publication awaits the private-reporting control |
| P2 — real integrated feasibility | P1 | Create/boot/work/interrupt/capture/reopen through both MCPs and a real PTY, with useful CPU-local reasoning on a real candidate host for each required OS | Planned |
| P3 — authority and durability | P2 | Project/grant/input ownership, scoped host/guest/network authority, original-byte durability, crash/reconnect and partial/unknown states pass fault/negative controls | Planned |
| P4 — all four workflows | P3 | Useful end-to-end work with required specialist interfaces on each claimed host row | Planned |
| P5 — inference/context/provider qualification | P3 | Useful CPU co-use profiles, native context/evidence fidelity, lawful actual model routes and evidence-based optional classifier decision | Planned |
| P6 — complete project/report lifecycle | P4, P5 | Create/work/review/report/export/close/reopen/backup/restore with client-project separation and no implicit authority imported from old state | Planned |
| P7 — qualified release candidate | P6 | Frozen rights-qualified signed artifacts, clean installation/update/rollback and tamper/compatibility checks | Planned |
| P8 — independent full qualification/pilot | P7 | Frozen candidate passes full host/workflow/security/recovery matrix and separately authorized pilot disposition | Planned |
| P9 — supported release | P8 | Human-authorized exact release publication, downloaded-artifact verification and actual maintenance/security-response handoff | Planned |

P4 and P5 can overlap only after stable P3 contracts. A schema/authority change invalidates affected evidence. Each gate may pass, fail or remain blocked with an explicit owner; a successful build, another OS's results or an agent's self-report cannot close it.

## Architecture and shared invariants

- **OMP fork:** owns the existing agent/TUI/context experience; no second general planner hidden in a tool integration.
- **Host broker:** owns VM lifecycle, authenticated guest connection and explicitly limited host facilities. Hypervisor/QMP and arbitrary host execution are not model/guest capabilities.
- **Guest supervisor:** owns real process/PTY identity, native exit/signal, input owner/epoch, timeout/cancel/disconnect and reconciliation. Both MCP paths must participate.
- **Project evidence:** host-local durable journal plus sealed original bytes; durable bytes precede references. Conversation summaries and memory are replaceable derived state, not proof of execution or vulnerability truth.
- **Managed assets:** pinned immutable bases with independent project writes; image/tool/model/runtime/firmware/ISA/source rights remain explicit.

Versioned interfaces cover ProjectManifest, ActionGrant, RunRecord/InputLease, CapabilityRegistry, EvidenceReference, Finding/Report, CompatibilityManifest and QualificationReceipt. Every action binds project, actor, generation and scope. Imported files or old state do not create fresh authority. Cancellation request, acknowledgement, native exit and complete capture are different facts; unknown work must not be blindly replayed.

Guest root can forge guest-local claims. Host-held capture proves what was captured, not that a target assertion is true. NAT alone is not target authorization; IP controls do not enforce arbitrary URL paths or destinations hidden by an encrypted guest tunnel. Application state separation is not host isolation.

## Qualification discipline

Use purpose-built or explicitly licensed isolated fixtures with independently known positive, benign and inconclusive outcomes. No live customer/production testing belongs in ordinary development. Keep pilot calibration separate from frozen held-out qualification and preserve failed/refused/OOM/incomplete cases in denominators.

The matrix must exercise clean install/boot, both MCPs plus manual terminals, concurrent/stale input and process descendants, hostile target/imported content, target-network boundaries, all four workflows, CPU co-use/offline behavior, original-evidence/context fidelity, optional learned-layer value, concurrent project separation, interrupted runs, full-state restore, update/tamper/rollback, complete human UX/reports and separately authorized adoption trials.

Actual accelerated Windows/macOS/Linux hosts are needed for the VM path. Hosted CI builds are useful but are not WHPX/HVF/KVM qualification. No universal hardware floor, fixed calendar release date, privacy/deletion guarantee or provider entitlement is inferred from planning.

## Explicit first-release exclusions

No replacement IDE, required hosted account, remote Kali execution, wireless/USB passthrough, mandatory full Kali desktop, hosted billing/client portal, real-time multi-user project synchronization, new generic agent/vector platform, foundation-model training, required learned classifier, copied subscription-token route, refusal evasion or unlimited OS/ISA/tool compatibility.

## Ownership and outward actions

The human maintainer is **@davidsly4954** under ArkenSecAI. Technical contributors can implement and review scoped changes; publication, external commitments, signing identity/custody, spending and private disclosure remain maintainer decisions. No backup maintainer or response SLA is assumed.

Source publication and binary release are separate gates. Exact source rights, notices, private-material exclusion, trusted review/build controls and a working private reporting path precede source publication. Signing/notarization, full artifact rights/inventory, supported hardware and downloaded-artifact proof precede the supported release. Do not copy a private development workspace, account homes, client data or another product's deployment policy into this repository.

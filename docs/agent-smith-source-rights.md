# Source origin, notices and distribution boundary

This record covers the **P1 development source**, not the future Kali/tool/model/installer distribution. It is an engineering inventory of observed licenses and retained notices, not legal advice, trademark clearance or a full release SBOM.

## Immutable origin

The repository preserves Git ancestry from [OMP v18.4.8](https://github.com/can1357/oh-my-pi/tree/717f97f4d22b3d65c4a4eef6a744255d46f4d1a6), commit **717f97f4d22b3d65c4a4eef6a744255d46f4d1a6**. The base is not a moving `main` or a copied installed executable. Git identifies every inherited blob and every fork modification. Before publication the maintainer binds the exact signed candidate commit/tree, explicit changed/new/deleted paths, per-path origin/integrity inventory and review/check receipts; those operational receipts stay separate from the public source tree.

The initial recursive Git-tree inventory contains **8,470 entries**, all regular-file modes; no tracked symlinks or submodule entries were observed at that pin. That is a complete base-tree metadata inventory, not a count of installed dependencies or a per-file legal conclusion.

| Source class | Origin and applicable notice | P1 treatment |
|---|---|---|
| OMP application, packages, build tooling and documentation | Pinned upstream tree; root and package `LICENSE` files | Preserve complete MIT copyright/permission/warranty text; factual OMP/Pi attribution in `NOTICE`. Modified paths remain identifiable through Git. |
| Agent Smith-owned application, build/CI changes and documentation | Fork commits after the immutable base | MIT owned additions; no claim of ownership of inherited work. No Matrix imagery/quotes/likeness or another same-name project's code/assets introduced. |
| Vendored brush shell components | `crates/vendor/brush-core/LICENSE`, `crates/vendor/brush-parser/LICENSE`, `crates/pi-builtins/LICENSE` / `LICENSE-MIT` | Retain their MIT and local-modification notices; do not label them newly authored Agent Smith code. |
| Vendored Node-API binding and parser/alias code | `crates/vendor/napi/LICENSE`, `crates/vendor/tree-sitter-go/LICENSE`, `crates/vendor/cfg_aliases/LICENSE` | Preserve their MIT notices and original author attribution. |
| Tokenizer vocabularies, cached source and transformed tables | [`crates/pi-natives/data/README.md`](../crates/pi-natives/data/README.md), component `LICENSE.*` and cache/table notices | Preserve distinct OpenAI, Qwen, Kimi, DeepSeek and ctok terms. Complete K3/V3 byte matches and Qwen/V4/GLM JSON matches are recorded; K3 is custom-licensed, not ordinary MIT. Unresolved items are listed below. |
| Document conversion and shell minimizer adaptations | `packages/coding-agent/src/markit/NOTICE`, `crates/pi-shell/NOTICE` | Retain MIT origin/modification notices, including the RTK source pin. |
| Inherited report-viewer browser assets | `packages/coding-agent/src/export/html/vendor/NOTICE` | Retain marked MIT and highlight.js BSD redistribution/non-endorsement terms. These inherited viewer internals are not a promise of a first-release client-report renderer. |
| Browser relay extension assets | `packages/coding-agent/src/tools/browser/relay/extension-assets/LICENSE.txt` | Retain upstream MIT text; not a license to redistribute arbitrary browsers, codecs, accounts or captured content. |
| Reconstructed protocol schemas | [`proto/PROVENANCE.md`](../packages/ai/src/providers/devin/proto/PROVENANCE.md), Apache-2.0, component notices and restored headers | Reconcile 19 identifiable open-component schemas; do not extend those grants to the 33 provider-specific `exa` schemas or invent their extraction history. |
| Embedded syntax grammars | [`syntaxes/PROVENANCE.md`](../crates/pi-natives/src/syntaxes/PROVENANCE.md), grammar licenses and notices | Restore Julia/TypeScript notices, preserve Mermaid/Nix terms and distinguish upstream comparison pins from import history. |
| Resolved JS/Rust/Bazel dependencies and generated native code | `bun.lock`, `Cargo.lock`, `MODULE.bazel.lock`, package/vendor licenses and `THIRD-PARTY-NOTICES.txt` | Preserve lock/integrity records and per-component notices. The aggregate is inherited release material, not an independently regenerated Agent Smith binary SBOM. |

The upstream `THIRD-PARTY-NOTICES.txt` aggregate is retained unmodified. It expressly does not replace package-level licenses and includes licenses with conditions beyond MIT. A root MIT declaration does not override per-file/package terms. Source references are not proof that a particular binary contains exactly those components.

Concrete inherited exceptions include **inferno 0.12.8 / CDDL-1.0**, **uluru 3.1.0 / MPL-2.0**, and **terminfo 0.9.0 / WTFPL** in `deny.toml`; lightningcss's MPL-2.0 build-only distinction is recorded in the aggregate. The aggregate identifies inferno/source availability but does not list uluru, although `Cargo.lock` contains it. Do not treat the inherited aggregate as a complete derivative binary notice bundle. Reconcile actual linked components and satisfy covered-source/notice obligations before any Agent Smith binary distribution; P1's source-only publication does not redistribute those resolved crate binaries.

## Unresolved source-publication material

The restored notices and successful source matches do **not** clear the whole
inherited source tree. Publication remains blocked pending independent review and
an established basis for the following retained material:

- The 33 reconstructed Codeium/Windsurf `exa` schemas: source artifact/version,
  reconstruction chain and license, permission or documented independent legal
  basis. Imported open-component licenses do not grant rights in them.
- GLM-5 tokenizer content is matched and the publisher declares MIT, but the
  pinned model snapshot supplies no complete component copyright/license notice.
  The separate GitHub code project's Apache license is not a substitute.
- K3's cached Python exactly matches its custom-licensed publisher source and
  preserves a Xenova gist citation; the cited fragment's separate grant is not
  established. No determination of copyrightability or a legal exception is made.
- Jev's inherited measured selections cite an absent intermediate vocabulary.
  OpenAI notices cover the underlying o200k content; measurement provenance and
  any separate rights basis have not been reconstructed.

The original DeepSeek V3 code/model-license ambiguity is resolved for the retained
tokenizer: its exact bytes also match the publisher's MIT-licensed V3-0324 release.
Open-component schema notice fetch gaps have been reconciled through public
sources; historical extraction versions remain unknown, not fabricated.
These are source-specific findings, separate from private reporting, secret-scan,
engineering review and future binary/service authorization.

## Runtime and native artifact seam

The maintained development route uses **Bun 1.4.2** and a real Rust source build
with **nightly-2026-08-12**, preserving Cargo/Bazel locks. It does not download an
upstream prebuilt addon. Separate upstream and reviewed-fork input fingerprints
are recorded in `scripts/agent-smith-native-source.json`; the generated receipt
binds source hash, toolchain, ABI, host/ISA filename and artifact SHA-256.
The loader/probe checks the exact artifact and exercises native behavior.
A matching hash identifies bytes, not license clearance or reproducibility;
see [development instructions](agent-smith-development.md).

P1 does not publish a supported binary installer, sign an OS release or redistribute a managed guest/model stack. Any future distributed binary/archive must reconcile actual build-selected dependencies, runtime/native assets, source obligations and notices, including post-install downloads; this source record cannot substitute for that work.

## Excluded private and unqualified material

No private ArkenSec SaaS code/configuration, customer evidence, account homes, tokens, raw research/history or development-machine state is part of this fork. The repository starts from the public upstream tree; project-specific docs are deliberately authored for publication, not copied wholesale from a private planning archive. Untracked local downloads, build outputs and qualification receipts are not source inventory.

Kali images/packages, both MCP distributions, QEMU/firmware, inference weights/templates, tool rules/wordlists, proprietary integrations and provider service entitlements remain separate exact-artifact gates before their dependent actions. No subprocess/MCP boundary or successful login automatically grants redistribution or productization rights.

The operator chose the qualified title **ArkenSec Agent Smith** despite a disclosed same-field name collision. The repository namespace and original/plain branding are not a trademark clearance or affiliation claim. Any concrete later rights conflict must be resolved before the affected distribution rather than hidden by a new top-level license.

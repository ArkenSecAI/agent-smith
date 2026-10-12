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
| Reconstructed protocol schemas | [`proto/PROVENANCE.md`](../packages/ai/src/providers/devin/proto/PROVENANCE.md), Apache-2.0, component notices and restored headers | Reconcile 19 identifiable open-component schemas and document bounded official MIT comparison sources for `exa`; neither establishes a grant for the entire 33-file provider-specific corpus or its extraction history. |
| Embedded syntax grammars | [`syntaxes/PROVENANCE.md`](../crates/pi-natives/src/syntaxes/PROVENANCE.md), grammar licenses and notices | Restore Julia/TypeScript notices, preserve Mermaid/Nix terms and distinguish upstream comparison pins from import history. |
| Web-prior counts and dictionary data | `crates/pi-predict/data/web-prior.bin.zst` and its retained generator | Preserve all bytes. The retained counts have a scoped U.S. factual-data determination below; dictionary selection and any actually applicable acquisition obligations remain separate. Norvig's code license is not automatically a data grant. |
| Resolved JS/Rust/Bazel dependencies and generated native code | `bun.lock`, `Cargo.lock`, `MODULE.bazel.lock`, package/vendor licenses and `THIRD-PARTY-NOTICES.txt` | Preserve lock/integrity records and per-component notices. The aggregate is inherited release material, not an independently regenerated Agent Smith binary SBOM. |

The upstream `THIRD-PARTY-NOTICES.txt` aggregate is retained unmodified. It expressly does not replace package-level licenses and includes licenses with conditions beyond MIT. A root MIT declaration does not override per-file/package terms. Source references are not proof that a particular binary contains exactly those components.

Concrete inherited exceptions include **inferno 0.12.8 / CDDL-1.0**, **uluru 3.1.0 / MPL-2.0**, and **terminfo 0.9.0 / WTFPL** in `deny.toml`; lightningcss's MPL-2.0 build-only distinction is recorded in the aggregate. The aggregate identifies inferno/source availability but does not list uluru, although `Cargo.lock` contains it. Do not treat the inherited aggregate as a complete derivative binary notice bundle. Reconcile actual linked components and satisfy covered-source/notice obligations before any Agent Smith binary distribution; P1's source-only publication does not redistribute those resolved crate binaries.

## Unresolved source-publication material

The restored notices and successful source matches do **not** clear the whole
inherited source tree. Publication remains blocked pending independent review and
an established basis for the following retained material:

- The 33 reconstructed Codeium/Windsurf `exa` schemas and derived
  `packages/catalog/src/discovery/devin-proto.ts` have bounded official MIT
  comparison sources and strong functional-interface characteristics.
  Full-corpus inspection found declarations and compatibility metadata, with
  no provider commentary or validation expressions. An independent basis
  covering any protected selection or arrangement, including unused reference
  schemas, remains unestablished. The
  [component record](../packages/ai/src/providers/devin/proto/PROVENANCE.md)
  separates individual protocol facts from possible residual structure.
  Original artifact/version and reconstruction details remain unknown; seek
  them where material to the applicable basis or an evidenced acquisition
  obligation, not as an automatic demand. Reverse engineering alone proves
  neither permission nor illegality.
- `crates/pi-predict/data/web-prior.bin.zst` incorporates Norvig-derived counts
  and **192,511 dictionary-only words**, not merely membership flags. Its Git blob
  is `cbc0b8da7be850ad04d790ca4443ae82a779d3da`; SHA-256 is
  `d930584e1f9585103367d3d0485d9a96afd50f961dcdedb708407c2045999d1d`.
  Independent reconstruction from Apple's
  [`files-974.120.2` dictionary](https://github.com/apple-oss-distributions/files/blob/5fc07dd6ecbaa178fff2431dc99e4dffd611ea2d/usr/share/dict/web2)
  and the retained Norvig count inputs reproduces all **6,184,980 decompressed
  bytes**, SHA-256
  `738701f105686d488bd3ee4ee4e48a20e5c77f624505daa32ede80c4c999d672`.
  This includes all 234,454 normalized dictionary words, 150,000 unigram counts
  and 258,168 bigram rows. It identifies same-content inputs, not the unknown
  original host acquisition or unique original input hashes; compressed encoding
  was not regenerated. The count payload SHA-256 values are
  [`51df159fd3de12b20e403c108f526e96dbd723d9cabdd5f17955cdc16059e690`](https://www.norvig.com/ngrams/count_1w.txt)
  and [`781c0596c3eea532d30bef9f3dba1d5137d652f00376260822c761a7584dfb8c`](https://www.norvig.com/ngrams/count_2w.txt).
  Apple's [dictionary README](https://github.com/apple-oss-distributions/files/blob/5fc07dd6ecbaa178fff2431dc99e4dffd611ea2d/usr/share/dict/README)
  reports a supplier's copyright-lapse assertion and later maintenance.
  Government [CCE 1961, page 1907](https://archive.org/details/catalogofcopyrig3151libr/page/1907/mode/1up)
  records renewals **R286978 and R286979**, dated 18 December 1961, for the
  identified 1934 second-edition book. Do not rely on blanket non-renewal of
  that book. These records do not establish protection of individual words
  or this normalized roster, and do not establish infringement.
  A surviving publisher prospectus reproduces the second-edition
  [preface, pp. v–vi](https://archive.org/details/webstersnewinter00unse),
  signed 2 July 1934. It describes discretionary additions and omissions,
  including a general pre-1500 cutoff with a Chaucer exception; it is not an
  exhaustive mechanical inclusion specification. The recoverable maintained
  roster's selection therefore needs a compilation-specific basis addressing
  what, if any, original selection survives the digital extraction and later
  maintenance. The preface itself does not prove such protected selection
  survives in this exact roster. Individual words, identified spelling
  corrections and ordinary lexical sorting are not the unresolved issue.
  Blanket package-level APSL coverage of this third-party list is not established.
  [Norvig's primary page](https://www.norvig.com/ngrams/) expressly licenses
  **code** under MIT and separately describes Google/LDC data origins.
  The [LDC agreement](https://catalog.ldc.upenn.edu/license/web-1t-5-gram-version-1.pdf)
  does not grant redistribution of this operational packed prior. Its unsigned
  form does not establish that ArkenSec is a party or exclude separate permission
  held by Norvig. An actually applicable acquisition obligation is distinct from
  the completed U.S. factual-count determination below; neither every hypothetical
  contract nor an unidentified historical transaction is presumed applicable.

## Completed source-rights determinations

The retained **150,000 unigram counts, 258,168 merged bigram records and
sentence-start total** have a scoped U.S. copyright-only factual-data
determination. They are occurrence measurements, selected by numerical
frequency and ordinary filters, with case merging, aggregation and lexical/ID
ordering. No source-document identities/order, long passages or expressive
taxonomy are retained. The basis is the actual objective selection and
arrangement, not that only a small quantity was copied. See
[17 U.S.C. §§102–103](https://www.copyright.gov/title17/92chap1.html) and
[Feist](https://www.law.cornell.edu/supremecourt/text/499/340).
This determination is not a data-license grant, dictionary-selection
clearance, contract waiver or worldwide database-rights determination.
All packed data and generator bytes remain unchanged.

K3's cached Python exactly matches its custom-licensed publisher source and
preserves its Xenova citation. Separate permission for the exact byte-mapping
expression is unnecessary under the narrow, independently reviewed U.S.
assessment in the [component record](../crates/pi-natives/data/README.md).
The determination inspects the pinned expression and earlier GPT-2 idiom; it
does not assume a notebook license or an exemption based only on size or
functionality. Python bytes, the citation and complete K3 notice are unchanged.
The notebook's BPE routine, whole-notebook rights and service rights are outside
that determination.

The original DeepSeek V3 code/model-license ambiguity is resolved for the retained
tokenizer: its exact bytes also match the publisher's MIT-licensed V3-0324 release.
GLM's full JSON match and affirmative publisher MIT declaration are retained with
standard permission/warranty terms in
[`LICENSE.glm5`](../crates/pi-natives/data/LICENSE.glm5), without an invented
copyright holder/year. The ten reconstructed Cockroach/App Engine Apache schemas
now carry individual modification comments and links to the corpus provenance and
license. Historical extraction versions remain unknown, not fabricated.

Independent decoding confirmed that every retained Jev entry is an exact o200k
piece at its original rank: 53,622 base and 144,562 whole-word entries. OpenAI
notices cover that content. Unverified historical measurement claims do not
establish an additional source-redistribution restriction or unlawful acquisition.
These findings are separate from private reporting, secret-scan, engineering
review and future binary/service authorization.

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

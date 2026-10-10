# Syntax grammar origins and notices

This record concerns the six grammar files present in OMP v18.4.8, commit
`717f97f4d22b3d65c4a4eef6a744255d46f4d1a6`, tree
`3f8ecdad21e55c5f47785ccfbd4f8c0528186976`. Research and notice restoration:
2026-10-10. It identifies components individually; the root MIT notice is not
substituted for their own copyright and license notices.

## Julia

- Local file: `Julia.sublime-syntax`; baseline Git blob
  `5125bfafc6ef7f5225d168435e26048bee8c4545`.
- Primary origin: [JuliaEditorSupport/Julia-sublime grammar](https://github.com/JuliaEditorSupport/Julia-sublime/blob/master/Julia.sublime-syntax)
  and [raw source](https://raw.githubusercontent.com/JuliaEditorSupport/Julia-sublime/master/Julia.sublime-syntax).
  The grammar's Julia operator/base-name definitions and context rules identify
  this origin, consistent with the independent pinned-baseline review.
- Authentic [upstream MIT license](https://raw.githubusercontent.com/JuliaEditorSupport/Julia-sublime/master/LICENSE)
  is retained in `LICENSE.Julia-sublime`, including
  `Copyright (c) 2016-2021 Viktor Qvarfordt and other contributors` and the
  historical `JuliaLang/julia-sublime/contributors` URL exactly as published.
  Neither the copyright years nor the license's historical URL was updated.
- Public OMP import commit:
  [`bcdd37260eabdaa3a481b05f335f9c2590e99370`](https://github.com/can1357/oh-my-pi/commit/bcdd37260eabdaa3a481b05f335f9c2590e99370).
  This establishes the receiving revision, not the upstream Julia-sublime
  revision. The original import does not record an upstream commit.
- Exact Julia-sublime commit/tag remains unestablished. Public GitHub metadata
  and history lookups were unavailable; the reachable source and license URLs
  reference mutable `master`. The grammar's own “Last update: Julia v1.0.0”
  comment is not an upstream source revision. No new byte-identity claim is
  made from the web-rendered source, whose whitespace presentation differs.
- This remediation adds comments linking the source, copyright and full
  license. It does not change a grammar rule.

## TypeScript and TypeScriptReact

| Local grammar | OMP baseline Git blob |
| --- | --- |
| `TypeScript.sublime-syntax` | `68c9b4a942f2e11b2b50b8240a4e9d44d2431bfb` |
| `TypeScriptReact.sublime-syntax` | `1b57bb140dd5423d89d884b2f1a3c2e489a54b64` |

Both entered OMP in
[`b8df99f5c92eb190955ecbd3036b9b1d69d10e8e`](https://github.com/can1357/oh-my-pi/commit/b8df99f5c92eb190955ecbd3036b9b1d69d10e8e).
That commit records adding TS/TSX definitions and `.ts`/`.mts`/`.cts`/`.tsx`
routing but does not record an upstream download or conversion command.

The source family is [Microsoft TypeScript-TmLanguage](https://github.com/microsoft/TypeScript-TmLanguage).
A primary comparison pin is **`48f608692aa6d6ad7bd65b478187906c798234a8`**:

- [TypeScript YAML source](https://raw.githubusercontent.com/microsoft/TypeScript-TmLanguage/48f608692aa6d6ad7bd65b478187906c798234a8/TypeScript.YAML-tmLanguage).
- [TypeScriptReact TextMate source](https://raw.githubusercontent.com/microsoft/TypeScript-TmLanguage/48f608692aa6d6ad7bd65b478187906c798234a8/TypeScriptReact.tmLanguage).
- [MIT license](https://raw.githubusercontent.com/microsoft/TypeScript-TmLanguage/48f608692aa6d6ad7bd65b478187906c798234a8/LICENSE.txt),
  retained in `LICENSE.TypeScript-TmLanguage`, including the year-free
  Microsoft copyright and `All rights reserved.` line.
- [Third-party notices](https://raw.githubusercontent.com/microsoft/TypeScript-TmLanguage/48f608692aa6d6ad7bd65b478187906c798234a8/ThirdPartyNotices.txt),
  retained in `NOTICE.TypeScript-TmLanguage`: Babel Sublime/Andres Suarez,
  Atom language-javascript/GitHub Inc., and the underlying TextMate JavaScript
  bundle permission notice. Retaining Microsoft's own license alone would
  omit this nested attribution. Wording is retained; web transcription can
  differ in blank-line layout from raw Git bytes.

Origin evidence includes distinctive repository rules such as
`after-operator-block-as-object-literal`, `directives`, `docblock`, TS scopes,
the JSDoc/internal-comment matching patterns, and regex contexts. The pinned
YAML's regex section explicitly attributes syntax to `atom/language-javascript`.
The local grammars express these as Sublime `contexts`/`match`/`push`/`pop`
rules, with expanded variables and `include` targets without TextMate's `#`;
the source uses TextMate `repository`/`patterns`/`begin`/`end` forms. This is
conversion/adaptation evidence, not byte identity. Local TypeScript also
declares `mts` and `cts` extensions; the comparison YAML declares `ts`.

The pin above is an inspected comparison and notice source, **not a verified
historical import pin**. Exact original source version, conversion tool and
any intervening distribution remain unrecorded. No full semantic equivalence
or build validation was performed. These limitations do not justify inventing
an upstream release or changing the grammar during notice remediation.

The [TypeScript-Sublime-Plugin project](https://github.com/microsoft/TypeScript-Sublime-Plugin)
explains that the shared TypeScript/TypeScriptReact grammars were moved into
TypeScript-TmLanguage. Its plugin repository advertises Apache-2.0, whereas
the identified grammar source and notices at the pin above supply MIT and the
nested notices. The plugin's repository-wide license must not be mechanically
applied to these converted grammar files merely because they target Sublime.
The immediate acquisition route into OMP is still unknown.

## Existing Mermaid, Nix and Astro records

| Local file | Component origin and retained evidence |
| --- | --- |
| `Mermaid.sublime-syntax` | Its existing header names [SublimeText/Mermaid](https://github.com/SublimeText/Mermaid), its `mermaid.sublime-syntax` source, MIT and 2017 Peng Wang. This file and its notices are unchanged. No exact imported upstream revision was established here. |
| `Nix.sublime-syntax` | Its existing header identifies derivation from [wmertens/sublime-nix](https://github.com/wmertens/sublime-nix), MIT and 2016 Wout Mertens. This file and its notices are unchanged. The word “derived” is retained; no upstream byte match or exact revision is asserted. |
| `Astro.sublime-syntax` | The inherited header describes OMP's composition of the vendored `source.ts` grammar with syntect's bundled `text.html.basic`. This file is unchanged. This record does not purport to inventory the separate grammars embedded in syntect. |

## Disposition and limits

The missing Julia copyright/full MIT notice is restored. The adjacent TS/TSX
grammar family, its MIT notice, and its nested notices now have an explicit
component mapping. Exact historical import pins remain unresolved as described
above; only the receiving OMP versions and the stated Microsoft comparison pin
are established. Further provenance work must preserve that distinction.

No builds, lints, tests, formatters, scanners, installs, grammar converters,
provider probes, credential reads, commits, pushes or publication were run.
The changes are adjacent notice/provenance files and attribution comments in
Julia/TS/TSX only. Main owns integrated verification, final source fingerprints
and fresh independent review. These additions do not lift the separate
private-vulnerability-reporting source-publication/remote-CI hold or establish
license coverage for a future compiled highlighter distribution.

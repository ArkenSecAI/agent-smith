# utok vocabulary data

## Source rights and provenance

This directory contains transformed third-party tokenizer data. Its companion
`../tools/cache/` contains retained source/data, including Python code. These
components do **not** acquire a universal MIT grant from the repository root.
Keep their component licenses, this mapping, the cache's `NOTICE.tokenizers`,
and file-specific `.NOTICE` sidecars with source redistributions.

The evidence below was collected on **2026-10-10** for OMP **v18.4.8**, commit
`717f97f4d22b3d65c4a4eef6a744255d46f4d1a6`. All ten retained cache files' locally
computed Git blob IDs matched that commit's tree. This work added notices only:
no cache, table, generator, `families.json`, or runtime code was changed.
**Publication remains blocked for the unresolved material listed below.**
An available license text is not itself proof that an unmatched file is covered.

### Component mapping

Paths in the first column are relative to `../tools/cache/`; table names are
relative to this directory. Transformations describe the retained OMP generators;
they were inspected, not run or independently validated by regenerating outputs.

| Retained source/data | Packed output and recorded transformation | Notice/terms and evidence status |
| --- | --- | --- |
| `cl100k_base.tiktoken` | `cl100k_base.bin.zst`; `pack-openai.ts` decodes base64 pieces, preserves 100256 ranks, writes UTOK1 and zstd -19. | [OpenAI tiktoken MIT](LICENSE.openai-tiktoken), Copyright (c) 2022 OpenAI, Shantanu Jain. Exact cache SHA-256 matches the publisher's expected hash. |
| `o200k_base.tiktoken` | `o200k_base.bin.zst`; same process for 199998 ranks. Also supplies the pieces/ranks for both Jev tables. | Same OpenAI notice; exact cache SHA-256 matches. Jev's separate measurement provenance is discussed below. |
| `qwen3.8.tokenizer.json` | `qwen3.bin.zst`; `pack-qwen.ts` decodes the byte alphabet, excludes 33 added tokens and empties 201 unreachable entries while retaining 248044 rank slots; UTOK1 and zstd -19. | [Qwen3.8 Apache-2.0](LICENSE.qwen3.8), including Copyright 2026 Alibaba Cloud. Full JSON identity established after reversing formatting/key-order changes. Attach the [cache modification notice](../tools/cache/qwen3.8.tokenizer.json.NOTICE) and [table modification notice](qwen3.bin.zst.NOTICE). |
| `kimi.tiktoken.model` | `kimi_k2.bin.zst`; `pack-kimi.ts` decodes 163584 base64/rank entries; specials are absent; UTOK1 and zstd -19. | Exact bytes match pinned **Kimi K3**. [K3 license](LICENSE.kimi-k3), Copyright (c) 2026 Moonshot AI; custom terms, not ordinary MIT. The identical vocabulary also appears in Kimi-VL; its separate [MIT notice](LICENSE.kimi-vl) is retained without asserting that OMP acquired it there. |
| `tokenization_kimi.py` | Retained Python source; its split expression is recorded in `families.json`. It imports K3 support (`encoding_k3`); `pack-kimi.ts` does not read it. | Exact bytes match the same K3 snapshot. K3 notice retained; the cited Xenova fragment's separate grant remains unestablished. |
| `deepseek-v4.tokenizer.json` | `deepseek3.bin.zst`; `pack-deepseek.ts` decodes 128000 byte-alphabet entries, empties sentinel ranks 0–2, excludes 1283 added tokens, then UTOK1 and zstd -19. | Full JSON content matches pinned **DeepSeek-V4-Pro**, ignoring object-key order/formatting only. [DeepSeek MIT](LICENSE.deepseek), Copyright (c) 2023 DeepSeek. |
| `deepseek-v3.tokenizer.json` | Retained comparison source used by `gen-deepseek-fixtures.py`; `pack-deepseek.ts` does not read it. | Exact bytes match both original V3 and the publisher's MIT-licensed **DeepSeek-V3-0324** snapshot. [DeepSeek MIT notice](LICENSE.deepseek) retained; the older [model agreement](LICENSE.deepseek-v3-model) is historical context, not the grant relied on for these matched bytes. |
| `glm-5.tokenizer.json` | `glm5.bin.zst`; `pack-glm.ts` decodes 154820 byte-alphabet entries, excludes 36 added tokens, then UTOK1 and zstd -19. | Full JSON content matches pinned **zai-org/GLM-5**, ignoring object-key order/formatting only. The publisher declares MIT, but no complete component copyright/license notice was supplied in that snapshot. |
| `ctok_v3.bin`, `ctok_v4_7.bin` | `ctok_v3.bin.zst`, `ctok_v4_7.bin.zst`; front-coded measured vocabulary, then zstd, as described below. | Existing [LICENSE.ctok](LICENSE.ctok) is preserved unchanged. Its inherited v1.0.0 pin is retained, not newly hash-matched in this work. |

`kimi_k2`, `qwen3` and `deepseek3` are **output/family identifiers**, not evidence
that the cache came from K2, Qwen3, or V3 respectively. The corresponding generator
inputs are the K3-labeled vocabulary, Qwen3.8 JSON and V4 JSON. Claims in
`families.json` about cross-version vocabulary equivalence do not establish
whole-file identity or license equivalence. Its Qwen id-0 encoding note is also
superseded by the explanation in `pack-qwen.ts`; this notice does not edit either.

### Exact cache identities

SHA-256 is over the complete retained bytes, without newline/JSON normalization.
These hashes identify the publication material even when its upstream match is
unresolved. They are not hashes of model weights or a binary SBOM.
The local Git comparison used SHA-1 of `blob <decimal-byte-length>\0<file-bytes>`
and the corresponding entries from `git ls-tree -rl` at the OMP commit above.

| Cache file | Bytes | SHA-256 |
| --- | ---: | --- |
| `cl100k_base.tiktoken` | 1681126 | `223921b76ee99bde995b7ff738513eef100fb51d18c93597a113bcffe865b2a7` |
| `o200k_base.tiktoken` | 3613922 | `446a9538cb6c348e3516120d7c08b09f57c36495e2acfffe59a5bf8b0cfb1a2d` |
| `qwen3.8.tokenizer.json` | 9089356 | `ae50d65939a34a089eaf1e541c15c8a7d866079a5fe9a1d35454e0aa88577753` |
| `kimi.tiktoken.model` | 2795286 | `b6c497a7469b33ced9c38afb1ad6e47f03f5e5dc05f15930799210ec050c5103` |
| `tokenization_kimi.py` | 16145 | `f28ea66e2d862a2a5814970b2ce40c2f7d8296ff09aed90a7e7def689b906944` |
| `deepseek-v3.tokenizer.json` | 7847652 | `621ac2e32d0dba658404412318818aaa8ce8cda492e59830109d8da6b517fb41` |
| `deepseek-v4.tokenizer.json` | 4363807 | `3ad46a8c78edf140516eb696f948ae6e7c3522ec64993b219833145e2e9951d0` |
| `glm-5.tokenizer.json` | 8683422 | `f73933d2e4b633ce5a75f049a68b339790c52b966025e895aae0a0eda67d5cda` |
| `ctok_v3.bin` | 202428 | `92a5fbaff2e5dca70e62a0765432008a9521e0c4e86d7248365818a23694f365` |
| `ctok_v4_7.bin` | 57304 | `0a887a9099ef7f82a011eedaeb1a84cd400011582c14945e346136694537bbb1` |

### Primary sources and comparison method

**OpenAI.** The [tiktoken 0.12.0 source](https://raw.githubusercontent.com/openai/tiktoken/0.12.0/tiktoken_ext/openai_public.py)
publishes both download URLs and expected SHA-256 values:
[cl100k](https://openaipublic.blob.core.windows.net/encodings/cl100k_base.tiktoken)
and [o200k](https://openaipublic.blob.core.windows.net/encodings/o200k_base.tiktoken).
Both expected values match the unmodified caches above. The release resolves to
commit [`97e49cbadd500b5cc9dbb51a486f0b42e6701bee`](https://github.com/openai/tiktoken/commit/97e49cbadd500b5cc9dbb51a486f0b42e6701bee).
[LICENSE.openai-tiktoken](LICENSE.openai-tiktoken) transcribes the
[license at that release tag](https://raw.githubusercontent.com/openai/tiktoken/0.12.0/LICENSE).
The cache acquisition date is unknown; the release and hashes establish the
identified vocabulary contents without downloading the vocabulary again.

**Qwen.** [Qwen3.8-27B's pinned tokenizer page](https://huggingface.co/Qwen/Qwen3.8-27B/blob/1d4bf0f2ff6012fd82039f2fa52739d0dd7c60c0/tokenizer.json)
publishes SHA-256
`0997f410c57a1f4e53b09e4be8f4a172d90edd9564368fb0847030937229b9f3`.
The cache is minified and its vocabulary object keys have been reordered.
Locally parsing that entire cache, sorting only `model.vocab` entries by their
numeric token IDs, and emitting UTF-8 with Python
`json.dumps(document, ensure_ascii=False, indent=2)` **without a final newline**
produced **12809320 bytes with exactly that SHA-256**. No JSON value, merge,
array order or vocabulary mapping was changed. This establishes full content
equivalence, not merely a shared base vocabulary. The publisher lists tokenizer
upload commit [`72a217afab8029b39e4af1c7273a829995a3dbaf`](https://huggingface.co/Qwen/Qwen3.8-27B/commit/72a217afab8029b39e4af1c7273a829995a3dbaf).
The [license at the matched snapshot](https://huggingface.co/Qwen/Qwen3.8-27B/raw/1d4bf0f2ff6012fd82039f2fa52739d0dd7c60c0/LICENSE)
is reproduced in LICENSE.qwen3.8, including Alibaba's appendix attribution.
No separate NOTICE file is listed in the [snapshot's root tree](https://huggingface.co/Qwen/Qwen3.8-27B/tree/1d4bf0f2ff6012fd82039f2fa52739d0dd7c60c0).

**Kimi.** Both cached files are byte-identical to
[`moonshotai/Kimi-K3` at `f831ab66814297da540d832a5235f8e904f29d06`](https://huggingface.co/moonshotai/Kimi-K3/tree/f831ab66814297da540d832a5235f8e904f29d06):
[vocabulary](https://huggingface.co/moonshotai/Kimi-K3/resolve/f831ab66814297da540d832a5235f8e904f29d06/tiktoken.model),
[Python](https://huggingface.co/moonshotai/Kimi-K3/resolve/f831ab66814297da540d832a5235f8e904f29d06/tokenization_kimi.py).
Their SHA-256 values are in the cache table above. The snapshot's
[license](https://huggingface.co/moonshotai/Kimi-K3/raw/f831ab66814297da540d832a5235f8e904f29d06/LICENSE)
is retained in LICENSE.kimi-k3. No cache modifications were found.
The Python's existing citation to the
[Xenova conversion notebook](https://gist.github.com/xenova/a452a6474428de0182b17605a98631ee)
is preserved. That public notebook contains the corresponding Latin-1
byte-alphabet join expression, but lists no separate license file. This record
does not invent a grant for that incorporated fragment.
The vocabulary also matches
[Kimi-VL-A3B-Instruct at `a2143f93a3f72a8ebcd64702a676fe47fd9c1937`](https://huggingface.co/moonshotai/Kimi-VL-A3B-Instruct/blob/a2143f93a3f72a8ebcd64702a676fe47fd9c1937/tiktoken.model).
LICENSE.kimi-vl preserves the separately observed
[official project's MIT text](https://raw.githubusercontent.com/MoonshotAI/Kimi-VL/main/LICENSE);
that moving license URL is not an acquisition pin or a grant for the K3 Python.

**DeepSeek V3.** The entire cache is byte-identical to both the original
[V3 tokenizer at `e815299b0bcbac849fa540c768ef21845365c9eb`](https://huggingface.co/deepseek-ai/DeepSeek-V3/resolve/e815299b0bcbac849fa540c768ef21845365c9eb/tokenizer.json)
and the publisher's
[V3-0324 tokenizer at `e9b33add76883f293d6bf61f6bd89b497e80e335`](https://huggingface.co/deepseek-ai/DeepSeek-V3-0324/resolve/e9b33add76883f293d6bf61f6bd89b497e80e335/tokenizer.json):
7847652 bytes, SHA-256
`621ac2e32d0dba658404412318818aaa8ce8cda492e59830109d8da6b517fb41`.
The latter snapshot's complete
[MIT license](https://huggingface.co/deepseek-ai/DeepSeek-V3-0324/raw/e9b33add76883f293d6bf61f6bd89b497e80e335/LICENSE)
supplies the grant and Copyright (c) 2023 DeepSeek notice retained here.
This match resolves the earlier original-V3 code/model-license ambiguity for
these exact tokenizer bytes; it does not assert OMP acquired them from V3-0324.
The original release's separately retained model agreement is historical
context, not a model entitlement or the grant relied upon for this cache.

**DeepSeek V4.** The complete cache JSON equals the
[DeepSeek-V4-Pro tokenizer at `b5968e9190ef611bbf34a7229255be88a0e937c1`](https://huggingface.co/deepseek-ai/DeepSeek-V4-Pro/resolve/b5968e9190ef611bbf34a7229255be88a0e937c1/tokenizer.json)
after ignoring object-key order and formatting, preserving every value and array
order. The publisher file is 6367146 bytes, SHA-256
`8f9f37ca37fdc4f5fd36d5cf4d3b0e8392edb4e894fd10cc0d70b4957c8633cf`.
Its [MIT license](https://huggingface.co/deepseek-ai/DeepSeek-V4-Pro/raw/b5968e9190ef611bbf34a7229255be88a0e937c1/LICENSE)
is retained in LICENSE.deepseek. This content match resolves the previously
unknown V4 edition; OMP's original acquisition date remains unknown.

**GLM.** The complete cache JSON likewise equals the
[GLM-5 tokenizer at `c183ef8c61faee82855eca1ed9bb3a9a7ce3b0b2`](https://huggingface.co/zai-org/GLM-5/resolve/c183ef8c61faee82855eca1ed9bb3a9a7ce3b0b2/tokenizer.json).
The publisher file is 20217442 bytes, SHA-256
`19e773648cb4e65de8660ea6365e10acca112d42a854923df93db4a6f333a82d`.
Its [model card](https://huggingface.co/zai-org/GLM-5/raw/c183ef8c61faee82855eca1ed9bb3a9a7ce3b0b2/README.md)
declares `license: mit`; the snapshot's file listing has no LICENSE or NOTICE.
No copyright holder/year or missing license text is invented. The separate
[GitHub code project's Apache-2.0 license](https://raw.githubusercontent.com/zai-org/GLM-5/main/LICENSE)
is not substituted for the tokenizer's declared MIT terms.

All newly included license texts reproduce the complete wording exposed by the
publisher's public text view; browser-rendered whitespace/blank lines may differ
from the downloadable originals. They are not claimed to be byte-identical
license downloads. Source URLs and the limits of each pin are recorded above.

### Redistribution conditions and outstanding prerequisites

- **MIT components:** retain their actual copyright and permission notices in
  copies/substantial portions, including transformed vocabulary tables. Existing
  ctok notices remain in force. These notices do not supply missing provenance.
- **Qwen Apache-2.0:** give recipients the full license, retain applicable source
  copyright/patent/trademark/attribution notices and any upstream NOTICE content,
  and prominently identify modified files (§4). The JSON and compressed table
  have adjacent, file-named modification notices because their formats cannot
  carry prose comments; distribute each sidecar with its file. The license's
  patent conditions, warranty terms and limited trademark grant also remain.
- **Kimi K3:** retain its complete copyright/permission notice. This is a custom
  license, **not ordinary MIT**. Section 2 requires a separate agreement before
  commercial use when the licensee/affiliates operate a Model as a Service
  business and exceed USD 20 million aggregate revenue over any consecutive
  12 months. Section 3 requires prominent Kimi K3 UI attribution for commercial
  products/services exceeding 100 million monthly users or USD 20 million monthly
  revenue; §4 states exceptions. No determination of an operator's qualification
  under these conditions is made here. Exact K3 content matching is complete;
  the separate basis for the cited Xenova fragment remains unestablished.
- **DeepSeek:** both tokenizer caches now match identified MIT-licensed publisher
  snapshots. Retain the actual copyright/permission notice with the caches and
  derived tables. Matching tokenizer bytes does not license a remote service or
  unrelated model weights.
- **GLM:** content matching is complete. Obtain or reconcile the publisher's
  applicable complete license/copyright notice; the metadata label has not
  supplied that notice. The cache and its packed derivative remain **blocked**.
- **Jev:** retain the OpenAI notice for the o200k-derived content. OMP describes
  the membership selections as its own measurements, but the referenced
  `cache/jev-1.13.vocab.json` is not retained in this source baseline. The historical
  measurement claims below were not independently verified. Reconstructing
  that measurement provenance/rights basis requires non-sensitive upstream
  evidence; no TypeSafe license or provider permission is inferred from it.

These matches establish complete retained content, not merely a shared base
vocabulary. They do not validate the packed-output generators, establish an
operator's service/model rights, or approve source/binary publication.

### Retrieval record and limits

The initial native author's direct HTTP requests failed DNS resolution and
several browser fetches were unavailable. Main subsequently retrieved the
pinned K3, DeepSeek V3/V4 and GLM tokenizer files and available licenses through
unauthenticated public endpoints, then compared complete bytes or parsed JSON.
The K3 and V3 comparisons are exact byte matches; V4 and GLM preserve all JSON
values and array order. No model weights were downloaded, no retained Python
or tokenizer generator was executed, and no model/provider request was made.
The failed initial requests are not evidence that a source or permission is
absent. Remaining missing grants and acquisition history are distinguished
from the successful content matches above.


## Existing ctok generation record

`ctok_v3.bin.zst` and `ctok_v4_7.bin.zst` are **generated** — do not
hand-edit. They are compacted from the measured vocabulary files of
[sanderland/ctok](https://github.com/sanderland/ctok) v1.0.0 (revision
`df3b59b5e645289a5eadc8e24036b99d39c333c4`), MIT licensed — see
`LICENSE.ctok`. The vocabulary data is Sander Land's measurement work
("On the biology of Claude's tokenizer",
<https://tokencontributions.substack.com/p/on-the-biology-of-claudes-tokenizer>);
the Rust implementation in `../src/utok/claude/` is this repository's own.

Upstream ships every piece with a `count_tokens` witness probe; compaction
drops that metadata, parses the public `⟨bow⟩the⟨eow⟩` key notation into the
compact C0 marker alphabet (single bytes `0x01`–`0x05`; safe because `nfc`
strips C0 controls from input), adds the glued contraction spellings, and
front-codes the sorted piece list into the version-2 binary format produced
by `../tools/gen-ctok-vocab.ts` (~4.7 MB of upstream JSON →
~254 KB front-coded → ~106 KB after zstd -19).

Regenerate the front-coded binaries, then compress them here:

```sh
cd ../tools
bun gen-ctok-vocab.ts   # fetch upstream, emit raw bins into cache/
bun pack-ctok.ts        # zstd -19 into ../data/
```

If the upstream pin moves, also regenerate
`../src/utok/claude/testdata/fixtures.json` against the same ctok release
(see the fixture doc in `../src/utok/claude/mod.rs`).

The other `*.bin.zst` files here are the UTOK1 BPE rank tables packed by
the per-family scripts in `../tools/` (container format and per-family
split specs: `families.json` in this directory).

## Inherited Jev measurement record

The following describes OMP's historical measurement work, not requests made or
claims independently validated during the source-notice review above.

`jev_base.bin.zst` and `jev_whole.bin.zst` are **measured**, not downloaded:
TypeSafe publishes no tokenizer for Jev, so both sets were recovered from
the live System One API's `usage.input_tokens` (jev-1.13.0, 2026-09-23,
~639k probes). `jev_whole` holds the whole-word entries (a piece that
equals one costs 1); `jev_base` holds the base tokens the merge loop may
form. Both are o200k subsets stored at their o200k ranks, with every other
slot empty. Membership came from difference probes inside non-merging
padding (e.g. `cost("世" + x + "世") - 2`), byte fragments were fitted
against per-character probes, and pieces padding cannot isolate (space
runs, newline-final punctuation, rare fragments) were settled with probes
built to flip on each one. The result reproduces all 638,573 recorded
counts (`fixtures/jev.json` pins 400 live counts). Regenerate the
blobs from the measured sets with:

```sh
cd ../tools
bun pack-jev.ts   # cache/jev-1.13.vocab.json + cache/o200k_base.tiktoken → ../data/jev_*.bin.zst
```

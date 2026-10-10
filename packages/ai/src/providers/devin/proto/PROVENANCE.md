# Reconstructed protocol sources and notices

Scope: the 52 `.proto` files inherited from OMP v18.4.8, commit
`717f97f4d22b3d65c4a4eef6a744255d46f4d1a6`, tree
`3f8ecdad21e55c5f47785ccfbd4f8c0528186976`. Attribution research and additions:
2026-10-10. This is a component record, not a blanket MIT grant or publication
clearance. Paths below are relative to this directory.

## Evidence and transformation

The public OMP history introduces this corpus at
[`fc01e3b6cba6e1add44a1613baa891a9b873f8a9`](https://github.com/can1357/oh-my-pi/commit/fc01e3b6cba6e1add44a1613baa891a9b873f8a9).
Its then-present
[`buf.gen.yaml`](https://github.com/can1357/oh-my-pi/blob/fc01e3b6cba6e1add44a1613baa891a9b873f8a9/packages/ai/src/providers/devin/proto/buf.gen.yaml)
explicitly calls the inputs a “reverse-engineered Codeium corpus,” retains
unused schemas for reference/maintenance, and generates selected transitive
dependencies using local `protoc-gen-es`, `target=ts`, into
`packages/catalog/src/discovery/devin-gen`. Its `version: v2` is the **Buf
configuration format**, not a Codeium product or schema version. Its comments
say Google well-known types are supplied by Buf, rather than vendored here.
These historical files were read from the public upstream Git objects; neither
Buf nor the generator was run for this remediation.

At the v18.4.8 pin,
[`packages/catalog/scripts/generate-protocols.ts`](https://github.com/can1357/oh-my-pi/blob/717f97f4d22b3d65c4a4eef6a744255d46f4d1a6/packages/catalog/scripts/generate-protocols.ts)
reads the `.proto` corpus, parses it through `ProtoContext`/`parseProto`, selects
`DEVIN_MESSAGES` and `DEVIN_ENUMS` plus dependencies, and writes
`packages/catalog/src/discovery/devin-proto.ts`. This is downstream regeneration
of TypeScript wire definitions; it does not recover the original authors'
comments, input product revision, or redistribution permissions.

The inherited text is consistent with **descriptor-style reconstruction**:
field numbers and nested messages remain, references are fully qualified,
enums/nested declarations move, comments and language/code-generation options
disappear, and proto2 files omit the explicit syntax declaration. This is an
inference from the reproduced text, not a receipt establishing a particular
descriptor dumper, command, compiler, input binary, or execution date.

[`packages/ai/scripts/proto-extractor.py`](https://github.com/can1357/oh-my-pi/blob/717f97f4d22b3d65c4a4eef6a744255d46f4d1a6/packages/ai/scripts/proto-extractor.py)
instead parses generated JavaScript field lists and `@generated` annotations.
Its current entrypoint consolidates a package into one proto3 file and its
emitter does not emit this corpus's imports. Its mere presence cannot establish
that it produced these 52 files. No matching input bundle, descriptor set,
product/version receipt, extraction command, or upstream dependency lock was
established in the inspected schema/generator material.

The comparison references establish recognizable open-component origins and
authentic notices, not byte identity or the original extraction versions.
The three subsequently retrieved pins below are resolved immutable commits.
Other branch references remain mutable and tags remain comparison references;
none is silently promoted to an extraction receipt.

## Component mapping

| Local files | Primary upstream evidence | Notice and version evidence |
| --- | --- | --- |
| `cel/expr/checked.proto`, `eval.proto`, `syntax.proto`, `value.proto`, `explain.proto` | [CEL source directory](https://github.com/cel-expr/cel-spec/tree/master/proto/cel/expr), formerly `google/cel-spec`; [project license](https://raw.githubusercontent.com/google/cel-spec/master/LICENSE) | Apache-2.0. All five source headers say `Copyright 2023 Google LLC`; restored in each file and `NOTICE`. Exact imported commit unresolved. |
| `io/prometheus/client/metrics.proto` | [v0.6.2 schema](https://raw.githubusercontent.com/prometheus/client_model/v0.6.2/io/prometheus/client/metrics.proto), [v0.6.2 NOTICE](https://raw.githubusercontent.com/prometheus/client_model/v0.6.2/NOTICE) | Apache-2.0; schema's `Copyright 2013 Prometheus Team`, plus the separate 2012–2015 authors/SoundCloud notice in `NOTICE.Prometheus`. v0.6.2 is a compatible comparison source, not an extraction pin. |
| `buf/validate/validate.proto` | [v0.11.0 schema](https://raw.githubusercontent.com/bufbuild/protovalidate/v0.11.0/proto/protovalidate/buf/validate/validate.proto) | Apache-2.0; authentic `Copyright 2023-2025 Buf Technologies, Inc.` from this comparison source. Exact imported revision unresolved. |
| `grpc/binlog/v1/binarylog.proto` | [grpc/grpc-proto schema](https://raw.githubusercontent.com/grpc/grpc-proto/master/grpc/binlog/v1/binarylog.proto) | Apache-2.0; `Copyright 2018 The gRPC Authors` and `All rights reserved.` restored. Exact imported revision unresolved. |
| `errorspb/errors.proto`, `hintdetail.proto`, `markers.proto`, `tags.proto`, `testing.proto` | [cockroachdb/errors at `b63dfdf0b860a689995c5e2a9eb0c089d61c9d95`](https://github.com/cockroachdb/errors/tree/b63dfdf0b860a689995c5e2a9eb0c089d61c9d95/errorspb), [pinned license](https://github.com/cockroachdb/errors/blob/b63dfdf0b860a689995c5e2a9eb0c089d61c9d95/LICENSE) | All five schemas retrieved; Apache-2.0, no per-file license headers or separate NOTICE in that complete tree. Exact extraction revision unknown. This is the errors library, not the differently licensed database. |
| `google.golang.org/appengine/internal/base/api_base.proto`, `datastore/datastore_v3.proto`, `log/log_service.proto`, `remote_api/remote_api.proto`, `urlfetch/urlfetch_service.proto` | [golang/appengine v1.6.8 at `aa58fcd18e4ab7ac816760ee266fa30a0907ab9e`](https://github.com/golang/appengine/tree/aa58fcd18e4ab7ac816760ee266fa30a0907ab9e/internal), [pinned license](https://github.com/golang/appengine/blob/aa58fcd18e4ab7ac816760ee266fa30a0907ab9e/LICENSE) | All five schemas retrieved; Apache-2.0, no per-file license headers or separate NOTICE in that complete tree. No copyright year is invented; extraction revision remains unknown. |
| `connectext/grpc/status/v1/status.proto` | [Connect Go v1.10.0 at `495b8810f4ab7fe3720eb3310cfcab570df06151`](https://github.com/connectrpc/connect-go/blob/495b8810f4ab7fe3720eb3310cfcab570df06151/internal/proto/connectext/grpc/status/v1/status.proto), [pinned license](https://github.com/connectrpc/connect-go/blob/495b8810f4ab7fe3720eb3310cfcab570df06151/LICENSE) | Apache-2.0; authentic `Copyright 2021-2023 Buf Technologies, Inc.` header restored. No separate NOTICE in that complete tree. The same `Status` fields are present; this is not a claimed extraction pin. |
| `exa/**/*.proto` (33 files) | Original OMP generation config above; retained `exa` package/service names | Provider-specific Codeium/Windsurf corpus. No upstream source release, license or other reproduction/publication basis established. These files are outside the open-component grants above. |

The five individually inspected CEL sources are
[checked](https://raw.githubusercontent.com/google/cel-spec/master/proto/cel/expr/checked.proto),
[eval](https://raw.githubusercontent.com/google/cel-spec/master/proto/cel/expr/eval.proto),
[syntax](https://raw.githubusercontent.com/google/cel-spec/master/proto/cel/expr/syntax.proto),
[value](https://raw.githubusercontent.com/google/cel-spec/master/proto/cel/expr/value.proto),
and [explain](https://raw.githubusercontent.com/cel-expr/cel-spec/master/proto/cel/expr/explain.proto).
The last was reached after the public GitHub page redirected from `google` to
`cel-expr`. A failed fetch at an old path was not treated as evidence of absence.

`LICENSE.Apache-2.0` contains the complete standard license, including its
appendix, copied from the system's common-license text. Its authority is the
[Apache Software Foundation text](https://www.apache.org/licenses/LICENSE-2.0.txt)
and the component grants cited above. The appendix's placeholders are the
license's example, not copyright assertions about this corpus.

## Concrete comparison observations

- CEL retains `Expr.Comprehension.iter_var2 = 8` and
  `SourceInfo.extensions = 6`, as well as optional list/struct entry fields.
  Its upstream comments and file options are absent. `explain.proto` also loses
  the upstream message-level `option deprecated = true`. These observations
  distinguish a reconstruction from an unmodified source copy; they do not
  uniquely date the dependency.
- Prometheus retains native histogram spans/deltas/counts and exemplars,
  created timestamps and `MetricFamily.unit = 5`, found in v0.6.2. The local
  text moves `MetricType` before messages, fully qualifies type references,
  and omits the upstream proto2 declaration, comments and language options.
- Buf v0.11.0 has `Rule`, `MessageRules`, `FieldRules`, proto2 optional fields,
  and reserved former `skipped`/`ignore_empty` fields. Earlier inspected
  [v0.9.0](https://raw.githubusercontent.com/bufbuild/protovalidate/v0.9.0/proto/protovalidate/buf/validate/validate.proto)
  still uses `Constraint`/`MessageConstraints`/`FieldConstraints`, so it is not
  the same declaration generation. The local file has no `PredefinedRules`
  message or top-level option-extension definitions, removes CEL option
  expressions and comments, and contains the single reserved string
  `"IGNORE_EMPTYIGNORE_DEFAULT"`, where the v0.11.0 source writes adjacent
  literals `"IGNORE_EMPTY" "IGNORE_DEFAULT"`. This is consistent with rendering
  a descriptor's resolved string, rather than copying source spelling; it is
  not a newly established schema defect and has not been altered here.
  No complete semantic equivalence or exact dependency match is claimed.
- gRPC retains the `grpc.binarylog.v1` messages and enums but loses source
  commentary and file options and qualifies type references. The directory
  name `binlog` and package name `binarylog` both come from upstream.

Baseline review anchors (Git blob IDs, **before** attribution additions):
`cel/expr/syntax.proto`: `ae16fa4c0ad48f6637046c382b009e1326ad590f`;
`io/prometheus/client/metrics.proto`: `a1bd8ea76e67d6d60da9d10af43ef6f7ebf0dc99`;
`buf/validate/validate.proto`: `cbc51f3aadfc7caadadd5e3c47f82b3f378c0a22`.
The OMP commit above identifies all other baseline blobs. These are not final
candidate fingerprints.

## Unresolved source-publication prerequisites

1. **Provider-specific retained source:** establish the actual source artifact
   and version for the 33 `exa` files, the reconstruction chain, and an applicable
   license, permission, or documented independent legal basis for reproducing
   and publishing these particular files. A public endpoint name, an OMP MIT
   notice, a generated client, or permissive licenses for imported dependencies
   do not supply that evidence. These files are already in the proposed source
   distribution, even when not selected by the TypeScript generator.
2. **Import-version evidence:** all 19 recognizable open-component schemas now
   have reconciled comparison-source notices. Their exact extraction inputs,
   versions and complete transformations remain unrecorded. Reference tags and
   the three recovered comparison commits must not become invented import pins.

The first native author's public fetches encountered DNS/cache failures.
Main subsequently retrieved all eleven previously unavailable CockroachDB errors,
Go App Engine and Connect schemas, their pinned project licenses and complete
repository trees. None of those trees lists a separate NOTICE. The ten errors/
App Engine schemas have no license header to restore; the Connect header is now
restored. These successful retrievals supersede the earlier fetch limitations,
not the unresolved provider-specific source basis or extraction history.
Subsequent complete-tree checks also found no separate NOTICE at
[CEL `40a3c9007a9305d1f2638d5f538a4e011732cace`](https://github.com/cel-expr/cel-spec/tree/40a3c9007a9305d1f2638d5f538a4e011732cace)
or [Buf v0.11.0 `9540054436ae001ce28d37215644dd6cbe4eeff4`](https://github.com/bufbuild/protovalidate/tree/9540054436ae001ce28d37215644dd6cbe4eeff4).
Their pinned project licenses were retrieved. This resolves the earlier NOTICE
fetch gap at those comparison pins, not the unknown historical extraction pins.

This record makes no categorical claim that interoperability or reverse
engineering is unlawful, and does not infer extraction or provider access
during Agent Smith P1. No provider request, login, credential inspection,
authenticated download, or model download was used here.

Future binary packaging must carry applicable component licenses/notices for
what it actually embeds, including derived definitions. Future provider
enablement has separate service/account/access obligations. Those future
questions do not resolve the source-publication prerequisites above. The
separate private-vulnerability-reporting publication/remote-CI hold is unchanged.

Attribution edits change comments and adjacent notices only, not declarations.
Source matching did not execute a schema generator or contact a provider.
Integrated checks and exact-candidate independent review are separate gates;
this provenance record does not itself declare the candidate publishable.

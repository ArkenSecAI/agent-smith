# Agent Smith P1 development

Agent Smith derives from OMP **18.4.8**, commit
`717f97f4d22b3d65c4a4eef6a744255d46f4d1a6`. Its command is `agent-smith`, its
application version is `0.0.0-unreleased`, and its source entrypoint is
`packages/coding-agent/src/cli.ts`. Internal workspace packages and the native ABI
retain version 18.4.8; this is not an upstream release or a supported installer.

**Publication controls:** private vulnerability reporting is enabled on
`ArkenSecAI/agent-smith`, with clear [private reporting instructions](../.github/SECURITY.md).
The synthetic outsider report → maintainer notification → private acknowledgement/
confidentiality round trip is deferred until users or an authorized reporter are
available; it remains unverified, not passed. Retained inherited material and its
maintainer decision are recorded in [the rights inventory](agent-smith-source-rights.md);
scanner dispositions are described below, and the [contribution policy](../CONTRIBUTING.md)
governs integration. Exact-pin independent review and the required hosted checks
gate every `main` advance. A local build does not authorize a supported release.

## Toolchain and maintained commands

Use an isolated checkout and owner-provisioned **Bun 1.4.2**. Put its executable
directory on PATH. Do not run upstream global-install snippets, replace an
existing `omp`, or borrow another installation's native binary or account home.
The native path is a real source build, with no prebuilt fallback. It requires:

- `rustup` and **nightly-2026-08-12**; set `RUSTUP_HOME` explicitly to the
  provisioned toolchain directory because child HOME is synthetic.
- A C/C++ compiler/linker, CMake, Ninja and `tar`.
- Linux glibc x64; or Windows x64 with VS C++ tools/Windows SDK; or Apple Silicon
  macOS with Xcode command-line tools and `codesign`.

Provisioning tools is explicit. The scripts do not install a global toolchain,
change shell profiles, use sudo, install models or discover personal Rust homes.
Cargo dependencies/outputs stay under `.agent-smith-dev/cargo` and
`.agent-smith-dev/target`. Run from the repository root:

```sh
bun --no-env-file run smith:prepare
bun --no-env-file run smith:check
bun --no-env-file run smith:smoke
bun --no-env-file run smith:build
# Separate source gate, on the integrated candidate commit (Linux x64):
bun --no-env-file run smith:scan
```

| Command                                              | Behavior                                                                                                                                                                                                                                                                                                                                                         |
| ---------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `smith:prepare`                                      | Check runtime/tools; frozen Bun install with lifecycle scripts disabled; locked Cargo fetch; source host addon build, load/ABI check and real asset generation.                                                                                                                                                                                                  |
| `smith:check`                                        | Verify the native receipt; lint/format checks and all workspace/tool typechecks; maintained environment, credentials, discovery, predictor privacy, native artifact integrity, settings, CLI and scan-boundary contracts; native crash-path/OAuth callback Rust tests. No automatic fixes.                                                                       |
| `smith:smoke`                                        | Run the actual source CLI/worker smoke and persistent config round trips, including rejected input and isolated state overrides.                                                                                                                                                                                                                                 |
| `smith:build`                                        | Generate real embedded assets, compile the host executable, restore generated inputs even after failure, package/hash/extract it, then smoke the extracted executable before populating `dist/agent-smith/<host>/`.                                                                                                                                              |
| `smith:scan`                                         | Verify provisioned scanner/runtime bytes; scan complete candidate ancestry, historical binary/link/type-change blob versions and an exact current-tree Git snapshot; account for external Git references without fetching them; apply only independently reviewed exact dispositions; retain native reports, errors and one fail-closed summary. Linux x64 only. |
| `smith:native`                                       | Rebuild the reviewed native input pin from source.                                                                                                                                                                                                                                                                                                               |
| `smith:native -- --verify`                           | Verify source/artifact fingerprints, ABI and live native behavior without compiling.                                                                                                                                                                                                                                                                             |
| `smith:native -- --allow-native-changes`             | Intentionally build changed native inputs for development; review and update the source pin before acceptance.                                                                                                                                                                                                                                                   |
| `smith:smoke -- --binary /absolute/path/agent-smith` | Exercise a particular executable (`agent-smith.exe` on Windows).                                                                                                                                                                                                                                                                                                 |

The root `build` command routes to `smith:build`. Retired global setup, lifecycle
prepare, publication and release aliases are removed, not compatibility shims.
Advanced inherited release/Bazel/Docker/Nix/Python scripts are not the maintained
P1 route or permission to run, deploy or publish them. No provider/model request
is necessary for the maintained development or scan gates.

## Native identity and local package

Preparation calls `scripts/bazel-natives.ts host --dest packages/natives/native`
with the Cargo backend selected explicitly. The upstream driver generates the
bindings, installs the canonical host addon and stamps its ABI identity. The
additional probe opens that exact addon and exercises Unicode width and positive/
negative regex search. Missing or extra addon candidates, wrong versions, changed
artifact bytes and stale source fingerprints fail the gate.

`scripts/agent-smith-native-source.json` records separate upstream and reviewed
fork fingerprints. The algorithm hashes sorted repository-relative paths, NUL,
each file's SHA-256 and newline. Inputs include all Rust crates (including their
notices), Cargo manifests/lock/config/toolchain and the native build/generation/
version helpers. Changing a covered notice also requires refreshing the pin and
rebuilding the receipt; the original upstream fingerprint must remain intact.
The local `.agent-smith-dev/native-receipt.json` binds output bytes, source hash,
host/ISA, toolchain and native version. It is an integrity receipt, not signed
provenance or a claim of reproducible builds.

The driver selects baseline/modern x64 for the build host. This does not qualify
musl, cross-compilation or an older CPU. Generated bindings use the existing
source generator, not a second hand-maintained implementation. Native crash logs
and callback registration use Agent Smith's namespace; these native components
are app-global rather than separate registrations for every profile.

Compiled addons carry a required per-file SHA-256 and a canonical manifest
artifact ID binding platform, ABI version, variant, filename, size and content
digest. Their cache is `~/.agent-smith/natives/<version>/<artifactId>/`, not just
a version directory. Same-size, same-ABI bytes are not interchangeable. Regular
cached files must match their expected size and full digest; symlinks are not
cache hits. An invalid cache is repaired only from a completely verified archive.
Missing/inconsistent manifest metadata fails before extraction or fallback.

Fallback candidates are copied to an owned temporary file, verified, and staged
at that same artifact-specific path before native loading. An adjacent/shared
path is never the compiled loader's final module identity. This requires a
writable artifact cache even for a valid fallback. Different artifacts of the
same release can coexist without reusing a resident old module. A verified warm
cache does not require reading the archive again.

Compilation reuses `compileCodingAgent`, the existing JSON/virtual-module
plugins, embedded documentation and single-entry worker host. Bun dotenv and
configuration autoloading are disabled in the compiled executable. Native/stats
payloads are restored to their exact pre-build bytes even on compiler failure;
build, restoration and lockfile failures are all retained. macOS ad-hoc signing
uses the upstream entitlements, not Developer ID or notarization.

The local output contains the executable, host `.tar.gz`, `SHA256SUMS`,
`build-manifest.json`, this guide and root/native license/notice files. Only the
explicit payload enters the archive. Extraction must preserve its exact file set,
hashes and executable permission. Compiled smoke requires the embedded addon to
extract under the synthetic version/artifact directory and match the receipt.
There is no binary upload, installer, global link or release qualification.
The inherited notice aggregate is not a complete derivative binary SBOM; public
binary distribution has additional component/source/notice obligations.

## Synthetic execution and isolation

Each maintained run creates fresh HOME/USERPROFILE, XDG and Windows app-data
paths, a synthetic working directory and temporary IPC paths. The environment
allowlist retains OS executable paths, not provider keys, broker settings,
personal app overrides, proxies or preload hooks. Bun dotenv loading is disabled;
preparation refuses repository-local dotenv files without reading their contents.
Evidence and synthetic state are under `.agent-smith-dev/`.

`--smoke-test` exercises actual native-loaded graphs, the stats dashboard, worker
threads and subprocess/daemon re-entry over local loopback/IPC. It performs no
provider login, model inference or model download. Config smoke saves both boolean
values across separate CLI processes, rejects malformed input without losing the
saved value, and proves an explicit state directory cannot alter default state.
CLI smoke children use the existing process-tree supervisor with deadlines;
bootstrap commands use a dependency-free runner until the addon exists.

Owned config/state is rooted at `.agent-smith` (with app-specific XDG markers).
`AGENT_SMITH_CODING_AGENT_DIR` selects an explicit agent directory. Foreign config,
plugin registries, accounts and memory stores are not automatically imported.
Foreign discovery requires app-owned consent, including project directories;
showing disabled dashboard items is not that consent. See the current
[settings](settings.md) and
[environment reference](environment-variables.md).

Text prediction automatically learns only this agent directory's Agent Smith
history. It does not seed from Claude or Codex history. Cache state lives under
`predict/own-history-v1/<engine>/`; pre-cutover snapshots and cursors are neither
adopted nor deleted. The daemon identity and handshake carry this independent
generation, so an old daemon advertising the same application version cannot
receive new completion text. Own-history incremental ingestion, persistence and
corrupt-state recovery remain supported. Explicit manual history imports are
separate from automatic predictor seeding.

The broker name and endpoint use the first 128 SHA-256 bits of the generation and
resolved agent directory, encoded as 22 canonical unpadded base64url characters.
The 35-character broker name fits its unchanged 48-character limit; the same key
forms a 27-byte Unix socket basename. A 75-byte runtime directory therefore gives
a 103-byte endpoint. The permanent Unix boundary regression listens, connects and
exchanges a request on that exact endpoint before joined socket/server cleanup.
This improves headroom without claiming arbitrary-path, symlink-alias or macOS
qualification; the current runtime evidence is Linux only.

The real-broker privacy regression runs its broker host and predictor under the
same whitelisted synthetic HOME/XDG environment as the client. It joins the host's
full shutdown, including predictor termination and log/metadata persistence,
before removing fixture state, even after a client is killed. The broker rejects
new `start` requests during shutdown and drains earlier starts still preparing
their records; a controlled filesystem gate requires the original request's
shutdown rejection as well as no late launch, without a sleep.
During ordinary operation, tracked starts remain owned until their reply write
completes or the caller disconnects. Shutdown starts a 250 ms delivery grace for
pending replies, including those already backpressured before shutdown. Completion,
disconnection or grace expiry releases that wait so teardown can close sockets.
Actual non-reading and resumed-reading socket regressions cover both outcomes;
ordinary elapsed time cannot consume a later shutdown's delivery grace. Reading
preparing callers still receive the specific broker shutdown rejection rather than
premature connection closure. This does not bound hung filesystem/process primitives
or unrelated restart/mode operations.
Startup, stop and shutdown failures are preserved together after the owned broker
finishes, rather than a later teardown exception hiding an earlier failure.

This separation is not VM containment, host sandboxing or target authorization.

## CI, review and scan boundaries

The workflow accepts normal PRs targeting `main` and pushes to `main`, `p1/**` or
`task/**`. A maintainer-only manual dispatch re-runs the same checks on the exact
head of a chosen ref without a new commit; it never runs the main provenance job.
It uses `ubuntu-24.04` x64, `windows-2025` x64 and `macos-15` Apple
Silicon, not self-hosted runners. Image labels pin an OS family, not immutable VM
contents. Candidate jobs are read-only, do not persist checkout credentials, and
have no service/signing secrets, privileged PR trigger, Docker or binary upload.
Each provisions the pinned Rust toolchain into RUNNER_TEMP and executes the same
four commands. Hosted runner results are evidence only for the exact commit they
checked and are not desktop hypervisor qualification; local Linux evidence does
not qualify the Windows or macOS rows.

The external main ruleset requires signed commits, no force-push/deletion, and
`Gitleaks 8.30.1` plus `Development (linux-x64)`, `Development (win32-x64)` and
`Development (darwin-arm64)`, bound to GitHub Actions App 15368. Initial branch
creation has no status-check exception. An independently reviewed exact candidate
must complete those checks on a `p1/**` or `task/**` ref before `main` is created
or advanced. GitHub did not credit such checks to the creation of a new `main`, so
the initial `main` was created at reviewed commit `d3fd958d90` under a one-time,
maintainer-approved creation exception that was reverted immediately; later
updates are fast-forwards of reviewed commits whose required checks have passed.
CI and workflow authors cannot approve their own integration; external
exact-commit/tree review remains required.

Both scan and build jobs check out `pull_request.head.sha` for a PR, or
`github.sha` for a push, with complete history. Each PR job explicitly fetches the
current target `main` and requires it to be an ancestor of the source head. The
upstream base must also be an ancestor. Qualification therefore concerns the
reviewed source head for fast-forward integration. Main must recheck the target
before advancing it; a moved target requires renewed ancestry checks and review
where the candidate changes. A GitHub-generated merge commit is not qualified by
these source-head checks. The scan summary records the candidate commit/tree and
fetched target-base SHA. Review and integration remain external controls.

### Maintained source scan

Provision **Bun 1.4.2**, **Gitleaks 8.30.1 Linux x64** and Git with working
`GIT_ATTR_SOURCE` support (Main's established implementation is Git 2.43).
`smith:scan` performs no installation or network access and needs no native addon,
dependencies, provider access or account stores. CI reuses the verified tool
provisioner and pinned Bun action. Executable SHA-256 checks precede scanner
execution; version output alone is insufficient. The Linux Bun executable digest
is `a83d263767d839e4d2649ca8e35d07159c7afc99afdc96d731ced29e056dda0c`, and the
Gitleaks executable digest is
`88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509`; these correspond
to the verified release archives below. Other scanner hosts are rejected.

```sh
bun --no-env-file run smith:scan -- \
  --candidate FULL_SOURCE_HEAD_SHA \
  --target-base FULL_CURRENT_TARGET_SHA \
  --gitleaks /absolute/path/to/gitleaks \
  --output /absolute/path/to/new-evidence-directory
```

All options are optional locally: candidate defaults to HEAD, Gitleaks is located
on PATH, and a fresh evidence directory is created below `.agent-smith-dev/`.
`--target-base` adds the fast-forward ancestry requirement and is supplied by PR
CI after its explicit fetch. An explicit output directory must not already exist.
Unknown/duplicate options fail. The candidate must equal checkout HEAD, and the
scan implementation, common helper and ledger must equal their committed bytes.
Main must integrate them before qualification; a dirty implementation cannot
approve an older commit. Other worktree bytes never become snapshot inputs.

The history scan uses the exact candidate's complete ancestry, with
`--full-history --diff-merges=first-parent --root`, without restricting traversal
to first parents. An owned bare Git view reads the original immutable object
database, with replacement objects and lazy network fetches disabled. Missing
objects/parents, shallow metadata, grafts, external object alternates and nonempty
repository `info/attributes` fail. Original upstream commit and tree pins remain
fixed. No upstream scripts, hooks, filters, external diff drivers or textconv run.

System/global attributes are disabled. For both the history scanner and object
metadata enumeration, `GIT_ATTR_SOURCE` selects immutable `SOURCE_BASE`
(`717f97f4d22b3d65c4a4eef6a744255d46f4d1a6`), whose tree must equal the pinned
`SOURCE_TREE`. Its reviewed `.gitattributes` marks the minified catalogs binary;
candidate/worktree attributes cannot redefine coverage. Retained positive and
negative controls use a synthetic `-diff` tree and the empty tree to prove that
Git honors the explicit source. The normal Git pass retains Gitleaks' archive
branch. No whole-history `--text` pass or attribute-neutral minified-line pass runs.

The historical-blob scope independently enumerates that same candidate and
history/diff selection using `--raw --numstat -z --no-abbrev --always`. The NUL
parser pairs raw paths with numstat paths and validates full object IDs, modes,
statuses and counts; missing/repeated commits must fail comparison with complete
ancestry. Root diffs, first-parent merge diffs, deletions, mode/type changes and
empty commits are accounted for. Unsupported modes, unsafe/non-UTF-8 paths,
renames or ambiguous/truncated records fail the scope. There is no extension
allowlist. Every non-deleted binary `-/-` result, stored symlink target, and
file/link type-change result enters `historical-blob-inventory.json`, deduplicated
only by exact original path plus resulting blob. Every occurrence commit remains.
Symlink targets are scanned as ordinary stored bytes, never materialized as
filesystem links or followed into a host path.

Historical mode-160000 Gitlinks are external commit references, not file blobs.
Their exact path/target-commit pairs and occurrence commits are inventoried
separately as `gitlinks`; additions, changes and deletions also remain in the full
raw metadata. No external repository is fetched or its contents claimed as
scanned. Current-tree symlinks and Gitlinks remain rejected. Full parsed object
metadata, native metadata digest, attribute pins, ancestry digest and candidate
commit/tree bind the inventory.
The inventory is generated from the candidate; exploratory base counts are not
imported or used as a future coverage limit.

Historical versions are exported and scanned sequentially. Each has a fresh
owned directory, only its original relative pathname, and verified exact Git
blob bytes. The per-object `cat-file` process exits before its directory scanner
starts; no 300-second batch deadline spans hundreds of scans. The native report,
logs, bindings, separate content/coverage context and receipt are retained under
`historical-blobs/000001/` and successive directories, then only that owned export
is removed. Cleanup failures block and stop further exports. Contents are never
executed and are not accumulated across versions. `historical-blob-results.json`
binds every context/receipt to the inventory; missing, failed or repeated versions
cannot pass coverage. Go children use `GOMEMLIMIT=512MiB` and `GOMAXPROCS=2`; there
is no new runtime dependency, virtual-address limiter or host-guard change.

The tree scan uses `git ls-tree` and a single `git cat-file --batch` stream to
materialize every regular file from the immutable tree, verifying each blob's
identity, length and written bytes. Unsafe paths, symlinks, submodules, invalid
UTF-8 paths and unexpected modes fail. No Git metadata, untracked dependencies,
workstation caches or synthetic runtime fixtures enter that snapshot. Committed
fixtures remain scanned. No `git archive`, checkout smudging, line-ending
conversion, export substitution or export-ignore omission defines scan bytes.
The implementation rejects blobs over 512 MiB instead of skipping them; reviewed
ZIP member verification is bounded to 64 MiB and extracts only in memory.

Before candidate-content scans, a mandatory synthetic canary exercises the same
copied, pinned Gitleaks executable and default configuration. Its owned Git fixture
sets `-diff` and `export-ignore`: ordinary history and archive controls omit the
synthetic finding, while maintained metadata/blob export and exact snapshot paths
must both detect the expected `github-pat` and deny it as unapproved. No real
credential or new source-disposition allowance is involved. Native reports,
invocations, metadata and their hashes are retained under `attribute-canary/`;
`receipt.json` is bound into the summary and its artifacts are rechecked before
completion. Missing, incomplete, changed or unexpected proof fails preflight,
leaving candidate scans `not-run`. This does not restore forced-text minified diffs.

All three scopes use explicit `[extend] useDefault = true`, an empty
ignore file, `--ignore-gitleaks-allow`, full redaction, archive/decode depth 2 and
error-only non-color logging. No custom default-rule edits, blanket baseline,
path/test/provider/rule/commit/ancestry exemption or inline allow comment is
applied. Once preflight succeeds, findings or decoder errors do not short-circuit
other versions/scopes. Incomplete execution remains an explicit failure; no
failed scan is retried into a passing receipt. Each scanner process has a
30-minute scanner deadline and a separate process deadline with signal/timeout
tracking. The combined scope can take longer than one invocation.
Missing/malformed reports, unexpected stdout, undispositioned stderr, unsupported
execution, output/exit disagreement or changed inputs fail. Native exit 1 can
pass disposition evaluation only when every finding is exactly approved and no
error remains; other nonzero exits always fail. `summary.json` is the authoritative
combined outcome, and requires the bound passing canary plus complete passing
coverage of all three scopes. Preflight failures explicitly leave scans marked
`not-run`. The summary schema is version 5; the disposition ledger remains version
4 and historical inventory version 2. Tools, configuration, canary evidence,
implementation/ledger inputs and source HEAD are rechecked before completion.

Native redacted `history-findings.json`, `tree-findings.json`, and per-object
`historicalBlob-findings.json` are retained
unchanged alongside stdout/error logs, exact invocation receipts, per-occurrence
source bindings, ancestry, snapshot inventory, configuration/ignore files and
`summary.json`. Digests bind the inputs, tools and reports. Raw reports can still
contain upstream author metadata and surrounding source text; they are evidence,
not public ledger content. CI retains the evidence for seven days and uploads no
snapshot, synthetic home, scanner executable or candidate binary. Bounded default
scanning is not exhaustive arbitrary-binary analysis or rights clearance.

### Disposition ledger

`scripts/agent-smith-scan-dispositions.json` is schema version 4, with no legacy
schema fallback. `sourceBase` and `sourceTree` preserve upstream identity.
`origins` retains each original raw report SHA-256, independent review digest,
report row count and reviewed source commit/tree. It also stores the original
ordered `rowDigests` and complete `reportContentSha256` commitment. `groups`
preserves each review's reason, citations and `reviewed_non_secret`,
`accepted_inherited_exposure` or `blocked` decision. `history`, `tree` and
`historicalBlob` have separate exact approval collections:

- `origin`, one-based `row`, and `group` bind the original reviewed report/evidence.
- `commit` is the full Git-report commit, or the native empty string for either
  directory scope. Historical-blob occurrence commits come from the hashed
  inventory/context; they are never injected into native directory reports.
- `file` includes exact archive member paths separated by `!`; `rule`, original
  `fingerprint`, and `span` bind the rule and all four coordinates. Span order is
  start line, end line, start column, end column.
- `nativeRowSha256` commits to every native field and value before projection,
  including metadata, optional-field presence and tag-array order. Unsupported
  native fields fail rather than being silently discarded.
- `occurrence` is the one-based ordinal among identical complete native records
  in the original report; `occurrences` is that record's exact multiplicity.
- `blob` is the containing Git blob; `containerSha256` hashes its full bytes;
  `contentSha256` hashes the file or decompressed reviewed member. Plain-file
  content and container digests must agree.

The row commitment hashes UTF-8 `agent-smith/gitleaks-row/v1\0` followed by
`JSON.stringify` of the native object's field/value entries sorted by field name
using ordinal comparison. The report commitment hashes UTF-8
`agent-smith/gitleaks-report/v1\0` followed by `JSON.stringify` of the sorted row
digests, retaining duplicates. Only native object-key order, JSON serialization
and report-row order are normalized. No field, value, context or occurrence is
filtered out. The original raw report digest and review row assignments are
never replaced by the current scanner's serialization or ordering.

Complete report membership and cardinality must match before a scope/path-blob
subset can reuse its reviews, including when findings disappear. Each disposition
must still match its original ordered row commitment and original occurrence
ordinal/count. New/missing rows or changed metadata require independent review;
an equivalent row permutation does not. Current raw reports are still hashed and
retained unchanged, separately from their complete-record commitments.

Fingerprints are not unique identifiers: distinct spans and distinct historical
blobs need distinct approvals. Historical-blob identity includes the blob as well
as the native tuple and full-record digest. Even identical native reports may
describe different blobs, each requiring its own content-bound approval.
Directory columns can be fragment-relative, so distinct source spans can produce
identical native records. Every such row retains its own reviewed ordinal and
source evidence. Missing, extra, changed, partially approved or blocked duplicate
members invalidate the whole group. Reused or reassigned original review rows are
rejected, including swaps between identical records.

The ledger is indexed once, with per-path/blob subsets used by object scans.
One exact path/blob version may reuse its review for occurrence commits supplied
by the complete inventory. A new Git-report commit, changed blob/container/member,
span or unresolved occurrence stays blocked. Scopes never inherit one another's
approvals. Only safe metadata, hashes and review explanations belong in this
public ledger, never detected token/PEM values, author emails, raw reports or
private workspace paths. Approvals require independent review followed by Main's
exact-pin integration and checks; similarity never extends their authority.
`accepted_inherited_exposure` is not a non-secret classification. It records the
maintainer's explicit decision to keep republishing an unresolved occurrence that
upstream already published. The ledger rejects it outside `history`, the scan
rejects it for any commit not reachable from the upstream base, and each decision
counts these occurrences as `accepted`, separately from `approved`.

The retained complete history review covers 281 rows: 267 reviewed non-secret
and 14 accepted inherited exposure. Its original review classified 265
non-secret and 16 blocked; exact Antigravity distribution evidence and the later
Startpage class-level determination each resolve one finding, without changing
any finding identity. All 273 earlier identities remain, but their native `Link`
fields changed and eight additional identities appeared. That required a new
complete review, not filtering `Link` or inheriting the earlier report's
authority. Current-tree dispositions bind one complete reviewed tree report.
Replacing the Xiaomi value with a synthetic placeholder removed exactly two rows
from the C6-reviewed 126-row report; the changed 124-row report needs its own
independent review, whose digest the tree origin binds, before those row reviews
apply again. Historical-blob review covers 13,527 findings from 197 exact native
reports, all reviewed non-secret; four duplicate groups preserve every separately
reviewed occurrence. The mechanical commitment reconciliation preserves those
original object reports, row assignments, source bindings and review digests.

The fourteen inherited Xiaomi history occurrences are accepted inherited exposure.
Exact construction is unresolved; a public third-party claim that the value was
valid is unverified, and no validity or revocation probe was made. This is not a
finding that the value was issued, is live or has been revoked.

The exact historical Startpage `sc` finding is classified as homepage-derived
search-form state. [Pre-capture SearXNG code](https://github.com/searxng/searxng/blob/cf1410af8d794793c8af02b97d3e1cf3bc7a7dda/searx/engines/startpage.py)
documents anonymous homepage extraction, no required API key and shared caching,
and associates the field with bot detection. This supports a bounded anti-bot
inference, not a confirmed account/API credential. The original capture context,
provider binding and lifetime remain unknown; client cache duration and unrelated
cookie lifetimes are not expiry guarantees. The disposition rests on the field
class and exact historical use, not replay mocking or a live validity probe.

The Antigravity pair is bound to the official 2.22.0 macOS ARM64 distribution: native
type metadata and static instructions place both exact parameters in one OAuth
configuration used by its token-acquisition paths. The ledger records publisher
URLs, archive/member digests and byte spans; the independently reviewed proof is
`candidate-13-antigravity-public-client-provenance.json`, SHA-256
`d7df4eb2f6a243c78eb246bb3dd88bce6a20b29994d43cc62d45d5eeb8ba9feb`.
Neither that proof nor the retained Gemini public-native evidence authorizes
registration reuse or provider service access. These are finding dispositions,
not a green baseline, exhaustive binary decoding, rights clearance or publication
approval. Apple code-signature/notarization verification is not claimed.

Native decoder errors are preserved unchanged. The only implemented supplemental
disposition is the independently reviewed AppleDouble v2 metadata in
`packages/utils/test/fixtures/ar.tar.gz`, blob
`cbc578e0d5e4dd556ad1d9d548e9086318e4831d`, at its sole occurrence commit
`6f0fec7bd2de45672050c2aba6be5406bc72e6b6`. Review SHA-256 is
`8d680bd86f879d1474864869c86185e9c68fc009ad046fd32b5e7477ee8ab496`.
The implementation in `scripts/agent-smith-scan-decoder.ts` pins the complete gzip
and tar lengths/hashes and the three complete 163-byte members, including fixed
reviewed header/data offsets, paths, checksums, sizes and member hashes. Bounded
gzip inflation and all member inspection happen in memory. The AppleDouble v2
header and entry table must identify the exact Finder/extended-attribute metadata
and empty resource fork; these members are not valid bzip2 streams.

Every gate run scans each complete member through stdin with the same verified
Gitleaks binary and default configuration, empty ignores, inline allows disabled,
full redaction and decode depth 2. Archive depth is deliberately 0 for these raw
stdin bytes, without the misleading filename. All three must deliver 163 bytes
and return exit 0, a valid empty native JSON report, empty stderr/stdout and no
signal or timeout. Native invocations, outputs and hashed execution receipts are
retained under the exact object's `appledouble/` evidence directory. A failed,
missing or changed supplemental receipt never authorizes an error; previous
exploratory raw-scan receipts cannot substitute for this run.

The historical-blob decision additionally requires the exact single-version
context and exactly one of each of the three observed error lines. Git-history
errors must include the pinned scanner's exact `commit=6f0fec7` field;
directory-scan errors must omit it. Neither scope may borrow the other's log
context. Only the normal clock prefix can vary; other stderr, missing/extra
errors, different paths/commits or unsupported log formats fail.
Whole-history reconciliation happens
after all historical object scans. It requires complete candidate ancestry and
inventory under pinned-base attributes, the reviewed blob's sole addition, the
passing independent whole-blob scan and all raw-member proofs. The archive path
has two baseline versions: the reviewed blob was replaced at
`156300200742fa25d53f9e1acab02afe7f76750d` by
`11b82d8a2cec26c2efd22961700c4435988f7897`; five other commits introduced that
successor. The coverage guard pins all seven raw changes, including exact
old/new modes and objects, plus both versions and all occurrence commits.
The successor receives no exception and must pass ordinary scanning.
`SOURCE_BASE` must remain an ancestor, so the known failing input is still
present; another same-looking failure changes the exact error multiset and
fails. Missing, changed or additional archive lifecycle records invalidate this
binding. Current-tree errors receive no exception, and findings from decoding
are never removed.

Receipts retain the original `nativeDecision`, native report and stderr digests,
plus the separate `decoderDisposition` and final decision; a passing disposition
does not mean native Gitleaks was clean. The implementation's immutable bindings
and this run's verified supplemental receipts govern that disposition; no stale
exploratory receipt authorizes it. No exception exists for the Qwen notice.

Publication, private-reporting, rights, exact-pin independent review and hosted
qualification holds all remain in force. Neither adding reviewed dispositions nor
passing a local scan authorizes publication or clears the other gates.

Only a successful trusted `push` to `main` in `ArkenSecAI/agent-smith` can run the
separate source-provenance job. It archives that exact `GITHUB_SHA`, then attests
and uploads the source archive with narrowly scoped OIDC/attestation permissions.
It accepts no external ref or downloaded PR artifact. The attestation identifies
workflow/repository/commit/digest; it does not prove security, review approval,
license clearance, reproducibility or binary release readiness.

## Verified tool/action pins

| Component               | Pin and primary source                                                                                                                                                               |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Bun                     | [1.4.2 release assets](https://github.com/oven-sh/bun/releases/expanded_assets/bun-v1.4.2), archive SHA-256 values below                                                             |
| Gitleaks                | [8.30.1 assets](https://github.com/gitleaks/gitleaks/releases/expanded_assets/v8.30.1); Linux x64 archive SHA-256 `551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb` |
| checkout                | [11bd71901bbe5b1630ceea73d27597364c9af683](https://github.com/actions/checkout/commit/11bd71901bbe5b1630ceea73d27597364c9af683), v4.2.2                                              |
| upload-artifact         | [ea165f8d65b6e75b540449e92b4886f43607fa02](https://github.com/actions/upload-artifact/commit/ea165f8d65b6e75b540449e92b4886f43607fa02), v4.6.2                                       |
| attest-build-provenance | [e8998f949152b193b063cb0ec769d69d929409be](https://github.com/actions/attest-build-provenance/commit/e8998f949152b193b063cb0ec769d69d929409be), v2.4.0                               |

| Bun archive              | SHA-256                                                            |
| ------------------------ | ------------------------------------------------------------------ |
| `bun-linux-x64.zip`      | `36368faef7527875d5ffa52e53cd48021741f2a83eb6208a8dd64068d422a913` |
| `bun-windows-x64.zip`    | `ce4c17497b2f29712a99d3d53f028de28cd42e3bacb8589599e7f000e49b6405` |
| `bun-darwin-aarch64.zip` | `90987a3a16d7db556d886ac3d551e7b6d3edf0a1cf43acaed622e8676be1d12f` |

`scripts/agent-smith-ci-tools.ps1` verifies hashes before extraction and executable
versions afterward; no curl-to-shell bootstrap is used. Dependency resolutions in
`bun.lock`, `Cargo.lock` and `MODULE.bazel.lock` are preserved and checked.

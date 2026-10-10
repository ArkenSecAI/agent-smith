# Agent Smith P1 development

Agent Smith derives from OMP **18.4.8**, commit
`717f97f4d22b3d65c4a4eef6a744255d46f4d1a6`. Its command is `agent-smith`, its
application version is `0.0.0-unreleased`, and its source entrypoint is
`packages/coding-agent/src/cli.ts`. Internal workspace packages and the native ABI
retain version 18.4.8; this is not an upstream release or a supported installer.

**Publication hold:** no product source ref or remote CI execution is authorized
until an actual non-maintainer tests private vulnerability reporting on
`ArkenSecAI/agent-smith`. An admin cannot substitute for that reporter. Source
rights, inherited scanner findings, exact-pin independent review and required
hosted checks are separate gates; see [the rights inventory](agent-smith-source-rights.md)
and [contribution policy](../CONTRIBUTING.md). A successful local build does not
clear any of them.

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
```

| Command | Behavior |
| --- | --- |
| `smith:prepare` | Check runtime/tools; frozen Bun install with lifecycle scripts disabled; locked Cargo fetch; source host addon build, load/ABI check and real asset generation. |
| `smith:check` | Verify the native receipt; lint/format checks and all workspace/tool typechecks; maintained environment, credentials, discovery, settings and CLI contracts; native crash-path/OAuth callback Rust tests. No automatic fixes. |
| `smith:smoke` | Run the actual source CLI/worker smoke and persistent config round trips, including rejected input and isolated state overrides. |
| `smith:build` | Generate real embedded assets, compile the host executable, restore generated inputs even after failure, package/hash/extract it, then smoke the extracted executable before populating `dist/agent-smith/<host>/`. |
| `smith:native` | Rebuild the reviewed native input pin from source. |
| `smith:native -- --verify` | Verify source/artifact fingerprints, ABI and live native behavior without compiling. |
| `smith:native -- --allow-native-changes` | Intentionally build changed native inputs for development; review and update the source pin before acceptance. |
| `smith:smoke -- --binary /absolute/path/agent-smith` | Exercise a particular executable (`agent-smith.exe` on Windows). |

The root `build` command routes to `smith:build`. Retired global setup, lifecycle
prepare, publication and release aliases are removed, not compatibility shims.
Advanced inherited release/Bazel/Docker/Nix/Python scripts are not the maintained
P1 route or permission to run, deploy or publish them. No provider/model request
is necessary for the four maintained development gates.

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
extract under the synthetic `~/.agent-smith/natives/18.4.8/` and match the receipt.
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
This separation is not VM containment, host sandboxing or target authorization.

## CI, review and scan boundaries

The workflow accepts normal PRs targeting `main` and pushes to `main`, `p1/**` or
`task/**`. It uses `ubuntu-24.04` x64, `windows-2025` x64 and `macos-15` Apple
Silicon, not self-hosted runners. Image labels pin an OS family, not immutable VM
contents. Candidate jobs are read-only, do not persist checkout credentials, and
have no service/signing secrets, privileged PR trigger, Docker or binary upload.
Each provisions the pinned Rust toolchain into RUNNER_TEMP and executes the same
four commands. The hosted matrix has not run while publication is held; local
Linux evidence does not qualify the Windows or macOS rows.

The external main ruleset requires signed commits, no force-push/deletion, and
`Gitleaks 8.30.1` plus `Development (linux-x64)`, `Development (win32-x64)` and
`Development (darwin-arm64)`, bound to GitHub Actions App 15368. Initial branch
creation has no status-check exception. Once all publication gates open, an
independently reviewed exact candidate must complete those checks on a `p1/**` or
`task/**` ref before `main` is created/advanced. CI and workflow authors cannot
approve their own integration; external exact-commit/tree review remains required.

Gitleaks uses the verified 8.30.1 binary, default rules, an explicit empty ignore
file and `--ignore-gitleaks-allow`. It scans full reachable history with first-
parent merge diffs (without restricting ancestry traversal), plus the checkout,
with archive and encoded-content depth 2. Both scans run even when one fails.
No SaaS allowlist, repository baseline or inline allow comment weakens the gate.
Findings are redacted. Gitleaks can exit zero after an archive-decoding error, so
error-only stderr is independently required to be empty. Reports and errors are
retained for seven days. Bounded decoding is not exhaustive analysis of arbitrary
binary formats; unresolved findings and parse errors remain failures, not bypasses.

Only a successful trusted `push` to `main` in `ArkenSecAI/agent-smith` can run the
separate source-provenance job. It archives that exact `GITHUB_SHA`, then attests
and uploads the source archive with narrowly scoped OIDC/attestation permissions.
It accepts no external ref or downloaded PR artifact. The attestation identifies
workflow/repository/commit/digest; it does not prove security, review approval,
license clearance, reproducibility or binary release readiness.

## Verified tool/action pins

| Component | Pin and primary source |
| --- | --- |
| Bun | [1.4.2 release assets](https://github.com/oven-sh/bun/releases/expanded_assets/bun-v1.4.2), archive SHA-256 values below |
| Gitleaks | [8.30.1 assets](https://github.com/gitleaks/gitleaks/releases/expanded_assets/v8.30.1); Linux x64 archive SHA-256 `551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb` |
| checkout | [11bd71901bbe5b1630ceea73d27597364c9af683](https://github.com/actions/checkout/commit/11bd71901bbe5b1630ceea73d27597364c9af683), v4.2.2 |
| upload-artifact | [ea165f8d65b6e75b540449e92b4886f43607fa02](https://github.com/actions/upload-artifact/commit/ea165f8d65b6e75b540449e92b4886f43607fa02), v4.6.2 |
| attest-build-provenance | [e8998f949152b193b063cb0ec769d69d929409be](https://github.com/actions/attest-build-provenance/commit/e8998f949152b193b063cb0ec769d69d929409be), v2.4.0 |

| Bun archive | SHA-256 |
| --- | --- |
| `bun-linux-x64.zip` | `36368faef7527875d5ffa52e53cd48021741f2a83eb6208a8dd64068d422a913` |
| `bun-windows-x64.zip` | `ce4c17497b2f29712a99d3d53f028de28cd42e3bacb8589599e7f000e49b6405` |
| `bun-darwin-aarch64.zip` | `90987a3a16d7db556d886ac3d551e7b6d3edf0a1cf43acaed622e8676be1d12f` |

`scripts/agent-smith-ci-tools.ps1` verifies hashes before extraction and executable
versions afterward; no curl-to-shell bootstrap is used. Dependency resolutions in
`bun.lock`, `Cargo.lock` and `MODULE.bazel.lock` are preserved and checked.

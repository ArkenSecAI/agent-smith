import * as childProcess from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import * as fs from "node:fs";
import { createRequire } from "node:module";
import * as os from "node:os";
import * as path from "node:path";
import * as zlib from "node:zlib";
import packageJson from "../package.json" with { type: "json" };
import { embeddedAddon } from "./embedded-addon.js";
import { validateEmbeddedAddon, validateEmbeddedAddonFiles } from "./embedded-addon-identity.js";
import { bindingsHaveReleaseIdentity, bindingsReleaseVersion, containsVersionStamp } from "./version-sentinel.js";

export * from "./embedded-addon-identity.js";

/**
 * Native addon loader for `@oh-my-pi/pi-natives`.
 *
 * Owns every step between "Node imports `native/index.js`" and "the right
 * `pi_natives.<platform>-<arch>*.node` is required, validated, and returned":
 * platform/variant detection, candidate-path resolution, on-disk staging from
 * `node_modules` (Windows update safety), embedded-addon extraction (Bun
 * standalone binaries), release-stamp validation, and the aggregated error
 * surface for diagnostic-friendly failures.
 *
 * `native/index.js` is reduced to one `loadNative()` call plus the generated
 * surface-area exports between `MARKER_START`/`MARKER_END` (rewritten by
 * `scripts/gen-enums.ts`); everything else lives here so the pure helpers stay
 * unit-testable without triggering the side-effectful module-load path.
 *
 * Background (issue #823): `bun build --compile --define PI_COMPILED=true`
 * substitutes the bare identifier `PI_COMPILED`, NOT `process.env.PI_COMPILED`,
 * so a runtime read of the env var returns `undefined`. Older CommonJS loader
 * code also saw the original build-host absolute path in `__filename`; ESM
 * `import.meta.url` is rewritten to the bunfs URL. The embedded-addon
 * presence (true iff the build pipeline ran `embed:native`, false in the
 * post-build `--reset` stub) is the authoritative compiled-mode signal.
 */

const SUPPORTED_PLATFORMS = [
	"linux-x64",
	"linux-arm64",
	"darwin-x64",
	"darwin-arm64",
	"win32-x64",
	"win32-arm64",
];

/**
 * Streaming startup marker, enabled by `PI_DEBUG_STARTUP`. Local copy of the
 * pi-utils helper (this loader cannot depend on pi-utils). Synchronous on
 * purpose: extraction/dlopen hangs must still leave the `:start` marker.
 * @param {string} text
 */
function startupMarker(text) {
	if (!process.env.PI_DEBUG_STARTUP) return;
	try {
		fs.writeSync(2, `[startup] ${text}\n`);
	} catch {
		// stderr unavailable; markers are best-effort
	}
}

/** Native cache is app-owned and profile-independent, including before CLI bootstrap. */
export function getNativesDir() {
	const xdgCacheHome = process.env.XDG_CACHE_HOME;
	if (
		(process.platform === "linux" || process.platform === "darwin") &&
		xdgCacheHome &&
		fs.existsSync(path.join(xdgCacheHome, "agent-smith"))
	) {
		return path.join(xdgCacheHome, "agent-smith", "natives");
	}
	return path.join(os.homedir(), process.env.AGENT_SMITH_CONFIG_DIR || ".agent-smith", "natives");
}

function resolveLeafPackageDir(platformTag) {
	try {
		const require_ = createRequire(import.meta.url);
		return path.dirname(require_.resolve(`@oh-my-pi/pi-natives-${platformTag}/package.json`));
	} catch {
		return null;
	}
}

// =========================================================================
// Pure helpers — re-exported for unit tests in `packages/natives/test/`.
// =========================================================================

/**
 * @param {{
 *   embeddedAddon: { platformTag: string; version: string; files: unknown[] } | null | undefined;
 *   env: Record<string, string | undefined>;
 *   importMetaUrl: string | null | undefined;
 * }} input
 * @returns {boolean}
 */
export function detectCompiledBinary({ embeddedAddon, env, importMetaUrl }) {
	if (embeddedAddon) return true;
	if (env && env.PI_COMPILED) return true;
	if (typeof importMetaUrl === "string") {
		if (importMetaUrl.includes("$bunfs")) return true;
		if (importMetaUrl.includes("~BUN")) return true;
		if (importMetaUrl.includes("%7EBUN")) return true;
	}
	return false;
}
/**
 * @param {{ tag: string; arch: string; variant: "modern" | "baseline" | null | undefined }} input
 * @returns {string[]}
 */
export function getAddonFilenames({ tag, arch, variant }) {
	const defaultFilename = `pi_natives.${tag}.node`;
	if (arch !== "x64" || !variant) return [defaultFilename];
	const baselineFilename = `pi_natives.${tag}-baseline.node`;
	const modernFilename = `pi_natives.${tag}-modern.node`;
	if (variant === "modern") {
		return [modernFilename, baselineFilename, defaultFilename];
	}
	return [baselineFilename, defaultFilename];
}

/**
 * Decide whether the loader should mirror the package's `native/<filename>.node`
 * into the per-version cache directory (`~/.agent-smith/natives/<version>/`) before loading.
 *
 * Windows-only safety net for `bun install -g` updates: when a previous application
 * process is running, bun cannot overwrite the locked `.node` inside
 * `node_modules/@oh-my-pi/pi-natives/native/`, leaving an old binary next to a
 * newer `index.js` and producing `<sym> is not a function` crashes on the next
 * launch. Staging into the version-pinned cache:
 *   1. Gives every package version its own filesystem path, so concurrent
 *      application processes never collide on the same file.
 *   2. Makes the running process keep its handle on the cache copy, freeing bun
 *      to overwrite the `node_modules` copy on subsequent updates.
 * Disabled on non-Windows (no file-lock problem), in workspace dev (`nativeDir`
 * is not inside a `node_modules` segment), and for compiled binaries (handled
 * by `maybeExtractEmbeddedAddon`).
 *
 * @param {{ platform: NodeJS.Platform | string; isCompiledBinary: boolean; nativeDir: string }} input
 * @returns {boolean}
 */
export function shouldStageNodeModulesAddon({ platform, isCompiledBinary, nativeDir }) {
	if (platform !== "win32") return false;
	if (isCompiledBinary) return false;
	// Check both separators independently of the host's `path.sep`: this helper
	// is shared by the loader (running on Windows with `\`) and the test suite
	// (typically running on POSIX hosts when CI executes the regression test).
	const normalizedNativeDir = nativeDir.toLowerCase();
	return normalizedNativeDir.includes("\\node_modules\\") || normalizedNativeDir.includes("/node_modules/");
}

/**
 * @param {{
 *   addonFilenames: string[];
 *   isCompiledBinary: boolean;
 *   stageFromNodeModules?: boolean;
 *   nativeDir: string;
 *   leafPackageDir?: string | null;
 *   execDir: string;
 *   versionedDir: string;
 *   userDataDir: string;
 * }} input
 * @returns {string[]}
 */
export function resolveLoaderCandidates({
	addonFilenames,
	isCompiledBinary,
	stageFromNodeModules = false,
	nativeDir,
	leafPackageDir = null,
	execDir,
	versionedDir,
	userDataDir,
}) {
	const baseReleaseCandidates = addonFilenames.flatMap(filename => [
		path.join(nativeDir, filename),
		path.join(execDir, filename),
	]);
	const leafCandidates = leafPackageDir ? addonFilenames.map(filename => path.join(leafPackageDir, filename)) : [];
	const compiledCandidates = addonFilenames.flatMap(filename => [
		path.join(versionedDir, filename),
		path.join(userDataDir, filename),
	]);
	const stagedCandidates = stageFromNodeModules ? addonFilenames.map(filename => path.join(versionedDir, filename)) : [];
	let releaseCandidates;
	if (isCompiledBinary) {
		releaseCandidates = [...compiledCandidates, ...baseReleaseCandidates];
	} else if (stageFromNodeModules) {
		releaseCandidates = [...stagedCandidates, ...leafCandidates, ...baseReleaseCandidates];
	} else {
		releaseCandidates = [...leafCandidates, ...baseReleaseCandidates];
	}
	return [...new Set(releaseCandidates)];
}

// =========================================================================

function parseReleaseVersion(version) {
	const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(version);
	return match ? [Number(match[1]), Number(match[2]), Number(match[3])] : null;
}

function isOlderReleaseVersion(candidate, current) {
	const candidateParts = parseReleaseVersion(candidate);
	const currentParts = parseReleaseVersion(current);
	if (!candidateParts || !currentParts) return false;
	for (let index = 0; index < candidateParts.length; index++) {
		if (candidateParts[index] !== currentParts[index]) {
			return candidateParts[index] < currentParts[index];
		}
	}
	return false;
}

// A concurrently starting older OMP binary creates or refreshes this directory
// before extracting its addon. Keep fresh directories long enough for that
// startup to finish; a later launch can reclaim them once they are genuinely
// stale.
const NATIVE_CACHE_CLEANUP_GRACE_MS = 10 * 60_000;

/**
 * Create a version cache directory and refresh its activity timestamp before
 * extraction or staging begins. Recursive mkdir does not update the mtime of
 * an existing directory, so the explicit touch is what protects interrupted
 * or partially populated caches from concurrent cleanup.
 *
 * @param {string} versionedDir
 */
export function prepareNativeVersionDir(versionedDir) {
	fs.mkdirSync(versionedDir, { recursive: true });
	const now = new Date();
	fs.utimesSync(versionedDir, now, now);
}

/**
 * Remove version-pinned native cache directories older than the loaded package.
 * Best-effort by design: permission errors and concurrent processes must not
 * abort startup after the native addon has already loaded successfully.
 *
 * @param {{ nativesDir: string; currentVersion: string }} input
 * @returns {string[]}
 */
export function cleanupStaleNativeVersions({ nativesDir, currentVersion }) {
	const removed = [];
	let entries;
	try {
		entries = fs.readdirSync(nativesDir, { withFileTypes: true });
	} catch {
		return removed;
	}

	for (const entry of entries) {
		if (!entry.isDirectory() || !isOlderReleaseVersion(entry.name, currentVersion)) continue;
		const targetPath = path.join(nativesDir, entry.name);
		try {
			const stat = fs.statSync(targetPath);
			if (Date.now() - stat.mtimeMs < NATIVE_CACHE_CLEANUP_GRACE_MS) continue;
			fs.rmSync(targetPath, { recursive: true, force: true });
			removed.push(targetPath);
		} catch {
			// Stale caches are opportunistic cleanup only.
		}
	}
	return removed;
}

// Side-effectful loader. Everything below runs only when `loadNative()` is
// called from `native/index.js` — tests that only import the pure helpers
// above pay nothing for variant detection, subprocess spawns, or fs probes.
// =========================================================================

/**
 * Hidden env key for the resolved x64 variant. Once any context (main thread,
 * worker, subprocess) finishes variant detection, the result is written here
 * so every Bun worker and child process spawned afterwards inherits the same
 * verdict and skips re-detection. See `selectCpuVariant` for the lookup order.
 */
const VARIANT_CACHE_ENV_KEY = "__PI_NATIVE_VARIANT_CACHE";

/**
 * Spawn `command` with `args` and capture stdout. Prefers `Bun.spawnSync`
 * because Bun's `child_process.spawnSync` shim has been observed to return
 * non-zero / null in worker threads on macOS even when the same binary works
 * fine from the parent — the failure mode behind issue #3238, where the worker
 * silently falls back to the "baseline" variant. Falls back to the Node shim
 * for non-Bun embeds.
 */
function runCommand(command, args) {
	if (typeof Bun !== "undefined" && typeof Bun.spawnSync === "function") {
		try {
			const result = Bun.spawnSync([command, ...args], { stdout: "pipe", stderr: "pipe" });
			if (result.exitCode === 0) {
				return result.stdout.toString("utf-8").trim();
			}
		} catch {
			// fall through to childProcess
		}
	}
	try {
		const result = childProcess.spawnSync(command, args, { encoding: "utf-8" });
		if (result.error) return null;
		if (result.status !== 0) return null;
		return (result.stdout || "").trim();
	} catch {
		return null;
	}
}

function getVariantOverride() {
	const value = process.env.AGENT_SMITH_NATIVE_VARIANT;
	if (!value) return null;
	if (value === "modern" || value === "baseline") return value;
	return null;
}

function detectAvx2Support() {
	if (process.arch !== "x64") {
		return false;
	}

	if (process.platform === "linux") {
		try {
			const cpuInfo = fs.readFileSync("/proc/cpuinfo", "utf8");
			return /\bavx2\b/i.test(cpuInfo);
		} catch {
			return false;
		}
	}

	if (process.platform === "darwin") {
		// Try the absolute path before bare `sysctl`: PATH may not include
		// `/usr/sbin` in worker/embedded spawn contexts (issue #3238).
		for (const sysctlBin of ["/usr/sbin/sysctl", "sysctl"]) {
			const leaf7 = runCommand(sysctlBin, ["-n", "machdep.cpu.leaf7_features"]);
			if (leaf7 && /\bAVX2\b/i.test(leaf7)) return true;
			const features = runCommand(sysctlBin, ["-n", "machdep.cpu.features"]);
			if (features && /\bAVX2\b/i.test(features)) return true;
		}
		return false;
	}

	if (process.platform === "win32") {
		// Under Bun, ask the kernel: PF_AVX2_INSTRUCTIONS_AVAILABLE == 40. Exact,
		// and ~0.5 ms against ~270 ms for the PowerShell spawn it replaces on the
		// startup path.
		if (typeof Bun !== "undefined") {
			try {
				const { dlopen, FFIType } = createRequire(import.meta.url)("bun:ffi");
				const kernel32 = dlopen("kernel32.dll", {
					IsProcessorFeaturePresent: { args: [FFIType.u32], returns: FFIType.i32 },
				});
				try {
					return kernel32.symbols.IsProcessorFeaturePresent(40) !== 0;
				} finally {
					kernel32.close();
				}
			} catch {
				// No FFI (embedder policy, unusual host): fall through to the shell probe.
			}
		}
		// Node embeds have no `bun:ffi`. `[System.Runtime.Intrinsics.X86.Avx2]`
		// exists only on .NET Core, so `pwsh` (PowerShell 7) answers correctly
		// while a stock `powershell.exe` (Windows PowerShell 5.1, .NET Framework)
		// raises TypeNotFound and pins such hosts to the baseline addon.
		for (const shell of ["pwsh.exe", "powershell.exe"]) {
			const output = runCommand(shell, [
				"-NoProfile",
				"-NonInteractive",
				"-Command",
				"[System.Runtime.Intrinsics.X86.Avx2]::IsSupported",
			]);
			if (output && output.toLowerCase() === "true") return true;
			if (output && output.toLowerCase() === "false") return false;
		}
		return false;
	}

	return false;
}

/**
 * Pure variant-selection helper, exposed for unit tests. Resolution order:
 *
 *   1. `override` (user-facing `PI_NATIVE_VARIANT` env var). Always wins.
 *   2. The private `__PI_NATIVE_VARIANT_CACHE` env var, populated by the first
 *      context that detected at runtime. Lets child workers / subprocesses
 *      inherit the main thread's verdict instead of re-spawning `sysctl` etc.
 *      from a worker context where the spawn may fail (issue #3238).
 *   3. `detectAvx2()` — the slow path, called at most once per process.
 *
 * Non-x64 architectures return `{ variant: null }` and never set the cache.
 * When detection runs, the result is surfaced as `cacheEnvKey`/`cacheEnvValue`
 * so the caller can write `process.env` (the pure helper itself stays
 * side-effect-free, which keeps it easy to test).
 *
 * @param {{
 *   arch: string;
 *   override: "modern" | "baseline" | null | undefined;
 *   env: Record<string, string | undefined>;
 *   detectAvx2: () => boolean;
 * }} input
 * @returns {{
 *   variant: "modern" | "baseline" | null;
 *   source: "non-x64" | "override" | "cache" | "detect";
 *   cacheEnvKey?: string;
 *   cacheEnvValue?: string;
 * }}
 */
export function selectCpuVariant({ arch, override, env, detectAvx2 }) {
	if (arch !== "x64") return { variant: null, source: "non-x64" };
	if (override === "modern" || override === "baseline") {
		return { variant: override, source: "override" };
	}
	const cached = env[VARIANT_CACHE_ENV_KEY];
	if (cached === "modern" || cached === "baseline") {
		return { variant: cached, source: "cache" };
	}
	const variant = detectAvx2() ? "modern" : "baseline";
	return {
		variant,
		source: "detect",
		cacheEnvKey: VARIANT_CACHE_ENV_KEY,
		cacheEnvValue: variant,
	};
}

function resolveCpuVariant(override) {
	const result = selectCpuVariant({
		arch: process.arch,
		override,
		env: process.env,
		detectAvx2: detectAvx2Support,
	});
	if (result.cacheEnvKey) {
		process.env[result.cacheEnvKey] = result.cacheEnvValue;
	}
	return result.variant;
}

function readTarString(buffer, offset, length) {
	const end = Math.min(offset + length, buffer.length);
	let stringEnd = offset;
	while (stringEnd < end && buffer[stringEnd] !== 0) stringEnd++;
	return buffer.toString("utf8", offset, stringEnd);
}

function readTarOctal(buffer, offset, length) {
	const value = readTarString(buffer, offset, length).trim();
	if (!value) return 0;
	const parsed = Number.parseInt(value, 8);
	if (!/^[0-7]+$/.test(value) || !Number.isSafeInteger(parsed)) {
		throw new Error(`Invalid tar octal value: ${value}`);
	}
	return parsed;
}

function isZeroTarBlock(buffer, offset) {
	for (let index = 0; index < 512; index++) {
		if (buffer[offset + index] !== 0) return false;
	}
	return true;
}

function getTarEntryName(header) {
	const name = readTarString(header, 0, 100);
	const prefix = readTarString(header, 345, 155);
	return prefix ? `${prefix}/${name}` : name;
}

function isSafeEmbeddedAddonFilename(filename) {
	return filename.length > 0 && path.basename(filename) === filename && !filename.includes("/") && !filename.includes("\\");
}

function isEmbeddedAddonFileCurrent(targetPath, file) {
	let fd;
	try {
		// A symlink would let require() resolve back to a shared module path.
		if (!fs.lstatSync(targetPath).isFile()) return false;
		fd = fs.openSync(targetPath, "r");
		const stat = fs.fstatSync(fd);
		if (!stat.isFile() || stat.size !== file.size) return false;
		const hash = createHash("sha256");
		const chunk = Buffer.allocUnsafe(Math.min(file.size, 1024 * 1024));
		let offset = 0;
		while (offset < file.size) {
			const count = fs.readSync(fd, chunk, 0, Math.min(chunk.length, file.size - offset), offset);
			if (count === 0) return false;
			hash.update(chunk.subarray(0, count));
			offset += count;
		}
		const after = fs.fstatSync(fd);
		return (
			after.size === stat.size &&
			after.mtimeMs === stat.mtimeMs &&
			after.ctimeMs === stat.ctimeMs &&
			hash.digest("hex") === file.sha256
		);
	} catch (err) {
		if (err && err.code === "ENOENT") return false;
		throw err;
	} finally {
		if (fd !== undefined) fs.closeSync(fd);
	}
}

function writeEmbeddedAddonFile(targetPath, content) {
	const tempPath = `${targetPath}.tmp.${process.pid}.${randomUUID()}`;
	try {
		fs.writeFileSync(tempPath, content, { mode: 0o755, flag: "wx" });
		fs.renameSync(tempPath, targetPath);
	} catch (err) {
		try {
			fs.unlinkSync(tempPath);
		} catch {
			// Best-effort cleanup only.
		}
		throw err;
	}
}

export function extractEmbeddedAddonArchive({ archivePath, files, targetDir }) {
	validateEmbeddedAddonFiles(files);
	const pending = new Map();
	for (const file of files) {
		const targetPath = path.join(targetDir, file.filename);
		if (!isEmbeddedAddonFileCurrent(targetPath, file)) {
			pending.set(file.filename, file);
		}
	}
	if (pending.size === 0) return [];

	const archive = zlib.gunzipSync(fs.readFileSync(archivePath));
	const expected = new Map(files.map(file => [file.filename, file]));
	const contents = new Map();
	let offset = 0;

	while (offset + 512 <= archive.length) {
		if (isZeroTarBlock(archive, offset)) break;
		const header = archive.subarray(offset, offset + 512);
		const filename = getTarEntryName(header);
		const size = readTarOctal(header, 124, 12);
		const typeflag = header[156] === 0 ? "0" : String.fromCharCode(header[156]);
		offset += 512;

		if (offset + size > archive.length) {
			throw new Error(`Truncated embedded addon archive entry: ${filename}`);
		}

		if (!isSafeEmbeddedAddonFilename(filename)) {
			throw new Error(`Unsafe embedded addon archive entry: ${filename}`);
		}
		if (typeflag !== "0") {
			throw new Error(`Unsupported embedded addon archive entry type ${typeflag}: ${filename}`);
		}

		const file = expected.get(filename);
		if (!file || contents.has(filename)) {
			throw new Error(`Unexpected or duplicate embedded addon archive entry: ${filename}`);
		}
		const content = archive.subarray(offset, offset + size);
		if (file.size !== size || createHash("sha256").update(content).digest("hex") !== file.sha256) {
			throw new Error(`Embedded addon integrity mismatch: ${filename}`);
		}
		// Retain views, not copies, and validate the entire archive before publishing any file.
		contents.set(filename, content);

		offset += Math.ceil(size / 512) * 512;
	}

	const missing = files.filter(file => !contents.has(file.filename));
	if (missing.length > 0) {
		throw new Error(`Embedded addon archive missing: ${missing.map(file => file.filename).join(", ")}`);
	}

	const writtenPaths = [];
	for (const filename of pending.keys()) {
		const targetPath = path.join(targetDir, filename);
		writeEmbeddedAddonFile(targetPath, contents.get(filename));
		writtenPaths.push(targetPath);
	}
	return writtenPaths;
}

function maybeExtractEmbeddedAddon(ctx, errors, verifiedCandidates) {
	const addon = ctx.embeddedAddon;
	if (!ctx.isCompiledBinary) return null;
	const selectedEmbeddedFile = ctx.addonFilenames
		.map(filename => addon.files.find(file => file.filename === filename))
		.find(Boolean);
	if (!selectedEmbeddedFile) return null;
	const targetPath = path.join(ctx.versionedDir, selectedEmbeddedFile.filename);

	startupMarker("native:extractEmbeddedAddon:start");
	try {
		prepareEmbeddedAddonCacheDir(ctx.nativesDir, addon);
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		errors.push(`embedded addon dir: ${message}`);
		return null;
	}

	try {
		extractEmbeddedAddonArchive({
			archivePath: addon.archive.filePath,
			files: addon.files,
			targetDir: ctx.versionedDir,
		});
		// This synchronous load attempt can reuse the checks just performed by
		// extraction, including checks on warm cache files. Never persist them.
		for (const file of addon.files) verifiedCandidates.add(path.join(ctx.versionedDir, file.filename));
		return targetPath;
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		errors.push(`embedded addon archive (${addon.archive.filename}): ${message}`);
		return null;
	}
}

function embeddedAddonCacheDir(nativesDir, addon) {
	return path.join(nativesDir, addon.version, addon.artifactId);
}

function prepareEmbeddedAddonCacheDir(nativesDir, addon) {
	// Cleanup examines the version parent, so refresh it as well as the
	// artifact directory while an older release starts beside a newer one.
	prepareNativeVersionDir(path.join(nativesDir, addon.version));
	prepareNativeVersionDir(embeddedAddonCacheDir(nativesDir, addon));
}

/** Verify a fallback's copied bytes before giving dlopen an artifact-specific path. */
export function prepareEmbeddedAddonCandidate({ addon, candidate, nativesDir }) {
	validateEmbeddedAddon(addon);
	const file = addon.files.find(file => file.filename === path.basename(candidate));
	if (!file) throw new Error(`Native candidate is absent from the embedded manifest: ${candidate}`);
	const targetDir = embeddedAddonCacheDir(nativesDir, addon);
	const targetPath = path.join(targetDir, file.filename);
	if (path.resolve(candidate) === path.resolve(targetPath)) {
		if (!isEmbeddedAddonFileCurrent(targetPath, file)) {
			throw new Error(`Embedded addon integrity mismatch: ${candidate}`);
		}
		return targetPath;
	}

	prepareEmbeddedAddonCacheDir(nativesDir, addon);
	const tempPath = `${targetPath}.tmp.${process.pid}.${randomUUID()}`;
	try {
		// Copy first, then hash that snapshot: no full-buffer allocation and no
		// gap between checking the fallback's bytes and copying different bytes.
		fs.copyFileSync(candidate, tempPath, fs.constants.COPYFILE_EXCL);
		if (!isEmbeddedAddonFileCurrent(tempPath, file)) {
			throw new Error(`Embedded addon integrity mismatch: ${candidate}`);
		}
		fs.renameSync(tempPath, targetPath);
		return targetPath;
	} finally {
		try {
			fs.unlinkSync(tempPath);
		} catch {
			// Renamed on success; cleanup is best-effort on failure.
		}
	}
}

/**
 * Mirror `leafPackageDir ?? nativeDir` addon binaries to
 * `versionedDir/<filename>.node` on Windows installs so the running process
 * cache path, never on the `node_modules` copy that bun must overwrite on
 * update. No-op on non-Windows, in workspace dev, and for compiled binaries —
 * see `shouldStageNodeModulesAddon` for the gating rules.
 */
function maybeStageNodeModulesAddon(ctx, errors) {
	if (!ctx.stageFromNodeModules) return null;

	let stagedPath = null;
	for (const filename of ctx.addonFilenames) {
		const sourcePath = path.join(ctx.leafPackageDir ?? ctx.nativeDir, filename);
		const targetPath = path.join(ctx.versionedDir, filename);

		if (fs.existsSync(targetPath)) {
			stagedPath = stagedPath || targetPath;
			continue;
		}
		if (!fs.existsSync(sourcePath)) continue;

		try {
			prepareNativeVersionDir(ctx.versionedDir);
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			errors.push(`staged addon dir: ${message}`);
			continue;
		}

		try {
			// `copyFileSync` is atomic on Windows (CopyFileW) and avoids holding
			// two large buffers in JS for the read/write dance.
			fs.copyFileSync(sourcePath, targetPath);
			stagedPath = stagedPath || targetPath;
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			errors.push(`staged addon copy (${filename}): ${message}`);
		}
	}
	return stagedPath;
}

/**
 * Before release identities existed, published native addons still shared
 * this stable core ABI. Let those on-disk addons bridge a package-version bump
 * when they expose the signature; keep every identified addon and a current
 * on-disk file paired with resident old exports on the strict path below.
 */
function isCompatiblePreSentinelNativeAddon(bindings, diskHasExpectedStamp) {
	if (diskHasExpectedStamp) return false;
	if (bindingsHaveReleaseIdentity(bindings)) return false;
	return (
		typeof bindings.countTokens === "function" &&
		typeof bindings.executeShell === "function" &&
		typeof bindings.visibleWidth === "function" &&
		typeof bindings.DesktopSession === "function" &&
		typeof bindings.DesktopSession.prototype?.capture === "function" &&
		typeof bindings.DesktopSession.prototype?.execute === "function" &&
		typeof bindings.DesktopSession.prototype?.close === "function"
	);
}

export function validateLoadedBindings(ctx, bindings, candidate) {
	// In workspace dev (running out of `packages/natives/native/` rather than a
	// `node_modules` install or a compiled bundle) the local `.node` only gains
	// the new release stamp after `bun --cwd=packages/natives run build`. Skip
	// validation there so a stale post-pull dev tree boots while the rebuild
	// completes; install and compiled-binary paths still validate. The mismatch
	// is not swallowed silently: `native/index.js` exports `missingNativeExport`
	// for every symbol the stale addon predates, so the first call through one
	// reports the addon, both releases, and the rebuild command.
	if (ctx.isWorkspaceLoad) return;
	const residentVersion = bindingsReleaseVersion(bindings);
	if (residentVersion === ctx.packageVersion) return;

	// The bindings report another release (or none). Distinguish two failure
	// modes by what the file on disk carries:
	//   - disk stale: the `.node` on disk predates this loader (its own build);
	//     reinstalling re-syncs the file.
	//   - process stale: an in-place upgrade landed a new release on disk while
	//     this process still holds the previous addon generation resident in the
	//     dynamic-loader's native-module cache. `require` returns those old
	//     exports, which report the PRIOR release — disk is already consistent,
	//     so reinstall is a no-op and only restarting the process re-syncs.
	// Resident exports alone cannot tell these apart: `require` returns the
	// same exports in both cases. The restart diagnosis is valid only when the
	// selected file itself carries the current stamp; otherwise a restart would
	// simply reload stale disk.
	let diskHasExpectedStamp = false;
	try {
		diskHasExpectedStamp = containsVersionStamp(fs.readFileSync(candidate), ctx.packageVersion);
	} catch {
		// The successful require above normally guarantees readability. If the
		// file disappears concurrently, retain the safe reinstall diagnosis.
	}
	if (isCompatiblePreSentinelNativeAddon(bindings, diskHasExpectedStamp)) return;
	if (residentVersion && diskHasExpectedStamp) {
		throw new Error(
			`Loaded ${candidate}, which reports @oh-my-pi/pi-natives@${residentVersion}, but this loader is ` +
				`@${ctx.packageVersion}. omp was upgraded to ${ctx.packageVersion} while this session was running; ` +
				`the ${residentVersion} addon is still resident in this process. Disk is already consistent — ` +
				`restart omp to pick up ${ctx.packageVersion} (reinstalling changes nothing).`,
		);
	}
	throw new Error(
		`Loaded ${candidate} but it reports ${residentVersion ? `@oh-my-pi/pi-natives@${residentVersion}` : "no release version"}, ` +
			`not the @${ctx.packageVersion} this loader expects. The .node file on disk is from a different ` +
			"release than this loader — reinstall to re-sync.",
	);
}

/**
 * Identity of the addon `loadNative()` returned, in the shape the
 * missing-export diagnostic reports. Null until a load succeeds.
 * @type {{ path: string; version: string | null; packageVersion: string; stale: boolean } | null}
 */
let loadedAddon = null;

// A module already loaded through its verified artifact path needs no further
// dlopen or 190 MB hash pass when another native facade imports this loader.
let loadedCompiledBindings = null;

/**
 * Describe a loaded addon so a symbol it predates can name the file, the
 * release the file came from, and the release this tree expects.
 * @param {Record<string, unknown>} bindings
 * @param {string} candidate
 * @param {{ packageVersion: string }} ctx
 */
function describeLoadedAddon(bindings, candidate, ctx) {
	const version = bindingsReleaseVersion(bindings);
	return {
		path: candidate,
		version,
		packageVersion: ctx.packageVersion,
		stale: version !== ctx.packageVersion,
	};
}

/**
 * The addon behind this process's `@oh-my-pi/pi-natives` exports.
 * @returns {{ path: string; version: string | null; packageVersion: string; stale: boolean } | null}
 */
export function nativeAddonStatus() {
	return loadedAddon;
}

/**
 * Stand-in for an export the loaded addon does not provide.
 *
 * A workspace tree tolerates a release mismatch on purpose: a checkout that
 * pulled a new release keeps running until `bun run build:native` finishes
 * (see `validateLoadedBindings`), and PR CI loads release addons under a newer
 * checkout the same way. Such an addon has no value for any symbol added after
 * its build, so a bare `undefined` export surfaced as `<symbol> is not a
 * function` — every `write` call in a tree that pulled the read-projection
 * guard, for one — with nothing naming the stale addon.
 *
 * Only a stale addon gets the stub. On a current addon an absent export is not
 * version drift but a symbol this build does not implement, and callers probe
 * for exactly that (`typeof native.x === "function"`); they must keep seeing
 * `undefined`.
 * @param {string} symbolName
 * @param {ReturnType<typeof nativeAddonStatus>} [addon]
 * @returns {((...args: unknown[]) => never) | undefined}
 */
export function missingNativeExport(symbolName, addon = loadedAddon) {
	if (!addon?.stale) return undefined;
	return () => {
		throw new Error(missingNativeExportMessage(symbolName, addon));
	};
}

/**
 * Actionable text for {@link missingNativeExport}. `addon` is injectable so the
 * wording can be pinned without a stale `.node` on disk.
 * @param {string} symbolName
 * @param {ReturnType<typeof nativeAddonStatus>} [addon]
 * @returns {string}
 */
export function missingNativeExportMessage(symbolName, addon = loadedAddon) {
	const rebuild = "rebuild it with `bun run build:native`";
	if (!addon) return `@oh-my-pi/pi-natives does not export \`${symbolName}\`; ${rebuild}.`;
	if (!addon.stale) {
		return `@oh-my-pi/pi-natives export \`${symbolName}\` is missing from ${addon.path}; ${rebuild}.`;
	}
	const loaded = addon.version
		? `the @oh-my-pi/pi-natives@${addon.version} addon`
		: "an addon without a release stamp";
	return (
		`@oh-my-pi/pi-natives export \`${symbolName}\` is missing: ${addon.path} is ${loaded}, not ` +
		`@${addon.packageVersion} — ${rebuild}.`
	);
}

/**
 * Install the addon's bounded Tokio runtime now that `dlopen` has returned and
 * the dynamic-loader lock is released. The Rust `#[module_init]` deliberately
 * does NOT build the runtime — spawning worker threads under the loader lock
 * deadlocks on some hosts — so it exposes `__ompInstallTokioRuntime` for the
 * loader to call once, before any async native runs. Best-effort: older addons
 * predating this export simply fall back to napi-rs's default runtime.
 */
function installNativeTokioRuntime(bindings) {
	const install = bindings.__ompInstallTokioRuntime;
	if (typeof install !== "function") return;
	try {
		install();
		startupMarker("native:tokioRuntime:installed");
	} catch (err) {
		startupMarker(`native:tokioRuntime:failed:${err instanceof Error ? err.message : String(err)}`);
	}
}


function buildHelpMessage(ctx) {
	if (ctx.isCompiledBinary) {
		const expectedPaths = ctx.addonFilenames.map(filename => `  ${path.join(ctx.versionedDir, filename)}`).join("\n");
		return `The compiled binary should extract one of:\n${expectedPaths}\n\n` +
			"Agent Smith is unreleased. Rebuild the native assets from the pinned source checkout.";
	}
	return (
		"If installed via npm/bun, try reinstalling: bun install @oh-my-pi/pi-natives\n" +
		"If developing locally, build with: bun --cwd=packages/natives run build\n" +
		"Explicit targets: bun scripts/bazel-natives.ts <target> --dest packages/natives/native"
	);
}

/**
 * Initialize the loader context: resolves every path, variant, and policy
 * decision once so the inner load loop stays a pure require/validate pipeline.
 * Called from `loadNative()` rather than at module scope so importing pure
 * helpers from this file doesn't trigger AVX2 detection or filesystem probes.
 */
/**
 * @param {{ nativeDir?: string; platform?: NodeJS.Platform | string; isCompiledBinary?: boolean; leafPackageDir?: string | null; embeddedAddon?: object | null }} [overrides]
 */
export function initLoaderContext(overrides = {}) {
	const platform = overrides.platform ?? process.platform;
	const platformTag = `${platform}-${process.arch}`;
	const packageVersion = packageJson.version;
	const nativeDir = overrides.nativeDir ?? path.join(import.meta.dir, "..", "native");
	const execDir = path.dirname(process.execPath);
	const nativesDir = getNativesDir();
	const addon = overrides.embeddedAddon === undefined ? embeddedAddon : overrides.embeddedAddon;
	const userDataDir =
		platform === "win32"
			? path.join(process.env.LOCALAPPDATA || path.join(os.homedir(), "AppData", "Local"), "agent-smith")
			: path.join(os.homedir(), ".local", "share", "agent-smith", "bin");

	const isCompiledBinary =
		overrides.isCompiledBinary ??
		detectCompiledBinary({
			embeddedAddon: addon,
			env: process.env,
			importMetaUrl: import.meta.url,
		});
	if (isCompiledBinary) {
		// Metadata failures are fatal before any extraction or fallback require.
		validateEmbeddedAddon(addon);
		if (addon.platformTag !== platformTag || addon.version !== packageVersion) {
			throw new Error("Embedded addon platform or version does not match this loader");
		}
	}
	const versionedDir = isCompiledBinary
		? embeddedAddonCacheDir(nativesDir, addon)
		: path.join(nativesDir, packageVersion);
	const normalizedNativeDir = platform === "win32" ? nativeDir.toLowerCase() : nativeDir;
	const isWorkspaceLoad =
		!isCompiledBinary &&
		!normalizedNativeDir.includes("\\node_modules\\") &&
		!normalizedNativeDir.includes("/node_modules/");
	const leafPackageDir =
		isCompiledBinary || isWorkspaceLoad
			? null
			: overrides.leafPackageDir === undefined
				? resolveLeafPackageDir(platformTag)
				: overrides.leafPackageDir;
	const stageFromNodeModules = shouldStageNodeModulesAddon({
		platform,
		isCompiledBinary,
		nativeDir: normalizedNativeDir,
	});

	const selectedVariant = resolveCpuVariant(getVariantOverride());
	const addonFilenames = getAddonFilenames({ tag: platformTag, arch: process.arch, variant: selectedVariant });
	const addonLabel = selectedVariant ? `${platformTag} (${selectedVariant})` : platformTag;

	const candidates = resolveLoaderCandidates({
		addonFilenames,
		isCompiledBinary,
		stageFromNodeModules,
		nativeDir,
		leafPackageDir,
		execDir,
		versionedDir,
		userDataDir,
	});

	// Release validation compares `__piNativesBuildVersion()` — the version the
	// build pipeline stamps into the addon after linking
	// (`scripts/stamp-native-version.ts`) — with `package.json#version`, so a
	// `.node` from a different release is rejected at load time instead of
	// surfacing later as a silent `<sym> is not a function` crash from a
	// Windows locked-file update.

	return {
		platformTag,
		packageVersion,
		nativeDir,
		leafPackageDir,
		versionedDir,
		isCompiledBinary,
		embeddedAddon: isCompiledBinary ? addon : null,
		stageFromNodeModules,
		selectedVariant,
		addonFilenames,
		addonLabel,
		candidates,
		isWorkspaceLoad,
		nativesDir,
	};
}

export function loadNative() {
	if (loadedCompiledBindings) return loadedCompiledBindings;
	startupMarker("native:loadNative:start");
	const ctx = initLoaderContext();
	const require_ = createRequire(import.meta.url);

	const errors = [];
	const verifiedCandidates = new Set();
	const embeddedCandidate = maybeExtractEmbeddedAddon(ctx, errors, verifiedCandidates);
	const stagedCandidate = embeddedCandidate ? null : maybeStageNodeModulesAddon(ctx, errors);
	const prepended = [embeddedCandidate, stagedCandidate].filter(c => typeof c === "string");
	const runtimeCandidates = prepended.length > 0 ? [...prepended, ...ctx.candidates] : ctx.candidates;
	const attempted = new Set();

	for (const candidate of new Set(runtimeCandidates)) {
		try {
			let loadPath = candidate;
			if (ctx.isCompiledBinary) {
				const targetPath = path.join(ctx.versionedDir, path.basename(candidate));
				if (attempted.has(targetPath)) continue;
				loadPath = verifiedCandidates.has(candidate)
					? candidate
					: prepareEmbeddedAddonCandidate({ addon: ctx.embeddedAddon, candidate, nativesDir: ctx.nativesDir });
				// Even fallback bytes use the artifact path: hashing a shared path
				// cannot identify an older same-ABI module already resident there.
				attempted.add(loadPath);
			}
			startupMarker(`native:require:${path.basename(loadPath)}`);
			const bindings = require_(loadPath);
			validateLoadedBindings(ctx, bindings, loadPath);
			installNativeTokioRuntime(bindings);
			loadedAddon = describeLoadedAddon(bindings, loadPath, ctx);
			if (ctx.isCompiledBinary) loadedCompiledBindings = bindings;
			cleanupStaleNativeVersions({ nativesDir: ctx.nativesDir, currentVersion: ctx.packageVersion });
			startupMarker("native:loadNative:done");
			return bindings;
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			errors.push(`${candidate}: ${message}`);
		}
	}

	if (!SUPPORTED_PLATFORMS.includes(ctx.platformTag)) {
		throw new Error(
			`Unsupported platform: ${ctx.platformTag}\n` +
				`Supported platforms: ${SUPPORTED_PLATFORMS.join(", ")}\n` +
				"If you need support for this platform, please open an issue.",
		);
	}
	const details = errors.map(error => `- ${error}`).join("\n");
	throw new Error(
		`Failed to load pi_natives native addon for ${ctx.addonLabel}.\n\nTried:\n${details}\n\n${buildHelpMessage(ctx)}`,
	);
}

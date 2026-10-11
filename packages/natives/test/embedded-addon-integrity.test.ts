import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
	cleanupStaleNativeVersions,
	type EmbeddedAddon,
	extractEmbeddedAddonArchive,
	getEmbeddedAddonArtifactId,
	initLoaderContext,
	prepareEmbeddedAddonCandidate,
} from "../native/loader-state.js";
import packageJson from "../package.json" with { type: "json" };
import { embedNativeAddon } from "../scripts/embed-native";

interface Fixture {
	root: string;
	nativeDir: string;
	nativesDir: string;
	addon: EmbeddedAddon;
	bytes: Buffer<ArrayBuffer>;
	alternate: Buffer<ArrayBuffer>;
	candidate: string;
	cacheDir: string;
	cachePath: string;
}

async function withFixture(run: (fixture: Fixture) => Promise<void>): Promise<void> {
	const root = await fs.mkdtemp(path.join(os.tmpdir(), "native-artifact-integrity-"));
	try {
		const nativeDir = path.join(root, "native");
		const nativesDir = path.join(root, "cache");
		const suffix = process.arch === "x64" ? "-baseline" : "";
		const candidate = path.join(nativeDir, `pi_natives.${process.platform}-${process.arch}${suffix}.node`);
		const bytes = Buffer.from(`payload A\0PI_NATIVES_VERSION_STAMP:${packageJson.version}\0`);
		const alternate = Buffer.from(`payload B\0PI_NATIVES_VERSION_STAMP:${packageJson.version}\0`);
		await Bun.write(candidate, bytes);
		const addon = await embedNativeAddon({
			targetPlatform: process.platform,
			targetArch: process.arch,
			nativeDir,
			outputPath: path.join(nativeDir, "embedded-addon.js"),
			version: packageJson.version,
		});
		const cacheDir = path.join(nativesDir, addon.version, addon.artifactId);
		await fs.mkdir(cacheDir, { recursive: true });
		await run({
			root,
			nativeDir,
			nativesDir,
			addon,
			bytes,
			alternate,
			candidate,
			cacheDir,
			cachePath: path.join(cacheDir, path.basename(candidate)),
		});
	} finally {
		await fs.rm(root, { recursive: true, force: true });
	}
}

function extract(addon: EmbeddedAddon, targetDir: string): string[] {
	return extractEmbeddedAddonArchive({ archivePath: addon.archive.filePath, files: addon.files, targetDir });
}

describe("embedded native artifact integrity", () => {
	it("replaces same-size, same-ABI cached bytes with the packaged bytes", async () => {
		await withFixture(async ({ addon, bytes, alternate, cacheDir, cachePath }) => {
			await Bun.write(cachePath, alternate);
			expect(extract(addon, cacheDir)).toEqual([cachePath]);
			expect(await fs.readFile(cachePath)).toEqual(bytes);
			// A verified warm cache does not need to read/decompress the archive.
			await fs.unlink(addon.archive.filePath);
			expect(extract(addon, cacheDir)).toEqual([]);
		});
	});

	it("gives same-version builds different load paths and preserves the prior artifact", async () => {
		await withFixture(async ({ addon, bytes, alternate, candidate, nativeDir, nativesDir, cacheDir, cachePath }) => {
			extract(addon, cacheDir);
			await Bun.write(candidate, alternate);
			const next = await embedNativeAddon({
				targetPlatform: process.platform,
				targetArch: process.arch,
				nativeDir,
				outputPath: path.join(nativeDir, "embedded-addon.js"),
				version: addon.version,
			});
			const nextPath = prepareEmbeddedAddonCandidate({ addon: next, candidate, nativesDir });
			expect(nextPath).not.toBe(cachePath);
			expect(await fs.readFile(nextPath)).toEqual(alternate);
			expect(await fs.readFile(cachePath)).toEqual(bytes);
		});
	});

	it("rejects altered packaged bytes without overwriting an existing cache entry", async () => {
		await withFixture(async ({ addon, alternate, cacheDir, cachePath }) => {
			await Bun.write(cachePath, alternate);
			await Bun.write(
				addon.archive.filePath,
				await new Bun.Archive({ [addon.files[0].filename]: alternate }, { compress: "gzip" }).bytes(),
			);
			expect(() => extract(addon, cacheDir)).toThrow();
			expect(await fs.readFile(cachePath)).toEqual(alternate);
			expect(await fs.readdir(cacheDir)).toEqual([addon.files[0].filename]);
		});
	});

	it("rejects a bad archive variant before publishing even the valid variant", async () => {
		await withFixture(async ({ addon, bytes, alternate, cacheDir }) => {
			const modernFilename = "pi_natives.linux-x64-modern.node";
			const baselineFilename = "pi_natives.linux-x64-baseline.node";
			const files = [
				{ ...addon.files[0], variant: "modern" as const, filename: modernFilename },
				{ ...addon.files[0], variant: "baseline" as const, filename: baselineFilename },
			];
			await Bun.write(
				addon.archive.filePath,
				await new Bun.Archive(
					{ [modernFilename]: bytes, [baselineFilename]: alternate },
					{ compress: "gzip" },
				).bytes(),
			);
			expect(() =>
				extractEmbeddedAddonArchive({ archivePath: addon.archive.filePath, files, targetDir: cacheDir }),
			).toThrow();
			expect(await fs.readdir(cacheDir)).toEqual([]);
		});
	});

	it("rejects changed fallback bytes and loads valid fallback bytes only from the artifact cache", async () => {
		await withFixture(async ({ addon, bytes, alternate, candidate, nativesDir, cacheDir, cachePath }) => {
			await Bun.write(candidate, alternate);
			expect(() => prepareEmbeddedAddonCandidate({ addon, candidate, nativesDir })).toThrow();
			expect(await fs.readdir(cacheDir)).toEqual([]);
			await Bun.write(candidate, bytes);
			const loadPath = prepareEmbeddedAddonCandidate({ addon, candidate, nativesDir });
			expect(loadPath).toBe(cachePath);
			expect(loadPath).not.toBe(candidate);
			expect(await fs.readFile(loadPath)).toEqual(bytes);
			// A later change at the same artifact path must also fail validation.
			await Bun.write(loadPath, alternate);
			expect(() => prepareEmbeddedAddonCandidate({ addon, candidate: loadPath, nativesDir })).toThrow();
		});
	});

	it("rejects a fallback filename that has no packaged digest", async () => {
		await withFixture(async ({ addon, bytes, root, nativesDir, cacheDir }) => {
			const candidate = path.join(root, "pi_natives.unlisted.node");
			await Bun.write(candidate, bytes);
			expect(() => prepareEmbeddedAddonCandidate({ addon, candidate, nativesDir })).toThrow();
			expect(await fs.readdir(cacheDir)).toEqual([]);
		});
	});

	it("keeps an actively prepared artifact safe from newer-release cache cleanup", async () => {
		await withFixture(async ({ addon, candidate, nativesDir, bytes }) => {
			const versionDir = path.join(nativesDir, addon.version);
			await fs.utimes(versionDir, new Date(0), new Date(0));
			const loadPath = prepareEmbeddedAddonCandidate({ addon, candidate, nativesDir });
			const nextMajor = Number.parseInt(addon.version, 10) + 1;
			cleanupStaleNativeVersions({ nativesDir, currentVersion: `${nextMajor}.0.0` });
			expect(await fs.readFile(loadPath)).toEqual(bytes);
		});
	});

	for (const [label, corrupt] of [
		[
			"missing file digest",
			(addon: EmbeddedAddon) => ({ ...addon, files: [{ ...addon.files[0], sha256: undefined }] }),
		],
		[
			"invalid file digest",
			(addon: EmbeddedAddon) => ({ ...addon, files: [{ ...addon.files[0], sha256: "invalid" }] }),
		],
		["missing file size", (addon: EmbeddedAddon) => ({ ...addon, files: [{ ...addon.files[0], size: undefined }] })],
		["missing artifact identity", (addon: EmbeddedAddon) => ({ ...addon, artifactId: undefined })],
		["inconsistent artifact identity", (addon: EmbeddedAddon) => ({ ...addon, artifactId: "0".repeat(64) })],
		["missing archive metadata", (addon: EmbeddedAddon) => ({ ...addon, archive: undefined })],
	] as const) {
		it(`fails closed with ${label} despite an exact fallback file`, async () => {
			await withFixture(async ({ addon, candidate, nativesDir, cacheDir }) => {
				const invalid = corrupt(addon) as unknown as EmbeddedAddon;
				expect(() => prepareEmbeddedAddonCandidate({ addon: invalid, candidate, nativesDir })).toThrow();
				expect(() => initLoaderContext({ isCompiledBinary: true, embeddedAddon: invalid })).toThrow();
				expect(await fs.readdir(cacheDir)).toEqual([]);
			});
		});
	}

	it("rejects compiled mode without a manifest and rejects mismatched release metadata", async () => {
		await withFixture(async ({ addon }) => {
			expect(() => initLoaderContext({ isCompiledBinary: true, embeddedAddon: null })).toThrow();
			const identity = { ...addon, version: "0.0.0" };
			const mismatched = { ...identity, artifactId: getEmbeddedAddonArtifactId(identity) };
			expect(() => initLoaderContext({ isCompiledBinary: true, embeddedAddon: mismatched })).toThrow();
		});
	});

	it("emits an importable manifest whose digests validate real archive outputs", async () => {
		await withFixture(async ({ root, nativeDir, nativesDir, bytes, cacheDir, cachePath }) => {
			const reader = path.join(nativeDir, "read-manifest.js");
			await Bun.write(
				reader,
				'import { embeddedAddon } from "./embedded-addon.js";\nconsole.log(JSON.stringify(embeddedAddon));\n',
			);
			// A separate module registry consumes the generated file without
			// mock.module(), dynamic imports, or changes to the suite's environment.
			const child = Bun.spawn([process.execPath, "--no-env-file", reader], {
				cwd: root,
				env: {
					HOME: root,
					USERPROFILE: root,
					TMPDIR: root,
					TEMP: root,
					TMP: root,
					SystemRoot: process.env.SystemRoot ?? process.env.SYSTEMROOT ?? "",
				},
				stdin: "ignore",
				stdout: "pipe",
				stderr: "pipe",
				timeout: 10_000,
				killSignal: "SIGKILL",
			});
			const [status, output, error] = await Promise.all([
				child.exited,
				new Response(child.stdout as ReadableStream<Uint8Array>).text(),
				new Response(child.stderr as ReadableStream<Uint8Array>).text(),
			]);
			if (status !== 0) throw new Error(`Generated manifest consumer failed: ${error}`);
			const addon: EmbeddedAddon = JSON.parse(output);
			extract(addon, cacheDir);
			const loadPath = prepareEmbeddedAddonCandidate({ addon, candidate: cachePath, nativesDir });
			expect(await fs.readFile(loadPath)).toEqual(bytes);
		});
	}, 15_000);
});

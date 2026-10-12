import * as fs from "node:fs/promises";
import * as path from "node:path";
import {
	assertLocks,
	assertRuntime,
	BUN_VERSION,
	bun,
	fail,
	fileHash,
	filesUnder,
	fixture,
	lockHashes,
	ROOT,
	run,
	UPSTREAM_REVISION,
} from "./agent-smith-common";
import { NATIVE_DIR, verifyNative } from "./agent-smith-native";
import { smoke } from "./agent-smith-smoke";

async function main(): Promise<void> {
	assertRuntime();
	if (process.argv.length !== 2) {
		throw new Error("smith:build builds only the current candidate host; it accepts no cross-target flags");
	}
	if (!Bun.which("tar")) throw new Error("Development packaging requires tar on PATH");
	const native = await verifyNative();
	const context = await fixture("build");
	const locks = await lockHashes();
	const tag = `${process.platform}-${process.arch}`;
	const filename = process.platform === "win32" ? "agent-smith.exe" : "agent-smith";
	const stage = path.join(context.dir, "package");
	await fs.mkdir(stage);
	const binary = path.join(stage, filename);
	const generated = [
		path.join(NATIVE_DIR, "embedded-addon.js"),
		path.join(ROOT, "packages/stats/src/embedded-client.generated.txt"),
	];
	const originals = await Promise.all(generated.map(file => Bun.file(file).bytes()));
	const archive = path.join(NATIVE_DIR, `embedded-addons.${tag}.tar.gz`);
	if (await Bun.file(archive).exists()) {
		throw new Error(`Existing generated native archive requires explicit cleanup: ${archive}`);
	}
	const buildErrors: unknown[] = [];
	try {
		await bun(["run", "gen:tool-views"], context);
		await bun(["run", "gen:stats"], context);
		await bun(["run", "gen:native"], context);
		await bun([path.join(ROOT, "scripts/agent-smith-compile.ts"), binary], context, context.cwd, 600_000);
		if (process.platform === "darwin") {
			await run(
				[
					"codesign",
					"--force",
					"--sign",
					"-",
					"--entitlements",
					path.join(ROOT, "scripts/macos-entitlements.plist"),
					binary,
				],
				{ env: context.env },
			);
		}
	} catch (error) {
		buildErrors.push(error);
	} finally {
		// Restore the exact pre-build generated stubs/payloads, including on compiler failure.
		const restorations = await Promise.allSettled([
			...generated.map((file, index) => Bun.write(file, originals[index])),
			fs.rm(archive, { force: true }),
			assertLocks(locks),
		]);
		for (const result of restorations) if (result.status === "rejected") buildErrors.push(result.reason);
	}
	if (buildErrors.length)
		throw new AggregateError(buildErrors, "Development build or generated-input restoration failed");
	const payload = [
		filename,
		"LICENSE",
		"NOTICE",
		"THIRD-PARTY-NOTICES.txt",
		"DEVELOPMENT.md",
		"native-LICENSE",
		"native-THIRD-PARTY-NOTICES.txt",
	];
	for (const name of ["LICENSE", "NOTICE", "THIRD-PARTY-NOTICES.txt"]) {
		await fs.copyFile(path.join(ROOT, name), path.join(stage, name));
	}
	await fs.copyFile(path.join(ROOT, "docs/agent-smith-development.md"), path.join(stage, "DEVELOPMENT.md"));
	for (const name of ["LICENSE", "THIRD-PARTY-NOTICES.txt"]) {
		await fs.copyFile(path.join(ROOT, "packages/natives", name), path.join(stage, `native-${name}`));
	}
	const hashes = Object.fromEntries(
		await Promise.all(payload.map(async name => [name, await fileHash(path.join(stage, name))])),
	);
	const manifest = {
		kind: "agent-smith-development",
		upstreamRevision: UPSTREAM_REVISION,
		bun: BUN_VERSION,
		host: tag,
		native,
		lockfiles: locks,
		files: hashes,
		qualification: "local development package; no release, signing identity, installer or VM qualification",
	};
	await Bun.write(path.join(stage, "build-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
	payload.push("build-manifest.json");
	const packageName = `agent-smith-dev-${tag}.tar.gz`;
	const pending = path.join(context.dir, packageName);
	const unpacked = path.join(context.dir, "unpacked");
	await fs.mkdir(unpacked);
	// Relative operands: GNU tar (Git for Windows) reads a `D:` archive prefix as a remote host.
	const tarOptions = { env: context.env, cwd: context.dir };
	await run(["tar", "-czf", packageName, "-C", path.relative(context.dir, stage), "--", ...payload], tarOptions);
	await run(["tar", "-xzf", packageName, "-C", path.relative(context.dir, unpacked)], tarOptions);
	const actual = (await filesUnder(unpacked))
		.map(file => path.relative(unpacked, file).split(path.sep).join("/"))
		.sort();
	if (JSON.stringify(actual) !== JSON.stringify([...payload].sort())) {
		throw new Error("Development package file set differs after extraction");
	}
	for (const name of payload) {
		if ((await fileHash(path.join(unpacked, name))) !== (await fileHash(path.join(stage, name)))) {
			throw new Error(`Packaged bytes differ: ${name}`);
		}
	}
	// Run the extracted executable with only its documented payload beside it.
	// The worker host must re-enter that executable, and natives must extract from it.
	await smoke(path.join(unpacked, filename));
	await assertLocks(locks);
	const out = path.join(ROOT, "dist", "agent-smith", tag);
	await fs.mkdir(out, { recursive: true });
	for (const name of payload) await fs.copyFile(path.join(unpacked, name), path.join(out, name));
	await fs.copyFile(pending, path.join(out, packageName));
	await Bun.write(
		path.join(out, "SHA256SUMS"),
		`${await fileHash(pending)}  ${packageName}\n${hashes[filename]}  ${filename}\n`,
	);
	console.log(`Development artifact and package: ${out}`);
}

main().catch(fail);

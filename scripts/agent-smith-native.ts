import * as fs from "node:fs/promises";
import * as path from "node:path";
import {
	assertLocks,
	assertRuntime,
	bun,
	DEV,
	fail,
	fileHash,
	filesUnder,
	fixture,
	lockHashes,
	NATIVE_VERSION,
	ROOT,
	run,
	RUST_TOOLCHAIN,
	sha256,
	UPSTREAM_REVISION,
} from "./agent-smith-common";
import sourceLock from "./agent-smith-native-source.json" with { type: "json" };
import { detectHostAvx2Support, detectHostMusl, resolveLocalHostAddon } from "./host-detect";

export interface NativeReceipt {
	mode: "source";
	upstreamRevision: string;
	version: string;
	host: string;
	sourceHash: string;
	modifiedNativeSources: boolean;
	toolchain: string;
	filename: string;
	sha256: string;
}

export const NATIVE_DIR = path.join(ROOT, "packages", "natives", "native");
export const RECEIPT = path.join(DEV, "native-receipt.json");

export async function nativeSourceHash(): Promise<string> {
	const files: string[] = [];
	for (const input of sourceLock.inputs) {
		const absolute = path.join(ROOT, input);
		const stat = await fs.stat(absolute);
		files.push(...(stat.isDirectory() ? await filesUnder(absolute) : [absolute]));
	}
	const rows: string[] = [];
	const relativeFiles = files.map(file => path.relative(ROOT, file).split(path.sep).join("/")).sort();
	for (const file of relativeFiles) rows.push(`${file}\0${await fileHash(path.join(ROOT, file))}\n`);
	return sha256(new TextEncoder().encode(rows.join("")));
}

export async function verifyNative(): Promise<NativeReceipt> {
	assertRuntime();
	const receipt: NativeReceipt = await Bun.file(RECEIPT).json();
	const host = `${process.platform}-${process.arch}`;
	if (
		receipt.mode !== "source" ||
		receipt.version !== NATIVE_VERSION ||
		receipt.host !== host ||
		receipt.upstreamRevision !== UPSTREAM_REVISION
	) {
		throw new Error("Native receipt does not match this checkout/host; run smith:native");
	}
	if (receipt.sourceHash !== (await nativeSourceHash())) {
		throw new Error("Native source changed since build; run smith:native --allow-native-changes");
	}
	if (
		path.basename(receipt.filename) !== receipt.filename ||
		!receipt.filename.startsWith(`pi_natives.${host}`) ||
		!receipt.filename.endsWith(".node")
	) {
		throw new Error("Invalid native receipt filename");
	}
	const addons = (await fs.readdir(NATIVE_DIR)).filter(file => file.endsWith(".node"));
	if (addons.length !== 1 || addons[0] !== receipt.filename) {
		throw new Error("Unexpected native candidates present; remove stale addons explicitly before preparation");
	}
	const addon = path.join(NATIVE_DIR, receipt.filename);
	if ((await fileHash(addon)) !== receipt.sha256) throw new Error("Native artifact hash mismatch");
	const context = await fixture("native-load");
	await bun(["scripts/agent-smith-native-probe.ts", addon], context, ROOT, 60_000);
	return receipt;
}

export async function buildNative(allowChanges: boolean): Promise<void> {
	assertRuntime();
	if (detectHostMusl()) throw new Error("P1 Linux candidate requires glibc; musl is not qualified");
	for (const executable of ["rustup", "cmake", "ninja"]) {
		if (!Bun.which(executable)) {
			throw new Error(`Source native build requires ${executable} on PATH; see docs/agent-smith-development.md`);
		}
	}
	if (!process.env.RUSTUP_HOME) throw new Error("Set RUSTUP_HOME to the owner-provisioned pinned toolchain directory");
	const version = (await Bun.file(path.join(ROOT, "packages/natives/package.json")).json()).version;
	if (version !== NATIVE_VERSION) throw new Error(`Native ABI must remain ${NATIVE_VERSION}`);
	const sourceHash = await nativeSourceHash();
	const changed = sourceHash !== sourceLock.sha256;
	if (changed && !allowChanges) {
		throw new Error(
			"Native inputs differ from the reviewed Agent Smith pin; use smith:native --allow-native-changes intentionally",
		);
	}
	const expected = resolveLocalHostAddon({
		platform: process.platform,
		arch: process.arch,
		avx2: detectHostAvx2Support(),
	}).filename;
	const existing = (await fs.readdir(NATIVE_DIR)).filter(file => file.endsWith(".node") && file !== expected);
	if (existing.length)
		throw new Error(`Stale native candidates would affect loader selection: ${existing.join(", ")}`);
	const context = await fixture("native-build");
	Object.assign(context.env, {
		RUSTUP_HOME: process.env.RUSTUP_HOME,
		RUSTUP_TOOLCHAIN: RUST_TOOLCHAIN,
		CARGO_HOME: path.join(DEV, "cargo"),
		CARGO_TARGET_DIR: path.join(DEV, "target"),
		CARGO_BUILD_JOBS: "2",
		OMP_NATIVE_BUILD_BACKEND: "cargo",
		OMP_NATIVE_CARGO_PROFILE: "ci",
	});
	const locks = await lockHashes();
	await fs.rm(RECEIPT, { force: true });
	try {
		await run(["rustup", "run", RUST_TOOLCHAIN, "rustc", "--version"], { env: context.env });
		await run(["rustup", "run", RUST_TOOLCHAIN, "cargo", "fetch", "--locked"], {
			env: context.env,
			timeoutMs: 900_000,
		});
		// Lock resolution is complete. A native build may not fetch a newer crate graph.
		context.env.CARGO_NET_OFFLINE = "true";
		await bun(["scripts/bazel-natives.ts", "host", "--dest", NATIVE_DIR], context, ROOT, 3_600_000);
		const addon = path.join(NATIVE_DIR, expected);
		await bun(["scripts/agent-smith-native-probe.ts", addon], context, ROOT, 60_000);
		await assertLocks(locks);
		const receipt: NativeReceipt = {
			mode: "source",
			upstreamRevision: UPSTREAM_REVISION,
			version: NATIVE_VERSION,
			host: `${process.platform}-${process.arch}`,
			sourceHash,
			modifiedNativeSources: sourceHash !== sourceLock.upstreamSha256,
			toolchain: RUST_TOOLCHAIN,
			filename: expected,
			sha256: await fileHash(addon),
		};
		await Bun.write(RECEIPT, `${JSON.stringify(receipt, null, 2)}\n`);
	} finally {
		await assertLocks(locks);
	}
}

if (import.meta.main) {
	const args = process.argv.slice(2);
	if (args[0] === "--") args.shift();
	if (args.some(arg => arg !== "--verify" && arg !== "--allow-native-changes")) {
		fail(new Error("Usage: agent-smith-native.ts [--verify | --allow-native-changes]"));
	} else {
		try {
			if (args.includes("--verify")) await verifyNative();
			else await buildNative(args.includes("--allow-native-changes"));
		} catch (error) {
			fail(error);
		}
	}
}

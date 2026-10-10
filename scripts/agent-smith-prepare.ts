import * as path from "node:path";
import { assertLocks, assertRuntime, bun, fail, fixture, lockHashes, ROOT } from "./agent-smith-common";
import { buildNative } from "./agent-smith-native";

async function main(): Promise<void> {
	assertRuntime();
	if (process.argv.length !== 2) {
		throw new Error("smith:prepare takes no arguments; use smith:native --allow-native-changes for Rust development");
	}
	for (const executable of ["rustup", "cmake", "ninja"]) {
		if (!Bun.which(executable)) {
			throw new Error(`Missing ${executable}; provision source-build prerequisites before smith:prepare`);
		}
	}
	if (!process.env.RUSTUP_HOME) throw new Error("Set RUSTUP_HOME to the owner-provisioned pinned toolchain directory");
	// Never let install/build scripts discover a developer's repository-local dotenv files.
	for (const name of [
		".env",
		".env.local",
		".env.production",
		".env.development",
		".omp/.env",
		".omp/agent/.env",
		".agent-smith/.env",
		".agent-smith/agent/.env",
	]) {
		if (await Bun.file(path.join(ROOT, name)).exists()) {
			throw new Error(`Move repository-local ${name} out of the build checkout before preparing`);
		}
	}
	const context = await fixture("prepare");
	const locks = await lockHashes();
	try {
		// No lifecycle hooks, global links, workspace publication, or lock regeneration.
		await bun(["install", "--frozen-lockfile", "--ignore-scripts"], context, ROOT, 900_000);
		await assertLocks(locks);
		await buildNative(false);
		await bun(["run", "gen:tool-views"], context);
		await bun(["run", "gen:stats"], context);
	} finally {
		await assertLocks(locks);
	}
}

main().catch(fail);

import * as path from "node:path";
import { assertRuntime, bun, DEV, fail, fixture, ROOT, run, RUST_TOOLCHAIN } from "./agent-smith-common";
import { verifyNative } from "./agent-smith-native";

async function main(): Promise<void> {
	assertRuntime();
	await verifyNative();
	const context = await fixture("check");
	await bun(["run", "check:ts"], context, ROOT, 900_000);
	await bun(["run", "--bun", "tsgo", "-p", "tsconfig.tools.json", "--noEmit"], context, ROOT, 900_000);
	await bun(
		[
			"test",
			"scripts/agent-smith-common.test.ts",
			"scripts/agent-smith-scan.test.ts",
			"scripts/agent-smith-scan-decoder.test.ts",
		],
		context,
	);
	for (const tests of [
		["packages/ai/test/agent-smith-credentials.test.ts"],
		["packages/mnemopi/test/triples-data-dir.test.ts"],
		[
			"packages/natives/test/embed-native.test.ts",
			"packages/natives/test/embedded-addon-integrity.test.ts",
			"packages/natives/test/issue-823-repro.test.ts",
			"packages/natives/test/windows-staging.test.ts",
			"packages/natives/test/issue-4812-repro.test.ts",
			"packages/natives/test/legacy-desktop-sentinel.test.ts",
		],
		[
			"packages/utils/test/profiles.test.ts",
			"packages/utils/test/logger-contract.test.ts",
			"packages/utils/test/logger-multiprocess.test.ts",
			"packages/utils/test/stderr-guard.test.ts",
		],
		[
			"packages/coding-agent/test/agent-smith-isolation.test.ts",
			"packages/coding-agent/test/text-predict-privacy.test.ts",
			"packages/coding-agent/test/launch/broker-metadata-writes.test.ts",
			"packages/coding-agent/test/discovery",
			"packages/coding-agent/test/settings-manager.test.ts",
			"packages/coding-agent/test/settings-reload-cwd.test.ts",
			"packages/coding-agent/test/cli/update-cli.test.ts",
			"packages/coding-agent/test/cli/completions.test.ts",
		],
	]) {
		await bun(["test", "--timeout", "60000", ...tests], context, ROOT, 900_000);
	}
	if (!process.env.RUSTUP_HOME) throw new Error("Set RUSTUP_HOME to the pinned toolchain used by smith:prepare");
	const rustEnv = {
		...context.env,
		RUSTUP_HOME: process.env.RUSTUP_HOME,
		RUSTUP_TOOLCHAIN: RUST_TOOLCHAIN,
		CARGO_HOME: path.join(DEV, "cargo"),
		CARGO_TARGET_DIR: path.join(DEV, "target"),
		CARGO_BUILD_JOBS: "2",
		CARGO_NET_OFFLINE: "true",
	};
	for (const filter of ["crash_handler::tests", "oauth_callback::"]) {
		await run(
			[
				"rustup",
				"run",
				RUST_TOOLCHAIN,
				"cargo",
				"test",
				"--locked",
				"--offline",
				"--profile",
				"ci",
				"-p",
				"pi-natives",
				"--lib",
				filter,
			],
			{ env: rustEnv, timeoutMs: 900_000 },
		);
	}
}

main().catch(fail);

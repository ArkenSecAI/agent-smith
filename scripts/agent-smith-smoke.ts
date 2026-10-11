import * as path from "node:path";
import { assertRuntime, fail, fileHash, filesUnder, fixture, NATIVE_VERSION, ROOT, run } from "./agent-smith-common";
import { verifyNative } from "./agent-smith-native";

function expectEqual(actual: unknown, expected: unknown, contract: string): void {
	if (actual !== expected) {
		throw new Error(`${contract}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
	}
}

/** Consumer contracts shared by the source CLI and the unpacked development artifact. */
export async function smoke(binary?: string): Promise<void> {
	assertRuntime();
	const receipt = await verifyNative();
	const context = await fixture(binary ? "package-smoke" : "source-smoke");
	const command = binary
		? [path.resolve(binary)]
		: [process.execPath, "--no-env-file", path.join(ROOT, "packages/coding-agent/src/cli.ts")];
	const supervisor = [process.execPath, "--no-env-file", path.join(ROOT, "scripts/agent-smith-cli-fixture.ts")];
	const invoke = async (args: string[], env = context.env, expectFailure = false): Promise<string> =>
		run([...supervisor, ...command, ...args], {
			cwd: context.cwd,
			env,
			capture: true,
			expectFailure,
			timeoutMs: 240_000,
		});
	const mouseValue = async (env = context.env): Promise<unknown> => {
		const result: { value: unknown } = JSON.parse(await invoke(["config", "get", "tui.mouse", "--json"], env));
		return result.value;
	};
	console.log(`Synthetic smoke evidence: ${context.dir}`);
	try {
		// Real assets, workers, subprocess host dispatch and the native module graph.
		await invoke(["--smoke-test"]);
		const defaultAgent = path.join(context.home, ".agent-smith", "agent");
		expectEqual(
			path.resolve((await invoke(["config", "path"])).trim()),
			defaultAgent,
			"Default state must use Agent Smith home",
		);
		for (const value of [false, true]) {
			await invoke(["config", "set", "tui.mouse", String(value), "--json"]);
			expectEqual(await mouseValue(), value, "Config persists across separate CLI processes");
		}
		await invoke(["config", "set", "tui.mouse", "not-a-boolean", "--json"], context.env, true);
		expectEqual(await mouseValue(), true, "Rejected config must preserve the last saved value");
		const customAgent = path.join(context.dir, "override-agent");
		const override = { ...context.env, AGENT_SMITH_CODING_AGENT_DIR: customAgent };
		expectEqual(
			path.resolve((await invoke(["config", "path"], override)).trim()),
			customAgent,
			"Agent Smith directory override",
		);
		await invoke(["config", "set", "tui.mouse", "false", "--json"], override);
		expectEqual(await mouseValue(override), false, "Override state persists");
		expectEqual(await mouseValue(), true, "Override state stays separate from default state");
		if (binary) {
			const nativesDir = path.join(context.home, ".agent-smith", "natives");
			const candidates = (await filesUnder(nativesDir)).filter(file => {
				const parts = path.relative(nativesDir, file).split(path.sep);
				return (
					parts.length === 3 &&
					parts[0] === NATIVE_VERSION &&
					/^[a-f0-9]{64}$/.test(parts[1]) &&
					parts[2] === receipt.filename
				);
			});
			expectEqual(candidates.length, 1, "Compiled package uses one content-specific native cache path");
			expectEqual(
				await fileHash(candidates[0]),
				receipt.sha256,
				"Compiled package extracts the verified native payload",
			);
		}
		const created = await filesUnder(context.home);
		const legacyState = created.some(file =>
			path
				.relative(context.home, file)
				.split(path.sep)
				.some(part => part === ".omp" || part === ".pi"),
		);
		if (legacyState) throw new Error("CLI created legacy application state inside the synthetic home");
		const result = {
			kind: binary ? "compiled" : "source",
			nativeSha256: receipt.sha256,
			contracts: [
				"worker-and-dashboard-smoke",
				"persistent-config",
				"invalid-config-rejected",
				"directory-override-isolated",
				"agent-smith-state",
			],
		};
		await Bun.write(path.join(context.dir, "result.json"), `${JSON.stringify(result, null, 2)}\n`);
		console.log("Agent Smith synthetic smoke completed");
	} catch (error) {
		console.error(`Smoke failed; synthetic state retained at ${context.dir}`);
		throw error;
	}
}

if (import.meta.main) {
	const args = process.argv.slice(2);
	if (args[0] === "--") args.shift();
	if (args.length !== 0 && (args.length !== 2 || args[0] !== "--binary")) {
		fail(new Error("Usage: smith:smoke [--binary <absolute-path>]"));
	} else {
		await smoke(args[1]).catch(fail);
	}
}

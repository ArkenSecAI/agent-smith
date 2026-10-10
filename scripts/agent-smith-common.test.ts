import { describe, expect, test } from "bun:test";
import { fixture, run } from "./agent-smith-common";

describe("development subprocess boundary", () => {
	test("a subprocess failure is surfaced instead of allowing later packaging", async () => {
		const context = await fixture("test-exit");
		await expect(
			run([process.execPath, "--no-env-file", "-e", "process.exit(23)"], { env: context.env }),
		).rejects.toThrow("Unexpected exit 23");
	});
	test("an unresponsive fixture terminates with an explicit timeout failure", async () => {
		const context = await fixture("test-timeout");
		await expect(
			run([process.execPath, "--no-env-file", "-e", "setInterval(() => {}, 1000)"], {
				env: context.env,
				timeoutMs: 200,
			}),
		).rejects.toThrow("Timed out");
	});
	test("a fresh CLI process sees an isolated home and no provider credential", async () => {
		const context = await fixture("test-env", {
			PATH: process.env.PATH,
			SystemRoot: process.env.SystemRoot,
			OPENAI_API_KEY: "synthetic-not-a-key",
			HOME: "/must-not-use",
			NODE_OPTIONS: "--require=/must-not-load.js",
		});
		const output = await run(
			[
				process.execPath,
				"--no-env-file",
				"-e",
				"process.stdout.write(JSON.stringify({home:process.env.HOME, key:process.env.OPENAI_API_KEY ?? null}))",
			],
			{ env: context.env, capture: true },
		);
		expect(JSON.parse(output)).toEqual({ home: context.home, key: null });
	});
});

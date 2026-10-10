import { afterEach, describe, expect, test } from "bun:test";
import * as path from "node:path";
import type { LoadContext } from "@oh-my-pi/pi-coding-agent/capability/types";
import { getConfigDirs } from "@oh-my-pi/pi-coding-agent/config";
import { resolveClaudePaths } from "@oh-my-pi/pi-coding-agent/config/claude-paths";
import { getUserPath } from "@oh-my-pi/pi-coding-agent/discovery/helpers";

describe("CLAUDE_CONFIG_DIR", () => {
	const original = process.env.CLAUDE_CONFIG_DIR;
	afterEach(() => {
		if (original === undefined) {
			delete process.env.CLAUDE_CONFIG_DIR;
		} else {
			process.env.CLAUDE_CONFIG_DIR = original;
		}
	});

	test("an ambient Claude path does not opt in; explicit discovery uses its selected location", () => {
		process.env.CLAUDE_CONFIG_DIR = "./fixtures/claude-home";
		const expectedRoot = path.resolve("./fixtures/claude-home");
		const ctx: LoadContext = {
			cwd: "/work/project",
			home: "/home/tester",
			repoRoot: null,
		};

		expect(resolveClaudePaths(ctx.home)).toEqual({
			configDir: expectedRoot,
			configFile: path.join(expectedRoot, ".claude.json"),
		});
		expect(getUserPath(ctx, "claude", "commands")).toBeNull();
		expect(
			getConfigDirs("commands", { user: true, project: false }).find(entry => entry.source === ".claude"),
		).toBeUndefined();
		ctx.explicitProviders = new Set(["claude"]);
		expect(getUserPath(ctx, "claude", "commands")).toBe(path.join(expectedRoot, "commands"));
	});

	test("keeps the legacy split paths when the override is unset", () => {
		delete process.env.CLAUDE_CONFIG_DIR;
		expect(resolveClaudePaths("/home/tester")).toEqual({
			configDir: path.join("/home/tester", ".claude"),
			configFile: path.join("/home/tester", ".claude.json"),
		});
	});
});

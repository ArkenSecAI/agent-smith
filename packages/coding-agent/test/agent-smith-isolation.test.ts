import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";

interface Snapshot {
	profile: string | null;
	root: string;
	agent: string;
	db: string;
	logs: string;
	sessions: string;
	natives: string;
	loaderNatives: string;
	runtime: string;
	worktrees: string;
	brokerCache: string;
	project: string;
	sessionOverride: string | null;
	modelRoles: Record<string, string>;
	configDirs: string[];
	mcp: string[];
	plugins: string[];
	memoryConfigured: boolean;
	memoryBank: string;
	accounts: number;
	codexAuth: unknown;
}

describe("Agent Smith application isolation", () => {
	let root: string;
	let home: string;
	let project: string;
	let env: Record<string, string>;

	beforeEach(async () => {
		root = await fs.mkdtemp(path.join(os.tmpdir(), "agent-smith-isolation-"));
		home = path.join(root, "home");
		project = path.join(root, "project");
		await fs.mkdir(home);
		await fs.mkdir(project);
		// Do not inherit provider keys, account homes, app overrides, or startup hooks.
		env = {
			HOME: home,
			USERPROFILE: home,
			PATH: process.env.PATH ?? "",
			SystemRoot: process.env.SystemRoot ?? "",
			TEMP: root,
			TMP: root,
			TMPDIR: root,
			XDG_CONFIG_HOME: path.join(root, "config"),
			XDG_DATA_HOME: path.join(root, "data"),
			XDG_STATE_HOME: path.join(root, "state"),
			XDG_CACHE_HOME: path.join(root, "cache"),
			NO_COLOR: "1",
		};
	});

	afterEach(async () => {
		await fs.rm(root, { recursive: true, force: true });
	});

	async function run(args: string[], overrides: Record<string, string> = {}): Promise<string> {
		const entry = path.join(import.meta.dir, "fixtures/agent-smith-isolation.ts");
		const child = Bun.spawn([process.execPath, "--no-env-file", entry, ...args], {
			cwd: project,
			env: { ...env, ...overrides },
			stdin: "ignore",
			stdout: "pipe",
			stderr: "pipe",
		});
		const [out, err, code] = await Promise.all([
			new Response(child.stdout).text(),
			new Response(child.stderr).text(),
			child.exited,
		]);
		expect(code, err).toBe(0);
		return out;
	}

	async function snapshot(overrides: Record<string, string> = {}, args: string[] = []): Promise<Snapshot> {
		return JSON.parse(await run(["snapshot", ...args], overrides)) as Snapshot;
	}

	test("foreign config, accounts, and legacy environment cannot redirect a fresh application", async () => {
		await run(["seed"]);
		for (const dir of [".omp", ".pi", ".claude", ".codex", ".gemini"]) {
			await Bun.write(path.join(home, dir, "agent/config.yml"), "modelRoles:\n  default: synthetic/foreign\n");
			await Bun.write(path.join(project, dir, "config.yml"), "modelRoles:\n  default: synthetic/foreign\n");
			await Bun.write(
				path.join(project, dir, "mcp.json"),
				JSON.stringify({
					mcpServers: { foreign: { command: "must-never-start" } },
				}),
			);
		}
		await Bun.write(path.join(home, ".codex/auth.json"), '{"tokens":{"access_token":"synthetic-codex-token"}}');
		await Bun.write(
			path.join(home, ".claude/.credentials.json"),
			'{"claudeAiOauth":{"accessToken":"synthetic-claude-token"}}',
		);
		await Bun.write(path.join(home, ".gemini/oauth_creds.json"), '{"access_token":"synthetic-gemini-token"}');
		await Bun.write(path.join(home, ".env"), "AGENT_SMITH_PROFILE=foreign\n");
		await Bun.write(path.join(project, ".claude/settings.json"), '{"modelRoles":{"default":"synthetic/foreign"}}');
		await Bun.write(path.join(home, ".omp/auth-broker.token"), "synthetic-foreign-broker");
		for (const category of ["data", "state", "cache"])
			await fs.mkdir(path.join(root, category, "omp"), { recursive: true });
		const legacy = {
			OMP_PROFILE: "foreign",
			PI_PROFILE: "foreign",
			OMP_CONFIG_DIR: ".omp",
			PI_CONFIG_DIR: ".omp",
			OMP_CODING_AGENT_DIR: path.join(home, ".omp/agent"),
			PI_CODING_AGENT_DIR: path.join(home, ".omp/agent"),
			PI_CONFIG_FILES: path.join(project, ".omp/config.yml"),
			OMP_CONFIG_FILES: path.join(project, ".omp/config.yml"),
			PI_CODING_AGENT_SESSION_DIR: path.join(home, ".omp/sessions"),
			OMP_WORKTREE_DIR: path.join(home, ".omp/wt"),
			OMP_AUTH_BROKER_URL: "https://foreign.invalid",
			OMP_AUTH_BROKER_TOKEN: "synthetic-foreign-broker",
			OMP_AUTH_BROKER_SNAPSHOT_CACHE: path.join(home, ".omp/snapshot.json"),
			CLAUDE_CONFIG_DIR: path.join(home, ".claude"),
		};
		const result = await snapshot(legacy);
		expect(result.profile).toBeNull();
		expect(result.root).toBe(path.join(home, ".agent-smith"));
		expect(result.agent).toBe(path.join(result.root, "agent"));
		for (const location of [
			result.db,
			result.logs,
			result.sessions,
			result.natives,
			result.runtime,
			result.worktrees,
			result.brokerCache,
		]) {
			expect(path.relative(result.root, location).startsWith("..")).toBe(false);
		}
		expect(result.loaderNatives).toBe(result.natives);
		expect(result.project).toBe(path.join(project, ".agent-smith"));
		expect(result.sessionOverride).toBeNull();
		expect(result.modelRoles.default).toBeUndefined();
		expect(result.mcp).toEqual([]);
		expect(result.accounts).toBe(0);
		expect(result.codexAuth).toBeNull();
		expect(await Bun.file(path.join(home, ".omp/auth-broker.token")).text()).toBe("synthetic-foreign-broker");
		const selected = await snapshot(legacy, ["--config", path.join(project, ".claude/settings.json")]);
		expect(selected.modelRoles.default).toBe("synthetic/foreign");
	}, 60_000);

	test("foreign plugin registries remain opt-in, while app-installed roots are discovered", async () => {
		for (const [directory, id] of [
			[".claude", "foreign@market"],
			[".agent-smith", "owned@market"],
		]) {
			await Bun.write(
				path.join(home, directory, "plugins/installed_plugins.json"),
				JSON.stringify({
					version: 2,
					plugins: { [id]: [{ scope: "user", installPath: path.join(root, id) }] },
				}),
			);
		}
		expect((await snapshot()).plugins).toEqual(["owned@market"]);
		await Bun.write(path.join(home, ".agent-smith/agent/config.yml"), "enabledProviders:\n  - claude-plugins\n");
		expect((await snapshot()).plugins).toEqual(["foreign@market", "owned@market"]);
	});

	test("remote memory requires an explicit app endpoint and defaults to a separate bank", async () => {
		const legacy = { HINDSIGHT_API_URL: "https://foreign.invalid", HINDSIGHT_BANK_ID: "omp" };
		expect((await snapshot(legacy)).memoryConfigured).toBe(false);
		const selected = await snapshot({ ...legacy, AGENT_SMITH_HINDSIGHT_API_URL: "https://selected.invalid" });
		expect(selected.memoryConfigured).toBe(true);
		expect(selected.memoryBank).toBe("agent-smith");
	}, 60_000);

	test("app config and explicitly selected overlays load with CLI overlay precedence", async () => {
		await Bun.write(path.join(home, ".agent-smith/agent/config.yml"), "modelRoles:\n  default: synthetic/global\n");
		await Bun.write(path.join(project, ".agent-smith/config.yml"), "modelRoles:\n  default: synthetic/project\n");
		const overlay = path.join(root, "selected.yml");
		await Bun.write(overlay, "modelRoles:\n  default: synthetic/selected\n");
		expect((await snapshot()).modelRoles.default).toBe("synthetic/project");
		expect((await snapshot({ AGENT_SMITH_CONFIG_FILES: overlay })).modelRoles.default).toBe("synthetic/selected");
		expect(
			(
				await snapshot({ AGENT_SMITH_CONFIG_FILES: overlay }, [
					"--config",
					path.join(project, ".agent-smith/config.yml"),
				])
			).modelRoles.default,
		).toBe("synthetic/project");
	}, 60_000);

	test("foreign MCP discovery requires an app-owned opt-in; native MCP remains available", async () => {
		for (const [dir, name] of [
			[".agent-smith", "owned"],
			[".claude", "selectedForeign"],
		]) {
			await Bun.write(
				path.join(project, dir, "mcp.json"),
				JSON.stringify({ mcpServers: { [name]: { command: `never-start-${name}` } } }),
			);
		}
		expect((await snapshot()).mcp).toEqual(["owned"]);
		await Bun.write(path.join(home, ".agent-smith/agent/config.yml"), "enabledProviders:\n  - claude\n");
		expect((await snapshot()).mcp).toEqual(["owned", "selectedForeign"]);
	});

	test("profile state and native cache stay in the app namespace with XDG markers", async () => {
		for (const category of ["data", "state", "cache"]) {
			await fs.mkdir(path.join(root, category, "agent-smith/profiles/work"), { recursive: true });
		}
		const result = await snapshot({ AGENT_SMITH_PROFILE: "work", PI_PROFILE: "other" });
		expect(result.agent).toBe(path.join(home, ".agent-smith/profiles/work/agent"));
		if (process.platform === "linux" || process.platform === "darwin") {
			expect(result.sessions).toBe(path.join(root, "data/agent-smith/profiles/work/sessions"));
			expect(result.logs).toBe(path.join(root, "state/agent-smith/profiles/work/logs"));
			expect(result.loaderNatives).toBe(path.join(root, "cache/agent-smith/natives"));
		}
		expect(result.loaderNatives).toBe(result.natives);
		const selected = path.join(root, "selected-agent");
		expect((await snapshot({ AGENT_SMITH_CODING_AGENT_DIR: selected })).agent).toBe(selected);
		const configured = await snapshot({ AGENT_SMITH_CONFIG_DIR: ".selected-smith", PI_CONFIG_DIR: ".omp" });
		expect(configured.root).toBe(path.join(home, ".selected-smith"));
		expect(configured.agent).toBe(path.join(configured.root, "agent"));
	}, 60_000);

	test("an explicitly configured broker fails without an app-owned token instead of borrowing OMP's token", async () => {
		await Bun.write(path.join(home, ".omp/auth-broker.token"), "synthetic-foreign-broker");
		const result = JSON.parse(await run(["broker"], { AGENT_SMITH_AUTH_BROKER_URL: "https://selected.invalid" })) as {
			error: string;
		};
		expect(result.error).toContain("AGENT_SMITH_AUTH_BROKER_TOKEN");
		const configured = JSON.parse(
			await run(["broker"], {
				AGENT_SMITH_AUTH_BROKER_URL: "https://selected.invalid",
				AGENT_SMITH_AUTH_BROKER_TOKEN: "synthetic-selected-token",
			}),
		) as { configured: boolean };
		expect(configured.configured).toBe(true);
	});
});

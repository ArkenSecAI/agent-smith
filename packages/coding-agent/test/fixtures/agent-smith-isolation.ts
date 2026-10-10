import * as path from "node:path";
import { AuthStorage } from "@oh-my-pi/pi-ai/auth-storage";
import { resolveAuthBrokerConfig } from "@oh-my-pi/pi-ai/auth-broker/discover";
import {
	getActiveProfile,
	getAgentDbPath,
	getAgentDir,
	getAuthBrokerSnapshotCachePath,
	getConfigRootDir,
	getLogsDir,
	getNativesDir,
	getProjectAgentDir,
	getSessionsDir,
	getTinyWorkerRuntimeDir,
	getWorktreesDir,
} from "@oh-my-pi/pi-utils/dirs";
import { getNativesDir as getLoaderNativesDir } from "../../../natives/native/loader-state.js";
import { type MCPServer, mcpCapability } from "../../src/capability/mcp";
import { parseArgs } from "../../src/cli/args";
import { getConfigDirs } from "../../src/config";
import { cfgModelRoles } from "../../src/config/model-settings";
import { Settings } from "../../src/config/settings";
import { initializeWithSettings, loadCapability } from "../../src/discovery";
import { listClaudePluginRoots } from "../../src/discovery/helpers";
import { deriveBankId } from "../../src/hindsight/bank";
import { isHindsightConfigured, loadHindsightConfig } from "../../src/hindsight/config";
import { discoverAuthStorage } from "../../src/session/auth-broker-config";

// Run only in the synthetic HOME supplied by agent-smith-isolation.test.ts.
const mode = process.argv[2];
if (mode === "seed") {
	const storage = await AuthStorage.create(path.join(process.env.HOME!, ".omp", "agent", "agent.db"));
	try {
		await storage.credentials.set("openai-codex", {
			type: "oauth",
			access: "synthetic-foreign-access",
			refresh: "synthetic-foreign-refresh",
			expires: 4_000_000_000_000,
		});
	} finally {
		storage.close();
	}
	process.stdout.write("{}\n");
} else if (mode === "broker") {
	try {
		const config = await resolveAuthBrokerConfig();
		process.stdout.write(JSON.stringify({ configured: config !== null }));
	} catch (error) {
		process.stdout.write(JSON.stringify({ error: String(error) }));
	}
} else {
	const parsed = parseArgs(process.argv.slice(3));
	const settings = await Settings.loadReadOnly({ configFiles: parsed.config });
	const release = initializeWithSettings(settings);
	try {
		const mcp = await loadCapability<MCPServer>(mcpCapability.id);
		const plugins = await listClaudePluginRoots(process.env.HOME!, process.cwd());
		const memoryConfig = loadHindsightConfig(settings);
		const auth = await discoverAuthStorage(getAgentDir());
		try {
			process.stdout.write(
				JSON.stringify({
					profile: getActiveProfile() ?? null,
					root: getConfigRootDir(),
					agent: getAgentDir(),
					db: getAgentDbPath(),
					logs: getLogsDir(),
					sessions: getSessionsDir(),
					natives: getNativesDir(),
					loaderNatives: getLoaderNativesDir(),
					runtime: getTinyWorkerRuntimeDir(),
					worktrees: getWorktreesDir(),
					brokerCache: getAuthBrokerSnapshotCachePath(),
					project: getProjectAgentDir(),
					sessionOverride: parsed.sessionDir ?? null,
					modelRoles: cfgModelRoles.get(settings),
					configDirs: getConfigDirs("", { existingOnly: true }).map(entry => entry.path),
					mcp: mcp.items.map(server => server.name).sort(),
					plugins: plugins.roots.map(plugin => plugin.id).sort(),
					memoryConfigured: isHindsightConfigured(memoryConfig),
					memoryBank: deriveBankId(memoryConfig, process.cwd()),
					accounts: auth.credentials.list().length,
					codexAuth: auth.keys.source("openai-codex") ?? null,
				}),
			);
		} finally {
			auth.close();
		}
	} finally {
		release();
		settings.cancelPendingSaves();
	}
}

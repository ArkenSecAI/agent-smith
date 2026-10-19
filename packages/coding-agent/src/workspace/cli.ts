import * as path from "node:path";
import type { McpServer, RunRequest, RunSnapshot, WorkspaceClient } from "./contracts";
import { investigate } from "./assistant";
import { serveWorkspace } from "./broker";
import { connectWorkspace, startWorkspace } from "./client";
import { originalBytes } from "./guest-transport";
import { createProject, integer, MAX_JSON_BYTES, object, runId, runtimeShape } from "./project";
import { runExitCode, runTerminal, withWorkspaceShutdown, writeTerminalBytes } from "./terminal";

export const WORKSPACE_HELP = `Usage: agent-smith workspace COMMAND
  create --root ROOT --name NAME --runtime JSON --targets JSON
  boot PROJECT
  status PROJECT
  run PROJECT -- ARG...
  terminal PROJECT [--attach RUN_ID | -- ARG...]
  tools PROJECT kali|hexstrike
  mcp PROJECT kali|hexstrike TOOL ARGUMENTS_JSON
  ask PROJECT PROMPT
  evidence PROJECT RUN_ID
  cancel PROJECT RUN_ID
  takeover PROJECT RUN_ID
  input PROJECT RUN_ID OWNER_EPOCH BASE64
  resize PROJECT RUN_ID OWNER_EPOCH ROWS COLS
  stop PROJECT
Run and MCP output is original combined guest bytes. Run identity and terminal status go to stderr.
status/evidence never boot a VM. boot/run/terminal/tools/mcp/ask keep the VM managed between calls.
`;

function jsonArgument(value: string): unknown {
	if (Buffer.byteLength(value) > MAX_JSON_BYTES) throw new Error("JSON argument exceeds size limit");
	return JSON.parse(value) as unknown;
}

function serverName(value: string): McpServer {
	if (value !== "kali" && value !== "hexstrike") throw new Error("MCP server must be kali or hexstrike");
	return value;
}

function decimal(value: string, min: number, max: number): number {
	if (!/^\d+$/.test(value)) throw new Error("Expected decimal integer");
	return integer(Number(value), min, max);
}

function print(value: unknown): void {
	process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

async function follow(client: WorkspaceClient, request: RunRequest, signal: AbortSignal): Promise<void> {
	signal.throwIfAborted();
	let run = await client.startRun(request);
	let offset = 0;
	let cancellationSent = false;
	try {
		await writeTerminalBytes(Buffer.from(`Guest run ${run.id}\n`), process.stderr);
		const deadline = Date.now() + request.timeoutMs + 60000;
		while (Date.now() < deadline) {
			if (signal.aborted && !cancellationSent) {
				cancellationSent = true;
				run = await client.cancel(run.id);
			}
			const output = await client.readRun(run.id, offset);
			run = output.run;
			const bytes = originalBytes(output.data);
			if (bytes.length) await writeTerminalBytes(bytes);
			offset = output.nextOffset;
			if (
				run.state !== "running" &&
				(run.captureComplete || run.state === "unknown") &&
				offset === run.outputBytes
			) {
				process.exitCode = runExitCode(run);
				return;
			}
			if (!bytes.length) await Bun.sleep(100);
		}
		throw new Error(`Host wait timed out for ${run.id}; query status/evidence for the durable outcome`);
	} finally {
		await writeTerminalBytes(Buffer.from(`${JSON.stringify(run)}\n`), process.stderr);
	}
}

export async function runWorkspaceCli(argv: string[]): Promise<void> {
	const [command, ...args] = argv;
	if (!command || command === "help" || command === "--help" || command === "-h") {
		process.stdout.write(WORKSPACE_HELP);
		return;
	}
	if (command === "create") {
		const options = new Map<string, string>();
		for (let index = 0; index < args.length; index += 2) {
			const name = args[index];
			const value = args[index + 1];
			if (!["--root", "--name", "--runtime", "--targets"].includes(name) || value === undefined || options.has(name))
				throw new Error("Invalid or repeated workspace create option");
			options.set(name, value);
		}
		const root = options.get("--root");
		const name = options.get("--name");
		const runtime = options.get("--runtime");
		const targets = options.get("--targets");
		if (!root || !name || !runtime || !targets)
			throw new Error("create requires --root, --name, --runtime and --targets");
		const parsedTargets = jsonArgument(targets);
		if (!Array.isArray(parsedTargets) || !parsedTargets.every(target => typeof target === "string"))
			throw new Error("Targets must be a JSON string array");
		process.stdout.write(
			`${await createProject(path.resolve(root), name, runtimeShape(jsonArgument(runtime)), parsedTargets)}\n`,
		);
		return;
	}
	if (!args[0]) throw new Error("Workspace command requires a project directory");
	const dir = path.resolve(args[0]);
	const rest = args.slice(1);
	function count(length: number): void {
		if (rest.length !== length) throw new Error(`Invalid arguments for workspace ${command}`);
	}
	if (command === "serve") {
		count(0);
		await serveWorkspace(dir);
		return;
	}
	if (command === "boot") {
		count(0);
		print(await (await startWorkspace(dir)).status());
		return;
	}
	if (command === "status") {
		count(0);
		print(await (await connectWorkspace(dir)).status());
		return;
	}
	if (command === "stop") {
		count(0);
		print(await (await connectWorkspace(dir)).stop());
		return;
	}
	if (command === "ask") {
		count(1);
		if (!rest[0].trim() || Buffer.byteLength(rest[0]) > 65536)
			throw new Error("Prompt must be nonempty and at most 64 KiB");
		await withWorkspaceShutdown(async signal => {
			const result = await investigate(dir, await startWorkspace(dir), rest[0], signal);
			await writeTerminalBytes(Buffer.from(`${JSON.stringify(result, null, 2)}\n`));
		});
		return;
	}
	if (command === "terminal") {
		if (rest.length && rest[0] !== "--" && !(rest.length === 2 && rest[0] === "--attach"))
			throw new Error("terminal accepts --attach RUN_ID or -- ARG...");
		if (rest[0] === "--" && rest.length === 1) throw new Error("Missing terminal argv");
		await runTerminal(await startWorkspace(dir), rest.length ? (rest[0] === "--" ? rest.slice(1) : rest) : undefined);
		return;
	}
	if (command === "run") {
		if (rest[0] !== "--" || rest.length < 2) throw new Error("run requires -- ARG...");
		await withWorkspaceShutdown(async signal => {
			await follow(
				await startWorkspace(dir),
				{
					actor: "human",
					kind: "command",
					argv: rest.slice(1),
					cwd: "/work",
					timeoutMs: 300000,
				},
				signal,
			);
		});
		return;
	}
	if (command === "tools" || command === "mcp") {
		count(command === "tools" ? 1 : 3);
		const server = serverName(rest[0]);
		const request: RunRequest =
			command === "tools"
				? { actor: "human", kind: "mcp-list", server, timeoutMs: 120000 }
				: {
						actor: "human",
						kind: "mcp",
						server,
						tool: rest[1],
						arguments: object(jsonArgument(rest[2])),
						timeoutMs: 300000,
					};
		await withWorkspaceShutdown(async signal => follow(await startWorkspace(dir), request, signal));
		return;
	}
	if (command === "evidence") {
		count(1);
		const id = runId(rest[0]);
		const client = await connectWorkspace(dir);
		let offset = 0;
		let snapshot: RunSnapshot;
		do {
			const output = await client.readRun(id, offset);
			snapshot = output.run;
			if (output.nextOffset > offset) await writeTerminalBytes(originalBytes(output.data));
			offset = output.nextOffset;
		} while (offset < snapshot.outputBytes);
		process.stderr.write(
			`${JSON.stringify({ ...snapshot, evidence: `${id}.bin`, journal: `${id}.journal.jsonl` })}\n`,
		);
		return;
	}
	if (command === "cancel" || command === "takeover") {
		count(1);
		const id = runId(rest[0]);
		const client = await connectWorkspace(dir);
		print(command === "cancel" ? await client.cancel(id) : await client.takeover(id));
		return;
	}
	if (command === "input") {
		count(3);
		const id = runId(rest[0]);
		const epoch = decimal(rest[1], 0, Number.MAX_SAFE_INTEGER);
		originalBytes(rest[2]);
		print(await (await connectWorkspace(dir)).input(id, rest[2], epoch));
		return;
	}
	if (command === "resize") {
		count(4);
		const id = runId(rest[0]);
		const epoch = decimal(rest[1], 0, Number.MAX_SAFE_INTEGER);
		print(
			await (await connectWorkspace(dir)).resize(id, decimal(rest[2], 1, 1000), decimal(rest[3], 1, 1000), epoch),
		);
		return;
	}
	throw new Error(`Unknown workspace command: ${command}`);
}

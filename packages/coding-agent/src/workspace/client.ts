import * as fs from "node:fs/promises";
import * as path from "node:path";
import { Process } from "@oh-my-pi/pi-natives";
import { acquireFileLock, isCompiledBinary, isEnoent } from "@oh-my-pi/pi-utils";
import { workerHostEntry } from "@oh-my-pi/pi-utils/worker-host";
import type { RunOutput, RunRequest, RunSnapshot, WorkspaceClient, WorkspaceStatus } from "./contracts";
import { CaptureStore, identityAlive, offlineStatus, processExited, savedState } from "./broker";
import { JsonPeer, originalBytes, validateOutput, validateRun, validateRunRequest } from "./guest-transport";
import { assertLinux, cleanEnvironment, integer, loadProject, object, readJson, regularFile, runId } from "./project";

async function socketExists(dir: string): Promise<boolean> {
	try {
		const stat = await fs.lstat(path.join(dir, "broker.sock"));
		if (!stat.isSocket() || stat.uid !== process.getuid?.() || (stat.mode & 0o077) !== 0)
			throw new Error("Unsafe private broker socket");
		return true;
	} catch (error) {
		if (isEnoent(error)) return false;
		throw error;
	}
}

class PrivateClient implements WorkspaceClient {
	#token: string;
	constructor(
		readonly dir: string,
		readonly project: string,
		token: string,
	) {
		this.#token = token;
	}
	async #request(op: string, args: Record<string, unknown> = {}, timeoutMs = 40000): Promise<unknown> {
		if (!(await socketExists(this.dir))) throw new Error("Workspace broker is unavailable");
		const peer = new JsonPeer(path.join(this.dir, "broker.sock"));
		try {
			const response = await peer.request(
				{ v: 1, id: crypto.randomUUID(), project: this.project, token: this.#token, op, args },
				timeoutMs,
			);
			if (response.v !== 1 || response.project !== this.project || typeof response.ok !== "boolean")
				throw new Error("Invalid private broker response");
			if (!response.ok)
				throw new Error(
					typeof response.error === "string" ? response.error.slice(0, 1024) : "Workspace operation failed",
				);
			return response.result;
		} finally {
			peer.close();
		}
	}
	#status(value: unknown): WorkspaceStatus {
		const result = object(value);
		if (
			object(result.project).id !== this.project ||
			!["stopped", "starting", "running", "stopping", "unknown"].includes(String(result.state)) ||
			(result.accelerator !== null && result.accelerator !== "kvm") ||
			!Array.isArray(result.runs)
		)
			throw new Error("Invalid broker status");
		if (result.generation !== null) runId(result.generation);
		for (const run of result.runs) validateRun(run, this.project);
		return result as unknown as WorkspaceStatus;
	}
	async status(): Promise<WorkspaceStatus> {
		return this.#status(await this.#request("status"));
	}
	async startRun(request: RunRequest): Promise<RunSnapshot> {
		return validateRun(await this.#request("start", { ...validateRunRequest(request) }), this.project);
	}
	async readRun(id: string, offset = 0): Promise<RunOutput> {
		runId(id);
		integer(offset, 0, Number.MAX_SAFE_INTEGER);
		return validateOutput(await this.#request("read", { id, offset }), this.project, id, offset);
	}
	async input(id: string, data: string, ownerEpoch: number): Promise<RunSnapshot> {
		return validateRun(
			await this.#request("input", {
				id: runId(id),
				data: originalBytes(data).toString("base64"),
				ownerEpoch: integer(ownerEpoch, 0, Number.MAX_SAFE_INTEGER),
			}),
			this.project,
		);
	}
	async resize(id: string, rows: number, cols: number, ownerEpoch: number): Promise<RunSnapshot> {
		return validateRun(
			await this.#request("resize", {
				id: runId(id),
				rows: integer(rows, 1, 1000),
				cols: integer(cols, 1, 1000),
				ownerEpoch: integer(ownerEpoch, 0, Number.MAX_SAFE_INTEGER),
			}),
			this.project,
		);
	}
	async takeover(id: string): Promise<RunSnapshot> {
		return validateRun(await this.#request("takeover", { id: runId(id) }), this.project);
	}
	async cancel(id: string): Promise<RunSnapshot> {
		return validateRun(await this.#request("cancel", { id: runId(id) }), this.project);
	}
	async stop(): Promise<WorkspaceStatus> {
		const deadline = Date.now() + 40000;
		const saved = await savedState(this.dir);
		if (!saved || !(await identityAlive(saved.broker))) throw new Error("Workspace broker identity is unavailable");
		const broker = Process.fromPid(saved.broker.pid);
		if (!broker || !(await identityAlive(saved.broker))) throw new Error("Workspace broker identity changed");
		const status = this.#status(await this.#request("stop", {}, Math.max(1, deadline - Date.now())));
		// The reply precedes socket teardown and lease release; it is not daemon exit.
		if (!(await broker.waitForExit({ timeoutMs: Math.max(0, deadline - Date.now()) })))
			throw new Error("Workspace broker exit could not be confirmed within the stop deadline");
		return status;
	}
}

class StoppedClient implements WorkspaceClient {
	constructor(
		readonly dir: string,
		readonly project: string,
	) {}
	async status(): Promise<WorkspaceStatus> {
		return offlineStatus(this.dir);
	}
	async readRun(id: string, offset = 0): Promise<RunOutput> {
		const result = await new CaptureStore(path.join(this.dir, "captures"), this.project).read(id, offset);
		if (result.run.state === "running") result.run = { ...result.run, state: "unknown", captureComplete: false };
		return result;
	}
	async startRun(_request: RunRequest): Promise<RunSnapshot> {
		throw new Error("Workspace is stopped; boot it explicitly");
	}
	async input(_id: string, _data: string, _ownerEpoch: number): Promise<RunSnapshot> {
		throw new Error("No live terminal ownership");
	}
	async resize(_id: string, _rows: number, _cols: number, _ownerEpoch: number): Promise<RunSnapshot> {
		throw new Error("No live terminal ownership");
	}
	async takeover(_id: string): Promise<RunSnapshot> {
		throw new Error("No live terminal ownership");
	}
	async cancel(_id: string): Promise<RunSnapshot> {
		throw new Error("No live guest run to cancel");
	}
	async stop(): Promise<WorkspaceStatus> {
		const status = await this.status();
		if (status.state !== "stopped")
			throw new Error("Unreachable broker with a live recorded process; stop is unconfirmed");
		return status;
	}
}

/** Read-only connect never starts a VM; historical captures remain readable while stopped. */
export async function connectWorkspace(projectDir: string): Promise<WorkspaceClient> {
	const project = await loadProject(projectDir);
	const auth = object(await readJson(path.join(projectDir, "client-token.json")));
	if (typeof auth.token !== "string" || !/^[a-f0-9]{64}$/.test(auth.token))
		throw new Error("Invalid private client token");
	if (await socketExists(projectDir)) {
		const client = new PrivateClient(projectDir, project.id, auth.token);
		try {
			await client.status();
			return client;
		} catch (error) {
			const state = await savedState(projectDir);
			if (state && ((await identityAlive(state.broker)) || (await identityAlive(state.vm)))) throw error;
		}
	}
	return new StoppedClient(projectDir, project.id);
}

export async function brokerCommand(projectDir: string): Promise<string[]> {
	if (isCompiledBinary()) return [process.execPath, "workspace", "serve", projectDir];
	// Declared by the actual CLI entrypoint, including source and npm bundles. No cwd inference.
	let entry = workerHostEntry();
	if (!entry) {
		// SDK embedding has no declared worker host. Resolve only installation-local
		// source/npm entrypoints, never a command discovered through PATH or cwd.
		for (const candidate of [
			path.resolve(import.meta.dir, "../cli.ts"),
			path.resolve(import.meta.dir, "cli.js"),
			path.resolve(import.meta.dir, "../cli.js"),
		]) {
			try {
				if ((await fs.stat(candidate)).isFile()) {
					entry = candidate;
					break;
				}
			} catch (error) {
				if (!isEnoent(error)) throw error;
			}
		}
	}
	if (!entry || !path.isAbsolute(entry))
		throw new Error("Application CLI entrypoint is unavailable in this installation");
	return [process.execPath, "--no-env-file", entry, "workspace", "serve", projectDir];
}

export async function startWorkspace(projectDir: string): Promise<WorkspaceClient> {
	assertLinux();
	await loadProject(projectDir);
	const lease = await acquireFileLock(path.join(projectDir, "startup"), { retries: 1200, retryDelayMs: 100 });
	try {
		// stop's reply is flushed before the daemon releases its OS lease. Allow that
		// short handoff to finish, while never inferring death from a PID alone.
		const stoppingDeadline = Date.now() + 3000;
		while (Date.now() < stoppingDeadline) {
			const saved = await savedState(projectDir);
			if (!saved || saved.state !== "stopped" || !(await identityAlive(saved.broker))) break;
			await Bun.sleep(25);
		}
		const current = await connectWorkspace(projectDir);
		const status = await current.status();
		if (status.state === "running") return current;
		if (status.state !== "stopped") throw new Error("Recorded workspace is still live; refusing duplicate boot");
		const logFile = path.join(projectDir, "broker.log");
		try {
			await regularFile(logFile, true);
		} catch (error) {
			if (!isEnoent(error)) throw error;
		}
		const command = await brokerCommand(projectDir);
		const log = await fs.open(
			logFile,
			fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_APPEND | fs.constants.O_NOFOLLOW,
			0o600,
		);
		const child = await (async () => {
			try {
				return Bun.spawn(command, {
					detached: true,
					cwd: path.join(projectDir, "home"),
					env: cleanEnvironment(projectDir),
					stdin: "ignore",
					stdout: log.fd,
					stderr: log.fd,
				});
			} finally {
				await log.close();
			}
		})();
		const deadline = Date.now() + 120000;
		try {
			while (Date.now() < deadline) {
				if (processExited(child))
					throw new Error(
						`Workspace broker exited (${child.exitCode ?? child.signalCode}); inspect project-local broker.log`,
					);
				if (await socketExists(projectDir)) {
					try {
						const client = await connectWorkspace(projectDir);
						if ((await client.status()).state === "running") {
							child.unref();
							return client;
						}
					} catch {
						/* Startup remains bounded; no operation is replayed. */
					}
				}
				await Bun.sleep(100);
			}
			throw new Error("Workspace boot timed out; inspect project-local broker.log");
		} catch (error) {
			if (!processExited(child)) child.kill("SIGTERM");
			await Promise.race([child.exited, Bun.sleep(15000)]);
			if (!processExited(child)) child.kill("SIGKILL");
			await Promise.race([child.exited, Bun.sleep(2000)]);
			child.unref();
			throw error;
		}
	} finally {
		lease.release();
	}
}

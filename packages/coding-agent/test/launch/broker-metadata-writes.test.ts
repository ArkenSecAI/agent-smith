import { describe, expect, it, spyOn, vi } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { TempDir } from "@oh-my-pi/pi-utils";
import { startDaemonBrokerFromEnvironment } from "../../src/launch/broker";
import { createDaemonBrokerClient } from "../../src/launch/client";
import {
	DAEMON_IDLE_GRACE_ENV,
	DAEMON_PROJECT_DIR_ENV,
	DAEMON_RUNTIME_DIR_ENV,
	type DaemonOperation,
} from "../../src/launch/protocol";
import type { DaemonSpec } from "@oh-my-pi/pi-tui/tools/daemon";
import { daemonBrokerEndpoint } from "../../src/launch/paths";
import { connectJsonlSocket, LineParser, writeJsonLine } from "../../src/tiny/jsonl-socket";

function startBroker(projectDir: string, runtimeDir: string): { listening: Promise<boolean>; finished: Promise<void> } {
	const previousProjectDir = process.env[DAEMON_PROJECT_DIR_ENV];
	const previousRuntimeDir = process.env[DAEMON_RUNTIME_DIR_ENV];
	const previousGrace = process.env[DAEMON_IDLE_GRACE_ENV];
	process.env[DAEMON_PROJECT_DIR_ENV] = projectDir;
	process.env[DAEMON_RUNTIME_DIR_ENV] = runtimeDir;
	process.env[DAEMON_IDLE_GRACE_ENV] = "5000";
	const listening = Promise.withResolvers<boolean>();
	const finished = startDaemonBrokerFromEnvironment({ onListening: () => listening.resolve(true) });
	if (previousProjectDir === undefined) delete process.env[DAEMON_PROJECT_DIR_ENV];
	else process.env[DAEMON_PROJECT_DIR_ENV] = previousProjectDir;
	if (previousRuntimeDir === undefined) delete process.env[DAEMON_RUNTIME_DIR_ENV];
	else process.env[DAEMON_RUNTIME_DIR_ENV] = previousRuntimeDir;
	if (previousGrace === undefined) delete process.env[DAEMON_IDLE_GRACE_ENV];
	else process.env[DAEMON_IDLE_GRACE_ENV] = previousGrace;
	return { listening: listening.promise, finished };
}

describe("daemon metadata writes", () => {
	it("does not rewrite settled history on subscriber changes or broker restart", async () => {
		using tempDir = TempDir.createSync("@omp-broker-metadata-");
		const projectDir = path.join(tempDir.path(), "project");
		const runtimeDir = path.join(tempDir.path(), "runtime");
		const metadataPath = path.join(runtimeDir, "daemons", "historical", "meta.json");
		await fs.mkdir(projectDir);
		await Bun.write(
			metadataPath,
			JSON.stringify({
				daemon: {
					name: "historical",
					id: "historical",
					state: "exited",
					owner: "shared-session",
					createdAt: 1,
					startedAt: 1,
					exitedAt: 2,
					restartCount: 0,
					outputBytes: 0,
					persist: false,
					detached: false,
				},
				spec: {
					name: "historical",
					application: process.execPath,
					args: [],
					env: {},
					cwd: projectDir,
					pty: false,
					restart: "no",
					persist: false,
					detached: false,
				},
			}),
		);
		const initialClient = await createDaemonBrokerClient(projectDir, { runtimeDir, idleGraceMs: 5_000 });
		const initialBroker = startBroker(projectDir, runtimeDir);
		try {
			await initialBroker.listening;
			await initialClient.request({ op: "ping" });
		} finally {
			await initialClient.request({ op: "shutdown" }).catch(() => undefined);
			initialClient.close();
			await initialBroker.finished;
		}
		// The initial recovery may normalize the fixture. Shutdown flushes all
		// queued metadata writes before establishing the stable inode baseline.
		const inode = (await fs.stat(metadataPath)).ino;
		const first = await createDaemonBrokerClient(projectDir, { runtimeDir, idleGraceMs: 5_000 });
		const second = await createDaemonBrokerClient(projectDir, { runtimeDir, idleGraceMs: 5_000 });
		const broker = startBroker(projectDir, runtimeDir);
		try {
			await broker.listening;
			first.onCompletion("shared-session", () => undefined);
			second.onCompletion("shared-session", () => undefined);
			for (let index = 0; index < 3; index++) {
				await first.request({ op: "ping" });
				await second.request({ op: "ping" });
			}
			await first.request({ op: "shutdown" });
			first.close();
			second.close();
			await broker.finished;
		} finally {
			await first.request({ op: "shutdown" }).catch(() => undefined);
			first.close();
			second.close();
			await broker.finished;
		}
		expect((await fs.stat(metadataPath)).ino).toBe(inode);

		const restartClient = await createDaemonBrokerClient(projectDir, { runtimeDir, idleGraceMs: 5_000 });
		const restarted = startBroker(projectDir, runtimeDir);
		try {
			await restarted.listening;
			await restartClient.request({ op: "ping" });
			await restartClient.request({ op: "shutdown" });
			await restarted.finished;
			expect((await fs.stat(metadataPath)).ino).toBe(inode);
		} finally {
			restartClient.close();
			await restarted.finished;
		}

		const relaunchClient = await createDaemonBrokerClient(projectDir, { runtimeDir, idleGraceMs: 5_000 });
		const relaunchBroker = startBroker(projectDir, runtimeDir);
		try {
			await relaunchBroker.listening;
			relaunchClient.onCompletion("shared-session", () => undefined);
			await relaunchClient.request({ op: "restart", name: "historical" });
			const metadata = (await Bun.file(metadataPath).json()) as { completionEvents: boolean };
			expect(metadata.completionEvents).toBe(true);
		} finally {
			await relaunchClient.request({ op: "shutdown" }).catch(() => undefined);
			relaunchClient.close();
			await relaunchBroker.finished;
		}
	}, 20_000);

	it("drains a preparing start and rejects new starts before completing shutdown", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "broker-drain-"));
		const projectDir = path.join(root, "project");
		const runtimeDir = path.join(root, "runtime");
		const marker = path.join(root, "unexpected-child");
		await fs.mkdir(projectDir);
		const client = await createDaemonBrokerClient(projectDir, { runtimeDir });
		const previousTitle = process.title;
		const broker = startBroker(projectDir, runtimeDir);
		await broker.listening;
		await client.request({ op: "ping" });
		const socket = await connectJsonlSocket(daemonBrokerEndpoint(projectDir, runtimeDir), 1_000);
		const token = (await fs.readFile(path.join(runtimeDir, "broker.token"), "utf8")).trim();
		async function rpc(operation: DaemonOperation): Promise<{ ok: boolean }> {
			const response = Promise.withResolvers<{ ok: boolean }>();
			const parser = new LineParser(line => response.resolve(JSON.parse(line)));
			const onData = (chunk: string) => parser.push(chunk);
			const onClose = () => response.reject(new Error("Broker closed before draining preparation"));
			socket.on("data", onData);
			socket.once("close", onClose);
			socket.once("error", response.reject);
			try {
				writeJsonLine(socket, { id: crypto.randomUUID(), token, operation });
				return await response.promise;
			} finally {
				socket.off("data", onData);
				socket.off("close", onClose);
				socket.off("error", response.reject);
			}
		}
		const preparing = Promise.withResolvers<void>();
		const release = Promise.withResolvers<void>();
		const stat = fs.stat;
		const delayedStat = (async (...args: Parameters<typeof fs.stat>) => {
			if (args[0] === projectDir) {
				preparing.resolve();
				await release.promise;
			}
			return stat(...args);
		}) as typeof fs.stat;
		const statSpy = spyOn(fs, "stat").mockImplementation(delayedStat);
		const spec: DaemonSpec = {
			name: "preparing",
			application: process.execPath,
			args: ["--no-env-file", "-e", `await Bun.write(${JSON.stringify(marker)}, "launched");`],
			env: {},
			cwd: projectDir,
			pty: false,
			restart: "no",
			persist: true,
			detached: false,
		};
		let passed = false;
		vi.useFakeTimers();
		const started = client.request({ op: "start", spec }).then(
			result => ({ result }),
			(error: unknown) => ({ error }),
		);
		try {
			await preparing.promise;
			expect((await rpc({ op: "shutdown" })).ok).toBe(true);
			// Deliver the acknowledged shutdown callback deterministically while
			// preparation remains gated; no guessed sleep or child-start timing.
			vi.advanceTimersByTime(10);
			expect((await rpc({ op: "start", spec: { ...spec, name: "after-shutdown" } })).ok).toBe(false);
			release.resolve();
			await started;
			await broker.finished;
			expect(await Bun.file(marker).exists()).toBe(false);
			passed = true;
		} finally {
			release.resolve();
			statSpy.mockRestore();
			client.close();
			socket.destroy();
			await broker.finished;
			vi.useRealTimers();
			process.title = previousTitle;
			// A failed lifecycle proof retains its state instead of deleting under
			// potentially outstanding preparation or a late child.
			if (passed) await fs.rm(root, { recursive: true, force: true });
		}
	}, 20_000);
});

import { afterEach, beforeEach, describe, expect, it, spyOn, vi } from "bun:test";
import * as fs from "node:fs/promises";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import type { BrokerState, TerminableProcess } from "../src/workspace/broker";
import {
	CaptureStore,
	identityAlive,
	offlineStatus,
	processExited,
	processIdentity,
	Qmp,
	terminateVm,
	validateDiskChain,
} from "../src/workspace/broker";
import { connectWorkspace } from "../src/workspace/client";
import type { ProjectManifest, RunSnapshot } from "../src/workspace/contracts";
import {
	authenticatedToken,
	GuestTransport,
	JsonLines,
	originalBytes,
	validateOutput,
	validateRunRequest,
} from "../src/workspace/guest-transport";
import {
	cleanEnvironment,
	durableJson,
	loadProject,
	object,
	readJson,
	verifyPinnedFile,
} from "../src/workspace/project";
import { runExitCode } from "../src/workspace/terminal";

const projectId = "9dfe93f0-7436-4c75-ad6e-78b3144d1011";
const generation = "740ec6e0-6a0f-477a-a476-e4548eb33f6b";
const runUuid = "1dbe219c-35a5-43e0-ad3f-86ac39a894f3";
const token = "ab".repeat(32);
let dir: string;
const servers: net.Server[] = [];
const sockets = new Set<net.Socket>();

function snapshot(changes: Partial<RunSnapshot> = {}): RunSnapshot {
	return {
		id: runUuid,
		project: projectId,
		generation,
		actor: "human",
		kind: "command",
		state: "running",
		exitCode: null,
		signal: null,
		cancelRequested: false,
		captureComplete: false,
		outputBytes: 0,
		ownerEpoch: 0,
		startedAt: "2026-10-13T00:00:00.000Z",
		endedAt: null,
		...changes,
	};
}

beforeEach(async () => {
	dir = await fs.mkdtemp(
		path.join(await fs.realpath(process.platform === "win32" ? os.tmpdir() : "/tmp"), "smith-host-"),
	);
	await fs.chmod(dir, 0o700);
});

afterEach(async () => {
	vi.restoreAllMocks();
	for (const socket of sockets) socket.destroy();
	sockets.clear();
	for (const server of servers.splice(0)) {
		const closed = Promise.withResolvers<void>();
		server.close(() => closed.resolve());
		await closed.promise;
	}
	await fs.rm(dir, { recursive: true, force: true });
});

async function unixServer(handle: (socket: net.Socket) => void): Promise<string> {
	const file = path.join(dir, `${crypto.randomUUID().slice(0, 8)}.sock`);
	const server = net.createServer(socket => {
		sockets.add(socket);
		socket.on("error", () => socket.destroy());
		socket.on("close", () => sockets.delete(socket));
		handle(socket);
	});
	servers.push(server);
	const ready = Promise.withResolvers<void>();
	server.once("error", ready.reject);
	server.listen(file, () => ready.resolve());
	await ready.promise;
	return file;
}

async function projectFixture(): Promise<ProjectManifest> {
	for (const sub of ["vm", "captures", "home", "tmp", "disk"]) await fs.mkdir(path.join(dir, sub), { mode: 0o700 });
	const hash = "0".repeat(64);
	const project: ProjectManifest = {
		schema: 1,
		id: projectId,
		name: "synthetic",
		createdAt: "2026-10-13T00:00:00.000Z",
		targets: ["127.0.0.1"],
		image: {
			schema: 1,
			id: "synthetic",
			isa: "x86_64",
			disk: { path: "/synthetic/base.qcow2", sha256: hash },
			guestSha256: hash,
			packages: { path: "/synthetic/packages.json", sha256: hash },
			provenance: { path: "/synthetic/provenance.json", sha256: hash },
		},
		runtime: {
			schema: 1,
			qemu: {
				binary: "/synthetic/qemu",
				sha256: hash,
				imageBinary: "/synthetic/qemu-img",
				imageSha256: hash,
				firmwareDir: "/synthetic/firmware",
			},
			imageManifest: "/synthetic/image.json",
			memoryMiB: 1024,
			cpus: 1,
		},
	};
	await durableJson(path.join(dir, "project.json"), project);
	await durableJson(path.join(dir, "client-token.json"), { token });
	return project;
}

async function privateBroker(
	project: ProjectManifest,
	handle: (op: string, args: Record<string, unknown>) => Promise<unknown>,
): Promise<void> {
	const socket = await unixServer(peer => {
		const parser = new JsonLines(value => {
			const request = object(value);
			void Promise.try(async () => {
				if (!authenticatedToken(request.token, token) || request.project !== project.id)
					throw new Error("Invalid synthetic broker identity");
				const result =
					request.op === "status"
						? { project, generation, state: "running", accelerator: "kvm", runs: [] }
						: await handle(String(request.op), object(request.args));
				peer.write(`${JSON.stringify({ v: 1, id: request.id, project: project.id, ok: true, result })}\n`);
			}).catch(error => {
				peer.write(
					`${JSON.stringify({ v: 1, id: request.id, project: project.id, ok: false, error: String(error) })}\n`,
				);
			});
		});
		peer.on("data", bytes => {
			if (typeof bytes === "string") throw new Error("Expected test peer bytes");
			parser.feed(bytes);
		});
	});
	const brokerSocket = path.join(dir, "broker.sock");
	await fs.rename(socket, brokerSocket);
	await fs.chmod(brokerSocket, 0o600);
}

async function beforeChildExit<T>(child: Pick<Bun.Subprocess, "exited">, ready: Promise<T>): Promise<T> {
	return Promise.race([
		ready,
		child.exited.then(code => {
			throw new Error(`CLI exited ${code} before completing the broker exchange`);
		}),
	]);
}

describe.skipIf(process.platform !== "linux")("workspace CLI interruption", () => {
	for (const boundary of ["read", "start", "cancel-error"] as const) {
		it(
			boundary === "read"
				? "awaits SIGINT cancellation and drains original bytes before its terminal snapshot"
				: boundary === "start"
					? "cancels a run whose start reply arrives after SIGTERM"
					: "reports rejected cancellation without claiming the guest stopped or losing captured bytes",
			async () => {
				const project = await projectFixture();
				const prefix = Buffer.from([0, 255, 13, 10, 65]);
				const suffix = Buffer.from([27, 91, 50, 74, 0, 66]);
				const original = Buffer.concat([prefix, suffix]);
				const reached = Promise.withResolvers<void>();
				const release = Promise.withResolvers<void>();
				const cancellation = Promise.withResolvers<void>();
				const releaseCancellation = Promise.withResolvers<void>();
				const signalHandled = Promise.withResolvers<void>();
				let cancellations = 0;
				let cancelled = false;
				const terminalRun = snapshot({
					state: "cancelled",
					signal: 15,
					cancelRequested: true,
					captureComplete: true,
					outputBytes: original.length,
					endedAt: "2026-10-13T00:00:01.000Z",
				});
				await privateBroker(project, async (op, args) => {
					if (op === "start") {
						if (boundary === "start") {
							reached.resolve();
							await release.promise;
						}
						return snapshot();
					}
					if (op === "cancel") {
						cancellations++;
						cancellation.resolve();
						await releaseCancellation.promise;
						if (boundary === "cancel-error") throw new Error("synthetic cancellation rejected");
						cancelled = true;
						// Guest completion does not yet prove host capture completion.
						return { ...terminalRun, captureComplete: false, outputBytes: prefix.length };
					}
					if (op === "read") {
						const offset = Number(args.offset);
						if (boundary !== "start" && !cancelled) {
							reached.resolve();
							await release.promise;
						}
						const nextOffset = offset === 0 ? prefix.length : cancelled ? original.length : offset;
						const run = cancelled
							? { ...terminalRun, captureComplete: nextOffset === original.length, outputBytes: nextOffset }
							: snapshot({ outputBytes: nextOffset });
						return { run, offset, nextOffset, data: original.subarray(offset, nextOffset).toString("base64") };
					}
					throw new Error(`Unexpected synthetic operation: ${op}`);
				});
				const signal = boundary === "start" ? "SIGTERM" : "SIGINT";
				const preload = path.join(dir, "signal-observer.ts");
				// Observe real OS dispatch without replacing any production signal listener.
				await Bun.write(preload, `process.on(${JSON.stringify(signal)}, () => process.send?.("signal"));\n`);
				const child = Bun.spawn(
					[
						process.execPath,
						"--no-env-file",
						"--preload",
						preload,
						path.resolve(import.meta.dir, "../src/cli.ts"),
						"workspace",
						"run",
						dir,
						"--",
						"/synthetic/never-executed",
					],
					{
						cwd: dir,
						env: cleanEnvironment(dir),
						stdin: "ignore",
						stdout: "pipe",
						stderr: "pipe",
						serialization: "json",
						ipc(message: unknown) {
							if (message === "signal") signalHandled.resolve();
						},
					},
				);
				const stdout = new Response(child.stdout).arrayBuffer();
				const stderr = new Response(child.stderr).text();
				const watchdog = setTimeout(() => child.kill("SIGKILL"), 20000);
				try {
					await beforeChildExit(child, reached.promise);
					child.kill(signal);
					await beforeChildExit(child, signalHandled.promise);
					release.resolve();
					await beforeChildExit(child, cancellation.promise);
					releaseCancellation.resolve();
					const code = await child.exited;
					const report = await stderr;
					if (boundary === "cancel-error") expect(code, report).not.toBe(0);
					else expect(code, report).toBe(boundary === "start" ? 143 : 130);
					expect(cancellations).toBe(1);
					expect(Buffer.from(await stdout)).toEqual(boundary === "cancel-error" ? prefix : original);
					const records = report.split("\n").filter(line => line.startsWith("{"));
					expect(records).toHaveLength(1);
					expect(JSON.parse(records[0])).toEqual(
						boundary === "cancel-error" ? snapshot({ outputBytes: prefix.length }) : terminalRun,
					);
					if (boundary === "cancel-error") expect(report).toContain("synthetic cancellation rejected");
				} finally {
					release.resolve();
					releaseCancellation.resolve();
					clearTimeout(watchdog);
					if (!processExited(child)) child.kill("SIGKILL");
					await child.exited;
				}
			},
			30000,
		);
	}

	it("forwards Ctrl-C to the guest and restores the host PTY after SIGTERM with pending input", async () => {
		const project = await projectFixture();
		const ready = Promise.withResolvers<void>();
		const inputReceived = Promise.withResolvers<void>();
		const releaseInput = Promise.withResolvers<void>();
		const signalHandled = Promise.withResolvers<void>();
		const inputs: { bytes: Buffer; epoch: unknown }[] = [];
		let cancellations = 0;
		const run = snapshot({ ownerEpoch: 1 });
		await privateBroker(project, async (op, args) => {
			if (op === "start") return snapshot();
			if (op === "takeover") return run;
			if (op === "resize") {
				ready.resolve();
				return run;
			}
			if (op === "input") {
				inputs.push({ bytes: Buffer.from(String(args.data), "base64"), epoch: args.ownerEpoch });
				inputReceived.resolve();
				await releaseInput.promise;
				return run;
			}
			if (op === "read") return { run, offset: 0, nextOffset: 0, data: "" };
			if (op === "cancel") {
				cancellations++;
				return run;
			}
			throw new Error(`Unexpected synthetic operation: ${op}`);
		});
		const preload = path.join(dir, "signal-observer.ts");
		await Bun.write(preload, 'process.on("SIGTERM", () => process.send?.("signal"));\n');
		const chunks: Buffer[] = [];
		await using terminal = new Bun.Terminal({
			data(_terminal, bytes) {
				chunks.push(Buffer.from(bytes));
			},
		});
		const initialFlags = [terminal.inputFlags, terminal.outputFlags, terminal.localFlags, terminal.controlFlags];
		const child = Bun.spawn(
			[
				process.execPath,
				"--no-env-file",
				"--preload",
				preload,
				path.resolve(import.meta.dir, "../src/cli.ts"),
				"workspace",
				"terminal",
				dir,
				"--",
				"/synthetic/never-executed",
			],
			{
				cwd: dir,
				env: cleanEnvironment(dir),
				terminal,
				serialization: "json",
				ipc(message: unknown) {
					if (message === "signal") signalHandled.resolve();
				},
			},
		);
		const watchdog = setTimeout(() => child.kill("SIGKILL"), 20000);
		try {
			await beforeChildExit(child, ready.promise);
			terminal.write(Uint8Array.of(3));
			await beforeChildExit(child, inputReceived.promise);
			child.kill("SIGTERM");
			await beforeChildExit(child, signalHandled.promise);
			releaseInput.resolve();
			expect(await child.exited, Buffer.concat(chunks).toString()).toBe(143);
			expect(inputs).toEqual([{ bytes: Buffer.from([3]), epoch: 1 }]);
			expect(cancellations).toBe(0);
			expect([terminal.inputFlags, terminal.outputFlags, terminal.localFlags, terminal.controlFlags]).toEqual(
				initialFlags,
			);
		} finally {
			releaseInput.resolve();
			clearTimeout(watchdog);
			if (!processExited(child)) child.kill("SIGKILL");
			await child.exited;
		}
	}, 30000);
});

describe.skipIf(process.platform !== "linux")("host original capture contract", () => {
	it("keeps guest exit separate from host completeness and preserves binary PTY bytes", async () => {
		const store = new CaptureStore(dir, projectId);
		const bytes = Buffer.from([0, 255, 13, 10, 27, 91, 50, 74]);
		const exited = snapshot({
			state: "exited",
			exitCode: 7,
			captureComplete: true,
			outputBytes: bytes.length,
			endedAt: "2026-10-13T00:00:01.000Z",
		});
		const observed = await store.observe(exited);
		expect(observed.guest.captureComplete).toBe(true);
		expect(observed.run).toMatchObject({ state: "exited", exitCode: 7, captureComplete: false, outputBytes: 0 });
		await store.append({ run: exited, offset: 0, nextOffset: 3, data: bytes.subarray(0, 3).toString("base64") });
		expect((await store.read(runUuid)).run.captureComplete).toBe(false);
		await store.append({
			run: exited,
			offset: 3,
			nextOffset: bytes.length,
			data: bytes.subarray(3).toString("base64"),
		});
		const output = await store.read(runUuid);
		expect(Buffer.from(output.data, "base64")).toEqual(bytes);
		expect(await Bun.file(path.join(dir, `${runUuid}.bin`)).bytes()).toEqual(new Uint8Array(bytes));
		expect(output.run).toMatchObject({
			state: "exited",
			exitCode: 7,
			captureComplete: true,
			outputBytes: bytes.length,
		});
		expect(runExitCode(output.run)).toBe(7);
	});

	it("does not publish a byte reference when capture fsync fails", async () => {
		const store = new CaptureStore(dir, projectId);
		await store.observe(snapshot());
		const originalOpen = fs.open;
		spyOn(fs, "open").mockImplementation(async (...args) => {
			const handle = await originalOpen(...args);
			if (String(args[0]).endsWith(".bin"))
				spyOn(handle, "sync").mockRejectedValue(new Error("synthetic fsync failure"));
			return handle;
		});
		await expect(
			store.append({ run: snapshot({ outputBytes: 2 }), offset: 0, nextOffset: 2, data: "QUI=" }),
		).rejects.toThrow("fsync");
		expect((await store.read(runUuid)).run).toMatchObject({ outputBytes: 0, captureComplete: false });
	});

	it("preserves an fsynced pre-publication tail and rejects changed guest replay", async () => {
		const store = new CaptureStore(dir, projectId);
		await store.observe(snapshot());
		await Bun.write(path.join(dir, `${runUuid}.bin`), Buffer.from("original"));
		await expect(
			store.append({
				run: snapshot({ outputBytes: 8 }),
				offset: 0,
				nextOffset: 8,
				data: Buffer.from("replaced").toString("base64"),
			}),
		).rejects.toThrow("differs");
		expect(await Bun.file(path.join(dir, `${runUuid}.bin`)).text()).toBe("original");
		await store.append({
			run: snapshot({ outputBytes: 8 }),
			offset: 0,
			nextOffset: 8,
			data: Buffer.from("original").toString("base64"),
		});
		expect((await store.read(runUuid)).data).toBe(Buffer.from("original").toString("base64"));
	});

	it("surfaces missing committed bytes instead of returning a shortened complete capture", async () => {
		const store = new CaptureStore(dir, projectId);
		const run = snapshot({
			state: "exited",
			exitCode: 0,
			captureComplete: true,
			outputBytes: 2,
			endedAt: "2026-10-13T00:00:01.000Z",
		});
		await store.append({ run, offset: 0, nextOffset: 2, data: "QUI=" });
		await fs.truncate(path.join(dir, `${runUuid}.bin`), 1);
		await expect(store.read(runUuid)).rejects.toThrow("missing bytes");
	});

	it("records unknown outcome after interruption without inventing exit or cancellation", async () => {
		const store = new CaptureStore(dir, projectId);
		await store.append({ run: snapshot({ outputBytes: 2 }), offset: 0, nextOffset: 2, data: "QUI=" });
		await store.interrupted();
		const output = await store.read(runUuid);
		expect(output.run).toMatchObject({
			state: "unknown",
			exitCode: null,
			signal: null,
			cancelRequested: false,
			captureComplete: false,
			outputBytes: 2,
		});
		expect(output.data).toBe("QUI=");
	});

	it("rejects generation reuse and output rewind without altering the published prefix", async () => {
		const store = new CaptureStore(dir, projectId);
		await store.append({ run: snapshot({ outputBytes: 2 }), offset: 0, nextOffset: 2, data: "QUI=" });
		await expect(store.observe(snapshot({ generation: crypto.randomUUID(), outputBytes: 2 }))).rejects.toThrow(
			"regressed",
		);
		await expect(store.observe(snapshot({ outputBytes: 1 }))).rejects.toThrow("regressed");
		await expect(store.read(runUuid, 3)).rejects.toThrow("Offset");
		expect((await store.read(runUuid)).data).toBe("QUI=");
	});

	it("refuses to append across a torn journal tail while retaining readable committed evidence", async () => {
		const store = new CaptureStore(dir, projectId);
		await store.append({ run: snapshot({ outputBytes: 2 }), offset: 0, nextOffset: 2, data: "QUI=" });
		await fs.appendFile(path.join(dir, `${runUuid}.journal.jsonl`), '{"event":');
		await expect(store.observe(snapshot({ outputBytes: 2, cancelRequested: true }))).rejects.toThrow(
			"incomplete tail",
		);
		expect((await store.read(runUuid)).data).toBe("QUI=");
		expect((await store.read(runUuid)).run.cancelRequested).toBe(false);
	});

	it("refuses a symlink capture target without overwriting its destination", async () => {
		const victim = path.join(dir, "owned-fixture.bin");
		await Bun.write(victim, "untouched");
		await fs.chmod(victim, 0o600);
		await fs.symlink(victim, path.join(dir, `${runUuid}.bin`));
		await expect(new CaptureStore(dir, projectId).observe(snapshot())).rejects.toThrow("Symlink");
		expect(await Bun.file(victim).text()).toBe("untouched");
	});

	it("keeps complete timeout output while reporting timeout failure", async () => {
		const store = new CaptureStore(dir, projectId);
		const run = snapshot({
			state: "timed_out",
			exitCode: 0,
			captureComplete: true,
			outputBytes: 2,
			endedAt: "2026-10-13T00:00:01.000Z",
		});
		await store.append({ run, offset: 0, nextOffset: 2, data: "QUI=" });
		const output = await store.read(runUuid);
		expect(output.data).toBe("QUI=");
		expect(runExitCode(output.run)).toBe(124);
	});
});

describe.skipIf(process.platform !== "linux")("guest protocol boundary", () => {
	it("parses split UTF-8 only after a complete bounded JSONL frame", () => {
		const values: unknown[] = [];
		const parser = new JsonLines(value => values.push(value), 64);
		const bytes = Buffer.from('{"text":"λ"}\n');
		const split = bytes.indexOf(0xce) + 1;
		parser.feed(bytes.subarray(0, split));
		expect(values).toEqual([]);
		parser.feed(bytes.subarray(split));
		expect(values).toEqual([{ text: "λ" }]);
		expect(() => parser.feed(Buffer.alloc(65, 65))).toThrow("too large");
	});

	it("rejects noncanonical base64, oversized chunks and mismatched output offsets", () => {
		expect(() => originalBytes("YR==")).toThrow("Noncanonical");
		expect(() => originalBytes(Buffer.alloc(65537).toString("base64"))).toThrow();
		expect(() =>
			validateOutput(
				{ run: snapshot({ outputBytes: 1 }), offset: 1, nextOffset: 2, data: "YQ==" },
				projectId,
				runUuid,
				0,
			),
		).toThrow("offset");
	});

	it("authenticates every request and rejects an otherwise valid stale-generation response", async () => {
		const requests: Record<string, unknown>[] = [];
		const socket = await unixServer(peer => {
			const parser = new JsonLines(value => {
				const request = value as Record<string, unknown>;
				requests.push(request);
				peer.write(
					`${JSON.stringify({ v: 1, id: request.id, project: projectId, generation: requests.length === 1 ? generation : crypto.randomUUID(), ok: true, result: { ready: true } })}\n`,
				);
			});
			peer.on("data", bytes => {
				if (typeof bytes === "string") throw new Error("Expected test peer bytes");
				parser.feed(bytes);
			});
		});
		const guest = new GuestTransport(socket, projectId, generation, token);
		try {
			expect(await guest.request("ping")).toEqual({ ready: true });
			await expect(guest.request("list")).rejects.toThrow("identity mismatch");
			expect(
				requests.map(request => [request.project, request.generation, authenticatedToken(request.token, token)]),
			).toEqual([
				[projectId, generation, true],
				[projectId, generation, true],
			]);
			expect(authenticatedToken(`${token}00`, token)).toBe(false);
		} finally {
			guest.close();
		}
	});

	it("does not replay a start when the reply channel disconnects", async () => {
		let starts = 0;
		const socket = await unixServer(peer => {
			const parser = new JsonLines(() => {
				starts++;
				peer.destroy();
			});
			peer.on("data", bytes => {
				if (typeof bytes === "string") throw new Error("Expected test peer bytes");
				parser.feed(bytes);
			});
		});
		const guest = new GuestTransport(socket, projectId, generation, token);
		try {
			await expect(guest.request("start", { actor: "human" })).rejects.toThrow();
			expect(starts).toBe(1);
		} finally {
			guest.close();
		}
	});

	it("rejects model command execution and out-of-work cwd before transport", () => {
		expect(() => validateRunRequest({ actor: "agent", kind: "command", argv: ["sh"], timeoutMs: 1000 })).toThrow(
			"forbidden",
		);
		expect(() =>
			validateRunRequest({ actor: "human", kind: "command", argv: ["true"], cwd: "/work/../root", timeoutMs: 1000 }),
		).toThrow("/work");
	});
});

describe.skipIf(process.platform !== "linux")("honest VM lifecycle", () => {
	it("requires QMP to report KVM enabled, even when it is present", async () => {
		let enabled = false;
		const socket = await unixServer(peer => {
			peer.write(`${JSON.stringify({ QMP: { version: {}, capabilities: [] } })}\n`);
			const parser = new JsonLines(value => {
				const message = value as Record<string, unknown>;
				peer.write(
					`${JSON.stringify({ id: message.id, return: message.execute === "query-kvm" ? { present: true, enabled } : {} })}\n`,
				);
			});
			peer.on("data", bytes => {
				if (typeof bytes === "string") throw new Error("Expected test peer bytes");
				parser.feed(bytes);
			});
		});
		const qmp = new Qmp(socket);
		try {
			await qmp.initialize();
			await expect(qmp.assertKvm()).rejects.toThrow("active KVM");
			enabled = true;
			await qmp.assertKvm();
		} finally {
			qmp.close();
		}
	});

	it.skipIf(process.platform !== "linux")("observes a real signal exit without reporting a live VM", async () => {
		const child = Bun.spawn(["/usr/bin/sleep", "60"], {
			env: {},
			stdin: "ignore",
			stdout: "ignore",
			stderr: "ignore",
		});
		try {
			await terminateVm(child, 1000, 1000);
			expect(await child.exited).toBe(143);
			expect(child.exitCode).toBeNull();
			expect(child.signalCode).toBe("SIGTERM");
			await terminateVm(child, 1000, 1000);
		} finally {
			if (child.exitCode === null && child.signalCode === null) {
				child.kill("SIGKILL");
				await child.exited;
			}
		}
	});

	it("escalates bounded termination and refuses to confirm an unobserved exit", async () => {
		const done = Promise.withResolvers<number>();
		const signals: string[] = [];
		const child: TerminableProcess & { signalCode: string | null } = {
			exitCode: null,
			signalCode: null,
			exited: done.promise,
			kill(signal) {
				signals.push(signal);
				if (signal === "SIGKILL") {
					this.signalCode = "SIGKILL";
					done.resolve(137);
				}
			},
		};
		await terminateVm(child, 1, 1);
		expect(signals).toEqual(["SIGTERM", "SIGKILL"]);
		expect(child.signalCode).toBe("SIGKILL");
		const stuck: TerminableProcess = {
			exitCode: null,
			signalCode: null,
			exited: Promise.withResolvers<number>().promise,
			kill() {},
		};
		await expect(terminateVm(stuck, 1, 1)).rejects.toThrow("could not be confirmed");
	});

	it("reads stopped original evidence without launching a broker or fabricating a live run", async () => {
		await projectFixture();
		const store = new CaptureStore(path.join(dir, "captures"), projectId);
		await store.append({ run: snapshot({ outputBytes: 2 }), offset: 0, nextOffset: 2, data: "QUI=" });
		const client = await connectWorkspace(dir);
		expect((await client.status()).state).toBe("stopped");
		expect((await client.readRun(runUuid)).run.state).toBe("unknown");
		expect((await client.readRun(runUuid)).data).toBe("QUI=");
		await expect(
			client.startRun({ actor: "human", kind: "command", argv: ["true"], timeoutMs: 1000 }),
		).rejects.toThrow("stopped");
		await expect(fs.lstat(path.join(dir, "broker.sock"))).rejects.toThrow();
	});

	it.skipIf(process.platform !== "linux")("waits for broker exit after its stop reply closes", async () => {
		const project = await projectFixture();
		const ready = Promise.withResolvers<void>();
		const replied = Promise.withResolvers<void>();
		// This real IPC child deliberately remains alive after acknowledging stop.
		const child = Bun.spawn(
			[
				process.execPath,
				"--no-env-file",
				"--eval",
				`
				import * as net from "node:net";
				import { chmod } from "node:fs/promises";
				const project = ${JSON.stringify(project)};
				const socketPath = ${JSON.stringify(path.join(dir, "broker.sock"))};
				const server = net.createServer(socket => {
					let input = "";
					socket.on("error", () => socket.destroy());
					socket.on("data", bytes => {
						input += bytes.toString();
						if (!input.includes("\\n")) return;
						const request = JSON.parse(input);
						const stopping = request.op === "stop";
						if (stopping)
							socket.once("close", () => console.log(JSON.stringify({ event: "replied" })));
						socket.end(JSON.stringify({
							v: 1, id: request.id, project: project.id, ok: true,
							result: {
								project, generation: ${JSON.stringify(generation)},
								state: stopping ? "stopped" : "running",
								accelerator: stopping ? null : "kvm", runs: []
							}
						}) + "\\n");
					});
				});
				server.listen(socketPath, async () => {
					await chmod(socketPath, 0o600);
					console.log(JSON.stringify({ event: "ready" }));
				});
				process.stdin.once("end", () => { server.close(); process.exit(0); });
				process.stdin.resume();
				`,
			],
			{ cwd: dir, env: cleanEnvironment(dir), stdin: "pipe", stdout: "pipe", stderr: "inherit" },
		);
		const output = (async () => {
			const parser = new JsonLines(value => {
				const event = object(value).event;
				if (event === "ready") ready.resolve();
				if (event === "replied") replied.resolve();
			});
			for await (const bytes of child.stdout) parser.feed(bytes);
		})();
		void ready.promise.catch(() => {});
		void replied.promise.catch(() => {});
		void child.exited.then(() => {
			ready.reject(new Error("Broker child exited before listening"));
			replied.reject(new Error("Broker child exited before flushing stop"));
		});
		void output.catch(error => {
			ready.reject(error);
			replied.reject(error);
		});
		try {
			await ready.promise;
			const broker = await processIdentity(child.pid);
			if (!broker) throw new Error("Missing owned broker identity");
			await durableJson(path.join(dir, "state.json"), {
				schema: 1,
				generation,
				state: "running",
				accelerator: "kvm",
				broker,
				vm: null,
			});
			const client = await connectWorkspace(dir);
			let settled = false;
			const stopped = client.stop().finally(() => {
				settled = true;
			});
			void stopped.catch(() => {});
			// The client has consumed and closed the reply, but the daemon has not exited.
			await replied.promise;
			expect(settled).toBe(false);
			expect(await identityAlive(broker)).toBe(true);
			child.stdin.end();
			expect((await stopped).state).toBe("stopped");
			expect(await child.exited).toBe(0);
			expect(await identityAlive(broker)).toBe(false);
		} finally {
			child.stdin.end();
			if (!processExited(child)) child.kill("SIGKILL");
			await child.exited;
			await output;
		}
	});

	it.skipIf(process.platform !== "linux")(
		"marks an unreachable live recorded process unknown and rejects PID reuse",
		async () => {
			await projectFixture();
			const identity = await processIdentity(process.pid);
			if (!identity) throw new Error("Missing test process identity");
			const state: BrokerState = {
				schema: 1,
				generation,
				state: "running",
				accelerator: "kvm",
				broker: identity,
				vm: null,
			};
			await durableJson(path.join(dir, "state.json"), state);
			expect((await offlineStatus(dir)).state).toBe("unknown");
			expect(await identityAlive({ ...identity, start: `${identity.start}0` })).toBe(false);
			await expect((await connectWorkspace(dir)).stop()).rejects.toThrow("unconfirmed");
		},
	);

	it("refuses writable project permissions and symlinked manifests", async () => {
		await projectFixture();
		await fs.chmod(dir, 0o755);
		await expect(loadProject(dir)).rejects.toThrow("0700");
		await fs.chmod(dir, 0o700);
		await fs.rename(path.join(dir, "project.json"), path.join(dir, "original.json"));
		await fs.symlink(path.join(dir, "original.json"), path.join(dir, "project.json"));
		await expect(readJson(path.join(dir, "project.json"))).rejects.toThrow("Symlink");
	});

	it("rejects a writable base and a read-only base with mismatched content pins", async () => {
		const file = path.join(dir, "base.qcow2");
		await Bun.write(file, "owned synthetic disk bytes");
		await fs.chmod(file, 0o600);
		const expected = new Bun.CryptoHasher("sha256").update("owned synthetic disk bytes").digest("hex");
		await expect(verifyPinnedFile(file, expected, true)).rejects.toThrow("write permission");
		await fs.chmod(file, 0o400);
		await verifyPinnedFile(file, expected, true);
		await expect(verifyPinnedFile(file, "f".repeat(64), true)).rejects.toThrow("pin mismatch");
	});

	it("rejects external qcow2 data and an overlay redirected away from the pinned base", () => {
		expect(() =>
			validateDiskChain([{ format: "qcow2", "format-specific": { data: { "data-file": "/vm/boot.json" } } }], false),
		).toThrow("External");
		expect(() =>
			validateDiskChain(
				[
					{ format: "qcow2", "backing-filename": "/other.qcow2", "backing-filename-format": "qcow2" },
					{ format: "qcow2" },
				],
				true,
			),
		).toThrow("backing image");
	});
});

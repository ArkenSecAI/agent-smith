import { afterEach, beforeEach, describe, expect, it, spyOn } from "bun:test";
import * as fs from "node:fs/promises";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import { Database } from "bun:sqlite";
import type { PredictedWord } from "@oh-my-pi/pi-natives";
import { VERSION } from "@oh-my-pi/pi-utils/dirs";
import type { Subprocess } from "bun";
import {
	TEXT_PREDICT_AGENT_DIR_ENV,
	TEXT_PREDICT_GENERATION,
	TEXT_PREDICT_SOCKET_ENV,
	TEXT_PREDICT_WORKER_ARG,
	type TextPredictRequest,
	type TextPredictResponse,
	textPredictDaemon,
} from "../src/predict/protocol";
import { connectJsonlSocket, LineParser, writeJsonLine } from "../src/tiny/jsonl-socket";
import { createHash } from "node:crypto";

interface ClientResult {
	ok: boolean;
	suggestion?: PredictedWord | null;
}

const TIMEOUT_MS = 15_000;

async function request(endpoint: string, message: TextPredictRequest): Promise<TextPredictResponse> {
	const socket = await connectJsonlSocket(endpoint, 1_000);
	const { promise, resolve, reject } = Promise.withResolvers<TextPredictResponse>();
	const timer = setTimeout(() => reject(new Error("Predictor request timed out")), TIMEOUT_MS);
	const parser = new LineParser(line => {
		try {
			resolve(JSON.parse(line) as TextPredictResponse);
		} catch (error) {
			reject(error);
		}
	});
	socket.on("data", (chunk: string) => parser.push(chunk));
	socket.once("error", reject);
	socket.once("close", () => reject(new Error("Predictor connection closed before reply")));
	try {
		writeJsonLine(socket, message);
		return await promise;
	} finally {
		clearTimeout(timer);
		socket.destroy();
	}
}

describe("Agent Smith predictor privacy", () => {
	let root: string;
	let home: string;
	let agentDir: string;
	let endpoint: string;
	let env: Record<string, string>;
	let children: Subprocess[];
	let servers: net.Server[];
	let sockets: Set<net.Socket>;
	let broker: Subprocess<"ignore", "ignore", "pipe"> | undefined;
	let brokerStderr: Promise<string> | undefined;

	beforeEach(async () => {
		// Keep the socket path short enough for macOS's Unix socket limit too.
		root = await fs.mkdtemp(path.join(os.tmpdir(), "sp-"));
		home = path.join(root, "home");
		agentDir = path.join(home, ".agent-smith", "agent");
		await fs.mkdir(agentDir, { recursive: true });
		endpoint = textPredictDaemon(root, agentDir).endpoint;
		children = [];
		servers = [];
		sockets = new Set();
		broker = undefined;
		brokerStderr = undefined;
		// Whitelist the environment so neither the fixture nor CLI can reach real account homes.
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
			AGENT_SMITH_CODING_AGENT_DIR: agentDir,
			[TEXT_PREDICT_AGENT_DIR_ENV]: agentDir,
			[TEXT_PREDICT_SOCKET_ENV]: endpoint,
			SMITH_PREDICT_READ_AUDIT: path.join(root, "foreign-read-audit.json"),
			NO_COLOR: "1",
		};
		await Bun.write(
			path.join(home, ".claude", "history.jsonl"),
			`${JSON.stringify({ display: "please inspect zqclaudebloom" })}\n`.repeat(120),
		);
		await Bun.write(
			path.join(home, ".codex", "history.jsonl"),
			`${JSON.stringify({ text: "please inspect zxcodexbloom" })}\n`.repeat(120),
		);
	});

	afterEach(async () => {
		for (const child of children) {
			if (child.exitCode === null) child.kill("SIGKILL");
			await child.exited;
		}
		if (broker) {
			try {
				if (broker.exitCode !== null) throw new Error("Owned global broker exited before teardown");
				broker.send("shutdown");
			} finally {
				// The host exits only after stopping its predictor and joining the
				// real broker's log/metadata persistence, even if the client was killed.
				expect(await broker.exited, await brokerStderr).toBe(0);
			}
		}
		for (const socket of sockets) socket.destroy();
		for (const server of servers) {
			const closed = Promise.withResolvers<void>();
			server.close(() => closed.resolve());
			await closed.promise;
		}
		await fs.rm(root, { recursive: true, force: true });
	});

	async function fixture<T>(mode: string): Promise<T> {
		const child = Bun.spawn(
			[
				process.execPath,
				"--no-env-file",
				path.join(import.meta.dir, "fixtures/text-predict-privacy.ts"),
				mode,
				root,
			],
			{ cwd: root, env, stdin: "ignore", stdout: "pipe", stderr: "pipe" },
		);
		children.push(child);
		const timer = setTimeout(() => child.kill("SIGKILL"), TIMEOUT_MS);
		try {
			const [stdout, stderr, code] = await Promise.all([
				new Response(child.stdout).text(),
				new Response(child.stderr).text(),
				child.exited,
			]);
			expect(code, stderr).toBe(0);
			return JSON.parse(stdout) as T;
		} finally {
			clearTimeout(timer);
		}
	}

	async function startGlobalBroker(): Promise<void> {
		const listening = Promise.withResolvers<void>();
		const host = Bun.spawn(
			[
				process.execPath,
				"--no-env-file",
				path.join(import.meta.dir, "fixtures/text-predict-privacy.ts"),
				"broker-host",
			],
			{
				cwd: root,
				env,
				stdin: "ignore",
				stdout: "ignore",
				stderr: "pipe",
				ipc(message) {
					if (message === "ready") listening.resolve();
					else listening.reject(new Error("Unexpected broker host message"));
				},
			},
		);
		broker = host;
		brokerStderr = new Response(host.stderr).text();
		// Real subprocess startup needs a wall-clock failure bound; success is
		// signalled by IPC, not a sleep. No prediction client exists before ready.
		const timer = setTimeout(() => host.kill("SIGKILL"), TIMEOUT_MS);
		try {
			await Promise.race([
				listening.promise,
				host.exited.then(async code => {
					throw new Error(`Owned global broker exited before readiness (${code}): ${await brokerStderr}`);
				}),
			]);
		} finally {
			clearTimeout(timer);
		}
	}

	async function startDaemon(): Promise<Subprocess> {
		const child = Bun.spawn(
			[
				process.execPath,
				"--no-env-file",
				"--preload",
				path.join(import.meta.dir, "fixtures/text-predict-read-audit.ts"),
				path.join(import.meta.dir, "../src/cli.ts"),
				TEXT_PREDICT_WORKER_ARG,
			],
			{ cwd: root, env, stdin: "ignore", stdout: "ignore", stderr: "pipe" },
		);
		children.push(child);
		const stderr = new Response(child.stderr).text();
		const deadline = Date.now() + TIMEOUT_MS;
		while (Date.now() < deadline && child.exitCode === null) {
			try {
				const response = await request(endpoint, { id: 1, op: "ping" });
				if (response.ok && response.op === "ping" && response.pid === child.pid) return child;
			} catch {
				// Startup has not bound the endpoint yet.
			}
			await Bun.sleep(25);
		}
		child.kill("SIGKILL");
		await child.exited;
		throw new Error(`Predictor daemon did not start: ${await stderr}`);
	}

	async function stopDaemon(child: Subprocess): Promise<void> {
		const response = await request(endpoint, { id: 1, op: "shutdown" });
		expect(response.ok).toBe(true);
		const timer = setTimeout(() => child.kill("SIGKILL"), TIMEOUT_MS);
		try {
			expect(await child.exited).toBe(0);
			expect(await Bun.file(env.SMITH_PREDICT_READ_AUDIT!).json()).toEqual([]);
		} finally {
			clearTimeout(timer);
		}
	}

	function addOwnHistory(prompt: string, count = 120): void {
		const db = new Database(path.join(agentDir, "history.db"));
		try {
			db.run("CREATE TABLE IF NOT EXISTS history (id INTEGER PRIMARY KEY, prompt TEXT NOT NULL)");
			const insert = db.query("INSERT INTO history (prompt) VALUES (?)");
			db.transaction(() => {
				for (let i = 0; i < count; i++) insert.run(prompt);
			})();
		} finally {
			db.close();
		}
	}

	async function complete(prefix: string, before = "please inspect "): Promise<PredictedWord | null> {
		const response = await request(endpoint, { id: 1, op: "complete", method: "ngram", before, prefix });
		if (!response.ok) throw new Error(response.error);
		if (response.op !== "complete") throw new Error("Unexpected predictor response");
		return response.suggestion;
	}

	async function sync(): Promise<number> {
		const response = await request(endpoint, { id: 1, op: "sync" });
		if (!response.ok) throw new Error(response.error);
		if (response.op !== "sync") throw new Error("Unexpected predictor response");
		return response.ingested;
	}

	async function expectNoForeignCompletions(): Promise<void> {
		expect(await complete("zqclaude")).toBeNull();
		expect(await complete("zxcodex")).toBeNull();
	}

	async function legacyListener(address: string): Promise<string[]> {
		const operations: string[] = [];
		const server = net.createServer(socket => {
			sockets.add(socket);
			socket.setEncoding("utf8");
			socket.on("error", () => {});
			socket.once("close", () => sockets.delete(socket));
			const parser = new LineParser(line => {
				const message = JSON.parse(line) as TextPredictRequest;
				operations.push(message.op);
				// The pre-cutover wire contract advertises the same app version and no generation.
				if (message.op === "ping") {
					writeJsonLine(socket, { id: message.id, ok: true, op: "ping", version: VERSION, pid: 1, engines: [] });
				} else if (message.op === "complete") {
					writeJsonLine(socket, {
						id: message.id,
						ok: true,
						op: "complete",
						suggestion: { suffix: "foreign", confidence: 1 },
					});
				} else if (message.op === "shutdown") {
					writeJsonLine(socket, { id: message.id, ok: true, op: "shutdown" });
				}
			});
			socket.on("data", (chunk: string) => parser.push(chunk));
		});
		servers.push(server);
		const ready = Promise.withResolvers<void>();
		server.once("error", ready.reject);
		server.listen(address, () => ready.resolve());
		await ready.promise;
		return operations;
	}

	it("keeps profile namespaces separate when the legacy non-cryptographic hash collides", () => {
		const legacyHash = spyOn(Bun.hash, "wyhash").mockReturnValue(0n);
		try {
			const first = textPredictDaemon(root, agentDir);
			const second = textPredictDaemon(root, path.join(home, "other-profile"));
			expect(first.name.length).toBeLessThanOrEqual(48);
			expect(first.name).toMatch(/^text-predict\.[A-Za-z0-9_-]{22}$/);
			const key = first.name.slice("text-predict.".length);
			const bytes = Buffer.from(key, "base64url");
			expect(bytes.byteLength).toBe(16);
			expect(bytes.toString("base64url")).toBe(key);
			expect(bytes).toEqual(
				createHash("sha256")
					.update(`${TEXT_PREDICT_GENERATION}\0${path.resolve(agentDir)}`)
					.digest()
					.subarray(0, 16),
			);
			if (process.platform === "win32") expect(first.endpoint.endsWith(`-${key}`)).toBe(true);
			else expect(path.basename(first.endpoint)).toBe(`${key}.sock`);
			expect(first.name).not.toBe(second.name);
			expect(first.endpoint).not.toBe(second.endpoint);
			expect(textPredictDaemon(root, path.join(agentDir, "..", "agent"))).toEqual(first);
		} finally {
			legacyHash.mockRestore();
		}
	});

	it.skipIf(process.platform === "win32")("retains all identity bits within a 103-byte Unix endpoint", () => {
		const runtime = "/tmp/agent-smith-runtime/".padEnd(75, "r");
		const { name, endpoint: longEndpoint } = textPredictDaemon(runtime, agentDir);
		expect(Buffer.byteLength(runtime)).toBe(75);
		expect(Buffer.byteLength(longEndpoint)).toBe(103);
		expect(path.dirname(longEndpoint)).toBe(runtime);
		expect(Buffer.from(path.basename(longEndpoint, ".sock"), "base64url")).toHaveLength(16);
		expect(path.basename(longEndpoint, ".sock")).toBe(name.slice("text-predict.".length));
	});

	it("fresh engines ignore foreign prompts, learn only new own rows, and persist on shutdown", async () => {
		let child = await startDaemon();
		await expectNoForeignCompletions();
		expect(await sync()).toBe(0);
		addOwnHistory("please inspect zqsmithbloom", 1_005);
		expect(await sync()).toBe(1_005);
		expect(await complete("zqsmith")).toMatchObject({ suffix: "bloom" });
		expect(await sync()).toBe(0);
		await stopDaemon(child);

		// Change an already-consumed row: replaying it would leak this new vocabulary
		// into completions and expose a lost incremental cursor on restart.
		const db = new Database(path.join(agentDir, "history.db"));
		try {
			db.run("UPDATE history SET prompt = ?", ["please inspect zqreplaybloom"]);
		} finally {
			db.close();
		}
		addOwnHistory("please inspect zqnewbranch");
		child = await startDaemon();
		expect(await complete("zqnew")).toMatchObject({ suffix: "branch" });
		expect(await complete("zqreplay")).toBeNull();
		expect(await sync()).toBe(0);
		await stopDaemon(child);
		const stateDir = path.join(agentDir, "predict", TEXT_PREDICT_GENERATION, "ngram");
		expect(await Bun.file(path.join(stateDir, "cursor.json")).json()).toEqual({ historyId: 1_125 });

		// Removing only the synthetic input DB proves the predictions survive from persisted state.
		await fs.rm(path.join(agentDir, "history.db"));
		child = await startDaemon();
		expect(await complete("zqsmith")).toMatchObject({ suffix: "bloom" });
		expect(await complete("zqnew")).toMatchObject({ suffix: "branch" });
		await expectNoForeignCompletions();
		await stopDaemon(child);
	}, 60_000);

	it("ignores a learnable pre-cutover snapshot and its cursor without modifying either", async () => {
		const seeded = await fixture<{ claude: PredictedWord; codex: PredictedWord }>("seed-legacy");
		expect(seeded.claude.suffix).toBe("bloom");
		expect(seeded.codex.suffix).toBe("bloom");
		const oldState = path.join(agentDir, "predict", "ngram");
		const snapshot = await fs.readFile(path.join(oldState, "ngram.snapshot"));
		const cursor = await fs.readFile(path.join(oldState, "cursor.json"));
		addOwnHistory("please inspect zqsmithbloom");
		const child = await startDaemon();
		await expectNoForeignCompletions();
		expect(await complete("zqsmith")).toMatchObject({ suffix: "bloom" });
		await stopDaemon(child);
		expect(await fs.readFile(path.join(oldState, "ngram.snapshot"))).toEqual(snapshot);
		expect(await fs.readFile(path.join(oldState, "cursor.json"))).toEqual(cursor);
	}, 60_000);

	it("rebuilds corrupt current state from own history and resets its stale cursor", async () => {
		const stateDir = path.join(agentDir, "predict", TEXT_PREDICT_GENERATION, "ngram");
		await Bun.write(path.join(stateDir, "ngram.snapshot"), "synthetic corrupt snapshot");
		await Bun.write(path.join(stateDir, "cursor.json"), JSON.stringify({ historyId: 100_000 }));
		addOwnHistory("please inspect zqsmithbloom");
		let child = await startDaemon();
		await expectNoForeignCompletions();
		expect(await complete("zqsmith")).toMatchObject({ suffix: "bloom" });
		await stopDaemon(child);
		expect(await Bun.file(path.join(stateDir, "cursor.json")).json()).toEqual({ historyId: 120 });
		await fs.rm(path.join(agentDir, "history.db"));
		child = await startDaemon();
		expect(await complete("zqsmith")).toMatchObject({ suffix: "bloom" });
		await expectNoForeignCompletions();
		await stopDaemon(child);
	}, 60_000);

	it("recovers an unreadable history cursor without losing new own prompts or learning foreign ones", async () => {
		addOwnHistory("please inspect zqsmithbloom");
		let child = await startDaemon();
		expect(await complete("zqsmith")).toMatchObject({ suffix: "bloom" });
		await stopDaemon(child);
		const stateDir = path.join(agentDir, "predict", TEXT_PREDICT_GENERATION, "ngram");
		await Bun.write(path.join(stateDir, "cursor.json"), "{");
		addOwnHistory("please inspect zqnewbranch");
		child = await startDaemon();
		expect(await complete("zqnew")).toMatchObject({ suffix: "branch" });
		expect(await complete("zqsmith")).toMatchObject({ suffix: "bloom" });
		await expectNoForeignCompletions();
		expect(await sync()).toBe(0);
		await stopDaemon(child);
		expect(await Bun.file(path.join(stateDir, "cursor.json")).json()).toEqual({ historyId: 240 });
	}, 60_000);

	it("the real global broker accepts the profile identity and serves only its own history", async () => {
		addOwnHistory("please inspect zqsmithbloom");
		await startGlobalBroker();
		const result = await fixture<{ own: PredictedWord | null; foreign: PredictedWord | null }>("broker-client");
		expect(result.own?.suffix).toBe("bloom");
		expect(result.foreign).toBeNull();
	}, 60_000);

	it("the public client reaches the new daemon while a same-version legacy endpoint remains live", async () => {
		const oldKey = Bun.hash.wyhash(path.resolve(agentDir)).toString(16).padStart(16, "0").slice(0, 12);
		const oldEndpoint =
			process.platform === "win32"
				? `\\\\.\\pipe\\agent-smith-text-predict-${Bun.hash.wyhash(root).toString(16)}-${oldKey}`
				: path.join(root, `text-predict-${oldKey}.sock`);
		const operations = await legacyListener(oldEndpoint);
		addOwnHistory("please inspect zqsmithbloom");
		const child = await startDaemon();
		const result = await fixture<ClientResult>("client");
		expect(result.ok).toBe(true);
		expect(result.suggestion?.suffix).toBe("bloom");
		expect(operations).toEqual([]);
		await stopDaemon(child);
	}, 60_000);

	it("rejects the pre-cutover handshake even at the new endpoint before sending completion text", async () => {
		const operations = await legacyListener(endpoint);
		const result = await fixture<ClientResult>("client");
		expect(result.ok).toBe(false);
		expect(operations).toContain("ping");
		expect(operations).toContain("shutdown");
		expect(operations).not.toContain("complete");
	}, 60_000);
});

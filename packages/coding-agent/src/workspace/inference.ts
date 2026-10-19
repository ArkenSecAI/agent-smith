import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { Effort, type Model, type SimpleStreamOptions } from "@oh-my-pi/pi-ai";
import { buildModel } from "@oh-my-pi/pi-catalog/build";
import { untilAborted } from "@oh-my-pi/pi-utils";
import { abortableSource } from "@oh-my-pi/pi-utils/abortable";
import type { WorkspaceRuntime } from "./contracts";
import { Process } from "@oh-my-pi/pi-natives";
import { startExternalInference } from "./external-inference";
import { regularFile, validateInferenceUrl } from "./project";

type InferenceConfig = NonNullable<WorkspaceRuntime["inference"]>;

const HELP_TIMEOUT_MS = 15_000;
const READY_TIMEOUT_MS = 180_000;
const STOP_TIMEOUT_MS = 5_000;
const LOG_BYTES = 256 * 1024;
const ENGINE_PATH = "/inference/llama-server";
const MODEL_PATH = "/inference/model.gguf";

export interface WorkspaceInference {
	model: Model;
	/** Ephemeral managed credential, or the explicit keyless-provider sentinel. */
	apiKey: string;
	signal: AbortSignal;
	thinkingLevel: Effort | "off";
	streamOptions?: SimpleStreamOptions;
	stop(): Promise<void>;
}

export function validateInferenceConfig(config: InferenceConfig): void {
	for (const filename of [config.binary, config.model]) {
		if (!path.isAbsolute(filename) || filename.includes("\0")) {
			throw new Error("Inference binary and model must be absolute local paths");
		}
	}
	for (const pin of [config.sha256, config.modelSha256]) {
		if (!/^[a-f0-9]{64}$/i.test(pin)) throw new Error("Inference requires SHA-256 binary and model pins");
	}
	if (!/^[A-Za-z0-9][A-Za-z0-9._/-]{0,159}$/.test(config.modelId)) {
		throw new Error("Invalid local model identifier");
	}
	if (!Number.isInteger(config.contextTokens) || config.contextTokens < 4096 || config.contextTokens > 32768) {
		throw new Error("Inference context must be between 4096 and 32768 tokens");
	}
	if (!Number.isInteger(config.threads) || config.threads < 1 || config.threads > 32) {
		throw new Error("CPU inference requires between 1 and 32 threads");
	}
}

/** Reconcile against the pinned executable itself, never silently substitute a runtime. */
export function cpuInferenceArgs(config: InferenceConfig, socketPath: string, help: string): string[] {
	validateInferenceConfig(config);
	validateInferenceSocket(socketPath);
	const flags = new Set(help.split(/[\s,=]+/));
	const required = [
		"--model",
		"--host",
		"--ctx-size",
		"--threads",
		"--parallel",
		"--alias",
		"--jinja",
		"--no-webui",
		"--no-kv-offload",
		"--no-op-offload",
		"--flash-attn",
		"--cache-type-k",
		"--cache-type-v",
		"--api-key",
		"--offline",
		"--no-agent",
		"--device",
		"-ngl",
		"--reasoning",
		"--reasoning-format",
		"--reasoning-budget",
		"--top-k",
		"--top-p",
		"--min-p",
		"--presence-penalty",
		"--repeat-penalty",
		"--seed",
	];
	for (const flag of required) {
		if (!flags.has(flag))
			throw new Error(`Pinned llama.cpp does not advertise required flag ${flag}; reconcile its --help`);
	}
	const args = [
		"--model",
		config.model,
		"--alias",
		config.modelId,
		"--host",
		socketPath,
		"--ctx-size",
		String(config.contextTokens),
		"--threads",
		String(config.threads),
		"--parallel",
		"1",
		"-ngl",
		"0",
		"--device",
		"none",
		"--no-kv-offload",
		"--no-op-offload",
		// Quantized V requires Flash Attention; cache and operation offload stay disabled.
		"--flash-attn",
		"on",
		"--cache-type-k",
		"q8_0",
		"--cache-type-v",
		"q8_0",
		"--jinja",
		"--no-webui",
		"--offline",
		"--no-agent",
		// Qwen3.5 general-task thinking profile; the SDK supplies request temperature.
		"--reasoning",
		"on",
		"--reasoning-format",
		"deepseek",
		"--reasoning-budget",
		"512",
		"--top-k",
		"20",
		"--top-p",
		"0.95",
		"--min-p",
		"0",
		"--presence-penalty",
		"1.5",
		"--repeat-penalty",
		"1",
		"--seed",
		"0",
	];
	if (flags.has("--threads-batch")) args.push("--threads-batch", String(config.threads));
	for (const flag of [
		"--no-ui-mcp-proxy",
		"--no-models-autoload",
		"--no-mmproj",
		"--no-slots",
		"--no-context-shift",
	]) {
		if (flags.has(flag)) args.push(flag);
	}
	return args;
}

function validateInferenceSocket(socketPath: string): void {
	if (
		!path.isAbsolute(socketPath) ||
		path.normalize(socketPath) !== socketPath ||
		socketPath.includes("\0") ||
		!socketPath.endsWith(".sock") ||
		Buffer.byteLength(socketPath) > 100
	) {
		throw new Error("Inference requires a short absolute Unix socket path");
	}
}

async function verifyPin(filename: string, expected: string, signal?: AbortSignal): Promise<fs.FileHandle> {
	signal?.throwIfAborted();
	await regularFile(filename);
	const handle = await fs.open(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
	try {
		const before = await handle.stat();
		if (
			!before.isFile() ||
			before.nlink !== 1 ||
			(before.mode & 0o222) !== 0 ||
			(before.uid !== 0 && before.uid !== process.getuid?.())
		) {
			throw new Error(`Pinned inference input must be an owned or root-owned read-only regular file: ${filename}`);
		}
		const hash = new Bun.CryptoHasher("sha256");
		for await (const bytes of abortableSource(Bun.file(handle.fd).stream(), signal)) hash.update(bytes);
		const after = await handle.stat();
		if (
			after.size !== before.size ||
			after.mtimeMs !== before.mtimeMs ||
			after.ctimeMs !== before.ctimeMs ||
			after.mode !== before.mode ||
			after.uid !== before.uid ||
			after.nlink !== before.nlink
		) {
			throw new Error(`Pinned inference input changed during verification: ${filename}`);
		}
		if (hash.digest("hex") !== expected.toLowerCase()) throw new Error(`Inference SHA-256 mismatch: ${filename}`);
		return handle;
	} catch (error) {
		await handle.close();
		throw error;
	}
}

async function capture(stream: ReadableStream<Uint8Array>): Promise<string> {
	const chunks: Uint8Array[] = [];
	let retained = 0;
	// Drain even after the cap so diagnostic output cannot deadlock the child.
	for await (const bytes of abortableSource(stream)) {
		if (retained < LOG_BYTES) {
			const kept = bytes.slice(0, LOG_BYTES - retained);
			chunks.push(kept);
			retained += kept.length;
		}
	}
	return Buffer.concat(chunks).toString("utf8");
}

async function stopChild(child: Bun.Subprocess): Promise<void> {
	if (child.exitCode !== null || child.signalCode !== null) return;
	child.kill("SIGTERM");
	try {
		await untilAborted(AbortSignal.timeout(STOP_TIMEOUT_MS), child.exited);
	} catch {
		child.kill("SIGKILL");
		try {
			await untilAborted(AbortSignal.timeout(STOP_TIMEOUT_MS), child.exited);
		} catch {
			throw new Error(`Could not observe llama.cpp process ${child.pid} terminate after SIGKILL`);
		}
	}
}

async function stopEngine(child: Bun.Subprocess, root: Process | null, executable: string): Promise<void> {
	const owned = root ? [root] : [];
	const deadline = Date.now() + STOP_TIMEOUT_MS;
	try {
		for (let index = 0; index < owned.length; index++) owned.push(...owned[index]!.children());
		if (child.exitCode === null && child.signalCode === null) {
			const engines = owned.filter(item => item.status() === "running" && item.args()[0] === executable);
			if (engines.length !== 1)
				throw new Error("Could not identify the owned inference engine for graceful shutdown");
			// Keep bubblewrap's namespace init alive to reap the engine normally.
			engines[0]!.killTree(15);
		}
		const code = await untilAborted(AbortSignal.timeout(Math.max(0, deadline - Date.now())), child.exited);
		if (code !== 0) throw new Error(`Inference sandbox did not exit cleanly (${code})`);
		// The root's exit notification can precede its descendants' observable exits.
		for (const item of owned) {
			if (item.status() === "exited") continue;
			const remaining = deadline - Date.now();
			if (remaining <= 0 || !(await item.waitForExit({ timeoutMs: remaining })))
				throw new Error(`Owned inference process ${item.pid} outlived the graceful shutdown deadline`);
		}
	} catch (cause) {
		const errors: unknown[] = [cause];
		for (let index = owned.length - 1; index >= 0; index--) {
			try {
				if (owned[index]!.status() !== "exited") owned[index]!.killTree(9);
			} catch (error) {
				errors.push(error);
			}
		}
		try {
			await stopChild(child);
		} catch (error) {
			errors.push(error);
		}
		await Promise.all(
			owned.map(async item => {
				try {
					if (!(await item.waitForExit({ timeoutMs: STOP_TIMEOUT_MS })))
						errors.push(new Error(`Could not observe owned inference process ${item.pid} exit`));
				} catch (error) {
					errors.push(error);
				}
			}),
		);
		throw new AggregateError(errors, "Inference did not shut down gracefully; forced cleanup was required");
	}
}

/** Only chat reaches the network-isolated engine's private Unix socket. */
export function createInferenceGateway(socketPath: string, apiKey: string, modelId: string, signal: AbortSignal) {
	validateInferenceSocket(socketPath);
	return Bun.serve({
		hostname: "127.0.0.1",
		port: 0,
		idleTimeout: 255,
		maxRequestBodySize: 1024 * 1024,
		async fetch(request) {
			const requested = new URL(request.url);
			if (request.method !== "POST" || requested.pathname !== "/v1/chat/completions" || requested.search) {
				return new Response("Only chat completions are available", { status: 404 });
			}
			if (request.headers.get("authorization") !== `Bearer ${apiKey}`) return new Response(null, { status: 401 });
			try {
				const body: unknown = await request.json();
				if (!body || typeof body !== "object" || !("model" in body) || body.model !== modelId) {
					return new Response("Unknown project model", { status: 400 });
				}
				return await fetch("http://127.0.0.1/v1/chat/completions", {
					method: "POST",
					body: JSON.stringify(body),
					headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` },
					unix: socketPath,
					redirect: "error",
					proxy: "",
					signal: AbortSignal.any([signal, request.signal]),
				});
			} catch (error) {
				return Response.json(
					{ error: { message: error instanceof Error ? error.message : "Local inference failed" } },
					{ status: 502 },
				);
			}
		},
	});
}

export async function startInference(
	runtime: WorkspaceRuntime,
	stateDir: string,
	signal?: AbortSignal,
): Promise<WorkspaceInference> {
	signal?.throwIfAborted();
	if (runtime.inference && runtime.externalInference)
		throw new Error("Select one inference source; managed and external cannot both be configured");
	if (runtime.externalInference) return startExternalInference(runtime.externalInference, signal);
	const config = runtime.inference;
	if (!config) throw new Error("Project has no pinned local inference runtime/model; external fallback is disabled");
	if (process.platform !== "linux" || process.arch !== "x64")
		throw new Error("Workspace inference is qualified only for Linux x86-64");
	validateInferenceConfig(config);
	const binary = await verifyPin(config.binary, config.sha256, signal);
	try {
		const model = await verifyPin(config.model, config.modelSha256, signal);
		try {
			return await startManagedInference(config, stateDir, binary.fd, model.fd, signal);
		} finally {
			await model.close();
		}
	} finally {
		await binary.close();
	}
}

async function startManagedInference(
	config: InferenceConfig,
	stateDir: string,
	binaryFd: number,
	modelFd: number,
	signal?: AbortSignal,
): Promise<WorkspaceInference> {
	await fs.mkdir(stateDir, { recursive: true, mode: 0o700 });
	const socketDir = await fs.mkdtemp(path.join(os.tmpdir(), "asm-inference-"));
	await fs.chmod(socketDir, 0o700);
	const socketPath = path.join(socketDir, "engine.sock");
	const apiKey = crypto.randomUUID() + crypto.randomUUID();
	// Deliberately do not inherit HOME, LLAMA_*, HF_*, proxies, accelerator or loader settings.
	const env = { HOME: socketDir, XDG_CACHE_HOME: socketDir, PATH: "/usr/bin:/bin", LANG: "C.UTF-8" };
	// Both capability probing and serving use only the verified open files, never their parents.
	// Descriptor binds retain the verified inodes without copying a multi-gigabyte model.
	const sandbox = [
		"/usr/bin/bwrap",
		"--unshare-all",
		"--die-with-parent",
		"--new-session",
		"--ro-bind",
		"/usr",
		"/usr",
		"--ro-bind",
		"/lib",
		"/lib",
		"--ro-bind",
		"/lib64",
		"/lib64",
		"--ro-bind",
		"/etc/ld.so.cache",
		"/etc/ld.so.cache",
		"--proc",
		"/proc",
		"--dev",
		"/dev",
		"--tmpfs",
		"/tmp",
		"--dir",
		"/inference",
		"--ro-bind-fd",
		"3",
		ENGINE_PATH,
		"--ro-bind-fd",
		"4",
		MODEL_PATH,
		"--bind",
		socketDir,
		socketDir,
		"--chdir",
		socketDir,
		"--",
		ENGINE_PATH,
		"--help",
	];
	let helpChild: Bun.Subprocess<"ignore", "pipe", "pipe"> | undefined;
	let child: Bun.Subprocess<"ignore", "pipe", "pipe">;
	try {
		signal?.throwIfAborted();
		helpChild = Bun.spawn(sandbox, {
			cwd: socketDir,
			env,
			stdio: ["ignore", "pipe", "pipe", binaryFd, modelFd],
		});
		const helpOutput = Promise.all([capture(helpChild.stdout), capture(helpChild.stderr)]);
		void helpOutput.catch(() => {}); // The bounded await below reports capture failure.
		let help: string;
		try {
			const bounded = AbortSignal.any([AbortSignal.timeout(HELP_TIMEOUT_MS), ...(signal ? [signal] : [])]);
			const code = await untilAborted(bounded, helpChild.exited);
			help = (await untilAborted(bounded, helpOutput)).join("\n");
			await Bun.write(path.join(stateDir, "llama-help.txt"), help);
			if (code !== 0) throw new Error(`Pinned llama.cpp --help failed with exit ${code}: ${help.slice(-4000)}`);
		} finally {
			await stopChild(helpChild);
		}
		const args = cpuInferenceArgs({ ...config, model: MODEL_PATH }, socketPath, help);
		sandbox.pop();
		sandbox.push(...args);
		signal?.throwIfAborted();
		child = Bun.spawn(sandbox, {
			cwd: socketDir,
			env: { ...env, LLAMA_API_KEY: apiKey },
			stdio: ["ignore", "pipe", "pipe", binaryFd, modelFd],
		});
	} catch (error) {
		if (!helpChild || helpChild.exitCode !== null || helpChild.signalCode !== null) {
			await fs.rm(socketDir, { recursive: true });
		}
		throw error;
	}
	let processTree: Process | null = null;
	const output = Promise.all([capture(child.stdout), capture(child.stderr)]);
	void output.catch(() => {}); // stop() observes this result even when a pipe fails early.
	const lifetime = new AbortController();
	const onAbort = () => lifetime.abort(signal?.reason);
	signal?.addEventListener("abort", onAbort, { once: true });
	let gateway: Bun.Server<undefined> | undefined;
	let stopping: Promise<void> | undefined;
	const stop = (): Promise<void> =>
		(stopping ??= (async () => {
			lifetime.abort();
			signal?.removeEventListener("abort", onAbort);
			const outcomes = await Promise.allSettled([
				gateway ? untilAborted(AbortSignal.timeout(STOP_TIMEOUT_MS), gateway.stop(true)) : Promise.resolve(),
				stopEngine(child, processTree, ENGINE_PATH),
			]);
			const errors = outcomes
				.filter((outcome): outcome is PromiseRejectedResult => outcome.status === "rejected")
				.map(outcome => outcome.reason);
			try {
				const logs = await untilAborted(AbortSignal.timeout(STOP_TIMEOUT_MS), output);
				await Bun.write(path.join(stateDir, "llama-output.txt"), logs.join("\n").replaceAll(apiKey, "[redacted]"));
			} catch (error) {
				errors.push(error);
			}
			if (errors.length) throw new AggregateError(errors, "Inference shutdown could not be fully observed");
			await fs.rm(socketDir, { recursive: true });
		})());
	try {
		processTree = Process.fromPid(child.pid);
		if (!processTree) throw new Error("Could not retain inference sandbox process identity");
		const deadline = Date.now() + READY_TIMEOUT_MS;
		const upstream = new URL("http://127.0.0.1/v1");
		let lastReadiness = "No response";
		while (true) {
			signal?.throwIfAborted();
			if (child.exitCode !== null || child.signalCode !== null)
				throw new Error(
					`llama.cpp exited during startup (${child.exitCode ?? child.signalCode}); see ${stateDir}/llama-output.txt`,
				);
			if (Date.now() >= deadline)
				throw new Error(`llama.cpp did not become ready within ${READY_TIMEOUT_MS}ms: ${lastReadiness}`);
			const requestSignal = AbortSignal.any([lifetime.signal, AbortSignal.timeout(1000)]);
			try {
				const response = await fetch(`${upstream.origin}/health`, {
					unix: socketPath,
					signal: requestSignal,
					redirect: "error",
					proxy: "",
				});
				lastReadiness = `Health HTTP ${response.status}`;
				await response.body?.cancel();
				if (response.ok) {
					const models = await fetch(`${upstream.href}/models`, {
						unix: socketPath,
						headers: { authorization: `Bearer ${apiKey}` },
						signal: requestSignal,
						redirect: "error",
						proxy: "",
					});
					const data = (await models.json()) as { data?: { id?: string }[] };
					lastReadiness = `Models HTTP ${models.status}; expected alias ${config.modelId}`;
					if (models.ok && data.data?.some(model => model.id === config.modelId)) {
						const unauthenticated = await fetch(`${upstream.href}/models`, {
							unix: socketPath,
							signal: requestSignal,
							redirect: "error",
							proxy: "",
						});
						await unauthenticated.body?.cancel();
						if (unauthenticated.status === 401) break;
						lastReadiness = "Runtime did not enforce its ephemeral API credential";
					}
				}
			} catch (error) {
				if (signal?.aborted) throw error;
				lastReadiness = (error instanceof Error ? error.message : String(error)).slice(0, 500);
			}
			await Bun.sleep(100);
		}
		gateway = createInferenceGateway(socketPath, apiKey, config.modelId, lifetime.signal);
		const baseUrl = validateInferenceUrl(`http://127.0.0.1:${gateway.port}/v1`).href;
		const model = buildModel({
			id: config.modelId,
			name: config.modelId,
			api: "openai-completions",
			provider: "llama.cpp",
			baseUrl,
			reasoning: true,
			input: ["text"],
			supportsTools: true,
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
			contextWindow: config.contextTokens,
			maxTokens: Math.min(2048, Math.floor(config.contextTokens / 4)),
		});
		return { model, apiKey, signal: lifetime.signal, thinkingLevel: Effort.High, stop };
	} catch (error) {
		try {
			await stop();
		} catch (cleanup) {
			throw new AggregateError([error, cleanup], "Inference startup and cleanup failed");
		}
		throw error;
	}
}

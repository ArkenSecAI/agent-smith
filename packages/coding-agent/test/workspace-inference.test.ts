import { afterEach, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { streamSimple } from "@oh-my-pi/pi-ai";
import { untilAborted } from "@oh-my-pi/pi-utils";
import type { WorkspaceExternalInference, WorkspaceRuntime } from "../src/workspace/contracts";
import { createInferenceGateway, startInference } from "../src/workspace/inference";
import { createInferenceFetch } from "../src/workspace/inference-fetch";
import { runtimeShape, validateInferenceUrl } from "../src/workspace/project";

const servers: Bun.Server<undefined>[] = [];
const directories: string[] = [];

async function localSocket(): Promise<string> {
	const directory = await fs.mkdtemp(
		path.join(await fs.realpath(process.platform === "win32" ? os.tmpdir() : "/tmp"), "smith-inf-"),
	);
	directories.push(directory);
	return path.join(directory, "engine.sock");
}

afterEach(async () => {
	for (const server of servers.splice(0)) await server.stop(true);
	for (const directory of directories.splice(0)) await fs.rm(directory, { recursive: true, force: true });
});

test("chat gateway rejects runtime management, wrong model, and missing credentials without forwarding", async () => {
	let calls = 0;
	const socket = await localSocket();
	const upstream = Bun.serve({
		unix: socket,
		fetch() {
			calls++;
			return Response.json({ choices: [] });
		},
	});
	servers.push(upstream);
	const gateway = createInferenceGateway(socket, "fixture-key", "fixture-model", new AbortController().signal);
	servers.push(gateway);
	const base = `http://127.0.0.1:${gateway.port}`;
	const headers = { authorization: "Bearer fixture-key", "content-type": "application/json" };
	for (const endpoint of ["/models/load", "/v1/models", "/tools", "/v1/chat/completions?url=https://example.com"]) {
		const response = await fetch(`${base}${endpoint}`, { method: "POST", headers, body: "{}" });
		expect(response.status).toBe(404);
	}
	const unauthorized = await fetch(`${base}/v1/chat/completions`, {
		method: "POST",
		body: JSON.stringify({ model: "fixture-model" }),
	});
	expect(unauthorized.status).toBe(401);
	const wrongModel = await fetch(`${base}/v1/chat/completions`, {
		method: "POST",
		headers,
		body: JSON.stringify({ model: "other-model" }),
	});
	expect(wrongModel.status).toBe(400);
	expect(calls).toBe(0);
	const accepted = await fetch(`${base}/v1/chat/completions`, {
		method: "POST",
		headers,
		body: JSON.stringify({ model: "fixture-model", messages: [] }),
	});
	expect(accepted.status).toBe(200);
	await accepted.body?.cancel();
	expect(calls).toBe(1);
});

test("an upstream redirect cannot turn local inference into a second endpoint request", async () => {
	let escaped = 0;
	const destination = Bun.serve({
		hostname: "127.0.0.1",
		port: 0,
		fetch() {
			escaped++;
			return new Response("escaped");
		},
	});
	servers.push(destination);
	const socket = await localSocket();
	const upstream = Bun.serve({
		unix: socket,
		fetch() {
			return Response.redirect(`http://127.0.0.1:${destination.port}/v1/chat/completions`);
		},
	});
	servers.push(upstream);
	const gateway = createInferenceGateway(socket, "fixture-key", "fixture-model", new AbortController().signal);
	servers.push(gateway);
	const response = await fetch(`http://127.0.0.1:${gateway.port}/v1/chat/completions`, {
		method: "POST",
		headers: { authorization: "Bearer fixture-key" },
		body: JSON.stringify({ model: "fixture-model" }),
	});
	expect(response.status).toBe(502);
	expect(escaped).toBe(0);
});

test("non-loopback and credential-bearing SDK endpoint URLs are rejected", () => {
	for (const url of [
		"https://127.0.0.1:8080/v1",
		"http://localhost:8080/v1",
		"http://192.0.2.1:8080/v1",
		"http://user:password@127.0.0.1:8080/v1",
		"http://127.0.0.1:8080/v1?model=remote",
	]) {
		expect(() => validateInferenceUrl(url)).toThrow();
	}
});

async function fixtureRuntime(): Promise<{ directory: string; runtime: WorkspaceRuntime }> {
	const directory = await fs.mkdtemp(path.join(os.tmpdir(), "workspace-inference-"));
	directories.push(directory);
	const binary = path.join(directory, "llama-fixture");
	const model = path.join(directory, "fixture.gguf");
	// An isolated failing executable is sufficient to exercise pin and native-exit boundaries.
	const script = "#!/bin/sh\nexit 23\n";
	await Bun.write(binary, script);
	await fs.chmod(binary, 0o700);
	await Bun.write(model, "GGUFfixture");
	return {
		directory,
		runtime: {
			schema: 1,
			qemu: {
				binary: "/fixture/qemu",
				sha256: "a".repeat(64),
				imageBinary: "/fixture/qemu-img",
				imageSha256: "a".repeat(64),
				firmwareDir: "/fixture/firmware",
			},
			imageManifest: "/fixture/image.json",
			memoryMiB: 4096,
			cpus: 2,
			inference: {
				binary,
				sha256: Bun.SHA256.hash(script, "hex"),
				model,
				modelSha256: Bun.SHA256.hash("GGUFfixture", "hex"),
				modelId: "fixture-model",
				contextTokens: 4096,
				threads: 1,
			},
		},
	};
}

test.skipIf(process.platform !== "linux" || process.arch !== "x64")(
	"binary and model pin failures stop startup before the executable runs",
	async () => {
		const { directory, runtime } = await fixtureRuntime();
		const config = runtime.inference!;
		await expect(
			startInference(
				{ ...runtime, inference: { ...config, sha256: "0".repeat(64) } },
				path.join(directory, "state"),
			),
		).rejects.toThrow("SHA-256 mismatch");
		await expect(
			startInference(
				{ ...runtime, inference: { ...config, modelSha256: "0".repeat(64) } },
				path.join(directory, "state"),
			),
		).rejects.toThrow("SHA-256 mismatch");
		expect(await Bun.file(path.join(directory, "state", "llama-help.txt")).exists()).toBe(false);
	},
);

test.skipIf(process.platform !== "linux" || process.arch !== "x64")(
	"the pinned executable's failed help command surfaces its native exit",
	async () => {
		const { directory, runtime } = await fixtureRuntime();
		await expect(startInference(runtime, path.join(directory, "state"))).rejects.toThrow(
			"--help failed with exit 23",
		);
	},
);

function externalConfig(baseUrl: string): WorkspaceExternalInference {
	return {
		baseUrl,
		modelId: "external-fixture",
		contextTokens: 8192,
		thinking: "low",
		sampling: {
			temperature: 1,
			topK: 20,
			topP: 0.95,
			minP: 0.05,
			presencePenalty: 0,
			frequencyPenalty: 0,
			repeatPenalty: 1,
			seed: 0,
		},
		provenance: {
			profile: "fixture",
			modelSha256: "a".repeat(64),
			serverSha256: "b".repeat(64),
			templateSha256: "c".repeat(64),
		},
	};
}

test("external runtime rejects ambiguous ownership and unsupported template effort", async () => {
	const { directory, runtime } = await fixtureRuntime();
	const externalInference = externalConfig("http://127.0.0.1:18080/v1");
	expect(() => runtimeShape({ ...runtime, externalInference })).toThrow();
	await expect(startInference({ ...runtime, externalInference }, path.join(directory, "state"))).rejects.toThrow();
	expect(() =>
		runtimeShape({
			...runtime,
			inference: undefined,
			externalInference: { ...externalInference, thinking: "high" },
		}),
	).toThrow();
});

test("closing an external consumer aborts its HTTP stream without stopping the service", async () => {
	const requested = Promise.withResolvers<void>();
	const disconnected = Promise.withResolvers<void>();
	const server = Bun.serve({
		hostname: "127.0.0.1",
		port: 0,
		fetch(request) {
			if (new URL(request.url).pathname === "/health") return Response.json({ status: "ok" });
			request.signal.addEventListener("abort", () => disconnected.resolve(), { once: true });
			return new Response(
				new ReadableStream({
					start(controller) {
						controller.enqueue(
							new TextEncoder().encode(
								`data: ${JSON.stringify({
									id: "external-fixture",
									object: "chat.completion.chunk",
									choices: [
										{ index: 0, delta: { role: "assistant", content: "Working" }, finish_reason: null },
									],
								})}\n\n`,
							),
						);
						requested.resolve();
					},
					cancel() {
						disconnected.resolve();
					},
				}),
				{ headers: { "content-type": "text/event-stream" } },
			);
		},
	});
	servers.push(server);
	const { directory, runtime } = await fixtureRuntime();
	const deadline = AbortSignal.timeout(5000);
	const consumer = await startInference(
		{
			...runtime,
			inference: undefined,
			externalInference: externalConfig(`http://127.0.0.1:${server.port}/v1`),
		},
		path.join(directory, "unused-native-state"),
		deadline,
	);
	const stream = streamSimple(
		consumer.model,
		{ systemPrompt: ["Synthetic transport fixture."], messages: [{ role: "user", content: "Wait.", timestamp: 0 }] },
		{
			...consumer.streamOptions,
			apiKey: consumer.apiKey,
			signal: consumer.signal,
			maxTokens: consumer.model.maxTokens ?? undefined,
			fetch: createInferenceFetch(consumer.model.baseUrl),
		},
	);
	try {
		await untilAborted(deadline, requested.promise);
		await consumer.stop();
		expect((await stream.result()).stopReason).toBe("aborted");
		await untilAborted(deadline, disconnected.promise);
		expect(await (await fetch(`http://127.0.0.1:${server.port}/health`)).json()).toEqual({ status: "ok" });
	} finally {
		await consumer.stop();
		await stream.result();
	}
}, 10_000);

test("inference HTTP cannot leak through environment or caller-supplied proxies", async () => {
	let proxyRequests = 0;
	const target = Bun.serve({
		hostname: "127.0.0.1",
		port: 0,
		fetch: () => new Response("target"),
	});
	const proxy = Bun.serve({
		hostname: "127.0.0.1",
		port: 0,
		fetch() {
			proxyRequests++;
			return new Response("proxy");
		},
	});
	servers.push(target, proxy);
	const { directory } = await fixtureRuntime();
	const baseUrl = `http://127.0.0.1:${target.port}/v1`;
	const proxyUrl = `http://127.0.0.1:${proxy.port}`;
	const child = Bun.spawn(
		[
			process.execPath,
			"--no-env-file",
			"-e",
			`import { createInferenceFetch } from ${JSON.stringify(path.resolve(import.meta.dir, "../src/workspace/inference-fetch.ts"))};
const direct = createInferenceFetch(${JSON.stringify(baseUrl)});
const response = await direct(${JSON.stringify(`${baseUrl}/chat/completions`)}, {
	method: "POST", body: "{}", proxy: ${JSON.stringify(proxyUrl)},
	signal: AbortSignal.timeout(3000)
});
console.log(await response.text());`,
		],
		{
			env: { HOME: directory, PATH: process.env.PATH, HTTP_PROXY: proxyUrl, HTTPS_PROXY: proxyUrl },
			stdin: "ignore",
			stdout: "pipe",
			stderr: "pipe",
		},
	);
	try {
		const [exit, stdout, stderr] = await untilAborted(
			AbortSignal.timeout(5000),
			Promise.all([child.exited, new Response(child.stdout).text(), new Response(child.stderr).text()]),
		);
		if (exit !== 0) throw new Error(`Isolated transport failed: ${stderr}`);
		expect(stdout.trim()).toBe("target");
		expect(proxyRequests).toBe(0);
	} finally {
		if (child.exitCode === null) child.kill();
		await child.exited;
	}
}, 10_000);

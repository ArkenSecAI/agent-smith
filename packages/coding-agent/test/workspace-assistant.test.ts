import { afterEach, describe, expect, test, vi } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { buildModel } from "@oh-my-pi/pi-catalog/build";
import { investigate, InvestigationTools, INVESTIGATION_LIMITS } from "../src/workspace/assistant";
import type {
	ProjectManifest,
	RunOutput,
	RunRequest,
	RunSnapshot,
	WorkspaceClient,
	WorkspaceStatus,
} from "../src/workspace/contracts";
import * as inference from "../src/workspace/inference";
import * as projects from "../src/workspace/project";
import { Effort } from "@oh-my-pi/pi-catalog/effort";

const projectId = "63250cda-c82b-4b80-bd4a-760a686b7b10";
const runId = "b39ea949-1a2d-49e0-b54c-eab9debc91d3";
const foreignId = "0f2cdbf4-fdc5-4c94-909e-455b0422b69c";
const pin = "a".repeat(64);
const manifest: ProjectManifest = {
	schema: 1,
	id: projectId,
	name: "fixture",
	createdAt: "2026-10-13T00:00:00Z",
	targets: ["127.0.0.1"],
	image: {
		schema: 1,
		id: "fixture",
		isa: "x86_64",
		disk: { path: "/fixture/base.qcow2", sha256: pin },
		guestSha256: pin,
		packages: { path: "/fixture/packages.json", sha256: pin },
		provenance: { path: "/fixture/provenance.json", sha256: pin },
	},
	runtime: {
		schema: 1,
		qemu: {
			binary: "/fixture/qemu",
			sha256: pin,
			imageBinary: "/fixture/qemu-img",
			imageSha256: pin,
			firmwareDir: "/fixture/firmware",
		},
		imageManifest: "/fixture/image.json",
		memoryMiB: 4096,
		cpus: 2,
		inference: {
			binary: "/fixture/llama-server",
			sha256: pin,
			model: "/fixture/model.gguf",
			modelSha256: pin,
			modelId: "workspace-fixture",
			contextTokens: 8192,
			threads: 2,
		},
	},
};

class FixtureClient implements WorkspaceClient {
	readonly started = Promise.withResolvers<void>();
	readonly output = Buffer.from("80/tcp open http\nfixture-service\n");
	run: RunSnapshot | undefined;
	completeOnStart = false;
	starts = 0;
	cancelReads = 0;
	observedCapture = false;
	wrongProject = false;
	startBarrier: Promise<void> | undefined;

	async status(): Promise<WorkspaceStatus> {
		return {
			project: manifest,
			generation: "fixture-boot",
			state: "running",
			accelerator: "kvm",
			runs: this.run ? [{ ...this.run }] : [],
		};
	}
	async startRun(request: RunRequest): Promise<RunSnapshot> {
		this.starts++;
		this.run = {
			id: runId,
			project: projectId,
			generation: "fixture-boot",
			actor: request.actor,
			kind: request.kind,
			state: this.completeOnStart ? "exited" : "running",
			exitCode: this.completeOnStart ? 0 : null,
			signal: null,
			cancelRequested: false,
			captureComplete: this.completeOnStart,
			outputBytes: this.output.length,
			ownerEpoch: 0,
			startedAt: "2026-10-13T00:00:00Z",
			endedAt: null,
			mcpResult: { outcome: "completed" },
		};
		this.started.resolve();
		await this.startBarrier;
		return { ...this.run };
	}
	async readRun(id: string, offset = 0): Promise<RunOutput> {
		if (!this.run || id !== this.run.id) throw new Error("Unknown fixture run");
		if (this.run.cancelRequested) {
			this.run.state = "cancelled";
			this.run.captureComplete = ++this.cancelReads >= 2;
			this.run.signal = 15;
			this.observedCapture ||= this.run.captureComplete;
		}
		return {
			run: { ...this.run, project: this.wrongProject ? foreignId : this.run.project },
			offset,
			nextOffset: this.output.length,
			data: this.output.subarray(offset).toString("base64"),
		};
	}
	async cancel(id: string): Promise<RunSnapshot> {
		if (!this.run || id !== this.run.id) throw new Error("Unknown fixture run");
		this.run.cancelRequested = true;
		return { ...this.run };
	}
	input(): Promise<RunSnapshot> {
		throw new Error("Assistant must not acquire guest terminal input");
	}
	resize(): Promise<RunSnapshot> {
		throw new Error("Assistant must not resize a terminal");
	}
	takeover(): Promise<RunSnapshot> {
		throw new Error("Assistant must not take terminal ownership");
	}
	stop(): Promise<WorkspaceStatus> {
		throw new Error("Assistant must not stop the VM");
	}
}

const limits = { ...INVESTIGATION_LIMITS, scanMs: 2000, cancelMs: 1000, pollMs: 1 };
const tempDirs: string[] = [];
const servers: Bun.Server<undefined>[] = [];

afterEach(async () => {
	vi.restoreAllMocks();
	for (const server of servers.splice(0)) await server.stop(true);
	for (const directory of tempDirs.splice(0)) await fs.rm(directory, { recursive: true, force: true });
});

describe("workspace assistant action boundary", () => {
	test("literal target and port violations never create guest work", async () => {
		const client = new FixtureClient();
		const tools = new InvestigationTools(manifest, client, new AbortController(), { ...limits, toolCalls: 10 });
		for (const target of ["localhost", "127.0.0.1;id", "127.0.0.2", "127.0.0.1/32"]) {
			await expect(tools.scan("kali", target, "80")).rejects.toThrow("literal manifest target");
		}
		for (const ports of ["80 --script=vuln", "0", "65536", "100-1", "1-257"]) {
			await expect(tools.scan("hexstrike", "127.0.0.1", ports)).rejects.toThrow();
		}
		expect(client.starts).toBe(0);
	});

	test("scan previews bound context and cite only the original tail bytes", async () => {
		const client = new (class extends FixtureClient {
			override readonly output = Buffer.concat([Buffer.alloc(65408, 0x78), Buffer.alloc(128, 0x79)]);
			override completeOnStart = true;
		})();
		const tools = new InvestigationTools(manifest, client, new AbortController(), { ...limits, evidenceBytes: 128 });
		const result = await tools.scan("kali", "127.0.0.1", "80");
		expect(result.details).toMatchObject({
			run: { id: runId, state: "exited", outputBytes: 65536, captureComplete: true },
			mcpOutcome: "completed",
			offset: 65408,
			nextOffset: 65536,
			more: false,
			text: client.output.subarray(65408).toString("utf8"),
			sha256: Bun.SHA256.hash(client.output.subarray(65408), "hex"),
		});
		expect([...tools.evidenceRefs]).toEqual([`workspace-run:${runId}:65408-65536`]);
	});

	test("evidence cannot read a host path, a foreign run, or a mismatched capture", async () => {
		const client = new FixtureClient();
		const tools = new InvestigationTools(manifest, client, new AbortController(), limits);
		await expect(tools.read("../../private")).rejects.toThrow("run UUID");
		await expect(tools.read(foreignId)).rejects.toThrow("not part of this project");
		await client.startRun({ actor: "human", kind: "command", timeoutMs: 1000 });
		client.wrongProject = true;
		await expect(tools.read(runId)).rejects.toThrow("identity does not match");
	});

	test("evidence reader returns the original requested bytes with truthful continuation offsets", async () => {
		const client = new FixtureClient();
		await client.startRun({ actor: "human", kind: "command", timeoutMs: 1000 });
		const tools = new InvestigationTools(manifest, client, new AbortController(), { ...limits, evidenceBytes: 8 });
		const first = await tools.read(runId, 3);
		expect(first.details).toMatchObject({
			offset: 3,
			nextOffset: 11,
			text: client.output.subarray(3, 11).toString(),
			more: true,
			evidenceRef: `workspace-run:${runId}:3-11`,
			sha256: Bun.SHA256.hash(client.output.subarray(3, 11), "hex"),
		});
		await expect(tools.read(runId, client.output.length + 1)).rejects.toThrow("outside the captured run");
	});

	test("abort waits for the guest's terminal outcome and drained capture", async () => {
		const client = new FixtureClient();
		const controller = new AbortController();
		const tools = new InvestigationTools(manifest, client, controller, limits);
		const scanning = tools.scan("kali", "127.0.0.1", "80");
		const rejected = expect(scanning).rejects.toThrow();
		await client.started.promise;
		controller.abort(new Error("Ctrl+C"));
		await rejected;
		expect(client.observedCapture).toBe(true);
		expect(client.run).toMatchObject({ state: "cancelled", captureComplete: true, cancelRequested: true });
	});

	test("a run accepted after interruption is still cancelled and observed", async () => {
		const client = new FixtureClient();
		const barrier = Promise.withResolvers<void>();
		client.startBarrier = barrier.promise;
		const controller = new AbortController();
		const tools = new InvestigationTools(manifest, client, controller, limits);
		const scanning = tools.scan("hexstrike", "127.0.0.1", "80");
		const rejected = expect(scanning).rejects.toThrow();
		await client.started.promise;
		controller.abort(new Error("Ctrl+C during start"));
		const cleanup = tools.cancelAll();
		barrier.resolve();
		await rejected;
		await cleanup;
		expect(client.observedCapture).toBe(true);
		expect(tools.runIds).toEqual([runId]);
	});

	test("exhausting the tool budget cancels an in-flight guest scan", async () => {
		const client = new FixtureClient();
		const controller = new AbortController();
		const tools = new InvestigationTools(manifest, client, controller, { ...limits, toolCalls: 1 });
		const scanning = tools.scan("kali", "127.0.0.1", "80");
		const rejected = expect(scanning).rejects.toThrow();
		await client.started.promise;
		await expect(tools.read()).rejects.toThrow("tool-call limit");
		await rejected;
		expect(client.observedCapture).toBe(true);
	});

	test("scan deadline causes observed guest cancellation", async () => {
		const client = new FixtureClient();
		const tools = new InvestigationTools(manifest, client, new AbortController(), { ...limits, scanMs: 20 });
		await expect(tools.scan("hexstrike", "127.0.0.1", "80")).rejects.toThrow();
		expect(client.observedCapture).toBe(true);
	});

	test("timeout-with-output remains an error result with readable evidence", async () => {
		const client = new FixtureClient();
		await client.startRun({ actor: "agent", kind: "mcp", timeoutMs: 1000 });
		Object.assign(client.run!, {
			state: "timed_out",
			captureComplete: true,
			exitCode: 1,
			mcpResult: { outcome: "timed_out" },
		});
		const tools = new InvestigationTools(manifest, client, new AbortController(), limits);
		const result = await tools.read(runId);
		expect(result.isError).toBe(true);
		expect(result.details).toMatchObject({ text: client.output.toString(), mcpOutcome: "timed_out" });
	});

	test("a failed cancellation cannot be reported as a stopped investigation", async () => {
		const client = new FixtureClient();
		vi.spyOn(client, "cancel").mockRejectedValue(new Error("control connection lost"));
		const controller = new AbortController();
		const tools = new InvestigationTools(manifest, client, controller, limits);
		const scanning = tools.scan("kali", "127.0.0.1", "80");
		const rejected = expect(scanning).rejects.toThrow("cancellation not confirmed");
		await client.started.promise;
		controller.abort();
		await rejected;
		await expect(tools.cancelAll()).rejects.toThrow("without confirmed guest cancellation");
	});
});

test("real SDK/provider loop rejects an ambient tool, consumes guest evidence, and persists its answer locally", async () => {
	const directory = await fs.mkdtemp(path.join(os.tmpdir(), "workspace-sdk-"));
	tempDirs.push(directory);
	const client = new FixtureClient();
	client.completeOnStart = true;
	const seenToolResults: string[] = [];
	let calls = 0;
	const server = Bun.serve({
		hostname: "127.0.0.1",
		port: 0,
		async fetch(request) {
			const body = (await request.json()) as {
				messages: { role: string; content: string; tool_call_id?: string }[];
			};
			for (const message of body.messages) if (message.role === "tool") seenToolResults.push(message.content);
			calls++;
			const tool =
				calls === 1
					? { name: "bash", arguments: JSON.stringify({ command: "id" }) }
					: calls === 2
						? { name: "kali_nmap", arguments: JSON.stringify({ target: "127.0.0.1", ports: "80" }) }
						: calls === 3
							? { name: "read_evidence", arguments: JSON.stringify({ runId, offset: 0 }) }
							: undefined;
			const delta = tool
				? { role: "assistant", tool_calls: [{ index: 0, id: `call-${calls}`, type: "function", function: tool }] }
				: {
						role: "assistant",
						content:
							"The fixture exposes TCP port 80 as HTTP. This is a service observation, not proof of a vulnerability.",
					};
			return new Response(
				`data: ${JSON.stringify({ id: "fixture", object: "chat.completion.chunk", choices: [{ index: 0, delta, finish_reason: null }] })}\n\ndata: ${JSON.stringify({ id: "fixture", object: "chat.completion.chunk", choices: [{ index: 0, delta: {}, finish_reason: tool ? "tool_calls" : "stop" }] })}\n\ndata: [DONE]\n\n`,
				{ headers: { "content-type": "text/event-stream" } },
			);
		},
	});
	servers.push(server);
	const model = buildModel({
		id: "workspace-fixture",
		name: "Fixture",
		api: "openai-completions",
		provider: "llama.cpp",
		baseUrl: `http://127.0.0.1:${server.port}/v1`,
		reasoning: false,
		input: ["text"],
		supportsTools: true,
		contextWindow: 8192,
		maxTokens: 512,
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
	});
	vi.spyOn(inference, "startInference").mockResolvedValue({
		model,
		apiKey: "isolated-fixture",
		signal: new AbortController().signal,
		thinkingLevel: "off",
		stop: async () => {},
	});
	vi.spyOn(projects, "loadProject").mockResolvedValue(manifest);
	const result = await investigate(
		directory,
		client,
		"Inspect the declared fixture service and cite original evidence.",
	);
	expect(client.starts).toBe(1);
	expect(seenToolResults.some(text => /not found|unknown tool|not available/i.test(text))).toBe(true);
	expect(result.text).toContain(`workspace-run:${runId}:`);
	expect(result.sessionFile.startsWith(`${directory}${path.sep}`)).toBe(true);
	const transcript = await Bun.file(result.sessionFile).text();
	expect(transcript).not.toContain("isolated-fixture");
}, 30_000);

for (const truncation of ["visible output", "thinking after a tool"] as const) {
	test(`truncated ${truncation} is rejected instead of returned as a final answer`, async () => {
		const directory = await fs.mkdtemp(path.join(os.tmpdir(), "workspace-truncated-"));
		tempDirs.push(directory);
		const client = new FixtureClient();
		client.completeOnStart = true;
		let providerRequests = 0;
		const server = Bun.serve({
			hostname: "127.0.0.1",
			port: 0,
			fetch() {
				const toolTurn = ++providerRequests === 1 && truncation === "thinking after a tool";
				const delta = toolTurn
					? {
							role: "assistant",
							content: "I will inspect the service before giving a final answer.",
							tool_calls: [
								{
									index: 0,
									id: "inspect-fixture",
									type: "function",
									function: {
										name: "kali_nmap",
										arguments: JSON.stringify({ target: "127.0.0.1", ports: "80" }),
									},
								},
							],
						}
					: truncation === "visible output"
						? { role: "assistant", content: "The captured observations indicate" }
						: { role: "assistant", reasoning_content: "Still reasoning; no final answer was produced." };
				const chunk = {
					id: "truncated-fixture",
					object: "chat.completion.chunk",
					choices: [{ index: 0, delta, finish_reason: null }],
				};
				const end = {
					...chunk,
					choices: [{ index: 0, delta: {}, finish_reason: toolTurn ? "tool_calls" : "length" }],
				};
				return new Response(`data: ${JSON.stringify(chunk)}\n\ndata: ${JSON.stringify(end)}\n\ndata: [DONE]\n\n`, {
					headers: { "content-type": "text/event-stream" },
				});
			},
		});
		servers.push(server);
		const model = buildModel({
			id: "workspace-fixture",
			name: "Fixture",
			api: "openai-completions",
			provider: "llama.cpp",
			baseUrl: `http://127.0.0.1:${server.port}/v1`,
			reasoning: true,
			input: ["text"],
			supportsTools: true,
			contextWindow: 8192,
			maxTokens: 512,
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
		});
		vi.spyOn(inference, "startInference").mockResolvedValue({
			model,
			apiKey: "isolated-fixture",
			signal: new AbortController().signal,
			thinkingLevel: Effort.Medium,
			stop: async () => {},
		});
		vi.spyOn(projects, "loadProject").mockResolvedValue(manifest);
		await expect(investigate(directory, client, "Summarize the project observations.")).rejects.toBeInstanceOf(Error);
		expect(providerRequests).toBe(truncation === "visible output" ? 1 : 2);
		const files = await fs.readdir(directory, { recursive: true });
		const sessionFile = files.find(file => file.endsWith(".jsonl"));
		if (!sessionFile) throw new Error("Investigation did not persist its session");
		const rows = (await Bun.file(path.join(directory, sessionFile)).text())
			.trim()
			.split("\n")
			.map(line => JSON.parse(line));
		const terminal = rows.findLast(row => row.type === "message" && row.message.role === "assistant");
		expect(terminal?.message.stopReason).toBe("length");
		const outcome = rows.findLast(
			row => row.type === "custom" && row.customType === "workspace-investigation-result",
		)?.data;
		expect(outcome?.completed).toBe(false);
		expect(outcome?.answer).toBeUndefined();
	}, 30_000);
}

for (const failure of ["multiple calls", "interrupted tool stream"] as const) {
	test(`external ${failure} cannot execute guest tools`, async () => {
		const directory = await fs.mkdtemp(path.join(os.tmpdir(), "workspace-external-"));
		tempDirs.push(directory);
		const client = new FixtureClient();
		client.completeOnStart = true;
		let requests = 0;
		const server = Bun.serve({
			hostname: "127.0.0.1",
			port: 0,
			fetch() {
				requests++;
				const calls = Array.from({ length: failure === "multiple calls" ? 2 : 1 }, (_, index) => ({
					index,
					id: `call-${index}`,
					type: "function",
					function: {
						name: "kali_nmap",
						arguments: JSON.stringify({ target: "127.0.0.1", ports: "80" }),
					},
				}));
				const chunk = {
					id: "external-fixture",
					object: "chat.completion.chunk",
					choices: [{ index: 0, delta: { role: "assistant", tool_calls: calls }, finish_reason: null }],
				};
				const end = { ...chunk, choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }] };
				return new Response(
					`data: ${JSON.stringify(chunk)}\n\n` +
						(failure === "multiple calls" ? `data: ${JSON.stringify(end)}\n\ndata: [DONE]\n\n` : ""),
					{ headers: { "content-type": "text/event-stream" } },
				);
			},
		});
		servers.push(server);
		const externalProject: ProjectManifest = {
			...manifest,
			runtime: {
				...manifest.runtime,
				inference: undefined,
				externalInference: {
					baseUrl: `http://127.0.0.1:${server.port}/v1`,
					modelId: "external-fixture",
					contextTokens: 65536,
					thinking: "off",
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
					provenance: { profile: "fixture", modelSha256: pin, serverSha256: pin, templateSha256: pin },
				},
			},
		};
		vi.spyOn(projects, "loadProject").mockResolvedValue(externalProject);
		await expect(investigate(directory, client, "Inspect the authorized service.")).rejects.toBeInstanceOf(Error);
		expect(client.starts).toBe(0);
		expect(requests).toBe(1);
	}, 30_000);
}

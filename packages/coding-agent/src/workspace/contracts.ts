/** Host-owned workspace and guest-wire contracts. No ambient host execution is part of this API. */
export type Actor = "human" | "agent";
export type McpServer = "kali" | "hexstrike";
export type RunState = "running" | "exited" | "cancelled" | "timed_out" | "unknown";

export interface RunRequest {
	actor: Actor;
	kind: "command" | "mcp" | "mcp-list";
	argv?: string[];
	cwd?: string;
	pty?: { rows: number; cols: number };
	server?: McpServer;
	tool?: string;
	arguments?: Record<string, unknown>;
	timeoutMs: number;
}

export interface RunSnapshot {
	id: string;
	project: string;
	generation: string;
	actor: Actor;
	kind: RunRequest["kind"];
	state: RunState;
	exitCode: number | null;
	signal: number | null;
	cancelRequested: boolean;
	captureComplete: boolean;
	outputBytes: number;
	ownerEpoch: number;
	startedAt: string;
	endedAt: string | null;
	mcpResult?: unknown;
}

export interface RunOutput {
	run: RunSnapshot;
	offset: number;
	nextOffset: number;
	data: string; // Base64 original combined stdout/stderr bytes; PTYs necessarily merge streams.
}

export interface ImageManifest {
	schema: 1;
	id: string;
	isa: "x86_64";
	disk: { path: string; sha256: string };
	guestSha256: string;
	packages: { path: string; sha256: string };
	provenance: { path: string; sha256: string };
}

/** Explicit keyless Qwen chat-template endpoint; lifecycle stays with its operator. */
export interface WorkspaceExternalInference {
	baseUrl: string;
	modelId: string;
	contextTokens: number;
	thinking: "off" | "low" | "medium" | "xhigh";
	sampling: {
		temperature: number;
		topK: number;
		topP: number;
		minP: number;
		presencePenalty: number;
		frequencyPenalty: number;
		repeatPenalty: number;
		seed: number;
	};
	/** Operator-declared provenance, not remote weight/build attestation. */
	provenance: {
		profile: string;
		modelSha256: string;
		serverSha256: string;
		templateSha256: string;
	};
}

export interface WorkspaceRuntime {
	schema: 1;
	qemu: {
		binary: string;
		sha256: string;
		imageBinary: string;
		imageSha256: string;
		firmwareDir: string;
		libraryDir?: string;
	};
	imageManifest: string;
	memoryMiB: number;
	cpus: number;
	inference?: {
		binary: string;
		sha256: string;
		model: string;
		modelSha256: string;
		modelId: string;
		contextTokens: number;
		threads: number;
	};
	/** Mutually exclusive with the managed CPU runtime above; never a fallback. */
	externalInference?: WorkspaceExternalInference;
	/** An operator-selected numeric loopback port only, never a model-supplied endpoint. */
	hostTargetPort?: number;
}

export interface ProjectManifest {
	schema: 1;
	id: string;
	name: string;
	createdAt: string;
	image: ImageManifest;
	runtime: WorkspaceRuntime;
	/** Model actions are bound to these literal guest target addresses. */
	targets: string[];
}

export interface WorkspaceStatus {
	project: ProjectManifest;
	generation: string | null;
	state: "stopped" | "starting" | "running" | "stopping" | "unknown";
	accelerator: "kvm" | null;
	runs: RunSnapshot[];
}

export interface WorkspaceClient {
	status(): Promise<WorkspaceStatus>;
	startRun(request: RunRequest): Promise<RunSnapshot>;
	readRun(id: string, offset?: number): Promise<RunOutput>;
	input(id: string, data: string, ownerEpoch: number): Promise<RunSnapshot>;
	resize(id: string, rows: number, cols: number, ownerEpoch: number): Promise<RunSnapshot>;
	takeover(id: string): Promise<RunSnapshot>;
	cancel(id: string): Promise<RunSnapshot>;
	stop(): Promise<WorkspaceStatus>;
}

export interface GuestRequest {
	v: 1;
	id: string;
	project: string;
	generation: string;
	token: string;
	op: "ping" | "poweroff" | "start" | "status" | "read" | "input" | "resize" | "takeover" | "cancel" | "list";
	args: Record<string, unknown>;
}

export type GuestResponse = {
	v: 1;
	id: string;
	project: string;
	generation: string;
} & ({ ok: true; result: unknown } | { ok: false; error: string });

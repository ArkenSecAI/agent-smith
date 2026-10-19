import * as net from "node:net";
import { timingSafeEqual } from "node:crypto";
import type { GuestRequest, GuestResponse, RunOutput, RunRequest, RunSnapshot } from "./contracts";
import { integer, MAX_JSON_BYTES, object, runId } from "./project";

export const OUTPUT_CHUNK = 64 * 1024;

export function authenticatedToken(actual: unknown, expected: string): boolean {
	if (typeof actual !== "string") return false;
	const left = Buffer.from(actual);
	const right = Buffer.from(expected);
	return left.length === right.length && timingSafeEqual(left, right);
}

export function originalBytes(value: unknown, limit = OUTPUT_CHUNK): Buffer {
	if (
		typeof value !== "string" ||
		value.length > Math.ceil(limit / 3) * 4 ||
		!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)
	)
		throw new Error("Invalid output encoding");
	const bytes = Buffer.from(value, "base64");
	if (bytes.length > limit || bytes.toString("base64") !== value)
		throw new Error("Noncanonical or oversized output encoding");
	return bytes;
}

export function validateRun(value: unknown, project: string): RunSnapshot {
	const run = object(value);
	runId(run.id);
	runId(run.generation);
	if (
		run.project !== project ||
		!["human", "agent"].includes(String(run.actor)) ||
		!["command", "mcp", "mcp-list"].includes(String(run.kind)) ||
		!["running", "exited", "cancelled", "timed_out", "unknown"].includes(String(run.state))
	)
		throw new Error("Invalid guest run identity/state");
	for (const key of ["cancelRequested", "captureComplete"])
		if (typeof run[key] !== "boolean") throw new Error("Invalid guest run flag");
	integer(run.outputBytes, 0, Number.MAX_SAFE_INTEGER);
	integer(run.ownerEpoch, 0, Number.MAX_SAFE_INTEGER);
	if (run.exitCode !== null) integer(run.exitCode, 0, 255);
	if (run.signal !== null) integer(run.signal, 1, 128);
	if (
		typeof run.startedAt !== "string" ||
		!Number.isFinite(Date.parse(run.startedAt)) ||
		(run.endedAt !== null && (typeof run.endedAt !== "string" || !Number.isFinite(Date.parse(run.endedAt))))
	)
		throw new Error("Invalid guest timestamps");
	if (
		run.state === "running" &&
		(run.captureComplete || run.exitCode !== null || run.signal !== null || run.endedAt !== null)
	)
		throw new Error("Inconsistent live guest state");
	return run as unknown as RunSnapshot;
}

export function validateOutput(value: unknown, project: string, id: string, offset: number): RunOutput {
	const output = object(value);
	const run = validateRun(output.run, project);
	if (run.id !== id || output.offset !== offset) throw new Error("Guest output identity/offset mismatch");
	const bytes = originalBytes(output.data);
	if (output.nextOffset !== offset + bytes.length || run.outputBytes < offset + bytes.length)
		throw new Error("Guest output discontinuity");
	return { run, offset, nextOffset: offset + bytes.length, data: bytes.toString("base64") };
}

export function validateRunRequest(value: unknown): RunRequest {
	const request = object(value);
	if (
		!["human", "agent"].includes(String(request.actor)) ||
		!["command", "mcp", "mcp-list"].includes(String(request.kind))
	)
		throw new Error("Invalid run request");
	integer(request.timeoutMs, 1, 3600000);
	if (
		request.cwd !== undefined &&
		(typeof request.cwd !== "string" ||
			!/^\/work(?:\/[a-zA-Z0-9_.-]+)*$/.test(request.cwd) ||
			request.cwd.split("/").some(part => part === ".." || part === "."))
	)
		throw new Error("Working directory must stay under /work");
	if (request.kind === "command") {
		if (request.actor !== "human") throw new Error("Agent command execution is forbidden");
		if (
			!Array.isArray(request.argv) ||
			request.argv.length === 0 ||
			request.argv.length > 256 ||
			request.argv.some(arg => typeof arg !== "string" || arg.includes("\0") || arg.length > 65536) ||
			!request.argv[0]
		)
			throw new Error("Invalid guest argv");
	} else {
		if (request.server !== "kali" && request.server !== "hexstrike") throw new Error("Unknown MCP server");
		if (request.kind === "mcp") {
			if (typeof request.tool !== "string" || !/^[a-zA-Z0-9_.-]{1,128}$/.test(request.tool))
				throw new Error("Invalid MCP tool");
			object(request.arguments);
		}
	}
	if (request.pty !== undefined) {
		if (request.kind !== "command") throw new Error("PTY requires a human command");
		const pty = object(request.pty);
		integer(pty.rows, 1, 1000);
		integer(pty.cols, 1, 1000);
	}
	if (Buffer.byteLength(JSON.stringify(request)) > MAX_JSON_BYTES - 2048) throw new Error("Run request too large");
	return request as unknown as RunRequest;
}

/** Byte-oriented framing, including fragmented UTF-8; no partial JSON is acted upon. */
export class JsonLines {
	#buffer: Buffer = Buffer.alloc(0);
	constructor(
		readonly accept: (value: unknown) => void,
		readonly max = MAX_JSON_BYTES,
	) {}
	feed(bytes: Uint8Array): void {
		let start = 0;
		for (let index = 0; index < bytes.length; index++) {
			if (bytes[index] !== 10) continue;
			if (this.#buffer.length + index - start > this.max) throw new Error("JSONL frame too large");
			const frame = Buffer.concat([this.#buffer, bytes.subarray(start, index)]);
			this.#buffer = Buffer.alloc(0);
			start = index + 1;
			if (frame.length === 0) throw new Error("Empty JSONL frame");
			this.accept(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(frame)) as unknown);
		}
		if (this.#buffer.length + bytes.length - start > this.max) throw new Error("JSONL frame too large");
		this.#buffer = Buffer.concat([this.#buffer, bytes.subarray(start)]);
	}
}

interface Pending {
	resolve(value: unknown): void;
	reject(error: Error): void;
	timer: Timer;
}

/** Used only for host-selected Unix endpoints; never accepts addresses from a guest. */
export class JsonPeer {
	#pending = new Map<string, Pending>();
	#socket: net.Socket;
	#closed = false;
	#ready = Promise.withResolvers<void>();
	#readyTimer: Timer;
	readonly ready: Promise<void>;
	constructor(
		socketPath: string,
		readonly unsolicited?: (message: Record<string, unknown>) => void,
		timeoutMs = 5000,
	) {
		this.ready = this.#ready.promise;
		this.#socket = net.createConnection({ path: socketPath });
		this.#readyTimer = setTimeout(() => this.close(new Error("Unix socket connection timed out")), timeoutMs);
		const parser = new JsonLines(value => {
			const message = object(value);
			if (typeof message.id !== "string") {
				if (!this.unsolicited) throw new Error("Unsolicited protocol message");
				this.unsolicited(message);
				return;
			}
			const pending = this.#pending.get(message.id);
			if (!pending) throw new Error("Unknown response identifier");
			this.#pending.delete(message.id);
			clearTimeout(pending.timer);
			pending.resolve(message);
		});
		this.#socket.on("connect", () => {
			clearTimeout(this.#readyTimer);
			this.#ready.resolve();
		});
		this.#socket.on("data", bytes => {
			try {
				if (typeof bytes === "string") throw new Error("Expected an unencoded peer byte stream");
				parser.feed(bytes);
			} catch {
				this.close(new Error("Invalid JSONL peer response"));
			}
		});
		this.#socket.on("error", error => this.close(error));
		this.#socket.on("close", () => this.close(new Error("Unix peer disconnected")));
	}
	async request(message: Record<string, unknown>, timeoutMs = 15000): Promise<Record<string, unknown>> {
		await this.ready;
		if (this.#closed) throw new Error("Unix peer closed");
		const id = runId(message.id);
		const encoded = `${JSON.stringify(message)}\n`;
		if (Buffer.byteLength(encoded) > MAX_JSON_BYTES || this.#pending.size >= 64 || this.#pending.has(id))
			throw new Error("Protocol request limit exceeded");
		const pending = Promise.withResolvers<unknown>();
		const timer = setTimeout(
			() => this.close(new Error("Protocol request timed out; operation may have executed")),
			timeoutMs,
		);
		this.#pending.set(id, { ...pending, timer });
		try {
			this.#socket.write(encoded, error => {
				if (error) this.close(error);
			});
		} catch (error) {
			this.close(error instanceof Error ? error : new Error("Unix socket write failed"));
		}
		return object(await pending.promise);
	}
	close(error = new Error("Unix peer closed")): void {
		if (this.#closed) return;
		this.#closed = true;
		clearTimeout(this.#readyTimer);
		this.#ready.reject(error);
		for (const pending of this.#pending.values()) {
			clearTimeout(pending.timer);
			pending.reject(error);
		}
		this.#pending.clear();
		this.#socket.destroy();
	}
}

export class GuestTransport {
	readonly peer: JsonPeer;
	#token: string;
	constructor(
		socketPath: string,
		readonly project: string,
		readonly generation: string,
		token: string,
	) {
		this.#token = token;
		this.peer = new JsonPeer(socketPath);
	}
	async request(op: GuestRequest["op"], args: Record<string, unknown> = {}, timeoutMs = 15000): Promise<unknown> {
		const request: GuestRequest = {
			v: 1,
			id: crypto.randomUUID(),
			project: this.project,
			generation: this.generation,
			token: this.#token,
			op,
			args,
		};
		const response = await this.peer.request({ ...request }, timeoutMs);
		if (
			response.v !== 1 ||
			response.project !== this.project ||
			response.generation !== this.generation ||
			typeof response.ok !== "boolean"
		) {
			this.peer.close();
			throw new Error("Guest authentication/identity mismatch");
		}
		const wire = response as unknown as GuestResponse;
		// Guest error strings are untrusted and could echo the boot token. Keep diagnostics generic.
		if (!wire.ok) throw new Error(`Guest rejected ${op}`);
		return wire.result;
	}
	close(): void {
		this.peer.close();
	}
}

import * as postmortem from "@oh-my-pi/pi-utils/postmortem";
import type { RunSnapshot, WorkspaceClient } from "./contracts";
import { originalBytes, OUTPUT_CHUNK } from "./guest-transport";
import { runId } from "./project";

export async function writeTerminalBytes(
	bytes: Uint8Array,
	stream: NodeJS.WritableStream = process.stdout,
): Promise<void> {
	const written = Promise.withResolvers<void>();
	stream.write(bytes, error => (error ? written.reject(error) : written.resolve()));
	await written.promise;
}

/** Join the CLI's process-wide shutdown pass before it forces a signal exit. */
export async function withWorkspaceShutdown<T>(work: (signal: AbortSignal) => Promise<T>): Promise<T> {
	const controller = new AbortController();
	const finished = Promise.withResolvers<void>();
	const unregister = postmortem.register(
		"workspace-command",
		() => {
			controller.abort();
			// A process.on("SIGINT") callback alone cannot delay postmortem's exit.
			// Keep its cleanup pass pending through cancellation, capture and finally.
			return finished.promise;
		},
		{ exitOnly: true, minimumDeadlineMs: 45000 },
	);
	try {
		return await work(controller.signal);
	} catch (error) {
		if (controller.signal.aborted) {
			// The global signal exit can beat the top-level rejection reporter.
			await writeTerminalBytes(
				Buffer.from(`Workspace shutdown failed: ${error instanceof Error ? error.message : String(error)}\n`),
				process.stderr,
			);
		}
		throw error;
	} finally {
		unregister();
		finished.resolve();
	}
}

export function runExitCode(run: RunSnapshot): number {
	if (!run.captureComplete || run.state === "unknown") return 1;
	if (run.state === "timed_out") return 124;
	if (run.signal !== null) return Math.min(255, 128 + run.signal);
	if (run.state === "cancelled") return run.exitCode || 130;
	return run.exitCode ?? 1;
}

/** A real guest PTY. Ctrl-C is delivered as an original byte; Ctrl-] detaches. */
export async function runTerminal(client: WorkspaceClient, argv: string[] = ["/bin/bash", "-l"]): Promise<void> {
	await withWorkspaceShutdown(signal => runTerminalSession(client, argv, signal));
}

async function runTerminalSession(client: WorkspaceClient, argv: string[], signal: AbortSignal): Promise<void> {
	signal.throwIfAborted();
	if (!process.stdin.isTTY || !process.stdout.isTTY) throw new Error("Workspace terminal requires a host TTY");
	const attach = argv.length === 2 && argv[0] === "--attach" ? runId(argv[1]) : null;
	let run = attach
		? (await client.readRun(attach)).run
		: await client.startRun({
				actor: "human",
				kind: "command",
				argv,
				cwd: "/work",
				timeoutMs: 3600000,
				pty: { rows: process.stdout.rows || 24, cols: process.stdout.columns || 80 },
			});
	if (run.state !== "running") throw new Error("Cannot attach to a terminal run that is not running");
	run = await client.takeover(run.id);
	const epoch = run.ownerEpoch;
	await writeTerminalBytes(
		Buffer.from(`Guest PTY run ${run.id}; ownership ${epoch}. Ctrl-] detaches; Ctrl-C goes to the guest.\n`),
		process.stderr,
	);
	const wasRaw = process.stdin.isRaw;
	const wasFlowing = process.stdin.readableFlowing;
	let detached = false;
	let acceptingInput = true;
	let failed: Error | undefined;
	let offset = 0;
	let queue: Promise<void> = Promise.resolve();
	function enqueue(work: () => Promise<void>): void {
		queue = queue.then(work).catch(error => {
			failed = error instanceof Error ? error : new Error("Terminal input failed");
		});
	}
	const onData = (bytes: Buffer) => {
		if (!acceptingInput || detached || signal.aborted || failed) return;
		process.stdin.pause();
		const detachAt = bytes.indexOf(0x1d);
		const input = detachAt < 0 ? bytes : bytes.subarray(0, detachAt);
		enqueue(async () => {
			for (let index = 0; index < input.length; index += OUTPUT_CHUNK) {
				await client.input(run.id, input.subarray(index, index + OUTPUT_CHUNK).toString("base64"), epoch);
			}
			if (detachAt >= 0) detached = true;
			else if (acceptingInput && !failed && !signal.aborted) process.stdin.resume();
		});
	};
	const onResize = () =>
		enqueue(async () => {
			await client.resize(run.id, process.stdout.rows || 24, process.stdout.columns || 80, epoch);
		});
	try {
		process.stdin.setRawMode(true);
		process.stdin.on("data", onData);
		process.stdout.on("resize", onResize);
		process.stdin.resume();
		onResize();
		while (!detached && !signal.aborted) {
			if (failed) throw failed;
			const output = await client.readRun(run.id, offset);
			run = output.run;
			if (run.ownerEpoch !== epoch && run.state === "running")
				throw new Error("Terminal ownership was taken over by another human");
			const bytes = originalBytes(output.data);
			if (bytes.length) await writeTerminalBytes(bytes);
			offset = output.nextOffset;
			if (run.state !== "running" && (run.captureComplete || run.state === "unknown") && offset === run.outputBytes)
				break;
			if (!bytes.length) await Bun.sleep(75);
		}
		if (!detached && !signal.aborted) process.exitCode = runExitCode(run);
	} finally {
		acceptingInput = false;
		process.stdin.off("data", onData);
		process.stdout.off("resize", onResize);
		// Stop queued input from resuming stdin after the terminal is restored.
		detached ||= signal.aborted;
		process.stdin.setRawMode(wasRaw);
		if (wasFlowing) process.stdin.resume();
		else process.stdin.pause();
		await queue;
		await writeTerminalBytes(
			Buffer.from(
				`\nGuest run ${run.id}: ${detached ? "detached" : run.state}; exit=${run.exitCode}; signal=${run.signal}; hostCaptureComplete=${run.captureComplete}\n`,
			),
			process.stderr,
		);
	}
	if (failed) throw failed;
}

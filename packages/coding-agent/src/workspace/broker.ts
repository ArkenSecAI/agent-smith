import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as net from "node:net";
import type { Subprocess } from "bun";
import { $which, acquireFileLock, isEnoent, logger, postmortem } from "@oh-my-pi/pi-utils";
import type { ProjectManifest, RunOutput, RunSnapshot, WorkspaceStatus } from "./contracts";
import {
	authenticatedToken,
	GuestTransport,
	JsonLines,
	JsonPeer,
	originalBytes,
	OUTPUT_CHUNK,
	validateOutput,
	validateRun,
	validateRunRequest,
} from "./guest-transport";
import {
	absolutePath,
	assertLinux,
	cleanEnvironment,
	durableJson,
	integer,
	loadProject,
	MAX_JSON_BYTES,
	object,
	readJson,
	regularFile,
	runId,
	syncDirectory,
	validateRuntime,
} from "./project";

export interface ProcessIdentity {
	pid: number;
	start: string;
	boot: string;
}
export interface BrokerState {
	schema: 1;
	generation: string;
	state: WorkspaceStatus["state"];
	accelerator: "kvm" | null;
	broker: ProcessIdentity;
	vm: ProcessIdentity | null;
}

/** PID reuse and host reboot must not turn an unrelated process into our VM. */
export async function processIdentity(pid: number): Promise<ProcessIdentity | null> {
	integer(pid, 1, 2147483647);
	try {
		const stat = await Bun.file(`/proc/${pid}/stat`).text();
		const fields = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
		if (fields[0] === "Z" || fields[0] === "X") return null;
		const start = fields[19];
		if (!start || !/^\d+$/.test(start)) throw new Error("Invalid process identity");
		return { pid, start, boot: (await Bun.file("/proc/sys/kernel/random/boot_id").text()).trim() };
	} catch (error) {
		if (isEnoent(error)) return null;
		throw error;
	}
}

export async function identityAlive(value: ProcessIdentity | null): Promise<boolean> {
	if (!value) return false;
	const identity = object(value);
	integer(identity.pid, 1, 2147483647);
	if (typeof identity.start !== "string" || typeof identity.boot !== "string")
		throw new Error("Invalid saved process identity");
	const current = await processIdentity(value.pid);
	return current !== null && current.start === value.start && current.boot === value.boot;
}

export async function savedState(dir: string): Promise<BrokerState | null> {
	try {
		const state = object(await readJson(path.join(dir, "state.json")));
		if (
			state.schema !== 1 ||
			!["stopped", "starting", "running", "stopping", "unknown"].includes(String(state.state)) ||
			(state.accelerator !== "kvm" && state.accelerator !== null)
		)
			throw new Error("Invalid broker state");
		runId(state.generation);
		object(state.broker);
		if (state.vm !== null) object(state.vm);
		return state as unknown as BrokerState;
	} catch (error) {
		if (isEnoent(error)) return null;
		throw error;
	}
}

export interface CaptureRecord {
	schema: 1;
	/** Original guest assertion, retained separately from host durability. */
	guest: RunSnapshot;
	/** Public view: outputBytes names only fsynced host bytes. */
	run: RunSnapshot;
}

export class CaptureStore {
	constructor(
		readonly dir: string,
		readonly project: string,
	) {}
	#file(id: string, extension: string): string {
		return path.join(this.dir, `${runId(id)}.${extension}`);
	}
	async get(id: string): Promise<CaptureRecord | null> {
		let value: unknown;
		try {
			value = await readJson(this.#file(id, "json"));
		} catch (error) {
			if (isEnoent(error)) return null;
			throw error;
		}
		const record = object(value);
		if (record.schema !== 1) throw new Error("Invalid capture schema");
		const guest = validateRun(record.guest, this.project);
		const run = validateRun(record.run, this.project);
		if (
			guest.id !== id ||
			run.id !== id ||
			guest.generation !== run.generation ||
			run.outputBytes > guest.outputBytes ||
			(run.captureComplete && (!guest.captureComplete || run.outputBytes !== guest.outputBytes))
		)
			throw new Error("Invalid durable capture record");
		await regularFile(this.#file(id, "bin"), true);
		const size = (await fs.stat(this.#file(id, "bin"))).size;
		if (size < run.outputBytes) throw new Error("Durable capture missing bytes");
		if (run.captureComplete && size !== run.outputBytes) throw new Error("Complete capture has an unexpected tail");
		return { schema: 1, guest, run };
	}
	async list(): Promise<CaptureRecord[]> {
		const records: CaptureRecord[] = [];
		for (const name of await fs.readdir(this.dir)) {
			if (!name.endsWith(".json")) continue;
			const record = await this.get(name.slice(0, -5));
			if (record) records.push(record);
		}
		return records.sort((left, right) => left.run.startedAt.localeCompare(right.run.startedAt));
	}
	async #appendJournal(id: string, event: Record<string, unknown>): Promise<void> {
		const file = this.#file(id, "journal.jsonl");
		try {
			await regularFile(file, true);
		} catch (error) {
			if (!isEnoent(error)) throw error;
		}
		const handle = await fs.open(
			file,
			fs.constants.O_RDWR | fs.constants.O_APPEND | fs.constants.O_CREAT | fs.constants.O_NOFOLLOW,
			0o600,
		);
		try {
			const size = (await handle.stat()).size;
			if (size) {
				const tail = Buffer.alloc(1);
				const result = await handle.read(tail, 0, 1, size - 1);
				if (result.bytesRead !== 1 || tail[0] !== 10)
					throw new Error("Capture journal has an incomplete tail; recovery is required");
			}
			await handle.writeFile(`${JSON.stringify(event)}\n`);
			await handle.sync();
		} finally {
			await handle.close();
		}
		await syncDirectory(this.dir);
	}
	async observe(value: unknown): Promise<CaptureRecord> {
		const guest = validateRun(value, this.project);
		const previous = await this.get(guest.id);
		if (
			previous &&
			(previous.guest.generation !== guest.generation ||
				previous.guest.actor !== guest.actor ||
				previous.guest.kind !== guest.kind ||
				previous.guest.startedAt !== guest.startedAt ||
				guest.outputBytes < previous.guest.outputBytes ||
				guest.ownerEpoch < previous.guest.ownerEpoch ||
				(previous.guest.captureComplete &&
					(!guest.captureComplete || guest.outputBytes !== previous.guest.outputBytes)) ||
				(previous.guest.cancelRequested && !guest.cancelRequested) ||
				(previous.guest.state !== "running" &&
					previous.guest.state !== "unknown" &&
					previous.guest.state !== guest.state &&
					guest.state !== "unknown"))
		)
			throw new Error("Guest run identity/state regressed");
		if (!previous) {
			const file = this.#file(guest.id, "bin");
			try {
				await regularFile(file, true);
			} catch (error) {
				if (!isEnoent(error)) throw error;
			}
			const handle = await fs.open(
				file,
				fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_NOFOLLOW,
				0o600,
			);
			try {
				await handle.sync();
			} finally {
				await handle.close();
			}
			await syncDirectory(this.dir);
		}
		const outputBytes = previous?.run.outputBytes ?? 0;
		const run = {
			...guest,
			outputBytes,
			captureComplete: guest.captureComplete && outputBytes === guest.outputBytes,
		};
		if (run.captureComplete && (await fs.stat(this.#file(guest.id, "bin"))).size !== outputBytes)
			throw new Error("Final capture length differs from durable original bytes");
		const record: CaptureRecord = { schema: 1, guest, run };
		if (JSON.stringify(previous) !== JSON.stringify(record)) {
			await this.#appendJournal(guest.id, {
				event: "state",
				at: new Date().toISOString(),
				guest,
				capturedBytes: outputBytes,
				hostComplete: run.captureComplete,
			});
			await durableJson(this.#file(guest.id, "json"), record);
		}
		return record;
	}
	async append(output: RunOutput): Promise<CaptureRecord> {
		const checked = validateOutput(output, this.project, output.run.id, output.offset);
		const previous = await this.observe(checked.run);
		if (previous.run.outputBytes !== checked.offset) throw new Error("Host capture offset mismatch");
		const bytes = originalBytes(checked.data);
		if (bytes.length > 0) {
			const file = this.#file(checked.run.id, "bin");
			try {
				await regularFile(file, true);
			} catch (error) {
				if (!isEnoent(error)) throw error;
			}
			const handle = await fs.open(
				file,
				fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_NOFOLLOW,
				0o600,
			);
			try {
				const size = (await handle.stat()).size;
				if (size < checked.offset) throw new Error("Durable capture was truncated");
				if (checked.run.captureComplete && size > checked.run.outputBytes)
					throw new Error("Guest final output conflicts with durable original bytes");
				// A crash can leave an fsynced tail before metadata publication. Preserve it and
				// require byte-for-byte agreement before making a new reference to that prefix.
				const overlap = Math.min(size - checked.offset, bytes.length);
				const existing = Buffer.alloc(overlap);
				let consumed = 0;
				while (consumed < overlap) {
					const result = await handle.read(existing, consumed, overlap - consumed, checked.offset + consumed);
					if (!result.bytesRead) throw new Error("Durable capture was truncated");
					consumed += result.bytesRead;
				}
				if (!existing.equals(bytes.subarray(0, overlap)))
					throw new Error("Guest replay differs from durable original bytes");
				let written = overlap;
				while (written < bytes.length) {
					const result = await handle.write(bytes, written, bytes.length - written, checked.offset + written);
					if (result.bytesWritten === 0) throw new Error("Capture write made no progress");
					written += result.bytesWritten;
				}
				await handle.sync();
			} finally {
				await handle.close();
			}
			await syncDirectory(this.dir);
		}
		const record: CaptureRecord = {
			schema: 1,
			guest: checked.run,
			run: {
				...checked.run,
				outputBytes: checked.nextOffset,
				captureComplete: checked.run.captureComplete && checked.nextOffset === checked.run.outputBytes,
			},
		};
		await this.#appendJournal(checked.run.id, {
			event: "capture",
			at: new Date().toISOString(),
			offset: checked.offset,
			nextOffset: checked.nextOffset,
			sha256: new Bun.CryptoHasher("sha256").update(bytes).digest("hex"),
			guestComplete: checked.run.captureComplete,
			hostComplete: record.run.captureComplete,
		});
		await durableJson(this.#file(checked.run.id, "json"), record);
		return record;
	}
	async read(id: string, offset = 0): Promise<RunOutput> {
		integer(offset, 0, Number.MAX_SAFE_INTEGER);
		const record = await this.get(id);
		if (!record) throw new Error("Unknown run");
		if (offset > record.run.outputBytes) throw new Error("Offset exceeds durable host capture");
		const length = Math.min(OUTPUT_CHUNK, record.run.outputBytes - offset);
		const bytes = Buffer.alloc(length);
		if (length > 0) {
			await regularFile(this.#file(id, "bin"), true);
			const handle = await fs.open(this.#file(id, "bin"), fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
			try {
				let consumed = 0;
				while (consumed < length) {
					const result = await handle.read(bytes, consumed, length - consumed, offset + consumed);
					if (!result.bytesRead) throw new Error("Durable capture missing bytes");
					consumed += result.bytesRead;
				}
			} finally {
				await handle.close();
			}
		}
		return { run: record.run, offset, nextOffset: offset + length, data: bytes.toString("base64") };
	}
	async interrupted(): Promise<void> {
		for (const record of await this.list()) {
			if (record.run.state !== "running") continue;
			record.run = { ...record.run, state: "unknown", captureComplete: false };
			await this.#appendJournal(record.run.id, { event: "host-interrupted", at: new Date().toISOString() });
			await durableJson(this.#file(record.run.id, "json"), record);
		}
	}
}

export async function offlineStatus(dir: string): Promise<WorkspaceStatus> {
	const project = await loadProject(dir);
	const state = await savedState(dir);
	const uncertain = state !== null && ((await identityAlive(state.broker)) || (await identityAlive(state.vm)));
	const records = await new CaptureStore(path.join(dir, "captures"), project.id).list();
	return {
		project,
		generation: state?.generation ?? null,
		state: uncertain ? "unknown" : "stopped",
		accelerator: null,
		runs: records.map(({ run }) =>
			run.state === "running" ? { ...run, state: "unknown", captureComplete: false } : run,
		),
	};
}

type ManagedProcess = Subprocess<"ignore", "pipe", "pipe">;

export interface TerminableProcess {
	readonly exited: Promise<number>;
	readonly exitCode: number | null;
	readonly signalCode: string | null;
	kill(signal: "SIGTERM" | "SIGKILL"): void;
}

export function processExited(child: Pick<TerminableProcess, "exitCode" | "signalCode">): boolean {
	// Bun leaves exitCode null when a signal terminates the process.
	return child.exitCode !== null || child.signalCode !== null;
}

export async function terminateVm(child: TerminableProcess, graceMs = 2000, killMs = 2000): Promise<void> {
	if (processExited(child)) return;
	child.kill("SIGTERM");
	await Promise.race([child.exited, Bun.sleep(graceMs)]);
	if (processExited(child)) return;
	child.kill("SIGKILL");
	await Promise.race([child.exited, Bun.sleep(killMs)]);
	if (!processExited(child)) throw new Error("VM termination could not be confirmed");
}

async function processResult(command: string[], dir: string, timeoutMs = 15000): Promise<string> {
	const child = Bun.spawn(command, {
		cwd: dir,
		env: cleanEnvironment(dir),
		stdin: "ignore",
		stdout: "pipe",
		stderr: "pipe",
	});
	let total = 0;
	let failure: Error | null = null;
	const timer = setTimeout(() => {
		failure = new Error("Runtime command timed out");
		child.kill("SIGKILL");
	}, timeoutMs);
	async function read(stream: ReadableStream<Uint8Array>): Promise<string> {
		const chunks: Uint8Array[] = [];
		for await (const chunk of stream) {
			total += chunk.length;
			if (total > MAX_JSON_BYTES) {
				failure = new Error("Runtime command output exceeded bound");
				child.kill("SIGKILL");
				break;
			}
			chunks.push(chunk);
		}
		return Buffer.concat(chunks).toString("utf8");
	}
	try {
		const [code, stdout] = await Promise.all([child.exited, read(child.stdout), read(child.stderr)]);
		if (failure) throw failure;
		if (code !== 0) throw new Error(`Confined runtime command failed (${code})`);
		return stdout;
	} finally {
		clearTimeout(timer);
	}
}

// libslirp starts this fixed program per TCP connection. No guest bytes become argv,
// paths or commands; its only peer is the operator-configured Unix target relay.
const TARGET_RELAY = Buffer.from(String.raw`import os
import socket
import sys
import threading

peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
peer.connect("/vm/target.sock")

def upload():
    try:
        while data := os.read(0, 65536):
            peer.sendall(data)
        peer.shutdown(socket.SHUT_WR)
    except OSError:
        try:
            peer.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

threading.Thread(target=upload, daemon=True).start()
try:
    while data := peer.recv(65536):
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
except (BrokenPipeError, ConnectionResetError):
    pass
finally:
    peer.close()
`);

async function sandboxPrefix(project: ProjectManifest, dir: string, bwrap: string, kvm: boolean): Promise<string[]> {
	const args = [
		bwrap,
		"--unshare-all",
		"--die-with-parent",
		"--new-session",
		"--cap-drop",
		"ALL",
		"--clearenv",
		"--setenv",
		"PATH",
		"/runtime",
		"--setenv",
		"HOME",
		"/nonexistent",
		"--setenv",
		"LANG",
		"C.UTF-8",
		"--proc",
		"/proc",
		"--dev",
		"/dev",
		"--tmpfs",
		"/tmp",
		"--dir",
		"/runtime",
		"--dir",
		"/base",
		"--dir",
		"/disk",
		"--dir",
		"/vm",
	];
	// Runtime libraries only. No /, home, /etc, /usr/bin, project evidence, or broker socket mount.
	for (const lib of ["/usr/lib", "/usr/lib64", "/lib", "/lib64"]) {
		try {
			const source = await fs.realpath(lib);
			const stat = await fs.stat(source);
			if (!stat.isDirectory() || stat.uid !== 0 || (stat.mode & 0o022) !== 0)
				throw new Error("Unsafe system library directory");
			args.push("--ro-bind", source, lib);
		} catch (error) {
			if (!isEnoent(error)) throw error;
		}
	}
	args.push(
		"--ro-bind",
		project.runtime.qemu.binary,
		"/runtime/qemu",
		"--ro-bind",
		project.runtime.qemu.imageBinary,
		"/runtime/qemu-img",
		"--ro-bind",
		project.runtime.qemu.firmwareDir,
		"/runtime/firmware",
		"--ro-bind",
		project.image.disk.path,
		"/base/base.qcow2",
		"--bind",
		path.join(dir, "disk"),
		"/disk",
		"--bind",
		path.join(dir, "vm"),
		"/vm",
		"--chdir",
		"/vm",
	);
	if (project.runtime.qemu.libraryDir)
		args.push(
			"--ro-bind",
			project.runtime.qemu.libraryDir,
			"/runtime/lib",
			"--setenv",
			"LD_LIBRARY_PATH",
			"/runtime/lib",
		);
	if (kvm) args.push("--dev-bind", "/dev/kvm", "/dev/kvm");
	if (kvm && project.runtime.hostTargetPort !== undefined) {
		const python = await fs.realpath("/usr/bin/python3");
		await regularFile(python);
		const stat = await fs.stat(python);
		if (stat.uid !== 0 || (stat.mode & 0o022) !== 0) throw new Error("Unsafe system Python executable");
		args.push("--ro-bind", python, "/runtime/python", "--ro-bind-data", "0", "/runtime/target-relay.py");
	}
	return args;
}

export function qemuArguments(project: ProjectManifest): string[] {
	// libslirp's fixed per-connection helper calls setsid(), which QEMU puts in
	// its privilege-syscall group. Bubblewrap already enforces no_new_privs and
	// zero capabilities; only the explicit target relay needs this group enabled.
	const args = [
		"/runtime/qemu",
		"-name",
		"agent-smith",
		"-nodefaults",
		"-no-user-config",
		"-display",
		"none",
		"-monitor",
		"none",
		"-serial",
		"none",
		"-parallel",
		"none",
		"-accel",
		"kvm",
		"-machine",
		"q35",
		"-cpu",
		"host",
		"-m",
		String(project.runtime.memoryMiB),
		"-smp",
		String(project.runtime.cpus),
		"-L",
		"/runtime/firmware",
		"-sandbox",
		project.runtime.hostTargetPort === undefined
			? "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny"
			: "on,obsolete=deny,elevateprivileges=allow,spawn=allow,resourcecontrol=deny",
		"-drive",
		"file=/disk/root.qcow2,if=virtio,format=qcow2,cache=none,aio=threads",
		"-qmp",
		"unix:/vm/qmp.sock,server=on,wait=off",
		"-chardev",
		"socket,id=control,path=/vm/control.sock,server=on,wait=off",
		"-device",
		"virtio-serial-pci",
		"-device",
		"virtserialport,chardev=control,name=org.arkensec.smith",
		"-fw_cfg",
		"name=opt/agent-smith/config,file=/vm/boot.json",
	];
	let network = "user,id=net0,restrict=on,ipv6=off";
	if (project.runtime.hostTargetPort !== undefined) {
		integer(project.runtime.hostTargetPort, 1, 65535);
		network += ",guestfwd=tcp:10.0.2.100:8080-cmd:/runtime/python -I -S /runtime/target-relay.py";
	}
	args.push("-netdev", network, "-device", "virtio-net-pci,netdev=net0");
	return args;
}

export function validateDiskChain(value: unknown, overlay: boolean): void {
	if (!Array.isArray(value) || value.length !== (overlay ? 2 : 1)) throw new Error("Unexpected qcow2 backing chain");
	for (const item of value) {
		const disk = object(item);
		const specific = disk["format-specific"] === undefined ? {} : object(disk["format-specific"]);
		const data = specific.data === undefined ? {} : object(specific.data);
		if (
			disk.format !== "qcow2" ||
			disk.corrupt === true ||
			disk.encrypted === true ||
			disk["data-file"] !== undefined ||
			data["data-file"] !== undefined ||
			data.encrypt !== undefined
		)
			throw new Error("External, encrypted or corrupt qcow2 data refused");
	}
	const base = object(value[value.length - 1]);
	if (base["backing-filename"] !== undefined) throw new Error("Base must be a standalone qcow2 image");
	if (overlay) {
		const disk = object(value[0]);
		if (
			disk["backing-filename"] !== "/base/base.qcow2" ||
			disk["backing-filename-format"] !== "qcow2" ||
			(disk["full-backing-filename"] !== undefined && disk["full-backing-filename"] !== "/base/base.qcow2")
		)
			throw new Error("Unexpected overlay backing image");
	}
}

export class Qmp {
	#hello = Promise.withResolvers<void>();
	#helloTimer: Timer;
	readonly peer: JsonPeer;
	constructor(socketPath: string) {
		this.#helloTimer = setTimeout(() => this.#hello.reject(new Error("QMP greeting timed out")), 5000);
		// Attach immediately, even if connect fails before the greeting wait begins.
		void this.#hello.promise.catch(() => {});
		this.peer = new JsonPeer(socketPath, message => {
			if (message.QMP) {
				clearTimeout(this.#helloTimer);
				this.#hello.resolve();
			} else if (typeof message.event !== "string") throw new Error("Invalid QMP event");
		});
	}
	async initialize(): Promise<void> {
		await this.peer.ready;
		await this.#hello.promise;
		await this.execute("qmp_capabilities");
	}
	async execute(command: "qmp_capabilities" | "query-kvm"): Promise<unknown> {
		const response = await this.peer.request({ execute: command, id: crypto.randomUUID() }, 5000);
		if (response.error || !("return" in response)) throw new Error(`QMP ${command} failed`);
		return response.return;
	}
	async assertKvm(): Promise<void> {
		const result = object(await this.execute("query-kvm"));
		if (result.enabled !== true || result.present !== true) throw new Error("QMP did not confirm active KVM");
	}
	close(): void {
		clearTimeout(this.#helloTimer);
		this.#hello.reject(new Error("QMP closed"));
		this.peer.close();
	}
}

async function socketReady(file: string, child: ManagedProcess, deadline: number): Promise<void> {
	while (Date.now() < deadline) {
		if (processExited(child)) throw new Error("Confined QEMU exited during startup");
		try {
			const stat = await fs.lstat(file);
			if (!stat.isSocket() || stat.uid !== process.getuid?.()) throw new Error("Unsafe VM socket");
			return;
		} catch (error) {
			if (!isEnoent(error)) throw error;
		}
		await Bun.sleep(100);
	}
	throw new Error("VM socket startup timed out");
}

async function listen(server: net.Server, socket: string): Promise<void> {
	const ready = Promise.withResolvers<void>();
	server.once("error", ready.reject);
	server.listen(socket, () => ready.resolve());
	await ready.promise;
	server.off("error", ready.reject);
	await fs.chmod(socket, 0o600);
}

/** Loopback-only operator target relay. Guest data is never interpreted as a host command or path. */
export async function targetRelay(dir: string, port: number): Promise<{ close(): void }> {
	integer(port, 1, 65535);
	const connections = new Set<net.Socket>();
	const server = net.createServer({ allowHalfOpen: true }, guest => {
		if (connections.size + 2 > 8) {
			guest.destroy();
			return;
		}
		const target = net.createConnection({ host: "127.0.0.1", port, allowHalfOpen: true });
		connections.add(guest);
		connections.add(target);
		const close = () => {
			guest.destroy();
			target.destroy();
		};
		guest.on("error", close);
		target.on("error", close);
		// Normal half-close must drain the opposite direction, not destroy its
		// buffered response. Cross-destroy is only for failure or explicit teardown.
		guest.on("close", () => connections.delete(guest));
		target.on("close", () => connections.delete(target));
		guest.setTimeout(60000, close);
		target.setTimeout(60000, close);
		guest.pipe(target);
		target.pipe(guest);
	});
	await listen(server, path.join(dir, "vm", "target.sock"));
	return {
		close() {
			server.close();
			for (const socket of connections) socket.destroy();
		},
	};
}

/** All mutations (including capture polling) pass through one queue. */
export async function serveWorkspace(projectDir: string): Promise<void> {
	assertLinux();
	absolutePath(projectDir);
	const project = await loadProject(projectDir);
	const lease = await acquireFileLock(path.join(projectDir, "broker"), { retries: 1 });
	const previousUmask = process.umask(0o077);
	const captures = new CaptureStore(path.join(projectDir, "captures"), project.id);
	let qemu: ManagedProcess | undefined;
	let qmp: Qmp | undefined;
	let guest: GuestTransport | undefined;
	let relay: { close(): void } | undefined;
	let server: net.Server | undefined;
	let state: BrokerState | undefined;
	let shutdown: Promise<WorkspaceStatus> | undefined;
	let poll: Timer | undefined;
	let hardStop: Timer | undefined;
	let stopping = false;
	const finished = Promise.withResolvers<void>();
	void finished.promise.catch(() => {});
	const cleaned = Promise.withResolvers<void>();
	let unregisterShutdown: (() => void) | undefined;
	const sockets = new Set<net.Socket>();
	let queue: Promise<unknown> = Promise.resolve();
	function serial<T>(work: () => Promise<T>): Promise<T> {
		const result = queue.then(work);
		queue = result.catch(() => {});
		return result;
	}
	async function save(): Promise<void> {
		if (state) await durableJson(path.join(projectDir, "state.json"), state);
	}
	async function status(): Promise<WorkspaceStatus> {
		const result: WorkspaceStatus = {
			project,
			state: state?.state ?? "unknown",
			generation: state?.generation ?? null,
			accelerator: state?.state === "running" ? state.accelerator : null,
			runs: (await captures.list()).map(record => record.run),
		};
		if (Buffer.byteLength(JSON.stringify(result)) > MAX_JSON_BYTES - 1024) {
			result.runs = result.runs.map(run => {
				const { mcpResult, ...snapshot } = run;
				return mcpResult === undefined
					? snapshot
					: { ...snapshot, mcpResult: { inline: false, availableVia: "readRun" } };
			});
		}
		return result;
	}
	async function captureRun(snapshot: RunSnapshot, chunks = 4): Promise<RunSnapshot> {
		let record = await captures.observe(snapshot);
		for (let index = 0; index < chunks && record.run.outputBytes < record.guest.outputBytes; index++) {
			if (!guest) throw new Error("Guest transport unavailable");
			const output = validateOutput(
				await guest.request("read", { id: snapshot.id, offset: record.run.outputBytes, limit: OUTPUT_CHUNK }),
				project.id,
				snapshot.id,
				record.run.outputBytes,
			);
			if (output.nextOffset === output.offset) throw new Error("Guest output stalled before advertised end");
			record = await captures.append(output);
		}
		return record.run;
	}
	let captureCursor = 0;
	async function refresh(): Promise<void> {
		if (!guest) throw new Error("Guest transport unavailable");
		const list = await guest.request("list");
		if (!Array.isArray(list) || list.length > 2048) throw new Error("Invalid guest run list");
		const seen = new Set<string>();
		const deadline = Date.now() + 1000;
		const rotated = [...list.slice(captureCursor), ...list.slice(0, captureCursor)];
		captureCursor = list.length ? (captureCursor + 1) % list.length : 0;
		for (const value of rotated) {
			const run = validateRun(value, project.id);
			if (seen.has(run.id)) throw new Error("Duplicate guest run identifier");
			seen.add(run.id);
			// State is always retained; a later poll drains any remaining advertised bytes.
			await captureRun(run, Date.now() < deadline ? 1 : 0);
		}
	}
	function armStop(): void {
		stopping = true;
		clearTimeout(poll);
		if (!hardStop)
			hardStop = setTimeout(() => {
				guest?.close();
				qmp?.close();
				if (qemu && !processExited(qemu)) qemu.kill("SIGKILL");
			}, 32000);
	}
	async function stop(): Promise<WorkspaceStatus> {
		if (shutdown) return shutdown;
		armStop();
		shutdown = (async () => {
			let failure: unknown;
			try {
				if (state) {
					state.state = "stopping";
					await save();
				}
				const deadline = Date.now() + 8000;
				if (guest) {
					try {
						// Cancellation intent stays distinct from the guest's eventual terminal outcome.
						for (const { run } of await captures.list())
							if (run.state === "running" && run.generation === state?.generation) {
								await guest.request("cancel", { id: run.id }, Math.max(1, deadline - Date.now()));
								if (Date.now() >= deadline) break;
							}
						while (Date.now() < deadline) {
							await refresh();
							if (
								(await captures.list()).every(
									record =>
										record.run.generation !== state?.generation ||
										(record.run.state !== "running" && record.run.captureComplete),
								)
							)
								break;
							await Bun.sleep(100);
						}
					} catch {
						/* The interruption record below preserves incomplete capture. */
					}
				}
				// Ask the authenticated guest OS to shut down, not its desktop
				// power-button policy. Keep the channel open until observed VM exit.
				if (qemu && !processExited(qemu)) {
					let poweroffRequestError: unknown;
					try {
						if (!guest) throw new Error("Authenticated guest shutdown control is unavailable");
						const requested = object(await guest.request("poweroff", {}, 5000));
						if (requested.requested !== true) throw new Error("Guest did not accept poweroff");
					} catch (error) {
						poweroffRequestError = error;
					}
					let powerOffTimer: Timer | undefined;
					try {
						await Promise.race([
							qemu.exited,
							new Promise<void>(resolve => {
								powerOffTimer = setTimeout(resolve, 15000);
							}),
						]);
					} finally {
						clearTimeout(powerOffTimer);
					}
					// A fast shutdown can close the channel before its receipt arrives.
					// Only normal process exit establishes success, never request acceptance.
					if (!processExited(qemu))
						failure = new Error("Guest power-off was not observed; forced VM termination was required", {
							cause: poweroffRequestError,
						});
					else if (qemu.exitCode !== 0)
						failure = new Error("VM exited abnormally during guest poweroff", { cause: poweroffRequestError });
				}
			} catch (error) {
				failure = error;
			}
			guest?.close();
			try {
				if (qemu) await terminateVm(qemu);
			} catch (error) {
				const failures = failure === undefined ? [error] : [failure, error];
				if (state) {
					state.state = "unknown";
					state.accelerator = null;
					try {
						await save();
					} catch (saveError) {
						failures.push(saveError);
					}
				}
				throw new AggregateError(failures, "Could not observe VM termination");
			} finally {
				clearTimeout(hardStop);
			}
			await captures.interrupted();
			if (state) {
				state.state = "stopped";
				state.accelerator = null;
				await save();
			}
			if (failure) throw failure;
			return status();
		})();
		return shutdown;
	}
	const onSignal = () => {
		armStop();
		void serial(stop).then(
			() => finished.resolve(),
			error => finished.reject(error),
		);
	};
	try {
		const previous = await savedState(projectDir);
		if (previous && ((await identityAlive(previous.broker)) || (await identityAlive(previous.vm))))
			throw new Error("A recorded broker/VM is still alive; refusing a second VM");
		const pins = await validateRuntime(project.runtime, project.image);
		const expected = object(await readJson(path.join(projectDir, "runtime-pins.json")));
		function sorted(value: unknown): string {
			if (value === null) return "null";
			return JSON.stringify(Object.entries(object(value)).sort(([left], [right]) => left.localeCompare(right)));
		}
		if (sorted(pins.firmware) !== sorted(expected.firmware) || sorted(pins.libraries) !== sorted(expected.libraries))
			throw new Error("Firmware/library directory pins changed");
		const kvm = await fs.open("/dev/kvm", fs.constants.O_RDWR | fs.constants.O_NOFOLLOW);
		try {
			if (!(await kvm.stat()).isCharacterDevice()) throw new Error("/dev/kvm is not a device");
		} finally {
			await kvm.close();
		}
		const found = $which("bwrap", { PATH: "/usr/bin:/bin" });
		if (!found) throw new Error("bubblewrap is required");
		const bwrap = await fs.realpath(found);
		await regularFile(bwrap);
		const prefix = await sandboxPrefix(project, projectDir, bwrap, false);
		// This actually enters unprivileged user, mount, PID and network namespaces.
		await processResult([...prefix, "--", "/runtime/qemu-img", "--version"], projectDir);
		const info = JSON.parse(
			await processResult(
				[...prefix, "--", "/runtime/qemu-img", "info", "--output=json", "--backing-chain", "/base/base.qcow2"],
				projectDir,
			),
		) as unknown;
		validateDiskChain(info, false);
		const disk = path.join(projectDir, "disk", "root.qcow2");
		try {
			await regularFile(disk, true);
		} catch (error) {
			if (!isEnoent(error)) throw error;
			await processResult(
				[
					...prefix,
					"--",
					"/runtime/qemu-img",
					"create",
					"-f",
					"qcow2",
					"-F",
					"qcow2",
					"-b",
					"/base/base.qcow2",
					"/disk/root.qcow2",
				],
				projectDir,
			);
			await fs.chmod(disk, 0o600);
			const handle = await fs.open(disk, "r+");
			try {
				await handle.sync();
			} finally {
				await handle.close();
			}
			await syncDirectory(path.dirname(disk));
		}
		const chain = JSON.parse(
			await processResult(
				[...prefix, "--", "/runtime/qemu-img", "info", "--output=json", "--backing-chain", "/disk/root.qcow2"],
				projectDir,
			),
		) as unknown;
		validateDiskChain(chain, true);
		await captures.interrupted();
		for (const name of ["broker.sock", "vm/qmp.sock", "vm/control.sock", "vm/target.sock"]) {
			const file = path.join(projectDir, name);
			try {
				const stat = await fs.lstat(file);
				if (!stat.isSocket() || stat.uid !== process.getuid?.()) throw new Error("Unsafe stale socket");
				await fs.unlink(file);
			} catch (error) {
				if (!isEnoent(error)) throw error;
			}
		}
		const broker = await processIdentity(process.pid);
		if (!broker) throw new Error("Cannot establish broker identity");
		state = { schema: 1, generation: crypto.randomUUID(), state: "starting", accelerator: null, broker, vm: null };
		await save();
		const token = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("hex");
		await durableJson(path.join(projectDir, "vm", "boot.json"), {
			project: project.id,
			generation: state.generation,
			token,
		});
		if (project.runtime.hostTargetPort !== undefined)
			relay = await targetRelay(projectDir, project.runtime.hostTargetPort);
		qemu = Bun.spawn([...(await sandboxPrefix(project, projectDir, bwrap, true)), "--", ...qemuArguments(project)], {
			cwd: projectDir,
			env: cleanEnvironment(projectDir),
			stdin: project.runtime.hostTargetPort === undefined ? "ignore" : TARGET_RELAY,
			stdout: "pipe",
			stderr: "pipe",
		});
		state.vm = await processIdentity(qemu.pid);
		if (!state.vm) throw new Error("QEMU exited before identity was recorded");
		await save();
		// Keep bounded VM diagnostics in the private broker log, not guest run evidence.
		for (const stream of [qemu.stdout, qemu.stderr])
			void (async () => {
				let total = 0;
				for await (const bytes of stream) {
					total += bytes.length;
					if (total > MAX_JSON_BYTES) {
						qemu?.kill("SIGKILL");
						throw new Error("QEMU diagnostics exceeded bound");
					}
					process.stderr.write(bytes);
				}
			})().catch(error => {
				logger.error("Workspace VM diagnostic failure", { error: String(error) });
				onSignal();
			});
		unregisterShutdown = postmortem.register(
			"workspace-broker",
			() => {
				onSignal();
				return cleaned.promise;
			},
			{ exitOnly: true, minimumDeadlineMs: 35000 },
		);
		const deadline = Date.now() + 90000;
		await socketReady(path.join(projectDir, "vm", "qmp.sock"), qemu, deadline);
		await fs.chmod(path.join(projectDir, "vm", "qmp.sock"), 0o600);
		qmp = new Qmp(path.join(projectDir, "vm", "qmp.sock"));
		await qmp.initialize();
		await qmp.assertKvm();
		await socketReady(path.join(projectDir, "vm", "control.sock"), qemu, deadline);
		await fs.chmod(path.join(projectDir, "vm", "control.sock"), 0o600);
		// One authenticated channel. A timed-out start/input is never replayed.
		while (Date.now() < deadline) {
			guest = new GuestTransport(path.join(projectDir, "vm", "control.sock"), project.id, state.generation, token);
			try {
				const pong = object(await guest.request("ping", {}, Math.min(5000, Math.max(1, deadline - Date.now()))));
				if (pong.ready !== true) throw new Error("Guest supervisor is not ready");
				break;
			} catch {
				guest.close();
				guest = undefined;
			}
			if (processExited(qemu)) throw new Error("QEMU exited before guest readiness");
			await Bun.sleep(250);
		}
		if (!guest) throw new Error("Authenticated guest readiness timed out");
		await refresh();
		await qmp.assertKvm();
		state.state = "running";
		state.accelerator = "kvm";
		await save();
		const auth = object(await readJson(path.join(projectDir, "client-token.json")));
		if (typeof auth.token !== "string" || !/^[0-9a-f]{64}$/.test(auth.token))
			throw new Error("Invalid private client token");
		const clientToken = auth.token;
		async function dispatch(message: Record<string, unknown>): Promise<unknown> {
			if (!state || !guest) throw new Error("Guest unavailable");
			const args = object(message.args);
			if (message.op === "status") return status();
			if (message.op === "read") {
				const id = runId(args.id);
				const offset = integer(args.offset ?? 0, 0, Number.MAX_SAFE_INTEGER);
				return captures.read(id, offset);
			}
			if (message.op === "stop") return stop();
			if (stopping || state.state !== "running") throw new Error("Workspace is not running");
			if (message.op === "start") {
				const request = validateRunRequest(args);
				const snapshot = validateRun(await guest.request("start", { ...request }), project.id);
				if (snapshot.generation !== state.generation || (await captures.get(snapshot.id)))
					throw new Error("Guest returned reused/stale run identity");
				return captureRun(snapshot);
			}
			const id = runId(args.id);
			const record = await captures.get(id);
			if (!record || record.run.generation !== state.generation || record.run.state !== "running")
				throw new Error("Run is terminal or belongs to a stale generation");
			let payload: Record<string, unknown> = { id };
			if (message.op === "input" || message.op === "resize") {
				const ownerEpoch = integer(args.ownerEpoch, 0, Number.MAX_SAFE_INTEGER);
				if (ownerEpoch !== record.run.ownerEpoch) throw new Error("Stale terminal ownership epoch");
				payload =
					message.op === "input"
						? { id, ownerEpoch, data: originalBytes(args.data).toString("base64") }
						: { id, ownerEpoch, rows: integer(args.rows, 1, 1000), cols: integer(args.cols, 1, 1000) };
			}
			if (message.op !== "input" && message.op !== "resize" && message.op !== "takeover" && message.op !== "cancel")
				throw new Error("Unknown workspace operation");
			const snapshot = validateRun(await guest.request(message.op, payload), project.id);
			if (snapshot.id !== id) throw new Error("Guest mutation response identity mismatch");
			return captureRun(snapshot);
		}
		server = net.createServer(socket => {
			if (sockets.size >= 32) {
				socket.destroy();
				return;
			}
			sockets.add(socket);
			let received = false;
			socket.setTimeout(45000, () => socket.destroy());
			const parser = new JsonLines(value => {
				if (received) throw new Error("One operation per private IPC connection");
				received = true;
				const message = object(value);
				const id = runId(message.id);
				if (message.v !== 1 || message.project !== project.id || !authenticatedToken(message.token, clientToken))
					throw new Error("Private IPC authentication failed");
				if (message.op === "stop") armStop();
				void serial(() => dispatch(message))
					.then(result => {
						const response = `${JSON.stringify({ v: 1, id, project: project.id, ok: true, result })}\n`;
						if (Buffer.byteLength(response) > MAX_JSON_BYTES) throw new Error("IPC response exceeded bound");
						socket.end(response);
						if (message.op === "stop") finished.resolve();
					})
					.catch(error => {
						// Only host-authored errors reach the local operator; the guest transport redacts its errors.
						const detail = error instanceof Error ? error.message : "Workspace operation failed";
						socket.end(
							`${JSON.stringify({ v: 1, id, project: project.id, ok: false, error: detail.slice(0, 1024) })}\n`,
						);
						if (message.op === "stop") finished.reject(error);
					});
			});
			socket.on("data", bytes => {
				try {
					if (typeof bytes === "string") throw new Error("Expected an unencoded IPC byte stream");
					parser.feed(bytes);
				} catch {
					socket.destroy();
				}
			});
			socket.on("error", () => socket.destroy());
			socket.on("close", () => sockets.delete(socket));
		});
		await listen(server, path.join(projectDir, "broker.sock"));
		server.on("error", error => finished.reject(error));
		void qemu.exited.then(() => {
			if (!stopping) onSignal();
		});
		function schedule(): void {
			poll = setTimeout(() => {
				void serial(async () => {
					if (!stopping) await refresh();
				}).then(
					() => {
						if (!stopping) schedule();
					},
					error => finished.reject(error),
				);
			}, 100);
		}
		schedule();
		await finished.promise;
	} finally {
		try {
			clearTimeout(poll);
			await queue;
			try {
				if (state) await stop();
			} finally {
				guest?.close();
				qmp?.close();
				relay?.close();
				server?.close();
				// Allow the final stop response to flush before dropping idle local connections.
				await Bun.sleep(25);
				for (const socket of sockets) socket.destroy();
				process.umask(previousUmask);
				lease.release();
			}
		} finally {
			unregisterShutdown?.();
			cleaned.resolve();
		}
	}
}

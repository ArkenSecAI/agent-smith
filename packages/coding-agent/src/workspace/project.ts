import * as fs from "node:fs/promises";
import * as path from "node:path";
import { isIP } from "node:net";
import { isEnoent } from "@oh-my-pi/pi-utils";
import { replaceFileAtomically } from "../utils/atomic-file";
import type { ImageManifest, ProjectManifest, WorkspaceExternalInference, WorkspaceRuntime } from "./contracts";

export const MAX_JSON_BYTES = 1024 * 1024;
export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH = /^[0-9a-f]{64}$/;

export function object(value: unknown): Record<string, unknown> {
	if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Expected an object");
	return value as Record<string, unknown>;
}

export function integer(value: unknown, min: number, max: number): number {
	if (typeof value !== "number" || !Number.isSafeInteger(value) || value < min || value > max) {
		throw new Error(`Expected integer in ${min}..${max}`);
	}
	return value;
}

export function runId(value: unknown): string {
	if (typeof value !== "string" || !UUID.test(value)) throw new Error("Invalid run identifier");
	return value;
}

export function absolutePath(value: unknown): string {
	if (
		typeof value !== "string" ||
		!path.isAbsolute(value) ||
		path.normalize(value) !== value ||
		/[\x00-\x1f,]/.test(value)
	) {
		throw new Error("Expected a normalized absolute path without control characters or commas");
	}
	if (value === "/") throw new Error("Refusing filesystem root");
	return value;
}

export function assertLinux(): void {
	if (process.platform !== "linux" || process.arch !== "x64")
		throw new Error("Workspace requires Linux x86-64 with KVM");
	if (process.getuid?.() === 0) throw new Error("Workspace must run as an unprivileged operator");
}

/** Refuse aliases and attacker-writable ancestors before opening operator-selected files. */
export async function safePath(file: string): Promise<void> {
	absolutePath(file);
	if ((await fs.realpath(file)) !== file) throw new Error(`Symlink/alias path refused: ${file}`);
	let parent = path.dirname(file);
	while (parent !== "/") {
		const stat = await fs.lstat(parent);
		if (stat.isSymbolicLink() || !stat.isDirectory()) throw new Error("Unsafe path ancestor");
		if ((stat.mode & 0o022) !== 0 && !(stat.uid === 0 && (stat.mode & 0o1000) !== 0)) {
			throw new Error(`Writable path ancestor refused: ${parent}`);
		}
		parent = path.dirname(parent);
	}
}

export async function privateDirectory(dir: string): Promise<void> {
	await safePath(dir);
	const stat = await fs.lstat(dir);
	if (!stat.isDirectory() || stat.uid !== process.getuid?.() || (stat.mode & 0o777) !== 0o700) {
		throw new Error(`Expected an owned 0700 directory: ${dir}`);
	}
}

export async function regularFile(file: string, owned = false): Promise<void> {
	await safePath(file);
	const stat = await fs.lstat(file);
	if (
		!stat.isFile() ||
		stat.nlink !== 1 ||
		(stat.mode & 0o022) !== 0 ||
		(owned && (stat.uid !== process.getuid?.() || (stat.mode & 0o077) !== 0))
	) {
		throw new Error(`Unsafe regular file: ${file}`);
	}
}

export async function readJson(file: string, owned = true): Promise<unknown> {
	await regularFile(file, owned);
	const handle = await fs.open(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
	try {
		const stat = await handle.stat();
		if (stat.size > MAX_JSON_BYTES) throw new Error("JSON file exceeds size limit");
		return JSON.parse(await handle.readFile({ encoding: "utf8" })) as unknown;
	} finally {
		await handle.close();
	}
}

export async function syncDirectory(dir: string): Promise<void> {
	const handle = await fs.open(dir, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
	try {
		await handle.sync();
	} finally {
		await handle.close();
	}
}

/** Publication is ordered after file fsync and followed by parent-directory fsync. */
export async function durableJson(file: string, value: unknown): Promise<void> {
	await privateDirectory(path.dirname(file));
	try {
		await regularFile(file, true);
	} catch (error) {
		if (!isEnoent(error)) throw error;
	}
	const bytes = `${JSON.stringify(value)}\n`;
	if (Buffer.byteLength(bytes) > MAX_JSON_BYTES) throw new Error("Durable JSON exceeds size limit");
	const temporary = `${file}.${crypto.randomUUID()}.tmp`;
	const handle = await fs.open(
		temporary,
		fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW,
		0o600,
	);
	try {
		await handle.writeFile(bytes);
		await handle.sync();
	} finally {
		await handle.close();
	}
	try {
		await replaceFileAtomically(temporary, file);
		await syncDirectory(path.dirname(file));
	} finally {
		await fs.unlink(temporary).catch(error => {
			if (!isEnoent(error)) throw error;
		});
	}
}

export async function hashFile(file: string): Promise<string> {
	await regularFile(file);
	const hasher = new Bun.CryptoHasher("sha256");
	const stream = Bun.file(file).stream();
	for await (const bytes of stream) hasher.update(bytes);
	return hasher.digest("hex");
}

export async function verifyPinnedFile(file: unknown, expected: unknown, immutable = false): Promise<void> {
	const name = absolutePath(file);
	if (typeof expected !== "string" || !HASH.test(expected)) throw new Error("Invalid SHA-256 pin");
	if (immutable && ((await fs.lstat(name)).mode & 0o222) !== 0)
		throw new Error("Base image must have no write permission bits");
	if ((await hashFile(name)) !== expected) throw new Error(`SHA-256 pin mismatch: ${name}`);
}

/** No DNS, credentials, query parameters, fragments, alternate schemes or redirects. */
export function validateInferenceUrl(value: string): URL {
	const url = new URL(value);
	if (
		url.protocol !== "http:" ||
		url.hostname !== "127.0.0.1" ||
		!url.port ||
		url.username ||
		url.password ||
		url.search ||
		url.hash ||
		url.pathname !== "/v1"
	)
		throw new Error("Inference URL must be an explicit IPv4 loopback /v1 endpoint");
	return url;
}

export function externalInferenceShape(value: unknown): WorkspaceExternalInference {
	const config = object(value);
	if (typeof config.baseUrl !== "string") throw new Error("Explicit external inference endpoint required");
	validateInferenceUrl(config.baseUrl);
	if (typeof config.modelId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,159}$/.test(config.modelId))
		throw new Error("Invalid external model identifier");
	integer(config.contextTokens, 4096, 131072);
	if (typeof config.thinking !== "string" || !["off", "low", "medium", "xhigh"].includes(config.thinking))
		throw new Error("External Qwen thinking must be off, low, medium or xhigh");
	const sampling = object(config.sampling);
	for (const [key, min, max] of [
		["temperature", 0, 2],
		["topP", 0, 1],
		["minP", 0, 1],
		["presencePenalty", -2, 2],
		["frequencyPenalty", -2, 2],
		["repeatPenalty", 0, 2],
	] as const) {
		const field = sampling[key];
		if (typeof field !== "number" || !Number.isFinite(field) || field < min || field > max)
			throw new Error(`Invalid external sampling ${key}`);
	}
	integer(sampling.topK, 0, 1_000_000);
	integer(sampling.seed, 0, 0xffff_ffff);
	const provenance = object(config.provenance);
	if (typeof provenance.profile !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/.test(provenance.profile))
		throw new Error("Explicit external profile name required");
	for (const key of ["modelSha256", "serverSha256", "templateSha256"])
		if (typeof provenance[key] !== "string" || !HASH.test(provenance[key]))
			throw new Error(`Invalid declared external ${key}`);
	return config as unknown as WorkspaceExternalInference;
}

export function runtimeShape(value: unknown): WorkspaceRuntime {
	const runtime = object(value);
	const qemu = object(runtime.qemu);
	if (runtime.schema !== 1) throw new Error("Unsupported runtime schema");
	for (const key of ["binary", "imageBinary", "firmwareDir"]) absolutePath(qemu[key]);
	if (qemu.libraryDir !== undefined) absolutePath(qemu.libraryDir);
	for (const key of ["sha256", "imageSha256"])
		if (typeof qemu[key] !== "string" || !HASH.test(qemu[key])) throw new Error("Invalid QEMU pin");
	absolutePath(runtime.imageManifest);
	integer(runtime.memoryMiB, 512, 65536);
	integer(runtime.cpus, 1, 64);
	if (runtime.hostTargetPort !== undefined) integer(runtime.hostTargetPort, 1, 65535);
	if (runtime.inference !== undefined && runtime.externalInference !== undefined)
		throw new Error("Select one inference source; managed and external cannot both be configured");
	if (runtime.externalInference !== undefined) externalInferenceShape(runtime.externalInference);
	if (runtime.inference !== undefined) {
		const inference = object(runtime.inference);
		absolutePath(inference.binary);
		absolutePath(inference.model);
		for (const key of ["sha256", "modelSha256"])
			if (typeof inference[key] !== "string" || !HASH.test(inference[key])) throw new Error("Invalid inference pin");
		if (typeof inference.modelId !== "string" || !inference.modelId)
			throw new Error("Explicit inference model required");
		integer(inference.contextTokens, 512, 131072);
		integer(inference.threads, 1, 64);
	}
	return runtime as unknown as WorkspaceRuntime;
}

function imageShape(value: unknown): ImageManifest {
	const image = object(value);
	if (
		image.schema !== 1 ||
		image.isa !== "x86_64" ||
		typeof image.id !== "string" ||
		!image.id ||
		typeof image.guestSha256 !== "string" ||
		!HASH.test(image.guestSha256)
	)
		throw new Error("Invalid image manifest");
	for (const key of ["disk", "packages", "provenance"]) {
		const entry = object(image[key]);
		absolutePath(entry.path);
		if (typeof entry.sha256 !== "string" || !HASH.test(entry.sha256)) throw new Error("Invalid image pin");
	}
	return image as unknown as ImageManifest;
}

export async function directoryPins(dir: string): Promise<Record<string, string>> {
	await safePath(dir);
	// Dedicated runtime directories only, never mount an operator's home or a system root.
	if (["/home", "/root", "/usr", "/etc", "/var", "/tmp", "/mnt"].includes(dir))
		throw new Error("Runtime directory is too broad");
	const pins: Record<string, string> = Object.create(null);
	let count = 0;
	// Member names are filesystem data, never interpolated into QEMU option strings.
	async function hashMember(file: string): Promise<string> {
		const handle = await fs.open(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
		try {
			const stat = await handle.stat();
			if (!stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o022) !== 0) throw new Error("Unsafe runtime file");
			const hasher = new Bun.CryptoHasher("sha256");
			for await (const bytes of handle.createReadStream({ autoClose: false })) hasher.update(bytes);
			return hasher.digest("hex");
		} finally {
			await handle.close();
		}
	}
	async function visit(current: string): Promise<void> {
		const stat = await fs.lstat(current);
		if (!stat.isDirectory() || (stat.mode & 0o022) !== 0) throw new Error("Unsafe asset directory");
		for (const entry of await fs.readdir(current, { withFileTypes: true })) {
			if (++count > 4096) throw new Error("Runtime tree exceeds bound");
			const file = path.join(current, entry.name);
			if (entry.isDirectory()) await visit(file);
			else if (entry.isSymbolicLink()) {
				const target = await fs.realpath(file);
				if (!target.startsWith(`${dir}/`)) throw new Error("Runtime symlink escapes the selected directory");
				for (let parent = path.dirname(target); parent !== dir; parent = path.dirname(parent)) {
					const ancestor = await fs.lstat(parent);
					if (!ancestor.isDirectory() || (ancestor.mode & 0o022) !== 0)
						throw new Error("Unsafe runtime symlink ancestor");
				}
				const link = await fs.readlink(file);
				if (path.isAbsolute(link)) throw new Error("Absolute runtime symlink refused");
				pins[path.relative(dir, file)] = `symlink:${link}:${await hashMember(target)}`;
			} else if (entry.isFile()) pins[path.relative(dir, file)] = await hashMember(file);
			else throw new Error("Special runtime file refused");
		}
	}
	await visit(dir);
	return pins;
}

export interface RuntimePins {
	firmware: Record<string, string>;
	libraries: Record<string, string> | null;
}

export async function validateRuntime(runtime: WorkspaceRuntime, image: ImageManifest): Promise<RuntimePins> {
	assertLinux();
	runtimeShape(runtime);
	imageShape(image);
	await verifyPinnedFile(runtime.qemu.binary, runtime.qemu.sha256);
	await verifyPinnedFile(runtime.qemu.imageBinary, runtime.qemu.imageSha256);
	await verifyPinnedFile(image.disk.path, image.disk.sha256, true);
	await verifyPinnedFile(image.packages.path, image.packages.sha256);
	await verifyPinnedFile(image.provenance.path, image.provenance.sha256);
	await fs.access(runtime.qemu.binary, fs.constants.X_OK);
	await fs.access(runtime.qemu.imageBinary, fs.constants.X_OK);
	return {
		firmware: await directoryPins(runtime.qemu.firmwareDir),
		libraries: runtime.qemu.libraryDir ? await directoryPins(runtime.qemu.libraryDir) : null,
	};
}

export function cleanEnvironment(dir: string): Record<string, string> {
	return {
		PATH: "/usr/bin:/bin",
		HOME: path.join(dir, "home"),
		XDG_CONFIG_HOME: path.join(dir, "home"),
		XDG_DATA_HOME: path.join(dir, "home"),
		XDG_CACHE_HOME: path.join(dir, "home"),
		XDG_STATE_HOME: path.join(dir, "home"),
		XDG_RUNTIME_DIR: path.join(dir, "vm"),
		TMPDIR: path.join(dir, "tmp"),
		LANG: "C.UTF-8",
		LC_ALL: "C.UTF-8",
		TERM: "dumb",
		NO_COLOR: "1",
		DO_NOT_TRACK: "1",
		GIT_CONFIG_NOSYSTEM: "1",
		GIT_CONFIG_GLOBAL: "/dev/null",
	};
}

export async function createProject(
	root: string,
	name: string,
	runtime: WorkspaceRuntime,
	targets: string[],
): Promise<string> {
	assertLinux();
	if (!/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,47}$/.test(name)) throw new Error("Invalid project name");
	if (
		!Array.isArray(targets) ||
		targets.length === 0 ||
		targets.length > 32 ||
		targets.some(target => typeof target !== "string" || isIP(target) !== 4)
	) {
		throw new Error("Targets must be explicit literal IPv4 guest addresses");
	}
	runtime = runtimeShape(runtime);
	const image = imageShape(await readJson(runtime.imageManifest, false));
	const pins = await validateRuntime(runtime, image);
	absolutePath(root);
	try {
		await fs.mkdir(root, { mode: 0o700 });
	} catch (error) {
		if (!(error instanceof Error && "code" in error && error.code === "EEXIST")) throw error;
	}
	await privateDirectory(root);
	const dir = path.join(root, name);
	if (Buffer.byteLength(path.join(dir, "vm", "control.sock")) > 100)
		throw new Error("Project path too long for private Unix sockets");
	await fs.mkdir(dir, { mode: 0o700 });
	for (const sub of ["vm", "captures", "home", "tmp", "disk"]) await fs.mkdir(path.join(dir, sub), { mode: 0o700 });
	const manifest: ProjectManifest = {
		schema: 1,
		id: crypto.randomUUID(),
		name,
		createdAt: new Date().toISOString(),
		image,
		runtime,
		targets: [...new Set(targets)],
	};
	await durableJson(path.join(dir, "runtime-pins.json"), pins);
	await durableJson(path.join(dir, "client-token.json"), {
		token: Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("hex"),
	});
	await durableJson(path.join(dir, "project.json"), manifest);
	await syncDirectory(root);
	return dir;
}

export async function loadProject(projectDir: string): Promise<ProjectManifest> {
	await privateDirectory(projectDir);
	const value = object(await readJson(path.join(projectDir, "project.json")));
	if (
		value.schema !== 1 ||
		typeof value.name !== "string" ||
		!/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,47}$/.test(value.name) ||
		typeof value.createdAt !== "string" ||
		!Number.isFinite(Date.parse(value.createdAt))
	)
		throw new Error("Invalid project manifest");
	runId(value.id);
	imageShape(value.image);
	runtimeShape(value.runtime);
	if (
		!Array.isArray(value.targets) ||
		value.targets.length === 0 ||
		value.targets.length > 32 ||
		value.targets.some(target => typeof target !== "string" || isIP(target) !== 4)
	)
		throw new Error("Invalid project targets");
	for (const sub of ["vm", "captures", "home", "tmp", "disk"]) await privateDirectory(path.join(projectDir, sub));
	return value as unknown as ProjectManifest;
}

import * as fs from "node:fs/promises";
import * as path from "node:path";
import type { ReadableStreamDefaultReader } from "node:stream/web";
import { inflateRawSync } from "node:zlib";
import { fileHash, ROOT, sha256 } from "./agent-smith-common";
import type { Binding, Finding, HistoricalVersion } from "./agent-smith-scan-policy";
import { EMPTY_TREE, identity, oid, safePath, SOURCE_BASE, SOURCE_TREE } from "./agent-smith-scan-policy";

export interface GitContext {
	executable: string;
	cwd: string;
	env: NodeJS.ProcessEnv;
	logs: string;
}
export interface TreeEntry {
	file: string;
	mode: string;
	blob: string;
	bytes: number;
}
export interface SnapshotEntry extends TreeEntry {
	sha256: string;
}

/** Plumbing only: no native addon, worktree filters, hooks, shell or upstream code. */
export async function git(context: GitContext, args: string[], input?: Uint8Array): Promise<string> {
	const child = Bun.spawn([context.executable, ...args], {
		cwd: context.cwd,
		env: context.env,
		stdin: input ?? "ignore",
		stdout: "pipe",
		stderr: "pipe",
		timeout: 180_000,
	});
	const [code, stdout, stderr] = await Promise.all([
		child.exited,
		new Response(child.stdout).arrayBuffer(),
		new Response(child.stderr).text(),
	]);
	if (code !== 0 || stderr !== "") {
		await fs.appendFile(context.logs, `${JSON.stringify({ args, code })}\n${stderr}\n`);
		throw new Error("Git plumbing failed; see git-errors.log");
	}
	return new TextDecoder("utf-8", { fatal: true }).decode(stdout);
}

export function neutralEnvironment(env: NodeJS.ProcessEnv, empty: string): NodeJS.ProcessEnv {
	const settings: Record<string, string> = {
		"core.attributesFile": empty,
		"core.hooksPath": empty,
		"core.autocrlf": "false",
		"core.fsmonitor": "false",
		"diff.renames": "false",
		"gc.auto": "0",
		"maintenance.auto": "false",
		"protocol.allow": "never",
	};
	const result: NodeJS.ProcessEnv = {
		...env,
		GIT_ATTR_SOURCE: SOURCE_BASE,
		GIT_ATTR_NOSYSTEM: "1",
		GIT_NO_REPLACE_OBJECTS: "1",
		GIT_NO_LAZY_FETCH: "1",
		GIT_TERMINAL_PROMPT: "0",
		GIT_OPTIONAL_LOCKS: "0",
		GIT_CONFIG_NOSYSTEM: "1",
		GIT_CONFIG_SYSTEM: empty,
		GIT_CONFIG_GLOBAL: empty,
		GIT_CONFIG_COUNT: String(Object.keys(settings).length),
		LC_ALL: "C",
		TZ: "UTC",
		GOMEMLIMIT: "512MiB",
		GOMAXPROCS: "2",
	};
	for (const [index, [key, value]] of Object.entries(settings).entries()) {
		result[`GIT_CONFIG_KEY_${index}`] = key;
		result[`GIT_CONFIG_VALUE_${index}`] = value;
	}
	return result;
}

async function requireEmpty(file: string): Promise<void> {
	try {
		const stat = await fs.lstat(file);
		if (!stat.isFile() || stat.size !== 0) throw new Error("Nonempty or unsafe Git metadata blocks scan");
	} catch (error) {
		if (!(error instanceof Error && "code" in error && error.code === "ENOENT")) throw error;
	}
}

/** The owned Git view uses immutable objects and only the pinned base's tree attributes. */
export async function sourceView(
	context: GitContext,
	dir: string,
	candidate: string,
	targetBase?: string,
): Promise<{ context: GitContext; tree: string; ancestrySha256: string; commits: Set<string> }> {
	oid(candidate);
	if (context.env.GIT_ATTR_SOURCE !== SOURCE_BASE) throw new Error("Unexpected attribute source");
	const original = { ...context, cwd: ROOT };
	const head = (await git(original, ["rev-parse", "--verify", "HEAD"])).trim();
	if (head !== candidate) throw new Error("Candidate must be the exact checked-out source HEAD");
	const common = path.resolve(ROOT, (await git(original, ["rev-parse", "--git-common-dir"])).trim());
	const gitDir = path.resolve(ROOT, (await git(original, ["rev-parse", "--git-dir"])).trim());
	for (const location of new Set([common, gitDir])) {
		for (const file of [
			"shallow",
			"info/attributes",
			"info/grafts",
			"objects/info/alternates",
			"objects/info/http-alternates",
		]) {
			await requireEmpty(path.join(location, file));
		}
	}
	const view = path.join(dir, "repository.git");
	const template = path.join(dir, "empty-template");
	await fs.mkdir(template);
	await git(context, ["init", "--bare", "--quiet", "--initial-branch=scan", `--template=${template}`, view]);
	const isolated = { ...context, cwd: view };
	const objects = await fs.realpath(path.join(common, "objects"));
	if (/[\r\n]/.test(objects)) throw new Error("Unsafe object database path");
	await Bun.write(path.join(view, "objects/info/alternates"), `${objects}\n`);
	await Bun.write(path.join(view, "HEAD"), `${candidate}\n`);
	// Materialize in the owned object store; never alter the source repository.
	if ((await git(isolated, ["hash-object", "-w", "-t", "tree", "--stdin"], new Uint8Array())).trim() !== EMPTY_TREE) {
		throw new Error("Empty tree identity mismatch");
	}
	if ((await git(isolated, ["rev-parse", "--show-object-format"])).trim() !== "sha1") {
		throw new Error("Unsupported object format");
	}
	if ((await git(isolated, ["rev-parse", `${SOURCE_BASE}^{tree}`])).trim() !== SOURCE_TREE) {
		throw new Error("Original source tree pin changed");
	}
	await git(isolated, ["merge-base", "--is-ancestor", SOURCE_BASE, candidate]);
	if (targetBase) await git(isolated, ["merge-base", "--is-ancestor", oid(targetBase), candidate]);
	const tree = oid((await git(isolated, ["rev-parse", `${candidate}^{tree}`])).trim());
	const ancestry = await git(isolated, ["rev-list", "--parents", candidate]);
	const commits = new Set<string>();
	const parents: string[] = [];
	for (const line of ancestry.trim().split("\n")) {
		const [commit, ...rest] = line.split(" ").map(oid);
		if (commits.has(commit)) throw new Error("Duplicate ancestry commit");
		commits.add(commit);
		parents.push(...rest);
	}
	if (!commits.has(candidate) || parents.some(parent => !commits.has(parent))) {
		throw new Error("Incomplete candidate ancestry");
	}
	// Enumerates reachable objects and fails on missing objects without lazy fetching.
	await git(isolated, ["rev-list", "--objects", "--no-object-names", "--missing=error", candidate]);
	await Bun.write(path.join(dir, "ancestry.txt"), ancestry);
	// Positive and negative controls prove GIT_ATTR_SOURCE is honored, even in a bare view.
	const attributeBlob = oid(
		(await git(isolated, ["hash-object", "-w", "--stdin"], new TextEncoder().encode("* -diff\n"))).trim(),
	);
	const attributeTree = oid(
		(
			await git(isolated, ["mktree"], new TextEncoder().encode(`100644 blob ${attributeBlob}\t.gitattributes\n`))
		).trim(),
	);
	// These are attribute controls only; history coverage enumerates every changed path.
	const paths = ["packages/catalog/src/models.json", "packages/catalog/src/compat/rules.json"];
	const check = ["check-attr", "-z", "diff", "--", ...paths];
	const negative = await git({ ...isolated, env: { ...isolated.env, GIT_ATTR_SOURCE: attributeTree } }, check);
	if (negative !== paths.map(file => `${file}\0diff\0unset\0`).join("")) {
		throw new Error("Git does not honor explicit attribute-source control");
	}
	const neutral = await git({ ...isolated, env: { ...isolated.env, GIT_ATTR_SOURCE: EMPTY_TREE } }, check);
	if (neutral !== paths.map(file => `${file}\0diff\0unspecified\0`).join("")) {
		throw new Error("Git does not honor the empty attribute-source control");
	}
	const attributes = await git(isolated, check);
	if (attributes !== paths.map(file => `${file}\0diff\0unset\0`).join("")) {
		throw new Error("Git does not honor the pinned base attribute source");
	}
	await Bun.write(
		path.join(dir, "attribute-controls.json"),
		`${JSON.stringify({
			source: SOURCE_BASE,
			tree: SOURCE_TREE,
			paths,
			negative,
			neutral,
			attributes,
		})}\n`,
	);
	return { context: isolated, tree, ancestrySha256: sha256(new TextEncoder().encode(ancestry)), commits };
}

export function parseTree(bytes: Uint8Array): TreeEntry[] {
	const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
	if (!text.endsWith("\0")) throw new Error("Missing tree record terminator");
	const seen = new Set<string>();
	return text
		.slice(0, -1)
		.split("\0")
		.map(line => {
			const match = /^(100644|100755) blob ([0-9a-f]{40}) +([0-9]+)\t(.+)$/.exec(line);
			if (!match) throw new Error("Unsupported tree entry: only regular files are accepted");
			const file = safePath(match[4]);
			const bytes = Number(match[3]);
			if (!Number.isSafeInteger(bytes) || bytes < 0 || seen.has(file)) throw new Error("Invalid tree entry");
			seen.add(file);
			return { file, mode: match[1], blob: match[2], bytes };
		});
}

/** Small protocol reader: each byte is copied at most once; no growing Buffer.concat loop. */
class BatchReader {
	#reader: ReadableStreamDefaultReader<Uint8Array>;
	#chunk: Uint8Array = new Uint8Array();
	#offset = 0;
	constructor(stream: ReadableStream<Uint8Array>) {
		this.#reader = stream.getReader();
	}
	async take(size: number): Promise<Uint8Array> {
		const output = new Uint8Array(size);
		let offset = 0;
		while (offset < size) {
			if (this.#offset === this.#chunk.length) {
				const next = await this.#reader.read();
				if (next.done) throw new Error("Truncated cat-file output");
				this.#chunk = next.value;
				this.#offset = 0;
			}
			const count = Math.min(size - offset, this.#chunk.length - this.#offset);
			output.set(this.#chunk.subarray(this.#offset, this.#offset + count), offset);
			this.#offset += count;
			offset += count;
		}
		return output;
	}
	async line(): Promise<string> {
		const bytes: number[] = [];
		while (bytes.length < 200) {
			const byte = (await this.take(1))[0];
			if (byte === 10) return new TextDecoder().decode(new Uint8Array(bytes));
			bytes.push(byte);
		}
		throw new Error("Oversized cat-file header");
	}
	async end(): Promise<void> {
		if (this.#offset !== this.#chunk.length || !(await this.#reader.read()).done) {
			throw new Error("Unexpected trailing cat-file output");
		}
	}
}

export interface BlobRequest {
	spec: string;
	blob?: string;
	bytes?: number;
}

export async function blobs(
	context: GitContext,
	requests: BlobRequest[],
	consume: (request: BlobRequest, blob: string, bytes: Uint8Array) => Promise<void>,
): Promise<void> {
	if (requests.length === 0) return;
	for (const request of requests) {
		if (!/^[0-9a-f]{40}(?::[^\r\n\0]+)?$/.test(request.spec)) throw new Error("Invalid blob request");
	}
	const child = Bun.spawn([context.executable, "cat-file", "--batch"], {
		cwd: context.cwd,
		env: context.env,
		stdin: new TextEncoder().encode(`${requests.map(item => item.spec).join("\n")}\n`),
		stdout: "pipe",
		stderr: "pipe",
		timeout: 300_000,
	});
	const errors = new Response(child.stderr).text();
	const reader = new BatchReader(child.stdout);
	try {
		for (const request of requests) {
			const header = /^([0-9a-f]{40}) blob ([0-9]+)$/.exec(await reader.line());
			if (!header) throw new Error("Missing or unexpected cat-file object");
			const size = Number(header[2]);
			// Explicit failure, never omission, for inputs outside the maintained memory bound.
			if (!Number.isSafeInteger(size) || size > 512 * 1024 * 1024) throw new Error("Blob exceeds scan memory bound");
			if ((request.blob && header[1] !== request.blob) || (request.bytes !== undefined && size !== request.bytes)) {
				throw new Error("Blob header does not match immutable tree");
			}
			const bytes = await reader.take(size);
			const actual = new Bun.CryptoHasher("sha1").update(`blob ${size}\0`).update(bytes).digest("hex");
			if (actual !== header[1] || (await reader.take(1))[0] !== 10) throw new Error("Invalid blob bytes/length");
			await consume(request, actual, bytes);
		}
		await reader.end();
		const [code, stderr] = await Promise.all([child.exited, errors]);
		if (code !== 0 || stderr) throw new Error("cat-file failed");
	} finally {
		if (child.exitCode === null) child.kill("SIGKILL");
		await child.exited;
		const stderr = await errors;
		if (stderr) await fs.appendFile(context.logs, stderr);
	}
}

export async function snapshot(context: GitContext, tree: string, destination: string): Promise<SnapshotEntry[]> {
	const listing = await git(context, ["ls-tree", "-r", "-z", "-l", "--full-tree", oid(tree)]);
	const entries = parseTree(new TextEncoder().encode(listing));
	await fs.mkdir(destination);
	const inventory: SnapshotEntry[] = [];
	let index = 0;
	await blobs(
		context,
		entries.map(item => ({ spec: item.blob, blob: item.blob, bytes: item.bytes })),
		async (_request, _blob, bytes) => {
			const entry = entries[index++];
			const file = path.join(destination, entry.file);
			await Bun.write(file, bytes);
			await fs.chmod(file, entry.mode === "100755" ? 0o700 : 0o600);
			const hash = sha256(bytes);
			if ((await fileHash(file)) !== hash) throw new Error("Snapshot write did not preserve Git bytes");
			inventory.push({ ...entry, sha256: hash });
		},
	);
	return inventory;
}

/** Extract only a reviewed ZIP member in memory, after its containing blob is pinned. */
export function zipMember(archive: Uint8Array, member: string): Uint8Array {
	safePath(member);
	const data = Buffer.from(archive.buffer, archive.byteOffset, archive.byteLength);
	let end = data.length - 22;
	for (; end >= Math.max(0, data.length - 65557); end--) {
		if (data.readUInt32LE(end) === 0x06054b50 && end + 22 + data.readUInt16LE(end + 20) === data.length) break;
	}
	if (end < Math.max(0, data.length - 65557) || data.readUInt32LE(end) !== 0x06054b50) {
		throw new Error("Invalid ZIP directory");
	}
	if (data.readUInt16LE(end + 4) !== 0 || data.readUInt16LE(end + 6) !== 0) {
		throw new Error("Multi-disk ZIP unsupported");
	}
	const count = data.readUInt16LE(end + 10);
	if (count === 65535 || count !== data.readUInt16LE(end + 8)) throw new Error("Unsupported ZIP directory size");
	let offset = data.readUInt32LE(end + 16);
	if (offset + data.readUInt32LE(end + 12) !== end) throw new Error("Invalid ZIP directory extent");
	let result: Uint8Array | undefined;
	for (let i = 0; i < count; i++) {
		if (offset + 46 > end || data.readUInt32LE(offset) !== 0x02014b50) throw new Error("Invalid ZIP entry");
		const nameLength = data.readUInt16LE(offset + 28);
		const next = offset + 46 + nameLength + data.readUInt16LE(offset + 30) + data.readUInt16LE(offset + 32);
		if (next > end) throw new Error("Truncated ZIP entry");
		const name = new TextDecoder("utf-8", { fatal: true }).decode(
			data.subarray(offset + 46, offset + 46 + nameLength),
		);
		if (name === member) {
			if (result) throw new Error("Ambiguous ZIP member");
			const flags = data.readUInt16LE(offset + 8);
			const method = data.readUInt16LE(offset + 10);
			const size = data.readUInt32LE(offset + 24);
			const compressed = data.readUInt32LE(offset + 20);
			const local = data.readUInt32LE(offset + 42);
			if ((flags & 1) !== 0 || size > 64 * 1024 * 1024 || local + 30 > data.length) {
				throw new Error("Unsupported ZIP member");
			}
			if (data.readUInt32LE(local) !== 0x04034b50 || data.readUInt16LE(local + 8) !== method) {
				throw new Error("Invalid ZIP header");
			}
			const localNameLength = data.readUInt16LE(local + 26);
			const start = local + 30 + localNameLength + data.readUInt16LE(local + 28);
			if (start + compressed > data.length) throw new Error("Truncated ZIP data");
			const localName = new TextDecoder("utf-8", { fatal: true }).decode(
				data.subarray(local + 30, local + 30 + localNameLength),
			);
			if (localName !== member || data.readUInt16LE(local + 6) !== flags) {
				throw new Error("ZIP local/central member identity mismatch");
			}
			const input = data.subarray(start, start + compressed);
			if (method !== 0 && method !== 8) throw new Error("Unsupported ZIP compression");
			result = method === 0 ? input : inflateRawSync(input, { maxOutputLength: 64 * 1024 * 1024 });
			if (result.length !== size) throw new Error("ZIP member length mismatch");
		}
		offset = next;
	}
	if (offset !== end || !result) throw new Error("Missing ZIP member");
	return result;
}

export async function bindFindings(
	context: GitContext,
	findings: Finding[],
	candidate: string,
	commits: ReadonlySet<string>,
	approvedContainers: ReadonlyMap<string, Binding>,
	version?: HistoricalVersion,
): Promise<Map<string, Binding>> {
	const bySpec = new Map<string, Finding[]>();
	for (const item of findings) {
		if (item.commit && !commits.has(item.commit)) throw new Error("Finding outside candidate ancestry");
		if (version && (item.commit !== "" || item.file.split("!")[0] !== version.file)) {
			throw new Error("Finding outside historical object snapshot");
		}
		const spec = version ? version.blob : `${item.commit || candidate}:${item.file.split("!")[0]}`;
		const rows = bySpec.get(spec) ?? [];
		rows.push(item);
		bySpec.set(spec, rows);
	}
	const bound = new Map<string, Binding>();
	await blobs(
		context,
		[...bySpec.keys()].map(spec => ({ spec })),
		async (request, blob, bytes) => {
			const containerSha256 = sha256(bytes);
			for (const item of bySpec.get(request.spec) ?? []) {
				const key = identity(item, version?.blob);
				const parts = item.file.split("!");
				let contentSha256 = containerSha256;
				if (parts.length > 1) {
					const approval = approvedContainers.get(key);
					// Unreviewed archives remain blocked; never invent a member binding.
					if (
						!approval ||
						approval.blob !== blob ||
						approval.containerSha256 !== containerSha256 ||
						parts.length !== 2
					) {
						continue;
					}
					contentSha256 = sha256(zipMember(bytes, parts[1]));
				}
				bound.set(key, { blob, containerSha256, contentSha256 });
			}
		},
	);
	return bound;
}

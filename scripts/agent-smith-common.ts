import * as fs from "node:fs/promises";
import * as path from "node:path";

export const ROOT = path.resolve(import.meta.dir, "..");
export const DEV = path.join(ROOT, ".agent-smith-dev");
export const BUN_VERSION = "1.4.2";
export const NATIVE_VERSION = "18.4.8";
export const UPSTREAM_REVISION = "717f97f4d22b3d65c4a4eef6a744255d46f4d1a6";
export const RUST_TOOLCHAIN = "nightly-2026-08-12";
export const LOCKFILES = ["bun.lock", "Cargo.lock", "MODULE.bazel.lock"] as const;

export function assertRuntime(): void {
	if (Bun.version !== BUN_VERSION) throw new Error(`Agent Smith requires Bun ${BUN_VERSION}; got ${Bun.version}`);
	const tag = `${process.platform}-${process.arch}`;
	if (!["linux-x64", "win32-x64", "darwin-arm64"].includes(tag)) {
		throw new Error(`P1 candidate host unsupported: ${tag}`);
	}
}

export function sha256(bytes: Uint8Array): string {
	return new Bun.CryptoHasher("sha256").update(bytes).digest("hex");
}

export async function fileHash(file: string): Promise<string> {
	return sha256(await Bun.file(file).bytes());
}

export async function lockHashes(): Promise<Record<string, string>> {
	return Object.fromEntries(
		await Promise.all(LOCKFILES.map(async file => [file, await fileHash(path.join(ROOT, file))])),
	);
}

export async function assertLocks(expected: Record<string, string>): Promise<void> {
	const actual = await lockHashes();
	for (const file of LOCKFILES) {
		if (actual[file] !== expected[file])
			throw new Error(`${file} changed during preparation/build; reconcile it explicitly`);
	}
}

export interface Fixture {
	dir: string;
	home: string;
	cwd: string;
	env: NodeJS.ProcessEnv;
}

/** Only OS execution paths survive; no provider, auth, proxy, loader or app settings are inherited. */
export async function fixture(label: string, inherited: NodeJS.ProcessEnv = process.env): Promise<Fixture> {
	await fs.mkdir(path.join(DEV, "runs"), { recursive: true });
	const dir = await fs.mkdtemp(path.join(DEV, "runs", `${label}-`));
	const home = path.join(dir, "home");
	const cwd = path.join(dir, "project");
	// Keep Unix-domain socket paths below the OS limit even in long checkouts.
	await fs.mkdir(path.join(DEV, "t"), { recursive: true });
	const temp = await fs.mkdtemp(path.join(DEV, "t", "s-"));
	await Promise.all([home, cwd, temp].map(file => fs.mkdir(file, { recursive: true })));
	const env: NodeJS.ProcessEnv = {};
	for (const key of [
		"PATH",
		"Path",
		"SystemRoot",
		"SYSTEMROOT",
		"WINDIR",
		"COMSPEC",
		"PATHEXT",
		"ProgramFiles",
		"ProgramFiles(x86)",
	]) {
		if (inherited[key] !== undefined) env[key] = inherited[key];
	}
	env.PATH = [
		path.dirname(process.execPath),
		path.join(ROOT, "node_modules", ".bin"),
		env.PATH ?? env.Path ?? "",
	].join(path.delimiter);
	delete env.Path;
	Object.assign(env, {
		HOME: home,
		USERPROFILE: home,
		APPDATA: path.join(home, "AppData", "Roaming"),
		LOCALAPPDATA: path.join(home, "AppData", "Local"),
		XDG_CONFIG_HOME: path.join(home, "config"),
		XDG_DATA_HOME: path.join(home, "data"),
		XDG_CACHE_HOME: path.join(home, "cache"),
		XDG_STATE_HOME: path.join(home, "state"),
		XDG_RUNTIME_DIR: temp,
		TMPDIR: temp,
		TMP: temp,
		TEMP: temp,
		BUN_INSTALL_CACHE_DIR: path.join(DEV, "bun-cache"),
		CI: "true",
		TERM: "dumb",
		NO_COLOR: "1",
		DO_NOT_TRACK: "1",
		GIT_CONFIG_NOSYSTEM: "1",
		GIT_CONFIG_GLOBAL: path.join(home, "empty-gitconfig"),
	});
	await Bun.write(path.join(home, "empty-gitconfig"), "");
	await Bun.write(path.join(dir, "fixture.json"), `${JSON.stringify({ temporaryDirectory: temp })}\n`);
	return { dir, home, cwd, env };
}

export interface RunOptions {
	cwd?: string;
	env: NodeJS.ProcessEnv;
	timeoutMs?: number;
	capture?: boolean;
	expectFailure?: boolean;
}

/** Bounded process lifetime; inherited output unless stdout is needed for a consumer assertion. */
export async function run(command: string[], options: RunOptions): Promise<string> {
	console.log(`$ ${command.join(" ")}`);
	const child = Bun.spawn(command, {
		cwd: options.cwd ?? ROOT,
		env: options.env,
		stdin: "ignore",
		stdout: options.capture ? "pipe" : "inherit",
		stderr: "inherit",
	});
	let timedOut = false;
	const timer = setTimeout(() => {
		timedOut = true;
		child.kill("SIGKILL");
	}, options.timeoutMs ?? 180_000);
	try {
		const [code, output] = await Promise.all([
			child.exited,
			options.capture ? new Response(child.stdout as ReadableStream<Uint8Array>).text() : Promise.resolve(""),
		]);
		if (output) process.stdout.write(output);
		if (timedOut) throw new Error(`Timed out: ${command.join(" ")}`);
		if (options.expectFailure ? code === 0 : code !== 0) {
			throw new Error(`Unexpected exit ${code}: ${command.join(" ")}`);
		}
		return output;
	} finally {
		clearTimeout(timer);
	}
}

export async function bun(args: string[], context: Fixture, cwd = ROOT, timeoutMs = 180_000): Promise<void> {
	await run([process.execPath, "--no-env-file", ...args], { env: context.env, cwd, timeoutMs });
}

export async function filesUnder(dir: string): Promise<string[]> {
	const files: string[] = [];
	for (const entry of await fs.readdir(dir, { withFileTypes: true })) {
		const file = path.join(dir, entry.name);
		if (entry.isSymbolicLink()) throw new Error(`Unexpected symlink in build input: ${file}`);
		if (entry.isDirectory()) files.push(...(await filesUnder(file)));
		else if (entry.isFile()) files.push(file);
	}
	return files.sort();
}

export function fail(error: unknown): void {
	console.error(error);
	process.exitCode = 1;
}

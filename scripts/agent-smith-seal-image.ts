#!/usr/bin/env bun
/**
 * Finalize an agent-smith-image-linux.py candidate, using the real guest supervisor.
 *
 * bun --no-env-file scripts/agent-smith-seal-image.ts --assets ABS --build ABS --out ABS
 *
 * Run only AFTER installation.json has been committed and the installer has exited.
 * --out must not exist. Failure retains original captures and never publishes image.json.
 * No downloads, package installation, host-root execution, project creation, or network.
 * Package presence / executable access are image qualification, not workflow acceptance.
 */
import * as fs from "node:fs/promises";
import * as path from "node:path";
import type { Subprocess } from "bun";
import { $which, isEnoent } from "@oh-my-pi/pi-utils";
import {
	CaptureStore,
	processExited,
	Qmp,
	terminateVm,
	validateDiskChain,
} from "../packages/coding-agent/src/workspace/broker";
import type { ImageManifest, RunRequest, RunSnapshot } from "../packages/coding-agent/src/workspace/contracts";
import {
	GuestTransport,
	originalBytes,
	validateOutput,
	validateRun,
} from "../packages/coding-agent/src/workspace/guest-transport";
import {
	absolutePath,
	assertLinux,
	cleanEnvironment,
	directoryPins,
	durableJson,
	hashFile,
	integer,
	object,
	privateDirectory,
	readJson,
	regularFile,
	safePath,
	syncDirectory,
	verifyPinnedFile,
} from "../packages/coding-agent/src/workspace/project";

const MiB = 1024 * 1024;
const EXPORT_LIMIT = 128 * MiB;
const HASH = /^[0-9a-f]{64}$/;
const KALI_PATCHED = "484b8131a80355a184bb5a93446c3dec0ca86854c2839fead7d04cd386470d87";
const HEXSTRIKE_PATCHED = "4cee604b1aaeb2cd20d8281ba4ae613a016879bc54d80a70091e012ed501969d";
// Deliberately match the builder's PACKAGES, including its exact patched package versions.
const REQUIRED_PACKAGES = [
	"kali-linux-default",
	"kali-desktop-xfce",
	"ghidra",
	"gdb",
	"radare2",
	"tshark",
	"metasploit-framework",
	"mitmproxy",
	"zaproxy",
	"burpsuite",
	"firefox-esr",
	"mcp-kali-server=0.0~git20260317.00154c0-0kali2",
	"hexstrike-ai=0.0~git20260803.d689933-0kali1",
	"python3-mcp",
	"patch",
];
const GUEST_INPUTS: Record<string, string> = {
	"supervisor.py": "/opt/agent-smith/supervisor.py",
	"mcp_runner.py": "/opt/agent-smith/mcp_runner.py",
	"agent-smith-guest.service": "/opt/agent-smith/agent-smith-guest.service",
	"mcp-kali-timeout.patch": "/opt/agent-smith/patches/mcp-kali-timeout.patch",
	"hexstrike-timeout.patch": "/opt/agent-smith/patches/hexstrike-timeout.patch",
};
const TOOLKIT: Record<string, string[]> = {
	"kali-linux-default": ["nmap"],
	"kali-desktop-xfce": ["xfce4-session"],
	ghidra: ["ghidra"],
	gdb: ["gdb"],
	radare2: ["radare2"],
	tshark: ["tshark"],
	"metasploit-framework": ["msfconsole"],
	mitmproxy: ["mitmproxy"],
	zaproxy: ["zaproxy"],
	burpsuite: ["burpsuite"],
	"firefox-esr": ["firefox-esr"],
	"mcp-kali-server": ["kali-server-mcp", "mcp-server"],
	"hexstrike-ai": ["hexstrike_server", "hexstrike_mcp"],
	"python3-mcp": ["python3"],
	patch: ["patch"],
};

// This is an inventory program, not an LLM prompt. It executes exclusively in the
// disposable guest through Supervisor.start(), with its cgroup/deadline/capture contract.
// Rights are exact bytes, deduplicated by hash; no guessed SPDX/license declarations.
const COLLECT_GUEST = String.raw`
import base64, hashlib, importlib.metadata, json, os, platform, re, shutil, stat, subprocess, sys
from pathlib import Path
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.exceptions import McpError
from pydantic import BaseModel

options = json.loads(sys.argv[1])
MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 80 * 1024 * 1024
used = 0
commands = []

def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)

def read(file, limit=MAX_FILE):
    with open(file, 'rb') as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, 'inventory input exceeds bound')
    return data

def sha(data):
    return hashlib.sha256(data).hexdigest()

def file_hash(file):
    with open(file, 'rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def command(argv, limit=8 * 1024 * 1024):
    # The enclosing supervised run also bounds the entire inventory and descendants.
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, check=False, timeout=30)
    except subprocess.TimeoutExpired as error:
        sys.stdout.buffer.write((error.stdout or b'')[:limit])
        sys.stdout.buffer.write((error.stderr or b'')[:limit])
        sys.stdout.buffer.flush()
        raise RuntimeError('inventory command timed out; bounded original diagnostic prefix retained') from None
    require(len(result.stdout) <= limit and len(result.stderr) <= limit, 'command output exceeds bound')
    commands.append({'argv': argv, 'exitCode': result.returncode,
                     'stdoutBase64': base64.b64encode(result.stdout).decode('ascii'),
                     'stderrBase64': base64.b64encode(result.stderr).decode('ascii')})
    if result.returncode != 0:
        # Preserve failed command diagnostics in the supervised original capture.
        sys.stdout.buffer.write(result.stdout)
        sys.stdout.buffer.write(result.stderr)
        sys.stdout.buffer.flush()
        raise RuntimeError('inventory command failed')
    return result.stdout

def embedded(file, limit=MAX_FILE):
    global used
    data = read(file, limit)
    used += len(data)
    require(used <= MAX_TOTAL, 'inventory export exceeds bound')
    return {'path': str(file), 'sha256': sha(data), 'bytes': len(data),
            'base64': base64.b64encode(data).decode('ascii')}

require(platform.machine() == 'x86_64', 'guest ISA mismatch')
require(command(['/usr/bin/dpkg', '--print-architecture']).strip() == b'amd64', 'dpkg ISA mismatch')
require(Path('/sys/fs/cgroup/cgroup.controllers').is_file(), 'cgroup v2 required')
require(hasattr(BaseModel, 'model_dump'), 'Pydantic v2 required by guest MCP runner')
service = {}
for line in command(['/usr/bin/systemctl', 'show', 'agent-smith-guest.service',
                     '--property=MainPID,ActiveState,LoadState,UnitFileState,FragmentPath,DropInPaths']).decode().splitlines():
    key, value = line.split('=', 1)
    service[key] = value
require(service.get('ActiveState') == 'active' and service.get('LoadState') == 'loaded'
        and service.get('UnitFileState') == 'enabled', 'guest service must be active and enabled')
require(service.get('FragmentPath') == '/etc/systemd/system/agent-smith-guest.service'
        and service.get('DropInPaths') == '', 'unexpected guest service definition')
pid = int(service['MainPID'])
require(pid > 1, 'missing guest service process')
argv = read('/proc/' + str(pid) + '/cmdline', 4096).split(b'\0')
require(argv == [b'/usr/bin/python3', b'-I', b'/opt/agent-smith/supervisor.py', b''],
        'running supervisor is not the installed implementation')
timesync = dict(line.split('=', 1) for line in command([
    '/usr/bin/systemctl', 'show', 'systemd-timesyncd.service',
    '--property=ActiveState,LoadState,UnitFileState']).decode().splitlines())
require(timesync == {'ActiveState': 'inactive', 'LoadState': 'masked', 'UnitFileState': 'masked'},
        'network time synchronization must be permanently masked for the isolated runtime')
sources = []
for name, file in sorted(options['guestInputs'].items()):
    require(not Path(file).is_symlink() and Path(file).is_file(), 'guest source missing or aliased')
    sources.append(dict(embedded(file, 1024 * 1024), input=name))
unit = '/etc/systemd/system/agent-smith-guest.service'
require(not Path(unit).is_symlink(), 'service fragment must be a regular file')
sources.append(dict(embedded(unit, 1024 * 1024), input='agent-smith-guest.service'))
recipe = embedded('/opt/agent-smith/image/recipe.json', 1024 * 1024)

fmt = chr(9).join('$' + '{' + key + '}' for key in
                 ('binary:Package', 'Package', 'Version', 'Architecture', 'source:Package', 'source:Version', 'Status')) + chr(10)
raw = command(['/usr/bin/dpkg-query', '-W', '-f=' + fmt])
rows = []
other_states = []
for line in raw.decode('utf-8', 'strict').splitlines():
    fields = line.split('\t')
    require(len(fields) == 7, 'invalid dpkg inventory row')
    row = dict(zip(('binaryPackage', 'package', 'version', 'architecture', 'sourcePackage', 'sourceVersion', 'status'), fields))
    require(all(row[k] for k in ('binaryPackage', 'package', 'version', 'architecture')), 'incomplete dpkg identity')
    (rows if row['status'] == 'install ok installed' else other_states).append(row)
require(0 < len(rows) <= 20000, 'installed package count outside bound')
require(all(r['status'].endswith(' config-files') or r['status'].endswith(' not-installed')
            for r in other_states), 'partially installed or damaged dpkg state')
by_name = {r['package']: r for r in rows if r['architecture'] in ('amd64', 'all')}
for spec in options['requiredPackages']:
    name, sep, version = spec.partition('=')
    require(name in by_name and (not sep or by_name[name]['version'] == version), 'required package/version missing: ' + name)

notices = {}
notice_name = re.compile(r'(?:copyright|licen[sc]e|copying|(?:third[-_ ]?party)?notices?)(?:[._-].+)?', re.IGNORECASE)
for row in rows:
    name = row['package']
    require(name and all(c in 'abcdefghijklmnopqrstuvwxyz0123456789+.-' for c in name), 'invalid dpkg package name')
    record = Path('/usr/share/doc') / name / 'copyright'
    rights = {'basis': 'debian-copyright', 'records': []}
    records = [record]
    registered = None
    if not record.exists() and not record.is_symlink():
        # Some upstream packages install their license and third-party notices
        # outside Debian's documentation tree. Preserve every registered notice,
        # with the original package file list proving ownership; never invent a grant.
        listing = command(['/usr/bin/dpkg-query', '-L', row['binaryPackage']]).decode('utf-8', 'strict').splitlines()
        require(len(listing) <= 20000 and str(record) not in listing, 'registered copyright record is missing')
        registered = set(listing)
        records = [Path(file) for file in sorted(registered)
                   if Path(file).is_absolute() and notice_name.fullmatch(Path(file).name)]
        require(0 < len(records) <= 256, 'installed package has no bounded registered rights records: ' + name)
        rights.update(basis='dpkg-registered-notices', fileListCommand=len(commands) - 1)
    for record in records:
        target = record.resolve(strict=True)
        require(target.is_file(), 'package rights record is not a regular file')
        if registered is None:
            require(target.is_relative_to('/usr/share/doc'), 'copyright escapes documentation tree')
        else:
            require(str(record) in registered and str(target) in registered,
                    'package notice resolves outside its registered files')
        data = read(target)
        require(data, 'empty installed package rights record')
        digest = sha(data)
        if digest not in notices:
            notices[digest] = embedded(target)
        rights['records'].append({'path': str(record), 'resolvedPath': str(target), 'sha256': digest})
    row['rights'] = rights
common = []
for file in sorted(Path('/usr/share/common-licenses').iterdir()):
    target = file.resolve(strict=True)
    require(target.is_relative_to('/usr/share/common-licenses') and target.is_file(), 'unexpected common-license entry')
    common.append(embedded(file))
require(common, 'common license texts missing')

toolkit = []
for package, names in options['toolkit'].items():
    for name in names:
        found = shutil.which(name)
        require(found is not None, 'required executable missing: ' + name)
        target = Path(found).resolve(strict=True)
        mode = target.stat().st_mode
        require(stat.S_ISREG(mode) and mode & 0o111 and os.access(target, os.X_OK), 'required tool is not executable: ' + name)
        toolkit.append({'package': package, 'command': name, 'path': found, 'resolvedPath': str(target),
                        'sha256': file_hash(target), 'executable': True,
                        'check': 'regular target with executable mode and access(X_OK); no workflow claim'})

mcp_sources = []
for package in ('mcp-kali-server', 'hexstrike-ai'):
    files = []
    listing = command(['/usr/bin/dpkg-query', '-L', package]).decode().splitlines()
    require(len(listing) <= 20000, 'MCP package file count outside bound')
    for name in sorted(set(listing)):
        file = Path(name)
        if file.is_absolute() and (file.suffix in ('.py', '.sh') or file.parent == Path('/usr/bin')) and file.is_file():
            files.append({'path': name, 'resolvedPath': str(file.resolve(strict=True)), 'sha256': file_hash(file)})
    require(files, 'MCP source hashes missing')
    mcp_sources.append({'package': package, 'version': by_name[package]['version'], 'files': files})
for file, expected in options['patched'].items():
    require(file_hash(file) == expected, 'patched MCP source digest mismatch')

# Real, noninteractive executions supplement X_OK observations. These bounded
# version probes are not acceptance of GUI, MCP, or security workflows.
for argv in (['/usr/bin/nmap', '--version'], ['/usr/bin/gdb', '--version'],
             ['/usr/bin/radare2', '-v'], ['/usr/bin/tshark', '--version'],
             ['/usr/bin/mitmproxy', '--version'], ['/usr/bin/patch', '--version']):
    command(argv, 1024 * 1024)

report = {'schema': 1, 'kernel': dict(zip(('system', 'node', 'release', 'version', 'machine'), platform.uname()[:5])),
          'dpkgArchitecture': 'amd64', 'cgroupV2': True, 'service': service,
          'sdk': {'mcpVersion': importlib.metadata.version('mcp'), 'pydanticVersion': importlib.metadata.version('pydantic'),
                  'requiredImportsExecuted': True, 'modelDumpAvailable': True},
          'sources': sources, 'recipe': recipe, 'packages': rows, 'otherDpkgStates': other_states,
          'dpkgQuery': {'sha256': sha(raw), 'bytes': len(raw), 'base64': base64.b64encode(raw).decode('ascii')},
          'notices': notices, 'commonLicenses': common, 'toolkit': toolkit, 'mcpSources': mcp_sources, 'commands': commands}
encoded = json.dumps(report, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode('ascii')
require(len(encoded) + 1 <= 128 * 1024 * 1024, 'final export exceeds bound')
sys.stdout.buffer.write(encoded + b'\n')
sys.stdout.buffer.flush()
`;

interface Options {
	assets: string;
	build: string;
	out: string;
}
interface Runtime {
	binary: string;
	sha256: string;
	imageBinary: string;
	imageSha256: string;
	firmwareDir: string;
	firmwarePins: Record<string, string>;
	libraryDir: string;
}
interface FilePin {
	path: string;
	sha256: string;
}
interface Embedded {
	path: string;
	sha256: string;
	bytes: number;
	base64: string;
	input?: string;
}
type Child = Subprocess<"ignore" | Uint8Array, "pipe", "pipe">;

function shaBytes(bytes: string | Uint8Array): string {
	return new Bun.CryptoHasher("sha256").update(bytes).digest("hex");
}

function digest(value: unknown): string {
	if (typeof value !== "string" || !HASH.test(value)) throw new Error("Invalid SHA-256 digest");
	return value;
}

function text(value: unknown): string {
	if (typeof value !== "string" || !value || value.length > 4096) throw new Error("Invalid metadata text");
	return value;
}

function array(value: unknown, limit = 20000): unknown[] {
	if (!Array.isArray(value) || value.length > limit) throw new Error("Invalid bounded inventory array");
	return value;
}

function decodeJson(value: string): unknown {
	try {
		return JSON.parse(value) as unknown;
	} catch {
		throw new Error("Invalid JSON evidence; original bytes retained");
	}
}

function childOf(root: string, value: unknown): string {
	const file = absolutePath(value);
	if (!file.startsWith(`${root}/`)) throw new Error("Runtime input escapes the selected asset directory");
	return file;
}

function filename(value: unknown): string {
	const name = text(value);
	if (!/^[a-zA-Z0-9_+.%:~-][a-zA-Z0-9_+.%:~-]*$/.test(name) || name === "." || name === "..")
		throw new Error("Invalid asset filename");
	return name;
}

function options(argv: string[]): Options | null {
	if (argv.length === 1 && (argv[0] === "--help" || argv[0] === "-h")) return null;
	const values = new Map<string, string>();
	for (let index = 0; index < argv.length; index += 2) {
		const key = argv[index];
		if (!key || !["--assets", "--build", "--out"].includes(key) || values.has(key))
			throw new Error("Expected each of --assets ABS --build ABS --out ABS exactly once");
		values.set(key, absolutePath(argv[index + 1]));
	}
	const assets = values.get("--assets"),
		build = values.get("--build"),
		out = values.get("--out");
	if (!assets || !build || !out) throw new Error("Required: --assets ABS --build ABS --out ABS");
	// Acquisition commonly places image-build-N below the assets umbrella. Only
	// the specific runtime files/directories are mounted, so this nesting is safe.
	const runtimeRoot = path.join(assets, "qemu", "runtime");
	if (out === assets || out === build || out === runtimeRoot || out.startsWith(`${runtimeRoot}/`))
		throw new Error("Output must be fresh and outside the QEMU runtime tree");
	return { assets, build, out };
}

async function bounded<T>(work: Promise<T>, timeoutMs: number, message: string): Promise<T> {
	const timeout = Promise.withResolvers<T>();
	const timer = setTimeout(() => timeout.reject(new Error(message)), timeoutMs);
	try {
		return await Promise.race([work, timeout.promise]);
	} finally {
		clearTimeout(timer);
	}
}

/** The normal durableJson helper intentionally caps JSON at 1 MiB. Inventories exceed that. */
async function newFile(file: string, bytes: string | Uint8Array, limit = EXPORT_LIMIT): Promise<FilePin> {
	if (Buffer.byteLength(bytes) > limit) throw new Error("Evidence file exceeds bound");
	await privateDirectory(path.dirname(file));
	const handle = await fs.open(
		file,
		fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW,
		0o600,
	);
	try {
		await handle.writeFile(bytes);
		await handle.sync();
	} finally {
		await handle.close();
	}
	await syncDirectory(path.dirname(file));
	return { path: file, sha256: shaBytes(bytes) };
}

async function newJson(file: string, value: unknown): Promise<FilePin> {
	return newFile(file, `${JSON.stringify(value)}\n`);
}

function samePins(left: Record<string, string>, right: Record<string, string>): boolean {
	return JSON.stringify(Object.entries(left).sort()) === JSON.stringify(Object.entries(right).sort());
}

/** Dedicated mounts for a candidate disk: no fake ProjectManifest or provisional ImageManifest. */
async function confinement(runtime: Runtime, bwrap: string, disk: string, temporary: string): Promise<string[]> {
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
		"--setenv",
		"LC_ALL",
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
	// Like the workspace broker, expose only root-owned dynamic loader/library trees.
	// The acquisition receipt does not pin these host libraries; record that trust boundary.
	for (const lib of ["/usr/lib", "/usr/lib64", "/lib", "/lib64"]) {
		try {
			const source = await fs.realpath(lib),
				stat = await fs.stat(source);
			if (!stat.isDirectory() || stat.uid !== 0 || (stat.mode & 0o022) !== 0)
				throw new Error("Unsafe host library tree");
			args.push("--ro-bind", source, lib);
		} catch (error) {
			if (!isEnoent(error)) throw error;
		}
	}
	args.push(
		"--ro-bind",
		runtime.binary,
		"/runtime/qemu",
		"--ro-bind",
		runtime.imageBinary,
		"/runtime/qemu-img",
		"--ro-bind",
		runtime.firmwareDir,
		"/runtime/firmware",
		"--ro-bind",
		runtime.libraryDir,
		"/runtime/lib",
		"--setenv",
		"LD_LIBRARY_PATH",
		"/runtime/lib",
		"--ro-bind",
		disk,
		"/base/base.qcow2",
		"--bind",
		path.join(temporary, "disk"),
		"/disk",
		"--bind",
		path.join(temporary, "vm"),
		"/vm",
		"--chdir",
		"/vm",
	);
	return args;
}

/** Original stdout/stderr are fsynced, capped and observed independently of process exit. */
class CapturedProcess {
	readonly child: Child;
	readonly done: Promise<void>;
	#failure: Error | undefined;
	#timer: Timer;
	constructor(
		command: string[],
		cwd: string,
		stdout: fs.FileHandle,
		stderr: fs.FileHandle,
		timeoutMs: number,
		input?: Uint8Array,
	) {
		this.child = Bun.spawn(command, {
			cwd,
			env: cleanEnvironment(cwd),
			stdin: input ?? "ignore",
			stdout: "pipe",
			stderr: "pipe",
		});
		this.#timer = setTimeout(() => this.fail(new Error("Confined process deadline exceeded")), timeoutMs);
		const drain = async (stream: ReadableStream<Uint8Array>, handle: fs.FileHandle): Promise<void> => {
			let total = 0;
			try {
				for await (const bytes of stream) {
					total += bytes.length;
					if (total > 16 * MiB) throw new Error("Confined process diagnostics exceeded bound");
					await handle.writeFile(bytes);
				}
				await handle.sync();
			} catch (error) {
				this.fail(error instanceof Error ? error : new Error("Diagnostic capture failed"));
				throw error;
			} finally {
				await handle.close();
			}
		};
		this.done = Promise.allSettled([
			this.child.exited,
			drain(this.child.stdout, stdout),
			drain(this.child.stderr, stderr),
		]).then(results => {
			clearTimeout(this.#timer);
			if (this.#failure) throw this.#failure;
			for (const result of results)
				if (result.status === "rejected") throw new Error("Process or diagnostic capture failed");
		});
		void this.done.catch(() => {});
	}
	fail(error: Error): void {
		this.#failure ??= error;
		if (!processExited(this.child)) this.child.kill("SIGKILL");
	}
	check(): void {
		if (this.#failure) throw this.#failure;
		if (processExited(this.child)) throw new Error("Confined QEMU exited unexpectedly");
	}
	async stop(): Promise<void> {
		try {
			await terminateVm(this.child, 3000, 5000);
		} finally {
			clearTimeout(this.#timer);
		}
		await bounded(this.done, 5000, "Diagnostic capture completion was not observed");
	}
	static async start(
		command: string[],
		cwd: string,
		logs: string,
		name: string,
		timeoutMs: number,
		input?: Uint8Array,
	): Promise<CapturedProcess> {
		const stdout = await fs.open(path.join(logs, `${name}.stdout`), "wx", 0o600);
		let stderr: fs.FileHandle | undefined;
		try {
			stderr = await fs.open(path.join(logs, `${name}.stderr`), "wx", 0o600);
			return new CapturedProcess(command, cwd, stdout, stderr, timeoutMs, input);
		} catch (error) {
			await stdout.close();
			await stderr?.close();
			throw error;
		}
	}
}

async function socketReady(file: string, vm: CapturedProcess, signal: AbortSignal, deadline: number): Promise<void> {
	while (Date.now() < deadline) {
		signal.throwIfAborted();
		vm.check();
		try {
			const stat = await fs.lstat(file);
			if (!stat.isSocket() || stat.uid !== process.getuid?.()) throw new Error("Unsafe private control socket");
			await fs.chmod(file, 0o600);
			return;
		} catch (error) {
			if (!isEnoent(error)) throw error;
		}
		await Bun.sleep(100);
	}
	throw new Error("VM control socket startup timed out");
}

/** Never recursively delete a tree the confined process could have populated. */
async function removeScratch(dir: string): Promise<void> {
	await privateDirectory(dir);
	for (const name of ["qmp.sock", "control.sock"]) {
		const file = path.join(dir, "vm", name);
		try {
			const stat = await fs.lstat(file);
			if (!stat.isSocket() || stat.uid !== process.getuid?.()) throw new Error("Unexpected scratch entry retained");
			await fs.unlink(file);
		} catch (error) {
			if (!isEnoent(error)) throw error;
		}
	}
	for (const sub of ["vm", "disk"]) {
		try {
			await fs.rmdir(path.join(dir, sub));
		} catch (error) {
			if (!isEnoent(error)) throw error;
		}
	}
	await fs.rmdir(dir);
}

async function collect(
	guest: GuestTransport,
	vm: CapturedProcess,
	captures: CaptureStore,
	signal: AbortSignal,
): Promise<RunSnapshot> {
	const request: RunRequest = {
		actor: "human",
		kind: "command",
		cwd: "/work",
		timeoutMs: 600000,
		argv: [
			"/usr/bin/python3",
			"-I",
			"-c",
			COLLECT_GUEST,
			JSON.stringify({
				guestInputs: GUEST_INPUTS,
				requiredPackages: REQUIRED_PACKAGES,
				toolkit: TOOLKIT,
				patched: {
					"/usr/share/mcp-kali-server/server.py": KALI_PATCHED,
					"/usr/share/hexstrike-ai/hexstrike_server.py": HEXSTRIKE_PATCHED,
				},
			}),
		],
	};
	let run = validateRun(await guest.request("start", { ...request }), guest.project);
	const id = run.id,
		deadline = Date.now() + request.timeoutMs + 20000;
	let offset = 0;
	await captures.observe(run);
	for (;;) {
		signal.throwIfAborted();
		vm.check();
		if (Date.now() >= deadline) throw new Error("Guest inventory completion timed out");
		if (run.id !== id || run.generation !== guest.generation || run.actor !== "human" || run.kind !== "command")
			throw new Error("Guest inventory identity mismatch");
		if (run.outputBytes > EXPORT_LIMIT) throw new Error("Guest inventory exceeded export bound");
		const output = validateOutput(await guest.request("read", { id, offset }), guest.project, id, offset);
		if (output.run.generation !== guest.generation || output.run.outputBytes > EXPORT_LIMIT)
			throw new Error("Guest output generation or bound mismatch");
		await captures.append(output);
		offset = output.nextOffset;
		run = output.run;
		if (run.state !== "running" && run.captureComplete && offset === run.outputBytes) break;
		if (run.state === "unknown" || (run.state !== "running" && !run.captureComplete))
			throw new Error("Guest supervision/capture incomplete");
		if (offset === run.outputBytes) await Bun.sleep(100);
	}
	if (run.state !== "exited" || run.exitCode !== 0 || run.signal !== null || run.cancelRequested)
		throw new Error("Guest inventory command did not succeed; original capture retained");
	return run;
}

function embedded(value: unknown, limit = 8 * MiB): { record: Embedded; data: Buffer } {
	const row = object(value),
		data = originalBytes(row.base64, limit);
	if (integer(row.bytes, 0, limit) !== data.length || digest(row.sha256) !== shaBytes(data))
		throw new Error("Exported file bytes do not match their digest/length");
	if (row.path !== undefined) absolutePath(row.path);
	return { record: row as unknown as Embedded, data };
}

async function exportEvidence(
	out: string,
	report: Record<string, unknown>,
	seed: Record<string, unknown>,
	recipeHash: string,
): Promise<{
	packages: FilePin;
	guestBundle: FilePin;
	evidence: FilePin[];
	observations: Record<string, unknown>;
}> {
	if (
		report.schema !== 1 ||
		object(report.kernel).machine !== "x86_64" ||
		object(report.kernel).system !== "Linux" ||
		report.dpkgArchitecture !== "amd64" ||
		report.cgroupV2 !== true ||
		object(report.sdk).requiredImportsExecuted !== true
	)
		throw new Error("Guest platform/SDK qualification failed");
	const expected = object(seed.guestInputs),
		sources = array(report.sources, 6);
	if (sources.length !== 6) throw new Error("Incomplete guest implementation bundle");
	const found = new Set<string>();
	const bundle: Embedded[] = [];
	for (const value of sources) {
		const { record } = embedded(value, MiB);
		const input = text(record.input),
			file = absolutePath(record.path);
		if (
			(GUEST_INPUTS[input] !== file &&
				!(input === "agent-smith-guest.service" && file === "/etc/systemd/system/agent-smith-guest.service")) ||
			found.has(file) ||
			digest(expected[input]) !== record.sha256
		)
			throw new Error("Actual guest implementation differs from seed guestInputs");
		found.add(file);
		bundle.push(record);
	}
	for (const file of [...Object.values(GUEST_INPUTS), "/etc/systemd/system/agent-smith-guest.service"])
		if (!found.has(file)) throw new Error("Guest source bundle is incomplete");
	const recipe = embedded(report.recipe, MiB);
	if (recipe.record.path !== "/opt/agent-smith/image/recipe.json" || recipe.record.sha256 !== recipeHash)
		throw new Error("Installed recipe differs from the builder seed");
	bundle.sort((left, right) => (left.path < right.path ? -1 : left.path > right.path ? 1 : 0));
	const guestBundle = await newJson(path.join(out, "guest-sources.json"), {
		schema: 1,
		encoding: "base64",
		files: bundle,
	});
	const evidence: FilePin[] = [guestBundle];
	const raw = embedded(report.dpkgQuery);
	evidence.push(await newFile(path.join(out, "dpkg-query.tsv"), raw.data));
	const rows = array(report.packages).map(object);
	const identities = new Set<string>();
	for (const row of rows) {
		const name = text(row.binaryPackage);
		if (identities.has(name) || row.status !== "install ok installed")
			throw new Error("Invalid installed package inventory");
		identities.add(name);
		for (const key of ["package", "version", "architecture", "sourcePackage", "sourceVersion"]) text(row[key]);
	}
	for (const spec of REQUIRED_PACKAGES) {
		const [name, version] = spec.split("=");
		if (
			!rows.some(
				row =>
					row.package === name &&
					["amd64", "all"].includes(String(row.architecture)) &&
					(!version || row.version === version),
			)
		)
			throw new Error("Required installed package/version missing");
	}
	// Cross-check the structured manifest against exact live dpkg output, not the seed's inventory.
	const installed = raw.data
		.toString("utf8")
		.trimEnd()
		.split("\n")
		.map(line => line.split("\t"))
		.filter(row => row[6] === "install ok installed");
	if (
		installed.length !== rows.length ||
		rows.some(
			(row, index) =>
				JSON.stringify(installed[index]) !==
				JSON.stringify([
					row.binaryPackage,
					row.package,
					row.version,
					row.architecture,
					row.sourcePackage,
					row.sourceVersion,
					row.status,
				]),
		)
	)
		throw new Error("Structured packages disagree with original dpkg output");
	const commands = array(report.commands, 32).map(object);
	for (const command of commands) {
		if (command.exitCode !== 0) throw new Error("A guest inventory or executable probe failed");
		originalBytes(command.stdoutBase64, 8 * MiB);
		originalBytes(command.stderrBase64, 8 * MiB);
	}
	const notices = object(report.notices),
		noticeIndex: Record<string, FilePin> = {};
	if (Object.keys(notices).length > 20000) throw new Error("Excess package notice records");
	for (const [hash, value] of Object.entries(notices)) {
		const entry = embedded(value);
		if (digest(hash) !== entry.record.sha256 || entry.data.length === 0) throw new Error("Invalid package notice");
		noticeIndex[hash] = await newFile(path.join(out, "notices", `${hash}.txt`), entry.data, 8 * MiB);
	}
	for (const row of rows) {
		const rights = object(row.rights);
		const records = array(rights.records, 256).map(object);
		if (!records.length) throw new Error("Installed component has no exported rights records");
		let registered: Set<string> | undefined;
		if (rights.basis === "debian-copyright") {
			if (records.length !== 1 || records[0]?.path !== `/usr/share/doc/${text(row.package)}/copyright`)
				throw new Error("Invalid Debian copyright record");
		} else if (rights.basis === "dpkg-registered-notices") {
			const command = commands[integer(rights.fileListCommand, 0, commands.length - 1)];
			if (
				!command ||
				JSON.stringify(command.argv) !== JSON.stringify(["/usr/bin/dpkg-query", "-L", row.binaryPackage])
			)
				throw new Error("Package notice ownership query is missing");
			registered = new Set(
				originalBytes(command.stdoutBase64, 8 * MiB)
					.toString("utf8")
					.split("\n"),
			);
		} else throw new Error("Unsupported installed package rights basis");
		for (const record of records) {
			const file = absolutePath(record.path);
			const target = absolutePath(record.resolvedPath);
			if (
				!noticeIndex[digest(record.sha256)] ||
				(registered ? !registered.has(file) || !registered.has(target) : !target.startsWith("/usr/share/doc/"))
			)
				throw new Error("Installed component rights record lacks exported bytes or path provenance");
		}
	}
	const common = [];
	for (const value of array(report.commonLicenses, 256)) {
		const entry = embedded(value);
		const target = path.join(out, "notices", `${entry.record.sha256}.txt`);
		if (!noticeIndex[entry.record.sha256]) noticeIndex[entry.record.sha256] = await newFile(target, entry.data);
		common.push({ guestPath: entry.record.path, ...noticeIndex[entry.record.sha256] });
	}
	if (!common.length) throw new Error("Common license records missing");
	evidence.push(
		await newJson(path.join(out, "rights.json"), {
			schema: 1,
			basis: "Exact installed Debian copyright records, package-registered license/notice bytes with original ownership queries, and guest common licenses; no inferred license grants or source-offer completeness claim.",
			records: noticeIndex,
			commonLicenses: common,
		}),
	);
	const toolkit = array(report.toolkit, 64).map(object);
	if (toolkit.length !== Object.values(TOOLKIT).flat().length) throw new Error("Incomplete executable inventory");
	for (const [name, commands] of Object.entries(TOOLKIT))
		for (const command of commands) {
			const matches = toolkit.filter(
				row => row.package === name && row.command === command && row.executable === true,
			);
			if (matches.length !== 1) throw new Error("Missing required executable observation");
			const match = matches[0];
			if (!match) throw new Error("Executable observation missing");
			absolutePath(match.path);
			absolutePath(match.resolvedPath);
			digest(match.sha256);
		}
	const mcpSources = array(report.mcpSources, 2).map(object);
	for (const [name, file, hash] of [
		["mcp-kali-server", "/usr/share/mcp-kali-server/server.py", KALI_PATCHED],
		["hexstrike-ai", "/usr/share/hexstrike-ai/hexstrike_server.py", HEXSTRIKE_PATCHED],
	]) {
		const source = mcpSources.find(row => row.package === name);
		if (
			!source ||
			!array(source.files)
				.map(object)
				.some(row => row.path === file && row.sha256 === hash)
		)
			throw new Error("Required patched MCP source hash was not observed");
	}
	evidence.push(
		await newJson(path.join(out, "mcp-sources.json"), {
			schema: 1,
			packages: mcpSources,
			basis: "Hashes of installed package code and wrappers, including local patches; not upstream pristine source hashes.",
		}),
	);
	evidence.push(
		await newJson(path.join(out, "guest-commands.json"), {
			schema: 1,
			commands,
			basis: "Original stdout/stderr of inventory queries and bounded executable version probes; no workflow acceptance claim.",
		}),
	);
	const packages = await newJson(path.join(out, "packages.json"), {
		schema: 1,
		producer: "live guest dpkg-query -W",
		packages: rows,
		otherDpkgStates: report.otherDpkgStates,
		original: evidence[1],
		required: REQUIRED_PACKAGES,
	});
	return {
		packages,
		guestBundle,
		evidence,
		observations: {
			kernel: report.kernel,
			dpkgArchitecture: report.dpkgArchitecture,
			service: report.service,
			sdk: report.sdk,
			cgroupV2: true,
			toolkit,
		},
	};
}

async function seal(opts: Options): Promise<void> {
	assertLinux();
	if (process.geteuid?.() === 0) throw new Error("Host root is forbidden");
	const previousUmask = process.umask(0o077);
	const abort = new AbortController();
	let stage = "input validation",
		outCreated = false,
		temporary: string | undefined;
	let active: CapturedProcess | undefined,
		vm: CapturedProcess | undefined,
		qmp: Qmp | undefined,
		guest: GuestTransport | undefined;
	let snapshotOwned = false,
		stopped = false,
		publishing = false;
	let scratchRetained = false;
	let captures: CaptureStore | undefined;
	let bootBytes: Buffer | undefined;
	const onSignal = () => {
		abort.abort(new Error("Sealing interrupted"));
		active?.fail(new Error("Sealing interrupted"));
	};
	for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"] as const) process.on(sig, onSignal);
	const overall = setTimeout(onSignal, 20 * 60 * 1000);
	try {
		await safePath(opts.assets);
		await privateDirectory(opts.build);
		await safePath(path.dirname(opts.out));
		// Do not touch the disk until the builder's post-exit record is present and valid.
		const installationPath = path.join(opts.build, "installation.json"),
			recipePath = path.join(opts.build, "seed", "recipe.json");
		const installation = object(await readJson(installationPath, false)),
			recipe = object(await readJson(recipePath, false));
		const disk = path.join(opts.build, "installed.qcow2");
		if (
			installation.schema !== 1 ||
			installation.state !== "installer-exited-awaiting-guest-qualification" ||
			installation.exitCode !== 0 ||
			installation.disk !== disk ||
			object(installation.kvm).enabled !== true ||
			object(installation.kvm).present !== true ||
			recipe.schema !== 1 ||
			JSON.stringify(installation.recipe) !== JSON.stringify(recipe) ||
			JSON.stringify(recipe.requestedPackages) !== JSON.stringify(REQUIRED_PACKAGES)
		)
			throw new Error("Builder completion/recipe contract is not satisfied");
		const seedInputs = object(recipe.guestInputs);
		if (Object.keys(seedInputs).sort().join("\n") !== Object.keys(GUEST_INPUTS).sort().join("\n"))
			throw new Error("Unexpected seed guestInputs");
		for (const value of Object.values(seedInputs)) digest(value);
		await regularFile(disk);
		const baseBefore = await fs.lstat(disk, { bigint: true });
		if (baseBefore.uid !== BigInt(process.getuid?.() ?? -1)) throw new Error("Candidate must be operator-owned");
		await fs.mkdir(opts.out, { mode: 0o700 });
		outCreated = true;
		await privateDirectory(opts.out);
		for (const name of ["logs", "captures", "inputs", "notices"])
			await fs.mkdir(path.join(opts.out, name), { mode: 0o700 });
		const inputPins: FilePin[] = [];
		async function pin(file: string, expected?: unknown): Promise<string> {
			abort.signal.throwIfAborted();
			const sha256 = await hashFile(file);
			if (expected !== undefined && sha256 !== digest(expected)) throw new Error("Input digest mismatch");
			inputPins.push({ path: file, sha256 });
			return sha256;
		}
		async function retain(file: string, name: string): Promise<void> {
			const bytes = await Bun.file(file).bytes();
			if (bytes.length > MiB) throw new Error("Input receipt exceeds bound");
			const hash = await pin(file);
			if (shaBytes(bytes) !== hash) throw new Error("Input receipt changed while retaining it");
			await newFile(path.join(opts.out, "inputs", name), bytes, MiB);
		}
		await retain(installationPath, "installation.json");
		await retain(recipePath, "recipe.json");
		const recipeHash = await hashFile(recipePath);
		await pin(path.join(opts.build, "installer.log"), installation.installerLogSha256);
		for (const [name, hash] of Object.entries(seedInputs))
			await pin(path.join(opts.build, "seed", name.endsWith(".patch") ? "patches" : "guest", name), hash);
		const runtimeRoot = path.join(opts.assets, "qemu", "runtime"),
			runtimePath = path.join(opts.assets, "qemu", "runtime.json");
		const receipt = object(await readJson(runtimePath, false));
		if (receipt.schema !== 1) throw new Error("Unsupported QEMU acquisition schema");
		const runtime: Runtime = {
			binary: childOf(runtimeRoot, receipt.binary),
			sha256: digest(receipt.sha256),
			imageBinary: childOf(runtimeRoot, receipt.imageBinary),
			imageSha256: digest(receipt.imageSha256),
			firmwareDir: childOf(runtimeRoot, receipt.firmwareDir),
			libraryDir: childOf(runtimeRoot, receipt.libraryDir),
			firmwarePins: Object.create(null),
		};
		for (const [name, hash] of Object.entries(object(receipt.firmwarePins)))
			runtime.firmwarePins[text(name)] = digest(hash);
		for (const name of ["bios-256k.bin", "vgabios-stdvga.bin", "efi-virtio.rom"])
			if (!runtime.firmwarePins[name]) throw new Error("QEMU firmware pin missing");
		await pin(path.join(opts.assets, "qemu", "receipt.json"), receipt.acquisitionReceiptSha256);
		await retain(runtimePath, "qemu-runtime.json");
		await retain(path.join(opts.assets, "qemu", "receipt.json"), "qemu-acquisition.json");
		const acquisition = object(await readJson(path.join(opts.assets, "qemu", "receipt.json"), false));
		for (const key of [
			"binary",
			"sha256",
			"imageBinary",
			"imageSha256",
			"libraryDir",
			"packages",
			"signedMetadata",
			"keyringSha256",
		])
			if (JSON.stringify(receipt[key]) !== JSON.stringify(acquisition[key]))
				throw new Error("Runtime receipt disagrees with its pinned acquisition record");
		await pin(runtime.binary, runtime.sha256);
		await pin(runtime.imageBinary, runtime.imageSha256);
		await fs.access(runtime.binary, fs.constants.X_OK);
		await fs.access(runtime.imageBinary, fs.constants.X_OK);
		if (!samePins(await directoryPins(runtime.firmwareDir), runtime.firmwarePins))
			throw new Error("Firmware directory differs from its pins");
		const libraryPins = await directoryPins(runtime.libraryDir);
		const runtimePackages = array(receipt.packages, 1024);
		if (!runtimePackages.length) throw new Error("QEMU package provenance is empty");
		for (const value of runtimePackages) {
			const row = object(value);
			await pin(path.join(opts.assets, "qemu", "packages", filename(row.file)), row.sha256);
		}
		const signedMetadata = object(receipt.signedMetadata);
		if (!Object.keys(signedMetadata).length) throw new Error("QEMU acquisition metadata is missing");
		for (const [name, hash] of Object.entries(signedMetadata))
			await pin(path.join(opts.assets, "qemu", "lists", filename(name)), hash);
		const kaliPath = path.join(opts.assets, "kali", "receipt.json"),
			kali = object(await readJson(kaliPath, false));
		if (kali.schema !== 1 || kali.fingerprint !== "827C8569F2518CC677FECA1AED65462EC8D5E4C5")
			throw new Error("Unexpected Kali provenance");
		const installer = object(recipe.installer);
		if (
			!array(kali.assets, 32)
				.map(object)
				.some(row => row.file === installer.file && row.sha256 === installer.sha256)
		)
			throw new Error("Recipe installer is not recorded by the acquisition receipt");
		await pin(path.join(opts.assets, "kali", filename(installer.file)), installer.sha256);
		await retain(kaliPath, "kali-acquisition.json");
		const selected = $which("bwrap", { PATH: "/usr/bin:/bin" });
		if (!selected) throw new Error("bubblewrap is required");
		const bwrap = await fs.realpath(selected);
		await regularFile(bwrap);
		const bwrapStat = await fs.stat(bwrap);
		if (bwrapStat.uid !== 0 || (bwrapStat.mode & 0o6000) !== 0)
			throw new Error("Unprivileged non-setuid bubblewrap is required");
		await pin(bwrap);
		const kvm = await fs.open("/dev/kvm", fs.constants.O_RDWR | fs.constants.O_NOFOLLOW);
		try {
			if (!(await kvm.stat()).isCharacterDevice()) throw new Error("KVM device required");
		} finally {
			await kvm.close();
		}
		const baseHash = await hashFile(disk);
		temporary = await fs.mkdtemp("/tmp/agent-smith-seal-");
		scratchRetained = true;
		await fs.chmod(temporary, 0o700);
		await privateDirectory(temporary);
		for (const sub of ["disk", "vm"]) await fs.mkdir(path.join(temporary, sub), { mode: 0o700 });
		await durableJson(path.join(opts.out, "lifecycle.json"), {
			schema: 1,
			state: "preparing-snapshot",
			temporary,
			base: { path: disk, sha256: baseHash },
		});
		const prefix = await confinement(runtime, bwrap, disk, temporary),
			logs = path.join(opts.out, "logs");
		async function imageCommand(name: string, args: string[]): Promise<unknown> {
			abort.signal.throwIfAborted();
			active = await CapturedProcess.start(
				[...prefix, "--", "/runtime/qemu-img", ...args],
				opts.out,
				logs,
				name,
				30000,
			);
			try {
				await bounded(active.done, 40000, "Image tool completion not observed");
				if (active.child.exitCode !== 0)
					throw new Error("Confined image tool failed; original diagnostics retained");
				return name.endsWith("info") ? decodeJson(await Bun.file(path.join(logs, `${name}.stdout`)).text()) : null;
			} finally {
				await active.stop();
				active = undefined;
			}
		}
		stage = "snapshot preparation";
		validateDiskChain(
			await imageCommand("base-info", ["info", "--output=json", "--backing-chain", "/base/base.qcow2"]),
			false,
		);
		snapshotOwned = true; // Only this fresh private directory can receive qemu-img's partial output.
		await imageCommand("snapshot-create", [
			"create",
			"-f",
			"qcow2",
			"-F",
			"qcow2",
			"-b",
			"/base/base.qcow2",
			"/disk/root.qcow2",
		]);
		validateDiskChain(
			await imageCommand("snapshot-info", ["info", "--output=json", "--backing-chain", "/disk/root.qcow2"]),
			true,
		);
		stage = "authenticated guest boot";
		const project = crypto.randomUUID(),
			generation = crypto.randomUUID();
		let token = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("hex");
		bootBytes = Buffer.from(JSON.stringify({ project, generation, token }));
		// bubblewrap consumes stdin into an anonymous, read-only data mount. There is
		// no host boot-token file, argument, environment entry, or persisted transcript.
		vm = await CapturedProcess.start(
			[
				...prefix,
				"--dev-bind",
				"/dev/kvm",
				"/dev/kvm",
				"--ro-bind-data",
				"0",
				"/boot.json",
				"--",
				"/runtime/qemu",
				"-name",
				"agent-smith-image-qualification",
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
				"-no-reboot",
				"-accel",
				"kvm",
				"-machine",
				"q35",
				"-cpu",
				"host",
				"-m",
				"3072",
				"-smp",
				"4",
				"-L",
				"/runtime/firmware",
				"-nic",
				"none",
				"-sandbox",
				"on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
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
				"name=opt/agent-smith/config,file=/boot.json",
			],
			opts.out,
			logs,
			"qualification-vm",
			15 * 60 * 1000,
			bootBytes,
		);
		active = vm;
		await durableJson(path.join(opts.out, "lifecycle.json"), {
			schema: 1,
			state: "booting",
			pid: vm.child.pid,
			temporary,
			project,
			generation,
		});
		const bootDeadline = Date.now() + 180000;
		await socketReady(path.join(temporary, "vm", "qmp.sock"), vm, abort.signal, bootDeadline);
		qmp = new Qmp(path.join(temporary, "vm", "qmp.sock"));
		await qmp.initialize();
		await qmp.assertKvm();
		await socketReady(path.join(temporary, "vm", "control.sock"), vm, abort.signal, bootDeadline);
		while (Date.now() < bootDeadline) {
			abort.signal.throwIfAborted();
			vm.check();
			guest = new GuestTransport(path.join(temporary, "vm", "control.sock"), project, generation, token);
			try {
				if (
					object(await guest.request("ping", {}, Math.min(5000, Math.max(1, bootDeadline - Date.now())))).ready ===
					true
				)
					break;
			} catch {
				/* Only the read-only readiness operation is retried. */
			}
			guest.close();
			guest = undefined;
			await Bun.sleep(250);
		}
		bootBytes.fill(0);
		bootBytes = undefined;
		token = "";
		if (!guest) throw new Error("Authenticated guest supervisor readiness timed out");
		if (array(await guest.request("list"), 512).length !== 0)
			throw new Error("Reusable base contains prior supervision history");
		stage = "guest inventory and rights collection";
		const collector = await newFile(path.join(opts.out, "collector.py"), COLLECT_GUEST, MiB);
		captures = new CaptureStore(path.join(opts.out, "captures"), project);
		const run = await collect(guest, vm, captures, abort.signal);
		const capturePath = path.join(opts.out, "captures", `${run.id}.bin`);
		const report = object(decodeJson(await Bun.file(capturePath).text()));
		const evidence = await exportEvidence(opts.out, report, recipe, recipeHash);
		evidence.evidence.push(collector);
		await qmp.assertKvm();
		vm.check();
		stage = "authenticated guest poweroff";
		let poweroffAccepted = false;
		try {
			const response = object(await guest.request("poweroff", {}, 5000));
			poweroffAccepted = response.requested === true;
		} catch {
			/* Both authenticated acceptance and normal exit are required to seal. */
		}
		await Promise.race([vm.child.exited, Bun.sleep(15000)]);
		guest.close();
		guest = undefined;
		const forced = !processExited(vm.child);
		await vm.stop();
		stopped = true;
		active = undefined;
		qmp.close();
		qmp = undefined;
		await durableJson(path.join(opts.out, "lifecycle.json"), {
			schema: 1,
			state: "terminated",
			pid: vm.child.pid,
			exitCode: vm.child.exitCode,
			signal: vm.child.signalCode,
			poweroffAccepted,
			forced,
			temporary,
			project,
			generation,
		});
		if (forced || vm.child.exitCode !== 0 || !poweroffAccepted)
			throw new Error("Authenticated guest poweroff and normal VM exit were not observed");
		stage = "unchanged base and input verification";
		abort.signal.throwIfAborted();
		const baseAfter = await fs.lstat(disk, { bigint: true });
		if (
			baseAfter.dev !== baseBefore.dev ||
			baseAfter.ino !== baseBefore.ino ||
			baseAfter.size !== baseBefore.size ||
			baseAfter.mtimeNs !== baseBefore.mtimeNs ||
			(await hashFile(disk)) !== baseHash
		)
			throw new Error("Candidate base changed during qualification");
		for (const input of inputPins) await verifyPinnedFile(input.path, input.sha256);
		if (
			!samePins(await directoryPins(runtime.firmwareDir), runtime.firmwarePins) ||
			!samePins(await directoryPins(runtime.libraryDir), libraryPins)
		)
			throw new Error("Runtime inputs changed during qualification");
		await fs.unlink(path.join(temporary, "disk", "root.qcow2"));
		snapshotOwned = false;
		await syncDirectory(path.join(temporary, "disk"));
		await removeScratch(temporary);
		scratchRetained = false;
		stage = "read-only base sealing";
		const base = await fs.open(disk, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
		try {
			const stat = await base.stat({ bigint: true });
			if (stat.dev !== baseBefore.dev || stat.ino !== baseBefore.ino || stat.mtimeNs !== baseBefore.mtimeNs)
				throw new Error("Base identity changed before sealing");
			await base.chmod(Number(stat.mode & 0o444n));
			await base.sync();
		} finally {
			await base.close();
		}
		await syncDirectory(opts.build);
		await verifyPinnedFile(disk, baseHash, true);
		const diagnostics: FilePin[] = [];
		for (const name of await fs.readdir(logs)) {
			const file = path.join(logs, name);
			diagnostics.push({ path: file, sha256: await hashFile(file) });
		}
		const qualification = await newJson(path.join(opts.out, "qualification.json"), {
			schema: 1,
			scope: "Linux P2 image qualification only; not full toolkit workflow acceptance, G2, or supported-release qualification",
			qualifiedAt: new Date().toISOString(),
			project,
			generation,
			isolation: {
				hostRoot: false,
				accelerator: "kvm",
				qmpConfirmed: true,
				network: "no guest NIC; unshared host network namespace",
				baseReadOnlyMount: true,
				temporaryWritableOverlay: true,
				bootToken: "ephemeral anonymous bubblewrap data mount; never persisted",
			},
			termination: {
				observed: true,
				exitCode: vm.child.exitCode,
				poweroffAccepted,
				forced,
				snapshotDiscarded: true,
				scratchRemoved: true,
			},
			base: {
				path: disk,
				beforeSha256: baseHash,
				afterSha256: baseHash,
				readOnly: true,
				qualificationHistoryWrittenToBase: false,
			},
			capture: { path: capturePath, sha256: await hashFile(capturePath), run },
			diagnostics,
			guestBundle: {
				...evidence.guestBundle,
				digestDefinition:
					"SHA-256 of the exact guest-sources.json bytes: sorted installed paths, verified source hashes, and original source bytes in base64",
			},
			observations: evidence.observations,
			limitations: [
				"All required tools have file/access validation; selected CLI version probes also executed. GUI, MCP, and security workflows have not been accepted.",
				"The supervisor and guest-reported inventory are within the trusted image boundary; this is not hardware attestation.",
				"No MCP tool list is treated as end-to-end workflow acceptance.",
			],
		});
		const provenance = await newJson(path.join(opts.out, "provenance.json"), {
			schema: 1,
			qualification,
			inputs: inputPins,
			runtime: { ...runtime, librariesObserved: libraryPins },
			packages: evidence.packages,
			guestBundle: evidence.guestBundle,
			exports: evidence.evidence,
			trust: {
				immutableHashes:
					"SHA-256 identifies the exact observed bytes; it does not establish authenticity on its own.",
				acquisition:
					"Local acquisition receipts claim signed Kali/APT verification. Their hashes and retained archives are checked here; upstream signatures are not independently reverified by this offline sealer.",
				libraries:
					"Dedicated acquired libraries are inventoried and checked for changes. Host root-owned dynamic libraries, the kernel, bubblewrap, and Bun remain trusted host inputs, not a hermetic pinned runtime.",
				sources:
					"Installed guest implementation bytes match seed guestInputs. MCP package code hashes describe patched installed sources, not upstream pristine archives.",
				rights:
					"Exported dpkg copyright/common-license records are evidence, not a complete redistribution or corresponding-source legal determination.",
				reproducibility: recipe.reproducibilityLimit,
				releaseStatus: "Development image only; no supported-release or G2 claim",
			},
		});
		const manifest: ImageManifest = {
			schema: 1,
			id: `agent-smith-kali-${baseHash.slice(0, 20)}`,
			isa: "x86_64",
			disk: { path: disk, sha256: baseHash },
			guestSha256: evidence.guestBundle.sha256,
			packages: evidence.packages,
			provenance,
		};
		stage = "manifest publication";
		abort.signal.throwIfAborted();
		publishing = true;
		await durableJson(path.join(opts.out, "image.json"), manifest);
		abort.signal.throwIfAborted();
	} catch (error) {
		guest?.close();
		guest = undefined;
		if (active) {
			try {
				await active.stop();
			} catch {
				/* Keep failure separate from whether process exit was actually observed. */
			}
		}
		stopped = !vm || processExited(vm.child);
		let captureInterruptionRecorded = false;
		try {
			await captures?.interrupted();
			captureInterruptionRecorded = true;
		} catch {
			/* The failure receipt must not imply that durable capture reconciliation succeeded. */
		}
		if (snapshotOwned && temporary && stopped && (!active || processExited(active.child))) {
			try {
				await fs.unlink(path.join(temporary, "disk", "root.qcow2"));
				snapshotOwned = false;
			} catch (cleanupError) {
				if (isEnoent(cleanupError)) snapshotOwned = false;
			}
		}
		if (temporary && scratchRetained && !snapshotOwned && stopped && (!active || processExited(active.child))) {
			try {
				await removeScratch(temporary);
				scratchRetained = false;
			} catch {
				/* Only empty owned directories and the two expected sockets are removed. */
			}
		}
		if (outCreated) {
			if (publishing)
				await fs.unlink(path.join(opts.out, "image.json")).catch(unlinkError => {
					if (!isEnoent(unlinkError)) throw unlinkError;
				});
			await durableJson(path.join(opts.out, "failure.json"), {
				schema: 1,
				stage,
				// Never persist exception payloads from guest/protocol/JSON parsers: they may contain secrets.
				error: error instanceof Error ? error.name : "UnknownError",
				vmTerminationObserved: vm ? stopped : null,
				processTerminationObserved: !active || processExited(active.child),
				captureInterruptionRecorded,
				snapshotRetained: snapshotOwned,
				scratchRetained,
				temporary,
				originalLogs: path.join(opts.out, "logs"),
				originalGuestCaptures: path.join(opts.out, "captures"),
				imagePublished: false,
			});
		}
		throw new Error(
			`Image sealing failed during ${stage}; ${outCreated ? "original evidence retained in the output directory" : "no output published"}`,
		);
	} finally {
		bootBytes?.fill(0);
		guest?.close();
		qmp?.close();
		clearTimeout(overall);
		for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"] as const) process.off(sig, onSignal);
		process.umask(previousUmask);
	}
}

if (import.meta.main) {
	try {
		const opts = options(Bun.argv.slice(2));
		if (!opts)
			console.log(
				"Usage: bun --no-env-file scripts/agent-smith-seal-image.ts --assets ABS --build ABS --out ABS\nRun after installer completion. Output must be a fresh directory. Image qualification only.",
			);
		else {
			await seal(opts);
			console.log(`Sealed image manifest: ${path.join(opts.out, "image.json")}`);
		}
	} catch (error) {
		console.error(error instanceof Error ? error.message : "Image sealing failed");
		// An unobserved, unkillable child must not keep this failed CLI alive forever.
		// Its retained receipt reports that failure; bubblewrap also dies with its parent.
		process.exit(1);
	}
}

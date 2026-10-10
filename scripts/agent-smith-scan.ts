import * as fs from "node:fs/promises";
import * as path from "node:path";
import { assertRuntime, BUN_VERSION, fail, fileHash, fixture, ROOT, sha256 } from "./agent-smith-common";
import type {
	DecoderCoverage,
	DecoderDisposition,
	DecoderProof,
	NativeEvidence,
	RawEvidence,
	VerifiedRawScan,
	WholeBlobProof,
} from "./agent-smith-scan-decoder";
import {
	APPLEDOUBLE,
	rawCommand,
	reconcileDecoder,
	reviewedMembers,
	reviewedVersion,
	verifyDecoderCoverage,
	verifyRawScan,
} from "./agent-smith-scan-decoder";
import type { HistoricalResult } from "./agent-smith-scan-history";
import { historicalCoverage, historyMetadata, parseHistoryMetadata } from "./agent-smith-scan-history";
import type { Decision, HistoricalVersion, PreparedLedger, Scope, ScopeOutcome } from "./agent-smith-scan-policy";
import {
	approvalsFor,
	decide,
	DEFAULT_CONFIG,
	HISTORY_SELECTION,
	oid,
	parseLedger,
	parseReport,
	prepareLedger,
	SCANNER_SHA256,
	SCANNER_VERSION,
	scopesPass,
	SOURCE_BASE,
	SOURCE_TREE,
} from "./agent-smith-scan-policy";
import type { GitContext } from "./agent-smith-scan-source";
import { bindFindings, blobs, git, neutralEnvironment, snapshot, sourceView } from "./agent-smith-scan-source";

const BUN_SHA256 = "a83d263767d839e4d2649ca8e35d07159c7afc99afdc96d731ced29e056dda0c";
const LEDGER = "scripts/agent-smith-scan-dispositions.json";
const INPUTS = [
	"scripts/agent-smith-common.ts",
	"scripts/agent-smith-scan.ts",
	"scripts/agent-smith-scan-source.ts",
	"scripts/agent-smith-scan-policy.ts",
	"scripts/agent-smith-scan-history.ts",
	"scripts/agent-smith-scan-decoder.ts",
	LEDGER,
];

interface Options {
	candidate?: string;
	targetBase?: string;
	gitleaks?: string;
	output?: string;
}
interface ScanReceipt extends ScopeOutcome {
	exitCode?: number;
	signal?: string | null;
	timedOut?: boolean;
	reportSha256?: string;
	stderrSha256?: string;
	stdoutSha256?: string;
	bindingsSha256?: string;
	invocationSha256?: string;
	decision?: Decision;
	nativeDecision?: Decision;
	decoderDisposition?: DecoderDisposition;
	decoderError?: string;
	error?: string;
}
interface HistoricalReceipt extends ScanReceipt {
	inventorySha256?: string;
	metadataSha256?: string;
	resultsSha256?: string;
	versions?: number;
	scanned?: number;
	binaryChanges?: number;
}
interface Summary {
	schemaVersion: 3;
	pass: boolean;
	sourceBase: string;
	sourceTree: string;
	candidate?: string;
	candidateTree?: string;
	targetBase?: string;
	ancestrySha256?: string;
	ancestryCommits?: number;
	attributeControlsSha256?: string;
	inputs?: Record<string, string>;
	toolchain?: Record<string, string>;
	snapshot?: { files: number; bytes: number; inventorySha256: string };
	history: ScanReceipt;
	tree: ScanReceipt;
	historicalBlob: HistoricalReceipt;
	errors: string[];
}
interface ProcessResult {
	exitCode: number;
	signal: string | null;
	timedOut: boolean;
	stdinBytes?: number;
}

function options(args: string[]): Options {
	if (args[0] === "--") args = args.slice(1);
	const result: Options = {};
	const names: Record<string, keyof Options> = {
		"--candidate": "candidate",
		"--target-base": "targetBase",
		"--gitleaks": "gitleaks",
		"--output": "output",
	};
	for (let i = 0; i < args.length; i += 2) {
		const key = Object.hasOwn(names, args[i]) ? names[args[i]] : undefined;
		const value = args[i + 1];
		if (!key || !value || value.startsWith("--") || result[key] !== undefined) {
			throw new Error("Invalid smith:scan arguments");
		}
		result[key] = value;
	}
	if (result.candidate) oid(result.candidate);
	if (result.targetBase) oid(result.targetBase);
	return result;
}

function errorMessage(error: unknown): string {
	return error instanceof Error ? error.message : "Unknown scan failure";
}

async function verifyInputs(context: GitContext, candidate: string): Promise<Record<string, string>> {
	const hashes: Record<string, string> = {};
	await blobs(
		context,
		INPUTS.map(file => ({ spec: `${candidate}:${file}` })),
		async (request, _blob, bytes) => {
			const file = request.spec.slice(41);
			const hash = sha256(bytes);
			if ((await fileHash(path.join(ROOT, file))) !== hash) {
				throw new Error(
					"Scan implementation/ledger differs from candidate; Main must integrate before qualification",
				);
			}
			hashes[file] = hash;
		},
	);
	return hashes;
}

async function execute(
	command: string[],
	cwd: string,
	env: NodeJS.ProcessEnv,
	output: string,
	label: string,
	input?: Uint8Array,
): Promise<ProcessResult> {
	await Bun.write(
		path.join(output, `${label}-invocation.json`),
		`${JSON.stringify(
			{ command, cwd, env, stdin: input ? { bytes: input.length, sha256: sha256(input) } : "ignore" },
			null,
			2,
		)}\n`,
	);
	const child = Bun.spawn(command, {
		cwd,
		env,
		stdin: input ? "pipe" : "ignore",
		stdout: Bun.file(path.join(output, `${label}-stdout.log`)),
		stderr: Bun.file(path.join(output, `${label}-errors.log`)),
	});
	let timedOut = false;
	const timer = setTimeout(() => {
		timedOut = true;
		child.kill("SIGKILL");
	}, 1_830_000);
	try {
		let stdinBytes: number | undefined;
		if (input) {
			if (!child.stdin) throw new Error("Missing scanner stdin pipe");
			stdinBytes = await child.stdin.write(input);
			await child.stdin.end();
			if (stdinBytes !== input.length) throw new Error("Incomplete scanner stdin write");
		}
		const exitCode = await child.exited;
		return { exitCode, signal: child.signalCode, timedOut, stdinBytes };
	} finally {
		clearTimeout(timer);
		if (child.exitCode === null) child.kill("SIGKILL");
		await child.exited;
	}
}

interface ScanContext {
	git: GitContext;
	candidate: string;
	commits: ReadonlySet<string>;
	scanner: string;
	config: string;
	ignore: string;
	output: string;
	prepared: PreparedLedger;
}

async function nativeEvidence(output: string, label: string, run: ProcessResult): Promise<NativeEvidence> {
	const [report, stderr, stdout] = await Promise.all([
		Bun.file(path.join(output, `${label}-findings.json`)).bytes(),
		Bun.file(path.join(output, `${label}-errors.log`)).bytes(),
		Bun.file(path.join(output, `${label}-stdout.log`)).bytes(),
	]);
	return { ...run, report, stderr, stdout };
}

async function receiptEvidence(output: string, scope: Scope, receipt: ScanReceipt): Promise<NativeEvidence> {
	const native = await nativeEvidence(output, scope, {
		exitCode: receipt.exitCode ?? -1,
		signal: receipt.signal === undefined ? "missing" : receipt.signal,
		timedOut: receipt.timedOut ?? true,
	});
	if (
		sha256(native.report) !== receipt.reportSha256 ||
		sha256(native.stderr) !== receipt.stderrSha256 ||
		sha256(native.stdout) !== receipt.stdoutSha256 ||
		(await fileHash(path.join(output, `${scope}-invocation.json`))) !== receipt.invocationSha256
	) {
		throw new Error("Native evidence changed before decoder reconciliation");
	}
	return native;
}

function reconcileReceipt(receipt: ScanReceipt, disposition: DecoderDisposition | undefined): void {
	if (!receipt.decision) return;
	if (disposition) {
		receipt.nativeDecision = receipt.decision;
		receipt.decoderDisposition = disposition;
		receipt.decision = disposition.decision;
	} else {
		receipt.decision.errors.push("Reviewed decoder errors lack exact complete supplemental proof");
		receipt.decision.pass = false;
	}
	receipt.status = receipt.complete && receipt.decision.pass ? "passed" : "failed";
}

interface SupplementalResult {
	proof: DecoderProof;
	files: Map<string, string>;
}

/** Fresh scans of all complete raw members. Nothing is extracted or executed from the archive. */
async function scanRawMembers(
	context: ScanContext,
	coverage: DecoderCoverage,
	version: HistoricalVersion,
	archive: Uint8Array,
): Promise<SupplementalResult> {
	const members = reviewedMembers(archive, version);
	const output = path.join(context.output, "appledouble");
	await fs.mkdir(output, { mode: 0o700 });
	const files = new Map<string, string>();
	const scans: VerifiedRawScan[] = [];
	let failed = false;
	for (const [index, input] of members.entries()) {
		const label = `member-${index + 1}`;
		const locations = {
			scanner: context.scanner,
			config: context.config,
			ignore: context.ignore,
			report: path.join(output, `${label}-findings.json`),
		};
		const command = rawCommand(locations);
		const receiptFile = path.join(output, `${label}-receipt.json`);
		const receipt: Record<string, unknown> = {
			member: APPLEDOUBLE.members[index].path,
			inputBytes: input.length,
			inputSha256: sha256(input),
			pass: false,
		};
		try {
			const scannerSha256 = await fileHash(context.scanner);
			const config = await Bun.file(context.config).bytes();
			const ignore = await Bun.file(context.ignore).bytes();
			if (
				scannerSha256 !== SCANNER_SHA256 ||
				sha256(config) !== sha256(new TextEncoder().encode(DEFAULT_CONFIG)) ||
				ignore.length !== 0
			)
				throw new Error("Raw scan tool/configuration changed");
			const run = await execute(command, context.git.cwd, context.git.env, output, label, input);
			Object.assign(receipt, run);
			const evidence: RawEvidence = {
				...(await nativeEvidence(output, label, run)),
				command,
				scannerSha256,
				scannerVersion: SCANNER_VERSION,
				config,
				ignore,
				input,
				stdinBytes: run.stdinBytes ?? -1,
			};
			const binding = {
				member: APPLEDOUBLE.members[index].path,
				bytes: input.length,
				inputSha256: sha256(input),
				reportSha256: sha256(evidence.report),
				stderrSha256: sha256(evidence.stderr),
				stdoutSha256: sha256(evidence.stdout),
				invocationSha256: await fileHash(path.join(output, `${label}-invocation.json`)),
				receiptSha256: "",
			};
			Object.assign(receipt, {
				...binding,
				receiptSha256: undefined,
				scannerSha256,
				scannerVersion: SCANNER_VERSION,
				configSha256: sha256(config),
				ignoreSha256: sha256(ignore),
				command,
			});
			verifyRawScan(evidence, locations);
			if (
				(await fileHash(context.scanner)) !== scannerSha256 ||
				(await fileHash(context.config)) !== sha256(config) ||
				(await fileHash(context.ignore)) !== sha256(ignore)
			)
				throw new Error("Raw scan inputs changed during execution");
			receipt.pass = true;
			await Bun.write(receiptFile, `${JSON.stringify(receipt, null, 2)}\n`);
			binding.receiptSha256 = await fileHash(receiptFile);
			for (const [name, hash] of [
				[`${label}-receipt.json`, binding.receiptSha256],
				[`${label}-findings.json`, binding.reportSha256],
				[`${label}-errors.log`, binding.stderrSha256],
				[`${label}-stdout.log`, binding.stdoutSha256],
				[`${label}-invocation.json`, binding.invocationSha256],
			])
				files.set(path.join(output, name), hash);
			scans.push({ binding, evidence, locations });
		} catch (error) {
			failed = true;
			receipt.pass = false;
			receipt.error = errorMessage(error);
			await Bun.write(receiptFile, `${JSON.stringify(receipt, null, 2)}\n`);
		}
	}
	if (failed || scans.length !== APPLEDOUBLE.members.length)
		throw new Error("Raw metadata supplement failed; native errors remain blocking");
	const proofFile = path.join(output, "proof.json");
	const provenance = {
		coverage,
		version,
		reviewSha256: APPLEDOUBLE.reviewSha256,
		archiveSha256: sha256(archive),
		tarSha256: APPLEDOUBLE.tarSha256,
	};
	await Bun.write(
		proofFile,
		`${JSON.stringify(
			{
				...provenance,
				archiveBytes: archive.length,
				tarBytes: APPLEDOUBLE.tarBytes,
				members: scans.map((scan, index) => ({
					...scan.binding,
					headerOffset: APPLEDOUBLE.members[index].headerOffset,
					dataOffset: APPLEDOUBLE.members[index].dataOffset,
				})),
			},
			null,
			2,
		)}\n`,
	);
	const proofSha256 = await fileHash(proofFile);
	files.set(proofFile, proofSha256);
	return { proof: { ...provenance, members: scans, proofSha256 }, files };
}

async function verifySupplementFiles(supplement: SupplementalResult): Promise<void> {
	for (const [file, expected] of supplement.files) {
		if ((await fileHash(file)) !== expected) throw new Error("Supplemental native evidence changed or is missing");
	}
}

async function scan(
	scope: Scope,
	cwd: string,
	context: ScanContext,
	version?: HistoricalVersion,
): Promise<ScanReceipt> {
	const receipt: ScanReceipt = { status: "failed", complete: false };
	const reportFile = path.join(context.output, `${scope}-findings.json`);
	const command = [
		context.scanner,
		scope === "history" ? "git" : "dir",
		"--no-banner",
		"--no-color",
		"--log-level=error",
		"--redact=100",
		"--ignore-gitleaks-allow",
		"--max-archive-depth=2",
		"--max-decode-depth=2",
		"--max-target-megabytes=0",
		"--exit-code=1",
		"--timeout=1800",
		`--config=${context.config}`,
		`--gitleaks-ignore-path=${context.ignore}`,
		"--report-format=json",
		`--report-path=${reportFile}`,
	];
	if (scope === "history") {
		command.push("--platform=none", `--log-opts=${HISTORY_SELECTION.join(" ")} ${context.candidate}`);
	}
	command.push(".");
	try {
		if (context.git.env.GIT_ATTR_SOURCE !== SOURCE_BASE) throw new Error("Scanner attribute source mismatch");
		Object.assign(receipt, await execute(command, cwd, context.git.env, context.output, scope));
		receipt.invocationSha256 = await fileHash(path.join(context.output, `${scope}-invocation.json`));
		const stderr = await Bun.file(path.join(context.output, `${scope}-errors.log`)).bytes();
		const stdout = await Bun.file(path.join(context.output, `${scope}-stdout.log`)).bytes();
		receipt.stderrSha256 = sha256(stderr);
		receipt.stdoutSha256 = sha256(stdout);
		const reportBytes = await Bun.file(reportFile).bytes();
		receipt.reportSha256 = sha256(reportBytes);
		const report: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(reportBytes));
		const findings = parseReport(report, scope);
		const containers = approvalsFor(context.prepared, scope, version).rows;
		const bindings = await bindFindings(
			context.git,
			findings,
			context.candidate,
			context.commits,
			containers,
			version,
		);
		const bindingsFile = path.join(context.output, `${scope}-bindings.json`);
		await Bun.write(bindingsFile, `${JSON.stringify([...bindings], null, 2)}\n`);
		receipt.bindingsSha256 = await fileHash(bindingsFile);
		receipt.decision = decide(
			report,
			scope,
			context.prepared,
			bindings,
			receipt.exitCode ?? -1,
			new TextDecoder("utf-8", { fatal: true }).decode(stderr),
			receipt.reportSha256,
			version,
		);
		if (stdout.length !== 0) {
			receipt.decision.errors.push("Unexpected scanner stdout");
			receipt.decision.pass = false;
		}
		receipt.complete =
			!receipt.timedOut && receipt.signal === null && (receipt.exitCode === 0 || receipt.exitCode === 1);
		if (!receipt.complete) {
			receipt.decision.errors.push("Scanner execution did not complete normally");
			receipt.decision.pass = false;
		}
		receipt.status = receipt.decision.pass ? "passed" : "failed";
	} catch (error) {
		receipt.error = errorMessage(error);
	}
	return receipt;
}

interface HistoricalScan {
	receipt: HistoricalReceipt;
	supplement?: SupplementalResult;
	wholeBlob?: WholeBlobProof;
}

async function scanHistoricalBlobs(
	context: ScanContext,
	ownedDir: string,
	candidateTree: string,
	ancestrySha256: string,
): Promise<HistoricalScan> {
	const receipt: HistoricalReceipt = { status: "failed", complete: false, scanned: 0 };
	const outcome: HistoricalScan = { receipt };
	try {
		const metadata = await historyMetadata(context.git, context.candidate);
		const metadataFile = path.join(context.output, "history-metadata.nul");
		await Bun.write(metadataFile, metadata);
		receipt.metadataSha256 = sha256(metadata);
		const inventory = parseHistoryMetadata(metadata, context.commits);
		const inventoryFile = path.join(context.output, "historical-blob-inventory.json");
		await Bun.write(
			inventoryFile,
			`${JSON.stringify(
				{
					schemaVersion: 1,
					candidate: context.candidate,
					candidateTree,
					ancestrySha256,
					attributeSource: SOURCE_BASE,
					attributeTree: SOURCE_TREE,
					selection: HISTORY_SELECTION,
					metadataSha256: receipt.metadataSha256,
					...inventory,
				},
				null,
				2,
			)}\n`,
		);
		receipt.inventorySha256 = await fileHash(inventoryFile);
		receipt.versions = inventory.versions.length;
		receipt.binaryChanges = inventory.binaryChanges;
		let decoderCoverage: DecoderCoverage | undefined;
		try {
			const coverage: DecoderCoverage = {
				candidate: context.candidate,
				candidateTree,
				ancestrySha256,
				metadataSha256: receipt.metadataSha256,
				inventorySha256: receipt.inventorySha256,
				attributeSource: SOURCE_BASE,
				attributeTree: SOURCE_TREE,
			};
			verifyDecoderCoverage(inventory, context.commits, coverage);
			decoderCoverage = coverage;
		} catch (error) {
			receipt.decoderError = errorMessage(error);
		}
		let target:
			| {
					version: HistoricalVersion;
					receipt: ScanReceipt;
					output: string;
					receiptSha256: string;
					contextSha256: string;
			  }
			| undefined;
		const results: (HistoricalResult & { receiptSha256: string; contextSha256: string; directory: string })[] = [];
		const resultsFile = path.join(context.output, "historical-blob-results.json");
		const exports = path.join(ownedDir, "historical-exports");
		await fs.mkdir(exports, { mode: 0o700 });
		for (const [index, version] of inventory.versions.entries()) {
			const directory = `historical-blobs/${String(index + 1).padStart(6, "0")}`;
			const output = path.join(context.output, directory);
			await fs.mkdir(output, { recursive: true, mode: 0o700 });
			const contextFile = path.join(output, "context.json");
			const receiptFile = path.join(output, "receipt.json");
			const objectContext: {
				version: HistoricalVersion;
				inventorySha256: string;
				bytes?: number;
				containerSha256?: string;
			} = { version, inventorySha256: receipt.inventorySha256 };
			let objectReceipt: ScanReceipt = { status: "failed", complete: false };
			let snapshotDir: string | undefined;
			let cleanupFailed = false;
			try {
				snapshotDir = await fs.mkdtemp(path.join(exports, "object-"));
				const file = path.join(snapshotDir, version.file);
				// This cat-file exits before the scanner starts; no batch timer spans child scans.
				await blobs(context.git, [{ spec: version.blob, blob: version.blob }], async (_request, _blob, bytes) => {
					objectContext.bytes = bytes.length;
					objectContext.containerSha256 = sha256(bytes);
					await Bun.write(file, bytes);
					await fs.chmod(file, 0o600);
					if ((await fileHash(file)) !== objectContext.containerSha256) {
						throw new Error("Historical export changed Git bytes");
					}
				});
				await Bun.write(contextFile, `${JSON.stringify(objectContext, null, 2)}\n`);
				objectReceipt = await scan("historicalBlob", snapshotDir, { ...context, output }, version);
				if ((await fileHash(file)) !== objectContext.containerSha256) {
					throw new Error("Historical snapshot changed during scan");
				}
				if (reviewedVersion(version)) {
					try {
						if (!decoderCoverage) throw new Error("No complete immutable decoder coverage binding");
						const supplement = await scanRawMembers(
							{ ...context, output },
							decoderCoverage,
							version,
							await Bun.file(file).bytes(),
						);
						await verifySupplementFiles(supplement);
						const native = await receiptEvidence(output, "historicalBlob", objectReceipt);
						reconcileReceipt(
							objectReceipt,
							objectReceipt.decision &&
								reconcileDecoder(
									objectReceipt.decision,
									"historicalBlob",
									native,
									decoderCoverage,
									supplement.proof,
									version,
								),
						);
						outcome.supplement = supplement;
					} catch (error) {
						objectReceipt.decoderError = errorMessage(error);
						reconcileReceipt(objectReceipt, undefined);
					}
				}
			} catch (error) {
				objectReceipt.status = "failed";
				objectReceipt.complete = false;
				objectReceipt.error = errorMessage(error);
			} finally {
				// Persist native report context and failure evidence before removing just this owned export.
				await Bun.write(contextFile, `${JSON.stringify(objectContext, null, 2)}\n`);
				await Bun.write(receiptFile, `${JSON.stringify(objectReceipt, null, 2)}\n`);
				if (snapshotDir) {
					try {
						await fs.rm(snapshotDir, { recursive: true });
					} catch {
						cleanupFailed = true;
						objectReceipt.status = "failed";
						objectReceipt.complete = false;
						objectReceipt.error = "Owned historical export cleanup failed";
						await Bun.write(receiptFile, `${JSON.stringify(objectReceipt, null, 2)}\n`);
					}
				}
			}
			const result = {
				version,
				directory,
				complete: objectReceipt.complete,
				pass: objectReceipt.status === "passed",
				receiptSha256: await fileHash(receiptFile),
				contextSha256: await fileHash(contextFile),
			};
			results.push(result);
			if (reviewedVersion(version)) target = { ...result, receipt: objectReceipt, output };
			if (result.complete) receipt.scanned = (receipt.scanned ?? 0) + 1;
			await Bun.write(resultsFile, `${JSON.stringify(results, null, 2)}\n`);
			receipt.resultsSha256 = await fileHash(resultsFile);
			if (cleanupFailed)
				throw new Error("Historical export retained after cleanup failure; remaining versions not run");
		}
		// An empty inventory still has an explicit, bound results collection.
		await Bun.write(resultsFile, `${JSON.stringify(results, null, 2)}\n`);
		receipt.resultsSha256 = await fileHash(resultsFile);
		const coverage = historicalCoverage(inventory.versions, results);
		receipt.complete = coverage.complete;
		receipt.status = coverage.pass ? "passed" : "failed";
		if (
			(await fileHash(metadataFile)) !== receipt.metadataSha256 ||
			(await fileHash(inventoryFile)) !== receipt.inventorySha256
		) {
			throw new Error("Historical coverage metadata changed during execution");
		}
		if (outcome.supplement && target) {
			await verifySupplementFiles(outcome.supplement);
			await receiptEvidence(target.output, "historicalBlob", target.receipt);
			if (
				(await fileHash(path.join(target.output, "receipt.json"))) !== target.receiptSha256 ||
				(await fileHash(path.join(target.output, "context.json"))) !== target.contextSha256
			) {
				throw new Error("Whole-blob decoder receipt/context changed");
			}
			outcome.wholeBlob = {
				version: target.version,
				complete: target.receipt.complete,
				pass: target.receipt.status === "passed",
				allVersionsComplete: coverage.complete,
				contextSha256: target.contextSha256,
				receiptSha256: target.receiptSha256,
				reportSha256: target.receipt.reportSha256 ?? "",
				stderrSha256: target.receipt.stderrSha256 ?? "",
				proofSha256: outcome.supplement.proof.proofSha256,
				inventorySha256: receipt.inventorySha256,
				resultsSha256: receipt.resultsSha256,
			};
			for (const [file, hash] of [
				[metadataFile, receipt.metadataSha256],
				[inventoryFile, receipt.inventorySha256],
				[resultsFile, receipt.resultsSha256],
				[path.join(target.output, "context.json"), target.contextSha256],
				[path.join(target.output, "receipt.json"), target.receiptSha256],
				[path.join(target.output, "historicalBlob-findings.json"), target.receipt.reportSha256],
				[path.join(target.output, "historicalBlob-errors.log"), target.receipt.stderrSha256],
				[path.join(target.output, "historicalBlob-stdout.log"), target.receipt.stdoutSha256],
				[path.join(target.output, "historicalBlob-invocation.json"), target.receipt.invocationSha256],
			] as const) {
				if (!hash) throw new Error("Missing whole-blob decoder evidence digest");
				outcome.supplement.files.set(file, hash);
			}
			await verifySupplementFiles(outcome.supplement);
		}
	} catch (error) {
		receipt.status = "failed";
		receipt.complete = false;
		receipt.error = errorMessage(error);
		outcome.wholeBlob = undefined;
	}
	return outcome;
}

async function main(): Promise<void> {
	const args = options(process.argv.slice(2));
	const owned = await fixture("scan");
	const output = args.output ? path.resolve(args.output) : path.join(owned.dir, "evidence");
	// An existing output directory is never reused: stale reports cannot satisfy this run.
	await fs.mkdir(output, { mode: 0o700 });
	const summary: Summary = {
		schemaVersion: 3,
		pass: false,
		sourceBase: SOURCE_BASE,
		sourceTree: SOURCE_TREE,
		history: { status: "not-run", complete: false },
		tree: { status: "not-run", complete: false },
		historicalBlob: { status: "not-run", complete: false },
		errors: [],
	};
	try {
		assertRuntime();
		if (process.platform !== "linux" || process.arch !== "x64") {
			throw new Error("smith:scan supports only Linux x64 tools");
		}
		if ((await fileHash(process.execPath)) !== BUN_SHA256) {
			throw new Error("Bun executable does not match the verified 1.4.2 release");
		}
		const scannerInput = args.gitleaks ?? Bun.which("gitleaks", { PATH: process.env.PATH });
		const gitInput = Bun.which("git", { PATH: process.env.PATH });
		if (!scannerInput || !gitInput) {
			throw new Error("Main must provision Git and Gitleaks; smith:scan never installs tools");
		}
		const scanner = path.join(owned.dir, "gitleaks");
		await fs.copyFile(scannerInput, scanner);
		await fs.chmod(scanner, 0o700);
		if ((await fileHash(scanner)) !== SCANNER_SHA256) throw new Error("Gitleaks executable digest mismatch");
		const gitExecutable = await fs.realpath(gitInput);
		if (gitExecutable.startsWith(`${ROOT}${path.sep}`)) {
			throw new Error("Git must be an owner-provisioned tool outside the source tree");
		}
		// Drop Bun run's injected dependency paths. Gitleaks only needs this Git executable.
		owned.env.PATH = path.dirname(gitExecutable);
		const empty = path.join(owned.dir, "empty");
		await Bun.write(empty, "");
		const env = neutralEnvironment(owned.env, empty);
		const context: GitContext = {
			executable: gitExecutable,
			cwd: owned.cwd,
			env,
			logs: path.join(output, "git-errors.log"),
		};
		await Bun.write(context.logs, "");
		const versionRun = await execute([scanner, "version"], owned.cwd, env, output, "scanner-version");
		if (
			versionRun.exitCode !== 0 ||
			versionRun.signal !== null ||
			versionRun.timedOut ||
			(await Bun.file(path.join(output, "scanner-version-stdout.log")).text()).trim() !== SCANNER_VERSION ||
			(await fs.stat(path.join(output, "scanner-version-errors.log"))).size !== 0
		) {
			throw new Error("Scanner version probe failed");
		}
		const gitVersion = (await git(context, ["--version"])).trim();
		const candidate = args.candidate ?? (await git({ ...context, cwd: ROOT }, ["rev-parse", "HEAD"])).trim();
		summary.candidate = oid(candidate);
		summary.targetBase = args.targetBase;
		const source = await sourceView(context, owned.dir, candidate, args.targetBase);
		summary.candidateTree = source.tree;
		summary.ancestrySha256 = source.ancestrySha256;
		summary.ancestryCommits = source.commits.size;
		await fs.copyFile(path.join(owned.dir, "ancestry.txt"), path.join(output, "ancestry.txt"));
		const controlsFile = path.join(output, "attribute-controls.json");
		await fs.copyFile(path.join(owned.dir, "attribute-controls.json"), controlsFile);
		summary.attributeControlsSha256 = await fileHash(controlsFile);
		summary.inputs = await verifyInputs(source.context, candidate);
		const ledger = parseLedger(await Bun.file(path.join(ROOT, LEDGER)).json());
		const reviewedTrees = new Map<string, string>();
		for (const origin of Object.values(ledger.origins)) {
			if (!source.commits.has(origin.sourceCommit)) throw new Error("Reviewed source outside candidate ancestry");
			let reviewedTree = reviewedTrees.get(origin.sourceCommit);
			if (reviewedTree === undefined) {
				reviewedTree = (await git(source.context, ["rev-parse", `${origin.sourceCommit}^{tree}`])).trim();
				reviewedTrees.set(origin.sourceCommit, reviewedTree);
			}
			if (reviewedTree !== origin.sourceTree) {
				throw new Error("Review source tree identity mismatch");
			}
		}
		const config = path.join(output, "default-rules.toml");
		const ignore = path.join(output, "empty-ignore");
		await Bun.write(config, DEFAULT_CONFIG);
		await Bun.write(ignore, "");
		summary.toolchain = {
			bunVersion: BUN_VERSION,
			bunSha256: BUN_SHA256,
			gitleaksVersion: SCANNER_VERSION,
			gitleaksSha256: SCANNER_SHA256,
			gitVersion,
			gitSha256: await fileHash(gitExecutable),
			configSha256: await fileHash(config),
			ignoreSha256: await fileHash(ignore),
			emptyGitConfigSha256: await fileHash(empty),
			attributeSource: SOURCE_BASE,
			attributeTree: SOURCE_TREE,
			goMemoryLimit: env.GOMEMLIMIT ?? "",
			goMaxProcs: env.GOMAXPROCS ?? "",
		};
		const scanContext: ScanContext = {
			git: source.context,
			candidate,
			commits: source.commits,
			scanner,
			config,
			ignore,
			output,
			prepared: prepareLedger(ledger),
		};
		// Findings/decoder errors in any scope never short-circuit the other scopes.
		summary.history = await scan("history", source.context.cwd, scanContext);
		await Bun.write(
			path.join(output, "history-native-receipt.json"),
			`${JSON.stringify(summary.history, null, 2)}\n`,
		);
		const historyNativeReceiptSha256 = await fileHash(path.join(output, "history-native-receipt.json"));
		const historical = await scanHistoricalBlobs(scanContext, owned.dir, source.tree, source.ancestrySha256);
		summary.historicalBlob = historical.receipt;
		try {
			const supplement = historical.supplement;
			if (!supplement || !historical.wholeBlob)
				throw new Error("Missing complete whole-blob/supplemental decoder proof");
			await verifySupplementFiles(supplement);
			const native = await receiptEvidence(output, "history", summary.history);
			for (const [name, hash] of [
				["history-native-receipt.json", historyNativeReceiptSha256],
				["history-findings.json", summary.history.reportSha256],
				["history-errors.log", summary.history.stderrSha256],
				["history-stdout.log", summary.history.stdoutSha256],
				["history-invocation.json", summary.history.invocationSha256],
			] as const) {
				if (!hash) throw new Error("Missing history decoder evidence digest");
				supplement.files.set(path.join(output, name), hash);
			}
			await verifySupplementFiles(supplement);
			reconcileReceipt(
				summary.history,
				summary.history.decision &&
					reconcileDecoder(
						summary.history.decision,
						"history",
						native,
						supplement.proof.coverage,
						supplement.proof,
						undefined,
						historical.wholeBlob,
					),
			);
		} catch (error) {
			summary.history.decoderError = errorMessage(error);
			reconcileReceipt(summary.history, undefined);
		}
		await Bun.write(path.join(output, "history-receipt.json"), `${JSON.stringify(summary.history, null, 2)}\n`);
		try {
			const treeDir = path.join(owned.dir, "snapshot");
			const inventory = await snapshot(source.context, source.tree, treeDir);
			const inventoryFile = path.join(output, "snapshot-inventory.json");
			await Bun.write(inventoryFile, `${JSON.stringify(inventory, null, 2)}\n`);
			summary.snapshot = {
				files: inventory.length,
				bytes: inventory.reduce((total, item) => total + item.bytes, 0),
				inventorySha256: await fileHash(inventoryFile),
			};
			summary.tree = await scan("tree", treeDir, scanContext);
			for (const item of inventory) {
				if ((await fileHash(path.join(treeDir, item.file))) !== item.sha256) {
					throw new Error("Snapshot changed during scan");
				}
			}
		} catch (error) {
			summary.tree.status = "failed";
			summary.tree.complete = false;
			summary.tree.error = errorMessage(error);
		}
		for (const [file, expected] of [
			[scanner, SCANNER_SHA256],
			[process.execPath, BUN_SHA256],
			[gitExecutable, summary.toolchain.gitSha256],
			[config, summary.toolchain.configSha256],
			[ignore, summary.toolchain.ignoreSha256],
			[empty, summary.toolchain.emptyGitConfigSha256],
			[controlsFile, summary.attributeControlsSha256],
		]) {
			if ((await fileHash(file)) !== expected) throw new Error("Scan tool/configuration changed during execution");
		}
		if (historical.supplement) await verifySupplementFiles(historical.supplement);
		await verifyInputs(source.context, candidate);
		const finalAncestry = await git(source.context, ["rev-list", "--parents", candidate]);
		if (
			sha256(new TextEncoder().encode(finalAncestry)) !== source.ancestrySha256 ||
			(await git(source.context, ["rev-parse", `${candidate}^{tree}`])).trim() !== source.tree ||
			(await git(source.context, ["rev-parse", `${SOURCE_BASE}^{tree}`])).trim() !== SOURCE_TREE
		) {
			throw new Error("Immutable source coverage changed during scan");
		}
		if ((await git({ ...context, cwd: ROOT }, ["rev-parse", "HEAD"])).trim() !== candidate) {
			throw new Error("Source HEAD moved during scan");
		}
	} catch (error) {
		summary.errors.push(errorMessage(error));
	} finally {
		summary.pass = scopesPass(summary, summary.errors);
		await Bun.write(path.join(output, "summary.json"), `${JSON.stringify(summary, null, 2)}\n`);
		console.log(
			`smith:scan ${summary.pass ? "PASS" : "FAIL"}; history=${summary.history.status}, historicalBlob=${summary.historicalBlob.status}, tree=${summary.tree.status}`,
		);
		console.log(`Retained scan evidence: ${output}`);
		if (!summary.pass) process.exitCode = 1;
	}
}

if (import.meta.main) main().catch(fail);

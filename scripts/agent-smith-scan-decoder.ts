import { gunzipSync } from "node:zlib";
import { sha256 } from "./agent-smith-common";
import type { HistoryMetadata } from "./agent-smith-scan-history";
import type { Decision, HistoricalVersion, Scope } from "./agent-smith-scan-policy";
import {
	DEFAULT_CONFIG,
	digest,
	oid,
	SCANNER_SHA256,
	SCANNER_VERSION,
	SOURCE_BASE,
	SOURCE_TREE,
	STDERR_ERROR,
} from "./agent-smith-scan-policy";

/** Independent review of these bytes only; never a path/rule/archive-type allowance. */
export const APPLEDOUBLE = {
	reviewSha256: "8d680bd86f879d1474864869c86185e9c68fc009ad046fd32b5e7477ee8ab496",
	file: "packages/utils/test/fixtures/ar.tar.gz",
	commit: "6f0fec7bd2de45672050c2aba6be5406bc72e6b6",
	blob: "cbc578e0d5e4dd556ad1d9d548e9086318e4831d",
	bytes: 111382,
	sha256: "f566e0d45e67770a10fd9e10e8ec6595271e33980f5e5ab926928bfd7ef10bdd",
	tarBytes: 1091072,
	tarSha256: "866d7d5bb9d923891fb458f968acdac9f2d88087528d78623589c85e06615fcc",
	memberBytes: 163,
	memberSha256: "6e10830b3322767c84d06a89b611d2bf34e039257fde890dbc3070d3f9b0e653",
	members: [
		{ path: "codecs/._bzip-concatenated.bz2", headerOffset: 124928, dataOffset: 125440 },
		{ path: "codecs/._bzip-level-9.txt.bz2", headerOffset: 194048, dataOffset: 194560 },
		{ path: "codecs/._bzip-level-1.txt.bz2", headerOffset: 226304, dataOffset: 226816 },
	],
} as const;

export function reviewedVersion(version: HistoricalVersion): boolean {
	return (
		version.file === APPLEDOUBLE.file &&
		version.blob === APPLEDOUBLE.blob &&
		version.commits.length === 1 &&
		version.commits[0] === APPLEDOUBLE.commit
	);
}

export interface DecoderCoverage {
	candidate: string;
	candidateTree: string;
	ancestrySha256: string;
	metadataSha256: string;
	inventorySha256: string;
	attributeSource: string;
	attributeTree: string;
}

/** Called on the complete parsed candidate metadata, never a selected path's log. */
export function verifyDecoderCoverage(
	inventory: HistoryMetadata,
	ancestry: ReadonlySet<string>,
	coverage: DecoderCoverage,
): void {
	oid(coverage.candidate);
	oid(coverage.candidateTree);
	digest(coverage.ancestrySha256);
	digest(coverage.metadataSha256);
	digest(coverage.inventorySha256);
	const commits = new Set(inventory.commits.map(item => item.commit));
	if (
		coverage.attributeSource !== SOURCE_BASE ||
		coverage.attributeTree !== SOURCE_TREE ||
		!ancestry.has(SOURCE_BASE) ||
		!ancestry.has(APPLEDOUBLE.commit) ||
		!ancestry.has(coverage.candidate) ||
		commits.size !== inventory.commits.length ||
		commits.size !== ancestry.size ||
		[...ancestry].some(commit => !commits.has(commit))
	) {
		throw new Error("Decoder proof lacks complete pinned-base candidate ancestry/inventory");
	}
	const occurrences = inventory.commits.flatMap(({ commit, changes }) =>
		changes
			.filter(
				change =>
					change.file === APPLEDOUBLE.file ||
					change.blob === APPLEDOUBLE.blob ||
					change.oldBlob === APPLEDOUBLE.blob,
			)
			.map(change => ({ commit, change })),
	);
	const occurrence = occurrences[0];
	const versions = inventory.versions.filter(
		version => version.file === APPLEDOUBLE.file || version.blob === APPLEDOUBLE.blob,
	);
	if (
		occurrences.length !== 1 ||
		!occurrence ||
		occurrence.commit !== APPLEDOUBLE.commit ||
		occurrence.change.file !== APPLEDOUBLE.file ||
		occurrence.change.blob !== APPLEDOUBLE.blob ||
		occurrence.change.status !== "A" ||
		occurrence.change.oldBlob !== "0".repeat(40) ||
		occurrence.change.oldMode !== "000000" ||
		occurrence.change.mode !== "100644" ||
		!occurrence.change.binary ||
		versions.length !== 1 ||
		!reviewedVersion(versions[0])
	) {
		throw new Error("Decoder proof requires the sole exact baseline archive occurrence");
	}
}

export function verifyAppleDouble(bytes: Uint8Array): void {
	const data = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
	// AppleDouble v2: Finder/extended attributes [50,163), empty resource fork at EOF.
	if (
		data.length !== APPLEDOUBLE.memberBytes ||
		data.readUInt32BE(0) !== 0x00051607 ||
		data.readUInt32BE(4) !== 0x00020000 ||
		data.readUInt16BE(24) !== 2 ||
		data.readUInt32BE(26) !== 9 ||
		data.readUInt32BE(30) !== 50 ||
		data.readUInt32BE(34) !== 113 ||
		data.readUInt32BE(38) !== 2 ||
		data.readUInt32BE(42) !== 163 ||
		data.readUInt32BE(46) !== 0 ||
		sha256(bytes) !== APPLEDOUBLE.memberSha256
	) {
		throw new Error("Changed or unsupported AppleDouble metadata member");
	}
}

/** Fixed reviewed ranges only, after verifying the entire immutable gzip and tar. No extraction to disk. */
export function reviewedMembers(archive: Uint8Array, version: HistoricalVersion): Uint8Array[] {
	if (
		!reviewedVersion(version) ||
		archive.length !== APPLEDOUBLE.bytes ||
		sha256(archive) !== APPLEDOUBLE.sha256 ||
		new Bun.CryptoHasher("sha1").update(`blob ${archive.length}\0`).update(archive).digest("hex") !== APPLEDOUBLE.blob
	) {
		throw new Error("Changed archive bytes or historical version");
	}
	const tar = gunzipSync(archive, { maxOutputLength: APPLEDOUBLE.tarBytes });
	if (tar.length !== APPLEDOUBLE.tarBytes || sha256(tar) !== APPLEDOUBLE.tarSha256) {
		throw new Error("Changed inflated archive");
	}
	return APPLEDOUBLE.members.map(member => {
		const header = tar.subarray(member.headerOffset, member.dataOffset);
		const end = member.dataOffset + APPLEDOUBLE.memberBytes;
		const name = header.subarray(0, 100);
		const terminator = name.indexOf(0);
		const checksum = header.reduce((sum, byte, index) => sum + (index >= 148 && index < 156 ? 32 : byte), 0);
		if (
			member.headerOffset % 512 !== 0 ||
			header.length !== 512 ||
			end > tar.length ||
			terminator < 0 ||
			name.subarray(0, terminator).toString("utf8") !== member.path ||
			name.subarray(terminator).some(byte => byte !== 0) ||
			header[156] !== 48 ||
			header.subarray(124, 136).toString("ascii") !== "00000000243 " ||
			header.subarray(257, 263).toString("ascii") !== "ustar\0" ||
			header.subarray(263, 265).toString("ascii") !== "00" ||
			header.subarray(345, 500).some(byte => byte !== 0) ||
			!/^[0-7]{6}\0 $/.test(header.subarray(148, 156).toString("ascii")) ||
			Number.parseInt(header.subarray(148, 154).toString("ascii"), 8) !== checksum ||
			tar.subarray(end, member.dataOffset + 512).some(byte => byte !== 0)
		) {
			throw new Error("Reviewed tar member header/path/size/range mismatch");
		}
		const bytes = tar.subarray(member.dataOffset, end);
		verifyAppleDouble(bytes);
		return bytes;
	});
}

export interface ScanLocations {
	scanner: string;
	config: string;
	ignore: string;
	report: string;
}

export function rawCommand(locations: ScanLocations): string[] {
	return [
		locations.scanner,
		"stdin",
		"--no-banner",
		"--no-color",
		"--log-level=error",
		"--redact=100",
		"--ignore-gitleaks-allow",
		"--max-archive-depth=0",
		"--max-decode-depth=2",
		"--max-target-megabytes=0",
		"--exit-code=1",
		"--timeout=1800",
		`--config=${locations.config}`,
		`--gitleaks-ignore-path=${locations.ignore}`,
		"--report-format=json",
		`--report-path=${locations.report}`,
	];
}

export interface NativeEvidence {
	exitCode: number;
	signal: string | null;
	timedOut: boolean;
	report: Uint8Array;
	stderr: Uint8Array;
	stdout: Uint8Array;
}
export interface RawEvidence extends NativeEvidence {
	command: string[];
	scannerSha256: string;
	scannerVersion: string;
	config: Uint8Array;
	ignore: Uint8Array;
	input: Uint8Array;
	stdinBytes: number;
}
export interface RawReceipt {
	member: string;
	bytes: number;
	inputSha256: string;
	reportSha256: string;
	stderrSha256: string;
	stdoutSha256: string;
	invocationSha256: string;
	receiptSha256: string;
}
export interface VerifiedRawScan {
	binding: RawReceipt;
	evidence: RawEvidence;
	locations: ScanLocations;
}

/** Validate actual output bytes and invocation, not a caller's claimed clean/pass flag. */
export function verifyRawScan(evidence: RawEvidence, locations: ScanLocations): void {
	verifyAppleDouble(evidence.input);
	const report: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(evidence.report));
	if (
		evidence.exitCode !== 0 ||
		evidence.signal !== null ||
		evidence.timedOut ||
		evidence.stdinBytes !== APPLEDOUBLE.memberBytes ||
		evidence.stderr.length !== 0 ||
		evidence.stdout.length !== 0 ||
		!Array.isArray(report) ||
		report.length !== 0 ||
		evidence.scannerSha256 !== SCANNER_SHA256 ||
		evidence.scannerVersion !== SCANNER_VERSION ||
		sha256(evidence.config) !== sha256(new TextEncoder().encode(DEFAULT_CONFIG)) ||
		evidence.ignore.length !== 0 ||
		JSON.stringify(evidence.command) !== JSON.stringify(rawCommand(locations))
	) {
		throw new Error("Incomplete, changed or non-clean raw member scan");
	}
}

export interface DecoderProof {
	coverage: DecoderCoverage;
	version: HistoricalVersion;
	reviewSha256: string;
	archiveSha256: string;
	tarSha256: string;
	members: VerifiedRawScan[];
	proofSha256: string;
}
export interface WholeBlobProof {
	version: HistoricalVersion;
	complete: boolean;
	pass: boolean;
	allVersionsComplete: boolean;
	contextSha256: string;
	receiptSha256: string;
	reportSha256: string;
	stderrSha256: string;
	proofSha256: string;
	inventorySha256: string;
	resultsSha256: string;
}
export interface DecoderDisposition {
	reviewSha256: string;
	proofSha256: string;
	nativeStderrSha256: string;
	nativeReportSha256: string;
	wholeBlobReceiptSha256?: string;
	wholeBlobResultsSha256?: string;
	decision: Decision;
}

function exactErrors(stderr: Uint8Array): boolean {
	let text: string;
	try {
		text = new TextDecoder("utf-8", { fatal: true }).decode(stderr);
	} catch {
		return false;
	}
	const lines = text.split("\n");
	if (lines.pop() !== "" || lines.length !== APPLEDOUBLE.members.length) return false;
	const expected = new Set<string>(
		APPLEDOUBLE.members.map(
			member =>
				`ERR error="could not read file: bzip2: corrupted input: invalid stream magic" path=${APPLEDOUBLE.file}!${member.path}`,
		),
	);
	for (const line of lines) {
		// Exact observed error-only/no-color log grammar; only the normal local clock varies.
		const match = /^(?:[1-9]|1[0-2]):[0-5][0-9](?:AM|PM) (.+)$/.exec(line);
		if (!match || !expected.delete(match[1])) return false;
	}
	return expected.size === 0;
}

/** Reconciliation preserves native errors and cannot excuse any other execution/finding failure. */
export function reconcileDecoder(
	decision: Decision,
	scope: Scope,
	native: NativeEvidence,
	coverage: DecoderCoverage,
	proof: DecoderProof | undefined,
	version?: HistoricalVersion,
	wholeBlob?: WholeBlobProof,
): DecoderDisposition | undefined {
	if (
		scope === "tree" ||
		!proof ||
		!decision.errors.includes(STDERR_ERROR) ||
		!exactErrors(native.stderr) ||
		native.stdout.length !== 0 ||
		native.signal !== null ||
		native.timedOut ||
		(native.exitCode !== 0 && native.exitCode !== 1) ||
		!reviewedVersion(proof.version) ||
		proof.reviewSha256 !== APPLEDOUBLE.reviewSha256 ||
		proof.archiveSha256 !== APPLEDOUBLE.sha256 ||
		proof.tarSha256 !== APPLEDOUBLE.tarSha256 ||
		JSON.stringify(proof.coverage) !== JSON.stringify(coverage) ||
		proof.members.length !== APPLEDOUBLE.members.length
	)
		return undefined;
	try {
		digest(proof.proofSha256);
		for (const [index, scan] of proof.members.entries()) {
			verifyRawScan(scan.evidence, scan.locations);
			const member = scan.binding;
			if (
				member.member !== APPLEDOUBLE.members[index].path ||
				member.bytes !== APPLEDOUBLE.memberBytes ||
				member.inputSha256 !== APPLEDOUBLE.memberSha256 ||
				member.stderrSha256 !== sha256(new Uint8Array()) ||
				member.stdoutSha256 !== sha256(new Uint8Array()) ||
				member.reportSha256 !== sha256(scan.evidence.report)
			)
				return undefined;
			for (const hash of [member.reportSha256, member.invocationSha256, member.receiptSha256]) digest(hash);
		}
		if (scope === "historicalBlob") {
			if (!version || !reviewedVersion(version)) return undefined;
		} else {
			if (
				!wholeBlob ||
				!reviewedVersion(wholeBlob.version) ||
				!wholeBlob.complete ||
				!wholeBlob.pass ||
				!wholeBlob.allVersionsComplete ||
				wholeBlob.proofSha256 !== proof.proofSha256 ||
				wholeBlob.inventorySha256 !== coverage.inventorySha256
			)
				return undefined;
			for (const hash of [
				wholeBlob.contextSha256,
				wholeBlob.receiptSha256,
				wholeBlob.reportSha256,
				wholeBlob.stderrSha256,
				wholeBlob.resultsSha256,
			])
				digest(hash);
		}
	} catch {
		return undefined;
	}
	const errors = decision.errors.filter(error => error !== STDERR_ERROR);
	return {
		reviewSha256: APPLEDOUBLE.reviewSha256,
		proofSha256: proof.proofSha256,
		nativeStderrSha256: sha256(native.stderr),
		nativeReportSha256: sha256(native.report),
		wholeBlobReceiptSha256: wholeBlob?.receiptSha256,
		wholeBlobResultsSha256: wholeBlob?.resultsSha256,
		decision: { ...decision, errors, pass: errors.length === 0 && decision.blocked.length === 0 },
	};
}

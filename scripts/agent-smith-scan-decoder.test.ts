import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import type { Fixture } from "./agent-smith-common";
import { fixture, ROOT, sha256 } from "./agent-smith-common";
import type {
	DecoderCoverage,
	DecoderProof,
	NativeEvidence,
	RawEvidence,
	ScanLocations,
	WholeBlobProof,
} from "./agent-smith-scan-decoder";
import {
	APPLEDOUBLE,
	rawCommand,
	reconcileDecoder,
	reviewedMembers,
	verifyAppleDouble,
	verifyDecoderCoverage,
	verifyRawScan,
} from "./agent-smith-scan-decoder";
import { parseHistoryMetadata } from "./agent-smith-scan-history";
import type { Decision, HistoricalVersion, Scope } from "./agent-smith-scan-policy";
import {
	decide,
	DEFAULT_CONFIG,
	parseLedger,
	prepareLedger,
	SCANNER_SHA256,
	SCANNER_VERSION,
	SOURCE_BASE,
	SOURCE_TREE,
	STDERR_ERROR,
} from "./agent-smith-scan-policy";
import { blobs, neutralEnvironment } from "./agent-smith-scan-source";

const encode = (text: string): Uint8Array => new TextEncoder().encode(text);
const version: HistoricalVersion = { file: APPLEDOUBLE.file, blob: APPLEDOUBLE.blob, commits: [APPLEDOUBLE.commit] };
const candidate = "a".repeat(40);
const coverage: DecoderCoverage = {
	candidate,
	candidateTree: "b".repeat(40),
	ancestrySha256: "c".repeat(64),
	metadataSha256: "d".repeat(64),
	inventorySha256: "e".repeat(64),
	attributeSource: SOURCE_BASE,
	attributeTree: SOURCE_TREE,
};
const successorBlob = "11b82d8a2cec26c2efd22961700c4435988f7897";
const replacementCommit = "156300200742fa25d53f9e1acab02afe7f76750d";
const successorAdditions = [
	"59c5ac386d6f8ceefee76cd98fac69ceeea9dbe0",
	"445021a4e82ccfb3fd527ebf62fefb1b5d456fdf",
	"e853f0b974eb364fcda8552964982639b2d90128",
	"f30e9e29344d7e25d3a21d74048265b98864cc17",
	"ad39907f8f2014d54be86e449607e17a61a9ed7b",
];
const ancestry = new Set([candidate, SOURCE_BASE, APPLEDOUBLE.commit, replacementCommit, ...successorAdditions]);
const header = (commit: string): string => `\0commit ${commit}\0\0`;
const metadata = encode(
	header(APPLEDOUBLE.commit) +
		"\n" +
		`:000000 100644 ${"0".repeat(40)} ${APPLEDOUBLE.blob} A\0${APPLEDOUBLE.file}\0-\t-\t${APPLEDOUBLE.file}\0` +
		header(replacementCommit) +
		"\n" +
		`:100644 100644 ${APPLEDOUBLE.blob} ${successorBlob} M\0${APPLEDOUBLE.file}\0-\t-\t${APPLEDOUBLE.file}\0` +
		successorAdditions
			.map(
				commit =>
					header(commit) +
					"\n" +
					`:000000 100644 ${"0".repeat(40)} ${successorBlob} A\0${APPLEDOUBLE.file}\0-\t-\t${APPLEDOUBLE.file}\0`,
			)
			.join("") +
		header(SOURCE_BASE) +
		header(candidate),
);
const errors = APPLEDOUBLE.members
	.map(
		(member, index) =>
			`${index + 1}:31PM ERR error="could not read file: bzip2: corrupted input: invalid stream magic" path=${APPLEDOUBLE.file}!${member.path}\n`,
	)
	.join("");
const historyErrors = errors.replaceAll(" path=", " commit=6f0fec7 path=");
let owned: Fixture;
let archive: Uint8Array;
let members: Uint8Array[];

beforeAll(async () => {
	// Immutable source fixture only. No scanner, archive command or upstream code is executed.
	owned = await fixture("test-decoder");
	const executable = Bun.which("git");
	if (!executable) throw new Error("Decoder boundary fixture requires Git");
	const empty = path.join(owned.dir, "empty");
	await Bun.write(empty, "");
	await blobs(
		{
			executable,
			cwd: ROOT,
			env: neutralEnvironment(owned.env, empty),
			logs: path.join(owned.dir, "git-errors.log"),
		},
		[{ spec: APPLEDOUBLE.blob, blob: APPLEDOUBLE.blob }],
		async (_request, _blob, bytes) => {
			archive = bytes;
		},
	);
	members = reviewedMembers(archive, version);
});

afterAll(async () => {
	if (!owned) return;
	await fs.rm(owned.dir, { recursive: true, force: true });
	if (owned.env.TMPDIR) await fs.rm(owned.env.TMPDIR, { recursive: true, force: true });
});

function rawCase(index = 0): { evidence: RawEvidence; locations: ScanLocations } {
	const locations = {
		scanner: "/owned/gitleaks",
		config: "/owned/default.toml",
		ignore: "/owned/empty-ignore",
		report: `/owned/member-${index + 1}.json`,
	};
	return {
		locations,
		evidence: {
			command: rawCommand(locations),
			scannerSha256: SCANNER_SHA256,
			scannerVersion: SCANNER_VERSION,
			config: encode(DEFAULT_CONFIG),
			ignore: new Uint8Array(),
			input: new Uint8Array(members[index]),
			stdinBytes: 163,
			report: encode("[]\n"),
			stderr: new Uint8Array(),
			stdout: new Uint8Array(),
			exitCode: 0,
			signal: null,
			timedOut: false,
		},
	};
}

function decoderCase(scope: Scope = "historicalBlob") {
	const stderr = scope === "history" ? historyErrors : errors;
	const native: NativeEvidence = {
		report: encode("[]\n"),
		stderr: encode(stderr),
		stdout: new Uint8Array(),
		exitCode: 0,
		signal: null,
		timedOut: false,
	};
	const prepared = prepareLedger(
		parseLedger({
			schemaVersion: 4,
			sourceBase: SOURCE_BASE,
			sourceTree: SOURCE_TREE,
			origins: {},
			groups: {},
			history: [],
			tree: [],
			historicalBlob: [],
		}),
		new Set(),
	);
	const decision = decide([], scope, prepared, new Map(), 0, stderr, sha256(native.report), version);
	const proof: DecoderProof = {
		coverage: { ...coverage },
		version,
		reviewSha256: APPLEDOUBLE.reviewSha256,
		archiveSha256: APPLEDOUBLE.sha256,
		tarSha256: APPLEDOUBLE.tarSha256,
		proofSha256: "f".repeat(64),
		members: APPLEDOUBLE.members.map((member, index) => {
			const { evidence, locations } = rawCase(index);
			return {
				evidence,
				locations,
				binding: {
					member: member.path,
					bytes: evidence.input.length,
					inputSha256: sha256(evidence.input),
					reportSha256: sha256(evidence.report),
					stderrSha256: sha256(evidence.stderr),
					stdoutSha256: sha256(evidence.stdout),
					invocationSha256: "1".repeat(64),
					receiptSha256: "2".repeat(64),
				},
			};
		}),
	};
	const wholeBlob: WholeBlobProof = {
		version,
		complete: true,
		pass: true,
		allVersionsComplete: true,
		contextSha256: "3".repeat(64),
		receiptSha256: "4".repeat(64),
		reportSha256: sha256(native.report),
		stderrSha256: sha256(encode(errors)),
		proofSha256: proof.proofSha256,
		inventorySha256: coverage.inventorySha256,
		resultsSha256: "5".repeat(64),
	};
	return { native, decision, proof, wholeBlob };
}

describe("reviewed immutable AppleDouble supplement", () => {
	test("fixed reviewed offsets recover three complete metadata objects from the pinned gzip", () => {
		expect(members.map(bytes => ({ bytes: bytes.length, hash: sha256(bytes) }))).toEqual(
			APPLEDOUBLE.members.map(() => ({ bytes: 163, hash: APPLEDOUBLE.memberSha256 })),
		);
		const mutated = new Uint8Array(archive);
		mutated[mutated.length - 1] ^= 1;
		expect(() => reviewedMembers(mutated, version)).toThrow();
		expect(() => reviewedMembers(archive.subarray(0, archive.length - 1), version)).toThrow();
		for (const changed of [
			{ ...version, file: "elsewhere/ar.tar.gz" },
			{ ...version, blob: "a".repeat(40) },
			{ ...version, commits: [candidate] },
			{ ...version, commits: [APPLEDOUBLE.commit, candidate] },
		])
			expect(() => reviewedMembers(archive, changed)).toThrow();
	});

	test("changed metadata format, entry extent or payload cannot masquerade as the reviewed member", () => {
		for (const offset of [0, 4, 25, 33, 45, 80]) {
			const changed = new Uint8Array(members[0]);
			changed[offset] ^= 1;
			expect(() => verifyAppleDouble(changed)).toThrow();
		}
		expect(() => verifyAppleDouble(members[0].subarray(0, 162))).toThrow();
		expect(() => verifyAppleDouble(encode("BZh9"))).toThrow();
	});

	test("full candidate metadata must retain the reviewed addition and exact existing successor lifecycle", () => {
		const inventory = parseHistoryMetadata(metadata, ancestry);
		verifyDecoderCoverage(inventory, ancestry, coverage);
		// A distinct immutable version of this path is a changed decoder context, even with the same error text.
		const added = structuredClone(inventory);
		added.commits[2].changes.push({ ...added.commits[0].changes[0], object: candidate });
		expect(() => verifyDecoderCoverage(added, ancestry, coverage)).toThrow();
		const repeated = structuredClone(inventory);
		repeated.versions[0].commits.push(candidate);
		expect(() => verifyDecoderCoverage(repeated, ancestry, coverage)).toThrow();
		const incomplete = { ...inventory, commits: inventory.commits.slice(1) };
		expect(() => verifyDecoderCoverage(incomplete, ancestry, coverage)).toThrow();
		expect(() => verifyDecoderCoverage(inventory, ancestry, { ...coverage, attributeSource: candidate })).toThrow();
		expect(() => verifyDecoderCoverage(inventory, new Set([candidate, APPLEDOUBLE.commit]), coverage)).toThrow();
		const nonbinary = structuredClone(inventory);
		nonbinary.commits[0].changes[0].binary = false;
		expect(() => verifyDecoderCoverage(nonbinary, ancestry, coverage)).toThrow();
	});

	test("missing, changed or duplicated archive retirement and successor context cannot authorize an exception", () => {
		const inventory = parseHistoryMetadata(metadata, ancestry);
		for (const field of ["oldObject", "object"] as const) {
			const changed = structuredClone(inventory);
			changed.commits[1].changes[0][field] = candidate;
			expect(() => verifyDecoderCoverage(changed, ancestry, coverage)).toThrow();
		}
		const missing = structuredClone(inventory);
		missing.commits[1].changes = [];
		expect(() => verifyDecoderCoverage(missing, ancestry, coverage)).toThrow();
		const relocated = structuredClone(inventory);
		relocated.commits[0].changes[0].file = "elsewhere/ar.tar.gz";
		expect(() => verifyDecoderCoverage(relocated, ancestry, coverage)).toThrow();
		const incompleteVersion = structuredClone(inventory);
		incompleteVersion.versions[1].commits.pop();
		expect(() => verifyDecoderCoverage(incompleteVersion, ancestry, coverage)).toThrow();
		const duplicateVersion = structuredClone(inventory);
		duplicateVersion.versions[1].commits[0] = duplicateVersion.versions[1].commits[1];
		expect(() => verifyDecoderCoverage(duplicateVersion, ancestry, coverage)).toThrow();
		const unreviewedVersion = structuredClone(inventory);
		unreviewedVersion.versions.push({ file: APPLEDOUBLE.file, blob: candidate, commits: [candidate] });
		expect(() => verifyDecoderCoverage(unreviewedVersion, ancestry, coverage)).toThrow();
	});

	test("raw scan proof requires every input byte and native clean outputs under the pinned invocation", () => {
		const { evidence, locations } = rawCase();
		verifyRawScan(evidence, locations);
		for (const changed of [
			{ ...evidence, stdinBytes: 162 },
			{ ...evidence, input: evidence.input.subarray(0, 162) },
			{ ...evidence, exitCode: 1 },
			{ ...evidence, signal: "SIGKILL" },
			{ ...evidence, timedOut: true },
			{ ...evidence, report: encode("null") },
			{ ...evidence, report: encode("[") },
			{ ...evidence, report: encode('[{"Secret":"REDACTED"}]') },
			{ ...evidence, stderr: encode("decoder error\n") },
			{ ...evidence, stdout: encode("partial scan\n") },
			{ ...evidence, scannerSha256: "0".repeat(64) },
			{ ...evidence, config: encode("[allowlist]\n") },
			{ ...evidence, ignore: encode("ignored") },
			{
				...evidence,
				command: evidence.command.map(arg => (arg === "--max-archive-depth=0" ? "--max-archive-depth=2" : arg)),
			},
			{ ...evidence, command: evidence.command.filter(arg => arg !== "--ignore-gitleaks-allow") },
		])
			expect(() => verifyRawScan(changed, locations)).toThrow();
	});

	test("exact errors are separately dispositioned while the native decision and bytes remain intact", () => {
		const { native, decision, proof } = decoderCase();
		const accepted = reconcileDecoder(decision, "historicalBlob", native, coverage, proof, version);
		expect(accepted?.decision.pass).toBe(true);
		expect(accepted?.nativeStderrSha256).toBe(sha256(encode(errors)));
		expect(decision.pass).toBe(false);
		expect(decision.errors).toEqual([STDERR_ERROR]);
		expect(new TextDecoder().decode(native.stderr)).toBe(errors);
	});

	test("missing, additional, repeated, unmatched and unsupported-shaped errors stay blocking", () => {
		const { native, decision, proof } = decoderCase();
		for (const text of [
			"",
			errors.split("\n").slice(1).join("\n"),
			`${errors}${errors.split("\n")[0]}\n`,
			errors.replace(APPLEDOUBLE.members[1].path, APPLEDOUBLE.members[0].path),
			errors.replace("invalid stream magic", "unexpected EOF"),
			errors.replace("1:31PM", "13:31"),
			`\u001b[31m${errors}`,
			errors.trimEnd(),
			errors.replaceAll("\n", "\r\n"),
		])
			expect(
				reconcileDecoder(decision, "historicalBlob", { ...native, stderr: encode(text) }, coverage, proof, version),
			).toBeUndefined();
		expect(
			reconcileDecoder(
				decision,
				"historicalBlob",
				{ ...native, stderr: new Uint8Array([255]) },
				coverage,
				proof,
				version,
			),
		).toBeUndefined();
		expect(
			reconcileDecoder(
				decision,
				"historicalBlob",
				{ ...native, stdout: encode("ignored") },
				coverage,
				proof,
				version,
			),
		).toBeUndefined();
	});

	test("failed raw scan, missing member or receipt, or changed parent binding cannot authorize native errors", () => {
		const { native, decision, proof } = decoderCase();
		expect(reconcileDecoder(decision, "historicalBlob", native, coverage, undefined, version)).toBeUndefined();
		for (const changed of [
			{ ...proof, members: proof.members.slice(1) },
			{ ...proof, archiveSha256: "0".repeat(64) },
			{ ...proof, coverage: { ...coverage, inventorySha256: "0".repeat(64) } },
			{ ...proof, version: { ...version, commits: [candidate] } },
		])
			expect(reconcileDecoder(decision, "historicalBlob", native, coverage, changed, version)).toBeUndefined();
		proof.members[1].evidence.exitCode = 1;
		expect(reconcileDecoder(decision, "historicalBlob", native, coverage, proof, version)).toBeUndefined();
		proof.members[1].evidence.exitCode = 0;
		proof.members[1].binding.receiptSha256 = "";
		expect(reconcileDecoder(decision, "historicalBlob", native, coverage, proof, version)).toBeUndefined();
	});

	test("history additionally needs complete inventory scans and the passing exact whole-blob receipt", () => {
		const { native, decision, proof, wholeBlob } = decoderCase("history");
		expect(reconcileDecoder(decision, "history", native, coverage, proof, undefined, wholeBlob)?.decision.pass).toBe(
			true,
		);
		for (const changed of [
			undefined,
			{ ...wholeBlob, pass: false },
			{ ...wholeBlob, complete: false },
			{ ...wholeBlob, allVersionsComplete: false },
			{ ...wholeBlob, receiptSha256: "" },
			{ ...wholeBlob, resultsSha256: "" },
			{ ...wholeBlob, proofSha256: "0".repeat(64) },
			{ ...wholeBlob, inventorySha256: "0".repeat(64) },
			{ ...wholeBlob, version: { ...version, blob: candidate } },
		])
			expect(reconcileDecoder(decision, "history", native, coverage, proof, undefined, changed)).toBeUndefined();
		expect(reconcileDecoder(decision, "tree", native, coverage, proof, version, wholeBlob)).toBeUndefined();
		const historical = decoderCase();
		expect(
			reconcileDecoder(historical.decision, "historicalBlob", historical.native, coverage, historical.proof, {
				...version,
				file: "other.gz",
			}),
		).toBeUndefined();
	});

	test("history requires the exact native commit field and directory errors cannot borrow that context", () => {
		const { native, decision, proof, wholeBlob } = decoderCase("history");
		for (const stderr of [
			errors,
			historyErrors.replaceAll("commit=6f0fec7", "commit=aaaaaaa"),
			historyErrors.replaceAll("commit=6f0fec7", `commit=${APPLEDOUBLE.commit}`),
		]) {
			expect(
				reconcileDecoder(
					decision,
					"history",
					{ ...native, stderr: encode(stderr) },
					coverage,
					proof,
					undefined,
					wholeBlob,
				),
			).toBeUndefined();
		}
		expect(reconcileDecoder(decision, "historicalBlob", native, coverage, proof, version)).toBeUndefined();
	});

	test("metadata disposition never removes decoded findings or unrelated execution errors", () => {
		const { native, decision, proof } = decoderCase();
		const blocked: Decision = {
			...decision,
			findings: 1,
			blocked: [{ row: 1, fingerprint: "example", span: [1, 1, 1, 2], reason: "Unreviewed occurrence" }],
		};
		const finding = reconcileDecoder(blocked, "historicalBlob", native, coverage, proof, version);
		expect(finding?.decision.pass).toBe(false);
		expect(finding?.decision.blocked).toEqual(blocked.blocked);
		const failed = reconcileDecoder(
			{ ...decision, errors: [...decision.errors, "Other failure"] },
			"historicalBlob",
			native,
			coverage,
			proof,
			version,
		);
		expect(failed?.decision.pass).toBe(false);
		expect(failed?.decision.errors).toEqual(["Other failure"]);
	});
});

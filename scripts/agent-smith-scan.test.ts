import { describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { fixture, sha256 } from "./agent-smith-common";
import { historicalCoverage, parseHistoryMetadata } from "./agent-smith-scan-history";
import type { Binding, Decision, Disposition, HistoricalVersion, Ledger, Scope } from "./agent-smith-scan-policy";
import {
	decide as decidePrepared,
	EMPTY_TREE,
	HISTORY_SELECTION,
	identity,
	parseLedger,
	parseReport,
	prepareLedger,
	reportContentSha256,
	scopesPass,
	SOURCE_BASE,
	SOURCE_TREE,
	verifyInheritedAcceptance,
} from "./agent-smith-scan-policy";
import { blobs, git, neutralEnvironment, parseTree, snapshot } from "./agent-smith-scan-source";

function decide(
	report: unknown,
	scope: Scope,
	ledger: Ledger,
	bindings: ReadonlyMap<string, Binding>,
	exitCode: number,
	stderr: string,
	version?: HistoricalVersion,
	reportSha256 = sha256(new TextEncoder().encode(JSON.stringify(report))),
): Decision {
	return decidePrepared(report, scope, prepareLedger(ledger), bindings, exitCode, stderr, reportSha256, version);
}

function reviewedReport(report: Record<string, unknown>[], scope: Scope) {
	const findings = parseReport(report, scope);
	const rowDigests = findings.map(item => item.nativeRowSha256);
	const bytes = new TextEncoder().encode(`${JSON.stringify(report, null, 2)}\n`);
	return {
		findings,
		bytes,
		origin: {
			reportSha256: sha256(bytes),
			reportContentSha256: reportContentSha256(rowDigests),
			rowDigests,
			reviewSha256: "e".repeat(64),
			sourceCommit: SOURCE_BASE,
			sourceTree: SOURCE_TREE,
			reportRows: report.length,
		},
	};
}

function reviewedCase(): {
	report: Record<string, unknown>[];
	ledger: Ledger;
	bindings: Map<string, Binding>;
	approval: Disposition;
} {
	const report: Record<string, unknown>[] = [
		{
			Commit: "a".repeat(40),
			File: "example.txt",
			RuleID: "example-rule",
			StartLine: 1,
			EndLine: 1,
			StartColumn: 3,
			EndColumn: 12,
			Fingerprint: `${"a".repeat(40)}:example.txt:example-rule:1`,
			Secret: "REDACTED",
			Match: "REDACTED",
			SymlinkFile: "",
			Description: "Example detection",
			Author: "",
			Email: "",
			Date: "",
			Message: "",
			Entropy: 0,
			Tags: [],
		},
	];
	const reviewed = reviewedReport(report, "history");
	const approval: Disposition = {
		...reviewed.findings[0],
		blob: "b".repeat(40),
		containerSha256: "c".repeat(64),
		contentSha256: "c".repeat(64),
		origin: "review",
		row: 1,
		group: "example",
	};
	const ledger = parseLedger({
		schemaVersion: 4,
		sourceBase: SOURCE_BASE,
		sourceTree: SOURCE_TREE,
		origins: { review: reviewed.origin },
		groups: {
			example: {
				origin: "review",
				disposition: "reviewed_non_secret",
				reason: "Constructed deterministic example for the disposition boundary.",
				evidence: ["example.txt:1"],
			},
		},
		history: [approval],
		tree: [],
		historicalBlob: [],
	});
	return { report, ledger, approval, bindings: new Map([[identity(approval), approval]]) };
}

describe("maintained scan disposition boundary", () => {
	test("an exact reviewed immutable occurrence can disposition native findings exit 1", () => {
		const { report, ledger, bindings } = reviewedCase();
		const result = decide(report, "history", ledger, bindings, 1, "");
		expect(result.pass).toBe(true);
		expect(result.approved).toBe(1);
		expect(result.blocked).toEqual([]);
	});

	test("equivalent JSON serialization does not replace original raw-report provenance", () => {
		const { report, ledger, bindings } = reviewedCase();
		const original = structuredClone(ledger);
		const reorderedKeys = report.map(row => Object.fromEntries(Object.entries(row).reverse()));
		expect(decide(reorderedKeys, "history", ledger, bindings, 1, "").pass).toBe(true);
		expect(ledger).toEqual(original);
	});

	test("review provenance rejects a different declared report size for a unique finding", () => {
		const { report, ledger, bindings } = reviewedCase();
		ledger.origins.review.reportRows = 2;
		expect(decide(report, "history", ledger, bindings, 1, "").pass).toBe(false);
	});

	test("review provenance rejects swapped review rows even when every distinct span is approved", () => {
		const { report, ledger, approval } = reviewedCase();
		report.push({ ...report[0], StartColumn: 23, EndColumn: 32 });
		const reviewed = reviewedReport(report, "history");
		ledger.origins.review = reviewed.origin;
		ledger.history[0].row = 2;
		ledger.history.push({ ...approval, ...reviewed.findings[1], row: 1 });
		expect(() => parseLedger(ledger)).toThrow();
	});

	test("same fingerprint at a different span needs its own approval", () => {
		const { report, ledger, bindings, approval } = reviewedCase();
		report.push({ ...report[0], StartColumn: 23, EndColumn: 32 });
		const reviewed = reviewedReport(report, "history");
		ledger.origins.review = reviewed.origin;
		const second: Disposition = { ...approval, ...reviewed.findings[1], row: 2 };
		bindings.set(identity(second), second);
		const blocked = decide(report, "history", ledger, bindings, 1, "");
		expect(blocked.pass).toBe(false);
		expect(blocked.approved).toBe(1);
		expect(blocked.blocked.map(item => item.row)).toEqual([2]);
		ledger.history.push(second);
		expect(decide(report, "history", parseLedger(ledger), bindings, 1, "").pass).toBe(true);
	});

	test("missing and extra unique records cannot reuse a complete report review", () => {
		const { report, ledger, bindings } = reviewedCase();
		for (const changed of [[], [...report, { ...report[0], StartColumn: 23, EndColumn: 32 }]]) {
			const result = decide(changed, "history", ledger, bindings, changed.length ? 1 : 0, "");
			expect(result.pass).toBe(false);
			expect(result.approved).toBe(0);
		}
	});

	test("native metadata outside the projected finding identity remains binding", () => {
		const { report, ledger, approval } = reviewedCase();
		for (const [field, value] of [
			["Description", "changed description"],
			["Author", "changed author"],
			["Email", "other@example.invalid"],
			["Date", "2026-10-10T00:00:00Z"],
			["Message", "changed message"],
			["Entropy", 1],
			["Tags", ["changed-tag"]],
			["Tags", null],
			["Link", "https://example.invalid/review"],
			["Match", "changed REDACTED match"],
		] as const) {
			const changed = [{ ...report[0], [field]: value }];
			const finding = parseReport(changed, "history")[0];
			const bindings = new Map([[identity(finding), approval]]);
			const result = decide(changed, "history", ledger, bindings, 1, "");
			expect(result.pass).toBe(false);
			expect(result.approved).toBe(0);
		}
	});

	test("a changed blob cannot reuse a reviewed fingerprint and span", () => {
		const { report, ledger, bindings, approval } = reviewedCase();
		bindings.set(identity(approval), { ...approval, blob: "f".repeat(40) });
		const result = decide(report, "history", ledger, bindings, 1, "");
		expect(result.pass).toBe(false);
		expect(result.approved).toBe(0);
	});

	test("missing source bytes and changed content digests both block an approved occurrence", () => {
		const { report, ledger, bindings, approval } = reviewedCase();
		expect(decide(report, "history", ledger, new Map(), 1, "").pass).toBe(false);
		for (const changed of [
			{ ...approval, contentSha256: "f".repeat(64) },
			{ ...approval, containerSha256: "f".repeat(64) },
		]) {
			bindings.set(identity(approval), changed);
			expect(decide(report, "history", ledger, bindings, 1, "").pass).toBe(false);
		}
	});

	test("an independently blocked row cannot be accepted merely because its bytes match", () => {
		const { report, ledger, bindings } = reviewedCase();
		ledger.groups.example.disposition = "blocked";
		const result = decide(report, "history", ledger, bindings, 1, "");
		expect(result.pass).toBe(false);
		expect(result.approved).toBe(0);
	});

	test("an inherited-exposure acceptance passes history without counting as reviewed non-secret", () => {
		const { report, ledger, bindings } = reviewedCase();
		ledger.groups.example.disposition = "accepted_inherited_exposure";
		const result = decide(report, "history", ledger, bindings, 1, "");
		expect(result.pass).toBe(true);
		expect(result.approved).toBe(0);
		expect(result.accepted).toBe(1);
	});

	test("an inherited-exposure acceptance cannot cover current-tree or stored-version rows", () => {
		const { ledger, approval } = reviewedCase();
		const groups = { example: { ...ledger.groups.example, disposition: "accepted_inherited_exposure" } };
		for (const scope of ["tree", "historicalBlob"] as const) {
			expect(() => parseLedger({ ...ledger, groups, history: [], [scope]: [approval] })).toThrow(
				"Inherited exposure acceptance applies only to Git history",
			);
		}
	});

	test("an inherited-exposure acceptance is limited to commits reachable from the upstream base", () => {
		const { ledger } = reviewedCase();
		ledger.groups.example.disposition = "accepted_inherited_exposure";
		expect(() => verifyInheritedAcceptance(ledger, new Set(["f".repeat(40)]))).toThrow(
			"Inherited exposure acceptance outside the upstream base history",
		);
		expect(() => verifyInheritedAcceptance(ledger, new Set(["a".repeat(40)]))).not.toThrow();
	});

	test("the same file content in a new history commit remains unreviewed", () => {
		const { report, ledger, approval } = reviewedCase();
		const changed = {
			...approval,
			commit: "f".repeat(40),
			fingerprint: `${"f".repeat(40)}:example.txt:example-rule:1`,
		};
		report[0] = { ...report[0], Commit: changed.commit, Fingerprint: changed.fingerprint };
		const result = decide(report, "history", ledger, new Map([[identity(changed), changed]]), 1, "");
		expect(result.pass).toBe(false);
	});

	test("identical member bytes under a different archive path need a separate review", () => {
		const { report, ledger, approval } = reviewedCase();
		report[0] = {
			...report[0],
			File: "archive.zip!first.txt",
			Fingerprint: `${approval.commit}:archive.zip!first.txt:example-rule:1`,
		};
		const reviewed = reviewedReport(report, "history");
		ledger.origins.review = reviewed.origin;
		ledger.history = [{ ...approval, ...reviewed.findings[0], contentSha256: "f".repeat(64) }];
		const parsed = parseLedger(ledger);
		report[0] = {
			...report[0],
			File: "archive.zip!other.txt",
			Fingerprint: `${approval.commit}:archive.zip!other.txt:example-rule:1`,
		};
		const changed = parseReport(report, "history")[0];
		expect(decide(report, "history", parsed, new Map([[identity(changed), ledger.history[0]]]), 1, "").pass).toBe(
			false,
		);
	});

	test("tree detections cannot inherit history approvals", () => {
		const { report, ledger, approval } = reviewedCase();
		report[0] = { ...report[0], Commit: "", Fingerprint: "example.txt:example-rule:1" };
		const reviewed = reviewedReport(report, "tree");
		const tree = { ...approval, ...reviewed.findings[0] };
		const bindings = new Map([[identity(tree), tree]]);
		expect(decide(report, "tree", ledger, bindings, 1, "").pass).toBe(false);
		ledger.origins["tree-review"] = reviewed.origin;
		ledger.groups["tree-example"] = { ...ledger.groups.example, origin: "tree-review" };
		ledger.tree.push({ ...tree, origin: "tree-review", group: "tree-example" });
		expect(decide(report, "tree", parseLedger(ledger), bindings, 1, "").pass).toBe(true);
	});

	test("native errors block even an empty report and exit zero", () => {
		const { ledger } = reviewedCase();
		const result = decide([], "history", ledger, new Map(), 0, "decoder error\n");
		expect(result.pass).toBe(false);
	});

	test("historical directory findings keep native Commit empty and need their own scope approval", () => {
		const { report, ledger, approval } = reviewedCase();
		report[0] = { ...report[0], Commit: "", Fingerprint: "example.txt:example-rule:1" };
		const reviewed = reviewedReport(report, "historicalBlob");
		const native = { ...approval, ...reviewed.findings[0] };
		const version = { file: native.file, blob: native.blob, commits: [approval.commit] };
		ledger.origins.review = reviewed.origin;
		ledger.history = [];
		ledger.tree = [native];
		const bindings = new Map([[identity(native, version.blob), native]]);
		expect(decide(report, "historicalBlob", parseLedger(ledger), bindings, 1, "", version).pass).toBe(false);
		ledger.tree = [];
		ledger.historicalBlob = [native];
		expect(decide(report, "historicalBlob", parseLedger(ledger), bindings, 1, "", version).pass).toBe(true);
		expect(decide(report, "historicalBlob", ledger, bindings, 1, "").pass).toBe(false);
		expect(decide(report, "historicalBlob", ledger, bindings, 1, "", { ...version, file: "other.txt" }).pass).toBe(
			false,
		);
		expect(() => parseReport([{ ...report[0], Commit: approval.commit }], "historicalBlob")).toThrow();
	});

	test("identical native fingerprints, spans and report rows on different blobs need distinct immutable approvals", () => {
		const { report, ledger, approval } = reviewedCase();
		report[0] = { ...report[0], Commit: "", Fingerprint: "example.txt:example-rule:1" };
		const reviewed = reviewedReport(report, "historicalBlob");
		const first = { ...approval, ...reviewed.findings[0] };
		const second = { ...first, blob: "f".repeat(40), containerSha256: "1".repeat(64), contentSha256: "1".repeat(64) };
		ledger.origins.review = reviewed.origin;
		ledger.history = [];
		ledger.historicalBlob = [first];
		const version = { file: first.file, blob: second.blob, commits: [approval.commit, "9".repeat(40)] };
		const bindings = new Map([[identity(second, second.blob), second]]);
		const blocked = decide(report, "historicalBlob", parseLedger(ledger), bindings, 1, "", version);
		expect(blocked.approved).toBe(0);
		ledger.historicalBlob.push(second);
		const parsed = parseLedger(ledger);
		expect(decide(report, "historicalBlob", parsed, bindings, 1, "", version).pass).toBe(true);
		expect(decide(report, "historicalBlob", parsed, bindings, 1, "decoder error", version).pass).toBe(false);
		expect(decide(report, "historicalBlob", parsed, bindings, 137, "", version).pass).toBe(false);
		expect(decide(undefined, "historicalBlob", parsed, bindings, 0, "", version).pass).toBe(false);
		expect(() => parseLedger({ ...ledger, historicalBlob: [first, first] })).toThrow();
	});

	test("an execution failure cannot be dispositioned as findings", () => {
		const { report, ledger, bindings } = reviewedCase();
		expect(decide(report, "history", ledger, bindings, 2, "").pass).toBe(false);
		expect(decide([], "history", ledger, new Map(), 1, "").pass).toBe(false);
		expect(decide(report, "history", ledger, bindings, 0, "").pass).toBe(false);
	});

	test("missing, malformed and unredacted reports cannot pass as clean", () => {
		const { report, ledger, bindings } = reviewedCase();
		for (const invalid of [
			undefined,
			[{ ...report[0], StartColumn: "3" }],
			[{ ...report[0], Secret: "plain" }],
			[{ ...report[0], Fragment: "unsupported" }],
			[{ ...report[0], Link: undefined }],
			[{ ...report[0], Tags: [undefined] }],
		]) {
			expect(decide(invalid, "history", ledger, bindings, 0, "").pass).toBe(false);
		}
	});

	test("unreviewed duplicate rows and reused review rows cannot share approvals", () => {
		const { report, ledger, bindings, approval } = reviewedCase();
		expect(decide([report[0], report[0]], "history", ledger, bindings, 1, "").pass).toBe(false);
		expect(() => parseLedger({ ...ledger, history: [approval, { ...approval, span: [1, 1, 23, 32] }] })).toThrow();
	});

	test("malformed fingerprints and missing evidence cannot authorize a row", () => {
		const { report, ledger } = reviewedCase();
		expect(() => parseReport([{ ...report[0], Fingerprint: "unbound" }], "history")).toThrow();
		ledger.groups.example.evidence = [];
		expect(() => parseLedger(ledger)).toThrow();
	});
});

function duplicateCase(scope: Scope = "historicalBlob") {
	const fixture = reviewedCase();
	const { ledger } = fixture;
	const first: Disposition = { ...fixture.approval, occurrences: 2 };
	if (scope !== "history") {
		first.commit = "";
		first.fingerprint = "example.txt:example-rule:1";
	}
	const distinct: Disposition = { ...first, occurrences: 1, row: 2, span: [1, 1, 23, 32] };
	const last: Disposition = { ...first, row: 3, occurrence: 2, group: "second-review" };
	ledger.groups[last.group] = { ...ledger.groups.example };
	const native = { ...fixture.report[0], Commit: first.commit, Fingerprint: first.fingerprint };
	const report = [native, { ...native, StartColumn: 23, EndColumn: 32 }, { ...native }];
	const { origin, findings, bytes } = reviewedReport(report, scope);
	Object.assign(first, findings[0]);
	Object.assign(distinct, findings[1]);
	Object.assign(last, findings[2]);
	ledger.origins.review = origin;
	ledger.history = [];
	ledger[scope] = [first, distinct, last];
	const version = { file: first.file, blob: first.blob, commits: [fixture.approval.commit] };
	const bindings = new Map(
		[first, distinct, last].map(item => [
			identity(item, scope === "historicalBlob" ? version.blob : undefined),
			item,
		]),
	);
	return { report, bytes, ledger: parseLedger(ledger), bindings, version, first, last };
}

describe("native duplicate report-row boundary", () => {
	for (const scope of ["history", "tree", "historicalBlob"] as const) {
		test(`${scope} preserves each duplicate and accepts only independently bound report rows`, () => {
			const { report, bytes, ledger, bindings, version } = duplicateCase(scope);
			expect(parseReport(report, scope).map(row => [row.occurrence, row.occurrences])).toEqual([
				[1, 2],
				[1, 1],
				[2, 2],
			]);
			const result = decide(report, scope, ledger, bindings, 1, "", version, sha256(bytes));
			expect({ pass: result.pass, approved: result.approved, blocked: result.blocked }).toEqual({
				pass: true,
				approved: 3,
				blocked: [],
			});
		});
	}

	test("partial approval or a blocked member invalidates the entire duplicate group", () => {
		const { report, bytes, ledger, bindings, version, last } = duplicateCase();
		ledger.historicalBlob.pop();
		let result = decide(report, "historicalBlob", ledger, bindings, 1, "", version, sha256(bytes));
		expect(result.approved).toBe(1);
		expect(result.blocked.map(row => row.row)).toEqual([1, 3]);
		ledger.historicalBlob.push(last);
		ledger.groups[last.group].disposition = "blocked";
		result = decide(report, "historicalBlob", ledger, bindings, 1, "", version, sha256(bytes));
		expect(result.pass).toBe(false);
		expect(result.approved).toBe(1);
	});

	test("missing, extra and entirely removed duplicates cannot pass a multiplicity review", () => {
		const { report, ledger, bindings, version } = duplicateCase();
		for (const changed of [report.slice(0, 2), [...report, report[0]], [report[1]]]) {
			const result = decide(
				changed,
				"historicalBlob",
				ledger,
				bindings,
				1,
				"",
				version,
				sha256(new TextEncoder().encode(JSON.stringify(changed))),
			);
			expect(result.pass).toBe(false);
		}
	});

	test("report permutation preserves the original review rows, raw digest and duplicate approvals", () => {
		const { report, ledger, bindings, version } = duplicateCase();
		const original = structuredClone(ledger);
		const permuted = [report[1], report[2], report[0]].map(row => Object.fromEntries(Object.entries(row).reverse()));
		const result = decide(permuted, "historicalBlob", ledger, bindings, 1, "", version);
		expect(result.pass).toBe(true);
		expect(result.approved).toBe(3);
		expect(ledger).toEqual(original);
	});

	test("swapping identical reviewed rows cannot exchange their original occurrence ordinals", () => {
		const { ledger } = duplicateCase();
		ledger.historicalBlob[0].row = 3;
		ledger.historicalBlob[2].row = 1;
		expect(() => parseLedger(ledger)).toThrow();
	});

	test("each duplicate needs its own immutable binding, and a new blob cannot inherit either review", () => {
		const { report, bytes, ledger, bindings, version, last } = duplicateCase();
		bindings.delete(identity(last, version.blob));
		expect(decide(report, "historicalBlob", ledger, bindings, 1, "", version, sha256(bytes)).pass).toBe(false);
		bindings.set(identity(last, version.blob), { ...last, contentSha256: "f".repeat(64) });
		expect(decide(report, "historicalBlob", ledger, bindings, 1, "", version, sha256(bytes)).approved).toBe(1);
		bindings.set(identity(last, version.blob), { ...last, blob: "f".repeat(40) });
		expect(decide(report, "historicalBlob", ledger, bindings, 1, "", version, sha256(bytes)).approved).toBe(1);
		expect(
			decide(report, "historicalBlob", ledger, bindings, 1, "", { ...version, blob: "f".repeat(40) }, sha256(bytes))
				.pass,
		).toBe(false);
	});

	test("unchanged report bytes cannot satisfy a review declaring a different multiplicity or report size", () => {
		const { report, bytes, ledger, bindings, version } = duplicateCase();
		ledger.historicalBlob[2].occurrences = 3;
		expect(decide(report, "historicalBlob", ledger, bindings, 1, "", version, sha256(bytes)).pass).toBe(false);
		ledger.historicalBlob[2].occurrences = 2;
		ledger.origins.review.reportRows++;
		expect(decide(report, "historicalBlob", ledger, bindings, 1, "", version, sha256(bytes)).pass).toBe(false);
	});

	test("the schema cutover rejects missing ordinals and inconsistent or reused review identities", () => {
		const { ledger } = duplicateCase();
		expect(() => parseLedger({ ...ledger, schemaVersion: 3 })).toThrow();
		for (const changed of [
			{ ...ledger.historicalBlob[0], occurrence: undefined },
			{ ...ledger.historicalBlob[0], nativeRowSha256: undefined },
			{ ...ledger.historicalBlob[0], occurrence: 3 },
		])
			expect(() => parseLedger({ ...ledger, historicalBlob: [changed] })).toThrow();
		const first = ledger.historicalBlob[0];
		expect(() => parseLedger({ ...ledger, historicalBlob: [first, { ...first, row: 3 }] })).toThrow();
	});
});

describe("immutable snapshot boundary", () => {
	test("nonregular entries, traversal and invalid UTF-8 are refused before writing", () => {
		const blob = "b".repeat(40);
		for (const entry of [
			`120000 blob ${blob} 12\tlink\0`,
			`160000 commit ${blob} -\tmodule\0`,
			`100644 blob ${blob} 12\t../escape\0`,
			`100644 blob ${blob} 12\t.git/config\0`,
		]) {
			expect(() => parseTree(new TextEncoder().encode(entry))).toThrow();
		}
		expect(() => parseTree(new Uint8Array([255, 0]))).toThrow();
	});

	test("snapshot preserves committed LF bytes and export-ignore files without exporting Git metadata", async () => {
		const owned = await fixture("test-snapshot");
		try {
			const executable = Bun.which("git");
			if (!executable) throw new Error("Snapshot contract requires Git");
			const empty = path.join(owned.dir, "empty");
			await Bun.write(empty, "");
			const template = path.join(owned.dir, "template");
			await fs.mkdir(template);
			// No attribute reads occur before the empty tree is materialized in this fixture.
			const env = { ...neutralEnvironment(owned.env, empty), GIT_ATTR_SOURCE: EMPTY_TREE };
			const context = { executable, cwd: owned.cwd, env, logs: path.join(owned.dir, "git-errors.log") };
			await git(context, ["init", "--bare", "--quiet", "--initial-branch=scan", `--template=${template}`, "."]);
			await git(context, ["hash-object", "-w", "-t", "tree", "--stdin"], new Uint8Array());
			const files: Record<string, string> = {
				".gitattributes": "*.cmd text eol=crlf\nhidden.txt export-ignore\n",
				"command.cmd": "first\nsecond\n",
				"hidden.txt": "included in the complete source snapshot\n",
			};
			const rows: string[] = [];
			for (const [file, content] of Object.entries(files)) {
				const blob = (
					await git(context, ["hash-object", "-w", "--stdin"], new TextEncoder().encode(content))
				).trim();
				rows.push(`100644 blob ${blob}\t${file}\n`);
			}
			const tree = (await git(context, ["mktree"], new TextEncoder().encode(rows.join("")))).trim();
			const destination = path.join(owned.dir, "snapshot");
			await snapshot(context, tree, destination);
			expect((await fs.readdir(destination)).sort()).toEqual(Object.keys(files).sort());
			expect(await Bun.file(path.join(destination, "command.cmd")).text()).toBe("first\nsecond\n");
			expect(await Bun.file(path.join(destination, "hidden.txt")).text()).toBe(files["hidden.txt"]);
		} finally {
			await fs.rm(owned.dir, { recursive: true, force: true });
			if (owned.env.TMPDIR) await fs.rm(owned.env.TMPDIR, { recursive: true, force: true });
		}
	});
});

describe("historical whole-blob coverage boundary", () => {
	const commit = "a".repeat(40);
	const next = "b".repeat(40);
	const blob = "c".repeat(40);
	const other = "d".repeat(40);
	const zero = "0".repeat(40);
	const encode = (text: string): Uint8Array => new TextEncoder().encode(text);
	const header = (id: string): string => `\0commit ${id}\0\0`;
	const addition = (file: string, object = blob): string => `:000000 100644 ${zero} ${object} A\0${file}\0`;

	test("deduplication retains every occurrence commit, mode changes and distinct paths while excluding only deletions", () => {
		const file = 'assets/opaque "name".data';
		const raw =
			header(commit) +
			"\n" +
			addition(file) +
			addition("archive.zip") +
			`-\t-\t${file}\0-\t-\tarchive.zip\0` +
			header(next) +
			"\n" +
			`:100644 100755 ${blob} ${blob} M\0${file}\0` +
			`:100644 000000 ${blob} ${zero} D\0archive.zip\0` +
			`-\t-\t${file}\0-\t-\tarchive.zip\0`;
		const inventory = parseHistoryMetadata(encode(raw), new Set([commit, next]));
		expect(inventory.versions).toEqual([
			{ file, blob, commits: [commit, next] },
			{ file: "archive.zip", blob, commits: [commit] },
		]);
		expect(inventory.binaryChanges).toBe(4);
		expect(inventory.commits[1].changes.map(change => change.status)).toEqual(["M", "D"]);
	});

	test("empty and text-only commits remain required ancestry members without inventing binary versions", () => {
		const raw = header(commit) + "\n" + addition("notes.txt") + "2\t0\tnotes.txt\0" + header(next);
		const inventory = parseHistoryMetadata(encode(raw), new Set([commit, next]));
		expect(inventory.versions).toEqual([]);
		expect(inventory.commits.map(item => item.commit)).toEqual([commit, next]);
		expect(() => parseHistoryMetadata(encode(header(commit)), new Set([commit, next]))).toThrow();
		expect(() => parseHistoryMetadata(encode(header(commit) + header(commit)), new Set([commit]))).toThrow();
	});

	test("historical link targets and type changes retain exact stored-blob coverage", () => {
		const third = "e".repeat(40);
		const fourth = "f".repeat(40);
		const raw =
			header(commit) +
			"\n" +
			`:000000 120000 ${zero} ${blob} A\0link\0` +
			"1\t0\tlink\0" +
			header(next) +
			"\n" +
			`:120000 120000 ${blob} ${other} M\0link\0` +
			"1\t1\tlink\0" +
			header(third) +
			"\n" +
			`:120000 100644 ${other} ${other} T\0link\0` +
			"0\t0\tlink\0" +
			header(fourth) +
			"\n" +
			`:100644 000000 ${other} ${zero} D\0link\0` +
			"0\t1\tlink\0";
		const inventory = parseHistoryMetadata(encode(raw), new Set([commit, next, third, fourth]));
		expect(inventory.versions).toEqual([
			{ file: "link", blob, commits: [commit] },
			{ file: "link", blob: other, commits: [next, third] },
		]);
		expect(inventory.binaryChanges).toBe(0);
		expect(inventory.commits.map(item => item.changes[0].status)).toEqual(["A", "M", "T", "D"]);
	});

	test("gitlinks retain external reference history without pretending their commits are file blobs", () => {
		const raw =
			header(commit) +
			"\n" +
			`:000000 160000 ${zero} ${blob} A\0external\0` +
			"1\t0\texternal\0" +
			header(next) +
			"\n" +
			`:160000 000000 ${blob} ${zero} D\0external\0` +
			"0\t1\texternal\0";
		const inventory = parseHistoryMetadata(encode(raw), new Set([commit, next]));
		expect(inventory.gitlinks).toEqual([{ file: "external", targetCommit: blob, commits: [commit] }]);
		expect(inventory.versions).toEqual([]);
		expect(inventory.commits[1].changes[0].oldObject).toBe(blob);
	});

	test("raw/numstat ambiguity, unsupported paths and truncated records fail instead of omitting blobs", () => {
		const start = header(commit) + "\n";
		for (const raw of [
			start + addition("one") + "-\t-\ttwo\0",
			start + addition("one") + "-\t0\tone\0",
			start + addition("one") + addition("one") + "-\t-\tone\0-\t-\tone\0",
			start + addition("one") + "-\t-\tone",
			start + addition("one") + "-\t-\tone\0-\t-\textra\0",
			start + addition("tab\tname") + "-\t-\ttab\tname\0",
			start + addition("line\nname") + "-\t-\tline\nname\0",
			start + addition("../escape") + "-\t-\t../escape\0",
			start + `:100644 100644 ${blob} ${other} R100\0old\0new\0-\t-\t\0old\0new\0`,
			start + `:000000 040000 ${zero} ${blob} A\0directory\0-\t-\tdirectory\0`,
			start + `:000000 100644 ${blob} ${other} A\0bad\0-\t-\tbad\0`,
			start + `:100644 120000 ${blob} ${other} M\0link\0-\t-\tlink\0`,
			start + `:100644 100755 ${blob} ${other} T\0file\0-\t-\tfile\0`,
		])
			expect(() => parseHistoryMetadata(encode(raw), new Set([commit]))).toThrow();
		expect(() => parseHistoryMetadata(new Uint8Array([255, 0]), new Set([commit]))).toThrow();
	});

	test("missing, duplicate, wrong-version and interrupted receipts cannot complete historical coverage", () => {
		const versions = [
			{ file: "one", blob, commits: [commit] },
			{ file: "one", blob: other, commits: [next] },
		];
		const first = { version: versions[0], complete: true, pass: true };
		const second = { version: versions[1], complete: true, pass: true };
		expect(historicalCoverage(versions, [first])).toEqual({ complete: false, pass: false });
		expect(historicalCoverage(versions, [first, first])).toEqual({ complete: false, pass: false });
		expect(historicalCoverage(versions, [first, { ...second, complete: false }]).pass).toBe(false);
		expect(historicalCoverage(versions, [first, { ...second, pass: false }])).toEqual({
			complete: true,
			pass: false,
		});
		expect(historicalCoverage(versions, [first, second])).toEqual({ complete: true, pass: true });
	});

	test("the combined receipt requires complete passing execution of all three scopes and unchanged inputs", () => {
		const scopes: Parameters<typeof scopesPass>[0] = {
			history: { status: "passed", complete: true },
			tree: { status: "passed", complete: true },
			historicalBlob: { status: "not-run", complete: false },
			attributeCanary: { status: "passed", complete: true, receiptSha256: "c".repeat(64) },
		};
		expect(scopesPass(scopes, [])).toBe(false);
		scopes.historicalBlob = { status: "failed", complete: true };
		expect(scopesPass(scopes, [])).toBe(false);
		scopes.historicalBlob = { status: "passed", complete: false };
		expect(scopesPass(scopes, [])).toBe(false);
		scopes.historicalBlob.complete = true;
		expect(scopesPass(scopes, ["Source HEAD moved during scan"])).toBe(false);
		expect(scopesPass(scopes, [])).toBe(true);
	});

	test("the combined gate rejects absent, incomplete, failed or unbound attribute canaries", () => {
		const scopes: Parameters<typeof scopesPass>[0] = {
			history: { status: "passed", complete: true },
			tree: { status: "passed", complete: true },
			historicalBlob: { status: "passed", complete: true },
		};
		expect(scopesPass(scopes, [])).toBe(false);
		for (const attributeCanary of [
			{ status: "not-run", complete: false },
			{ status: "failed", complete: true, receiptSha256: "c".repeat(64) },
			{ status: "passed", complete: false, receiptSha256: "c".repeat(64) },
			{ status: "passed", complete: true },
			{ status: "passed", complete: true, receiptSha256: "not-a-digest" },
		] as const) {
			scopes.attributeCanary = attributeCanary;
			expect(scopesPass(scopes, [])).toBe(false);
		}
		scopes.attributeCanary = { status: "passed", complete: true, receiptSha256: "c".repeat(64) };
		expect(scopesPass(scopes, [])).toBe(true);
	});

	test("real Git root, merge and empty-commit metadata honors the pinned attribute tree over candidate attributes", async () => {
		const owned = await fixture("test-history-metadata");
		try {
			const executable = Bun.which("git");
			if (!executable) throw new Error("History metadata contract requires Git");
			const empty = path.join(owned.dir, "empty");
			await Bun.write(empty, "");
			const template = path.join(owned.dir, "template");
			await fs.mkdir(template);
			const context = {
				executable,
				cwd: owned.cwd,
				logs: path.join(owned.dir, "git-errors.log"),
				env: {
					...neutralEnvironment(owned.env, empty),
					GIT_ATTR_SOURCE: EMPTY_TREE,
					GIT_AUTHOR_NAME: "Fixture",
					GIT_AUTHOR_EMAIL: "fixture@example.invalid",
					GIT_COMMITTER_NAME: "Fixture",
					GIT_COMMITTER_EMAIL: "fixture@example.invalid",
				},
			};
			await git(context, ["init", "--bare", "--quiet", "--initial-branch=scan", `--template=${template}`, "."]);
			await git(context, ["hash-object", "-w", "-t", "tree", "--stdin"], new Uint8Array());
			async function tree(attributes: string, content: string): Promise<{ tree: string; blob: string }> {
				const attributeBlob = (await git(context, ["hash-object", "-w", "--stdin"], encode(attributes))).trim();
				const object = (await git(context, ["hash-object", "-w", "--stdin"], encode(content))).trim();
				const tree = (
					await git(
						context,
						["mktree"],
						encode(`100644 blob ${attributeBlob}\t.gitattributes\n100644 blob ${object}\topaque.data\n`),
					)
				).trim();
				return { tree, blob: object };
			}
			async function commitTree(tree: string, parents: string[] = []): Promise<string> {
				return (
					await git(
						context,
						["commit-tree", tree, ...parents.flatMap(parent => ["-p", parent])],
						encode("fixture\n"),
					)
				).trim();
			}
			const baseTree = await tree("*.data binary\n", "first line\n");
			const root = await commitTree(baseTree.tree);
			context.env.GIT_ATTR_SOURCE = root;
			const sideTree = await tree("*.data diff\n", "second line\n");
			const side = await commitTree(sideTree.tree, [root]);
			const emptyCommit = await commitTree(baseTree.tree, [root]);
			const merge = await commitTree(sideTree.tree, [emptyCommit, side]);
			const canary = path.join(owned.dir, "outside-canary");
			await Bun.write(canary, "host bytes must not be ingested");
			const targetBlob = (await git(context, ["hash-object", "-w", "--stdin"], encode(canary))).trim();
			const external = "f".repeat(40);
			const linkTree = (
				await git(
					context,
					["mktree", "--missing"],
					encode(`160000 commit ${external}\texternal-ref\n120000 blob ${targetBlob}\thistoric-link\n`),
				)
			).trim();
			const plainTree = (
				await git(context, ["mktree"], encode(`100644 blob ${targetBlob}\thistoric-link\n`))
			).trim();
			const linkCommit = await commitTree(linkTree, [root]);
			const plainCommit = await commitTree(plainTree, [linkCommit]);
			const candidate = await commitTree(sideTree.tree, [merge, plainCommit]);
			const ancestry = new Set([candidate, plainCommit, linkCommit, merge, side, emptyCommit, root]);
			const raw = await git(context, [
				"log",
				...HISTORY_SELECTION,
				"--always",
				"--raw",
				"--numstat",
				"-z",
				"--no-abbrev",
				"--format=%x00commit %H%x00",
				candidate,
				"--",
			]);
			const inventory = parseHistoryMetadata(encode(raw), ancestry);
			const changed = inventory.versions.find(version => version.blob === sideTree.blob);
			expect(changed?.commits.sort()).toEqual([merge, side].sort());
			expect(inventory.versions.find(version => version.blob === baseTree.blob)?.commits).toEqual([root]);
			expect(inventory.commits.find(item => item.commit === emptyCommit)?.changes).toEqual([]);
			expect(inventory.versions.find(version => version.blob === targetBlob)?.commits).toEqual([
				plainCommit,
				linkCommit,
			]);
			expect(inventory.gitlinks).toEqual([{ file: "external-ref", targetCommit: external, commits: [linkCommit] }]);
			const exported = path.join(owned.dir, "exported-target");
			await blobs(context, [{ spec: targetBlob, blob: targetBlob }], async (_request, _blob, bytes) => {
				await Bun.write(exported, bytes);
			});
			const stat = await fs.lstat(exported);
			expect(stat.isFile() && !stat.isSymbolicLink()).toBe(true);
			expect(await Bun.file(exported).text()).toBe(canary);
			expect(await Bun.file(canary).text()).toBe("host bytes must not be ingested");
		} finally {
			await fs.rm(owned.dir, { recursive: true, force: true });
			if (owned.env.TMPDIR) await fs.rm(owned.env.TMPDIR, { recursive: true, force: true });
		}
	}, 30_000);
});

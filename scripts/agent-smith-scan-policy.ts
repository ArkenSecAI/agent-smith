/** Pure, fail-closed disposition boundary. Raw report payloads never enter the public ledger. */
export const SOURCE_BASE = "717f97f4d22b3d65c4a4eef6a744255d46f4d1a6";
export const SOURCE_TREE = "3f8ecdad21e55c5f47785ccfbd4f8c0528186976";
export const EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
export const SCANNER_VERSION = "8.30.1";
export const SCANNER_SHA256 = "88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509";
export const DEFAULT_CONFIG = "[extend]\nuseDefault = true\n";

export type Scope = "history" | "tree" | "historicalBlob";
export const HISTORY_SELECTION = [
	"--full-history",
	"--diff-merges=first-parent",
	"--root",
	"--no-renames",
	"--no-ext-diff",
	"--no-textconv",
];
export interface HistoricalVersion {
	file: string;
	blob: string;
	commits: string[];
}
export type Span = [number, number, number, number];
export interface Finding {
	commit: string;
	file: string;
	rule: string;
	span: Span;
	fingerprint: string;
	/** Commitment to every native field, before projection or occurrence numbering. */
	nativeRowSha256: string;
	/** One-based ordinal and total within identical complete native records in this report. */
	occurrence: number;
	occurrences: number;
}
export interface Binding {
	blob: string;
	containerSha256: string;
	contentSha256: string;
}
export interface Disposition extends Finding, Binding {
	origin: string;
	row: number;
	group: string;
}
export interface Origin {
	reportSha256: string;
	reportContentSha256: string;
	/** Original reviewed order; never replaced by the current scanner's row order. */
	rowDigests: string[];
	reviewSha256: string;
	sourceCommit: string;
	sourceTree: string;
	reportRows: number;
}
export interface ReviewGroup {
	origin: string;
	disposition: "reviewed_non_secret" | "blocked";
	reason: string;
	evidence: string[];
}
export interface Ledger {
	schemaVersion: 4;
	sourceBase: string;
	sourceTree: string;
	origins: Record<string, Origin>;
	groups: Record<string, ReviewGroup>;
	history: Disposition[];
	tree: Disposition[];
	historicalBlob: Disposition[];
}
export interface Decision {
	pass: boolean;
	findings: number;
	approved: number;
	blocked: { row: number; fingerprint: string; span: Span; reason: string }[];
	errors: string[];
	reportContentSha256?: string;
}
export interface ScopeOutcome {
	status: "not-run" | "failed" | "passed";
	complete: boolean;
}
export interface AttributeCanaryOutcome extends ScopeOutcome {
	receiptSha256?: string;
}
export const STDERR_ERROR = "Scanner stderr is not empty; native errors remain blocking";

export function scopesPass(
	scopes: Record<Scope, ScopeOutcome> & { attributeCanary?: AttributeCanaryOutcome },
	errors: readonly string[],
): boolean {
	return (
		errors.length === 0 &&
		scopes.attributeCanary?.complete === true &&
		scopes.attributeCanary.status === "passed" &&
		/^[0-9a-f]{64}$/.test(scopes.attributeCanary.receiptSha256 ?? "") &&
		(["history", "historicalBlob", "tree"] as const).every(
			scope => scopes[scope].complete && scopes[scope].status === "passed",
		)
	);
}

export function record(value: unknown): Record<string, unknown> {
	if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("Expected object");
	return value as Record<string, unknown>;
}

export function string(value: unknown): string {
	if (typeof value !== "string") throw new Error("Expected string");
	return value;
}

export function oid(value: unknown): string {
	const result = string(value);
	if (!/^[0-9a-f]{40}$/.test(result)) throw new Error("Expected complete SHA-1 object identity");
	return result;
}

export function digest(value: unknown): string {
	const result = string(value);
	if (!/^[0-9a-f]{64}$/.test(result)) throw new Error("Expected SHA-256 digest");
	return result;
}

function integer(value: unknown, minimum = 1): number {
	if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum) {
		throw new Error("Invalid integer");
	}
	return value;
}

function array(value: unknown): unknown[] {
	if (!Array.isArray(value)) throw new Error("Expected array");
	return value;
}

/** Reject ambiguous filesystem and archive identities, rather than rewriting them. */
export function safePath(value: unknown): string {
	const result = string(value);
	if (
		!result ||
		/[\x00-\x1f\x7f\\:!]/.test(result) ||
		result.split("/").some(part => !part || part === "." || part === ".." || part.toLowerCase() === ".git")
	) {
		throw new Error("Unsafe source path");
	}
	return result;
}

function detectionPath(value: unknown): string {
	const result = string(value);
	const parts = result.split("!");
	if (parts.length > 3) throw new Error("Unexpected archive nesting");
	for (const part of parts) safePath(part);
	return result;
}

function span(value: unknown): Span {
	const parts = array(value);
	if (parts.length !== 4) throw new Error("Invalid detection span");
	const result: Span = [integer(parts[0]), integer(parts[1]), integer(parts[2], 0), integer(parts[3], 0)];
	if (result[1] < result[0] || (result[0] === result[1] && result[3] < result[2])) {
		throw new Error("Reversed detection span");
	}
	return result;
}

function finding(value: unknown, scope: Scope): Finding {
	const item = record(value);
	const commit = scope === "history" ? oid(item.commit) : string(item.commit);
	if (scope !== "history" && commit !== "") throw new Error("Directory reports must retain their empty native Commit");
	const file = detectionPath(item.file);
	const rule = string(item.rule);
	if (!/^[a-z0-9-]+$/.test(rule)) throw new Error("Invalid rule identity");
	const coordinates = span(item.span);
	const fingerprint = string(item.fingerprint);
	if (fingerprint !== `${commit ? `${commit}:` : ""}${file}:${rule}:${coordinates[0]}`) {
		throw new Error("Fingerprint does not bind the reported occurrence");
	}
	const occurrence = integer(item.occurrence);
	const occurrences = integer(item.occurrences);
	if (occurrence > occurrences) throw new Error("Invalid occurrence ordinal");
	return {
		commit,
		file,
		rule,
		span: coordinates,
		fingerprint,
		nativeRowSha256: digest(item.nativeRowSha256),
		occurrence,
		occurrences,
	};
}

const NATIVE_FIELDS = new Set([
	"RuleID",
	"Description",
	"StartLine",
	"EndLine",
	"StartColumn",
	"EndColumn",
	"Match",
	"Secret",
	"File",
	"SymlinkFile",
	"Commit",
	"Entropy",
	"Author",
	"Email",
	"Date",
	"Message",
	"Tags",
	"Fingerprint",
	"Link",
]);

/** Row order is irrelevant; multiplicity and every original native field remain binding. */
export function reportContentSha256(rowDigests: readonly string[]): string {
	return new Bun.CryptoHasher("sha256")
		.update("agent-smith/gitleaks-report/v1\0")
		.update(JSON.stringify(rowDigests.toSorted()))
		.digest("hex");
}

export function parseReport(value: unknown, scope: Scope): Finding[] {
	const counts = new Map<string, number>();
	const findings = array(value).map(raw => {
		const item = record(raw);
		const entries = Object.entries(item);
		if (entries.some(([key]) => !NATIVE_FIELDS.has(key))) throw new Error("Unsupported native report field");
		if (item.Secret !== "REDACTED" || !string(item.Match).includes("REDACTED") || item.SymlinkFile !== "") {
			throw new Error("Unredacted or unsupported report finding");
		}
		for (const field of ["Description", "Author", "Email", "Date", "Message"]) string(item[field]);
		if (Object.hasOwn(item, "Link")) string(item.Link);
		if (typeof item.Entropy !== "number" || !Number.isFinite(item.Entropy)) throw new Error("Invalid entropy");
		if (item.Tags !== null) for (const tag of array(item.Tags)) string(tag);
		const nativeRowSha256 = new Bun.CryptoHasher("sha256")
			.update("agent-smith/gitleaks-row/v1\0")
			.update(JSON.stringify(entries.sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))))
			.digest("hex");
		const result = finding(
			{
				commit: item.Commit,
				file: item.File,
				rule: item.RuleID,
				span: [item.StartLine, item.EndLine, item.StartColumn, item.EndColumn],
				fingerprint: item.Fingerprint,
				nativeRowSha256,
				occurrence: 1,
				occurrences: 1,
			},
			scope,
		);
		const key = rawIdentity(result);
		result.occurrence = (counts.get(key) ?? 0) + 1;
		counts.set(key, result.occurrence);
		return result;
	});
	for (const item of findings) item.occurrences = counts.get(rawIdentity(item)) ?? 0;
	return findings;
}

function rawIdentity(item: Finding, blob?: string): string {
	const parts = [item.commit, item.file, item.rule, ...item.span, item.fingerprint, item.nativeRowSha256];
	if (blob !== undefined) parts.push(oid(blob));
	return JSON.stringify(parts);
}

export function identity(item: Finding, blob?: string): string {
	return JSON.stringify([rawIdentity(item, blob), item.occurrence]);
}

export function parseLedger(value: unknown): Ledger {
	const input = record(value);
	if (input.schemaVersion !== 4 || input.sourceBase !== SOURCE_BASE || input.sourceTree !== SOURCE_TREE) {
		throw new Error("Unsupported ledger or changed original source pin");
	}
	const origins: Record<string, Origin> = Object.create(null);
	const originalOccurrences = new Map<string, { ordinals: number[]; counts: Map<string, number> }>();
	for (const [key, raw] of Object.entries(record(input.origins))) {
		const item = record(raw);
		origins[key] = {
			reportSha256: digest(item.reportSha256),
			reportContentSha256: digest(item.reportContentSha256),
			rowDigests: array(item.rowDigests).map(digest),
			reviewSha256: digest(item.reviewSha256),
			sourceCommit: oid(item.sourceCommit),
			sourceTree: oid(item.sourceTree),
			reportRows: integer(item.reportRows),
		};
		const origin = origins[key];
		if (
			origin.reportRows !== origin.rowDigests.length ||
			origin.reportContentSha256 !== reportContentSha256(origin.rowDigests)
		) {
			throw new Error("Inconsistent complete reviewed report commitment");
		}
		const counts = new Map<string, number>();
		const ordinals = origin.rowDigests.map(hash => {
			const ordinal = (counts.get(hash) ?? 0) + 1;
			counts.set(hash, ordinal);
			return ordinal;
		});
		originalOccurrences.set(key, { ordinals, counts });
	}
	const groups: Record<string, ReviewGroup> = Object.create(null);
	for (const [key, raw] of Object.entries(record(input.groups))) {
		const item = record(raw);
		const origin = string(item.origin);
		if (!origins[origin] || !["reviewed_non_secret", "blocked"].includes(string(item.disposition))) {
			throw new Error("Unbound review group");
		}
		const reason = string(item.reason);
		const evidence = array(item.evidence).map(string);
		if (!reason.trim() || evidence.length === 0 || evidence.some(text => !text.trim())) {
			throw new Error("Missing review evidence");
		}
		groups[key] = { origin, disposition: item.disposition as ReviewGroup["disposition"], reason, evidence };
	}
	const rows = new Set<string>();
	function dispositions(scope: Scope): Disposition[] {
		const seen = new Set<string>();
		return array(input[scope]).map(raw => {
			const item = record(raw);
			const origin = string(item.origin);
			const group = string(item.group);
			const row = integer(item.row);
			const review = origins[origin];
			if (!review || row > review.reportRows || groups[group]?.origin !== origin) {
				throw new Error("Disposition lacks an exact reviewed report row");
			}
			// Identical native directory reports can belong to distinct immutable blobs.
			const rowKey = `${review.reportSha256}:${row}${scope === "historicalBlob" ? `:${oid(item.blob)}` : ""}`;
			if (rows.has(rowKey)) throw new Error("Review row reused");
			rows.add(rowKey);
			const result: Disposition = {
				...finding(item, scope),
				origin,
				row,
				group,
				blob: oid(item.blob),
				containerSha256: digest(item.containerSha256),
				contentSha256: digest(item.contentSha256),
			};
			const original = originalOccurrences.get(origin)!;
			if (
				review.rowDigests[row - 1] !== result.nativeRowSha256 ||
				original.ordinals[row - 1] !== result.occurrence ||
				original.counts.get(result.nativeRowSha256) !== result.occurrences
			) {
				throw new Error("Disposition changed its original native record or reviewed ordinal");
			}
			if (!result.file.includes("!") && result.contentSha256 !== result.containerSha256) {
				throw new Error("Plain file has inconsistent content binding");
			}
			const key = identity(result, scope === "historicalBlob" ? result.blob : undefined);
			if (seen.has(key)) throw new Error("Duplicate disposition identity");
			seen.add(key);
			return result;
		});
	}
	return {
		schemaVersion: 4,
		sourceBase: SOURCE_BASE,
		sourceTree: SOURCE_TREE,
		origins,
		groups,
		history: dispositions("history"),
		tree: dispositions("tree"),
		historicalBlob: dispositions("historicalBlob"),
	};
}

export interface ApprovalIndex {
	rows: ReadonlyMap<string, Disposition>;
	duplicates: ReadonlyMap<string, readonly Disposition[]>;
	origins: ReadonlySet<string>;
}
export interface PreparedLedger {
	ledger: Ledger;
	history: ApprovalIndex;
	tree: ApprovalIndex;
	historicalBlob: ReadonlyMap<string, ApprovalIndex>;
}
const EMPTY_INDEX: ApprovalIndex = { rows: new Map(), duplicates: new Map(), origins: new Set() };

/** Prepare once, including exact path/blob subsets; hundreds of scans do not rebuild the ledger. */
export function prepareLedger(ledger: Ledger): PreparedLedger {
	function index(rows: Disposition[], historical = false): ApprovalIndex {
		const indexed = new Map<string, Disposition>();
		const duplicates = new Map<string, Disposition[]>();
		const origins = new Set<string>();
		for (const item of rows) {
			origins.add(item.origin);
			const blob = historical ? item.blob : undefined;
			const key = identity(item, blob);
			if (indexed.has(key)) throw new Error("Duplicate disposition identity");
			indexed.set(key, item);
			if (item.occurrences > 1) {
				const raw = rawIdentity(item, blob);
				const group = duplicates.get(raw) ?? [];
				group.push(item);
				duplicates.set(raw, group);
			}
		}
		return { rows: indexed, duplicates, origins };
	}
	const versions = new Map<string, Disposition[]>();
	for (const item of ledger.historicalBlob) {
		const key = JSON.stringify([item.file.split("!")[0], item.blob]);
		const rows = versions.get(key) ?? [];
		rows.push(item);
		versions.set(key, rows);
	}
	return {
		ledger,
		history: index(ledger.history),
		tree: index(ledger.tree),
		historicalBlob: new Map([...versions].map(([key, rows]) => [key, index(rows, true)])),
	};
}

export function approvalsFor(prepared: PreparedLedger, scope: Scope, version?: HistoricalVersion): ApprovalIndex {
	return scope === "historicalBlob"
		? (prepared.historicalBlob.get(JSON.stringify([version?.file, version?.blob])) ?? EMPTY_INDEX)
		: prepared[scope];
}

export function decide(
	report: unknown,
	scope: Scope,
	prepared: PreparedLedger,
	bindings: ReadonlyMap<string, Binding>,
	exitCode: number,
	stderr: string,
	reportSha256: string,
	version?: HistoricalVersion,
): Decision {
	const { ledger } = prepared;
	const result: Decision = { pass: false, findings: 0, approved: 0, blocked: [], errors: [] };
	if (scope === "historicalBlob" && (!version || version.commits.length === 0)) {
		result.errors.push("Missing historical version coverage context");
		return result;
	}
	if (stderr.length !== 0) result.errors.push(STDERR_ERROR);
	if (exitCode !== 0 && exitCode !== 1) result.errors.push(`Scanner failed with exit ${exitCode}`);
	let findings: Finding[];
	try {
		digest(reportSha256);
		findings = parseReport(report, scope);
	} catch {
		result.errors.push("Missing, malformed or unredacted report/digest");
		return result;
	}
	result.findings = findings.length;
	result.reportContentSha256 = reportContentSha256(findings.map(item => item.nativeRowSha256));
	if ((exitCode === 0 && findings.length !== 0) || (exitCode === 1 && findings.length === 0)) {
		result.errors.push("Scanner exit/report inconsistency");
	}
	const index = approvalsFor(prepared, scope, version);
	for (const id of index.origins) {
		const origin = ledger.origins[id];
		if (
			!origin ||
			origin.reportRows !== findings.length ||
			origin.reportContentSha256 !== result.reportContentSha256
		) {
			result.errors.push("Complete native report membership or metadata changed since independent review");
		}
	}
	const approvals = index.rows;
	const blob = scope === "historicalBlob" ? version?.blob : undefined;
	const groups = new Map<string, Finding[]>();
	for (const item of findings) {
		const raw = rawIdentity(item, blob);
		if (item.occurrences > 1 || index.duplicates.has(raw)) {
			const rows = groups.get(raw) ?? [];
			rows.push(item);
			groups.set(raw, rows);
		}
	}
	const invalid = new Set<string>();
	for (const raw of new Set([...index.duplicates.keys(), ...groups.keys()])) {
		const rows = groups.get(raw) ?? [];
		const reviewed = index.duplicates.get(raw) ?? [];
		// Every duplicate member must independently bind the original bytes, row, ordinal and source.
		const valid =
			rows.length > 1 &&
			reviewed.length === rows.length &&
			rows.every((item, offset) => {
				const approval = approvals.get(identity(item, blob));
				const bound = bindings.get(identity(item, blob));
				const origin = approval && ledger.origins[approval.origin];
				return (
					approval &&
					bound &&
					origin &&
					approval.occurrence === offset + 1 &&
					approval.occurrences === rows.length &&
					item.occurrences === rows.length &&
					origin.rowDigests[approval.row - 1] === item.nativeRowSha256 &&
					origin.reportRows === findings.length &&
					origin.reportContentSha256 === result.reportContentSha256 &&
					approval.blob === bound.blob &&
					approval.containerSha256 === bound.containerSha256 &&
					approval.contentSha256 === bound.contentSha256 &&
					ledger.groups[approval.group].disposition === "reviewed_non_secret"
				);
			});
		if (!valid) {
			invalid.add(raw);
			result.errors.push("Duplicate group lacks complete independent report-row/source review");
		}
	}
	for (const [index, item] of findings.entries()) {
		if (scope === "historicalBlob" && item.file.split("!")[0] !== version?.file) {
			result.errors.push("Finding outside historical object snapshot");
			continue;
		}
		const key = identity(item, scope === "historicalBlob" ? version?.blob : undefined);
		const approval = approvals.get(key);
		const bound = bindings.get(key);
		let reason = "Unreviewed occurrence";
		if (invalid.has(rawIdentity(item, blob))) reason = "Unbound duplicate group";
		else if (!bound) reason = "Missing immutable source binding";
		else if (scope === "historicalBlob" && bound.blob !== version?.blob)
			reason = "Changed historical version binding";
		else if (approval) {
			const origin = ledger.origins[approval.origin];
			if (
				!origin ||
				origin.reportContentSha256 !== result.reportContentSha256 ||
				origin.reportRows !== findings.length ||
				origin.rowDigests[approval.row - 1] !== item.nativeRowSha256
			) {
				reason = "Changed reviewed report binding";
			} else if (
				approval.occurrences !== item.occurrences ||
				approval.blob !== bound.blob ||
				approval.containerSha256 !== bound.containerSha256 ||
				approval.contentSha256 !== bound.contentSha256
			) {
				reason = "Changed immutable source binding";
			} else if (ledger.groups[approval.group].disposition === "reviewed_non_secret") {
				result.approved++;
				continue;
			} else reason = ledger.groups[approval.group].reason;
		}
		result.blocked.push({ row: index + 1, fingerprint: item.fingerprint, span: item.span, reason });
	}
	result.pass = result.errors.length === 0 && result.blocked.length === 0;
	return result;
}

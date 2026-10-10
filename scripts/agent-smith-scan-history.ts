import type { HistoricalVersion } from "./agent-smith-scan-policy";
import { HISTORY_SELECTION, oid, safePath, SOURCE_BASE } from "./agent-smith-scan-policy";
import type { GitContext } from "./agent-smith-scan-source";
import { git } from "./agent-smith-scan-source";

interface Change {
	file: string;
	oldMode: string;
	mode: string;
	oldBlob: string;
	blob: string;
	status: string;
	binary: boolean;
}
export interface HistoryMetadata {
	commits: { commit: string; changes: Change[] }[];
	binaryChanges: number;
	versions: HistoricalVersion[];
}

/** Parse Git's NUL protocol by position, never by lines or a path-shaped delimiter. */
export function parseHistoryMetadata(bytes: Uint8Array, ancestry: ReadonlySet<string>): HistoryMetadata {
	const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
	let offset = 0;
	function token(): string {
		const end = text.indexOf("\0", offset);
		if (end === -1) throw new Error("Truncated history metadata");
		const result = text.slice(offset, end);
		offset = end + 1;
		return result;
	}
	const result: HistoryMetadata = { commits: [], binaryChanges: 0, versions: [] };
	const seen = new Set<string>();
	const versions = new Map<string, HistoricalVersion>();
	const zero = "0".repeat(40);
	while (offset < text.length) {
		if (token() !== "") throw new Error("Invalid history record boundary");
		const header = /^commit ([0-9a-f]{40})$/.exec(token());
		if (!header || token() !== "") throw new Error("Invalid history commit header");
		const commit = oid(header[1]);
		if (!ancestry.has(commit) || seen.has(commit)) throw new Error("Unexpected or repeated history commit");
		seen.add(commit);
		const changes: Change[] = [];
		const paths = new Set<string>();
		if (text[offset] === "\n") {
			offset++;
			if (text[offset] !== ":") throw new Error("Missing raw diff after commit separator");
		}
		while (text[offset] === ":") {
			const raw = /^:(000000|100644|100755) (000000|100644|100755) ([0-9a-f]{40}) ([0-9a-f]{40}) ([AMD])$/.exec(
				token(),
			);
			if (!raw) throw new Error("Unsupported raw diff mode/status or ambiguous metadata");
			const [, oldMode, mode, oldBlob, blob, status] = raw;
			const file = safePath(token());
			if (paths.has(file)) throw new Error("Repeated raw diff path");
			paths.add(file);
			if (
				(oldMode === "000000") !== (oldBlob === zero) ||
				(mode === "000000") !== (blob === zero) ||
				(status === "A" && (oldBlob !== zero || blob === zero)) ||
				(status === "D" && (oldBlob === zero || blob !== zero)) ||
				(status === "M" && (oldBlob === zero || blob === zero)) ||
				(oldBlob === blob && oldMode === mode)
			) {
				throw new Error("Inconsistent raw diff identity");
			}
			changes.push({ file, oldMode, mode, oldBlob, blob, status, binary: false });
		}
		for (const change of changes) {
			const stat = /^(-|[0-9]+)\t(-|[0-9]+)\t(.+)$/.exec(token());
			if (!stat || safePath(stat[3]) !== change.file || (stat[1] === "-") !== (stat[2] === "-")) {
				throw new Error("Raw/numstat paths or counts do not align");
			}
			change.binary = stat[1] === "-";
			if (!change.binary && (!Number.isSafeInteger(Number(stat[1])) || !Number.isSafeInteger(Number(stat[2])))) {
				throw new Error("Unsupported numstat count");
			}
			if (!change.binary) continue;
			result.binaryChanges++;
			if (change.status === "D") continue;
			const key = JSON.stringify([change.file, change.blob]);
			let version = versions.get(key);
			if (!version) {
				version = { file: change.file, blob: change.blob, commits: [] };
				versions.set(key, version);
			}
			version.commits.push(commit);
		}
		result.commits.push({ commit, changes });
	}
	if (seen.size !== ancestry.size) throw new Error("History metadata does not cover complete ancestry");
	result.versions = [...versions.values()];
	return result;
}

export async function historyMetadata(context: GitContext, candidate: string): Promise<Uint8Array> {
	if (context.env.GIT_ATTR_SOURCE !== SOURCE_BASE) throw new Error("History metadata attribute source mismatch");
	// --always retains empty commits. No patches, pathspecs, traversal limits or extension filters.
	const text = await git(context, [
		"log",
		...HISTORY_SELECTION,
		"--always",
		"--raw",
		"--numstat",
		"-z",
		"--no-abbrev",
		"--format=%x00commit %H%x00",
		oid(candidate),
		"--",
	]);
	return new TextEncoder().encode(text);
}

export interface HistoricalResult {
	version: HistoricalVersion;
	complete: boolean;
	pass: boolean;
}

/** Missing/duplicate exports or scans cannot turn a partial run into a passing scope. */
export function historicalCoverage(
	versions: HistoricalVersion[],
	results: HistoricalResult[],
): { complete: boolean; pass: boolean } {
	const incomplete = { complete: false, pass: false };
	if (results.length !== versions.length) return incomplete;
	const seen = new Set<string>();
	for (const [index, version] of versions.entries()) {
		const key = JSON.stringify([version.file, version.blob]);
		const result = results[index];
		if (
			seen.has(key) ||
			version.commits.length === 0 ||
			JSON.stringify(result.version) !== JSON.stringify(version) ||
			!result.complete
		) {
			return incomplete;
		}
		seen.add(key);
	}
	return { complete: true, pass: results.every(result => result.pass) };
}

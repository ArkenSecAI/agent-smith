import { createRequire } from "node:module";
import * as path from "node:path";
import { compileCodingAgent } from "../packages/coding-agent/scripts/compile-binary";
import { assertRuntime, ROOT } from "./agent-smith-common";

// Invoked by the build coordinator only, with a synthetic HOME and clean env.
assertRuntime();
const outfile = process.argv[2];
if (!outfile || !path.isAbsolute(outfile)) throw new Error("Expected an absolute compile output path");
const manifest: unknown = createRequire(import.meta.url)("@huggingface/transformers/package.json");
if (
	typeof manifest !== "object" ||
	manifest === null ||
	!("version" in manifest) ||
	typeof manifest.version !== "string"
) {
	throw new Error("Installed worker dependency has no concrete version; run smith:prepare");
}
await compileCodingAgent({
	repoRoot: ROOT,
	entrypoint: path.join(ROOT, "packages/coding-agent/src/cli.ts"),
	outfile,
	transformersVersion: manifest.version,
	// Reuse the explicitly provisioned Bun 1.4.2; no cross-runtime download.
	executablePath: process.execPath,
	minifyIdentifiers: true,
	skipBuiltinCodesign: process.platform === "darwin",
});

import { spyOn } from "bun:test";
import * as fs from "node:fs";
import * as path from "node:path";

// Preloaded only in the synthetic daemon subprocess. Record attempts even when
// a reader catches its own error, so "no suggestion" cannot hide a foreign read.
const auditPath = process.env.SMITH_PREDICT_READ_AUDIT;
const home = process.env.HOME;
if (!auditPath || !home) throw new Error("Synthetic predictor read audit environment required");
const foreignFiles = new Set([path.join(home, ".claude", "history.jsonl"), path.join(home, ".codex", "history.jsonl")]);
const attempts: string[] = [];
const originalFile = Bun.file;
spyOn(Bun, "file").mockImplementation(
	(filePath: string | URL | number | ArrayBufferLike | Uint8Array<ArrayBuffer>, options) => {
		if (typeof filePath === "string" && foreignFiles.has(path.resolve(filePath))) attempts.push(filePath);
		if (typeof filePath === "number") return originalFile(filePath, options);
		if (typeof filePath === "string" || filePath instanceof URL) return originalFile(filePath, options);
		return originalFile(filePath, options);
	},
);
// The process exit callback is synchronous; no state escapes this subprocess.
process.on("exit", () => fs.writeFileSync(auditPath, JSON.stringify(attempts)));

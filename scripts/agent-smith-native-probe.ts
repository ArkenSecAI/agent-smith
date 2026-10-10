import { createRequire } from "node:module";
import { bindingsReleaseVersion } from "../packages/natives/native/version-sentinel.js";
import { NATIVE_VERSION } from "./agent-smith-common";

// Direct dlopen of the exact produced file: the workspace loader deliberately
// skips its version check and can otherwise hide a stale/missing addon.
const filename = process.argv[2];
if (!filename) throw new Error("Expected the absolute addon path");
const bindings: Record<string, unknown> = createRequire(import.meta.url)(filename);
if (bindingsReleaseVersion(bindings) !== NATIVE_VERSION) throw new Error("Native release identity mismatch");
if (typeof bindings.visibleWidth !== "function" || typeof bindings.hasMatch !== "function") {
	throw new Error("Native text/search ABI exports missing");
}
if (bindings.visibleWidth("a界", 4) !== 3) throw new Error("Native Unicode width contract failed");
if (bindings.hasMatch("alpha\nbeta", "^beta$", false, true) !== true || bindings.hasMatch("alpha", "beta") !== false) {
	throw new Error("Native positive/negative regex search contract failed");
}
console.log(`Native release ${NATIVE_VERSION}: Unicode width and regex search verified`);

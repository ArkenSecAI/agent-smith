import { createHash } from "node:crypto";

// Independent of loader-state.js: the embed/reset script must remain usable
// when a previously generated manifest points at an archive that is missing.
const SHA256 = /^[a-f0-9]{64}$/;

export function validateEmbeddedAddonFiles(files) {
	if (!Array.isArray(files) || files.length === 0) throw new Error("Missing embedded addon files");
	const names = new Set();
	for (const file of files) {
		if (
			!file ||
			typeof file.filename !== "string" ||
			!/^pi_natives\.[a-z0-9-]+\.node$/.test(file.filename) ||
			names.has(file.filename) ||
			!["modern", "baseline", "default"].includes(file.variant) ||
			!Number.isSafeInteger(file.size) ||
			file.size <= 0 ||
			typeof file.sha256 !== "string" ||
			file.sha256.length !== 64 ||
			!SHA256.test(file.sha256)
		) {
			throw new Error("Invalid embedded addon file identity");
		}
		names.add(file.filename);
	}
}

/** Hash the canonical manifest identity, independent of archive compression and host paths. */
export function getEmbeddedAddonArtifactId({ platformTag, version, files }) {
	if (
		typeof platformTag !== "string" ||
		!/^(linux|darwin|win32)-(x64|arm64)$/.test(platformTag) ||
		typeof version !== "string" ||
		!/^\d+\.\d+\.\d+$/.test(version)
	) {
		throw new Error("Invalid embedded addon platform or version");
	}
	validateEmbeddedAddonFiles(files);
	for (const file of files) {
		const suffix = file.variant === "default" ? "" : `-${file.variant}`;
		if (
			file.filename !== `pi_natives.${platformTag}${suffix}.node` ||
			(!platformTag.endsWith("-x64") && file.variant !== "default")
		) {
			throw new Error(`Embedded addon variant does not match its platform: ${file.filename}`);
		}
	}
	const entries = [...files]
		.sort((a, b) => (a.filename < b.filename ? -1 : a.filename > b.filename ? 1 : 0))
		.map(file => [file.filename, file.variant, file.size, file.sha256]);
	return createHash("sha256")
		.update(JSON.stringify(["pi-natives-embedded-v1", platformTag, version, entries]))
		.digest("hex");
}

export function validateEmbeddedAddon(addon) {
	if (!addon || addon.artifactId !== getEmbeddedAddonArtifactId(addon)) {
		throw new Error("Missing or inconsistent embedded addon artifact identity");
	}
	if (
		!addon.archive ||
		addon.archive.format !== "tar.gz" ||
		addon.archive.filename !== `embedded-addons.${addon.platformTag}.tar.gz` ||
		typeof addon.archive.filePath !== "string" ||
		addon.archive.filePath.length === 0
	) {
		throw new Error("Invalid embedded addon archive metadata");
	}
}

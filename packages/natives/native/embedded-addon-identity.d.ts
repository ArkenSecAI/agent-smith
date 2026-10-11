export interface EmbeddedAddonFile {
	variant: "modern" | "baseline" | "default";
	filename: string;
	size: number;
	/** Lowercase SHA-256 of the exact addon bytes stored in the archive. */
	sha256: string;
}

export interface EmbeddedAddonArchive {
	format: "tar.gz";
	filename: string;
	filePath: string;
}

export interface EmbeddedAddonIdentity {
	platformTag: string;
	version: string;
	files: EmbeddedAddonFile[];
}

export interface EmbeddedAddon extends EmbeddedAddonIdentity {
	/** SHA-256 of the canonical platform, version and sorted file identities. */
	artifactId: string;
	archive: EmbeddedAddonArchive;
}

export function validateEmbeddedAddonFiles(files: EmbeddedAddonFile[]): void;
export function getEmbeddedAddonArtifactId(addon: EmbeddedAddonIdentity): string;
export function validateEmbeddedAddon(addon: EmbeddedAddon): void;

import type { EmbeddedAddon, EmbeddedAddonFile } from "./embedded-addon-identity.js";
export * from "./embedded-addon-identity.js";

/** App-owned, profile-independent native extraction/staging directory. */
export function getNativesDir(): string;

export interface DetectCompiledBinaryInput {
	embeddedAddon: EmbeddedAddon | null | undefined;
	env: Record<string, string | undefined>;
	importMetaUrl: string | null | undefined;
}

export function detectCompiledBinary(input: DetectCompiledBinaryInput): boolean;


export interface GetAddonFilenamesInput {
	tag: string;
	arch: string;
	variant: "modern" | "baseline" | null | undefined;
}

export function getAddonFilenames(input: GetAddonFilenamesInput): string[];

export interface ShouldStageNodeModulesAddonInput {
	platform: NodeJS.Platform | string;
	isCompiledBinary: boolean;
	nativeDir: string;
}

export function shouldStageNodeModulesAddon(input: ShouldStageNodeModulesAddonInput): boolean;

export interface ResolveLoaderCandidatesInput {
	addonFilenames: string[];
	isCompiledBinary: boolean;
	stageFromNodeModules?: boolean;
	nativeDir: string;
	leafPackageDir?: string | null;
	execDir: string;
	versionedDir: string;
	userDataDir: string;
}

export function resolveLoaderCandidates(input: ResolveLoaderCandidatesInput): string[];

export interface InitLoaderContextOverrides {
	nativeDir?: string;
	platform?: NodeJS.Platform | string;
	isCompiledBinary?: boolean;
	leafPackageDir?: string | null;
	embeddedAddon?: EmbeddedAddon | null;
}

export interface NativeLoaderContext {
	platformTag: string;
	packageVersion: string;
	nativeDir: string;
	leafPackageDir: string | null;
	versionedDir: string;
	isCompiledBinary: boolean;
	embeddedAddon: EmbeddedAddon | null;
	stageFromNodeModules: boolean;
	selectedVariant: "modern" | "baseline" | null;
	addonFilenames: string[];
	addonLabel: string;
	candidates: string[];
	isWorkspaceLoad: boolean;
	nativesDir: string;
}

export function initLoaderContext(overrides?: InitLoaderContextOverrides): NativeLoaderContext;

export interface CleanupStaleNativeVersionsInput {
	nativesDir: string;
	currentVersion: string;
}

export function cleanupStaleNativeVersions(input: CleanupStaleNativeVersionsInput): string[];

export function prepareNativeVersionDir(versionedDir: string): void;

export interface ExtractEmbeddedAddonArchiveInput {
	archivePath: string;
	files: EmbeddedAddonFile[];
	targetDir: string;
}

export function extractEmbeddedAddonArchive(input: ExtractEmbeddedAddonArchiveInput): string[];

export interface PrepareEmbeddedAddonCandidateInput {
	addon: EmbeddedAddon;
	candidate: string;
	nativesDir: string;
}

/** Verify bytes and return an artifact-specific path safe for compiled dlopen. */
export function prepareEmbeddedAddonCandidate(input: PrepareEmbeddedAddonCandidateInput): string;

export interface SelectCpuVariantInput {
	arch: string;
	override: "modern" | "baseline" | null | undefined;
	env: Record<string, string | undefined>;
	detectAvx2: () => boolean;
}

export interface SelectCpuVariantResult {
	variant: "modern" | "baseline" | null;
	source: "non-x64" | "override" | "cache" | "detect";
	cacheEnvKey?: string;
	cacheEnvValue?: string;
}

export function selectCpuVariant(input: SelectCpuVariantInput): SelectCpuVariantResult;

export interface ValidateLoadedBindingsContext {
	isWorkspaceLoad: boolean;
	packageVersion: string;
}

export function validateLoadedBindings(
	ctx: ValidateLoadedBindingsContext,
	bindings: Record<string, unknown>,
	candidate: string,
): void;

/** Identity of the addon `loadNative()` returned, for missing-export diagnostics. */
export interface NativeAddonStatus {
	/** Absolute path of the loaded `.node`. */
	path: string;
	/** Release the loaded addon reports (post-link stamp or legacy sentinel), or `null` when unidentified. */
	version: string | null;
	/** `package.json#version` of the loader that loaded it. */
	packageVersion: string;
	/** True when the addon carries a different release than this package. */
	stale: boolean;
}

/** The addon behind this process's exports; `null` before a successful load. */
export function nativeAddonStatus(): NativeAddonStatus | null;

/**
 * Stub for an export the addon does not provide: `undefined` on a current
 * addon, a throwing function on a stale one.
 */
export function missingNativeExport(
	symbolName: string,
	addon?: NativeAddonStatus | null,
): (() => never) | undefined;

/** Actionable text for {@link missingNativeExport}. */
export function missingNativeExportMessage(symbolName: string, addon?: NativeAddonStatus | null): string;

export function loadNative(): Record<string, unknown>;

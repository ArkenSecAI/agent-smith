import { afterEach, beforeEach, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";

let home: string;

beforeEach(async () => {
	home = await fs.mkdtemp(path.join(os.tmpdir(), "agent-smith-credentials-"));
	await Bun.write(
		path.join(home, ".aws/credentials"),
		"[default]\naws_access_key_id=synthetic-id\naws_secret_access_key=synthetic-secret\n",
	);
	await Bun.write(
		path.join(home, ".config/gcloud/application_default_credentials.json"),
		JSON.stringify({
			type: "authorized_user",
			client_id: "synthetic-client",
			refresh_token: "synthetic-refresh",
		}),
	);
});

afterEach(async () => {
	await fs.rm(home, { recursive: true, force: true });
});

async function probe(
	overrides: Record<string, string> = {},
): Promise<{ aws: boolean; vertex: boolean; openai: boolean }> {
	const child = Bun.spawn(
		[process.execPath, "--no-env-file", path.join(import.meta.dir, "fixtures/agent-smith-credentials.ts")],
		{
			cwd: home,
			env: {
				HOME: home,
				USERPROFILE: home,
				PATH: process.env.PATH ?? "",
				SystemRoot: process.env.SystemRoot ?? "",
				GOOGLE_CLOUD_PROJECT: "synthetic-project",
				GOOGLE_CLOUD_LOCATION: "synthetic-location",
				...overrides,
			},
			stdout: "pipe",
			stderr: "pipe",
		},
	);
	const [out, err, code] = await Promise.all([
		new Response(child.stdout).text(),
		new Response(child.stderr).text(),
		child.exited,
	]);
	expect(code, err).toBe(0);
	return JSON.parse(out);
}

test("signed-in cloud account homes do not authenticate the fresh application", async () => {
	expect(await probe()).toEqual({ aws: false, vertex: false, openai: false });
});

test("deliberately selected credential sources and generic API-key env remain usable", async () => {
	expect(
		await probe({
			AWS_PROFILE: "default",
			GOOGLE_APPLICATION_CREDENTIALS: path.join(home, ".config/gcloud/application_default_credentials.json"),
			OPENAI_API_KEY: "synthetic-explicit-key",
		}),
	).toEqual({ aws: true, vertex: true, openai: true });
});

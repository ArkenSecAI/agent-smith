import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { createHash } from "node:crypto";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { directoryPins } from "../src/workspace/project";

const firmware = Buffer.from([0x51, 0x45, 0x4d, 0x55, 0, 0xff]);
const digest = createHash("sha256").update(firmware).digest("hex");

describe.skipIf(process.platform !== "linux")("runtime directory inventory", () => {
	let dir: string;
	let runtime: string;
	beforeEach(async () => {
		dir = await fs.mkdtemp(path.join(await fs.realpath("/tmp"), "smith-seal-"));
		runtime = path.join(dir, "runtime");
		await fs.mkdir(runtime, { mode: 0o700 });
	});
	afterEach(async () => {
		await fs.rm(dir, { recursive: true, force: true });
	});

	it("hashes real firmware basenames without interpreting punctuation or object keys", async () => {
		await fs.writeFile(path.join(runtime, "QEMU,VGA.bin"), firmware, { mode: 0o600 });
		await fs.writeFile(path.join(runtime, "__proto__"), "different firmware", { mode: 0o600 });
		const pins = await directoryPins(runtime);
		expect(pins["QEMU,VGA.bin"]).toBe(digest);
		expect(Object.getOwnPropertyDescriptor(pins, "__proto__")?.value).toBe(
			createHash("sha256").update("different firmware").digest("hex"),
		);
	});

	it("pins a confined relative symlink to a punctuation-bearing directory", async () => {
		await fs.mkdir(path.join(runtime, "firm,ware"), { mode: 0o700 });
		await fs.writeFile(path.join(runtime, "firm,ware", "bios.bin"), firmware, { mode: 0o600 });
		await fs.symlink("firm,ware/bios.bin", path.join(runtime, "boot.rom"));
		expect(await directoryPins(runtime)).toEqual({
			"boot.rom": `symlink:firm,ware/bios.bin:${digest}`,
			"firm,ware/bios.bin": digest,
		});
	});

	it("refuses a symlink escaping the inventory root before reading its target", async () => {
		await fs.writeFile(path.join(dir, "outside.bin"), firmware, { mode: 0 });
		await fs.symlink("../outside.bin", path.join(runtime, "escape.rom"));
		await expect(directoryPins(runtime)).rejects.toThrow();
	});

	it("refuses absolute symlinks even when the target is inside the root", async () => {
		const target = path.join(runtime, "bios.bin");
		await fs.writeFile(target, firmware, { mode: 0o600 });
		await fs.symlink(target, path.join(runtime, "absolute.rom"));
		await expect(directoryPins(runtime)).rejects.toThrow();
	});

	it("refuses group-writable members", async () => {
		const file = path.join(runtime, "bios.bin");
		await fs.writeFile(file, firmware, { mode: 0o600 });
		await fs.chmod(file, 0o664);
		await expect(directoryPins(runtime)).rejects.toThrow();
	});

	it("refuses hard-linked members", async () => {
		const file = path.join(runtime, "bios.bin");
		await fs.writeFile(file, firmware, { mode: 0o600 });
		await fs.link(file, path.join(runtime, "alias.bin"));
		await expect(directoryPins(runtime)).rejects.toThrow();
	});

	it("refuses special files without waiting for a writer", async () => {
		const result = Bun.spawnSync(["/usr/bin/mkfifo", path.join(runtime, "pipe")]);
		if (result.exitCode !== 0) throw new Error(result.stderr.toString());
		await expect(directoryPins(runtime)).rejects.toThrow();
	});

	it("keeps QEMU option-path restrictions on the directory itself", async () => {
		const commandPath = path.join(dir, "runtime,driver=unexpected");
		await fs.mkdir(commandPath, { mode: 0o700 });
		await expect(directoryPins(commandPath)).rejects.toThrow();
	});
});

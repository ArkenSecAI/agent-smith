import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as http from "node:http";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import { targetRelay } from "../src/workspace/broker";

describe.skipIf(process.platform === "win32")("workspace target TCP lifetime", () => {
	for (const halfClose of [false, true]) {
		it(`retains the complete response after target close with client write-half-close=${halfClose}`, async () => {
			const dir = await fs.mkdtemp(path.join(os.tmpdir(), "as-relay-"));
			await fs.mkdir(path.join(dir, "vm"), { mode: 0o700 });
			const body = Buffer.alloc(4 * 1024 * 1024, 0x61);
			body.write("end-of-response", body.length - 15);
			const accepted = Promise.withResolvers<void>();
			const server = http.createServer((_request, response) => {
				response.writeHead(200, { "Content-Length": body.length, Connection: "close" });
				response.end(body);
				accepted.resolve();
			});
			await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
			const address = server.address() as net.AddressInfo;
			const relay = await targetRelay(dir, address.port);
			const peer = net.createConnection({ path: path.join(dir, "vm", "target.sock") });
			try {
				const received = Promise.withResolvers<Buffer>();
				const chunks: Buffer[] = [];
				peer.on("data", chunk => chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk));
				peer.once("end", () => received.resolve(Buffer.concat(chunks)));
				peer.once("error", received.reject);
				peer.setTimeout(3000, () => peer.destroy(new Error("Response did not finish")));
				peer.pause();
				const request = "GET /response HTTP/1.1\r\nHost: owned-fixture\r\nConnection: close\r\n\r\n";
				if (halfClose) peer.end(request);
				else peer.write(request);
				await accepted.promise;
				// Exercise a real receiver that temporarily stops consuming data,
				// rather than assuming a small write has already reached its peer.
				await Bun.sleep(25);
				peer.resume();
				const bytes = await received.promise;
				const headers = bytes.indexOf("\r\n\r\n");
				expect(headers).toBeGreaterThan(0);
				expect(bytes.subarray(headers + 4).equals(body)).toBe(true);
			} finally {
				peer.destroy();
				relay.close();
				server.closeAllConnections();
				await new Promise<void>(resolve => server.close(() => resolve()));
				await fs.rm(dir, { recursive: true, force: true });
			}
		});
	}
});

import { request } from "node:http";
import { Readable } from "node:stream";
import type { FetchImpl } from "@oh-my-pi/pi-utils";
import { validateInferenceUrl } from "./project";

/** One loopback chat route; node:http neither uses environment proxies nor follows redirects. */
export function createInferenceFetch(baseUrl: string): FetchImpl {
	const endpoint = validateInferenceUrl(baseUrl);
	return (input, init) => {
		const requested = new URL(input instanceof Request ? input.url : String(input));
		if (
			requested.origin !== endpoint.origin ||
			requested.pathname !== "/v1/chat/completions" ||
			requested.search ||
			requested.hash ||
			requested.username ||
			requested.password ||
			init?.method !== "POST" ||
			typeof init.body !== "string"
		)
			throw new Error("Provider request escaped the explicit JSON chat endpoint");
		const body = init.body;
		return new Promise<Response>((resolve, reject) => {
			const outgoing = request(
				requested,
				{
					method: "POST",
					headers: Object.fromEntries(new Headers(init.headers)),
					agent: false,
					signal: init.signal ?? undefined,
				},
				incoming => {
					const headers = new Headers();
					for (const [key, value] of Object.entries(incoming.headers)) {
						if (Array.isArray(value)) for (const item of value) headers.append(key, item);
						else if (value !== undefined) headers.set(key, value);
					}
					const status = incoming.statusCode ?? 502;
					const noBody = status === 204 || status === 205 || status === 304;
					if (noBody) incoming.resume();
					resolve(
						new Response(noBody ? null : (Readable.toWeb(incoming) as ReadableStream<Uint8Array>), {
							status,
							headers,
						}),
					);
				},
			);
			outgoing.once("error", reject);
			outgoing.end(body);
		});
	};
}

import { Effort, NO_AUTH_SENTINEL, type SimpleStreamOptions } from "@oh-my-pi/pi-ai";
import { buildModel } from "@oh-my-pi/pi-catalog/build";
import type { WorkspaceExternalInference } from "./contracts";
import type { WorkspaceInference } from "./inference";
import { externalInferenceShape, object, validateInferenceUrl } from "./project";

/** Prepare a consumer only: no server/tunnel launch, discovery, health request or shutdown. */
export function startExternalInference(input: WorkspaceExternalInference, signal?: AbortSignal): WorkspaceInference {
	signal?.throwIfAborted();
	const config = externalInferenceShape(input);
	const baseUrl = validateInferenceUrl(config.baseUrl).href;
	// Cooperating application instances share one request permit per endpoint, not per project/model.
	const provider = `workspace-external-${Bun.SHA256.hash(baseUrl, "hex")}`;
	const lifetime = new AbortController();
	const requestSignal = AbortSignal.any([lifetime.signal, ...(signal ? [signal] : [])]);
	const thinkingLevel = {
		off: "off",
		low: Effort.Low,
		medium: Effort.Medium,
		xhigh: Effort.XHigh,
	} as const;
	const sampling = config.sampling;
	const generation = {
		temperature: sampling.temperature,
		top_k: sampling.topK,
		top_p: sampling.topP,
		min_p: sampling.minP,
		presence_penalty: sampling.presencePenalty,
		frequency_penalty: sampling.frequencyPenalty,
		repeat_penalty: sampling.repeatPenalty,
		seed: sampling.seed,
	};
	const generationEntries = Object.entries(generation);
	const model = buildModel({
		id: config.modelId,
		name: config.modelId,
		api: "openai-completions",
		provider,
		baseUrl,
		reasoning: true,
		thinking: {
			mode: "effort",
			efforts: [Effort.Low, Effort.Medium, Effort.XHigh],
			requiresEffort: false,
		},
		input: ["text"],
		supportsTools: true,
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
		contextWindow: config.contextTokens,
		maxTokens: 8192,
		compat: {
			wireModelIdMode: "raw",
			supportsStore: false,
			supportsDeveloperRole: false,
			supportsMultipleSystemMessages: false,
			maxTokensField: "max_tokens",
			supportsReasoningParams: true,
			supportsReasoningEffort: true,
			thinkingFormat: "qwen-chat-template",
			qwenTemplateReasoningEffort: true,
			qwenPreserveThinking: false,
			replayReasoningContent: true,
			reasoningContentField: "reasoning_content",
			reasoningDeltasMayBeCumulative: false,
			supportsNamedToolChoice: false,
			supportsStrictMode: false,
			toolStrictMode: "none",
			toolSchemaFlavor: "grammar",
			extraBody: { ...generation, parallel_tool_calls: false, cache_prompt: false },
		},
	});
	const streamOptions: SimpleStreamOptions = {
		temperature: sampling.temperature,
		reasoning: config.thinking === "off" ? undefined : thinkingLevel[config.thinking],
		disableReasoning: config.thinking === "off",
		cacheRetention: "none",
		maxInFlightRequests: { [provider]: 1 },
		// The investigation's existing 600s deadline remains the outer bound, including queue waits.
		streamFirstEventTimeoutMs: 600_000,
		streamIdleTimeoutMs: 600_000,
		onPayload(payload) {
			requestSignal.throwIfAborted();
			const body = object(payload);
			const thinking = object(body.chat_template_kwargs);
			if (
				body.model !== config.modelId ||
				body.stream !== true ||
				body.max_tokens !== model.maxTokens ||
				body.parallel_tool_calls !== false ||
				body.cache_prompt !== false ||
				body.enable_thinking !== undefined ||
				body.reasoning_effort !== undefined ||
				thinking.enable_thinking !== (config.thinking !== "off") ||
				thinking.reasoning_effort !== (config.thinking === "off" ? undefined : config.thinking)
			)
				throw new Error("External inference request changed outside its explicit profile");
			for (const [key, expected] of generationEntries)
				if (body[key] !== expected) throw new Error(`External inference changed sampling ${key}`);
			if (!Array.isArray(body.messages) || body.messages.length === 0)
				throw new Error("External inference requires its explicit system message");
			let systems = 0;
			for (let index = 0; index < body.messages.length; index++) {
				const message = object(body.messages[index]);
				if (message.role === "developer") throw new Error("External template does not accept developer messages");
				if (message.role === "system") {
					if (index !== 0) throw new Error("External system message must be first");
					systems++;
				}
			}
			if (systems !== 1) throw new Error("External template requires one system message");
		},
	};
	return {
		model,
		apiKey: NO_AUTH_SENTINEL,
		signal: requestSignal,
		thinkingLevel: thinkingLevel[config.thinking],
		streamOptions,
		async stop() {
			// Abort only this consumer's HTTP/stream activity; remote termination requires owner evidence.
			lifetime.abort(new Error("External inference consumer closed"));
		},
	};
}

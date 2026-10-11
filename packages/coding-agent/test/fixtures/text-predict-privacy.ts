import { spyOn } from "bun:test";
import * as path from "node:path";
import { TextPredictor } from "@oh-my-pi/pi-natives";
import * as launch from "../../src/launch/client";
import { closeTextPrediction, requestTextPrediction } from "../../src/predict/client";
import { TEXT_PREDICT_BROKER_SCOPE } from "../../src/predict/protocol";

// The parent supplies an isolated HOME and agent directory; no inherited account environment.
const agentDir = process.env.AGENT_SMITH_CODING_AGENT_DIR;
if (!agentDir) throw new Error("Synthetic agent directory required");

switch (process.argv[2]) {
	case "seed-legacy": {
		const stateDir = path.join(agentDir, "predict", "ngram");
		const predictor = new TextPredictor({ method: "ngram", stateDir });
		await predictor.ready();
		await predictor.observe(
			Array.from({ length: 120 }, () => ["please inspect zqclaudebloom", "please inspect zxcodexbloom"]).flat(),
		);
		await predictor.persist();
		await Bun.write(path.join(stateDir, "cursor.json"), JSON.stringify({ historyId: 100_000 }));
		process.stdout.write(
			JSON.stringify({
				claude: await predictor.complete("please inspect ", "zqclaude"),
				codex: await predictor.complete("please inspect ", "zxcodex"),
			}),
		);
		break;
	}
	case "client": {
		const runtimeDir = process.argv[3];
		if (!runtimeDir) throw new Error("Synthetic daemon runtime directory required");
		// Exercise the production client/socket handshake without starting a global broker.
		// Only the broker is substituted; completion traffic reaches the real test endpoint.
		const broker: launch.DaemonBrokerClient = {
			projectDir: runtimeDir,
			async request(operation) {
				if (operation.op === "ping") return { op: "ping", projectDir: runtimeDir };
				throw new Error("Test broker does not start or adopt replacement daemons");
			},
			onCompletion() {
				throw new Error("Unexpected broker subscription");
			},
			close() {},
		};
		const brokerSpy = spyOn(launch, "daemonClientForGlobal").mockResolvedValue(broker);
		try {
			try {
				const result = await requestTextPrediction("auto", "please inspect ", "zqsmith");
				process.stdout.write(JSON.stringify({ ok: true, ...result }));
			} catch {
				process.stdout.write(JSON.stringify({ ok: false }));
			}
		} finally {
			closeTextPrediction();
			brokerSpy.mockRestore();
		}
		break;
	}
	case "broker-client": {
		const broker = await launch.daemonClientForGlobal(TEXT_PREDICT_BROKER_SCOPE);
		try {
			const own = (await requestTextPrediction("ngram", "please inspect ", "zqsmith")).suggestion;
			const foreign = (await requestTextPrediction("ngram", "please inspect ", "zqclaude")).suggestion;
			process.stdout.write(JSON.stringify({ own, foreign }));
		} finally {
			closeTextPrediction();
			try {
				await broker.request({ op: "shutdown" });
			} finally {
				await launch.closeDaemonClients();
			}
		}
		break;
	}
	default:
		throw new Error("Unknown predictor privacy fixture operation");
}

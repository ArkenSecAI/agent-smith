import { spyOn } from "bun:test";
import * as path from "node:path";
import { TextPredictor } from "@oh-my-pi/pi-natives";
import * as launch from "../../src/launch/client";
import { closeTextPrediction, requestTextPrediction } from "../../src/predict/client";
import { TEXT_PREDICT_BROKER_SCOPE } from "../../src/predict/protocol";
import { getGlobalDaemonRuntimeDir } from "@oh-my-pi/pi-utils";
import { startDaemonBrokerFromEnvironment } from "../../src/launch/broker";
import { DAEMON_PROJECT_DIR_ENV, DAEMON_RUNTIME_DIR_ENV, DAEMON_IDLE_GRACE_ENV } from "../../src/launch/protocol";

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
	case "broker-host": {
		if (!process.send) throw new Error("Owned broker host requires parent IPC");
		const runtimeDir = getGlobalDaemonRuntimeDir(TEXT_PREDICT_BROKER_SCOPE);
		const control = await launch.createDaemonBrokerClient(runtimeDir, { runtimeDir, idleGraceMs: 5_000 });
		const shutdown = Promise.withResolvers<void>();
		process.on("message", message => {
			if (message === "shutdown") shutdown.resolve();
		});
		process.once("disconnect", () => shutdown.resolve());
		process.env[DAEMON_PROJECT_DIR_ENV] = runtimeDir;
		process.env[DAEMON_RUNTIME_DIR_ENV] = runtimeDir;
		process.env[DAEMON_IDLE_GRACE_ENV] = "5000";
		const listening = Promise.withResolvers<void>();
		let ready = false;
		const finished = startDaemonBrokerFromEnvironment({
			onListening: () => {
				ready = true;
				listening.resolve();
			},
		});
		try {
			await Promise.race([
				listening.promise,
				finished.then(() => {
					throw new Error("Owned global broker stopped before listening");
				}),
			]);
			await control.request({ op: "ping" });
			process.send("ready");
			await shutdown.promise;
		} finally {
			try {
				if (ready) {
					try {
						const listed = await control.request({ op: "list" });
						if (listed.op !== "list") throw new Error("Unexpected broker list response");
						for (const daemon of listed.daemons) {
							const stopped = await control.request({ op: "stop", name: daemon.name, timeoutMs: 2_000 });
							if (stopped.op !== "stop" || !["exited", "failed"].includes(stopped.daemon.state)) {
								throw new Error("Owned predictor did not terminate");
							}
						}
					} finally {
						await control.request({ op: "shutdown" });
					}
				}
			} finally {
				control.close();
				try {
					await finished;
				} finally {
					if (process.connected && process.disconnect) process.disconnect();
				}
			}
		}
		break;
	}
	case "broker-client": {
		try {
			const own = (await requestTextPrediction("ngram", "please inspect ", "zqsmith")).suggestion;
			const foreign = (await requestTextPrediction("ngram", "please inspect ", "zqclaude")).suggestion;
			process.stdout.write(JSON.stringify({ own, foreign }));
		} finally {
			closeTextPrediction();
			await launch.closeDaemonClients();
		}
		break;
	}
	default:
		throw new Error("Unknown predictor privacy fixture operation");
}

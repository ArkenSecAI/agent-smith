import { ENV_HOOKS } from "../../src/registry/hooks/env";
import { getEnvApiKey } from "../../src/stream";
import { hasConfiguredAwsProfile } from "../../src/utils/aws-profile";

process.stdout.write(
	JSON.stringify({
		aws: hasConfiguredAwsProfile(),
		vertex: !!ENV_HOOKS["google-vertex-adc"](),
		openai: getEnvApiKey("openai") === "synthetic-explicit-key",
	}),
);

import * as ptree from "@oh-my-pi/pi-utils/ptree";

// Only launched in the synthetic environment by agent-smith-smoke.ts. Importing
// ptree loads natives, so this must not be part of pre-install bootstrap helpers.
const command = process.argv.slice(2);
if (command.length === 0) throw new Error("Expected a CLI command");
const result = await ptree.exec(command, {
	cwd: process.cwd(),
	env: process.env,
	timeout: 180_000,
	detached: true,
	subreaper: true,
	stderr: "full",
	allowNonZero: true,
	allowAbort: true,
});
process.stdout.write(result.stdout);
process.stderr.write(result.stderr);
if (result.exitError) console.error(result.exitError.message);
process.exitCode = result.ok && !result.exitError ? 0 : result.exitCode || 1;

import { Command } from "@oh-my-pi/pi-utils/cli";
import { workspaceHelp } from "../cli/command-help";
import { runWorkspaceCli } from "../workspace/cli";

export default class Workspace extends Command {
	static description = workspaceHelp.description;
	static examples = workspaceHelp.examples;
	static strict = false;
	async run(): Promise<void> {
		await runWorkspaceCli(this.argv);
	}
}

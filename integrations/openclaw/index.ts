import { spawn } from "node:child_process";
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";

type FirewallConfig = {
  binary?: string;
  policy: string;
  workspace: string;
  dataDir?: string;
  timeoutMs?: number;
};

type FirewallDecision = {
  schema: "afw.decision/v1alpha1";
  decision: "allow" | "ask" | "deny";
  risk: "low" | "medium" | "high" | "critical";
  rule_id: string;
  reason: string;
  action_fingerprint?: string;
  policy_digest?: string;
};

const MAX_OUTPUT = 1024 * 1024;

function configFrom(event: unknown): FirewallConfig {
  const candidate = (event as { context?: { pluginConfig?: unknown } })?.context?.pluginConfig;
  if (!candidate || typeof candidate !== "object") {
    throw new Error("Agent Firewall plugin config is unavailable");
  }
  const config = candidate as Partial<FirewallConfig>;
  if (!config.policy || !config.workspace) {
    throw new Error("Agent Firewall requires absolute policy and workspace paths");
  }
  return config as FirewallConfig;
}

async function callFirewall(config: FirewallConfig, envelope: Record<string, unknown>): Promise<FirewallDecision | { recorded: boolean }> {
  const binary = config.binary || "agent-firewall";
  const args = ["hook", "--host", "openclaw", "--policy", config.policy];
  if (config.dataDir) {
    args.push("--data-dir", config.dataDir);
  }
  const timeoutMs = Math.min(Math.max(config.timeoutMs || 5000, 100), 15000);

  return new Promise((resolve, reject) => {
    const child = spawn(binary, args, { stdio: ["pipe", "pipe", "pipe"] });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let outputBytes = 0;
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("Agent Firewall hook timed out"));
    }, timeoutMs);

    child.stdout.on("data", (chunk: Buffer) => {
      outputBytes += chunk.length;
      if (outputBytes > MAX_OUTPUT) {
        child.kill("SIGKILL");
        reject(new Error("Agent Firewall output exceeded 1 MiB"));
        return;
      }
      stdout.push(chunk);
    });
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (code !== 0) {
        reject(new Error(`Agent Firewall exited ${String(code)}: ${Buffer.concat(stderr).toString("utf8").trim()}`));
        return;
      }
      try {
        resolve(JSON.parse(Buffer.concat(stdout).toString("utf8")));
      } catch {
        reject(new Error("Agent Firewall returned invalid JSON"));
      }
    });
    child.stdin.end(JSON.stringify(envelope));
  });
}

export default definePluginEntry({
  id: "agent-firewall",
  name: "Agent Firewall",
  description: "Local pre-execution policy, approval, and replayable evidence",
  register(api) {
    api.on(
      "before_tool_call",
      async (event, ctx) => {
        try {
          const config = configFrom(event);
          const decision = (await callFirewall(config, {
            event: "before_tool_call",
            cwd: config.workspace,
            toolName: event.toolName,
            params: event.params,
            runId: event.runId || ctx.runId,
          })) as FirewallDecision;
          if (decision.decision === "allow") {
            return;
          }
          if (decision.decision === "deny") {
            return { block: true, blockReason: decision.reason };
          }
          return {
            requireApproval: {
              title: `Agent Firewall: ${event.toolName}`,
              description: decision.reason,
              severity: decision.risk === "critical" ? "critical" : "warning",
              timeoutMs: 60_000,
              allowedDecisions: ["allow-once", "deny"],
              pluginId: "agent-firewall",
            },
          };
        } catch (error) {
          api.logger.error(`Agent Firewall failed closed: ${String(error)}`);
          return { block: true, blockReason: "Agent Firewall policy evaluation was unavailable." };
        }
      },
      { priority: 10_000, timeoutMs: 15_000 },
    );

    api.on("after_tool_call", async (event, ctx) => {
      try {
        const config = configFrom(event);
        await callFirewall(config, {
          event: "after_tool_call",
          cwd: config.workspace,
          toolName: event.toolName,
          params: event.params,
          tool_response: { success: !(event as { error?: unknown }).error },
          duration_ms: (event as { durationMs?: number }).durationMs || 0,
          runId: event.runId || ctx.runId,
        });
      } catch (error) {
        api.logger.warn(`Agent Firewall completion evidence failed: ${String(error)}`);
      }
    });
  },
});

import { spawn, spawnSync } from "node:child_process";
import path from "node:path";
import process from "node:process";

async function readRequest() {
  let text = "";
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) text += chunk;
  return JSON.parse(text);
}

function reply(value) {
  process.stdout.write(JSON.stringify(value));
}

function parseHealth(text) {
  const values = {};
  for (const token of String(text || "").trim().split(/\s+/)) {
    const index = token.indexOf("=");
    if (index > 0) values[token.slice(0, index)] = token.slice(index + 1);
  }
  return values;
}

function status(moduleDir) {
  const result = spawnSync("py", ["-3", "sopshelf.py", "--check"], {
    cwd: moduleDir,
    encoding: "utf8",
    windowsHide: true,
    timeout: 6000
  });
  const health = parseHealth(result.stdout);
  const ready = result.status === 0 && health.SOPS === "OK" && health.STORE === "OK" && health.AGE === "OK" && health.DECRYPT === "OK";
  const signals = [
    { id: "sops", label: "SOPS", value: health.SOPS || "N/A", detail: "binary and store integration" },
    { id: "age", label: "Age", value: health.AGE || "N/A", detail: "identity availability" },
    { id: "secrets", label: "Secrets", value: health.SECRETS || "N/A", detail: "encrypted entries" }
  ];
  return {
    ok: true,
    state: ready ? "READY" : "ATTENTION",
    detail: ready ? "Sopshelf health check passed" : "Sopshelf health check needs attention",
    updatedAt: new Date().toISOString(),
    signals,
    quickView: [],
    activity: []
  };
}

function openSopshelf(moduleDir) {
  const child = spawn(
    "pyw",
    ["-3", path.join(moduleDir, "sopshelf.py")],
    { cwd: moduleDir, detached: true, stdio: "ignore", windowsHide: false }
  );
  child.unref();
  return { ok: true, message: "Sopshelf launch requested" };
}

const request = await readRequest();
if (request.protocol !== "modora.adapter/v1" || request.moduleId !== "sopshelf") {
  reply({ ok: false, message: "Unsupported Modora request" });
} else if (request.action === "status") {
  reply(status(request.context.manifestDir));
} else if (request.action === "open") {
  reply(openSopshelf(request.context.manifestDir));
} else {
  reply({ ok: false, message: `Unsupported action: ${request.action}` });
}

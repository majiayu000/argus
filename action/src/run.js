"use strict";

const { spawn } = require("node:child_process");

function runBounded(executable, args, options = {}) {
  const timeoutMs = options.timeoutMs || 30_000;
  const stdoutLimit = options.stdoutLimit || 64 * 1024 * 1024;
  const stderrLimit = options.stderrLimit || 1024 * 1024;
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, { cwd: options.cwd, env: options.env || process.env, shell: false, windowsHide: true });
    const stdout = [];
    const stderr = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let settled = false;
    const finishError = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.kill("SIGKILL");
      reject(error);
    };
    const timer = setTimeout(() => finishError(new Error(`process timed out after ${timeoutMs} ms`)), timeoutMs);
    child.stdout.on("data", (chunk) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > stdoutLimit) finishError(new Error("process stdout exceeded limit"));
      else stdout.push(chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderrBytes += chunk.length;
      if (stderrBytes > stderrLimit) finishError(new Error("process stderr exceeded limit"));
      else stderr.push(chunk);
    });
    child.on("error", finishError);
    child.on("close", (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (signal || code === null) return reject(new Error(`process terminated by ${signal || "unknown signal"}`));
      const decode = (chunks, label) => {
        const bytes = Buffer.concat(chunks);
        const value = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
        if (value.includes("\u0000")) throw new Error(`${label} contains NUL`);
        return value;
      };
      try { resolve({ code, stdout: decode(stdout, "stdout"), stderr: decode(stderr, "stderr") }); }
      catch (error) { reject(error); }
    });
  });
}

module.exports = { runBounded };

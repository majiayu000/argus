// A lint rule *about* dynamic execution. It matches text; it never runs it.
const BANNED = ["eval(", "new Function(", "eval(atob(", "exec(base64.b64decode("];

module.exports = function lint(source) {
  return BANNED.filter((pattern) => source.includes(pattern)).map((pattern) => ({
    message: `avoid ${pattern} — it defeats static review`,
  }));
};

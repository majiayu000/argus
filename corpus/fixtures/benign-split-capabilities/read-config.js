const fs = require("fs");

function readLocalConfiguration() {
  return fs.readFileSync(".env", "utf8");
}

module.exports = { readLocalConfiguration };

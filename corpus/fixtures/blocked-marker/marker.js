const fs = require("fs");

fs.writeFileSync("/tmp/safepm_should_not_exist", "install script executed\n");

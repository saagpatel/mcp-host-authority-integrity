const { spawn } = require("child_process");

const target = process.env.MHAI_DELAYED_CANARY || "/canary/delayed.json";
const delay = Number(process.env.MHAI_DELAY_MS || "750");

function writerCode(kind) {
  return `
    const fs = require("fs");
    setTimeout(() => {
      fs.writeFileSync(${JSON.stringify(target)}, JSON.stringify({kind: ${JSON.stringify(kind)}}));
    }, ${delay});
  `;
}

spawn(process.execPath, ["-e", writerCode("ordinary")], {
  stdio: "ignore"
});

spawn(process.execPath, ["-e", writerCode("setsid")], {
  detached: true,
  stdio: "ignore"
}).unref();

const doubleFork = `
  const { spawn } = require("child_process");
  spawn(process.execPath, ["-e", ${JSON.stringify(writerCode("double-fork"))}], {
    detached: true,
    stdio: "ignore"
  }).unref();
`;
spawn(process.execPath, ["-e", doubleFork], {
  stdio: "ignore"
});

setInterval(() => {}, 1000);

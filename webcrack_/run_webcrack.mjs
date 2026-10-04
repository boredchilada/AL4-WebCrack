// Runs webcrack on one file. Called by webcrack_/service.py:
//   node run_webcrack.mjs <input.js> <output.js> <info.json> '<options json>'
// Writes the transformed code to <output.js> and {hasBundle, bundleType} to <info.json>.
// On failure prints {"name", "message"} as JSON on stderr and exits 1.
//
//   node run_webcrack.mjs --self-test     (used by the Dockerfile to prove webcrack runs)
import fs from "node:fs";
import { webcrack } from "/opt/webcrack/dist/index.js";

async function selfTest() {
  const result = await webcrack('const a = "\\x68\\x69"; console.log(a);', { mangle: false });
  if (!result.code.includes('"hi"')) {
    throw new Error(`unexpected self-test output: ${result.code}`);
  }
  console.log("webcrack self-test OK");
}

async function main([input, output, info, optionsJson]) {
  const options = JSON.parse(optionsJson);
  const result = await webcrack(fs.readFileSync(input, "utf8"), {
    jsx: true,
    unpack: Boolean(options.unpack),
    unminify: Boolean(options.unminify),
    deobfuscate: Boolean(options.deobfuscate),
    mangle: false,
  });
  fs.writeFileSync(output, result.code);
  fs.writeFileSync(info, JSON.stringify({
    hasBundle: Boolean(result.bundle),
    bundleType: result.bundle ? result.bundle.type : null,
  }));
}

const args = process.argv.slice(2);
try {
  if (args[0] === "--self-test") {
    await selfTest();
  } else {
    await main(args);
  }
} catch (error) {
  console.error(JSON.stringify({ name: error.name, message: error.message }));
  process.exit(1);
}

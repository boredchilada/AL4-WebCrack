// Runs webcrack on a list of JavaScript inputs in one Node process. Called by webcrack_/runner.py:
//   node run_webcrack.mjs <jobs.json> '<options json>'
// jobs.json is a list of {input, output, reprint, deobfuscated, info} paths. For each job it writes:
//   output        full webcrack result (deobfuscate + unminify + unpack, per options)
//   reprint       webcrack's reprint of the input with every transform off
//   deobfuscated  the deobfuscate step alone (only when options.deobfuscate is true)
//   info          {"ok": true, "bundleType": ...} or {"ok": false, "error": {"name", "message"}}
// A failing job records its error and the others still run.
//
//   node run_webcrack.mjs --self-test     (used by the Dockerfile to prove webcrack runs)
import fs from "node:fs";
import { webcrack } from "/opt/webcrack/dist/index.js";

const OFF = { jsx: false, unpack: false, unminify: false, deobfuscate: false, mangle: false };

async function selfTest() {
  const result = await webcrack('const a = "\\x68\\x69"; console.log(a);', { mangle: false });
  if (!result.code.includes('"hi"')) {
    throw new Error(`unexpected self-test output: ${result.code}`);
  }
  console.log("webcrack self-test OK");
}

async function runJob(job, options) {
  try {
    const source = fs.readFileSync(job.input, "utf8");
    const result = await webcrack(source, {
      jsx: true,
      unpack: Boolean(options.unpack),
      unminify: Boolean(options.unminify),
      deobfuscate: Boolean(options.deobfuscate),
      mangle: false,
    });
    fs.writeFileSync(job.output, result.code);
    fs.writeFileSync(job.reprint, (await webcrack(source, OFF)).code);
    if (options.deobfuscate) {
      fs.writeFileSync(job.deobfuscated, (await webcrack(source, { ...OFF, deobfuscate: true })).code);
    }
    fs.writeFileSync(job.info, JSON.stringify({ ok: true, bundleType: result.bundle ? result.bundle.type : null }));
  } catch (error) {
    fs.writeFileSync(job.info, JSON.stringify({ ok: false, error: { name: error.name, message: error.message } }));
  }
}

try {
  const [first, optionsJson] = process.argv.slice(2);
  if (first === "--self-test") {
    await selfTest();
  } else {
    const options = JSON.parse(optionsJson);
    for (const job of JSON.parse(fs.readFileSync(first, "utf8"))) {
      await runJob(job, options);
    }
  }
} catch (error) {
  console.error(JSON.stringify({ name: error.name, message: error.message }));
  process.exit(1);
}

// Build the Worker: injects site/dashboard.html into the Worker template as DASHBOARD_HTML.
// Usage: node tools/build.mjs <base-worker.mjs> <out-worker.mjs> <version>
import fs from "node:fs";
const [base, out, version] = process.argv.slice(2);
if (!base || !out || !version) { console.error("usage: build.mjs <base> <out> <version>"); process.exit(1); }
const lines = fs.readFileSync(base, "utf8").split("\n");
const i = lines.findIndex(l => l.startsWith("const DASHBOARD_HTML = "));
if (i < 0) throw new Error("DASHBOARD_HTML not found in base worker");
let html = fs.readFileSync(new URL("../site/dashboard.html", import.meta.url), "utf8");
html = html.replace(/v\d+\.\d+\.\d+(<\/div>)/, "v" + version + "$1");
lines[i] = "const DASHBOARD_HTML = " + JSON.stringify(html).replace(/<\//g, "<\\/") + ";";
let src = lines.join("\n").replace(/version: "\d+\.\d+\.\d+"/, 'version: "' + version + '"');
fs.writeFileSync(out, src);
console.log("built", out, src.length, "bytes");

// Usage: node tools/build-worker.mjs <base-worker.mjs> <site/dashboard.html> <out.mjs> <version>
// Replaces the embedded DASHBOARD_HTML string and the version string of a bundled worker.
import fs from 'fs';
const [base, html, out, version] = process.argv.slice(2);
const lines = fs.readFileSync(base, 'utf8').split('\n');
const i = lines.findIndex(l => l.startsWith('const DASHBOARD_HTML = '));
if (i < 0) throw new Error('DASHBOARD_HTML not found in ' + base);
// JSON.stringify output is a valid JS string literal; escape </ like the original bundle does.
lines[i] = 'const DASHBOARD_HTML = ' + JSON.stringify(fs.readFileSync(html, 'utf8')).replace(/<\//g, '<\\/') + ';';
let src = lines.join('\n').replace(/version: "[\d.]+"/, 'version: "' + version + '"');
fs.writeFileSync(out, src);
console.log('wrote', out, src.length, 'bytes');

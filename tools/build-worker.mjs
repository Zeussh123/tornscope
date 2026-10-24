// Rebuilds the Worker from the editable dashboard source.
//   node tools/build-worker.mjs <base-worker.mjs> <dashboard.html> <out.mjs> [oldVersion newVersion]
// The Worker keeps the dashboard as one escaped string (DASHBOARD_HTML); this swaps it for the
// contents of updates/src/dashboard.html so the page can be edited as a normal HTML file.
import fs from 'fs';
const [base, html, out, oldV, newV] = process.argv.slice(2);
const lines = fs.readFileSync(base, 'utf8').split('\n');
const i = lines.findIndex(l => l.startsWith('const DASHBOARD_HTML = '));
if (i < 0) throw new Error('DASHBOARD_HTML not found in ' + base);
lines[i] = 'const DASHBOARD_HTML = ' + JSON.stringify(fs.readFileSync(html, 'utf8')).replace(/<\//g, '<\\/') + ';';
let code = lines.join('\n');
if (oldV && newV) code = code.replace(`version: "${oldV}"`, `version: "${newV}"`);
fs.writeFileSync(out, code);
console.log('written', out, code.length, 'bytes');

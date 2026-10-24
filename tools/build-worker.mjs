// Re-embeds site/dashboard.html into the worker's DASHBOARD_HTML constant.
// Usage: node tools/build-worker.mjs worker3.25.2.mjs
import fs from 'node:fs';
const file = process.argv[2] || 'worker3.25.2.mjs';
const html = fs.readFileSync(new URL('../site/dashboard.html', import.meta.url), 'utf8');
const src = fs.readFileSync(file, 'utf8');
const re = /const DASHBOARD_HTML = ".*?";\n/s;
if (!re.test(src)) throw new Error('DASHBOARD_HTML not found in ' + file);
const lit = JSON.stringify(html).replace(/<\//g, '<\\/');
fs.writeFileSync(file, src.replace(re, () => 'const DASHBOARD_HTML = ' + lit + ';\n'));
console.log('embedded', html.length, 'chars into', file);

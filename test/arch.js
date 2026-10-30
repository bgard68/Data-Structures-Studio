// Architecture suite: static rules the fuzz suite cannot see. The model layer
// (every build file between core.js and app.js) must stay browser-free on all
// paths — run.js only proves the paths the fuzzer happens to execute — and the
// two hand-maintained file lists (build.mjs, test/run.js) must agree with src/
// and with each other, or CI quietly tests a different artifact than ships.
// Run: node test/arch.js
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const read = f => readFileSync(join(root, f), 'utf8').replace(/\r\n/g, '\n');

let pass = 0, fail = 0;
function ok(cond, msg) {
  if (cond) { pass++; return; }
  fail++;
  console.error('FAIL:', msg);
}

/* ---------- strip comments, strings and regex bodies, keep ${...} code ----------
   Newlines inside stripped regions are preserved so offsets still map to lines. */
function codeOnly(js) {
  let out = '', i = 0, prev = '';                 // prev = last significant char, for regex-vs-divide
  const tmpl = [];                                // brace depth per open `${` interpolation
  const keepNL = s => out += s.replace(/[^\n]/g, ' ');
  const reCanStart = () => prev === '' || '([{,;:=!&|?+-*/%<>^~'.includes(prev)
    || /(?:^|[^.$\w])(?:return|typeof|case|do|else|in|of|new|void|delete|instanceof|yield)\s*$/.test(out);
  while (i < js.length) {
    const c = js[i], d = js[i + 1];
    if (c === '/' && d === '/') { const j = js.indexOf('\n', i); i = j < 0 ? js.length : j; continue; }
    if (c === '/' && d === '*') { const j = js.indexOf('*/', i + 2); keepNL(js.slice(i, j < 0 ? js.length : j + 2)); i = j < 0 ? js.length : j + 2; continue; }
    if (c === "'" || c === '"') {
      let j = i + 1;
      while (j < js.length && js[j] !== c) j += js[j] === '\\' ? 2 : 1;
      keepNL(js.slice(i, j + 1)); prev = c; i = j + 1; continue;
    }
    if (c === '`') {                              // template: blank the text, recurse into ${ } as code
      let j = i + 1;
      while (j < js.length && js[j] !== '`') {
        if (js[j] === '\\') { j += 2; continue; }
        if (js[j] === '$' && js[j + 1] === '{') break;
        j++;
      }
      keepNL(js.slice(i, j));
      if (js[j] === '$') { out += '('; tmpl.push(0); prev = '('; i = j + 2; continue; }
      prev = '`'; i = j + 1; continue;
    }
    if (c === '/' && reCanStart()) {              // regex literal: blank it, honour [classes] and escapes
      let j = i + 1, cls = false;
      for (; j < js.length && (cls || js[j] !== '/'); j++) {
        if (js[j] === '\\') j++;
        else if (js[j] === '[') cls = true;
        else if (js[j] === ']') cls = false;
      }
      keepNL(js.slice(i, j + 1)); prev = '/'; i = j + 1; continue;
    }
    if (tmpl.length) {
      if (c === '{') tmpl[tmpl.length - 1]++;
      if (c === '}' && tmpl[tmpl.length - 1]-- === 0) {   // interpolation closed: back into template text
        tmpl.pop(); out += ')'; prev = ')';
        let j = i + 1;
        while (j < js.length && js[j] !== '`') {
          if (js[j] === '\\') { j += 2; continue; }
          if (js[j] === '$' && js[j + 1] === '{') break;
          j++;
        }
        keepNL(js.slice(i + 1, j));
        if (js[j] === '$') { out += '('; tmpl.push(0); prev = '('; i = j + 2; continue; }
        prev = '`'; i = j + 1; continue;
      }
    }
    out += c;
    if (!/\s/.test(c)) prev = c;
    i++;
  }
  return out;
}

/* ---------- rule: model files never touch the browser ----------
   Unambiguous browser globals plus timers: the model layer is a synchronous
   recorder, so anything scheduled or rendered belongs to core's player/renderer
   or to app.js. Node has fetch and setTimeout too, so run.js cannot catch these
   even on executed paths — only this scan does. */
const BROWSER = [
  'document', 'window', 'navigator', 'localStorage', 'sessionStorage',
  'alert', 'confirm', 'prompt', 'fetch', 'XMLHttpRequest', 'WebSocket',
  'requestAnimationFrame', 'cancelAnimationFrame', 'setTimeout', 'setInterval',
  'clearTimeout', 'clearInterval', 'getComputedStyle', 'matchMedia',
  'MutationObserver', 'ResizeObserver', 'IntersectionObserver', 'DOMParser',
  'HTMLElement', 'SVGElement', 'CustomEvent',
];
function browserRefs(code) {
  const hits = [];
  for (const name of BROWSER) {
    const re = new RegExp(`(^|[^.$\\w])${name}\\b`, 'g');   // bare global, not a property or longer name
    for (let m; (m = re.exec(code));) {
      hits.push(`${name} (line ${code.slice(0, m.index + m[1].length).split('\n').length})`);
    }
  }
  return hits;
}

// the scanner itself is tested, so a stripping bug cannot quietly blind the rule
ok(browserRefs(codeOnly('// document\nconst x = 1;')).length === 0, 'scanner ignores comments');
ok(browserRefs(codeOnly('const s = "window", t = `doc ${1} ument`;')).length === 0, 'scanner ignores string and template text');
ok(browserRefs(codeOnly('const re = /document/; a = b / c;')).length === 0, 'scanner ignores regex bodies and division');
ok(browserRefs(codeOnly('this.fetch(k); obj.document;')).length === 0, 'scanner ignores property names');
ok(browserRefs(codeOnly('document.title = 1;')).length === 1, 'scanner catches a bare global');
ok(browserRefs(codeOnly('label = `n is ${window.n}`;')).length === 1, 'scanner catches globals inside ${ }');

/* ---------- rule: the two file lists agree with src/ and each other ---------- */
function jsList(file) {
  const m = read(file).match(/\[\s*(?:'[^']*\.js'\s*,\s*)*'[^']*\.js'\s*,?\s*\]/);
  return m ? [...m[0].matchAll(/'([^']*\.js)'/g)].map(x => x[1]) : null;
}
const build = jsList('build.mjs');
const harness = jsList('test/run.js');
const disk = readdirSync(join(root, 'src')).filter(f => f.endsWith('.js')).sort();

ok(build !== null, 'build.mjs declares its source list as a literal array of .js names');
ok(harness !== null, 'test/run.js declares its harness list as a literal array of .js names');
if (build && harness) {
  ok(new Set(build).size === build.length, `build list has no duplicates: ${build}`);
  ok(build[0] === 'core.js', `core.js is concatenated first (classes extend Struct at load), got ${build[0]}`);
  ok(build.at(-1) === 'app.js', `app.js (the DOM layer) is concatenated last, got ${build.at(-1)}`);
  ok([...build].sort().join() === disk.join(),
    `build.mjs ships exactly what src/ holds — build [${[...build].sort()}] vs disk [${disk}]`);
  ok(harness.join() === build.slice(0, -1).join(),
    `test/run.js loads the build minus app.js, in build order — harness [${harness}] vs build [${build}]`);

  // model layer = everything between core.js (renderer/player, DOM by design) and app.js
  for (const f of build.slice(1, -1)) {
    const hits = browserRefs(codeOnly(read(join('src', f))));
    ok(hits.length === 0, `src/${f} is model-only but references the browser: ${hits.join(', ')}`);
  }
}

/* ---------- verdict ---------- */
console.log(`\n${pass} assertions passed, ${fail} failed`);
if (fail) process.exit(1);
console.log('OK — the layers still hold.');

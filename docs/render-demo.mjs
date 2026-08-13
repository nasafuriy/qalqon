/**
 * Regenerates the terminal screenshots used in the README.
 *
 *   go build -o qalqon ./cmd/qalqon
 *   node docs/render-demo.mjs
 *
 * It builds a small sample project, runs the real binary against it, converts
 * the ANSI output to HTML and screenshots that with headless Chrome. Nothing
 * in the images is typed by hand, so they cannot drift from what the tool
 * actually prints — rerun this whenever the output format changes.
 *
 * Node is only needed for this; the project itself has no JavaScript.
 */

import { writeFile, mkdir, rm, mkdtemp } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';

const docs = dirname(fileURLToPath(import.meta.url));
const repo = join(docs, '..');

const BINARY = ['qalqon', 'qalqon.exe'].map((n) => join(repo, n)).find(existsSync);
if (!BINARY) {
  console.error('Build the binary first: go build -o qalqon ./cmd/qalqon');
  process.exit(1);
}

const CHROME = [
  process.env.CHROME_PATH,
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/usr/bin/google-chrome',
  '/usr/bin/chromium'
].filter(Boolean).find(existsSync);

if (!CHROME) {
  console.log('No Chrome found — keeping the existing screenshots.');
  process.exit(0);
}

/* ------------------------------------------------------------ sample repo */

const sample = await mkdtemp(join(tmpdir(), 'qalqon-demo-'));
await mkdir(join(sample, '.github', 'workflows'), { recursive: true });

await writeFile(join(sample, 'Dockerfile'), `FROM node:latest

ENV NPM_TOKEN=npm_9f2a4c8e1b7d3a6f0c5e

COPY . /app
WORKDIR /app
RUN npm ci

CMD ["node", "server.js"]
`);

await writeFile(join(sample, 'docker-compose.yml'), `services:
  api:
    build: .
    ports:
      - "3000:3000"

  db:
    image: postgres:16
    privileged: true
    environment:
      POSTGRES_PASSWORD: devpassword
`);

await writeFile(join(sample, '.github', 'workflows', 'ci.yml'), `name: CI
on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "Building \${{ github.event.pull_request.title }}"
`);

const run = (args) =>
  spawnSync(BINARY, args, { cwd: sample, encoding: 'buffer', maxBuffer: 8 << 20 })
    .stdout.toString('utf8');

/* -------------------------------------------------------- ANSI conversion */

const COLORS = {
  31: '#ff6b6b', 32: '#5fd97e', 33: '#ffcc66',
  34: '#7aa2f7', 35: '#d580ff', 36: '#5fe3e0',
  37: '#c8d0e0', 97: '#ffffff'
};

const escapeHtml = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

function ansiToHtml(text) {
  let out = '';
  let open = false;
  let state = { bold: false, dim: false, color: null };

  const flush = () => {
    if (open) { out += '</span>'; open = false; }
    const styles = [];
    if (state.color) styles.push(`color:${state.color}`);
    if (state.bold) styles.push('font-weight:700');
    if (state.dim) styles.push('opacity:.62');
    if (styles.length) { out += `<span style="${styles.join(';')}">`; open = true; }
  };

  const parts = text.split(/\x1b\[([0-9;]*)m/);
  for (let i = 0; i < parts.length; i++) {
    if (i % 2 === 0) { out += escapeHtml(parts[i]); continue; }
    for (const code of parts[i].split(';').map(Number)) {
      if (code === 0) state = { bold: false, dim: false, color: null };
      else if (code === 1) state.bold = true;
      else if (code === 2) state.dim = true;
      else if (COLORS[code]) state.color = COLORS[code];
    }
    flush();
  }
  if (open) out += '</span>';
  return out;
}

/* -------------------------------------------------------------- rendering */

function page(title, prompt, body) {
  return `<!DOCTYPE html><meta charset="utf-8">
<style>
  :root { color-scheme: dark; }
  html, body { margin: 0; padding: 0; background: transparent; }
  .frame {
    width: 1020px; margin: 24px;
    background: #0d1117; border: 1px solid #2a3240; border-radius: 12px;
    overflow: hidden; box-shadow: 0 18px 50px rgba(0,0,0,.55);
    font-family: "Cascadia Mono", "Cascadia Code", Consolas, "JetBrains Mono", ui-monospace, monospace;
  }
  .bar {
    display: flex; align-items: center; gap: 8px;
    padding: 11px 14px; background: #161b22; border-bottom: 1px solid #2a3240;
  }
  .dot { width: 12px; height: 12px; border-radius: 50%; }
  .title { flex: 1; text-align: center; color: #6e7a8f; font-size: 12.5px; margin-right: 44px; }
  pre {
    margin: 0; padding: 18px 20px 20px; color: #c8d0e0;
    font-size: 13.5px; line-height: 1.62;
    white-space: pre-wrap; word-break: break-word;
  }
  .prompt { color: #5fd97e; font-weight: 700; }
  .cmd { color: #e6edf7; }
</style>
<div class="frame">
  <div class="bar">
    <span class="dot" style="background:#ff5f57"></span>
    <span class="dot" style="background:#febc2e"></span>
    <span class="dot" style="background:#28c840"></span>
    <span class="title">${title}</span>
  </div>
  <pre><span class="prompt">$</span> <span class="cmd">${prompt}</span>
${body}</pre>
</div>`;
}

async function chrome(args) {
  const profile = await mkdtemp(join(tmpdir(), 'qalqon-shot-'));
  const stdout = await new Promise((resolve, reject) => {
    const child = spawn(CHROME, [
      '--headless=new', '--disable-gpu', '--no-sandbox', '--no-first-run',
      '--hide-scrollbars', '--allow-file-access-from-files',
      '--default-background-color=00000000',
      `--user-data-dir=${profile}`, '--virtual-time-budget=4000',
      ...args
    ], { stdio: ['ignore', 'pipe', 'ignore'] });
    let out = '';
    child.stdout.on('data', (d) => { out += d; });
    child.on('close', () => resolve(out));
    child.on('error', reject);
  });
  await rm(profile, { recursive: true, force: true }).catch(() => {});
  return stdout;
}

// Wrapped output makes the height impossible to predict, so let the browser
// lay it out first and report what it produced.
async function shot(html, out) {
  const probe = join(tmpdir(), `qalqon-measure-${Date.now()}.html`);
  await writeFile(probe, html + `
<script>
  var f = document.querySelector('.frame').getBoundingClientRect();
  document.title = String(Math.ceil(f.height + 48));
</script>`, 'utf8');

  const dom = await chrome(['--window-size=1070,2400', '--dump-dom', `file:///${probe.replace(/\\/g, '/')}`]);
  const height = Number((/<title>(\d+)<\/title>/.exec(dom) || [])[1]) || 900;

  const file = join(tmpdir(), `qalqon-shot-${Date.now()}.html`);
  await writeFile(file, html, 'utf8');
  await chrome([
    '--force-device-scale-factor=2',
    `--window-size=1070,${height}`,
    `--screenshot=${out}`,
    `file:///${file.replace(/\\/g, '/')}`
  ]);

  await rm(probe, { force: true }).catch(() => {});
  await rm(file, { force: true }).catch(() => {});
  console.log(`rendered ${out} (1070x${height})`);
}

await shot(
  page('qalqon — scan', 'qalqon scan .', ansiToHtml(run(['scan', '.', '-color']))),
  join(docs, 'demo-scan.png')
);

const target = process.env.QALQON_DEMO_TARGET || 'https://nasafuriy.github.io/offline-devtools/';
await shot(
  page('qalqon — target', `qalqon target ${target}`, ansiToHtml(run(['target', target, '-color']))),
  join(docs, 'demo-target.png')
);

await rm(sample, { recursive: true, force: true }).catch(() => {});

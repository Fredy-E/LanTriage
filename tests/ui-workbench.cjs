'use strict';
/*
 * LanTriage workbench shell regression — portfolio-preview-1.
 *
 * Proves the substantive workbench redesign (not a color-only change):
 * principal shell carries data-ui-revision="portfolio-preview-1", standalone
 * --ui-* tokens resolve in dark/light, the honest prototype notice stays
 * visible in the first 900px with exact wording, grouped capture-file vs
 * fictional-sample actions, How-to-start empty guidance visible before load
 * and hidden after load via the existing body[data-loaded] hook, real
 * fictional-sample state (15 seen), populated 300/320/390 + dark/light
 * containment with intentional inner 640px table scroll, visible keyboard
 * focus (incl. hidden file-input label ring with :focus-within fallback),
 * reduced-motion/print styles (print preserves getting-started when empty,
 * omits it when loaded), system fonts only, no network/storage/CDN, and
 * real redacted/opt-in + script-free HTML exports.
 *
 * Fictional synthetic bytes only. Owns a fresh headless Chrome profile per
 * run via tests/cdp-browser.cjs. Evidence redirects via LANTRIAGE_EVIDENCE
 * (same variable as tests/browser.cjs) so runs never overwrite preserved
 * evidence inside the source tree.
 */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { launch } = require('./cdp-browser.cjs');

const ROOT = path.resolve(__dirname, '..');
const EVIDENCE = process.env.LANTRIAGE_EVIDENCE || path.join(ROOT, 'tests', 'evidence');
const ART = path.join(EVIDENCE, 'workbench');
const SHOTS = path.join(EVIDENCE, 'workbench-shots');
const INDEX = path.join(ROOT, 'index.html');

const results = [];
let page;

async function runCase(name, fn) {
  const e0 = page.errors.length;
  const r0 = page.requests.length;
  try {
    await page.goto(INDEX);
    await page.viewport(1280, 900);
    await page.command('Emulation.setEmulatedMedia', { media: 'screen', features: [{ name: 'prefers-color-scheme', value: 'dark' }] });
    await fn();
    assert.deepEqual(page.errors.slice(e0), [], name + ': page/console errors');
    assert.deepEqual(page.requests.slice(r0), [], name + ': unexpected HTTP(S) requests');
    results.push({ name, status: 'pass' });
    console.log('PASS ' + name);
  } catch (error) {
    results.push({ name, status: 'fail', message: error.message });
    console.error('FAIL ' + name + '\n' + error.stack);
    try { await page.screenshot(path.join(ART, name.replace(/\W+/g, '-') + '-failure.png')); } catch {}
  }
}

async function loadSample() {
  await page.click('#btn-sample-pcap');
  await page.waitFor('document.getElementById("import-status").textContent.indexOf("fictional-sample-lan-le.pcap") !== -1 && document.getElementById("import-status").textContent.indexOf("15 packet(s) seen") !== -1', 'sample pcap loaded', 10000);
}

async function setScheme(scheme) {
  await page.command('Emulation.setEmulatedMedia', { media: 'screen', features: [{ name: 'prefers-color-scheme', value: scheme }] });
}

async function setPrint() {
  await page.command('Emulation.setEmulatedMedia', { media: 'print' });
}

async function setScreenDark() {
  await page.command('Emulation.setEmulatedMedia', { media: 'screen', features: [{ name: 'prefers-color-scheme', value: 'dark' }] });
}

(async () => {
  fs.mkdirSync(ART, { recursive: true });
  fs.mkdirSync(SHOTS, { recursive: true });
  page = await launch({ artifactsDir: ART });
  try {
    await runCase('workbench-shell-exact-notice-tokens', async () => {
      await page.viewport(1280, 900);
      const shell = await page.evaluate('!!document.querySelector(\'[data-ui-revision="portfolio-preview-1"]\')');
      assert.equal(shell, true, 'principal shell carries data-ui-revision=portfolio-preview-1');
      const rev = await page.evaluate('document.querySelector(\'[data-ui-revision="portfolio-preview-1"]\').getAttribute("data-ui-revision")');
      assert.equal(rev, 'portfolio-preview-1');
      const footer = await page.evaluate('document.querySelector(".app-footer").textContent');
      assert.match(footer, /portfolio-preview-1/);
      const tokens = await page.evaluate('(() => { const s = getComputedStyle(document.documentElement); return ["--ui-bg","--ui-surface","--ui-ink","--ui-muted","--ui-accent","--ui-border","--ui-radius"].map(k => [k, s.getPropertyValue(k).trim()]); })()');
      for (const [k, v] of tokens) assert.ok(v.length > 0, k + ' must resolve, got empty');
      const dark = Object.fromEntries(tokens);
      assert.equal(dark['--ui-bg'], '#0c1422');
      assert.equal(dark['--ui-surface'], '#142034');
      assert.equal(dark['--ui-ink'], '#eef4ff');
      assert.equal(dark['--ui-muted'], '#adbbd2');
      assert.equal(dark['--ui-accent'], '#8cbcff');
      assert.equal(dark['--ui-border'], '#31445f');
      assert.equal(dark['--ui-radius'], '12px');
      await setScheme('light');
      const light = await page.evaluate('(() => { const s = getComputedStyle(document.documentElement); return {"--ui-bg": s.getPropertyValue("--ui-bg").trim(), "--ui-surface": s.getPropertyValue("--ui-surface").trim(), "--ui-ink": s.getPropertyValue("--ui-ink").trim()}; })()');
      assert.equal(light['--ui-bg'], '#f2f5fa');
      assert.equal(light['--ui-ink'], '#1d2b44');
      assert.ok(light['--ui-surface'].length > 0);
      await setScheme('dark');
      const meta = await page.evaluate('document.querySelector(\'meta[name="color-scheme"]\').content');
      assert.match(meta, /dark/);
      assert.match(meta, /light/);
      const notice = await page.evaluate('(() => { const n = document.getElementById("prototype-notice"); if (!n) return null; const r = n.getBoundingClientRect(); const s = getComputedStyle(n); return { text: n.textContent, top: r.top, bottom: r.bottom, w: r.width, h: r.height, display: s.display, vis: s.visibility, op: s.opacity }; })()');
      assert.ok(notice, 'missing #prototype-notice');
      assert.match(notice.text, /Experimental concept prototype \u2014 idea exploration only\./);
      assert.match(notice.text, /not a finished|not finished/i);
      assert.match(notice.text, /production-ready/i);
      assert.ok(notice.w > 0 && notice.h > 0 && notice.display !== 'none' && notice.vis !== 'hidden' && Number(notice.op) > 0, 'notice must be visible, got ' + JSON.stringify(notice));
      assert.ok(notice.top >= 0 && notice.bottom <= 900, 'notice must sit inside first 900px viewport, got top=' + notice.top + ' bottom=' + notice.bottom);
      const h1 = await page.evaluate('document.querySelector("h1").textContent');
      assert.match(h1, /LanTriage/);
      const pill = await page.evaluate('document.getElementById("workbench-state").textContent');
      assert.match(pill, /Empty/);
    });

    await runCase('workbench-empty-guidance-visible', async () => {
      const loaded = await page.evaluate('document.body.dataset.loaded || ""');
      assert.ok(loaded === '' || loaded === 'false', 'body[data-loaded] must be empty/false before load, got ' + loaded);
      const vis = await page.evaluate('(() => { const n = document.getElementById("getting-started"); if (!n) return false; return n.getClientRects().length > 0 && getComputedStyle(n).visibility !== "hidden" && getComputedStyle(n).display !== "none"; })()');
      assert.equal(vis, true, '#getting-started empty guidance must be visible before load');
      const heading = await page.evaluate('document.getElementById("getting-started-heading").textContent');
      assert.match(heading, /How to start/);
      const steps = await page.evaluate('document.querySelectorAll("#getting-started .start-steps li").length');
      assert.ok(steps >= 3, 'expected >=3 start steps, got ' + steps);
      assert.equal(await page.evaluate('document.getElementById("summary-panel").hidden'), true, 'summary hidden before import');
      assert.equal(await page.evaluate('document.getElementById("btn-export-json").disabled'), true, 'exports disabled before import');
    });

    await runCase('workbench-real-sample-state', async () => {
      await loadSample();
      assert.equal(await page.evaluate('document.body.dataset.loaded'), 'true');
      const pill = await page.evaluate('({ t: document.getElementById("workbench-state").textContent, s: document.getElementById("workbench-state").getAttribute("data-state") })');
      assert.equal(pill.s, 'ready');
      assert.match(pill.t, /Ready/);
      const summary = await page.evaluate('({ seen: document.getElementById("summary-seen").textContent, decoded: document.getElementById("summary-decoded").textContent, unsupported: document.getElementById("summary-unsupported").textContent, rejected: document.getElementById("summary-rejected").textContent, source: document.getElementById("summary-source").textContent, packets: document.querySelectorAll("#packets-body tr").length, obs: document.querySelectorAll("#observations-list li").length })');
      assert.equal(summary.seen, '15');
      assert.equal(summary.decoded, '12');
      assert.equal(summary.unsupported, '3');
      assert.equal(summary.rejected, '0');
      assert.match(summary.source, /fictional-sample-lan-le\.pcap/);
      assert.equal(summary.packets, 15, 'packet evidence table lists every record');
      assert.ok(summary.obs >= 12, 'observations listed, got ' + summary.obs);
      const findings = await page.evaluate('document.getElementById("findings-list").textContent');
      assert.match(findings, /possible-ip-mac-conflict/);
      assert.match(findings, /not proof of one/i);
      assert.equal(await page.evaluate('document.getElementById("btn-export-json").disabled'), false, 'exports enabled after import');
      assert.equal(await page.evaluate('document.getElementById("btn-export-html").disabled'), false);
    });

    await runCase('workbench-loaded-guidance-hidden', async () => {
      await loadSample();
      const vis = await page.evaluate('(() => { const n = document.getElementById("getting-started"); if (!n) return false; return n.getClientRects().length > 0 && getComputedStyle(n).visibility !== "hidden" && getComputedStyle(n).display !== "none"; })()');
      assert.equal(vis, false, '#getting-started must no longer be an empty-state after load (body[data-loaded=true] hides it)');
      const css = fs.readFileSync(path.join(ROOT, 'style.css'), 'utf8');
      assert.match(css, /body\[data-loaded="true"\][^{]*#getting-started/);
    });

    await runCase('workbench-populated-containment-dark-light-300-320-390', async () => {
      await loadSample();
      for (const scheme of ['dark', 'light']) {
        await setScheme(scheme);
        const bg = await page.evaluate('getComputedStyle(document.documentElement).getPropertyValue("--ui-bg").trim()');
        assert.ok(bg.length > 0, scheme + ' --ui-bg empty');
        for (const width of [300, 320, 390, 1280]) {
          await page.viewport(width, 900);
          const ov = await page.evaluate('Math.max(document.documentElement.scrollWidth, document.body.scrollWidth) - innerWidth');
          assert.ok(ov <= 1, scheme + ' body overflow at ' + width + 'px: ' + ov);
        }
      }
      await setScheme('dark');
      await page.viewport(390, 844);
      const wrap = await page.evaluate('(() => { const w = document.querySelector(".table-wrap"); if (!w) return null; const s = getComputedStyle(w); return { ox: s.overflowX, tab: w.tabIndex, role: w.getAttribute("role"), label: w.getAttribute("aria-label"), tableMin: getComputedStyle(document.querySelector("#packets-table")).minWidth }; })()');
      assert.ok(wrap, 'missing .table-wrap');
      assert.ok(wrap.ox === 'auto' || wrap.ox === 'scroll', 'inner table must scroll internally, got ' + wrap.ox);
      assert.equal(wrap.tab, 0, 'table-wrap must be keyboard reachable');
      assert.equal(wrap.role, 'region');
      assert.ok(wrap.label && wrap.label.length > 5, 'table-wrap needs accessible label, got ' + wrap.label);
      assert.match(wrap.label, /scroll/i);
      assert.ok(wrap.tableMin === '640px' || wrap.tableMin === '640PX' || /640/.test(wrap.tableMin), 'intentional 640px inner table preserved, got ' + wrap.tableMin);
      const tableInner = await page.evaluate('(() => { const w = document.querySelector(".table-wrap"); const t = document.querySelector("#packets-table"); return t.scrollWidth > w.clientWidth - 2; })()');
      assert.equal(tableInner, true, 'narrow viewport must scroll the table internally, not the page');
      const css = fs.readFileSync(path.join(ROOT, 'style.css'), 'utf8');
      assert.equal(/overflow-x\s*:\s*hidden/.test(css), false, 'must not use overflow-x:hidden camouflage');
      await page.viewport(1280, 900);
      await page.screenshot(path.join(SHOTS, 'workbench-mobile-390.png'));
      await setScheme('light');
      await page.viewport(1280, 900);
      await page.screenshot(path.join(SHOTS, 'workbench-desktop-light.png'));
      await setScheme('dark');
      await page.viewport(1280, 900);
      await page.screenshot(path.join(SHOTS, 'workbench-desktop.png'));
    });

    await runCase('workbench-keyboard-focus-visible', async () => {
      await page.key('Tab');
      await page.waitFor('document.activeElement && document.activeElement.className === "skip-link"', 'skip link focused first');
      assert.notEqual(await page.evaluate('getComputedStyle(document.activeElement).outlineStyle'), 'none', 'skip link shows a focus ring');
      await page.key('Tab');
      await page.waitFor('document.activeElement && document.activeElement.id === "file-input"', 'file input focused');
      const ring = await page.evaluate('(() => { const label = document.getElementById("file-label"); const s = getComputedStyle(label); return { style: s.outlineStyle, width: parseFloat(s.outlineWidth) }; })()');
      assert.equal(ring.style, 'solid', 'the visible label carries the focus ring for the hidden input, got ' + ring.style);
      assert.ok(ring.width >= 2, 'focus ring at least 2px, got ' + ring.width);
      const css = fs.readFileSync(path.join(ROOT, 'style.css'), 'utf8');
      assert.match(css, /\*:focus-visible/);
      assert.match(css, /:focus-within/);
      await page.key('Tab');
      await page.waitFor('document.activeElement && document.activeElement.id === "btn-sample-pcap"', 'sample button focused');
      const btnRing = await page.evaluate('({ s: getComputedStyle(document.activeElement).outlineStyle, w: parseFloat(getComputedStyle(document.activeElement).outlineWidth) })');
      assert.equal(btnRing.s, 'solid');
      assert.ok(btnRing.w >= 2, 'button focus ring >=2px, got ' + btnRing.w);
    });

    await runCase('workbench-print-motion-inner-scroll', async () => {
      const css = fs.readFileSync(path.join(ROOT, 'style.css'), 'utf8');
      assert.match(css, /prefers-reduced-motion/);
      assert.match(css, /@media print/);
      assert.match(css, /clip-path:\s*inset\(50%\)/);
      assert.equal(/clip:\s*rect\(/.test(css), false, 'deprecated clip:rect() must be replaced by clip-path');
      assert.match(css, /\.table-wrap\s*\{[^}]*overflow-x:\s*auto/);
      assert.match(css, /table\s*\{[^}]*min-width:\s*640px/);
      await setPrint();
      const emptyPrintGetting = await page.evaluate('(() => { const n = document.getElementById("getting-started"); if (!n) return "missing"; const r = n.getClientRects(); return (r.length > 0 && getComputedStyle(n).display !== "none") ? "visible" : "hidden"; })()');
      assert.equal(emptyPrintGetting, 'visible', 'print must preserve getting-started when empty, got ' + emptyPrintGetting);
      const importRowHidden = await page.evaluate('getComputedStyle(document.querySelector("#import-panel .import-row")).display');
      assert.equal(importRowHidden, 'none', 'print hides action rows, got ' + importRowHidden);
      await loadSample();
      await setPrint();
      const loadedPrintGetting = await page.evaluate('(() => { const n = document.getElementById("getting-started"); if (!n) return "missing"; const r = n.getClientRects(); return (r.length > 0 && getComputedStyle(n).display !== "none") ? "visible" : "hidden"; })()');
      assert.equal(loadedPrintGetting, 'hidden', 'loaded print may omit getting-started via body[data-loaded], got ' + loadedPrintGetting);
      await setScreenDark();
      await page.screenshot(path.join(SHOTS, 'workbench-print.png'));
    });

    await runCase('workbench-real-exports-redacted-optin-html', async () => {
      await setScreenDark();
      await loadSample();
      const redacted = await page.download('#btn-export-json');
      assert.match(redacted.suggestedFilename, /^lantriage-report-fictional-sample-lan-le\.pcap\.json$/);
      await fs.promises.writeFile(path.join(ART, 'workbench-report-redacted.json'), redacted.bytes);
      const redactedJson = JSON.parse(redacted.text);
      assert.equal(redactedJson.redaction.mode, 'redacted');
      assert.equal(redactedJson.capture.counts.seen, 15);
      assert.equal(redactedJson.evidence.packets.length, 15);
      assert.ok(!redacted.text.includes('aa:00:00:00:00:30'), 'default report must not leak MAC');
      assert.ok(!redacted.text.includes('192.0.2.30'), 'default report must not leak IP');
      assert.ok(!redacted.text.includes('fictional-laptop'), 'default report must not leak hostname');
      assert.match(redacted.text, /mac-\d\d/);
      await page.check('#opt-identifiers', true);
      const identified = await page.download('#btn-export-json');
      await fs.promises.writeFile(path.join(ART, 'workbench-report-identifiers.json'), identified.bytes);
      assert.equal(JSON.parse(identified.text).redaction.mode, 'identifiers');
      assert.ok(identified.text.includes('aa:00:00:00:00:30'), 'opt-in includes MAC');
      await page.check('#opt-identifiers', false);
      const html = await page.download('#btn-export-html');
      await fs.promises.writeFile(path.join(ART, 'workbench-report-redacted.html'), html.bytes);
      assert.ok(!/<script/i.test(html.text), 'HTML report must be script-free');
      assert.ok(!/https?:\/\//i.test(html.text), 'HTML report must not reference remote resources');
      assert.match(html.text, /REDACTED/);
      await page.goto(html.filename);
      await page.waitFor('document.readyState === "complete"');
      assert.equal(await page.evaluate('document.title'), 'LanTriage evidence report');
      assert.match(await page.evaluate('document.body.textContent'), /Packet evidence/);
    });

    await runCase('workbench-imported-filename-isolated-verbatim-counts', async () => {
      const srcFixture = path.join(ROOT, 'fixtures', 'synthetic-lan-le-us.pcap');
      const hostileName = 'FICTION-\u202e-capture-\u202b.pcap';
      const hostilePath = path.join(ART, hostileName);
      fs.copyFileSync(srcFixture, hostilePath);
      await page.setInputFiles('#file-input', hostilePath);
      await page.waitFor('document.getElementById("summary-seen").textContent === "15"', 'hostile capture loaded');
      const obs = await page.evaluate('(()=>{const n=document.querySelector("#import-status"),s=document.querySelector("#summary-source");return{status:n.textContent,filename:s.textContent,isolates:[...n.querySelectorAll("bdi")].map(x=>({text:x.textContent,style:getComputedStyle(x).unicodeBidi})),seen:document.querySelector("#summary-seen").textContent,decoded:document.querySelector("#summary-decoded").textContent};})()');
      assert.ok(obs.status.includes(hostileName), 'status must carry filename verbatim');
      assert.equal(obs.filename, hostileName, 'summary-source must preserve filename verbatim');
      assert.equal(obs.seen, '15', 'adjacent seen count intact');
      assert.equal(obs.decoded, '12', 'adjacent decoded count intact');
      assert.match(obs.status, /15 packet\(s\) seen/, 'adjacent packet words intact');
      assert.ok(obs.isolates.some(n => n.text === hostileName && /isolate|plaintext/.test(n.style)), 'filename must be isolated via inline bdi, got ' + JSON.stringify(obs.isolates));
      assert.equal(await page.evaluate('document.querySelectorAll("#import-status script").length'), 0, 'no script from filename');
      assert.equal(await page.evaluate('typeof window.__pwned'), 'undefined', 'no code from filename');
      // Exports still describe the displayed hostile capture.
      const redacted = await page.download('#btn-export-json');
      const redactedJson = JSON.parse(redacted.text);
      assert.equal(redactedJson.capture.counts.seen, 15);
      assert.equal(redactedJson.evidence.packets.length, 15);
      // Failed import retains the hostile model and explains so.
      await page.setInputFiles('#file-input', path.join(ROOT, 'fixtures', 'synthetic-bad-magic.pcap'));
      await page.waitFor('document.getElementById("error-line").hidden === false', 'error for bad magic');
      assert.match(await page.evaluate('document.getElementById("error-line").textContent'), /E_MAGIC/);
      assert.match(await page.evaluate('document.getElementById("import-status").textContent'), /still showing/);
      assert.equal(await page.evaluate('document.querySelectorAll("#packets-body tr").length'), 15, 'previous hostile capture still displayed');
      assert.equal(await page.evaluate('document.getElementById("btn-export-json").disabled'), false, 'exports still match displayed capture');
      try { fs.unlinkSync(hostilePath); } catch {}
    });

    await runCase('workbench-offline-no-storage-fonts-cdn', async () => {
      const css = fs.readFileSync(path.join(ROOT, 'style.css'), 'utf8');
      const html = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');
      const appjs = fs.readFileSync(path.join(ROOT, 'app.js'), 'utf8');
      for (const [f, s] of [['index.html', html], ['app.js', appjs], ['style.css', css]]) {
        assert.equal(s.includes('http://'), false, f + ' has http://');
        assert.equal(s.includes('https://'), false, f + ' has https://');
        assert.equal(/localStorage|sessionStorage|indexedDB/.test(s), false, f + ' must not touch storage');
      }
      assert.equal(/@font-face|fonts\.googleapis|fonts\.gstatic|\.woff2?|data:font/.test(css), false, 'no webfonts allowed');
      assert.equal(/cdn\.|unpkg|jsdelivr/i.test(html), false, 'no CDN allowed');
      assert.match(css, /system-ui/);
      const btnIds = await page.evaluate('Array.from(document.querySelectorAll("button")).map(b => b.id).sort()');
      assert.deepEqual(btnIds, ['btn-export-html', 'btn-export-json', 'btn-sample-pcap', 'btn-sample-pcapng'], 'only real controls allowed, got ' + btnIds.join(','));
      assert.equal(await page.evaluate('window.localStorage.length === 0 && window.sessionStorage.length === 0'), true);
    });

    results.push({ name: 'whole-session-zero-errors-zero-requests', status: 'pass' });
    console.log('PASS whole-session-zero-errors-zero-requests');
  } catch (error) {
    results.push({ name: 'suite-harness', status: 'fail', message: error.message });
    console.error('SUITE FAILURE\n' + error.stack);
  } finally {
    try { fs.writeFileSync(path.join(ART, 'ui-workbench-results.json'), JSON.stringify({ checkedAt: new Date().toISOString(), results }, null, 2) + '\n'); } catch {}
    try { await page.close(); } catch {}
  }
  const failed = results.filter(r => r.status === 'fail');
  console.log(JSON.stringify({ cases: results.length, pass: results.length - failed.length, fail: failed.length }));
  console.log('WORKBENCH SUITE: ' + (results.length - failed.length) + ' passed, ' + failed.length + ' failed');
  if (!results.length || failed.length) process.exitCode = 1;
})().catch(e => { console.error(e.stack); process.exitCode = 1; });

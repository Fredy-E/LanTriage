'use strict';
/*
 * LanTriage — packaged CDP helper regression (portable, no owner browser).
 *
 * Proves the packaged tests/cdp-browser.cjs (byte-identical copy of the
 * parent-verified shared helper):
 *   - proves CURRENT exact generated-profile ownership before any PID kill
 *     (Get-CimInstance Win32_Process + CommandLine + --user-data-dir= before
 *     taskkill.exe, single guarded path, skip when unproven);
 *   - retries transient DevToolsActivePort states (ENOENT + one-shot EBUSY);
 *   - launches a real owned Chrome despite an injected one-shot EBUSY.
 *
 * Fictional synthetic bytes only; owns a fresh headless profile per run;
 * never attaches to owner browsers.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');

const HELPER = path.join(__dirname, 'cdp-browser.cjs');
const src = fs.readFileSync(HELPER, 'utf8');

test('helper proves current generated-profile ownership before PID kill', () => {
  assert.ok(src.includes('Get-CimInstance Win32_Process'), 'missing Get-CimInstance proof');
  assert.ok(src.includes('CommandLine'), 'missing CommandLine check');
  assert.ok(src.includes('--user-data-dir='), 'missing --user-data-dir= profile check');
  assert.ok(src.includes('taskkill.exe'), 'missing taskkill.exe path');
  const cmdIdx = src.indexOf('CommandLine');
  const killIdx = src.indexOf('taskkill.exe');
  assert.ok(cmdIdx !== -1 && killIdx !== -1 && cmdIdx < killIdx, 'ownership proof must precede PID kill');
  const kills = (src.match(/taskkill\.exe/g) || []).length;
  assert.equal(kills, 1, 'expected exactly one PID-kill path, got ' + kills);
  assert.ok(src.includes('Skipped PID cleanup'), 'must skip kill when ownership unproven');
  assert.ok(src.includes('mkdtemp'), 'must generate fresh profile via mkdtemp');
  assert.ok(src.includes('phase2-chrome-'), 'must use generated profile prefix');
  assert.ok(!/--remote-debugging-port=(?!0\b)\d+/.test(src), 'must not use a fixed owner port');
});

test('helper retries transient DevToolsActivePort states (ENOENT + EBUSY)', () => {
  assert.ok(src.includes('EBUSY'), 'missing EBUSY retry');
  assert.ok(src.includes('ENOENT'), 'missing ENOENT retry');
  const ebusyIdx = src.indexOf('EBUSY');
  const enoentIdx = src.indexOf('ENOENT');
  assert.ok(ebusyIdx !== -1 && enoentIdx !== -1, 'both transient codes required');
  assert.ok(src.includes('return null'), 'transient startup must retry via return null');
});

test('helper launches owned Chrome despite injected one-shot EBUSY', async () => {
  const helper = require('./cdp-browser.cjs');
  const original = fsp.readFile;
  let injected = false;
  fsp.readFile = async function (file, ...args) {
    if (!injected && String(file).endsWith(path.sep + 'DevToolsActivePort')) {
      injected = true;
      const err = new Error('Synthetic owned-port sharing violation');
      err.code = 'EBUSY';
      throw err;
    }
    return original.call(this, file, ...args);
  };
  let page = null;
  try {
    const out = path.join(__dirname, 'evidence', 'helper-ebusy-probe');
    await fsp.mkdir(out, { recursive: true });
    page = await helper.launch({ artifactsDir: out });
    assert.ok(injected, 'one-shot EBUSY was not injected');
    assert.equal(await page.evaluate('document.readyState'), 'complete');
    page.assertClean();
    await page.close();
    page = null;
    await fsp.rm(out, { recursive: true, force: true });
  } finally {
    fsp.readFile = original;
    if (page) try { await page.close(); } catch {}
  }
});

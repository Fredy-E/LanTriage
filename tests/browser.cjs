'use strict';
/*
 * LanTriage browser suite: real Chrome (headless), owned profile, zero skips.
 *
 * Uses the parent-verified dependency-free CDP helper copied verbatim into
 * tests/cdp-browser.cjs. Every scenario:
 *   - opens index.html from file:// (no server),
 *   - imports REAL fixture files through a real file input,
 *   - downloads REAL report bytes and inspects them,
 *   - fails on any page error, console error or http(s) request,
 *   - is screenshot only with fictional synthetic data.
 *
 * Run: node tests/browser.cjs      (from the tool root)
 */

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { launch } = require('./cdp-browser.cjs');
const F = require('./fixtures.cjs');

const ROOT = path.resolve(__dirname, '..');
const FIXTURES = path.join(ROOT, 'fixtures');
// Keep reruns portable; LANTRIAGE_EVIDENCE redirects new artifacts when needed.
const EVIDENCE = process.env.LANTRIAGE_EVIDENCE || path.join(ROOT, 'tests', 'evidence');
const INDEX = path.join(ROOT, 'index.html');
const results = [];

async function scenario(page, name, callback) {
  try {
    await callback();
    page.assertClean();
    results.push({ name, status: 'pass' });
    console.log('PASS ' + name);
  } catch (error) {
    results.push({ name, status: 'fail', message: error.message, stack: error.stack });
    console.error('FAIL ' + name + '\n' + error.stack);
    try {
      await page.screenshot(path.join(EVIDENCE, name.replace(/\W+/g, '-') + '-failure.png'));
    } catch (shotError) { /* screenshot is best-effort */ }
    throw error;
  }
}

async function loadSample(page) {
  await page.click('#btn-sample-pcap');
  await page.waitFor('document.getElementById("import-status").textContent.indexOf("fictional-sample-lan-le.pcap") !== -1 && document.getElementById("import-status").textContent.indexOf("15 packet(s) seen") !== -1', 'sample pcap loaded', 10000);
}

const bodyOverflow = 'Math.max(document.documentElement.scrollWidth, document.body.scrollWidth) - window.innerWidth';

(async () => {
  await fs.mkdir(EVIDENCE, { recursive: true });
  const scratch = process.env.TMPDIR || os.tmpdir();
  const page = await launch({ artifactsDir: EVIDENCE });
  let failure = null;
  try {
    // ------------------------------------------------------------------
    // 1. real imports: embedded sample, pcap fixture file, pcapng fixture file
    // ------------------------------------------------------------------
    await scenario(page, 'import-samples-and-real-files', async () => {
      await page.goto(INDEX);
      assert.equal(await page.evaluate('document.getElementById("btn-export-json").disabled'), true, 'exports disabled before any import');
      assert.equal(await page.evaluate('document.getElementById("summary-panel").hidden'), true, 'summary hidden before import');

      await loadSample(page);
      const summary = await page.evaluate(`({
        seen: document.getElementById('summary-seen').textContent,
        decoded: document.getElementById('summary-decoded').textContent,
        unsupported: document.getElementById('summary-unsupported').textContent,
        rejected: document.getElementById('summary-rejected').textContent,
        source: document.getElementById('summary-source').textContent,
        coverage: document.getElementById('coverage-limited').textContent,
        packets: document.querySelectorAll('#packets-body tr').length,
        observations: document.querySelectorAll('#observations-list li').length,
        findings: document.getElementById('findings-list').textContent,
        warnings: document.getElementById('warnings-list').textContent
      })`);
      assert.equal(summary.seen, '15');
      assert.equal(summary.decoded, '12');
      assert.equal(summary.unsupported, '3');
      assert.equal(summary.rejected, '0');
      assert.match(summary.source, /fictional-sample-lan-le\.pcap/);
      assert.match(summary.coverage, /LIMITED/);
      assert.equal(summary.packets, 15, 'packet evidence table lists every record');
      assert.ok(summary.observations >= 12, 'observations listed, got ' + summary.observations);
      assert.match(summary.findings, /possible-ip-mac-conflict/);
      assert.match(summary.findings, /192\.0\.2\.20/);
      assert.match(summary.findings, /not proof of one/i);
      assert.match(summary.warnings, /W_TRUNCATED_PAYLOAD/);
      const arpObs = await page.evaluate('document.getElementById("observations-list").textContent');
      assert.match(arpObs, /who-has 192\.0\.2\.20 tell 192\.0\.2\.10/);
      assert.match(arpObs, /fictional-laptop/);
      assert.equal(await page.evaluate('document.getElementById("btn-export-json").disabled'), false, 'exports enabled after import');

      // real file import: pcap fixture
      await page.setInputFiles('#file-input', path.join(FIXTURES, 'synthetic-lan-le-us.pcap'));
      await page.waitFor('document.getElementById("import-status").textContent.indexOf("synthetic-lan-le-us.pcap") !== -1 && document.getElementById("import-status").textContent.indexOf("15 packet(s) seen") !== -1', 'fixture pcap loaded');
      assert.equal(await page.evaluate('document.getElementById("summary-seen").textContent'), '15');

      // real file import: pcapng fixture (two sections, SPB, skipped blocks)
      await page.setInputFiles('#file-input', path.join(FIXTURES, 'synthetic-multi-section.pcapng'));
      await page.waitFor('document.getElementById("import-status").textContent.indexOf("synthetic-multi-section.pcapng") !== -1 && document.getElementById("import-status").textContent.indexOf("6 packet(s) seen") !== -1', 'fixture pcapng loaded');
      const pcapng = await page.evaluate(`({
        sections: document.getElementById('summary-sections').textContent,
        packets: document.querySelectorAll('#packets-body tr').length,
        table: document.getElementById('packets-table').textContent
      })`);
      assert.match(pcapng.sections, /2 section\(s\)/);
      assert.equal(pcapng.packets, 6);
      assert.match(pcapng.table, /no timestamp \(Simple Packet Block\)/, 'SPB row explains the missing timestamp');
      assert.match(pcapng.table, /interface-unknown/, 'rejected record is visible in the evidence table');
      // fix round 1: EPB timestamps must read Timestamp High then Low per
      // section byte order; these labels would be catastrophically wrong
      // (≈ year 187000) if the words were read as one whole uint64.
      assert.match(pcapng.table, /2026-10-11 12:00:00\.100000 UTC/, 'LE EPB timestamp High-then-Low');
      assert.match(pcapng.table, /2026-10-11 12:00:00\.200000 UTC/);
      assert.match(pcapng.table, /~2026-10-11 12:00:00\.500 UTC \(approx, 2\^-10 s units\)/, 'binary resolution stays approximate-marked');
      assert.match(pcapng.table, /2026-10-11 13:00:05\.000000 UTC/, 'if_tsoffset still applied');
      assert.match(await page.evaluate('document.getElementById("coverage-reasons").textContent'), /option/i, 'uninterpreted options are visible in the coverage list');

      // clean-state screenshot with fictional sample data for the README
      await page.click('#btn-sample-pcap');
      await page.waitFor('document.getElementById("import-status").textContent.indexOf("fictional-sample-lan-le.pcap") !== -1', 'sample reloaded for screenshot');
      await page.viewport(1440, 1000);
      await page.screenshot(path.join(EVIDENCE, 'screenshot-desktop.png'));
    });

    // ------------------------------------------------------------------
    // 2. exports: default redaction, opt-in identifiers, real HTML file
    // ------------------------------------------------------------------
    await scenario(page, 'export-redaction-and-html-report', async () => {
      await page.goto(INDEX);
      await loadSample(page);

      const redacted = await page.download('#btn-export-json');
      assert.match(redacted.suggestedFilename, /^lantriage-report-fictional-sample-lan-le\.pcap\.json$/);
      await fs.writeFile(path.join(EVIDENCE, 'sample-report-redacted.json'), redacted.bytes);
      const redactedJson = JSON.parse(redacted.text);
      assert.equal(redactedJson.redaction.mode, 'redacted');
      assert.equal(redactedJson.capture.counts.seen, 15);
      assert.equal(redactedJson.evidence.packets.length, 15);
      assert.ok(!redacted.text.includes('aa:00:00:00:00:30'), 'default report must not leak MAC');
      assert.ok(!redacted.text.includes('192.0.2.30'), 'default report must not leak IP');
      assert.ok(!redacted.text.includes('fictional-laptop'), 'default report must not leak hostname');
      assert.ok(!redacted.text.includes('fictional-sample-lan-le.pcap'), 'default report must not leak file name');
      assert.match(redacted.text, /mac-\d\d/);
      assert.match(redacted.text, /ip-\d\d/);
      assert.match(redacted.text, /cannot prove the absence/i);

      await page.check('#opt-identifiers', true);
      const identified = await page.download('#btn-export-json');
      const identifiedJson = JSON.parse(identified.text);
      assert.equal(identifiedJson.redaction.mode, 'identifiers');
      assert.ok(identified.text.includes('aa:00:00:00:00:30'), 'opt-in includes MAC');
      assert.ok(identified.text.includes('fictional-laptop'), 'opt-in includes hostname');
      await fs.writeFile(path.join(EVIDENCE, 'sample-report-identifiers.json'), identified.bytes);
      await page.check('#opt-identifiers', false);

      const html = await page.download('#btn-export-html');
      assert.match(html.suggestedFilename, /\.html$/);
      await fs.writeFile(path.join(EVIDENCE, 'sample-report-redacted.html'), html.bytes);
      assert.ok(!/<script/i.test(html.text), 'HTML report must be script-free');
      assert.ok(!/https?:\/\//i.test(html.text), 'HTML report must not reference remote resources');
      assert.ok(!html.text.includes('aa:00:00:00:00:30'), 'redacted HTML must not leak MAC');
      assert.match(html.text, /REDACTED/);
      assert.match(html.text, /Limitations/);
      assert.match(html.text, /possible-ip-mac-conflict/);

      // open the downloaded report as a real file:// page and verify it renders
      await page.goto(html.filename);
      await page.waitFor('document.readyState === "complete"');
      assert.equal(await page.evaluate('document.title'), 'LanTriage evidence report');
      const reportText = await page.evaluate('document.body.textContent');
      assert.match(reportText, /Packet evidence/);
      assert.match(reportText, /cannot prove the absence/i);
      assert.match(reportText, /Counterexamples/);
    });

    // ------------------------------------------------------------------
    // 3. filters, failed import (previous capture retained), race + busy state
    // ------------------------------------------------------------------
    await scenario(page, 'filters-failed-import-and-race', async () => {
      await page.goto(INDEX);
      await loadSample(page);

      await page.check('#filter-dhcp', false);
      await page.waitFor('document.querySelectorAll("#packets-body tr").length === 11', 'DHCP packets filtered out');
      const obsText = await page.evaluate('document.getElementById("observations-list").textContent');
      assert.ok(!/DHCP DISCOVER/.test(obsText), 'filtered protocol must disappear from observations');
      assert.match(obsText, /ARP request/);

      await page.fill('#filter-text', 'printer');
      await page.waitFor('document.querySelectorAll("#packets-body tr").length === 2', 'text filter narrows packets to the mDNS pair');
      const countText = await page.evaluate('document.getElementById("filter-count").textContent');
      assert.match(countText, /of 12 observation\(s\)/);
      await page.fill('#filter-text', '');
      await page.check('#filter-dhcp', true);
      await page.waitFor('document.querySelectorAll("#packets-body tr").length === 15', 'filters cleared');

      // failed import keeps the displayed capture and says so
      await page.setInputFiles('#file-input', path.join(FIXTURES, 'synthetic-bad-magic.pcap'));
      await page.waitFor('document.getElementById("error-line").hidden === false', 'error shown for bad magic');
      const errorText = await page.evaluate('document.getElementById("error-line").textContent');
      assert.match(errorText, /E_MAGIC/);
      const statusText = await page.evaluate('document.getElementById("import-status").textContent');
      assert.match(statusText, /still showing/);
      assert.equal(await page.evaluate('document.querySelectorAll("#packets-body tr").length'), 15, 'previous capture still displayed');
      assert.equal(await page.evaluate('document.getElementById("btn-export-json").disabled'), false, 'exports still match the displayed capture');

      // race: two imports back to back; the LAST one must win
      await page.setInputFiles('#file-input', path.join(FIXTURES, 'synthetic-multi-section.pcapng'));
      await page.setInputFiles('#file-input', path.join(FIXTURES, 'synthetic-counter-dhcp-duplicate.pcap'));
      await page.waitFor('document.getElementById("import-status").textContent.indexOf("synthetic-counter-dhcp-duplicate.pcap") !== -1 && document.getElementById("import-status").textContent.indexOf("4 packet(s) seen") !== -1', 'newest import wins the race');
      assert.equal(await page.evaluate('document.querySelectorAll("#packets-body tr").length'), 4);
      assert.equal(await page.evaluate('document.getElementById("error-line").hidden'), true, 'no error from the superseded import');
      assert.match(await page.evaluate('document.getElementById("findings-list").textContent'), /possible-duplicate-dhcp-assignment/);

      // busy window: a large read must disable exports until it finishes
      const bigFile = path.join(scratch, 'lantriage-big-synthetic.pcap');
      const header = Buffer.alloc(24);
      header.writeUInt32LE(0xa1b2c3d4, 0);
      header.writeUInt16LE(2, 4); header.writeUInt16LE(4, 6);
      header.writeUInt32LE(65535, 16); header.writeUInt32LE(1, 20);
      await fs.writeFile(bigFile, Buffer.concat([header, Buffer.alloc(30 * 1024 * 1024)]));
      await page.setInputFiles('#file-input', bigFile);
      const disabledDuringRead = await page.evaluate('document.getElementById("btn-export-json").disabled');
      assert.equal(disabledDuringRead, true, 'exports must be disabled while an import is in flight');
      await page.waitFor('document.getElementById("import-status").textContent.indexOf("lantriage-big-synthetic.pcap") !== -1 && document.getElementById("import-status").textContent.indexOf("packet(s) seen") !== -1', 'large import finished');
      assert.match(await page.evaluate('document.getElementById("warnings-list").textContent'), /W_LIMIT_PACKETS/, 'packet cap is visible in the UI');
      assert.match(await page.evaluate('document.getElementById("coverage-limited").textContent'), /LIMITED/);
      await fs.rm(bigFile, { force: true });
    });

    // ------------------------------------------------------------------
    // 4. keyboard: skip link, file-input focus ring, Enter on a button
    // ------------------------------------------------------------------
    await scenario(page, 'keyboard-focus-and-activation', async () => {
      await page.goto(INDEX);
      await page.key('Tab');
      await page.waitFor('document.activeElement && document.activeElement.className === "skip-link"', 'skip link focused first');
      const skipOutline = await page.evaluate('getComputedStyle(document.activeElement).outlineStyle');
      assert.notEqual(skipOutline, 'none', 'skip link shows a focus ring');

      await page.key('Tab');
      await page.waitFor('document.activeElement && document.activeElement.id === "file-input"', 'file input focused');
      const ring = await page.evaluate(`(() => {
        const label = document.getElementById('file-label');
        const style = getComputedStyle(label);
        return { outline: style.outlineStyle, width: parseFloat(style.outlineWidth), labelWidth: label.getBoundingClientRect().width };
      })()`);
      assert.equal(ring.outline, 'solid', 'the visible label carries the focus ring for the hidden input');
      assert.ok(ring.width >= 2, 'focus ring at least 2px, got ' + ring.width);
      assert.ok(ring.labelWidth > 40, 'ring drawn on the visible label');

      await page.key('Tab');
      await page.waitFor('document.activeElement && document.activeElement.id === "btn-sample-pcap"', 'sample button focused');
      // A real Enter press is rawKeyDown + char + keyUp; the helper's simple
      // key() pair does not carry the char event Blink needs to activate a button.
      await page.command('Input.dispatchKeyEvent', { type: 'rawKeyDown', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, nativeVirtualKeyCode: 13 });
      await page.command('Input.dispatchKeyEvent', { type: 'char', key: 'Enter', text: '\r', unmodifiedText: '\r' });
      await page.command('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, nativeVirtualKeyCode: 13 });
      await page.waitFor('document.getElementById("import-status").textContent.indexOf("fictional-sample-lan-le.pcap") !== -1', 'Enter activates the sample button');
      assert.equal(await page.evaluate('document.querySelectorAll("#packets-body tr").length'), 15);
    });

    // ------------------------------------------------------------------
    // 5. longest legal strings at 320/390 px must not overflow anything
    // ------------------------------------------------------------------
    await scenario(page, 'long-values-mobile-layout', async () => {
      const longHostname = 'h'.repeat(253);
      const longMdnsName = ['m'.repeat(63), 'n'.repeat(63), 'o'.repeat(63), 'p'.repeat(61)].join('.');
      const longFrame = F.mdnsQuery({ name: longMdnsName });
      const bytes = F.pcapFile({ variant: 'le-us', packets: [
        { data: F.dhcpDiscover({ hostname: longHostname }), tsSec: F.T0, tsFrac: 1 },
        { data: longFrame, tsSec: F.T0, tsFrac: 2 }
      ] }).bytes;
      const longFile = path.join(scratch, 'lantriage-long-values-synthetic.pcap');
      await fs.writeFile(longFile, bytes);

      await page.goto(INDEX);
      await page.setInputFiles('#file-input', longFile);
      await page.waitFor('document.getElementById("import-status").textContent.indexOf("lantriage-long-values-synthetic.pcap") !== -1', 'long-value capture loaded');
      assert.equal(await page.evaluate('document.getElementById("summary-decoded").textContent'), '2', 'longest legal hostname and name decode');
      const obsText = await page.evaluate('document.getElementById("observations-list").textContent');
      assert.match(obsText, /m{40}/, 'long mDNS name present in observations');

      for (const width of [390, 320]) {
        await page.viewport(width, 844);
        const overflow = await page.evaluate(bodyOverflow);
        assert.ok(overflow <= 1, 'body overflow at ' + width + 'px: ' + overflow + 'px');
        const listOverflow = await page.evaluate('document.getElementById("observations-list").scrollWidth - document.getElementById("observations-list").clientWidth');
        assert.ok(listOverflow <= 1, 'observations list overflows its box at ' + width + 'px: ' + listOverflow);
        const panelOverflow = await page.evaluate(`(() => {
          const panel = document.getElementById('summary-panel');
          return panel.scrollWidth - panel.clientWidth;
        })()`);
        assert.ok(panelOverflow <= 1, 'summary panel overflows at ' + width + 'px: ' + panelOverflow);
      }
      await page.screenshot(path.join(EVIDENCE, 'screenshot-mobile-390.png'));
      await page.viewport(1440, 1000);
      await fs.rm(longFile, { force: true });
    });

    // ------------------------------------------------------------------
    // 6. conforming pcapng: corrected timestamp labels, option coverage and
    //    real JSON/HTML downloads (default redacted + identifier opt-in)
    // ------------------------------------------------------------------
    await scenario(page, 'pcapng-timestamps-options-and-downloads', async () => {
      await page.goto(INDEX);
      await page.setInputFiles('#file-input', path.join(FIXTURES, 'synthetic-multi-section.pcapng'));
      await page.waitFor('document.getElementById("import-status").textContent.indexOf("synthetic-multi-section.pcapng") !== -1 && document.getElementById("import-status").textContent.indexOf("6 packet(s) seen") !== -1', 'conforming pcapng fixture loaded');

      const table = await page.evaluate('document.getElementById("packets-table").textContent');
      assert.match(table, /2026-10-11 12:00:00\.100000 UTC/, 'LE EPB timestamp reads High-then-Low in section byte order');
      assert.match(table, /2026-10-11 12:00:00\.200000 UTC/);
      assert.match(table, /~2026-10-11 12:00:00\.500 UTC \(approx, 2\^-10 s units\)/);
      assert.match(table, /2026-10-11 13:00:05\.000000 UTC/);

      assert.equal(await page.evaluate('document.getElementById("summary-options").textContent'), '1 skipped, 0 malformed', 'unsupported option counted in the viewer');
      assert.match(await page.evaluate('document.getElementById("coverage-reasons").textContent'), /option/i);

      // screenshot of the conforming pcapng capture with corrected timestamps
      await page.viewport(1440, 1000);
      await page.screenshot(path.join(EVIDENCE, 'screenshot-pcapng-corrected-times.png'));

      const redacted = await page.download('#btn-export-json');
      await fs.writeFile(path.join(EVIDENCE, 'pcapng-report-redacted.json'), redacted.bytes);
      const json = JSON.parse(redacted.text);
      assert.equal(json.capture.counts.unsupportedOptions, 1);
      assert.ok(json.warnings.some(w => w.code === 'W_OPTION_UNSUPPORTED'), 'option coverage warning present in the report');
      assert.equal(json.evidence.packets[0].timestampText, '2026-10-11 12:00:00.100000 UTC');
      assert.equal(json.evidence.packets[3].timestampText, '~2026-10-11 12:00:00.500 UTC (approx, 2^-10 s units)');
      assert.ok(!redacted.text.includes('fictional-eth0'), 'default report must not leak the interface name');

      await page.check('#opt-identifiers', true);
      const identified = await page.download('#btn-export-json');
      await fs.writeFile(path.join(EVIDENCE, 'pcapng-report-identifiers.json'), identified.bytes);
      assert.ok(identified.text.includes('fictional-eth0'), 'opt-in keeps the interface name');
      await page.check('#opt-identifiers', false);

      const html = await page.download('#btn-export-html');
      await fs.writeFile(path.join(EVIDENCE, 'pcapng-report-redacted.html'), html.bytes);
      assert.ok(!/<script/i.test(html.text), 'HTML report must be script-free');
      assert.match(html.text, /skipped options: 1/, 'option counters visible in the HTML report');
    });
  } catch (error) {
    failure = error;
  } finally {
    try { await page.close(); } catch (error) { console.error('close: ' + error.message); }
  }

  await fs.writeFile(path.join(EVIDENCE, 'browser-results.json'), JSON.stringify({ checkedAt: new Date().toISOString(), results }, null, 2));
  const failed = results.filter(item => item.status === 'fail');
  console.log(JSON.stringify({ cases: results.length, pass: results.length - failed.length, fail: failed.length }));
  if (failure || !results.length || failed.length) process.exitCode = 1;
})().catch(error => { console.error(error.stack); process.exitCode = 1; });

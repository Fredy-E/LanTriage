# LanTriage verification record

Everything below was produced by real execution on this machine
(Windows 11 ARM64, Node v26.7.0, npm 11.19.0, Google Chrome at
`C:/Program Files/Google/Chrome/Application/chrome.exe`). No CI, no
publication, no dependency installation: the unit suite is zero-dependency
`node:test` and the browser suite drives the parent-verified dependency-free
CDP helper (`tests/cdp-browser.cjs`, byte-identical copy of
`phase2-tools/shared/cdp-browser.cjs`, sha256
`3db68b5b…305c67` before and after this work — re-checked mechanically in
fix round 1).

**Portability note.** Every `evidence/…`, `parent-qa/…` and `review-round-3/…`
handle named in this document is a workspace-local reference: those files live
only in the build workspace and are not bundled with the standalone folder.
They are not shipped proof, only build-local history. The standalone folder
ships `index.html`, `app.js`, `core.js`, `style.css`, `package.json`,
`LICENSE`, `docs/` (including this record and `docs/screenshot-desktop.png`),
`fixtures/` and `tests/`; nothing outside it is required to run the viewer,
the unit suite (`npm test`) or the browser suite.

## 0. Current verified baseline (post-fix-round-2; supersedes the historical fix-round-1 §1–§2 below)

* Unit: **91 tests, 91 pass, 0 fail, exit 0** — parent record
  `parent-qa/LanTriage/post-fix-round-2/full-core.log` (workspace-local, not
  bundled). This supersedes the historical fix-round-1 83/83 in §1: the suite
  grew with the fix-round-2 precision/snapshot-coverage cases (83 historical,
  91 current).
* Frozen parent gates: **41/41 pass, exit 0** (27 precision/coverage + 4
  timestamp + 10 options/resolution) — parent record
  `parent-qa/LanTriage/post-fix-round-2/frozen-node-gates.log`
  (workspace-local, not bundled).
* Browser: **6 scenarios, 6 pass, 0 fail** — parent record
  `parent-qa/LanTriage/post-fix-round-2/full-browser.log` plus the
  workspace-local `parent-qa/LanTriage/post-fix-round-2/browser-artifacts/`
  directory (not bundled, not shipped). The fixer did **not** rerun the
  browser suite fresh and claims no fresh browser run here; §1's scenario
  list is retained as the preserved description of those same 6 scenarios.
* Independent review probes: **80/80 checks pass, exit 0** (final run only;
  no intermediate historical count is cited) — reviewer-owned
  `review-round-3/LanTriage/probes/lantriage-review-round3-probes.cjs` with
  log `review-round-3/LanTriage/logs/probes-run-2.txt` (workspace-local, not
  bundled), Stage 1 PASS and Stage 2 APPROVED with zero Critical/Important in
  `review-round-3/LanTriage/REPORT.md`.
* Fixer corroboration (this correction round): a fresh
  `node --test tests/core.test.cjs` from the standalone folder returned
  **91 pass / 0 fail, exit 0**; its log is kept only in the fixer-owned
  workspace-local directory `evidence/LanTriage/package-correction-round-1/`
  (`npm-test.txt`) and is not bundled. No fresh browser, network, capture or
  hardware run was made or is claimed.
* No application, style, test, fixture or helper file was changed in this
  correction round — only this document. Runtime `core.js`/`app.js`/CSS,
  fixtures, tests and the helper remain byte-identical to the reviewed tree.

## 1. Commands and results at fix round 1 (historical record; superseded by §0 above)

Run from `work/LanTriage`:

| Command | Result (final run) | Evidence log |
|---|---|---|
| `node tests/fixtures.cjs --write` | 25 synthetic fixtures + `manifest.json` + `README.md` regenerated (3 files changed by the corrected EPB writer) | `evidence/LanTriage/fix-round-1/fixture-write-fix-round-1.txt` |
| `node --test tests/core.test.cjs` | **83 tests, 83 pass, 0 fail, exit 0** (RED before the fix: 71 pass / 12 fail, exit 1) | `evidence/LanTriage/fix-round-1/green-unit-fix-round-1.txt` (RED: `red-unit-before-fix.txt`) |
| `node tests/browser.cjs` | **6 scenarios, 6 pass, 0 fail, exit 0** (real Chrome, owned headless profile) | `evidence/LanTriage/fix-round-1/browser-fix-round-1.txt` |
| `node --test parent-qa/LanTriage/pcapng-timestamp-regression.test.cjs` (frozen parent gate, unedited) | **4 tests, 4 pass, exit 0** | `evidence/LanTriage/fix-round-1/parent-timestamp-gate-green.txt` |
| `node --test parent-qa/LanTriage/pcapng-options-resolution-regression.test.cjs` (frozen parent gate, unedited) | **10 tests, 10 pass, exit 0** | `evidence/LanTriage/fix-round-1/parent-options-gate-green.txt` |

Browser scenarios (no skips; any skip is a failure by construction):

1. `import-samples-and-real-files` — embedded sample, real `setInputFiles`
   imports of `synthetic-lan-le-us.pcap` and `synthetic-multi-section.pcapng`,
   exact counts (15 seen / 12 decoded / 3 not decoded), findings text, SPB
   "no timestamp" row, rejected-record row, corrected EPB timestamp labels
   (`2026-10-11 12:00:00.100000 UTC`, `~… 12:00:00.500 (approx, 2^-10 s units)`,
   `13:00:05.000000 UTC`), the options coverage reason, clean screenshot.
2. `export-redaction-and-html-report` — real downloaded JSON parsed and
   asserted (default `redacted` mode: no MAC/IP/hostname/file-name leak; opt-in
   mode includes them), real downloaded HTML opened back in Chrome as a
   `file://` page and asserted script-free with the limitations text present.
3. `filters-failed-import-and-race` — protocol + text filters with exact row
   counts, failed import (`E_MAGIC`) keeps the displayed capture and says so,
   two back-to-back imports resolve to the newest one, a 30 MiB read keeps
   exports disabled while in flight, packet-limit warning visible in the UI.
4. `keyboard-focus-and-activation` — Tab order (skip link → file input → sample
   button), visible 3px focus ring drawn on the label for the visually hidden
   file input, Enter activation of a button.
5. `long-values-mobile-layout` — a synthetic capture carrying a 253-character
   DHCP hostname and a 253-character mDNS name imported as a real file;
   body/list/panel overflow ≤ 1px at **390px and 320px**.
6. `pcapng-timestamps-options-and-downloads` (new in fix round 1) — real import
   of the conforming `synthetic-multi-section.pcapng`: corrected timestamp
   labels in the evidence table; the viewer shows `1 skipped, 0 malformed`
   options and the coverage list names the uninterpreted option; real JSON
   downloads in both modes (`capture.counts.unsupportedOptions === 1`,
   `W_OPTION_UNSUPPORTED` present, redacted mode leaks no interface name,
   opt-in includes it) and a real script-free HTML download containing the
   option counters.

Every scenario asserts zero page errors, zero console errors and zero HTTP(S)
requests from the page (`assertClean`).

## 2. RED → GREEN history (preserved historical log through fix round 1; real logs retained)

| Log | Stage | Result |
|---|---|---|
| `red-core-initial.txt` | tests written before any implementation | exit 1 — `MODULE_NOT_FOUND` for `core.js` |
| `red-core-stage1-pcap.txt` | pcap container + timestamps + limits | 14 pass / 51 fail |
| `red-core-stage2-pcapng.txt` | pcapng container added | 21 pass / 44 fail |
| `red-core-stage2b-pcapng-fixed.txt` | EPB 64-bit timestamp + `E_NO_SHB` fixes | 23 pass / 42 fail |
| `red-core-stage3-protocols.txt` | Ethernet/VLAN/ARP/IPv4/UDP/DHCP/mDNS decoders | 44 pass / 21 fail |
| `green-core-stage4-analysis.txt` | analysis + reports | 64 pass / 1 fail |
| `green-core-final.txt` | file-name redaction fix | **65 pass / 0 fail, exit 0** |
| `green-core-after-warning-fix.txt` | after warning-priority fix | **65 pass / 0 fail, exit 0** |
| `final-unit-run.txt` (last run) | after adding the interface-name and raw-bytes leak tests | **67 pass / 0 fail, exit 0** |
| `browser-run-1.txt` | first browser run | 2 pass / 1 fail |
| `browser-run-2.txt` | after warning-priority fix | 3 pass / 1 fail |
| `browser-run-3.txt` | after Enter-sequence fix | **5 pass / 0 fail, exit 0** |
| `final-unit-run.txt`, `final-browser-run.txt` (round 1) | final confirmation runs | both exit 0 |
| `fix-round-1/red-unit-before-fix.txt` | fix round 1: primary-layout regressions written before the fix | 71 pass / 12 fail, exit 1 |
| `fix-round-1/green-unit-fix-round-1.txt` | after parser + generator + fixture fixes | **83 pass / 0 fail, exit 0** |
| `fix-round-1/parent-timestamp-gate-green.txt` | frozen parent timestamp gate after the fix | 4/4 pass, exit 0 |
| `fix-round-1/parent-options-gate-green.txt` | frozen parent options/resolution gate after the fix | 10/10 pass, exit 0 |
| `fix-round-1/browser-fix-round-1.txt` | browser suite after the fix | **6/6 pass, exit 0** |

The rows above are frozen history through the fix-round-1 83-test era; the
current 91-test baseline is §0 and is not re-argued here.

### Defects the tests actually caught (fixed, then re-verified)

1. **pcapng EPB timestamp words misread in little-endian sections (C1) — corrected in fix round 1.** The first implementation read the two 32-bit words in the order drawn in the draft's Figure 11 (Timestamp High at block +12, Timestamp Low at block +16, each in section byte order) — which is the **normative** layout. A later "fix" replaced that with a whole-64-bit-in-section-order read and the fixture generator was changed to match; because parser and fixtures then shared the same wrong assumption, the suite stayed green while **every real little-endian pcapng EPB** displayed a catastrophically wrong time (`high=0 low=1000000` decoded to seconds `4294967296` instead of `1`; the round-1 sample bytes stored the words low-first, so a conforming reader would have displayed a time ≈187,000 CE for the same logical time). Found by the parent's independent primary-layout gate (`parent-qa/LanTriage/pcapng-timestamp-regression.test.cjs`: LE cases RED), not by this suite. Fix round 1: the parser reads High then Low per field in section byte order and combines `High·2³² + Low` (BigInt, exact to 2^53−1); the generator gained a dedicated EPB timestamp writer; all 25 fixtures, the manifest, `fixtures/README.md` and both embedded `app.js` samples were regenerated; permanent project regressions (independent bytes, both byte orders, nonzero High/Low, byte-level fixture check, numeric boundaries) were added. The retraction of the incorrect "single 64-bit integer" claim lives in `docs/formats.md` §1.2.
2. **pcapng stream without a Section Header Block reported `E_MAGIC`.** Now a
   file that begins with a known block type is diagnosed as `E_NO_SHB`.
3. **Option data read with absolute buffer offsets.** Internal option reads now
   use view-relative offsets (found while validating the option table tests).
4. **ARP variant check ordered after the length check**, mis-reporting
   non-Ethernet ARP as truncated; variants are now classified first.
5. **Default JSON report leaked the source file name** (`source.file` was copied
   un-redacted). Caught by the redaction leak test; fixed and re-proved.
6. **The warning cap swallowed `W_LIMIT_PACKETS`.** Found by the browser
   scenario: 20 000 zero-length records filled the warning array first. Limit
   warnings now displace the oldest routine warning, and the cap marker stays
   visible.
7. **CDP `key('Enter')` does not activate a button.** A probe (clicks = 0 for
   the helper's keyDown/keyUp pair, clicks = 1 for rawKeyDown + char + keyUp)
   established the correct sequence; the browser test now sends the full
   sequence via the helper's public `command()` method. The shared helper file
   was not modified.
8. **`if_tsresol` beyond the internal cap was replaced by 10^-6 and the wrong
   time was marked exact (I1) — corrected in fix round 1.** Declared 10^-13
   with 10^13 ticks (exactly 1 s) displayed `10000000` s marked `exact:true`,
   and the interface's recorded resolution was replaced. The declared
   base/exponent (0..127) is now recorded exactly as declared and never
   replaced; resolutions beyond the exact display range are converted to
   milliseconds with exact integer arithmetic and clearly marked approximate
   (`~… (approx, 10^-13 s units)`); the 64-bit tick value is carried as BigInt
   so large ticks that scale into a displayable time stay exact (fix round 2: no raw 2^53 pre-reject; only out-of-range seconds are flagged with seconds:null). Found by the parent's
   frozen options/resolution gate and the reviewer probes.
9. **Unsupported option content inside supported blocks was silently dropped
   (I2) and a code-0 end marker with length > 0 was accepted (M1) — corrected
   in fix round 1.** SHB/IDB/EPB option areas are now structurally framed and
   counted (`unsupportedOptions` / `malformedOptions`), each uninterpreted
   option is warned by numeric code and byte offset only, and a malformed
   end-of-options marker is flagged. Found by the parent's frozen gate and
   reviewer probes.

## 3. Fixtures (all synthetic)

25 fixture files under `fixtures/`, each documented in `fixtures/README.md`
with byte size, SHA-256 and per-record file offsets (generated from the builder,
so documentation cannot drift from the bytes). Coverage: both byte orders,
micro/nanosecond pcap, multi-section pcapng (LE+BE sections, `if_tsresol`
10^-6 / 2^-10, `if_tsoffset`, SPB, NRB, custom block, unknown interface),
malformed magic/version/snaplen/lengths/trailers/pointers/options, IPv4
fragmentation, prototype-name identifiers (`__proto__`, `constructor`, an
HTML-metacharacter name) and analysis counterexamples (VLAN split, probe-only,
address transition, DHCP retransmit, cross-section claims).

Fix round 1 regenerated exactly three fixtures whose little-endian EPB
timestamps had been written with the wrong word order
(`synthetic-multi-section.pcapng`, `synthetic-bad-iface.pcapng`,
`synthetic-counter-multi-section.pcapng`; the other 22 files are byte-unchanged,
verified against the round-1 generation log). The two embedded UI samples were
regenerated and are **byte-identical** to
`fixtures/synthetic-lan-le-us.pcap` and `fixtures/synthetic-multi-section.pcapng`;
a permanent unit test decodes both `app.js` samples and compares them with the
fixture files and their manifest hashes mechanically.

## 4. Retained artifacts (relative workspace-local handles; not bundled or shipped)

All handles in this section are workspace-local references and are not bundled
with the standalone folder; they are not shipped proof, only build-local
history.

Fix-round-1 evidence directory:
`evidence/LanTriage/fix-round-1/`

* `red-unit-before-fix.txt`, `green-unit-fix-round-1.txt` — fix-round-1 RED→GREEN unit logs.
* `parent-timestamp-gate-green.txt`, `parent-options-gate-green.txt` — frozen parent gates, 4/4 and 10/10.
* `browser-fix-round-1.txt`, `browser-results.json` — 6/6 browser scenarios.
* `screenshot-desktop.png`, `screenshot-mobile-390.png` — re-captured from a clean state.
* `screenshot-pcapng-corrected-times.png` — the conforming pcapng fixture loaded, showing the corrected timestamp labels and the `1 skipped, 0 malformed` options row.
* `sample-report-redacted.json`, `sample-report-identifiers.json`, `sample-report-redacted.html` — real downloaded sample reports (redacted default / opt-in / script-free HTML).
* `pcapng-report-redacted.json`, `pcapng-report-identifiers.json`, `pcapng-report-redacted.html` — real downloads for the conforming pcapng fixture (corrected timestamp labels, option counters).
* `fixture-write-fix-round-1.txt`, `sample-regen-fix-round-1.txt` — fixture/sample regeneration logs.

Round-1 artifacts (unchanged, still valid as round-1 evidence):
`sample-report-redacted.json`, `sample-report-identifiers.json`,
`sample-report-redacted.html`, `screenshot-desktop.png`,
`screenshot-mobile-390.png`, `filters-failed-import-and-race-failure.png`,
`keyboard-focus-and-activation-failure.png`, `browser-results.json` in
`evidence/LanTriage/`.

Current-baseline records live in the workspace-local
`parent-qa/LanTriage/post-fix-round-2/` directory and the reviewer-owned
`review-round-3/LanTriage/` directory (neither bundled nor shipped); the fixer
corroboration log for this correction round lives in the workspace-local
`evidence/LanTriage/package-correction-round-1/` directory (not bundled).

## 5. Honest limitations of this verification

* **Synthetic only.** The parser was verified exclusively against self-authored
  byte sequences; no real hardware capture, no vendor-specific pcap dialect and
  no multi-gigabyte file was tested. The subset and its rejections are
  documented in `docs/formats.md`.
* **One browser.** Real Chrome (headless, owned profile) on Windows 11 ARM64.
  No Firefox/Safari/mobile device runs. No mobile-hardware testing.
* **Not verified:** IP/UDP checksum correctness, FCS handling, IPv6, TCP,
  reassembly, DHCP option-overload space, DNS-over-TCP, mDNS
  known-answer-suppression semantics — all are declared out of subset and
  counted as not decoded.
* **Timestamps:** binary resolutions and decimal resolutions finer than 10^-9
  are converted to milliseconds and marked approximate; the declared
  resolution is recorded and never replaced; invalid fractions are displayed
  as invalid.
* **Findings are candidates, not verdicts.** The suite proves the counterexample
  behaviour (no conflict across VLANs/sections, probes excluded, retransmissions
  not duplicates) but cannot prove anything about a real network.
* **Known deferred Minors (review-round-3, neither blocks acceptance; no code
  changed here).** (a) A dead, non-exported `readInt64` helper remains in
  `core.js` with no callers (the live offset path uses `readInt64Big`); it is
  unrelated dead code and was deliberately left untouched. (b) At a narrow
  390px viewport the packet-evidence table can clip timestamp cell content
  even though the `long-values-mobile-layout` body-overflow assertions pass;
  the complete evidence always remains in the exported JSON/HTML reports.
  Mobile content beyond the suite's overflow assertions is not claimed fully
  readable, and nothing here was tested on mobile hardware.

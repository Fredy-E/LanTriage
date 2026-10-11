/* LanTriage UI wiring (classic script; no modules, no fetch/XHR, no storage).
 *
 * All rendering uses createElement/textContent — imported bytes never reach an
 * HTML sink. Imports are race-safe: every import owns a token, and a result
 * that arrives after a newer import started is discarded. Export buttons are
 * disabled while an import is in flight so a report can never describe
 * something other than what is displayed.
 */
(function () {
  'use strict';

  var LT = window.LanTriage;
  var state = { model: null, sourceFile: null, importToken: 0, busy: false };

  // Embedded fictional samples (self-authored synthetic bytes; see fixtures/).
  var SAMPLES = {
    pcap: { name: 'fictional-sample-lan-le.pcap', b64: '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' },
    pcapng: { name: 'fictional-sample-multi-section.pcapng', b64: 'Cg0NCjgAAABNPCsaAQAAAP//////////BAATAExhblRyaWFnZS1zeW50aGV0aWMAAAAAADgAAAABAAAANAAAAAEAAAD//wAAAgAOAGZpY3Rpb25hbC1ldGgwAAAJAAEABgAAAAAAAAA0AAAABgAAAFAAAAAAAAAAj10GAKCWJFIqAAAAKgAAAP///////6oAAAAAEAgGAAEIAAYEAAGqAAAAABDAAAIKAAAAAAAAwAACFAAAAAAAAFAAAAAGAAAAZAEAAAAAAACPXQYAQB0mUkABAABAAQAA////////qgAAAAAwCABFAAEyEjRAAEARAAAAAAAA/////wBEAEMBHgAAAQEGABEiM0QAAIAAAAAAAAAAAAAAAAAAAAAAAKoAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABjglNjNQEBDBBmaWN0aW9uYWwtbGFwdG9wNwUBAwYPMz0HAaoAAAAAMP8AAAAAZAEAAAMAAAA8AAAAKgAAAKoAAAAAEKoAAAAAIAgGAAEIAAYEAAKqAAAAACDAAAIUqgAAAAAQwAACCgAAPAAAAAQAAAAQAAAAAAAAABAAAACtCwAAEAAAAAECAwQQAAAACg0NCgAAACAaKzxNAAEAAP//////////AAAAAAAAACAAAAABAAAAIAABAAAAAP//AAkAAYoAAAAAAAAAAAAAIAAAAAEAAAAsAAEAAAAA//8ACQABBgAAAAAOAAgAAAAAAAAOEAAAAAAAAAAsAAAABgAAAHgAAAAAAAABqy3pAgAAAABTAAAAUwEAXgAA+6oAAAAAEAgARQAARRI0QAD/EQAAwAACCuAAAPsU6RTpADEAAAAAAAAAAQAAAAAAABFmaWN0aW9uYWwtcHJpbnRlcgVsb2NhbAAAAQABAAAAAAAAAAB4AAAABgAAAFAAAAABAAZdj1JvW0AAAAAqAAAAKqoAAAAAEKoAAAAAIQgGAAEIAAYEAAKqAAAAACHAAAIUqgAAAAAQwAACCgAAAAAAAAAAAFAAAAAGAAAAYAAAAAUABl2PUiMQAAAAADsAAAA7qgAAAAAgqgAAAAAQCABFAAAtEjRAAEARAADAAAIKwAACFBFcFbMAGQAAc3ludGhldGljIHBheWxvYWQAAAAAAAAAAGA=' }
  };

  var el = function (id) { return document.getElementById(id); };
  var nodes = {
    fileInput: el('file-input'), samplePcap: el('btn-sample-pcap'), samplePcapng: el('btn-sample-pcapng'),
    status: el('import-status'), error: el('error-line'),
    summaryPanel: el('summary-panel'), coveragePanel: el('coverage-panel'), filtersPanel: el('filters-panel'),
    findingsPanel: el('findings-panel'), observationsPanel: el('observations-panel'),
    packetsPanel: el('packets-panel'), warningsPanel: el('warnings-panel'),
    summarySource: el('summary-source'), summaryFormat: el('summary-format'), summaryEndian: el('summary-endian'),
    summarySeen: el('summary-seen'), summaryDecoded: el('summary-decoded'), summaryUnsupported: el('summary-unsupported'),
    summaryRejected: el('summary-rejected'), summaryMalformed: el('summary-malformed'), summaryOptions: el('summary-options'),
    summarySections: el('summary-sections'),
    coverageLimited: el('coverage-limited'), coverageReasons: el('coverage-reasons'), limitations: el('limitations-list'),
    filterArp: el('filter-arp'), filterDhcp: el('filter-dhcp'), filterMdns: el('filter-mdns'), filterOther: el('filter-other'),
    filterText: el('filter-text'), filterCount: el('filter-count'),
    findings: el('findings-list'), observations: el('observations-list'),
    packetsBody: el('packets-body'), warnings: el('warnings-list'),
    optIdentifiers: el('opt-identifiers'), exportJson: el('btn-export-json'), exportHtml: el('btn-export-html'),
    exportStatus: el('export-status')
  };

  // -------------------------------------------------------------------------
  // helpers
  // -------------------------------------------------------------------------
  function clearChildren(node) { while (node.firstChild) node.removeChild(node.firstChild); }
  function addText(parent, tag, text, className) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    node.textContent = text;
    parent.appendChild(node);
    return node;
  }
  function bytesFromBase64(b64) {
    var binary = window.atob(b64);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }
  function sanitizeName(name) {
    return String(name || 'pasted').replace(/[^a-zA-Z0-9._-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 80) || 'pasted';
  }
  function formatError(error) {
    return (error && error.code ? error.code + ': ' : '') + (error && error.message ? error.message : 'unknown error');
  }
  function setStatus(text) { nodes.status.textContent = text; }
  function showError(error) {
    nodes.error.hidden = false;
    nodes.error.textContent = formatError(error);
  }
  function clearError() { nodes.error.hidden = true; nodes.error.textContent = ''; }

  function updateExportButtons() {
    var enabled = !state.busy && !!state.model;
    nodes.exportJson.disabled = !enabled;
    nodes.exportHtml.disabled = !enabled;
  }

  // -------------------------------------------------------------------------
  // import pipeline (token-guarded against races)
  // -------------------------------------------------------------------------
  function beginImport(readFn, sourceFile, label) {
    var token = ++state.importToken;
    state.busy = true;
    updateExportButtons();
    clearError();
    setStatus('Reading ' + label + ' …');
    readFn().then(function (bytes) {
      if (token !== state.importToken) return; // a newer import superseded this one
      finishImport(token, bytes, sourceFile);
    }, function (error) {
      if (token !== state.importToken) return;
      importFailed(token, { code: 'E_READ', message: 'The file could not be read: ' + (error && error.message ? error.message : 'unknown read error') }, label);
    });
  }

  function finishImport(token, bytes, sourceFile) {
    var parsed = LT.parseCapture(bytes);
    if (token !== state.importToken) return;
    if (!parsed.ok) { importFailed(token, parsed.error, sourceFile); return; }
    var analysis = LT.analyze(parsed.value, { sourceFile: sourceFile });
    if (token !== state.importToken) return;
    if (!analysis.ok) { importFailed(token, analysis.error, sourceFile); return; }
    state.model = analysis.value;
    state.sourceFile = sourceFile;
    state.busy = false;
    updateExportButtons();
    render();
    var c = parsed.value.counts;
    setStatus('Loaded ' + sourceFile + ' — ' + c.seen + ' packet(s) seen, ' + c.decoded + ' decoded, ' + c.unsupported +
      ' not decoded, ' + c.rejected + ' rejected, ' + c.truncated + ' truncated. Analysis complete; exports are current for this capture.');
    nodes.exportStatus.textContent = '';
  }

  function importFailed(token, error, label) {
    state.busy = false;
    updateExportButtons();
    showError(error);
    if (state.model) {
      setStatus('Import of ' + label + ' failed; still showing ' + state.sourceFile + '. Exports still describe the displayed capture.');
    } else {
      setStatus('Import of ' + label + ' failed; nothing is loaded.');
    }
  }

  function importFile(file) {
    if (!file) return;
    beginImport(function () {
      return new Promise(function (resolve, reject) {
        var reader = new FileReader();
        reader.onerror = function () { reject(reader.error || new Error('read error')); };
        reader.onload = function () { resolve(new Uint8Array(reader.result)); };
        reader.readAsArrayBuffer(file);
      });
    }, file.name, file.name);
  }

  function loadSample(key) {
    var sample = SAMPLES[key];
    if (!sample) return;
    beginImport(function () { return Promise.resolve(bytesFromBase64(sample.b64)); }, sample.name, sample.name + ' (fictional synthetic sample)');
  }

  // -------------------------------------------------------------------------
  // rendering
  // -------------------------------------------------------------------------
  function render() {
    var model = state.model;
    if (!model) return;
    nodes.summaryPanel.hidden = false;
    nodes.coveragePanel.hidden = false;
    nodes.filtersPanel.hidden = false;
    nodes.findingsPanel.hidden = false;
    nodes.observationsPanel.hidden = false;
    nodes.packetsPanel.hidden = false;
    nodes.warningsPanel.hidden = false;
    renderSummary(model);
    renderCoverage(model);
    renderFindings(model);
    renderWarnings(model);
    renderFilters();
  }

  function renderSummary(model) {
    var c = model.capture.counts;
    nodes.summarySource.textContent = model.source.file || '(pasted bytes)';
    nodes.summaryFormat.textContent = model.capture.format + (model.capture.pcap ? ' (version ' + model.capture.pcap.versionMajor + '.' + model.capture.pcap.versionMinor + ', ' + model.capture.pcap.timestampResolution + ' timestamps)' : '');
    nodes.summaryEndian.textContent = model.capture.endianLabel;
    nodes.summarySeen.textContent = String(c.seen);
    nodes.summaryDecoded.textContent = String(c.decoded);
    nodes.summaryUnsupported.textContent = String(c.unsupported);
    nodes.summaryRejected.textContent = String(c.rejected);
    nodes.summaryMalformed.textContent = String(c.malformed);
    nodes.summaryOptions.textContent = c.unsupportedOptions + ' skipped, ' + c.malformedOptions + ' malformed';
    var interfaces = 0;
    for (var i = 0; i < model.capture.sections.length; i++) interfaces += model.capture.sections[i].interfaces.length;
    nodes.summarySections.textContent = model.capture.sections.length + ' section(s), ' + interfaces + ' interface(s), ' + c.unsupportedBlocks + ' skipped block(s)';
  }

  function renderCoverage(model) {
    var coverage = model.capture.coverage;
    nodes.coverageLimited.className = 'coverage-note ' + (coverage.limited ? 'limited' : 'full');
    nodes.coverageLimited.textContent = coverage.limited
      ? 'LIMITED coverage: ' + coverage.reasons.length + ' reason(s) — unparsed or rejected content exists in this file and is never treated as healthy.'
      : 'Coverage of the supported subset is complete for this capture (nothing was skipped, rejected or malformed).';
    clearChildren(nodes.coverageReasons);
    coverage.reasons.forEach(function (reason) { addText(nodes.coverageReasons, 'li', reason); });
    clearChildren(nodes.limitations);
    model.limitations.forEach(function (item) { addText(nodes.limitations, 'li', item); });
  }

  function renderFindings(model) {
    clearChildren(nodes.findings);
    if (!model.findings.length) {
      addText(nodes.findings, 'p', 'No possible-conflict or transition candidates were identified from the supported subset of this capture. That is not evidence that the network is healthy.', 'hint');
      return;
    }
    model.findings.forEach(function (finding) {
      var card = document.createElement('div');
      card.className = 'finding';
      addText(card, 'h3', finding.kind + ' (severity: ' + finding.severity + ')');
      addText(card, 'p', finding.statement);
      addText(card, 'p', finding.qualification, 'qualifier');
      addText(card, 'p', 'Counterexamples / benign explanations:', 'qualifier');
      var list = document.createElement('ul');
      finding.counterexamples.forEach(function (item) { addText(list, 'li', item); });
      card.appendChild(list);
      addText(card, 'p', 'Evidence: ' + finding.refs.map(function (ref) {
        return 'packet ' + ref.packetIndex + ' (offset ' + ref.fileOffset + ', ' + ref.timestampText + ', iface ' + ref.interfaceId +
          (ref.vlanIds.length ? ', vlan ' + ref.vlanIds.join('/') : '') + ')';
      }).join('; '), 'refs');
      nodes.findings.appendChild(card);
    });
  }

  function renderWarnings(model) {
    clearChildren(nodes.warnings);
    if (!model.warnings.length) {
      addText(nodes.warnings, 'li', 'No warnings: the supported subset of this capture parsed cleanly.');
      return;
    }
    model.warnings.forEach(function (warning) {
      var item = document.createElement('li');
      var code = addText(item, 'code', warning.code);
      code.textContent = warning.code;
      item.appendChild(document.createTextNode(' ' + warning.message));
      nodes.warnings.appendChild(item);
    });
  }

  function observationVisible(observation) {
    var text = nodes.filterText.value.trim().toLowerCase();
    var refs = observation.refs || [];
    var protocolOk = refs.some(function (ref) { return packetVisibleByProtocol(ref.packetIndex); });
    if (!protocolOk) return false;
    if (!text) return true;
    return observationHaystack(observation).indexOf(text) !== -1;
  }

  function observationHaystack(observation) {
    var parts = [observation.kind, observation.summary];
    try { parts.push(JSON.stringify(observation.details)); } catch (error) { /* details are plain data */ }
    return parts.join(' ').toLowerCase();
  }

  function packetVisibleByProtocol(index) {
    var packet = state.model.packets[index];
    if (!packet) return false;
    if (packet.status !== 'decoded') return nodes.filterOther.checked;
    if (packet.protocol === 'arp') return nodes.filterArp.checked;
    if (packet.protocol === 'dhcp') return nodes.filterDhcp.checked;
    if (packet.protocol === 'mdns') return nodes.filterMdns.checked;
    return nodes.filterOther.checked;
  }

  function packetHaystack(packet) {
    var parts = [packet.protocol, packet.status, packet.reason || '', packet.timestampText, 'p' + packet.index, 'offset ' + packet.fileOffset];
    try { parts.push(JSON.stringify(packet.details)); } catch (error) { /* plain data */ }
    return parts.join(' ').toLowerCase();
  }

  function packetVisible(packet) {
    if (!packetVisibleByProtocol(packet.index)) return false;
    var text = nodes.filterText.value.trim().toLowerCase();
    if (!text) return true;
    return packetHaystack(packet).indexOf(text) !== -1;
  }

  function renderFilters() {
    var model = state.model;
    if (!model) return;
    // observations
    clearChildren(nodes.observations);
    var shownObs = 0;
    model.observations.forEach(function (observation) {
      if (!observationVisible(observation)) return;
      shownObs += 1;
      var item = document.createElement('li');
      addText(item, 'span', observation.kind, 'obs-kind');
      item.appendChild(document.createTextNode(observation.summary + ' '));
      addText(item, 'span', observation.refs.map(function (ref) {
        return 'p' + ref.packetIndex + '@' + ref.fileOffset + ' · iface ' + ref.interfaceId + ' · vlan ' + (ref.vlanIds.length ? ref.vlanIds.join('/') : '-');
      }).join('; '), 'obs-ref');
      nodes.observations.appendChild(item);
    });
    // packets
    clearChildren(nodes.packetsBody);
    var shownPackets = 0;
    model.packets.forEach(function (packet) {
      if (!packetVisible(packet)) return;
      shownPackets += 1;
      var row = document.createElement('tr');
      var cells = [
        String(packet.index),
        String(packet.fileOffset),
        packet.timestampText,
        String(packet.interfaceId),
        packet.vlanIds.length ? packet.vlanIds.join('/') : '-',
        packet.caplen + '/' + packet.origlen,
        packet.protocol,
        packet.status + (packet.reason ? ' (' + packet.reason + ')' : '')
      ];
      cells.forEach(function (value, index) {
        var cell = document.createElement('td');
        cell.textContent = value;
        if (index === 7) cell.className = 'status-' + packet.status;
        row.appendChild(cell);
      });
      nodes.packetsBody.appendChild(row);
    });
    nodes.filterCount.textContent = 'Showing ' + shownObs + ' of ' + model.observations.length + ' observation(s) · ' +
      shownPackets + ' of ' + model.packets.length + ' packet record(s).';
  }

  // -------------------------------------------------------------------------
  // exports (real downloads; redacted by default)
  // -------------------------------------------------------------------------
  function download(filename, text, mime) {
    var blob = new Blob([text], { type: mime });
    var url = URL.createObjectURL(blob);
    var anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    window.setTimeout(function () { URL.revokeObjectURL(url); }, 2000);
  }

  function exportReport(kind) {
    if (!state.model || state.busy) return;
    var report = LT.buildReport(state.model, { includeIdentifiers: nodes.optIdentifiers.checked });
    if (!report.ok) { showError(report.error); return; }
    var base = 'lantriage-report-' + sanitizeName(state.sourceFile);
    var mode = nodes.optIdentifiers.checked ? 'identifiers included' : 'redacted ordinals';
    if (kind === 'json') {
      download(base + '.json', JSON.stringify(report.value.json, null, 2), 'application/json');
    } else {
      download(base + '.html', report.value.html, 'text/html');
    }
    nodes.exportStatus.textContent = 'Exported ' + base + '.' + kind + ' (' + mode + ').';
  }

  // -------------------------------------------------------------------------
  // wiring
  // -------------------------------------------------------------------------
  nodes.fileInput.addEventListener('change', function () {
    var file = nodes.fileInput.files && nodes.fileInput.files[0];
    if (file) importFile(file);
  });
  nodes.samplePcap.addEventListener('click', function () { loadSample('pcap'); });
  nodes.samplePcapng.addEventListener('click', function () { loadSample('pcapng'); });
  [nodes.filterArp, nodes.filterDhcp, nodes.filterMdns, nodes.filterOther].forEach(function (checkbox) {
    checkbox.addEventListener('change', renderFilters);
  });
  nodes.filterText.addEventListener('input', renderFilters);
  nodes.exportJson.addEventListener('click', function () { exportReport('json'); });
  nodes.exportHtml.addEventListener('click', function () { exportReport('html'); });
  updateExportButtons();
  setStatus('No capture loaded.');
})();

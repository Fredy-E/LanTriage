/*!
 * LanTriage core - bounded offline pcap/pcapng evidence analyzer.
 *
 * Classic script: loads as `window.LanTriage` in the browser and as a
 * CommonJS module in Node (the unit tests drive this same file).
 *
 * Design rules (see README.md and docs/formats.md):
 *  - pure functions only; no DOM, no network, no storage, no timers;
 *  - fallible API: parseCapture/analyze/buildReport return
 *    {ok:true, value} or {ok:false, error:{code, message, ...}};
 *  - every limit is a named constant in LIMITS and every skipped or
 *    unsupported item is counted and reported - unparsed content is never
 *    presented as healthy;
 *  - raw packet payloads are dropped after decoding and never stored in the
 *    model or written into reports.
 */
(function (root, factory) {
  'use strict';
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (typeof window !== 'undefined') window.LanTriage = api;
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const VERSION = '0.1.0';

  // -------------------------------------------------------------------------
  // hard limits (documented in README.md; all failures/truncations visible)
  // -------------------------------------------------------------------------
  const LIMITS = {
    maxBytes: 32 * 1024 * 1024,      // whole-file cap -> E_TOO_LARGE
    maxPackets: 20000,               // packet records parsed per capture
    maxBlocks: 50000,                // pcapng blocks visited per file
    maxObservations: 2000,           // observations kept per analysis
    maxWarnings: 200,                // warnings kept per capture
    maxStringBytes: 255,             // stored decoded string cap (RFC 1035 name limit)
    maxRefsPerItem: 8,               // evidence refs per observation/finding
    maxDnsJumps: 64,                 // compression pointer hops per name
    maxAnswersPerMessage: 64,        // DNS records decoded per message
    maxVlanTags: 2,                  // 802.1Q tags decoded before "unsupported"
    maxSections: 64,                 // pcapng sections per file
    maxInterfacesPerSection: 256     // IDBs per section
  };

  const MAGIC = {
    PCAP_US_BE: 0xa1b2c3d4,   // file header written big-endian, microsecond stamps
    PCAP_US_LE: 0xd4c3b2a1,
    PCAP_NS_BE: 0xa1b23c4d,   // nanosecond stamps
    PCAP_NS_LE: 0x4d3cb2a1,
    PCAP_MODIFIED: 0xa1b2cd34, // pre-2.4 "modified" variant - explicitly unsupported
    PCAPNG_SHB: 0x0a0d0d0a
  };

  const PCAPNG_BOM = 0x1a2b3c4d;
  const BLOCK = {
    IDB: 0x00000001,
    PACKET: 0x00000002,        // obsolete Packet Block - unsupported
    SPB: 0x00000003,
    NRB: 0x00000004,
    ISB: 0x00000005,
    EPB: 0x00000006,
    DSB: 0x0000000a,
    CUSTOM: 0x00000bad,
    CUSTOM_LOCAL: 0x40000bad
  };

  const LINKTYPE_ETHERNET = 1;
  const ETHERTYPE = { IPV4: 0x0800, ARP: 0x0806, IPV6: 0x86dd, VLAN: 0x8100, QINQ: 0x88a8, VLAN_9100: 0x9100 };

  // -------------------------------------------------------------------------
  // errors and small helpers
  // -------------------------------------------------------------------------
  function fail(code, message, extra) {
    const error = { code, message };
    if (extra) for (const key of Object.keys(extra)) error[key] = extra[key];
    return { ok: false, error };
  }
  const succeed = value => ({ ok: true, value });

  function isBytes(value) {
    return value instanceof Uint8Array ||
      (typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView(value));
  }
  function toBytes(value) {
    if (value instanceof Uint8Array) return value;
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }

  function hexByte(n) { return n.toString(16).padStart(2, '0'); }
  function macToString(bytes, offset) {
    const parts = [];
    for (let i = 0; i < 6; i++) parts.push(hexByte(bytes[offset + i]));
    return parts.join(':');
  }
  function ipv4ToString(bytes, offset) {
    return bytes[offset] + '.' + bytes[offset + 1] + '.' + bytes[offset + 2] + '.' + bytes[offset + 3];
  }

  function truncateString(text) {
    if (typeof text !== 'string') return text;
    // bound stored strings; multibyte-safe-ish truncation with a marker
    if (text.length <= LIMITS.maxStringBytes) return text;
    return text.slice(0, LIMITS.maxStringBytes - 1) + '\u2026';
  }

  // -------------------------------------------------------------------------
  // timestamp formatting (never claims more precision than the file carries)
  // -------------------------------------------------------------------------
  function pad(n, width) { return String(n).padStart(width, '0'); }

  function formatEpoch(seconds, fractionDigits, fractionValue) {
    const date = new Date(seconds * 1000);
    if (!isFinite(seconds) || isNaN(date.getTime())) return null;
    const text = date.getUTCFullYear() + '-' + pad(date.getUTCMonth() + 1, 2) + '-' + pad(date.getUTCDate(), 2) +
      ' ' + pad(date.getUTCHours(), 2) + ':' + pad(date.getUTCMinutes(), 2) + ':' + pad(date.getUTCSeconds(), 2);
    if (fractionDigits > 0) {
      return text + '.' + pad(fractionValue, fractionDigits);
    }
    return text;
  }

  function timestampFromPcap(tsSec, tsFrac, nanosecond) {
    const maxFrac = nanosecond ? 1e9 : 1e6;
    const unit = nanosecond ? 'nanosecond' : 'microsecond';
    if (tsFrac >= maxFrac) {
      return {
        kind: nanosecond ? 'pcap-ns' : 'pcap-us', seconds: null, fractionDigits: 0, exact: false,
        text: 'invalid timestamp fraction ' + tsFrac + ' (must be < ' + maxFrac + ' for a ' + unit + ' file)'
      };
    }
    const digits = nanosecond ? 9 : 6;
    const text = formatEpoch(tsSec, digits, tsFrac);
    return {
      kind: nanosecond ? 'pcap-ns' : 'pcap-us',
      seconds: tsSec, fractionDigits: digits, exact: true,
      text: text ? text + ' UTC' : 'timestamp out of displayable range (' + tsSec + ')'
    };
  }

  function timestampFromPcapng(rawUnitsBig, tsresol, tsoffsetSeconds) {
    // rawUnitsBig: the EPB tick count as a BigInt (High*2^32 + Low), exact.
    // The declared resolution is used exactly as declared - base 10 or base 2,
    // exponent 0..127 - and is never replaced by a different scale.
    // Fix round 2: raw ticks and the signed if_tsoffset are kept as BigInt
    // through the resolution-aware quotient/remainder conversion. A large raw
    // tick count is never pre-rejected: when the quotient and remainder scale
    // down (or cancel with a large negative offset) into an exact displayable
    // time, the exact display is returned. Only a result whose final seconds
    // cannot be represented exactly (outside 2^53-1) or cannot be displayed
    // by Date is reported out-of-range with seconds:null/exact:false, so no
    // rounded numeric seconds value is ever exported as exact.
    const base = tsresol && tsresol.base === 2 ? 2 : 10;
    const exponent = tsresol && Number.isInteger(tsresol.exponent) ? tsresol.exponent : 6;
    let offsetBig = 0n;
    if (typeof tsoffsetSeconds === 'bigint') offsetBig = tsoffsetSeconds;
    else if (typeof tsoffsetSeconds === 'string' && /^-?\d+$/.test(tsoffsetSeconds.trim())) {
      try { offsetBig = BigInt(tsoffsetSeconds.trim()); } catch (e) { offsetBig = 0n; }
    } else if (typeof tsoffsetSeconds === 'number' && Number.isFinite(tsoffsetSeconds)) {
      offsetBig = BigInt(Math.trunc(tsoffsetSeconds));
    }
    const scale = base === 2 ? (1n << BigInt(exponent)) : (10n ** BigInt(exponent));
    const MAX_SAFE_BIG = 9007199254740991n;
    const secondsBig = rawUnitsBig / scale;      // raw is non-negative: exact floor
    const remainderBig = rawUnitsBig % scale;
    if (base === 10 && exponent <= 9) {
      // exact decimal display with the declared number of fraction digits
      const totalSecondsBig = secondsBig + offsetBig;
      if (totalSecondsBig > MAX_SAFE_BIG || totalSecondsBig < -MAX_SAFE_BIG) {
        return { kind: 'pcapng', seconds: null, fractionDigits: 0, exact: false, text: 'timestamp out of displayable range' };
      }
      const seconds = Number(totalSecondsBig);
      const fraction = Number(remainderBig);
      const text = formatEpoch(seconds, exponent, fraction);
      if (!text) {
        return { kind: 'pcapng', seconds: null, fractionDigits: 0, exact: false, text: 'timestamp out of displayable range' };
      }
      return {
        kind: 'pcapng', seconds, fractionDigits: exponent, exact: true,
        text: text + ' UTC'
      };
    }
    // binary resolution, or a decimal resolution finer than the exact display
    // range: the tick count is converted to milliseconds (rounded) and clearly
    // marked approximate; the declared resolution is stated in the text.
    const millisBig = (remainderBig * 1000n + scale / 2n) / scale;
    let totalSecondsBig = secondsBig + offsetBig;
    let msBig = millisBig;
    if (msBig >= 1000n) { totalSecondsBig += 1n; msBig -= 1000n; }
    if (totalSecondsBig > MAX_SAFE_BIG || totalSecondsBig < -MAX_SAFE_BIG) {
      return { kind: 'pcapng', seconds: null, fractionDigits: 0, exact: false, text: 'timestamp out of displayable range' };
    }
    const secAdj = Number(totalSecondsBig);
    const msAdj = Number(msBig);
    const text = formatEpoch(secAdj, 3, msAdj);
    const unitText = base === 2 ? '2^-' + exponent + ' s units' : '10^-' + exponent + ' s units';
    if (!text) {
      return { kind: 'pcapng', seconds: null, fractionDigits: 0, exact: false, text: 'timestamp out of displayable range' };
    }
    return {
      kind: 'pcapng', seconds: secAdj, fractionDigits: 3, exact: false,
      text: '~' + text + ' UTC (approx, ' + unitText + ')'
    };
  }

  // -------------------------------------------------------------------------
  // capture scaffold
  // -------------------------------------------------------------------------
  function makeCapture(format, endianLabel) {
    return {
      format,
      endianLabel,
      fileBytes: 0,
      pcap: null,
      sections: [],
      packets: [],
      counts: { seen: 0, decoded: 0, unsupported: 0, rejected: 0, malformed: 0, truncated: 0, unsupportedBlocks: 0, unsupportedOptions: 0, malformedOptions: 0 },
      warnings: [],
      warningsTruncated: false,
      coverage: { limited: false, reasons: [] }
    };
  }

  function addWarning(capture, code, message, extra) {
    const isLimitWarning = code.indexOf('W_LIMIT_') === 0;
    if (capture.warnings.length >= LIMITS.maxWarnings) {
      // Cap reached. Limit warnings still matter (they explain truncated
      // coverage), so they displace the oldest routine warning.
      if (!isLimitWarning) return;
      const dropIndex = capture.warnings.findIndex(item => item.code.indexOf('W_LIMIT_') !== 0);
      if (dropIndex === -1) return;
      capture.warnings.splice(dropIndex, 1);
    } else if (capture.warnings.length >= LIMITS.maxWarnings - 1 && !isLimitWarning) {
      if (!capture.warningsTruncated) {
        capture.warningsTruncated = true;
        capture.warnings.push({ code: 'W_LIMIT_WARNINGS', message: 'Warning limit reached (' + LIMITS.maxWarnings + '); further warnings suppressed.' });
      }
      return;
    }
    const warning = { code, message };
    if (extra) for (const key of Object.keys(extra)) warning[key] = extra[key];
    capture.warnings.push(warning);
  }

  function limitCoverage(capture, reason) {
    capture.coverage.limited = true;
    if (!capture.coverage.reasons.includes(reason)) capture.coverage.reasons.push(reason);
  }

  function finishCoverage(capture) {
    const c = capture.counts;
    if (c.unsupported > 0) limitCoverage(capture, c.unsupported + ' packet(s) were outside the supported subset (not decoded)');
    if (c.rejected > 0) limitCoverage(capture, c.rejected + ' packet record(s) were rejected by validation');
    if (c.malformed > 0) limitCoverage(capture, c.malformed + ' packet(s) had malformed protocol payloads');
    if (c.truncated > 0) limitCoverage(capture, c.truncated + ' packet(s) are truncated by the capture snapshot length');
    if (c.unsupportedBlocks > 0) limitCoverage(capture, c.unsupportedBlocks + ' pcapng block(s) outside the supported subset were skipped by length');
    if (c.unsupportedOptions > 0) limitCoverage(capture, c.unsupportedOptions + ' option(s) inside supported blocks were outside the supported subset (content not interpreted)');
    if (c.malformedOptions > 0) limitCoverage(capture, c.malformedOptions + ' option(s) had malformed framing (length, padding or end marker)');
    return capture;
  }

  // -------------------------------------------------------------------------
  // classic pcap (RFC-lesson sources: pcap-savefile(5); draft-gharris-opsawg-pcap-01)
  // -------------------------------------------------------------------------
  function parsePcap(bytes, view, magic) {
    const le = magic === MAGIC.PCAP_US_LE || magic === MAGIC.PCAP_NS_LE;
    const nanosecond = magic === MAGIC.PCAP_NS_LE || magic === MAGIC.PCAP_NS_BE;
    if (bytes.length < 24) return fail('E_HEADER_TRUNCATED', 'pcap file header needs 24 bytes, got ' + bytes.length, { offset: 0 });
    const versionMajor = view.getUint16(4, le);
    const versionMinor = view.getUint16(6, le);
    if (versionMajor !== 2) return fail('E_VERSION', 'unsupported pcap version ' + versionMajor + '.' + versionMinor + ' (only major 2 is supported)', { offset: 4 });
    const snaplen = view.getUint32(16, le);
    if (snaplen === 0) return fail('E_SNAPLEN', 'pcap snaplen is 0; the format forbids zero', { offset: 16 });
    const linkField = view.getUint32(20, le);
    const linkType = linkField & 0xffff;
    const reservedBits = (linkField >>> 16) & 0x3ff;
    const fcsPresent = ((linkField >>> 26) & 1) === 1;
    const fcsLen = (linkField >>> 28) & 0xf;

    const capture = makeCapture('pcap', le ? 'little-endian' : 'big-endian');
    capture.fileBytes = bytes.length;
    capture.pcap = { versionMajor, versionMinor, snaplen, linkType, timestampResolution: nanosecond ? 'nanosecond' : 'microsecond', fcsPresent, fcsLen };
    capture.sections.push({
      index: 0, endian: le ? 'le' : 'be', versionMajor, versionMinor,
      interfaces: [{ id: 0, linkType, snaplen, name: null, tsresol: { base: 10, exponent: nanosecond ? 9 : 6 }, tsoffsetSeconds: 0 }]
    });
    if (reservedBits !== 0) addWarning(capture, 'W_LINKTYPE_BITS', 'LinkType field carries non-zero reserved bits (0x' + linkField.toString(16) + '); reserved bits MUST be zero', { fileOffset: 20 });

    let offset = 24;
    while (offset < bytes.length) {
      if (capture.packets.length >= LIMITS.maxPackets) {
        addWarning(capture, 'W_LIMIT_PACKETS', 'Packet limit reached (' + LIMITS.maxPackets + '); the rest of the file was not parsed');
        limitCoverage(capture, 'packet limit reached (' + LIMITS.maxPackets + ')');
        break;
      }
      if (offset + 16 > bytes.length) {
        addWarning(capture, 'W_FILE_TRUNCATED', 'File ends inside a packet record header at byte ' + offset, { fileOffset: offset });
        limitCoverage(capture, 'file ends inside a packet record');
        break;
      }
      const tsSec = view.getUint32(offset, le);
      const tsFrac = view.getUint32(offset + 4, le);
      const inclLen = view.getUint32(offset + 8, le);
      const origLen = view.getUint32(offset + 12, le);
      capture.counts.seen += 1;
      const packet = {
        index: capture.packets.length,
        fileOffset: offset,
        sectionIndex: 0,
        interfaceId: 0,
        blockType: 'packet-record',
        vlanIds: [],
        caplen: inclLen,
        origlen: origLen,
        truncated: inclLen < origLen,
        status: 'unsupported',
        reason: null,
        protocol: 'unknown',
        details: null,
        timestamp: timestampFromPcap(tsSec, tsFrac, nanosecond)
      };
      if (!packet.timestamp.exact && /invalid timestamp fraction/.test(packet.timestamp.text)) {
        addWarning(capture, 'W_TIMESTAMP_FRACTION', 'Packet ' + packet.index + ': ' + packet.timestamp.text, { packetIndex: packet.index, fileOffset: offset });
      }
      if (inclLen > origLen) {
        packet.status = 'rejected';
        packet.reason = 'record-lengths';
        capture.counts.rejected += 1;
        addWarning(capture, 'W_RECORD_LENGTHS', 'Packet ' + packet.index + ': captured length ' + inclLen + ' exceeds original length ' + origLen + ' (draft-gharris-opsawg-pcap-01 §5)', { packetIndex: packet.index, fileOffset: offset });
        capture.packets.push(packet);
        offset += 16 + inclLen;
        continue;
      }
      if (offset + 16 + inclLen > bytes.length) {
        packet.status = 'rejected';
        packet.reason = 'file-truncated';
        capture.counts.rejected += 1;
        addWarning(capture, 'W_FILE_TRUNCATED', 'Packet ' + packet.index + ': declared ' + inclLen + ' captured bytes but only ' + (bytes.length - offset - 16) + ' remain', { packetIndex: packet.index, fileOffset: offset });
        limitCoverage(capture, 'file ends inside packet data');
        capture.packets.push(packet);
        break;
      }
      let data = bytes.subarray(offset + 16, offset + 16 + inclLen);
      if (snaplen > 0 && inclLen > snaplen) {
        data = data.subarray(0, snaplen);
        packet.caplen = snaplen;
        // A snapshot-length prefix is decodable but not full coverage: the
        // original record was longer than snaplen, so mark truncated.
        packet.truncated = true;
        addWarning(capture, 'W_SNAPLEN_CAP', 'Packet ' + packet.index + ': captured length ' + inclLen + ' exceeds snaplen ' + snaplen + '; delivered at most snaplen bytes (pcap-savefile(5))', { packetIndex: packet.index, fileOffset: offset });
      }
      if (packet.truncated) capture.counts.truncated += 1;
      decodeFrame(capture, packet, data, linkType);
      capture.packets.push(packet);
      offset += 16 + inclLen;
    }
    return succeed(finishCoverage(capture));
  }

  // -------------------------------------------------------------------------
  // frame decoding: Ethernet -> VLAN -> ARP / IPv4 -> UDP -> DHCP / mDNS
  // -------------------------------------------------------------------------
  const u16 = (b, o) => (b[o] << 8) | b[o + 1];
  const u32 = (b, o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;

  function markUnsupported(capture, packet, reason, protocol) {
    packet.status = 'unsupported';
    packet.reason = reason;
    if (protocol) packet.protocol = protocol;
    capture.counts.unsupported += 1;
  }
  function markMalformed(capture, packet, reason, code, message) {
    packet.status = 'malformed';
    packet.reason = reason;
    capture.counts.malformed += 1;
    if (code) addWarning(capture, code, message, { packetIndex: packet.index, fileOffset: packet.fileOffset });
  }

  function decodeFrame(capture, packet, data, linkType) {
    if (linkType !== LINKTYPE_ETHERNET) return markUnsupported(capture, packet, 'linktype-unsupported');
    if (data.length === 0) {
      addWarning(capture, 'W_EMPTY_RECORD', 'Packet ' + packet.index + ' carries zero captured bytes', { packetIndex: packet.index, fileOffset: packet.fileOffset });
      return markUnsupported(capture, packet, 'empty');
    }
    if (data.length < 14) {
      addWarning(capture, 'W_TRUNCATED_PAYLOAD', 'Packet ' + packet.index + ' is shorter than an Ethernet header (' + data.length + ' bytes)', { packetIndex: packet.index, fileOffset: packet.fileOffset });
      return markUnsupported(capture, packet, 'truncated-payload');
    }
    let ethertype = u16(data, 12);
    if (ethertype <= 1500) return markUnsupported(capture, packet, 'llc'); // 802.3 length field => LLC frame
    let offset = 14;
    const vlans = [];
    while (ethertype === ETHERTYPE.VLAN || ethertype === ETHERTYPE.QINQ || ethertype === ETHERTYPE.VLAN_9100) {
      if (vlans.length >= LIMITS.maxVlanTags) return markUnsupported(capture, packet, 'vlan-nested');
      if (offset + 4 > data.length) {
        addWarning(capture, 'W_TRUNCATED_PAYLOAD', 'Packet ' + packet.index + ' ends inside a VLAN tag', { packetIndex: packet.index, fileOffset: packet.fileOffset });
        return markUnsupported(capture, packet, 'truncated-payload');
      }
      vlans.push(u16(data, offset) & 0x0fff);
      ethertype = u16(data, offset + 2);
      offset += 4;
    }
    packet.vlanIds = vlans;
    const payload = data.subarray(offset);
    if (ethertype === ETHERTYPE.ARP) return decodeArp(capture, packet, payload);
    if (ethertype === ETHERTYPE.IPV4) return decodeIpv4(capture, packet, payload);
    if (ethertype === ETHERTYPE.IPV6) return markUnsupported(capture, packet, 'ipv6', 'ipv6');
    return markUnsupported(capture, packet, 'non-ip');
  }

  function decodeArp(capture, packet, payload) {
    packet.protocol = 'arp';
    if (payload.length < 8) {
      addWarning(capture, 'W_TRUNCATED_PAYLOAD', 'Packet ' + packet.index + ': ARP payload is ' + payload.length + ' bytes, needs at least 8', { packetIndex: packet.index, fileOffset: packet.fileOffset });
      return markUnsupported(capture, packet, 'truncated-payload');
    }
    const hrd = u16(payload, 0);
    const pro = u16(payload, 2);
    const hln = payload[4];
    const pln = payload[5];
    const op = u16(payload, 6);
    // Variant fields are checked before the length check: a non-Ethernet/IPv4
    // ARP has different address widths and must be classified, not mis-sized.
    if (hrd !== 1 || pro !== ETHERTYPE.IPV4 || hln !== 6 || pln !== 4) {
      return markUnsupported(capture, packet, 'arp-variant');
    }
    const total = 8 + 2 * hln + 2 * pln;
    if (payload.length < total) {
      addWarning(capture, 'W_TRUNCATED_PAYLOAD', 'Packet ' + packet.index + ': ARP payload is ' + payload.length + ' bytes, needs ' + total, { packetIndex: packet.index, fileOffset: packet.fileOffset });
      return markUnsupported(capture, packet, 'truncated-payload');
    }
    if (op !== 1 && op !== 2) return markUnsupported(capture, packet, 'rarp');
    const senderMac = macToString(payload, 8);
    const senderIp = ipv4ToString(payload, 14);
    const targetMac = macToString(payload, 18);
    const targetIp = ipv4ToString(payload, 24);
    const probe = op === 1 && senderIp === '0.0.0.0';
    const gratuitous = op === 2 && senderIp === targetIp;
    packet.status = 'decoded';
    packet.details = {
      op,
      opName: op === 1 ? 'request' : 'reply',
      senderMac, senderIp, targetMac, targetIp, probe, gratuitous
    };
    capture.counts.decoded += 1;
  }

  function decodeIpv4(capture, packet, payload) {
    packet.protocol = 'ipv4';
    if (payload.length < 20) {
      addWarning(capture, 'W_TRUNCATED_PAYLOAD', 'Packet ' + packet.index + ': IPv4 payload is ' + payload.length + ' bytes, needs 20', { packetIndex: packet.index, fileOffset: packet.fileOffset });
      return markUnsupported(capture, packet, 'truncated-payload');
    }
    const version = payload[0] >>> 4;
    const ihl = (payload[0] & 0x0f) * 4;
    const totalLen = u16(payload, 2);
    const fragField = u16(payload, 6);
    const moreFragments = (fragField & 0x2000) !== 0;
    const fragmentOffset = fragField & 0x1fff;
    if (version !== 4 || ihl < 20 || totalLen < ihl) {
      return markMalformed(capture, packet, 'ip-length-invalid', 'W_IP_LENGTH', 'Packet ' + packet.index + ': invalid IPv4 header (version ' + version + ', IHL ' + ihl + ', total length ' + totalLen + ')');
    }
    if (moreFragments || fragmentOffset !== 0) {
      return markUnsupported(capture, packet, 'fragmented', 'ipv4-fragment');
    }
    if (totalLen > payload.length) {
      addWarning(capture, 'W_IP_LENGTH', 'Packet ' + packet.index + ': IPv4 total length ' + totalLen + ' exceeds the captured ' + payload.length + ' bytes', { packetIndex: packet.index, fileOffset: packet.fileOffset });
      return markUnsupported(capture, packet, 'truncated-payload');
    }
    const protocolNumber = payload[9];
    if (protocolNumber !== 17) return markUnsupported(capture, packet, 'ipv4-other-protocol', 'ipv4-other');
    const datagram = payload.subarray(ihl, totalLen);
    return decodeUdp(capture, packet, datagram);
  }

  function decodeUdp(capture, packet, datagram) {
    if (datagram.length < 8) {
      addWarning(capture, 'W_TRUNCATED_PAYLOAD', 'Packet ' + packet.index + ': UDP header is ' + datagram.length + ' bytes, needs 8', { packetIndex: packet.index, fileOffset: packet.fileOffset });
      return markUnsupported(capture, packet, 'truncated-payload');
    }
    const srcPort = u16(datagram, 0);
    const dstPort = u16(datagram, 2);
    const udpLen = u16(datagram, 4);
    if (udpLen < 8 || udpLen > datagram.length) {
      return markMalformed(capture, packet, 'udp-length-mismatch', 'W_UDP_LENGTH', 'Packet ' + packet.index + ': UDP length ' + udpLen + ' does not fit the ' + datagram.length + ' available bytes');
    }
    const udpData = datagram.subarray(8, udpLen); // trailing bytes beyond udpLen are padding, ignored
    packet.transport = { srcPort, dstPort, length: udpLen };
    if ((srcPort === 67 && dstPort === 68) || (srcPort === 68 && dstPort === 67)) return decodeDhcp(capture, packet, udpData, srcPort, dstPort);
    if (srcPort === 5353 && dstPort === 5353) return decodeMdns(capture, packet, udpData, srcPort, dstPort);
    return markUnsupported(capture, packet, 'ipv4-other-protocol', 'ipv4-udp-other');
  }

  // -------------------------------------------------------------------------
  // DHCP (RFC 2131 message format; RFC 2132 options)
  // -------------------------------------------------------------------------
  const DHCP_MESSAGE_TYPES = { 1: 'DISCOVER', 2: 'OFFER', 3: 'REQUEST', 4: 'DECLINE', 5: 'ACK', 6: 'NAK', 7: 'RELEASE', 8: 'INFORM' };

  function decodeDhcp(capture, packet, data, srcPort, dstPort) {
    packet.protocol = 'dhcp';
    if (data.length < 236) {
      addWarning(capture, 'W_TRUNCATED_PAYLOAD', 'Packet ' + packet.index + ': BOOTP/DHCP header is ' + data.length + ' bytes, needs 236', { packetIndex: packet.index, fileOffset: packet.fileOffset });
      return markUnsupported(capture, packet, 'truncated-payload');
    }
    const op = data[0];
    const htype = data[1];
    const hlen = data[2];
    const xid = u32(data, 4);
    const ciaddr = ipv4ToString(data, 12);
    const yiaddr = ipv4ToString(data, 16);
    const siaddr = ipv4ToString(data, 20);
    const giaddr = ipv4ToString(data, 24);
    const clientMac = hlen === 6 ? macToString(data, 28) : 'hwaddr(' + hlen + ' bytes)';
    const details = {
      op, opName: op === 1 ? 'BOOTREQUEST' : op === 2 ? 'BOOTREPLY' : 'op-' + op,
      htype, hlen, xid, clientMac, ciaddr, yiaddr, siaddr, giaddr,
      messageType: null, messageTypeName: null, hostname: null, requestedIp: null,
      serverId: null, leaseSeconds: null, overload: null, malformed: false,
      direction: srcPort === 68 ? 'client-to-server' : 'server-to-client'
    };
    packet.details = details;
    if (data.length < 240 || data[236] !== 0x63 || data[237] !== 0x82 || data[238] !== 0x53 || data[239] !== 0x63) {
      details.malformed = true;
      packet.details = details;
      return markMalformed(capture, packet, 'dhcp-no-cookie', 'W_DHCP_COOKIE', 'Packet ' + packet.index + ': BOOTP/DHCP magic cookie 0x63825363 is missing; options were not parsed');
    }
    let offset = 240;
    let optionError = false;
    while (offset < data.length) {
      const code = data[offset];
      if (code === 0) { offset += 1; continue; }              // pad
      if (code === 255) { offset += 1; break; }              // end
      if (offset + 1 >= data.length) { optionError = true; break; }
      const length = data[offset + 1];
      if (offset + 2 + length > data.length) { optionError = true; break; }
      const value = data.subarray(offset + 2, offset + 2 + length);
      switch (code) {
        case 53: if (length >= 1) { details.messageType = value[0]; details.messageTypeName = DHCP_MESSAGE_TYPES[value[0]] || ('UNKNOWN(' + value[0] + ')'); if (!DHCP_MESSAGE_TYPES[value[0]]) addWarning(capture, 'W_DHCP_MSG_TYPE', 'Packet ' + packet.index + ': unknown DHCP message type ' + value[0], { packetIndex: packet.index, fileOffset: packet.fileOffset }); } break;
        case 12: details.hostname = truncateString(decodeUtf8Bounded(value, 0, value.length)); break;
        case 50: if (length === 4) details.requestedIp = ipv4ToString(value, 0); break;
        case 54: if (length === 4) details.serverId = ipv4ToString(value, 0); break;
        case 51: if (length === 4) details.leaseSeconds = u32(value, 0); break;
        case 52: if (length === 1) { details.overload = value[0]; addWarning(capture, 'W_DHCP_OVERLOAD', 'Packet ' + packet.index + ': DHCP option overload (' + value[0] + ') is outside the supported subset; sname/file option space is not parsed', { packetIndex: packet.index, fileOffset: packet.fileOffset }); } break;
        case 61: details.clientIdPresent = true; break;
        case 55: details.parameterRequestList = Array.from(value).slice(0, 64); break;
        default: break; // unknown options are skipped by their declared length
      }
      offset += 2 + length;
    }
    if (optionError) {
      details.malformed = true;
      return markMalformed(capture, packet, 'dhcp-option-overrun', 'W_DHCP_OPTION_LEN', 'Packet ' + packet.index + ': a DHCP option declares more bytes than remain; options after that point were not parsed');
    }
    packet.status = 'decoded';
    capture.counts.decoded += 1;
  }

  // -------------------------------------------------------------------------
  // DNS / mDNS (RFC 1035 §4.1 + §4.1.4; RFC 6762 §5, §10.2)
  // -------------------------------------------------------------------------
  const DNS_TYPES = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 255: 'ANY' };

  function decodeDnsName(bytes, start, messageEnd) {
    let offset = start;
    let name = '';
    let pointers = 0;
    const visited = new Set();
    let jumps = 0;
    let end = null;
    while (true) {
      if (offset + 1 > messageEnd) return { error: 'dns-truncated' };
      const lengthByte = bytes[offset];
      if (lengthByte === 0) { offset += 1; if (end === null) end = offset; break; }
      if ((lengthByte & 0xc0) === 0xc0) {
        if (offset + 2 > messageEnd) return { error: 'dns-truncated' };
        const pointer = ((lengthByte & 0x3f) << 8) | bytes[offset + 1];
        if (pointer >= messageEnd) return { error: 'dns-pointer-range' };
        if (visited.has(pointer) || pointer >= offset) return { error: 'dns-loop' }; // pointers must reference a PRIOR occurrence
        visited.add(pointer);
        pointers += 1;
        if (++jumps > LIMITS.maxDnsJumps) return { error: 'dns-loop' };
        if (end === null) end = offset + 2;
        offset = pointer;
        continue;
      }
      if (lengthByte > 63) return { error: 'dns-label-length' };
      if (offset + 1 + lengthByte > messageEnd) return { error: 'dns-truncated' };
      let label = '';
      for (let i = 0; i < lengthByte; i++) label += String.fromCharCode(bytes[offset + 1 + i]);
      name += (name ? '.' : '') + label;
      if (name.length > 253) return { error: 'dns-name-length' }; // 255 octets incl. length bytes/root
      offset += 1 + lengthByte;
    }
    return { name, next: end, pointers };
  }

  function decodeMdns(capture, packet, data, srcPort, dstPort) {
    packet.protocol = 'mdns';
    if (data.length < 12) {
      addWarning(capture, 'W_TRUNCATED_PAYLOAD', 'Packet ' + packet.index + ': DNS header is ' + data.length + ' bytes, needs 12', { packetIndex: packet.index, fileOffset: packet.fileOffset });
      return markUnsupported(capture, packet, 'truncated-payload');
    }
    const id = u16(data, 0);
    const flags = u16(data, 2);
    const isResponse = (flags & 0x8000) !== 0;
    const counts = { questions: u16(data, 4), answers: u16(data, 6), authority: u16(data, 8), additional: u16(data, 10) };
    const details = { id, isResponse, flags, counts, questions: [], answers: [], pointerCount: 0, truncatedRecords: 0 };
    packet.details = details;
    let offset = 12;
    const messageEnd = data.length;

    const failName = (error) => {
      const warningCode = {
        'dns-loop': 'W_DNS_LOOP', 'dns-pointer-range': 'W_DNS_POINTER_RANGE',
        'dns-label-length': 'W_DNS_LABEL_LENGTH', 'dns-name-length': 'W_DNS_NAME_LENGTH',
        'dns-truncated': 'W_DNS_TRUNCATED'
      }[error] || 'W_DNS_TRUNCATED';
      return markMalformed(capture, packet, error, warningCode, 'Packet ' + packet.index + ': DNS name error (' + error + ')');
    };

    for (let i = 0; i < counts.questions; i++) {
      if (offset + 4 > messageEnd) return failName('dns-truncated');
      const named = decodeDnsName(data, offset, messageEnd);
      if (named.error) return failName(named.error);
      details.pointerCount += named.pointers;
      offset = named.next;
      if (offset + 4 > messageEnd) return failName('dns-truncated');
      const type = u16(data, offset);
      const rrclass = u16(data, offset + 2);
      offset += 4;
      details.questions.push({ name: truncateString(named.name), type, typeName: DNS_TYPES[type] || ('TYPE' + type), qu: (rrclass & 0x8000) !== 0 });
    }
    for (let i = 0; i < counts.answers + counts.authority + counts.additional; i++) {
      if (i >= LIMITS.maxAnswersPerMessage) {
        details.truncatedRecords = counts.answers + counts.authority + counts.additional - i;
        addWarning(capture, 'W_LIMIT_ANSWERS', 'Packet ' + packet.index + ': record limit reached (' + LIMITS.maxAnswersPerMessage + '); remaining records were not decoded', { packetIndex: packet.index, fileOffset: packet.fileOffset });
        break;
      }
      if (offset + 10 > messageEnd) return failName('dns-truncated');
      const named = decodeDnsName(data, offset, messageEnd);
      if (named.error) return failName(named.error);
      details.pointerCount += named.pointers;
      offset = named.next;
      if (offset + 10 > messageEnd) return failName('dns-truncated');
      const type = u16(data, offset);
      const rrclass = u16(data, offset + 2);
      const ttl = u32(data, offset + 4);
      const rdlength = u16(data, offset + 8);
      offset += 10;
      if (offset + rdlength > messageEnd) return failName('dns-truncated');
      const rdata = data.subarray(offset, offset + rdlength);
      offset += rdlength;
      const answer = {
        name: truncateString(named.name), type, typeName: DNS_TYPES[type] || ('TYPE' + type),
        cacheFlush: (rrclass & 0x8000) !== 0, ttl
      };
      if (type === 1 && rdlength === 4) answer.address = ipv4ToString(rdata, 0);
      else if (type === 28 && rdlength === 16) answer.address = Array.from(rdata).map(hexByte).join('').replace(/(.{4})(?=.)/g, '$1:');
      else if (type === 12 || type === 2 || type === 5) {
        const target = decodeDnsName(data, offset - rdlength, messageEnd);
        if (!target.error) answer.target = truncateString(target.name);
      } else if (type === 33 && rdlength >= 6) {
        answer.priority = u16(rdata, 0); answer.weight = u16(rdata, 2); answer.port = u16(rdata, 4);
        const target = decodeDnsName(data, offset - rdlength + 6, messageEnd);
        if (!target.error) answer.target = truncateString(target.name);
      } else if (type === 16) {
        const strings = [];
        let cursor = 0;
        while (cursor < rdlength && strings.length < 16) {
          const len = rdata[cursor];
          if (cursor + 1 + len > rdlength) break;
          strings.push(truncateString(decodeUtf8Bounded(rdata, cursor + 1, cursor + 1 + len)));
          cursor += 1 + len;
        }
        answer.text = strings;
      } else {
        answer.rdlength = rdlength; // rdata of unknown types is not retained
      }
      details.answers.push(answer);
    }
    packet.status = 'decoded';
    capture.counts.decoded += 1;
  }

  // -------------------------------------------------------------------------
  // entry point
  // -------------------------------------------------------------------------
  function parseCapture(input) {
    if (!isBytes(input)) return fail('E_INPUT', 'expected a Uint8Array of capture bytes');
    const bytes = toBytes(input);
    if (bytes.length === 0) return fail('E_EMPTY', 'empty input: a capture file needs at least a 4-byte magic');
    if (bytes.length > LIMITS.maxBytes) return fail('E_TOO_LARGE', 'file is ' + bytes.length + ' bytes; the limit is ' + LIMITS.maxBytes + ' bytes');
    if (bytes.length < 4) return fail('E_HEADER_TRUNCATED', 'file is shorter than the 4-byte magic number');
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const magic = view.getUint32(0, false);
    if (magic === MAGIC.PCAP_MODIFIED) {
      return fail('E_MAGIC', 'this is a pre-2.4 "modified" pcap variant (0xa1b2cd34); it is explicitly outside the supported subset', { offset: 0 });
    }
    if (magic === MAGIC.PCAPNG_SHB) return parsePcapng(bytes, view);
    // A file that starts with a known pcapng block type (in either byte order)
    // is a pcapng stream whose leading Section Header Block is missing or
    // damaged; report that precisely instead of "unrecognized magic".
    const swapped = ((magic & 0xff) << 24) | ((magic & 0xff00) << 8) | ((magic >>> 8) & 0xff00) | ((magic >>> 24) & 0xff);
    const PCAPNG_LIKE = [BLOCK.IDB, BLOCK.PACKET, BLOCK.SPB, BLOCK.NRB, BLOCK.ISB, BLOCK.EPB, BLOCK.DSB, BLOCK.CUSTOM, BLOCK.CUSTOM_LOCAL];
    if (PCAPNG_LIKE.includes(magic) || PCAPNG_LIKE.includes(swapped)) return parsePcapng(bytes, view);
    if (magic === MAGIC.PCAP_US_BE || magic === MAGIC.PCAP_US_LE || magic === MAGIC.PCAP_NS_BE || magic === MAGIC.PCAP_NS_LE) {
      return parsePcap(bytes, view, magic);
    }
    return fail('E_MAGIC', 'unrecognized file magic 0x' + magic.toString(16).padStart(8, '0') + '; not a supported pcap or pcapng file', { offset: 0 });
  }

  // -------------------------------------------------------------------------
  // pcapng (source: draft-tuexen-opsawg-pcapng-05)
  // -------------------------------------------------------------------------
  function readUint64(view, offset, le) {
    // A genuine single 64-bit field in section byte order (used only for the
    // SHB Section Length). The EPB timestamp pair is NOT such a field: it is
    // two separate 32-bit fields (Timestamp High then Timestamp Low), each in
    // the section's byte order (draft-tuexen-opsawg-pcapng-05 §4.3, Figure 11).
    const high = view.getUint32(le ? offset + 4 : offset, le);
    const low = view.getUint32(le ? offset : offset + 4, le);
    return high * 4294967296 + low;
  }
  function readInt64(view, offset, le) {
    const high = view.getInt32(le ? offset + 4 : offset, le);
    const low = view.getUint32(le ? offset : offset + 4, le);
    return high * 4294967296 + low;
  }
  function readInt64Big(view, offset, le) {
    // Signed 64-bit if_tsoffset in section byte order, kept exact as BigInt.
    // DataView has no signed-64 reader here; combine the two 32-bit halves.
    const high = BigInt(view.getInt32(offset + (le ? 4 : 0), le));
    const low = BigInt(view.getUint32(offset + (le ? 0 : 4), le));
    return high * 4294967296n + low;
  }
  function tsoffsetToJsonSafe(valueBig) {
    // JSON-safe storage for if_tsoffset: an exact Number while inside the
    // 53-bit safe range, otherwise the exact decimal string. Either form
    // satisfies String(stored) === String(original BigInt) and survives
    // JSON.stringify (a raw BigInt would throw and break reports).
    const MAX_SAFE_BIG = 9007199254740991n;
    if (valueBig >= -MAX_SAFE_BIG && valueBig <= MAX_SAFE_BIG) return Number(valueBig);
    return valueBig.toString();
  }

  function decodeUtf8Bounded(bytes, start, end) {
    let text = '';
    for (let i = start; i < end && i < start + LIMITS.maxStringBytes * 4; i++) {
      const b = bytes[i];
      if (b === 0) break;
      text += String.fromCharCode(b < 0x80 ? b : 0x3f); // ASCII-safe view; full UTF-8 not needed for fixture/documentation purposes
    }
    return truncateString(text);
  }

  // Option codes this subset actually interprets, per block type. Every other
  // option in a supported block is counted and warned by code (never by
  // content); a benign opt_endofopt (code 0, length 0) is not "unsupported".
  const IDB_SUPPORTED_OPTIONS = new Set([2, 9, 14]); // if_name, if_tsresol, if_tsoffset
  const NO_SUPPORTED_OPTIONS = new Set();            // SHB and EPB options are not interpreted

  function parsePcapngOptions(view, bytes, start, end, le, capture, context, supported) {
    const found = new Map();
    let offset = start;
    while (offset < end) {
      if (offset + 4 > end) {
        // trailing bytes too short for an option header (defensive: aligned
        // option areas cannot produce this, but a damaged block could)
        addWarning(capture, 'W_OPTION_PADDING', 'The ' + context + ' option area at byte ' + start + ' ends with ' + (end - offset) + ' trailing byte(s) that are too short for an option header', { fileOffset: offset });
        capture.counts.malformedOptions += 1;
        limitCoverage(capture, 'malformed option framing');
        break;
      }
      const code = view.getUint16(offset, le);
      const length = view.getUint16(offset + 2, le);
      if (code === 0) {
        if (length === 0) break; // benign opt_endofopt
        addWarning(capture, 'W_OPTION_END_MARKER', 'Option code 0 (end-of-options marker) in the ' + context + ' at byte ' + offset + ' declares ' + length + ' byte(s); it must declare length 0, so the remaining option area was not parsed', { fileOffset: offset });
        capture.counts.malformedOptions += 1;
        limitCoverage(capture, 'malformed option framing');
        break;
      }
      if (offset + 4 + length > end) {
        addWarning(capture, 'W_OPTION_LENGTH', 'Option ' + code + ' in the ' + context + ' at byte ' + offset + ' declares ' + length + ' bytes but only ' + (end - offset - 4) + ' remain', { fileOffset: offset });
        capture.counts.malformedOptions += 1;
        limitCoverage(capture, 'malformed option framing');
        break;
      }
      const paddedEnd = offset + 4 + ((length + 3) & ~3);
      if (paddedEnd > end) {
        addWarning(capture, 'W_OPTION_PADDING', 'Option ' + code + ' in the ' + context + ' at byte ' + offset + ' declares ' + length + ' byte(s) whose padding does not fit in the option area', { fileOffset: offset });
        capture.counts.malformedOptions += 1;
        limitCoverage(capture, 'malformed option framing');
        break;
      }
      found.set(code, { start: offset + 4, length });
      if (!supported.has(code)) {
        capture.counts.unsupportedOptions += 1;
        addWarning(capture, 'W_OPTION_UNSUPPORTED', 'Option code ' + code + ' (' + length + ' byte(s)) in the ' + context + ' at byte ' + offset + ' is unsupported in this subset; its content was not interpreted', { fileOffset: offset });
      }
      offset = paddedEnd;
    }
    return found;
  }

  function parsePcapng(bytes, view) {
    const capture = makeCapture('pcapng', 'mixed');
    capture.fileBytes = bytes.length;
    let offset = 0;
    let blocks = 0;
    let section = null;
    let sawShb = false;

    const closeSection = () => {
      if (!section) return;
      if (section.declaredLength !== null && section.declaredLength >= 0 && section.consumed !== section.declaredLength) {
        addWarning(capture, 'W_SECTION_LENGTH', 'Section ' + section.index + ' declares length ' + section.declaredLength + ' but its blocks consume ' + section.consumed + ' bytes', { fileOffset: section.offset });
        limitCoverage(capture, 'section length does not match its blocks');
      }
      section = null;
    };

    while (offset < bytes.length) {
      if (blocks++ >= LIMITS.maxBlocks) {
        addWarning(capture, 'W_LIMIT_BLOCKS', 'Block limit reached (' + LIMITS.maxBlocks + ')');
        limitCoverage(capture, 'block limit reached');
        break;
      }
      if (offset + 12 > bytes.length) {
        addWarning(capture, 'W_FILE_TRUNCATED', 'File ends inside a block header at byte ' + offset, { fileOffset: offset });
        limitCoverage(capture, 'file ends inside a block header');
        break;
      }
      const rawType = view.getUint32(offset, false);
      if (rawType === MAGIC.PCAPNG_SHB) {
        closeSection();
        if (offset + 16 > bytes.length) {
          addWarning(capture, 'W_FILE_TRUNCATED', 'File ends inside a Section Header Block at byte ' + offset, { fileOffset: offset });
          limitCoverage(capture, 'file ends inside a Section Header Block');
          break;
        }
        const bomBig = view.getUint32(offset + 8, false);
        let le;
        if (bomBig === PCAPNG_BOM) le = false;
        else if (view.getUint32(offset + 8, true) === PCAPNG_BOM) le = true;
        else return fail('E_BOM', 'Section Header Block at byte ' + offset + ' has byte-order magic 0x' + bomBig.toString(16).padStart(8, '0') + '; expected 0x1a2b3c4d', { offset: offset + 8 });
        const totalLength = view.getUint32(offset + 4, le);
        if (totalLength % 4 !== 0 || totalLength < 28) {
          addWarning(capture, 'W_BLOCK_LENGTH', 'Section Header Block at byte ' + offset + ' declares total length ' + totalLength + ' (must be a multiple of 4 and >= 28)', { fileOffset: offset });
          limitCoverage(capture, 'untrusted block length');
          break;
        }
        if (offset + totalLength > bytes.length) {
          addWarning(capture, 'W_FILE_TRUNCATED', 'Section Header Block at byte ' + offset + ' declares ' + totalLength + ' bytes but the file ends first', { fileOffset: offset });
          limitCoverage(capture, 'file ends inside a Section Header Block');
          break;
        }
        const trailer = view.getUint32(offset + totalLength - 4, le);
        if (trailer !== totalLength) {
          addWarning(capture, 'W_BLOCK_TRAILER', 'Section Header Block at byte ' + offset + ' trailer ' + trailer + ' disagrees with its length ' + totalLength, { fileOffset: offset });
          limitCoverage(capture, 'block trailer mismatch');
          break;
        }
        const major = view.getUint16(offset + 12, le);
        const minor = view.getUint16(offset + 14, le);
        if (major !== 1) return fail('E_VERSION', 'unsupported pcapng section version ' + major + '.' + minor + ' (only major 1 is supported)', { offset: offset + 12 });
        if (minor !== 0 && minor !== 2) addWarning(capture, 'W_SH_VERSION', 'Section ' + capture.sections.length + ' uses minor version ' + minor + '; readers treat only 0 and 2 as known', { fileOffset: offset + 14 });
        const sectionLengthRaw = readUint64(view, offset + 16, le);
        const declaredLength = sectionLengthRaw > 1e19 ? -1 : sectionLengthRaw; // 0xFFFF... = "not specified"
        if (capture.sections.length >= LIMITS.maxSections) {
          addWarning(capture, 'W_LIMIT_SECTIONS', 'Section limit reached (' + LIMITS.maxSections + ')');
          limitCoverage(capture, 'section limit reached');
          break;
        }
        section = {
          index: capture.sections.length, endian: le ? 'le' : 'be', versionMajor: major, versionMinor: minor,
          offset, declaredLength, consumed: 0, interfaces: []
        };
        capture.sections.push(section);
        if (capture.sections.length === 1) capture.endianLabel = le ? 'little-endian' : 'big-endian';
        sawShb = true;
        // The SHB option area starts after the 16-byte fixed part. Its options
        // are structurally framed and counted; none of them is interpreted.
        const shbOptionsStart = offset + 8 + 16;
        const shbOptionsEnd = offset + totalLength - 4;
        if (shbOptionsStart < shbOptionsEnd) {
          parsePcapngOptions(view, bytes, shbOptionsStart, shbOptionsEnd, le, capture, 'Section Header Block', NO_SUPPORTED_OPTIONS);
        }
        offset += totalLength;
        continue;
      }
      if (!sawShb) {
        return fail('E_NO_SHB', 'pcapng file does not begin with a Section Header Block (first block type 0x' + rawType.toString(16).padStart(8, '0') + ')', { offset: 0 });
      }
      const le = section.endian === 'le';
      const type = view.getUint32(offset, le);
      const totalLength = view.getUint32(offset + 4, le);
      if (totalLength % 4 !== 0 || totalLength < 12) {
        addWarning(capture, 'W_BLOCK_LENGTH', 'Block 0x' + type.toString(16) + ' at byte ' + offset + ' declares total length ' + totalLength + ' (must be a multiple of 4 and >= 12)', { fileOffset: offset });
        limitCoverage(capture, 'untrusted block length');
        break;
      }
      if (offset + totalLength > bytes.length) {
        addWarning(capture, 'W_FILE_TRUNCATED', 'Block at byte ' + offset + ' declares ' + totalLength + ' bytes but the file ends first', { fileOffset: offset });
        limitCoverage(capture, 'file ends inside a block');
        break;
      }
      const trailer = view.getUint32(offset + totalLength - 4, le);
      if (trailer !== totalLength) {
        addWarning(capture, 'W_BLOCK_TRAILER', 'Block at byte ' + offset + ' trailer ' + trailer + ' disagrees with its length ' + totalLength, { fileOffset: offset });
        limitCoverage(capture, 'block trailer mismatch');
        break;
      }
      const bodyStart = offset + 8;
      const bodyEnd = offset + totalLength - 4;
      section.consumed += totalLength;

      if (type === BLOCK.IDB) {
        if (bodyEnd - bodyStart < 8) {
          addWarning(capture, 'W_BLOCK_LENGTH', 'Interface Description Block at byte ' + offset + ' is too short (' + (bodyEnd - bodyStart) + ' body bytes, needs 8)', { fileOffset: offset });
          limitCoverage(capture, 'undersized IDB');
          break;
        }
        const linkType = view.getUint16(bodyStart, le);
        const snaplen = view.getUint32(bodyStart + 4, le);
        const options = parsePcapngOptions(view, bytes, bodyStart + 8, bodyEnd, le, capture, 'Interface Description Block', IDB_SUPPORTED_OPTIONS);
        let name = null;
        let tsresol = { base: 10, exponent: 6 }; // pcapng default when if_tsresol is absent
        let tsoffsetSeconds = 0;
        if (options.has(2)) name = decodeUtf8Bounded(bytes, options.get(2).start, options.get(2).start + options.get(2).length);
        if (options.has(9)) {
          const data = options.get(9);
          if (data.length !== 1) {
            addWarning(capture, 'W_OPTION_LENGTH', 'if_tsresol must be 1 byte, got ' + data.length, { fileOffset: offset });
            capture.counts.malformedOptions += 1;
            limitCoverage(capture, 'malformed option framing');
          } else {
            const value = bytes[data.start];
            // The DECLARED resolution is recorded exactly as declared (base 10
            // or base 2, exponent 0..127) and is never replaced by another
            // scale. Resolutions beyond the exact display range are converted
            // to milliseconds and marked approximate in the timestamp text.
            if (value & 0x80) tsresol = { base: 2, exponent: value & 0x7f };
            else tsresol = { base: 10, exponent: value };
            if (tsresol.base === 10 && tsresol.exponent > 9) {
              addWarning(capture, 'W_TSRESOL', 'Interface ' + section.interfaces.length + ' declares a 10^-' + tsresol.exponent + ' timestamp resolution; timestamps from this interface are shown with millisecond approximation (the declared resolution is retained)', { fileOffset: offset });
            }
          }
        }
        if (options.has(14)) {
          const data = options.get(14);
          if (data.length !== 8) {
            addWarning(capture, 'W_OPTION_LENGTH', 'if_tsoffset must be 8 bytes, got ' + data.length, { fileOffset: offset });
            capture.counts.malformedOptions += 1;
            limitCoverage(capture, 'malformed option framing');
          } else {
            tsoffsetSeconds = tsoffsetToJsonSafe(readInt64Big(view, data.start, le));
          }
        }
        if (section.interfaces.length >= LIMITS.maxInterfacesPerSection) {
          addWarning(capture, 'W_LIMIT_INTERFACES', 'Interface limit reached (' + LIMITS.maxInterfacesPerSection + ') in section ' + section.index);
          limitCoverage(capture, 'interface limit reached');
        } else {
          section.interfaces.push({ id: section.interfaces.length, linkType, snaplen, name, tsresol, tsoffsetSeconds });
        }
        offset += totalLength;
        continue;
      }

      if (type === BLOCK.EPB) {
        if (bodyEnd - bodyStart < 20) {
          addWarning(capture, 'W_BLOCK_LENGTH', 'Enhanced Packet Block at byte ' + offset + ' is too short (' + (bodyEnd - bodyStart) + ' body bytes, needs at least 20)', { fileOffset: offset });
          limitCoverage(capture, 'undersized EPB');
          break;
        }
        const interfaceId = view.getUint32(bodyStart, le);
        // Timestamp (High) is the 32-bit field at block offset 12, Timestamp
        // (Low) at block offset 16; each field is read in the SECTION's byte
        // order and the value is High*2^32 + Low (draft-tuexen-opsawg-pcapng-05
        // §4.3, Figure 11; Wireshark wiretap/pcapng.c combine; libpcap
        // sf-pcapng.c combine). A whole-64-bit read in section order would
        // swap the two words in little-endian sections - that was defect C1.
        const tsHigh = view.getUint32(bodyStart + 4, le);
        const tsLow = view.getUint32(bodyStart + 8, le);
        const rawTimestamp = BigInt(tsHigh) * 4294967296n + BigInt(tsLow);
        const caplen = view.getUint32(bodyStart + 12, le);
        const origlen = view.getUint32(bodyStart + 16, le);
        capture.counts.seen += 1;
        const packet = {
          index: capture.packets.length, fileOffset: offset, sectionIndex: section.index,
          interfaceId, blockType: 'enhanced-packet', vlanIds: [], caplen, origlen,
          truncated: caplen < origlen, status: 'unsupported', reason: null, protocol: 'unknown', details: null,
          timestamp: null
        };
        if (bodyStart + 20 + caplen > bodyEnd) {
          addWarning(capture, 'W_BLOCK_LENGTH', 'Enhanced Packet Block at byte ' + offset + ' declares ' + caplen + ' captured bytes that do not fit in the block', { fileOffset: offset });
          limitCoverage(capture, 'untrusted block length');
          break;
        }
        // The EPB option area follows the captured data padded to 32 bits. It
        // is structurally framed and counted; EPB options are not interpreted.
        const epbOptionsStart = bodyStart + 20 + ((caplen + 3) & ~3);
        if (epbOptionsStart > bodyEnd) {
          addWarning(capture, 'W_OPTION_PADDING', 'Enhanced Packet Block at byte ' + offset + ' ends before the captured-data padding completes; its option area was not parsed', { fileOffset: offset });
          limitCoverage(capture, 'untrusted block length');
        } else if (epbOptionsStart < bodyEnd) {
          parsePcapngOptions(view, bytes, epbOptionsStart, bodyEnd, le, capture, 'Enhanced Packet Block', NO_SUPPORTED_OPTIONS);
        }
        const iface = section.interfaces.find(item => item.id === interfaceId);
        if (!iface) {
          packet.status = 'rejected';
          packet.reason = 'interface-unknown';
          capture.counts.rejected += 1;
          addWarning(capture, 'W_IFACE_UNKNOWN', 'Packet ' + packet.index + ' references interface ' + interfaceId + ' but section ' + section.index + ' defines ' + section.interfaces.length + ' interface(s)', { packetIndex: packet.index, fileOffset: offset });
          capture.packets.push(packet);
          offset += totalLength;
          continue;
        }
        if (caplen > origlen) {
          packet.status = 'rejected';
          packet.reason = 'record-lengths';
          capture.counts.rejected += 1;
          addWarning(capture, 'W_RECORD_LENGTHS', 'Packet ' + packet.index + ': captured length ' + caplen + ' exceeds original length ' + origlen, { packetIndex: packet.index, fileOffset: offset });
          capture.packets.push(packet);
          offset += totalLength;
          continue;
        }
        // Fix round 2: resolution-aware conversion first. The raw 64-bit tick
        // count and the signed offset stay BigInt until the quotient/remainder
        // conversion decides exactness. Only a final result outside the exact
        // 53-bit seconds range or outside the displayable Date range is
        // reported out-of-range (seconds:null/exact:false) with W_TIMESTAMP_RANGE.
        packet.timestamp = timestampFromPcapng(rawTimestamp, iface.tsresol, iface.tsoffsetSeconds);
        if (packet.timestamp.seconds === null) {
          addWarning(capture, 'W_TIMESTAMP_RANGE', 'Packet ' + packet.index + ': timestamp is out of the exact displayable range and is shown as out-of-range rather than as a rounded time', { packetIndex: packet.index, fileOffset: offset });
        }
        let data = bytes.subarray(bodyStart + 20, bodyStart + 20 + caplen);
        if (iface.snaplen > 0 && caplen > iface.snaplen) {
          data = data.subarray(0, iface.snaplen);
          packet.caplen = iface.snaplen;
          packet.truncated = true;
          addWarning(capture, 'W_SNAPLEN_CAP', 'Packet ' + packet.index + ': captured length ' + caplen + ' exceeds the interface snaplen ' + iface.snaplen + '; delivered at most snaplen bytes', { packetIndex: packet.index, fileOffset: offset });
        }
        if (packet.truncated) capture.counts.truncated += 1;
        decodeFrame(capture, packet, data, iface.linkType);
        capture.packets.push(packet);
        offset += totalLength;
        continue;
      }

      if (type === BLOCK.SPB) {
        if (bodyEnd - bodyStart < 4) {
          addWarning(capture, 'W_BLOCK_LENGTH', 'Simple Packet Block at byte ' + offset + ' is too short', { fileOffset: offset });
          limitCoverage(capture, 'undersized SPB');
          break;
        }
        const origlen = view.getUint32(bodyStart, le);
        capture.counts.seen += 1;
        const packet = {
          index: capture.packets.length, fileOffset: offset, sectionIndex: section.index,
          interfaceId: 0, blockType: 'simple-packet', vlanIds: [], caplen: 0, origlen,
          truncated: false, status: 'unsupported', reason: null, protocol: 'unknown', details: null,
          timestamp: { kind: 'pcapng-spb', seconds: null, fractionDigits: 0, exact: false, text: 'no timestamp (Simple Packet Block)' }
        };
        if (section.interfaces.length > 1) {
          packet.status = 'rejected';
          packet.reason = 'spb-multi-interface';
          capture.counts.rejected += 1;
          addWarning(capture, 'W_SPB_INTERFACE', 'Packet ' + packet.index + ': Simple Packet Block cannot be attributed in a section with ' + section.interfaces.length + ' interfaces', { packetIndex: packet.index, fileOffset: offset });
          capture.packets.push(packet);
          offset += totalLength;
          continue;
        }
        const iface = section.interfaces[0];
        if (!iface) {
          packet.status = 'rejected';
          packet.reason = 'interface-unknown';
          capture.counts.rejected += 1;
          addWarning(capture, 'W_IFACE_UNKNOWN', 'Packet ' + packet.index + ': Simple Packet Block in a section without interfaces', { packetIndex: packet.index, fileOffset: offset });
          capture.packets.push(packet);
          offset += totalLength;
          continue;
        }
        const dataAvail = bodyEnd - (bodyStart + 4);
        let caplen = iface.snaplen > 0 ? Math.min(origlen, iface.snaplen) : origlen;
        // A snapshot-length prefix is decodable but not full coverage: an
        // original length beyond snaplen was delivered capped.
        const snapCapped = iface.snaplen > 0 && origlen > iface.snaplen;
        if (snapCapped) {
          addWarning(capture, 'W_SNAPLEN_CAP', 'Packet ' + packet.index + ': original length ' + origlen + ' exceeds the interface snaplen ' + iface.snaplen + '; delivered at most snaplen bytes', { packetIndex: packet.index, fileOffset: offset });
        }
        if (caplen > dataAvail) {
          addWarning(capture, 'W_BLOCK_LENGTH', 'Simple Packet Block at byte ' + offset + ' declares ' + origlen + ' bytes but carries ' + dataAvail, { fileOffset: offset });
          caplen = dataAvail;
        }
        packet.caplen = caplen;
        if (origlen > caplen) packet.truncated = true;
        if (packet.truncated) capture.counts.truncated += 1;
        decodeFrame(capture, packet, bytes.subarray(bodyStart + 4, bodyStart + 4 + caplen), iface.linkType);
        capture.packets.push(packet);
        offset += totalLength;
        continue;
      }

      // everything else is outside the supported subset: skipped by length,
      // counted, and reflected in the coverage report
      capture.counts.unsupportedBlocks += 1;
      offset += totalLength;
    }
    closeSection();
    return succeed(finishCoverage(capture));
  }

  // -------------------------------------------------------------------------
  // analysis: observations, qualified findings, evidence references
  // -------------------------------------------------------------------------
  const LIMITATIONS = [
    'A capture file contains only the traffic that reached the capture point. It cannot prove the absence of a problem: switched networks, other VLANs and devices whose traffic was never mirrored to the capture point are invisible here.',
    'A "possible" finding is an observation of what this capture saw, not proof of a live fault. Benign causes include virtual-router or failover MACs, a device that changed its adapter, and hosts that are still joining the network.',
    'Packets outside the supported subset (IPv6, non-UDP IP traffic, IP fragments, deeply nested VLANs, non-Ethernet link types) are counted as not decoded and are never used to claim that anything is healthy.',
    'DHCP and mDNS conclusions rest only on the packets present in this file; missing packets are not evidence that nothing happened.',
    'Timestamps are printed with only the precision the file declares; approximate resolutions are marked, and invalid values are shown as invalid rather than as a confident time.'
  ];

  const MAC_KEYS = new Set(['senderMac', 'targetMac', 'clientMac']);
  const IP_KEYS = new Set(['senderIp', 'targetIp', 'ciaddr', 'yiaddr', 'siaddr', 'giaddr', 'serverId', 'requestedIp', 'address']);
  const NAME_KEYS = new Set(['hostname', 'name', 'target', 'text']);
  const CONSTANT_VALUES = new Set(['0.0.0.0', '255.255.255.255', '224.0.0.251', 'ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00']);

  function makeRef(capture, index) {
    const packet = capture.packets[index];
    return {
      packetIndex: packet.index,
      fileOffset: packet.fileOffset,
      timestampText: packet.timestamp ? packet.timestamp.text : '',
      sectionIndex: packet.sectionIndex,
      interfaceId: packet.interfaceId,
      vlanIds: packet.vlanIds.slice()
    };
  }
  const contextKey = packet => 's' + packet.sectionIndex + '/i' + packet.interfaceId + '/v' + packet.vlanIds.join('.');

  function observationFor(packet) {
    const d = packet.details;
    if (packet.protocol === 'arp') {
      if (d.probe) return { kind: 'arp-probe', summary: 'ARP probe: ' + d.senderMac + ' asks who-has ' + d.targetIp + ' (sender address 0.0.0.0)', details: d };
      if (d.gratuitous) return { kind: 'arp-gratuitous', summary: 'ARP announcement: ' + d.senderIp + ' is-at ' + d.senderMac + ' (broadcast)', details: d };
      if (d.op === 1) return { kind: 'arp-request', summary: 'ARP request: who-has ' + d.targetIp + ' tell ' + d.senderIp, details: d };
      return { kind: 'arp-reply', summary: 'ARP reply: ' + d.senderIp + ' is-at ' + d.senderMac, details: d };
    }
    if (packet.protocol === 'dhcp') {
      const kind = {
        DISCOVER: 'dhcp-discover', OFFER: 'dhcp-offer', REQUEST: 'dhcp-request', ACK: 'dhcp-ack',
        DECLINE: 'dhcp-decline', NAK: 'dhcp-nak', RELEASE: 'dhcp-release', INFORM: 'dhcp-inform'
      }[d.messageTypeName] || 'dhcp-other';
      const parts = ['DHCP ' + (d.messageTypeName || 'unknown type') + ' from ' + d.clientMac];
      if (d.hostname) parts.push('hostname "' + d.hostname + '"');
      if (d.yiaddr !== '0.0.0.0') parts.push('assigned ' + d.yiaddr);
      if (d.requestedIp) parts.push('requested ' + d.requestedIp);
      parts.push('xid 0x' + (d.xid >>> 0).toString(16).padStart(8, '0'));
      return { kind, summary: parts.join(', '), details: d };
    }
    if (packet.protocol === 'mdns') {
      if (d.isResponse) {
        const names = d.answers.slice(0, 3).map(a => a.name + ' ' + a.typeName).join('; ');
        return { kind: 'mdns-response', summary: 'mDNS response: ' + d.answers.length + ' record(s)' + (names ? ' (' + names + ')' : ''), details: d };
      }
      const names = d.questions.slice(0, 3).map(q => q.name + ' ' + q.typeName + (q.qu ? ' QU' : '')).join('; ');
      return { kind: 'mdns-query', summary: 'mDNS query: ' + (names || '(no questions)'), details: d };
    }
    return null;
  }

  function analyze(capture, options) {
    if (!capture || !Array.isArray(capture.packets) || !capture.counts) {
      return fail('E_INPUT', 'analyze expects a capture object from parseCapture');
    }
    const opts = options || {};
    const model = {
      source: {
        file: typeof opts.sourceFile === 'string' ? opts.sourceFile : null,
        format: capture.format,
        fileBytes: capture.fileBytes,
        endianLabel: capture.endianLabel
      },
      capture: {
        format: capture.format,
        fileBytes: capture.fileBytes,
        endianLabel: capture.endianLabel,
        pcap: capture.pcap,
        counts: Object.assign({}, capture.counts),
        coverage: { limited: capture.coverage.limited, reasons: capture.coverage.reasons.slice() },
        sections: capture.sections.map(section => ({
          index: section.index, endian: section.endian,
          versionMajor: section.versionMajor, versionMinor: section.versionMinor,
          interfaces: section.interfaces.map(iface => ({
            id: iface.id, linkType: iface.linkType, snaplen: iface.snaplen, name: iface.name,
            tsresol: Object.assign({}, iface.tsresol), tsoffsetSeconds: iface.tsoffsetSeconds
          }))
        }))
      },
      packets: capture.packets.map(packet => ({
        index: packet.index, fileOffset: packet.fileOffset, sectionIndex: packet.sectionIndex,
        interfaceId: packet.interfaceId, vlanIds: packet.vlanIds.slice(), caplen: packet.caplen, origlen: packet.origlen,
        truncated: packet.truncated, status: packet.status, reason: packet.reason, protocol: packet.protocol,
        blockType: packet.blockType,
        timestampText: packet.timestamp ? packet.timestamp.text : '',
        details: packet.details
      })),
      observations: [],
      findings: [],
      warnings: capture.warnings.map(w => Object.assign({}, w)),
      limitations: LIMITATIONS.slice(),
      limits: { observationsTruncated: false },
      counts: { observations: 0, findings: 0, byObservationKind: {}, byFindingKind: {} }
    };

    // ---- observations (packet order) ----
    for (const packet of capture.packets) {
      if (packet.status !== 'decoded') continue;
      const obs = observationFor(packet);
      if (!obs) continue;
      if (model.observations.length >= LIMITS.maxObservations) {
        model.limits.observationsTruncated = true;
        model.warnings.push({ code: 'W_LIMIT_OBSERVATIONS', message: 'Observation limit reached (' + LIMITS.maxObservations + '); further observations were not recorded.' });
        break;
      }
      model.observations.push({ kind: obs.kind, summary: obs.summary, details: obs.details, refs: [makeRef(capture, packet.index)] });
      model.counts.byObservationKind[obs.kind] = (model.counts.byObservationKind[obs.kind] || 0) + 1;
    }
    model.counts.observations = model.observations.length;

    // ---- bindings for findings (scoped per section/interface/VLAN) ----
    const arpClaims = new Map();   // context -> Map(ip -> Map(mac -> [packetIndex]))
    const probes = new Map();      // context -> [{targetIp, packetIndex}]
    const dhcpAssignments = new Map(); // context -> Map(yiaddr -> Map(clientMac -> [packetIndex]))
    const macAddresses = new Map();    // context -> Map(mac -> Map(ip -> firstPacketIndex))

    for (const packet of capture.packets) {
      if (packet.status !== 'decoded' || !packet.details) continue;
      const key = contextKey(packet);
      const d = packet.details;
      if (packet.protocol === 'arp') {
        if (d.probe) {
          if (!probes.has(key)) probes.set(key, []);
          probes.get(key).push({ targetIp: d.targetIp, packetIndex: packet.index });
        } else {
          if (!arpClaims.has(key)) arpClaims.set(key, new Map());
          const inner = arpClaims.get(key);
          if (!inner.has(d.senderIp)) inner.set(d.senderIp, new Map());
          const macMap = inner.get(d.senderIp);
          if (!macMap.has(d.senderMac)) macMap.set(d.senderMac, []);
          macMap.get(d.senderMac).push(packet.index);
          if (!macAddresses.has(key)) macAddresses.set(key, new Map());
          const perMac = macAddresses.get(key);
          if (!perMac.has(d.senderMac)) perMac.set(d.senderMac, new Map());
          const perIp = perMac.get(d.senderMac);
          if (!perIp.has(d.senderIp)) perIp.set(d.senderIp, packet.index);
        }
      }
      if (packet.protocol === 'dhcp' && (d.messageTypeName === 'OFFER' || d.messageTypeName === 'ACK')) {
        if (!dhcpAssignments.has(key)) dhcpAssignments.set(key, new Map());
        const perIp = dhcpAssignments.get(key);
        if (!perIp.has(d.yiaddr)) perIp.set(d.yiaddr, new Map());
        const perClient = perIp.get(d.yiaddr);
        if (!perClient.has(d.clientMac)) perClient.set(d.clientMac, []);
        perClient.get(d.clientMac).push(packet.index);
      }
    }

    const findings = [];
    const pushFinding = (kind, severity, statement, qualification, counterexamples, refs) => {
      findings.push({ kind, severity, statement, qualification, counterexamples, refs: refs.slice(0, LIMITS.maxRefsPerItem) });
    };

    for (const [key, perIp] of arpClaims) {
      for (const [ip, macMap] of perIp) {
        if (macMap.size < 2) continue;
        const macs = Array.from(macMap.keys());
        const refs = [];
        for (const mac of macs) for (const index of macMap.get(mac)) refs.push(makeRef(capture, index));
        pushFinding(
          'possible-ip-mac-conflict', 'note',
          'Address ' + ip + ' was observed claimed by ' + macs.length + ' different hardware addresses (' + macs.join(', ') + ') within the same capture interface and VLAN context.',
          'This is consistent with an address conflict, but it is not proof of one; the capture alone cannot distinguish a conflict from benign causes.',
          [
            'ARP probes (sender protocol address 0.0.0.0) are excluded from claims and can never create this finding.',
            'Claims in different VLANs, capture sections or interfaces are analysed as separate contexts and are never merged.',
            'A virtual-router or failover MAC (VRRP/HSRP-style) can legitimately answer for an address that another host also uses.',
            'A host that replaced its network adapter or re-joined with a randomised MAC keeps its address, which looks identical here.'
          ],
          refs
        );
      }
    }

    for (const [key, probeList] of probes) {
      const perIp = arpClaims.get(key) || new Map();
      const dhcpPerIp = dhcpAssignments.get(key) || new Map();
      const seenTargets = new Set();
      for (const probe of probeList) {
        if (seenTargets.has(probe.targetIp)) continue;
        seenTargets.add(probe.targetIp);
        const claimedBy = perIp.get(probe.targetIp);
        const assigned = dhcpPerIp.get(probe.targetIp);
        if (!claimedBy && !assigned) continue;
        const refs = [makeRef(capture, probe.packetIndex)];
        const extra = [];
        if (assigned) for (const indexes of assigned.values()) for (const index of indexes) extra.push(index);
        if (claimedBy) for (const indexes of claimedBy.values()) for (const index of indexes) extra.push(index);
        extra.sort((a, b) => a - b);
        for (const index of extra) refs.push(makeRef(capture, index));
        pushFinding(
          'probe-for-in-use-address', 'note',
          'A host probed for address ' + probe.targetIp + ' while that address was also observed in use within the same interface and VLAN context.',
          'Probing is a normal startup step for many hosts (an address-conflict-detection style probe), and it may simply mean a device is joining; it is not proof that the address is misconfigured.',
          [
            'The probe itself (sender 0.0.0.0) is never counted as a claim on the address.',
            'A probe for an address that this capture never observed in use produces no finding.',
            'DHCP offers/acks seen here may belong to a different moment in time than the probe.'
          ],
          refs
        );
      }
    }

    for (const [key, perIp] of dhcpAssignments) {
      for (const [ip, perClient] of perIp) {
        if (perClient.size < 2) continue;
        const clients = Array.from(perClient.keys());
        const refs = [];
        for (const client of clients) for (const index of perClient.get(client)) refs.push(makeRef(capture, index));
        refs.sort((a, b) => a.packetIndex - b.packetIndex);
        pushFinding(
          'possible-duplicate-dhcp-assignment', 'note',
          'DHCP offered or acknowledged address ' + ip + ' to ' + clients.length + ' different client hardware addresses (' + clients.join(', ') + ') in the same interface and VLAN context.',
          'This may indicate a stale lease, an overlapping DHCP pool or a client that changed adapters; it is not proof that two hosts were simultaneously using the address.',
          [
            'Repeated offers/acks to the SAME client hardware address are treated as retransmissions, not as a duplicate.',
            'Assignments in different VLANs, capture sections or interfaces are separate contexts.',
            'The capture may not contain the DHCP DECLINE or RELEASE that resolved the situation.'
          ],
          refs
        );
      }
    }

    for (const [key, perMac] of macAddresses) {
      for (const [mac, perIp] of perMac) {
        if (perIp.size < 2) continue;
        const ips = Array.from(perIp.keys());
        const refs = ips.map(ip => makeRef(capture, perIp.get(ip)));
        pushFinding(
          'arp-address-transition', 'info',
          'Hardware address ' + mac + ' was observed using ' + ips.length + ' different addresses over time (' + ips.join(', ') + ') within one interface and VLAN context.',
          'An address transition is normal (a new lease, a manual change, or a device joining a different subnet) and is reported for context only.',
          [
            'This is never reported as a conflict: the hardware address is constant while the address changed.',
            'The order of observations follows packet order in the capture, not necessarily real-world time order.'
          ],
          refs
        );
      }
    }

    // deterministic order: conflicts, probes, duplicates, transitions
    const priority = { 'possible-ip-mac-conflict': 0, 'probe-for-in-use-address': 1, 'possible-duplicate-dhcp-assignment': 2, 'arp-address-transition': 3 };
    findings.sort((a, b) => (priority[a.kind] - priority[b.kind]) || ((a.refs[0] ? a.refs[0].packetIndex : 0) - (b.refs[0] ? b.refs[0].packetIndex : 0)));
    model.findings = findings;
    model.counts.findings = findings.length;
    for (const finding of findings) model.counts.byFindingKind[finding.kind] = (model.counts.byFindingKind[finding.kind] || 0) + 1;
    return succeed(model);
  }

  // -------------------------------------------------------------------------
  // reports: redaction by default, explicit identifier opt-in
  // -------------------------------------------------------------------------
  const REDACTION_CATEGORIES = ['mac', 'ip', 'name', 'iface', 'file'];

  function collectIdentifiers(model) {
    const maps = new Map(REDACTION_CATEGORIES.map(cat => [cat, new Map()]));
    const add = (category, value) => {
      if (typeof value !== 'string' || !value) return;
      if (CONSTANT_VALUES.has(value)) return;
      const map = maps.get(category);
      if (!map.has(value)) map.set(value, true);
    };
    const walk = (value, keyHint) => {
      if (typeof value === 'string') {
        if (MAC_KEYS.has(keyHint)) add('mac', value);
        else if (IP_KEYS.has(keyHint)) add('ip', value);
        else if (NAME_KEYS.has(keyHint)) add('name', value);
        return;
      }
      if (Array.isArray(value)) { for (const item of value) walk(item, keyHint); return; }
      if (value && typeof value === 'object') {
        for (const key of Object.keys(value)) walk(value[key], key);
      }
    };
    for (const obs of model.observations) walk(obs.details, null);
    for (const packet of model.packets) walk(packet.details, null);
    for (const section of model.capture.sections) {
      for (const iface of section.interfaces) add('iface', iface.name);
    }
    add('file', model.source.file);
    return maps;
  }

  function buildRedactionMaps(model) {
    const collected = collectIdentifiers(model);
    const ordinals = {};
    const replacements = [];
    for (const category of REDACTION_CATEGORIES) {
      ordinals[category] = {};
      let index = 0;
      for (const value of collected.get(category).keys()) {
        index += 1;
        const ordinal = category + '-' + String(index).padStart(2, '0');
        ordinals[category][ordinal] = index; // ordinal -> assignment order (no raw values retained)
        replacements.push([value, ordinal]);
      }
    }
    replacements.sort((a, b) => b[0].length - a[0].length);
    return { ordinals, replacements };
  }

  function redactString(text, replacements) {
    let out = text;
    for (const [value, ordinal] of replacements) {
      if (out.indexOf(value) !== -1) out = out.split(value).join(ordinal);
    }
    return out;
  }
  function redactDeep(value, replacements) {
    if (typeof value === 'string') return redactString(value, replacements);
    if (Array.isArray(value)) return value.map(item => redactDeep(item, replacements));
    if (value && typeof value === 'object') {
      const out = {};
      for (const key of Object.keys(value)) out[key] = redactDeep(value[key], replacements);
      return out;
    }
    return value;
  }

  function escapeHtml(text) {
    return String(text)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  const MAX_EVIDENCE_PACKETS = 500;

  function renderHtmlReport(json) {
    const lines = [];
    const esc = escapeHtml;
    lines.push('<!DOCTYPE html>');
    lines.push('<html lang="en"><head><meta charset="utf-8">');
    lines.push('<meta name="viewport" content="width=device-width, initial-scale=1">');
    lines.push('<title>LanTriage evidence report</title>');
    lines.push('<style>');
    lines.push('body{font-family:system-ui,Segoe UI,Arial,sans-serif;background:#0b1f3a;color:#e8f0fa;margin:0;padding:24px;line-height:1.5}');
    lines.push('h1,h2,h3{color:#9fc6ff} .card{background:#122c4d;border:1px solid #24507f;border-radius:8px;padding:16px;margin:16px 0}');
    lines.push('table{border-collapse:collapse;width:100%} th,td{border:1px solid #24507f;padding:6px 8px;text-align:left;font-size:13px;vertical-align:top}');
    lines.push('th{background:#17365c} .banner{background:#5a2d0c;border:1px solid #b4762a;padding:10px 14px;border-radius:8px}');
    lines.push('code{background:#0b1f3a;padding:1px 4px;border-radius:4px} .muted{color:#a9bed8}');
    lines.push('</style></head><body>');
    lines.push('<h1>LanTriage evidence report</h1>');
    lines.push('<p class="muted">Generated ' + esc(json.generatedAt) + ' by LanTriage ' + esc(json.appVersion) + '. Offline pcap/pcapng DHCP/ARP/mDNS evidence analysis. This report is evidence about what the capture contains, not a network-health certification.</p>');
    lines.push('<div class="banner"><strong>' + (json.redaction.mode === 'redacted' ? 'REDACTED' : 'IDENTIFIERS INCLUDED (explicit opt-in)') + '</strong> - ' + esc(json.redaction.note) + '</div>');
    lines.push('<div class="card"><h2>Capture summary</h2>');
    lines.push('<p>Source file: <code>' + esc(json.source.file || '(pasted bytes)') + '</code> | format: ' + esc(json.capture.format) + ' | ' + json.capture.fileBytes + ' bytes | byte order: ' + esc(json.capture.endianLabel) + '</p>');
    const c = json.capture.counts;
    lines.push('<p>Packets seen: ' + c.seen + ' | decoded: ' + c.decoded + ' | not decoded (unsupported): ' + c.unsupported + ' | rejected records: ' + c.rejected + ' | malformed payloads: ' + c.malformed + ' | truncated by snaplen: ' + c.truncated + ' | skipped pcapng blocks: ' + c.unsupportedBlocks + ' | skipped options: ' + c.unsupportedOptions + ' | malformed options: ' + c.malformedOptions + '</p>');
    lines.push('<p>Coverage: ' + (json.capture.coverage.limited ? '<strong>LIMITED</strong> - ' + json.capture.coverage.reasons.map(esc).join('; ') : 'no unsupported or rejected content was found in the supported subset') + '</p>');
    lines.push('</div>');
    lines.push('<div class="card"><h2>Limitations (read before drawing conclusions)</h2><ul>');
    for (const item of json.limitations) lines.push('<li>' + esc(item) + '</li>');
    lines.push('</ul></div>');
    lines.push('<div class="card"><h2>Findings (' + json.findings.length + ')</h2>');
    if (!json.findings.length) lines.push('<p>No possible-conflict or transition candidates were identified from the supported subset of this capture. That is not evidence that the network is healthy.</p>');
    for (const finding of json.findings) {
      lines.push('<h3>' + esc(finding.kind) + ' <span class="muted">(severity: ' + esc(finding.severity) + ')</span></h3>');
      lines.push('<p>' + esc(finding.statement) + '</p>');
      lines.push('<p class="muted">' + esc(finding.qualification) + '</p>');
      lines.push('<p><em>Counterexamples / benign explanations:</em></p><ul>');
      for (const item of finding.counterexamples) lines.push('<li>' + esc(item) + '</li>');
      lines.push('</ul>');
      lines.push('<p>Evidence: ' + finding.refs.map(r => 'packet ' + r.packetIndex + ' (offset ' + r.fileOffset + ', ' + esc(r.timestampText) + ', iface ' + r.interfaceId + (r.vlanIds.length ? ', vlan ' + r.vlanIds.join('/') : '') + ')').join('; ') + '</p>');
    }
    lines.push('</div>');
    lines.push('<div class="card"><h2>Observations (' + json.observations.length + ')</h2><table><tr><th>#</th><th>Kind</th><th>Summary</th><th>Evidence</th></tr>');
    json.observations.forEach((obs, i) => {
      lines.push('<tr><td>' + (i + 1) + '</td><td>' + esc(obs.kind) + '</td><td>' + esc(obs.summary) + '</td><td>' + obs.refs.map(r => 'p' + r.packetIndex + '@' + r.fileOffset).join(', ') + '</td></tr>');
    });
    lines.push('</table></div>');
    const evidence = json.evidence;
    lines.push('<div class="card"><h2>Packet evidence (' + evidence.listed + ' of ' + evidence.total + ' listed)</h2><table><tr><th>#</th><th>Offset</th><th>Timestamp</th><th>Iface</th><th>VLAN</th><th>Length</th><th>Protocol</th><th>Status</th></tr>');
    for (const packet of evidence.packets) {
      lines.push('<tr><td>' + packet.index + '</td><td>' + packet.fileOffset + '</td><td>' + esc(packet.timestampText) + '</td><td>' + packet.interfaceId + '</td><td>' + (packet.vlanIds.length ? packet.vlanIds.join('/') : '-') + '</td><td>' + packet.caplen + '/' + packet.origlen + '</td><td>' + esc(packet.protocol) + '</td><td>' + esc(packet.status + (packet.reason ? ' (' + packet.reason + ')' : '')) + '</td></tr>');
    }
    lines.push('</table></div>');
    lines.push('<div class="card"><h2>Warnings (' + json.warnings.length + ')</h2><table><tr><th>Code</th><th>Message</th></tr>');
    for (const warning of json.warnings) lines.push('<tr><td>' + esc(warning.code) + '</td><td>' + esc(warning.message) + '</td></tr>');
    lines.push('</table></div>');
    lines.push('<p class="muted">No raw packet payloads are included in this report. This document is self-contained (no scripts, no remote resources) and can be archived or shared as a static file.</p>');
    lines.push('</body></html>');
    return lines.join('\n');
  }

  function buildReport(model, options) {
    if (!model || !Array.isArray(model.observations) || !model.capture) {
      return fail('E_INPUT', 'buildReport expects an analysis model from analyze');
    }
    const opts = options || {};
    const includeIdentifiers = opts.includeIdentifiers === true;
    const redactionMaps = includeIdentifiers ? { ordinals: null, replacements: [] } : buildRedactionMaps(model);
    const generatedAt = new Date().toISOString();

    const base = {
      app: 'LanTriage',
      appVersion: VERSION,
      generatedAt,
      source: redactDeep(model.source, redactionMaps.replacements),
      capture: redactDeep(model.capture, redactionMaps.replacements),
      observations: redactDeep(model.observations, redactionMaps.replacements),
      findings: redactDeep(model.findings, redactionMaps.replacements),
      warnings: redactDeep(model.warnings, redactionMaps.replacements),
      limitations: model.limitations.slice(),
      limits: Object.assign({}, model.limits),
      counts: Object.assign({}, model.counts),
      redaction: includeIdentifiers ? {
        mode: 'identifiers',
        note: 'Raw identifiers (MAC addresses, IP addresses, host/service names, interface and file names) are included because the operator explicitly opted in. Raw packet payloads are still never included.'
      } : {
        mode: 'redacted',
        note: 'Identifiers were replaced by per-report ordinals (mac-01, ip-01, name-01, iface-01, file-01) in first-seen order. Raw packet payloads are never included.',
        ordinals: redactionMaps.ordinals
      }
    };
    const evidencePackets = model.packets.slice(0, MAX_EVIDENCE_PACKETS).map(packet => ({
      index: packet.index, fileOffset: packet.fileOffset, sectionIndex: packet.sectionIndex,
      interfaceId: packet.interfaceId, vlanIds: packet.vlanIds.slice(), caplen: packet.caplen, origlen: packet.origlen,
      truncated: packet.truncated, status: packet.status, reason: packet.reason, protocol: packet.protocol,
      timestampText: packet.timestampText
    }));
    base.evidence = {
      total: model.packets.length,
      listed: evidencePackets.length,
      note: model.packets.length > evidencePackets.length ? 'Evidence table is bounded to the first ' + MAX_EVIDENCE_PACKETS + ' packets.' : null,
      packets: redactDeep(evidencePackets, redactionMaps.replacements)
    };
    const json = base;
    return succeed({ json, html: renderHtmlReport(json) });
  }

  return {
    VERSION, LIMITS, MAGIC, BLOCK,
    parseCapture, analyze, buildReport,
    // exported for tests and the browser UI
    formatEpoch
  };
});

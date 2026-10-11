'use strict';
/*
 * LanTriage core unit tests (node:test, zero dependencies).
 *
 * These tests drive the SAME core.js the browser runs. Fixtures under
 * ../fixtures are self-authored SYNTHETIC byte sequences (see
 * fixtures/README.md and docs/formats.md) - never real captures.
 *
 * Run: node --test tests/core.test.cjs   (from the tool root)
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const core = require('../core.js');
const F = require('./fixtures.cjs');

const FIXTURE_DIR = path.resolve(__dirname, '..', 'fixtures');
const manifest = JSON.parse(fs.readFileSync(path.join(FIXTURE_DIR, 'manifest.json'), 'utf8'));
const fixture = name => {
  const entry = manifest.files.find(f => f.name === name);
  if (!entry) throw new Error('Unknown fixture: ' + name);
  const bytes = fs.readFileSync(path.join(FIXTURE_DIR, name));
  return { bytes, entry };
};

const ok = result => {
  assert.equal(result.ok, true, 'expected ok:true, got error ' + JSON.stringify(result.error));
  return result.value;
};
const err = result => {
  assert.equal(result.ok, false, 'expected a structured error, got success');
  return result.error;
};

// ---------------------------------------------------------------------------
// fixture integrity + container basics
// ---------------------------------------------------------------------------
test('fixtures are synthetic and byte-stable (manifest sha256 matches files)', () => {
  assert.ok(manifest.files.length >= 20, 'expected the documented fixture set');
  for (const entry of manifest.files) {
    const bytes = fs.readFileSync(path.join(FIXTURE_DIR, entry.name));
    assert.equal(bytes.length, entry.bytes, entry.name + ' byte size drifted');
    const sha = crypto.createHash('sha256').update(bytes).digest('hex');
    assert.equal(sha, entry.sha256, entry.name + ' content drifted');
  }
});

test('module exposes the documented API surface', () => {
  for (const fn of ['parseCapture', 'analyze', 'buildReport']) assert.equal(typeof core[fn], 'function', fn + ' missing');
  assert.equal(typeof core.VERSION, 'string');
  assert.ok(core.LIMITS && core.LIMITS.maxBytes > 0 && core.LIMITS.maxPackets > 0, 'LIMITS must be exported');
});

// ---------------------------------------------------------------------------
// classic pcap: byte order, timestamp resolution, offsets
// ---------------------------------------------------------------------------
test('pcap LE microsecond baseline parses with exact counts and offsets', () => {
  const { bytes, entry } = fixture('synthetic-lan-le-us.pcap');
  const capture = ok(core.parseCapture(bytes));
  assert.equal(capture.format, 'pcap');
  assert.equal(capture.endianLabel, 'little-endian');
  assert.equal(capture.fileBytes, bytes.length);
  assert.equal(capture.counts.seen, 15);
  assert.equal(capture.counts.decoded, 12);
  assert.equal(capture.counts.unsupported, 3);
  assert.equal(capture.counts.rejected, 0);
  assert.equal(capture.counts.malformed, 0);
  assert.equal(capture.counts.truncated, 1);
  // byte offsets come from the generated manifest
  entry.packetOffsets.forEach((offset, i) => {
    assert.equal(capture.packets[i].fileOffset, offset, 'packet ' + i + ' offset');
  });
  assert.equal(capture.packets[0].fileOffset, 24, 'first record starts after the 24-byte file header');
  assert.equal(capture.packets[0].caplen, 42);
  assert.equal(capture.packets[0].origlen, 42);
});

test('pcap BE microsecond file decodes identically to LE for the shared packets', () => {
  const be = ok(core.parseCapture(fixture('synthetic-lan-be-us.pcap').bytes));
  assert.equal(be.endianLabel, 'big-endian');
  assert.equal(be.counts.seen, 5);
  assert.equal(be.counts.decoded, 5);
  const le = ok(core.parseCapture(fixture('synthetic-lan-le-us.pcap').bytes));
  const kinds = p => p.protocol;
  assert.deepEqual(be.packets.map(kinds), ['arp', 'arp', 'dhcp', 'dhcp', 'mdns']);
  assert.equal(be.packets[0].details.senderIp, le.packets[0].details.senderIp);
  assert.equal(be.packets[2].details.xid, le.packets[2].details.xid);
});

test('pcap nanosecond magic yields nanosecond timestamps, not microseconds', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-lan-le-ns.pcap').bytes));
  assert.equal(capture.pcap.timestampResolution, 'nanosecond');
  assert.equal(capture.packets[0].timestamp.text, '2026-10-11 12:00:00.123456789 UTC');
  assert.equal(capture.packets[1].timestamp.text, '2026-10-11 12:00:00.987654321 UTC');
  assert.equal(capture.packets[0].timestamp.exact, true);
  assert.equal(capture.packets[0].timestamp.seconds, F.T0);
});

test('pcap microsecond timestamps format with six fraction digits', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-lan-le-us.pcap').bytes));
  assert.equal(capture.packets[0].timestamp.text, '2026-10-11 12:00:00.100000 UTC');
  assert.equal(capture.packets[0].timestamp.exact, true);
});

test('invalid microsecond fraction is flagged instead of printed as confident time', () => {
  const bytes = F.pcapFile({ variant: 'le-us', packets: [{ data: F.arpRequest(), tsSec: F.T0, tsFrac: 2000000 }] }).bytes;
  const capture = ok(core.parseCapture(bytes));
  assert.equal(capture.packets[0].timestamp.exact, false);
  assert.match(capture.packets[0].timestamp.text, /invalid/);
  assert.ok(capture.warnings.some(w => w.code === 'W_TIMESTAMP_FRACTION'));
});

// ---------------------------------------------------------------------------
// pcapng: sections, interfaces, resolutions, offsets
// ---------------------------------------------------------------------------
test('pcapng multi-section file: interface ids reset per section, endian changes', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-multi-section.pcapng').bytes));
  assert.equal(capture.format, 'pcapng');
  assert.equal(capture.sections.length, 2);
  assert.equal(capture.sections[0].endian, 'le');
  assert.equal(capture.sections[1].endian, 'be');
  assert.equal(capture.sections[0].interfaces.length, 1);
  assert.equal(capture.sections[1].interfaces.length, 2);
  // interface id 0 exists in BOTH sections and must not be confused across them
  assert.equal(capture.packets[0].sectionIndex, 0);
  assert.equal(capture.packets[3].sectionIndex, 1);
  assert.equal(capture.packets[3].interfaceId, 0);
  assert.equal(capture.packets[4].interfaceId, 1);
});

test('pcapng timestamp resolutions: 10^-6 exact, 2^-10 approximate, if_tsoffset applied', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-multi-section.pcapng').bytes));
  assert.equal(capture.packets[0].timestamp.text, '2026-10-11 12:00:00.100000 UTC');
  assert.equal(capture.packets[0].timestamp.exact, true);
  const approx = capture.packets[3].timestamp;
  assert.equal(approx.exact, false);
  assert.match(approx.text, /^~2026-10-11 12:00:00\.500/);
  assert.match(approx.text, /approx/);
  // interface 1 of section 2 declares if_tsoffset 3600 s (RFC-lesson: offsets are
  // part of the interface, not the block)
  assert.equal(capture.packets[4].timestamp.text, '2026-10-11 13:00:05.000000 UTC');
});

test('pcapng if_name and if_tsresol are recorded per interface; SPB has no timestamp', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-multi-section.pcapng').bytes));
  assert.equal(capture.sections[0].interfaces[0].name, 'fictional-eth0');
  assert.equal(capture.sections[0].interfaces[0].tsresol.exponent, 6);
  assert.equal(capture.sections[1].interfaces[0].tsresol.base, 2);
  const spb = capture.packets.find(p => p.blockType === 'simple-packet');
  assert.ok(spb, 'SPB present');
  assert.equal(spb.interfaceId, 0);
  assert.equal(spb.timestamp.text, 'no timestamp (Simple Packet Block)');
  assert.equal(spb.timestamp.seconds, null);
  assert.equal(spb.details.senderIp, '192.0.2.20');
});

test('pcapng counts unsupported blocks (NRB, custom) visibly', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-multi-section.pcapng').bytes));
  assert.equal(capture.counts.unsupportedBlocks, 2);
  assert.ok(capture.coverage.limited, 'skipped blocks must limit coverage');
  assert.ok(capture.coverage.reasons.some(r => /block/i.test(r)), 'reason must mention skipped blocks');
});

test('pcapng EPB referencing a nonexistent interface is rejected visibly', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-multi-section.pcapng').bytes));
  const rejected = capture.packets.filter(p => p.status === 'rejected');
  assert.equal(rejected.length, 1);
  assert.equal(rejected[0].reason, 'interface-unknown');
  assert.ok(capture.warnings.some(w => w.code === 'W_IFACE_UNKNOWN'));
});

test('pcapng minor version 2 is treated as 0 (draft-tuexen-opsawg-pcapng-05 §4.1)', () => {
  const bytes = F.concat([
    F.pcapngSectionHeader({ endian: 'le', minor: 2 }),
    F.pcapngInterface({ endian: 'le' }),
    F.pcapngEnhancedPacket({ endian: 'le', interfaceId: 0, timestamp: 1000n, data: F.arpRequest() })
  ]);
  const capture = ok(core.parseCapture(bytes));
  assert.equal(capture.sections[0].versionMinor, 2);
  assert.equal(capture.packets[0].status, 'decoded');
  assert.equal(capture.warnings.filter(w => w.code === 'W_SH_VERSION').length, 0);
});

test('pcapng section length that disagrees with parsed blocks warns', () => {
  const bytes = F.concat([
    F.pcapngSectionHeader({ endian: 'le', sectionLength: 4n }), // wrong: blocks take more than 4 bytes
    F.pcapngInterface({ endian: 'le' }),
    F.pcapngEnhancedPacket({ endian: 'le', interfaceId: 0, timestamp: 1000n, data: F.arpRequest() })
  ]);
  const capture = ok(core.parseCapture(bytes));
  assert.ok(capture.warnings.some(w => w.code === 'W_SECTION_LENGTH'));
});

// ---------------------------------------------------------------------------
// malformed containers: hard errors vs visible per-record rejections
// ---------------------------------------------------------------------------
test('empty input and short header produce structured hard errors', () => {
  assert.equal(err(core.parseCapture(Buffer.alloc(0))).code, 'E_EMPTY');
  const short = err(core.parseCapture(Buffer.from([0xa1, 0xb2, 0xc3, 0xd4, 2, 0, 4, 0])));
  assert.equal(short.code, 'E_HEADER_TRUNCATED');
  assert.equal(typeof short.message, 'string');
});

test('illegal pcap magic / version / snaplen are hard errors with codes', () => {
  assert.equal(err(core.parseCapture(fixture('synthetic-bad-magic.pcap').bytes)).code, 'E_MAGIC');
  assert.equal(err(core.parseCapture(fixture('synthetic-bad-version.pcap').bytes)).code, 'E_VERSION');
  assert.equal(err(core.parseCapture(fixture('synthetic-bad-snaplen.pcap').bytes)).code, 'E_SNAPLEN');
});

test('pcap record with captured length above original length is rejected, file still parses', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-bad-incl-gt-orig.pcap').bytes));
  assert.equal(capture.counts.seen, 1);
  assert.equal(capture.counts.rejected, 1);
  assert.equal(capture.packets[0].reason, 'record-lengths');
  assert.ok(capture.warnings.some(w => w.code === 'W_RECORD_LENGTHS'));
  assert.ok(capture.coverage.limited);
});

test('pcap file cut mid-record stops with a visible truncation warning', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-bad-truncated-final.pcap').bytes));
  assert.equal(capture.counts.seen, 1);
  assert.equal(capture.counts.rejected, 1);
  assert.ok(capture.warnings.some(w => w.code === 'W_FILE_TRUNCATED'));
  assert.ok(capture.coverage.limited);
});

test('pcapng without a Section Header Block is a hard error', () => {
  assert.equal(err(core.parseCapture(fixture('synthetic-bad-no-shb.pcapng').bytes)).code, 'E_NO_SHB');
});

test('pcapng corrupted byte-order magic is a hard error', () => {
  assert.equal(err(core.parseCapture(fixture('synthetic-bad-bom.pcapng').bytes)).code, 'E_BOM');
});

test('pcapng block whose declared length is not 4-aligned stops visibly', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-bad-blocklen.pcapng').bytes));
  assert.ok(capture.warnings.some(w => w.code === 'W_BLOCK_LENGTH'));
  assert.ok(capture.coverage.limited);
  assert.equal(capture.counts.seen, 0);
});

test('pcapng EPB with unknown interface is rejected with a visible warning', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-bad-iface.pcapng').bytes));
  assert.equal(capture.counts.rejected, 1);
  assert.equal(capture.packets[0].reason, 'interface-unknown');
  assert.ok(capture.warnings.some(w => w.code === 'W_IFACE_UNKNOWN'));
});

test('reserved linktype bits set produce a warning (draft-gharris-opsawg-pcap-01 §4)', () => {
  const bytes = F.pcapFile({ variant: 'le-us', linkType: 0x00010001, packets: [{ data: F.arpRequest(), tsSec: F.T0, tsFrac: 1 }] }).bytes;
  const capture = ok(core.parseCapture(bytes));
  assert.ok(capture.warnings.some(w => w.code === 'W_LINKTYPE_BITS'));
});

// ---------------------------------------------------------------------------
// protocol decoding: Ethernet/VLAN/ARP/DHCP/mDNS
// ---------------------------------------------------------------------------
test('ARP request/reply/probe/gratuitous are distinguished with full details', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-lan-le-us.pcap').bytes));
  const [req, rep, , , , , , , probe] = capture.packets;
  assert.equal(req.protocol, 'arp');
  assert.equal(req.details.opName, 'request');
  assert.equal(req.details.senderIp, '192.0.2.10');
  assert.equal(req.details.targetIp, '192.0.2.20');
  assert.equal(req.details.probe, false);
  assert.equal(rep.details.opName, 'reply');
  assert.equal(rep.details.senderMac, 'aa:00:00:00:00:20');
  assert.equal(probe.details.probe, true, 'spa 0.0.0.0 is a probe');
  assert.equal(probe.details.senderIp, '0.0.0.0');
});

test('bounded VLAN tag is decoded and its id is attached to the packet and observations', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-lan-le-us.pcap').bytes));
  const tagged = capture.packets.find(p => p.vlanIds.length === 1);
  assert.ok(tagged, 'VLAN-tagged packet decoded');
  assert.equal(tagged.vlanIds[0], 42);
  assert.equal(tagged.protocol, 'arp');
  const model = ok(core.analyze(capture, { sourceFile: 'synthetic-lan-le-us.pcap' }));
  const taggedObs = model.observations.find(o => o.refs.some(r => r.packetIndex === tagged.index));
  assert.ok(taggedObs, 'tagged packet has an observation');
  assert.deepEqual(taggedObs.refs[0].vlanIds, [42]);
});

test('more than two VLAN tags is outside the subset and counted visibly', () => {
  const frame = F.ethernet({
    dst: F.BCAST, src: F.MAC.hostA, ethertype: 0x0806,
    vlans: [{ tpid: 0x8100, tci: 1 }, { tpid: 0x8100, tci: 2 }, { tpid: 0x8100, tci: 3 }],
    payload: F.arpPacket({ op: 1, sha: F.MAC.hostA, spa: '192.0.2.10', tha: F.ZERO, tpa: '192.0.2.20' })
  });
  const capture = ok(core.parseCapture(F.pcapFile({ variant: 'le-us', packets: [{ data: frame, tsSec: F.T0, tsFrac: 1 }] }).bytes));
  assert.equal(capture.packets[0].status, 'unsupported');
  assert.equal(capture.packets[0].reason, 'vlan-nested');
  assert.equal(capture.counts.unsupported, 1);
});

test('non-IP ethertypes and LLC frames are unsupported but visible', () => {
  const nonIp = F.ethernet({ dst: F.BCAST, src: F.MAC.hostA, ethertype: 0x88cc, payload: Buffer.alloc(4) });
  const llc = F.ethernet({ dst: F.BCAST, src: F.MAC.hostA, ethertype: 0x0010, payload: Buffer.alloc(8) }); // length field <= 1500 => LLC
  const capture = ok(core.parseCapture(F.pcapFile({ variant: 'le-us', packets: [
    { data: nonIp, tsSec: F.T0, tsFrac: 1 },
    { data: llc, tsSec: F.T0, tsFrac: 2 }
  ] }).bytes));
  assert.equal(capture.packets[0].reason, 'non-ip');
  assert.equal(capture.packets[1].reason, 'llc');
  assert.equal(capture.counts.unsupported, 2);
});

test('ARP variants outside Ethernet/IPv4 and RARP ops are unsupported, never mis-decoded', () => {
  const variant = F.ethernet({ dst: F.BCAST, src: F.MAC.hostA, ethertype: 0x0806, payload: F.arpPacket({ op: 1, sha: F.MAC.hostA, spa: '192.0.2.10', tha: F.ZERO, tpa: '192.0.2.20', hln: 8 }) });
  const rarp = F.ethernet({ dst: F.BCAST, src: F.MAC.hostA, ethertype: 0x0806, payload: F.arpPacket({ op: 3, sha: F.MAC.hostA, spa: '192.0.2.10', tha: F.ZERO, tpa: '192.0.2.20' }) });
  const capture = ok(core.parseCapture(F.pcapFile({ variant: 'le-us', packets: [
    { data: variant, tsSec: F.T0, tsFrac: 1 },
    { data: rarp, tsSec: F.T0, tsFrac: 2 }
  ] }).bytes));
  assert.equal(capture.packets[0].reason, 'arp-variant');
  assert.equal(capture.packets[1].reason, 'rarp');
});

test('DHCP DISCOVER/OFFER/REQUEST/ACK decode message type, xid, client, hostname, addresses', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-lan-le-us.pcap').bytes));
  const [, , discover, offer, request, ack] = capture.packets;
  assert.equal(discover.protocol, 'dhcp');
  assert.equal(discover.details.messageType, 1);
  assert.equal(discover.details.messageTypeName, 'DISCOVER');
  assert.equal(discover.details.clientMac, 'aa:00:00:00:00:30');
  assert.equal(discover.details.hostname, 'fictional-laptop');
  assert.equal(discover.details.xid, 0x11223344);
  assert.equal(offer.details.messageTypeName, 'OFFER');
  assert.equal(offer.details.yiaddr, '192.0.2.30');
  assert.equal(offer.details.serverId, '192.0.2.1');
  assert.equal(offer.details.leaseSeconds, 3600);
  assert.equal(request.details.messageTypeName, 'REQUEST');
  assert.equal(request.details.requestedIp, '192.0.2.30');
  assert.equal(ack.details.messageTypeName, 'ACK');
});

test('DHCP option overrun is malformed-visible with a warning, not silently healthy', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-bad-dhcp-option.pcap').bytes));
  const p = capture.packets[0];
  assert.equal(p.protocol, 'dhcp');
  assert.equal(p.status, 'malformed');
  assert.equal(p.reason, 'dhcp-option-overrun');
  assert.equal(p.details.messageType, 1, 'option 53 before the bad option is still decoded');
  assert.ok(capture.warnings.some(w => w.code === 'W_DHCP_OPTION_LEN'));
  assert.ok(capture.coverage.limited);
});

test('DHCP without the magic cookie is flagged and options are not parsed', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-bad-dhcp-cookie.pcap').bytes));
  const p = capture.packets[0];
  assert.equal(p.status, 'malformed');
  assert.equal(p.reason, 'dhcp-no-cookie');
  assert.equal(p.details.messageType, null);
  assert.equal(p.details.xid, 0x99887766, 'header fields remain useful');
  assert.ok(capture.warnings.some(w => w.code === 'W_DHCP_COOKIE'));
});

test('DHCP option overload is declared unsupported instead of silently ignored', () => {
  const msg = F.dhcp({
    op: 1, xid: 7, chaddr: F.MAC.client,
    options: [F.dhcpMsgType(1), F.dhcpOpt(52, [1]), F.dhcpOpt(255, Buffer.alloc(0))]
  });
  const frame = F.ethernet({ dst: F.BCAST, src: F.MAC.client, ethertype: 0x0800, payload: F.ipv4({ src: '0.0.0.0', dst: '255.255.255.255', proto: 17, payload: F.udp({ sp: 68, dp: 67, payload: msg }) }) });
  const capture = ok(core.parseCapture(F.pcapFile({ variant: 'le-us', packets: [{ data: frame, tsSec: F.T0, tsFrac: 1 }] }).bytes));
  assert.ok(capture.warnings.some(w => w.code === 'W_DHCP_OVERLOAD'));
  assert.equal(capture.packets[0].details.overload, 1);
});

test('mDNS query decodes name/type and the QU bit', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-lan-le-us.pcap').bytes));
  const query = capture.packets[6];
  assert.equal(query.protocol, 'mdns');
  assert.equal(query.details.isResponse, false);
  assert.equal(query.details.questions[0].name, 'fictional-printer.local');
  assert.equal(query.details.questions[0].typeName, 'A');
  assert.equal(query.details.questions[0].qu, false);
  const quFrame = F.mdnsQuery({ name: 'fictional-nas.local', qu: true });
  const qu = ok(core.parseCapture(F.pcapFile({ variant: 'le-us', packets: [{ data: quFrame, tsSec: F.T0, tsFrac: 1 }] }).bytes));
  assert.equal(qu.packets[0].details.questions[0].qu, true, 'top class bit is the unicast-response bit');
});

test('mDNS response decodes a compression pointer and the cache-flush bit', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-lan-le-us.pcap').bytes));
  const response = capture.packets[7];
  assert.equal(response.details.isResponse, true);
  assert.equal(response.details.pointerCount, 1);
  const answer = response.details.answers[0];
  assert.equal(answer.name, 'fictional-printer.local', 'pointer must be expanded to the full name');
  assert.equal(answer.typeName, 'A');
  assert.equal(answer.cacheFlush, true);
  assert.equal(answer.address, '192.0.2.40');
  assert.equal(answer.ttl, 120);
});

test('DNS pointer cycles are detected and the packet is not decoded as healthy', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-bad-dns-loop.pcap').bytes));
  const p = capture.packets[0];
  assert.equal(p.status, 'malformed');
  assert.equal(p.reason, 'dns-loop');
  assert.ok(capture.warnings.some(w => w.code === 'W_DNS_LOOP'));
});

test('DNS pointers outside the message are detected', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-bad-dns-pointer.pcap').bytes));
  assert.equal(capture.packets[0].status, 'malformed');
  assert.equal(capture.packets[0].reason, 'dns-pointer-range');
  assert.ok(capture.warnings.some(w => w.code === 'W_DNS_POINTER_RANGE'));
});

test('oversized DNS labels and names are rejected per RFC 1035 limits', () => {
  const longLabel = 'x'.repeat(64) + '.local';
  const longName = ('y'.repeat(60) + '.').repeat(5) + 'local';
  const capture = ok(core.parseCapture(F.pcapFile({ variant: 'le-us', packets: [
    { data: F.mdnsQuery({ name: longLabel }), tsSec: F.T0, tsFrac: 1 },
    { data: F.mdnsQuery({ name: longName }), tsSec: F.T0, tsFrac: 2 }
  ] }).bytes));
  assert.equal(capture.packets[0].reason, 'dns-label-length');
  assert.equal(capture.packets[1].reason, 'dns-name-length');
  assert.ok(capture.warnings.some(w => w.code === 'W_DNS_LABEL_LENGTH'));
  assert.ok(capture.warnings.some(w => w.code === 'W_DNS_NAME_LENGTH'));
});

test('IPv6, other-protocol IPv4, and fragments are counted as not decoded', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-lan-le-us.pcap').bytes));
  const ipv6 = capture.packets.find(p => p.protocol === 'ipv6');
  const other = capture.packets.find(p => p.reason === 'ipv4-other-protocol');
  assert.ok(ipv6 && other);
  assert.equal(ipv6.status, 'unsupported');
  const frag = ok(core.parseCapture(fixture('synthetic-bad-fragment.pcap').bytes));
  assert.equal(frag.packets[0].reason, 'fragmented');
  assert.equal(frag.packets[0].protocol, 'ipv4-fragment');
  assert.notEqual(frag.packets[0].details && frag.packets[0].details.messageType, 1, 'fragment must never decode as DHCP');
});

test('IPv4 header options are skipped correctly (IHL > 5)', () => {
  const msg = F.dhcp({ op: 1, xid: 9, chaddr: F.MAC.client, options: [F.dhcpMsgType(1), F.dhcpOpt(255, Buffer.alloc(0))] });
  const frame = F.ethernet({
    dst: F.BCAST, src: F.MAC.client, ethertype: 0x0800,
    payload: F.ipv4({ src: '0.0.0.0', dst: '255.255.255.255', proto: 17, ihlOptions: Buffer.from([0x94, 0x04, 0x00, 0x00]), payload: F.udp({ sp: 68, dp: 67, payload: msg }) })
  });
  const capture = ok(core.parseCapture(F.pcapFile({ variant: 'le-us', packets: [{ data: frame, tsSec: F.T0, tsFrac: 1 }] }).bytes));
  assert.equal(capture.packets[0].protocol, 'dhcp');
  assert.equal(capture.packets[0].details.messageType, 1);
});

test('UDP length field larger than the captured bytes is flagged, not decoded', () => {
  const msg = F.dhcp({ op: 1, xid: 3, chaddr: F.MAC.client, options: [F.dhcpMsgType(1)] });
  const frame = F.ethernet({
    dst: F.BCAST, src: F.MAC.client, ethertype: 0x0800,
    payload: F.ipv4({ src: '0.0.0.0', dst: '255.255.255.255', proto: 17, payload: F.udp({ sp: 68, dp: 67, payload: msg, lenOverride: 5000 }) })
  });
  const capture = ok(core.parseCapture(F.pcapFile({ variant: 'le-us', packets: [{ data: frame, tsSec: F.T0, tsFrac: 1 }] }).bytes));
  assert.equal(capture.packets[0].status, 'malformed');
  assert.equal(capture.packets[0].reason, 'udp-length-mismatch');
  assert.ok(capture.warnings.some(w => w.code === 'W_UDP_LENGTH'));
});

test('Ethernet padding beyond the UDP length is ignored, not treated as data', () => {
  const msg = F.dhcp({ op: 1, xid: 4, chaddr: F.MAC.client, options: [F.dhcpMsgType(1), F.dhcpOpt(255, Buffer.alloc(0))] });
  const frame = F.ethernet({
    dst: F.BCAST, src: F.MAC.client, ethertype: 0x0800,
    payload: F.ipv4({ src: '0.0.0.0', dst: '255.255.255.255', proto: 17, payload: F.udp({ sp: 68, dp: 67, payload: msg }) })
  });
  const padded = F.concat([frame, Buffer.alloc(12)]); // pad to a longer frame
  const capture = ok(core.parseCapture(F.pcapFile({ variant: 'le-us', packets: [{ data: padded, tsSec: F.T0, tsFrac: 1 }] }).bytes));
  assert.equal(capture.packets[0].protocol, 'dhcp');
  assert.equal(capture.packets[0].details.messageType, 1);
});

test('zero-length packet records are visible, not silently skipped', () => {
  const capture = ok(core.parseCapture(F.pcapFile({ variant: 'le-us', packets: [{ data: Buffer.alloc(0), tsSec: F.T0, tsFrac: 1 }] }).bytes));
  assert.equal(capture.counts.seen, 1);
  assert.equal(capture.packets[0].reason, 'empty');
  assert.ok(capture.warnings.some(w => w.code === 'W_EMPTY_RECORD'));
});

test('prototype-member identifiers (__proto__, constructor) are handled as plain data', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-prototype-names.pcap').bytes));
  assert.equal(capture.counts.decoded, 3);
  const model = ok(core.analyze(capture, { sourceFile: 'synthetic-prototype-names.pcap' }));
  const hostObs = model.observations.find(o => o.kind === 'dhcp-discover');
  assert.equal(hostObs.details.hostname, 'constructor');
  const query = model.observations.find(o => o.kind === 'mdns-query');
  assert.equal(query.details.questions[0].name, '__proto__.local');
  // no prototype pollution
  assert.equal(Object.keys(Object.prototype).length, 0);
  assert.equal({}.polluted, undefined);
});

// ---------------------------------------------------------------------------
// resource limits
// ---------------------------------------------------------------------------
test('file above maxBytes is rejected with E_TOO_LARGE before parsing', () => {
  const error = err(core.parseCapture(Buffer.alloc(core.LIMITS.maxBytes + 1)));
  assert.equal(error.code, 'E_TOO_LARGE');
});

test('packet cap stops parsing with a visible limited-coverage warning', () => {
  const packets = [];
  for (let i = 0; i < core.LIMITS.maxPackets + 5; i++) {
    packets.push({ data: Buffer.alloc(30, i & 0xff), tsSec: F.T0, tsFrac: i });
  }
  const capture = ok(core.parseCapture(F.pcapFile({ variant: 'le-us', packets }).bytes));
  assert.equal(capture.packets.length, core.LIMITS.maxPackets);
  assert.equal(capture.coverage.limited, true);
  assert.ok(capture.warnings.some(w => w.code === 'W_LIMIT_PACKETS'));
});

test('warning cap keeps a visible truncation marker', () => {
  const packets = [];
  for (let i = 0; i < core.LIMITS.maxWarnings + 10; i++) {
    packets.push({ data: Buffer.alloc(60), tsSec: F.T0, tsFrac: i, inclLenOverride: 60, origLenOverride: 20 });
  }
  const capture = ok(core.parseCapture(F.pcapFile({ variant: 'le-us', packets }).bytes));
  assert.equal(capture.warnings.length, core.LIMITS.maxWarnings);
  assert.equal(capture.warningsTruncated, true);
  assert.ok(capture.warnings.some(w => w.code === 'W_LIMIT_WARNINGS'));
});

test('snaplen smaller than a record length caps the delivered bytes and warns', () => {
  const bytes = F.pcapFile({ variant: 'le-us', snaplen: 64, packets: [{ data: F.arpRequest(), tsSec: F.T0, tsFrac: 1, inclLenOverride: 42, origLenOverride: 42 }] }).bytes;
  const capture = ok(core.parseCapture(bytes));
  assert.equal(capture.pcap.snaplen, 64);
  assert.equal(capture.packets[0].caplen, 42, '42 < snaplen 64, so nothing is cut');
  const bytes2 = F.pcapFile({ variant: 'le-us', snaplen: 40, packets: [{ data: Buffer.alloc(60), tsSec: F.T0, tsFrac: 1 }] }).bytes;
  const capture2 = ok(core.parseCapture(bytes2));
  assert.equal(capture2.packets[0].caplen, 40, 'libpcap delivers at most snaplen bytes');
  assert.equal(capture2.packets[0].origlen, 60);
  assert.ok(capture2.warnings.some(w => w.code === 'W_SNAPLEN_CAP'));
});

// ---------------------------------------------------------------------------
// analysis: observations, evidence refs, qualified findings, counterexamples
// ---------------------------------------------------------------------------
test('every observation carries packet index, byte offset, timestamp, interface and VLAN refs', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-lan-le-us.pcap').bytes));
  const model = ok(core.analyze(capture, { sourceFile: 'synthetic-lan-le-us.pcap' }));
  assert.ok(model.observations.length >= 10);
  for (const obs of model.observations) {
    assert.ok(obs.refs.length >= 1, obs.kind + ' must cite evidence');
    for (const ref of obs.refs) {
      assert.equal(typeof ref.packetIndex, 'number');
      assert.equal(typeof ref.fileOffset, 'number');
      assert.equal(typeof ref.timestampText, 'string');
      assert.equal(typeof ref.interfaceId, 'number');
      assert.ok(Array.isArray(ref.vlanIds));
    }
  }
  const arp = model.observations.find(o => o.kind === 'arp-reply');
  assert.equal(arp.refs[0].packetIndex, 1);
  assert.equal(arp.refs[0].fileOffset, capture.packets[1].fileOffset);
  assert.equal(arp.refs[0].timestampText, capture.packets[1].timestamp.text);
});

test('ARP observations carry enough detail to be useful evidence', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-lan-le-us.pcap').bytes));
  const model = ok(core.analyze(capture, { sourceFile: 'x.pcap' }));
  const req = model.observations.find(o => o.kind === 'arp-request');
  assert.match(req.summary, /who-has 192\.0\.2\.20 tell 192\.0\.2\.10/);
  const dhcp = model.observations.find(o => o.kind === 'dhcp-discover');
  assert.equal(dhcp.details.hostname, 'fictional-laptop');
  assert.equal(dhcp.details.clientMac, 'aa:00:00:00:00:30');
  const mdns = model.observations.find(o => o.kind === 'mdns-response');
  assert.equal(mdns.details.answers[0].address, '192.0.2.40');
});

test('possible IP/MAC conflict is qualified and scoped to one interface/VLAN context', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-lan-le-us.pcap').bytes));
  const model = ok(core.analyze(capture, { sourceFile: 'x.pcap' }));
  const conflict = model.findings.find(f => f.kind === 'possible-ip-mac-conflict');
  assert.ok(conflict, 'expected a qualified conflict candidate');
  const indexes = conflict.refs.map(r => r.packetIndex).sort((a, b) => a - b);
  assert.deepEqual(indexes, [1, 9], 'only same-VLAN claims count');
  assert.ok(!indexes.includes(10), 'VLAN 42 claim must not be merged');
  assert.match(conflict.statement, /192\.0\.2\.20/);
  assert.match(conflict.qualification, /not (proof|conclusive)|cannot prove|may/i);
  assert.ok(conflict.counterexamples.length >= 2, 'counterexamples must be stated');
  assert.ok(conflict.counterexamples.some(c => /probe/i.test(c)));
  assert.ok(conflict.counterexamples.some(c => /VLAN|interface|section/i.test(c)));
});

test('counterexample: same IP on two MACs in different VLANs produces no conflict finding', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-counter-vlan-split.pcap').bytes));
  const model = ok(core.analyze(capture, { sourceFile: 'x.pcap' }));
  assert.equal(model.findings.filter(f => f.kind === 'possible-ip-mac-conflict').length, 0);
});

test('counterexample: ARP probes alone never create a conflict or an in-use claim', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-counter-probe-only.pcap').bytes));
  const model = ok(core.analyze(capture, { sourceFile: 'x.pcap' }));
  assert.equal(model.findings.filter(f => f.kind === 'possible-ip-mac-conflict').length, 0);
  assert.equal(model.findings.filter(f => f.kind === 'probe-for-in-use-address').length, 0);
  assert.ok(model.observations.some(o => o.kind === 'arp-probe'), 'probes are still observed');
});

test('probe for an address that DHCP just assigned is a qualified observation', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-lan-le-us.pcap').bytes));
  const model = ok(core.analyze(capture, { sourceFile: 'x.pcap' }));
  const probe = model.findings.find(f => f.kind === 'probe-for-in-use-address');
  assert.ok(probe, 'probe targeting a recently assigned address is surfaced');
  assert.ok(probe.refs.some(r => r.packetIndex === 8));
  assert.match(probe.qualification, /may|normal|not proof/i);
});

test('counterexample: one MAC with two addresses is an informational transition, not a conflict', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-counter-transition.pcap').bytes));
  const model = ok(core.analyze(capture, { sourceFile: 'x.pcap' }));
  assert.equal(model.findings.filter(f => f.kind === 'possible-ip-mac-conflict').length, 0);
  const transition = model.findings.find(f => f.kind === 'arp-address-transition');
  assert.ok(transition, 'transition is reported informationally');
  assert.equal(transition.severity, 'info');
});

test('counterexample: identical address claims in different pcapng sections are not merged', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-counter-multi-section.pcapng').bytes));
  const model = ok(core.analyze(capture, { sourceFile: 'x.pcapng' }));
  assert.equal(model.findings.filter(f => f.kind === 'possible-ip-mac-conflict').length, 0);
});

test('duplicate DHCP assignment to different clients is a qualified finding', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-counter-dhcp-duplicate.pcap').bytes));
  const model = ok(core.analyze(capture, { sourceFile: 'x.pcap' }));
  const dup = model.findings.find(f => f.kind === 'possible-duplicate-dhcp-assignment');
  assert.ok(dup);
  assert.deepEqual(dup.refs.map(r => r.packetIndex).sort((a, b) => a - b), [0, 1, 2, 3]);
  assert.match(dup.qualification, /not proof|cannot prove|may/i);
});

test('counterexample: a retransmitted DHCP offer to the same client is not a duplicate assignment', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-counter-dhcp-retransmit.pcap').bytes));
  const model = ok(core.analyze(capture, { sourceFile: 'x.pcap' }));
  assert.equal(model.findings.filter(f => f.kind === 'possible-duplicate-dhcp-assignment').length, 0);
});

test('analysis states capture-visibility limitations (no absence-of-fault claims)', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-lan-le-us.pcap').bytes));
  const model = ok(core.analyze(capture, { sourceFile: 'x.pcap' }));
  const text = model.limitations.join(' ');
  assert.match(text, /cannot prove the absence/i);
  assert.match(text, /switch/i);
  assert.match(text, /VLAN/i);
  assert.ok(model.limitations.length >= 3);
});

test('observation cap is enforced and visible', () => {
  const packets = [];
  const total = core.LIMITS.maxObservations + 25;
  for (let i = 0; i < total; i++) packets.push({ data: F.arpRequest({ sha: 'aa:00:00:00:00:10', spa: '192.0.2.10', tpa: '192.0.2.' + (i % 250) }), tsSec: F.T0, tsFrac: i });
  const capture = ok(core.parseCapture(F.pcapFile({ variant: 'le-us', packets }).bytes));
  const model = ok(core.analyze(capture, { sourceFile: 'x.pcap' }));
  assert.equal(model.observations.length, core.LIMITS.maxObservations);
  assert.equal(model.limits.observationsTruncated, true);
  assert.ok(model.warnings.some(w => w.code === 'W_LIMIT_OBSERVATIONS'));
});

// ---------------------------------------------------------------------------
// reports: redaction by default, identifier opt-in, standalone HTML
// ---------------------------------------------------------------------------
test('default JSON report redacts MAC, IP, hostnames, service names, interface and file names', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-lan-le-us.pcap').bytes));
  const model = ok(core.analyze(capture, { sourceFile: 'synthetic-lan-le-us.pcap' }));
  const report = ok(core.buildReport(model, {}));
  const text = JSON.stringify(report.json);
  assert.equal(report.json.redaction.mode, 'redacted');
  for (const secret of ['aa:00:00:00:00:30', '192.0.2.30', 'fictional-laptop', 'fictional-printer.local', 'synthetic-lan-le-us.pcap']) {
    assert.ok(!text.includes(secret), 'default report must not leak ' + secret);
  }
  assert.ok(!text.includes('synthetic payload'), 'raw payload bytes are never in a report');
  assert.match(text, /mac-\d\d/, 'MAC ordinals present');
  assert.match(text, /ip-\d\d/, 'IP ordinals present');
});

test('redaction is consistent: the same MAC keeps the same ordinal everywhere', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-lan-le-us.pcap').bytes));
  const model = ok(core.analyze(capture, { sourceFile: 'x.pcap' }));
  const report = ok(core.buildReport(model, {}));
  const conflict = report.json.findings.find(f => f.kind === 'possible-ip-mac-conflict');
  const statements = JSON.stringify(conflict);
  const ordinals = new Set([...statements.matchAll(/mac-\d\d/g)].map(m => m[0]));
  assert.ok(ordinals.size >= 2, 'two distinct MAC ordinals expected');
  const macToOrdinal = report.json.redaction.ordinals.mac;
  assert.equal(new Set(Object.values(macToOrdinal)).size, Object.keys(macToOrdinal).length, 'ordinals are unique per value');
});

test('identifier opt-in includes raw values, still without payloads', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-lan-le-us.pcap').bytes));
  const model = ok(core.analyze(capture, { sourceFile: 'synthetic-lan-le-us.pcap' }));
  const report = ok(core.buildReport(model, { includeIdentifiers: true }));
  const text = JSON.stringify(report.json);
  assert.equal(report.json.redaction.mode, 'identifiers');
  assert.ok(text.includes('aa:00:00:00:00:30'));
  assert.ok(text.includes('192.0.2.30'));
  assert.ok(text.includes('fictional-laptop'));
  assert.ok(!text.includes('synthetic payload'), 'payload bytes still excluded');
});

test('standalone HTML report is script-free, escaped, and carries coverage + limitations', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-prototype-names.pcap').bytes));
  const model = ok(core.analyze(capture, { sourceFile: 'prototype.pcap' }));
  const report = ok(core.buildReport(model, { includeIdentifiers: true }));
  const html = report.html;
  assert.match(html, /^<!DOCTYPE html>/i);
  assert.ok(!/<script/i.test(html), 'HTML report must be script-free');
  assert.ok(!/https?:\/\//i.test(html), 'HTML report must not reference remote resources');
  assert.ok(!html.includes('<img src=x'), 'hostile name must be escaped');
  assert.ok(html.includes('&lt;img src=x'), 'escaped form present');
  assert.match(html, /cannot prove the absence/i);
  assert.match(html, /not decoded|unsupported/i, 'coverage must be visible in the report');
  assert.match(html, /__proto__\.local/, 'opt-in identifiers appear escaped, as text');
});

test('default HTML report redacts identifiers too', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-lan-le-us.pcap').bytes));
  const model = ok(core.analyze(capture, { sourceFile: 'synthetic-lan-le-us.pcap' }));
  const report = ok(core.buildReport(model, {}));
  assert.ok(!report.html.includes('aa:00:00:00:00:30'));
  assert.ok(!report.html.includes('fictional-laptop'));
  assert.match(report.html, /REDACTED/);
});

test('JSON report includes per-packet evidence references and coverage counts', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-lan-le-us.pcap').bytes));
  const model = ok(core.analyze(capture, { sourceFile: 'x.pcap' }));
  const report = ok(core.buildReport(model, {}));
  assert.equal(report.json.capture.counts.seen, 15);
  assert.equal(report.json.capture.counts.decoded, 12);
  assert.equal(report.json.capture.counts.unsupported, 3);
  assert.ok(report.json.capture.coverage.limited);
  const obs = report.json.observations[0];
  assert.ok(obs.refs[0].packetIndex >= 0);
  assert.equal(typeof obs.refs[0].fileOffset, 'number');
  assert.ok(Array.isArray(report.json.limitations));
  assert.ok(report.json.generatedAt);
});

test('pcapng interface names are redacted by default and included on opt-in', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-multi-section.pcapng').bytes));
  const model = ok(core.analyze(capture, { sourceFile: 'multi.pcapng' }));
  const redacted = ok(core.buildReport(model, {}));
  assert.ok(!JSON.stringify(redacted.json).includes('fictional-eth0'), 'if_name must not leak by default');
  assert.ok(!redacted.html.includes('fictional-eth0'));
  assert.match(JSON.stringify(redacted.json), /iface-01/);
  const identified = ok(core.buildReport(model, { includeIdentifiers: true }));
  assert.ok(JSON.stringify(identified.json).includes('fictional-eth0'), 'opt-in keeps the interface name');
});

test('raw packet payload bytes and raw DHCP client-id bytes are never retained', () => {
  const capture = ok(core.parseCapture(fixture('synthetic-lan-le-us.pcap').bytes));
  const model = ok(core.analyze(capture, { sourceFile: 'x.pcap' }));
  const serialized = JSON.stringify(model);
  assert.ok(!serialized.includes('synthetic payload'), 'the plainUdp payload string must not survive decoding');
  // option 61 carried [1, aa:00:00:00:00:30]; only a presence flag may remain
  assert.ok(!serialized.includes('01aa00000000'), 'raw client-id bytes must not be retained');
  for (const packet of model.packets) {
    assert.equal(packet.payload, undefined, 'no payload field on packets');
    assert.equal(packet.data, undefined, 'no raw data field on packets');
  }
  const report = ok(core.buildReport(model, { includeIdentifiers: true }));
  assert.ok(!JSON.stringify(report.json).includes('synthetic payload'));
});

// ---------------------------------------------------------------------------
// fix-round-1 regressions: pcapng primary layout (C1), if_tsresol (I1),
// option framing (I2/M1) and the block/section/interface caps.
//
// These cases build their bytes directly from the primary field layout
// (draft-tuexen-opsawg-pcapng-05 Figures 7 and 11: Timestamp High at block
// +12, Timestamp Low at block +16, each a 32-bit field in section byte
// order) and never use the fixture generator, so a wrong framing assumption
// cannot be shared by parser and fixtures ("fixtures cannot prove their own
// framing assumptions").
// ---------------------------------------------------------------------------
function primaryBlock(little, type, body) {
  const padded = Buffer.concat([body, Buffer.alloc((4 - (body.length % 4)) % 4)]);
  const total = 12 + padded.length;
  const out = Buffer.alloc(total);
  const put32 = (value, at) => little ? out.writeUInt32LE(value >>> 0, at) : out.writeUInt32BE(value >>> 0, at);
  put32(type, 0); put32(total, 4);
  padded.copy(out, 8);
  put32(total, total - 4);
  return out;
}
function primaryOption(little, code, data) {
  const out = Buffer.alloc(4 + data.length + ((4 - (data.length % 4)) % 4));
  if (little) { out.writeUInt16LE(code, 0); out.writeUInt16LE(data.length, 2); }
  else { out.writeUInt16BE(code, 0); out.writeUInt16BE(data.length, 2); }
  data.copy(out, 4);
  return out;
}
function primaryShb(little, options = []) {
  const body = Buffer.alloc(16);
  if (little) { body.writeUInt32LE(0x1a2b3c4d, 0); body.writeUInt16LE(1, 4); body.writeUInt16LE(0, 6); body.writeUInt32LE(0xffffffff, 8); body.writeUInt32LE(0xffffffff, 12); }
  else { body.writeUInt32BE(0x1a2b3c4d, 0); body.writeUInt16BE(1, 4); body.writeUInt16BE(0, 6); body.writeUInt32BE(0xffffffff, 8); body.writeUInt32BE(0xffffffff, 12); }
  return primaryBlock(little, 0x0a0d0d0a, Buffer.concat([body, ...options]));
}
function primaryIdb(little, options = []) {
  const body = Buffer.alloc(8);
  if (little) { body.writeUInt16LE(1, 0); body.writeUInt32LE(65535, 4); }
  else { body.writeUInt16BE(1, 0); body.writeUInt32BE(65535, 4); }
  return primaryBlock(little, 1, Buffer.concat([body, ...options]));
}
function primaryEpb(little, { high = 0, low = 0, data = stubFrame(), options = [] }) {
  const body = Buffer.alloc(20);
  if (little) { body.writeUInt32LE(0, 0); body.writeUInt32LE(high >>> 0, 4); body.writeUInt32LE(low >>> 0, 8); body.writeUInt32LE(data.length, 12); body.writeUInt32LE(data.length, 16); }
  else { body.writeUInt32BE(0, 0); body.writeUInt32BE(high >>> 0, 4); body.writeUInt32BE(low >>> 0, 8); body.writeUInt32BE(data.length, 12); body.writeUInt32BE(data.length, 16); }
  const paddedData = Buffer.concat([data, Buffer.alloc((4 - (data.length % 4)) % 4)]);
  return primaryBlock(little, 6, Buffer.concat([body, paddedData, ...options]));
}
function stubFrame() {
  const frame = Buffer.alloc(14);
  frame.writeUInt16BE(0x88b5, 12); // unsupported ethertype: no invented protocol data
  return frame;
}
const primaryEndOfOptions = little => primaryOption(little, 0, Buffer.alloc(0));

test('fix-round-1 C1: EPB timestamp is Timestamp High (block +12) then Low (block +16), each in section byte order', () => {
  for (const little of [true, false]) {
    for (const [high, low] of [[0, 1000000], [1, 1000000], [1, 17]]) {
      const bytes = Buffer.concat([primaryShb(little), primaryIdb(little), primaryEpb(little, { high, low })]);
      // meta-check: the constructed bytes really are normative (High first, per field endianness)
      const epbOffset = 28 + 20;
      const wordAt = at => little ? bytes.readUInt32LE(at) : bytes.readUInt32BE(at);
      assert.equal(wordAt(epbOffset + 12), high, 'test bytes: block +12 carries Timestamp (High)');
      assert.equal(wordAt(epbOffset + 16), low, 'test bytes: block +16 carries Timestamp (Low)');
      const capture = ok(core.parseCapture(bytes));
      const expected = Number((BigInt(high) * 4294967296n + BigInt(low)) / 1000000n);
      const tag = (little ? 'LE' : 'BE') + ' high=' + high + ' low=' + low;
      assert.equal(capture.packets[0].timestamp.seconds, expected, tag + ' seconds');
      assert.equal(capture.packets[0].timestamp.exact, true, tag + ' exact');
    }
  }
});

test('fix-round-1 C1: the same logical EPB time in an LE and a BE section displays identically', () => {
  const text = little => ok(core.parseCapture(Buffer.concat([
    primaryShb(little), primaryIdb(little), primaryEpb(little, { high: 1, low: 17 })
  ]))).packets[0].timestamp.text;
  assert.equal(text(true), text(false), 'LE and BE must agree on the same logical time');
  assert.equal(text(true), '1970-01-01 01:11:34.967313 UTC', 'value = High*2^32 + Low in both byte orders');
});

test('fix-round-1 C1: 64-bit numeric boundary — resolution-aware (fix round 2)', () => {
  // Fix round 2: the raw tick count is no longer pre-rejected at 2^53. With the
  // default microsecond resolution, 2^53 ticks scale to 9007199254 s (safe and
  // displayable) and stay exact. The max uint64 scales to 18446744073709 s,
  // which fits 53 bits but is beyond the Date display range, so it stays
  // out-of-range with seconds:null/exact:false (never a rounded exact time).
  const cases = [
    { high: 0x1fffff, low: 0xffffffff, flagged: false },  // exactly 2^53-1
    { high: 0x200000, low: 0, flagged: false },           // exactly 2^53 -> exact after /1e6
    { high: 0xffffffff, low: 0xffffffff, flagged: true }  // largest 64-bit value -> out of display range
  ];
  for (const little of [true, false]) {
    for (const item of cases) {
      const bytes = Buffer.concat([primaryShb(little), primaryIdb(little), primaryEpb(little, { high: item.high, low: item.low })]);
      const capture = ok(core.parseCapture(bytes));
      assert.doesNotThrow(() => JSON.stringify(capture), 'capture must stay JSON-safe (no BigInt leak)');
      const stamp = capture.packets[0].timestamp;
      const tag = (little ? 'LE' : 'BE') + ' high=' + item.high + ' low=' + item.low;
      if (item.flagged) {
        assert.equal(stamp.seconds, null, tag + ' seconds');
        assert.equal(stamp.exact, false, tag + ' exact');
        assert.equal(stamp.text, 'timestamp out of displayable range', tag + ' text');
        assert.ok(capture.warnings.some(w => w.code === 'W_TIMESTAMP_RANGE'), tag + ' W_TIMESTAMP_RANGE');
      } else {
        const raw = BigInt(item.high) * 4294967296n + BigInt(item.low);
        assert.equal(stamp.seconds, Number(raw / 1000000n), tag + ' seconds');
        assert.equal(stamp.exact, true, tag + ' exact');
        assert.ok(!capture.warnings.some(w => w.code === 'W_TIMESTAMP_RANGE'), tag + ' no spurious range warning');
      }
    }
  }
});

test('fix-round-1 C1: shipped pcapng fixture stores EPB words High-first per section byte order (byte level)', () => {
  const { bytes } = fixture('synthetic-multi-section.pcapng');
  const capture = ok(core.parseCapture(bytes));
  const leEpb = capture.packets.find(p => p.blockType === 'enhanced-packet' && p.sectionIndex === 0);
  const beEpb = capture.packets.find(p => p.blockType === 'enhanced-packet' && p.sectionIndex === 1 && p.interfaceId === 0);
  assert.ok(leEpb && beEpb, 'fixture contains both LE and BE enhanced packets');
  const ticksLe = BigInt(F.T0) * 1000000n + 100000n;
  assert.equal(bytes.readUInt32LE(leEpb.fileOffset + 12), Number((ticksLe >> 32n) & 0xffffffffn), 'LE block +12 is Timestamp (High)');
  assert.equal(bytes.readUInt32LE(leEpb.fileOffset + 16), Number(ticksLe & 0xffffffffn), 'LE block +16 is Timestamp (Low)');
  const ticksBe = BigInt(F.T0) * 1024n + 512n;
  assert.equal(bytes.readUInt32BE(beEpb.fileOffset + 12), Number((ticksBe >> 32n) & 0xffffffffn), 'BE block +12 is Timestamp (High)');
  assert.equal(bytes.readUInt32BE(beEpb.fileOffset + 16), Number(ticksBe & 0xffffffffn), 'BE block +16 is Timestamp (Low)');
});

test('fix-round-1 I1: if_tsresol 10^-13 and 2^-41 keep the declared scale and never fabricate 10^-6', () => {
  const cases = [
    { value: 13, base: 10, exponent: 13, ticks: 10000000000000n, seconds: 1 },       // 10^13 units = exactly 1 s
    { value: 0x80 | 41, base: 2, exponent: 41, ticks: 1n << 41n, seconds: 1 }        // 2^41 units = exactly 1 s
  ];
  for (const little of [true, false]) {
    for (const item of cases) {
      const bytes = Buffer.concat([
        primaryShb(little),
        primaryIdb(little, [primaryOption(little, 9, Buffer.from([item.value])), primaryEndOfOptions(little)]),
        primaryEpb(little, { high: Number((item.ticks >> 32n) & 0xffffffffn), low: Number(item.ticks & 0xffffffffn) })
      ]);
      const capture = ok(core.parseCapture(bytes));
      const tag = (little ? 'LE' : 'BE') + ' ' + item.base + '^-' + item.exponent;
      assert.deepEqual(capture.sections[0].interfaces[0].tsresol, { base: item.base, exponent: item.exponent },
        tag + ': declared resolution must be recorded exactly as declared');
      const stamp = capture.packets[0].timestamp;
      if (stamp.seconds === null) {
        assert.equal(stamp.exact, false, tag + ': unrepresentable time must not claim exactness');
      } else {
        assert.equal(stamp.seconds, item.seconds, tag + ' seconds');
        assert.equal(stamp.exact, false, tag + ': sub-millisecond resolutions are approximate-marked');
        assert.match(stamp.text, /approx/, tag + ' text flags the approximation');
        assert.match(stamp.text, new RegExp(item.base + '\\^-' + item.exponent), tag + ' text states the declared resolution');
      }
    }
  }
});

test('fix-round-1 I2: unsupported options in SHB/IDB/EPB are counted, warned, and limit coverage without exposing content', () => {
  const SENTINEL = 'OPTION-CONTENT-MUST-NOT-LEAK';
  for (const little of [true, false]) {
    const cases = {
      shb: [primaryShb(little, [primaryOption(little, 4, Buffer.from(SENTINEL))])],                        // shb_userappl
      idb: [primaryShb(little), primaryIdb(little, [primaryOption(little, 99, Buffer.from(SENTINEL))])],
      epb: [primaryShb(little), primaryIdb(little), primaryEpb(little, { high: 0, low: 1000000, options: [primaryOption(little, 2, Buffer.from(SENTINEL))] })] // epb_flags
    };
    for (const where of Object.keys(cases)) {
      const capture = ok(core.parseCapture(Buffer.concat(cases[where])));
      const tag = (little ? 'LE' : 'BE') + ' ' + where;
      assert.equal(capture.counts.unsupportedOptions, 1, tag + ': one unsupported option counted');
      const warning = capture.warnings.find(w => w.code === 'W_OPTION_UNSUPPORTED');
      assert.ok(warning, tag + ': W_OPTION_UNSUPPORTED present');
      assert.match(warning.message, /option/i, tag);
      assert.match(warning.message, /unsupported|skipped|ignored/i, tag);
      assert.equal(capture.coverage.limited, true, tag + ': coverage must be limited');
      assert.ok(capture.coverage.reasons.some(r => /option/i.test(r)), tag + ': coverage reason mentions options');
      const exposed = JSON.stringify(capture.warnings) + JSON.stringify(capture.coverage);
      assert.ok(!exposed.includes(SENTINEL), tag + ': raw option content must never be exposed');
    }
  }
});

test('fix-round-1 I2: a benign end-of-options marker alone is not unsupported content', () => {
  const bytes = Buffer.concat([
    primaryShb(true, [primaryEndOfOptions(true)]),
    primaryIdb(true, [primaryEndOfOptions(true)]),
    primaryEpb(true, { high: 0, low: 1000000, options: [primaryEndOfOptions(true)] })
  ]);
  const capture = ok(core.parseCapture(bytes));
  assert.equal(capture.counts.unsupportedOptions, 0);
  assert.equal(capture.counts.malformedOptions, 0);
  assert.ok(!capture.warnings.some(w => w.code === 'W_OPTION_UNSUPPORTED' || w.code === 'W_OPTION_END_MARKER'));
});

test('fix-round-1 M1: a code-0 option with length > 0 is a malformed end marker, warned and counted', () => {
  for (const little of [true, false]) {
    const cases = {
      shb: [primaryShb(little, [primaryOption(little, 0, Buffer.alloc(4))])],
      idb: [primaryShb(little), primaryIdb(little, [primaryOption(little, 0, Buffer.alloc(4))])],
      epb: [primaryShb(little), primaryIdb(little), primaryEpb(little, { high: 0, low: 1000000, options: [primaryOption(little, 0, Buffer.alloc(4))] })]
    };
    for (const where of Object.keys(cases)) {
      const capture = ok(core.parseCapture(Buffer.concat(cases[where])));
      const tag = (little ? 'LE' : 'BE') + ' ' + where;
      assert.equal(capture.counts.malformedOptions, 1, tag + ': malformed end marker counted');
      assert.ok(capture.warnings.some(w => /option|end-of-options/i.test(w.message)), tag + ': malformed marker warned');
      assert.equal(capture.coverage.limited, true, tag);
    }
  }
});

test('fix-round-1 I2: an option whose declared length overruns its area is flagged and defaults are kept', () => {
  const header = Buffer.alloc(6);
  header.writeUInt16LE(9, 0); header.writeUInt16LE(5, 2); header[4] = 13; // declares 5 bytes, one present
  const idb = primaryBlock(true, 1, Buffer.concat([Buffer.alloc(8), header]));
  const capture = ok(core.parseCapture(Buffer.concat([primaryShb(true), idb, primaryEpb(true, { high: 0, low: 1000000 })])));
  assert.ok(capture.warnings.some(w => w.code === 'W_OPTION_LENGTH'), 'overrun warned');
  assert.equal(capture.counts.malformedOptions, 1, 'overrun counted as malformed option framing');
  assert.deepEqual(capture.sections[0].interfaces[0].tsresol, { base: 10, exponent: 6 }, 'default resolution kept');
  assert.equal(capture.packets.length, 1, 'the following EPB is still parsed');
  assert.equal(capture.packets[0].timestamp.seconds, 1);
  assert.equal(capture.coverage.limited, true);
});

test('fix-round-1 I1: an if_tsresol with the wrong length warns, keeps the default, and is counted', () => {
  const capture = ok(core.parseCapture(Buffer.concat([
    primaryShb(true),
    primaryIdb(true, [primaryOption(true, 9, Buffer.from([6, 0]))]),
    primaryEpb(true, { high: 0, low: 1000000 })
  ])));
  assert.ok(capture.warnings.some(w => w.code === 'W_OPTION_LENGTH'));
  assert.equal(capture.counts.malformedOptions, 1);
  assert.deepEqual(capture.sections[0].interfaces[0].tsresol, { base: 10, exponent: 6 });
});

test('fix-round-1: unsupported-option counting stays accurate when the warning cap suppresses messages', () => {
  const options = [];
  for (let i = 0; i < 300; i++) options.push(primaryOption(true, 100 + (i % 50), Buffer.from([1, 2, 3, 4])));
  const capture = ok(core.parseCapture(Buffer.concat([
    primaryShb(true), primaryIdb(true), primaryEpb(true, { high: 0, low: 1000000, options })
  ])));
  assert.equal(capture.counts.unsupportedOptions, 300, 'every unsupported option is counted even when warnings are capped');
  assert.ok(capture.warnings.length <= core.LIMITS.maxWarnings);
  assert.ok(capture.warningsTruncated && capture.warnings.some(w => w.code === 'W_LIMIT_WARNINGS'));
});

test('fix-round-1: option counters are visible in the analysis model and in both report forms', () => {
  const SENTINEL = 'OPTION-LEAK-CHECK';
  const capture = ok(core.parseCapture(Buffer.concat([
    primaryShb(true, [primaryOption(true, 4, Buffer.from(SENTINEL))]),
    primaryIdb(true, [primaryEndOfOptions(true)]),
    primaryEpb(true, { high: 0, low: 1000000 })
  ])));
  const model = ok(core.analyze(capture, { sourceFile: 'options.pcapng' }));
  assert.equal(model.capture.counts.unsupportedOptions, 1);
  const report = ok(core.buildReport(model, {}));
  assert.equal(report.json.capture.counts.unsupportedOptions, 1);
  assert.match(report.html, /skipped options: 1/);
  assert.ok(!report.html.includes(SENTINEL), 'option content is never rendered into the HTML report');
  assert.ok(!JSON.stringify(report.json).includes(SENTINEL), 'option content is never in the JSON report');
});

test('fix-round-1: embedded app.js samples are byte-identical to the shipped fixtures', () => {
  const appSource = fs.readFileSync(path.join(__dirname, '..', 'app.js'), 'utf8');
  const pairs = [
    { key: 'pcap', fixtureName: 'synthetic-lan-le-us.pcap' },
    { key: 'pcapng', fixtureName: 'synthetic-multi-section.pcapng' }
  ];
  for (const pair of pairs) {
    const match = appSource.match(new RegExp(pair.key + ": \\{ name: '([^']+)', b64: '([A-Za-z0-9+/=]+)'"));
    assert.ok(match, pair.key + ' sample present in app.js');
    const sample = Buffer.from(match[2], 'base64');
    const { bytes, entry } = fixture(pair.fixtureName);
    assert.equal(sample.length, bytes.length, pair.key + ' sample byte size');
    assert.equal(crypto.createHash('sha256').update(sample).digest('hex'), entry.sha256,
      pair.key + ' sample must match the manifest hash of ' + pair.fixtureName);
    assert.ok(sample.equals(bytes), pair.key + ' sample bytes');
  }
});

test('fix-round-1: maxBlocks cap stops parsing with W_LIMIT_BLOCKS and a coverage reason', () => {
  const filler = Buffer.alloc(12);
  filler.writeUInt32LE(0x00000bad, 0); filler.writeUInt32LE(12, 4); filler.writeUInt32LE(12, 8);
  const parts = [primaryShb(true)];
  for (let i = 0; i < core.LIMITS.maxBlocks; i++) parts.push(filler);
  const capture = ok(core.parseCapture(Buffer.concat(parts)));
  assert.ok(capture.warnings.some(w => w.code === 'W_LIMIT_BLOCKS'), 'block cap warned');
  assert.ok(capture.coverage.limited);
  assert.ok(capture.coverage.reasons.some(r => /block limit/i.test(r)));
});

test('fix-round-1: maxSections cap stops parsing with W_LIMIT_SECTIONS', () => {
  const parts = [];
  for (let i = 0; i < core.LIMITS.maxSections + 1; i++) parts.push(primaryShb(true));
  const capture = ok(core.parseCapture(Buffer.concat(parts)));
  assert.equal(capture.sections.length, core.LIMITS.maxSections);
  assert.ok(capture.warnings.some(w => w.code === 'W_LIMIT_SECTIONS'));
  assert.ok(capture.coverage.limited);
});

test('fix-round-1: maxInterfacesPerSection cap warns, limits coverage, and stops adding interfaces', () => {
  const parts = [primaryShb(true)];
  for (let i = 0; i < core.LIMITS.maxInterfacesPerSection + 1; i++) parts.push(primaryIdb(true));
  const capture = ok(core.parseCapture(Buffer.concat(parts)));
  assert.equal(capture.sections[0].interfaces.length, core.LIMITS.maxInterfacesPerSection);
  assert.ok(capture.warnings.some(w => w.code === 'W_LIMIT_INTERFACES'));
  assert.ok(capture.coverage.reasons.some(r => /interface limit/i.test(r)));
});

// ---------------------------------------------------------------------------
// fix round 2: timestamp precision (F1/F3) and snapshot-coverage (F2)
// Own bytes via the primary normative-layout helpers above (High at +12 then
// Low at +16, each section-endian); never imports the frozen parent gate.
// ---------------------------------------------------------------------------
function fix2Epoch(secBig, fracBig, digits) {
  const sec = Number(secBig);
  const date = new Date(sec * 1000);
  const pad = (n, w) => String(n).padStart(w, '0');
  const base = date.getUTCFullYear() + '-' + pad(date.getUTCMonth() + 1, 2) + '-' + pad(date.getUTCDate(), 2) +
    ' ' + pad(date.getUTCHours(), 2) + ':' + pad(date.getUTCMinutes(), 2) + ':' + pad(date.getUTCSeconds(), 2);
  return base + (digits ? '.' + String(fracBig).padStart(digits, '0') : '') + ' UTC';
}
function fix2Idb(little, { tsresolValue = null, tsoffsetBig = null, snaplen = null } = {}) {
  const opts = [];
  if (tsresolValue !== null) opts.push(primaryOption(little, 9, Buffer.from([tsresolValue])));
  if (tsoffsetBig !== null) {
    const buf = Buffer.alloc(8);
    if (little) buf.writeBigInt64LE(BigInt(tsoffsetBig), 0);
    else buf.writeBigInt64BE(BigInt(tsoffsetBig), 0);
    opts.push(primaryOption(little, 14, buf));
  }
  opts.push(primaryEndOfOptions(little));
  if (snaplen === null) return primaryIdb(little, opts);
  const body = Buffer.alloc(8);
  if (little) { body.writeUInt16LE(1, 0); body.writeUInt32LE(snaplen >>> 0, 4); }
  else { body.writeUInt16BE(1, 0); body.writeUInt32BE(snaplen >>> 0, 4); }
  return primaryBlock(little, 1, Buffer.concat([body, ...opts]));
}
function fix2Epb(little, rawBig) {
  const big = BigInt(rawBig);
  const high = Number((big >> 32n) & 0xffffffffn);
  const low = Number(big & 0xffffffffn);
  return primaryEpb(little, { high, low });
}

test('fix-round-2 F1: modern decimal ticks above 2^53 remain exact when the scaled seconds fit', () => {
  for (const little of [true, false]) {
    for (const exponent of [6, 7, 8, 9]) {
      const scale = 10n ** BigInt(exponent);
      const sec = 1780000000n;
      const frac = scale - 1n;
      const raw = sec * scale + frac;
      const bytes = Buffer.concat([primaryShb(little), fix2Idb(little, { tsresolValue: exponent }), fix2Epb(little, raw)]);
      const capture = ok(core.parseCapture(bytes));
      assert.doesNotThrow(() => JSON.stringify(capture));
      const stamp = capture.packets[0].timestamp;
      const tag = (little ? 'LE' : 'BE') + ' 10^-' + exponent;
      assert.equal(stamp.text, fix2Epoch(sec, frac, exponent), tag + ' text');
      assert.equal(stamp.seconds, Number(sec), tag + ' seconds');
      assert.equal(stamp.exact, true, tag + ' exact');
      assert.ok(!capture.warnings.some(w => w.code === 'W_TIMESTAMP_RANGE'), tag + ' no range warning');
      const model = ok(core.analyze(capture, {}));
      const report = ok(core.buildReport(model, {}));
      assert.ok(JSON.stringify(report.json).includes(fix2Epoch(sec, frac, exponent)), tag + ' report text');
    }
  }
});

test('fix-round-2 F1: full uint64 nanosecond ticks retain exact quotient/remainder', () => {
  const raw = (1n << 64n) - 1n;
  for (const little of [true, false]) {
    const bytes = Buffer.concat([primaryShb(little), fix2Idb(little, { tsresolValue: 9 }), fix2Epb(little, raw)]);
    const capture = ok(core.parseCapture(bytes));
    assert.doesNotThrow(() => JSON.stringify(capture));
    const stamp = capture.packets[0].timestamp;
    const tag = little ? 'LE' : 'BE';
    assert.equal(stamp.text, fix2Epoch(raw / 1000000000n, raw % 1000000000n, 9), tag + ' text');
    assert.equal(stamp.exact, true, tag + ' exact');
  }
});

test('fix-round-2 F3: extreme if_tsoffset never exports rounded seconds as exact', () => {
  for (const little of [true, false]) {
    for (const offset of [-(1n << 63n), (1n << 63n) - 1n, 9007199254740993n]) {
      const bytes = Buffer.concat([primaryShb(little), fix2Idb(little, { tsresolValue: 0, tsoffsetBig: offset }), fix2Epb(little, 0n)]);
      const capture = ok(core.parseCapture(bytes));
      assert.doesNotThrow(() => JSON.stringify(capture));
      const stamp = capture.packets[0].timestamp;
      const tag = (little ? 'LE' : 'BE') + ' offset=' + String(offset);
      assert.equal(stamp.seconds, null, tag + ' seconds');
      assert.equal(stamp.exact, false, tag + ' exact');
      assert.equal(stamp.text, 'timestamp out of displayable range', tag + ' text');
      assert.equal(String(capture.sections[0].interfaces[0].tsoffsetSeconds), String(offset), tag + ' offset preserved');
      assert.ok(capture.warnings.some(w => w.code === 'W_TIMESTAMP_RANGE'), tag + ' warning');
      const model = ok(core.analyze(capture, {}));
      const report = ok(core.buildReport(model, {}));
      assert.doesNotThrow(() => JSON.stringify(report.json), tag + ' report JSON-safe');
    }
  }
});

test('fix-round-2 F1: large raw seconds plus large negative offset cancel exactly', () => {
  const raw = 9007199254740993n;
  for (const little of [true, false]) {
    const bytes = Buffer.concat([primaryShb(little), fix2Idb(little, { tsresolValue: 0, tsoffsetBig: -raw }), fix2Epb(little, raw)]);
    const capture = ok(core.parseCapture(bytes));
    assert.doesNotThrow(() => JSON.stringify(capture));
    const stamp = capture.packets[0].timestamp;
    const tag = little ? 'LE' : 'BE';
    assert.equal(stamp.text, '1970-01-01 00:00:00 UTC', tag + ' text');
    assert.equal(stamp.seconds, 0, tag + ' seconds');
    assert.equal(stamp.exact, true, tag + ' exact');
  }
});

test('fix-round-2 F1: large approximate ticks retain declared scale', () => {
  const raw = 1780000000123456789n;
  for (const little of [true, false]) {
    for (const resolution of [10, 0xaa]) {
      const exponent = resolution & 0x7f;
      const scale = resolution & 0x80 ? 1n << BigInt(exponent) : 10n ** BigInt(exponent);
      const totalMillis = (raw * 1000n + scale / 2n) / scale;
      const bytes = Buffer.concat([primaryShb(little), fix2Idb(little, { tsresolValue: resolution }), fix2Epb(little, raw)]);
      const capture = ok(core.parseCapture(bytes));
      assert.doesNotThrow(() => JSON.stringify(capture));
      const stamp = capture.packets[0].timestamp;
      const tag = (little ? 'LE' : 'BE') + ' res=' + resolution;
      assert.equal(stamp.seconds, Number(totalMillis / 1000n), tag + ' seconds');
      assert.match(stamp.text, /^~/, tag + ' approximate prefix');
      assert.equal(stamp.exact, false, tag + ' exact');
    }
  }
});

test('fix-round-2 F2: pcap snaplen cap is truncated with limited coverage', () => {
  const bytes = F.pcapFile({ variant: 'le-us', snaplen: 40, packets: [{ data: Buffer.alloc(60), tsSec: F.T0, tsFrac: 1 }] }).bytes;
  const capture = ok(core.parseCapture(bytes));
  assert.doesNotThrow(() => JSON.stringify(capture));
  assert.equal(capture.packets[0].caplen, 40);
  assert.equal(capture.packets[0].truncated, true);
  assert.equal(capture.counts.truncated, 1);
  assert.equal(capture.coverage.limited, true);
  assert.ok(capture.warnings.some(w => w.code === 'W_SNAPLEN_CAP'));
});

test('fix-round-2 F2: pcapng EPB snaplen cap is truncated with limited coverage', () => {
  const frame = Buffer.concat([F.arpRequest(), Buffer.alloc(18)]);
  assert.equal(frame.length, 60);
  for (const endian of ['le', 'be']) {
    const little = endian === 'le';
    const idb = F.pcapngInterface({ endian, snaplen: 42, options: [] });
    const epb = F.pcapngEnhancedPacket({ endian, interfaceId: 0, timestamp: 1000000n, data: frame });
    const shb = F.pcapngSectionHeader({ endian });
    const capture = ok(core.parseCapture(Buffer.concat([shb, idb, epb])));
    assert.doesNotThrow(() => JSON.stringify(capture));
    const tag = endian;
    assert.equal(capture.packets[0].caplen, 42, tag);
    assert.equal(capture.packets[0].truncated, true, tag);
    assert.equal(capture.counts.truncated, 1, tag);
    assert.equal(capture.coverage.limited, true, tag);
    assert.ok(capture.coverage.reasons.some(r => /snapshot length/.test(r)), tag + ' reason');
  }
});

test('fix-round-2 F2: pcapng SPB snaplen cap is truncated with limited coverage', () => {
  const frame = Buffer.concat([F.arpRequest(), Buffer.alloc(18)]);
  for (const endian of ['le', 'be']) {
    const shb = F.pcapngSectionHeader({ endian });
    const idb = F.pcapngInterface({ endian, snaplen: 42, options: [] });
    const spb = F.pcapngSimplePacket({ endian, data: frame });
    const capture = ok(core.parseCapture(Buffer.concat([shb, idb, spb])));
    assert.doesNotThrow(() => JSON.stringify(capture));
    const tag = endian;
    assert.equal(capture.packets[0].caplen, 42, tag);
    assert.equal(capture.packets[0].truncated, true, tag);
    assert.equal(capture.counts.truncated, 1, tag);
    assert.equal(capture.coverage.limited, true, tag);
    assert.ok(capture.coverage.reasons.some(r => /snapshot length/.test(r)), tag + ' reason');
    assert.ok(capture.warnings.some(w => w.code === 'W_SNAPLEN_CAP'), tag + ' warning');
  }
});

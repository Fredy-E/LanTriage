'use strict';
/*
 * LanTriage synthetic fixture builder.
 *
 * IMPORTANT: Every byte produced here is SELF-AUTHORED and SYNTHETIC.
 * These are not captures of real hardware, real networks or real traffic.
 * They are constructed to exercise exact format rules from the primary
 * specifications (see docs/formats.md for citations) and to give every
 * observation a deterministic packet index / byte offset / timestamp.
 *
 * `node tests/fixtures.cjs --write` writes the fixture files plus a
 * machine-checked manifest (sha256, byte size, per-record offsets) into
 * ../fixtures/ and regenerates fixtures/README.md.
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

// ---------------------------------------------------------------------------
// byte helpers
// ---------------------------------------------------------------------------
const concat = parts => Buffer.concat(parts.map(p => Buffer.from(p)));

const writers = {
  le: {
    u16: (out, n) => out.push(n & 0xff, (n >>> 8) & 0xff),
    u32: (out, n) => out.push(n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff),
    // A single 64-bit FIELD in section byte order: used only for the SHB
    // Section Length and if_tsoffset. Never for the EPB timestamp pair.
    u64: (out, n) => { writers.le.u32(out, Number(BigInt(n) & 0xffffffffn)); writers.le.u32(out, Number((BigInt(n) >> 32n) & 0xffffffffn)); }
  },
  be: {
    u16: (out, n) => out.push((n >>> 8) & 0xff, n & 0xff),
    u32: (out, n) => out.push((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff),
    u64: (out, n) => { writers.be.u32(out, Number((BigInt(n) >> 32n) & 0xffffffffn)); writers.be.u32(out, Number(BigInt(n) & 0xffffffffn)); }
  }
};

// The EPB timestamp is NOT a single 64-bit integer: it is two separate 32-bit
// fields, Timestamp (High) at block offset 12 followed by Timestamp (Low) at
// block offset 16, EACH written in the section's byte order
// (draft-tuexen-opsawg-pcapng-05 §4.3, Figure 11). A `u64` write would put
// the words in the wrong order for little-endian sections - the exact framing
// defect C1 that this dedicated writer exists to prevent.
function writeEpbTimestamp(out, ticks, endian) {
  const w = writers[endian];
  const big = BigInt(ticks);
  w.u32(out, Number((big >> 32n) & 0xffffffffn)); // Timestamp (High)
  w.u32(out, Number(big & 0xffffffffn));          // Timestamp (Low)
}
const bytes16 = n => [n & 0xff, (n >>> 8) & 0xff];
const beBytes16 = n => [(n >>> 8) & 0xff, n & 0xff];
const beBytes32 = n => [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];

const mac = s => Buffer.from(s.split(':').map(h => parseInt(h, 16)));
const ip = s => Buffer.from(s.split('.').map(d => parseInt(d, 10)));
const str = s => Buffer.from(s, 'latin1'); // fixtures use ASCII labels only

// ---------------------------------------------------------------------------
// L2 / L3 / L4 packet construction
// ---------------------------------------------------------------------------
function ethernet({ dst, src, ethertype, vlans = [], payload }) {
  const head = [];
  head.push(...mac(dst), ...mac(src));
  let inner = ethertype;
  for (const vlan of vlans) {
    head.push(...beBytes16(vlan.tpid), ...beBytes16(vlan.tci));
  }
  head.push(...beBytes16(inner));
  return concat([head, payload]);
}

function arpPacket({ op, sha, spa, tha, tpa, hrd = 1, pro = 0x0800, hln = 6, pln = 4 }) {
  return concat([
    beBytes16(hrd), beBytes16(pro), [hln, pln], beBytes16(op),
    mac(sha), ip(spa), mac(tha), ip(tpa)
  ]);
}

function ipv4({ src, dst, proto, payload, totalLenOverride = null, fragField = 0x4000, id = 0x1234, ttl = 64, ihlOverride = null, ihlOptions = null }) {
  const options = ihlOptions ? Buffer.from(ihlOptions) : Buffer.alloc(0);
  if (options.length % 4 !== 0) throw new Error('IPv4 options must be a multiple of 4 bytes');
  const headerLen = 20 + options.length;
  const total = totalLenOverride !== null ? totalLenOverride : headerLen + payload.length;
  const head = [
    ihlOverride !== null ? ihlOverride : (0x40 | (headerLen / 4)), 0x00,
    ...beBytes16(total & 0xffff), ...beBytes16(id), ...beBytes16(fragField),
    ttl, proto, 0x00, 0x00, // checksum not validated by the analyzer (documented)
    ...ip(src), ...ip(dst)
  ];
  return concat([head, options, payload]);
}

function udp({ sp, dp, payload, lenOverride = null, checksum = 0 }) {
  const len = lenOverride !== null ? lenOverride : 8 + payload.length;
  return concat([beBytes16(sp), beBytes16(dp), beBytes16(len & 0xffff), beBytes16(checksum), payload]);
}

// BOOTP/DHCP message: 236-byte fixed header + magic cookie + options.
function dhcp({
  op = 1, htype = 1, hlen = 6, hops = 0, xid = 0x11223344, secs = 0, flags = 0x8000,
  ciaddr = '0.0.0.0', yiaddr = '0.0.0.0', siaddr = '0.0.0.0', giaddr = '0.0.0.0',
  chaddr = 'aa:00:00:00:00:30', sname = '', file = '',
  cookie = true, options = [], padTo = null
}) {
  const out = [];
  out.push(op, htype, hlen, hops);
  out.push(...beBytes32(xid));
  out.push(...beBytes16(secs), ...beBytes16(flags));
  out.push(...ip(ciaddr), ...ip(yiaddr), ...ip(siaddr), ...ip(giaddr));
  const ch = mac(chaddr);
  out.push(...ch);
  for (let i = ch.length; i < 16; i++) out.push(0);
  const sn = str(sname); for (let i = 0; i < 64; i++) out.push(i < sn.length ? sn[i] : 0);
  const fl = str(file); for (let i = 0; i < 128; i++) out.push(i < fl.length ? fl[i] : 0);
  if (cookie) out.push(0x63, 0x82, 0x53, 0x63);
  for (const opt of options) {
    if (opt.code === 0) { out.push(0); continue; }          // pad
    if (opt.code === 255) { out.push(255); continue; }      // end
    const data = opt.data;
    out.push(opt.code, data.length, ...data);
  }
  if (padTo !== null) { while (out.length < padTo) out.push(0); }
  return Buffer.from(out);
}

const dhcpOpt = (code, data) => ({ code, data: Buffer.from(data) });
const dhcpMsgType = t => dhcpOpt(53, [t]);
const dhcpIp = s => dhcpOpt(50, ip(s));

// DNS / mDNS message construction (RFC 1035 §4.1; RFC 6762 §5/§10).
// Names are written as literal labels here; compression pointers are emitted
// only where a test explicitly asks for them.
function dnsName(name) {
  const out = [];
  for (const label of name.split('.')) {
    if (label === '') continue;
    out.push(label.length, ...str(label));
  }
  out.push(0);
  return out;
}

function dnsMessage({ id = 0, flags = 0x0000, questions = [], answers = [] }) {
  const out = [];
  out.push(...beBytes16(id), ...beBytes16(flags));
  out.push(...beBytes16(questions.length), ...beBytes16(answers.length), ...beBytes16(0), ...beBytes16(0));
  for (const q of questions) {
    out.push(...dnsName(q.name), ...beBytes16(q.type), ...beBytes16(q.class));
  }
  for (const a of answers) {
    out.push(...a.name, ...beBytes16(a.type), ...beBytes16(a.class), ...beBytes32(a.ttl), ...beBytes16(a.rdata.length), ...a.rdata);
  }
  return Buffer.from(out);
}

// ---------------------------------------------------------------------------
// capture containers
// ---------------------------------------------------------------------------
const PCAP_MAGIC = {
  'le-us': [0xd4, 0xc3, 0xb2, 0xa1], // bytes as written little-endian => value 0xa1b2c3d4
  'le-ns': [0x4d, 0x3c, 0xb2, 0xa1], // value 0xa1b23c4d
  'be-us': [0xa1, 0xb2, 0xc3, 0xd4],
  'be-ns': [0xa1, 0xb2, 0x3c, 0x4d]
};

function pcapFile({ variant = 'le-us', linkType = 1, snaplen = 65535, packets = [] }) {
  const endian = variant.startsWith('le') ? 'le' : 'be';
  const w = writers[endian];
  const head = [...PCAP_MAGIC[variant]];
  w.u16(head, 2); w.u16(head, 4);      // version 2.4 (RFC draft §4)
  w.u32(head, 0); w.u32(head, 0);      // reserved1/reserved2, ignored by readers
  w.u32(head, snaplen);
  w.u32(head, linkType);
  const parts = [Buffer.from(head)];
  const records = [];
  for (const p of packets) {
    const rec = [];
    w.u32(rec, p.tsSec); w.u32(rec, p.tsFrac);
    const incl = p.inclLenOverride !== undefined ? p.inclLenOverride : p.data.length;
    const orig = p.origLenOverride !== undefined ? p.origLenOverride : p.data.length;
    w.u32(rec, incl); w.u32(rec, orig);
    parts.push(Buffer.from(rec), p.data);
    records.push({ tsSec: p.tsSec, tsFrac: p.tsFrac, inclLen: incl, origLen: orig });
  }
  return { bytes: concat(parts), records, endian, snaplen, linkType };
}

function pcapngBlock({ type, body, endian }) {
  const w = writers[endian];
  const padded = body.length % 4 === 0 ? Buffer.from(body) : concat([body, Buffer.alloc(4 - (body.length % 4))]);
  const total = 12 + padded.length;
  const out = [];
  w.u32(out, type); w.u32(out, total);
  return { header: Buffer.from(out), total, body: padded };
}

function pcapngOption({ code, data, endian }) {
  const w = writers[endian];
  const out = [];
  w.u16(out, code); w.u16(out, data.length);
  const padded = data.length % 4 === 0 ? Buffer.from(data) : concat([data, Buffer.alloc(4 - (data.length % 4))]);
  return concat([Buffer.from(out), padded]);
}

const pcapngOptionsEnd = endian => pcapngOption({ code: 0, data: Buffer.alloc(0), endian });

function pcapngSectionHeader({ endian, sectionLength = -1n, options = [], minor = 0 }) {
  const w = writers[endian];
  const body = [];
  w.u32(body, 0x1a2b3c4d);
  w.u16(body, 1); w.u16(body, minor);
  w.u64(body, sectionLength);
  const opts = concat([...options, pcapngOptionsEnd(endian)]);
  const block = pcapngBlock({ type: 0x0a0d0d0a, body: concat([Buffer.from(body), opts]), endian });
  return concat([block.header, block.body, block.header.slice(4, 8)]);
}

function pcapngInterface({ endian, linkType = 1, snaplen = 65535, options = [] }) {
  const w = writers[endian];
  const body = [];
  w.u16(body, linkType); w.u16(body, 0); w.u32(body, snaplen);
  const opts = concat([...options, pcapngOptionsEnd(endian)]);
  const block = pcapngBlock({ type: 1, body: concat([Buffer.from(body), opts]), endian });
  return concat([block.header, block.body, block.header.slice(4, 8)]);
}

function pcapngEnhancedPacket({ endian, interfaceId = 0, timestamp = 0n, data, caplenOverride = null, origlenOverride = null, options = [] }) {
  const w = writers[endian];
  const body = [];
  const caplen = caplenOverride !== null ? caplenOverride : data.length;
  const origlen = origlenOverride !== null ? origlenOverride : data.length;
  w.u32(body, interfaceId);
  writeEpbTimestamp(body, timestamp, endian); // High word then Low word, per field endianness
  w.u32(body, caplen); w.u32(body, origlen);
  const opts = concat([...options, pcapngOptionsEnd(endian)]);
  const block = pcapngBlock({ type: 6, body: concat([Buffer.from(body), data, opts]), endian });
  return concat([block.header, block.body, block.header.slice(4, 8)]);
}

function pcapngSimplePacket({ endian, data, origlenOverride = null }) {
  const w = writers[endian];
  const body = [];
  w.u32(body, origlenOverride !== null ? origlenOverride : data.length);
  const block = pcapngBlock({ type: 3, body: concat([Buffer.from(body), data]), endian });
  return concat([block.header, block.body, block.header.slice(4, 8)]);
}

// A block the analyzer must skip by length and count as unsupported (NRB).
function pcapngNameResolutionBlock({ endian }) {
  const body = concat([pcapngOption({ code: 0, data: Buffer.alloc(0), endian })]);
  const block = pcapngBlock({ type: 4, body, endian });
  return concat([block.header, block.body, block.header.slice(4, 8)]);
}

// A block type that is not part of the supported subset (0x00000BAD custom).
function pcapngUnknownBlock({ endian, payload = Buffer.from([1, 2, 3, 4]) }) {
  const block = pcapngBlock({ type: 0x00000bad, body: payload, endian });
  return concat([block.header, block.body, block.header.slice(4, 8)]);
}

// ---------------------------------------------------------------------------
// reusable synthetic conversations (all names/addresses are fictional)
// ---------------------------------------------------------------------------
const T0 = Math.floor(Date.parse('2026-10-11T12:00:00Z') / 1000); // fixed synthetic epoch

const MAC = {
  hostA: 'aa:00:00:00:00:10',
  hostB: 'aa:00:00:00:00:20',
  hostB2: 'aa:00:00:00:00:21', // second claimant of 192.0.2.20 (conflict candidate)
  client: 'aa:00:00:00:00:30',
  server: 'aa:00:00:00:00:01',
  printer: 'aa:00:00:00:00:40',
  router: 'aa:00:00:00:00:02',
  vlan42: 'aa:00:00:00:00:42'
};
const BCAST = 'ff:ff:ff:ff:ff:ff';
const ZERO = '00:00:00:00:00:00';

function arpRequest({ sha = MAC.hostA, spa = '192.0.2.10', tpa = '192.0.2.20', dst = BCAST, tha = ZERO } = {}) {
  return ethernet({ dst, src: sha, ethertype: 0x0806, payload: arpPacket({ op: 1, sha, spa, tha, tpa }) });
}
function arpReply({ sha = MAC.hostB, spa = '192.0.2.20', tpa = '192.0.2.10', dst = MAC.hostA, tha = MAC.hostA } = {}) {
  return ethernet({ dst, src: sha, ethertype: 0x0806, payload: arpPacket({ op: 2, sha, spa, tha, tpa }) });
}
function arpProbe({ sha = MAC.client, tpa = '192.0.2.30' } = {}) {
  // ARP probe: sender protocol address 0.0.0.0, target = address being probed.
  return ethernet({ dst: BCAST, src: sha, ethertype: 0x0806, payload: arpPacket({ op: 1, sha, spa: '0.0.0.0', tha: ZERO, tpa }) });
}
function arpAnnouncement({ sha = MAC.hostB, spa = '192.0.2.20' } = {}) {
  return ethernet({ dst: BCAST, src: sha, ethertype: 0x0806, payload: arpPacket({ op: 2, sha, spa, tha: ZERO, tpa: spa }) });
}

function dhcpDiscover({ chaddr = MAC.client, xid = 0x11223344, hostname = 'fictional-laptop', extraOptions = [] } = {}) {
  return ethernet({
    dst: BCAST, src: chaddr, ethertype: 0x0800,
    payload: ipv4({
      src: '0.0.0.0', dst: '255.255.255.255', proto: 17,
      payload: udp({
        sp: 68, dp: 67, payload: dhcp({
          op: 1, xid, chaddr,
          options: [dhcpMsgType(1), dhcpOpt(12, str(hostname)), dhcpOpt(55, [1, 3, 6, 15, 51]), dhcpOpt(61, concat([[1], mac(chaddr)])), dhcpOpt(255, Buffer.alloc(0)), ...extraOptions]
        })
      })
    })
  });
}

function dhcpOffer({ yiaddr = '192.0.2.30', serverId = '192.0.2.1', xid = 0x11223344, chaddr = MAC.client, lease = 3600 } = {}) {
  return ethernet({
    dst: chaddr, src: MAC.server, ethertype: 0x0800,
    payload: ipv4({
      src: serverId, dst: '255.255.255.255', proto: 17,
      payload: udp({
        sp: 67, dp: 68, payload: dhcp({
          op: 2, xid, yiaddr, siaddr: serverId, chaddr, flags: 0x8000,
          options: [dhcpMsgType(2), dhcpIp('192.0.2.1'), dhcpOpt(54, ip(serverId)), dhcpOpt(51, beBytes32(lease)), dhcpOpt(255, Buffer.alloc(0))]
        })
      })
    })
  });
}

function dhcpRequest({ chaddr = MAC.client, xid = 0x11223344, requested = '192.0.2.30', serverId = '192.0.2.1', ciaddr = '0.0.0.0' } = {}) {
  return ethernet({
    dst: BCAST, src: chaddr, ethertype: 0x0800,
    payload: ipv4({
      src: ciaddr, dst: '255.255.255.255', proto: 17,
      payload: udp({
        sp: 68, dp: 67, payload: dhcp({
          op: 1, xid, chaddr, ciaddr,
          options: [dhcpMsgType(3), dhcpIp(requested), dhcpOpt(54, ip(serverId)), dhcpOpt(255, Buffer.alloc(0))]
        })
      })
    })
  });
}

function dhcpAck({ yiaddr = '192.0.2.30', serverId = '192.0.2.1', xid = 0x11223344, chaddr = MAC.client, lease = 3600 } = {}) {
  return ethernet({
    dst: chaddr, src: MAC.server, ethertype: 0x0800,
    payload: ipv4({
      src: serverId, dst: '255.255.255.255', proto: 17,
      payload: udp({
        sp: 67, dp: 68, payload: dhcp({
          op: 2, xid, yiaddr, siaddr: serverId, chaddr,
          options: [dhcpMsgType(5), dhcpOpt(54, ip(serverId)), dhcpOpt(51, beBytes32(lease)), dhcpOpt(255, Buffer.alloc(0))]
        })
      })
    })
  });
}

function mdnsQuery({ name = 'fictional-printer.local', type = 1, qu = false } = {}) {
  return ethernet({
    dst: '01:00:5e:00:00:fb', src: MAC.hostA, ethertype: 0x0800,
    payload: ipv4({
      src: '192.0.2.10', dst: '224.0.0.251', proto: 17, ttl: 255,
      payload: udp({ sp: 5353, dp: 5353, payload: dnsMessage({ id: 0, flags: 0x0000, questions: [{ name, type, class: qu ? 0x8001 : 0x0001 }] }) })
    })
  });
}

// mDNS response that uses a compression pointer for the answer name:
// the pointer 0xC00C targets offset 12, the first question's name.
function mdnsResponseCompressed({ name = 'fictional-printer.local', addr = '192.0.2.40', cacheFlush = true } = {}) {
  const question = dnsName(name);
  const header = [0x00, 0x00, 0x84, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
  const q = concat([question, beBytes16(1), beBytes16(0x0001)]);
  const answer = concat([
    [0xc0, 0x0c],                       // pointer to offset 12 (prior occurrence)
    beBytes16(1),                       // type A
    beBytes16(cacheFlush ? 0x8001 : 0x0001),
    beBytes32(120),                     // RFC 6762 §10: 120 s for address records
    beBytes16(4), ip(addr)
  ]);
  const message = concat([header, q, answer]);
  return ethernet({
    dst: MAC.hostA, src: MAC.printer, ethertype: 0x0800,
    payload: ipv4({ src: addr, dst: '192.0.2.10', proto: 17, ttl: 255, payload: udp({ sp: 5353, dp: 5353, payload: message }) })
  });
}

function plainUdp({ sp = 4444, dp = 5555, src = '192.0.2.10', dst = '192.0.2.20', payload = Buffer.from('synthetic payload') } = {}) {
  return ethernet({ dst: MAC.hostB, src: MAC.hostA, ethertype: 0x0800, payload: ipv4({ src, dst, proto: 17, payload: udp({ sp, dp, payload }) }) });
}

function ipv6Stub() {
  const header = [0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 17, 64];
  const src = Buffer.from('20010db8000000000000000000000001', 'hex');
  const dst = Buffer.from('ff0200000000000000000000000000fb', 'hex');
  const payload = udp({ sp: 5353, dp: 5353, payload: Buffer.from([0, 0, 0, 0, 0, 0, 0, 0]) });
  return ethernet({ dst: '33:33:00:00:00:fb', src: MAC.hostA, ethertype: 0x86dd, payload: concat([header, src, dst, payload]) });
}

// ---------------------------------------------------------------------------
// fixture catalogue
// ---------------------------------------------------------------------------
function defineFixtures() {
  const fixtures = [];
  const add = (name, description, built, notes = []) => fixtures.push({ name, description, ...built, notes });

  // --- 1. baseline little-endian microsecond pcap -------------------------
  {
    const packets = [
      { note: 'ARP request: who-has 192.0.2.20 tell 192.0.2.10', data: arpRequest(), tsSec: T0, tsFrac: 100000 },
      { note: 'ARP reply: 192.0.2.20 is-at aa:00:00:00:00:20', data: arpReply(), tsSec: T0, tsFrac: 200000 },
      { note: 'DHCP DISCOVER from aa:00:00:00:00:30 (hostname fictional-laptop)', data: dhcpDiscover(), tsSec: T0, tsFrac: 300000 },
      { note: 'DHCP OFFER 192.0.2.30 from 192.0.2.1', data: dhcpOffer(), tsSec: T0, tsFrac: 400000 },
      { note: 'DHCP REQUEST for 192.0.2.30', data: dhcpRequest(), tsSec: T0, tsFrac: 500000 },
      { note: 'DHCP ACK 192.0.2.30', data: dhcpAck(), tsSec: T0, tsFrac: 600000 },
      { note: 'mDNS query fictional-printer.local A', data: mdnsQuery(), tsSec: T0, tsFrac: 700000 },
      { note: 'mDNS response with compression pointer + cache-flush bit', data: mdnsResponseCompressed(), tsSec: T0, tsFrac: 800000 },
      { note: 'ARP probe (spa 0.0.0.0) for 192.0.2.30 which was just assigned', data: arpProbe(), tsSec: T0, tsFrac: 900000 },
      { note: 'ARP reply: 192.0.2.20 also claimed by aa:00:00:00:00:21 (conflict candidate)', data: arpReply({ sha: MAC.hostB2 }), tsSec: T0, tsFrac: 1000000 },
      { note: 'VLAN 42 tagged ARP reply claiming 192.0.2.20 from aa:00:00:00:00:42 (different VLAN)', data: ethernet({ dst: BCAST, src: MAC.vlan42, ethertype: 0x0806, vlans: [{ tpid: 0x8100, tci: 42 }], payload: arpPacket({ op: 2, sha: MAC.vlan42, spa: '192.0.2.20', tha: ZERO, tpa: '192.0.2.20' }) }), tsSec: T0, tsFrac: 1100000 },
      { note: 'UDP 4444->5555: outside the supported protocol subset (visible unsupported)', data: plainUdp(), tsSec: T0, tsFrac: 1200000 },
      { note: 'IPv6 mDNS packet: IPv6 is outside the supported subset (visible unsupported)', data: ipv6Stub(), tsSec: T0, tsFrac: 1300000 },
      { note: 'truncated capture: incl_len 24 < orig_len 60, ARP payload cut', data: arpRequest().slice(0, 24), origLenOverride: 60, tsSec: T0, tsFrac: 1400000 },
      { note: 'ARP reply from aa:00:00:00:00:02 (router) for 192.0.2.1', data: arpReply({ sha: MAC.router, spa: '192.0.2.1', tpa: '192.0.2.10' }), tsSec: T0, tsFrac: 1500000 }
    ];
    const built = pcapFile({ variant: 'le-us', packets });
    add('synthetic-lan-le-us.pcap',
      'Baseline little-endian microsecond pcap: ARP, DHCP, mDNS, VLAN, unsupported IPv6/UDP, one truncated record. All names/addresses fictional.',
      built,
      ['16 packet records, Ethernet link type 1, snaplen 65535', 'Packet index 13 (the 14th record) has incl_len 24 < orig_len 60']);
  }

  // --- 2. big-endian pcap, same conversation shape ------------------------
  {
    const packets = [
      { note: 'ARP request (BE file)', data: arpRequest(), tsSec: T0, tsFrac: 100000 },
      { note: 'ARP reply (BE file)', data: arpReply(), tsSec: T0, tsFrac: 200000 },
      { note: 'DHCP DISCOVER (BE file)', data: dhcpDiscover(), tsSec: T0, tsFrac: 300000 },
      { note: 'DHCP ACK (BE file)', data: dhcpAck(), tsSec: T0, tsFrac: 400000 },
      { note: 'mDNS response (BE file)', data: mdnsResponseCompressed(), tsSec: T0, tsFrac: 500000 }
    ];
    add('synthetic-lan-be-us.pcap',
      'Big-endian microsecond pcap (magic bytes a1 b2 c3 d4). Same synthetic conversation subset as the LE baseline.',
      pcapFile({ variant: 'be-us', packets }),
      ['5 packet records, all fields big-endian']);
  }

  // --- 3. nanosecond timestamps -------------------------------------------
  {
    const packets = [
      { note: 'ARP request with nanosecond timestamp 123456789 ns', data: arpRequest(), tsSec: T0, tsFrac: 123456789 },
      { note: 'mDNS query with nanosecond timestamp 987654321 ns', data: mdnsQuery(), tsSec: T0, tsFrac: 987654321 }
    ];
    add('synthetic-lan-le-ns.pcap',
      'Little-endian nanosecond pcap (magic 0xa1b23c4d): fraction field is nanoseconds, not microseconds.',
      pcapFile({ variant: 'le-ns', packets }),
      ['2 packet records; tsFrac values exceed 10^6 to prove ns handling']);
  }

  // --- 4. multi-section pcapng --------------------------------------------
  {
    const w = writers.le;
    const optName = data => pcapngOption({ code: 2, data: str(data), endian: 'le' });
    const optTsresol = value => pcapngOption({ code: 9, data: Buffer.from([value]), endian: 'le' });

    const sec1 = [
      pcapngSectionHeader({ endian: 'le', options: [pcapngOption({ code: 4, data: str('LanTriage-synthetic'), endian: 'le' })] }),
      pcapngInterface({ endian: 'le', options: [optName('fictional-eth0'), optTsresol(6)] }),
      pcapngEnhancedPacket({ endian: 'le', interfaceId: 0, timestamp: BigInt(T0) * 1000000n + 100000n, data: arpRequest() }),
      pcapngEnhancedPacket({ endian: 'le', interfaceId: 0, timestamp: BigInt(T0) * 1000000n + 200000n, data: dhcpDiscover() }),
      pcapngSimplePacket({ endian: 'le', data: arpReply() }),
      pcapngNameResolutionBlock({ endian: 'le' }),
      pcapngUnknownBlock({ endian: 'le' })
    ];

    const beOpt = (code, data) => pcapngOption({ code, data, endian: 'be' });
    const sec2 = [
      pcapngSectionHeader({ endian: 'be' }),
      pcapngInterface({ endian: 'be', options: [beOpt(9, Buffer.from([0x8a]))] }),                      // 2^-10 resolution
      pcapngInterface({ endian: 'be', options: [beOpt(9, Buffer.from([6])), beOpt(14, writers.be.u64 ? (() => { const o = []; writers.be.u64(o, 3600n); return Buffer.from(o); })() : Buffer.alloc(8))] }),
      pcapngEnhancedPacket({ endian: 'be', interfaceId: 0, timestamp: (BigInt(T0) * 1024n + 512n), data: mdnsQuery() }),
      pcapngEnhancedPacket({ endian: 'be', interfaceId: 1, timestamp: (BigInt(T0) + 5n) * 1000000n, data: arpReply({ sha: MAC.hostB2 }) }),
      pcapngEnhancedPacket({ endian: 'be', interfaceId: 5, timestamp: BigInt(T0) * 1000000n, data: plainUdp() }) // unknown interface id
    ];

    add('synthetic-multi-section.pcapng',
      'Two-section pcapng: little-endian section then big-endian section; interface timestamp resolutions 10^-6, 2^-10 and an if_tsoffset; SPB; NRB and custom blocks outside the subset; one EPB referencing a nonexistent interface.',
      { bytes: concat([...sec1, ...sec2]), records: [], endian: 'multi', snaplen: 65535, linkType: 1 },
      ['Section 1: LE, if_tsresol 6, if_name fictional-eth0, EPB+EPB+SPB, NRB, custom 0x00000BAD',
       'Section 2: BE, interface 0 tsresol 0x8a (2^-10), interface 1 tsresol 6 + if_tsoffset 3600',
       'EPB with interface id 5 has no matching IDB (visible rejection)']);
  }

  // --- 5. malformed containers --------------------------------------------
  {
    const good = pcapFile({ variant: 'le-us', packets: [{ note: 'ARP request', data: arpRequest(), tsSec: T0, tsFrac: 1 }] });
    const badMagic = Buffer.from(good.bytes); badMagic.writeUInt8(0x00, 0);
    add('synthetic-bad-magic.pcap', 'pcap whose first byte breaks every legal magic variant.', { bytes: badMagic, records: [], endian: 'le', snaplen: 65535, linkType: 1 }, ['Expect a hard E_MAGIC error.']);

    const badVersion = Buffer.from(good.bytes); badVersion.writeUInt16LE(3, 4);
    add('synthetic-bad-version.pcap', 'pcap declaring format version 3.0.', { bytes: badVersion, records: [], endian: 'le', snaplen: 65535, linkType: 1 }, ['Expect a hard E_VERSION error.']);

    const zeroSnap = Buffer.from(good.bytes); zeroSnap.writeUInt32LE(0, 16);
    add('synthetic-bad-snaplen.pcap', 'pcap with snaplen 0 (the draft forbids zero).', { bytes: zeroSnap, records: [], endian: 'le', snaplen: 0, linkType: 1 }, ['Expect a hard E_SNAPLEN error.']);

    const inclGtOrig = pcapFile({
      variant: 'le-us',
      packets: [{ note: 'record with incl_len 60 > orig_len 20', data: arpRequest(), tsSec: T0, tsFrac: 1, inclLenOverride: 60, origLenOverride: 20 }]
    });
    add('synthetic-bad-incl-gt-orig.pcap', 'pcap record whose captured length exceeds the original length.', inclGtOrig, ['Expect the record to be rejected with a visible warning; file still parses.']);

    const headerOnly = concat([good.bytes.slice(0, 24), good.bytes.slice(24, 40), good.bytes.slice(40, 60)]);
    add('synthetic-bad-truncated-final.pcap', 'pcap whose final record is cut mid-packet by end of file.', { bytes: headerOnly, records: [], endian: 'le', snaplen: 65535, linkType: 1 }, ['Expect a visible truncation warning and limited coverage, not a crash.']);
  }
  {
    const noShb = concat([
      pcapngInterface({ endian: 'le' }),
      pcapngEnhancedPacket({ endian: 'le', interfaceId: 0, timestamp: 0n, data: arpRequest() })
    ]);
    add('synthetic-bad-no-shb.pcapng', 'pcapng that begins with an Interface Description Block instead of a Section Header Block.', { bytes: noShb, records: [], endian: 'le', snaplen: 65535, linkType: 1 }, ['Expect a hard E_NO_SHB error.']);

    const badBom = (() => {
      const block = pcapngBlock({ type: 0x0a0d0d0a, body: Buffer.from([0x11, 0x22, 0x33, 0x44, 0x00, 0x01, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]), endian: 'le' });
      return concat([block.header, block.body, block.header.slice(4, 8)]);
    })();
    add('synthetic-bad-bom.pcapng', 'pcapng Section Header Block with a corrupted byte-order magic.', { bytes: badBom, records: [], endian: 'le', snaplen: 65535, linkType: 1 }, ['Expect a hard E_BOM error.']);

    const badBlockLen = (() => {
      const good = pcapngInterface({ endian: 'le' });
      const tampered = Buffer.from(good);
      tampered.writeUInt32LE(tampered.readUInt32LE(4) + 2, 4); // total length no longer a multiple of 4 / mismatched trailer
      return concat([pcapngSectionHeader({ endian: 'le' }), tampered]);
    })();
    add('synthetic-bad-blocklen.pcapng', 'pcapng IDB whose declared total length is not a multiple of 4 and disagrees with its trailer.', { bytes: badBlockLen, records: [], endian: 'le', snaplen: 65535, linkType: 1 }, ['Expect a visible W_BLOCK_TRAILER warning with limited coverage.']);

    const unknownIface = (() => concat([
      pcapngSectionHeader({ endian: 'le' }),
      pcapngInterface({ endian: 'le' }),
      pcapngEnhancedPacket({ endian: 'le', interfaceId: 3, timestamp: 1000n, data: arpRequest() })
    ]))();
    add('synthetic-bad-iface.pcapng', 'pcapng EPB referencing interface id 3 when only interface 0 exists.', { bytes: unknownIface, records: [], endian: 'le', snaplen: 65535, linkType: 1 }, ['Expect a visible W_IFACE_UNKNOWN warning; the record is rejected, the file still parses.']);
  }

  // --- 6. malformed protocol payloads -------------------------------------
  {
    const badDhcp = ethernet({
      dst: BCAST, src: MAC.client, ethertype: 0x0800,
      payload: ipv4({
        src: '0.0.0.0', dst: '255.255.255.255', proto: 17,
        payload: udp({
          sp: 68, dp: 67, payload: dhcp({
            op: 1, xid: 0x55667788, chaddr: MAC.client,
            options: [dhcpMsgType(1), dhcpOpt(12, str('fictional-laptop'))]
          }).subarray(0, 248) // cut inside option 12: it declares 16 data bytes, only 3 remain
        })
      })
    });
    add('synthetic-bad-dhcp-option.pcap', 'DHCP message cut inside option 12: the option length overruns the available bytes.', pcapFile({ variant: 'le-us', packets: [{ note: 'DHCP with truncated option', data: badDhcp, tsSec: T0, tsFrac: 1 }] }), ['Expect a visible W_DHCP_OPTION_LEN warning; the message is still reported as DHCP with malformed options.']);

    const noCookie = ethernet({
      dst: BCAST, src: MAC.client, ethertype: 0x0800,
      payload: ipv4({
        src: '0.0.0.0', dst: '255.255.255.255', proto: 17,
        payload: udp({ sp: 68, dp: 67, payload: dhcp({ op: 1, xid: 0x99887766, chaddr: MAC.client, cookie: false, options: [] }) })
      })
    });
    add('synthetic-bad-dhcp-cookie.pcap', 'BOOTP/DHCP message without the 0x63825363 magic cookie.', pcapFile({ variant: 'le-us', packets: [{ note: 'DHCP without cookie', data: noCookie, tsSec: T0, tsFrac: 1 }] }), ['Expect a visible W_DHCP_COOKIE warning; options are not parsed.']);

    const dnsLoop = (() => {
      // Answer name is a pointer to itself: offset 12 would need to point at the
      // answer, but the question is empty (qdcount 0) so 0xC00C lands inside the
      // answer itself; the parser must detect the revisit and stop.
      const header = [0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
      const answer = concat([
        [0xc0, 0x0c], beBytes16(1), beBytes16(0x0001), beBytes32(120), beBytes16(4), ip('192.0.2.40')
      ]);
      const message = concat([header, answer]);
      return ethernet({
        dst: MAC.hostA, src: MAC.printer, ethertype: 0x0800,
        payload: ipv4({ src: '192.0.2.40', dst: '192.0.2.10', proto: 17, ttl: 255, payload: udp({ sp: 5353, dp: 5353, payload: message }) })
      });
    })();
    add('synthetic-bad-dns-loop.pcap', 'mDNS response whose answer name pointer targets its own offset (a compression cycle).', pcapFile({ variant: 'le-us', packets: [{ note: 'DNS pointer cycle', data: dnsLoop, tsSec: T0, tsFrac: 1 }] }), ['Expect a visible W_DNS_LOOP warning; the answer is not decoded and the packet is counted as not decoded.']);

    const dnsForward = (() => {
      const header = [0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
      const answer = concat([
        [0xc0, 0xff], // pointer far beyond the message end
        beBytes16(1), beBytes16(0x0001), beBytes32(120), beBytes16(4), ip('192.0.2.40')
      ]);
      const message = concat([header, answer]);
      return ethernet({
        dst: MAC.hostA, src: MAC.printer, ethertype: 0x0800,
        payload: ipv4({ src: '192.0.2.40', dst: '192.0.2.10', proto: 17, ttl: 255, payload: udp({ sp: 5353, dp: 5353, payload: message }) })
      });
    })();
    add('synthetic-bad-dns-pointer.pcap', 'mDNS response whose answer name pointer is outside the message.', pcapFile({ variant: 'le-us', packets: [{ note: 'DNS pointer out of range', data: dnsForward, tsSec: T0, tsFrac: 1 }] }), ['Expect a visible W_DNS_POINTER_RANGE warning.']);

    const fragmented = ethernet({
      dst: BCAST, src: MAC.client, ethertype: 0x0800,
      payload: ipv4({
        src: '0.0.0.0', dst: '255.255.255.255', proto: 17, fragField: 0x2000, // MF set
        payload: udp({ sp: 68, dp: 67, payload: Buffer.from([0, 1, 2, 3]) })
      })
    });
    add('synthetic-bad-fragment.pcap', 'IPv4 fragment (MF flag set) carrying a DHCP-shaped UDP datagram: fragments are outside the supported subset.', pcapFile({ variant: 'le-us', packets: [{ note: 'IPv4 fragment', data: fragmented, tsSec: T0, tsFrac: 1 }] }), ['Expect the fragment to be counted as not decoded (visible unsupported), never decoded as DHCP.']);

    const protoNames = (() => {
      const hostile = mdnsQuery({ name: '__proto__.local' });
      const hostile2 = ethernet({
        dst: BCAST, src: MAC.client, ethertype: 0x0800,
        payload: ipv4({
          src: '0.0.0.0', dst: '255.255.255.255', proto: 17,
          payload: udp({ sp: 68, dp: 67, payload: dhcp({ op: 1, xid: 1, chaddr: MAC.client, options: [dhcpMsgType(1), dhcpOpt(12, str('constructor')), dhcpOpt(255, Buffer.alloc(0))] }) })
        })
      });
      const hostile3 = mdnsQuery({ name: '<img src=x onerror=y>.local' });
      return pcapFile({ variant: 'le-us', packets: [
        { note: 'mDNS query for __proto__.local', data: hostile, tsSec: T0, tsFrac: 1 },
        { note: 'DHCP hostname "constructor"', data: hostile2, tsSec: T0, tsFrac: 2 },
        { note: 'mDNS query whose name carries HTML metacharacters', data: hostile3, tsSec: T0, tsFrac: 3 }
      ] });
    })();
    add('synthetic-prototype-names.pcap', 'Synthetic identifiers that collide with JavaScript prototype member names (__proto__, constructor).', protoNames, ['Expect normal decoding; internal sets must not treat these as pre-existing members.']);
  }

  // --- 7. analysis counterexamples ----------------------------------------
  {
    // Same IP, two MACs, but in different VLANs: must NOT be a conflict finding.
    const vlanSplit = pcapFile({ variant: 'le-us', packets: [
      { note: 'VLAN 100: 192.0.2.50 at aa:00:00:00:00:50', data: ethernet({ dst: BCAST, src: 'aa:00:00:00:00:50', ethertype: 0x0806, vlans: [{ tpid: 0x8100, tci: 100 }], payload: arpPacket({ op: 2, sha: 'aa:00:00:00:00:50', spa: '192.0.2.50', tha: ZERO, tpa: '192.0.2.50' }) }), tsSec: T0, tsFrac: 1 },
      { note: 'VLAN 200: 192.0.2.50 at aa:00:00:00:00:51', data: ethernet({ dst: BCAST, src: 'aa:00:00:00:00:51', ethertype: 0x0806, vlans: [{ tpid: 0x8100, tci: 200 }], payload: arpPacket({ op: 2, sha: 'aa:00:00:00:00:51', spa: '192.0.2.50', tha: ZERO, tpa: '192.0.2.50' }) }), tsSec: T0, tsFrac: 2 }
    ] });
    add('synthetic-counter-vlan-split.pcap', 'Counterexample: one IP claimed by two MACs in two DIFFERENT VLANs (not a conflict candidate).', vlanSplit, ['Expect NO possible-ip-mac-conflict finding.']);

    const probesOnly = pcapFile({ variant: 'le-us', packets: [
      { note: 'probe for 192.0.2.60', data: arpProbe({ sha: 'aa:00:00:00:00:60', tpa: '192.0.2.60' }), tsSec: T0, tsFrac: 1 },
      { note: 'probe for 192.0.2.60 from a second MAC', data: arpProbe({ sha: 'aa:00:00:00:00:61', tpa: '192.0.2.60' }), tsSec: T0, tsFrac: 2 }
    ] });
    add('synthetic-counter-probe-only.pcap', 'Counterexample: only ARP probes (sender protocol address 0.0.0.0) for one address from two MACs.', probesOnly, ['Expect NO conflict finding and NO "in use" claim from probes alone.']);

    const transition = pcapFile({ variant: 'le-us', packets: [
      { note: 'aa:00:00:00:00:70 announces 192.0.2.70', data: arpAnnouncement({ sha: 'aa:00:00:00:00:70', spa: '192.0.2.70' }), tsSec: T0, tsFrac: 1 },
      { note: 'aa:00:00:00:00:70 announces 192.0.2.71 (same MAC, new address)', data: arpAnnouncement({ sha: 'aa:00:00:00:00:70', spa: '192.0.2.71' }), tsSec: T0, tsFrac: 2 }
    ] });
    add('synthetic-counter-transition.pcap', 'Counterexample: one MAC observed with two different addresses over time (a normal address transition).', transition, ['Expect an informational transition observation, never a conflict finding.']);

    const dupDhcp = pcapFile({ variant: 'le-us', packets: [
      { note: 'OFFER 192.0.2.80 to client A', data: dhcpOffer({ yiaddr: '192.0.2.80', chaddr: 'aa:00:00:00:00:80', xid: 0xaaaa0001 }), tsSec: T0, tsFrac: 1 },
      { note: 'OFFER 192.0.2.80 to client B (different xid)', data: dhcpOffer({ yiaddr: '192.0.2.80', chaddr: 'aa:00:00:00:00:81', xid: 0xbbbb0002 }), tsSec: T0, tsFrac: 2 },
      { note: 'ACK 192.0.2.80 to client A', data: dhcpAck({ yiaddr: '192.0.2.80', chaddr: 'aa:00:00:00:00:80', xid: 0xaaaa0001 }), tsSec: T0, tsFrac: 3 },
      { note: 'ACK 192.0.2.80 to client B', data: dhcpAck({ yiaddr: '192.0.2.80', chaddr: 'aa:00:00:00:00:81', xid: 0xbbbb0002 }), tsSec: T0, tsFrac: 4 }
    ] });
    add('synthetic-counter-dhcp-duplicate.pcap', 'Two different client MACs are offered and ACKed the same address 192.0.2.80.', dupDhcp, ['Expect a qualified possible-duplicate-dhcp-assignment finding with refs to all four packets.']);

    const sameXid = pcapFile({ variant: 'le-us', packets: [
      { note: 'OFFER 192.0.2.90 to client A (xid 0xcc000001)', data: dhcpOffer({ yiaddr: '192.0.2.90', chaddr: 'aa:00:00:00:00:90', xid: 0xcc000001 }), tsSec: T0, tsFrac: 1 },
      { note: 'retransmitted OFFER 192.0.2.90 to the same client (same xid)', data: dhcpOffer({ yiaddr: '192.0.2.90', chaddr: 'aa:00:00:00:00:90', xid: 0xcc000001 }), tsSec: T0, tsFrac: 2 }
    ] });
    add('synthetic-counter-dhcp-retransmit.pcap', 'Counterexample: the same OFFER retransmitted to the same client (same xid, same MAC).', sameXid, ['Expect NO duplicate-assignment finding.']);

    const multiSectionConflict = (() => concat([
      pcapngSectionHeader({ endian: 'le' }),
      pcapngInterface({ endian: 'le' }),
      pcapngEnhancedPacket({ endian: 'le', interfaceId: 0, timestamp: 1000n, data: arpAnnouncement({ sha: 'aa:00:00:00:00:a0', spa: '192.0.2.100' }) }),
      pcapngSectionHeader({ endian: 'le' }),
      pcapngInterface({ endian: 'le' }),
      pcapngEnhancedPacket({ endian: 'le', interfaceId: 0, timestamp: 2000n, data: arpAnnouncement({ sha: 'aa:00:00:00:00:a1', spa: '192.0.2.100' }) })
    ]))();
    add('synthetic-counter-multi-section.pcapng', 'Counterexample: one address claimed by two MACs in two different pcapng sections.', { bytes: multiSectionConflict, records: [], endian: 'le', snaplen: 65535, linkType: 1 }, ['Expect NO conflict finding across section boundaries.']);
  }

  return fixtures;
}

// ---------------------------------------------------------------------------
// CLI: write fixtures + manifest + README
// ---------------------------------------------------------------------------
function renderReadme(fixtures, written) {
  const lines = [];
  lines.push('# LanTriage synthetic fixtures');
  lines.push('');
  lines.push('**Every file in this directory is SELF-AUTHORED SYNTHETIC DATA.** They are constructed');
  lines.push('byte by byte by `tests/fixtures.cjs` to exercise the exact rules of the primary');
  lines.push('format specifications (see `../docs/formats.md` for citations). They are **not**');
  lines.push('captures of real hardware, real networks or real traffic, and no statement about');
  lines.push('any real network may be inferred from them. All MAC addresses use the locally');
  lines.push('administered / fictional `aa:00:...` range and all names contain "fictional".');
  lines.push('');
  lines.push('Regenerate with: `node tests/fixtures.cjs --write` (from the tool root).');
  lines.push('');
  for (const fixture of fixtures) {
    const entry = written.find(w => w.name === fixture.name);
    lines.push('## ' + fixture.name);
    lines.push('');
    lines.push(fixture.description);
    lines.push('');
    lines.push(`- Bytes: ${entry.bytes} | SHA-256: \`${entry.sha256}\``);
    for (const note of fixture.notes) lines.push('- ' + note);
    if (fixture.records && fixture.records.length) {
      lines.push('');
      lines.push('| packet | file offset (bytes) | ts_sec | ts_frac | incl_len | orig_len |');
      lines.push('|---|---|---|---|---|---|');
      fixture.records.forEach((r, i) => {
        lines.push(`| ${i} | ${entry.packetOffsets[i]} | ${r.tsSec} | ${r.tsFrac} | ${r.inclLen} | ${r.origLen} |`);
      });
      lines.push('');
      lines.push('Per-packet header is 16 bytes at `offset - 16`; the first record starts at byte 24.');
    }
    lines.push('');
  }
  return lines.join('\n');
}

function writeFixtures(rootDir) {
  const fixtures = defineFixtures();
  const written = [];
  for (const fixture of fixtures) {
    const filePath = path.join(rootDir, fixture.name);
    fs.writeFileSync(filePath, fixture.bytes);
    const packetOffsets = [];
    if (fixture.records && fixture.records.length) {
      let offset = 24;
      for (const r of fixture.records) { packetOffsets.push(offset); offset += 16 + r.inclLen; }
    }
    written.push({
      name: fixture.name,
      bytes: fixture.bytes.length,
      sha256: crypto.createHash('sha256').update(fixture.bytes).digest('hex'),
      packetOffsets
    });
  }
  fs.writeFileSync(path.join(rootDir, 'manifest.json'), JSON.stringify({ generatedBy: 'tests/fixtures.cjs', synthetic: true, files: written }, null, 2));
  fs.writeFileSync(path.join(rootDir, 'README.md'), renderReadme(fixtures, written));
  return written;
}

function buildFixtures() {
  const map = new Map();
  for (const fixture of defineFixtures()) map.set(fixture.name, fixture.bytes);
  return map;
}

module.exports = {
  defineFixtures, buildFixtures, writeFixtures,
  T0, MAC, BCAST, ZERO,
  ethernet, arpPacket, ipv4, udp, dhcp, dhcpOpt, dhcpMsgType, dnsName, dnsMessage,
  pcapFile, pcapngSectionHeader, pcapngInterface, pcapngEnhancedPacket, pcapngSimplePacket,
  pcapngNameResolutionBlock, pcapngUnknownBlock, pcapngOption, pcapngBlock,
  arpRequest, arpReply, arpProbe, arpAnnouncement,
  dhcpDiscover, dhcpOffer, dhcpRequest, dhcpAck, mdnsQuery, mdnsResponseCompressed,
  plainUdp, ipv6Stub, mac, ip, str, concat
};

if (require.main === module && process.argv.includes('--write')) {
  const rootDir = path.resolve(__dirname, '..', 'fixtures');
  fs.mkdirSync(rootDir, { recursive: true });
  const written = writeFixtures(rootDir);
  for (const w of written) console.log(`${w.name} ${w.bytes} bytes ${w.sha256}`);
}

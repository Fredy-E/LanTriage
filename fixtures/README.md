# LanTriage synthetic fixtures

**Every file in this directory is SELF-AUTHORED SYNTHETIC DATA.** They are constructed
byte by byte by `tests/fixtures.cjs` to exercise the exact rules of the primary
format specifications (see `../docs/formats.md` for citations). They are **not**
captures of real hardware, real networks or real traffic, and no statement about
any real network may be inferred from them. All MAC addresses use the locally
administered / fictional `aa:00:...` range and all names contain "fictional".

Regenerate with: `node tests/fixtures.cjs --write` (from the tool root).

## synthetic-lan-le-us.pcap

Baseline little-endian microsecond pcap: ARP, DHCP, mDNS, VLAN, unsupported IPv6/UDP, one truncated record. All names/addresses fictional.

- Bytes: 2075 | SHA-256: `6176583ba1365f3a2b261bb3621b1fa0958ddd5b9d263beeaf643c8dd00287c2`
- 16 packet records, Ethernet link type 1, snaplen 65535
- Packet index 13 (the 14th record) has incl_len 24 < orig_len 60

| packet | file offset (bytes) | ts_sec | ts_frac | incl_len | orig_len |
|---|---|---|---|---|---|
| 0 | 24 | 1791720000 | 100000 | 42 | 42 |
| 1 | 82 | 1791720000 | 200000 | 42 | 42 |
| 2 | 140 | 1791720000 | 300000 | 320 | 320 |
| 3 | 476 | 1791720000 | 400000 | 304 | 304 |
| 4 | 796 | 1791720000 | 500000 | 298 | 298 |
| 5 | 1110 | 1791720000 | 600000 | 298 | 298 |
| 6 | 1424 | 1791720000 | 700000 | 83 | 83 |
| 7 | 1523 | 1791720000 | 800000 | 99 | 99 |
| 8 | 1638 | 1791720000 | 900000 | 42 | 42 |
| 9 | 1696 | 1791720000 | 1000000 | 42 | 42 |
| 10 | 1754 | 1791720000 | 1100000 | 46 | 46 |
| 11 | 1816 | 1791720000 | 1200000 | 59 | 59 |
| 12 | 1891 | 1791720000 | 1300000 | 70 | 70 |
| 13 | 1977 | 1791720000 | 1400000 | 24 | 60 |
| 14 | 2017 | 1791720000 | 1500000 | 42 | 42 |

Per-packet header is 16 bytes at `offset - 16`; the first record starts at byte 24.

## synthetic-lan-be-us.pcap

Big-endian microsecond pcap (magic bytes a1 b2 c3 d4). Same synthetic conversation subset as the LE baseline.

- Bytes: 905 | SHA-256: `498a5913647faf407ddcab35691f088165790e291b065ee0d0d65194d3224b50`
- 5 packet records, all fields big-endian

| packet | file offset (bytes) | ts_sec | ts_frac | incl_len | orig_len |
|---|---|---|---|---|---|
| 0 | 24 | 1791720000 | 100000 | 42 | 42 |
| 1 | 82 | 1791720000 | 200000 | 42 | 42 |
| 2 | 140 | 1791720000 | 300000 | 320 | 320 |
| 3 | 476 | 1791720000 | 400000 | 298 | 298 |
| 4 | 790 | 1791720000 | 500000 | 99 | 99 |

Per-packet header is 16 bytes at `offset - 16`; the first record starts at byte 24.

## synthetic-lan-le-ns.pcap

Little-endian nanosecond pcap (magic 0xa1b23c4d): fraction field is nanoseconds, not microseconds.

- Bytes: 181 | SHA-256: `35ac524ea9d0cf6bf5dd017f3e7a7c1a571d274a72c6e27bab8f9323f5da77e4`
- 2 packet records; tsFrac values exceed 10^6 to prove ns handling

| packet | file offset (bytes) | ts_sec | ts_frac | incl_len | orig_len |
|---|---|---|---|---|---|
| 0 | 24 | 1791720000 | 123456789 | 42 | 42 |
| 1 | 82 | 1791720000 | 987654321 | 83 | 83 |

Per-packet header is 16 bytes at `offset - 16`; the first record starts at byte 24.

## synthetic-multi-section.pcapng

Two-section pcapng: little-endian section then big-endian section; interface timestamp resolutions 10^-6, 2^-10 and an if_tsoffset; SPB; NRB and custom blocks outside the subset; one EPB referencing a nonexistent interface.

- Bytes: 1040 | SHA-256: `7628f6135f6294fb795f26d5ad43db1418fabeee0f7e788a133dd58335c29ea3`
- Section 1: LE, if_tsresol 6, if_name fictional-eth0, EPB+EPB+SPB, NRB, custom 0x00000BAD
- Section 2: BE, interface 0 tsresol 0x8a (2^-10), interface 1 tsresol 6 + if_tsoffset 3600
- EPB with interface id 5 has no matching IDB (visible rejection)

## synthetic-bad-magic.pcap

pcap whose first byte breaks every legal magic variant.

- Bytes: 82 | SHA-256: `4cc1ad2a788009314c7ab3e2bfddabf22ce079ef99492232bc1ad6aee5a4616b`
- Expect a hard E_MAGIC error.

## synthetic-bad-version.pcap

pcap declaring format version 3.0.

- Bytes: 82 | SHA-256: `efa07cedd69eb6bcee93dbda3ca0d79a0a7365fe1f9804ae6f1236aae34be5a7`
- Expect a hard E_VERSION error.

## synthetic-bad-snaplen.pcap

pcap with snaplen 0 (the draft forbids zero).

- Bytes: 82 | SHA-256: `42cde93ac21b3459762e452bfe0455726b60023656e598991812cdb6ff94707f`
- Expect a hard E_SNAPLEN error.

## synthetic-bad-incl-gt-orig.pcap

pcap record whose captured length exceeds the original length.

- Bytes: 82 | SHA-256: `b702267992ae7d89676c06e8203bbc7b159a8bf66c4b04c5acf9141b1fe0820f`
- Expect the record to be rejected with a visible warning; file still parses.

| packet | file offset (bytes) | ts_sec | ts_frac | incl_len | orig_len |
|---|---|---|---|---|---|
| 0 | 24 | 1791720000 | 1 | 60 | 20 |

Per-packet header is 16 bytes at `offset - 16`; the first record starts at byte 24.

## synthetic-bad-truncated-final.pcap

pcap whose final record is cut mid-packet by end of file.

- Bytes: 60 | SHA-256: `88c450fb5c0ec0b05cc533d4753db8271b51a338d88fb8665145bccf3f729de0`
- Expect a visible truncation warning and limited coverage, not a crash.

## synthetic-bad-no-shb.pcapng

pcapng that begins with an Interface Description Block instead of a Section Header Block.

- Bytes: 104 | SHA-256: `ac5f0cb41ea53ec5fbeed22ff35c460f676a92bf38c4c8625375a405168e7d15`
- Expect a hard E_NO_SHB error.

## synthetic-bad-bom.pcapng

pcapng Section Header Block with a corrupted byte-order magic.

- Bytes: 28 | SHA-256: `6477df63306504aecf6130773bf8d605b556a1858bc83520c1c4d5cf71eb48a9`
- Expect a hard E_BOM error.

## synthetic-bad-blocklen.pcapng

pcapng IDB whose declared total length is not a multiple of 4 and disagrees with its trailer.

- Bytes: 56 | SHA-256: `dc19d4439a543cee8b701338888184266df83239c0e111c007664cd22930b54a`
- Expect a visible W_BLOCK_TRAILER warning with limited coverage.

## synthetic-bad-iface.pcapng

pcapng EPB referencing interface id 3 when only interface 0 exists.

- Bytes: 136 | SHA-256: `38a5a525b3beaa289b288b5ba40a48c0ab0be263a1ee6be170c279bddfc5c831`
- Expect a visible W_IFACE_UNKNOWN warning; the record is rejected, the file still parses.

## synthetic-bad-dhcp-option.pcap

DHCP message cut inside option 12: the option length overruns the available bytes.

- Bytes: 330 | SHA-256: `faa96abaf497c713b4219b6e23c67da8b76008e9f80c08c64a1868bd0d532ea3`
- Expect a visible W_DHCP_OPTION_LEN warning; the message is still reported as DHCP with malformed options.

| packet | file offset (bytes) | ts_sec | ts_frac | incl_len | orig_len |
|---|---|---|---|---|---|
| 0 | 24 | 1791720000 | 1 | 290 | 290 |

Per-packet header is 16 bytes at `offset - 16`; the first record starts at byte 24.

## synthetic-bad-dhcp-cookie.pcap

BOOTP/DHCP message without the 0x63825363 magic cookie.

- Bytes: 318 | SHA-256: `8b154e8745c9d5ba4feb20cf0cb7181521105c89e24459e9b18b7f16b63f5a64`
- Expect a visible W_DHCP_COOKIE warning; options are not parsed.

| packet | file offset (bytes) | ts_sec | ts_frac | incl_len | orig_len |
|---|---|---|---|---|---|
| 0 | 24 | 1791720000 | 1 | 278 | 278 |

Per-packet header is 16 bytes at `offset - 16`; the first record starts at byte 24.

## synthetic-bad-dns-loop.pcap

mDNS response whose answer name pointer targets its own offset (a compression cycle).

- Bytes: 110 | SHA-256: `964fae4ff8885d8d31d96385a4c52c829c0d214310376f15f375b6d1bb649874`
- Expect a visible W_DNS_LOOP warning; the answer is not decoded and the packet is counted as not decoded.

| packet | file offset (bytes) | ts_sec | ts_frac | incl_len | orig_len |
|---|---|---|---|---|---|
| 0 | 24 | 1791720000 | 1 | 70 | 70 |

Per-packet header is 16 bytes at `offset - 16`; the first record starts at byte 24.

## synthetic-bad-dns-pointer.pcap

mDNS response whose answer name pointer is outside the message.

- Bytes: 110 | SHA-256: `0929c7be1fd64f1f56623dbcc72ed4efd6ceefbc9c20bfc96de7956ab9753495`
- Expect a visible W_DNS_POINTER_RANGE warning.

| packet | file offset (bytes) | ts_sec | ts_frac | incl_len | orig_len |
|---|---|---|---|---|---|
| 0 | 24 | 1791720000 | 1 | 70 | 70 |

Per-packet header is 16 bytes at `offset - 16`; the first record starts at byte 24.

## synthetic-bad-fragment.pcap

IPv4 fragment (MF flag set) carrying a DHCP-shaped UDP datagram: fragments are outside the supported subset.

- Bytes: 86 | SHA-256: `cf28257f8421e00ab2728f04b29e489e5965109387643484224397c651a87b23`
- Expect the fragment to be counted as not decoded (visible unsupported), never decoded as DHCP.

| packet | file offset (bytes) | ts_sec | ts_frac | incl_len | orig_len |
|---|---|---|---|---|---|
| 0 | 24 | 1791720000 | 1 | 46 | 46 |

Per-packet header is 16 bytes at `offset - 16`; the first record starts at byte 24.

## synthetic-prototype-names.pcap

Synthetic identifiers that collide with JavaScript prototype member names (__proto__, constructor).

- Bytes: 533 | SHA-256: `10614cdb607398c35f2bf2ea9028916306d191251279ad93415671f4c86b5eae`
- Expect normal decoding; internal sets must not treat these as pre-existing members.

| packet | file offset (bytes) | ts_sec | ts_frac | incl_len | orig_len |
|---|---|---|---|---|---|
| 0 | 24 | 1791720000 | 1 | 75 | 75 |
| 1 | 115 | 1791720000 | 2 | 299 | 299 |
| 2 | 430 | 1791720000 | 3 | 87 | 87 |

Per-packet header is 16 bytes at `offset - 16`; the first record starts at byte 24.

## synthetic-counter-vlan-split.pcap

Counterexample: one IP claimed by two MACs in two DIFFERENT VLANs (not a conflict candidate).

- Bytes: 148 | SHA-256: `eea2768bfe0e1c4ccae63aba5ae85c05d6dc2c1a55cc4ee8d87e8c216cc0fbb1`
- Expect NO possible-ip-mac-conflict finding.

| packet | file offset (bytes) | ts_sec | ts_frac | incl_len | orig_len |
|---|---|---|---|---|---|
| 0 | 24 | 1791720000 | 1 | 46 | 46 |
| 1 | 86 | 1791720000 | 2 | 46 | 46 |

Per-packet header is 16 bytes at `offset - 16`; the first record starts at byte 24.

## synthetic-counter-probe-only.pcap

Counterexample: only ARP probes (sender protocol address 0.0.0.0) for one address from two MACs.

- Bytes: 140 | SHA-256: `7654cdabd73b5004ec42820b3500eeea7a7531d3601f2c691eb4f3b12ff8634a`
- Expect NO conflict finding and NO "in use" claim from probes alone.

| packet | file offset (bytes) | ts_sec | ts_frac | incl_len | orig_len |
|---|---|---|---|---|---|
| 0 | 24 | 1791720000 | 1 | 42 | 42 |
| 1 | 82 | 1791720000 | 2 | 42 | 42 |

Per-packet header is 16 bytes at `offset - 16`; the first record starts at byte 24.

## synthetic-counter-transition.pcap

Counterexample: one MAC observed with two different addresses over time (a normal address transition).

- Bytes: 140 | SHA-256: `b5bfa37bbbf1d291d4e778008cbf0c97afe11d534d46c8f7e2e828b68e16ad4f`
- Expect an informational transition observation, never a conflict finding.

| packet | file offset (bytes) | ts_sec | ts_frac | incl_len | orig_len |
|---|---|---|---|---|---|
| 0 | 24 | 1791720000 | 1 | 42 | 42 |
| 1 | 82 | 1791720000 | 2 | 42 | 42 |

Per-packet header is 16 bytes at `offset - 16`; the first record starts at byte 24.

## synthetic-counter-dhcp-duplicate.pcap

Two different client MACs are offered and ACKed the same address 192.0.2.80.

- Bytes: 1292 | SHA-256: `09990ee37aaae1db20caeaf43457c770bcc3802e8b301b6ae5a49c95600691e1`
- Expect a qualified possible-duplicate-dhcp-assignment finding with refs to all four packets.

| packet | file offset (bytes) | ts_sec | ts_frac | incl_len | orig_len |
|---|---|---|---|---|---|
| 0 | 24 | 1791720000 | 1 | 304 | 304 |
| 1 | 344 | 1791720000 | 2 | 304 | 304 |
| 2 | 664 | 1791720000 | 3 | 298 | 298 |
| 3 | 978 | 1791720000 | 4 | 298 | 298 |

Per-packet header is 16 bytes at `offset - 16`; the first record starts at byte 24.

## synthetic-counter-dhcp-retransmit.pcap

Counterexample: the same OFFER retransmitted to the same client (same xid, same MAC).

- Bytes: 664 | SHA-256: `2cf15619ccd65b3d5559c9353fcb9d835584d40d8e2830219d716788a1fa14dd`
- Expect NO duplicate-assignment finding.

| packet | file offset (bytes) | ts_sec | ts_frac | incl_len | orig_len |
|---|---|---|---|---|---|
| 0 | 24 | 1791720000 | 1 | 304 | 304 |
| 1 | 344 | 1791720000 | 2 | 304 | 304 |

Per-packet header is 16 bytes at `offset - 16`; the first record starts at byte 24.

## synthetic-counter-multi-section.pcapng

Counterexample: one address claimed by two MACs in two different pcapng sections.

- Bytes: 272 | SHA-256: `b71e4fa24c505e8e06571d37f94a044bb34f48a1b75159449269fe43bbd5f118`
- Expect NO conflict finding across section boundaries.

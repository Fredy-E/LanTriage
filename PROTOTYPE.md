# LanTriage — prototype status

**Experimental concept prototype — idea exploration only.** This repository shares runnable exploratory code, not a finished product or production-ready release. The repository's package version identifies this iteration; it is not a release-readiness claim.

## Purpose

Explore a bounded, local pcap/pcapng evidence viewer for imported DHCP, ARP and mDNS observations. Examples, capture fixtures and the included screenshot use fictional data. No real packet capture or owner network data is included.

## What is not established

This is not live packet capture, a Wireshark replacement or a network-health diagnosis. Findings are qualified candidates; unseen traffic and unsupported protocols remain outside the evidence. Narrow evidence tables can clip content. No real-network hardware matrix, complete protocol coverage or clean-machine qualification is established. Features may change or remain unfinished. Review reports before sharing them.

## Verification provenance

The approved local source baseline, verified on 2026-10-11, passed 91 default Node tests and 6 real-Chrome scenarios using synthetic capture bytes and actual browser downloads. Those results measure tested behavior only, not real-world reliability.

This publication copy adds prototype status text to the README and viewer plus this document, and replaces the misleading “first release” label with “implemented prototype subset.” Runtime JavaScript, parsers, fixtures and test logic are preserved from the approved source. Reviewer logs and owner data are not included.

Open `index.html` directly. For development, use `npm test`; the real-Chrome suite is `node tests/browser.cjs`. Full historical scope and limitations are in [docs/verification.md](docs/verification.md). Publication is source sharing only: no GitHub Release, deployment or support commitment is implied.

// SPDX-License-Identifier: MIT

// Package mdns is a small, dependency-free implementation of the parts of
// Multicast DNS (RFC 6762) and DNS-Based Service Discovery (RFC 6763) that an
// OPC UA Local Discovery Server with the multicast extension (LDS-ME, OPC UA
// Part 12) needs: it announces service instances and it browses for the
// instances announced by others.
//
// # What is implemented
//
//   - A DNS message encoder and decoder for the record types DNS-SD uses (PTR,
//     SRV, TXT, A, AAAA; any other type is carried as opaque data), with name
//     compression on both sides. The decoder is written for hostile input:
//     see [Unpack].
//   - A responder: unsolicited announcements when an instance is registered
//     (two, one second apart, RFC 6762 §8.3), answers to PTR, SRV, TXT, A,
//     AAAA and ANY questions including the DNS-SD service type enumeration
//     name (RFC 6763 §9), additional records (RFC 6763 §12), known-answer
//     suppression (RFC 6762 §7.1), legacy unicast responses to queriers that
//     do not use port 5353 (RFC 6762 §6.7), the cache-flush bit on unique
//     records (§10.2), the one-second multicast rate limit per record and
//     interface (§6), and goodbye packets (TTL 0, §10.1) when an instance is
//     withdrawn or the node is closed.
//   - A browser: continuous PTR queries with exponential back-off and known
//     answers (§5.2), resolution of SRV and TXT records of discovered
//     instances, a cache with TTL expiry and refresh queries at 80% and 90% of
//     the lifetime (§5.2), and goodbye handling with the one-second grace
//     period (§10.1).
//   - Transport over one UDP socket per interface and address family, joined
//     to 224.0.0.251 and ff02::fb on port 5353, with a hop limit of 255,
//     multicast loopback (so that processes on the same host see each other)
//     and the source-address check of §11. The engine only talks to the
//     [PacketConn] interface; [MemNetwork] is an in-memory implementation for
//     tests.
//
// # What is not implemented
//
//   - Probing and conflict resolution (§8.1, §8.2, §9). Instance names are
//     announced without probing. A conflicting SRV record from another
//     responder is detected and logged, not resolved by renaming.
//   - The random 20-120 ms delay before answering with shared records (§6)
//     and the aggregation of responses.
//   - Truncated queries: the TC bit is neither set nor honoured (§7.2), and a
//     known-answer list that does not fit one packet is shortened.
//   - Unicast responses on request (the QU bit, §5.4) and direct unicast
//     queries to port 5353: such queries are answered by multicast.
//   - NSEC records for negative responses (§6.1) and reverse address mapping.
//   - Caching of the address records of other hosts: discovered instances are
//     reported with the host name of their SRV record.
//   - Sleep proxy, wide-area DNS-SD and service subtypes.
//
// # Deliberate deviations
//
// Two rules of RFC 6762 are relaxed for the mdnsd library that open62541
// embeds, which sends all its traffic from an ephemeral UDP port:
//
//   - §6 says that a response from a source port other than 5353 must be
//     ignored. Such responses are accepted. The source-address check of §11
//     still applies.
//   - §6.7 says that a query from a source port other than 5353 is a legacy
//     unicast query. It is only treated as one if its query id is not zero; a
//     query with id zero (which a multicast querier must use, §18.1) is
//     answered by multicast.
package mdns

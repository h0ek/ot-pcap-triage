from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .metadata import generate_suggested_metadata, metadata_allowed_plc_talkers, metadata_expected_protocols
from .rules import CORE_RULES, INDUSTRIAL_RULES, SENSITIVE_RULES
from .utils import first_nonempty, is_public_ip, normalize_protocol_name, redact, safe_float, safe_int, sha256_file


PACKET_FIELDS = [
    "frame.number",
    "frame.time",
    "frame.time_epoch",
    "frame.len",
    "eth.src",
    "eth.dst",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "_ws.col.Protocol",
    "frame.protocols",
    "vlan.id",
]


def _iso(epoch):
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat() if epoch else ""


def _dur(seconds):
    if seconds < 60:
        return f"{seconds:.1f}s"
    if seconds < 3600:
        return f"{seconds / 60:.1f}m"
    return f"{seconds / 3600:.2f}h"


def _proto(row):
    src_port = first_nonempty(row.get("tcp.srcport"), row.get("udp.srcport"))
    dst_port = first_nonempty(row.get("tcp.dstport"), row.get("udp.dstport"))
    ports = {src_port, dst_port}

    by_port = {
        "67": "DHCP",
        "68": "DHCP",
        "137": "NBNS",
        "138": "NBDGM/Browser",
        "139": "NBSS",
        "445": "SMB",
        "53": "DNS",
        "123": "NTP",
        "161": "SNMP",
        "162": "SNMPTRAP",
        "1947": "Sentinel/HASP",
        "3702": "WS-Discovery",
        "502": "Modbus",
        "102": "S7/COTP",
        "44818": "EtherNet/IP",
        "4840": "OPC UA",
        "20000": "DNP3",
        "2404": "IEC104",
        "47808": "BACnet",
        "9600": "FINS",
        "48898": "Beckhoff ADS",
        "18245": "GE SRTP",
        "5094": "HART-IP",
        "1194": "OPENVPN",
        "500": "ISAKMP",
        "4500": "IPsec/UDP-encap",
    }
    for port in ports:
        if port in by_port:
            return by_port[port]

    protocols = str(row.get("frame.protocols") or "").split(":")
    preferred = [
        "arp", "icmp", "icmpv6", "dhcp", "dns", "nbns", "nbdgm", "smb", "smb2",
        "llmnr", "mdns", "ssdp", "http", "tls", "ssl", "ftp", "telnet",
        "tftp", "snmp", "ntp", "ldap", "kerberos", "modbus", "mbtcp",
        "s7comm", "s7comm_plus", "cotp", "tpkt", "pn_rt", "pn_dcp", "ptcp",
        "enip", "cip", "opcua", "dnp3", "iec104", "bacnet", "ecat", "fins",
        "ams", "srtp", "lldp", "cdp", "stp", "rstp", "mstp", "vrrp", "hsrp",
        "ospf", "syslog", "openvpn", "isakmp", "esp", "udpencap",
    ]

    for protocol in reversed(protocols):
        if protocol in preferred:
            if protocol in {"cotp", "tpkt", "s7comm", "s7comm_plus"}:
                return "S7/COTP"
            if protocol == "mbtcp":
                return "Modbus"
            return protocol.upper()

    col = row.get("_ws.col.Protocol")
    if col and col != "UNKNOWN":
        return col

    for protocol in reversed(protocols):
        if protocol and protocol not in {"frame", "eth", "ethertype", "ip", "ipv6", "tcp", "udp", "data"}:
            return protocol.upper()

    return "UNKNOWN"


def _ev(row):
    return {
        "frame_number": row.get("frame.number", ""),
        "timestamp": row.get("frame.time", ""),
        "timestamp_epoch": row.get("frame.time_epoch", ""),
        "protocol": _proto(row),
        "src_ip": first_nonempty(row.get("ip.src"), row.get("ipv6.src")),
        "src_mac": row.get("eth.src", ""),
        "src_port": first_nonempty(row.get("tcp.srcport"), row.get("udp.srcport")),
        "dst_ip": first_nonempty(row.get("ip.dst"), row.get("ipv6.dst")),
        "dst_mac": row.get("eth.dst", ""),
        "dst_port": first_nonempty(row.get("tcp.dstport"), row.get("udp.dstport")),
        "tcp_stream": row.get("tcp.stream", ""),
        "info": row.get("_ws.col.Info", ""),
    }


def _finding(rule, pcap, evidence, flt, status="candidate", conf="medium", severity=None, reason=None, owner=True):
    return {
        "id": rule["id"],
        "title": rule["title"],
        "severity": severity or rule.get("severity", "info"),
        "confidence": conf,
        "status": status,
        "category": rule.get("category", "unknown"),
        "source": "automated",
        "requires_owner_confirmation": owner,
        "pcap_file": pcap.name,
        "evidence": [_ev(row) for row in evidence],
        "wireshark_filter": flt,
        "reason": reason or rule.get("reason", ""),
        "recommendation": rule.get("recommendation", "Validate with site owner."),
        "manual_validation": {
            "required": True,
            "steps": [
                "Open the PCAP in Wireshark.",
                "Apply the provided Wireshark filter or use listed frame numbers.",
                "Confirm evidence and expected architecture.",
            ],
        },
    }


def _flow_key(row):
    return (
        first_nonempty(row.get("ip.src"), row.get("ipv6.src")),
        first_nonempty(row.get("ip.dst"), row.get("ipv6.dst")),
        first_nonempty(row.get("tcp.srcport"), row.get("udp.srcport")),
        first_nonempty(row.get("tcp.dstport"), row.get("udp.dstport")),
        _proto(row),
    )


def _private_dst_filter(field: str = "ip.dst") -> str:
    return (
        f"!({field} == 10.0.0.0/8) && "
        f"!({field} == 172.16.0.0/12) && "
        f"!({field} == 192.168.0.0/16) && "
        f"!({field} == 127.0.0.0/8) && "
        f"!({field} == 169.254.0.0/16) && "
        f"!({field} == 224.0.0.0/4) && "
        f"!({field} == 0.0.0.0) && "
        f"!({field} == 255.255.255.255)"
    )


def _private_any_filter() -> str:
    return (
        "ip && "
        "!(ip.addr == 10.0.0.0/8) && "
        "!(ip.addr == 172.16.0.0/12) && "
        "!(ip.addr == 192.168.0.0/16) && "
        "!(ip.addr == 127.0.0.0/8) && "
        "!(ip.addr == 169.254.0.0/16) && "
        "!(ip.addr == 224.0.0.0/4) && "
        "!(ip.addr == 0.0.0.0) && "
        "!(ip.addr == 255.255.255.255)"
    )


def _dynamic_evidence(tshark, pcap: Path, display_filter: str, max_evidence: int):
    try:
        rows = tshark.evidence_rows(pcap, display_filter, max_evidence)
        return rows, display_filter
    except Exception:
        # Dynamic helper should never break the whole report.
        return [], display_filter


def _write_partial(work_dir: Path | None, name: str, data):
    if not work_dir:
        return
    work_dir.mkdir(parents=True, exist_ok=True)
    (work_dir / name).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def analyze_pcap(pcap: Path, metadata, tshark, max_evidence=10, work_dir: Path | None = None):
    metadata = metadata or {}

    frame_count = 0
    total_bytes = 0
    first = None
    last = None
    endpoints = {}
    conv = Counter()
    conv_bytes = Counter()
    protos = Counter()
    vlans = set()

    print("[*]   streaming packet aggregation...")

    for row in tshark.iter_fields(pcap, PACKET_FIELDS):
        frame_count += 1
        total_bytes += safe_int(row.get("frame.len"))

        epoch = safe_float(row.get("frame.time_epoch"))
        if epoch:
            first = epoch if first is None else min(first, epoch)
            last = epoch if last is None else max(last, epoch)

        proto = _proto(row)
        protos[proto] += 1

        if row.get("vlan.id"):
            for vlan in str(row["vlan.id"]).split(","):
                if vlan:
                    vlans.add(vlan)

        for ipf, macf in [
            ("ip.src", "eth.src"),
            ("ip.dst", "eth.dst"),
            ("ipv6.src", "eth.src"),
            ("ipv6.dst", "eth.dst"),
        ]:
            ip = row.get(ipf)
            if not ip:
                continue

            endpoints.setdefault(
                ip,
                {
                    "ip": ip,
                    "macs": set(),
                    "packets": 0,
                    "bytes": 0,
                    "protocols": Counter(),
                    "public": is_public_ip(ip),
                },
            )
            endpoints[ip]["packets"] += 1
            endpoints[ip]["bytes"] += safe_int(row.get("frame.len"))
            endpoints[ip]["protocols"][proto] += 1

            if row.get(macf):
                endpoints[ip]["macs"].add(row[macf])

        key = _flow_key(row)
        if key[0] or key[1]:
            conv[key] += 1
            conv_bytes[key] += safe_int(row.get("frame.len"))

    duration = (last - first) if first and last else 0.0

    endpoint_rows = [
        {
            "ip": ip,
            "macs": ",".join(sorted(data["macs"])),
            "packets": data["packets"],
            "bytes": data["bytes"],
            "public": data["public"],
            "top_protocols": ", ".join(f"{k}:{v}" for k, v in data["protocols"].most_common(5)),
        }
        for ip, data in endpoints.items()
    ]
    endpoint_rows.sort(key=lambda item: item["bytes"], reverse=True)

    conversation_rows = [
        {
            "src_ip": src,
            "dst_ip": dst,
            "src_port": sport,
            "dst_port": dport,
            "protocol": proto,
            "packets": count,
            "bytes": conv_bytes[(src, dst, sport, dport, proto)],
            "external": is_public_ip(src) or is_public_ip(dst),
        }
        for (src, dst, sport, dport, proto), count in conv.most_common()
    ]

    protocol_rows = [
        {"name": proto, "normalized": normalize_protocol_name(proto), "count": count, "group": "observed"}
        for proto, count in protos.most_common()
    ]

    _write_partial(work_dir, "partial_main_summary.json", {
        "frame_count": frame_count,
        "bytes": total_bytes,
        "duration_human": _dur(duration),
        "top_protocols": protocol_rows[:25],
        "top_endpoints": endpoint_rows[:25],
        "top_conversations": conversation_rows[:25],
    })

    findings = []
    rule_results = []
    expected = metadata_expected_protocols(metadata)

    print("[*]   running rule filters...")
    for idx, (rule, group) in enumerate([(r, "core") for r in CORE_RULES] + [(r, "industrial") for r in INDUSTRIAL_RULES], start=1):
        print(f"[*]     rule {idx}: {rule['id']}")
        evidence = tshark.evidence_rows(pcap, rule["filter"], max_evidence)
        count = tshark.count_filter(pcap, rule["filter"]) if evidence else 0

        result = {
            "id": rule["id"],
            "name": rule.get("name", rule["id"]),
            "title": rule["title"],
            "filter": rule["filter"],
            "count": count,
            "group": group,
        }
        rule_results.append(result)
        _write_partial(work_dir, "partial_rule_results.json", rule_results)

        if count <= 0:
            continue

        protocol_rows.append({
            "name": rule.get("name", rule["title"]),
            "normalized": rule.get("name", normalize_protocol_name(rule["title"])),
            "count": count,
            "group": group,
        })

        severity = rule.get("severity", "info")
        status = "informational" if severity == "info" else "candidate"
        reason = rule.get("reason", "")

        if group == "industrial" and expected and str(rule.get("name", "")).lower() not in expected:
            severity = "medium"
            status = "candidate"
            reason = f"{rule['title']} but this protocol is not listed in expected_protocols."

        if severity != "info" or status == "candidate":
            findings.append(_finding(rule, pcap, evidence, rule["filter"], status=status, severity=severity, reason=reason))

    # Dynamic findings with real frame evidence.
    public_ip_filter = _private_any_filter()
    public_ip_evidence, public_ip_filter = _dynamic_evidence(tshark, pcap, public_ip_filter, max_evidence)
    if public_ip_evidence:
        findings.append(_finding({
            "id": "OT-NET-PUBLIC-IP",
            "title": "Public IP communication observed",
            "severity": "medium",
            "category": "external_communication",
            "reason": "Communication with public IP addresses was observed.",
            "recommendation": "Confirm whether this external communication is approved.",
        }, pcap, public_ip_evidence, public_ip_filter, conf="high"))

    public_dns_filter = f"dns && {_private_dst_filter('ip.dst')}"
    public_dns_evidence, public_dns_filter = _dynamic_evidence(tshark, pcap, public_dns_filter, max_evidence)
    if public_dns_evidence:
        findings.append(_finding({
            "id": "OT-NET-PUBLIC-DNS",
            "title": "Public DNS resolver used",
            "severity": "medium",
            "category": "external_communication",
            "reason": "DNS traffic to a public IP address was observed.",
            "recommendation": "Confirm whether public DNS is approved. Prefer controlled internal resolvers for OT.",
        }, pcap, public_dns_evidence, public_dns_filter, conf="high"))

    public_ntp_filter = f"ntp && {_private_dst_filter('ip.dst')}"
    public_ntp_evidence, public_ntp_filter = _dynamic_evidence(tshark, pcap, public_ntp_filter, max_evidence)
    if public_ntp_evidence:
        findings.append(_finding({
            "id": "OT-NET-PUBLIC-NTP",
            "title": "Public NTP server used",
            "severity": "medium",
            "category": "external_communication",
            "reason": "NTP traffic to a public IP address was observed.",
            "recommendation": "Confirm whether public NTP is approved. Prefer controlled internal time sources for OT.",
        }, pcap, public_ntp_evidence, public_ntp_filter, conf="high"))

    vpn_filter = "openvpn || isakmp || esp || udpencap || udp.port == 1194 || udp.port == 500 || udp.port == 4500"
    vpn_evidence, vpn_filter = _dynamic_evidence(tshark, pcap, vpn_filter, max_evidence)
    if vpn_evidence:
        findings.append(_finding({
            "id": "OT-NET-VPN-TRAFFIC",
            "title": "VPN/IPsec/OpenVPN-like traffic observed",
            "severity": "medium",
            "category": "remote_access",
            "reason": "VPN/IPsec/OpenVPN-like traffic was observed.",
            "recommendation": "Confirm whether this is an approved remote access path and whether it is properly controlled/logged.",
        }, pcap, vpn_evidence, vpn_filter, conf="medium"))

    sensitive = []
    print("[*]   checking sensitive/plaintext indicators...")
    for sr in SENSITIVE_RULES:
        rs = tshark.evidence_rows(pcap, sr["filter"], max_evidence, extra_fields=sr.get("fields", []))
        for row in rs:
            sensitive.append({
                "rule_id": sr["id"],
                "title": sr["title"],
                "severity": sr["severity"],
                "evidence": _ev(row),
                "redacted_fields": {f: redact(row.get(f)) for f in sr.get("fields", []) if row.get(f)},
                "wireshark_filter": f"frame.number == {row.get('frame.number')}" if row.get("frame.number") else sr["filter"],
            })
        if rs:
            findings.append(_finding(sr, pcap, rs, sr["filter"], status="confirmed_by_rule", conf="high", owner=False))

    allowed = metadata_allowed_plc_talkers(metadata)
    if allowed:
        known_plcs = set(allowed.keys())
        industrial_filter = " || ".join(rule["filter"] for rule in INDUSTRIAL_RULES[:15])
        industrial_rows = tshark.evidence_rows(pcap, industrial_filter, max_evidence * 20)
        unexpected = []
        for row in industrial_rows:
            src = first_nonempty(row.get("ip.src"), row.get("ipv6.src"))
            dst = first_nonempty(row.get("ip.dst"), row.get("ipv6.dst"))
            for plc in known_plcs:
                if dst == plc and src and src not in allowed.get(plc, set()):
                    unexpected.append(row)
                elif src == plc and dst and dst not in allowed.get(plc, set()):
                    unexpected.append(row)
            if len(unexpected) >= max_evidence:
                break

        if unexpected:
            findings.append(_finding({
                "id": "OT-ICS-UNEXPECTED-PLC-TALKER",
                "title": "Unexpected host communicating with known PLC/controller",
                "severity": "medium",
                "category": "expected_vs_observed",
                "reason": "Industrial traffic involving a known PLC/controller was observed from a host not listed as an allowed PLC talker in metadata.",
                "recommendation": "Validate the source host role. Restrict direct PLC communication to approved HMI/SCADA/engineering systems.",
            }, pcap, unexpected, industrial_filter, conf="high"))

    quality = {
        "duration_seconds": duration,
        "duration_human": _dur(duration),
        "frame_count": frame_count,
        "total_bytes": total_bytes,
        "avg_packets_per_second": frame_count / duration if duration > 0 else 0,
        "avg_bytes_per_second": total_bytes / duration if duration > 0 else 0,
        "notes": [],
    }
    if duration and duration < 60:
        quality["notes"].append("Very short capture. Findings may have lower confidence.")
    if frame_count == 0:
        quality["notes"].append("No packets parsed.")

    summary = {
        "tool": "ot-pcap-triage",
        "pcap": {
            "file": pcap.name,
            "path": str(pcap),
            "sha256": sha256_file(pcap),
            "first_packet_time": _iso(first),
            "last_packet_time": _iso(last),
            "duration_seconds": duration,
            "duration_human": _dur(duration),
            "frames": frame_count,
            "bytes": total_bytes,
        },
        "metadata_provided": bool(metadata),
        "baseline_mode_notice": (
            "No metadata YAML was provided. Findings are based on generic OT/ICS good-practice checks and should be validated with the site owner."
            if not metadata else ""
        ),
        "capture_quality": quality,
        "vlans": sorted(vlans),
        "endpoints": endpoint_rows,
        "conversations": conversation_rows,
        "protocols": protocol_rows,
        "rule_results": rule_results,
        "sensitive_hits_redacted": sensitive,
        "findings_count": len(findings),
    }

    _write_partial(work_dir, "partial_findings.json", findings)
    return summary, findings, generate_suggested_metadata(summary), tshark.raw_protocol_hierarchy(pcap)

from __future__ import annotations

import json
from collections import Counter, defaultdict
from importlib.resources import files
import yaml
from datetime import datetime, timezone
from math import isfinite
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
    "tcp.stream",
    "dns.flags.response",
    "ntp.flags.mode",
]


def _iso(epoch):
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat() if epoch else ""


def _dur(seconds):
    if seconds < 60:
        return f"{seconds:.1f}s"
    if seconds < 3600:
        return f"{seconds / 60:.1f}m"
    return f"{seconds / 3600:.2f}h"


GENERIC = {"frame", "eth", "ethertype", "ip", "ipv6", "tcp", "udp", "data", "vlan", "sll", "sll2", "null", "loop", "raw", "tcp.segments", "tcp.segment", "_ws.malformed", "_ws.short", "eth.trailer", "ipv6.hopopts", "ipv6.fraghdr", "ipv6.routing"}

PROTOCOL_LABELS = {
    "modbus": "Modbus", "mbtcp": "Modbus", "s7comm": "S7/COTP", "s7comm_plus": "S7comm Plus",
    "cotp": "COTP", "tpkt": "TPKT", "enip": "EtherNet/IP", "cip": "EtherNet/IP", "cipsafety": "CIP Safety",
    "opcua": "OPC UA", "iec60870_104": "IEC104", "iec104": "IEC104", "pn_rt": "PROFINET", "pn_dcp": "PROFINET DCP",
    "pn_io": "PROFINET IO", "pn_ptcp": "PROFINET PTCP", "ptcp": "PROFINET PTCP", "ecat": "EtherCAT", "ethercat": "EtherCAT", "ecat_mailbox": "EtherCAT",
    "omron": "FINS", "ams": "Beckhoff ADS", "ams_tcp": "Beckhoff ADS", "gesrtp": "GE SRTP", "egd": "GE EGD", "epl": "POWERLINK",
    "bacapp": "BACnet", "bvlc": "BACnet", "hart_ip": "HART-IP", "hartip": "HART-IP", "knxnetip": "KNXnet/IP",
    "pcomtcp": "PCOM", "pcomascii": "PCOM", "pcombinary": "PCOM", "optommp": "OptoMMP",
    "smb2": "SMB2/3", "smb": "SMBv1", "nbdgm": "NBDGM/Browser", "udpencap": "IPsec/UDP-encap",
}


def _tokens(row):
    return set(str(row.get("frame.protocols") or "").lower().split(":")) - {""}


def _transport(row):
    if row.get("tcp.srcport") or row.get("tcp.dstport"):
        return "tcp"
    if row.get("udp.srcport") or row.get("udp.dstport"):
        return "udp"
    return ""


def _proto(row):
    layers = str(row.get("frame.protocols") or "").lower().split(":")
    for protocol in reversed(layers):
        if protocol and protocol not in GENERIC:
            return PROTOCOL_LABELS.get(protocol, protocol.upper())
    col = str(row.get("_ws.col.Protocol") or "").strip()
    if col and col.upper() not in {"TCP", "UDP", "IP", "IPV6", "ETH", "ETHERNET", "UNKNOWN", "DATA", "MALFORMED PACKET"}:
        return col
    return "UNKNOWN"


def _frame_filter(rows):
    frames = sorted({int(row["frame.number"]) for row in rows if str(row.get("frame.number", "")).isdigit()})
    return " || ".join(f"frame.number == {number}" for number in frames)


def _candidate_ports():
    catalog = yaml.safe_load(files("ot_pcap_triage").joinpath("protocol_catalog.yml").read_text(encoding="utf-8"))["protocols"]
    return {tuple(str(port).split("/", 1)) for data in catalog.values() if data.get("category") in {"industrial", "utility", "industrial integration", "instrumentation", "building automation", "safety"} for port in data.get("ports", [])}


def _ev(row):
    return {
        "frame_number": row.get("frame.number", ""),
        "timestamp": row.get("frame.time", ""),
        "timestamp_epoch": row.get("frame.time_epoch", ""),
        "protocol": _proto(row),
        "transport": _transport(row),
        "src_ip": first_nonempty(row.get("ip.src"), row.get("ipv6.src")),
        "src_mac": row.get("eth.src", ""),
        "src_port": first_nonempty(row.get("tcp.srcport"), row.get("udp.srcport")),
        "dst_ip": first_nonempty(row.get("ip.dst"), row.get("ipv6.dst")),
        "dst_mac": row.get("eth.dst", ""),
        "dst_port": first_nonempty(row.get("tcp.dstport"), row.get("udp.dstport")),
        "tcp_stream": row.get("tcp.stream", ""),
        "info": "",
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
        _transport(row),
    )


def _write_partial(work_dir: Path | None, name: str, data):
    if not work_dir:
        return
    work_dir.mkdir(parents=True, exist_ok=True)
    (work_dir / name).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def analyze_pcap(pcap: Path, metadata, tshark, max_evidence=10, work_dir: Path | None = None):
    metadata = metadata or {}
    if max_evidence < 1:
        raise ValueError("max_evidence must be at least 1")

    frame_count = 0
    total_bytes = 0
    first = None
    last = None
    endpoints = {}
    conv = Counter()
    conv_bytes = Counter()
    protos = Counter()
    decoded_layers = Counter()
    vlans = set()
    allowed = metadata_allowed_plc_talkers(metadata)
    candidate_ports = _candidate_ports() if allowed else set()
    decoded_counts = Counter()
    decoded_samples = defaultdict(list)
    dynamic_counts = Counter()
    dynamic_samples = defaultdict(list)
    rules_by_token = defaultdict(list)
    for rule in INDUSTRIAL_RULES:
        for token in rule["tokens"]:
            rules_by_token[token].append(rule["id"])
    industrial_ids = {rule["id"] for rule in INDUSTRIAL_RULES if rule["category"] == "industrial_protocol" and rule["name"] not in {"mqtt", "amqp"}}

    def record(key, row, counts, samples):
        counts[key] += 1
        if len(samples[key]) < max_evidence:
            samples[key].append(row)


    print("[*]   streaming packet aggregation...")

    for row in tshark.iter_fields(pcap, PACKET_FIELDS):
        frame_count += 1
        total_bytes += safe_int(row.get("frame.len"))

        epoch = safe_float(row.get("frame.time_epoch"))
        if epoch and isfinite(epoch):
            first = epoch if first is None else min(first, epoch)
            last = epoch if last is None else max(last, epoch)

        proto = _proto(row)
        protos[proto] += 1
        tokens = _tokens(row)
        decoded_layers.update(tokens - GENERIC)
        matched = {rid for token in tokens for rid in rules_by_token.get(token, [])}
        for rid in matched:
            record(rid, row, decoded_counts, decoded_samples)
        src = first_nonempty(row.get("ip.src"), row.get("ipv6.src"))
        dst = first_nonempty(row.get("ip.dst"), row.get("ipv6.dst"))
        if any(is_public_ip(row.get(field)) for field in ("ip.src", "ip.dst", "ipv6.src", "ipv6.dst")):
            record("public_ip", row, dynamic_counts, dynamic_samples)
        if is_public_ip(dst) and "dns" in tokens and str(row.get("dns.flags.response", "")).lower() in {"0", "false"}:
            record("public_dns", row, dynamic_counts, dynamic_samples)
        if is_public_ip(dst) and "ntp" in tokens and row.get("ntp.flags.mode") == "3":
            record("public_ntp", row, dynamic_counts, dynamic_samples)
        transport = _transport(row)
        ports = {first_nonempty(row.get("tcp.srcport"), row.get("udp.srcport")), first_nonempty(row.get("tcp.dstport"), row.get("udp.dstport"))}
        decoded_industrial = bool(matched & industrial_ids)
        possible_industrial = proto in {"UNKNOWN", "COTP", "TPKT"} and any((port, transport) in candidate_ports for port in ports)
        if (decoded_industrial or possible_industrial) and src and dst and ((src in allowed and dst not in allowed[src]) or (dst in allowed and src not in allowed[dst])):
            record("plc_decoded" if decoded_industrial else "plc_candidate", row, dynamic_counts, dynamic_samples)


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
            "transport": transport,
            "packets": count,
            "bytes": conv_bytes[(src, dst, sport, dport, proto, transport)],
            "external": is_public_ip(src) or is_public_ip(dst),
        }
        for (src, dst, sport, dport, proto, transport), count in conv.most_common()
    ]

    protocol_rows = [
        {"name": proto, "normalized": normalize_protocol_name(proto), "count": count, "group": "observed"}
        for proto, count in protos.most_common()
    ]

    _write_partial(work_dir, "partial_main_summary.json", {
        "frame_count": frame_count,
        "bytes": total_bytes,
        "duration_human": _dur(duration) if first and last and duration > 0 else "Unknown",
        "top_protocols": protocol_rows[:25],
        "top_endpoints": endpoint_rows[:25],
        "top_conversations": conversation_rows[:25],
    })

    findings = []
    rule_results = []
    expected = metadata_expected_protocols(metadata)

    print("[*]   running rule filters...")
    for idx, (rule, group) in enumerate([(r, "core") for r in CORE_RULES] + [(r, "industrial" if r["category"] == "industrial_protocol" else "infrastructure") for r in INDUSTRIAL_RULES], start=1):
        print(f"[*]     rule {idx}: {rule['id']}")
        if "tokens" in rule:
            count, evidence = decoded_counts[rule["id"]], decoded_samples[rule["id"]]
        else:
            count, evidence = tshark.count_and_evidence(pcap, rule["filter"], max_evidence)

        result = {
            "id": rule["id"],
            "name": rule.get("name", rule["id"]),
            "title": rule["title"],
            "filter": rule["filter"],
            "count": count,
            "group": group,
            "confidence": "dissector-confirmed" if "tokens" in rule else "filter match",
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
            findings.append(_finding(rule, pcap, evidence, _frame_filter(evidence) if "tokens" in rule else rule["filter"], status=status, severity=severity, reason=reason))
            findings[-1]["match_count"] = count

    for key, rule_id, title, reason, recommendation in (
        ("public_ip", "OT-NET-PUBLIC-IP", "Public IP communication observed", "Communication with a globally routable unicast IP was observed.", "Confirm whether this external communication is approved."),
        ("public_dns", "OT-NET-PUBLIC-DNS", "Public DNS resolver used", "A decoded DNS query targeted a public IP.", "Prefer controlled internal resolvers for OT."),
        ("public_ntp", "OT-NET-PUBLIC-NTP", "Public NTP server used", "A decoded NTP client request targeted a public IP.", "Prefer controlled internal time sources for OT."),
    ):
        evidence = dynamic_samples[key]
        if evidence:
            finding = _finding({"id": rule_id, "title": title, "severity": "medium", "category": "external_communication", "reason": reason, "recommendation": recommendation}, pcap, evidence, _frame_filter(evidence), conf="high")
            finding["match_count"] = dynamic_counts[key]
            findings.append(finding)

    vpn_filter = "openvpn || isakmp || esp || udpencap || udp.port == 1194 || udp.port == 500 || udp.port == 4500"
    vpn_count, vpn_evidence = tshark.count_and_evidence(pcap, vpn_filter, max_evidence)
    if vpn_evidence:
        finding = _finding({"id": "OT-NET-VPN-TRAFFIC", "title": "VPN/IPsec/OpenVPN-like traffic observed", "severity": "medium", "category": "remote_access", "reason": "VPN protocol or common VPN port matched.", "recommendation": "Confirm whether this is an approved remote access path."}, pcap, vpn_evidence, vpn_filter, conf="medium")
        finding["match_count"] = vpn_count
        findings.append(finding)

    sensitive = []
    print("[*]   checking sensitive/plaintext indicators...")
    for sr in SENSITIVE_RULES:
        count, rs = tshark.count_and_evidence(pcap, sr["filter"], max_evidence, extra_fields=sr.get("fields", []))
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
            findings.append(_finding(sr, pcap, rs, sr["filter"], status="confirmed_by_rule" if sr["id"] in {"OT-SENSITIVE-FTP-PASS", "OT-SENSITIVE-SNMP-COMMUNITY"} else "candidate", conf="high", owner=True))
            findings[-1]["match_count"] = count

    for key, confidence in (("plc_decoded", "high"), ("plc_candidate", "medium")):
        evidence = dynamic_samples[key]
        if evidence:
            finding = _finding({
                "id": "OT-ICS-UNEXPECTED-PLC-TALKER" if key == "plc_decoded" else "OT-ICS-UNEXPECTED-PLC-TALKER-CANDIDATE",
                "title": "Unexpected host communicating with known PLC/controller" if key == "plc_decoded" else "Possible unexpected PLC/controller communication (port candidate)",
                "severity": "medium", "category": "expected_vs_observed",
                "reason": "Traffic involving a known controller and a host outside its approved talker list was observed. Protocol identity is based on " + ("decoded layers." if key == "plc_decoded" else "a matching transport port only."),
                "recommendation": "Validate host roles and restrict controller communication to approved systems.",
            }, pcap, evidence, _frame_filter(evidence), conf=confidence)
            finding["match_count"] = dynamic_counts[key]
            findings.append(finding)

    quality = {
        "duration_seconds": duration,
        "duration_human": _dur(duration) if first and last and duration > 0 else "Unknown",
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
    if frame_count > 0 and (not first or not last or duration <= 0):
        quality["notes"].append("Packet timestamps are missing or zeroed; time-based analysis is limited.")

    summary = {
        "tool": "ot-pcap-triage",
        "pcap": {
            "file": pcap.name,
            "path": str(pcap),
            "sha256": sha256_file(pcap),
            "first_packet_time": _iso(first) if first is not None else "Timestamp unavailable/zeroed",
            "last_packet_time": _iso(last) if last is not None else "Timestamp unavailable/zeroed",
            "duration_seconds": duration,
            "duration_human": _dur(duration) if first and last and duration > 0 else "Unknown",
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
        "decoded_protocol_layers": [{"name": name, "frames": count} for name, count in decoded_layers.most_common()],
        "rule_results": rule_results,
        "sensitive_hits_redacted": sensitive,
        "findings_count": len(findings),
    }

    _write_partial(work_dir, "partial_findings.json", findings)
    return summary, findings, generate_suggested_metadata(summary), tshark.raw_protocol_hierarchy(pcap)

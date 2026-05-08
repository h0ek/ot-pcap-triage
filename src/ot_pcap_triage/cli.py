from __future__ import annotations

import argparse
import ipaddress
import re
import shutil
import sys
import time
from collections import defaultdict
from datetime import datetime
from importlib.resources import files
from pathlib import Path



from . import __version__
from .analyzer import analyze_pcap
from .metadata import load_metadata
from .reports import render_reports
from .tshark import Tshark, TsharkError
from .utils import is_public_ip


def build_parser():
    p = argparse.ArgumentParser(prog="ot-pcap-triage", description=f"Offline passive OT PCAP triage helper using tshark. Version: {__version__}")
    p.add_argument("pcap", type=Path, nargs="?")
    p.add_argument("--metadata", "-m", type=Path)
    p.add_argument("--output", "-o", type=Path)
    p.add_argument("--max-evidence", type=int, default=10)
    p.add_argument("--tshark-bin", default="tshark")
    p.add_argument("--graph-top-n", type=int, default=18, help="Top N conversations to include in generated communication graphs (default: 18)")
    p.add_argument("--check-deps", action="store_true", help="Only run system dependency checks and exit")
    p.add_argument("--version", action="version", version=f"ot-pcap-triage {__version__}")
    return p


def _safe_output_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_") or "capture"


def _human_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    if size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


def _human_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    if seconds < 3600:
        return f"{seconds / 60:.1f}m"
    return f"{seconds / 3600:.2f}h"


def _metadata_summary(metadata: dict) -> dict:
    if not metadata:
        return {}

    site = metadata.get("site", {}) or {}
    cap = metadata.get("capture_point", {}) or {}
    pcap = metadata.get("pcap", {}) or {}

    return {
        "plant": site.get("plant", "Unknown"),
        "area": site.get("area", "Unknown"),
        "criticality": site.get("criticality", "Unknown"),
        "switch_name": cap.get("switch_name", "Unknown"),
        "mirror_source": cap.get("mirror_source", "Unknown"),
        "mirror_source_type": cap.get("mirror_source_type", "Unknown"),
        "mirror_direction": cap.get("mirror_direction", "Unknown"),
        "normal_production": pcap.get("normal_production", "Unknown"),
        "special_activity": pcap.get("special_activity_during_capture", "Unknown"),
    }


def _preflight_output_dir(out: Path):
    try:
        if str(out).startswith("/output"):
            return False, (
                f"Refusing to write to absolute path: {out}\n"
                "    Use a relative path like: -o output/test1\n"
                "    Or omit -o to use output/<pcap>-<timestamp>."
            )

        out.mkdir(parents=True, exist_ok=True)
        test_file = out / ".ot_pcap_triage_write_test"
        test_file.write_text("ok\n", encoding="utf-8")
        test_file.unlink(missing_ok=True)
        return True, ""
    except PermissionError:
        return False, f"Permission denied for output directory: {out}"
    except Exception as exc:
        return False, f"Cannot prepare output directory {out}: {exc}"



def _load_packaged_yaml(filename: str) -> dict:
    """Load YAML bundled inside the ot_pcap_triage package.

    Required for PyPI/pipx installs where current working directory is not
    the repository root.
    """
    try:
        import yaml
        resource = files("ot_pcap_triage").joinpath(filename)
        if resource.is_file():
            return yaml.safe_load(resource.read_text(encoding="utf-8")) or {}
    except Exception:
        pass
    return {}

def _load_protocol_catalog(root: Path) -> dict:
    try:
        import yaml
    except Exception:
        return {}

    candidates = [
        root / "protocol_catalog.yml",
        root / "src" / "ot_pcap_triage" / "protocol_catalog.yml",
    ]

    for path in candidates:
        if path.exists():
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            return data.get("protocols", {}) if isinstance(data, dict) else {}

    data = _load_packaged_yaml("protocol_catalog.yml")
    return data.get("protocols", {}) if isinstance(data, dict) else {}

def _parse_catalog_ports(protocol_data: dict) -> list[tuple[str, str]]:
    out = []
    for port in protocol_data.get("ports", []) or []:
        value = str(port).strip().lower()
        if "/" not in value:
            continue
        number, transport = value.split("/", 1)
        out.append((number.strip(), transport.strip()))
    return out


def _derive_extended_protocol_candidates(summary: dict, catalog: dict) -> list[dict]:
    if not catalog:
        return []

    rows = []
    conversations = summary.get("conversations", [])

    for proto_id, proto_data in catalog.items():
        ports = _parse_catalog_ports(proto_data)
        if not ports:
            continue

        for number, transport in ports:
            packets = 0
            bytes_ = 0
            src_hosts = set()
            dst_hosts = set()

            for conv in conversations:
                src_port = str(conv.get("src_port", ""))
                dst_port = str(conv.get("dst_port", ""))

                if src_port != number and dst_port != number:
                    continue

                packets += int(conv.get("packets") or 0)
                bytes_ += int(conv.get("bytes") or 0)
                if conv.get("src_ip"):
                    src_hosts.add(conv.get("src_ip"))
                if conv.get("dst_ip"):
                    dst_hosts.add(conv.get("dst_ip"))

            if packets <= 0:
                continue

            confidence = proto_data.get("confidence", "low")
            if packets < 5:
                confidence = "low"

            rows.append({
                "id": proto_id,
                "name": proto_data.get("name", proto_id),
                "category": proto_data.get("category", "unknown"),
                "port": f"{number}/{transport}",
                "packets": packets,
                "bytes": bytes_,
                "src_host_count": len(src_hosts),
                "dst_host_count": len(dst_hosts),
                "sample_sources": ", ".join(sorted(src_hosts)[:5]),
                "sample_destinations": ", ".join(sorted(dst_hosts)[:5]),
                "confidence": f"{confidence} port-based candidate",
                "note": proto_data.get("note", ""),
                "source": "protocol_catalog.yml",
            })

    rows.sort(key=lambda item: item["packets"], reverse=True)
    return rows[:50]

def _derive_observed_industrial_protocols(summary: dict) -> list[dict]:
    rows = []
    for rule in summary.get("rule_results", []):
        if rule.get("group") != "industrial":
            continue
        count = int(rule.get("count") or 0)
        if count <= 0:
            continue

        flt = rule.get("filter", "")
        if "tcp.port" in flt or "udp.port" in flt:
            confidence = "port-based candidate"
        else:
            confidence = "dissector-confirmed"

        if count >= 100:
            volume = "high"
        elif count >= 10:
            volume = "medium"
        else:
            volume = "low"

        rows.append({
            "id": rule.get("id", ""),
            "title": rule.get("title", ""),
            "count": count,
            "filter": flt,
            "confidence": confidence,
            "volume": volume,
        })

    rows.sort(key=lambda r: r["count"], reverse=True)
    return rows


def _derive_top_risky_observations(findings: list[dict]) -> list[dict]:
    severity_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    interesting = []
    for finding in findings:
        severity = finding.get("severity", "info")
        if severity == "info":
            continue
        interesting.append({
            "id": finding.get("id", ""),
            "title": finding.get("title", ""),
            "severity": severity,
            "confidence": finding.get("confidence", ""),
            "status": finding.get("status", ""),
            "reason": finding.get("reason", ""),
            "evidence_count": len(finding.get("evidence", []) or []),
        })

    interesting.sort(key=lambda item: (severity_rank.get(item["severity"], 0), item["confidence"]), reverse=True)
    return interesting[:15]


def _top_s7_matrix(summary: dict) -> list[dict]:
    pairs = {}
    for conv in summary.get("conversations", []):
        if conv.get("protocol") != "S7/COTP":
            continue
        src = conv.get("src_ip", "")
        dst = conv.get("dst_ip", "")
        dst_port = str(conv.get("dst_port", ""))
        src_port = str(conv.get("src_port", ""))

        if dst_port == "102":
            plc = dst
            client = src
        elif src_port == "102":
            plc = src
            client = dst
        else:
            continue

        key = (client, plc)
        pairs.setdefault(key, {"client": client, "plc": plc, "packets": 0, "bytes": 0})
        pairs[key]["packets"] += int(conv.get("packets") or 0)
        pairs[key]["bytes"] += int(conv.get("bytes") or 0)

    rows = list(pairs.values())
    rows.sort(key=lambda item: item["packets"], reverse=True)
    return rows[:10]


def _is_private_or_internal(ip_s: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_s)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except Exception:
        return False


def _ip_prefix(ip_s: str) -> str:
    try:
        ip = ipaddress.ip_address(ip_s)
        if ip.version == 4:
            parts = ip_s.split(".")
            return ".".join(parts[:3]) + ".0/24"
    except Exception:
        pass
    return "unknown"


def _derive_passive_asset_inventory(summary: dict) -> list[dict]:
    roles = defaultdict(set)
    reasons = defaultdict(list)
    peers = defaultdict(set)

    for endpoint in summary.get("endpoints", []):
        ip = endpoint.get("ip", "")
        if endpoint.get("public"):
            roles[ip].add("public/external host")
            reasons[ip].append("public IP observed")
        if "DNS:" in endpoint.get("top_protocols", ""):
            roles[ip].add("DNS participant")
        if "NTP:" in endpoint.get("top_protocols", ""):
            roles[ip].add("NTP participant")

    for conv in summary.get("conversations", []):
        src = conv.get("src_ip", "")
        dst = conv.get("dst_ip", "")
        proto = conv.get("protocol", "")
        sp = str(conv.get("src_port", ""))
        dp = str(conv.get("dst_port", ""))
        peers[src].add(dst)
        peers[dst].add(src)

        if dp == "53":
            roles[dst].add("possible DNS server")
            roles[src].add("DNS client")
        if sp == "53":
            roles[src].add("possible DNS server")
        if dp == "123":
            roles[dst].add("possible NTP server")
            roles[src].add("NTP client")
        if sp == "123":
            roles[src].add("possible NTP server")

        if dp == "102" or proto == "S7/COTP":
            if dp == "102":
                roles[dst].add("possible Siemens S7 PLC/controller")
                roles[src].add("possible S7 client / HMI / engineering")
                reasons[dst].append("S7/COTP service on TCP/102")
                reasons[src].append("initiates S7/COTP communication")
            elif sp == "102":
                roles[src].add("possible Siemens S7 PLC/controller")
                roles[dst].add("possible S7 client / HMI / engineering")

        if dp == "502" or proto == "Modbus":
            if dp == "502":
                roles[dst].add("possible Modbus device/gateway")
                roles[src].add("possible Modbus client / SCADA / engineering")
                reasons[dst].append("Modbus service on TCP/502")
            elif sp == "502":
                roles[src].add("possible Modbus device/gateway")

        if dp in {"44818", "2222"} or proto == "EtherNet/IP":
            roles[dst].add("possible EtherNet/IP device")
            roles[src].add("possible EtherNet/IP scanner/client")

        if dp == "20000" or proto == "DNP3":
            roles[dst].add("possible DNP3 outstation/device")
            roles[src].add("possible DNP3 master/client")

        if dp == "4840" or proto == "OPC UA":
            roles[dst].add("possible OPC UA server")
            roles[src].add("possible OPC UA client")

        if dp in {"21", "22", "23", "80", "443", "3389", "5900"} or proto in {"FTP", "SSH", "TELNET", "HTTP", "TLS", "RDP", "VNC"}:
            roles[dst].add("management/service endpoint")
            roles[src].add("management/admin client")

        if dp in {"1194", "500", "4500"} or proto in {"OPENVPN", "ISAKMP", "ESP", "IPsec/UDP-encap"}:
            roles[src].add("VPN/remote-access participant")
            roles[dst].add("VPN/remote-access participant")

    rows = []
    endpoint_by_ip = {e.get("ip"): e for e in summary.get("endpoints", [])}
    for ip, endpoint in endpoint_by_ip.items():
        if not ip:
            continue
        role_list = sorted(roles.get(ip, {"unknown"}))
        rows.append({
            "ip": ip,
            "macs": endpoint.get("macs", ""),
            "packets": endpoint.get("packets", 0),
            "bytes": endpoint.get("bytes", 0),
            "public": endpoint.get("public", False),
            "roles": ", ".join(role_list),
            "subnet_hint": _ip_prefix(ip),
            "top_protocols": endpoint.get("top_protocols", ""),
            "peer_count": len(peers.get(ip, set())),
            "reason": "; ".join(sorted(set(reasons.get(ip, []))))[:300],
        })

    rows.sort(key=lambda r: int(r.get("bytes") or 0), reverse=True)
    return rows[:50]


def _derive_cleartext_management_surface(summary: dict, findings: list[dict]) -> list[dict]:
    protocols = {"TELNET", "FTP", "HTTP", "TFTP", "SNMP", "NBDGM/Browser"}
    service_ports = {"21", "23", "69", "80", "161", "514"}
    surface = {}

    for conv in summary.get("conversations", []):
        proto = conv.get("protocol", "")
        src = conv.get("src_ip", "")
        dst = conv.get("dst_ip", "")
        sp = str(conv.get("src_port", ""))
        dp = str(conv.get("dst_port", ""))

        if proto not in protocols and dp not in service_ports and sp not in service_ports:
            continue

        service_host = dst if dp in service_ports else src
        key = (service_host, proto if proto != "UNKNOWN" else f"port-{dp or sp}")
        surface.setdefault(key, {
            "host": service_host,
            "protocol": key[1],
            "packets": 0,
            "bytes": 0,
            "clients": set(),
            "risk": "review",
        })
        surface[key]["packets"] += int(conv.get("packets") or 0)
        surface[key]["bytes"] += int(conv.get("bytes") or 0)
        if src != service_host:
            surface[key]["clients"].add(src)
        if dst != service_host:
            surface[key]["clients"].add(dst)

    rows = []
    for item in surface.values():
        proto = item["protocol"]
        if proto in {"TELNET", "FTP", "TFTP", "port-23", "port-21", "port-69", "port-514"}:
            risk = "high"
        elif proto in {"HTTP", "SNMP", "port-80", "port-161"}:
            risk = "medium"
        else:
            risk = "review"
        rows.append({
            "host": item["host"],
            "protocol": proto,
            "packets": item["packets"],
            "bytes": item["bytes"],
            "client_count": len(item["clients"]),
            "clients": ", ".join(sorted(item["clients"]))[:300],
            "risk": risk,
        })

    rows.sort(key=lambda r: (r["risk"] != "high", -r["packets"]))
    return rows[:30]


def _derive_convergence_indicators(summary: dict, findings: list[dict]) -> list[dict]:
    indicators = []

    subnets = defaultdict(int)
    for endpoint in summary.get("endpoints", []):
        ip = endpoint.get("ip", "")
        if _is_private_or_internal(ip):
            subnets[_ip_prefix(ip)] += int(endpoint.get("packets") or 0)

    if len(subnets) >= 3:
        indicators.append({
            "indicator": "Multiple private/internal subnets observed in one capture",
            "evidence": ", ".join(f"{k} ({v} packets)" for k, v in sorted(subnets.items())[:10]),
            "risk": "review segmentation and capture point scope",
        })

    for finding in findings:
        fid = finding.get("id", "")
        if fid in {"OT-NET-PUBLIC-IP", "OT-NET-PUBLIC-DNS", "OT-NET-PUBLIC-NTP", "OT-NET-VPN-TRAFFIC"}:
            indicators.append({
                "indicator": finding.get("title", fid),
                "evidence": finding.get("reason", ""),
                "risk": "review IT/OT boundary and approved external paths",
            })

    industrial_hosts = set()
    client_hosts = set()
    for conv in summary.get("conversations", []):
        proto = conv.get("protocol", "")
        sp = str(conv.get("src_port", ""))
        dp = str(conv.get("dst_port", ""))
        if proto in {"S7/COTP", "Modbus", "DNP3", "OPC UA", "EtherNet/IP"} or dp in {"102", "502", "20000", "4840", "44818"}:
            industrial_hosts.add(conv.get("dst_ip", ""))
            client_hosts.add(conv.get("src_ip", ""))

    cross = []
    for client in client_hosts:
        for device in industrial_hosts:
            if client and device and _ip_prefix(client) != _ip_prefix(device):
                cross.append(f"{client} -> {device}")
                if len(cross) >= 5:
                    break
        if len(cross) >= 5:
            break

    if cross:
        indicators.append({
            "indicator": "Cross-subnet industrial communication observed",
            "evidence": "; ".join(cross),
            "risk": "validate routing/segmentation and allowed industrial talkers",
        })

    return indicators[:20]


def _derive_engineering_candidates(summary: dict) -> list[dict]:
    stats = defaultdict(lambda: {"industrial_targets": set(), "protocols": set(), "packets": 0, "mgmt_protocols": set()})
    industrial_ports = {"102", "502", "20000", "4840", "44818", "2222", "2404", "9600", "48898", "18245", "5094"}
    industrial_protocols = {"S7/COTP", "Modbus", "DNP3", "OPC UA", "EtherNet/IP", "IEC104", "FINS"}
    mgmt_protocols = {"HTTP", "TLS", "SSH", "TELNET", "FTP", "SMB", "RDP", "VNC"}

    for conv in summary.get("conversations", []):
        src = conv.get("src_ip", "")
        dst = conv.get("dst_ip", "")
        proto = conv.get("protocol", "")
        dp = str(conv.get("dst_port", ""))
        packets = int(conv.get("packets") or 0)

        if dp in industrial_ports or proto in industrial_protocols:
            stats[src]["industrial_targets"].add(dst)
            stats[src]["protocols"].add(proto)
            stats[src]["packets"] += packets

        if proto in mgmt_protocols:
            stats[src]["mgmt_protocols"].add(proto)

    rows = []
    for host, item in stats.items():
        target_count = len(item["industrial_targets"])
        if target_count == 0:
            continue
        score = target_count
        if item["mgmt_protocols"]:
            score += 2
        if item["packets"] > 1000:
            score += 1

        if score < 2:
            continue

        rows.append({
            "host": host,
            "industrial_target_count": target_count,
            "industrial_targets": ", ".join(sorted(item["industrial_targets"]))[:300],
            "industrial_protocols": ", ".join(sorted(item["protocols"])),
            "management_protocols": ", ".join(sorted(item["mgmt_protocols"])),
            "packets": item["packets"],
            "assessment": "possible engineering / scanner / HMI / SCADA client",
            "confidence": "medium" if score >= 4 else "low",
        })

    rows.sort(key=lambda r: (r["industrial_target_count"], r["packets"]), reverse=True)
    return rows[:20]


def _derive_analyst_questions(summary: dict, findings: list[dict]) -> list[str]:
    ids = {f.get("id") for f in findings}
    questions = []

    if "OT-NET-PUBLIC-DNS" in ids:
        questions.append("Is public DNS approved in this OT segment, or should OT assets use only internal DNS resolvers?")
    if "OT-NET-PUBLIC-NTP" in ids:
        questions.append("Is public NTP approved, or should OT assets use controlled internal time sources?")
    if "OT-NET-VPN-TRAFFIC" in ids:
        questions.append("Is this VPN/IPsec/OpenVPN-like traffic an approved remote access path, and is it logged/controlled?")
    if "OT-NET-PUBLIC-IP" in ids:
        questions.append("Which OT assets are allowed to communicate with public IP addresses, and through which approved path?")
    if "OT-NET-PLAINTEXT" in ids or "OT-SENSITIVE-TELNET" in ids or "OT-NET-RSH" in ids:
        questions.append("Are Telnet/FTP/TFTP/RSH protocols still required, and can they be restricted or replaced with encrypted alternatives?")
    if "OT-SENSITIVE-FTP-PASS" in ids:
        questions.append("Were real FTP credentials exposed in the capture, and do they need rotation?")
    if "OT-SENSITIVE-SNMP-COMMUNITY" in ids:
        questions.append("Which SNMP version and community strings are used, and can SNMPv3 be enforced?")
    if "OT-SENSITIVE-HTTP-AUTH" in ids:
        questions.append("Are HTTP authentication/cookie/form submissions expected, and can management interfaces be moved to HTTPS?")

    rule_counts = {r.get("id"): int(r.get("count") or 0) for r in summary.get("rule_results", [])}
    if rule_counts.get("OT-NET-TCP-SYN", 0) > 1000 or rule_counts.get("OT-NET-TCP-RESET", 0) > 1000:
        questions.append("Is the high TCP SYN/RESET volume expected, or does it indicate scanning, unstable services or failed connection attempts?")

    industrial = _derive_observed_industrial_protocols(summary)
    if industrial:
        protocols = ", ".join(row["title"].replace(" observed", "") for row in industrial[:5])
        questions.append(f"Are the observed industrial protocols expected in this capture point: {protocols}?")

    s7_pairs = _top_s7_matrix(summary)
    if s7_pairs:
        examples = "; ".join(f"{row['client']} -> {row['plc']}" for row in s7_pairs[:3])
        questions.append(f"Are these S7 client-to-PLC communication paths expected: {examples}?")

    engineering = summary.get("engineering_candidates", [])
    if engineering:
        examples = "; ".join(f"{row['host']} ({row['industrial_target_count']} targets)" for row in engineering[:3])
        questions.append(f"Do these hosts represent approved HMI/SCADA/engineering/scanner systems: {examples}?")

    convergence = summary.get("convergence_indicators", [])
    if convergence:
        questions.append("Do the convergence indicators match the intended segmentation model and approved IT/OT communication paths?")

    return questions



def _derive_nist_review_context(summary: dict, findings: list[dict]) -> list[dict]:
    """Map observed findings/sections to NIST SP 800-82r3 review themes.

    This is context for the analyst, not a compliance assertion.
    """
    contexts = []

    def add(key: str, title: str, themes: list[str], why: str, related: list[str]) -> None:
        existing = {item["key"] for item in contexts}
        if key in existing:
            return
        contexts.append({
            "key": key,
            "source": "NIST SP 800-82r3",
            "title": title,
            "themes": ", ".join(themes),
            "why_it_matters": why,
            "related_observations": ", ".join(sorted(set(related))),
            "note": "Review context only; not a compliance certification.",
        })

    finding_ids = {f.get("id", "") for f in findings}
    finding_categories = {f.get("category", "") for f in findings}

    if {"OT-NET-PUBLIC-IP", "OT-NET-PUBLIC-DNS", "OT-NET-PUBLIC-NTP"} & finding_ids:
        add(
            "external_communication",
            "Restrict logical access and external connectivity",
            ["Network segmentation", "Boundary protection", "DMZ / firewall architecture", "Approved external communication paths"],
            "OT assets should not communicate directly with external networks unless the path is approved, controlled, monitored, and segmented.",
            [fid for fid in finding_ids if fid in {"OT-NET-PUBLIC-IP", "OT-NET-PUBLIC-DNS", "OT-NET-PUBLIC-NTP"}],
        )

    if {"OT-NET-PUBLIC-DNS", "OT-NET-PUBLIC-NTP"} & finding_ids:
        add(
            "public_dns_ntp",
            "Use controlled infrastructure services",
            ["Time synchronization", "Name resolution", "Boundary protection", "Monitoring"],
            "Public DNS/NTP from OT may indicate weak segmentation or unmanaged dependencies. OT environments should normally use approved internal infrastructure services.",
            [fid for fid in finding_ids if fid in {"OT-NET-PUBLIC-DNS", "OT-NET-PUBLIC-NTP"}],
        )

    if "OT-NET-VPN-TRAFFIC" in finding_ids:
        add(
            "remote_access",
            "Control and monitor remote access",
            ["Remote access", "MFA", "Jump hosts / approved paths", "Logging and monitoring"],
            "Remote access paths into OT should be explicit, restricted, authenticated, logged, and approved by OT/network owners.",
            ["OT-NET-VPN-TRAFFIC"],
        )

    plaintext_ids = {
        "OT-NET-PLAINTEXT",
        "OT-NET-RSH",
        "OT-NET-HTTP",
        "OT-SENSITIVE-FTP-PASS",
        "OT-SENSITIVE-HTTP-AUTH",
        "OT-SENSITIVE-TELNET",
        "OT-SENSITIVE-SNMP-COMMUNITY",
    }
    if plaintext_ids & finding_ids:
        add(
            "plaintext_protocols",
            "Avoid or tightly restrict plaintext protocols",
            ["Secure protocols", "Credential protection", "Data in transit", "Disable unused services"],
            "Plaintext protocols can expose credentials, management sessions, operational data, or configuration details to anyone with network visibility.",
            [fid for fid in finding_ids if fid in plaintext_ids],
        )

    anomaly_ids = {"OT-NET-TCP-SYN", "OT-NET-TCP-RESET", "OT-NET-ICMP-UNREACHABLE", "OT-NET-TCP-QUALITY", "OT-NET-DISCOVERY"}
    if anomaly_ids & finding_ids:
        add(
            "monitoring_anomalies",
            "Detect events and anomalous activity",
            ["Security continuous monitoring", "Anomalies and events", "Logging", "Incident detection"],
            "Connection failures, resets, unreachable traffic, unusual bursts, and scan-like behavior should be reviewed against expected OT communication patterns.",
            [fid for fid in finding_ids if fid in anomaly_ids],
        )

    industrial = summary.get("observed_industrial_protocols", []) or []
    if industrial:
        add(
            "industrial_protocols",
            "Validate OT protocol security and expected communication",
            ["OT protocol security", "Authentication and integrity", "Allowed talkers", "Segmentation", "Engineering access control"],
            "Many OT protocols require compensating controls such as segmentation, allowlists, monitoring, and strict control of engineering access.",
            [item.get("id", "") for item in industrial if item.get("id")],
        )

    if summary.get("passive_asset_inventory"):
        add(
            "asset_inventory",
            "Maintain and validate OT asset inventory",
            ["Asset management", "Passive discovery", "Expected architecture", "Risk-based assessment"],
            "Passive inventory is useful for discovery, but inferred roles must be validated against the authoritative OT asset inventory.",
            ["Passive Asset Inventory"],
        )

    if summary.get("convergence_indicators"):
        add(
            "convergence",
            "Review IT/OT convergence and segmentation",
            ["Defense-in-depth", "Layered network architecture", "Corporate/OT separation", "DMZ and boundary controls"],
            "Multiple subnets, direct client-to-controller paths, and external dependencies may indicate convergence points that need architectural validation.",
            ["IT/OT Convergence Indicators"],
        )

    return contexts


def _load_mitre_ics_context(root: Path) -> dict:
    try:
        import yaml
    except Exception:
        return {}

    candidates = [
        root / "mitre_ics_context.yml",
        root / "src" / "ot_pcap_triage" / "mitre_ics_context.yml",
    ]

    for path in candidates:
        if path.exists():
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            return data.get("mappings", {}) if isinstance(data, dict) else {}

    data = _load_packaged_yaml("mitre_ics_context.yml")
    return data.get("mappings", {}) if isinstance(data, dict) else {}

def _derive_mitre_ics_context(summary: dict, findings: list[dict], mitre_map: dict | None = None) -> list[dict]:
    """Map observed findings/sections to MITRE ATT&CK for ICS context.

    This is context only. It is not proof of adversary activity.
    """
    mitre_map = mitre_map or {}
    if not mitre_map:
        return []

    finding_ids = {finding.get("id", "") for finding in findings}
    contexts = []

    def section_has_data(section_name: str) -> bool:
        value = summary.get(section_name)
        if isinstance(value, list):
            return len(value) > 0
        if isinstance(value, dict):
            return len(value) > 0
        return bool(value)

    for key, mapping in mitre_map.items():
        matched = []

        for obs_id in mapping.get("observation_ids", []) or []:
            if obs_id in finding_ids:
                matched.append(obs_id)

        for section in mapping.get("observation_sections", []) or []:
            if section_has_data(section):
                matched.append(section)

        if not matched:
            continue

        techniques = []
        for technique in mapping.get("techniques", []) or []:
            techniques.append({
                "id": technique.get("id", ""),
                "name": technique.get("name", ""),
                "tactic": technique.get("tactic", ""),
                "url": technique.get("url", ""),
            })

        contexts.append({
            "key": key,
            "title": mapping.get("title", key),
            "matched_observations": ", ".join(sorted(set(matched))),
            "techniques": techniques,
            "technique_summary": "; ".join(
                f"{tech.get('id', '')} {tech.get('name', '')} ({tech.get('tactic', '')})".strip()
                for tech in techniques
            ),
            "confidence": mapping.get("confidence", "contextual"),
            "note": mapping.get("note", "Contextual mapping only; not proof of adversary activity."),
            "source": "MITRE ATT&CK for ICS",
        })

    return contexts

def _timeline_bucket_seconds(summary: dict) -> int:
    pcap = (summary or {}).get("pcap", {}) or {}
    duration = float(pcap.get("duration_seconds") or 0)
    return 60 if duration <= 7200 else 300


def _timeline_bucket_human(seconds: int) -> str:
    return "1 minute" if seconds == 60 else f"{int(seconds // 60)} minutes"


def _timeline_group_from_row(row: dict) -> str:
    proto = str(row.get("_ws.col.Protocol") or "").strip().lower()
    frame_protocols = str(row.get("frame.protocols") or "").strip().lower()
    combined = f"{proto}:{frame_protocols}"

    ports = {
        str(v).strip()
        for v in (
            row.get("tcp.srcport"), row.get("tcp.dstport"),
            row.get("udp.srcport"), row.get("udp.dstport"),
        )
        if str(v or "").strip()
    }

    if any(token in combined for token in ("s7", "cotp", "s7comm")) or "102" in ports:
        return "S7/COTP"
    if any(token in combined for token in ("modbus", "mbtcp")) or "502" in ports:
        return "Modbus"
    if any(token in combined for token in ("enip", "cip", "ethernet/ip")) or ports & {"44818", "2222"}:
        return "EtherNet/IP"
    if "bacnet" in combined or "47808" in ports:
        return "BACnet"
    if "opcua" in combined or "4840" in ports:
        return "OPC UA"
    if "dnp3" in combined or "20000" in ports:
        return "DNP3"
    if "http" in combined or ports & {"80", "8080", "8000", "8008"}:
        return "HTTP"
    if any(token in combined for token in ("smb", "nbss", "nbdgm", "nbns")) or ports & {"137", "138", "139", "445"}:
        return "SMB/NetBIOS"
    if "dns" in combined or "53" in ports:
        return "DNS"
    if "ntp" in combined or "123" in ports:
        return "NTP"
    if any(token in combined for token in ("icmp", "icmpv6", "arp")):
        return "ICMP/ARP"
    if any(token in combined for token in ("openvpn", "isakmp", "esp", "udpencap")) or ports & {"1194", "500", "4500"}:
        return "VPN"
    if any(token in combined for token in ("llmnr", "mdns", "ssdp", "ws-discovery")) or ports & {"3702", "5355", "5353", "1900"}:
        return "Discovery"
    return "Other"

def _derive_traffic_timeline(pcap: Path, tshark, summary: dict) -> dict:
    from datetime import datetime, timezone
    import math

    fields = [
        "frame.time_epoch",
        "_ws.col.Protocol",
        "frame.protocols",
        "tcp.srcport",
        "tcp.dstport",
        "udp.srcport",
        "udp.dstport",
    ]

    if hasattr(tshark, "iter_fields"):
        row_iter = tshark.iter_fields(pcap, fields)
    else:
        row_iter = tshark.fields(pcap, fields)

    parsed_rows = []
    valid_epochs = []

    for index, row in enumerate(row_iter):
        raw_epoch = row.get("frame.time_epoch")
        epoch = None
        try:
            candidate = float(raw_epoch)
            if candidate > 0:
                epoch = candidate
                valid_epochs.append(candidate)
        except (TypeError, ValueError):
            pass
        parsed_rows.append((index, epoch, row))

    if not parsed_rows:
        return {}

    groups = [
        "S7/COTP",
        "Modbus",
        "EtherNet/IP",
        "BACnet",
        "OPC UA",
        "DNP3",
        "HTTP",
        "SMB/NetBIOS",
        "DNS",
        "NTP",
        "ICMP/ARP",
        "VPN",
        "Discovery",
        "Other",
    ]

    if valid_epochs:
        first = min(valid_epochs)
        last = max(valid_epochs)
        bucket_seconds = _timeline_bucket_seconds(summary)
        bucket_count = max(1, int((last - first) // bucket_seconds) + 1)
        series = {group: [0] * bucket_count for group in groups}

        for _index, epoch, row in parsed_rows:
            if epoch is None:
                continue
            idx = int((epoch - first) // bucket_seconds)
            if idx < 0:
                idx = 0
            elif idx >= bucket_count:
                idx = bucket_count - 1
            series[_timeline_group_from_row(row)][idx] += 1

        labels = []
        for idx in range(bucket_count):
            ts = datetime.fromtimestamp(first + idx * bucket_seconds, tz=timezone.utc)
            labels.append(ts.strftime("%Y-%m-%d %H:%M"))

        mode = "time"
        bucket_human = _timeline_bucket_human(bucket_seconds)
        start_time = datetime.fromtimestamp(first, tz=timezone.utc).isoformat()
        end_time = datetime.fromtimestamp(last, tz=timezone.utc).isoformat()

    else:
        packet_count = len(parsed_rows)
        bucket_count = min(60, max(1, packet_count))
        packets_per_bucket = max(1, math.ceil(packet_count / bucket_count))
        series = {group: [0] * bucket_count for group in groups}

        for index, _epoch, row in parsed_rows:
            idx = min(bucket_count - 1, index // packets_per_bucket)
            series[_timeline_group_from_row(row)][idx] += 1

        labels = [f"Packet bucket {idx + 1}" for idx in range(bucket_count)]
        mode = "packet_order"
        bucket_human = f"{packets_per_bucket} packets"
        start_time = "Timestamp unavailable/zeroed"
        end_time = "Timestamp unavailable/zeroed"

    totals = {group: sum(values) for group, values in series.items()}
    dominant = max(totals, key=totals.get) if totals else "n/a"
    bucket_totals = [sum(series[group][idx] for group in groups) for idx in range(len(labels))]
    nonzero_bucket_totals = [value for value in bucket_totals if value > 0]
    avg = (sum(nonzero_bucket_totals) / len(nonzero_bucket_totals)) if nonzero_bucket_totals else 0.0
    peak = max(nonzero_bucket_totals) if nonzero_bucket_totals else 0
    bursts_detected = bool(nonzero_bucket_totals and peak >= max(50, avg * 3.0))

    return {
        "mode": mode,
        "bucket_seconds": bucket_seconds if valid_epochs else None,
        "bucket_human": bucket_human,
        "labels": labels,
        "series": series,
        "groups": groups,
        "start_time": start_time,
        "end_time": end_time,
        "dominant_protocol": dominant,
        "bursts_detected": bursts_detected,
        "peak_bucket_packets": peak,
        "bucket_count": len(labels),
        "total_packets": sum(bucket_totals),
    }

def _derive_dns_summary(summary: dict) -> dict:
    rows = []
    server_stats = {}
    for conv in summary.get("conversations", []):
        if conv.get("protocol") != "DNS":
            continue

        src = conv.get("src_ip", "")
        dst = conv.get("dst_ip", "")
        src_port = str(conv.get("src_port", ""))
        dst_port = str(conv.get("dst_port", ""))
        packets = int(conv.get("packets") or 0)
        bytes_ = int(conv.get("bytes") or 0)

        if dst_port == "53":
            server = dst
            client = src
        elif src_port == "53":
            server = src
            client = dst
        else:
            server = dst
            client = src

        if not server:
            continue

        stats = server_stats.setdefault(
            server,
            {
                "server": server,
                "packets": 0,
                "bytes": 0,
                "clients": set(),
                "public": is_public_ip(server),
            },
        )
        stats["packets"] += packets
        stats["bytes"] += bytes_
        if client:
            stats["clients"].add(client)

    for server, stats in server_stats.items():
        rows.append(
            {
                "server": server,
                "public": stats["public"],
                "client_count": len(stats["clients"]),
                "clients": ", ".join(sorted(stats["clients"])[:8]),
                "packets": stats["packets"],
                "bytes": stats["bytes"],
                "assessment": "public resolver review" if stats["public"] else "internal/unknown resolver",
            }
        )

    rows.sort(key=lambda item: (item["public"], item["packets"]), reverse=True)
    return {
        "servers": rows[:25],
        "public_server_count": sum(1 for row in rows if row["public"]),
        "server_count": len(rows),
    }


def _derive_top_services(summary: dict) -> list[dict]:
    services = {}
    for conv in summary.get("conversations", []):
        dst_ip = conv.get("dst_ip", "")
        dst_port = str(conv.get("dst_port", ""))
        protocol = conv.get("protocol", "") or "UNKNOWN"
        if not dst_ip or not dst_port:
            continue

        key = (dst_ip, dst_port, protocol)
        item = services.setdefault(
            key,
            {
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": protocol,
                "packets": 0,
                "bytes": 0,
                "clients": set(),
                "public": is_public_ip(dst_ip),
            },
        )
        item["packets"] += int(conv.get("packets") or 0)
        item["bytes"] += int(conv.get("bytes") or 0)
        if conv.get("src_ip"):
            item["clients"].add(conv.get("src_ip"))

    rows = []
    for item in services.values():
        dst_port = item["dst_port"]
        proto = item["protocol"]
        review = "review"
        if item["public"]:
            review = "public service path"
        elif dst_port in {"102", "502", "44818", "2222", "20000", "4840", "2404"}:
            review = "industrial service"
        elif dst_port in {"21", "23", "80", "161", "514"}:
            review = "cleartext/legacy management candidate"
        elif dst_port in {"22", "443", "3389", "5900"}:
            review = "remote/admin service candidate"
        elif proto == "DNS" or dst_port == "53":
            review = "DNS service"
        elif proto == "NTP" or dst_port == "123":
            review = "NTP service"

        rows.append(
            {
                "dst_ip": item["dst_ip"],
                "dst_port": dst_port,
                "protocol": proto,
                "packets": item["packets"],
                "bytes": item["bytes"],
                "client_count": len(item["clients"]),
                "clients": ", ".join(sorted(item["clients"])[:8]),
                "public": item["public"],
                "review": review,
            }
        )

    rows.sort(key=lambda item: item["packets"], reverse=True)
    return rows[:50]


def _derive_top_unknown_conversations(summary: dict) -> list[dict]:
    rows = []
    for conv in summary.get("conversations", []):
        proto = str(conv.get("protocol") or "")
        if proto.upper() not in {"UNKNOWN", "OTHER"}:
            continue

        packets = int(conv.get("packets") or 0)
        if packets <= 0:
            continue

        rows.append(
            {
                "src_ip": conv.get("src_ip", ""),
                "src_port": conv.get("src_port", ""),
                "dst_ip": conv.get("dst_ip", ""),
                "dst_port": conv.get("dst_port", ""),
                "packets": packets,
                "bytes": int(conv.get("bytes") or 0),
                "external": bool(conv.get("external")),
                "review_hint": "public/unknown protocol" if conv.get("external") else "unknown internal protocol or undecoded application",
            }
        )

    rows.sort(key=lambda item: item["packets"], reverse=True)
    return rows[:50]

def _enrich_summary(summary: dict, findings: list[dict], catalog: dict | None = None, mitre_map: dict | None = None) -> None:
    summary["observed_industrial_protocols"] = _derive_observed_industrial_protocols(summary)
    summary["extended_protocol_candidates"] = _derive_extended_protocol_candidates(summary, catalog or {})
    summary["top_risky_observations"] = _derive_top_risky_observations(findings)
    summary["top_s7_communications"] = _top_s7_matrix(summary)
    summary["passive_asset_inventory"] = _derive_passive_asset_inventory(summary)
    summary["cleartext_management_surface"] = _derive_cleartext_management_surface(summary, findings)
    summary["convergence_indicators"] = _derive_convergence_indicators(summary, findings)
    summary["engineering_candidates"] = _derive_engineering_candidates(summary)
    summary["analyst_questions"] = _derive_analyst_questions(summary, findings)
    summary["nist_review_context"] = _derive_nist_review_context(summary, findings)
    summary["mitre_ics_context"] = _derive_mitre_ics_context(summary, findings, mitre_map or {})
    summary["dns_summary"] = _derive_dns_summary(summary)
    summary["top_services"] = _derive_top_services(summary)
    summary["top_unknown_conversations"] = _derive_top_unknown_conversations(summary)



def _detect_linux_family() -> str:
    try:
        os_release = Path("/etc/os-release")
        if os_release.exists():
            data = os_release.read_text(encoding="utf-8", errors="ignore").lower()
            if any(token in data for token in ["debian", "ubuntu", "kali"]):
                return "debian"
            if any(token in data for token in ["fedora", "rhel", "centos", "rocky"]):
                return "fedora"
    except Exception:
        pass
    return "generic"


def _dependency_status(tshark_bin: str | None = None) -> dict:
    checks = [
        {"name": "tshark", "binary": tshark_bin or "tshark", "required": True, "debian": "tshark wireshark-common", "fedora": "wireshark-cli", "purpose": "packet decoding"},
        {"name": "graphviz-dot", "binary": "dot", "required": False, "debian": "graphviz", "fedora": "graphviz", "purpose": "Graphviz PNG graph rendering"},
        {"name": "python3", "binary": "python3", "required": True, "debian": "python3", "fedora": "python3", "purpose": "runtime"},
        {"name": "pip3", "binary": "pip3", "required": False, "debian": "python3-pip", "fedora": "python3-pip", "purpose": "package installation"},
        {"name": "7z", "binary": "7z", "required": False, "debian": "p7zip-full", "fedora": "p7zip p7zip-plugins", "purpose": "archive handling"},
    ]
    family = _detect_linux_family()
    for item in checks:
        item["found"] = shutil.which(item["binary"]) is not None
        item["hint"] = item.get(family) or item.get("debian") or item.get("fedora") or ""
    missing_required = [item for item in checks if item["required"] and not item["found"]]
    missing_optional = [item for item in checks if not item["required"] and not item["found"]]
    return {"family": family, "checks": checks, "missing_required": missing_required, "missing_optional": missing_optional, "ok_required": not missing_required}


def _print_dependency_status(status: dict) -> None:
    print("[*] System dependency check")
    print(f"    Platform family: {status.get('family', 'generic')}")
    for item in status.get("checks", []):
        state = "OK" if item.get("found") else "MISSING"
        print(f"    - {item['name']}: {state} | binary={item['binary']} | purpose={item['purpose']}")
        if not item.get("found") and item.get("hint"):
            print(f"      install hint: {item['hint']}")
    if status.get("missing_optional"):
        print("[!] Optional tools missing. Some report features may be skipped.")
    if status.get("missing_required"):
        print("[!] Required tools missing. Analysis may fail until they are installed.")

def main(argv=None):
    a = build_parser().parse_args(argv)

    dep_status = _dependency_status(getattr(a, "tshark_bin", "tshark"))
    _print_dependency_status(dep_status)
    if getattr(a, "check_deps", False):
        return 0 if dep_status.get("ok_required") else 2
    if not a.pcap or not a.pcap.exists():
        print(f"[!] PCAP not found: {a.pcap}", file=sys.stderr)
        return 2
    if a.metadata and not a.metadata.exists():
        print(f"[!] Metadata YAML not found: {a.metadata}", file=sys.stderr)
        return 2

    run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    default_out = Path("output") / f"{_safe_output_name(a.pcap.stem)}-{run_id}"
    out = a.output or default_out

    ok, msg = _preflight_output_dir(out)
    if not ok:
        print(f"[!] {msg}", file=sys.stderr)
        return 2

    work_dir = out / ".work"

    try:
        metadata = load_metadata(a.metadata)
        protocol_catalog = _load_protocol_catalog(Path.cwd())
        mitre_context = _load_mitre_ics_context(Path.cwd())
        tshark = Tshark(a.tshark_bin)
        pcap_size = a.pcap.stat().st_size

        print(f"[*] Analyzing: {a.pcap}")
        print(f"[*] PCAP size: {_human_size(pcap_size)}")
        print(f"[*] Output: {out}")
        print(f"[*] Metadata: {a.metadata if a.metadata else 'not provided; running baseline mode'}")

        if pcap_size > 100 * 1024 * 1024:
            print("[!] Large PCAP detected. This may take several minutes and use multiple GB of RAM.")
            print("[!] Current version uses streaming aggregation, but rule checks still run multiple tshark passes.")

        print("[*] Stage 1/3: running tshark-based analysis...")
        started = time.perf_counter()

        summary, findings, suggested, ph = analyze_pcap(
            a.pcap,
            metadata,
            tshark,
            a.max_evidence,
            work_dir=work_dir,
        )

        elapsed = time.perf_counter() - started
        summary["analysis_runtime_seconds"] = elapsed
        summary["analysis_runtime_human"] = _human_duration(elapsed)
        summary["metadata_summary"] = _metadata_summary(metadata)

        _enrich_summary(summary, findings, protocol_catalog, mitre_context)

        if metadata:
            suggested["provided_metadata_was_used"] = True
            suggested["generation_mode"] = "pcap_inferred_with_external_metadata_available"
            suggested["metadata_merge_guidance"] = [
                "Do not overwrite factory/site metadata automatically.",
                "Treat this file as observed/inferred enrichment.",
                "Review differences between factory metadata and observed traffic manually.",
                "Use a human-reviewed YAML file for context-aware assessment.",
            ]
            suggested.setdefault("unknowns", []).append(
                "External metadata was provided for analysis, but this suggested file still contains PCAP-inferred observations only."
            )

        print(f"[*] Stage 2/3: rendering reports... analysis runtime: {_human_duration(elapsed)}")
        summary["traffic_timeline"] = _derive_traffic_timeline(a.pcap, tshark, summary)
        summary["_graph_top_n"] = max(3, int(getattr(a, "graph_top_n", 18) or 18))
        render_reports(out, summary, findings, suggested, ph, tshark.commands_used)

        if work_dir.exists():
            shutil.rmtree(work_dir, ignore_errors=True)

        print("[*] Stage 3/3: done.")
        print(f"[+] Output written to: {out}")
        print(f"[+] Findings candidates: {len(findings)}")
        print("[+] Open report.html for the human-readable report.")
        return 0

    except TsharkError as exc:
        print(f"[!] tshark error:\n{exc}", file=sys.stderr)
        print(f"[!] Partial work files may be available in: {work_dir}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[!] Error: {exc}", file=sys.stderr)
        print(f"[!] Partial work files may be available in: {work_dir}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

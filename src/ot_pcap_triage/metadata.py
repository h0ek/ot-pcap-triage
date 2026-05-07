from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any

import yaml


def load_metadata(path: Path | None):
    if not path:
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError("Metadata YAML root must be a mapping/object.")
    return data


def save_yaml(path: Path, data: dict[str, Any]):
    path.write_text(
        yaml.safe_dump(data, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )


def _usable_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        ip = ipaddress.ip_address(value)
    except Exception:
        return False

    if (
        ip.is_unspecified
        or ip.is_loopback
        or ip.is_multicast
        or ip.is_link_local
        or ip.is_reserved
        or (hasattr(ip, "is_broadcast") and ip.is_broadcast)
    ):
        return False

    if str(ip) == "255.255.255.255":
        return False

    return True


def metadata_expected_protocols(metadata):
    protocols = (metadata.get("expected_protocols") or {}) if metadata else {}
    out = set()

    if isinstance(protocols, dict):
        for vals in protocols.values():
            for val in vals or []:
                out.add(str(val).lower())
    elif isinstance(protocols, list):
        for val in protocols:
            out.add(str(val).lower())

    return out


def metadata_allowed_plc_talkers(metadata):
    rows = ((metadata.get("expected_communications") or {}).get("plc_allowed_talkers") or []) if metadata else []
    out = {}

    for row in rows:
        if isinstance(row, dict) and row.get("plc"):
            out[str(row["plc"])] = set(str(v) for v in (row.get("allowed_sources") or []))

    return out


def generate_suggested_metadata(summary):
    conv = summary.get("conversations", [])
    endpoints = summary.get("endpoints", [])
    protocols = summary.get("protocols", [])

    subnets = set()
    for endpoint in endpoints:
        ip_s = endpoint.get("ip", "")
        if not _usable_ip(ip_s):
            continue
        try:
            ip = ipaddress.ip_address(ip_s)
            if ip.version == 4 and ip.is_private:
                subnets.add(str(ipaddress.ip_network(f"{ip}/24", strict=False)))
        except Exception:
            pass

    def servers(port):
        out = {}
        for item in conv:
            if str(item.get("dst_port", "")) == port and _usable_ip(item.get("dst_ip")):
                ip = item["dst_ip"]
                out[ip] = {
                    "ip": ip,
                    "name": "Unknown",
                    "inferred_from": [f"Observed destination port {port}"],
                    "confidence": "medium",
                }
            if str(item.get("src_port", "")) == port and _usable_ip(item.get("src_ip")):
                ip = item["src_ip"]
                out[ip] = {
                    "ip": ip,
                    "name": "Unknown",
                    "inferred_from": [f"Observed source port {port}"],
                    "confidence": "medium",
                }
        return list(out.values())

    industrial = sorted(
        {
            p.get("name")
            for p in protocols
            if p.get("group") == "industrial" and p.get("count", 0) > 0 and p.get("name")
        }
    )

    plc = {}
    ot_ports = {"502", "102", "44818", "4840", "20000", "2404", "47808", "9600", "48898", "18245", "5094"}
    for item in conv:
        if str(item.get("dst_port", "")) in ot_ports and _usable_ip(item.get("dst_ip")):
            ip = item["dst_ip"]
            plc[ip] = {
                "ip": ip,
                "name": "Unknown",
                "vendor": "Unknown",
                "model": "Unknown",
                "area": "Unknown",
                "inferred_from": [f"Observed industrial/common OT port {item.get('dst_port')}"],
                "confidence": "low",
            }

    return {
        "metadata_version": "1.0",
        "generated_by": "ot-pcap-triage",
        "generation_mode": "pcap_inferred",
        "requires_review": True,
        "pcap": {
            "file": summary.get("pcap", {}).get("file", "Unknown"),
            "capture_start_local_time": summary.get("pcap", {}).get("first_packet_time", "Unknown"),
            "capture_duration": summary.get("pcap", {}).get("duration_human", "Unknown"),
            "normal_production": "Unknown",
            "special_activity_during_capture": "Unknown",
            "comments": "Generated from PCAP only. Review before use.",
        },
        "site": {
            "plant": "Unknown",
            "area": "Unknown",
            "criticality": "unknown",
        },
        "capture_point": {
            "switch_name": "Unknown",
            "switch_vendor_model": "Unknown",
            "switch_location": "Unknown",
            "mirror_source": "Unknown",
            "mirror_source_type": "unknown",
            "mirror_destination": "Unknown",
            "mirror_direction": "Unknown",
            "vlans_observed": summary.get("vlans", []),
            "possible_oversubscription": "Unknown",
        },
        "observed_private_subnets": sorted(subnets),
        "expected_network_services": {
            "dns_servers": servers("53"),
            "ntp_servers": servers("123"),
            "dhcp_servers": servers("67"),
            "domain_controllers": servers("88") + servers("389") + servers("636"),
            "monitoring_servers": servers("161"),
            "backup_servers": [],
            "remote_access_servers": servers("3389") + servers("22") + servers("5900"),
        },
        "expected_protocols": {
            "industrial": industrial,
            "infrastructure": [],
            "administration": [],
            "file_transfer": [],
        },
        "known_assets": {
            "plcs": list(plc.values()),
            "hmis": [],
            "scada_servers": [],
            "engineering_stations": [],
            "historian_mes_opc_servers": [],
            "switches_routers_firewalls": [],
            "vendor_remote_access_devices": [],
            "other_assets": [],
        },
        "expected_communications": {
            "plc_allowed_talkers": [],
            "internet_access_allowed": "Unknown",
            "it_network_access_allowed": "Unknown",
            "vendor_remote_access_used": "Unknown",
            "windows_domain_used": "Unknown",
            "dhcp_used": "Unknown",
            "smb_used": "Unknown",
            "rdp_vnc_ssh_used": "Unknown",
        },
        "unknowns": [
            "This YAML was generated from PCAP only and must be reviewed.",
            "Asset roles are inferred and may be incorrect.",
            "Expected PLC talkers are not confirmed.",
        ],
    }

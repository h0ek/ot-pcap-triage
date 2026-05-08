from __future__ import annotations

import csv
import ipaddress
import json
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from .metadata import save_yaml


INDUSTRIAL_TOKENS = (
    "s7", "cotp", "modbus", "cip", "profinet", "opc", "dnp3", "iec", "bacnet",
    "fins", "ethercat", "hart", "ads", "ams", "slmp", "melsec", "srtp",
)


def _json(path, data):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")



def _csv(path, rows):
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)



def _flat_sensitive(rows):
    out = []
    for row in rows:
        evidence = row.get("evidence", {})
        out.append(
            {
                "rule_id": row.get("rule_id", ""),
                "title": row.get("title", ""),
                "severity": row.get("severity", ""),
                "frame_number": evidence.get("frame_number", ""),
                "timestamp": evidence.get("timestamp", ""),
                "protocol": evidence.get("protocol", ""),
                "src_ip": evidence.get("src_ip", ""),
                "src_mac": evidence.get("src_mac", ""),
                "src_port": evidence.get("src_port", ""),
                "dst_ip": evidence.get("dst_ip", ""),
                "dst_mac": evidence.get("dst_mac", ""),
                "dst_port": evidence.get("dst_port", ""),
                "redacted_fields": json.dumps(row.get("redacted_fields", {}), ensure_ascii=False),
                "wireshark_filter": row.get("wireshark_filter", ""),
            }
        )
    return out



def _inject_external_link_targets(html: str) -> str:
    import re

    def repl(match):
        tag = match.group(0)
        if "target=" not in tag:
            tag = tag[:-1] + ' target="_blank"' + tag[-1]
        if "rel=" not in tag:
            tag = tag[:-1] + ' rel="noopener noreferrer"' + tag[-1]
        return tag

    return re.sub(r'<a\s+[^>]*href="https?://[^"]+"[^>]*>', repl, html, flags=re.IGNORECASE)



def _render_timeline_chart(output_dir: Path, summary: dict):
    timeline = (summary or {}).get("traffic_timeline") or {}
    labels = timeline.get("labels") or []
    series = timeline.get("series") or {}
    if not labels or not series:
        return None

    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        return None

    order = [
        group
        for group in ["S7/COTP", "Modbus", "EtherNet/IP", "BACnet", "OPC UA", "DNP3", "HTTP", "SMB/NetBIOS", "DNS", "NTP", "ICMP/ARP", "VPN", "Discovery", "Other"]
        if group in series
    ]
    if not order:
        return None

    x = list(range(len(labels)))
    bottom = [0] * len(labels)

    fig, ax = plt.subplots(figsize=(12, 4.8))
    for group in order:
        values = [int(value or 0) for value in series.get(group, [])]
        ax.bar(x, values, bottom=bottom, label=group, width=0.9)
        bottom = [bottom[i] + values[i] for i in range(len(values))]

    tick_step = max(1, len(labels) // 12)
    ticks = x[::tick_step]
    tick_labels = [labels[i] for i in ticks]
    ax.set_xticks(ticks)
    ax.set_xticklabels(tick_labels, rotation=45, ha="right")
    ax.set_xlabel(f"Time buckets ({timeline.get('bucket_human', 'n/a')})")
    ax.set_ylabel("Packets")
    ax.set_title("Traffic Timeline")
    ax.grid(True, axis="y", alpha=0.3)
    ax.legend(loc="upper right", fontsize=8, ncols=2)
    fig.tight_layout()

    chart_path = output_dir / "timeline_packets.png"
    fig.savefig(chart_path, dpi=160)
    plt.close(fig)
    return chart_path.name



def _endpoint_ip(value: str) -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    if value.startswith("[") and "]" in value:
        return value[1:].split("]", 1)[0]
    if value.count(":") == 1:
        return value.rsplit(":", 1)[0]
    return value



def _packet_count(row: dict) -> int:
    try:
        return int(row.get("packets") or 0)
    except Exception:
        return 0



def _bytes_count(row: dict) -> int:
    try:
        return int(row.get("bytes") or 0)
    except Exception:
        return 0



def _row_src_ip(row: dict) -> str:
    return _endpoint_ip(
        row.get("source")
        or row.get("src")
        or row.get("src_ip")
        or row.get("client")
        or ""
    )



def _row_dst_ip(row: dict) -> str:
    return _endpoint_ip(
        row.get("destination")
        or row.get("dst")
        or row.get("dst_ip")
        or row.get("server")
        or row.get("plc")
        or ""
    )



def _short_role(summary: dict, ip: str) -> str:
    inventory = (summary or {}).get("passive_asset_inventory") or []
    for row in inventory:
        if row.get("ip") == ip:
            roles = row.get("possible_roles") or []
            if isinstance(roles, str):
                roles = [r.strip() for r in roles.split(",") if r.strip()]
            if roles:
                role = str(roles[0])
                replacements = [
                    ("possible ", ""),
                    (" / ", "/"),
                    ("controller", "PLC"),
                    ("engineering", "eng"),
                    ("participant", "node"),
                    ("scanner/client", "scanner"),
                    ("remote-access", "remote"),
                ]
                for old, new in replacements:
                    role = role.replace(old, new)
                return role[:36]
    return ""



def _public_ips(summary: dict) -> set[str]:
    out = set()
    for row in (summary or {}).get("endpoints") or []:
        if row.get("public"):
            ip = row.get("ip")
            if ip:
                out.add(str(ip))
    for row in (summary or {}).get("passive_asset_inventory") or []:
        roles = row.get("possible_roles") or []
        if isinstance(roles, str):
            roles = [roles]
        joined = " ".join(str(x) for x in roles).lower()
        if "public/external host" in joined:
            ip = row.get("ip")
            if ip:
                out.add(str(ip))
    return out



def _node_style(summary: dict, ip: str) -> dict:
    public_set = _public_ips(summary)
    role = _short_role(summary, ip)
    fill = "#eef4ff"
    shape = "ellipse"
    if ip in public_set:
        fill = "#fdeaea"
        shape = "box"
    elif any(token in role for token in ("PLC", "S7")):
        fill = "#fff3cd"
        shape = "box"
    elif any(token in role for token in ("DNS", "NTP")):
        fill = "#eaf7ff"
    elif any(token in role for token in ("eng", "HMI", "SCADA", "scanner")):
        fill = "#f5ecff"
    label = f"{ip}\n{role}" if role else ip
    return {"fillcolor": fill, "shape": shape, "label": label}



def _edge_color(protocol: str) -> str:
    proto = str(protocol or "").lower()
    if any(token in proto for token in INDUSTRIAL_TOKENS):
        return "#b35c00"
    if "dns" in proto:
        return "#1f77b4"
    if "ntp" in proto:
        return "#17a2b8"
    if any(token in proto for token in ("openvpn", "vpn", "isakmp", "esp", "udpencap")):
        return "#7f3fbf"
    if "icmp" in proto:
        return "#666666"
    if any(token in proto for token in ("http", "ftp", "telnet", "ssh", "rdp", "vnc", "rsh")):
        return "#2ca02c"
    return "#444444"



def _truncate_text(value: str, max_len: int = 26) -> str:
    value = str(value or "")
    if len(value) <= max_len:
        return value
    return value[: max_len - 1].rstrip() + "…"


def _edge_penwidth(packets: int, max_packets: int) -> str:
    if max_packets <= 0:
        return "1.2"
    ratio = max(0.0, min(1.0, float(packets) / float(max_packets)))
    return f"{1.2 + ratio * 3.8:.2f}"



def _conversation_rows(summary: dict) -> list[dict]:
    rows = list((summary or {}).get("conversations") or [])
    rows.sort(key=_packet_count, reverse=True)
    return rows



def _overview_rows(summary: dict, limit: int = 18) -> list[dict]:
    rows = _conversation_rows(summary)
    return [row for row in rows if _packet_count(row) > 0][:limit]



def _risk_or_industrial_rows(summary: dict, limit: int = 18) -> list[dict]:
    out = []
    for row in _conversation_rows(summary):
        proto = str(row.get("protocol") or "")
        proto_l = proto.lower()
        external = bool(row.get("external"))
        interesting = external or any(
            token in proto_l
            for token in INDUSTRIAL_TOKENS + (
                "openvpn", "vpn", "dns", "ntp", "icmp", "http", "ftp", "telnet", "ssh", "rdp", "vnc", "rsh"
            )
        )
        if interesting and _packet_count(row) > 0:
            out.append(row)
        if len(out) >= limit:
            break
    return out



def _industrial_rows(summary: dict, limit: int = 18) -> list[dict]:
    out = []
    for row in _conversation_rows(summary):
        proto_l = str(row.get("protocol") or "").lower()
        if any(token in proto_l for token in INDUSTRIAL_TOKENS) and _packet_count(row) > 0:
            out.append(row)
        if len(out) >= limit:
            break
    return out



def _external_rows(summary: dict, limit: int = 18) -> list[dict]:
    out = []
    for row in _conversation_rows(summary):
        if bool(row.get("external")) and _packet_count(row) > 0:
            out.append(row)
        if len(out) >= limit:
            break
    return out


def _guess_bucket(ip: str, summary: dict) -> tuple[str, str, str]:
    public_set = _public_ips(summary)
    if ip in public_set:
        return ("external", "Public / External", "#fff5f5")

    try:
        ip_obj = ipaddress.ip_address(ip)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            if ip_obj.is_private:
                net = ipaddress.ip_network(f"{ip}/24", strict=False)
                key = str(net).replace("/", "_")
                return (f"private_{key}", str(net), "#f8fbff")
            if ip_obj.is_loopback:
                return ("loopback", "Loopback", "#f9f9f9")
            if ip_obj.is_link_local:
                return ("linklocal", "Link-local", "#f9f9f9")
            return ("other_ipv4", "Other IPv4", "#f9f9f9")
        if ip_obj.is_private:
            return ("ipv6_private", "IPv6 private", "#f8fbff")
        return ("ipv6_other", "IPv6 / Other", "#f9f9f9")
    except Exception:
        pass

    if ip.startswith("127."):
        return ("loopback", "Loopback", "#f9f9f9")
    return ("other", "Other / Unparsed", "#f9f9f9")



def _graph_stats(rows: list[dict]) -> tuple[int, int]:
    nodes = set()
    for row in rows:
        src = _row_src_ip(row)
        dst = _row_dst_ip(row)
        if src:
            nodes.add(src)
        if dst:
            nodes.add(dst)
    return (len(nodes), len(rows))



def _render_graph(output_dir: Path, summary: dict, rows: list[dict], stem: str, title: str, subtitle: str) -> str | None:
    if not rows:
        return None
    try:
        from graphviz import Digraph
    except Exception:
        return None

    dot = Digraph(
        name=stem,
        format="png",
        engine="dot",
        graph_attr={
            "rankdir": "LR",
            "label": f"{title}\n{subtitle}",
            "labelloc": "t",
            "fontsize": "18",
            "fontname": "Helvetica",
            "overlap": "false",
            "splines": "true",
            "pad": "0.2",
            "nodesep": "0.35",
            "ranksep": "0.5",
            "compound": "true",
        },
        node_attr={
            "style": "filled,rounded",
            "fontname": "Helvetica",
            "fontsize": "10",
            "color": "#666666",
            "margin": "0.10,0.06",
        },
        edge_attr={
            "fontname": "Helvetica",
            "fontsize": "9",
            "color": "#444444",
            "arrowsize": "0.7",
        },
    )

    max_packets = max((_packet_count(row) for row in rows), default=0)
    nodes = set()
    for row in rows:
        src = _row_src_ip(row)
        dst = _row_dst_ip(row)
        if src:
            nodes.add(src)
        if dst:
            nodes.add(dst)

    buckets = {}
    for ip in sorted(nodes):
        bucket_key, bucket_label, bucket_color = _guess_bucket(ip, summary)
        buckets.setdefault(bucket_key, {"label": bucket_label, "color": bucket_color, "nodes": []})["nodes"].append(ip)

    for idx, bucket_key in enumerate(sorted(buckets, key=lambda k: buckets[k]["label"])):
        bucket = buckets[bucket_key]
        with dot.subgraph(name=f"cluster_{idx}") as sub:
            sub.attr(label=bucket["label"], color="#c9d2dc", style="rounded,filled", fillcolor=bucket["color"])
            for ip in bucket["nodes"]:
                attrs = _node_style(summary, ip)
                sub.node(ip, label=attrs["label"], fillcolor=attrs["fillcolor"], shape=attrs["shape"])

    for row in rows:
        src = _row_src_ip(row)
        dst = _row_dst_ip(row)
        if not src or not dst:
            continue
        protocol = str(row.get("protocol") or "UNKNOWN")
        packets = _packet_count(row)
        bytes_ = _bytes_count(row)
        short_proto = _truncate_text(protocol, 24)
        label = f"{short_proto}\n{packets} pkts / {bytes_} B"
        dot.edge(
            src,
            dst,
            label=label,
            color=_edge_color(protocol),
            penwidth=_edge_penwidth(packets, max_packets),
        )

    target = output_dir / stem
    try:
        rendered = dot.render(str(target), cleanup=True)
    except Exception:
        return None
    return Path(rendered).name



def _render_communication_graphs(output_dir: Path, summary: dict) -> dict:
    graphs = {}
    top_n = max(3, int((summary or {}).get("_graph_top_n") or 18))
    graphs["graph_top_n"] = top_n

    overview_rows = _overview_rows(summary, limit=top_n)
    overview_file = _render_graph(
        output_dir,
        summary,
        overview_rows,
        "communication_graph",
        "Communication Graph",
        f"Top {len(overview_rows)} conversations by packet count",
    )
    if overview_file:
        nodes, edges = _graph_stats(overview_rows)
        graphs["communication_graph"] = overview_file
        graphs["communication_edges"] = edges
        graphs["communication_nodes"] = nodes

    risk_rows = _risk_or_industrial_rows(summary, limit=top_n)
    risk_file = _render_graph(
        output_dir,
        summary,
        risk_rows,
        "industrial_risk_graph",
        "Industrial / Risk Communication Graph",
        f"Top {len(risk_rows)} industrial, external or risky paths",
    )
    if risk_file:
        nodes, edges = _graph_stats(risk_rows)
        graphs["industrial_risk_graph"] = risk_file
        graphs["industrial_risk_edges"] = edges
        graphs["industrial_risk_nodes"] = nodes

    industrial_rows = _industrial_rows(summary, limit=top_n)
    industrial_file = _render_graph(
        output_dir,
        summary,
        industrial_rows,
        "industrial_protocol_graph",
        "Industrial Protocol Graph",
        f"Top {len(industrial_rows)} industrial protocol paths",
    )
    if industrial_file:
        nodes, edges = _graph_stats(industrial_rows)
        graphs["industrial_protocol_graph"] = industrial_file
        graphs["industrial_protocol_edges"] = edges
        graphs["industrial_protocol_nodes"] = nodes

    external_rows = _external_rows(summary, limit=top_n)
    external_file = _render_graph(
        output_dir,
        summary,
        external_rows,
        "external_communication_graph",
        "External Communication Graph",
        f"Top {len(external_rows)} external communication paths",
    )
    if external_file:
        nodes, edges = _graph_stats(external_rows)
        graphs["external_communication_graph"] = external_file
        graphs["external_communication_edges"] = edges
        graphs["external_communication_nodes"] = nodes

    return graphs



def render_reports(output_dir, summary, findings, suggested_metadata, protocol_hierarchy_raw, commands_used):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    env = Environment(
        loader=PackageLoader("ot_pcap_triage", "templates"),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )

    timeline_chart = _render_timeline_chart(output_dir, summary)
    if timeline_chart:
        summary.setdefault("traffic_timeline", {})["chart_file"] = timeline_chart

    graph_info = _render_communication_graphs(output_dir, summary)
    if graph_info:
        summary["graphs"] = graph_info

    context = {
        "summary": summary,
        "findings": findings,
        "protocol_hierarchy_raw": protocol_hierarchy_raw,
    }

    html_text = env.get_template("report.html.j2").render(**context)
    html_text = _inject_external_link_targets(html_text)
    (output_dir / "report.html").write_text(html_text, encoding="utf-8")

    md_text = env.get_template("report.md.j2").render(**context)
    (output_dir / "report.md").write_text(md_text, encoding="utf-8")

    _json(output_dir / "summary.json", summary)
    _json(output_dir / "findings.json", findings)
    _csv(output_dir / "endpoints.csv", summary.get("endpoints", []))
    _csv(output_dir / "conversations.csv", summary.get("conversations", []))
    _csv(output_dir / "protocols.csv", summary.get("protocols", []))
    _csv(output_dir / "sensitive_hits_redacted.csv", _flat_sensitive(summary.get("sensitive_hits_redacted", [])))
    save_yaml(output_dir / "suggested_metadata.yml", suggested_metadata)
    (output_dir / "commands_used.txt").write_text(
        "\n".join(" ".join(command) for command in commands_used) + "\n",
        encoding="utf-8",
    )

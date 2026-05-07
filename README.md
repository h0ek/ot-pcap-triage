# ot-pcap-triage

Offline passive OT PCAP triage helper using `tshark`.

`ot-pcap-triage` reads existing `.pcap` / `.pcapng` files and generates a lightweight triage report for passive OT/ICS network assessment.

It does not actively scan, inject packets, or connect to any target.

## What it does

`ot-pcap-triage` helps analyze passive OT traffic by generating:

- HTML and Markdown reports;
- finding candidates and review points;
- endpoint and conversation summaries;
- passive asset inventory;
- industrial protocol observations;
- risky/external communication indicators;
- redacted sensitive/plaintext evidence;
- timeline and communication graphs;
- suggested metadata for follow-up context-aware analysis.

The tool is intended for **triage and analyst support**, not automatic vulnerability confirmation.

## Fedora install

```bash
sudo dnf install -y git wireshark-cli python3 python3-pip graphviz p7zip p7zip-plugins
```

## Debian / Kali install

```bash
sudo apt install -y git tshark wireshark-common python3 python3-pip graphviz p7zip-full
```

## Python install with virtualenvwrapper

Clone the repository:

```bash
git clone https://github.com/h0ek/ot-pcap-traige
cd ot-pcap-traige
```

Create and install in a virtualenv:

```bash
mkvirtualenv ot-pcap-triage -p python3
pip install -e .
```

Verify:

```bash
ot-pcap-triage --help
ot-pcap-triage --check-deps
```

## Basic usage

PCAP-only mode:

```bash
ot-pcap-triage capture.pcapng
```

PCAP with factory/site metadata:

```bash
ot-pcap-triage capture.pcapng --metadata capture.yml
```

Custom output directory:

```bash
ot-pcap-triage capture.pcapng -o output/test1
```

More evidence frames per rule:

```bash
ot-pcap-triage capture.pcapng --max-evidence 25
```

Graph size tuning:

```bash
ot-pcap-triage capture.pcapng --graph-top-n 25
```

Dependency-only preflight:

```bash
ot-pcap-triage --check-deps
```

## Metadata template

A default metadata template is provided:

```text
metadata_template.yml
```

Copy it for a specific capture:

```bash
cp metadata_template.yml plant1-line2-capture.yml
nano plant1-line2-capture.yml
```

Use it:

```bash
ot-pcap-triage capture.pcapng --metadata plant1-line2-capture.yml -o output/plant1-line2
```

## Recommended workflow

Best workflow when the factory/site can provide context:

```text
1. Ask the factory/site to fill metadata_template.yml.

2. Run PCAP-only mode first:
   ot-pcap-triage capture.pcapng -o out-pass1

3. Review out-pass1/suggested_metadata.yml.

4. Compare observed/inferred data with the factory-provided metadata.

5. Create reviewed metadata:
   cp factory_metadata.yml reviewed_metadata.yml
   nano reviewed_metadata.yml

6. Add useful observations from suggested_metadata.yml manually.

7. Run context-aware mode:
   ot-pcap-triage capture.pcapng --metadata reviewed_metadata.yml -o out-pass2

8. Use out-pass2/report.html and findings.json for manual validation.
```

When no metadata exists:

```bash
ot-pcap-triage capture.pcapng -o out-pass1
cp out-pass1/suggested_metadata.yml reviewed_capture.yml
nano reviewed_capture.yml
ot-pcap-triage capture.pcapng --metadata reviewed_capture.yml -o out-pass2
```

## Metadata behavior

```text
factory metadata = expected architecture
suggested_metadata.yml = observed/inferred helper
reviewed_metadata.yml = human-reviewed combination
```

The generated `suggested_metadata.yml` is not authoritative. It must be reviewed.

If `--metadata` is provided, the provided metadata is used for expected-vs-observed checks, but `suggested_metadata.yml` is still generated as observed/inferred enrichment.

## Output files

Default output directory:

```text
output/<pcap-name>-<timestamp>/
  report.html
  report.md
  summary.json
  findings.json
  endpoints.csv
  conversations.csv
  protocols.csv
  sensitive_hits_redacted.csv
  suggested_metadata.yml
  commands_used.txt
  timeline_packets.png
  communication_graph.png
  industrial_risk_graph.png
  industrial_protocol_graph.png
  external_communication_graph.png
```

Some files may be missing if there is no matching data or an optional renderer is unavailable. For example, graph images require Graphviz `dot`.

## Report sections

The HTML and Markdown reports include:

- PCAP Summary;
- Baseline Mode Notice, when no metadata YAML was provided;
- NIST SP 800-82r3 Review Context;
- MITRE ATT&CK for ICS Review Context;
- Top Risky Observations;
- Observed Industrial Protocols;
- Top S7/COTP Communication Paths, when S7 traffic is observed;
- Extended Protocol Candidates;
- Traffic Timeline;
- Communication Graph;
- Industrial / Risk Communication Graph;
- Industrial Protocol Graph;
- External Communication Graph;
- Graph Legend;
- Passive Asset Inventory;
- Cleartext Management Surface;
- IT/OT Convergence Indicators;
- Engineering / Scanner Candidates;
- Analyst Questions;
- Capture Quality Notes;
- Finding Candidates;
- Top Endpoints;
- Top Conversations;
- Rule Results;
- Protocol Hierarchy Raw.

## Baseline mode without metadata

When no metadata YAML is provided, the tool still reports generic OT/ICS best-practice review points.

Examples:

- public DNS;
- public NTP;
- VPN-like traffic;
- plaintext protocols;
- discovery/name-resolution noise;
- TCP connection anomalies;
- observed industrial protocols.

Without metadata, these are usually `candidate` or `informational` observations that require validation with the local OT/site owner.

Metadata does not make the tool “work”; metadata increases confidence and enables expected-vs-observed checks.

## Finding candidates

A finding candidate is not automatically a confirmed vulnerability.

Typical statuses:

| Status | Meaning |
|---|---|
| `candidate` | Potential issue detected automatically. |
| `confirmed_by_rule` | Strong direct evidence, for example cleartext credential indicator. |
| `informational` | Useful observation, not a finding by itself. |

Manual validation is required.

## OT enrichment

The report includes OT-specific enrichment sections:

- `Passive Asset Inventory` — inferred roles based on observed protocols and ports;
- `Cleartext Management Surface` — Telnet/FTP/HTTP/SNMP/RSH-like management exposure candidates;
- `IT/OT Convergence Indicators` — public communication, VPN-like traffic, cross-subnet industrial communication;
- `Engineering / Scanner Candidates` — hosts that initiate industrial protocol communication to controllers/devices.

These sections are heuristic. Without metadata, they are review points. With metadata, they help validate expected-vs-observed architecture.

## Protocol catalog enrichment

`protocol_catalog.yml` contains a curated list of industrial, utility, and building automation protocol port mappings.

The catalog is used for enrichment only:

- it helps label possible industrial/building/utility protocol candidates;
- it does not automatically create high-severity findings;
- matches based only on ports are shown as candidates;
- analyst validation is required.

The report section `Extended Protocol Candidates` shows catalog matches with:

- protocol name;
- category;
- matched port;
- packet/byte counters;
- confidence;
- note.

This is useful when a protocol is not decoded by Wireshark/tshark but the traffic uses a known industrial port.

## NIST SP 800-82r3 review context

Reports include an optional `NIST SP 800-82r3 Review Context` section.

This maps observed PCAP findings to high-level OT security themes such as:

- network segmentation and boundary protection;
- remote access control;
- plaintext protocol exposure;
- anomaly and event monitoring;
- industrial protocol security;
- asset inventory validation;
- IT/OT convergence review.

This is **not** a compliance certification. It is analyst guidance that helps connect packet evidence to recognized OT security review areas.

Source: https://doi.org/10.6028/NIST.SP.800-82r3

## MITRE ATT&CK for ICS review context

Reports include an optional `MITRE ATT&CK for ICS Review Context` section.

This maps observed PCAP findings to related ATT&CK for ICS techniques to consider, such as:

- Remote Services;
- Internet Accessible Device;
- Remote System Discovery;
- Port Scan;
- Broadcast Discovery;
- Multicast Discovery;
- Standard Application Layer Protocol;
- Commonly Used Port;
- Rogue Master;
- Unauthorized Message;
- Program Upload / Program Download context where later evidence supports it.

This is **not** proof of adversary activity. It is a contextual mapping to help analysts think about how observed network behavior could relate to known adversary techniques.

MITRE context is generated from:

```text
mitre_ics_context.yml
```

Source: https://attack.mitre.org/matrices/ics/

## Traffic timeline

Reports include a `Traffic Timeline` section with a static PNG chart generated from the PCAP.

Behavior:

- bucket size is selected automatically;
- captures up to roughly 2 hours use 1-minute buckets;
- larger captures use 5-minute buckets;
- series shown: S7/COTP, DNS, NTP, ICMP, VPN, Discovery, and Other.

Output file:

```text
timeline_packets.png
```

## Communication graphs

Reports include Graphviz-based static communication maps:

- `communication_graph.png` — top communication paths by packet count;
- `industrial_risk_graph.png` — industrial, external, or otherwise high-interest paths;
- `industrial_protocol_graph.png` — industrial-only communication view;
- `external_communication_graph.png` — public/external communication view.

Graph behavior:

- graph size is controlled with `--graph-top-n`;
- node labels include IP plus a short inferred role when available;
- nodes are grouped into subnet clusters;
- edge labels show protocol, packet count, and byte count;
- graph legend is included in the report.

## Public test PCAPs

Public ICS/SCADA PCAPs are available at Netresec:

```text
https://www.netresec.com/?page=PcapFiles
```

Useful sections:

- `SCADA/ICS Network Captures`;
- `4SICS ICS Lab PCAP files`;
- `DigitalBond S4x15 ICS Village CTF PCAPs`.

## Performance notes

Main packet aggregation is streamed from `tshark` line-by-line instead of loading all packet rows into memory.

This reduces Python memory usage for large PCAP files.

The tool still runs additional `tshark` passes for rule evidence and counts, so large files can still take time.

Temporary partial files are written to:

```text
output/<pcap-name>/.work/
```

The `.work` directory is removed after a successful run. If the tool crashes, it may remain for debugging.

## Limitations

- Passive PCAP only.
- Traffic not visible at the capture point cannot be assessed.
- Short captures may miss scheduled jobs, vendor access, or engineering activity.
- SPAN/mirror oversubscription may cause missing packets.
- Encrypted payloads cannot be fully inspected.
- Findings are candidates/review points until manually validated.
- Absence of evidence is not evidence of absence.

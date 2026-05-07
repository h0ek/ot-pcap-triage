from __future__ import annotations

import csv
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


class TsharkError(RuntimeError):
    pass


@dataclass
class CommandResult:
    command: list[str]
    stdout: str
    stderr: str
    returncode: int


class Tshark:
    def __init__(self, tshark_bin: str = "tshark") -> None:
        self.tshark_bin = tshark_bin
        self.commands_used: list[list[str]] = []
        if shutil.which(tshark_bin) is None:
            raise TsharkError(
                f"'{tshark_bin}' not found in PATH. Install wireshark-cli/tshark first."
            )

    def _field_args(
        self,
        pcap: Path,
        fields: list[str],
        display_filter: str | None = None,
        limit: int | None = None,
        occurrence: str = "f",
    ) -> list[str]:
        args = ["-r", str(pcap)]
        if display_filter:
            args += ["-Y", display_filter]
        if limit:
            args += ["-c", str(limit)]
        args += [
            "-T", "fields",
            "-E", "header=y",
            "-E", "separator=\t",
            "-E", f"occurrence={occurrence}",
        ]
        for field in fields:
            args += ["-e", field]
        return args

    def run(self, args: list[str], check: bool = True) -> CommandResult:
        cmd = [self.tshark_bin] + args
        self.commands_used.append(cmd)
        proc = subprocess.run(
            cmd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if check and proc.returncode != 0:
            raise TsharkError(
                f"Command failed: {' '.join(cmd)}\n"
                f"Exit: {proc.returncode}\n"
                f"{proc.stderr}"
            )
        return CommandResult(cmd, proc.stdout, proc.stderr, proc.returncode)

    def fields(
        self,
        pcap: Path,
        fields: list[str],
        display_filter: str | None = None,
        limit: int | None = None,
        occurrence: str = "f",
    ) -> list[dict[str, str]]:
        args = self._field_args(pcap, fields, display_filter, limit, occurrence)
        res = self.run(args, check=False)
        if res.returncode != 0 or not res.stdout.strip():
            return []
        return [dict(row) for row in csv.DictReader(res.stdout.splitlines(), delimiter="\t")]

    def iter_fields(
        self,
        pcap: Path,
        fields: list[str],
        display_filter: str | None = None,
        occurrence: str = "f",
    ) -> Iterator[dict[str, str]]:
        """Stream tshark -T fields output row-by-row.

        This avoids holding all packet rows in memory for large PCAP files.
        """
        args = self._field_args(pcap, fields, display_filter, None, occurrence)
        cmd = [self.tshark_bin] + args
        self.commands_used.append(cmd)

        proc = subprocess.Popen(
            cmd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1,
        )
        assert proc.stdout is not None

        header_line = proc.stdout.readline()
        if not header_line:
            stderr = proc.stderr.read() if proc.stderr else ""
            proc.wait()
            if proc.returncode not in (0, None):
                raise TsharkError(
                    f"Command failed: {' '.join(cmd)}\n"
                    f"Exit: {proc.returncode}\n"
                    f"{stderr}"
                )
            return

        headers = header_line.rstrip("\n").split("\t")
        for line in proc.stdout:
            values = line.rstrip("\n").split("\t")
            if len(values) < len(headers):
                values += [""] * (len(headers) - len(values))
            elif len(values) > len(headers):
                values = values[:len(headers)]
            yield dict(zip(headers, values))

        stderr = proc.stderr.read() if proc.stderr else ""
        rc = proc.wait()
        if rc != 0:
            raise TsharkError(
                f"Command failed: {' '.join(cmd)}\n"
                f"Exit: {rc}\n"
                f"{stderr}"
            )

    def raw_protocol_hierarchy(self, pcap: Path) -> str:
        res = self.run(["-r", str(pcap), "-q", "-z", "io,phs"], check=False)
        return (res.stdout or "") + (("\nSTDERR:\n" + res.stderr) if res.stderr else "")

    def count_filter(self, pcap: Path, display_filter: str) -> int:
        return len(self.fields(pcap, ["frame.number"], display_filter=display_filter))

    def evidence_rows(
        self,
        pcap: Path,
        display_filter: str,
        max_rows: int,
        extra_fields: list[str] | None = None,
    ) -> list[dict[str, str]]:
        base = [
            "frame.number",
            "frame.time",
            "frame.time_epoch",
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
            "tcp.stream",
            "_ws.col.Protocol",
            "_ws.col.Info",
            "frame.protocols",
        ]

        rows = self.fields(
            pcap,
            base + (extra_fields or []),
            display_filter=display_filter,
            limit=None,
        )
        return rows[:max_rows]

from __future__ import annotations

import csv
import shutil
import subprocess
import tempfile
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
        args = ["-n", "-r", str(pcap)]
        if display_filter:
            args += ["-Y", display_filter]
        if limit:
            args += ["-c", str(limit)]
        args += [
            "-T", "fields",
            "-E", "header=y",
            "-E", "separator=/t",
            "-E", "quote=d",
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
        return list(self.iter_fields(pcap, fields, display_filter, occurrence, limit))

    def iter_fields(
        self,
        pcap: Path,
        fields: list[str],
        display_filter: str | None = None,
        occurrence: str = "f",
        limit: int | None = None,
    ) -> Iterator[dict[str, str]]:
        cmd = [self.tshark_bin] + self._field_args(pcap, fields, display_filter, limit, occurrence)
        self.commands_used.append(cmd)
        with tempfile.TemporaryFile(mode="w+t", encoding="utf-8", errors="replace") as stderr:
            with subprocess.Popen(cmd, text=True, encoding="utf-8", errors="replace", stdout=subprocess.PIPE, stderr=stderr, bufsize=1) as proc:
                try:
                    assert proc.stdout is not None
                    for row in csv.DictReader(proc.stdout, delimiter="\t"):
                        yield dict(row)
                    rc = proc.wait()
                    if rc:
                        stderr.seek(0)
                        raise TsharkError(f"Command failed: {' '.join(cmd)}\nExit: {rc}\n{stderr.read(16000)}")
                finally:
                    if proc.poll() is None:
                        proc.terminate()
                        try:
                            proc.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            proc.wait()

    def raw_protocol_hierarchy(self, pcap: Path) -> str:
        res = self.run(["-n", "-r", str(pcap), "-q", "-z", "io,phs"])
        return (res.stdout or "") + (("\nSTDERR:\n" + res.stderr) if res.stderr else "")

    def count_filter(self, pcap: Path, display_filter: str) -> int:
        return sum(1 for _ in self.iter_fields(pcap, ["frame.number"], display_filter=display_filter))

    def count_and_evidence(self, pcap, display_filter, max_rows, extra_fields=None):
        base = [
            "frame.number", "frame.time", "frame.time_epoch", "eth.src", "eth.dst",
            "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "tcp.srcport", "tcp.dstport",
            "udp.srcport", "udp.dstport", "tcp.stream", "_ws.col.Protocol", "frame.protocols",
        ]
        count, samples = 0, []
        for row in self.iter_fields(pcap, base + (extra_fields or []), display_filter):
            count += 1
            if len(samples) < max_rows:
                samples.append(row)
        return count, samples

    def evidence_rows(self, pcap, display_filter, max_rows, extra_fields=None):
        return self.count_and_evidence(pcap, display_filter, max_rows, extra_fields)[1]

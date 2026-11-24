import ipaddress
import struct


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    value = sum(struct.unpack(f"!{len(data)//2}H", data))
    while value >> 16:
        value = (value & 0xffff) + (value >> 16)
    return (~value) & 0xffff


def udp_packet(src, dst, sport, dport, payload):
    src, dst = ipaddress.ip_address(src), ipaddress.ip_address(dst)
    udp = struct.pack("!HHHH", sport, dport, len(payload) + 8, 0) + payload
    eth = bytes.fromhex("00112233445566778899aabb")
    if src.version == 4:
        header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, src.packed, dst.packed)
        header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
        return eth + b"\x08\x00" + header + udp
    pseudo = src.packed + dst.packed + struct.pack("!I3xB", len(udp), 17)
    udp = udp[:6] + struct.pack("!H", checksum(pseudo + udp) or 0xffff) + udp[8:]
    header = struct.pack("!IHBB16s16s", 6 << 28, len(udp), 17, 64, src.packed, dst.packed)
    return eth + b"\x86\xdd" + header + udp


def write_fixture(path):
    dns = struct.pack("!6H", 1, 0x0100, 1, 0, 0, 0) + b"\x07example\x03com\x00\x00\x01\x00\x01"
    ntp = bytes([0x23]) + bytes(47)
    packets = [
        udp_packet("10.0.0.2", "8.8.8.8", 49152, 53, dns),
        udp_packet("fd00::2", "2606:4700:4700::1111", 49153, 53, dns),
        udp_packet("10.0.0.2", "10.0.0.3", 49154, 53, dns),
        udp_packet("10.0.0.2", "1.1.1.1", 49155, 123, ntp),
    ]
    with path.open("wb") as stream:
        stream.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for index, packet in enumerate(packets):
            stream.write(struct.pack("<IIII", 1700000000 + index, 0, len(packet), len(packet)))
            stream.write(packet)
